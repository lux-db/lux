#[cfg(test)]
use super::ExecAfterCommandHook;
use super::Store;
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::Ordering;

thread_local! {
    /// Command surfaces enter once; leaf mutation helpers may re-enter while
    /// preparing their journal records on the same thread.
    static READ_DEPTHS: RefCell<HashMap<usize, usize>> = RefCell::new(HashMap::new());
    /// Live changes stay hidden behind the exclusive execution gate while their
    /// recovery commands and notifications are accumulated for one commit.
    static ACTIVE: RefCell<Option<ActiveExec>> = const { RefCell::new(None) };
}

struct ActiveExec {
    store_id: usize,
    commands: Vec<Vec<Vec<u8>>>,
    row_deltas: BTreeMap<(String, String), ()>,
    key_events: Vec<Vec<Vec<u8>>>,
    list_wake_keys: BTreeMap<String, ()>,
}

pub(crate) struct ExecCommitEffects {
    pub(crate) key_events: Vec<Vec<Vec<u8>>>,
    pub(crate) list_wake_keys: Vec<String>,
}

pub(crate) struct ExecutionReadGuard<'a> {
    store_id: usize,
    _guard: Option<parking_lot::RwLockReadGuard<'a, ()>>,
    tracked: bool,
}

impl Drop for ExecutionReadGuard<'_> {
    fn drop(&mut self) {
        if !self.tracked {
            return;
        }
        READ_DEPTHS.with(|depths| {
            let mut depths = depths.borrow_mut();
            let depth = depths
                .get_mut(&self.store_id)
                .expect("execution read depth must exist while guard is alive");
            *depth -= 1;
            if *depth == 0 {
                depths.remove(&self.store_id);
            }
        });
    }
}

pub(crate) struct ExecTransactionGuard<'a> {
    store: &'a Store,
    _guard: parking_lot::RwLockWriteGuard<'a, ()>,
    closed: bool,
}

impl ExecTransactionGuard<'_> {
    pub(crate) fn commit(&mut self) -> std::io::Result<ExecCommitEffects> {
        let state = self.store.take_active_exec()?;

        if !state.commands.is_empty()
            && self.store.journal.is_some()
            && !self.store.wal_suppress.load(Ordering::Relaxed)
        {
            let arg_refs: Vec<Vec<&[u8]>> = state
                .commands
                .iter()
                .map(|command| command.iter().map(Vec::as_slice).collect())
                .collect();
            let command_refs: Vec<&[&[u8]]> = arg_refs.iter().map(Vec::as_slice).collect();
            if let Err(error) = self.store.append_journal_commands_physical(&command_refs) {
                // Live changes remain hidden, but no longer have a durable
                // outcome. Fence traffic; restart recovers the prior state.
                self.store.poison_journal();
                self.closed = true;
                return Err(error);
            }
        }

        for ((table, pk), ()) in state.row_deltas {
            self.store.publish_row_delta(&table, &pk);
        }
        self.closed = true;
        Ok(ExecCommitEffects {
            key_events: state.key_events,
            list_wake_keys: state.list_wake_keys.into_keys().collect(),
        })
    }
}

impl Drop for ExecTransactionGuard<'_> {
    fn drop(&mut self) {
        if self.closed {
            return;
        }
        if let Ok(state) = self.store.take_active_exec() {
            if !state.commands.is_empty()
                || !state.row_deltas.is_empty()
                || !state.key_events.is_empty()
                || !state.list_wake_keys.is_empty()
            {
                self.store.poison_journal();
            }
        } else {
            self.store.poison_journal();
        }
    }
}

impl Store {
    fn transaction_id(&self) -> usize {
        self as *const Self as usize
    }

    pub(crate) fn execution_read_guard(&self) -> std::io::Result<ExecutionReadGuard<'_>> {
        self.ensure_journal_healthy()?;
        let guard = self.enter_execution_read();
        self.ensure_journal_healthy()?;
        Ok(guard)
    }

    /// Subscription APIs cannot return storage-health errors. They still join
    /// the isolation boundary, while data-bearing operations fail closed via
    /// `execution_read_guard` when the journal is poisoned.
    pub(crate) fn execution_barrier_guard(&self) -> ExecutionReadGuard<'_> {
        self.enter_execution_read()
    }

    pub(super) fn enter_execution_read(&self) -> ExecutionReadGuard<'_> {
        let store_id = self.transaction_id();
        if self.in_exec_transaction() {
            return ExecutionReadGuard {
                store_id,
                _guard: None,
                tracked: false,
            };
        }

        let nested = READ_DEPTHS.with(|depths| {
            let mut depths = depths.borrow_mut();
            if let Some(depth) = depths.get_mut(&store_id) {
                *depth += 1;
                true
            } else {
                false
            }
        });
        if nested {
            return ExecutionReadGuard {
                store_id,
                _guard: None,
                tracked: true,
            };
        }

        let guard = self.execution_gate.read();
        READ_DEPTHS.with(|depths| {
            depths.borrow_mut().insert(store_id, 1);
        });
        ExecutionReadGuard {
            store_id,
            _guard: Some(guard),
            tracked: true,
        }
    }

    pub(crate) fn begin_exec_transaction(&self) -> std::io::Result<ExecTransactionGuard<'_>> {
        self.ensure_journal_healthy()?;
        let store_id = self.transaction_id();
        let nested_read =
            READ_DEPTHS.with(|depths| depths.borrow().get(&store_id).copied().unwrap_or(0));
        if nested_read != 0 || self.in_exec_transaction() {
            return Err(std::io::Error::other(
                "cannot start EXEC from inside another execution boundary",
            ));
        }
        let guard = self.execution_gate.write();
        self.ensure_journal_healthy()?;
        ACTIVE.with(|active| {
            let mut active = active.borrow_mut();
            if active.is_some() {
                return Err(std::io::Error::other(
                    "another EXEC transaction is already active on this thread",
                ));
            }
            *active = Some(ActiveExec {
                store_id,
                commands: Vec::new(),
                row_deltas: BTreeMap::new(),
                key_events: Vec::new(),
                list_wake_keys: BTreeMap::new(),
            });
            Ok(ExecTransactionGuard {
                store: self,
                _guard: guard,
                closed: false,
            })
        })
    }

    pub(crate) fn in_exec_transaction(&self) -> bool {
        let store_id = self.transaction_id();
        ACTIVE.with(|active| {
            active
                .borrow()
                .as_ref()
                .is_some_and(|state| state.store_id == store_id)
        })
    }

    pub(crate) fn defer_exec_key_event(&self, args: &[&[u8]]) -> bool {
        self.with_active_exec(|state| {
            state
                .key_events
                .push(args.iter().map(|argument| argument.to_vec()).collect());
        })
    }

    pub(crate) fn defer_exec_list_wake(&self, key: &str) -> bool {
        self.with_active_exec(|state| {
            state.list_wake_keys.insert(key.to_string(), ());
        })
    }

    pub(super) fn defer_exec_row_delta(&self, table: &str, pk: &str) -> bool {
        self.with_active_exec(|state| {
            state
                .row_deltas
                .insert((table.to_string(), pk.to_string()), ());
        })
    }

    pub(super) fn buffer_exec_journal_commands(&self, commands: &[&[&[u8]]]) -> bool {
        self.with_active_exec(|state| {
            state.commands.extend(
                commands
                    .iter()
                    .map(|command| command.iter().map(|argument| argument.to_vec()).collect()),
            );
        })
    }

    pub(super) fn active_exec_command_len(&self) -> Option<usize> {
        let store_id = self.transaction_id();
        ACTIVE.with(|active| {
            active
                .borrow()
                .as_ref()
                .and_then(|state| (state.store_id == store_id).then_some(state.commands.len()))
        })
    }

    pub(super) fn truncate_active_exec(&self, checkpoint: usize) {
        self.with_active_exec(|state| state.commands.truncate(checkpoint));
    }

    fn with_active_exec(&self, operation: impl FnOnce(&mut ActiveExec)) -> bool {
        let store_id = self.transaction_id();
        ACTIVE.with(|active| {
            let mut active = active.borrow_mut();
            let Some(state) = active.as_mut() else {
                return false;
            };
            if state.store_id != store_id {
                return false;
            }
            operation(state);
            true
        })
    }

    fn take_active_exec(&self) -> std::io::Result<ActiveExec> {
        let store_id = self.transaction_id();
        ACTIVE.with(|active| {
            let mut active = active.borrow_mut();
            let state = active
                .take()
                .ok_or_else(|| std::io::Error::other("EXEC transaction state is not active"))?;
            if state.store_id != store_id {
                *active = Some(state);
                return Err(std::io::Error::other(
                    "EXEC transaction belongs to a different store",
                ));
            }
            Ok(state)
        })
    }

    #[cfg(test)]
    pub(crate) fn set_exec_after_command_hook(&self, hook: Option<ExecAfterCommandHook>) {
        *self.exec_after_command_hook.lock() = hook;
    }

    #[cfg(test)]
    pub(crate) fn exec_command_applied(&self, index: usize) {
        let hook = self.exec_after_command_hook.lock().clone();
        if let Some(hook) = hook {
            hook(index);
        }
    }

    #[cfg(not(test))]
    pub(crate) fn exec_command_applied(&self, _index: usize) {}
}
