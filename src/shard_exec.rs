use bytes::BytesMut;
use std::sync::Arc;
use std::time::Instant;

use crate::cmd::{self, PipelineAccess};
use crate::pubsub::Broker;
use crate::store::Store;
use crate::ArgvSlice;

pub(crate) struct ShardPipelineCommand<'argv, 'data> {
    pub(crate) args: &'argv [&'data [u8]],
    pub(crate) access: PipelineAccess,
}

#[derive(Debug)]
pub(crate) enum ShardExecutionError {
    Command(String),
    Eviction(&'static str),
    Wal(String),
}

impl std::fmt::Display for ShardExecutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Command(message) => f.write_str(message),
            Self::Eviction(message) => f.write_str(message),
            Self::Wal(message) => write!(f, "ERR WAL append failed: {message}"),
        }
    }
}

#[derive(Clone)]
pub(crate) struct ShardExecutor {
    store: Arc<Store>,
    broker: Broker,
}

impl ShardExecutor {
    pub(crate) fn new(store: Arc<Store>, broker: Broker) -> Self {
        Self { store, broker }
    }

    pub(crate) fn execute_pipeline_batch<'argv, 'data>(
        &self,
        shard_idx: usize,
        commands: &[ShardPipelineCommand<'argv, 'data>],
        out: &mut BytesMut,
        now: Instant,
    ) -> Result<(), ShardExecutionError> {
        if commands
            .iter()
            .any(|command| command.access == PipelineAccess::Write)
        {
            self.execute_write_batch(shard_idx, commands, out, now)
        } else {
            self.execute_read_batch(shard_idx, commands, out, now);
            Ok(())
        }
    }

    pub(crate) fn execute_argv_pipeline_batch<A: ArgvSlice>(
        &self,
        shard_idx: usize,
        commands: &[A],
        access: &[PipelineAccess],
        out: &mut BytesMut,
        now: Instant,
    ) -> Result<(), ShardExecutionError> {
        debug_assert_eq!(commands.len(), access.len());
        if access.contains(&PipelineAccess::Write) {
            self.execute_argv_write_batch(shard_idx, commands, access, out, now)
        } else {
            self.execute_argv_read_batch(shard_idx, commands, out, now);
            Ok(())
        }
    }

    pub(crate) fn apply_mset_batches<'data>(
        &self,
        pairs_by_shard: Vec<Vec<(&'data [u8], &'data [u8])>>,
        now: Instant,
    ) {
        for (shard_idx, pairs) in pairs_by_shard.into_iter().enumerate() {
            if pairs.is_empty() {
                continue;
            }
            let mut shard = self.store.lock_write_shard(shard_idx);
            shard.version += 1;
            for (key, value) in pairs {
                self.store
                    .set_on_shard(&mut shard.data, key, value, None, now);
            }
        }
    }

    fn execute_write_batch<'argv, 'data>(
        &self,
        shard_idx: usize,
        commands: &[ShardPipelineCommand<'argv, 'data>],
        out: &mut BytesMut,
        now: Instant,
    ) -> Result<(), ShardExecutionError> {
        let eviction_enabled = crate::eviction::eviction_enabled(&self.store);
        let tiered = self.store.is_tiered();
        let wal_enabled = self.store.wal_enabled();
        let mut wal_commands: Vec<&[&[u8]]> = Vec::new();
        let bare_set_batch = commands
            .iter()
            .all(|command| command.args.len() == 3 && command.args[0].eq_ignore_ascii_case(b"SET"));

        for command in commands {
            let args = command.args;
            if tiered {
                self.store.try_promote(args[1], now);
            }
            if bare_set_batch || crate::eviction::is_write_command(args[0]) {
                if !bare_set_batch {
                    if let Some(err) = crate::auth::reserved_table_mutation_error(args, &self.store)
                    {
                        return Err(ShardExecutionError::Command(err));
                    }
                }
                if eviction_enabled {
                    crate::eviction::evict_if_needed(&self.store)
                        .map_err(ShardExecutionError::Eviction)?;
                }
                if wal_enabled {
                    wal_commands.push(args);
                }
            }
        }

        if wal_enabled {
            self.store
                .wal_log_command_batch(&wal_commands)
                .map_err(|err| ShardExecutionError::Wal(err.to_string()))?;
        }
        {
            let mut shard = self.store.lock_write_shard(shard_idx);
            shard.version += 1;
            if bare_set_batch {
                out.reserve(commands.len() * crate::resp::OK.len());
                let mut stats = crate::store::StoreBatchStats::default();
                for command in commands {
                    self.store.set_on_shard_batched(
                        &mut shard.data,
                        command.args[1],
                        command.args[2],
                        &mut stats,
                    );
                    crate::resp::write_ok(out);
                }
                self.store.apply_batch_stats(stats);
            } else {
                for command in commands {
                    cmd::execute_on_shard(
                        &mut shard,
                        &self.store,
                        &self.broker,
                        command.args,
                        out,
                        now,
                    );
                }
            }
        }

        if self.broker.has_key_subs() {
            for command in commands {
                if command.access == PipelineAccess::Write {
                    self.broker
                        .enqueue_key_event(command.args[1], command.args[0]);
                }
            }
        }

        Ok(())
    }

    fn execute_argv_write_batch<A: ArgvSlice>(
        &self,
        shard_idx: usize,
        commands: &[A],
        access: &[PipelineAccess],
        out: &mut BytesMut,
        now: Instant,
    ) -> Result<(), ShardExecutionError> {
        let eviction_enabled = crate::eviction::eviction_enabled(&self.store);
        let tiered = self.store.is_tiered();
        let wal_enabled = self.store.wal_enabled();
        let mut wal_commands: Vec<&[&[u8]]> = Vec::new();
        let bare_set_batch = commands.iter().all(|command| {
            let args = command.argv();
            args.len() == 3 && args[0].eq_ignore_ascii_case(b"SET")
        });

        for command in commands {
            let args = command.argv();
            if tiered {
                self.store.try_promote(args[1], now);
            }
            if bare_set_batch || crate::eviction::is_write_command(args[0]) {
                if !bare_set_batch {
                    if let Some(err) = crate::auth::reserved_table_mutation_error(args, &self.store)
                    {
                        return Err(ShardExecutionError::Command(err));
                    }
                }
                if eviction_enabled {
                    crate::eviction::evict_if_needed(&self.store)
                        .map_err(ShardExecutionError::Eviction)?;
                }
                if wal_enabled {
                    wal_commands.push(args);
                }
            }
        }

        if wal_enabled {
            self.store
                .wal_log_command_batch(&wal_commands)
                .map_err(|err| ShardExecutionError::Wal(err.to_string()))?;
        }
        {
            let mut shard = self.store.lock_write_shard(shard_idx);
            shard.version += 1;
            if bare_set_batch {
                out.reserve(commands.len() * crate::resp::OK.len());
                let mut stats = crate::store::StoreBatchStats::default();
                for command in commands {
                    let args = command.argv();
                    self.store
                        .set_on_shard_batched(&mut shard.data, args[1], args[2], &mut stats);
                    crate::resp::write_ok(out);
                }
                self.store.apply_batch_stats(stats);
            } else {
                for command in commands {
                    cmd::execute_on_shard(
                        &mut shard,
                        &self.store,
                        &self.broker,
                        command.argv(),
                        out,
                        now,
                    );
                }
            }
        }

        if self.broker.has_key_subs() {
            for (command, access) in commands.iter().zip(access) {
                if *access == PipelineAccess::Write {
                    let args = command.argv();
                    self.broker.enqueue_key_event(args[1], args[0]);
                }
            }
        }

        Ok(())
    }

    fn execute_read_batch<'argv, 'data>(
        &self,
        shard_idx: usize,
        commands: &[ShardPipelineCommand<'argv, 'data>],
        out: &mut BytesMut,
        now: Instant,
    ) {
        if self.store.is_tiered() {
            for command in commands {
                self.store.try_promote(command.args[1], now);
            }
        }
        let shard = self.store.lock_read_shard(shard_idx);
        if commands
            .iter()
            .all(|command| command.args.len() == 2 && command.args[0].eq_ignore_ascii_case(b"GET"))
        {
            for command in commands {
                Store::get_and_write(&shard.data, command.args[1], now, out);
            }
        } else {
            for command in commands {
                cmd::execute_on_shard_read(&shard.data, command.args, out, now);
            }
        }
    }

    fn execute_argv_read_batch<A: ArgvSlice>(
        &self,
        shard_idx: usize,
        commands: &[A],
        out: &mut BytesMut,
        now: Instant,
    ) {
        if self.store.is_tiered() {
            for command in commands {
                self.store.try_promote(command.argv()[1], now);
            }
        }
        let shard = self.store.lock_read_shard(shard_idx);
        if commands.iter().all(|command| {
            let args = command.argv();
            args.len() == 2 && args[0].eq_ignore_ascii_case(b"GET")
        }) {
            for command in commands {
                Store::get_and_write(&shard.data, command.argv()[1], now, out);
            }
        } else {
            for command in commands {
                cmd::execute_on_shard_read(&shard.data, command.argv(), out, now);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn write_batch_preserves_command_order() {
        let store = Arc::new(Store::new());
        let broker = Broker::new();
        let executor = ShardExecutor::new(store.clone(), broker);
        let now = Instant::now();
        let shard_idx = store.shard_for_key(b"k");
        let set: [&[u8]; 3] = [b"SET", b"k", b"v"];
        let get: [&[u8]; 2] = [b"GET", b"k"];
        let commands = [
            ShardPipelineCommand {
                args: &set,
                access: PipelineAccess::Write,
            },
            ShardPipelineCommand {
                args: &get,
                access: PipelineAccess::Read,
            },
        ];
        let mut out = BytesMut::new();

        executor
            .execute_pipeline_batch(shard_idx, &commands, &mut out, now)
            .unwrap();

        assert_eq!(&out[..], b"+OK\r\n$1\r\nv\r\n");
    }

    #[test]
    fn read_batch_does_not_increment_shard_version() {
        let store = Arc::new(Store::new());
        let broker = Broker::new();
        let executor = ShardExecutor::new(store.clone(), broker);
        let now = Instant::now();
        let shard_idx = store.shard_for_key(b"missing");
        let before = store.shard_version(shard_idx);
        let get: [&[u8]; 2] = [b"GET", b"missing"];
        let commands = [ShardPipelineCommand {
            args: &get,
            access: PipelineAccess::Read,
        }];
        let mut out = BytesMut::new();

        executor
            .execute_pipeline_batch(shard_idx, &commands, &mut out, now)
            .unwrap();

        assert_eq!(before, store.shard_version(shard_idx));
        assert_eq!(&out[..], b"$-1\r\n");
    }

    #[test]
    fn write_batch_enqueues_key_events_once_per_write() {
        let store = Arc::new(Store::new());
        let broker = Broker::new();
        broker.ksubscribe("k");
        let executor = ShardExecutor::new(store.clone(), broker);
        let now = Instant::now();
        let shard_idx = store.shard_for_key(b"k");
        let set: [&[u8]; 3] = [b"SET", b"k", b"v"];
        let get: [&[u8]; 2] = [b"GET", b"k"];
        let commands = [
            ShardPipelineCommand {
                args: &set,
                access: PipelineAccess::Write,
            },
            ShardPipelineCommand {
                args: &get,
                access: PipelineAccess::Read,
            },
        ];
        let mut out = BytesMut::new();

        executor
            .execute_pipeline_batch(shard_idx, &commands, &mut out, now)
            .unwrap();

        let stats = executor.broker.key_event_stats();
        assert_eq!(stats.enqueued, 1);
    }

    #[test]
    fn bare_set_batch_updates_key_accounting_once_per_new_key() {
        let store = Arc::new(Store::new());
        let broker = Broker::new();
        let executor = ShardExecutor::new(store.clone(), broker);
        let now = Instant::now();
        let shard_idx = store.shard_for_key(b"k");
        let set_first: [&[u8]; 3] = [b"SET", b"k", b"v1"];
        let set_replace: [&[u8]; 3] = [b"SET", b"k", b"v2"];
        let commands = [
            ShardPipelineCommand {
                args: &set_first,
                access: PipelineAccess::Write,
            },
            ShardPipelineCommand {
                args: &set_replace,
                access: PipelineAccess::Write,
            },
        ];
        let mut out = BytesMut::new();

        executor
            .execute_pipeline_batch(shard_idx, &commands, &mut out, now)
            .unwrap();

        assert_eq!(&out[..], b"+OK\r\n+OK\r\n");
        assert_eq!(store.dbsize(now), 1);
        assert_eq!(store.get(b"k", now).unwrap().as_ref(), b"v2");
    }

    #[test]
    fn argv_bare_set_batch_updates_key_accounting_once_per_new_key() {
        let store = Arc::new(Store::new());
        let broker = Broker::new();
        let executor = ShardExecutor::new(store.clone(), broker);
        let now = Instant::now();
        let shard_idx = store.shard_for_key(b"k");
        let commands = vec![
            vec![b"SET".as_slice(), b"k".as_slice(), b"v1".as_slice()],
            vec![b"SET".as_slice(), b"k".as_slice(), b"v2".as_slice()],
        ];
        let access = vec![PipelineAccess::Write, PipelineAccess::Write];
        let mut out = BytesMut::new();

        executor
            .execute_argv_pipeline_batch(shard_idx, &commands, &access, &mut out, now)
            .unwrap();

        assert_eq!(&out[..], b"+OK\r\n+OK\r\n");
        assert_eq!(store.dbsize(now), 1);
        assert_eq!(store.get(b"k", now).unwrap().as_ref(), b"v2");
    }

    #[test]
    fn mset_batches_apply_to_target_shards() {
        let store = Arc::new(Store::new());
        let broker = Broker::new();
        let executor = ShardExecutor::new(store.clone(), broker);
        let now = Instant::now();
        let mut pairs_by_shard = vec![Vec::new(); store.shard_count()];
        for (key, value) in [(b"a".as_slice(), b"one".as_slice()), (b"b", b"two")] {
            let idx = store.shard_for_key(key);
            pairs_by_shard[idx].push((key, value));
        }

        executor.apply_mset_batches(pairs_by_shard, now);

        for (key, expected) in [(b"a".as_slice(), b"one".as_slice()), (b"b", b"two")] {
            let idx = store.shard_for_key(key);
            let shard = store.lock_read_shard(idx);
            let actual = Store::get_from_shard(&shard.data, key, now).unwrap();
            assert_eq!(actual.as_ref(), expected);
        }
    }
}
