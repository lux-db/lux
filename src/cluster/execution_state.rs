use super::durable_state::{read_bounded, write_json_atomic};
use super::execution::{CompiledExecution, SignedExecution};
use super::ClusterError;
use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const MAX_DURABLE_EXECUTION_STATE_BYTES: u64 = 128 * 1024 * 1024;

/// One immutable view of committed and prepared execution metadata.
///
/// Requests retain the current compiled bundle for their full lifetime. Control
/// operations replace this entire snapshot, so a reader cannot combine parts
/// from different execution versions.
#[derive(Debug)]
pub struct ExecutionSnapshot {
    current: Arc<CompiledExecution>,
    pending: Option<Arc<CompiledExecution>>,
}

impl ExecutionSnapshot {
    #[inline]
    #[must_use]
    pub fn current(&self) -> &CompiledExecution {
        &self.current
    }

    #[must_use]
    pub fn pending(&self) -> Option<&CompiledExecution> {
        self.pending.as_deref()
    }
}

/// Crash-safe execution-metadata prepare/commit state.
///
/// Mutations serialize behind one control-path lock. Owner-local requests only
/// perform an RCU-style atomic `Arc` load and never acquire this lock.
pub struct ExecutionState {
    published: ArcSwap<ExecutionSnapshot>,
    mutation: parking_lot::Mutex<()>,
    controller_public_key: String,
    state_path: Option<PathBuf>,
}

impl ExecutionState {
    #[must_use]
    pub fn in_memory(current: CompiledExecution, controller_public_key: String) -> Self {
        Self {
            published: ArcSwap::from_pointee(ExecutionSnapshot {
                current: Arc::new(current),
                pending: None,
            }),
            mutation: parking_lot::Mutex::new(()),
            controller_public_key,
            state_path: None,
        }
    }

    pub fn open(
        supplied: CompiledExecution,
        controller_public_key: String,
        state_path: impl AsRef<Path>,
    ) -> Result<Self, ClusterError> {
        let state_path = state_path.as_ref().to_path_buf();
        let (current, pending) = if state_path.exists() {
            let bytes = read_bounded(&state_path, MAX_DURABLE_EXECUTION_STATE_BYTES)?;
            if bytes.len() as u64 > MAX_DURABLE_EXECUTION_STATE_BYTES {
                return invalid("durable execution state exceeds the size limit");
            }
            let disk: ExecutionDiskState = serde_json::from_slice(&bytes).map_err(|error| {
                ClusterError::InvalidExecution(format!(
                    "failed to read durable execution state {}: {error}",
                    state_path.display()
                ))
            })?;
            let durable = disk.current.verify(&controller_public_key)?;
            if durable.manifest().cluster_id != supplied.manifest().cluster_id {
                return invalid("durable execution metadata belongs to another cluster");
            }
            if durable.manifest().version == supplied.manifest().version
                && durable.signed() != supplied.signed()
            {
                return invalid("same execution version has different signed contents");
            }
            let pending = disk
                .pending
                .map(|signed| signed.verify(&controller_public_key))
                .transpose()?;
            if let Some(candidate) = &pending {
                durable.transition_to(candidate)?;
            }
            (durable, pending)
        } else {
            (supplied, None)
        };
        let state = Self {
            published: ArcSwap::from_pointee(ExecutionSnapshot {
                current: Arc::new(current),
                pending: pending.map(Arc::new),
            }),
            mutation: parking_lot::Mutex::new(()),
            controller_public_key,
            state_path: Some(state_path),
        };
        let snapshot = state.snapshot();
        state.persist(snapshot.current(), snapshot.pending())?;
        Ok(state)
    }

    #[inline]
    #[must_use]
    pub fn snapshot(&self) -> Arc<ExecutionSnapshot> {
        self.published.load_full()
    }

    #[inline]
    #[must_use]
    pub fn current(&self) -> Arc<CompiledExecution> {
        Arc::clone(&self.snapshot().current)
    }

    #[must_use]
    pub fn pending(&self) -> Option<Arc<CompiledExecution>> {
        self.snapshot().pending.clone()
    }

    pub fn prepare(&self, signed: SignedExecution) -> Result<u64, ClusterError> {
        let candidate = Arc::new(signed.verify(&self.controller_public_key)?);
        let _guard = self.mutation.lock();
        let published = self.snapshot();
        if let Some(pending) = published.pending() {
            if pending.signed() == candidate.signed() {
                return Ok(candidate.manifest().version);
            }
            return invalid(format!(
                "execution version {} is already prepared; abort it before another",
                pending.manifest().version
            ));
        }
        published.current().transition_to(&candidate)?;
        let version = candidate.manifest().version;
        self.persist(published.current(), Some(&candidate))?;
        self.published.store(Arc::new(ExecutionSnapshot {
            current: Arc::clone(&published.current),
            pending: Some(candidate),
        }));
        Ok(version)
    }

    pub fn commit(&self, version: u64) -> Result<Arc<CompiledExecution>, ClusterError> {
        let _guard = self.mutation.lock();
        let published = self.snapshot();
        let pending = published.pending.as_ref().cloned().ok_or_else(|| {
            ClusterError::InvalidExecution("no execution metadata is prepared".to_owned())
        })?;
        if pending.manifest().version != version {
            return invalid(format!(
                "prepared execution version does not match commit version {version}"
            ));
        }
        self.persist(&pending, None)?;
        self.published.store(Arc::new(ExecutionSnapshot {
            current: Arc::clone(&pending),
            pending: None,
        }));
        Ok(pending)
    }

    pub fn abort(&self, version: u64) -> Result<bool, ClusterError> {
        let _guard = self.mutation.lock();
        let published = self.snapshot();
        let Some(pending) = published.pending() else {
            return Ok(false);
        };
        if pending.manifest().version != version {
            return Ok(false);
        }
        self.persist(published.current(), None)?;
        self.published.store(Arc::new(ExecutionSnapshot {
            current: Arc::clone(&published.current),
            pending: None,
        }));
        Ok(true)
    }

    fn persist(
        &self,
        current: &CompiledExecution,
        pending: Option<&CompiledExecution>,
    ) -> Result<(), ClusterError> {
        let Some(path) = &self.state_path else {
            return Ok(());
        };
        let disk = ExecutionDiskState {
            current: current.signed().clone(),
            pending: pending.map(|candidate| candidate.signed().clone()),
        };
        write_json_atomic(
            path,
            &disk,
            "execution",
            MAX_DURABLE_EXECUTION_STATE_BYTES as usize,
        )
    }
}

#[derive(Serialize, Deserialize)]
struct ExecutionDiskState {
    current: SignedExecution,
    pending: Option<SignedExecution>,
}

fn invalid<T>(message: impl Into<String>) -> Result<T, ClusterError> {
    Err(ClusterError::InvalidExecution(message.into()))
}
