use super::topology::{CompiledTopology, NodeDescriptor, SignedTopology, TopologyTransitionPlan};
use super::ClusterError;
use arc_swap::ArcSwap;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand_core::{OsRng as SystemRandom, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// One immutable, internally consistent view of committed and prepared topology.
///
/// Owner-local request routing should retain this snapshot for the duration of
/// one operation and route through `current`. A prepare, commit, or abort swaps
/// the entire view atomically, so readers cannot combine different generations.
#[derive(Debug)]
pub struct TopologySnapshot {
    current: Arc<CompiledTopology>,
    pending: Option<Arc<CompiledTopology>>,
}

impl TopologySnapshot {
    #[inline]
    #[must_use]
    pub fn current(&self) -> &CompiledTopology {
        &self.current
    }

    #[must_use]
    pub fn pending(&self) -> Option<&CompiledTopology> {
        self.pending.as_deref()
    }
}

/// Crash-safe topology prepare/commit state with lock-free request snapshots.
///
/// Mutation paths serialize behind `mutation`; owner-local request routing only
/// calls `snapshot`, which is an RCU-style atomic `Arc` load.
pub struct TopologyState {
    published: ArcSwap<TopologySnapshot>,
    mutation: parking_lot::Mutex<()>,
    controller_public_key: String,
    state_path: Option<PathBuf>,
}

impl TopologyState {
    #[must_use]
    pub fn in_memory(current: CompiledTopology, controller_public_key: String) -> Self {
        Self {
            published: ArcSwap::from_pointee(TopologySnapshot {
                current: Arc::new(current),
                pending: None,
            }),
            mutation: parking_lot::Mutex::new(()),
            controller_public_key,
            state_path: None,
        }
    }

    pub fn open(
        supplied: CompiledTopology,
        controller_public_key: String,
        state_path: impl AsRef<Path>,
    ) -> Result<Self, ClusterError> {
        let state_path = state_path.as_ref().to_path_buf();
        let (current, pending) = if state_path.exists() {
            let bytes = std::fs::read(&state_path)?;
            let disk: TopologyDiskState = serde_json::from_slice(&bytes).map_err(|error| {
                ClusterError::InvalidTopology(format!(
                    "failed to read durable topology state {}: {error}",
                    state_path.display()
                ))
            })?;
            let durable = disk.current.verify(&controller_public_key)?;
            if durable.manifest().cluster_id != supplied.manifest().cluster_id {
                return invalid("durable topology belongs to another cluster");
            }
            if durable.manifest().epoch == supplied.manifest().epoch
                && durable.signed() != supplied.signed()
            {
                return invalid("same topology epoch has different signed contents");
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
            published: ArcSwap::from_pointee(TopologySnapshot {
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
    pub fn snapshot(&self) -> Arc<TopologySnapshot> {
        self.published.load_full()
    }

    #[inline]
    #[must_use]
    pub fn current(&self) -> Arc<CompiledTopology> {
        Arc::clone(&self.snapshot().current)
    }

    #[must_use]
    pub fn pending(&self) -> Option<Arc<CompiledTopology>> {
        self.snapshot().pending.clone()
    }

    #[must_use]
    pub fn trusted_nodes(&self) -> Vec<NodeDescriptor> {
        let snapshot = self.snapshot();
        let mut seen = HashSet::new();
        snapshot
            .current()
            .manifest()
            .nodes
            .iter()
            .chain(
                snapshot
                    .pending()
                    .iter()
                    .flat_map(|candidate| candidate.manifest().nodes.iter()),
            )
            .filter(|node| seen.insert((*node).clone()))
            .cloned()
            .collect()
    }

    pub fn transition_plan(&self) -> Result<Option<TopologyTransitionPlan>, ClusterError> {
        let snapshot = self.snapshot();
        snapshot
            .pending()
            .map(|candidate| snapshot.current().transition_to(candidate))
            .transpose()
    }

    pub fn prepare(&self, signed: SignedTopology) -> Result<u64, ClusterError> {
        let candidate = Arc::new(signed.verify(&self.controller_public_key)?);
        let _guard = self.mutation.lock();
        let published = self.snapshot();
        if let Some(pending) = published.pending() {
            if pending.signed() == candidate.signed() {
                return Ok(candidate.manifest().epoch);
            }
            return invalid(format!(
                "topology epoch {} is already prepared; abort it before another",
                pending.manifest().epoch
            ));
        }
        published.current().transition_to(&candidate)?;
        let epoch = candidate.manifest().epoch;
        self.persist(published.current(), Some(&candidate))?;
        self.published.store(Arc::new(TopologySnapshot {
            current: Arc::clone(&published.current),
            pending: Some(candidate),
        }));
        Ok(epoch)
    }

    pub fn commit(&self, epoch: u64) -> Result<Arc<CompiledTopology>, ClusterError> {
        let _guard = self.mutation.lock();
        let published = self.snapshot();
        let pending =
            published.pending.as_ref().cloned().ok_or_else(|| {
                ClusterError::InvalidTopology("no topology is prepared".to_owned())
            })?;
        if pending.manifest().epoch != epoch {
            return invalid(format!(
                "prepared topology epoch does not match commit epoch {epoch}"
            ));
        }
        self.persist(&pending, None)?;
        self.published.store(Arc::new(TopologySnapshot {
            current: Arc::clone(&pending),
            pending: None,
        }));
        Ok(pending)
    }

    pub fn abort(&self, epoch: u64) -> Result<bool, ClusterError> {
        let _guard = self.mutation.lock();
        let published = self.snapshot();
        let Some(pending) = published.pending() else {
            return Ok(false);
        };
        if pending.manifest().epoch != epoch {
            return Ok(false);
        }
        self.persist(published.current(), None)?;
        self.published.store(Arc::new(TopologySnapshot {
            current: Arc::clone(&published.current),
            pending: None,
        }));
        Ok(true)
    }

    fn persist(
        &self,
        current: &CompiledTopology,
        pending: Option<&CompiledTopology>,
    ) -> Result<(), ClusterError> {
        let Some(path) = &self.state_path else {
            return Ok(());
        };
        if let Some(parent) = state_parent(path) {
            std::fs::create_dir_all(parent)?;
        }
        let disk = TopologyDiskState {
            current: current.signed().clone(),
            pending: pending.map(|candidate| candidate.signed().clone()),
        };
        let bytes = serde_json::to_vec_pretty(&disk)?;
        let mut nonce = [0_u8; 16];
        SystemRandom.try_fill_bytes(&mut nonce).map_err(|error| {
            std::io::Error::other(format!("failed to create topology state nonce: {error}"))
        })?;
        let nonce = URL_SAFE_NO_PAD.encode(nonce);
        let temporary = path.with_extension(format!("tmp-{}-{nonce}", std::process::id()));
        let result = (|| -> Result<(), ClusterError> {
            let mut file = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            std::fs::rename(&temporary, path)?;
            if let Some(parent) = state_parent(path) {
                std::fs::File::open(parent)?.sync_all()?;
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
    }
}

fn state_parent(path: &Path) -> Option<&Path> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
}

#[derive(Serialize, Deserialize)]
struct TopologyDiskState {
    current: SignedTopology,
    pending: Option<SignedTopology>,
}

fn invalid<T>(message: impl Into<String>) -> Result<T, ClusterError> {
    Err(ClusterError::InvalidTopology(message.into()))
}
