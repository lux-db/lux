use super::{ClusterError, CompiledExecution, CompiledTopology, NodeDescriptor};
use arc_swap::ArcSwap;
use std::cmp::Ordering;
use std::sync::Arc;

/// The complete immutable state retained by one owner-local request.
///
/// Topology and execution metadata share one atomic publication boundary. A
/// request can therefore never route with one generation while authorizing or
/// decoding with a separately loaded generation.
#[derive(Debug)]
pub struct ServingSnapshot {
    topology: Arc<CompiledTopology>,
    execution: Arc<CompiledExecution>,
}

impl ServingSnapshot {
    #[inline]
    #[must_use]
    pub fn topology(&self) -> &CompiledTopology {
        &self.topology
    }

    #[inline]
    #[must_use]
    pub fn execution(&self) -> &CompiledExecution {
        &self.execution
    }

    #[inline]
    #[must_use]
    pub fn owner_for_key(&self, key: &[u8]) -> &NodeDescriptor {
        self.topology.owner_for_key(key)
    }

    #[inline]
    #[must_use]
    pub fn owner_for_table_row(&self, table: &[u8], primary_key: &[u8]) -> &NodeDescriptor {
        self.topology.owner_for_table_row(table, primary_key)
    }
}

/// RCU publication point for the request dataplane.
///
/// Control-path publishers serialize transitions. Requests perform exactly one
/// atomic `Arc` load and then use only that immutable snapshot.
pub struct ServingState {
    published: ArcSwap<ServingSnapshot>,
    mutation: parking_lot::Mutex<()>,
}

impl ServingState {
    pub fn new(
        topology: Arc<CompiledTopology>,
        execution: Arc<CompiledExecution>,
    ) -> Result<Self, ClusterError> {
        validate_cluster(&topology, &execution)?;
        Ok(Self {
            published: ArcSwap::from_pointee(ServingSnapshot {
                topology,
                execution,
            }),
            mutation: parking_lot::Mutex::new(()),
        })
    }

    #[inline]
    #[must_use]
    pub fn snapshot(&self) -> Arc<ServingSnapshot> {
        self.published.load_full()
    }

    /// Atomically publish already verified, durably committed components.
    ///
    /// Each component may remain unchanged or advance by exactly one valid
    /// transition. Publishing the current pair is idempotent; rollback, skips,
    /// and same-version content changes are rejected.
    pub fn publish(
        &self,
        topology: Arc<CompiledTopology>,
        execution: Arc<CompiledExecution>,
    ) -> Result<Arc<ServingSnapshot>, ClusterError> {
        validate_cluster(&topology, &execution)?;
        let _guard = self.mutation.lock();
        let current = self.snapshot();
        if topology.manifest().cluster_id != current.topology().manifest().cluster_id {
            return execution_invalid("serving state belongs to another cluster");
        }

        match topology
            .manifest()
            .epoch
            .cmp(&current.topology().manifest().epoch)
        {
            Ordering::Less => return topology_invalid("serving topology cannot roll back"),
            Ordering::Equal if topology.signed() != current.topology().signed() => {
                return topology_invalid("same serving topology epoch has different contents")
            }
            Ordering::Greater => {
                current.topology().transition_to(&topology)?;
            }
            Ordering::Equal => {}
        }

        match execution
            .manifest()
            .version
            .cmp(&current.execution().manifest().version)
        {
            Ordering::Less => return execution_invalid("serving execution cannot roll back"),
            Ordering::Equal if execution.signed() != current.execution().signed() => {
                return execution_invalid("same serving execution version has different contents")
            }
            Ordering::Greater => {
                current.execution().transition_to(&execution)?;
            }
            Ordering::Equal => {}
        }

        if Arc::ptr_eq(&topology, &current.topology) && Arc::ptr_eq(&execution, &current.execution)
        {
            return Ok(current);
        }
        let next = Arc::new(ServingSnapshot {
            topology,
            execution,
        });
        self.published.store(Arc::clone(&next));
        Ok(next)
    }
}

fn validate_cluster(
    topology: &CompiledTopology,
    execution: &CompiledExecution,
) -> Result<(), ClusterError> {
    if topology.manifest().cluster_id != execution.manifest().cluster_id {
        return execution_invalid("topology and execution metadata name different clusters");
    }
    Ok(())
}

fn topology_invalid<T>(message: impl Into<String>) -> Result<T, ClusterError> {
    Err(ClusterError::InvalidTopology(message.into()))
}

fn execution_invalid<T>(message: impl Into<String>) -> Result<T, ClusterError> {
    Err(ClusterError::InvalidExecution(message.into()))
}

#[cfg(test)]
#[path = "serving_state_tests.rs"]
mod tests;
