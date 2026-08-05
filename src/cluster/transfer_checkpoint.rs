use super::durable_state::{read_bounded, write_json_atomic};
use super::transfer_coordinator::apply_target_store_records;
use super::{
    ClusterError, CompiledExecution, TransferDescriptor, TransferId, TransferJournal,
    TransferReceipt,
};
use crate::disk::WalBoundary;
use crate::pubsub::Broker;
use crate::store::{DumpValue, Store};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Instant;

const TARGET_CHECKPOINT_SCHEMA_VERSION: u16 = 1;
const MAX_TARGET_CHECKPOINT_BYTES: u64 = 256 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CheckpointPhase {
    Armed,
    Ready,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CheckpointDiskState {
    schema_version: u16,
    descriptor: TransferDescriptor,
    execution_version: u64,
    execution_digest: String,
    receipt: TransferReceipt,
    wal_boundaries: Vec<WalBoundary>,
    phase: CheckpointPhase,
    proof: [u8; 32],
}

/// Capability returned only after a target checkpoint has a reproducible WAL
/// cutover, a matching in-Store marker, and durable checkpoint state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetReadyProof {
    transfer_id: TransferId,
    token: [u8; 32],
}

impl TargetReadyProof {
    pub(super) fn validate_transfer(&self, transfer_id: TransferId) -> Result<(), ClusterError> {
        if self.transfer_id != transfer_id {
            return invalid("target readiness proof belongs to another transfer");
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn for_test(transfer_id: TransferId) -> Self {
        Self {
            transfer_id,
            token: [0x5a; 32],
        }
    }
}

/// Durable target-side ownership cutover state.
///
/// The sealed transfer remains immutable. `prepare` fsyncs every WAL and stores
/// exact per-shard boundaries before data application. Recovery replays all WAL
/// prefixes, installs the sealed transfer, then replays all suffixes. A marker
/// embedded in normal snapshots proves that a later snapshot already includes
/// the transfer and makes old boundaries unnecessary after WAL truncation.
pub struct TargetCheckpoint {
    path: PathBuf,
    state: parking_lot::Mutex<CheckpointDiskState>,
}

impl TargetCheckpoint {
    pub fn prepare(
        store: &Store,
        target: &TransferJournal,
        descriptor: &TransferDescriptor,
        execution: &CompiledExecution,
        receipt: &TransferReceipt,
        path: impl AsRef<Path>,
    ) -> Result<Self, ClusterError> {
        target.prepare_target_apply(descriptor, receipt)?;
        validate_execution(descriptor, execution)?;
        let path = path.as_ref().to_path_buf();
        if path.exists() {
            return invalid("target checkpoint already exists; reopen it instead");
        }

        // Keep Lua atomicity and persistence ordering aligned: normal command
        // paths acquire the script gate before a mutation lease, so ownership
        // cutovers take the same order before closing mutation admission.
        let _script = store.script_write_guard();
        let disk = store
            .with_persistence_cutover(|| {
                let wal_boundaries = store.durable_wal_boundaries()?;
                let mut disk = CheckpointDiskState {
                    schema_version: TARGET_CHECKPOINT_SCHEMA_VERSION,
                    descriptor: descriptor.clone(),
                    execution_version: execution.manifest().version,
                    execution_digest: execution.digest().to_owned(),
                    receipt: receipt.clone(),
                    wal_boundaries,
                    phase: CheckpointPhase::Armed,
                    proof: [0; 32],
                };
                disk.proof = checkpoint_proof(&disk);
                persist(&path, &disk)?;
                Ok::<_, ClusterError>(disk)
            })
            .map_err(cutover_error)??;
        Ok(Self {
            path,
            state: parking_lot::Mutex::new(disk),
        })
    }

    pub fn open(
        descriptor: &TransferDescriptor,
        execution: &CompiledExecution,
        receipt: &TransferReceipt,
        path: impl AsRef<Path>,
    ) -> Result<Self, ClusterError> {
        let path = path.as_ref().to_path_buf();
        let bytes = read_bounded(&path, MAX_TARGET_CHECKPOINT_BYTES)?;
        if bytes.len() as u64 > MAX_TARGET_CHECKPOINT_BYTES {
            return invalid("durable target checkpoint exceeds the size limit");
        }
        let disk: CheckpointDiskState = serde_json::from_slice(&bytes).map_err(|error| {
            ClusterError::InvalidTransfer(format!(
                "failed to read durable target checkpoint {}: {error}",
                path.display()
            ))
        })?;
        validate_disk_state(&disk, descriptor, execution, receipt)?;
        Ok(Self {
            path,
            state: parking_lot::Mutex::new(disk),
        })
    }

    pub fn apply(
        &self,
        store: &Store,
        target: &TransferJournal,
        execution: &CompiledExecution,
    ) -> Result<TargetReadyProof, ClusterError> {
        let _script = store.script_write_guard();
        store
            .with_persistence_cutover(|| {
                let disk = self.validated_state(target, execution)?;
                self.install_marker_and_data(store, target, execution, &disk)?;
                self.commit_ready(target, &disk)
            })
            .map_err(cutover_error)?
    }

    /// Recover after the ordinary snapshot has loaded but before the engine is
    /// allowed to serve requests.
    pub fn recover_after_snapshot(
        &self,
        store: &Store,
        target: &TransferJournal,
        execution: &CompiledExecution,
    ) -> Result<TargetReadyProof, ClusterError> {
        // Startup invokes recovery before listeners or background writers exist.
        // Do not retain the script gate while replaying commands: a durable Lua
        // operation may legitimately acquire that gate itself.
        let disk = self.validated_state(target, execution)?;
        let broker = Broker::new();
        match marker_state(store, &disk)? {
            MarkerState::Matching => {
                if disk.phase != CheckpointPhase::Ready {
                    return invalid("snapshot contains an uncommitted target checkpoint marker");
                }
                store.replay_wal_strict(&broker)?;
            }
            MarkerState::Missing => {
                store.replay_wal_at_boundaries(&broker, &disk.wal_boundaries, || {
                    self.install_marker_and_data(store, target, execution, &disk)
                })?;
            }
        }
        self.commit_ready(target, &disk)
    }

    fn validated_state(
        &self,
        target: &TransferJournal,
        execution: &CompiledExecution,
    ) -> Result<CheckpointDiskState, ClusterError> {
        let disk = self.state.lock().clone();
        validate_disk_state(&disk, &disk.descriptor, execution, &disk.receipt)?;
        let snapshot = target.snapshot();
        if snapshot.descriptor != disk.descriptor || checkpoint_receipt(&snapshot) != disk.receipt {
            return invalid("target journal no longer matches its durable checkpoint");
        }
        Ok(disk)
    }

    fn install_marker_and_data(
        &self,
        store: &Store,
        target: &TransferJournal,
        execution: &CompiledExecution,
        disk: &CheckpointDiskState,
    ) -> Result<(), ClusterError> {
        if marker_state(store, disk)? == MarkerState::Matching {
            return Ok(());
        }
        let proof = ready_proof(disk);
        store.clear_transfer_ranges(&disk.descriptor, execution)?;
        apply_target_store_records(
            store,
            &disk.descriptor,
            execution,
            target.open_target_checkpoint_reader(&proof)?,
        )?;
        target.mark_target_applied_from_checkpoint(&disk.receipt, &proof)?;
        store.load_entry_bytes(
            marker_key(disk.descriptor.transfer_id),
            DumpValue::Str(marker_value(disk.proof)),
            None,
        );
        Ok(())
    }

    fn commit_ready(
        &self,
        target: &TransferJournal,
        original: &CheckpointDiskState,
    ) -> Result<TargetReadyProof, ClusterError> {
        let proof = ready_proof(original);
        let mut state = self.state.lock();
        if state.phase == CheckpointPhase::Armed {
            let mut next = state.clone();
            next.phase = CheckpointPhase::Ready;
            persist(&self.path, &next)?;
            *state = next;
        }
        target.mark_target_ready(&state.receipt, &proof)?;
        Ok(proof)
    }
}

fn cutover_error(error: &'static str) -> ClusterError {
    ClusterError::InvalidTransfer(format!("ownership checkpoint rejected: {error}"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MarkerState {
    Missing,
    Matching,
}

fn marker_state(store: &Store, disk: &CheckpointDiskState) -> Result<MarkerState, ClusterError> {
    match store.get(&marker_key(disk.descriptor.transfer_id), Instant::now()) {
        None => Ok(MarkerState::Missing),
        Some(value) if value.as_ref() == marker_value(disk.proof) => Ok(MarkerState::Matching),
        Some(_) => invalid("target checkpoint marker conflicts with durable proof"),
    }
}

fn marker_key(transfer_id: TransferId) -> Vec<u8> {
    let mut key = b"_t:_cp:".to_vec();
    for byte in transfer_id.0 {
        key.extend_from_slice(format!("{byte:02x}").as_bytes());
    }
    key
}

fn marker_value(proof: [u8; 32]) -> Vec<u8> {
    let mut value = Vec::with_capacity(64);
    for byte in proof {
        value.extend_from_slice(format!("{byte:02x}").as_bytes());
    }
    value
}

fn checkpoint_receipt(snapshot: &super::TransferJournalSnapshot) -> TransferReceipt {
    TransferReceipt {
        transfer_id: snapshot.descriptor.transfer_id,
        attempt: snapshot.attempt,
        next_sequence: snapshot.next_sequence,
        last_round: snapshot.last_round,
        last_digest: snapshot.last_digest,
        staged_bytes: snapshot.staged_bytes,
    }
}

fn ready_proof(disk: &CheckpointDiskState) -> TargetReadyProof {
    TargetReadyProof {
        transfer_id: disk.descriptor.transfer_id,
        token: disk.proof,
    }
}

fn checkpoint_proof(disk: &CheckpointDiskState) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"LUX-TARGET-CHECKPOINT\0");
    digest.update(disk.schema_version.to_be_bytes());
    digest.update(disk.descriptor.transfer_id.0);
    digest.update(disk.execution_version.to_be_bytes());
    digest.update((disk.execution_digest.len() as u64).to_be_bytes());
    digest.update(disk.execution_digest.as_bytes());
    digest.update(disk.receipt.attempt.to_be_bytes());
    digest.update(disk.receipt.next_sequence.to_be_bytes());
    digest.update(disk.receipt.last_round.to_be_bytes());
    match disk.receipt.last_digest {
        Some(last) => {
            digest.update([1]);
            digest.update(last);
        }
        None => digest.update([0]),
    }
    digest.update(disk.receipt.staged_bytes.to_be_bytes());
    digest.update((disk.wal_boundaries.len() as u64).to_be_bytes());
    for boundary in &disk.wal_boundaries {
        digest.update(boundary.generation);
        digest.update(boundary.offset.to_be_bytes());
    }
    digest.finalize().into()
}

fn validate_disk_state(
    disk: &CheckpointDiskState,
    descriptor: &TransferDescriptor,
    execution: &CompiledExecution,
    receipt: &TransferReceipt,
) -> Result<(), ClusterError> {
    descriptor.validate()?;
    validate_execution(descriptor, execution)?;
    if disk.schema_version != TARGET_CHECKPOINT_SCHEMA_VERSION
        || disk.descriptor != *descriptor
        || disk.execution_version != execution.manifest().version
        || disk.execution_digest != execution.digest()
        || disk.receipt != *receipt
        || disk.wal_boundaries.is_empty()
        || disk.proof != checkpoint_proof(disk)
    {
        return invalid("durable target checkpoint does not match its recovery context");
    }
    Ok(())
}

fn validate_execution(
    descriptor: &TransferDescriptor,
    execution: &CompiledExecution,
) -> Result<(), ClusterError> {
    if execution.manifest().cluster_id != descriptor.cluster_id {
        return invalid("target checkpoint execution belongs to another cluster");
    }
    Ok(())
}

fn persist(path: &Path, disk: &CheckpointDiskState) -> Result<(), ClusterError> {
    write_json_atomic(
        path,
        disk,
        "target checkpoint",
        MAX_TARGET_CHECKPOINT_BYTES as usize,
    )
}

fn invalid<T>(message: impl Into<String>) -> Result<T, ClusterError> {
    Err(ClusterError::InvalidTransfer(message.into()))
}

#[cfg(test)]
#[path = "transfer_checkpoint_tests.rs"]
mod tests;
