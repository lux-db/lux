use super::durable_state::{read_bounded, write_json_atomic};
use super::transfer::{
    ChunkDisposition, TransferChunk, TransferDescriptor, TransferId, TransferJournalSnapshot,
    TransferPhase, TransferReceipt, TransferRole, TRANSFER_SCHEMA_VERSION,
};
use super::transfer_stage::{stage_header, validate_stage_contents, STAGE_HEADER_BYTES};
use super::ClusterError;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

const MAX_TRANSFER_JOURNAL_BYTES: u64 = 128 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TransferDiskState {
    schema_version: u16,
    snapshot: TransferJournalSnapshot,
}

pub struct TransferJournal {
    journal_path: PathBuf,
    stage_path: PathBuf,
    max_staged_bytes: u64,
    inner: parking_lot::Mutex<TransferDiskState>,
    source_restart_required: AtomicBool,
}

impl TransferJournal {
    pub fn open(
        role: TransferRole,
        descriptor: TransferDescriptor,
        journal_path: impl AsRef<Path>,
        max_staged_bytes: u64,
    ) -> Result<Self, ClusterError> {
        descriptor.validate()?;
        if max_staged_bytes <= STAGE_HEADER_BYTES {
            return transfer_invalid("configured staged-byte limit is too small");
        }
        let journal_path = journal_path.as_ref().to_path_buf();
        let stage_path = journal_path.with_extension("stage");
        let journal_existed = journal_path.exists();
        let state = if journal_existed {
            let bytes = read_bounded(&journal_path, MAX_TRANSFER_JOURNAL_BYTES)?;
            if bytes.len() as u64 > MAX_TRANSFER_JOURNAL_BYTES {
                return transfer_invalid("durable journal exceeds its size limit");
            }
            let state: TransferDiskState = serde_json::from_slice(&bytes).map_err(|error| {
                ClusterError::InvalidTransfer(format!(
                    "failed to read durable journal {}: {error}",
                    journal_path.display()
                ))
            })?;
            validate_disk_state(&state, role, &descriptor)?;
            state
        } else {
            TransferDiskState {
                schema_version: TRANSFER_SCHEMA_VERSION,
                snapshot: TransferJournalSnapshot {
                    descriptor,
                    role,
                    phase: TransferPhase::Prepared,
                    attempt: 0,
                    next_sequence: 0,
                    last_round: 0,
                    last_digest: None,
                    staged_bytes: if role == TransferRole::Target {
                        STAGE_HEADER_BYTES
                    } else {
                        0
                    },
                },
            }
        };
        let source_restart_required = journal_existed
            && role == TransferRole::Source
            && state.snapshot.phase == TransferPhase::Copying
            && state.snapshot.staged_bytes >= STAGE_HEADER_BYTES;
        let journal = Self {
            journal_path,
            stage_path,
            max_staged_bytes,
            inner: parking_lot::Mutex::new(state),
            source_restart_required: AtomicBool::new(source_restart_required),
        };
        let state = journal.inner.lock().clone();
        if !journal.journal_path.exists() {
            journal.persist(&state)?;
        }
        if state.snapshot.staged_bytes > max_staged_bytes {
            return transfer_invalid("durable progress exceeds the configured staged-byte limit");
        }
        if role == TransferRole::Target {
            journal.reconcile_stage(&state.snapshot)?;
            validate_stage_contents(&journal.stage_path, &state.snapshot)?;
        }
        Ok(journal)
    }

    #[must_use]
    pub fn snapshot(&self) -> TransferJournalSnapshot {
        self.inner.lock().snapshot.clone()
    }

    #[must_use]
    pub fn source_requires_restart(&self) -> bool {
        self.source_restart_required.load(Ordering::Acquire)
    }

    pub fn begin_source_attempt(&self) -> Result<u32, ClusterError> {
        let attempt = self.mutate(|snapshot| {
            require_role(snapshot, TransferRole::Source)?;
            if !matches!(
                snapshot.phase,
                TransferPhase::Prepared | TransferPhase::Copying
            ) {
                return transfer_invalid("source attempt cannot restart in this phase");
            }
            snapshot.attempt = snapshot
                .attempt
                .checked_add(1)
                .ok_or_else(|| ClusterError::InvalidTransfer("attempt is exhausted".to_owned()))?;
            snapshot.phase = TransferPhase::Copying;
            reset_progress(snapshot);
            Ok(snapshot.attempt)
        })?;
        self.source_restart_required.store(false, Ordering::Release);
        Ok(attempt)
    }

    pub fn accept_target_attempt(&self, attempt: u32) -> Result<TransferReceipt, ClusterError> {
        if attempt == 0 {
            return transfer_invalid("target attempt must be nonzero");
        }
        let mut state = self.inner.lock();
        require_role(&state.snapshot, TransferRole::Target)?;
        if attempt == state.snapshot.attempt {
            self.reconcile_stage(&state.snapshot)?;
            return Ok(receipt(&state.snapshot));
        }
        if attempt != state.snapshot.attempt.checked_add(1).unwrap_or(0)
            || !matches!(
                state.snapshot.phase,
                TransferPhase::Prepared | TransferPhase::Copying
            )
        {
            return transfer_invalid("target attempt is out of order or no longer restartable");
        }
        let mut next = state.clone();
        next.snapshot.attempt = attempt;
        next.snapshot.phase = TransferPhase::Copying;
        reset_progress(&mut next.snapshot);
        next.snapshot.staged_bytes = STAGE_HEADER_BYTES;
        self.persist(&next)?;
        *state = next;
        self.replace_stage_with_header(&state.snapshot.descriptor.transfer_id)?;
        Ok(receipt(&state.snapshot))
    }

    pub fn next_source_chunk(
        &self,
        round: u32,
        payload: Vec<u8>,
    ) -> Result<TransferChunk, ClusterError> {
        self.require_source_resumable()?;
        let state = self.inner.lock();
        require_role(&state.snapshot, TransferRole::Source)?;
        if state.snapshot.phase != TransferPhase::Copying
            || state.snapshot.attempt == 0
            || state.snapshot.staged_bytes < STAGE_HEADER_BYTES
        {
            return transfer_invalid("source is not accepting transfer chunks");
        }
        if round < state.snapshot.last_round {
            return transfer_invalid("source chunk round cannot move backward");
        }
        TransferChunk::new(
            state.snapshot.descriptor.transfer_id,
            state.snapshot.attempt,
            state.snapshot.next_sequence,
            round,
            state.snapshot.last_digest,
            payload,
        )
    }

    pub fn record_target_start(&self, target: &TransferReceipt) -> Result<(), ClusterError> {
        self.require_source_resumable()?;
        self.mutate(|snapshot| {
            require_role(snapshot, TransferRole::Source)?;
            validate_receipt_identity(snapshot, target)?;
            if snapshot.phase != TransferPhase::Copying
                || snapshot.next_sequence != 0
                || snapshot.last_digest.is_some()
                || target.next_sequence != 0
                || target.last_round != 0
                || target.last_digest.is_some()
                || target.staged_bytes != STAGE_HEADER_BYTES
            {
                return transfer_invalid("target start receipt is inconsistent");
            }
            snapshot.staged_bytes = STAGE_HEADER_BYTES;
            Ok(())
        })
    }

    pub fn append_target_chunk(
        &self,
        chunk: &TransferChunk,
    ) -> Result<(ChunkDisposition, TransferReceipt), ClusterError> {
        chunk.verify()?;
        let mut state = self.inner.lock();
        let snapshot = &state.snapshot;
        require_role(snapshot, TransferRole::Target)?;
        if snapshot.phase != TransferPhase::Copying {
            return transfer_invalid("target is not accepting transfer chunks");
        }
        self.reconcile_stage(snapshot)?;
        if chunk.transfer_id != snapshot.descriptor.transfer_id || chunk.attempt != snapshot.attempt
        {
            return transfer_invalid("chunk belongs to another transfer attempt");
        }
        if chunk.sequence < snapshot.next_sequence {
            if chunk.sequence.checked_add(1) == Some(snapshot.next_sequence)
                && snapshot.last_digest == Some(chunk.digest)
            {
                return Ok((ChunkDisposition::Replay, receipt(snapshot)));
            }
            return transfer_invalid("replayed chunk is too old or has a conflicting digest");
        }
        if chunk.sequence != snapshot.next_sequence
            || chunk.previous_digest != snapshot.last_digest
            || chunk.round < snapshot.last_round
        {
            return transfer_invalid("chunk sequence, chain, or round is out of order");
        }

        let encoded = chunk.encoded()?;
        let encoded_len = u32::try_from(encoded.len())
            .map_err(|_| ClusterError::InvalidTransfer("encoded chunk is too large".to_owned()))?;
        let next_sequence = snapshot.next_sequence.checked_add(1).ok_or_else(|| {
            ClusterError::InvalidTransfer("chunk sequence is exhausted".to_owned())
        })?;
        let old_length = snapshot.staged_bytes;
        let frame_length = 4_u64.saturating_add(u64::from(encoded_len));
        let new_length = old_length.checked_add(frame_length).ok_or_else(|| {
            ClusterError::InvalidTransfer("staged transfer length is exhausted".to_owned())
        })?;
        if new_length > self.max_staged_bytes {
            return transfer_invalid("target staged-byte limit would be exceeded");
        }
        self.append_stage_frame(encoded_len, &encoded)?;

        let mut next = state.clone();
        next.snapshot.next_sequence = next_sequence;
        next.snapshot.last_round = chunk.round;
        next.snapshot.last_digest = Some(chunk.digest);
        next.snapshot.staged_bytes = new_length;
        if let Err(error) = self.persist(&next) {
            let _ = self.truncate_stage(old_length);
            return Err(error);
        }
        *state = next;
        Ok((ChunkDisposition::Applied, receipt(&state.snapshot)))
    }

    pub fn record_source_receipt(
        &self,
        chunk: &TransferChunk,
        target: &TransferReceipt,
    ) -> Result<(), ClusterError> {
        self.require_source_resumable()?;
        chunk.verify()?;
        let frame_bytes = 4_u64
            .checked_add(u64::try_from(chunk.encoded_len()?).map_err(|_| {
                ClusterError::InvalidTransfer("encoded chunk length is exhausted".to_owned())
            })?)
            .ok_or_else(|| {
                ClusterError::InvalidTransfer("encoded chunk length is exhausted".to_owned())
            })?;
        self.mutate(|snapshot| {
            require_role(snapshot, TransferRole::Source)?;
            validate_receipt_identity(snapshot, target)?;
            if chunk.sequence.checked_add(1) == Some(snapshot.next_sequence)
                && snapshot.last_digest == Some(chunk.digest)
            {
                if receipt(snapshot) == *target {
                    return Ok(());
                }
                return transfer_invalid("replayed target receipt conflicts with durable progress");
            }
            if snapshot.phase != TransferPhase::Copying {
                return transfer_invalid("source is not accepting target receipts");
            }
            let expected_staged_bytes =
                snapshot
                    .staged_bytes
                    .checked_add(frame_bytes)
                    .ok_or_else(|| {
                        ClusterError::InvalidTransfer(
                            "staged transfer length is exhausted".to_owned(),
                        )
                    })?;
            if chunk.transfer_id != snapshot.descriptor.transfer_id
                || chunk.attempt != snapshot.attempt
                || chunk.sequence != snapshot.next_sequence
                || chunk.previous_digest != snapshot.last_digest
                || chunk.round < snapshot.last_round
                || target.next_sequence != chunk.sequence.checked_add(1).unwrap_or(0)
                || target.last_digest != Some(chunk.digest)
                || target.last_round != chunk.round
                || target.staged_bytes != expected_staged_bytes
                || target.staged_bytes > self.max_staged_bytes
            {
                return transfer_invalid("target receipt does not acknowledge the source chunk");
            }
            snapshot.next_sequence = target.next_sequence;
            snapshot.last_round = target.last_round;
            snapshot.last_digest = target.last_digest;
            snapshot.staged_bytes = target.staged_bytes;
            Ok(())
        })
    }

    pub fn mark_source_fenced(&self, final_receipt: &TransferReceipt) -> Result<(), ClusterError> {
        self.require_source_resumable()?;
        self.mutate(|snapshot| {
            require_role(snapshot, TransferRole::Source)?;
            validate_receipt_identity(snapshot, final_receipt)?;
            if receipt(snapshot) != *final_receipt {
                return transfer_invalid("source fence receipt does not match durable progress");
            }
            if snapshot.phase == TransferPhase::Fenced {
                return Ok(());
            }
            if snapshot.phase != TransferPhase::Copying {
                return transfer_invalid("source can fence only while copying");
            }
            snapshot.phase = TransferPhase::Fenced;
            Ok(())
        })
    }

    pub fn seal(&self, expected: &TransferReceipt) -> Result<(), ClusterError> {
        self.mutate(|snapshot| {
            validate_receipt_identity(snapshot, expected)?;
            if receipt(snapshot) != *expected {
                return transfer_invalid("seal receipt does not match durable progress");
            }
            if matches!(
                snapshot.phase,
                TransferPhase::Sealed | TransferPhase::Activated | TransferPhase::Finalized
            ) {
                return Ok(());
            }
            let valid_phase = match snapshot.role {
                TransferRole::Source => snapshot.phase == TransferPhase::Fenced,
                TransferRole::Target => snapshot.phase == TransferPhase::Copying,
            };
            if !valid_phase {
                return transfer_invalid("transfer cannot seal in this phase");
            }
            snapshot.phase = TransferPhase::Sealed;
            Ok(())
        })
    }

    pub fn mark_topology_committed(&self, epoch: u64) -> Result<(), ClusterError> {
        self.mutate(|snapshot| {
            if epoch != snapshot.descriptor.to_epoch {
                return transfer_invalid("committed topology epoch does not match transfer");
            }
            if matches!(
                snapshot.phase,
                TransferPhase::Activated | TransferPhase::Finalized
            ) {
                return Ok(());
            }
            if snapshot.phase != TransferPhase::Sealed {
                return transfer_invalid("topology cannot activate an unsealed transfer");
            }
            snapshot.phase = TransferPhase::Activated;
            Ok(())
        })
    }

    pub fn finalize(&self) -> Result<(), ClusterError> {
        self.mutate(|snapshot| {
            if snapshot.phase == TransferPhase::Finalized {
                return Ok(());
            }
            if snapshot.phase != TransferPhase::Activated {
                return transfer_invalid("transfer cannot finalize before activation");
            }
            snapshot.phase = TransferPhase::Finalized;
            Ok(())
        })?;
        self.cleanup_stage_if_terminal()
    }

    pub fn abort(&self) -> Result<(), ClusterError> {
        self.mutate(|snapshot| {
            if snapshot.phase == TransferPhase::Aborted {
                return Ok(());
            }
            if matches!(
                snapshot.phase,
                TransferPhase::Activated | TransferPhase::Finalized
            ) {
                return transfer_invalid("activated transfer cannot be aborted");
            }
            snapshot.phase = TransferPhase::Aborted;
            Ok(())
        })?;
        self.cleanup_stage_if_terminal()
    }

    fn mutate<R>(
        &self,
        update: impl FnOnce(&mut TransferJournalSnapshot) -> Result<R, ClusterError>,
    ) -> Result<R, ClusterError> {
        let mut state = self.inner.lock();
        let mut next = state.clone();
        let result = update(&mut next.snapshot)?;
        self.persist(&next)?;
        *state = next;
        Ok(result)
    }

    fn require_source_resumable(&self) -> Result<(), ClusterError> {
        if self.source_restart_required.load(Ordering::Acquire) {
            return transfer_invalid("reopened source must begin a new attempt before continuing");
        }
        Ok(())
    }

    fn persist(&self, state: &TransferDiskState) -> Result<(), ClusterError> {
        write_json_atomic(
            &self.journal_path,
            state,
            "ownership transfer",
            MAX_TRANSFER_JOURNAL_BYTES as usize,
        )
    }

    fn reconcile_stage(&self, snapshot: &TransferJournalSnapshot) -> Result<(), ClusterError> {
        if matches!(
            snapshot.phase,
            TransferPhase::Finalized | TransferPhase::Aborted
        ) {
            return self.remove_stage();
        }
        if !self.stage_path.exists() {
            if snapshot.staged_bytes != STAGE_HEADER_BYTES {
                return transfer_invalid("durable target stage file is missing");
            }
            return self.replace_stage_with_header(&snapshot.descriptor.transfer_id);
        }
        let metadata = std::fs::metadata(&self.stage_path)?;
        if metadata.permissions().mode() & 0o077 != 0 {
            std::fs::set_permissions(&self.stage_path, std::fs::Permissions::from_mode(0o600))?;
        }
        if metadata.len() < snapshot.staged_bytes || snapshot.staged_bytes < STAGE_HEADER_BYTES {
            return transfer_invalid("durable target stage file is shorter than its journal");
        }
        let mut header = [0_u8; STAGE_HEADER_BYTES as usize];
        std::io::Read::read_exact(&mut std::fs::File::open(&self.stage_path)?, &mut header)?;
        if header != stage_header(&snapshot.descriptor.transfer_id) {
            return transfer_invalid("durable target stage header belongs to another transfer");
        }
        if metadata.len() > snapshot.staged_bytes {
            self.truncate_stage(snapshot.staged_bytes)?;
        }
        Ok(())
    }

    fn replace_stage_with_header(&self, transfer_id: &TransferId) -> Result<(), ClusterError> {
        if let Some(parent) = self.stage_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut nonce = [0_u8; 16];
        OsRng.try_fill_bytes(&mut nonce).map_err(|error| {
            ClusterError::Io(std::io::Error::other(format!(
                "failed to create transfer-stage nonce: {error}"
            )))
        })?;
        let temporary = self.stage_path.with_extension(format!(
            "stage-tmp-{}-{}",
            std::process::id(),
            encode_hex(&nonce)
        ));
        let result = (|| -> Result<(), ClusterError> {
            let mut file = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&temporary)?;
            file.write_all(&stage_header(transfer_id))?;
            file.sync_all()?;
            std::fs::rename(&temporary, &self.stage_path)?;
            sync_parent(&self.stage_path)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
    }

    fn append_stage_frame(&self, encoded_len: u32, encoded: &[u8]) -> Result<(), ClusterError> {
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .mode(0o600)
            .open(&self.stage_path)?;
        file.write_all(&encoded_len.to_be_bytes())?;
        file.write_all(encoded)?;
        file.sync_all()?;
        Ok(())
    }

    fn truncate_stage(&self, length: u64) -> Result<(), ClusterError> {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&self.stage_path)?;
        file.set_len(length)?;
        file.sync_all()?;
        Ok(())
    }

    fn cleanup_stage_if_terminal(&self) -> Result<(), ClusterError> {
        let snapshot = self.inner.lock().snapshot.clone();
        if snapshot.role == TransferRole::Target
            && matches!(
                snapshot.phase,
                TransferPhase::Finalized | TransferPhase::Aborted
            )
        {
            self.remove_stage()?;
        }
        Ok(())
    }

    fn remove_stage(&self) -> Result<(), ClusterError> {
        match std::fs::remove_file(&self.stage_path) {
            Ok(()) => sync_parent(&self.stage_path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

fn validate_disk_state(
    state: &TransferDiskState,
    role: TransferRole,
    descriptor: &TransferDescriptor,
) -> Result<(), ClusterError> {
    if state.schema_version != TRANSFER_SCHEMA_VERSION
        || state.snapshot.role != role
        || &state.snapshot.descriptor != descriptor
    {
        return transfer_invalid("durable journal does not match the requested transfer");
    }
    descriptor.validate()?;
    if role == TransferRole::Target && state.snapshot.phase == TransferPhase::Fenced {
        return transfer_invalid("target journal cannot contain a source fence");
    }
    match state.snapshot.phase {
        TransferPhase::Prepared if state.snapshot.attempt != 0 => {
            return transfer_invalid("prepared journal cannot contain an attempt")
        }
        TransferPhase::Copying
        | TransferPhase::Fenced
        | TransferPhase::Sealed
        | TransferPhase::Activated
        | TransferPhase::Finalized
            if state.snapshot.attempt == 0 =>
        {
            return transfer_invalid("started journal is missing its attempt")
        }
        _ => {}
    }
    if state.snapshot.attempt == 0 {
        if !matches!(
            state.snapshot.phase,
            TransferPhase::Prepared | TransferPhase::Aborted
        ) || state.snapshot.next_sequence != 0
            || state.snapshot.last_round != 0
            || state.snapshot.last_digest.is_some()
        {
            return transfer_invalid("unstarted journal contains transfer progress");
        }
    } else if state.snapshot.next_sequence == 0
        && (state.snapshot.last_round != 0 || state.snapshot.last_digest.is_some())
    {
        return transfer_invalid("empty journal contains chunk progress");
    } else if state.snapshot.next_sequence > 0 && state.snapshot.last_digest.is_none() {
        return transfer_invalid("nonempty journal is missing its last chunk digest");
    }
    if role == TransferRole::Target {
        if state.snapshot.staged_bytes < STAGE_HEADER_BYTES
            || (state.snapshot.next_sequence == 0
                && state.snapshot.staged_bytes != STAGE_HEADER_BYTES)
            || (state.snapshot.next_sequence > 0
                && state.snapshot.staged_bytes <= STAGE_HEADER_BYTES)
        {
            return transfer_invalid("target journal has an invalid stage length");
        }
    } else {
        if state.snapshot.staged_bytes != 0 && state.snapshot.staged_bytes < STAGE_HEADER_BYTES {
            return transfer_invalid("source journal has an invalid target stage length");
        }
        if state.snapshot.next_sequence > 0 && state.snapshot.staged_bytes <= STAGE_HEADER_BYTES {
            return transfer_invalid("source journal has an invalid target stage length");
        }
        if matches!(
            state.snapshot.phase,
            TransferPhase::Fenced
                | TransferPhase::Sealed
                | TransferPhase::Activated
                | TransferPhase::Finalized
        ) && state.snapshot.staged_bytes < STAGE_HEADER_BYTES
        {
            return transfer_invalid("fenced source is missing target stage acknowledgement");
        }
    }
    Ok(())
}

fn reset_progress(snapshot: &mut TransferJournalSnapshot) {
    snapshot.next_sequence = 0;
    snapshot.last_round = 0;
    snapshot.last_digest = None;
    snapshot.staged_bytes = if snapshot.role == TransferRole::Target {
        STAGE_HEADER_BYTES
    } else {
        0
    };
}

fn receipt(snapshot: &TransferJournalSnapshot) -> TransferReceipt {
    TransferReceipt {
        transfer_id: snapshot.descriptor.transfer_id,
        attempt: snapshot.attempt,
        next_sequence: snapshot.next_sequence,
        last_round: snapshot.last_round,
        last_digest: snapshot.last_digest,
        staged_bytes: snapshot.staged_bytes,
    }
}

fn validate_receipt_identity(
    snapshot: &TransferJournalSnapshot,
    receipt: &TransferReceipt,
) -> Result<(), ClusterError> {
    if receipt.transfer_id != snapshot.descriptor.transfer_id
        || receipt.attempt != snapshot.attempt
        || receipt.attempt == 0
    {
        return transfer_invalid("receipt belongs to another transfer attempt");
    }
    Ok(())
}

fn require_role(
    snapshot: &TransferJournalSnapshot,
    expected: TransferRole,
) -> Result<(), ClusterError> {
    if snapshot.role != expected {
        return transfer_invalid("journal operation is invalid for this transfer role");
    }
    Ok(())
}

fn sync_parent(path: &Path) -> Result<(), ClusterError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn transfer_invalid<T>(message: impl Into<String>) -> Result<T, ClusterError> {
    Err(ClusterError::InvalidTransfer(message.into()))
}

#[cfg(test)]
#[path = "transfer_tests.rs"]
mod tests;
