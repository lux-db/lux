use super::transfer::{
    TransferChunk, TransferId, TransferJournalSnapshot, TransferPhase,
    MAX_TRANSFER_ENCODED_CHUNK_BYTES, TRANSFER_SCHEMA_VERSION,
};
use super::ClusterError;
use std::io::{Read, Seek};
use std::path::Path;

const TRANSFER_STAGE_MAGIC: &[u8; 4] = b"LXTS";
pub(super) const STAGE_HEADER_BYTES: u64 = 4 + 2 + 32;

pub(super) fn stage_header(transfer_id: &TransferId) -> [u8; STAGE_HEADER_BYTES as usize] {
    let mut header = [0_u8; STAGE_HEADER_BYTES as usize];
    header[..4].copy_from_slice(TRANSFER_STAGE_MAGIC);
    header[4..6].copy_from_slice(&TRANSFER_SCHEMA_VERSION.to_be_bytes());
    header[6..].copy_from_slice(&transfer_id.0);
    header
}

pub(super) fn validate_stage_contents(
    path: &Path,
    snapshot: &TransferJournalSnapshot,
) -> Result<(), ClusterError> {
    if matches!(
        snapshot.phase,
        TransferPhase::Finalized | TransferPhase::Aborted
    ) {
        return Ok(());
    }
    let mut file = std::fs::File::open(path)?;
    file.seek(std::io::SeekFrom::Start(STAGE_HEADER_BYTES))?;
    let mut remaining = snapshot
        .staged_bytes
        .checked_sub(STAGE_HEADER_BYTES)
        .ok_or_else(|| ClusterError::InvalidTransfer("target stage is too short".to_owned()))?;
    let mut next_sequence = 0_u64;
    let mut last_round = 0_u32;
    let mut last_digest = None;
    while remaining != 0 {
        if remaining < 4 {
            return invalid("target stage ends inside a frame header");
        }
        let mut length_bytes = [0_u8; 4];
        file.read_exact(&mut length_bytes)?;
        let frame_length = u32::from_be_bytes(length_bytes) as usize;
        if frame_length == 0 || frame_length > MAX_TRANSFER_ENCODED_CHUNK_BYTES {
            return invalid("target stage contains an invalid frame length");
        }
        let total_length = 4_u64
            .checked_add(frame_length as u64)
            .ok_or_else(|| ClusterError::InvalidTransfer("stage frame is too large".to_owned()))?;
        if total_length > remaining {
            return invalid("target stage frame exceeds durable progress");
        }
        let mut encoded = vec![0_u8; frame_length];
        file.read_exact(&mut encoded)?;
        let chunk = TransferChunk::decode(&encoded)?;
        if chunk.transfer_id != snapshot.descriptor.transfer_id
            || chunk.attempt != snapshot.attempt
            || chunk.sequence != next_sequence
            || chunk.previous_digest != last_digest
            || chunk.round < last_round
        {
            return invalid("target stage chunk chain does not match its journal");
        }
        next_sequence = next_sequence.checked_add(1).ok_or_else(|| {
            ClusterError::InvalidTransfer("stage chunk sequence is exhausted".to_owned())
        })?;
        last_round = chunk.round;
        last_digest = Some(chunk.digest);
        remaining -= total_length;
    }
    if next_sequence != snapshot.next_sequence
        || last_round != snapshot.last_round
        || last_digest != snapshot.last_digest
    {
        return invalid("target stage progress does not match its journal");
    }
    Ok(())
}

fn invalid<T>(message: impl Into<String>) -> Result<T, ClusterError> {
    Err(ClusterError::InvalidTransfer(message.into()))
}
