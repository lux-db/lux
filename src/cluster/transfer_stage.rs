use super::transfer::{
    TransferChunk, TransferId, TransferJournalSnapshot, TransferPhase,
    MAX_TRANSFER_ENCODED_CHUNK_BYTES, TRANSFER_SCHEMA_VERSION,
};
use super::ClusterError;
use std::io::{Read, Seek};
use std::path::Path;

const TRANSFER_STAGE_MAGIC: &[u8; 4] = b"LXTS";
pub(super) const STAGE_HEADER_BYTES: u64 = 4 + 2 + 32;

pub(crate) struct TransferStageReader {
    file: std::io::BufReader<std::fs::File>,
    snapshot: TransferJournalSnapshot,
    remaining: u64,
    next_sequence: u64,
    last_round: u32,
    last_digest: Option<[u8; 32]>,
    payload: std::io::Cursor<Vec<u8>>,
    verified: bool,
}

impl TransferStageReader {
    pub(crate) fn open(
        path: &Path,
        snapshot: &TransferJournalSnapshot,
    ) -> Result<Self, ClusterError> {
        let mut file = std::io::BufReader::new(std::fs::File::open(path)?);
        let mut header = [0_u8; STAGE_HEADER_BYTES as usize];
        file.read_exact(&mut header)?;
        if header != stage_header(&snapshot.descriptor.transfer_id) {
            return invalid("target stage header belongs to another transfer");
        }
        let remaining = snapshot
            .staged_bytes
            .checked_sub(STAGE_HEADER_BYTES)
            .ok_or_else(|| ClusterError::InvalidTransfer("target stage is too short".to_owned()))?;
        Ok(Self {
            file,
            snapshot: snapshot.clone(),
            remaining,
            next_sequence: 0,
            last_round: 0,
            last_digest: None,
            payload: std::io::Cursor::new(Vec::new()),
            verified: false,
        })
    }

    fn load_payload(&mut self) -> std::io::Result<bool> {
        if self.remaining == 0 {
            if self.next_sequence != self.snapshot.next_sequence
                || self.last_round != self.snapshot.last_round
                || self.last_digest != self.snapshot.last_digest
            {
                return Err(invalid_data(
                    "target stage progress does not match its journal",
                ));
            }
            self.verified = true;
            return Ok(false);
        }
        if self.remaining < 4 {
            return Err(invalid_data("target stage ends inside a frame header"));
        }
        let mut length_bytes = [0_u8; 4];
        self.file.read_exact(&mut length_bytes)?;
        let frame_length = u32::from_be_bytes(length_bytes) as usize;
        if frame_length == 0 || frame_length > MAX_TRANSFER_ENCODED_CHUNK_BYTES {
            return Err(invalid_data(
                "target stage contains an invalid frame length",
            ));
        }
        let total_length = 4_u64
            .checked_add(frame_length as u64)
            .ok_or_else(|| invalid_data("stage frame is too large"))?;
        if total_length > self.remaining {
            return Err(invalid_data("target stage frame exceeds durable progress"));
        }
        let mut encoded = vec![0_u8; frame_length];
        self.file.read_exact(&mut encoded)?;
        let chunk = TransferChunk::decode(&encoded).map_err(cluster_as_invalid_data)?;
        if chunk.transfer_id != self.snapshot.descriptor.transfer_id
            || chunk.attempt != self.snapshot.attempt
            || chunk.sequence != self.next_sequence
            || chunk.previous_digest != self.last_digest
            || chunk.round < self.last_round
        {
            return Err(invalid_data(
                "target stage chunk chain does not match its journal",
            ));
        }
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or_else(|| invalid_data("stage chunk sequence is exhausted"))?;
        self.last_round = chunk.round;
        self.last_digest = Some(chunk.digest);
        self.remaining -= total_length;
        self.payload = std::io::Cursor::new(chunk.payload);
        Ok(true)
    }
}

impl Read for TransferStageReader {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if output.is_empty() || self.verified {
            return Ok(0);
        }
        loop {
            let copied = self.payload.read(output)?;
            if copied != 0 {
                return Ok(copied);
            }
            if !self.load_payload()? {
                return Ok(0);
            }
        }
    }
}

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

fn invalid_data(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.into())
}

fn cluster_as_invalid_data(error: ClusterError) -> std::io::Error {
    invalid_data(error.to_string())
}
