use super::{
    ClusterError, CompiledTopology, TopologyTransitionKind, CLUSTER_PROTOCOL_VERSION,
    CLUSTER_SLOT_COUNT,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(super) const TRANSFER_SCHEMA_VERSION: u16 = 1;
const MAX_TRANSFER_IDENTIFIER_BYTES: usize = 128;
pub const MAX_TRANSFER_CHUNK_BYTES: usize = 3 * 1024 * 1024;
pub(super) const MAX_TRANSFER_ENCODED_CHUNK_BYTES: usize =
    32 + 4 + 8 + 4 + 1 + 32 + 32 + 4 + MAX_TRANSFER_CHUNK_BYTES;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct TransferId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SlotRange {
    pub start: u16,
    pub end: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransferDescriptor {
    pub schema_version: u16,
    pub protocol_version: u16,
    pub transfer_id: TransferId,
    pub cluster_id: String,
    pub from_epoch: u64,
    pub to_epoch: u64,
    pub source_node_id: String,
    pub target_node_id: String,
    pub ranges: Vec<SlotRange>,
}

impl TransferDescriptor {
    pub fn from_topologies(
        current: &CompiledTopology,
        candidate: &CompiledTopology,
        source_node_id: &str,
        target_node_id: &str,
    ) -> Result<Self, ClusterError> {
        let transition = current.transition_to(candidate)?;
        if transition.kind != TopologyTransitionKind::Ownership {
            return transfer_invalid("transfer requires an ownership topology transition");
        }
        let ranges = transition
            .moves
            .iter()
            .filter(|movement| {
                movement.source_node_id == source_node_id
                    && movement.target_node_id == target_node_id
            })
            .map(|movement| SlotRange {
                start: movement.start,
                end: movement.end,
            })
            .collect::<Vec<_>>();
        let mut descriptor = Self {
            schema_version: TRANSFER_SCHEMA_VERSION,
            protocol_version: CLUSTER_PROTOCOL_VERSION,
            transfer_id: TransferId([0; 32]),
            cluster_id: current.manifest().cluster_id.clone(),
            from_epoch: transition.from_epoch,
            to_epoch: transition.to_epoch,
            source_node_id: source_node_id.to_owned(),
            target_node_id: target_node_id.to_owned(),
            ranges,
        };
        descriptor.transfer_id = descriptor.expected_id()?;
        descriptor.validate()?;
        Ok(descriptor)
    }

    pub fn validate(&self) -> Result<(), ClusterError> {
        if self.schema_version != TRANSFER_SCHEMA_VERSION {
            return transfer_invalid(format!(
                "unsupported descriptor schema {}",
                self.schema_version
            ));
        }
        if self.protocol_version != CLUSTER_PROTOCOL_VERSION {
            return transfer_invalid(format!(
                "unsupported descriptor protocol {}",
                self.protocol_version
            ));
        }
        if !valid_identifier(&self.cluster_id)
            || !valid_identifier(&self.source_node_id)
            || !valid_identifier(&self.target_node_id)
            || self.source_node_id == self.target_node_id
        {
            return transfer_invalid("descriptor identities are invalid");
        }
        if self.from_epoch == 0 || self.to_epoch != self.from_epoch.checked_add(1).unwrap_or(0) {
            return transfer_invalid("descriptor epochs must be consecutive and nonzero");
        }
        if self.ranges.is_empty() {
            return transfer_invalid("descriptor contains no slot ranges");
        }
        let mut previous_end = None;
        for range in &self.ranges {
            if range.start > range.end || range.end >= CLUSTER_SLOT_COUNT {
                return transfer_invalid("descriptor contains an invalid slot range");
            }
            if previous_end.is_some_and(|end| range.start <= end) {
                return transfer_invalid("descriptor slot ranges overlap or are not sorted");
            }
            previous_end = Some(range.end);
        }
        if self.transfer_id != self.expected_id()? {
            return transfer_invalid("descriptor transfer id does not match its contents");
        }
        Ok(())
    }

    #[must_use]
    pub fn contains_slot(&self, slot: u16) -> bool {
        self.ranges
            .iter()
            .any(|range| slot >= range.start && slot <= range.end)
    }

    pub(crate) fn expected_id(&self) -> Result<TransferId, ClusterError> {
        let mut canonical = Vec::with_capacity(256);
        canonical.extend_from_slice(b"LUX-OWNERSHIP-TRANSFER\0");
        canonical.extend_from_slice(&self.schema_version.to_be_bytes());
        canonical.extend_from_slice(&self.protocol_version.to_be_bytes());
        push_string(&mut canonical, &self.cluster_id)?;
        canonical.extend_from_slice(&self.from_epoch.to_be_bytes());
        canonical.extend_from_slice(&self.to_epoch.to_be_bytes());
        push_string(&mut canonical, &self.source_node_id)?;
        push_string(&mut canonical, &self.target_node_id)?;
        let range_count = u16::try_from(self.ranges.len())
            .map_err(|_| ClusterError::InvalidTransfer("too many slot ranges".to_owned()))?;
        canonical.extend_from_slice(&range_count.to_be_bytes());
        for range in &self.ranges {
            canonical.extend_from_slice(&range.start.to_be_bytes());
            canonical.extend_from_slice(&range.end.to_be_bytes());
        }
        Ok(TransferId(Sha256::digest(canonical).into()))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferRole {
    Source,
    Target,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferPhase {
    Prepared,
    Copying,
    Fenced,
    Sealed,
    Applied,
    Ready,
    Activated,
    Finalized,
    Aborted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferChunk {
    pub transfer_id: TransferId,
    pub attempt: u32,
    pub sequence: u64,
    pub round: u32,
    pub previous_digest: Option<[u8; 32]>,
    pub payload: Vec<u8>,
    pub digest: [u8; 32],
}

impl TransferChunk {
    pub fn new(
        transfer_id: TransferId,
        attempt: u32,
        sequence: u64,
        round: u32,
        previous_digest: Option<[u8; 32]>,
        payload: Vec<u8>,
    ) -> Result<Self, ClusterError> {
        if attempt == 0 {
            return transfer_invalid("chunk attempt must be nonzero");
        }
        if payload.is_empty() || payload.len() > MAX_TRANSFER_CHUNK_BYTES {
            return transfer_invalid(format!(
                "chunk payload must contain 1 to {MAX_TRANSFER_CHUNK_BYTES} bytes"
            ));
        }
        let digest = chunk_digest(
            transfer_id,
            attempt,
            sequence,
            round,
            previous_digest,
            &payload,
        );
        Ok(Self {
            transfer_id,
            attempt,
            sequence,
            round,
            previous_digest,
            payload,
            digest,
        })
    }

    pub fn verify(&self) -> Result<(), ClusterError> {
        if self.attempt == 0
            || self.payload.is_empty()
            || self.payload.len() > MAX_TRANSFER_CHUNK_BYTES
        {
            return transfer_invalid("chunk bounds are invalid");
        }
        let expected = chunk_digest(
            self.transfer_id,
            self.attempt,
            self.sequence,
            self.round,
            self.previous_digest,
            &self.payload,
        );
        if self.digest != expected {
            return transfer_invalid("chunk digest does not match its contents");
        }
        Ok(())
    }

    pub(super) fn encoded(&self) -> Result<Vec<u8>, ClusterError> {
        self.verify()?;
        let payload_len = u32::try_from(self.payload.len())
            .map_err(|_| ClusterError::InvalidTransfer("chunk payload is too large".to_owned()))?;
        let mut encoded = Vec::with_capacity(self.encoded_len()?);
        encoded.extend_from_slice(&self.transfer_id.0);
        encoded.extend_from_slice(&self.attempt.to_be_bytes());
        encoded.extend_from_slice(&self.sequence.to_be_bytes());
        encoded.extend_from_slice(&self.round.to_be_bytes());
        match self.previous_digest {
            Some(digest) => {
                encoded.push(1);
                encoded.extend_from_slice(&digest);
            }
            None => encoded.push(0),
        }
        encoded.extend_from_slice(&self.digest);
        encoded.extend_from_slice(&payload_len.to_be_bytes());
        encoded.extend_from_slice(&self.payload);
        Ok(encoded)
    }

    pub(super) fn encoded_len(&self) -> Result<usize, ClusterError> {
        let fixed = 32_usize + 4 + 8 + 4 + 1 + 32 + 4;
        fixed
            .checked_add(self.previous_digest.map_or(0, |_| 32))
            .and_then(|length| length.checked_add(self.payload.len()))
            .ok_or_else(|| ClusterError::InvalidTransfer("encoded chunk is too large".to_owned()))
    }

    pub(super) fn decode(mut encoded: &[u8]) -> Result<Self, ClusterError> {
        if encoded.len() > MAX_TRANSFER_ENCODED_CHUNK_BYTES {
            return transfer_invalid("encoded chunk exceeds its size limit");
        }
        let transfer_id = TransferId(take_array(&mut encoded)?);
        let attempt = u32::from_be_bytes(take_array(&mut encoded)?);
        let sequence = u64::from_be_bytes(take_array(&mut encoded)?);
        let round = u32::from_be_bytes(take_array(&mut encoded)?);
        let previous_digest = match take_array::<1>(&mut encoded)?[0] {
            0 => None,
            1 => Some(take_array(&mut encoded)?),
            _ => return transfer_invalid("encoded chunk has an invalid chain flag"),
        };
        let digest = take_array(&mut encoded)?;
        let payload_length = u32::from_be_bytes(take_array(&mut encoded)?) as usize;
        if encoded.len() != payload_length {
            return transfer_invalid("encoded chunk payload length does not match its frame");
        }
        let chunk = Self::new(
            transfer_id,
            attempt,
            sequence,
            round,
            previous_digest,
            encoded.to_vec(),
        )?;
        if chunk.digest != digest {
            return transfer_invalid("encoded chunk digest does not match its contents");
        }
        Ok(chunk)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransferReceipt {
    pub transfer_id: TransferId,
    pub attempt: u32,
    pub next_sequence: u64,
    pub last_round: u32,
    pub last_digest: Option<[u8; 32]>,
    pub staged_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChunkDisposition {
    Applied,
    Replay,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransferJournalSnapshot {
    pub descriptor: TransferDescriptor,
    pub role: TransferRole,
    pub phase: TransferPhase,
    pub attempt: u32,
    pub next_sequence: u64,
    pub last_round: u32,
    pub last_digest: Option<[u8; 32]>,
    pub staged_bytes: u64,
}

fn chunk_digest(
    transfer_id: TransferId,
    attempt: u32,
    sequence: u64,
    round: u32,
    previous_digest: Option<[u8; 32]>,
    payload: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"LUX-OWNERSHIP-TRANSFER-CHUNK\0");
    hasher.update(transfer_id.0);
    hasher.update(attempt.to_be_bytes());
    hasher.update(sequence.to_be_bytes());
    hasher.update(round.to_be_bytes());
    match previous_digest {
        Some(digest) => {
            hasher.update([1]);
            hasher.update(digest);
        }
        None => hasher.update([0]),
    }
    hasher.update((payload.len() as u64).to_be_bytes());
    hasher.update(payload);
    hasher.finalize().into()
}

fn push_string(output: &mut Vec<u8>, value: &str) -> Result<(), ClusterError> {
    if !valid_identifier(value) {
        return transfer_invalid("canonical transfer identifier is invalid");
    }
    let length = u16::try_from(value.len())
        .map_err(|_| ClusterError::InvalidTransfer("identifier is too large".to_owned()))?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TRANSFER_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn take_array<const LENGTH: usize>(input: &mut &[u8]) -> Result<[u8; LENGTH], ClusterError> {
    if input.len() < LENGTH {
        return transfer_invalid("encoded chunk is truncated");
    }
    let (head, tail) = input.split_at(LENGTH);
    *input = tail;
    head.try_into()
        .map_err(|_| ClusterError::InvalidTransfer("encoded chunk is truncated".to_owned()))
}

fn transfer_invalid<T>(message: impl Into<String>) -> Result<T, ClusterError> {
    Err(ClusterError::InvalidTransfer(message.into()))
}
