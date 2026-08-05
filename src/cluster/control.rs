use super::{ClusterError, CLUSTER_PROTOCOL_VERSION};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

const MAX_CONTROL_ID_BYTES: usize = 128;
pub const MAX_CONTROL_DEADLINE_MS: u64 = 30_000;
const REQUEST_MAGIC: &[u8; 4] = b"LXCQ";
const RESPONSE_MAGIC: &[u8; 4] = b"LXCR";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct ControlRequestId(pub [u8; 16]);

impl ControlRequestId {
    pub fn random() -> Result<Self, ClusterError> {
        let mut bytes = [0_u8; 16];
        OsRng.try_fill_bytes(&mut bytes).map_err(|error| {
            ClusterError::Transport(format!("failed to generate control request id: {error}"))
        })?;
        Ok(Self(bytes))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ControlRequest {
    pub protocol_version: u16,
    pub cluster_id: String,
    pub topology_epoch: u64,
    pub execution_version: u64,
    pub source_node_id: String,
    pub target_node_id: String,
    pub request_id: ControlRequestId,
    /// Absolute Unix time in milliseconds. Control calls are deliberately
    /// short-lived and receivers reject deadlines too far into the future.
    pub deadline_unix_ms: u64,
    pub body: ControlRequestBody,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlRequestBody {
    /// Authenticated liveness and generation check. This is control traffic,
    /// never a user-data forwarding path.
    Probe,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlRejectCode {
    InvalidEnvelope,
    DeadlineElapsed,
    DeadlineTooFar,
    ClusterMismatch,
    SourceIdentityMismatch,
    TargetMismatch,
    MembershipPending,
    TopologyStale,
    TopologyAhead,
    ExecutionStale,
    ExecutionAhead,
    HandlerFailed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ControlResponse {
    pub protocol_version: u16,
    pub cluster_id: String,
    pub topology_epoch: u64,
    pub execution_version: u64,
    pub source_node_id: String,
    pub target_node_id: String,
    pub request_id: ControlRequestId,
    pub body: ControlResponseBody,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlResponseBody {
    Pong,
    Rejected { code: ControlRejectCode },
}

impl ControlRequest {
    pub(crate) fn validate_untrusted(&self, now_unix_ms: u64) -> Result<(), ControlRejectCode> {
        if self.protocol_version != CLUSTER_PROTOCOL_VERSION
            || self.topology_epoch == 0
            || self.execution_version == 0
            || self.source_node_id == self.target_node_id
            || !valid_identifier(&self.cluster_id)
            || !valid_identifier(&self.source_node_id)
            || !valid_identifier(&self.target_node_id)
        {
            return Err(ControlRejectCode::InvalidEnvelope);
        }
        if self.deadline_unix_ms <= now_unix_ms {
            return Err(ControlRejectCode::DeadlineElapsed);
        }
        if self.deadline_unix_ms.saturating_sub(now_unix_ms) > MAX_CONTROL_DEADLINE_MS {
            return Err(ControlRejectCode::DeadlineTooFar);
        }
        Ok(())
    }
}

impl ControlResponse {
    pub(crate) fn validate_for(&self, request: &ControlRequest) -> Result<(), ClusterError> {
        if self.protocol_version != CLUSTER_PROTOCOL_VERSION {
            return protocol("control response has an unsupported protocol version");
        }
        if self.cluster_id != request.cluster_id
            || self.source_node_id != request.target_node_id
            || self.target_node_id != request.source_node_id
            || self.request_id != request.request_id
        {
            return protocol("control response is not bound to its request");
        }
        if self.topology_epoch == 0 || self.execution_version == 0 {
            return protocol("control response has an invalid serving generation");
        }
        Ok(())
    }
}

pub(super) fn encode_request(request: &ControlRequest) -> Result<Vec<u8>, ClusterError> {
    let mut output = Vec::with_capacity(128);
    output.extend_from_slice(REQUEST_MAGIC);
    output.extend_from_slice(&request.protocol_version.to_be_bytes());
    push_string(&mut output, &request.cluster_id)?;
    output.extend_from_slice(&request.topology_epoch.to_be_bytes());
    output.extend_from_slice(&request.execution_version.to_be_bytes());
    push_string(&mut output, &request.source_node_id)?;
    push_string(&mut output, &request.target_node_id)?;
    output.extend_from_slice(&request.request_id.0);
    output.extend_from_slice(&request.deadline_unix_ms.to_be_bytes());
    output.push(match request.body {
        ControlRequestBody::Probe => 0,
    });
    Ok(output)
}

pub(super) fn decode_request(encoded: &[u8]) -> Result<ControlRequest, ClusterError> {
    let mut reader = WireReader::new(encoded);
    reader.expect_magic(REQUEST_MAGIC)?;
    let protocol_version = reader.read_u16()?;
    let cluster_id = reader.read_string()?;
    let topology_epoch = reader.read_u64()?;
    let execution_version = reader.read_u64()?;
    let source_node_id = reader.read_string()?;
    let target_node_id = reader.read_string()?;
    let request_id = ControlRequestId(reader.read_array()?);
    let deadline_unix_ms = reader.read_u64()?;
    let body = match reader.read_u8()? {
        0 => ControlRequestBody::Probe,
        _ => return protocol("control request has an unknown body tag"),
    };
    reader.finish()?;
    Ok(ControlRequest {
        protocol_version,
        cluster_id,
        topology_epoch,
        execution_version,
        source_node_id,
        target_node_id,
        request_id,
        deadline_unix_ms,
        body,
    })
}

pub(super) fn encode_response(response: &ControlResponse) -> Result<Vec<u8>, ClusterError> {
    let mut output = Vec::with_capacity(128);
    output.extend_from_slice(RESPONSE_MAGIC);
    output.extend_from_slice(&response.protocol_version.to_be_bytes());
    push_string(&mut output, &response.cluster_id)?;
    output.extend_from_slice(&response.topology_epoch.to_be_bytes());
    output.extend_from_slice(&response.execution_version.to_be_bytes());
    push_string(&mut output, &response.source_node_id)?;
    push_string(&mut output, &response.target_node_id)?;
    output.extend_from_slice(&response.request_id.0);
    match response.body {
        ControlResponseBody::Pong => output.push(0),
        ControlResponseBody::Rejected { code } => {
            output.push(1);
            output.push(reject_code_tag(code));
        }
    }
    Ok(output)
}

pub(super) fn decode_response(encoded: &[u8]) -> Result<ControlResponse, ClusterError> {
    let mut reader = WireReader::new(encoded);
    reader.expect_magic(RESPONSE_MAGIC)?;
    let protocol_version = reader.read_u16()?;
    let cluster_id = reader.read_string()?;
    let topology_epoch = reader.read_u64()?;
    let execution_version = reader.read_u64()?;
    let source_node_id = reader.read_string()?;
    let target_node_id = reader.read_string()?;
    let request_id = ControlRequestId(reader.read_array()?);
    let body = match reader.read_u8()? {
        0 => ControlResponseBody::Pong,
        1 => ControlResponseBody::Rejected {
            code: reject_code_from_tag(reader.read_u8()?)?,
        },
        _ => return protocol("control response has an unknown body tag"),
    };
    reader.finish()?;
    Ok(ControlResponse {
        protocol_version,
        cluster_id,
        topology_epoch,
        execution_version,
        source_node_id,
        target_node_id,
        request_id,
        body,
    })
}

fn push_string(output: &mut Vec<u8>, value: &str) -> Result<(), ClusterError> {
    if !valid_identifier(value) {
        return protocol("control wire identifier is invalid");
    }
    let length = u16::try_from(value.len())
        .map_err(|_| ClusterError::Protocol("control wire identifier is too large".to_owned()))?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

const fn reject_code_tag(code: ControlRejectCode) -> u8 {
    match code {
        ControlRejectCode::InvalidEnvelope => 0,
        ControlRejectCode::DeadlineElapsed => 1,
        ControlRejectCode::DeadlineTooFar => 2,
        ControlRejectCode::ClusterMismatch => 3,
        ControlRejectCode::SourceIdentityMismatch => 4,
        ControlRejectCode::TargetMismatch => 5,
        ControlRejectCode::MembershipPending => 6,
        ControlRejectCode::TopologyStale => 7,
        ControlRejectCode::TopologyAhead => 8,
        ControlRejectCode::ExecutionStale => 9,
        ControlRejectCode::ExecutionAhead => 10,
        ControlRejectCode::HandlerFailed => 11,
    }
}

fn reject_code_from_tag(tag: u8) -> Result<ControlRejectCode, ClusterError> {
    match tag {
        0 => Ok(ControlRejectCode::InvalidEnvelope),
        1 => Ok(ControlRejectCode::DeadlineElapsed),
        2 => Ok(ControlRejectCode::DeadlineTooFar),
        3 => Ok(ControlRejectCode::ClusterMismatch),
        4 => Ok(ControlRejectCode::SourceIdentityMismatch),
        5 => Ok(ControlRejectCode::TargetMismatch),
        6 => Ok(ControlRejectCode::MembershipPending),
        7 => Ok(ControlRejectCode::TopologyStale),
        8 => Ok(ControlRejectCode::TopologyAhead),
        9 => Ok(ControlRejectCode::ExecutionStale),
        10 => Ok(ControlRejectCode::ExecutionAhead),
        11 => Ok(ControlRejectCode::HandlerFailed),
        _ => protocol("control response has an unknown rejection code"),
    }
}

struct WireReader<'a> {
    encoded: &'a [u8],
    offset: usize,
}

impl<'a> WireReader<'a> {
    const fn new(encoded: &'a [u8]) -> Self {
        Self { encoded, offset: 0 }
    }

    fn read(&mut self, length: usize) -> Result<&'a [u8], ClusterError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| ClusterError::Protocol("control frame length overflows".to_owned()))?;
        let value = self
            .encoded
            .get(self.offset..end)
            .ok_or_else(|| ClusterError::Protocol("control frame is truncated".to_owned()))?;
        self.offset = end;
        Ok(value)
    }

    fn expect_magic(&mut self, expected: &[u8; 4]) -> Result<(), ClusterError> {
        if self.read(expected.len())? != expected {
            return protocol("control frame has invalid magic");
        }
        Ok(())
    }

    fn read_u8(&mut self) -> Result<u8, ClusterError> {
        Ok(self.read(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, ClusterError> {
        Ok(u16::from_be_bytes(self.read_array()?))
    }

    fn read_u64(&mut self) -> Result<u64, ClusterError> {
        Ok(u64::from_be_bytes(self.read_array()?))
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], ClusterError> {
        self.read(N)?
            .try_into()
            .map_err(|_| ClusterError::Protocol("control frame field has wrong size".to_owned()))
    }

    fn read_string(&mut self) -> Result<String, ClusterError> {
        let length = usize::from(self.read_u16()?);
        if length == 0 || length > MAX_CONTROL_ID_BYTES {
            return protocol("control frame identifier exceeds its bound");
        }
        let value = std::str::from_utf8(self.read(length)?).map_err(|_| {
            ClusterError::Protocol("control frame identifier is not UTF-8".to_owned())
        })?;
        if !valid_identifier(value) {
            return protocol("control frame identifier is invalid");
        }
        Ok(value.to_owned())
    }

    fn finish(self) -> Result<(), ClusterError> {
        if self.offset != self.encoded.len() {
            return protocol("control frame has trailing bytes");
        }
        Ok(())
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CONTROL_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn protocol<T>(message: impl Into<String>) -> Result<T, ClusterError> {
    Err(ClusterError::Protocol(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> ControlRequest {
        ControlRequest {
            protocol_version: CLUSTER_PROTOCOL_VERSION,
            cluster_id: "cluster-a".to_owned(),
            topology_epoch: 3,
            execution_version: 7,
            source_node_id: "node-a".to_owned(),
            target_node_id: "node-b".to_owned(),
            request_id: ControlRequestId([9; 16]),
            deadline_unix_ms: 2_000,
            body: ControlRequestBody::Probe,
        }
    }

    #[test]
    fn request_deadline_and_identity_are_bounded_before_dispatch() {
        let mut candidate = request();
        assert_eq!(candidate.validate_untrusted(1_000), Ok(()));
        candidate.deadline_unix_ms = 1_000;
        assert_eq!(
            candidate.validate_untrusted(1_000),
            Err(ControlRejectCode::DeadlineElapsed)
        );
        candidate = request();
        candidate.deadline_unix_ms = 1_000 + MAX_CONTROL_DEADLINE_MS + 1;
        assert_eq!(
            candidate.validate_untrusted(1_000),
            Err(ControlRejectCode::DeadlineTooFar)
        );
        candidate = request();
        candidate.source_node_id = "x".repeat(MAX_CONTROL_ID_BYTES + 1);
        assert_eq!(
            candidate.validate_untrusted(1_000),
            Err(ControlRejectCode::InvalidEnvelope)
        );
    }

    #[test]
    fn response_is_bound_to_request_identity() {
        let request = request();
        let mut response = ControlResponse {
            protocol_version: CLUSTER_PROTOCOL_VERSION,
            cluster_id: request.cluster_id.clone(),
            topology_epoch: request.topology_epoch,
            execution_version: request.execution_version,
            source_node_id: request.target_node_id.clone(),
            target_node_id: request.source_node_id.clone(),
            request_id: request.request_id,
            body: ControlResponseBody::Pong,
        };
        response.validate_for(&request).unwrap();
        response.target_node_id = "node-c".to_owned();
        assert!(matches!(
            response.validate_for(&request),
            Err(ClusterError::Protocol(_))
        ));
    }

    #[test]
    fn control_wire_enums_are_snake_case() {
        assert_eq!(
            serde_json::to_string(&ControlRequestBody::Probe).unwrap(),
            "\"probe\""
        );
        assert_eq!(
            serde_json::to_string(&ControlRejectCode::TopologyStale).unwrap(),
            "\"topology_stale\""
        );
    }

    #[test]
    fn binary_wire_round_trips_without_unbounded_length_directed_allocations() {
        let request = request();
        assert_eq!(
            decode_request(&encode_request(&request).unwrap()).unwrap(),
            request
        );

        let response = ControlResponse {
            protocol_version: CLUSTER_PROTOCOL_VERSION,
            cluster_id: request.cluster_id.clone(),
            topology_epoch: request.topology_epoch,
            execution_version: request.execution_version,
            source_node_id: request.target_node_id.clone(),
            target_node_id: request.source_node_id.clone(),
            request_id: request.request_id,
            body: ControlResponseBody::Rejected {
                code: ControlRejectCode::ExecutionStale,
            },
        };
        assert_eq!(
            decode_response(&encode_response(&response).unwrap()).unwrap(),
            response
        );
    }

    #[test]
    fn binary_wire_rejects_truncation_and_trailing_bytes() {
        let encoded = encode_request(&request()).unwrap();
        assert!(matches!(
            decode_request(&encoded[..encoded.len() - 1]),
            Err(ClusterError::Protocol(_))
        ));
        let mut trailing = encoded;
        trailing.push(0);
        assert!(matches!(
            decode_request(&trailing),
            Err(ClusterError::Protocol(_))
        ));
    }
}
