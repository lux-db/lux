use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

pub const CLUSTER_PROTOCOL_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct RequestId(pub [u8; 16]);

impl RequestId {
    pub fn random() -> Self {
        let mut bytes = [0u8; 16];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PeerRequest {
    pub protocol_version: u16,
    pub cluster_id: String,
    pub topology_epoch: u64,
    pub source_node_id: String,
    pub target_node_id: String,
    pub request_id: RequestId,
    /// Absolute Unix time in milliseconds. Receivers reject expired work before execution.
    pub deadline_unix_ms: u64,
    pub slot: Option<u16>,
    pub catalog_version: u64,
    pub body: PeerRequestBody,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PeerRequestBody {
    Probe,
    Status,
    Execute {
        argv: Vec<Vec<u8>>,
        read_only: bool,
        /// Authoritative table schema supplied only by the signed system node.
        /// Slot owners durably install it before executing a table-row command.
        catalog: Option<Vec<u8>>,
        /// Logical table primary key used for the route. Receivers derive it
        /// again from `argv` plus `catalog`; this field is never trusted alone.
        table_primary_key: Option<Vec<u8>>,
    },
    /// Read-only user-table query broadcast by the signed system node. Every
    /// peer returns a structured shard partial; only the system node merges it.
    TableScan {
        argv: Vec<Vec<u8>>,
        catalog: Vec<u8>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PeerResponse {
    pub protocol_version: u16,
    pub request_id: RequestId,
    pub topology_epoch: u64,
    pub body: PeerResponseBody,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum TableScanPartial {
    Count(i64),
    Rows(Vec<Vec<(String, String)>>),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PeerResponseBody {
    Ok(Vec<u8>),
    TableScan(TableScanPartial),
    Moved { owner_node_id: String, epoch: u64 },
    Fenced { epoch: u64 },
    CatalogStale { required_version: u64 },
    Error { message: String },
    OutcomeUnknown { message: String },
}

impl PeerRequest {
    pub fn validate_envelope(&self, now_unix_ms: u64) -> Result<(), &'static str> {
        if self.protocol_version != CLUSTER_PROTOCOL_VERSION {
            return Err("unsupported protocol version");
        }
        if self.cluster_id.is_empty()
            || self.source_node_id.is_empty()
            || self.target_node_id.is_empty()
        {
            return Err("cluster and node ids are required");
        }
        if self.deadline_unix_ms <= now_unix_ms {
            return Err("request deadline elapsed");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messagepack_round_trip_preserves_binary_argv() {
        let request = PeerRequest {
            protocol_version: CLUSTER_PROTOCOL_VERSION,
            cluster_id: "cluster-a".into(),
            topology_epoch: 7,
            source_node_id: "node-a".into(),
            target_node_id: "node-b".into(),
            request_id: RequestId([3; 16]),
            deadline_unix_ms: 500,
            slot: Some(42),
            catalog_version: 9,
            body: PeerRequestBody::Execute {
                argv: vec![b"SET".to_vec(), vec![0, 255], b"value".to_vec()],
                read_only: false,
                catalog: None,
                table_primary_key: None,
            },
        };
        let encoded = rmp_serde::to_vec_named(&request).unwrap();
        let decoded: PeerRequest = rmp_serde::from_slice(&encoded).unwrap();
        assert_eq!(decoded, request);
    }

    #[test]
    fn expired_work_is_rejected_before_dispatch() {
        let request = PeerRequest {
            protocol_version: CLUSTER_PROTOCOL_VERSION,
            cluster_id: "cluster-a".into(),
            topology_epoch: 1,
            source_node_id: "a".into(),
            target_node_id: "b".into(),
            request_id: RequestId([0; 16]),
            deadline_unix_ms: 100,
            slot: None,
            catalog_version: 0,
            body: PeerRequestBody::Probe,
        };
        assert_eq!(
            request.validate_envelope(100),
            Err("request deadline elapsed")
        );
    }

    #[test]
    fn table_scan_wire_types_round_trip_without_resp_reencoding() {
        let request = PeerRequest {
            protocol_version: CLUSTER_PROTOCOL_VERSION,
            cluster_id: "cluster-a".into(),
            topology_epoch: 8,
            source_node_id: "system".into(),
            target_node_id: "data".into(),
            request_id: RequestId([4; 16]),
            deadline_unix_ms: 1_000,
            slot: None,
            catalog_version: 3,
            body: PeerRequestBody::TableScan {
                argv: vec![b"TCOUNT".to_vec(), b"orders".to_vec()],
                catalog: vec![0, 1, 255],
            },
        };
        let request: PeerRequest =
            rmp_serde::from_slice(&rmp_serde::to_vec_named(&request).unwrap()).unwrap();
        assert!(matches!(request.body, PeerRequestBody::TableScan { .. }));

        let response = PeerResponse {
            protocol_version: CLUSTER_PROTOCOL_VERSION,
            request_id: request.request_id,
            topology_epoch: 8,
            body: PeerResponseBody::TableScan(TableScanPartial::Rows(vec![vec![(
                "id".to_string(),
                "order-1".to_string(),
            )]])),
        };
        let decoded: PeerResponse =
            rmp_serde::from_slice(&rmp_serde::to_vec_named(&response).unwrap()).unwrap();
        assert_eq!(decoded, response);
    }
}
