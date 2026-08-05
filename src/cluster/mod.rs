mod control;
mod durable_state;
mod execution;
mod execution_state;
mod execution_wire;
mod metrics;
mod serving_state;
mod signature;
mod topology;
mod topology_state;
mod transfer;
mod transfer_coordinator;
mod transfer_dirty;
mod transfer_journal;
pub(crate) mod transfer_record;
mod transfer_runtime;
mod transfer_stage;
mod transfer_stream;
mod transport;

pub use control::{
    ControlRejectCode, ControlRequest, ControlRequestBody, ControlRequestId, ControlResponse,
    ControlResponseBody, MAX_CONTROL_DEADLINE_MS,
};
pub use execution::{
    CompiledExecution, ExecutionApiKey, ExecutionApiKeyKind, ExecutionAuth, ExecutionField,
    ExecutionGrant, ExecutionGrantScope, ExecutionJwtKey, ExecutionManifest, ExecutionPathIndex,
    ExecutionPrincipalBlock, ExecutionPrincipalBlockKind, ExecutionSessionRevocation,
    ExecutionTable, SignedExecution, CLUSTER_EXECUTION_SCHEMA_VERSION,
};
pub use execution_state::{ExecutionSnapshot, ExecutionState};
pub use metrics::{
    RouteCounterSnapshot, RouteCounterValues, RouteCounters, ROUTE_SNAPSHOT_SCHEMA_VERSION,
};
pub use serving_state::{ServingSnapshot, ServingState};
pub use signature::encode_controller_public_key;
pub use topology::{
    certificate_fingerprint, slot_for_key, slot_for_table_row, CompiledTopology, NodeDescriptor,
    RedisSlotRange, SignedTopology, SlotAssignment, SlotMove, TopologyManifest,
    TopologyTransitionKind, TopologyTransitionPlan, CLUSTER_CLIENT_SLOT_COUNT, CLUSTER_MAX_NODES,
    CLUSTER_SLOT_COUNT, CLUSTER_TOPOLOGY_SCHEMA_VERSION,
};
pub use topology_state::{TopologySnapshot, TopologyState};
pub use transfer::{
    ChunkDisposition, SlotRange, TransferChunk, TransferDescriptor, TransferId,
    TransferJournalSnapshot, TransferPhase, TransferReceipt, TransferRole,
    MAX_TRANSFER_CHUNK_BYTES,
};
pub use transfer_coordinator::{apply_target_store_transfer, SourceStoreTransfer};
pub use transfer_journal::TransferJournal;
pub use transfer_runtime::{
    DirtyStats, TransferDataKey, TransferFence, TransferFinalBatch, TransferRuntime,
    TransferRuntimeConfig, TransferWriteAdmission, TransferWriteGuard,
};
pub use transport::{AuthenticatedControlRequest, PeerControlConfig, PeerControlTransport};

pub const CLUSTER_PROTOCOL_VERSION: u16 = 1;

#[derive(Debug)]
pub enum ClusterError {
    InvalidConfig(String),
    InvalidTopology(String),
    InvalidExecution(String),
    InvalidTransfer(String),
    Protocol(String),
    Signature(String),
    Transport(String),
    Io(std::io::Error),
    Json(serde_json::Error),
}

impl std::fmt::Display for ClusterError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(message) => write!(formatter, "invalid cluster config: {message}"),
            Self::InvalidTopology(message) => {
                write!(formatter, "invalid cluster topology: {message}")
            }
            Self::InvalidExecution(message) => {
                write!(formatter, "invalid cluster execution metadata: {message}")
            }
            Self::InvalidTransfer(message) => {
                write!(formatter, "invalid cluster ownership transfer: {message}")
            }
            Self::Protocol(message) => write!(formatter, "cluster protocol error: {message}"),
            Self::Signature(message) => write!(formatter, "cluster signature error: {message}"),
            Self::Transport(message) => write!(formatter, "cluster transport error: {message}"),
            Self::Io(error) => write!(formatter, "cluster I/O error: {error}"),
            Self::Json(error) => write!(formatter, "cluster JSON error: {error}"),
        }
    }
}

impl std::error::Error for ClusterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::InvalidConfig(_)
            | Self::InvalidTopology(_)
            | Self::InvalidExecution(_)
            | Self::InvalidTransfer(_)
            | Self::Protocol(_)
            | Self::Signature(_)
            | Self::Transport(_) => None,
        }
    }
}

impl From<std::io::Error> for ClusterError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for ClusterError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}
