mod metrics;
mod topology;
mod topology_state;

pub use metrics::{
    RouteCounterSnapshot, RouteCounterValues, RouteCounters, ROUTE_SNAPSHOT_SCHEMA_VERSION,
};
pub use topology::{
    certificate_fingerprint, encode_controller_public_key, slot_for_key, slot_for_table_row,
    CompiledTopology, NodeDescriptor, RedisSlotRange, SignedTopology, SlotAssignment, SlotMove,
    TopologyManifest, TopologyTransitionKind, TopologyTransitionPlan, CLUSTER_CLIENT_SLOT_COUNT,
    CLUSTER_MAX_NODES, CLUSTER_SLOT_COUNT, CLUSTER_TOPOLOGY_SCHEMA_VERSION,
};
pub use topology_state::{TopologySnapshot, TopologyState};

pub const CLUSTER_PROTOCOL_VERSION: u16 = 1;

#[derive(Debug)]
pub enum ClusterError {
    InvalidTopology(String),
    Signature(String),
    Io(std::io::Error),
    Json(serde_json::Error),
}

impl std::fmt::Display for ClusterError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTopology(message) => {
                write!(formatter, "invalid cluster topology: {message}")
            }
            Self::Signature(message) => write!(formatter, "cluster signature error: {message}"),
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
            Self::InvalidTopology(_) | Self::Signature(_) => None,
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
