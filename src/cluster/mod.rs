//! Cluster is Lux's optional, capacity-oriented multi-node routing layer.
//!
//! The normal single-node engine does not construct any of these types. When
//! enabled, a signed topology maps a fixed slot space to ordinary Lux runtimes;
//! the data engine and persistence formats remain the same on every node.

mod config;
mod protocol;
mod topology;

pub(crate) mod transport;

pub use config::ClusterConfig;
pub use protocol::{
    PeerRequest, PeerRequestBody, PeerResponse, PeerResponseBody, RequestId,
    CLUSTER_PROTOCOL_VERSION,
};
pub use topology::{
    certificate_fingerprint, slot_for_key, slot_for_table_row, CompiledTopology, NodeDescriptor,
    SignedTopology, SlotAssignment, TopologyManifest, TopologyState, CLUSTER_SLOT_COUNT,
    CLUSTER_TOPOLOGY_SCHEMA_VERSION,
};

use std::fmt;
use std::sync::Arc;

pub(crate) struct ClusterNode {
    pub(crate) local_node_id: String,
    pub(crate) topology: Arc<TopologyState>,
    pub(crate) transport: Arc<transport::PeerTransport>,
}

impl ClusterNode {
    pub(crate) fn bind(config: &ClusterConfig) -> Result<Arc<Self>, ClusterError> {
        let compiled = config
            .load_topology()?
            .verify(&config.controller_public_key)?;
        if compiled.node(&config.local_node_id).is_none() {
            return Err(ClusterError::InvalidConfig(format!(
                "local node {} is absent from topology epoch {}",
                config.local_node_id,
                compiled.manifest().epoch
            )));
        }
        let topology = Arc::new(TopologyState::open(
            compiled,
            config.controller_public_key.clone(),
            &config.topology_state_path,
        )?);
        let transport = transport::PeerTransport::bind(config, topology.clone())?;
        Ok(Arc::new(Self {
            local_node_id: config.local_node_id.clone(),
            topology,
            transport,
        }))
    }

    pub(crate) async fn serve_foundation(self: Arc<Self>) {
        let node = self.clone();
        self.transport
            .clone()
            .serve(move |_source, request| {
                let node = node.clone();
                async move {
                    let topology = node.topology.current();
                    let body = match request.body {
                        PeerRequestBody::Probe => PeerResponseBody::Ok(b"PONG".to_vec()),
                        PeerRequestBody::Status => PeerResponseBody::Ok(
                            serde_json::to_vec(&serde_json::json!({
                                "node_id": node.local_node_id,
                                "cluster_id": topology.manifest().cluster_id,
                                "epoch": topology.manifest().epoch,
                                "catalog_version": topology.manifest().catalog_version,
                                "slots": topology.manifest().assignments.iter()
                                    .filter(|assignment| assignment.node_id == node.local_node_id)
                                    .map(|assignment| u64::from(assignment.end - assignment.start) + 1)
                                    .sum::<u64>(),
                            }))
                            .unwrap_or_default(),
                        ),
                        PeerRequestBody::Execute { .. } => PeerResponseBody::Error {
                            message: "peer execution is not enabled by this engine build"
                                .to_string(),
                        },
                    };
                    PeerResponse {
                        protocol_version: CLUSTER_PROTOCOL_VERSION,
                        request_id: request.request_id,
                        topology_epoch: topology.manifest().epoch,
                        body,
                    }
                }
            })
            .await;
    }

    pub(crate) async fn probe_peers(self: Arc<Self>) {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            let topology = self.topology.current();
            for peer in &topology.manifest().nodes {
                if peer.node_id == self.local_node_id {
                    continue;
                }
                let request = PeerRequest {
                    protocol_version: CLUSTER_PROTOCOL_VERSION,
                    cluster_id: topology.manifest().cluster_id.clone(),
                    topology_epoch: topology.manifest().epoch,
                    source_node_id: self.local_node_id.clone(),
                    target_node_id: peer.node_id.clone(),
                    request_id: RequestId::random(),
                    deadline_unix_ms: transport::unix_time_ms() + 3_000,
                    slot: None,
                    catalog_version: topology.manifest().catalog_version,
                    body: PeerRequestBody::Probe,
                };
                // Availability metrics consume these results in the routing PR.
                // A peer being offline must never stop this node's local slots.
                let _ = self.transport.request(&peer.node_id, &request).await;
            }
        }
    }
}

/// Errors raised before a request reaches the ordinary Lux execution path.
#[derive(Debug)]
pub enum ClusterError {
    Io(std::io::Error),
    Json(serde_json::Error),
    InvalidConfig(String),
    InvalidTopology(String),
    Signature(String),
    Protocol(String),
    Transport(String),
}

impl fmt::Display for ClusterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "{error}"),
            Self::Json(error) => write!(f, "{error}"),
            Self::InvalidConfig(message) => write!(f, "invalid Cluster config: {message}"),
            Self::InvalidTopology(message) => write!(f, "invalid Cluster topology: {message}"),
            Self::Signature(message) => write!(f, "invalid Cluster signature: {message}"),
            Self::Protocol(message) => write!(f, "Cluster protocol error: {message}"),
            Self::Transport(message) => write!(f, "Cluster transport error: {message}"),
        }
    }
}

impl std::error::Error for ClusterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Json(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ClusterError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for ClusterError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}
