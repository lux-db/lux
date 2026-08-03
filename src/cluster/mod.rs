//! Cluster is Lux's optional, capacity-oriented multi-node routing layer.
//!
//! The normal single-node engine does not construct any of these types. When
//! enabled, a signed topology maps a fixed slot space to ordinary Lux runtimes;
//! the data engine and persistence formats remain the same on every node.

mod config;
mod protocol;
mod routing;
mod topology;

pub(crate) mod transport;

pub use config::ClusterConfig;
pub use protocol::{
    PeerRequest, PeerRequestBody, PeerResponse, PeerResponseBody, RequestId,
    CLUSTER_PROTOCOL_VERSION,
};
pub(crate) use routing::{classify_command, routed_table, CommandRoute};
pub use topology::{
    certificate_fingerprint, slot_for_key, slot_for_table_row, CompiledTopology, NodeDescriptor,
    SignedTopology, SlotAssignment, TopologyManifest, TopologyState, CLUSTER_SLOT_COUNT,
    CLUSTER_TOPOLOGY_SCHEMA_VERSION,
};

use std::fmt;
use std::future::Future;
use std::sync::Arc;

pub(crate) struct RemoteTarget {
    pub(crate) node_id: String,
    pub(crate) slot: Option<u16>,
    pub(crate) read_only: bool,
}

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

    pub(crate) fn remote_target(&self, argv: &[&[u8]]) -> Result<Option<RemoteTarget>, String> {
        let topology = self.topology.current();
        let (target, slot, read_only) = match classify_command(argv) {
            CommandRoute::Local => return Ok(None),
            CommandRoute::System { read_only } => {
                (topology.manifest().system_node_id.as_str(), None, read_only)
            }
            CommandRoute::Slot { slot, read_only } => (
                topology.owner_for_slot(slot).node_id.as_str(),
                Some(slot),
                read_only,
            ),
            CommandRoute::Unsupported(message) => return Err(message),
        };
        if target == self.local_node_id {
            return Ok(None);
        }
        Ok(Some(RemoteTarget {
            node_id: target.to_string(),
            slot,
            read_only,
        }))
    }

    pub(crate) fn remote_table_target(
        &self,
        table: &[u8],
        primary_key: &[u8],
        read_only: bool,
    ) -> Option<RemoteTarget> {
        let topology = self.topology.current();
        let slot = slot_for_table_row(table, primary_key);
        let target = &topology.owner_for_slot(slot).node_id;
        (target != &self.local_node_id).then(|| RemoteTarget {
            node_id: target.clone(),
            slot: Some(slot),
            read_only,
        })
    }

    pub(crate) async fn execute_remote(
        &self,
        target: RemoteTarget,
        argv: Vec<Vec<u8>>,
        catalog: Option<Vec<u8>>,
        table_primary_key: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, String> {
        let topology = self.topology.current();
        let request = PeerRequest {
            protocol_version: CLUSTER_PROTOCOL_VERSION,
            cluster_id: topology.manifest().cluster_id.clone(),
            topology_epoch: topology.manifest().epoch,
            source_node_id: self.local_node_id.clone(),
            target_node_id: target.node_id.clone(),
            request_id: RequestId::random(),
            deadline_unix_ms: transport::unix_time_ms() + 5_000,
            slot: target.slot,
            catalog_version: topology.manifest().catalog_version,
            body: PeerRequestBody::Execute {
                argv,
                read_only: target.read_only,
                catalog,
                table_primary_key,
            },
        };
        let response = self
            .transport
            .request(&target.node_id, &request)
            .await
            .map_err(|error| {
                if target.read_only {
                    format!("TRYAGAIN Cluster peer request failed: {error}")
                } else {
                    format!(
                        "OUTCOMEUNKNOWN Cluster mutation did not receive a response; do not retry blindly: {error}"
                    )
                }
            })?;
        match response.body {
            PeerResponseBody::Ok(bytes) => Ok(bytes),
            PeerResponseBody::Moved {
                owner_node_id,
                epoch,
            } => Err(format!(
                "MOVED Cluster topology epoch {epoch} routes this command to {owner_node_id}"
            )),
            PeerResponseBody::Fenced { epoch } => Err(format!(
                "TRYAGAIN Cluster topology epoch {epoch} fenced the request"
            )),
            PeerResponseBody::CatalogStale { required_version } => Err(format!(
                "TRYAGAIN Cluster catalog version {required_version} is required"
            )),
            PeerResponseBody::Error { message } => Err(message),
            PeerResponseBody::OutcomeUnknown { message } => {
                Err(format!("OUTCOMEUNKNOWN {message}"))
            }
        }
    }

    pub(crate) async fn serve<F, Fut>(self: Arc<Self>, execute: F)
    where
        F: Fn(PeerRequest) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = PeerResponseBody> + Send + 'static,
    {
        let node = self.clone();
        self.transport
            .clone()
            .serve(move |_source, request| {
                let node = node.clone();
                let execute = execute.clone();
                async move {
                    let topology = node.topology.current();
                    let body = match &request.body {
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
                        PeerRequestBody::Execute { .. } => match node.validate_peer_route(&request) {
                            Ok(()) => execute(request.clone()).await,
                            Err(body) => body,
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

    fn validate_peer_route(&self, request: &PeerRequest) -> Result<(), PeerResponseBody> {
        let PeerRequestBody::Execute {
            argv,
            read_only,
            catalog,
            table_primary_key,
        } = &request.body
        else {
            return Ok(());
        };
        let topology = self.topology.current();
        if request.catalog_version != topology.manifest().catalog_version {
            return Err(PeerResponseBody::CatalogStale {
                required_version: topology.manifest().catalog_version,
            });
        }
        let refs = argv.iter().map(Vec::as_slice).collect::<Vec<_>>();
        if let Some(primary_key) = table_primary_key {
            let Some(catalog) = catalog.as_deref() else {
                return Err(PeerResponseBody::Error {
                    message: "Cluster routed table command has no catalog".to_string(),
                });
            };
            if request.source_node_id != topology.manifest().system_node_id {
                return Err(PeerResponseBody::Error {
                    message: "Cluster table routes must come from the signed system node"
                        .to_string(),
                });
            }
            let (table, expected_read_only) =
                crate::tables::validate_cluster_routed_table_command(catalog, &refs, primary_key)
                    .map_err(|message| PeerResponseBody::Error { message })?;
            let slot = slot_for_table_row(table.as_bytes(), primary_key);
            if request.slot != Some(slot) || expected_read_only != *read_only {
                return Err(PeerResponseBody::Error {
                    message: "Cluster peer table route metadata mismatch".to_string(),
                });
            }
            let owner = topology.owner_for_slot(slot);
            if owner.node_id != self.local_node_id {
                return Err(PeerResponseBody::Moved {
                    owner_node_id: owner.node_id.clone(),
                    epoch: topology.manifest().epoch,
                });
            }
            return Ok(());
        }
        if catalog.is_some() {
            return Err(PeerResponseBody::Error {
                message: "Cluster catalog context requires a verified table route".to_string(),
            });
        }
        match classify_command(&refs) {
            CommandRoute::System {
                read_only: expected,
            } => {
                if request.slot.is_some() || expected != *read_only {
                    return Err(PeerResponseBody::Error {
                        message: "Cluster peer system route metadata mismatch".to_string(),
                    });
                }
                if topology.manifest().system_node_id != self.local_node_id {
                    return Err(PeerResponseBody::Moved {
                        owner_node_id: topology.manifest().system_node_id.clone(),
                        epoch: topology.manifest().epoch,
                    });
                }
            }
            CommandRoute::Slot {
                slot,
                read_only: expected,
            } => {
                if request.slot != Some(slot) || expected != *read_only {
                    return Err(PeerResponseBody::Error {
                        message: "Cluster peer slot route metadata mismatch".to_string(),
                    });
                }
                let owner = topology.owner_for_slot(slot);
                if owner.node_id != self.local_node_id {
                    return Err(PeerResponseBody::Moved {
                        owner_node_id: owner.node_id.clone(),
                        epoch: topology.manifest().epoch,
                    });
                }
                if routed_table(&refs).is_some() {
                    return Err(PeerResponseBody::Error {
                        message: "Cluster table command has no verified primary-key route"
                            .to_string(),
                    });
                }
            }
            CommandRoute::Local => {
                return Err(PeerResponseBody::Error {
                    message: "connection-local commands cannot be forwarded over Cluster"
                        .to_string(),
                });
            }
            CommandRoute::Unsupported(message) => {
                return Err(PeerResponseBody::Error { message });
            }
        }
        Ok(())
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
