//! Cluster is Lux's optional, capacity-oriented multi-node routing layer.
//!
//! The normal single-node engine does not construct any of these types. When
//! enabled, a signed topology maps a fixed slot space to ordinary Lux runtimes;
//! the data engine and persistence formats remain the same on every node.

mod backup;
mod config;
mod protocol;
mod routing;
mod scatter;
mod topology;
mod transition;

pub(crate) mod transport;

pub use config::ClusterConfig;
pub use protocol::{
    GlobalScanPartial, PeerRequest, PeerRequestBody, PeerResponse, PeerResponseBody, RequestId,
    TableScanPartial, TimeSeriesResult, TransferCatalogProof, TransferItem, TransferReceipt,
    VectorSearchHit, CLUSTER_PROTOCOL_VERSION,
};
pub(crate) use routing::{classify_command, routed_table, CommandRoute};
pub(crate) use scatter::{global_scan_spec, GlobalScanSpec};
pub(crate) use topology::endpoint_host_port;
pub(crate) use topology::CLUSTER_CLIENT_SLOT_COUNT;
pub use topology::{
    certificate_fingerprint, slot_for_key, slot_for_table_row, CompiledTopology, NodeDescriptor,
    SignedTopology, SlotAssignment, SlotMove, TopologyManifest, TopologyState,
    TopologyTransitionKind, TopologyTransitionPlan, CLUSTER_MAX_NODES, CLUSTER_SLOT_COUNT,
    CLUSTER_TOPOLOGY_SCHEMA_VERSION,
};
pub(crate) use transition::{transfer_payload_digest, ChunkDisposition};

use base64::Engine;
use sha2::Digest;
use std::fmt;
use std::future::Future;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;

const TRANSFER_BUNDLE_SCHEMA_VERSION: u16 = 1;

#[derive(serde::Serialize, serde::Deserialize)]
struct TransferBundleChunk {
    sequence: u64,
    catalogs: Vec<TransferCatalogProof>,
    items: Vec<TransferItem>,
    digest: String,
    byte_count: u64,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct TransferBundle {
    schema_version: u16,
    transition_epoch: u64,
    route: transition::TransferRoute,
    chunks: Vec<TransferBundleChunk>,
    receipt: TransferReceipt,
}

pub(crate) struct RemoteTarget {
    pub(crate) node_id: String,
    pub(crate) slot: Option<u16>,
    pub(crate) read_only: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct BackupPartDescriptor {
    pub(crate) schema_version: u16,
    pub(crate) cluster_id: String,
    pub(crate) topology_epoch: u64,
    pub(crate) topology_sha256: String,
    pub(crate) node_id: String,
    pub(crate) system_node: bool,
    pub(crate) catalog_version: u64,
    pub(crate) assignments: Vec<SlotAssignment>,
}

pub(crate) struct ClusterNode {
    pub(crate) local_node_id: String,
    pub(crate) topology: Arc<TopologyState>,
    pub(crate) transitions: Arc<transition::TransitionState>,
    pub(crate) transport: Arc<transport::PeerTransport>,
    backup_control: Arc<std::sync::Mutex<()>>,
    backup_prepare: Arc<std::sync::Mutex<()>>,
    backups: Arc<backup::BackupCoordinator>,
}

pub(crate) enum BackupControlError {
    Forbidden,
    Cluster(ClusterError),
}

impl From<ClusterError> for BackupControlError {
    fn from(error: ClusterError) -> Self {
        Self::Cluster(error)
    }
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
        let transition_plan = topology.transition_plan()?;
        let transitions = Arc::new(transition::TransitionState::open(
            config.local_node_id.clone(),
            &config.topology_state_path,
            topology.current().manifest().epoch,
            transition_plan.as_ref(),
        )?);
        let transport = transport::PeerTransport::bind(config, topology.clone())?;
        Ok(Arc::new(Self {
            local_node_id: config.local_node_id.clone(),
            topology,
            transitions,
            transport,
            backup_control: Arc::new(std::sync::Mutex::new(())),
            backup_prepare: Arc::new(std::sync::Mutex::new(())),
            backups: Arc::new(backup::BackupCoordinator::default()),
        }))
    }

    pub(crate) fn prepare_topology(
        &self,
        signed: SignedTopology,
    ) -> Result<TopologyTransitionPlan, ClusterError> {
        let _backup_control = self
            .backup_control
            .lock()
            .map_err(|_| ClusterError::Protocol("backup control lock is poisoned".to_string()))?;
        let epoch = self.topology.prepare(signed)?;
        let plan = self.topology.transition_plan()?.ok_or_else(|| {
            ClusterError::InvalidTopology("prepared topology has no transition plan".to_string())
        })?;
        if let Err(error) = self.transitions.prepare(&plan) {
            let _ = self.topology.abort(epoch);
            return Err(error);
        }
        if let Err(error) = self.transport.refresh_server_trust() {
            let _ = self.topology.abort(epoch);
            let _ = self.transitions.abort(epoch);
            return Err(error);
        }
        Ok(plan)
    }

    pub(crate) fn prepare_backup(
        self: &Arc<Self>,
        store: Arc<crate::store::Store>,
        cache: crate::tables::SharedSchemaCache,
        backup_id: &str,
        credential: &str,
    ) -> Result<BackupPartDescriptor, BackupControlError> {
        let _prepare = self.backup_prepare.lock().map_err(|_| {
            ClusterError::Protocol("backup preparation lock is poisoned".to_string())
        })?;
        self.backups.expire_old_session()?;
        match self.backups.access(backup_id, credential)? {
            backup::SessionAccess::Authorized => {}
            backup::SessionAccess::Forbidden => return Err(BackupControlError::Forbidden),
            backup::SessionAccess::Conflict => {
                return Err(
                    ClusterError::Protocol("another cluster backup is active".to_string()).into(),
                );
            }
            backup::SessionAccess::Missing => {
                let allowed = match crate::auth::resolve_credential(
                    credential,
                    "",
                    crate::auth::Surface::Http,
                    &store,
                    &cache,
                ) {
                    Ok(crate::auth::Credential::Operator | crate::auth::Credential::Secret) => true,
                    Ok(crate::auth::Credential::Anonymous) => {
                        store.config().password.is_empty()
                            && !crate::auth::project_keys_configured(&store, &cache)
                    }
                    _ => false,
                };
                if !allowed {
                    return Err(BackupControlError::Forbidden);
                }
            }
        }
        self.backups
            .prepare(self.clone(), store, backup_id, credential)
            .map_err(Into::into)
    }

    pub(crate) fn capture_backup(
        &self,
        backup_id: &str,
        credential: &str,
    ) -> Result<(), BackupControlError> {
        self.authorize_backup(backup_id, credential)?;
        self.backups
            .capture(backup_id)
            .map(|_| ())
            .map_err(Into::into)
    }

    pub(crate) fn release_backup(
        &self,
        backup_id: &str,
        credential: &str,
    ) -> Result<bool, BackupControlError> {
        self.authorize_backup(backup_id, credential)?;
        self.backups.release(backup_id).map_err(Into::into)
    }

    pub(crate) fn finish_backup(
        &self,
        backup_id: &str,
        credential: &str,
    ) -> Result<bool, BackupControlError> {
        self.authorize_backup(backup_id, credential)?;
        self.backups.finish(backup_id).map_err(Into::into)
    }

    pub(crate) fn backup_part(
        &self,
        backup_id: &str,
        credential: &str,
    ) -> Result<(BackupPartDescriptor, std::path::PathBuf), BackupControlError> {
        self.authorize_backup(backup_id, credential)?;
        self.backups.part(backup_id).map_err(Into::into)
    }

    fn authorize_backup(
        &self,
        backup_id: &str,
        credential: &str,
    ) -> Result<(), BackupControlError> {
        match self.backups.access(backup_id, credential)? {
            backup::SessionAccess::Authorized => Ok(()),
            backup::SessionAccess::Forbidden => Err(BackupControlError::Forbidden),
            backup::SessionAccess::Missing => Err(ClusterError::Protocol(
                "cluster backup session was not prepared".to_string(),
            )
            .into()),
            backup::SessionAccess::Conflict => {
                Err(ClusterError::Protocol("another cluster backup is active".to_string()).into())
            }
        }
    }

    pub(crate) fn commit_topology(
        &self,
        epoch: u64,
    ) -> Result<Arc<CompiledTopology>, ClusterError> {
        let plan = self
            .topology
            .transition_plan()?
            .ok_or_else(|| ClusterError::InvalidTopology("no topology is prepared".to_string()))?;
        if plan.kind == TopologyTransitionKind::Ownership
            && !self.transitions.ready_to_commit(epoch)
        {
            return Err(ClusterError::InvalidTopology(
                "slot ownership cannot commit before every durable transfer receipt is ready"
                    .to_string(),
            ));
        }
        let committed = self.topology.commit(epoch)?;
        if plan.kind == TopologyTransitionKind::Ownership {
            // The signed topology is authoritative once its fsync succeeds.
            // Keep receipts after cutover; a source may need to recover an ACK
            // from this node. If this secondary marker fails, startup or
            // finalize reconstructs it from current topology + ready receipts.
            let _ = self.transitions.mark_topology_committed(epoch);
        }
        self.transport.refresh_server_trust()?;
        Ok(committed)
    }

    pub(crate) fn abort_topology(&self, epoch: u64) -> Result<bool, ClusterError> {
        let aborted = self.topology.abort(epoch)?;
        self.transitions.abort(epoch)?;
        self.transport.refresh_server_trust()?;
        Ok(aborted)
    }

    pub(crate) fn backup_part_descriptor(&self) -> Result<BackupPartDescriptor, ClusterError> {
        if self.topology.pending().is_some() {
            return Err(ClusterError::InvalidTopology(
                "cluster backup is unavailable while a topology is prepared".to_string(),
            ));
        }
        if let Some(transfer) = self.transitions.status() {
            return Err(ClusterError::InvalidTopology(format!(
                "cluster backup is unavailable until ownership epoch {} is finalized",
                transfer.epoch
            )));
        }
        let topology = self.topology.current();
        let signed = serde_json::to_vec(topology.signed())?;
        let topology_sha256 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(signed));
        Ok(BackupPartDescriptor {
            schema_version: 1,
            cluster_id: topology.manifest().cluster_id.clone(),
            topology_epoch: topology.manifest().epoch,
            topology_sha256,
            node_id: self.local_node_id.clone(),
            system_node: topology.manifest().system_node_id == self.local_node_id,
            catalog_version: topology.manifest().catalog_version,
            assignments: topology
                .manifest()
                .assignments
                .iter()
                .filter(|assignment| assignment.node_id == self.local_node_id)
                .cloned()
                .collect(),
        })
    }

    pub(crate) fn validate_restore_part(
        &self,
        expected: &BackupPartDescriptor,
    ) -> Result<(), ClusterError> {
        let actual = self.backup_part_descriptor()?;
        if &actual != expected {
            return Err(ClusterError::InvalidTopology(
                "backup part descriptor does not match this node's committed topology".to_string(),
            ));
        }
        Ok(())
    }

    /// Finalize one locally committed ownership epoch after the controller has
    /// observed that epoch on every node. Source nodes durably delete their
    /// stale physical copies first; targets retain ACK receipts until this
    /// succeeds, so every step is safe to retry after a crash.
    pub(crate) fn finalize_topology(
        &self,
        epoch: u64,
        store: &crate::store::Store,
        cache: &crate::tables::SharedSchemaCache,
    ) -> Result<bool, ClusterError> {
        let Some(status) = self.transitions.status() else {
            return Ok(false);
        };
        if status.epoch != epoch {
            return Err(ClusterError::InvalidTopology(format!(
                "ownership transfer epoch {} does not match finalize epoch {epoch}",
                status.epoch
            )));
        }
        if !status.ready_to_commit() {
            return Err(ClusterError::InvalidTopology(
                "ownership transfer cannot finalize before durable receipts are complete"
                    .to_string(),
            ));
        }
        let topology = self.topology.current();
        if topology.manifest().epoch < epoch {
            return Err(ClusterError::InvalidTopology(format!(
                "topology epoch {} has not committed ownership epoch {epoch}",
                topology.manifest().epoch
            )));
        }
        self.transitions.mark_topology_committed(epoch)?;

        for progress in &status.outbound {
            if !progress.complete {
                return Err(ClusterError::InvalidTopology(format!(
                    "outbound transfer {} is incomplete",
                    progress.route.transfer_id
                )));
            }
            for movement in &progress.route.moves {
                for slot in movement.start..=movement.end {
                    if topology.owner_for_slot(slot).node_id != progress.route.target_node_id {
                        return Err(ClusterError::InvalidTopology(format!(
                            "slot {slot} is not committed to transfer target {}",
                            progress.route.target_node_id
                        )));
                    }
                }
            }
            let path = progress.bundle_path.as_ref().ok_or_else(|| {
                ClusterError::InvalidTopology(format!(
                    "outbound transfer {} has no durable bundle",
                    progress.route.transfer_id
                ))
            })?;
            let bundle = read_transfer_bundle(path)?;
            validate_transfer_bundle(&bundle, &progress.route, epoch)?;
            for chunk in &bundle.chunks {
                for item in &chunk.items {
                    let slot = match item {
                        TransferItem::Key { key, .. } => {
                            if key.starts_with(b"_t:") {
                                return Err(ClusterError::Protocol(
                                    "durable transfer bundle contains a reserved key".to_string(),
                                ));
                            }
                            slot_for_key(key)
                        }
                        TransferItem::TableRow {
                            table, primary_key, ..
                        } => {
                            if crate::auth::is_reserved_system_table(table) {
                                return Err(ClusterError::Protocol(
                                    "durable transfer bundle contains a reserved table".to_string(),
                                ));
                            }
                            slot_for_table_row(table.as_bytes(), primary_key.as_bytes())
                        }
                    };
                    if !progress
                        .route
                        .moves
                        .iter()
                        .any(|movement| slot >= movement.start && slot <= movement.end)
                    {
                        return Err(ClusterError::Protocol(format!(
                            "durable transfer item slot {slot} is outside its signed move"
                        )));
                    }
                    match item {
                        TransferItem::Key { key, .. } => store
                            .remove_cluster_key(key)
                            .map_err(ClusterError::Protocol)?,
                        TransferItem::TableRow {
                            table, primary_key, ..
                        } => crate::tables::remove_cluster_transfer_row(
                            store,
                            cache,
                            table,
                            primary_key,
                            std::time::Instant::now(),
                        )
                        .map_err(ClusterError::Protocol)?,
                    }
                }
            }
        }
        self.transitions.finalize(epoch)
    }

    pub(crate) async fn sync_table_catalogs(
        &self,
        store: &crate::store::Store,
        cache: &crate::tables::SharedSchemaCache,
    ) -> Result<usize, ClusterError> {
        let topology = self.topology.current();
        if topology.manifest().system_node_id != self.local_node_id {
            return Err(ClusterError::InvalidTopology(
                "table catalog sync must run on the signed system node".to_string(),
            ));
        }
        let catalogs = crate::tables::export_all_cluster_table_catalogs(
            store,
            cache,
            std::time::Instant::now(),
        )
        .map_err(ClusterError::Protocol)?;
        let mut installed = 0usize;
        for peer in &topology.manifest().nodes {
            if peer.node_id == self.local_node_id {
                continue;
            }
            for proof in &catalogs {
                let request = self.control_request(
                    &topology,
                    &peer.node_id,
                    PeerRequestBody::CatalogInstall {
                        table: proof.table.clone(),
                        catalog: proof.catalog.clone(),
                    },
                );
                match self.transport.request(&peer.node_id, &request).await?.body {
                    PeerResponseBody::Ok(_) => installed += 1,
                    PeerResponseBody::Error { message } => {
                        return Err(ClusterError::Protocol(message))
                    }
                    other => {
                        return Err(ClusterError::Protocol(format!(
                            "catalog sync returned an unexpected response: {other:?}"
                        )))
                    }
                }
            }
        }
        Ok(installed)
    }

    pub(crate) async fn run_prepared_transfers(
        &self,
        store: &crate::store::Store,
        cache: &crate::tables::SharedSchemaCache,
    ) -> Result<transition::OwnershipTransferStatus, ClusterError> {
        let plan = self
            .topology
            .transition_plan()?
            .ok_or_else(|| ClusterError::InvalidTopology("no topology is prepared".to_string()))?;
        if plan.kind != TopologyTransitionKind::Ownership {
            return Err(ClusterError::InvalidTopology(
                "prepared topology is not an ownership transition".to_string(),
            ));
        }
        for route in self.transitions.outbound_routes(plan.to_epoch)? {
            let bundle =
                self.load_or_create_transfer_bundle(&route, plan.to_epoch, store, cache)?;
            let topology = self.topology.current();
            let mut rolling_digest = String::new();
            let mut total_items = 0u64;
            let mut total_bytes = 0u64;
            for chunk in &bundle.chunks {
                let request = self.control_request(
                    &topology,
                    &route.target_node_id,
                    PeerRequestBody::TransferChunk {
                        transition_epoch: plan.to_epoch,
                        transfer_id: route.transfer_id.clone(),
                        sequence: chunk.sequence,
                        catalogs: chunk.catalogs.clone(),
                        items: chunk.items.clone(),
                    },
                );
                let frame_size = rmp_serde::to_vec_named(&request)
                    .map_err(|error| ClusterError::Protocol(error.to_string()))?
                    .len();
                if frame_size > self.transport.max_frame_bytes() {
                    return Err(ClusterError::Protocol(format!(
                        "transfer frame {frame_size} exceeds configured peer limit {}",
                        self.transport.max_frame_bytes()
                    )));
                }
                rolling_digest = transition::chain_digest(&rolling_digest, &chunk.digest);
                total_items = total_items.saturating_add(chunk.items.len() as u64);
                total_bytes = total_bytes.saturating_add(chunk.byte_count);
                let expected = TransferReceipt {
                    transfer_id: route.transfer_id.clone(),
                    chunk_count: chunk.sequence + 1,
                    rolling_digest: rolling_digest.clone(),
                    total_items,
                    total_bytes,
                };
                match self
                    .transport
                    .request(&route.target_node_id, &request)
                    .await?
                    .body
                {
                    PeerResponseBody::TransferAck { receipt, .. } if receipt == expected => {}
                    PeerResponseBody::TransferAck { .. } => {
                        return Err(ClusterError::Protocol(
                            "target transfer acknowledgement does not match the sent prefix"
                                .to_string(),
                        ))
                    }
                    PeerResponseBody::Error { message } => {
                        return Err(ClusterError::Protocol(message))
                    }
                    other => {
                        return Err(ClusterError::Protocol(format!(
                            "transfer chunk returned an unexpected response: {other:?}"
                        )))
                    }
                }
            }
            let finish = self.control_request(
                &topology,
                &route.target_node_id,
                PeerRequestBody::TransferFinish {
                    transition_epoch: plan.to_epoch,
                    receipt: bundle.receipt.clone(),
                },
            );
            match self
                .transport
                .request(&route.target_node_id, &finish)
                .await?
                .body
            {
                PeerResponseBody::TransferComplete { receipt } if receipt == bundle.receipt => {
                    self.transitions.mark_outbound_complete(&receipt)?;
                }
                PeerResponseBody::TransferComplete { .. } => {
                    return Err(ClusterError::Protocol(
                        "target completion receipt does not match the source bundle".to_string(),
                    ))
                }
                PeerResponseBody::Error { message } => return Err(ClusterError::Protocol(message)),
                other => {
                    return Err(ClusterError::Protocol(format!(
                        "transfer completion returned an unexpected response: {other:?}"
                    )))
                }
            }
        }
        self.transitions.status().ok_or_else(|| {
            ClusterError::InvalidTopology("ownership transfer state disappeared".to_string())
        })
    }

    fn control_request(
        &self,
        topology: &CompiledTopology,
        target_node_id: &str,
        body: PeerRequestBody,
    ) -> PeerRequest {
        PeerRequest {
            protocol_version: CLUSTER_PROTOCOL_VERSION,
            cluster_id: topology.manifest().cluster_id.clone(),
            topology_epoch: topology.manifest().epoch,
            source_node_id: self.local_node_id.clone(),
            target_node_id: target_node_id.to_string(),
            request_id: RequestId::random(),
            deadline_unix_ms: transport::unix_time_ms() + 30_000,
            slot: None,
            catalog_version: topology.manifest().catalog_version,
            body,
        }
    }

    fn load_or_create_transfer_bundle(
        &self,
        route: &transition::TransferRoute,
        transition_epoch: u64,
        store: &crate::store::Store,
        cache: &crate::tables::SharedSchemaCache,
    ) -> Result<TransferBundle, ClusterError> {
        if let Some(progress) = self.transitions.outbound_progress(&route.transfer_id) {
            if let Some(path) = progress.bundle_path {
                let bundle = read_transfer_bundle(&path)?;
                validate_transfer_bundle(&bundle, route, transition_epoch)?;
                return Ok(bundle);
            }
        }
        std::fs::create_dir_all(self.transitions.bundle_dir())?;
        let path = self
            .transitions
            .bundle_dir()
            .join(format!("{}-{}.mpk", transition_epoch, route.transfer_id));
        if path.exists() {
            let bundle = read_transfer_bundle(&path)?;
            validate_transfer_bundle(&bundle, route, transition_epoch)?;
            self.transitions.record_outbound_bundle(
                &bundle.receipt,
                path,
                bundle
                    .chunks
                    .iter()
                    .map(|chunk| chunk.digest.clone())
                    .collect(),
            )?;
            return Ok(bundle);
        }

        let in_route = |slot: u16| {
            route
                .moves
                .iter()
                .any(|movement| slot >= movement.start && slot <= movement.end)
        };
        let mut items = store
            .export_dump_blobs_matching(std::time::Instant::now(), |key| {
                !key.starts_with(b"_t:") && in_route(slot_for_key(key))
            })
            .map_err(ClusterError::Protocol)?
            .into_iter()
            .map(|(key, dump, expires_unix_ms)| TransferItem::Key {
                key,
                dump,
                expires_unix_ms,
            })
            .collect::<Vec<_>>();
        let (catalogs, mut table_rows) = crate::tables::export_cluster_transfer_data(
            store,
            cache,
            &|table, primary_key| {
                in_route(slot_for_table_row(table.as_bytes(), primary_key.as_bytes()))
            },
            std::time::Instant::now(),
        )
        .map_err(ClusterError::Protocol)?;
        items.append(&mut table_rows);
        items.sort_by(|left, right| {
            transfer_item_identity(left).cmp(&transfer_item_identity(right))
        });
        let chunks = build_transfer_chunks(
            items,
            &catalogs,
            self.transport
                .max_frame_bytes()
                .saturating_mul(3)
                .saturating_div(4)
                .min(4 * 1024 * 1024),
        )?;
        let mut receipt = TransferReceipt {
            transfer_id: route.transfer_id.clone(),
            chunk_count: chunks.len() as u64,
            rolling_digest: String::new(),
            total_items: 0,
            total_bytes: 0,
        };
        for chunk in &chunks {
            receipt.rolling_digest =
                transition::chain_digest(&receipt.rolling_digest, &chunk.digest);
            receipt.total_items = receipt.total_items.saturating_add(chunk.items.len() as u64);
            receipt.total_bytes = receipt.total_bytes.saturating_add(chunk.byte_count);
        }
        let bundle = TransferBundle {
            schema_version: TRANSFER_BUNDLE_SCHEMA_VERSION,
            transition_epoch,
            route: route.clone(),
            chunks,
            receipt,
        };
        write_transfer_bundle(&path, &bundle)?;
        self.transitions.record_outbound_bundle(
            &bundle.receipt,
            path,
            bundle
                .chunks
                .iter()
                .map(|chunk| chunk.digest.clone())
                .collect(),
        )?;
        Ok(bundle)
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
            PeerResponseBody::TableScan(_) => {
                Err("ERR Cluster peer returned a table scan to a point command".to_string())
            }
            PeerResponseBody::GlobalScan(_) => {
                Err("ERR Cluster peer returned a global scan to a point command".to_string())
            }
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
            PeerResponseBody::TransferAck { .. } | PeerResponseBody::TransferComplete { .. } => {
                Err("ERR Cluster peer returned a transfer response to a point command".to_string())
            }
        }
    }

    pub(crate) async fn execute_table_scan_peers(
        &self,
        argv: Vec<Vec<u8>>,
        catalog: Vec<u8>,
        decrypt_authorized: bool,
    ) -> Result<Vec<TableScanPartial>, String> {
        let topology = self.topology.current();
        if topology.manifest().system_node_id != self.local_node_id {
            return Err("ERR Cluster table scans must enter through the system node".to_string());
        }
        let mut requests = tokio::task::JoinSet::new();
        for peer in &topology.manifest().nodes {
            if peer.node_id == self.local_node_id
                || !topology
                    .manifest()
                    .assignments
                    .iter()
                    .any(|assignment| assignment.node_id == peer.node_id)
            {
                continue;
            }
            let target_node_id = peer.node_id.clone();
            let transport = self.transport.clone();
            let request = PeerRequest {
                protocol_version: CLUSTER_PROTOCOL_VERSION,
                cluster_id: topology.manifest().cluster_id.clone(),
                topology_epoch: topology.manifest().epoch,
                source_node_id: self.local_node_id.clone(),
                target_node_id: target_node_id.clone(),
                request_id: RequestId::random(),
                deadline_unix_ms: transport::unix_time_ms() + 5_000,
                slot: None,
                catalog_version: topology.manifest().catalog_version,
                body: PeerRequestBody::TableScan {
                    argv: argv.clone(),
                    catalog: catalog.clone(),
                    decrypt_authorized,
                },
            };
            requests.spawn(async move {
                let response =
                    transport
                        .request(&target_node_id, &request)
                        .await
                        .map_err(|error| {
                            format!(
                            "TRYAGAIN Cluster table scan failed on peer {target_node_id}: {error}"
                        )
                        })?;
                match response.body {
                    PeerResponseBody::TableScan(partial) => Ok(partial),
                    PeerResponseBody::GlobalScan(_) => {
                        Err("ERR Cluster peer returned a global scan to a table scan".to_string())
                    }
                    PeerResponseBody::Ok(_) => Err(
                        "ERR Cluster peer returned a command response to a table scan".to_string(),
                    ),
                    PeerResponseBody::Moved {
                        owner_node_id,
                        epoch,
                    } => Err(format!(
                        "MOVED Cluster topology epoch {epoch} routes this scan to {owner_node_id}"
                    )),
                    PeerResponseBody::Fenced { epoch } => Err(format!(
                        "TRYAGAIN Cluster topology epoch {epoch} fenced the table scan"
                    )),
                    PeerResponseBody::CatalogStale { required_version } => Err(format!(
                        "TRYAGAIN Cluster catalog version {required_version} is required"
                    )),
                    PeerResponseBody::Error { message } => Err(message),
                    PeerResponseBody::OutcomeUnknown { message } => Err(format!(
                        "TRYAGAIN read-only Cluster table scan had an unknown outcome: {message}"
                    )),
                    PeerResponseBody::TransferAck { .. }
                    | PeerResponseBody::TransferComplete { .. } => Err(
                        "ERR Cluster peer returned a transfer response to a table scan".to_string(),
                    ),
                }
            });
        }

        let mut partials = Vec::with_capacity(requests.len());
        while let Some(result) = requests.join_next().await {
            let partial = result
                .map_err(|error| format!("TRYAGAIN Cluster table scan task failed: {error}"))??;
            partials.push(partial);
        }
        Ok(partials)
    }

    pub(crate) async fn execute_global_scan_peers(
        &self,
        argv: Vec<Vec<u8>>,
    ) -> Result<Vec<GlobalScanPartial>, String> {
        let topology = self.topology.current();
        if topology.manifest().system_node_id != self.local_node_id {
            return Err("ERR Cluster global scans must enter through the system node".to_string());
        }
        let mut requests = tokio::task::JoinSet::new();
        for peer in &topology.manifest().nodes {
            if peer.node_id == self.local_node_id
                || !topology
                    .manifest()
                    .assignments
                    .iter()
                    .any(|assignment| assignment.node_id == peer.node_id)
            {
                continue;
            }
            let target_node_id = peer.node_id.clone();
            let transport = self.transport.clone();
            let request = PeerRequest {
                protocol_version: CLUSTER_PROTOCOL_VERSION,
                cluster_id: topology.manifest().cluster_id.clone(),
                topology_epoch: topology.manifest().epoch,
                source_node_id: self.local_node_id.clone(),
                target_node_id: target_node_id.clone(),
                request_id: RequestId::random(),
                deadline_unix_ms: transport::unix_time_ms() + 5_000,
                slot: None,
                catalog_version: topology.manifest().catalog_version,
                body: PeerRequestBody::GlobalScan { argv: argv.clone() },
            };
            requests.spawn(async move {
                let response =
                    transport
                        .request(&target_node_id, &request)
                        .await
                        .map_err(|error| {
                            format!(
                            "TRYAGAIN Cluster global scan failed on peer {target_node_id}: {error}"
                        )
                        })?;
                match response.body {
                    PeerResponseBody::GlobalScan(partial) => Ok(partial),
                    PeerResponseBody::Moved {
                        owner_node_id,
                        epoch,
                    } => Err(format!(
                        "MOVED Cluster topology epoch {epoch} routes this scan to {owner_node_id}"
                    )),
                    PeerResponseBody::Fenced { epoch } => Err(format!(
                        "TRYAGAIN Cluster topology epoch {epoch} fenced the global scan"
                    )),
                    PeerResponseBody::CatalogStale { required_version } => Err(format!(
                        "TRYAGAIN Cluster catalog version {required_version} is required"
                    )),
                    PeerResponseBody::Error { message } => Err(message),
                    PeerResponseBody::OutcomeUnknown { message } => Err(format!(
                        "TRYAGAIN read-only Cluster global scan had an unknown outcome: {message}"
                    )),
                    _ => {
                        Err("ERR Cluster peer returned the wrong global scan response".to_string())
                    }
                }
            });
        }
        let mut partials = Vec::with_capacity(requests.len());
        while let Some(result) = requests.join_next().await {
            partials.push(
                result.map_err(|error| format!("TRYAGAIN Cluster scan task failed: {error}"))??,
            );
        }
        Ok(partials)
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
                        PeerRequestBody::Execute { .. }
                        | PeerRequestBody::TableScan { .. }
                        | PeerRequestBody::GlobalScan { .. } => {
                            match node.validate_peer_route(&request) {
                                Ok(()) => execute(request.clone()).await,
                                Err(body) => body,
                            }
                        }
                        PeerRequestBody::CatalogInstall { .. }
                        | PeerRequestBody::TransferChunk { .. }
                        | PeerRequestBody::TransferFinish { .. } => {
                            match node.validate_peer_control(&request) {
                                Ok(()) => execute(request.clone()).await,
                                Err(body) => body,
                            }
                        }
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
        let topology = self.topology.current();
        if request.catalog_version != topology.manifest().catalog_version {
            return Err(PeerResponseBody::CatalogStale {
                required_version: topology.manifest().catalog_version,
            });
        }
        if let PeerRequestBody::TableScan { argv, catalog, .. } = &request.body {
            if request.slot.is_some()
                || request.source_node_id != topology.manifest().system_node_id
            {
                return Err(PeerResponseBody::Error {
                    message:
                        "Cluster table scans must come from the signed system node without a slot"
                            .to_string(),
                });
            }
            let refs = argv.iter().map(Vec::as_slice).collect::<Vec<_>>();
            crate::tables::validate_cluster_table_scan(catalog, &refs)
                .map_err(|message| PeerResponseBody::Error { message })?;
            return Ok(());
        }
        if let PeerRequestBody::GlobalScan { argv } = &request.body {
            if request.slot.is_some()
                || request.source_node_id != topology.manifest().system_node_id
            {
                return Err(PeerResponseBody::Error {
                    message:
                        "Cluster global scans must come from the signed system node without a slot"
                            .to_string(),
                });
            }
            let refs = argv.iter().map(Vec::as_slice).collect::<Vec<_>>();
            match global_scan_spec(&refs) {
                Ok(Some(_)) => return Ok(()),
                Ok(None) => {
                    return Err(PeerResponseBody::Error {
                        message: "command is not a supported Cluster global scan".to_string(),
                    })
                }
                Err(message) => return Err(PeerResponseBody::Error { message }),
            }
        }
        let PeerRequestBody::Execute {
            argv,
            read_only,
            catalog,
            table_primary_key,
        } = &request.body
        else {
            return Ok(());
        };
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

    fn validate_peer_control(&self, request: &PeerRequest) -> Result<(), PeerResponseBody> {
        let topology = self.topology.current();
        if request.slot.is_some() || request.catalog_version != topology.manifest().catalog_version
        {
            return Err(PeerResponseBody::Error {
                message: "Cluster control request metadata mismatch".to_string(),
            });
        }
        match &request.body {
            PeerRequestBody::CatalogInstall { table, .. } => {
                if request.source_node_id != topology.manifest().system_node_id
                    || crate::auth::is_reserved_system_table(table)
                {
                    return Err(PeerResponseBody::Error {
                        message: "Cluster catalogs may only come from the signed system node"
                            .to_string(),
                    });
                }
            }
            PeerRequestBody::TransferChunk {
                transition_epoch,
                transfer_id,
                ..
            }
            | PeerRequestBody::TransferFinish {
                transition_epoch,
                receipt: TransferReceipt { transfer_id, .. },
            } => {
                self.transitions
                    .validate_route(
                        *transition_epoch,
                        transfer_id,
                        &request.source_node_id,
                        &request.target_node_id,
                    )
                    .map_err(|error| PeerResponseBody::Error {
                        message: error.to_string(),
                    })?;
            }
            _ => {
                return Err(PeerResponseBody::Error {
                    message: "request is not a Cluster control operation".to_string(),
                })
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

fn transfer_item_identity(item: &TransferItem) -> Vec<u8> {
    match item {
        TransferItem::Key { key, .. } => {
            let mut identity = Vec::with_capacity(key.len() + 1);
            identity.push(0);
            identity.extend_from_slice(key);
            identity
        }
        TransferItem::TableRow {
            table, primary_key, ..
        } => {
            let mut identity = Vec::with_capacity(table.len() + primary_key.len() + 2);
            identity.push(1);
            identity.extend_from_slice(table.as_bytes());
            identity.push(0);
            identity.extend_from_slice(primary_key.as_bytes());
            identity
        }
    }
}

fn catalogs_for_items(
    items: &[TransferItem],
    catalogs: &[TransferCatalogProof],
) -> Result<Vec<TransferCatalogProof>, ClusterError> {
    let tables = items
        .iter()
        .filter_map(|item| match item {
            TransferItem::TableRow { table, .. } => Some(table.as_str()),
            TransferItem::Key { .. } => None,
        })
        .collect::<std::collections::BTreeSet<_>>();
    tables
        .into_iter()
        .map(|table| {
            catalogs
                .iter()
                .find(|proof| proof.table == table)
                .cloned()
                .ok_or_else(|| {
                    ClusterError::Protocol(format!(
                        "transfer row table '{table}' has no catalog proof"
                    ))
                })
        })
        .collect()
}

fn build_transfer_chunks(
    items: Vec<TransferItem>,
    catalogs: &[TransferCatalogProof],
    max_payload_bytes: usize,
) -> Result<Vec<TransferBundleChunk>, ClusterError> {
    let mut chunks = Vec::new();
    let mut current = Vec::new();
    for item in items {
        current.push(item);
        let proofs = catalogs_for_items(&current, catalogs)?;
        let (_, size) = transition::transfer_payload_digest(&proofs, &current)?;
        if size as usize <= max_payload_bytes {
            continue;
        }
        let last = current
            .pop()
            .expect("candidate chunk contains the new item");
        if current.is_empty() {
            return Err(ClusterError::Protocol(format!(
                "one transfer item exceeds the safe peer payload limit of {max_payload_bytes} bytes"
            )));
        }
        let proofs = catalogs_for_items(&current, catalogs)?;
        let (digest, byte_count) = transition::transfer_payload_digest(&proofs, &current)?;
        chunks.push(TransferBundleChunk {
            sequence: chunks.len() as u64,
            catalogs: proofs,
            items: std::mem::take(&mut current),
            digest,
            byte_count,
        });
        current.push(last);
        let proofs = catalogs_for_items(&current, catalogs)?;
        let (_, size) = transition::transfer_payload_digest(&proofs, &current)?;
        if size as usize > max_payload_bytes {
            return Err(ClusterError::Protocol(format!(
                "one transfer item exceeds the safe peer payload limit of {max_payload_bytes} bytes"
            )));
        }
    }
    if !current.is_empty() {
        let proofs = catalogs_for_items(&current, catalogs)?;
        let (digest, byte_count) = transition::transfer_payload_digest(&proofs, &current)?;
        chunks.push(TransferBundleChunk {
            sequence: chunks.len() as u64,
            catalogs: proofs,
            items: current,
            digest,
            byte_count,
        });
    }
    Ok(chunks)
}

fn validate_transfer_bundle(
    bundle: &TransferBundle,
    route: &transition::TransferRoute,
    transition_epoch: u64,
) -> Result<(), ClusterError> {
    if bundle.schema_version != TRANSFER_BUNDLE_SCHEMA_VERSION
        || bundle.transition_epoch != transition_epoch
        || &bundle.route != route
        || bundle.receipt.transfer_id != route.transfer_id
        || bundle.receipt.chunk_count != bundle.chunks.len() as u64
    {
        return Err(ClusterError::InvalidTopology(
            "durable transfer bundle does not match the signed route".to_string(),
        ));
    }
    let mut rolling_digest = String::new();
    let mut total_items = 0u64;
    let mut total_bytes = 0u64;
    for (sequence, chunk) in bundle.chunks.iter().enumerate() {
        let (digest, byte_count) =
            transition::transfer_payload_digest(&chunk.catalogs, &chunk.items)?;
        if chunk.sequence != sequence as u64
            || chunk.digest != digest
            || chunk.byte_count != byte_count
        {
            return Err(ClusterError::Protocol(
                "durable transfer bundle failed its chunk integrity check".to_string(),
            ));
        }
        rolling_digest = transition::chain_digest(&rolling_digest, &digest);
        total_items = total_items.saturating_add(chunk.items.len() as u64);
        total_bytes = total_bytes.saturating_add(byte_count);
    }
    if bundle.receipt.rolling_digest != rolling_digest
        || bundle.receipt.total_items != total_items
        || bundle.receipt.total_bytes != total_bytes
    {
        return Err(ClusterError::Protocol(
            "durable transfer bundle failed its receipt integrity check".to_string(),
        ));
    }
    Ok(())
}

fn read_transfer_bundle(path: &Path) -> Result<TransferBundle, ClusterError> {
    let bytes = std::fs::read(path)?;
    rmp_serde::from_slice(&bytes).map_err(|error| {
        ClusterError::Protocol(format!(
            "failed to decode durable transfer bundle {}: {error}",
            path.display()
        ))
    })
}

fn write_transfer_bundle(path: &Path, bundle: &TransferBundle) -> Result<(), ClusterError> {
    let bytes = rmp_serde::to_vec_named(bundle)
        .map_err(|error| ClusterError::Protocol(error.to_string()))?;
    let nonce = TRANSFER_BUNDLE_NONCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let temporary = path.with_extension(format!("tmp-{}-{nonce}", std::process::id()));
    let result = (|| -> Result<(), ClusterError> {
        let mut options = std::fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        if let Some(parent) = path.parent() {
            std::fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

static TRANSFER_BUNDLE_NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

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
