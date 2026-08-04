use super::{
    ClusterError, SlotMove, TopologyTransitionKind, TopologyTransitionPlan, TransferReceipt,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

const TRANSFER_STATE_SCHEMA_VERSION: u16 = 1;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct TransferRoute {
    pub(crate) transfer_id: String,
    pub(crate) source_node_id: String,
    pub(crate) target_node_id: String,
    pub(crate) moves: Vec<SlotMove>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct InboundTransferProgress {
    pub(crate) route: TransferRoute,
    pub(crate) next_sequence: u64,
    pub(crate) chunk_digests: Vec<String>,
    pub(crate) rolling_digest: String,
    pub(crate) total_items: u64,
    pub(crate) total_bytes: u64,
    pub(crate) complete: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct OutboundTransferProgress {
    pub(crate) route: TransferRoute,
    pub(crate) bundle_path: Option<PathBuf>,
    pub(crate) chunk_digests: Vec<String>,
    pub(crate) rolling_digest: String,
    pub(crate) total_items: u64,
    pub(crate) total_bytes: u64,
    pub(crate) complete: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct OwnershipTransferStatus {
    pub(crate) epoch: u64,
    /// The local topology has durably committed this ownership epoch. Transfer
    /// receipts remain available after cutover so a source that crashed after
    /// the target ACK can replay and recover the exact receipt.
    #[serde(default)]
    pub(crate) topology_committed: bool,
    pub(crate) inbound: Vec<InboundTransferProgress>,
    pub(crate) outbound: Vec<OutboundTransferProgress>,
}

impl OwnershipTransferStatus {
    pub(crate) fn ready_to_commit(&self) -> bool {
        self.inbound.iter().all(|transfer| transfer.complete)
            && self.outbound.iter().all(|transfer| transfer.complete)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChunkDisposition {
    Applied,
    Replay,
}

#[derive(Debug, Serialize, Deserialize)]
struct TransferDiskState {
    schema_version: u16,
    ownership: Option<OwnershipTransferStatus>,
}

pub(crate) struct TransitionState {
    local_node_id: String,
    state_path: PathBuf,
    bundle_dir: PathBuf,
    inner: parking_lot::RwLock<TransferDiskState>,
}

pub(crate) struct SlotPermit<'a> {
    _state: parking_lot::RwLockReadGuard<'a, TransferDiskState>,
}

impl TransitionState {
    pub(crate) fn open(
        local_node_id: String,
        topology_state_path: &Path,
        current_epoch: u64,
        transition: Option<&TopologyTransitionPlan>,
    ) -> Result<Self, ClusterError> {
        let state_path = topology_state_path.with_extension("transfer-state.json");
        let bundle_dir = topology_state_path.with_extension("transfer-bundles");
        let inner = if state_path.exists() {
            let bytes = std::fs::read(&state_path)?;
            let state: TransferDiskState = serde_json::from_slice(&bytes).map_err(|error| {
                ClusterError::InvalidTopology(format!(
                    "failed to read durable transfer state {}: {error}",
                    state_path.display()
                ))
            })?;
            if state.schema_version != TRANSFER_STATE_SCHEMA_VERSION {
                return Err(ClusterError::InvalidTopology(format!(
                    "unsupported durable transfer state version {}",
                    state.schema_version
                )));
            }
            state
        } else {
            TransferDiskState {
                schema_version: TRANSFER_STATE_SCHEMA_VERSION,
                ownership: None,
            }
        };
        let state = Self {
            local_node_id,
            state_path,
            bundle_dir,
            inner: parking_lot::RwLock::new(inner),
        };
        state.reconcile(current_epoch, transition)?;
        Ok(state)
    }

    pub(crate) fn prepare(&self, transition: &TopologyTransitionPlan) -> Result<(), ClusterError> {
        if let Some(committed) = self
            .inner
            .read()
            .ownership
            .as_ref()
            .filter(|ownership| ownership.topology_committed)
        {
            return Err(invalid_transfer(format!(
                "committed ownership epoch {} must be finalized before preparing epoch {}",
                committed.epoch, transition.to_epoch
            )));
        }
        if transition.kind != TopologyTransitionKind::Ownership {
            return Ok(());
        }
        let expected = self.expected_status(transition);
        let mut inner = self.inner.write();
        match &inner.ownership {
            Some(current) if current.epoch == transition.to_epoch => {
                if !same_routes(current, &expected) {
                    return Err(ClusterError::InvalidTopology(
                        "durable transfer routes do not match the signed topology transition"
                            .to_string(),
                    ));
                }
                return Ok(());
            }
            Some(current) if current.topology_committed => {
                return Err(invalid_transfer(format!(
                    "committed ownership epoch {} must be finalized before preparing epoch {}",
                    current.epoch, transition.to_epoch
                )));
            }
            Some(current) if current.epoch > transition.to_epoch => {
                return Err(ClusterError::InvalidTopology(format!(
                    "durable transfer epoch {} is ahead of prepared epoch {}",
                    current.epoch, transition.to_epoch
                )));
            }
            _ => {}
        }
        inner.ownership = Some(expected);
        self.persist(&inner)
    }

    pub(crate) fn abort(&self, epoch: u64) -> Result<(), ClusterError> {
        let mut inner = self.inner.write();
        if inner
            .ownership
            .as_ref()
            .is_some_and(|ownership| ownership.epoch == epoch && !ownership.topology_committed)
        {
            let bundles = bundle_paths(&inner);
            inner.ownership = None;
            self.persist(&inner)?;
            drop(inner);
            remove_bundles(bundles);
        }
        Ok(())
    }

    pub(crate) fn mark_topology_committed(&self, epoch: u64) -> Result<(), ClusterError> {
        let mut inner = self.inner.write();
        let ownership = inner
            .ownership
            .as_mut()
            .ok_or_else(|| invalid_transfer("no ownership transfer state exists"))?;
        if ownership.epoch != epoch {
            return Err(invalid_transfer(format!(
                "ownership epoch {} does not match committed epoch {epoch}",
                ownership.epoch
            )));
        }
        if !ownership.ready_to_commit() {
            return Err(invalid_transfer(
                "ownership transfer is not complete at topology commit",
            ));
        }
        if !ownership.topology_committed {
            ownership.topology_committed = true;
            self.persist(&inner)?;
        }
        Ok(())
    }

    /// Remove finalized bookkeeping only after the controller has observed
    /// this epoch committed on every node and the caller has cleaned stale
    /// source copies. Until then, completed target receipts remain replayable.
    pub(crate) fn finalize(&self, epoch: u64) -> Result<bool, ClusterError> {
        let mut inner = self.inner.write();
        let Some(ownership) = inner.ownership.as_ref() else {
            return Ok(false);
        };
        if ownership.epoch != epoch {
            return Err(invalid_transfer(format!(
                "ownership epoch {} does not match finalize epoch {epoch}",
                ownership.epoch
            )));
        }
        if !ownership.topology_committed || !ownership.ready_to_commit() {
            return Err(invalid_transfer(
                "ownership epoch cannot finalize before local commit and durable receipts",
            ));
        }
        let bundles = bundle_paths(&inner);
        inner.ownership = None;
        self.persist(&inner)?;
        drop(inner);
        remove_bundles(bundles);
        Ok(true)
    }

    pub(crate) fn status(&self) -> Option<OwnershipTransferStatus> {
        self.inner.read().ownership.clone()
    }

    #[cfg(test)]
    pub(crate) fn is_fenced(&self, slot: u16) -> bool {
        self.fenced_epoch(slot).is_some()
    }

    /// Enter a slot operation while holding a read guard. Preparing an
    /// ownership transition takes the write guard, so it cannot persist a
    /// source fence until every already-admitted operation has drained.
    pub(crate) fn enter_slot(&self, slot: u16) -> Result<SlotPermit<'_>, u64> {
        let state = self.inner.read();
        if let Some(epoch) = fenced_epoch_in(&state, slot) {
            return Err(epoch);
        }
        Ok(SlotPermit { _state: state })
    }

    #[cfg(test)]
    pub(crate) fn fenced_epoch(&self, slot: u16) -> Option<u64> {
        fenced_epoch_in(&self.inner.read(), slot)
    }

    pub(crate) fn ready_to_commit(&self, epoch: u64) -> bool {
        self.inner
            .read()
            .ownership
            .as_ref()
            .is_some_and(|ownership| ownership.epoch == epoch && ownership.ready_to_commit())
    }

    pub(crate) fn outbound_routes(&self, epoch: u64) -> Result<Vec<TransferRoute>, ClusterError> {
        let inner = self.inner.read();
        let ownership = ownership_for_epoch(&inner, epoch)?;
        Ok(ownership
            .outbound
            .iter()
            .map(|transfer| transfer.route.clone())
            .collect())
    }

    pub(crate) fn outbound_progress(&self, transfer_id: &str) -> Option<OutboundTransferProgress> {
        self.inner
            .read()
            .ownership
            .as_ref()?
            .outbound
            .iter()
            .find(|transfer| transfer.route.transfer_id == transfer_id)
            .cloned()
    }

    pub(crate) fn validate_route(
        &self,
        epoch: u64,
        transfer_id: &str,
        source_node_id: &str,
        target_node_id: &str,
    ) -> Result<TransferRoute, ClusterError> {
        let inner = self.inner.read();
        let ownership = ownership_for_epoch(&inner, epoch)?;
        ownership
            .inbound
            .iter()
            .map(|progress| &progress.route)
            .chain(ownership.outbound.iter().map(|progress| &progress.route))
            .find(|route| {
                route.transfer_id == transfer_id
                    && route.source_node_id == source_node_id
                    && route.target_node_id == target_node_id
            })
            .cloned()
            .ok_or_else(|| invalid_transfer("peer route is not in the signed transition"))
    }

    pub(crate) fn record_outbound_bundle(
        &self,
        receipt: &TransferReceipt,
        bundle_path: PathBuf,
        chunk_digests: Vec<String>,
    ) -> Result<(), ClusterError> {
        let mut inner = self.inner.write();
        let ownership = inner
            .ownership
            .as_mut()
            .ok_or_else(|| invalid_transfer("no ownership transfer is prepared"))?;
        let transfer = ownership
            .outbound
            .iter_mut()
            .find(|transfer| transfer.route.transfer_id == receipt.transfer_id)
            .ok_or_else(|| invalid_transfer("outbound transfer is not in the signed plan"))?;
        if let Some(existing_path) = &transfer.bundle_path {
            if existing_path != &bundle_path
                || transfer.chunk_digests != chunk_digests
                || transfer.rolling_digest != receipt.rolling_digest
                || transfer.total_items != receipt.total_items
                || transfer.total_bytes != receipt.total_bytes
            {
                return Err(invalid_transfer(
                    "outbound transfer bundle conflicts with durable state",
                ));
            }
            return Ok(());
        }
        transfer.bundle_path = Some(bundle_path);
        transfer.chunk_digests = chunk_digests;
        transfer.rolling_digest = receipt.rolling_digest.clone();
        transfer.total_items = receipt.total_items;
        transfer.total_bytes = receipt.total_bytes;
        self.persist(&inner)
    }

    pub(crate) fn mark_outbound_complete(
        &self,
        receipt: &TransferReceipt,
    ) -> Result<(), ClusterError> {
        let mut inner = self.inner.write();
        let ownership = inner
            .ownership
            .as_mut()
            .ok_or_else(|| invalid_transfer("no ownership transfer is prepared"))?;
        let transfer = ownership
            .outbound
            .iter_mut()
            .find(|transfer| transfer.route.transfer_id == receipt.transfer_id)
            .ok_or_else(|| invalid_transfer("outbound transfer is not in the signed plan"))?;
        if transfer.bundle_path.is_none()
            || transfer.chunk_digests.len() as u64 != receipt.chunk_count
            || transfer.rolling_digest != receipt.rolling_digest
            || transfer.total_items != receipt.total_items
            || transfer.total_bytes != receipt.total_bytes
        {
            return Err(invalid_transfer(
                "target receipt does not match the durable outbound bundle",
            ));
        }
        if !transfer.complete {
            transfer.complete = true;
            self.persist(&inner)?;
        }
        Ok(())
    }

    pub(crate) fn apply_inbound_chunk<F>(
        &self,
        transfer_id: &str,
        sequence: u64,
        chunk_digest: &str,
        item_count: u64,
        byte_count: u64,
        apply: F,
    ) -> Result<(ChunkDisposition, TransferReceipt), ClusterError>
    where
        F: FnOnce() -> Result<(), ClusterError>,
    {
        let mut inner = self.inner.write();
        let ownership = inner
            .ownership
            .as_mut()
            .ok_or_else(|| invalid_transfer("no ownership transfer is prepared"))?;
        let transfer = ownership
            .inbound
            .iter_mut()
            .find(|transfer| transfer.route.transfer_id == transfer_id)
            .ok_or_else(|| invalid_transfer("inbound transfer is not in the signed plan"))?;
        if sequence < transfer.next_sequence {
            let matches = transfer
                .chunk_digests
                .get(sequence as usize)
                .is_some_and(|digest| digest == chunk_digest);
            if !matches {
                return Err(invalid_transfer(
                    "replayed transfer sequence has a different digest",
                ));
            }
            return Ok((ChunkDisposition::Replay, inbound_receipt(transfer)));
        }
        if transfer.complete {
            return Err(invalid_transfer("inbound transfer is already complete"));
        }
        if sequence != transfer.next_sequence {
            return Err(invalid_transfer(format!(
                "transfer sequence {sequence} arrived before sequence {}",
                transfer.next_sequence
            )));
        }
        apply()?;
        transfer.chunk_digests.push(chunk_digest.to_string());
        transfer.rolling_digest = chain_digest(&transfer.rolling_digest, chunk_digest);
        transfer.next_sequence += 1;
        transfer.total_items = transfer.total_items.saturating_add(item_count);
        transfer.total_bytes = transfer.total_bytes.saturating_add(byte_count);
        let receipt = inbound_receipt(transfer);
        self.persist(&inner)?;
        Ok((ChunkDisposition::Applied, receipt))
    }

    pub(crate) fn finish_inbound(
        &self,
        expected: &TransferReceipt,
    ) -> Result<TransferReceipt, ClusterError> {
        let mut inner = self.inner.write();
        let ownership = inner
            .ownership
            .as_mut()
            .ok_or_else(|| invalid_transfer("no ownership transfer is prepared"))?;
        let transfer = ownership
            .inbound
            .iter_mut()
            .find(|transfer| transfer.route.transfer_id == expected.transfer_id)
            .ok_or_else(|| invalid_transfer("inbound transfer is not in the signed plan"))?;
        let actual = inbound_receipt(transfer);
        if actual.chunk_count != expected.chunk_count
            || actual.rolling_digest != expected.rolling_digest
            || actual.total_items != expected.total_items
            || actual.total_bytes != expected.total_bytes
        {
            return Err(invalid_transfer(
                "transfer completion receipt does not match imported chunks",
            ));
        }
        if !transfer.complete {
            transfer.complete = true;
            self.persist(&inner)?;
        }
        Ok(actual)
    }

    pub(crate) fn bundle_dir(&self) -> &Path {
        &self.bundle_dir
    }

    fn reconcile(
        &self,
        current_epoch: u64,
        transition: Option<&TopologyTransitionPlan>,
    ) -> Result<(), ClusterError> {
        if let Some(transition) =
            transition.filter(|transition| transition.kind == TopologyTransitionKind::Ownership)
        {
            return self.prepare(transition);
        }
        let mut inner = self.inner.write();
        if current_epoch == 0 {
            return Err(invalid_transfer("committed topology epoch cannot be zero"));
        }
        let mut clear_aborted = false;
        if let Some(ownership) = inner.ownership.as_mut() {
            if ownership.epoch == current_epoch && ownership.ready_to_commit() {
                // Topology commit is persisted before this secondary marker.
                // A crash between those writes lands here; retain receipts and
                // complete the marker rather than erasing recovery evidence.
                if !ownership.topology_committed {
                    ownership.topology_committed = true;
                    self.persist(&inner)?;
                }
                return Ok(());
            }
            if ownership.topology_committed {
                if ownership.epoch > current_epoch {
                    return Err(invalid_transfer(format!(
                        "committed transfer epoch {} is ahead of topology epoch {current_epoch}",
                        ownership.epoch
                    )));
                }
                // A later membership-only topology can legitimately be current
                // while the most recent ownership receipts await finalize.
                return Ok(());
            }
            clear_aborted = true;
        }
        if clear_aborted {
            // No matching pending topology and no committed marker means abort
            // won the crash. Release fences and discard unfinished bundles.
            let bundles = bundle_paths(&inner);
            inner.ownership = None;
            self.persist(&inner)?;
            drop(inner);
            remove_bundles(bundles);
        } else {
            self.persist(&inner)?;
        }
        Ok(())
    }

    fn expected_status(&self, transition: &TopologyTransitionPlan) -> OwnershipTransferStatus {
        let routes = grouped_routes(transition);
        let inbound = routes
            .iter()
            .filter(|route| route.target_node_id == self.local_node_id)
            .cloned()
            .map(|route| InboundTransferProgress {
                route,
                next_sequence: 0,
                chunk_digests: Vec::new(),
                rolling_digest: String::new(),
                total_items: 0,
                total_bytes: 0,
                complete: false,
            })
            .collect();
        let outbound = routes
            .into_iter()
            .filter(|route| route.source_node_id == self.local_node_id)
            .map(|route| OutboundTransferProgress {
                route,
                bundle_path: None,
                chunk_digests: Vec::new(),
                rolling_digest: String::new(),
                total_items: 0,
                total_bytes: 0,
                complete: false,
            })
            .collect();
        OwnershipTransferStatus {
            epoch: transition.to_epoch,
            topology_committed: false,
            inbound,
            outbound,
        }
    }

    fn persist(&self, state: &TransferDiskState) -> Result<(), ClusterError> {
        if let Some(parent) = self.state_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec_pretty(state)?;
        let nonce = TRANSFER_FILE_NONCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let temporary = self
            .state_path
            .with_extension(format!("tmp-{}-{nonce}", std::process::id()));
        let result = (|| -> Result<(), ClusterError> {
            let mut file = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            std::fs::rename(&temporary, &self.state_path)?;
            if let Some(parent) = self.state_path.parent() {
                std::fs::File::open(parent)?.sync_all()?;
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
    }
}

fn ownership_for_epoch(
    state: &TransferDiskState,
    epoch: u64,
) -> Result<&OwnershipTransferStatus, ClusterError> {
    state
        .ownership
        .as_ref()
        .filter(|ownership| ownership.epoch == epoch)
        .ok_or_else(|| invalid_transfer(format!("ownership epoch {epoch} is not prepared")))
}

fn fenced_epoch_in(state: &TransferDiskState, slot: u16) -> Option<u64> {
    let ownership = state.ownership.as_ref()?;
    ownership
        .outbound
        .iter()
        .flat_map(|transfer| &transfer.route.moves)
        .any(|movement| slot >= movement.start && slot <= movement.end)
        .then_some(ownership.epoch)
}

fn grouped_routes(transition: &TopologyTransitionPlan) -> Vec<TransferRoute> {
    let mut grouped = BTreeMap::<(String, String), Vec<SlotMove>>::new();
    for movement in &transition.moves {
        grouped
            .entry((
                movement.source_node_id.clone(),
                movement.target_node_id.clone(),
            ))
            .or_default()
            .push(movement.clone());
    }
    grouped
        .into_iter()
        .map(|((source_node_id, target_node_id), moves)| {
            let mut hasher = Sha256::new();
            hasher.update(transition.from_epoch.to_be_bytes());
            hasher.update(transition.to_epoch.to_be_bytes());
            hasher.update(source_node_id.as_bytes());
            hasher.update([0]);
            hasher.update(target_node_id.as_bytes());
            for movement in &moves {
                hasher.update(movement.start.to_be_bytes());
                hasher.update(movement.end.to_be_bytes());
            }
            TransferRoute {
                transfer_id: URL_SAFE_NO_PAD.encode(hasher.finalize()),
                source_node_id,
                target_node_id,
                moves,
            }
        })
        .collect()
}

fn same_routes(current: &OwnershipTransferStatus, expected: &OwnershipTransferStatus) -> bool {
    current.epoch == expected.epoch
        && current
            .inbound
            .iter()
            .map(|transfer| &transfer.route)
            .eq(expected.inbound.iter().map(|transfer| &transfer.route))
        && current
            .outbound
            .iter()
            .map(|transfer| &transfer.route)
            .eq(expected.outbound.iter().map(|transfer| &transfer.route))
}

fn inbound_receipt(transfer: &InboundTransferProgress) -> TransferReceipt {
    TransferReceipt {
        transfer_id: transfer.route.transfer_id.clone(),
        chunk_count: transfer.next_sequence,
        rolling_digest: transfer.rolling_digest.clone(),
        total_items: transfer.total_items,
        total_bytes: transfer.total_bytes,
    }
}

fn bundle_paths(state: &TransferDiskState) -> Vec<PathBuf> {
    state
        .ownership
        .iter()
        .flat_map(|ownership| &ownership.outbound)
        .filter_map(|transfer| transfer.bundle_path.clone())
        .collect()
}

fn remove_bundles(paths: Vec<PathBuf>) {
    for path in paths {
        let _ = std::fs::remove_file(path);
    }
}

fn chunk_digest(encoded: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(encoded))
}

pub(crate) fn transfer_payload_digest(
    catalogs: &[crate::cluster::TransferCatalogProof],
    items: &[crate::cluster::TransferItem],
) -> Result<(String, u64), ClusterError> {
    let encoded = rmp_serde::to_vec_named(&(catalogs, items)).map_err(|error| {
        ClusterError::Protocol(format!("failed to encode transfer chunk digest: {error}"))
    })?;
    Ok((chunk_digest(&encoded), encoded.len() as u64))
}

pub(crate) fn chain_digest(previous: &str, chunk: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(previous.as_bytes());
    hasher.update([0]);
    hasher.update(chunk.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

fn invalid_transfer(message: impl Into<String>) -> ClusterError {
    ClusterError::InvalidTopology(format!("ownership transfer: {}", message.into()))
}

static TRANSFER_FILE_NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[cfg(test)]
mod tests {
    use super::*;

    fn move_plan() -> TopologyTransitionPlan {
        TopologyTransitionPlan {
            from_epoch: 2,
            to_epoch: 3,
            kind: TopologyTransitionKind::Ownership,
            added_node_ids: Vec::new(),
            removed_node_ids: Vec::new(),
            updated_node_ids: Vec::new(),
            moves: vec![SlotMove {
                start: 2048,
                end: 4095,
                source_node_id: "node-a".to_string(),
                target_node_id: "node-b".to_string(),
            }],
        }
    }

    #[test]
    fn outbound_slots_fence_immediately_and_survive_restart() {
        let dir = tempfile::tempdir().unwrap();
        let topology_path = dir.path().join("topology-state.json");
        let plan = move_plan();
        let state = TransitionState::open("node-a".into(), &topology_path, 2, Some(&plan)).unwrap();
        assert!(!state.is_fenced(2047));
        assert!(state.is_fenced(2048));
        assert!(!state.ready_to_commit(3));
        drop(state);

        let restarted =
            TransitionState::open("node-a".into(), &topology_path, 2, Some(&plan)).unwrap();
        assert!(restarted.is_fenced(4095));
        assert_eq!(restarted.outbound_routes(3).unwrap().len(), 1);
    }

    #[test]
    fn inbound_chunks_are_ordered_idempotent_and_durable() {
        let dir = tempfile::tempdir().unwrap();
        let topology_path = dir.path().join("topology-state.json");
        let plan = move_plan();
        let state = TransitionState::open("node-b".into(), &topology_path, 2, Some(&plan)).unwrap();
        let transfer_id = state.status().unwrap().inbound[0].route.transfer_id.clone();
        let applied = std::cell::Cell::new(0);
        let (disposition, receipt) = state
            .apply_inbound_chunk(&transfer_id, 0, "chunk-a", 2, 50, || {
                applied.set(applied.get() + 1);
                Ok(())
            })
            .unwrap();
        assert_eq!(disposition, ChunkDisposition::Applied);
        assert_eq!(applied.get(), 1);
        let (disposition, replay) = state
            .apply_inbound_chunk(&transfer_id, 0, "chunk-a", 2, 50, || {
                applied.set(applied.get() + 1);
                Ok(())
            })
            .unwrap();
        assert_eq!(disposition, ChunkDisposition::Replay);
        assert_eq!(applied.get(), 1);
        assert_eq!(receipt, replay);
        assert!(state
            .apply_inbound_chunk(&transfer_id, 2, "chunk-c", 1, 10, || Ok(()))
            .is_err());
        assert!(!state.ready_to_commit(3));
        state.finish_inbound(&receipt).unwrap();
        assert!(state.ready_to_commit(3));
        drop(state);

        let restarted =
            TransitionState::open("node-b".into(), &topology_path, 2, Some(&plan)).unwrap();
        assert!(restarted.ready_to_commit(3));
    }

    #[test]
    fn abort_releases_fences_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let topology_path = dir.path().join("topology-state.json");
        let plan = move_plan();
        let state = TransitionState::open("node-a".into(), &topology_path, 2, Some(&plan)).unwrap();
        state.abort(3).unwrap();
        assert!(!state.is_fenced(2048));
        drop(state);
        let restarted = TransitionState::open("node-a".into(), &topology_path, 2, None).unwrap();
        assert!(!restarted.is_fenced(2048));
    }

    #[test]
    fn committed_target_retains_and_replays_receipt_until_finalize() {
        let dir = tempfile::tempdir().unwrap();
        let topology_path = dir.path().join("topology-state.json");
        let plan = move_plan();
        let state = TransitionState::open("node-b".into(), &topology_path, 2, Some(&plan)).unwrap();
        let transfer_id = state.status().unwrap().inbound[0].route.transfer_id.clone();
        let (_, receipt) = state
            .apply_inbound_chunk(&transfer_id, 0, "chunk-a", 2, 50, || Ok(()))
            .unwrap();
        state.finish_inbound(&receipt).unwrap();
        state.mark_topology_committed(3).unwrap();
        drop(state);

        // Restart after topology commit but before cluster-wide finalize. The
        // target must retain the receipt for a source that missed the ACK.
        let restarted = TransitionState::open("node-b".into(), &topology_path, 3, None).unwrap();
        assert!(restarted.status().unwrap().topology_committed);
        let applied = std::cell::Cell::new(false);
        let (disposition, replay) = restarted
            .apply_inbound_chunk(&transfer_id, 0, "chunk-a", 2, 50, || {
                applied.set(true);
                Ok(())
            })
            .unwrap();
        assert_eq!(disposition, ChunkDisposition::Replay);
        assert!(!applied.get());
        assert_eq!(replay, receipt);
        assert_eq!(restarted.finish_inbound(&receipt).unwrap(), receipt);
        assert!(restarted.finalize(3).unwrap());
        assert!(restarted.status().is_none());
    }

    #[test]
    fn committed_receipts_cannot_be_aborted_or_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let topology_path = dir.path().join("topology-state.json");
        let plan = move_plan();
        let state = TransitionState::open("node-b".into(), &topology_path, 2, Some(&plan)).unwrap();
        let transfer_id = state.status().unwrap().inbound[0].route.transfer_id.clone();
        let (_, receipt) = state
            .apply_inbound_chunk(&transfer_id, 0, "chunk-a", 1, 10, || Ok(()))
            .unwrap();
        state.finish_inbound(&receipt).unwrap();
        state.mark_topology_committed(3).unwrap();
        state.abort(3).unwrap();
        assert!(state.status().is_some());

        let mut next = plan.clone();
        next.from_epoch = 3;
        next.to_epoch = 4;
        assert!(state.prepare(&next).is_err());
    }
}
