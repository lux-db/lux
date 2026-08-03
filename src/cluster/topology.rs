use super::{ClusterError, CLUSTER_PROTOCOL_VERSION};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub const CLUSTER_TOPOLOGY_SCHEMA_VERSION: u16 = 1;
pub const CLUSTER_SLOT_COUNT: u16 = 4096;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NodeDescriptor {
    pub node_id: String,
    /// DNS name or IP plus port. DNS is resolved for each new connection so a
    /// Kubernetes Service can move without changing the signed topology.
    pub peer_addr: String,
    pub server_name: String,
    /// Public DER certificate, base64url encoded. The signed manifest is the trust root.
    pub certificate_der: String,
    /// Lowercase SHA-256 of the DER certificate.
    pub certificate_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SlotAssignment {
    /// Inclusive first slot.
    pub start: u16,
    /// Inclusive last slot.
    pub end: u16,
    pub node_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TopologyManifest {
    pub schema_version: u16,
    pub protocol_version: u16,
    pub cluster_id: String,
    pub epoch: u64,
    pub system_node_id: String,
    pub slot_count: u16,
    pub catalog_version: u64,
    pub nodes: Vec<NodeDescriptor>,
    pub assignments: Vec<SlotAssignment>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignedTopology {
    pub manifest: TopologyManifest,
    /// P-256 ECDSA signature over [`TopologyManifest::signing_payload`].
    pub signature: String,
}

impl SignedTopology {
    pub fn sign(
        manifest: TopologyManifest,
        signing_key: &SigningKey,
    ) -> Result<Self, ClusterError> {
        let bytes = canonical_manifest_bytes(&manifest)?;
        let signature: Signature = signing_key.sign(&bytes);
        Ok(Self {
            manifest,
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        })
    }

    pub fn verify(&self, controller_public_key: &str) -> Result<CompiledTopology, ClusterError> {
        let key_bytes = URL_SAFE_NO_PAD
            .decode(controller_public_key)
            .map_err(|error| {
                ClusterError::Signature(format!("public key is not base64url: {error}"))
            })?;
        let verifying_key = VerifyingKey::from_sec1_bytes(&key_bytes).map_err(|error| {
            ClusterError::Signature(format!("public key is not P-256 SEC1: {error}"))
        })?;
        let signature_bytes = URL_SAFE_NO_PAD.decode(&self.signature).map_err(|error| {
            ClusterError::Signature(format!("signature is not base64url: {error}"))
        })?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|error| ClusterError::Signature(format!("signature is not P-256: {error}")))?;
        let bytes = canonical_manifest_bytes(&self.manifest)?;
        verifying_key.verify(&bytes, &signature).map_err(|_| {
            ClusterError::Signature("manifest signature did not verify".to_string())
        })?;
        CompiledTopology::compile(self.clone())
    }
}

impl TopologyManifest {
    /// Deterministic, language-independent bytes covered by the controller signature.
    pub fn signing_payload(&self) -> Result<Vec<u8>, ClusterError> {
        canonical_manifest_bytes(self)
    }
}

fn canonical_manifest_bytes(manifest: &TopologyManifest) -> Result<Vec<u8>, ClusterError> {
    // This explicit length-prefixed encoding is the cross-language signing
    // contract. It does not depend on JSON object order, whitespace, or number
    // formatting, so the Cloud controller and OSS CLI can produce identical bytes.
    let mut bytes = Vec::with_capacity(1024);
    bytes.extend_from_slice(b"LUX-CLUSTER-TOPOLOGY\0");
    bytes.extend_from_slice(&manifest.schema_version.to_be_bytes());
    bytes.extend_from_slice(&manifest.protocol_version.to_be_bytes());
    push_string(&mut bytes, &manifest.cluster_id)?;
    bytes.extend_from_slice(&manifest.epoch.to_be_bytes());
    push_string(&mut bytes, &manifest.system_node_id)?;
    bytes.extend_from_slice(&manifest.slot_count.to_be_bytes());
    bytes.extend_from_slice(&manifest.catalog_version.to_be_bytes());
    push_len(&mut bytes, manifest.nodes.len())?;
    for node in &manifest.nodes {
        push_string(&mut bytes, &node.node_id)?;
        push_string(&mut bytes, &node.peer_addr)?;
        push_string(&mut bytes, &node.server_name)?;
        push_string(&mut bytes, &node.certificate_der)?;
        push_string(&mut bytes, &node.certificate_sha256)?;
    }
    push_len(&mut bytes, manifest.assignments.len())?;
    for assignment in &manifest.assignments {
        bytes.extend_from_slice(&assignment.start.to_be_bytes());
        bytes.extend_from_slice(&assignment.end.to_be_bytes());
        push_string(&mut bytes, &assignment.node_id)?;
    }
    Ok(bytes)
}

fn push_string(bytes: &mut Vec<u8>, value: &str) -> Result<(), ClusterError> {
    push_len(bytes, value.len())?;
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

fn push_len(bytes: &mut Vec<u8>, length: usize) -> Result<(), ClusterError> {
    let length = u32::try_from(length).map_err(|_| {
        ClusterError::InvalidTopology("canonical field exceeds u32 length".to_string())
    })?;
    bytes.extend_from_slice(&length.to_be_bytes());
    Ok(())
}

#[derive(Clone, Debug)]
pub struct CompiledTopology {
    signed: SignedTopology,
    node_indexes: HashMap<String, usize>,
    slot_owners: Box<[usize]>,
}

impl CompiledTopology {
    fn compile(signed: SignedTopology) -> Result<Self, ClusterError> {
        validate_manifest(&signed.manifest)?;
        let node_indexes: HashMap<String, usize> = signed
            .manifest
            .nodes
            .iter()
            .enumerate()
            .map(|(index, node)| (node.node_id.clone(), index))
            .collect();
        let mut slot_owners = vec![usize::MAX; CLUSTER_SLOT_COUNT as usize].into_boxed_slice();
        for assignment in &signed.manifest.assignments {
            let owner = node_indexes[&assignment.node_id];
            for slot in assignment.start..=assignment.end {
                slot_owners[slot as usize] = owner;
            }
        }
        Ok(Self {
            signed,
            node_indexes,
            slot_owners,
        })
    }

    pub fn manifest(&self) -> &TopologyManifest {
        &self.signed.manifest
    }

    pub fn signed(&self) -> &SignedTopology {
        &self.signed
    }

    #[inline]
    pub fn owner_for_slot(&self, slot: u16) -> &NodeDescriptor {
        &self.signed.manifest.nodes[self.slot_owners[slot as usize]]
    }

    pub fn node(&self, node_id: &str) -> Option<&NodeDescriptor> {
        self.node_indexes
            .get(node_id)
            .map(|index| &self.signed.manifest.nodes[*index])
    }

    pub fn owns_slot(&self, node_id: &str, slot: u16) -> bool {
        self.owner_for_slot(slot).node_id == node_id
    }
}

#[derive(Debug)]
struct TopologyStateInner {
    current: Arc<CompiledTopology>,
    pending: Option<Arc<CompiledTopology>>,
}

/// Atomically tracks the committed and prepared topology for one node.
#[derive(Debug)]
pub struct TopologyState {
    inner: parking_lot::RwLock<TopologyStateInner>,
    controller_public_key: String,
    state_path: Option<PathBuf>,
}

impl TopologyState {
    pub fn in_memory(current: CompiledTopology, controller_public_key: String) -> Self {
        Self {
            inner: parking_lot::RwLock::new(TopologyStateInner {
                current: Arc::new(current),
                pending: None,
            }),
            controller_public_key,
            state_path: None,
        }
    }

    pub fn open(
        supplied: CompiledTopology,
        controller_public_key: String,
        state_path: impl AsRef<Path>,
    ) -> Result<Self, ClusterError> {
        let state_path = state_path.as_ref().to_path_buf();
        let (current, pending) = if state_path.exists() {
            let bytes = std::fs::read(&state_path)?;
            let disk: TopologyDiskState = serde_json::from_slice(&bytes).map_err(|error| {
                ClusterError::InvalidTopology(format!(
                    "failed to read durable topology state {}: {error}",
                    state_path.display()
                ))
            })?;
            let durable = disk.current.verify(&controller_public_key)?;
            if durable.manifest().cluster_id != supplied.manifest().cluster_id {
                return invalid("durable topology state belongs to another cluster");
            }
            let current = match durable.manifest().epoch.cmp(&supplied.manifest().epoch) {
                std::cmp::Ordering::Greater => durable,
                std::cmp::Ordering::Less => supplied,
                std::cmp::Ordering::Equal => {
                    if durable.signed() != supplied.signed() {
                        return invalid("same topology epoch has different signed contents");
                    }
                    durable
                }
            };
            let pending = disk
                .pending
                .map(|pending| pending.verify(&controller_public_key))
                .transpose()?;
            if pending.as_ref().is_some_and(|pending| {
                pending.manifest().cluster_id != current.manifest().cluster_id
            }) {
                return invalid("durable pending topology belongs to another cluster");
            }
            let pending =
                pending.filter(|pending| pending.manifest().epoch > current.manifest().epoch);
            (current, pending)
        } else {
            (supplied, None)
        };
        let state = Self {
            inner: parking_lot::RwLock::new(TopologyStateInner {
                current: Arc::new(current),
                pending: pending.map(Arc::new),
            }),
            controller_public_key,
            state_path: Some(state_path),
        };
        {
            let inner = state.inner.read();
            state.persist(&inner.current, inner.pending.as_deref())?;
        }
        Ok(state)
    }

    pub fn current(&self) -> Arc<CompiledTopology> {
        self.inner.read().current.clone()
    }

    pub fn prepare(&self, signed: SignedTopology) -> Result<u64, ClusterError> {
        let candidate = Arc::new(signed.verify(&self.controller_public_key)?);
        let mut inner = self.inner.write();
        if candidate.manifest().cluster_id != inner.current.manifest().cluster_id {
            return Err(ClusterError::InvalidTopology(
                "prepared topology belongs to another cluster".to_string(),
            ));
        }
        if candidate.manifest().epoch <= inner.current.manifest().epoch {
            return Err(ClusterError::InvalidTopology(format!(
                "epoch {} does not advance committed epoch {}",
                candidate.manifest().epoch,
                inner.current.manifest().epoch
            )));
        }
        if inner
            .pending
            .as_ref()
            .is_some_and(|pending| candidate.manifest().epoch <= pending.manifest().epoch)
        {
            return Err(ClusterError::InvalidTopology(
                "prepared epoch does not advance the existing pending topology".to_string(),
            ));
        }
        let epoch = candidate.manifest().epoch;
        self.persist(&inner.current, Some(&candidate))?;
        inner.pending = Some(candidate);
        Ok(epoch)
    }

    pub fn commit(&self, epoch: u64) -> Result<Arc<CompiledTopology>, ClusterError> {
        let mut inner = self.inner.write();
        let pending = inner
            .pending
            .take()
            .ok_or_else(|| ClusterError::InvalidTopology("no topology is prepared".to_string()))?;
        if pending.manifest().epoch != epoch {
            inner.pending = Some(pending);
            return Err(ClusterError::InvalidTopology(format!(
                "prepared topology epoch does not match commit epoch {epoch}"
            )));
        }
        self.persist(&pending, None)?;
        inner.current = pending;
        Ok(inner.current.clone())
    }

    pub fn abort(&self, epoch: u64) -> Result<bool, ClusterError> {
        let mut inner = self.inner.write();
        if inner
            .pending
            .as_ref()
            .is_some_and(|pending| pending.manifest().epoch == epoch)
        {
            self.persist(&inner.current, None)?;
            inner.pending = None;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn persist(
        &self,
        current: &CompiledTopology,
        pending: Option<&CompiledTopology>,
    ) -> Result<(), ClusterError> {
        let Some(path) = &self.state_path else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let disk = TopologyDiskState {
            current: current.signed().clone(),
            pending: pending.map(|value| value.signed().clone()),
        };
        let bytes = serde_json::to_vec_pretty(&disk)?;
        let nonce = STATE_FILE_NONCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let temporary = path.with_extension(format!("tmp-{}-{nonce}", std::process::id()));
        let result = (|| -> Result<(), ClusterError> {
            let mut file = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary)?;
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
}

#[derive(Serialize, Deserialize)]
struct TopologyDiskState {
    current: SignedTopology,
    pending: Option<SignedTopology>,
}

static STATE_FILE_NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn validate_manifest(manifest: &TopologyManifest) -> Result<(), ClusterError> {
    if manifest.schema_version != CLUSTER_TOPOLOGY_SCHEMA_VERSION {
        return invalid(format!(
            "unsupported schema version {}",
            manifest.schema_version
        ));
    }
    if manifest.protocol_version != CLUSTER_PROTOCOL_VERSION {
        return invalid(format!(
            "unsupported protocol version {}",
            manifest.protocol_version
        ));
    }
    if manifest.cluster_id.trim().is_empty() || manifest.cluster_id.len() > 128 {
        return invalid("cluster_id must contain 1 to 128 characters");
    }
    if manifest.epoch == 0 {
        return invalid("epoch must be greater than zero");
    }
    if manifest.slot_count != CLUSTER_SLOT_COUNT {
        return invalid(format!("slot_count must be {CLUSTER_SLOT_COUNT}"));
    }
    if manifest.nodes.is_empty() || manifest.nodes.len() > 8 {
        return invalid("topology must contain 1 to 8 nodes");
    }

    let mut node_ids = HashSet::new();
    let mut addresses = HashSet::new();
    let mut certificate_fingerprints = HashSet::new();
    for node in &manifest.nodes {
        if node.node_id.trim().is_empty() || node.node_id.len() > 128 {
            return invalid("node_id must contain 1 to 128 characters");
        }
        if !node_ids.insert(node.node_id.as_str()) {
            return invalid(format!("duplicate node id {}", node.node_id));
        }
        if !addresses.insert(node.peer_addr.as_str()) {
            return invalid(format!("duplicate peer address {}", node.peer_addr));
        }
        if peer_port(&node.peer_addr).is_none() {
            return invalid(format!(
                "node {} peer_addr must be a DNS name or IP with a non-zero port",
                node.node_id
            ));
        }
        if node.server_name.is_empty() || node.server_name.len() > 253 {
            return invalid(format!("node {} has an invalid server_name", node.node_id));
        }
        rustls::pki_types::ServerName::try_from(node.server_name.clone()).map_err(|_| {
            ClusterError::InvalidTopology(format!(
                "node {} server_name is not a valid TLS name",
                node.node_id
            ))
        })?;
        let certificate = decode_certificate(node)?;
        let actual = certificate_fingerprint(&certificate);
        if actual != node.certificate_sha256 {
            return invalid(format!(
                "node {} certificate fingerprint mismatch",
                node.node_id
            ));
        }
        if !certificate_fingerprints.insert(node.certificate_sha256.as_str()) {
            return invalid(format!(
                "node {} reuses another node's certificate",
                node.node_id
            ));
        }
    }
    if !node_ids.contains(manifest.system_node_id.as_str()) {
        return invalid("system_node_id is not present in nodes");
    }

    if manifest.assignments.is_empty() {
        return invalid("slot assignments are required");
    }
    let mut assignments = manifest.assignments.iter();
    let first = assignments.next().expect("checked non-empty");
    if first.start != 0 {
        return invalid("slot assignments must begin at slot 0");
    }
    if first.end < first.start || !node_ids.contains(first.node_id.as_str()) {
        return invalid("first slot assignment is invalid");
    }
    let mut expected = first.end as u32 + 1;
    for assignment in assignments {
        if assignment.start as u32 != expected {
            return invalid("slot assignments must be ordered, contiguous, and non-overlapping");
        }
        if assignment.end < assignment.start {
            return invalid("slot assignment end precedes start");
        }
        if !node_ids.contains(assignment.node_id.as_str()) {
            return invalid(format!(
                "slot owner {} is not a topology node",
                assignment.node_id
            ));
        }
        expected = assignment.end as u32 + 1;
    }
    if expected != CLUSTER_SLOT_COUNT as u32 {
        return invalid(format!(
            "slot assignments must end at slot {}",
            CLUSTER_SLOT_COUNT - 1
        ));
    }
    Ok(())
}

fn invalid<T>(message: impl Into<String>) -> Result<T, ClusterError> {
    Err(ClusterError::InvalidTopology(message.into()))
}

pub(crate) fn decode_certificate(node: &NodeDescriptor) -> Result<Vec<u8>, ClusterError> {
    URL_SAFE_NO_PAD
        .decode(&node.certificate_der)
        .map_err(|error| {
            ClusterError::InvalidTopology(format!(
                "node {} certificate is not base64url: {error}",
                node.node_id
            ))
        })
}

pub(crate) fn peer_port(endpoint: &str) -> Option<u16> {
    if let Ok(address) = endpoint.parse::<SocketAddr>() {
        return (address.port() != 0).then_some(address.port());
    }
    let (host, port) = endpoint.rsplit_once(':')?;
    if host.is_empty() || host.contains(char::is_whitespace) {
        return None;
    }
    let port = port.parse::<u16>().ok()?;
    (port != 0).then_some(port)
}

pub fn certificate_fingerprint(certificate_der: &[u8]) -> String {
    let digest = Sha256::digest(certificate_der);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

#[inline]
pub fn slot_for_key(key: &[u8]) -> u16 {
    (fnv1a64(hash_tag(key)) % CLUSTER_SLOT_COUNT as u64) as u16
}

#[inline]
pub fn slot_for_table_row(table: &[u8], primary_key: &[u8]) -> u16 {
    let mut hash = FNV_OFFSET;
    hash = fnv1a64_continue(hash, table);
    hash ^= 0;
    hash = hash.wrapping_mul(FNV_PRIME);
    hash = fnv1a64_continue(hash, primary_key);
    (hash % CLUSTER_SLOT_COUNT as u64) as u16
}

const FNV_OFFSET: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;

#[inline]
fn fnv1a64(bytes: &[u8]) -> u64 {
    fnv1a64_continue(FNV_OFFSET, bytes)
}

#[inline]
fn fnv1a64_continue(mut hash: u64, bytes: &[u8]) -> u64 {
    for &byte in bytes {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

fn hash_tag(key: &[u8]) -> &[u8] {
    let Some(open) = key.iter().position(|byte| *byte == b'{') else {
        return key;
    };
    let tail = &key[open + 1..];
    match tail.iter().position(|byte| *byte == b'}') {
        Some(length) if length > 0 => &tail[..length],
        _ => key,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    fn node(node_id: &str, port: u16, certificate: &[u8]) -> NodeDescriptor {
        NodeDescriptor {
            node_id: node_id.to_string(),
            peer_addr: format!("127.0.0.1:{port}"),
            server_name: format!("{node_id}.cluster.local"),
            certificate_der: URL_SAFE_NO_PAD.encode(certificate),
            certificate_sha256: certificate_fingerprint(certificate),
        }
    }

    fn manifest(certificate: &[u8]) -> TopologyManifest {
        TopologyManifest {
            schema_version: CLUSTER_TOPOLOGY_SCHEMA_VERSION,
            protocol_version: CLUSTER_PROTOCOL_VERSION,
            cluster_id: "cluster-a".to_string(),
            epoch: 1,
            system_node_id: "node-1".to_string(),
            slot_count: CLUSTER_SLOT_COUNT,
            catalog_version: 1,
            nodes: vec![node("node-1", 7001, certificate)],
            assignments: vec![SlotAssignment {
                start: 0,
                end: CLUSTER_SLOT_COUNT - 1,
                node_id: "node-1".to_string(),
            }],
        }
    }

    #[test]
    fn signed_manifest_verifies_and_compiles_all_slots() {
        let signing_key = SigningKey::random(&mut OsRng);
        let public_key = URL_SAFE_NO_PAD.encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        let signed = SignedTopology::sign(manifest(b"public-certificate"), &signing_key).unwrap();
        let compiled = signed.verify(&public_key).unwrap();
        assert_eq!(compiled.owner_for_slot(0).node_id, "node-1");
        assert_eq!(
            compiled.owner_for_slot(CLUSTER_SLOT_COUNT - 1).node_id,
            "node-1"
        );
    }

    #[test]
    fn signature_rejects_tampered_epoch() {
        let signing_key = SigningKey::random(&mut OsRng);
        let public_key = URL_SAFE_NO_PAD.encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        let mut signed =
            SignedTopology::sign(manifest(b"public-certificate"), &signing_key).unwrap();
        signed.manifest.epoch = 2;
        assert!(matches!(
            signed.verify(&public_key),
            Err(ClusterError::Signature(_))
        ));
    }

    #[test]
    fn rejects_slot_gaps_and_fingerprint_mismatch() {
        let signing_key = SigningKey::random(&mut OsRng);
        let public_key = URL_SAFE_NO_PAD.encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        let mut broken = manifest(b"public-certificate");
        broken.assignments[0].start = 1;
        let signed = SignedTopology::sign(broken, &signing_key).unwrap();
        assert!(matches!(
            signed.verify(&public_key),
            Err(ClusterError::InvalidTopology(_))
        ));

        let mut broken = manifest(b"public-certificate");
        broken.nodes[0].certificate_sha256 = "00".repeat(32);
        let signed = SignedTopology::sign(broken, &signing_key).unwrap();
        assert!(matches!(
            signed.verify(&public_key),
            Err(ClusterError::InvalidTopology(_))
        ));
    }

    #[test]
    fn rejects_a_certificate_shared_by_multiple_node_identities() {
        let signing_key = SigningKey::random(&mut OsRng);
        let public_key = URL_SAFE_NO_PAD.encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        let certificate = b"shared-public-certificate";
        let mut broken = manifest(certificate);
        broken.nodes.push(node("node-2", 7002, certificate));
        broken.assignments = vec![
            SlotAssignment {
                start: 0,
                end: 2047,
                node_id: "node-1".to_string(),
            },
            SlotAssignment {
                start: 2048,
                end: CLUSTER_SLOT_COUNT - 1,
                node_id: "node-2".to_string(),
            },
        ];
        let signed = SignedTopology::sign(broken, &signing_key).unwrap();
        assert!(matches!(
            signed.verify(&public_key),
            Err(ClusterError::InvalidTopology(_))
        ));
    }

    #[test]
    fn hash_tags_co_locate_and_table_name_participates() {
        assert_eq!(
            slot_for_key(b"cart:{user-1}"),
            slot_for_key(b"orders:{user-1}")
        );
        assert_ne!(
            slot_for_key(b"cart:{user-1}"),
            slot_for_key(b"cart:{user-2}")
        );
        assert_ne!(
            slot_for_table_row(b"orders", b"42"),
            slot_for_table_row(b"users", b"42")
        );
    }

    #[test]
    fn prepare_rejects_epoch_rollback_and_commit_is_exact() {
        let signing_key = SigningKey::random(&mut OsRng);
        let public_key = URL_SAFE_NO_PAD.encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        let initial = SignedTopology::sign(manifest(b"public-certificate"), &signing_key)
            .unwrap()
            .verify(&public_key)
            .unwrap();
        let state = TopologyState::in_memory(initial, public_key.clone());

        let mut next = manifest(b"public-certificate");
        next.epoch = 2;
        state
            .prepare(SignedTopology::sign(next, &signing_key).unwrap())
            .unwrap();
        assert!(state.commit(3).is_err());
        assert_eq!(state.commit(2).unwrap().manifest().epoch, 2);

        let rollback = SignedTopology::sign(manifest(b"public-certificate"), &signing_key).unwrap();
        assert!(state.prepare(rollback).is_err());
    }

    #[test]
    fn durable_state_survives_restart_and_rejects_rollback() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("topology-state.json");
        let signing_key = SigningKey::random(&mut OsRng);
        let public_key = URL_SAFE_NO_PAD.encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        let initial_signed =
            SignedTopology::sign(manifest(b"public-certificate"), &signing_key).unwrap();
        let state = TopologyState::open(
            initial_signed.verify(&public_key).unwrap(),
            public_key.clone(),
            &path,
        )
        .unwrap();
        let mut next = manifest(b"public-certificate");
        next.epoch = 2;
        state
            .prepare(SignedTopology::sign(next, &signing_key).unwrap())
            .unwrap();
        state.commit(2).unwrap();
        drop(state);

        let restarted = TopologyState::open(
            initial_signed.verify(&public_key).unwrap(),
            public_key,
            &path,
        )
        .unwrap();
        assert_eq!(restarted.current().manifest().epoch, 2);
    }
}
