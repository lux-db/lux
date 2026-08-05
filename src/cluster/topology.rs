use super::{ClusterError, CLUSTER_PROTOCOL_VERSION};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{client::WebPkiServerVerifier, server::WebPkiClientVerifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

pub const CLUSTER_TOPOLOGY_SCHEMA_VERSION: u16 = 1;
pub const CLUSTER_SLOT_COUNT: u16 = 4096;
pub const CLUSTER_CLIENT_SLOT_COUNT: u16 = 16_384;
pub const CLUSTER_MAX_NODES: usize = 16;
const MAX_ENCODED_CONTROLLER_KEY_BYTES: usize = 128;
const MAX_ENCODED_SIGNATURE_BYTES: usize = 128;
const MAX_PEER_ENDPOINT_BYTES: usize = 512;
const MAX_CLIENT_ENDPOINT_BYTES: usize = 2048;
const MAX_CERTIFICATE_DER_BYTES: usize = 64 * 1024;
const MAX_CERTIFICATE_BASE64_BYTES: usize = (MAX_CERTIFICATE_DER_BYTES * 4).div_ceil(3);

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct NodeDescriptor {
    pub node_id: String,
    /// Internal DNS name or IP plus port for authenticated peer transport.
    pub peer_addr: String,
    /// TLS server name presented by this node's peer certificate.
    pub peer_server_name: String,
    /// Direct public endpoint used by topology-aware RESP clients.
    pub client_resp_url: String,
    /// Direct public base endpoint used by topology-aware HTTP clients.
    pub client_http_url: String,
    /// Public DER peer certificate, base64url encoded.
    pub peer_certificate_der: String,
    /// Lowercase SHA-256 of `peer_certificate_der`.
    pub peer_certificate_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SlotAssignment {
    pub start: u16,
    pub end: u16,
    pub node_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SlotMove {
    pub start: u16,
    pub end: u16,
    pub source_node_id: String,
    pub target_node_id: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TopologyTransitionKind {
    Membership,
    Ownership,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TopologyTransitionPlan {
    pub from_epoch: u64,
    pub to_epoch: u64,
    pub kind: TopologyTransitionKind,
    pub added_node_ids: Vec<String>,
    pub removed_node_ids: Vec<String>,
    pub updated_node_ids: Vec<String>,
    pub moves: Vec<SlotMove>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TopologyManifest {
    pub schema_version: u16,
    pub protocol_version: u16,
    pub cluster_id: String,
    pub epoch: u64,
    /// Node coordinating rare control-plane mutations. It is not part of the
    /// owner-local point-operation dataplane.
    pub control_node_id: String,
    pub slot_count: u16,
    /// Nodes must be sorted by `node_id` for a unique canonical manifest.
    pub nodes: Vec<NodeDescriptor>,
    /// Ordered, contiguous ownership ranges covering every internal slot.
    pub assignments: Vec<SlotAssignment>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignedTopology {
    pub manifest: TopologyManifest,
    /// Base64url P-256 ECDSA signature over the canonical manifest bytes.
    pub signature: String,
}

impl SignedTopology {
    pub fn sign(
        manifest: TopologyManifest,
        signing_key: &SigningKey,
    ) -> Result<Self, ClusterError> {
        validate_manifest(&manifest)?;
        let payload = canonical_manifest_bytes(&manifest)?;
        let signature: Signature = signing_key.sign(&payload);
        let signature = signature.normalize_s().unwrap_or(signature);
        Ok(Self {
            manifest,
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        })
    }

    pub fn verify(&self, controller_public_key: &str) -> Result<CompiledTopology, ClusterError> {
        if controller_public_key.len() > MAX_ENCODED_CONTROLLER_KEY_BYTES {
            return Err(ClusterError::Signature(
                "encoded controller public key is too large".to_owned(),
            ));
        }
        if self.signature.len() > MAX_ENCODED_SIGNATURE_BYTES {
            return Err(ClusterError::Signature(
                "encoded topology signature is too large".to_owned(),
            ));
        }
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
        if signature.normalize_s().is_some() {
            return Err(ClusterError::Signature(
                "signature is not in canonical low-S form".to_owned(),
            ));
        }
        let payload = canonical_manifest_bytes(&self.manifest)?;
        verifying_key
            .verify(&payload, &signature)
            .map_err(|_| ClusterError::Signature("manifest signature did not verify".to_owned()))?;
        CompiledTopology::compile(self.clone())
    }
}

impl TopologyManifest {
    pub fn signing_payload(&self) -> Result<Vec<u8>, ClusterError> {
        canonical_manifest_bytes(self)
    }
}

#[must_use]
pub fn encode_controller_public_key(verifying_key: &VerifyingKey) -> String {
    URL_SAFE_NO_PAD.encode(verifying_key.to_encoded_point(false).as_bytes())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedisSlotRange {
    pub start: u16,
    pub end: u16,
    pub node_id: String,
    pub client_resp_url: String,
}

#[derive(Clone, Debug)]
pub struct CompiledTopology {
    signed: SignedTopology,
    node_indexes: HashMap<String, u8>,
    slot_owners: Box<[u8; CLUSTER_SLOT_COUNT as usize]>,
}

impl CompiledTopology {
    fn compile(signed: SignedTopology) -> Result<Self, ClusterError> {
        validate_manifest(&signed.manifest)?;
        let node_indexes = signed
            .manifest
            .nodes
            .iter()
            .enumerate()
            .map(|(index, node)| (node.node_id.clone(), index as u8))
            .collect::<HashMap<_, _>>();
        let mut slot_owners = Box::new([u8::MAX; CLUSTER_SLOT_COUNT as usize]);
        for assignment in &signed.manifest.assignments {
            let owner = node_indexes[&assignment.node_id];
            for slot in assignment.start..=assignment.end {
                slot_owners[usize::from(slot)] = owner;
            }
        }
        Ok(Self {
            signed,
            node_indexes,
            slot_owners,
        })
    }

    #[must_use]
    pub fn manifest(&self) -> &TopologyManifest {
        &self.signed.manifest
    }

    #[must_use]
    pub fn signed(&self) -> &SignedTopology {
        &self.signed
    }

    #[inline]
    #[must_use]
    pub fn owner_for_slot(&self, slot: u16) -> Option<&NodeDescriptor> {
        let index = *self.slot_owners.get(usize::from(slot))?;
        self.signed.manifest.nodes.get(usize::from(index))
    }

    #[inline]
    #[must_use]
    pub fn owner_for_key(&self, key: &[u8]) -> &NodeDescriptor {
        self.owner_for_slot(slot_for_key(key))
            .expect("slot_for_key always returns a compiled slot")
    }

    #[inline]
    #[must_use]
    pub fn owner_for_table_row(&self, table: &[u8], primary_key: &[u8]) -> &NodeDescriptor {
        self.owner_for_slot(slot_for_table_row(table, primary_key))
            .expect("slot_for_table_row always returns a compiled slot")
    }

    #[must_use]
    pub fn node(&self, node_id: &str) -> Option<&NodeDescriptor> {
        self.node_indexes
            .get(node_id)
            .and_then(|index| self.signed.manifest.nodes.get(usize::from(*index)))
    }

    #[must_use]
    pub fn owns_slot(&self, node_id: &str, slot: u16) -> bool {
        self.owner_for_slot(slot)
            .is_some_and(|owner| owner.node_id == node_id)
    }

    #[must_use]
    pub fn redis_slot_ranges(&self) -> Vec<RedisSlotRange> {
        let projections = CLUSTER_CLIENT_SLOT_COUNT / CLUSTER_SLOT_COUNT;
        let mut ranges =
            Vec::with_capacity(self.manifest().assignments.len() * usize::from(projections));
        for projection in 0..projections {
            let offset = projection * CLUSTER_SLOT_COUNT;
            for assignment in &self.manifest().assignments {
                let owner = self
                    .node(&assignment.node_id)
                    .expect("validated assignment owner");
                ranges.push(RedisSlotRange {
                    start: assignment.start + offset,
                    end: assignment.end + offset,
                    node_id: owner.node_id.clone(),
                    client_resp_url: owner.client_resp_url.clone(),
                });
            }
        }
        ranges
    }

    pub fn transition_to(
        &self,
        candidate: &CompiledTopology,
    ) -> Result<TopologyTransitionPlan, ClusterError> {
        let current = self.manifest();
        let next = candidate.manifest();
        if current.cluster_id != next.cluster_id {
            return invalid("prepared topology belongs to another cluster");
        }
        let expected_epoch = current.epoch.checked_add(1).ok_or_else(|| {
            ClusterError::InvalidTopology("committed topology epoch is exhausted".to_owned())
        })?;
        if next.epoch != expected_epoch {
            return invalid(format!(
                "prepared epoch {} must immediately follow committed epoch {}",
                next.epoch, current.epoch
            ));
        }
        if current.control_node_id != next.control_node_id {
            return invalid("control-node failover requires its own coordination protocol");
        }
        for next_node in &next.nodes {
            for current_node in &current.nodes {
                if next_node.node_id == current_node.node_id {
                    continue;
                }
                let rebound_field =
                    if next_node.peer_certificate_sha256 == current_node.peer_certificate_sha256 {
                        Some("peer certificate")
                    } else if next_node.peer_addr == current_node.peer_addr {
                        Some("peer address")
                    } else if next_node.client_resp_url == current_node.client_resp_url {
                        Some("client RESP endpoint")
                    } else if next_node.client_http_url == current_node.client_http_url {
                        Some("client HTTP endpoint")
                    } else {
                        None
                    };
                if let Some(field) = rebound_field {
                    return invalid(format!(
                        "{field} cannot move directly from node {} to node {} in one epoch",
                        current_node.node_id, next_node.node_id
                    ));
                }
            }
        }

        let current_nodes = current
            .nodes
            .iter()
            .map(|node| (node.node_id.as_str(), node))
            .collect::<HashMap<_, _>>();
        let next_nodes = next
            .nodes
            .iter()
            .map(|node| (node.node_id.as_str(), node))
            .collect::<HashMap<_, _>>();
        let mut added_node_ids = next_nodes
            .keys()
            .filter(|node_id| !current_nodes.contains_key(**node_id))
            .map(|node_id| (*node_id).to_owned())
            .collect::<Vec<_>>();
        let mut removed_node_ids = current_nodes
            .keys()
            .filter(|node_id| !next_nodes.contains_key(**node_id))
            .map(|node_id| (*node_id).to_owned())
            .collect::<Vec<_>>();
        let mut updated_node_ids = current_nodes
            .iter()
            .filter_map(|(node_id, node)| {
                next_nodes
                    .get(node_id)
                    .filter(|next_node| *next_node != node)
                    .map(|_| (*node_id).to_owned())
            })
            .collect::<Vec<_>>();
        added_node_ids.sort();
        removed_node_ids.sort();
        updated_node_ids.sort();

        let mut moves = Vec::<SlotMove>::new();
        for slot in 0..CLUSTER_SLOT_COUNT {
            let source = &self
                .owner_for_slot(slot)
                .expect("compiled current slot")
                .node_id;
            let target = &candidate
                .owner_for_slot(slot)
                .expect("compiled candidate slot")
                .node_id;
            if source == target {
                continue;
            }
            if let Some(previous) = moves.last_mut() {
                if previous.end.saturating_add(1) == slot
                    && previous.source_node_id == *source
                    && previous.target_node_id == *target
                {
                    previous.end = slot;
                    continue;
                }
            }
            moves.push(SlotMove {
                start: slot,
                end: slot,
                source_node_id: source.clone(),
                target_node_id: target.clone(),
            });
        }

        let membership_changed = !added_node_ids.is_empty()
            || !removed_node_ids.is_empty()
            || !updated_node_ids.is_empty();
        if membership_changed && !moves.is_empty() {
            return invalid(
                "membership/certificate changes and slot ownership changes require separate epochs",
            );
        }
        if !membership_changed && moves.is_empty() {
            return invalid("prepared topology has no semantic change");
        }
        for node_id in &removed_node_ids {
            if (0..CLUSTER_SLOT_COUNT).any(|slot| self.owns_slot(node_id, slot)) {
                return invalid(format!("node {node_id} must own zero slots before removal"));
            }
        }

        Ok(TopologyTransitionPlan {
            from_epoch: current.epoch,
            to_epoch: next.epoch,
            kind: if membership_changed {
                TopologyTransitionKind::Membership
            } else {
                TopologyTransitionKind::Ownership
            },
            added_node_ids,
            removed_node_ids,
            updated_node_ids,
            moves,
        })
    }
}

fn canonical_manifest_bytes(manifest: &TopologyManifest) -> Result<Vec<u8>, ClusterError> {
    let mut bytes = Vec::with_capacity(1024);
    bytes.extend_from_slice(b"LUX-PROJECT-CLUSTER-TOPOLOGY\0");
    bytes.extend_from_slice(&manifest.schema_version.to_be_bytes());
    bytes.extend_from_slice(&manifest.protocol_version.to_be_bytes());
    push_string(&mut bytes, &manifest.cluster_id)?;
    bytes.extend_from_slice(&manifest.epoch.to_be_bytes());
    push_string(&mut bytes, &manifest.control_node_id)?;
    bytes.extend_from_slice(&manifest.slot_count.to_be_bytes());
    push_len(&mut bytes, manifest.nodes.len())?;
    for node in &manifest.nodes {
        push_string(&mut bytes, &node.node_id)?;
        push_string(&mut bytes, &node.peer_addr)?;
        push_string(&mut bytes, &node.peer_server_name)?;
        push_string(&mut bytes, &node.client_resp_url)?;
        push_string(&mut bytes, &node.client_http_url)?;
        push_string(&mut bytes, &node.peer_certificate_der)?;
        push_string(&mut bytes, &node.peer_certificate_sha256)?;
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
        ClusterError::InvalidTopology("canonical field exceeds u32 length".to_owned())
    })?;
    bytes.extend_from_slice(&length.to_be_bytes());
    Ok(())
}

fn validate_manifest(manifest: &TopologyManifest) -> Result<(), ClusterError> {
    if manifest.schema_version != CLUSTER_TOPOLOGY_SCHEMA_VERSION {
        return invalid(format!(
            "unsupported topology schema {}",
            manifest.schema_version
        ));
    }
    if manifest.protocol_version != CLUSTER_PROTOCOL_VERSION {
        return invalid(format!(
            "unsupported cluster protocol {}",
            manifest.protocol_version
        ));
    }
    validate_identifier("cluster_id", &manifest.cluster_id)?;
    if manifest.epoch == 0 {
        return invalid("epoch must be greater than zero");
    }
    if manifest.slot_count != CLUSTER_SLOT_COUNT {
        return invalid(format!("slot_count must be {CLUSTER_SLOT_COUNT}"));
    }
    if manifest.nodes.is_empty() || manifest.nodes.len() > CLUSTER_MAX_NODES {
        return invalid(format!(
            "topology must contain 1 to {CLUSTER_MAX_NODES} nodes"
        ));
    }
    if manifest
        .nodes
        .windows(2)
        .any(|nodes| nodes[0].node_id >= nodes[1].node_id)
    {
        return invalid("nodes must be uniquely sorted by node_id");
    }

    let mut node_ids = HashSet::new();
    let mut peer_addresses = HashSet::new();
    let mut resp_urls = HashSet::new();
    let mut http_urls = HashSet::new();
    let mut certificate_fingerprints = HashSet::new();
    for node in &manifest.nodes {
        validate_identifier("node_id", &node.node_id)?;
        node_ids.insert(node.node_id.as_str());
        if !peer_addresses.insert(node.peer_addr.as_str()) {
            return invalid(format!("duplicate peer address {}", node.peer_addr));
        }
        validate_host_port(&node.peer_addr).map_err(|message| {
            ClusterError::InvalidTopology(format!("node {} {message}", node.node_id))
        })?;
        if node.peer_server_name.len() > 253 {
            return invalid(format!(
                "node {} peer_server_name is too large",
                node.node_id
            ));
        }
        ServerName::try_from(node.peer_server_name.clone()).map_err(|_| {
            ClusterError::InvalidTopology(format!(
                "node {} peer_server_name is not a valid TLS name",
                node.node_id
            ))
        })?;
        validate_client_url(&node.client_resp_url, ClientProtocol::Resp)?;
        validate_client_url(&node.client_http_url, ClientProtocol::Http)?;
        if !resp_urls.insert(node.client_resp_url.as_str()) {
            return invalid(format!(
                "duplicate client RESP URL {}",
                node.client_resp_url
            ));
        }
        if !http_urls.insert(node.client_http_url.as_str()) {
            return invalid(format!(
                "duplicate client HTTP URL {}",
                node.client_http_url
            ));
        }
        let certificate = decode_certificate(node)?;
        let mut roots = rustls::RootCertStore::empty();
        let certificate = CertificateDer::from(certificate);
        roots.add(certificate.clone()).map_err(|error| {
            ClusterError::InvalidTopology(format!(
                "node {} peer certificate is not a valid trust anchor: {error}",
                node.node_id
            ))
        })?;
        let roots = Arc::new(roots);
        let server_name = ServerName::try_from(node.peer_server_name.clone()).map_err(|_| {
            ClusterError::InvalidTopology(format!(
                "node {} peer_server_name is not a valid TLS name",
                node.node_id
            ))
        })?;
        let now = rustls::pki_types::UnixTime::now();
        WebPkiServerVerifier::builder(Arc::clone(&roots))
            .build()
            .map_err(|error| {
                ClusterError::InvalidTopology(format!(
                    "node {} peer server verifier is invalid: {error}",
                    node.node_id
                ))
            })?
            .verify_server_cert(&certificate, &[], &server_name, &[], now)
            .map_err(|error| {
                ClusterError::InvalidTopology(format!(
                    "node {} peer certificate is not valid for {}: {error}",
                    node.node_id, node.peer_server_name
                ))
            })?;
        WebPkiClientVerifier::builder(roots)
            .build()
            .map_err(|error| {
                ClusterError::InvalidTopology(format!(
                    "node {} peer client verifier is invalid: {error}",
                    node.node_id
                ))
            })?
            .verify_client_cert(&certificate, &[], now)
            .map_err(|error| {
                ClusterError::InvalidTopology(format!(
                    "node {} peer certificate cannot authenticate as a client: {error}",
                    node.node_id
                ))
            })?;
        let actual_fingerprint = certificate_fingerprint(certificate.as_ref());
        if actual_fingerprint != node.peer_certificate_sha256 {
            return invalid(format!(
                "node {} peer certificate fingerprint mismatch",
                node.node_id
            ));
        }
        if !certificate_fingerprints.insert(node.peer_certificate_sha256.as_str()) {
            return invalid(format!(
                "node {} reuses another node's peer certificate",
                node.node_id
            ));
        }
    }
    if !node_ids.contains(manifest.control_node_id.as_str()) {
        return invalid("control_node_id is not present in nodes");
    }

    let Some(first) = manifest.assignments.first() else {
        return invalid("slot assignments are required");
    };
    if first.start != 0 || first.end < first.start {
        return invalid("slot assignments must begin at slot zero");
    }
    if !node_ids.contains(first.node_id.as_str()) {
        return invalid("first slot assignment references an unknown node");
    }
    let mut previous = first;
    for assignment in &manifest.assignments[1..] {
        if u32::from(assignment.start) != u32::from(previous.end) + 1 {
            return invalid("slot assignments must be contiguous and non-overlapping");
        }
        if assignment.end < assignment.start {
            return invalid("slot assignment end precedes start");
        }
        if assignment.node_id == previous.node_id {
            return invalid("adjacent ranges for one owner must be coalesced");
        }
        if !node_ids.contains(assignment.node_id.as_str()) {
            return invalid(format!(
                "slot owner {} is not a topology node",
                assignment.node_id
            ));
        }
        previous = assignment;
    }
    if previous.end != CLUSTER_SLOT_COUNT - 1 {
        return invalid(format!(
            "slot assignments must end at slot {}",
            CLUSTER_SLOT_COUNT - 1
        ));
    }
    Ok(())
}

fn validate_identifier(label: &str, value: &str) -> Result<(), ClusterError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return invalid(format!(
            "{label} must contain 1 to 128 ASCII identifier characters"
        ));
    }
    Ok(())
}

fn validate_host_port(endpoint: &str) -> Result<(), String> {
    if endpoint.len() > MAX_PEER_ENDPOINT_BYTES {
        return Err("peer_addr is too large".to_owned());
    }
    let url = reqwest::Url::parse(&format!("cluster-peer://{endpoint}"))
        .map_err(|_| "peer_addr must be a DNS name or IP plus port".to_owned())?;
    let host = url
        .host_str()
        .ok_or_else(|| "peer_addr has an invalid host".to_owned())?;
    ServerName::try_from(host.to_owned())
        .map_err(|_| "peer_addr has an invalid host".to_owned())?;
    if url.port().filter(|port| *port != 0).is_none() {
        return Err("peer_addr must use a non-zero port".to_owned());
    }
    if url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err("peer_addr must contain only a host and port".to_owned());
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum ClientProtocol {
    Resp,
    Http,
}

fn validate_client_url(raw: &str, protocol: ClientProtocol) -> Result<(), ClusterError> {
    if raw.len() > MAX_CLIENT_ENDPOINT_BYTES {
        return invalid("direct client URL is too large");
    }
    let url = reqwest::Url::parse(raw).map_err(|error| {
        ClusterError::InvalidTopology(format!("invalid direct client URL {raw}: {error}"))
    })?;
    let host = url
        .host_str()
        .ok_or_else(|| ClusterError::InvalidTopology(format!("client URL {raw} has no host")))?;
    let (secure, allowed) = match protocol {
        ClientProtocol::Resp => (
            matches!(url.scheme(), "rediss" | "luxs"),
            matches!(url.scheme(), "redis" | "rediss" | "lux" | "luxs"),
        ),
        ClientProtocol::Http => (
            url.scheme() == "https",
            matches!(url.scheme(), "http" | "https"),
        ),
    };
    if !allowed {
        return invalid(format!("client URL {raw} uses an unsupported scheme"));
    }
    if !secure && !host_is_loopback(host) {
        return invalid(format!("non-loopback client URL {raw} must use TLS"));
    }
    if url.port_or_known_default().is_none() {
        return invalid(format!("client URL {raw} has no usable port"));
    }
    if url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return invalid(format!(
            "client URL {raw} cannot contain credentials, query, or fragment"
        ));
    }
    if matches!(protocol, ClientProtocol::Resp) && !matches!(url.path(), "" | "/") {
        return invalid(format!("RESP client URL {raw} cannot contain a path"));
    }
    Ok(())
}

fn host_is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn decode_certificate(node: &NodeDescriptor) -> Result<Vec<u8>, ClusterError> {
    if node.peer_certificate_der.len() > MAX_CERTIFICATE_BASE64_BYTES {
        return invalid(format!(
            "node {} peer certificate is too large",
            node.node_id
        ));
    }
    let certificate = URL_SAFE_NO_PAD
        .decode(&node.peer_certificate_der)
        .map_err(|error| {
            ClusterError::InvalidTopology(format!(
                "node {} peer certificate is not base64url: {error}",
                node.node_id
            ))
        })?;
    if certificate.is_empty() || certificate.len() > MAX_CERTIFICATE_DER_BYTES {
        return invalid(format!(
            "node {} peer certificate has an invalid size",
            node.node_id
        ));
    }
    Ok(certificate)
}

#[must_use]
pub fn certificate_fingerprint(certificate_der: &[u8]) -> String {
    hex_digest(&Sha256::digest(certificate_der))
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

#[inline]
#[must_use]
pub fn slot_for_key(key: &[u8]) -> u16 {
    redis_crc16(hash_tag(key)) % CLUSTER_SLOT_COUNT
}

#[inline]
#[must_use]
pub fn slot_for_table_row(table: &[u8], primary_key: &[u8]) -> u16 {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x100_0000_01b3;
    let mut hash = fnv1a64_continue(FNV_OFFSET, table);
    hash ^= 0;
    hash = hash.wrapping_mul(FNV_PRIME);
    hash = fnv1a64_continue(hash, primary_key);
    (hash % u64::from(CLUSTER_SLOT_COUNT)) as u16
}

fn redis_crc16(bytes: &[u8]) -> u16 {
    let mut crc = 0_u16;
    for &byte in bytes {
        crc ^= u16::from(byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

fn fnv1a64_continue(mut hash: u64, bytes: &[u8]) -> u64 {
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100_0000_01b3);
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

fn invalid<T>(message: impl Into<String>) -> Result<T, ClusterError> {
    Err(ClusterError::InvalidTopology(message.into()))
}

#[cfg(test)]
#[path = "topology_tests.rs"]
mod tests;
