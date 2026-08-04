use super::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use rand_core::OsRng;

pub(super) const CLUSTER_PROTOCOL_VERSION: u16 = 1;
pub(super) const CLUSTER_TOPOLOGY_SCHEMA_VERSION: u16 = 1;
pub(super) const CLUSTER_SLOT_COUNT: u16 = 4096;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct NodeDescriptor {
    pub(super) node_id: String,
    pub(super) peer_addr: String,
    pub(super) client_addr: String,
    pub(super) server_name: String,
    pub(super) certificate_der: String,
    pub(super) certificate_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct SlotAssignment {
    pub(super) start: u16,
    pub(super) end: u16,
    pub(super) node_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct TopologyManifest {
    pub(super) schema_version: u16,
    pub(super) protocol_version: u16,
    pub(super) cluster_id: String,
    pub(super) epoch: u64,
    pub(super) system_node_id: String,
    pub(super) slot_count: u16,
    pub(super) catalog_version: u64,
    pub(super) nodes: Vec<NodeDescriptor>,
    pub(super) assignments: Vec<SlotAssignment>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct SignedTopology {
    pub(super) manifest: TopologyManifest,
    pub(super) signature: String,
}

impl SignedTopology {
    fn sign(manifest: TopologyManifest, signing_key: &SigningKey) -> Result<Self, String> {
        let payload = topology_signing_payload(&manifest)?;
        let signature: Signature = signing_key.sign(&payload);
        Ok(Self {
            manifest,
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        })
    }
}

pub(super) fn topology_signing_payload(manifest: &TopologyManifest) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::with_capacity(1024);
    bytes.extend_from_slice(b"LUX-CLUSTER-TOPOLOGY\0");
    bytes.extend_from_slice(&manifest.schema_version.to_be_bytes());
    bytes.extend_from_slice(&manifest.protocol_version.to_be_bytes());
    topology_push_string(&mut bytes, &manifest.cluster_id)?;
    bytes.extend_from_slice(&manifest.epoch.to_be_bytes());
    topology_push_string(&mut bytes, &manifest.system_node_id)?;
    bytes.extend_from_slice(&manifest.slot_count.to_be_bytes());
    bytes.extend_from_slice(&manifest.catalog_version.to_be_bytes());
    topology_push_len(&mut bytes, manifest.nodes.len())?;
    for node in &manifest.nodes {
        topology_push_string(&mut bytes, &node.node_id)?;
        topology_push_string(&mut bytes, &node.peer_addr)?;
        topology_push_string(&mut bytes, &node.client_addr)?;
        topology_push_string(&mut bytes, &node.server_name)?;
        topology_push_string(&mut bytes, &node.certificate_der)?;
        topology_push_string(&mut bytes, &node.certificate_sha256)?;
    }
    topology_push_len(&mut bytes, manifest.assignments.len())?;
    for assignment in &manifest.assignments {
        bytes.extend_from_slice(&assignment.start.to_be_bytes());
        bytes.extend_from_slice(&assignment.end.to_be_bytes());
        topology_push_string(&mut bytes, &assignment.node_id)?;
    }
    Ok(bytes)
}

pub(super) fn topology_push_string(bytes: &mut Vec<u8>, value: &str) -> Result<(), String> {
    topology_push_len(bytes, value.len())?;
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

pub(super) fn topology_push_len(bytes: &mut Vec<u8>, length: usize) -> Result<(), String> {
    let length = u32::try_from(length).map_err(|_| "topology field exceeds u32 length")?;
    bytes.extend_from_slice(&length.to_be_bytes());
    Ok(())
}

pub(super) fn certificate_fingerprint(certificate_der: &[u8]) -> String {
    let digest = Sha256::digest(certificate_der);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct LocalClusterNode {
    pub(super) node_id: String,
    pub(super) container: String,
    pub(super) volume: String,
    #[serde(default)]
    pub(super) resp_port: u16,
    pub(super) http_port: u16,
    pub(super) server_name: String,
    pub(super) certificate_der: String,
    pub(super) certificate_file: String,
    pub(super) private_key_file: String,
    pub(super) config_file: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct LocalClusterState {
    pub(super) cluster_id: String,
    pub(super) network: String,
    pub(super) epoch: u64,
    pub(super) controller_private_key_file: String,
    pub(super) controller_public_key: String,
    pub(super) topology_file: String,
    pub(super) nodes: Vec<LocalClusterNode>,
    #[serde(default)]
    pub(super) retired_nodes: Vec<LocalClusterNode>,
    #[serde(default)]
    pub(super) pending_resize: Option<PendingLocalResize>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct PendingLocalResize {
    pub(super) desired_nodes: u16,
    pub(super) direction: String,
    pub(super) membership: SignedTopology,
    pub(super) ownership: SignedTopology,
    pub(super) next_nodes: Vec<LocalClusterNode>,
    pub(super) leaving_nodes: Vec<LocalClusterNode>,
}

pub(super) const LOCAL_CLUSTER_MAX_NODES: u16 = 16;
pub(super) const LOCAL_CLUSTER_PEER_PORT: u16 = 7443;

pub(super) fn local_cluster_dir() -> PathBuf {
    PathBuf::from("lux").join(".lux-cluster")
}

pub(super) fn validate_local_node_count(nodes: u16) -> Result<(), String> {
    if (1..=LOCAL_CLUSTER_MAX_NODES).contains(&nodes) {
        Ok(())
    } else {
        Err(format!(
            "local node count must be between 1 and {LOCAL_CLUSTER_MAX_NODES}"
        ))
    }
}

pub(super) fn create_local_cluster_node(
    state: &LocalState,
    ordinal: u16,
    resp_port: u16,
    http_port: u16,
) -> Result<LocalClusterNode, String> {
    let node_id = format!("node-{ordinal}");
    let server_name = format!("{node_id}.cluster.local");
    let key = rcgen::KeyPair::generate().map_err(|error| format!("generate node key: {error}"))?;
    let certificate = rcgen::CertificateParams::new(vec![server_name.clone()])
        .map_err(|error| format!("create node certificate: {error}"))?
        .self_signed(&key)
        .map_err(|error| format!("sign node certificate: {error}"))?;
    let dir = local_cluster_dir();
    ensure_private_dir(&dir)?;
    let certificate_file = format!("{node_id}.pem");
    let private_key_file = format!("{node_id}.key");
    let config_file = format!("{node_id}.json");
    write_secret_file(&dir.join(&certificate_file), certificate.pem().as_bytes())?;
    write_secret_file(&dir.join(&private_key_file), key.serialize_pem().as_bytes())?;
    let certificate_der = certificate.der().as_ref();
    Ok(LocalClusterNode {
        node_id,
        container: if ordinal == 1 {
            state.container.clone()
        } else {
            format!("{}-node-{ordinal}", state.container)
        },
        volume: if ordinal == 1 {
            state.volume.clone()
        } else {
            format!("{}-node-{ordinal}", state.volume)
        },
        resp_port,
        http_port,
        server_name,
        certificate_der: URL_SAFE_NO_PAD.encode(certificate_der),
        certificate_file,
        private_key_file,
        config_file,
    })
}

pub(super) fn controller_signing_key(cluster: &LocalClusterState) -> Result<SigningKey, String> {
    let encoded =
        std::fs::read_to_string(local_cluster_dir().join(&cluster.controller_private_key_file))
            .map_err(|error| format!("read local cluster controller key: {error}"))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded.trim())
        .map_err(|error| format!("decode local cluster controller key: {error}"))?;
    SigningKey::from_slice(&bytes)
        .map_err(|error| format!("parse local cluster controller key: {error}"))
}

pub(super) fn local_node_descriptor(node: &LocalClusterNode) -> Result<NodeDescriptor, String> {
    let certificate_der = URL_SAFE_NO_PAD
        .decode(&node.certificate_der)
        .map_err(|error| format!("decode certificate for {}: {error}", node.node_id))?;
    Ok(NodeDescriptor {
        node_id: node.node_id.clone(),
        peer_addr: format!("{}:{LOCAL_CLUSTER_PEER_PORT}", node.container),
        client_addr: format!("127.0.0.1:{}", node.resp_port),
        server_name: node.server_name.clone(),
        certificate_der: node.certificate_der.clone(),
        certificate_sha256: certificate_fingerprint(&certificate_der),
    })
}

pub(super) fn balanced_slot_assignments(nodes: &[LocalClusterNode]) -> Vec<SlotAssignment> {
    let count = nodes.len() as u32;
    nodes
        .iter()
        .enumerate()
        .map(|(index, node)| {
            let index = index as u32;
            let start = (index * u32::from(CLUSTER_SLOT_COUNT) / count) as u16;
            let end = (((index + 1) * u32::from(CLUSTER_SLOT_COUNT) / count) - 1) as u16;
            SlotAssignment {
                start,
                end,
                node_id: node.node_id.clone(),
            }
        })
        .collect()
}

pub(super) fn assignment_owner(assignments: &[SlotAssignment], slot: u16) -> Option<&str> {
    assignments
        .iter()
        .find(|assignment| slot >= assignment.start && slot <= assignment.end)
        .map(|assignment| assignment.node_id.as_str())
}

pub(super) fn ownership_target_nodes(
    current: &[SlotAssignment],
    next: &[SlotAssignment],
) -> HashSet<String> {
    (0..CLUSTER_SLOT_COUNT)
        .filter_map(|slot| {
            let source = assignment_owner(current, slot)?;
            let target = assignment_owner(next, slot)?;
            (source != target).then(|| target.to_string())
        })
        .collect()
}

pub(super) fn sign_local_topology(
    cluster: &LocalClusterState,
    nodes: &[LocalClusterNode],
    assignments: Vec<SlotAssignment>,
    epoch: u64,
) -> Result<SignedTopology, String> {
    let descriptors = nodes
        .iter()
        .map(local_node_descriptor)
        .collect::<Result<Vec<_>, _>>()?;
    SignedTopology::sign(
        TopologyManifest {
            schema_version: CLUSTER_TOPOLOGY_SCHEMA_VERSION,
            protocol_version: CLUSTER_PROTOCOL_VERSION,
            cluster_id: cluster.cluster_id.clone(),
            epoch,
            system_node_id: "node-1".to_string(),
            slot_count: CLUSTER_SLOT_COUNT,
            catalog_version: 1,
            nodes: descriptors,
            assignments,
        },
        &controller_signing_key(cluster)?,
    )
    .map_err(|error| format!("sign local topology: {error}"))
}

pub(super) fn write_local_topology(
    cluster: &LocalClusterState,
    topology: &SignedTopology,
) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(topology)
        .map_err(|error| format!("encode local topology: {error}"))?;
    write_secret_file(&local_cluster_dir().join(&cluster.topology_file), &bytes)
}

pub(super) fn write_local_node_config(
    cluster: &LocalClusterState,
    node: &LocalClusterNode,
) -> Result<(), String> {
    let config = serde_json::json!({
        "local_node_id": node.node_id,
        "peer_bind_addr": format!("0.0.0.0:{LOCAL_CLUSTER_PEER_PORT}"),
        "certificate_chain_path": format!("/cluster/{}", node.certificate_file),
        "private_key_path": format!("/cluster/{}", node.private_key_file),
        "topology_path": format!("/cluster/{}", cluster.topology_file),
        "topology_state_path": "/data/cluster-topology-state.json",
        "controller_public_key": cluster.controller_public_key,
    });
    let bytes = serde_json::to_vec_pretty(&config)
        .map_err(|error| format!("encode {} config: {error}", node.node_id))?;
    write_secret_file(&local_cluster_dir().join(&node.config_file), &bytes)
}

pub(super) fn ensure_local_cluster_network(cluster: &LocalClusterState) -> Result<(), String> {
    if docker_output(&["network", "inspect", &cluster.network]).is_ok() {
        return Ok(());
    }
    docker_output(&["network", "create", &cluster.network]).map(|_| ())
}

pub(super) fn run_local_cluster_node(
    state: &LocalState,
    cluster: &LocalClusterState,
    node: &LocalClusterNode,
) -> Result<(), String> {
    let cluster_dir = std::fs::canonicalize(local_cluster_dir())
        .map_err(|error| format!("resolve local cluster directory: {error}"))?;
    let cluster_mount = format!("{}:/cluster:ro", cluster_dir.display());
    let volume_mount = format!("{}:/data", node.volume);
    let mut owned = local_engine_env(state);
    owned.push(format!("LUX_CLUSTER_CONFIG=/cluster/{}", node.config_file));
    let mut args: Vec<String> = vec![
        "run".into(),
        "-d".into(),
        "--name".into(),
        node.container.clone(),
        "--network".into(),
        cluster.network.clone(),
        "-v".into(),
        volume_mount,
        "-v".into(),
        cluster_mount,
    ];
    if node.node_id == "node-1" {
        args.extend([
            "-p".into(),
            docker_port_map(state.bind_host, state.resp_port, 6379),
            "-p".into(),
            docker_port_map(state.bind_host, state.http_port, 5890),
        ]);
    } else {
        args.extend([
            "-p".into(),
            docker_port_map(IpAddr::V4(Ipv4Addr::LOCALHOST), node.resp_port, 6379),
            "-p".into(),
            docker_port_map(IpAddr::V4(Ipv4Addr::LOCALHOST), node.http_port, 5890),
        ]);
    }
    for entry in &owned {
        args.push("-e".into());
        args.push(entry.clone());
    }
    args.extend([
        "--restart".into(),
        "unless-stopped".into(),
        state.image.clone(),
    ]);
    let refs = args.iter().map(String::as_str).collect::<Vec<_>>();
    docker_output(&refs).map(|_| ())
}

pub(super) fn load_local_topology(cluster: &LocalClusterState) -> Result<SignedTopology, String> {
    let bytes = std::fs::read(local_cluster_dir().join(&cluster.topology_file))
        .map_err(|error| format!("read local topology: {error}"))?;
    serde_json::from_slice(&bytes).map_err(|error| format!("decode local topology: {error}"))
}

pub(super) fn local_cluster_node_url(state: &LocalState, node: &LocalClusterNode) -> String {
    if node.node_id == "node-1" {
        state.lux_url()
    } else {
        format!("http://127.0.0.1:{}", node.http_port)
    }
}

pub(super) async fn wait_for_local_cluster_node(
    state: &LocalState,
    node: &LocalClusterNode,
) -> bool {
    let client = reqwest::Client::new();
    let url = format!("{}/v1/version", local_cluster_node_url(state, node));
    for _ in 0..60 {
        if client
            .get(&url)
            .header("Authorization", format!("Bearer {}", state.password))
            .send()
            .await
            .is_ok_and(|response| response.status().is_success())
        {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    false
}

pub(super) fn wait_for_local_cluster_node_tcp(state: &LocalState, node: &LocalClusterNode) -> bool {
    let address = if node.node_id == "node-1" {
        std::net::SocketAddr::new(state.connection_ip(), state.http_port)
    } else {
        std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), node.http_port)
    };
    for _ in 0..60 {
        if TcpStream::connect_timeout(&address, std::time::Duration::from_millis(250)).is_ok() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    false
}

pub(super) async fn local_cluster_post(
    state: &LocalState,
    node: &LocalClusterNode,
    path: &str,
    body: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let response = reqwest::Client::new()
        .post(format!("{}{}", local_cluster_node_url(state, node), path))
        .header("Authorization", format!("Bearer {}", state.password))
        .json(body)
        .send()
        .await
        .map_err(|error| format!("{} {path}: {error}", node.node_id))?;
    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|error| format!("{} {path}: read response: {error}", node.node_id))?;
    if !status.is_success() {
        return Err(format!("{} {path}: HTTP {status}: {text}", node.node_id));
    }
    serde_json::from_str(&text)
        .map_err(|error| format!("{} {path}: invalid response: {error}", node.node_id))
}

pub(super) async fn local_cluster_status(
    state: &LocalState,
    node: &LocalClusterNode,
) -> Result<serde_json::Value, String> {
    let response = reqwest::Client::new()
        .get(format!(
            "{}/v1/cluster/status",
            local_cluster_node_url(state, node)
        ))
        .header("Authorization", format!("Bearer {}", state.password))
        .send()
        .await
        .map_err(|error| format!("{} status: {error}", node.node_id))?;
    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|error| format!("{} status: read response: {error}", node.node_id))?;
    if !status.is_success() {
        return Err(format!("{} status: HTTP {status}: {text}", node.node_id));
    }
    serde_json::from_str(&text)
        .map_err(|error| format!("{} status: invalid response: {error}", node.node_id))
}

pub(super) fn next_local_node_ordinal(cluster: &LocalClusterState) -> u16 {
    cluster
        .nodes
        .iter()
        .chain(cluster.retired_nodes.iter())
        .filter_map(|node| node.node_id.strip_prefix("node-")?.parse::<u16>().ok())
        .max()
        .unwrap_or(0)
        .saturating_add(1)
}

pub(super) fn reserve_local_node_http_port(state: &LocalState, used: &mut HashSet<u16>) -> u16 {
    let mut port = state.http_port.saturating_add(10);
    while used.contains(&port) || !port_is_free(IpAddr::V4(Ipv4Addr::LOCALHOST), port) {
        port = port.saturating_add(1);
    }
    used.insert(port);
    port
}

pub(super) fn reserve_local_node_resp_port(state: &LocalState, used: &mut HashSet<u16>) -> u16 {
    let mut port = state.resp_port.saturating_add(10);
    while used.contains(&port) || !port_is_free(IpAddr::V4(Ipv4Addr::LOCALHOST), port) {
        port = port.saturating_add(1);
    }
    used.insert(port);
    port
}

pub(super) async fn initialize_local_cluster(state: &mut LocalState) -> Result<(), String> {
    if state.cluster.is_some() {
        return Ok(());
    }
    ensure_private_dir(&local_cluster_dir())?;
    let controller = SigningKey::random(&mut OsRng);
    let controller_private_key_file = "controller.key".to_string();
    write_secret_file(
        &local_cluster_dir().join(&controller_private_key_file),
        URL_SAFE_NO_PAD.encode(controller.to_bytes()).as_bytes(),
    )?;
    let controller_public_key = URL_SAFE_NO_PAD.encode(
        controller
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes(),
    );
    let system = create_local_cluster_node(state, 1, state.resp_port, state.http_port)?;
    let cluster = LocalClusterState {
        cluster_id: format!("local-{}-{}", project_slug(), random_hex(8)),
        network: format!("{}-cluster", state.container),
        epoch: 1,
        controller_private_key_file,
        controller_public_key,
        topology_file: "topology.json".to_string(),
        nodes: vec![system.clone()],
        retired_nodes: Vec::new(),
        pending_resize: None,
    };
    let topology = sign_local_topology(
        &cluster,
        &cluster.nodes,
        vec![SlotAssignment {
            start: 0,
            end: CLUSTER_SLOT_COUNT - 1,
            node_id: system.node_id.clone(),
        }],
        cluster.epoch,
    )?;
    write_local_topology(&cluster, &topology)?;
    write_local_node_config(&cluster, &system)?;
    ensure_local_cluster_network(&cluster)?;

    if docker_container_state(&state.container).is_some() {
        docker_output(&["rm", "-f", &state.container])?;
    }
    state.cluster = Some(cluster.clone());
    save_local_state(state);
    run_local_cluster_node(state, &cluster, &system)?;
    if !wait_for_local_cluster_node(state, &system).await {
        return Err(format!(
            "{} did not become ready; check `docker logs {}`",
            system.node_id, system.container
        ));
    }
    Ok(())
}

pub(super) async fn start_persisted_local_cluster(state: &LocalState) -> Result<(), String> {
    let cluster = state
        .cluster
        .as_ref()
        .ok_or_else(|| "local cluster state is missing".to_string())?;
    ensure_local_cluster_network(cluster)?;
    for node in &cluster.nodes {
        write_local_node_config(cluster, node)?;
        if docker_container_state(&node.container).as_deref() != Some("running") {
            if docker_container_state(&node.container).is_some() {
                docker_output(&["rm", "-f", &node.container])?;
            }
            run_local_cluster_node(state, cluster, node)?;
        }
    }
    for node in &cluster.nodes {
        if !wait_for_local_cluster_node(state, node).await {
            return Err(format!(
                "{} did not become ready; check `docker logs {}`",
                node.node_id, node.container
            ));
        }
    }
    Ok(())
}

pub(super) async fn apply_local_topology(
    state: &LocalState,
    nodes: &[LocalClusterNode],
    topology: &SignedTopology,
    ownership: bool,
    target_node_ids: &HashSet<String>,
) -> Result<(), String> {
    let body = serde_json::to_value(topology)
        .map_err(|error| format!("encode topology request: {error}"))?;
    let epoch = topology.manifest.epoch;
    for node in nodes {
        let status = local_cluster_status(state, node).await?;
        let current_epoch = status["current"]["epoch"].as_u64().unwrap_or(0);
        let pending_epoch = status["pending"]["epoch"].as_u64();
        if current_epoch > epoch {
            return Err(format!(
                "{} is already at epoch {current_epoch}, ahead of resize epoch {epoch}",
                node.node_id
            ));
        }
        if current_epoch == epoch || pending_epoch == Some(epoch) {
            continue;
        }
        if current_epoch + 1 != epoch {
            return Err(format!(
                "{} is at epoch {current_epoch} with no prepared epoch {epoch}",
                node.node_id
            ));
        }
        local_cluster_post(state, node, "/v1/cluster/topology/prepare", &body).await?;
    }
    if ownership {
        let system = nodes
            .iter()
            .find(|node| node.node_id == "node-1")
            .ok_or_else(|| "local cluster has no system node".to_string())?;
        if local_cluster_status(state, system).await?["current"]["epoch"].as_u64() != Some(epoch) {
            local_cluster_post(
                state,
                system,
                "/v1/cluster/catalogs/sync",
                &serde_json::json!({}),
            )
            .await?;
        }
        for node in nodes {
            if local_cluster_status(state, node).await?["current"]["epoch"].as_u64() != Some(epoch)
            {
                local_cluster_post(
                    state,
                    node,
                    "/v1/cluster/transfers/run",
                    &serde_json::json!({}),
                )
                .await?;
            }
        }
    }
    for target_first in [true, false] {
        for node in nodes {
            if target_node_ids.contains(&node.node_id) != target_first {
                continue;
            }
            if local_cluster_status(state, node).await?["current"]["epoch"].as_u64() == Some(epoch)
            {
                continue;
            }
            local_cluster_post(
                state,
                node,
                "/v1/cluster/topology/commit",
                &serde_json::json!({ "epoch": epoch }),
            )
            .await?;
        }
    }
    if ownership {
        for node in nodes {
            let status = local_cluster_status(state, node).await?;
            if !status["transfer"].is_null() {
                local_cluster_post(
                    state,
                    node,
                    "/v1/cluster/transfers/finalize",
                    &serde_json::json!({ "epoch": epoch }),
                )
                .await?;
            }
        }
    }
    Ok(())
}

pub(super) async fn resize_local_cluster(
    state: &mut LocalState,
    desired: u16,
) -> Result<(), String> {
    validate_local_node_count(desired)?;
    if desired > 1 && state.cluster.is_none() {
        println!("{} enabling Cluster on the system node", "Cluster:".bold());
        initialize_local_cluster(state).await?;
    }
    let Some(mut cluster) = state.cluster.clone() else {
        return Ok(());
    };
    start_persisted_local_cluster(state).await?;

    // A resize intent is saved before its first network mutation. Reconcile it
    // exactly (same certificates, manifests, signatures, and epochs) after a
    // CLI crash before considering a newly requested size.
    if cluster.pending_resize.is_some() {
        reconcile_pending_local_resize(state).await?;
        cluster = state
            .cluster
            .clone()
            .ok_or_else(|| "local cluster state disappeared".to_string())?;
    }
    let current = cluster.nodes.len() as u16;
    if current == desired {
        return Ok(());
    }
    let current_topology = load_local_topology(&cluster)?;
    let pending = if desired > current {
        let mut all_nodes = cluster.nodes.clone();
        let mut used = all_nodes
            .iter()
            .map(|node| node.http_port)
            .collect::<HashSet<_>>();
        let mut used_resp = all_nodes
            .iter()
            .map(|node| node.resp_port)
            .collect::<HashSet<_>>();
        let mut ordinal = next_local_node_ordinal(&cluster);
        while all_nodes.len() < desired as usize {
            let port = reserve_local_node_http_port(state, &mut used);
            let resp_port = reserve_local_node_resp_port(state, &mut used_resp);
            all_nodes.push(create_local_cluster_node(state, ordinal, resp_port, port)?);
            ordinal = ordinal.saturating_add(1);
        }

        let membership_epoch = cluster.epoch + 1;
        let membership = sign_local_topology(
            &cluster,
            &all_nodes,
            current_topology.manifest.assignments.clone(),
            membership_epoch,
        )?;
        let ownership_epoch = membership_epoch + 1;
        let assignments = balanced_slot_assignments(&all_nodes);
        let ownership = sign_local_topology(&cluster, &all_nodes, assignments, ownership_epoch)?;
        PendingLocalResize {
            desired_nodes: desired,
            direction: "up".to_string(),
            membership,
            ownership,
            next_nodes: all_nodes,
            leaving_nodes: Vec::new(),
        }
    } else {
        let retained = cluster.nodes[..desired as usize].to_vec();
        let leaving = cluster.nodes[desired as usize..].to_vec();
        let ownership_epoch = cluster.epoch + 1;
        let assignments = balanced_slot_assignments(&retained);
        let ownership =
            sign_local_topology(&cluster, &cluster.nodes, assignments, ownership_epoch)?;
        let membership_epoch = ownership_epoch + 1;
        let membership = sign_local_topology(
            &cluster,
            &retained,
            ownership.manifest.assignments.clone(),
            membership_epoch,
        )?;
        PendingLocalResize {
            desired_nodes: desired,
            direction: "down".to_string(),
            membership,
            ownership,
            next_nodes: retained,
            leaving_nodes: leaving,
        }
    };
    cluster.pending_resize = Some(pending);
    state.cluster = Some(cluster);
    save_local_state(state);
    reconcile_pending_local_resize(state).await
}

pub(super) async fn reconcile_pending_local_resize(state: &mut LocalState) -> Result<(), String> {
    let mut cluster = state
        .cluster
        .clone()
        .ok_or_else(|| "local cluster state is missing".to_string())?;
    let pending = cluster
        .pending_resize
        .clone()
        .ok_or_else(|| "local cluster has no pending resize".to_string())?;
    match pending.direction.as_str() {
        "up" => {
            println!(
                "{} admitting {} node(s)",
                "Cluster:".bold(),
                pending.next_nodes.len().saturating_sub(cluster.nodes.len())
            );
            apply_local_topology(
                state,
                &cluster.nodes,
                &pending.membership,
                false,
                &HashSet::new(),
            )
            .await?;
            cluster.epoch = pending.membership.manifest.epoch;
            cluster.nodes = pending.next_nodes.clone();
            write_local_topology(&cluster, &pending.membership)?;
            for node in &cluster.nodes {
                write_local_node_config(&cluster, node)?;
            }
            state.cluster = Some(cluster.clone());
            save_local_state(state);
            start_persisted_local_cluster(state).await?;

            println!("{} redistributing 4,096 slots", "Cluster:".bold());
            let targets = ownership_target_nodes(
                &pending.membership.manifest.assignments,
                &pending.ownership.manifest.assignments,
            );
            apply_local_topology(state, &cluster.nodes, &pending.ownership, true, &targets).await?;
            cluster.epoch = pending.ownership.manifest.epoch;
            write_local_topology(&cluster, &pending.ownership)?;
        }
        "down" => {
            println!(
                "{} consolidating data off {} node(s)",
                "Cluster:".bold(),
                pending.leaving_nodes.len()
            );
            let current = load_local_topology(&cluster)?;
            let targets = ownership_target_nodes(
                &current.manifest.assignments,
                &pending.ownership.manifest.assignments,
            );
            apply_local_topology(state, &cluster.nodes, &pending.ownership, true, &targets).await?;
            cluster.epoch = pending.ownership.manifest.epoch;
            write_local_topology(&cluster, &pending.ownership)?;
            state.cluster = Some(cluster.clone());
            save_local_state(state);

            let leaving = pending
                .leaving_nodes
                .iter()
                .map(|node| node.node_id.clone())
                .collect::<HashSet<_>>();
            apply_local_topology(state, &cluster.nodes, &pending.membership, false, &leaving)
                .await?;
            cluster.epoch = pending.membership.manifest.epoch;
            write_local_topology(&cluster, &pending.membership)?;
            for node in &pending.leaving_nodes {
                if docker_container_state(&node.container).is_some() {
                    docker_output(&["rm", "-f", &node.container])?;
                }
            }
            cluster.nodes = pending.next_nodes.clone();
            cluster
                .retired_nodes
                .extend(pending.leaving_nodes.iter().cloned());
        }
        other => return Err(format!("unknown pending local resize direction {other}")),
    }
    cluster.pending_resize = None;
    state.cluster = Some(cluster);
    save_local_state(state);
    Ok(())
}

pub(super) async fn consolidate_local_cluster(state: &mut LocalState) -> Result<(), String> {
    if state.cluster.is_none() {
        return Ok(());
    }
    resize_local_cluster(state, 1).await?;
    let cluster = state
        .cluster
        .take()
        .ok_or_else(|| "local cluster state disappeared".to_string())?;
    for node in cluster
        .nodes
        .iter()
        .chain(cluster.retired_nodes.iter())
        .filter(|node| node.node_id != "node-1")
    {
        if !state.retired_cluster_volumes.contains(&node.volume) {
            state.retired_cluster_volumes.push(node.volume.clone());
        }
    }
    if docker_container_state(&state.container).is_some() {
        docker_output(&["rm", "-f", &state.container])?;
    }
    save_local_state(state);
    run_local_engine_container(state)?;
    if !wait_for_local_ready(state) {
        return Err("standalone system node did not become ready after consolidation".to_string());
    }
    let _ = docker_output(&["network", "rm", &cluster.network]);
    Ok(())
}
