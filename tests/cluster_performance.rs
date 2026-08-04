use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use lux::cluster::{
    certificate_fingerprint, slot_for_key, ClusterConfig, NodeDescriptor, SignedTopology,
    SlotAssignment, TopologyManifest, CLUSTER_PROTOCOL_VERSION, CLUSTER_SLOT_COUNT,
    CLUSTER_TOPOLOGY_SCHEMA_VERSION,
};
use lux::{EmbeddedClient, ServerConfig, ServerHandle};
use p256::ecdsa::SigningKey;
use rand_core::OsRng;
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair};
use std::sync::Arc;
use std::time::{Duration, Instant};

const DEFAULT_OPERATIONS: usize = 30_000;
const DEFAULT_CLIENTS: usize = 64;
const SAMPLES: usize = 3;
// Every in-process node shares the host's Tokio runtime and CPU budget. Keep
// each node to one storage shard so this gate models fixed per-node capacity;
// otherwise a single 32-shard node already saturates the host and adding a
// second node cannot demonstrate horizontal scaling.
const NODE_SHARDS: usize = 1;
const MIN_CLUSTER_SINGLE_RATIO: f64 = 0.80;
const MIN_DIRECT_SCALE_RATIO: f64 = 1.25;

struct ClusterHarness {
    _directory: tempfile::TempDir,
    nodes: Vec<ServerHandle>,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "explicit release-mode performance gate"]
async fn added_nodes_increase_measured_throughput() {
    let operations = setting("LUX_CLUSTER_PERF_OPERATIONS", DEFAULT_OPERATIONS);
    let clients = setting("LUX_CLUSTER_PERF_CLIENTS", DEFAULT_CLIENTS);

    let standalone_directory = tempfile::tempdir().unwrap();
    let standalone = lux::run_with_config(ServerConfig {
        enable_resp: false,
        http_port: 0,
        shards: NODE_SHARDS,
        save_interval: Duration::ZERO,
        data_dir: standalone_directory.path().display().to_string(),
        ..Default::default()
    })
    .await
    .unwrap();
    let standalone_rate =
        measure("standalone", vec![standalone.client()], operations, clients).await;
    shutdown(vec![standalone]).await;

    let single = start_cluster(1).await;
    let cluster_single_rate = measure(
        "cluster-single",
        vec![single.nodes[0].client()],
        operations,
        clients,
    )
    .await;
    shutdown(single.nodes).await;

    let cluster = start_cluster(2).await;
    let single_ingress_rate = measure(
        "cluster-two-single-ingress",
        vec![cluster.nodes[0].client()],
        operations,
        clients,
    )
    .await;
    let balanced_ingress_rate = measure(
        "cluster-two-balanced-ingress",
        cluster.nodes.iter().map(ServerHandle::client).collect(),
        operations,
        clients,
    )
    .await;
    let owner_aligned_rate = measure_owner_aligned(
        "cluster-two-owner-aligned",
        cluster.nodes.iter().map(ServerHandle::client).collect(),
        operations,
        clients,
    )
    .await;
    shutdown(cluster.nodes).await;

    eprintln!(
        "cluster performance: standalone={standalone_rate:.0} ops/s, cluster-single={cluster_single_rate:.0} ops/s ({:.2}x), two-single-ingress={single_ingress_rate:.0} ops/s ({:.2}x), two-balanced-ingress={balanced_ingress_rate:.0} ops/s ({:.2}x), two-owner-aligned={owner_aligned_rate:.0} ops/s ({:.2}x)",
        cluster_single_rate / standalone_rate,
        single_ingress_rate / cluster_single_rate,
        balanced_ingress_rate / cluster_single_rate,
        owner_aligned_rate / cluster_single_rate,
    );

    assert!(
        cluster_single_rate >= standalone_rate * MIN_CLUSTER_SINGLE_RATIO,
        "one-node cluster throughput regressed below {:.0}% of standalone: {cluster_single_rate:.0} vs {standalone_rate:.0} ops/s",
        MIN_CLUSTER_SINGLE_RATIO * 100.0
    );
    assert!(
        owner_aligned_rate >= cluster_single_rate * MIN_DIRECT_SCALE_RATIO,
        "adding a directly addressed owner did not improve throughput by {:.0}%: {owner_aligned_rate:.0} vs {cluster_single_rate:.0} ops/s",
        (MIN_DIRECT_SCALE_RATIO - 1.0) * 100.0
    );
}

async fn measure(
    label: &str,
    clients: Vec<EmbeddedClient>,
    operations: usize,
    concurrency: usize,
) -> f64 {
    let warmup = operations.clamp(1_000, 5_000);
    let _ = run_workload(
        &format!("{label}:warmup"),
        &clients,
        warmup,
        concurrency,
        None,
    )
    .await;
    let mut samples = Vec::with_capacity(SAMPLES);
    for sample in 0..SAMPLES {
        samples.push(
            run_workload(
                &format!("{label}:sample:{sample}"),
                &clients,
                operations,
                concurrency,
                None,
            )
            .await,
        );
    }
    samples.sort_by(f64::total_cmp);
    samples[SAMPLES / 2]
}

async fn measure_owner_aligned(
    label: &str,
    clients: Vec<EmbeddedClient>,
    operations: usize,
    concurrency: usize,
) -> f64 {
    let tags = owner_tags(concurrency, clients.len());
    let warmup = operations.clamp(1_000, 5_000);
    let _ = run_workload(
        &format!("{label}:warmup"),
        &clients,
        warmup,
        concurrency,
        Some(&tags),
    )
    .await;
    let mut samples = Vec::with_capacity(SAMPLES);
    for sample in 0..SAMPLES {
        samples.push(
            run_workload(
                &format!("{label}:sample:{sample}"),
                &clients,
                operations,
                concurrency,
                Some(&tags),
            )
            .await,
        );
    }
    samples.sort_by(f64::total_cmp);
    samples[SAMPLES / 2]
}

async fn run_workload(
    prefix: &str,
    clients: &[EmbeddedClient],
    operations: usize,
    concurrency: usize,
    tags: Option<&[String]>,
) -> f64 {
    let concurrency = concurrency.clamp(1, operations);
    let barrier = Arc::new(tokio::sync::Barrier::new(concurrency + 1));
    let mut tasks = tokio::task::JoinSet::new();
    for worker in 0..concurrency {
        let client = clients[worker % clients.len()].clone();
        let barrier = barrier.clone();
        let prefix = prefix.to_string();
        let tag = tags.map(|tags| tags[worker].clone());
        let count = operations / concurrency + usize::from(worker < operations % concurrency);
        tasks.spawn(async move {
            barrier.wait().await;
            for operation in 0..count {
                let key = match &tag {
                    Some(tag) => format!("perf:{{{tag}}}:{prefix}:{worker}:{operation}"),
                    None => format!("perf:{prefix}:{worker}:{operation}"),
                };
                client.set_value(&key, "1").await.unwrap();
            }
        });
    }
    let start = Instant::now();
    barrier.wait().await;
    while let Some(result) = tasks.join_next().await {
        result.unwrap();
    }
    operations as f64 / start.elapsed().as_secs_f64()
}

fn owner_tags(concurrency: usize, nodes: usize) -> Vec<String> {
    (0..concurrency)
        .map(|worker| {
            let owner = worker % nodes;
            let start = owner * usize::from(CLUSTER_SLOT_COUNT) / nodes;
            let end = ((owner + 1) * usize::from(CLUSTER_SLOT_COUNT) / nodes) - 1;
            (0usize..)
                .map(|candidate| format!("owner-{worker}-{candidate}"))
                .find(|tag| {
                    let key = format!("{{{tag}}}");
                    let slot = usize::from(slot_for_key(key.as_bytes()));
                    slot >= start && slot <= end
                })
                .unwrap()
        })
        .collect()
}

async fn start_cluster(node_count: usize) -> ClusterHarness {
    let directory = tempfile::tempdir().unwrap();
    let signing_key = SigningKey::random(&mut OsRng);
    let controller_public_key = URL_SAFE_NO_PAD.encode(
        signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes(),
    );
    let mut identities = Vec::with_capacity(node_count);
    let mut descriptors = Vec::with_capacity(node_count);
    for ordinal in 1..=node_count {
        let node_id = format!("node-{ordinal}");
        let server_name = format!("{node_id}.cluster.local");
        let mut params = CertificateParams::new(vec![server_name.clone()]).unwrap();
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let key = KeyPair::generate().unwrap();
        let certificate = params.self_signed(&key).unwrap();
        let certificate_path = directory.path().join(format!("{node_id}.pem"));
        let private_key_path = directory.path().join(format!("{node_id}.key"));
        std::fs::write(&certificate_path, certificate.pem()).unwrap();
        std::fs::write(&private_key_path, key.serialize_pem()).unwrap();
        let certificate_der = certificate.der().to_vec();
        let peer_port = reserve_udp_port();
        descriptors.push(NodeDescriptor {
            node_id: node_id.clone(),
            peer_addr: format!("127.0.0.1:{peer_port}"),
            client_addr: format!("127.0.0.1:{}", 16_379 + ordinal),
            server_name,
            certificate_der: URL_SAFE_NO_PAD.encode(&certificate_der),
            certificate_sha256: certificate_fingerprint(&certificate_der),
        });
        identities.push((node_id, peer_port, certificate_path, private_key_path));
    }
    let assignments = descriptors
        .iter()
        .enumerate()
        .map(|(index, node)| SlotAssignment {
            start: (index * usize::from(CLUSTER_SLOT_COUNT) / node_count) as u16,
            end: (((index + 1) * usize::from(CLUSTER_SLOT_COUNT) / node_count) - 1) as u16,
            node_id: node.node_id.clone(),
        })
        .collect();
    let topology = SignedTopology::sign(
        TopologyManifest {
            schema_version: CLUSTER_TOPOLOGY_SCHEMA_VERSION,
            protocol_version: CLUSTER_PROTOCOL_VERSION,
            cluster_id: format!("performance-{node_count}"),
            epoch: 1,
            system_node_id: "node-1".to_string(),
            slot_count: CLUSTER_SLOT_COUNT,
            catalog_version: 1,
            nodes: descriptors,
            assignments,
        },
        &signing_key,
    )
    .unwrap();
    let topology_path = directory.path().join("topology.json");
    std::fs::write(&topology_path, serde_json::to_vec(&topology).unwrap()).unwrap();

    let mut nodes = Vec::with_capacity(node_count);
    for (node_id, peer_port, certificate_chain_path, private_key_path) in identities {
        nodes.push(
            lux::run_with_config(ServerConfig {
                enable_resp: false,
                http_port: 0,
                shards: NODE_SHARDS,
                save_interval: Duration::ZERO,
                data_dir: directory
                    .path()
                    .join(format!("{node_id}-data"))
                    .display()
                    .to_string(),
                cluster: Some(ClusterConfig {
                    local_node_id: node_id.clone(),
                    peer_bind_addr: format!("127.0.0.1:{peer_port}").parse().unwrap(),
                    certificate_chain_path,
                    private_key_path,
                    topology_path: topology_path.clone(),
                    topology_state_path: directory.path().join(format!("{node_id}-state.json")),
                    controller_public_key: controller_public_key.clone(),
                    max_frame_bytes: 1024 * 1024,
                }),
                ..Default::default()
            })
            .await
            .unwrap(),
        );
    }
    ClusterHarness {
        _directory: directory,
        nodes,
    }
}

async fn shutdown(nodes: Vec<ServerHandle>) {
    for node in &nodes {
        node.shutdown();
    }
    for node in nodes {
        node.wait().await.unwrap();
    }
}

fn reserve_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn setting(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}
