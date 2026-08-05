use super::*;
use crate::cluster::{
    certificate_fingerprint, encode_controller_public_key, ExecutionAuth, ExecutionField,
    ExecutionManifest, ExecutionTable, NodeDescriptor, SignedExecution, SignedTopology,
    SlotAssignment, TopologyManifest, CLUSTER_EXECUTION_SCHEMA_VERSION, CLUSTER_PROTOCOL_VERSION,
    CLUSTER_SLOT_COUNT, CLUSTER_TOPOLOGY_SCHEMA_VERSION,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::SigningKey;
use rand_core::OsRng;
use rcgen::{CertificateParams, KeyPair};
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::{Arc, Barrier};

fn certificate(server_name: &str) -> Vec<u8> {
    let params = CertificateParams::new(vec![server_name.to_owned()]).unwrap();
    let key = KeyPair::generate().unwrap();
    params.self_signed(&key).unwrap().der().to_vec()
}

fn node(node_id: &str, port: u16) -> NodeDescriptor {
    let server_name = format!("{node_id}.cluster.local");
    let certificate = certificate(&server_name);
    NodeDescriptor {
        node_id: node_id.to_owned(),
        peer_addr: format!("127.0.0.1:{port}"),
        peer_server_name: server_name,
        client_resp_url: format!("redis://127.0.0.1:{}", port + 1000),
        client_http_url: format!("http://127.0.0.1:{}", port + 2000),
        peer_certificate_der: URL_SAFE_NO_PAD.encode(&certificate),
        peer_certificate_sha256: certificate_fingerprint(&certificate),
    }
}

fn topology(key: &SigningKey) -> Arc<CompiledTopology> {
    let manifest = TopologyManifest {
        schema_version: CLUSTER_TOPOLOGY_SCHEMA_VERSION,
        protocol_version: CLUSTER_PROTOCOL_VERSION,
        cluster_id: "project-cluster-1".to_owned(),
        epoch: 1,
        control_node_id: "node-1".to_owned(),
        slot_count: CLUSTER_SLOT_COUNT,
        nodes: vec![node("node-1", 7001), node("node-2", 7002)],
        assignments: vec![
            SlotAssignment {
                start: 0,
                end: 2047,
                node_id: "node-1".to_owned(),
            },
            SlotAssignment {
                start: 2048,
                end: CLUSTER_SLOT_COUNT - 1,
                node_id: "node-2".to_owned(),
            },
        ],
    };
    Arc::new(
        SignedTopology::sign(manifest, key)
            .unwrap()
            .verify(&encode_controller_public_key(key.verifying_key()))
            .unwrap(),
    )
}

fn execution(key: &SigningKey) -> Arc<CompiledExecution> {
    let manifest = ExecutionManifest {
        schema_version: CLUSTER_EXECUTION_SCHEMA_VERSION,
        protocol_version: CLUSTER_PROTOCOL_VERSION,
        cluster_id: "project-cluster-1".to_owned(),
        version: 1,
        previous_digest: None,
        encryption_keyring_digest: None,
        tables: vec![ExecutionTable {
            name: "accounts".to_owned(),
            primary_key: Some("id".to_owned()),
            fields: vec![ExecutionField {
                name: "id".to_owned(),
                definition: "uuid|pk|unique|notnull".to_owned(),
            }],
            path_indexes: Vec::new(),
            default_ttl_seconds: None,
        }],
        auth: ExecutionAuth {
            enabled: false,
            issuer: String::new(),
            access_token_ttl_seconds: 0,
            api_keys: Vec::new(),
            jwt_keys: Vec::new(),
            grants: Vec::new(),
            session_revocations: Vec::new(),
            principal_blocks: Vec::new(),
        },
    };
    Arc::new(
        SignedExecution::sign(manifest, key)
            .unwrap()
            .verify(&encode_controller_public_key(key.verifying_key()))
            .unwrap(),
    )
}

fn next_pair(
    topology: &CompiledTopology,
    execution: &CompiledExecution,
    key: &SigningKey,
) -> (Arc<CompiledTopology>, Arc<CompiledExecution>) {
    let next_generation = topology.manifest().epoch + 1;
    let mut next_topology = topology.manifest().clone();
    next_topology.epoch = next_generation;
    if next_generation.is_multiple_of(2) {
        next_topology.assignments[0].end = 1023;
        next_topology.assignments[1].start = 1024;
    } else {
        next_topology.assignments[0].end = 2047;
        next_topology.assignments[1].start = 2048;
    }
    let next_topology = Arc::new(
        SignedTopology::sign(next_topology, key)
            .unwrap()
            .verify(&encode_controller_public_key(key.verifying_key()))
            .unwrap(),
    );

    let mut next_execution = execution.manifest().clone();
    next_execution.version = next_generation;
    next_execution.previous_digest = Some(execution.digest().to_owned());
    next_execution.tables[0].default_ttl_seconds = Some(next_generation);
    let next_execution = Arc::new(
        SignedExecution::sign(next_execution, key)
            .unwrap()
            .verify(&encode_controller_public_key(key.verifying_key()))
            .unwrap(),
    );
    (next_topology, next_execution)
}

#[test]
fn serving_snapshot_routes_and_executes_from_one_generation() {
    let key = SigningKey::random(&mut OsRng);
    let state = ServingState::new(topology(&key), execution(&key)).unwrap();
    let snapshot = state.snapshot();
    assert_eq!(snapshot.topology().manifest().epoch, 1);
    assert_eq!(snapshot.execution().manifest().version, 1);
    assert_eq!(
        snapshot.owner_for_table_row(b"accounts", b"user-1").node_id,
        snapshot
            .topology()
            .owner_for_table_row(b"accounts", b"user-1")
            .node_id
    );
}

#[test]
fn concurrent_readers_never_observe_torn_serving_generations() {
    let key = Arc::new(SigningKey::random(&mut OsRng));
    let state = Arc::new(ServingState::new(topology(&key), execution(&key)).unwrap());
    let stop = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(5));
    let readers = (0..4)
        .map(|_| {
            let state = Arc::clone(&state);
            let stop = Arc::clone(&stop);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                while !stop.load(AtomicOrdering::Acquire) {
                    let snapshot = state.snapshot();
                    assert_eq!(
                        snapshot.topology().manifest().epoch,
                        snapshot.execution().manifest().version
                    );
                }
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();

    for _ in 2..=25 {
        let current = state.snapshot();
        let (next_topology, next_execution) =
            next_pair(current.topology(), current.execution(), &key);
        state.publish(next_topology, next_execution).unwrap();
        std::thread::yield_now();
    }
    stop.store(true, AtomicOrdering::Release);
    for reader in readers {
        reader.join().unwrap();
    }
}

#[test]
fn serving_publication_rejects_rollbacks_and_cross_cluster_pairs() {
    let key = SigningKey::random(&mut OsRng);
    let topology_v1 = topology(&key);
    let execution_v1 = execution(&key);
    let state = ServingState::new(Arc::clone(&topology_v1), Arc::clone(&execution_v1)).unwrap();
    let (topology_v2, execution_v2) = next_pair(&topology_v1, &execution_v1, &key);
    state
        .publish(Arc::clone(&topology_v2), Arc::clone(&execution_v2))
        .unwrap();
    assert!(matches!(
        state.publish(topology_v1, execution_v1),
        Err(ClusterError::InvalidTopology(_))
    ));

    let mut wrong_cluster = execution_v2.manifest().clone();
    wrong_cluster.cluster_id = "another-project".to_owned();
    let wrong_cluster = Arc::new(
        SignedExecution::sign(wrong_cluster, &key)
            .unwrap()
            .verify(&encode_controller_public_key(key.verifying_key()))
            .unwrap(),
    );
    assert!(matches!(
        ServingState::new(topology_v2, wrong_cluster),
        Err(ClusterError::InvalidExecution(_))
    ));
}
