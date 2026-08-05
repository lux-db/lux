use super::*;
use crate::cluster::{
    encode_controller_public_key, ExecutionAuth, ExecutionManifest, SignedExecution,
    SignedTopology, SlotAssignment, TopologyManifest, CLUSTER_EXECUTION_SCHEMA_VERSION,
    CLUSTER_SLOT_COUNT, CLUSTER_TOPOLOGY_SCHEMA_VERSION,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::SigningKey;
use rand_core::OsRng;
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct TestIdentity {
    certificate_path: PathBuf,
    private_key_path: PathBuf,
    certificate_der: Vec<u8>,
}

fn reserve_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn identity(server_name: &str, directory: &std::path::Path) -> TestIdentity {
    let mut params = CertificateParams::new(vec![server_name.to_owned()]).unwrap();
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    let key = KeyPair::generate().unwrap();
    let certificate = params.self_signed(&key).unwrap();
    let certificate_path = directory.join(format!("{server_name}.pem"));
    let private_key_path = directory.join(format!("{server_name}.key"));
    std::fs::write(&certificate_path, certificate.pem()).unwrap();
    std::fs::write(&private_key_path, key.serialize_pem()).unwrap();
    TestIdentity {
        certificate_path,
        private_key_path,
        certificate_der: certificate.der().to_vec(),
    }
}

fn node(node_id: &str, port: u16, identity: &TestIdentity) -> NodeDescriptor {
    NodeDescriptor {
        node_id: node_id.to_owned(),
        peer_addr: format!("127.0.0.1:{port}"),
        peer_server_name: format!("{node_id}.cluster.local"),
        client_resp_url: format!("redis://127.0.0.1:{port}"),
        client_http_url: format!("http://127.0.0.1:{port}"),
        peer_certificate_der: URL_SAFE_NO_PAD.encode(&identity.certificate_der),
        peer_certificate_sha256: certificate_fingerprint(&identity.certificate_der),
    }
}

fn topology_manifest(cluster_id: &str, epoch: u64, nodes: Vec<NodeDescriptor>) -> TopologyManifest {
    TopologyManifest {
        schema_version: CLUSTER_TOPOLOGY_SCHEMA_VERSION,
        protocol_version: CLUSTER_PROTOCOL_VERSION,
        cluster_id: cluster_id.to_owned(),
        epoch,
        control_node_id: "node-a".to_owned(),
        slot_count: CLUSTER_SLOT_COUNT,
        nodes,
        assignments: vec![SlotAssignment {
            start: 0,
            end: CLUSTER_SLOT_COUNT - 1,
            node_id: "node-a".to_owned(),
        }],
    }
}

fn execution(key: &SigningKey, cluster_id: &str) -> Arc<super::super::CompiledExecution> {
    let manifest = ExecutionManifest {
        schema_version: CLUSTER_EXECUTION_SCHEMA_VERSION,
        protocol_version: CLUSTER_PROTOCOL_VERSION,
        cluster_id: cluster_id.to_owned(),
        version: 1,
        previous_digest: None,
        encryption_keyring_digest: None,
        tables: Vec::new(),
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

fn states(signed: &SignedTopology, key: &SigningKey) -> (Arc<TopologyState>, Arc<ServingState>) {
    let public_key = encode_controller_public_key(key.verifying_key());
    let topology_state = Arc::new(TopologyState::in_memory(
        signed.clone().verify(&public_key).unwrap(),
        public_key,
    ));
    let serving = Arc::new(
        ServingState::new(
            Arc::new(
                signed
                    .clone()
                    .verify(&encode_controller_public_key(key.verifying_key()))
                    .unwrap(),
            ),
            execution(key, &signed.manifest.cluster_id),
        )
        .unwrap(),
    );
    (topology_state, serving)
}

fn config(node_id: &str, port: u16, identity: &TestIdentity) -> PeerControlConfig {
    PeerControlConfig {
        local_node_id: node_id.to_owned(),
        peer_bind_addr: format!("127.0.0.1:{port}").parse().unwrap(),
        certificate_chain_path: identity.certificate_path.clone(),
        private_key_path: identity.private_key_path.clone(),
        max_frame_bytes: 1024 * 1024,
        max_request_duration: Duration::from_secs(5),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pinned_mtls_control_transport_reuses_one_authenticated_connection() {
    let directory = tempfile::tempdir().unwrap();
    let port_a = reserve_udp_port();
    let port_b = reserve_udp_port();
    let identity_a = identity("node-a.cluster.local", directory.path());
    let identity_b = identity("node-b.cluster.local", directory.path());
    let key = SigningKey::random(&mut OsRng);
    let topology = SignedTopology::sign(
        topology_manifest(
            "cluster-a",
            1,
            vec![
                node("node-a", port_a, &identity_a),
                node("node-b", port_b, &identity_b),
            ],
        ),
        &key,
    )
    .unwrap();
    let (topology_a, serving_a) = states(&topology, &key);
    let (topology_b, serving_b) = states(&topology, &key);
    let transport_a = PeerControlTransport::bind(
        &config("node-a", port_a, &identity_a),
        topology_a,
        serving_a,
    )
    .unwrap();
    let transport_b = PeerControlTransport::bind(
        &config("node-b", port_b, &identity_b),
        topology_b,
        serving_b,
    )
    .unwrap();
    let handled = Arc::new(AtomicUsize::new(0));
    let handled_by_server = Arc::clone(&handled);
    let server = Arc::clone(&transport_b);
    let task = tokio::spawn(server.serve(move |request| {
        let handled = Arc::clone(&handled_by_server);
        async move {
            assert_eq!(request.source_node_id(), "node-a");
            assert_eq!(request.serving().topology().manifest().epoch, 1);
            assert_eq!(request.serving().execution().manifest().version, 1);
            handled.fetch_add(1, Ordering::Relaxed);
            Ok(ControlResponseBody::Pong)
        }
    }));

    let connection = transport_a.connection("node-b").await.unwrap();
    let (mut send, mut receive) = connection.open_bi().await.unwrap();
    let request = ControlRequest {
        protocol_version: CLUSTER_PROTOCOL_VERSION,
        cluster_id: "cluster-a".to_owned(),
        topology_epoch: 1,
        execution_version: 1,
        source_node_id: "node-a".to_owned(),
        target_node_id: "node-b".to_owned(),
        request_id: ControlRequestId([3; 16]),
        deadline_unix_ms: unix_time_ms() + 2_000,
        body: ControlRequestBody::Probe,
    };
    let encoded = encode_request(&request).unwrap();
    write_frame(&mut send, &encoded, transport_a.max_frame_bytes)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(handled.load(Ordering::Relaxed), 0);
    send.finish().unwrap();
    let frame = read_frame(
        &mut receive,
        transport_a.max_frame_bytes,
        Arc::clone(&transport_a.frame_budget),
    )
    .await
    .unwrap();
    assert_eq!(
        decode_response(&frame.bytes).unwrap().body,
        ControlResponseBody::Pong
    );

    for _ in 0..4 {
        let response = transport_a
            .request("node-b", ControlRequestBody::Probe, Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(response.body, ControlResponseBody::Pong);
    }
    assert_eq!(handled.load(Ordering::Relaxed), 5);
    assert_eq!(transport_a.endpoint.open_connections(), 1);
    task.abort();
}

#[test]
fn in_flight_frame_budget_is_global_and_recovers_on_drop() {
    let frame_budget = Arc::new(tokio::sync::Semaphore::new(8));
    let reservation = reserve_frame_bytes(Arc::clone(&frame_budget), 8).unwrap();
    assert!(matches!(
        reserve_frame_bytes(Arc::clone(&frame_budget), 1),
        Err(ClusterError::Transport(_))
    ));
    drop(reservation);
    assert!(reserve_frame_bytes(frame_budget, 8).is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_generation_is_rejected_before_the_handler() {
    let directory = tempfile::tempdir().unwrap();
    let port_a = reserve_udp_port();
    let port_b = reserve_udp_port();
    let identity_a = identity("node-a.cluster.local", directory.path());
    let identity_b = identity("node-b.cluster.local", directory.path());
    let key = SigningKey::random(&mut OsRng);
    let topology = SignedTopology::sign(
        topology_manifest(
            "cluster-stale",
            2,
            vec![
                node("node-a", port_a, &identity_a),
                node("node-b", port_b, &identity_b),
            ],
        ),
        &key,
    )
    .unwrap();
    let (topology_a, serving_a) = states(&topology, &key);
    let (topology_b, serving_b) = states(&topology, &key);
    let transport_a = PeerControlTransport::bind(
        &config("node-a", port_a, &identity_a),
        topology_a,
        serving_a,
    )
    .unwrap();
    let transport_b = PeerControlTransport::bind(
        &config("node-b", port_b, &identity_b),
        topology_b,
        serving_b,
    )
    .unwrap();
    let called = Arc::new(AtomicBool::new(false));
    let called_by_server = Arc::clone(&called);
    let server = Arc::clone(&transport_b);
    let task = tokio::spawn(server.serve(move |_| {
        let called = Arc::clone(&called_by_server);
        async move {
            called.store(true, Ordering::Relaxed);
            Ok(ControlResponseBody::Pong)
        }
    }));

    let request = ControlRequest {
        protocol_version: CLUSTER_PROTOCOL_VERSION,
        cluster_id: "cluster-stale".to_owned(),
        topology_epoch: 1,
        execution_version: 1,
        source_node_id: "node-a".to_owned(),
        target_node_id: "node-b".to_owned(),
        request_id: ControlRequestId([7; 16]),
        deadline_unix_ms: unix_time_ms() + 2_000,
        body: ControlRequestBody::Probe,
    };
    let response = transport_a
        .request_envelope("node-b", request, Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(
        response.body,
        ControlResponseBody::Rejected {
            code: ControlRejectCode::TopologyStale
        }
    );
    assert!(!called.load(Ordering::Relaxed));
    task.abort();
}

#[test]
fn local_identity_must_match_the_signed_node_certificate() {
    let directory = tempfile::tempdir().unwrap();
    let port_a = reserve_udp_port();
    let port_b = reserve_udp_port();
    let identity_a = identity("node-a.cluster.local", directory.path());
    let identity_b = identity("node-b.cluster.local", directory.path());
    let key = SigningKey::random(&mut OsRng);
    let topology = SignedTopology::sign(
        topology_manifest(
            "cluster-identity",
            1,
            vec![
                node("node-a", port_a, &identity_a),
                node("node-b", port_b, &identity_b),
            ],
        ),
        &key,
    )
    .unwrap();
    let (topology_state, serving) = states(&topology, &key);
    assert!(matches!(
        PeerControlTransport::bind(
            &config("node-a", port_a, &identity_b),
            topology_state,
            serving
        ),
        Err(ClusterError::InvalidConfig(_))
    ));
}

#[test]
fn topology_state_must_match_the_atomic_serving_topology() {
    let directory = tempfile::tempdir().unwrap();
    let port_a = reserve_udp_port();
    let identity_a = identity("node-a.cluster.local", directory.path());
    let node_a = node("node-a", port_a, &identity_a);
    let key = SigningKey::random(&mut OsRng);
    let first = SignedTopology::sign(
        topology_manifest("cluster-first", 1, vec![node_a.clone()]),
        &key,
    )
    .unwrap();
    let second =
        SignedTopology::sign(topology_manifest("cluster-second", 1, vec![node_a]), &key).unwrap();
    let (topology_state, _) = states(&first, &key);
    let (_, serving) = states(&second, &key);
    assert!(matches!(
        PeerControlTransport::bind(
            &config("node-a", port_a, &identity_a),
            topology_state,
            serving
        ),
        Err(ClusterError::InvalidConfig(_))
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prepared_member_can_handshake_but_cannot_dispatch_until_commit() {
    let directory = tempfile::tempdir().unwrap();
    let port_a = reserve_udp_port();
    let port_b = reserve_udp_port();
    let identity_a = identity("node-a.cluster.local", directory.path());
    let identity_b = identity("node-b.cluster.local", directory.path());
    let node_a = node("node-a", port_a, &identity_a);
    let node_b = node("node-b", port_b, &identity_b);
    let key = SigningKey::random(&mut OsRng);
    let initial = SignedTopology::sign(
        topology_manifest("cluster-admission", 1, vec![node_a.clone()]),
        &key,
    )
    .unwrap();
    let prepared = SignedTopology::sign(
        topology_manifest("cluster-admission", 2, vec![node_a, node_b]),
        &key,
    )
    .unwrap();
    let (topology_a, serving_a) = states(&initial, &key);
    let (topology_b, serving_b) = states(&prepared, &key);
    let transport_a = PeerControlTransport::bind(
        &config("node-a", port_a, &identity_a),
        Arc::clone(&topology_a),
        Arc::clone(&serving_a),
    )
    .unwrap();
    let transport_b = PeerControlTransport::bind(
        &config("node-b", port_b, &identity_b),
        topology_b,
        serving_b,
    )
    .unwrap();
    topology_a.prepare(prepared.clone()).unwrap();
    transport_a.refresh_server_trust().unwrap();
    let server = Arc::clone(&transport_a);
    let task = tokio::spawn(server.serve(|_| async { Ok(ControlResponseBody::Pong) }));

    let pending = transport_b
        .request("node-a", ControlRequestBody::Probe, Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(
        pending.body,
        ControlResponseBody::Rejected {
            code: ControlRejectCode::MembershipPending
        }
    );

    let committed = topology_a.commit(2).unwrap();
    let execution = serving_a.snapshot().execution().signed().clone();
    let execution = Arc::new(
        execution
            .verify(&encode_controller_public_key(key.verifying_key()))
            .unwrap(),
    );
    serving_a.publish(committed, execution).unwrap();
    let admitted = transport_b
        .request("node-a", ControlRequestBody::Probe, Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(admitted.body, ControlResponseBody::Pong);
    task.abort();
}
