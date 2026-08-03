use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use lux::cluster::{
    certificate_fingerprint, slot_for_key, ClusterConfig, NodeDescriptor, SignedTopology,
    SlotAssignment, TopologyManifest, CLUSTER_PROTOCOL_VERSION, CLUSTER_SLOT_COUNT,
    CLUSTER_TOPOLOGY_SCHEMA_VERSION,
};
use p256::ecdsa::SigningKey;
use rand_core::OsRng;
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn reserve_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn identity(
    server_name: &str,
    dir: &std::path::Path,
) -> (std::path::PathBuf, std::path::PathBuf, Vec<u8>) {
    let mut params = CertificateParams::new(vec![server_name.to_string()]).unwrap();
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    let key = KeyPair::generate().unwrap();
    let certificate = params.self_signed(&key).unwrap();
    let cert_path = dir.join(format!("{server_name}.pem"));
    let key_path = dir.join(format!("{server_name}.key"));
    std::fs::write(&cert_path, certificate.pem()).unwrap();
    std::fs::write(&key_path, key.serialize_pem()).unwrap();
    (cert_path, key_path, certificate.der().to_vec())
}

fn key_for_range(start: u16, end: u16) -> String {
    (0u64..)
        .map(|value| format!("cluster:key:{value}"))
        .find(|key| {
            let slot = slot_for_key(key.as_bytes());
            slot >= start && slot <= end
        })
        .unwrap()
}

fn resp_command(parts: &[&str]) -> Vec<u8> {
    let mut bytes = format!("*{}\r\n", parts.len()).into_bytes();
    for part in parts {
        bytes.extend_from_slice(format!("${}\r\n", part.len()).as_bytes());
        bytes.extend_from_slice(part.as_bytes());
        bytes.extend_from_slice(b"\r\n");
    }
    bytes
}

#[tokio::test]
async fn embedded_clients_route_to_the_signed_owner_without_a_local_hop() {
    let dir = tempfile::tempdir().unwrap();
    let port_a = reserve_udp_port();
    let port_b = reserve_udp_port();
    let (cert_a_path, key_a_path, cert_a) = identity("node-a.cluster.local", dir.path());
    let (cert_b_path, key_b_path, cert_b) = identity("node-b.cluster.local", dir.path());
    let signing_key = SigningKey::random(&mut OsRng);
    let controller_public_key = URL_SAFE_NO_PAD.encode(
        signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes(),
    );
    let topology = SignedTopology::sign(
        TopologyManifest {
            schema_version: CLUSTER_TOPOLOGY_SCHEMA_VERSION,
            protocol_version: CLUSTER_PROTOCOL_VERSION,
            cluster_id: "runtime-routing-test".into(),
            epoch: 1,
            system_node_id: "node-a".into(),
            slot_count: CLUSTER_SLOT_COUNT,
            catalog_version: 1,
            nodes: vec![
                NodeDescriptor {
                    node_id: "node-a".into(),
                    peer_addr: format!("127.0.0.1:{port_a}"),
                    server_name: "node-a.cluster.local".into(),
                    certificate_der: URL_SAFE_NO_PAD.encode(&cert_a),
                    certificate_sha256: certificate_fingerprint(&cert_a),
                },
                NodeDescriptor {
                    node_id: "node-b".into(),
                    peer_addr: format!("127.0.0.1:{port_b}"),
                    server_name: "node-b.cluster.local".into(),
                    certificate_der: URL_SAFE_NO_PAD.encode(&cert_b),
                    certificate_sha256: certificate_fingerprint(&cert_b),
                },
            ],
            assignments: vec![
                SlotAssignment {
                    start: 0,
                    end: 2047,
                    node_id: "node-a".into(),
                },
                SlotAssignment {
                    start: 2048,
                    end: CLUSTER_SLOT_COUNT - 1,
                    node_id: "node-b".into(),
                },
            ],
        },
        &signing_key,
    )
    .unwrap();
    let topology_path = dir.path().join("topology.json");
    std::fs::write(
        &topology_path,
        serde_json::to_vec_pretty(&topology).unwrap(),
    )
    .unwrap();

    let cluster = |node_id: &str,
                   port: u16,
                   certificate_chain_path: std::path::PathBuf,
                   private_key_path: std::path::PathBuf| ClusterConfig {
        local_node_id: node_id.to_string(),
        peer_bind_addr: format!("127.0.0.1:{port}").parse().unwrap(),
        certificate_chain_path,
        private_key_path,
        topology_path: topology_path.clone(),
        topology_state_path: dir.path().join(format!("{node_id}-topology-state.json")),
        controller_public_key: controller_public_key.clone(),
        max_frame_bytes: 1024 * 1024,
    };

    let node_a = lux::run_with_config(lux::ServerConfig {
        enable_resp: true,
        port: 0,
        http_port: 0,
        shards: 4,
        data_dir: dir.path().join("node-a-data").display().to_string(),
        cluster: Some(cluster("node-a", port_a, cert_a_path, key_a_path)),
        ..Default::default()
    })
    .await
    .unwrap();
    let node_b = lux::run_with_config(lux::ServerConfig {
        enable_resp: false,
        http_port: 0,
        shards: 4,
        data_dir: dir.path().join("node-b-data").display().to_string(),
        cluster: Some(cluster("node-b", port_b, cert_b_path, key_b_path)),
        ..Default::default()
    })
    .await
    .unwrap();

    let key_a = key_for_range(0, 2047);
    let key_b = key_for_range(2048, CLUSTER_SLOT_COUNT - 1);
    let client_a = node_a.client();
    let client_b = node_b.client();

    client_a.set(&key_b, b"owned-by-b").await.unwrap();
    assert_eq!(
        client_b.get(&key_b).await.unwrap().as_deref(),
        Some(b"owned-by-b".as_slice())
    );

    client_b.set(&key_a, b"owned-by-a").await.unwrap();
    assert_eq!(
        client_a.get(&key_a).await.unwrap().as_deref(),
        Some(b"owned-by-a".as_slice())
    );

    let cross_slot = client_a
        .execute_value("MGET", &[&key_a, &key_b])
        .await
        .unwrap_err();
    assert!(cross_slot.to_string().contains("CROSSSLOT"));

    let mut resp = tokio::net::TcpStream::connect(node_a.local_addr().unwrap())
        .await
        .unwrap();
    resp.write_all(&resp_command(&["GET", &key_b]))
        .await
        .unwrap();
    let expected = b"$10\r\nowned-by-b\r\n";
    let mut actual = vec![0; expected.len()];
    resp.read_exact(&mut actual).await.unwrap();
    assert_eq!(actual, expected);

    drop(client_a);
    drop(client_b);
    node_a.shutdown_and_wait().await.unwrap();
    node_b.shutdown_and_wait().await.unwrap();
}
