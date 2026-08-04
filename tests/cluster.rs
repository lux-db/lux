use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use lux::cluster::{
    certificate_fingerprint, slot_for_key, slot_for_table_row, ClusterConfig, NodeDescriptor,
    SignedTopology, SlotAssignment, TopologyManifest, CLUSTER_PROTOCOL_VERSION, CLUSTER_SLOT_COUNT,
    CLUSTER_TOPOLOGY_SCHEMA_VERSION,
};
use lux::EmbeddedValue;
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

fn table_pk_for_range(table: &str, start: u16, end: u16) -> String {
    (0u64..)
        .map(|value| format!("order-{value}"))
        .find(|primary_key| {
            let logical = slot_for_table_row(table.as_bytes(), primary_key.as_bytes());
            logical >= start && logical <= end
        })
        .unwrap()
}

fn table_pks_for_range(table: &str, start: u16, end: u16, count: usize) -> Vec<String> {
    (0u64..)
        .map(|value| format!("row-{value}"))
        .filter(|primary_key| {
            let slot = slot_for_table_row(table.as_bytes(), primary_key.as_bytes());
            slot >= start && slot <= end
        })
        .take(count)
        .collect()
}

fn table_rows(value: EmbeddedValue) -> Vec<std::collections::BTreeMap<String, String>> {
    let EmbeddedValue::Array(rows) = value else {
        panic!("expected table rows, got {value:?}");
    };
    rows.into_iter()
        .map(|row| {
            let EmbeddedValue::Array(fields) = row else {
                panic!("expected table row, got {row:?}");
            };
            assert!(fields.len().is_multiple_of(2));
            fields
                .chunks_exact(2)
                .map(|pair| {
                    let key = match &pair[0] {
                        EmbeddedValue::Bulk(value) => String::from_utf8(value.to_vec()).unwrap(),
                        value => panic!("expected bulk field name, got {value:?}"),
                    };
                    let value = match &pair[1] {
                        EmbeddedValue::Bulk(value) => String::from_utf8(value.to_vec()).unwrap(),
                        EmbeddedValue::Int(value) => value.to_string(),
                        value => panic!("expected scalar field value, got {value:?}"),
                    };
                    (key, value)
                })
                .collect()
        })
        .collect()
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

    assert_eq!(
        client_a
            .execute_value(
                "TCREATE",
                &["orders", "id STR PRIMARY KEY,", "state STR NOT NULL"],
            )
            .await
            .unwrap(),
        EmbeddedValue::Simple("OK".to_string())
    );
    let order_id = table_pk_for_range("orders", 2048, CLUSTER_SLOT_COUNT - 1);
    assert_eq!(
        client_a
            .execute_value("TGET", &["orders", &order_id])
            .await
            .unwrap(),
        EmbeddedValue::Nil
    );
    assert_eq!(
        client_a
            .execute_value("TINSERT", &["orders", "id", &order_id, "state", "pending"],)
            .await
            .unwrap(),
        EmbeddedValue::Int(0)
    );
    assert_eq!(
        client_a
            .execute_value("TGET", &["orders", &order_id, "state"])
            .await
            .unwrap(),
        EmbeddedValue::Bulk(bytes::Bytes::from_static(b"pending"))
    );
    assert_eq!(
        client_a
            .execute_value("TSET", &["orders", &order_id, "state", "paid"])
            .await
            .unwrap(),
        EmbeddedValue::Int(1)
    );
    assert_eq!(
        client_a
            .execute_value("TGET", &["orders", &order_id, "state"])
            .await
            .unwrap(),
        EmbeddedValue::Bulk(bytes::Bytes::from_static(b"paid"))
    );
    client_a
        .execute_value(
            "TALTER",
            &[
                "orders", "ADD", "priority", "INT", "DEFAULT", "7", "NOT", "NULL",
            ],
        )
        .await
        .unwrap();
    assert_eq!(
        client_a
            .execute_value("TGET", &["orders", &order_id, "priority"])
            .await
            .unwrap(),
        EmbeddedValue::Bulk(bytes::Bytes::from_static(b"7"))
    );
    client_a
        .execute_value("TALTER", &["orders", "DROP", "priority"])
        .await
        .unwrap();
    assert_eq!(
        client_a
            .execute_value("TGET", &["orders", &order_id, "priority"])
            .await
            .unwrap(),
        EmbeddedValue::Nil
    );
    let duplicate = client_a
        .execute_value(
            "TINSERT",
            &["orders", "id", &order_id, "state", "duplicate"],
        )
        .await
        .unwrap_err();
    assert!(
        duplicate
            .to_string()
            .contains("unique constraint violation"),
        "{duplicate}"
    );
    assert_eq!(
        client_a
            .execute_value(
                "TUPDATE",
                &["orders", "SET", "state", "shipped", "WHERE", "id", "=", &order_id,],
            )
            .await
            .unwrap(),
        EmbeddedValue::Int(1)
    );
    client_a
        .execute_value(
            "TUPSERT",
            &["orders", "id", &order_id, "state", "delivered"],
        )
        .await
        .unwrap();
    assert_eq!(
        client_a
            .execute_value("TGET", &["orders", &order_id, "state"])
            .await
            .unwrap(),
        EmbeddedValue::Bulk(bytes::Bytes::from_static(b"delivered"))
    );
    let broad_update = client_a
        .execute_value(
            "TUPDATE",
            &[
                "orders",
                "SET",
                "state",
                "bad",
                "WHERE",
                "state",
                "=",
                "delivered",
            ],
        )
        .await
        .unwrap_err();
    assert!(broad_update.to_string().contains("must use WHERE id"));
    client_a
        .execute_value(
            "TDELETE",
            &["FROM", "orders", "WHERE", "id", "=", &order_id],
        )
        .await
        .unwrap();
    assert_eq!(
        client_a
            .execute_value("TGET", &["orders", &order_id])
            .await
            .unwrap(),
        EmbeddedValue::Nil
    );

    client_a
        .execute_value("TALTER", &["orders", "ADD", "amount", "INT", "NOT", "NULL"])
        .await
        .unwrap();
    let mut order_ids = table_pks_for_range("orders", 0, 2047, 2);
    order_ids.extend(table_pks_for_range(
        "orders",
        2048,
        CLUSTER_SLOT_COUNT - 1,
        2,
    ));
    for (id, state, amount) in [
        (&order_ids[0], "open", "10"),
        (&order_ids[1], "closed", "20"),
        (&order_ids[2], "open", "30"),
        (&order_ids[3], "closed", "40"),
    ] {
        client_a
            .execute_value(
                "TINSERT",
                &["orders", "id", id, "state", state, "amount", amount],
            )
            .await
            .unwrap();
    }

    // Enter through the non-system node to prove it forwards the coordinator
    // command to node A before A fans the structured scan back out.
    assert_eq!(
        client_b.execute_value("TCOUNT", &["orders"]).await.unwrap(),
        EmbeddedValue::Int(4)
    );
    let page = table_rows(
        client_b
            .execute_value(
                "TSELECT",
                &[
                    "id,amount",
                    "FROM",
                    "orders",
                    "WHERE",
                    "amount",
                    ">=",
                    "10",
                    "ORDER",
                    "BY",
                    "amount",
                    "DESC",
                    "LIMIT",
                    "2",
                    "OFFSET",
                    "1",
                ],
            )
            .await
            .unwrap(),
    );
    assert_eq!(
        page.iter()
            .map(|row| row.get("amount").unwrap().as_str())
            .collect::<Vec<_>>(),
        vec!["30", "20"]
    );

    let aggregate = table_rows(
        client_a
            .execute_value(
                "TSELECT",
                &[
                    "COUNT(*) AS count,SUM(amount) AS total,AVG(amount) AS average,MIN(amount) AS minimum,MAX(amount) AS maximum",
                    "FROM",
                    "orders",
                ],
            )
            .await
            .unwrap(),
    );
    assert_eq!(aggregate[0].get("count").unwrap(), "4");
    assert_eq!(aggregate[0].get("total").unwrap(), "100");
    assert_eq!(aggregate[0].get("average").unwrap(), "25");
    assert_eq!(aggregate[0].get("minimum").unwrap(), "10");
    assert_eq!(aggregate[0].get("maximum").unwrap(), "40");

    let grouped = table_rows(
        client_a
            .execute_value(
                "TSELECT",
                &[
                    "state,COUNT(*) AS count",
                    "FROM",
                    "orders",
                    "GROUP",
                    "BY",
                    "state",
                    "ORDER",
                    "BY",
                    "state",
                    "ASC",
                ],
            )
            .await
            .unwrap(),
    );
    assert_eq!(grouped.len(), 2);
    assert!(grouped
        .iter()
        .all(|row| row.get("count") == Some(&"2".to_string())));

    client_a
        .execute_value(
            "TCREATE",
            &[
                "documents",
                "id STR PRIMARY KEY,",
                "title STR NOT NULL,",
                "embedding VECTOR(2)",
            ],
        )
        .await
        .unwrap();
    let mut document_ids = table_pks_for_range("documents", 0, 2047, 2);
    document_ids.extend(table_pks_for_range(
        "documents",
        2048,
        CLUSTER_SLOT_COUNT - 1,
        2,
    ));
    for (id, title, embedding) in [
        (&document_ids[0], "best", "[1,0]"),
        (&document_ids[1], "far", "[0,1]"),
        (&document_ids[2], "second", "[0.99,0.01]"),
        (&document_ids[3], "also-far", "[0.1,0.9]"),
    ] {
        client_a
            .execute_value(
                "TINSERT",
                &[
                    "documents",
                    "id",
                    id,
                    "title",
                    title,
                    "embedding",
                    embedding,
                ],
            )
            .await
            .unwrap();
    }
    let nearest = table_rows(
        client_a
            .execute_value(
                "TSELECT",
                &[
                    "id,title,_similarity",
                    "FROM",
                    "documents",
                    "NEAR",
                    "embedding",
                    "[1,0]",
                    "K",
                    "2",
                ],
            )
            .await
            .unwrap(),
    );
    assert_eq!(
        nearest
            .iter()
            .map(|row| row.get("title").unwrap().as_str())
            .collect::<Vec<_>>(),
        vec!["best", "second"]
    );

    drop(client_a);
    drop(client_b);
    node_a.shutdown_and_wait().await.unwrap();
    node_b.shutdown_and_wait().await.unwrap();
}
