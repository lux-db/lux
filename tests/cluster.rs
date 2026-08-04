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

fn reserve_tcp_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn post_engine_json(
    client: &reqwest::Client,
    port: u16,
    path: &str,
    body: serde_json::Value,
) -> serde_json::Value {
    let response = client
        .post(format!("http://127.0.0.1:{port}{path}"))
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let text = response.text().await.unwrap();
    assert!(status.is_success(), "{path} returned {status}: {text}");
    serde_json::from_str(&text).unwrap()
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
    key_for_range_with_prefix("cluster:key", start, end)
}

fn key_for_range_with_prefix(prefix: &str, start: u16, end: u16) -> String {
    (0u64..)
        .map(|value| format!("{prefix}:{value}"))
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
    let mut remote_events = client_a.ksubscribe(&key_b);
    client_a.set(&key_b, b"remote-event").await.unwrap();
    let event = tokio::time::timeout(std::time::Duration::from_secs(1), remote_events.recv())
        .await
        .expect("remote owner mutation did not wake the ingress subscriber")
        .unwrap();
    assert_eq!(event.channel, key_b);
    assert_eq!(event.payload.as_ref(), b"set");

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

    let vector_a = key_for_range_with_prefix("vector", 0, 2047);
    let vector_b = key_for_range_with_prefix("vector", 2048, CLUSTER_SLOT_COUNT - 1);
    client_a
        .execute_value("VSET", &[&vector_a, "2", "1", "0"])
        .await
        .unwrap();
    client_a
        .execute_value("VSET", &[&vector_b, "2", "0.9", "0.1"])
        .await
        .unwrap();
    assert_eq!(
        client_b.execute_value("VCARD", &[]).await.unwrap(),
        EmbeddedValue::Int(2)
    );
    let search = client_b
        .execute_value("VSEARCH", &["2", "1", "0", "K", "2"])
        .await
        .unwrap();
    let EmbeddedValue::Array(search) = search else {
        panic!("expected VSEARCH array");
    };
    assert_eq!(search.len(), 2);
    let EmbeddedValue::Array(best) = &search[0] else {
        panic!("expected VSEARCH hit");
    };
    assert_eq!(best[0], EmbeddedValue::Bulk(vector_a.clone().into()));

    let series_a = key_for_range_with_prefix("series", 0, 2047);
    let series_b = key_for_range_with_prefix("series", 2048, CLUSTER_SLOT_COUNT - 1);
    for (key, timestamp, value) in [(&series_a, "1000", "1"), (&series_b, "2000", "2")] {
        client_a
            .execute_value("TSADD", &[key, timestamp, value, "LABELS", "site", "west"])
            .await
            .unwrap();
    }
    let series = client_b
        .execute_value("TSMRANGE", &["-", "+", "FILTER", "site=west"])
        .await
        .unwrap();
    let EmbeddedValue::Array(series) = series else {
        panic!("expected TSMRANGE array");
    };
    assert_eq!(series.len(), 2);

    let keys = client_b
        .execute_value("KEYS", &["cluster:key:*"])
        .await
        .unwrap();
    let EmbeddedValue::Array(keys) = keys else {
        panic!("expected KEYS array");
    };
    assert_eq!(keys.len(), 2);

    let mut resp = tokio::net::TcpStream::connect(node_a.local_addr().unwrap())
        .await
        .unwrap();
    resp.write_all(&resp_command(&["GET", &key_b]))
        .await
        .unwrap();
    let expected = b"$12\r\nremote-event\r\n";
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
    assert!(broad_update
        .to_string()
        .contains("must include WHERE id = <value> as an AND condition"));
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

#[tokio::test]
async fn online_resize_and_consolidation_move_kv_and_table_rows_without_duplicates() {
    let dir = tempfile::tempdir().unwrap();
    let peer_port_a = reserve_udp_port();
    let peer_port_b = reserve_udp_port();
    let http_port_a = reserve_tcp_port();
    let http_port_b = reserve_tcp_port();
    let (cert_a_path, key_a_path, cert_a) = identity("resize-a.cluster.local", dir.path());
    let (cert_b_path, key_b_path, cert_b) = identity("resize-b.cluster.local", dir.path());
    let signing_key = SigningKey::random(&mut OsRng);
    let controller_public_key = URL_SAFE_NO_PAD.encode(
        signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes(),
    );
    let encryption = lux::EncryptionConfig {
        active_key_id: Some("cluster-test-key".to_string()),
        keys: vec![lux::EncryptionKeyConfig {
            id: "cluster-test-key".to_string(),
            secret: b"shared-cluster-test-encryption-key".to_vec(),
            decrypt_only: false,
        }],
        ..Default::default()
    };
    let nodes = vec![
        NodeDescriptor {
            node_id: "node-a".into(),
            peer_addr: format!("127.0.0.1:{peer_port_a}"),
            server_name: "resize-a.cluster.local".into(),
            certificate_der: URL_SAFE_NO_PAD.encode(&cert_a),
            certificate_sha256: certificate_fingerprint(&cert_a),
        },
        NodeDescriptor {
            node_id: "node-b".into(),
            peer_addr: format!("127.0.0.1:{peer_port_b}"),
            server_name: "resize-b.cluster.local".into(),
            certificate_der: URL_SAFE_NO_PAD.encode(&cert_b),
            certificate_sha256: certificate_fingerprint(&cert_b),
        },
    ];
    let initial = SignedTopology::sign(
        TopologyManifest {
            schema_version: CLUSTER_TOPOLOGY_SCHEMA_VERSION,
            protocol_version: CLUSTER_PROTOCOL_VERSION,
            cluster_id: "resize-test".into(),
            epoch: 1,
            system_node_id: "node-a".into(),
            slot_count: CLUSTER_SLOT_COUNT,
            catalog_version: 1,
            nodes: nodes.clone(),
            assignments: vec![SlotAssignment {
                start: 0,
                end: CLUSTER_SLOT_COUNT - 1,
                node_id: "node-a".into(),
            }],
        },
        &signing_key,
    )
    .unwrap();
    let topology_path = dir.path().join("resize-topology.json");
    std::fs::write(&topology_path, serde_json::to_vec_pretty(&initial).unwrap()).unwrap();
    let cluster = |node_id: &str,
                   peer_port: u16,
                   certificate_chain_path: std::path::PathBuf,
                   private_key_path: std::path::PathBuf| ClusterConfig {
        local_node_id: node_id.to_string(),
        peer_bind_addr: format!("127.0.0.1:{peer_port}").parse().unwrap(),
        certificate_chain_path,
        private_key_path,
        topology_path: topology_path.clone(),
        topology_state_path: dir.path().join(format!("{node_id}-resize-state.json")),
        controller_public_key: controller_public_key.clone(),
        max_frame_bytes: 1024 * 1024,
    };
    let node_a = lux::run_with_config(lux::ServerConfig {
        enable_resp: false,
        http_port: http_port_a,
        shards: 4,
        data_dir: dir.path().join("resize-a-data").display().to_string(),
        encryption: encryption.clone(),
        cluster: Some(cluster("node-a", peer_port_a, cert_a_path, key_a_path)),
        ..Default::default()
    })
    .await
    .unwrap();
    let node_b = lux::run_with_config(lux::ServerConfig {
        enable_resp: false,
        http_port: http_port_b,
        shards: 4,
        data_dir: dir.path().join("resize-b-data").display().to_string(),
        encryption,
        cluster: Some(cluster("node-b", peer_port_b, cert_b_path, key_b_path)),
        ..Default::default()
    })
    .await
    .unwrap();
    let client_a = node_a.client();
    let client_b = node_b.client();
    let moved_key = key_for_range(2048, CLUSTER_SLOT_COUNT - 1);
    let retained_key = key_for_range(0, 2047);
    client_a.set(&moved_key, b"move-me").await.unwrap();
    client_a.set(&retained_key, b"stay-here").await.unwrap();
    client_a
        .execute_value(
            "TCREATE",
            &[
                "resize_rows",
                "id STR PRIMARY KEY,",
                "state STR NOT NULL,",
                "secret STR ENCRYPTED",
            ],
        )
        .await
        .unwrap();
    let moved_row = table_pk_for_range("resize_rows", 2048, CLUSTER_SLOT_COUNT - 1);
    let retained_row = table_pk_for_range("resize_rows", 0, 2047);
    for (id, state) in [(&moved_row, "moved"), (&retained_row, "retained")] {
        client_a
            .execute_value("TINSERT", &["resize_rows", "id", id, "state", state])
            .await
            .unwrap();
    }

    let http = reqwest::Client::new();
    post_engine_json(
        &http,
        http_port_a,
        "/v1/cluster/catalogs/sync",
        serde_json::json!({}),
    )
    .await;
    let mut split_manifest = initial.manifest.clone();
    split_manifest.epoch = 2;
    split_manifest.assignments = vec![
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
    ];
    let split = SignedTopology::sign(split_manifest, &signing_key).unwrap();
    let split_json = serde_json::to_value(&split).unwrap();
    post_engine_json(
        &http,
        http_port_b,
        "/v1/cluster/topology/prepare",
        split_json.clone(),
    )
    .await;
    post_engine_json(
        &http,
        http_port_a,
        "/v1/cluster/topology/prepare",
        split_json,
    )
    .await;
    let fenced = client_a.get(&moved_key).await.unwrap_err();
    assert!(fenced.to_string().contains("fenced slot"), "{fenced}");
    assert_eq!(
        client_a.get(&retained_key).await.unwrap().as_deref(),
        Some(b"stay-here".as_slice())
    );
    let source_transfer = post_engine_json(
        &http,
        http_port_a,
        "/v1/cluster/transfers/run",
        serde_json::json!({}),
    )
    .await;
    assert_eq!(source_transfer["ready_to_commit"], true);
    post_engine_json(
        &http,
        http_port_b,
        "/v1/cluster/topology/commit",
        serde_json::json!({ "epoch": 2 }),
    )
    .await;
    // The target has cut over but the source is still on the previous epoch.
    // Replaying the transfer recovers the same receipt instead of being fenced.
    let recovered = post_engine_json(
        &http,
        http_port_a,
        "/v1/cluster/transfers/run",
        serde_json::json!({}),
    )
    .await;
    assert_eq!(recovered["ready_to_commit"], true);
    post_engine_json(
        &http,
        http_port_a,
        "/v1/cluster/topology/commit",
        serde_json::json!({ "epoch": 2 }),
    )
    .await;

    assert_eq!(
        client_a.get(&moved_key).await.unwrap().as_deref(),
        Some(b"move-me".as_slice())
    );
    let http_moved: serde_json::Value = http
        .get(format!("http://127.0.0.1:{http_port_a}/v1/kv/{moved_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(http_moved["result"], "move-me");
    let http_keys: serde_json::Value = http
        .get(format!("http://127.0.0.1:{http_port_a}/v1/keys"))
        .query(&[("pattern", "cluster:key:*")])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let mut http_keys = http_keys["result"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    http_keys.sort();
    let mut expected_keys = vec![moved_key.clone(), retained_key.clone()];
    expected_keys.sort();
    assert_eq!(http_keys, expected_keys);
    assert_eq!(
        client_b.get(&retained_key).await.unwrap().as_deref(),
        Some(b"stay-here".as_slice())
    );
    assert_eq!(
        client_a
            .execute_value("TGET", &["resize_rows", &moved_row, "state"])
            .await
            .unwrap(),
        EmbeddedValue::Bulk(bytes::Bytes::from_static(b"moved"))
    );
    assert_eq!(
        client_a
            .execute_value("TCOUNT", &["resize_rows"])
            .await
            .unwrap(),
        EmbeddedValue::Int(2)
    );

    // The PostgREST-style table surface uses the same distributed path. The
    // new row hashes to B even though every request enters through A.
    let http_row = table_pks_for_range("resize_rows", 2048, CLUSTER_SLOT_COUNT - 1, 2)
        .into_iter()
        .find(|id| id != &moved_row)
        .unwrap();
    let inserted = http
        .post(format!(
            "http://127.0.0.1:{http_port_a}/v1/tables/resize_rows"
        ))
        .json(&serde_json::json!({
            "id": http_row,
            "state": "http-created",
            "secret": "must-not-leak",
        }))
        .send()
        .await
        .unwrap();
    let status = inserted.status();
    let inserted: serde_json::Value = inserted.json().await.unwrap();
    assert!(status.is_success(), "HTTP insert failed: {inserted}");
    assert_eq!(inserted["result"]["id"], http_row);
    // Bare auth-disabled HTTP is an anonymous surface; ENCRYPTED values are
    // materialized as null rather than returned in plaintext.
    assert_eq!(inserted["result"]["secret"], serde_json::Value::Null);

    let fetched: serde_json::Value = http
        .get(format!(
            "http://127.0.0.1:{http_port_a}/v1/tables/resize_rows/{http_row}"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(fetched["result"]["state"], "http-created");
    assert_eq!(fetched["result"]["secret"], serde_json::Value::Null);

    let updated = http
        .patch(format!(
            "http://127.0.0.1:{http_port_a}/v1/tables/resize_rows/{http_row}"
        ))
        .json(&serde_json::json!({ "state": "http-updated" }))
        .send()
        .await
        .unwrap();
    let status = updated.status();
    let updated: serde_json::Value = updated.json().await.unwrap();
    assert!(status.is_success(), "HTTP update failed: {updated}");
    assert_eq!(updated["result"][0]["state"], "http-updated");

    let broad = http
        .patch(format!(
            "http://127.0.0.1:{http_port_a}/v1/tables/resize_rows"
        ))
        .query(&[("where", "state = http-updated")])
        .json(&serde_json::json!({ "state": "must-not-run" }))
        .send()
        .await
        .unwrap();
    assert_eq!(broad.status(), reqwest::StatusCode::BAD_REQUEST);
    assert!(broad
        .text()
        .await
        .unwrap()
        .contains("must include WHERE id"));

    let count: serde_json::Value = http
        .get(format!(
            "http://127.0.0.1:{http_port_a}/v1/tables/resize_rows/count"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(count["result"], 3);

    let deleted = http
        .delete(format!(
            "http://127.0.0.1:{http_port_a}/v1/tables/resize_rows"
        ))
        .query(&[("where", format!("id = {http_row}"))])
        .send()
        .await
        .unwrap();
    let status = deleted.status();
    let deleted: serde_json::Value = deleted.json().await.unwrap();
    assert!(status.is_success(), "HTTP delete failed: {deleted}");
    assert_eq!(deleted["result"][0]["id"], http_row);
    assert_eq!(
        client_a
            .execute_value("TGET", &["resize_rows", &http_row])
            .await
            .unwrap(),
        EmbeddedValue::Nil
    );
    for port in [http_port_b, http_port_a] {
        let finalized = post_engine_json(
            &http,
            port,
            "/v1/cluster/transfers/finalize",
            serde_json::json!({ "epoch": 2 }),
        )
        .await;
        assert_eq!(finalized["finalized"], true);
    }

    let mut consolidated_manifest = initial.manifest.clone();
    consolidated_manifest.epoch = 3;
    let consolidated = SignedTopology::sign(consolidated_manifest.clone(), &signing_key).unwrap();
    let consolidated_json = serde_json::to_value(&consolidated).unwrap();
    post_engine_json(
        &http,
        http_port_a,
        "/v1/cluster/topology/prepare",
        consolidated_json.clone(),
    )
    .await;
    post_engine_json(
        &http,
        http_port_b,
        "/v1/cluster/topology/prepare",
        consolidated_json,
    )
    .await;
    post_engine_json(
        &http,
        http_port_b,
        "/v1/cluster/transfers/run",
        serde_json::json!({}),
    )
    .await;
    post_engine_json(
        &http,
        http_port_a,
        "/v1/cluster/topology/commit",
        serde_json::json!({ "epoch": 3 }),
    )
    .await;
    post_engine_json(
        &http,
        http_port_b,
        "/v1/cluster/topology/commit",
        serde_json::json!({ "epoch": 3 }),
    )
    .await;
    assert_eq!(
        client_b.get(&moved_key).await.unwrap().as_deref(),
        Some(b"move-me".as_slice())
    );
    assert_eq!(
        client_a
            .execute_value("TCOUNT", &["resize_rows"])
            .await
            .unwrap(),
        EmbeddedValue::Int(2)
    );
    for port in [http_port_a, http_port_b] {
        let finalized = post_engine_json(
            &http,
            port,
            "/v1/cluster/transfers/finalize",
            serde_json::json!({ "epoch": 3 }),
        )
        .await;
        assert_eq!(finalized["finalized"], true);
    }

    let legacy_snapshot = http
        .get(format!("http://127.0.0.1:{http_port_a}/v1/snapshot"))
        .send()
        .await
        .unwrap();
    assert_eq!(legacy_snapshot.status(), reqwest::StatusCode::CONFLICT);
    let mut descriptors = Vec::new();
    for port in [http_port_a, http_port_b] {
        let response = http
            .get(format!("http://127.0.0.1:{port}/v1/cluster/backup/part"))
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success());
        let encoded = response
            .headers()
            .get("x-lux-cluster-part")
            .unwrap()
            .to_str()
            .unwrap();
        let descriptor: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).unwrap()).unwrap();
        assert!(!response.bytes().await.unwrap().is_empty());
        descriptors.push(descriptor);
    }
    assert_eq!(descriptors[0]["cluster_id"], "resize-test");
    assert_eq!(descriptors[0]["topology_epoch"], 3);
    assert_eq!(
        descriptors[0]["topology_sha256"],
        descriptors[1]["topology_sha256"]
    );
    assert_ne!(descriptors[0]["node_id"], descriptors[1]["node_id"]);

    consolidated_manifest.epoch = 4;
    consolidated_manifest.nodes = vec![nodes[0].clone()];
    let remove_b = SignedTopology::sign(consolidated_manifest, &signing_key).unwrap();
    let remove_json = serde_json::to_value(&remove_b).unwrap();
    post_engine_json(
        &http,
        http_port_a,
        "/v1/cluster/topology/prepare",
        remove_json.clone(),
    )
    .await;
    post_engine_json(
        &http,
        http_port_b,
        "/v1/cluster/topology/prepare",
        remove_json,
    )
    .await;
    post_engine_json(
        &http,
        http_port_b,
        "/v1/cluster/topology/commit",
        serde_json::json!({ "epoch": 4 }),
    )
    .await;
    post_engine_json(
        &http,
        http_port_a,
        "/v1/cluster/topology/commit",
        serde_json::json!({ "epoch": 4 }),
    )
    .await;
    assert_eq!(
        client_a.get(&moved_key).await.unwrap().as_deref(),
        Some(b"move-me".as_slice())
    );

    drop(client_a);
    drop(client_b);
    node_a.shutdown_and_wait().await.unwrap();
    node_b.shutdown_and_wait().await.unwrap();
}
