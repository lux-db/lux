use super::*;
use crate::cluster::TopologyState;
use p256::ecdsa::SigningKey;
use proptest::prelude::*;
use rand_core::OsRng;
use rcgen::{CertificateParams, KeyPair};
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::Barrier;

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

fn manifest(epoch: u64) -> TopologyManifest {
    TopologyManifest {
        schema_version: CLUSTER_TOPOLOGY_SCHEMA_VERSION,
        protocol_version: CLUSTER_PROTOCOL_VERSION,
        cluster_id: "project-cluster-1".to_owned(),
        epoch,
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
    }
}

fn signed(epoch: u64, key: &SigningKey) -> SignedTopology {
    SignedTopology::sign(manifest(epoch), key).unwrap()
}

#[test]
fn signed_manifest_compiles_every_slot_and_direct_endpoint() {
    let key = SigningKey::random(&mut OsRng);
    let topology = signed(1, &key)
        .verify(&encode_controller_public_key(key.verifying_key()))
        .unwrap();
    assert_eq!(topology.owner_for_slot(0).unwrap().node_id, "node-1");
    assert_eq!(
        topology
            .owner_for_slot(CLUSTER_SLOT_COUNT - 1)
            .unwrap()
            .node_id,
        "node-2"
    );
    assert!(topology
        .owner_for_key(b"account:42")
        .client_resp_url
        .starts_with("redis://"));
    let ranges = topology.redis_slot_ranges();
    assert_eq!(ranges.len(), 8);
    for client_slot in 0..CLUSTER_CLIENT_SLOT_COUNT {
        let projected = ranges
            .iter()
            .find(|range| range.start <= client_slot && client_slot <= range.end)
            .unwrap();
        assert_eq!(
            projected.node_id,
            topology
                .owner_for_slot(client_slot % CLUSTER_SLOT_COUNT)
                .unwrap()
                .node_id
        );
    }
}

#[test]
fn signature_covers_direct_endpoints_and_ownership() {
    let key = SigningKey::random(&mut OsRng);
    let public_key = encode_controller_public_key(key.verifying_key());
    let mut topology = signed(1, &key);
    topology.manifest.nodes[0].client_resp_url = "rediss://attacker.example:6379".to_owned();
    assert!(matches!(
        topology.verify(&public_key),
        Err(ClusterError::Signature(_))
    ));

    let mut topology = signed(1, &key);
    topology.manifest.assignments[0].node_id = "node-2".to_owned();
    assert!(matches!(
        topology.verify(&public_key),
        Err(ClusterError::Signature(_))
    ));
}

#[test]
fn signature_encoding_is_canonical_and_rejects_malleability() {
    let key = SigningKey::random(&mut OsRng);
    let public_key = encode_controller_public_key(key.verifying_key());
    let mut topology = signed(1, &key);
    let bytes = URL_SAFE_NO_PAD.decode(&topology.signature).unwrap();
    let signature = Signature::from_slice(&bytes).unwrap();
    assert!(signature.normalize_s().is_none());
    let (r, s) = signature.split_scalars();
    let high_s = Signature::from_scalars(r, -s).unwrap();
    assert!(high_s.normalize_s().is_some());
    topology.signature = URL_SAFE_NO_PAD.encode(high_s.to_bytes());
    assert!(matches!(
        topology.verify(&public_key),
        Err(ClusterError::Signature(_))
    ));
}

#[test]
fn rejects_insecure_public_client_endpoints() {
    let key = SigningKey::random(&mut OsRng);
    let mut candidate = manifest(1);
    candidate.nodes[0].client_http_url = "http://node-1.example:5890".to_owned();
    assert!(matches!(
        SignedTopology::sign(candidate, &key),
        Err(ClusterError::InvalidTopology(_))
    ));
}

#[test]
fn rejects_malformed_peer_endpoints_and_certificate_name_mismatch() {
    let key = SigningKey::random(&mut OsRng);
    for peer_addr in [
        "node-1.cluster.local",
        "node-1.cluster.local:0",
        "user@node-1.cluster.local:7001",
        "node-1.cluster.local:7001/path",
        "bad host:7001",
    ] {
        let mut candidate = manifest(1);
        candidate.nodes[0].peer_addr = peer_addr.to_owned();
        assert!(matches!(
            SignedTopology::sign(candidate, &key),
            Err(ClusterError::InvalidTopology(_))
        ));
    }

    let mut candidate = manifest(1);
    candidate.nodes[0].peer_server_name = "another-node.cluster.local".to_owned();
    assert!(matches!(
        SignedTopology::sign(candidate, &key),
        Err(ClusterError::InvalidTopology(_))
    ));
}

#[test]
fn ownership_plan_is_deterministic_and_separate_from_membership() {
    let key = SigningKey::random(&mut OsRng);
    let public_key = encode_controller_public_key(key.verifying_key());
    let current = signed(1, &key).verify(&public_key).unwrap();
    let mut next = current.manifest().clone();
    next.epoch = 2;
    next.assignments[0].end = 1023;
    next.assignments[1].start = 1024;
    let next = SignedTopology::sign(next, &key)
        .unwrap()
        .verify(&public_key)
        .unwrap();
    let plan = current.transition_to(&next).unwrap();
    assert_eq!(plan.kind, TopologyTransitionKind::Ownership);
    assert_eq!(plan.moves.len(), 1);
    assert_eq!(plan.moves[0].start, 1024);
    assert_eq!(plan.moves[0].end, 2047);

    let mut membership = next.manifest().clone();
    membership.epoch = 3;
    membership.nodes.push(node("node-3", 7003));
    let membership = SignedTopology::sign(membership, &key)
        .unwrap()
        .verify(&public_key)
        .unwrap();
    assert_eq!(
        next.transition_to(&membership).unwrap().kind,
        TopologyTransitionKind::Membership
    );

    let mut mixed = next.manifest().clone();
    mixed.epoch = 3;
    mixed.nodes.push(node("node-3", 7003));
    mixed.assignments = vec![
        SlotAssignment {
            start: 0,
            end: 1023,
            node_id: "node-1".to_owned(),
        },
        SlotAssignment {
            start: 1024,
            end: 2047,
            node_id: "node-3".to_owned(),
        },
        SlotAssignment {
            start: 2048,
            end: CLUSTER_SLOT_COUNT - 1,
            node_id: "node-2".to_owned(),
        },
    ];
    let mixed = SignedTopology::sign(mixed, &key)
        .unwrap()
        .verify(&public_key)
        .unwrap();
    assert!(matches!(
        next.transition_to(&mixed),
        Err(ClusterError::InvalidTopology(_))
    ));
}

#[test]
fn membership_identity_material_cannot_be_rebound_in_one_epoch() {
    let key = SigningKey::random(&mut OsRng);
    let public_key = encode_controller_public_key(key.verifying_key());
    let mut current = manifest(1);
    current.assignments = vec![SlotAssignment {
        start: 0,
        end: CLUSTER_SLOT_COUNT - 1,
        node_id: "node-1".to_owned(),
    }];
    let current = SignedTopology::sign(current, &key)
        .unwrap()
        .verify(&public_key)
        .unwrap();
    let mut candidate = current.manifest().clone();
    candidate.epoch = 2;
    candidate.nodes[1].node_id = "node-3".to_owned();
    let candidate = SignedTopology::sign(candidate, &key)
        .unwrap()
        .verify(&public_key)
        .unwrap();
    assert!(matches!(
        current.transition_to(&candidate),
        Err(ClusterError::InvalidTopology(_))
    ));
}

#[test]
fn rcu_state_keeps_current_immutable_until_durable_commit() {
    let key = SigningKey::random(&mut OsRng);
    let public_key = encode_controller_public_key(key.verifying_key());
    let current = signed(1, &key).verify(&public_key).unwrap();
    let state = TopologyState::in_memory(current, public_key);
    let before = state.current();
    let mut next = before.manifest().clone();
    next.epoch = 2;
    next.assignments[0].end = 1023;
    next.assignments[1].start = 1024;
    let next = SignedTopology::sign(next, &key).unwrap();
    state.prepare(next).unwrap();
    let prepared = state.snapshot();
    assert_eq!(prepared.current().manifest().epoch, 1);
    assert_eq!(prepared.pending().unwrap().manifest().epoch, 2);
    assert_eq!(state.current().manifest().epoch, 1);
    assert_eq!(before.manifest().epoch, 1);
    state.commit(2).unwrap();
    let committed = state.snapshot();
    assert_eq!(committed.current().manifest().epoch, 2);
    assert!(committed.pending().is_none());
    assert_eq!(prepared.current().manifest().epoch, 1);
    assert_eq!(prepared.pending().unwrap().manifest().epoch, 2);
    assert_eq!(before.manifest().epoch, 1);
}

#[test]
fn concurrent_rcu_readers_never_observe_a_torn_topology() {
    let key = SigningKey::random(&mut OsRng);
    let public_key = encode_controller_public_key(key.verifying_key());
    let current = signed(1, &key).verify(&public_key).unwrap();
    let state = Arc::new(TopologyState::in_memory(current, public_key));
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
                    let topology = state.current();
                    let expected_owner = if topology.manifest().epoch.is_multiple_of(2) {
                        "node-2"
                    } else {
                        "node-1"
                    };
                    assert_eq!(
                        topology.owner_for_slot(1500).unwrap().node_id,
                        expected_owner
                    );
                }
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();

    for epoch in 2..=25 {
        let mut next = state.current().manifest().clone();
        next.epoch = epoch;
        if epoch.is_multiple_of(2) {
            next.assignments[0].end = 1023;
            next.assignments[1].start = 1024;
        } else {
            next.assignments[0].end = 2047;
            next.assignments[1].start = 2048;
        }
        state
            .prepare(SignedTopology::sign(next, &key).unwrap())
            .unwrap();
        state.commit(epoch).unwrap();
        std::thread::yield_now();
    }
    stop.store(true, AtomicOrdering::Release);
    for reader in readers {
        reader.join().unwrap();
    }
}

#[test]
fn durable_pending_state_survives_restart_without_cutover() {
    let key = SigningKey::random(&mut OsRng);
    let public_key = encode_controller_public_key(key.verifying_key());
    let current = signed(1, &key).verify(&public_key).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let state_path = directory.path().join("topology-state.json");
    let state = TopologyState::open(current.clone(), public_key.clone(), &state_path).unwrap();
    let mut next = current.manifest().clone();
    next.epoch = 2;
    next.assignments[0].end = 1023;
    next.assignments[1].start = 1024;
    state
        .prepare(SignedTopology::sign(next, &key).unwrap())
        .unwrap();
    drop(state);

    let reopened = TopologyState::open(current, public_key, &state_path).unwrap();
    assert_eq!(reopened.current().manifest().epoch, 1);
    assert_eq!(reopened.pending().unwrap().manifest().epoch, 2);
    reopened.commit(2).unwrap();
    assert_eq!(reopened.current().manifest().epoch, 2);
}

#[test]
fn durable_state_rejects_same_epoch_with_different_contents() {
    let key = SigningKey::random(&mut OsRng);
    let public_key = encode_controller_public_key(key.verifying_key());
    let current = signed(1, &key).verify(&public_key).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let state_path = directory.path().join("topology-state.json");
    let state = TopologyState::open(current.clone(), public_key.clone(), &state_path).unwrap();
    drop(state);

    let mut conflicting = current.manifest().clone();
    conflicting.nodes[0].client_http_url = "http://127.0.0.1:9999".to_owned();
    let conflicting = SignedTopology::sign(conflicting, &key)
        .unwrap()
        .verify(&public_key)
        .unwrap();
    assert!(matches!(
        TopologyState::open(conflicting, public_key, &state_path),
        Err(ClusterError::InvalidTopology(_))
    ));
}

#[test]
fn topology_epoch_cannot_wrap_or_repeat() {
    let key = SigningKey::random(&mut OsRng);
    let public_key = encode_controller_public_key(key.verifying_key());
    let current = SignedTopology::sign(manifest(u64::MAX), &key)
        .unwrap()
        .verify(&public_key)
        .unwrap();
    let mut candidate = current.manifest().clone();
    candidate.assignments[0].end = 1023;
    candidate.assignments[1].start = 1024;
    let candidate = SignedTopology::sign(candidate, &key)
        .unwrap()
        .verify(&public_key)
        .unwrap();
    assert!(matches!(
        current.transition_to(&candidate),
        Err(ClusterError::InvalidTopology(_))
    ));
}

#[test]
fn slot_hash_contract_matches_clients_and_tables() {
    assert_eq!(redis_crc16(b"123456789"), 0x31c3);
    assert_eq!(slot_for_key(b"123456789"), 451);
    assert_eq!(
        slot_for_key(b"cart:{user-1}"),
        slot_for_key(b"order:{user-1}")
    );
    assert_ne!(
        slot_for_table_row(b"orders", b"42"),
        slot_for_table_row(b"users", b"42")
    );
}

proptest! {
    #[test]
    fn slot_hashes_are_bounded_and_redis_projection_is_exact(
        key in proptest::collection::vec(any::<u8>(), 0..512),
        table in proptest::collection::vec(any::<u8>(), 0..128),
        primary_key in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        let internal = slot_for_key(&key);
        let client = redis_crc16(hash_tag(&key)) % CLUSTER_CLIENT_SLOT_COUNT;
        prop_assert!(internal < CLUSTER_SLOT_COUNT);
        prop_assert_eq!(internal, client % CLUSTER_SLOT_COUNT);
        prop_assert!(slot_for_table_row(&table, &primary_key) < CLUSTER_SLOT_COUNT);
    }
}
