use super::*;
use crate::cluster::{
    certificate_fingerprint, encode_controller_public_key, NodeDescriptor, SignedTopology,
    SlotAssignment, TopologyManifest, TransferJournal, CLUSTER_PROTOCOL_VERSION,
    CLUSTER_TOPOLOGY_SCHEMA_VERSION,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use p256::ecdsa::SigningKey;
use rand_core::OsRng;
use rcgen::{CertificateParams, KeyPair};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::{mpsc, Barrier};
use std::thread;
use std::time::Duration;

fn node(node_id: &str, port: u16) -> NodeDescriptor {
    let server_name = format!("{node_id}.cluster.local");
    let params = CertificateParams::new(vec![server_name.clone()]).unwrap();
    let key = KeyPair::generate().unwrap();
    let certificate = params.self_signed(&key).unwrap().der().to_vec();
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

fn descriptor() -> TransferDescriptor {
    let key = SigningKey::random(&mut OsRng);
    let controller_key = encode_controller_public_key(key.verifying_key());
    let current = TopologyManifest {
        schema_version: CLUSTER_TOPOLOGY_SCHEMA_VERSION,
        protocol_version: CLUSTER_PROTOCOL_VERSION,
        cluster_id: "cluster-a".to_owned(),
        epoch: 3,
        control_node_id: "node-a".to_owned(),
        slot_count: CLUSTER_SLOT_COUNT,
        nodes: vec![node("node-a", 7001), node("node-b", 7002)],
        assignments: vec![
            SlotAssignment {
                start: 0,
                end: 2047,
                node_id: "node-a".to_owned(),
            },
            SlotAssignment {
                start: 2048,
                end: CLUSTER_SLOT_COUNT - 1,
                node_id: "node-b".to_owned(),
            },
        ],
    };
    let current = SignedTopology::sign(current, &key)
        .unwrap()
        .verify(&controller_key)
        .unwrap();
    let mut candidate = current.manifest().clone();
    candidate.epoch = 4;
    candidate.assignments[0].end = 1023;
    candidate.assignments[1].start = 1024;
    let candidate = SignedTopology::sign(candidate, &key)
        .unwrap()
        .verify(&controller_key)
        .unwrap();
    TransferDescriptor::from_topologies(&current, &candidate, "node-a", "node-b").unwrap()
}

fn config() -> TransferRuntimeConfig {
    TransferRuntimeConfig {
        max_dirty_keys: 100_000,
        max_dirty_bytes: 128 * 1024 * 1024,
    }
}

fn kv_for(descriptor: &TransferDescriptor, label: &str, moving: bool) -> TransferDataKey {
    (0..100_000)
        .map(|index| TransferDataKey::kv(format!("{label}:{index}")).unwrap())
        .find(|key| descriptor.contains_slot(key.slot()) == moving)
        .unwrap()
}

fn distinct_moving_keys(descriptor: &TransferDescriptor, count: usize) -> Vec<TransferDataKey> {
    (0..)
        .map(|index| TransferDataKey::kv(format!("concurrent:{index}")).unwrap())
        .filter(|key| descriptor.contains_slot(key.slot()))
        .take(count)
        .collect()
}

fn expect_admitted(admission: TransferWriteAdmission) -> TransferWriteGuard {
    match admission {
        TransferWriteAdmission::Admitted(guard) => guard,
        TransferWriteAdmission::Untracked => panic!("write was unexpectedly untracked"),
        TransferWriteAdmission::Fenced(_) => panic!("write was unexpectedly fenced"),
        TransferWriteAdmission::Redirect(_) => panic!("write was unexpectedly redirected"),
    }
}

fn begin(runtime: &TransferRuntime, key: &TransferDataKey) -> TransferWriteAdmission {
    match key {
        TransferDataKey::Kv(key) => runtime.begin_kv_write(key).unwrap(),
        TransferDataKey::TableRow { table, primary_key } => {
            runtime.begin_table_row_write(table, primary_key).unwrap()
        }
    }
}

#[test]
fn only_source_slots_under_transfer_pay_the_tracking_cost() {
    let descriptor = descriptor();
    let moving = kv_for(&descriptor, "moving", true);
    let stationary = kv_for(&descriptor, "stationary", false);
    let runtime = TransferRuntime::new("node-a", config()).unwrap();

    assert!(matches!(
        begin(&runtime, &moving),
        TransferWriteAdmission::Untracked
    ));
    runtime.install_source(descriptor.clone()).unwrap();
    assert!(matches!(
        begin(&runtime, &stationary),
        TransferWriteAdmission::Untracked
    ));
    drop(expect_admitted(begin(&runtime, &moving)));
    assert_eq!(runtime.dirty_stats(descriptor.transfer_id).unwrap().keys, 1);

    let wrong_node = TransferRuntime::new("node-b", config()).unwrap();
    assert!(matches!(
        wrong_node.install_source(descriptor),
        Err(ClusterError::InvalidTransfer(_))
    ));
}

#[test]
fn untracked_and_fenced_writes_do_not_materialize_dirty_identities() {
    let descriptor = descriptor();
    let key = kv_for(&descriptor, "lazy", true);
    let runtime = TransferRuntime::new("node-a", config()).unwrap();
    let materialized = AtomicBool::new(false);
    assert!(matches!(
        runtime.begin_write(key.slot(), key.tracked_bytes(), || {
            materialized.store(true, AtomicOrdering::Release);
            key.clone()
        }),
        TransferWriteAdmission::Untracked
    ));
    assert!(!materialized.load(AtomicOrdering::Acquire));

    runtime.install_source(descriptor.clone()).unwrap();
    runtime
        .fence_and_drain(descriptor.transfer_id, Duration::from_secs(2))
        .unwrap();
    assert!(matches!(
        runtime.begin_write(key.slot(), key.tracked_bytes(), || {
            materialized.store(true, AtomicOrdering::Release);
            key.clone()
        }),
        TransferWriteAdmission::Fenced(_)
    ));
    assert!(!materialized.load(AtomicOrdering::Acquire));
}

#[test]
fn identity_becomes_dirty_only_after_the_admitted_mutation_finishes() {
    let descriptor = descriptor();
    let key = kv_for(&descriptor, "guarded", true);
    let runtime = TransferRuntime::new("node-a", config()).unwrap();
    runtime.install_source(descriptor.clone()).unwrap();

    let guard = expect_admitted(begin(&runtime, &key));
    let stats = runtime.dirty_stats(descriptor.transfer_id).unwrap();
    assert_eq!(stats.keys, 1);
    assert!(!stats.overflowed);
    assert!(runtime
        .drain_dirty(descriptor.transfer_id)
        .unwrap()
        .is_empty());
    drop(guard);
    assert_eq!(
        runtime.drain_dirty(descriptor.transfer_id).unwrap(),
        vec![key]
    );
    assert_eq!(runtime.dirty_stats(descriptor.transfer_id).unwrap().keys, 0);
}

#[test]
fn dirty_rounds_deduplicate_and_retrack_later_mutations() {
    let descriptor = descriptor();
    let first = kv_for(&descriptor, "first", true);
    let second = kv_for(&descriptor, "second", true);
    let runtime = TransferRuntime::new("node-a", config()).unwrap();
    runtime.install_source(descriptor.clone()).unwrap();

    drop(expect_admitted(begin(&runtime, &first)));
    drop(expect_admitted(begin(&runtime, &first)));
    drop(expect_admitted(begin(&runtime, &second)));
    let mut expected = vec![first.clone(), second];
    expected.sort_unstable();
    assert_eq!(
        runtime.drain_dirty(descriptor.transfer_id).unwrap(),
        expected
    );

    drop(expect_admitted(begin(&runtime, &first)));
    assert_eq!(
        runtime.drain_dirty(descriptor.transfer_id).unwrap(),
        vec![first]
    );
}

#[test]
fn table_rows_route_by_logical_table_identity() {
    let descriptor = descriptor();
    let (table_row, raw_key) = (0..100_000)
        .find_map(|index| {
            let primary_key = format!("row:{index}").into_bytes();
            let table = TransferDataKey::table_row("accounts", primary_key.clone()).unwrap();
            let raw = TransferDataKey::kv(primary_key).unwrap();
            (descriptor.contains_slot(table.slot()) && !descriptor.contains_slot(raw.slot()))
                .then_some((table, raw))
        })
        .unwrap();
    let runtime = TransferRuntime::new("node-a", config()).unwrap();
    runtime.install_source(descriptor.clone()).unwrap();

    assert!(matches!(
        begin(&runtime, &raw_key),
        TransferWriteAdmission::Untracked
    ));
    drop(expect_admitted(begin(&runtime, &table_row)));
    assert_eq!(
        runtime.drain_dirty(descriptor.transfer_id).unwrap(),
        vec![table_row]
    );
}

#[test]
fn final_fence_waits_for_admitted_writers_and_rejects_new_ones() {
    let descriptor = descriptor();
    let key = kv_for(&descriptor, "in-flight", true);
    let runtime = Arc::new(TransferRuntime::new("node-a", config()).unwrap());
    runtime.install_source(descriptor.clone()).unwrap();
    let guard = expect_admitted(begin(&runtime, &key));
    let (finished_tx, finished_rx) = mpsc::channel();
    let fence_runtime = Arc::clone(&runtime);
    let transfer_id = descriptor.transfer_id;
    let fence_thread = thread::spawn(move || {
        let result = fence_runtime.fence_and_drain(transfer_id, Duration::from_secs(2));
        finished_tx.send(result).unwrap();
    });

    let transfer = runtime.find(transfer_id).unwrap();
    while transfer.phase.load(Ordering::Acquire) != PHASE_FENCING {
        thread::yield_now();
    }
    assert!(finished_rx.try_recv().is_err());
    match begin(&runtime, &key) {
        TransferWriteAdmission::Fenced(fence) => {
            assert_eq!(fence.transfer_id, transfer_id);
            assert_eq!(fence.target_node_id, "node-b");
            assert_eq!(fence.to_epoch, 4);
        }
        _ => panic!("post-fence write was not fenced"),
    }

    drop(guard);
    let final_batch = finished_rx
        .recv_timeout(Duration::from_secs(2))
        .unwrap()
        .unwrap();
    assert_eq!(final_batch.as_ref(), std::slice::from_ref(&key));
    fence_thread.join().unwrap();
    let retry = runtime
        .fence_and_drain(transfer_id, Duration::from_secs(2))
        .unwrap();
    assert!(Arc::ptr_eq(&final_batch.keys, &retry.keys));
    assert_eq!(runtime.dirty_stats(transfer_id).unwrap().keys, 1);

    let directory = tempfile::tempdir().unwrap();
    let source = TransferJournal::open(
        TransferRole::Source,
        descriptor.clone(),
        directory.path().join("source.json"),
        16 * 1024 * 1024,
    )
    .unwrap();
    let target = TransferJournal::open(
        TransferRole::Target,
        descriptor.clone(),
        directory.path().join("target.json"),
        16 * 1024 * 1024,
    )
    .unwrap();
    source.begin_source_attempt().unwrap();
    let start = target.accept_target_attempt(1).unwrap();
    source.record_target_start(&start).unwrap();
    let chunk = source
        .next_source_chunk(1, b"final-dirty-batch".to_vec())
        .unwrap();
    let (_, receipt) = target.append_target_chunk(&chunk).unwrap();
    source.record_source_receipt(&chunk, &receipt).unwrap();
    source.mark_source_fenced(&receipt).unwrap();
    let fenced_snapshot = source.snapshot();
    assert!(matches!(
        runtime.mark_activated(&fenced_snapshot),
        Err(ClusterError::InvalidTransfer(_))
    ));
    runtime.confirm_final(&fenced_snapshot).unwrap();
    assert_eq!(runtime.dirty_stats(transfer_id).unwrap().keys, 0);
    assert!(matches!(
        runtime.mark_activated(&fenced_snapshot),
        Err(ClusterError::InvalidTransfer(_))
    ));
    let recovered_fence = TransferRuntime::new("node-a", config()).unwrap();
    recovered_fence.recover_source(&fenced_snapshot).unwrap();
    assert!(matches!(
        begin(&recovered_fence, &key),
        TransferWriteAdmission::Fenced(_)
    ));
    recovered_fence.confirm_final(&fenced_snapshot).unwrap();
    source.seal(&receipt).unwrap();
    target.seal(&receipt).unwrap();
    source.mark_topology_committed(4).unwrap();
    target.mark_target_applied(&receipt).unwrap();
    let proof = crate::cluster::TargetReadyProof::for_test(receipt.transfer_id);
    target.mark_target_ready(&receipt, &proof).unwrap();
    target.mark_topology_committed(4).unwrap();
    let activated_snapshot = source.snapshot();

    let recovered_redirect = TransferRuntime::new("node-a", config()).unwrap();
    recovered_redirect
        .recover_source(&activated_snapshot)
        .unwrap();
    assert!(matches!(
        begin(&recovered_redirect, &key),
        TransferWriteAdmission::Redirect(_)
    ));

    runtime.mark_activated(&activated_snapshot).unwrap();
    match begin(&runtime, &kv_for(&descriptor, "stale-client", true)) {
        TransferWriteAdmission::Redirect(redirect) => {
            assert_eq!(redirect.transfer_id, transfer_id);
            assert_eq!(redirect.target_node_id, "node-b");
            assert_eq!(redirect.to_epoch, 4);
        }
        _ => panic!("activated source did not redirect a stale write"),
    }
    assert!(matches!(
        runtime.release_aborted(transfer_id),
        Err(ClusterError::InvalidTransfer(_))
    ));
    runtime.release_activated(transfer_id).unwrap();
    assert!(matches!(
        begin(&runtime, &kv_for(&descriptor, "post-grace", true)),
        TransferWriteAdmission::Untracked
    ));
}

#[test]
fn final_fence_has_a_bounded_wait_and_remains_abortable_on_timeout() {
    let descriptor = descriptor();
    let key = kv_for(&descriptor, "timeout", true);
    let runtime = TransferRuntime::new("node-a", config()).unwrap();
    runtime.install_source(descriptor.clone()).unwrap();
    let guard = expect_admitted(begin(&runtime, &key));

    assert!(matches!(
        runtime.fence_and_drain(descriptor.transfer_id, Duration::from_millis(1)),
        Err(ClusterError::InvalidTransfer(_))
    ));
    assert!(matches!(
        begin(&runtime, &key),
        TransferWriteAdmission::Fenced(_)
    ));
    drop(guard);
    runtime.release_aborted(descriptor.transfer_id).unwrap();
    assert!(matches!(
        begin(&runtime, &key),
        TransferWriteAdmission::Untracked
    ));
}

#[test]
fn concurrent_round_drains_never_lose_or_duplicate_committed_writes() {
    const WRITERS: usize = 8;
    const KEYS_PER_WRITER: usize = 250;
    let descriptor = descriptor();
    let keys = distinct_moving_keys(&descriptor, WRITERS * KEYS_PER_WRITER);
    let expected = keys.iter().cloned().collect::<HashSet<_>>();
    let runtime = Arc::new(TransferRuntime::new("node-a", config()).unwrap());
    runtime.install_source(descriptor.clone()).unwrap();
    let start = Arc::new(Barrier::new(WRITERS + 1));
    let writers_done = Arc::new(AtomicBool::new(false));
    let mut threads = Vec::new();
    for partition in keys.chunks(KEYS_PER_WRITER) {
        let runtime = Arc::clone(&runtime);
        let start = Arc::clone(&start);
        let partition = partition.to_vec();
        threads.push(thread::spawn(move || {
            start.wait();
            for key in partition {
                drop(expect_admitted(begin(&runtime, &key)));
            }
        }));
    }
    let drain_runtime = Arc::clone(&runtime);
    let drain_done = Arc::clone(&writers_done);
    let transfer_id = descriptor.transfer_id;
    let drain_thread = thread::spawn(move || {
        let mut drained = Vec::new();
        while !drain_done.load(AtomicOrdering::Acquire) {
            drained.extend(drain_runtime.drain_dirty(transfer_id).unwrap());
            thread::yield_now();
        }
        drained.extend(drain_runtime.drain_dirty(transfer_id).unwrap());
        drained
    });

    start.wait();
    for writer in threads {
        writer.join().unwrap();
    }
    writers_done.store(true, AtomicOrdering::Release);
    let mut drained = drain_thread.join().unwrap();
    let final_batch = runtime
        .fence_and_drain(transfer_id, Duration::from_secs(2))
        .unwrap();
    drained.extend(final_batch.iter().cloned());
    let observed = drained.iter().cloned().collect::<HashSet<_>>();
    assert_eq!(observed, expected);
    assert_eq!(drained.len(), observed.len());
}

#[test]
fn overflow_fails_the_resize_closed_without_rejecting_the_write() {
    let descriptor = descriptor();
    let first = kv_for(&descriptor, "quota-a", true);
    let second = kv_for(&descriptor, "quota-b", true);
    let runtime = TransferRuntime::new(
        "node-a",
        TransferRuntimeConfig {
            max_dirty_keys: 1,
            max_dirty_bytes: MAX_TRANSFER_IDENTITY_BYTES,
        },
    )
    .unwrap();
    runtime.install_source(descriptor.clone()).unwrap();

    drop(expect_admitted(begin(&runtime, &first)));
    drop(expect_admitted(begin(&runtime, &second)));
    assert_eq!(
        runtime.dirty_stats(descriptor.transfer_id).unwrap(),
        DirtyStats {
            keys: 1,
            bytes: runtime.dirty_stats(descriptor.transfer_id).unwrap().bytes,
            overflowed: true,
        }
    );
    assert!(matches!(
        runtime.drain_dirty(descriptor.transfer_id),
        Err(ClusterError::InvalidTransfer(_))
    ));
    assert!(matches!(
        runtime.fence_and_drain(descriptor.transfer_id, Duration::from_secs(2)),
        Err(ClusterError::InvalidTransfer(_))
    ));
}

#[test]
fn in_flight_identity_memory_is_reserved_before_materialization() {
    let descriptor = descriptor();
    let first = kv_for(&descriptor, "in-flight-quota-a", true);
    let second = kv_for(&descriptor, "in-flight-quota-b", true);
    let runtime = TransferRuntime::new(
        "node-a",
        TransferRuntimeConfig {
            max_dirty_keys: 1,
            max_dirty_bytes: MAX_TRANSFER_IDENTITY_BYTES,
        },
    )
    .unwrap();
    runtime.install_source(descriptor.clone()).unwrap();
    let first_guard = expect_admitted(begin(&runtime, &first));
    let materialized = AtomicBool::new(false);
    let second_guard =
        expect_admitted(
            runtime.begin_write(second.slot(), second.tracked_bytes(), || {
                materialized.store(true, AtomicOrdering::Release);
                second
            }),
        );

    assert!(!materialized.load(AtomicOrdering::Acquire));
    assert!(
        runtime
            .dirty_stats(descriptor.transfer_id)
            .unwrap()
            .overflowed
    );
    drop(second_guard);
    drop(first_guard);
    assert!(matches!(
        runtime.fence_and_drain(descriptor.transfer_id, Duration::from_secs(2)),
        Err(ClusterError::InvalidTransfer(_))
    ));
}

#[test]
fn aborted_transfer_releases_the_fence_and_can_be_reinstalled() {
    let descriptor = descriptor();
    let key = kv_for(&descriptor, "abort", true);
    let runtime = TransferRuntime::new("node-a", config()).unwrap();
    runtime.install_source(descriptor.clone()).unwrap();
    runtime
        .fence_and_drain(descriptor.transfer_id, Duration::from_secs(2))
        .unwrap();
    assert!(matches!(
        begin(&runtime, &key),
        TransferWriteAdmission::Fenced(_)
    ));
    runtime.release_aborted(descriptor.transfer_id).unwrap();
    assert!(matches!(
        begin(&runtime, &key),
        TransferWriteAdmission::Untracked
    ));

    runtime.install_source(descriptor.clone()).unwrap();
    runtime.install_source(descriptor).unwrap();
    drop(expect_admitted(begin(&runtime, &key)));
}

#[test]
fn malformed_identities_and_undersized_runtime_budgets_are_rejected() {
    assert!(TransferDataKey::kv(Vec::new()).is_ok());
    assert!(TransferDataKey::table_row("bad table", b"id".to_vec()).is_err());
    assert!(TransferDataKey::table_row("accounts", Vec::new()).is_ok());
    assert!(TransferDataKey::table_row("münchen.accounts", b"id".to_vec()).is_ok());
    assert!(TransferRuntime::new("bad node", config()).is_err());
    assert!(TransferRuntime::new(
        "node-a",
        TransferRuntimeConfig {
            max_dirty_keys: 1,
            max_dirty_bytes: MAX_TRANSFER_IDENTITY_BYTES - 1,
        },
    )
    .is_err());
}
