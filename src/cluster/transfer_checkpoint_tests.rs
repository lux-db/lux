use super::*;
use crate::cluster::test_support::compiled_execution;
use crate::cluster::{
    SlotRange, SourceStoreTransfer, TransferId, TransferPhase, TransferRole, TransferRuntime,
    TransferRuntimeConfig, CLUSTER_PROTOCOL_VERSION, CLUSTER_SLOT_COUNT,
};
use crate::disk::{StorageConfig, StorageMode};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn descriptor() -> TransferDescriptor {
    let mut descriptor = TransferDescriptor {
        schema_version: 1,
        protocol_version: CLUSTER_PROTOCOL_VERSION,
        transfer_id: TransferId([0; 32]),
        cluster_id: "cluster-a".to_owned(),
        from_epoch: 8,
        to_epoch: 9,
        source_node_id: "node-a".to_owned(),
        target_node_id: "node-b".to_owned(),
        ranges: vec![SlotRange {
            start: 0,
            end: CLUSTER_SLOT_COUNT - 1,
        }],
    };
    descriptor.transfer_id = descriptor.expected_id().unwrap();
    descriptor
}

fn execution() -> CompiledExecution {
    compiled_execution("cluster-a", Vec::new())
}

fn config(root: &Path) -> Arc<crate::ServerConfig> {
    let data = root.join("data");
    let storage = data.join("storage");
    std::fs::create_dir_all(&storage).unwrap();
    Arc::new(crate::ServerConfig {
        shards: 4,
        data_dir: data.to_string_lossy().into_owned(),
        storage: StorageConfig {
            mode: StorageMode::Tiered,
            dir: storage.to_string_lossy().into_owned(),
        },
        ..crate::ServerConfig::default()
    })
}

fn durable_set(store: &Store, key: &[u8], value: &[u8]) {
    store.wal_log_command(&[b"SET", key, value]).unwrap();
    store.set(key, value, None, Instant::now());
}

fn sealed_target(
    root: &Path,
) -> (
    TransferDescriptor,
    CompiledExecution,
    TransferReceipt,
    PathBuf,
    TransferJournal,
) {
    let descriptor = descriptor();
    let execution = execution();
    let source_store = Store::new();
    source_store.set(b"moved", b"transfer", None, Instant::now());
    let source_path = root.join("source.json");
    let target_path = root.join("target.json");
    let source = TransferJournal::open(
        TransferRole::Source,
        descriptor.clone(),
        &source_path,
        16 * 1024 * 1024,
    )
    .unwrap();
    let target = TransferJournal::open(
        TransferRole::Target,
        descriptor.clone(),
        &target_path,
        16 * 1024 * 1024,
    )
    .unwrap();
    source.begin_source_attempt().unwrap();
    let start = target.accept_target_attempt(1).unwrap();
    source.record_target_start(&start).unwrap();
    let runtime = TransferRuntime::new(
        "node-a",
        TransferRuntimeConfig {
            max_dirty_keys: 1_000,
            max_dirty_bytes: 128 * 1024 * 1024,
        },
    )
    .unwrap();
    runtime.install_source(descriptor.clone()).unwrap();
    let mut transfer =
        SourceStoreTransfer::begin(&source_store, &source, &descriptor, &execution, |chunk| {
            let (_, receipt) = target.append_target_chunk(chunk)?;
            Ok(receipt)
        })
        .unwrap();
    assert_eq!(transfer.write_initial().unwrap(), 1);
    let final_batch = runtime
        .fence_and_drain(descriptor.transfer_id, Duration::from_secs(2))
        .unwrap();
    let receipt = transfer
        .finish_and_fence(&runtime, 1, &final_batch)
        .unwrap();
    target.seal(&receipt).unwrap();
    (descriptor, execution, receipt, target_path, target)
}

fn reopen_target(path: &Path, descriptor: &TransferDescriptor) -> TransferJournal {
    TransferJournal::open(
        TransferRole::Target,
        descriptor.clone(),
        path,
        16 * 1024 * 1024,
    )
    .unwrap()
}

#[test]
fn checkpoint_boundary_waits_for_an_inflight_wal_mutation() {
    let root = tempfile::tempdir().unwrap();
    let (descriptor, execution, receipt, _target_path, target) = sealed_target(root.path());
    let store = Arc::new(Store::new_with_config(config(root.path())));
    let checkpoint_path = root.path().join("checkpoint.json");
    let (logged_tx, logged_rx) = std::sync::mpsc::channel();
    let (commit_tx, commit_rx) = std::sync::mpsc::channel();
    let writer = {
        let store = Arc::clone(&store);
        std::thread::spawn(move || {
            store.with_persistence_mutation(|| {
                store
                    .wal_log_command(&[b"SET", b"before-boundary", b"committed"])
                    .unwrap();
                logged_tx.send(()).unwrap();
                commit_rx.recv().unwrap();
                store.set(b"before-boundary", b"committed", None, Instant::now());
            });
        })
    };
    logged_rx.recv().unwrap();

    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (prepared_tx, prepared_rx) = std::sync::mpsc::channel();
    let prepare = {
        let store = Arc::clone(&store);
        std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let result = TargetCheckpoint::prepare(
                &store,
                &target,
                &descriptor,
                &execution,
                &receipt,
                checkpoint_path,
            )
            .map(|_| ())
            .map_err(|error| error.to_string());
            prepared_tx.send(result).unwrap();
        })
    };
    started_rx.recv().unwrap();
    assert!(
        prepared_rx.recv_timeout(Duration::from_millis(50)).is_err(),
        "checkpoint captured a boundary inside a WAL-backed mutation"
    );

    commit_tx.send(()).unwrap();
    writer.join().unwrap();
    prepared_rx
        .recv_timeout(Duration::from_secs(2))
        .unwrap()
        .unwrap();
    prepare.join().unwrap();
}

#[test]
fn armed_checkpoint_recovers_after_crash_before_apply() {
    let root = tempfile::tempdir().unwrap();
    let (descriptor, execution, receipt, target_path, target) = sealed_target(root.path());
    let store_config = config(root.path());
    let store = Store::new_with_config(Arc::clone(&store_config));
    durable_set(&store, b"moved", b"stale-before-cutover");
    let checkpoint_path = root.path().join("checkpoint.json");
    TargetCheckpoint::prepare(
        &store,
        &target,
        &descriptor,
        &execution,
        &receipt,
        &checkpoint_path,
    )
    .unwrap();
    drop(store);
    drop(target);

    let recovered = Store::new_with_config(store_config);
    crate::snapshot::load(&recovered).unwrap();
    let target = reopen_target(&target_path, &descriptor);
    let checkpoint =
        TargetCheckpoint::open(&descriptor, &execution, &receipt, &checkpoint_path).unwrap();
    checkpoint
        .recover_after_snapshot(&recovered, &target, &execution)
        .unwrap();

    assert_eq!(
        recovered.get(b"moved", Instant::now()).unwrap(),
        b"transfer"[..]
    );
    assert_eq!(target.snapshot().phase, TransferPhase::Ready);
}

#[test]
fn recovery_orders_wal_prefix_transfer_and_wal_suffix() {
    let root = tempfile::tempdir().unwrap();
    let (descriptor, execution, receipt, target_path, target) = sealed_target(root.path());
    let store_config = config(root.path());
    let store = Store::new_with_config(Arc::clone(&store_config));
    durable_set(&store, b"moved", b"stale-before-cutover");
    let checkpoint_path = root.path().join("checkpoint.json");
    let checkpoint = TargetCheckpoint::prepare(
        &store,
        &target,
        &descriptor,
        &execution,
        &receipt,
        &checkpoint_path,
    )
    .unwrap();
    checkpoint.apply(&store, &target, &execution).unwrap();
    target.mark_topology_committed(descriptor.to_epoch).unwrap();
    durable_set(&store, b"moved", b"committed-after-cutover");
    drop(checkpoint);
    drop(store);
    drop(target);

    let recovered = Store::new_with_config(store_config);
    crate::snapshot::load(&recovered).unwrap();
    let target = reopen_target(&target_path, &descriptor);
    let checkpoint =
        TargetCheckpoint::open(&descriptor, &execution, &receipt, &checkpoint_path).unwrap();
    checkpoint
        .recover_after_snapshot(&recovered, &target, &execution)
        .unwrap();

    assert_eq!(
        recovered.get(b"moved", Instant::now()).unwrap(),
        b"committed-after-cutover"[..]
    );
    assert_eq!(target.snapshot().phase, TransferPhase::Activated);
}

#[test]
fn applied_but_uncommitted_checkpoint_replays_idempotently() {
    let root = tempfile::tempdir().unwrap();
    let (descriptor, execution, receipt, target_path, target) = sealed_target(root.path());
    let store_config = config(root.path());
    let store = Store::new_with_config(Arc::clone(&store_config));
    durable_set(&store, b"moved", b"stale");
    let checkpoint_path = root.path().join("checkpoint.json");
    let checkpoint = TargetCheckpoint::prepare(
        &store,
        &target,
        &descriptor,
        &execution,
        &receipt,
        &checkpoint_path,
    )
    .unwrap();
    let disk = checkpoint.state.lock().clone();
    checkpoint
        .install_marker_and_data(&store, &target, &execution, &disk)
        .unwrap();
    assert_eq!(target.snapshot().phase, TransferPhase::Applied);
    drop(checkpoint);
    drop(store);
    drop(target);

    let recovered = Store::new_with_config(store_config);
    crate::snapshot::load(&recovered).unwrap();
    let target = reopen_target(&target_path, &descriptor);
    let checkpoint =
        TargetCheckpoint::open(&descriptor, &execution, &receipt, &checkpoint_path).unwrap();
    checkpoint
        .recover_after_snapshot(&recovered, &target, &execution)
        .unwrap();
    assert_eq!(target.snapshot().phase, TransferPhase::Ready);
    assert_eq!(
        recovered.get(b"moved", Instant::now()).unwrap(),
        b"transfer"[..]
    );
}

#[test]
fn ready_checkpoint_repairs_a_journal_crash_before_ready_transition() {
    let root = tempfile::tempdir().unwrap();
    let (descriptor, execution, receipt, target_path, target) = sealed_target(root.path());
    let store_config = config(root.path());
    let store = Store::new_with_config(Arc::clone(&store_config));
    let checkpoint_path = root.path().join("checkpoint.json");
    let checkpoint = TargetCheckpoint::prepare(
        &store,
        &target,
        &descriptor,
        &execution,
        &receipt,
        &checkpoint_path,
    )
    .unwrap();
    let disk = checkpoint.state.lock().clone();
    checkpoint
        .install_marker_and_data(&store, &target, &execution, &disk)
        .unwrap();
    let mut ready = disk;
    ready.phase = CheckpointPhase::Ready;
    persist(&checkpoint_path, &ready).unwrap();
    assert_eq!(target.snapshot().phase, TransferPhase::Applied);
    drop(checkpoint);
    drop(store);
    drop(target);

    let recovered = Store::new_with_config(store_config);
    crate::snapshot::load(&recovered).unwrap();
    let target = reopen_target(&target_path, &descriptor);
    let checkpoint =
        TargetCheckpoint::open(&descriptor, &execution, &receipt, &checkpoint_path).unwrap();
    checkpoint
        .recover_after_snapshot(&recovered, &target, &execution)
        .unwrap();
    assert_eq!(target.snapshot().phase, TransferPhase::Ready);
    assert_eq!(
        recovered.get(b"moved", Instant::now()).unwrap(),
        b"transfer"[..]
    );
}

#[test]
fn snapshot_marker_supersedes_old_boundaries_after_wal_truncation() {
    let root = tempfile::tempdir().unwrap();
    let (descriptor, execution, receipt, target_path, target) = sealed_target(root.path());
    let store_config = config(root.path());
    let store = Store::new_with_config(Arc::clone(&store_config));
    let checkpoint_path = root.path().join("checkpoint.json");
    let checkpoint = TargetCheckpoint::prepare(
        &store,
        &target,
        &descriptor,
        &execution,
        &receipt,
        &checkpoint_path,
    )
    .unwrap();
    checkpoint.apply(&store, &target, &execution).unwrap();
    crate::snapshot::save_and_truncate_wal_consistent(&store).unwrap();
    durable_set(&store, b"moved", b"after-snapshot");
    drop(checkpoint);
    drop(store);
    drop(target);

    let recovered = Store::new_with_config(store_config);
    crate::snapshot::load(&recovered).unwrap();
    let target = reopen_target(&target_path, &descriptor);
    let checkpoint =
        TargetCheckpoint::open(&descriptor, &execution, &receipt, &checkpoint_path).unwrap();
    checkpoint
        .recover_after_snapshot(&recovered, &target, &execution)
        .unwrap();
    assert_eq!(
        recovered.get(b"moved", Instant::now()).unwrap(),
        b"after-snapshot"[..]
    );
}

#[test]
fn replaced_wal_generation_fails_closed_without_a_snapshot_marker() {
    let root = tempfile::tempdir().unwrap();
    let (descriptor, execution, receipt, _target_path, target) = sealed_target(root.path());
    let store = Store::new_with_config(config(root.path()));
    durable_set(&store, b"moved", b"stale");
    let checkpoint_path = root.path().join("checkpoint.json");
    let checkpoint = TargetCheckpoint::prepare(
        &store,
        &target,
        &descriptor,
        &execution,
        &receipt,
        &checkpoint_path,
    )
    .unwrap();
    store.truncate_wal();

    assert!(checkpoint
        .recover_after_snapshot(&store, &target, &execution)
        .is_err());
    assert_eq!(target.snapshot().phase, TransferPhase::Sealed);
}

#[test]
fn tampered_checkpoint_proof_is_rejected_on_open() {
    let root = tempfile::tempdir().unwrap();
    let (descriptor, execution, receipt, _target_path, target) = sealed_target(root.path());
    let store = Store::new_with_config(config(root.path()));
    let checkpoint_path = root.path().join("checkpoint.json");
    let checkpoint = TargetCheckpoint::prepare(
        &store,
        &target,
        &descriptor,
        &execution,
        &receipt,
        &checkpoint_path,
    )
    .unwrap();
    let mut disk = checkpoint.state.lock().clone();
    disk.proof[0] ^= 0xff;
    persist(&checkpoint_path, &disk).unwrap();

    assert!(TargetCheckpoint::open(&descriptor, &execution, &receipt, &checkpoint_path).is_err());
}
