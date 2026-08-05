use super::*;
use crate::cluster::test_support::{compiled_execution, execution_table};
use crate::cluster::transfer_record::{table_row_key, table_vector_key, TransferRecordWriter};
use crate::cluster::transfer_stream::TransferChunkWriter;
use crate::cluster::{
    SlotRange, TransferId, TransferRole, TransferRuntime, TransferRuntimeConfig,
    TransferWriteAdmission, CLUSTER_PROTOCOL_VERSION, CLUSTER_SLOT_COUNT,
};
use crate::store::DumpValue;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

fn execution() -> CompiledExecution {
    compiled_execution(
        "cluster-a",
        vec![execution_table(
            "accounts",
            Some("id"),
            &[
                ("embedding", "vector:2"),
                ("id", "str|pk|unique|notnull"),
                ("name", "str"),
            ],
            &[],
        )],
    )
}

fn descriptor() -> TransferDescriptor {
    let mut descriptor = TransferDescriptor {
        schema_version: 1,
        protocol_version: CLUSTER_PROTOCOL_VERSION,
        transfer_id: TransferId([0; 32]),
        cluster_id: "cluster-a".to_owned(),
        from_epoch: 40,
        to_epoch: 41,
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

#[test]
fn fuzzy_snapshot_plus_dirty_round_converges_target_to_source() {
    let descriptor = descriptor();
    let execution = execution();
    let source_store = Store::new();
    let target_store = Store::new();
    let now = Instant::now();
    source_store.set(b"account:a", b"old", None, now);
    source_store.set(b"account:deleted", b"old", None, now);
    source_store.load_entry_bytes(
        table_row_key("accounts", b"user-1").unwrap(),
        DumpValue::Hash(
            vec![
                ("embedding".to_owned(), b"[0.1,0.2]".to_vec()),
                ("id".to_owned(), b"user-1".to_vec()),
                ("name".to_owned(), b"Old".to_vec()),
            ],
            Vec::new(),
        ),
        None,
    );
    source_store
        .zadd(
            b"_t:accounts:ids",
            &[(b"user-1", 11.0)],
            false,
            false,
            false,
            false,
            false,
            now,
        )
        .unwrap();
    source_store.load_entry_bytes(
        table_vector_key("accounts", "embedding", b"user-1").unwrap(),
        DumpValue::Vector(vec![0.1, 0.2], None, false),
        None,
    );
    target_store.set(b"target-only", b"stale", None, now);
    target_store.load_entry_bytes(
        table_row_key("accounts", b"stale-user").unwrap(),
        DumpValue::Hash(
            vec![
                ("embedding".to_owned(), b"[0.0,0.0]".to_vec()),
                ("id".to_owned(), b"stale-user".to_vec()),
                ("name".to_owned(), b"Stale".to_vec()),
            ],
            Vec::new(),
        ),
        None,
    );
    target_store
        .zadd(
            b"_t:accounts:ids",
            &[(b"stale-user", 99.0)],
            false,
            false,
            false,
            false,
            false,
            now,
        )
        .unwrap();
    target_store.load_entry_bytes(
        table_vector_key("accounts", "embedding", b"stale-user").unwrap(),
        DumpValue::Vector(vec![0.0, 0.0], None, false),
        None,
    );
    target_store.set(b"_t:accounts:schema", b"replicated", None, now);

    let directory = tempfile::tempdir().unwrap();
    let source = TransferJournal::open(
        TransferRole::Source,
        descriptor.clone(),
        directory.path().join("source.json"),
        32 * 1024 * 1024,
    )
    .unwrap();
    let target = TransferJournal::open(
        TransferRole::Target,
        descriptor.clone(),
        directory.path().join("target.json"),
        32 * 1024 * 1024,
    )
    .unwrap();
    source.begin_source_attempt().unwrap();
    let start = target.accept_target_attempt(1).unwrap();
    source.record_target_start(&start).unwrap();

    let chunks = TransferChunkWriter::new(&source, 0, |chunk| {
        let (_, receipt) = target.append_target_chunk(chunk)?;
        Ok(receipt)
    });
    let mut records =
        TransferRecordWriter::new(chunks, &source_store, &descriptor, &execution).unwrap();
    assert_eq!(
        write_initial_store_records(&source_store, &descriptor, &mut records).unwrap(),
        3
    );
    records.flush().unwrap();

    source_store.set(b"account:a", b"new", None, Instant::now());
    source_store.set(b"account:b", b"created", None, Instant::now());
    source_store.del(&[b"account:deleted"]);
    source_store.load_entry_bytes(
        table_row_key("accounts", b"user-1").unwrap(),
        DumpValue::Hash(
            vec![
                ("embedding".to_owned(), b"[0.8,0.9]".to_vec()),
                ("id".to_owned(), b"user-1".to_vec()),
                ("name".to_owned(), b"New".to_vec()),
            ],
            Vec::new(),
        ),
        None,
    );
    source_store.load_entry_bytes(
        table_vector_key("accounts", "embedding", b"user-1").unwrap(),
        DumpValue::Vector(vec![0.8, 0.9], None, false),
        None,
    );
    records.inner_mut().begin_round(1).unwrap();
    let dirty = vec![
        TransferDataKey::kv(b"account:a".to_vec()).unwrap(),
        TransferDataKey::kv(b"account:b".to_vec()).unwrap(),
        TransferDataKey::kv(b"account:deleted".to_vec()).unwrap(),
        TransferDataKey::table_row("accounts", b"user-1".to_vec()).unwrap(),
    ];
    assert_eq!(
        write_dirty_store_records(&source_store, &dirty, &mut records).unwrap(),
        4
    );
    let chunks = records.finish().unwrap();
    let receipt = chunks.finish().unwrap();
    source.mark_source_fenced(&receipt).unwrap();
    source.seal(&receipt).unwrap();
    target.seal(&receipt).unwrap();

    let mut wrong_receipt = receipt.clone();
    wrong_receipt.next_sequence += 1;
    assert!(apply_target_store_transfer(
        &target_store,
        &descriptor,
        &execution,
        &target,
        &wrong_receipt,
    )
    .is_err());
    assert_eq!(
        target_store.get(b"target-only", Instant::now()).unwrap(),
        b"stale"[..]
    );
    assert_eq!(
        apply_target_store_transfer(&target_store, &descriptor, &execution, &target, &receipt,)
            .unwrap(),
        7
    );
    assert_eq!(
        apply_target_store_transfer(&target_store, &descriptor, &execution, &target, &receipt,)
            .unwrap(),
        7
    );
    assert_eq!(
        target.snapshot().phase,
        super::super::TransferPhase::Applied
    );
    assert_eq!(
        target_store.get(b"account:a", Instant::now()).unwrap(),
        b"new"[..]
    );
    assert_eq!(
        target_store.get(b"account:b", Instant::now()).unwrap(),
        b"created"[..]
    );
    assert!(target_store
        .get(b"account:deleted", Instant::now())
        .is_none());
    assert!(target_store.get(b"target-only", Instant::now()).is_none());
    assert!(target_store
        .hgetall(
            &table_row_key("accounts", b"stale-user").unwrap(),
            Instant::now(),
        )
        .unwrap()
        .is_empty());
    assert_eq!(
        target_store
            .get(b"_t:accounts:schema", Instant::now())
            .unwrap(),
        b"replicated"[..]
    );
    assert_eq!(
        target_store
            .hget(
                &table_row_key("accounts", b"user-1").unwrap(),
                b"name",
                Instant::now(),
            )
            .unwrap(),
        b"New"[..]
    );
    assert_eq!(
        target_store
            .vget(
                &table_vector_key("accounts", "embedding", b"user-1").unwrap(),
                Instant::now(),
            )
            .unwrap()
            .0,
        vec![0.8, 0.9]
    );

    source.mark_topology_committed(descriptor.to_epoch).unwrap();
    assert!(target.mark_topology_committed(descriptor.to_epoch).is_err());
    let proof = crate::cluster::TargetReadyProof::for_test(receipt.transfer_id);
    target.mark_target_ready(&receipt, &proof).unwrap();
    target.mark_topology_committed(descriptor.to_epoch).unwrap();
    target_store.set(b"account:a", b"post-activation", None, Instant::now());
    assert!(
        apply_target_store_transfer(&target_store, &descriptor, &execution, &target, &receipt,)
            .is_err()
    );
    assert_eq!(
        target.snapshot().phase,
        super::super::TransferPhase::Activated
    );
    assert_eq!(
        target_store.get(b"account:a", Instant::now()).unwrap(),
        b"post-activation"[..]
    );
}

#[test]
fn concurrent_admitted_writes_converge_through_the_final_fence() {
    let descriptor = descriptor();
    let execution = execution();
    let source_store = Arc::new(Store::new());
    let target_store = Store::new();
    for index in 0..100 {
        source_store.set(
            format!("key:{index}").as_bytes(),
            b"initial",
            None,
            Instant::now(),
        );
    }
    let runtime = Arc::new(
        TransferRuntime::new(
            "node-a",
            TransferRuntimeConfig {
                max_dirty_keys: 100_000,
                max_dirty_bytes: 128 * 1024 * 1024,
            },
        )
        .unwrap(),
    );
    runtime.install_source(descriptor.clone()).unwrap();

    let directory = tempfile::tempdir().unwrap();
    let source = TransferJournal::open(
        TransferRole::Source,
        descriptor.clone(),
        directory.path().join("source.json"),
        64 * 1024 * 1024,
    )
    .unwrap();
    let target = TransferJournal::open(
        TransferRole::Target,
        descriptor.clone(),
        directory.path().join("target.json"),
        64 * 1024 * 1024,
    )
    .unwrap();
    source.begin_source_attempt().unwrap();
    let start = target.accept_target_attempt(1).unwrap();
    source.record_target_start(&start).unwrap();

    let started = Arc::new(Barrier::new(2));
    let committed = Arc::new(AtomicUsize::new(0));
    let writer_store = Arc::clone(&source_store);
    let writer_runtime = Arc::clone(&runtime);
    let writer_started = Arc::clone(&started);
    let writer_committed = Arc::clone(&committed);
    let writer = thread::spawn(move || {
        writer_started.wait();
        for operation in 0..50_000_usize {
            let key = format!("key:{}", operation % 100);
            match writer_runtime.begin_kv_write(key.as_bytes()).unwrap() {
                TransferWriteAdmission::Admitted(guard) => {
                    writer_store.set(
                        key.as_bytes(),
                        operation.to_string().as_bytes(),
                        None,
                        Instant::now(),
                    );
                    drop(guard);
                    writer_committed.fetch_add(1, Ordering::Relaxed);
                }
                TransferWriteAdmission::Fenced(_) => break,
                _ => panic!("moved key bypassed source transfer admission"),
            }
        }
    });

    let mut transfer =
        SourceStoreTransfer::begin(&source_store, &source, &descriptor, &execution, |chunk| {
            let (_, receipt) = target.append_target_chunk(chunk)?;
            Ok(receipt)
        })
        .unwrap();
    started.wait();
    transfer.write_initial().unwrap();
    for round in 1..=3 {
        let dirty = runtime.drain_dirty(descriptor.transfer_id).unwrap();
        transfer.write_dirty_round(round, &dirty).unwrap();
        thread::yield_now();
    }
    let final_dirty = runtime
        .fence_and_drain(descriptor.transfer_id, Duration::from_secs(5))
        .unwrap();
    let receipt = transfer
        .finish_and_fence(&runtime, 4, &final_dirty)
        .unwrap();
    assert_eq!(source.snapshot().phase, super::super::TransferPhase::Sealed);
    target.seal(&receipt).unwrap();
    writer.join().unwrap();
    assert!(committed.load(Ordering::Relaxed) > 0);

    apply_target_store_transfer(&target_store, &descriptor, &execution, &target, &receipt).unwrap();
    for index in 0..100 {
        let key = format!("key:{index}");
        assert_eq!(
            target_store.get(key.as_bytes(), Instant::now()),
            source_store.get(key.as_bytes(), Instant::now()),
            "target diverged for {key}"
        );
    }
}

#[test]
fn high_level_source_stream_requires_fresh_acknowledged_attempt_and_strict_rounds() {
    let descriptor = descriptor();
    let execution = execution();
    let store = Store::new();
    let runtime = TransferRuntime::new(
        "node-a",
        TransferRuntimeConfig {
            max_dirty_keys: 1_000,
            max_dirty_bytes: 128 * 1024 * 1024,
        },
    )
    .unwrap();
    runtime.install_source(descriptor.clone()).unwrap();
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
    assert!(
        SourceStoreTransfer::begin(&store, &source, &descriptor, &execution, |_| {
            Err(ClusterError::Transport("must not send".to_owned()))
        })
        .is_err()
    );

    let start = target.accept_target_attempt(1).unwrap();
    source.record_target_start(&start).unwrap();
    let mut transfer =
        SourceStoreTransfer::begin(&store, &source, &descriptor, &execution, |chunk| {
            let (_, receipt) = target.append_target_chunk(chunk)?;
            Ok(receipt)
        })
        .unwrap();
    assert!(transfer.write_dirty_round(1, &[]).is_err());
    assert_eq!(transfer.write_initial().unwrap(), 0);
    assert_eq!(transfer.write_dirty_round(1, &[]).unwrap(), 0);
    assert!(transfer.write_dirty_round(1, &[]).is_err());
    assert_eq!(transfer.write_dirty_round(2, &[]).unwrap(), 0);
    assert!(
        SourceStoreTransfer::begin(&store, &source, &descriptor, &execution, |_| {
            Err(ClusterError::Transport("must not send".to_owned()))
        })
        .is_err()
    );

    let final_batch = runtime
        .fence_and_drain(descriptor.transfer_id, Duration::from_secs(2))
        .unwrap();
    let receipt = transfer
        .finish_and_fence(&runtime, 3, &final_batch)
        .unwrap();
    target.seal(&receipt).unwrap();
    assert_eq!(source.snapshot().phase, super::super::TransferPhase::Sealed);
}
