use super::*;
use crate::cluster::transfer_record::{table_row_key, table_vector_key};
use crate::cluster::{SlotRange, TransferId, CLUSTER_PROTOCOL_VERSION, CLUSTER_SLOT_COUNT};

fn descriptor() -> TransferDescriptor {
    let mut descriptor = TransferDescriptor {
        schema_version: 1,
        protocol_version: CLUSTER_PROTOCOL_VERSION,
        transfer_id: TransferId([0; 32]),
        cluster_id: "cluster-a".to_owned(),
        from_epoch: 20,
        to_epoch: 21,
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

fn identities(store: &Store, descriptor: &TransferDescriptor) -> Vec<TransferDataKey> {
    let now = Instant::now();
    let mut identities = Vec::new();
    for shard in 0..store.shard_count() {
        identities.extend(
            store
                .transfer_identities_for_shard(shard, descriptor, now)
                .unwrap(),
        );
    }
    identities.sort_unstable();
    identities.dedup();
    identities
}

#[test]
fn snapshot_identity_scan_is_binary_safe_and_collapses_table_sidecars() {
    let store = Store::new();
    let descriptor = descriptor();
    let now = Instant::now();
    let binary_key = vec![0, 255, b'k'];
    store.set(&binary_key, b"value", None, now);
    store.load_entry_bytes(
        table_row_key("accounts", b"user-1").unwrap(),
        DumpValue::Hash(vec![("name".to_owned(), b"Matty".to_vec())], Vec::new()),
        None,
    );
    store.load_entry_bytes(
        table_vector_key("accounts", "embedding", b"user-1").unwrap(),
        DumpValue::Vector(vec![0.25, 0.5], None, false),
        None,
    );
    store.set(b"_t:accounts:schema", b"replicated", None, now);

    assert_eq!(
        identities(&store, &descriptor),
        vec![
            TransferDataKey::kv(binary_key).unwrap(),
            TransferDataKey::table_row("accounts", b"user-1".to_vec()).unwrap(),
        ]
    );
}

#[test]
fn kv_and_table_records_apply_idempotently_with_ttls_and_vectors() {
    let source = Store::new();
    let target = Store::new();
    let now = Instant::now();
    let binary_key = vec![0, 255, b'k'];
    let kv_identity = TransferDataKey::kv(binary_key.clone()).unwrap();
    let row_identity = TransferDataKey::table_row("accounts", b"user-1".to_vec()).unwrap();
    source.set(&binary_key, b"value", Some(Duration::from_secs(60)), now);
    source.load_entry_bytes(
        table_row_key("accounts", b"user-1").unwrap(),
        DumpValue::Hash(vec![("name".to_owned(), b"Matty".to_vec())], Vec::new()),
        None,
    );
    source.load_entry_bytes(
        table_vector_key("accounts", "embedding", b"user-1").unwrap(),
        DumpValue::Vector(vec![0.25, 0.5], Some("profile".to_owned()), false),
        None,
    );

    let kv = source
        .transfer_record(&kv_identity, Instant::now())
        .unwrap();
    let row = source
        .transfer_record(&row_identity, Instant::now())
        .unwrap();
    target.apply_transfer_record(kv.clone()).unwrap();
    target.apply_transfer_record(row.clone()).unwrap();
    target.apply_transfer_record(kv).unwrap();
    target.apply_transfer_record(row).unwrap();

    assert_eq!(
        target.get(&binary_key, Instant::now()).unwrap(),
        b"value"[..]
    );
    assert_eq!(
        target
            .hget(
                &table_row_key("accounts", b"user-1").unwrap(),
                b"name",
                Instant::now(),
            )
            .unwrap(),
        b"Matty"[..]
    );
    assert_eq!(
        target
            .vget(
                &table_vector_key("accounts", "embedding", b"user-1").unwrap(),
                Instant::now(),
            )
            .unwrap(),
        (vec![0.25, 0.5], Some("profile".to_owned()))
    );

    source.del(&[binary_key.as_slice()]);
    source.del(&[table_row_key("accounts", b"user-1").unwrap().as_slice()]);
    source.del(&[table_vector_key("accounts", "embedding", b"user-1")
        .unwrap()
        .as_slice()]);
    target
        .apply_transfer_record(
            source
                .transfer_record(&kv_identity, Instant::now())
                .unwrap(),
        )
        .unwrap();
    target
        .apply_transfer_record(
            source
                .transfer_record(&row_identity, Instant::now())
                .unwrap(),
        )
        .unwrap();
    assert!(target.get(&binary_key, Instant::now()).is_none());
    assert!(target
        .hgetall(
            &table_row_key("accounts", b"user-1").unwrap(),
            Instant::now()
        )
        .unwrap()
        .is_empty());
    assert!(target
        .vget(
            &table_vector_key("accounts", "embedding", b"user-1").unwrap(),
            Instant::now()
        )
        .is_none());
}

#[test]
fn expired_upserts_delete_stale_target_values() {
    let target = Store::new();
    target.set(b"key", b"stale", None, Instant::now());
    target
        .apply_transfer_record(TransferRecord::UpsertKv {
            key: b"key".to_vec(),
            value: DumpValue::Str(b"expired".to_vec()),
            expires_at_ms: Some(1),
        })
        .unwrap();
    assert!(target.get(b"key", Instant::now()).is_none());
}

#[test]
fn replacement_load_keeps_memory_and_vector_indexes_consistent() {
    let store = Store::new();
    let key = b"vector".to_vec();
    store.load_entry_bytes(
        key.clone(),
        DumpValue::Vector(vec![1.0, 2.0], None, false),
        None,
    );
    let vector_memory = store.approximate_memory();
    assert!(store.vget(&key, Instant::now()).is_some());

    store.load_entry_bytes(key.clone(), DumpValue::Str(b"x".to_vec()), None);
    assert!(store.vget(&key, Instant::now()).is_none());
    assert!(store.approximate_memory() < vector_memory);
    assert!(store
        .vsearch(&[1.0, 2.0], 10, None, None, Instant::now())
        .is_empty());
}
