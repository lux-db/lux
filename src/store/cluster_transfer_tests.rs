use super::*;
use crate::cluster::test_support::{compiled_execution, execution_table};
use crate::cluster::transfer_record::{table_row_key, table_vector_key};
use crate::cluster::{
    CompiledExecution, SlotRange, TransferId, CLUSTER_PROTOCOL_VERSION, CLUSTER_SLOT_COUNT,
};

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

fn indexed_execution() -> CompiledExecution {
    compiled_execution(
        "cluster-a",
        vec![execution_table(
            "accounts",
            Some("id"),
            &[
                ("age", "int"),
                ("email", "str|unique"),
                ("embedding", "vector:2"),
                ("id", "str|pk|unique|notnull"),
                ("metadata", "json"),
            ],
            &[("metadata.level", "int")],
        )],
    )
}

fn indexed_row(
    primary_key: &str,
    email: &str,
    age: i64,
    level: i64,
    vector: [f32; 2],
    order_score: f64,
) -> TransferRecord {
    TransferRecord::UpsertTableRow {
        table: "accounts".to_owned(),
        primary_key: primary_key.as_bytes().to_vec(),
        order_score,
        value: DumpValue::Hash(
            vec![
                ("\0ttl".to_owned(), b"2000000000000".to_vec()),
                ("age".to_owned(), age.to_le_bytes().to_vec()),
                ("email".to_owned(), email.as_bytes().to_vec()),
                (
                    "embedding".to_owned(),
                    format!("[{},{}]", vector[0], vector[1]).into_bytes(),
                ),
                ("id".to_owned(), primary_key.as_bytes().to_vec()),
                (
                    "metadata".to_owned(),
                    crate::jsonb::encode(&serde_json::json!({ "level": level })),
                ),
            ],
            Vec::new(),
        ),
        expires_at_ms: None,
        vectors: vec![TableVectorRecord {
            field: "embedding".to_owned(),
            value: DumpValue::Vector(vector.to_vec(), None, false),
            expires_at_ms: None,
        }],
    }
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
    let execution = execution();
    let now = Instant::now();
    let binary_key = vec![0, 255, b'k'];
    let kv_identity = TransferDataKey::kv(binary_key.clone()).unwrap();
    let row_identity = TransferDataKey::table_row("accounts", b"user-1".to_vec()).unwrap();
    source.set(&binary_key, b"value", Some(Duration::from_secs(60)), now);
    source.load_entry_bytes(
        table_row_key("accounts", b"user-1").unwrap(),
        DumpValue::Hash(
            vec![
                ("id".to_owned(), b"user-1".to_vec()),
                ("name".to_owned(), b"Matty".to_vec()),
                ("embedding".to_owned(), b"[0.25,0.5]".to_vec()),
            ],
            Vec::new(),
        ),
        None,
    );
    source.load_entry_bytes(
        table_vector_key("accounts", "embedding", b"user-1").unwrap(),
        DumpValue::Vector(vec![0.25, 0.5], Some("profile".to_owned()), false),
        None,
    );
    source
        .zadd(
            b"_t:accounts:ids",
            &[(b"user-1", 42.0)],
            false,
            false,
            false,
            false,
            false,
            now,
        )
        .unwrap();

    let kv = source
        .transfer_record(&kv_identity, Instant::now())
        .unwrap();
    let row = source
        .transfer_record(&row_identity, Instant::now())
        .unwrap();
    target
        .apply_transfer_record(kv.clone(), &execution)
        .unwrap();
    target
        .apply_transfer_record(row.clone(), &execution)
        .unwrap();
    target.apply_transfer_record(kv, &execution).unwrap();
    target.apply_transfer_record(row, &execution).unwrap();

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
            &execution,
        )
        .unwrap();
    target
        .apply_transfer_record(
            source
                .transfer_record(&row_identity, Instant::now())
                .unwrap(),
            &execution,
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
    let execution = execution();
    target.set(b"key", b"stale", None, Instant::now());
    target
        .apply_transfer_record(
            TransferRecord::UpsertKv {
                key: b"key".to_vec(),
                value: DumpValue::Str(b"expired".to_vec()),
                expires_at_ms: Some(1),
            },
            &execution,
        )
        .unwrap();
    assert!(target.get(b"key", Instant::now()).is_none());
}

#[test]
fn expired_table_state_is_filtered_or_deleted_before_it_can_move() {
    let source = Store::new();
    let target = Store::new();
    let execution = execution();
    let identity = TransferDataKey::table_row("accounts", b"user-1".to_vec()).unwrap();
    let now = Instant::now();
    source.load_entry_bytes(
        table_row_key("accounts", b"user-1").unwrap(),
        DumpValue::Hash(
            vec![
                ("id".to_owned(), b"user-1".to_vec()),
                ("name".to_owned(), b"expired".to_vec()),
            ],
            vec![("name".to_owned(), 1)],
        ),
        None,
    );
    source
        .zadd(
            b"_t:accounts:ids",
            &[(b"user-1", 1.0)],
            false,
            false,
            false,
            false,
            false,
            now,
        )
        .unwrap();
    let record = source.transfer_record(&identity, now).unwrap();
    let TransferRecord::UpsertTableRow { value, .. } = record else {
        panic!("live row should produce an upsert");
    };
    let DumpValue::Hash(fields, expiries) = value else {
        panic!("table row should remain a hash");
    };
    assert!(!fields.iter().any(|(field, _)| field == "name"));
    assert!(expiries.is_empty());

    target
        .apply_transfer_record(
            TransferRecord::UpsertTableRow {
                table: "accounts".to_owned(),
                primary_key: b"user-1".to_vec(),
                order_score: 1.0,
                value: DumpValue::Hash(
                    vec![
                        ("id".to_owned(), b"user-1".to_vec()),
                        ("name".to_owned(), b"old".to_vec()),
                    ],
                    Vec::new(),
                ),
                expires_at_ms: None,
                vectors: Vec::new(),
            },
            &execution,
        )
        .unwrap();
    target
        .apply_transfer_record(
            TransferRecord::UpsertTableRow {
                table: "accounts".to_owned(),
                primary_key: b"user-1".to_vec(),
                order_score: 1.0,
                value: DumpValue::Hash(
                    vec![
                        ("\0ttl".to_owned(), b"1".to_vec()),
                        ("id".to_owned(), b"user-1".to_vec()),
                    ],
                    Vec::new(),
                ),
                expires_at_ms: None,
                vectors: Vec::new(),
            },
            &execution,
        )
        .unwrap();
    assert!(target
        .hgetall(
            &table_row_key("accounts", b"user-1").unwrap(),
            Instant::now(),
        )
        .unwrap()
        .is_empty());
    assert_eq!(
        target
            .zscore(b"_t:accounts:ids", b"user-1", Instant::now())
            .unwrap(),
        None
    );
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

#[test]
fn transferred_rows_rebuild_signed_metadata_without_touching_other_ranges() {
    let store = Store::new();
    let execution = indexed_execution();
    let moved = "user-moved";
    let moved_slot = TransferDataKey::table_row("accounts", moved.as_bytes().to_vec())
        .unwrap()
        .slot();
    let retained = (0_u64..)
        .map(|index| format!("user-retained-{index}"))
        .find(|primary_key| {
            TransferDataKey::table_row("accounts", primary_key.as_bytes().to_vec())
                .unwrap()
                .slot()
                != moved_slot
        })
        .unwrap();

    store
        .apply_transfer_record(
            indexed_row(moved, "old@example.com", 10, 1, [0.1, 0.2], 7.0),
            &execution,
        )
        .unwrap();
    store
        .apply_transfer_record(
            indexed_row(&retained, "retained@example.com", 20, 2, [0.3, 0.4], 8.0),
            &execution,
        )
        .unwrap();

    assert!(store
        .apply_transfer_record(
            indexed_row(moved, "retained@example.com", 30, 3, [0.8, 0.9], 42.0,),
            &execution,
        )
        .is_err());
    assert_eq!(
        store
            .hget(
                &table_row_key("accounts", moved.as_bytes()).unwrap(),
                b"email",
                Instant::now(),
            )
            .as_deref(),
        Some(b"old@example.com".as_slice())
    );

    let mut narrow = descriptor();
    narrow.ranges = vec![SlotRange {
        start: moved_slot,
        end: moved_slot,
    }];
    narrow.transfer_id = narrow.expected_id().unwrap();
    assert_eq!(store.clear_transfer_ranges(&narrow, &execution).unwrap(), 1);
    let now = Instant::now();
    assert!(store
        .hgetall(&table_row_key("accounts", moved.as_bytes()).unwrap(), now)
        .unwrap()
        .is_empty());
    assert!(store
        .hgetall(
            &table_row_key("accounts", retained.as_bytes()).unwrap(),
            now,
        )
        .unwrap()
        .iter()
        .any(|(field, _)| field == "email"));
    assert!(!store
        .smembers(b"_t:accounts:idx:email:old@example.com", now)
        .unwrap()
        .iter()
        .any(|member| member == moved));
    assert!(store
        .smembers(b"_t:accounts:idx:email:retained@example.com", now)
        .unwrap()
        .iter()
        .any(|member| member == &retained));

    store
        .apply_transfer_record(
            indexed_row(moved, "new@example.com", 30, 3, [0.8, 0.9], 42.0),
            &execution,
        )
        .unwrap();
    let now = Instant::now();
    assert_eq!(
        store
            .zscore(b"_t:accounts:ids", moved.as_bytes(), now)
            .unwrap(),
        Some(42.0)
    );
    assert_eq!(
        store
            .zscore(b"_t:accounts:idx:age", moved.as_bytes(), now)
            .unwrap(),
        Some(30.0)
    );
    assert_eq!(
        store
            .zscore(b"_t:accounts:idx:metadata.level", moved.as_bytes(), now)
            .unwrap(),
        Some(3.0)
    );
    assert!(store
        .smembers(b"_t:accounts:idx:email:new@example.com", now)
        .unwrap()
        .iter()
        .any(|member| member == moved));
    assert_eq!(
        store
            .hget(b"_t:accounts:uniq:email", b"new@example.com", now)
            .as_deref(),
        Some(moved.as_bytes())
    );
    assert_eq!(
        store
            .zscore(b"_t:_ttl", b"accounts\0user-moved", now)
            .unwrap(),
        Some(2_000_000_000_000.0)
    );
    assert_eq!(
        store
            .vget(
                &table_vector_key("accounts", "embedding", moved.as_bytes()).unwrap(),
                now,
            )
            .unwrap()
            .0,
        vec![0.8, 0.9]
    );
}
