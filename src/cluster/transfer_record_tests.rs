use super::*;
use crate::cluster::{SlotRange, TransferId, CLUSTER_PROTOCOL_VERSION, CLUSTER_SLOT_COUNT};

fn descriptor() -> TransferDescriptor {
    let mut descriptor = TransferDescriptor {
        schema_version: 1,
        protocol_version: CLUSTER_PROTOCOL_VERSION,
        transfer_id: TransferId([0; 32]),
        cluster_id: "cluster-a".to_owned(),
        from_epoch: 10,
        to_epoch: 11,
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

fn values() -> Vec<DumpValue> {
    let registers = vec![0_u8; 16_384];
    vec![
        DumpValue::Str(vec![0, 255, b'v']),
        DumpValue::List(vec![b"one".to_vec(), b"two".to_vec()]),
        DumpValue::Hash(
            vec![("field".to_owned(), b"value".to_vec())],
            vec![("field".to_owned(), 2_000_000_000_000)],
        ),
        DumpValue::Set(vec!["a".to_owned(), "b".to_owned()]),
        DumpValue::SortedSet(vec![("a".to_owned(), 1.5), ("b".to_owned(), -2.0)]),
        DumpValue::Stream(
            vec![(
                "1-0".to_owned(),
                vec![("field".to_owned(), b"value".to_vec())],
            )],
            "1-0".to_owned(),
            vec![],
        ),
        DumpValue::Vector(vec![1.0, 2.0, 3.0], Some("meta".to_owned()), false),
        DumpValue::HyperLogLog(registers.clone(), crate::hll::hll_count(&registers)),
        DumpValue::TimeSeries(
            vec![(10, 1.5), (20, 2.5)],
            60_000,
            vec![("region".to_owned(), "east".to_owned())],
        ),
    ]
}

#[test]
fn record_stream_round_trips_every_store_value_and_table_sidecars() {
    let descriptor = descriptor();
    let store = Store::new();
    let mut records = values()
        .into_iter()
        .enumerate()
        .map(|(index, value)| TransferRecord::UpsertKv {
            key: vec![0, 255, index as u8],
            value,
            expires_at_ms: (index == 0).then_some(2_000_000_000_000),
        })
        .collect::<Vec<_>>();
    records.push(TransferRecord::Delete(
        TransferDataKey::kv(b"deleted".to_vec()).unwrap(),
    ));
    records.push(TransferRecord::UpsertTableRow {
        table: "accounts".to_owned(),
        primary_key: b"user-1".to_vec(),
        value: DumpValue::Hash(vec![("name".to_owned(), b"Matty".to_vec())], Vec::new()),
        expires_at_ms: None,
        vectors: vec![TableVectorRecord {
            field: "embedding".to_owned(),
            value: DumpValue::Vector(vec![0.25, 0.5], None, false),
            expires_at_ms: None,
        }],
    });
    records.push(TransferRecord::Delete(
        TransferDataKey::table_row("sessions", b"expired".to_vec()).unwrap(),
    ));

    let mut writer = TransferRecordWriter::new(Vec::new(), &store, &descriptor).unwrap();
    for record in &records {
        writer.write_record(record).unwrap();
    }
    let encoded = writer.finish().unwrap();

    let mut reader = TransferRecordReader::new(encoded.as_slice(), &store, &descriptor).unwrap();
    let mut decoded = Vec::new();
    while let Some(record) = reader.next_record().unwrap() {
        decoded.push(record);
    }
    assert_eq!(decoded, records);
    assert!(reader.next_record().unwrap().is_none());
}

#[test]
fn stream_identity_completion_and_bounds_fail_closed() {
    let descriptor = descriptor();
    let store = Store::new();
    let record = TransferRecord::UpsertKv {
        key: b"key".to_vec(),
        value: DumpValue::Str(b"value".to_vec()),
        expires_at_ms: None,
    };
    let mut writer = TransferRecordWriter::new(Vec::new(), &store, &descriptor).unwrap();
    writer.write_record(&record).unwrap();
    let encoded = writer.finish().unwrap();

    let mut truncated = encoded.clone();
    truncated.truncate(truncated.len() - 9);
    let mut reader = TransferRecordReader::new(truncated.as_slice(), &store, &descriptor).unwrap();
    assert_eq!(reader.next_record().unwrap(), Some(record.clone()));
    assert!(reader.next_record().is_err());

    let mut trailing = encoded.clone();
    trailing.push(1);
    let mut reader = TransferRecordReader::new(trailing.as_slice(), &store, &descriptor).unwrap();
    assert!(reader.next_record().unwrap().is_some());
    assert!(reader.next_record().is_err());

    let mut other = descriptor.clone();
    other.to_epoch += 1;
    other.from_epoch += 1;
    other.transfer_id = other.expected_id().unwrap();
    assert!(TransferRecordReader::new(encoded.as_slice(), &store, &other).is_err());
}

#[test]
fn invalid_table_shapes_and_records_outside_the_move_are_rejected() {
    let store = Store::new();
    let descriptor = descriptor();
    let mut writer = TransferRecordWriter::new(Vec::new(), &store, &descriptor).unwrap();
    assert!(writer
        .write_record(&TransferRecord::UpsertTableRow {
            table: "accounts".to_owned(),
            primary_key: b"user-1".to_vec(),
            value: DumpValue::Str(b"not-a-row".to_vec()),
            expires_at_ms: None,
            vectors: Vec::new(),
        })
        .is_err());
    assert!(writer
        .write_record(&TransferRecord::UpsertTableRow {
            table: "accounts".to_owned(),
            primary_key: b"user-1".to_vec(),
            value: DumpValue::Hash(Vec::new(), Vec::new()),
            expires_at_ms: None,
            vectors: vec![
                TableVectorRecord {
                    field: "embedding".to_owned(),
                    value: DumpValue::Vector(vec![1.0], None, false),
                    expires_at_ms: None,
                },
                TableVectorRecord {
                    field: "embedding".to_owned(),
                    value: DumpValue::Vector(vec![2.0], None, false),
                    expires_at_ms: None,
                },
            ],
        })
        .is_err());

    let mut narrow = descriptor;
    narrow.ranges = vec![SlotRange { start: 0, end: 0 }];
    narrow.transfer_id = narrow.expected_id().unwrap();
    let key = (0_u64..)
        .map(|index| format!("outside-{index}").into_bytes())
        .find(|key| TransferDataKey::kv(key.clone()).unwrap().slot() != 0)
        .unwrap();
    let mut writer = TransferRecordWriter::new(Vec::new(), &store, &narrow).unwrap();
    assert!(writer
        .write_record(&TransferRecord::Delete(TransferDataKey::kv(key).unwrap()))
        .is_err());
}
