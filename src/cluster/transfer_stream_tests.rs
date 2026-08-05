use super::*;
use crate::cluster::test_support::compiled_execution;
use crate::cluster::transfer_record::{TransferRecord, TransferRecordReader, TransferRecordWriter};
use crate::cluster::{
    SlotRange, TransferDescriptor, TransferId, TransferRole, CLUSTER_PROTOCOL_VERSION,
    CLUSTER_SLOT_COUNT,
};
use crate::store::{DumpValue, Store};

fn descriptor() -> TransferDescriptor {
    let mut descriptor = TransferDescriptor {
        schema_version: 1,
        protocol_version: CLUSTER_PROTOCOL_VERSION,
        transfer_id: TransferId([0; 32]),
        cluster_id: "cluster-a".to_owned(),
        from_epoch: 30,
        to_epoch: 31,
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
fn records_stream_across_chunks_rounds_and_a_lost_receipt() {
    let directory = tempfile::tempdir().unwrap();
    let descriptor = descriptor();
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
    let store = Store::new();
    let execution = compiled_execution("cluster-a", Vec::new());
    let mut lose_first_receipt = true;
    let chunks = TransferChunkWriter::new(&source, 0, |chunk| {
        let (_, receipt) = target.append_target_chunk(chunk)?;
        if lose_first_receipt {
            lose_first_receipt = false;
            return Err(ClusterError::Transport("simulated lost receipt".to_owned()));
        }
        Ok(receipt)
    });
    let mut records = TransferRecordWriter::new(chunks, &store, &descriptor, &execution).unwrap();
    let small = TransferRecord::UpsertKv {
        key: b"small".to_vec(),
        value: DumpValue::Str(b"value".to_vec()),
        expires_at_ms: None,
    };
    records.write_record(&small).unwrap();
    assert!(records.flush().is_err());
    records.flush().unwrap();
    let large = TransferRecord::UpsertKv {
        key: b"large".to_vec(),
        value: DumpValue::Str(vec![7; MAX_TRANSFER_CHUNK_BYTES + 1_024]),
        expires_at_ms: None,
    };
    records.write_record(&large).unwrap();
    records.flush().unwrap();
    records.inner_mut().begin_round(1).unwrap();
    let deleted =
        TransferRecord::Delete(crate::cluster::TransferDataKey::kv(b"deleted".to_vec()).unwrap());
    records.write_record(&deleted).unwrap();
    let chunks = records.finish().unwrap();
    let receipt = chunks.finish().unwrap();
    source.mark_source_fenced(&receipt).unwrap();
    assert!(target.open_target_reader().is_err());
    source.seal(&receipt).unwrap();
    target.seal(&receipt).unwrap();

    let stage = target.open_target_reader().unwrap();
    let mut reader = TransferRecordReader::new(stage, &store, &descriptor, &execution).unwrap();
    assert_eq!(reader.next_record().unwrap(), Some(small));
    assert_eq!(reader.next_record().unwrap(), Some(large));
    assert_eq!(reader.next_record().unwrap(), Some(deleted));
    assert!(reader.next_record().unwrap().is_none());
    assert!(target.snapshot().next_sequence >= 3);
    assert_eq!(target.snapshot().last_round, 1);
}
