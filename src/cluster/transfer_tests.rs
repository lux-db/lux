use super::*;
use crate::cluster::{SlotRange, CLUSTER_PROTOCOL_VERSION, MAX_TRANSFER_CHUNK_BYTES};

const MAX_STAGED_BYTES: u64 = 16 * 1024 * 1024;

fn descriptor() -> TransferDescriptor {
    let mut descriptor = TransferDescriptor {
        schema_version: TRANSFER_SCHEMA_VERSION,
        protocol_version: CLUSTER_PROTOCOL_VERSION,
        transfer_id: TransferId([0; 32]),
        cluster_id: "cluster-a".to_owned(),
        from_epoch: 3,
        to_epoch: 4,
        source_node_id: "node-a".to_owned(),
        target_node_id: "node-b".to_owned(),
        ranges: vec![
            SlotRange {
                start: 100,
                end: 199,
            },
            SlotRange {
                start: 500,
                end: 700,
            },
        ],
    };
    descriptor.transfer_id = descriptor.expected_id().unwrap();
    descriptor.validate().unwrap();
    descriptor
}

#[test]
fn descriptor_id_is_canonical_and_covers_every_route_field() {
    let descriptor = descriptor();
    assert!(descriptor.contains_slot(100));
    assert!(descriptor.contains_slot(700));
    assert!(!descriptor.contains_slot(499));

    let mut changed = descriptor.clone();
    changed.ranges[1].end -= 1;
    assert_ne!(changed.expected_id().unwrap(), descriptor.transfer_id);
    assert!(matches!(
        changed.validate(),
        Err(ClusterError::InvalidTransfer(_))
    ));

    let mut overlapping = descriptor;
    overlapping.ranges[1].start = 199;
    overlapping.transfer_id = overlapping.expected_id().unwrap();
    assert!(matches!(
        overlapping.validate(),
        Err(ClusterError::InvalidTransfer(_))
    ));
}

#[test]
fn chained_chunks_are_ordered_idempotent_and_durable() {
    let directory = tempfile::tempdir().unwrap();
    let descriptor = descriptor();
    let source_path = directory.path().join("source.json");
    let target_path = directory.path().join("target.json");
    let source = TransferJournal::open(
        TransferRole::Source,
        descriptor.clone(),
        &source_path,
        MAX_STAGED_BYTES,
    )
    .unwrap();
    let target = TransferJournal::open(
        TransferRole::Target,
        descriptor.clone(),
        &target_path,
        MAX_STAGED_BYTES,
    )
    .unwrap();

    assert_eq!(source.begin_source_attempt().unwrap(), 1);
    let start = target.accept_target_attempt(1).unwrap();
    source.record_target_start(&start).unwrap();

    let first = source
        .next_source_chunk(0, b"initial-copy".to_vec())
        .unwrap();
    let (disposition, first_receipt) = target.append_target_chunk(&first).unwrap();
    assert_eq!(disposition, ChunkDisposition::Applied);
    let mut forged = first_receipt.clone();
    forged.last_digest = Some([0; 32]);
    assert!(source.record_source_receipt(&first, &forged).is_err());
    source
        .record_source_receipt(&first, &first_receipt)
        .unwrap();
    source
        .record_source_receipt(&first, &first_receipt)
        .unwrap();
    let (disposition, replay) = target.append_target_chunk(&first).unwrap();
    assert_eq!(disposition, ChunkDisposition::Replay);
    assert_eq!(replay, first_receipt);

    let conflicting = TransferChunk::new(
        descriptor.transfer_id,
        1,
        0,
        0,
        None,
        b"different-copy".to_vec(),
    )
    .unwrap();
    assert!(matches!(
        target.append_target_chunk(&conflicting),
        Err(ClusterError::InvalidTransfer(_))
    ));

    let second = source
        .next_source_chunk(1, b"dirty-round".to_vec())
        .unwrap();
    let (_, final_receipt) = target.append_target_chunk(&second).unwrap();
    source
        .record_source_receipt(&second, &final_receipt)
        .unwrap();
    assert_eq!(final_receipt.next_sequence, 2);
    assert_eq!(final_receipt.last_round, 1);

    source.mark_source_fenced(&final_receipt).unwrap();
    target.seal(&final_receipt).unwrap();
    source.seal(&final_receipt).unwrap();
    target.mark_topology_committed(4).unwrap();
    source.mark_topology_committed(4).unwrap();
    assert!(matches!(
        target.abort(),
        Err(ClusterError::InvalidTransfer(_))
    ));
    target.finalize().unwrap();
    source.finalize().unwrap();
    assert!(!target.stage_path.exists());

    drop(source);
    drop(target);
    let reopened = TransferJournal::open(
        TransferRole::Target,
        descriptor,
        target_path,
        MAX_STAGED_BYTES,
    )
    .unwrap();
    assert_eq!(reopened.snapshot().phase, TransferPhase::Finalized);
    assert!(!reopened.stage_path.exists());
}

#[test]
fn unjournaled_stage_tail_is_truncated_after_a_crash() {
    let directory = tempfile::tempdir().unwrap();
    let descriptor = descriptor();
    let path = directory.path().join("target.json");
    let target = TransferJournal::open(
        TransferRole::Target,
        descriptor.clone(),
        &path,
        MAX_STAGED_BYTES,
    )
    .unwrap();
    target.accept_target_attempt(1).unwrap();
    let chunk =
        TransferChunk::new(descriptor.transfer_id, 1, 0, 0, None, b"durable".to_vec()).unwrap();
    let (_, receipt) = target.append_target_chunk(&chunk).unwrap();
    let mut stage = std::fs::OpenOptions::new()
        .append(true)
        .open(&target.stage_path)
        .unwrap();
    stage.write_all(b"uncommitted-tail").unwrap();
    stage.sync_all().unwrap();
    assert!(std::fs::metadata(&target.stage_path).unwrap().len() > receipt.staged_bytes);
    drop(stage);
    drop(target);

    let reopened =
        TransferJournal::open(TransferRole::Target, descriptor, path, MAX_STAGED_BYTES).unwrap();
    assert_eq!(
        std::fs::metadata(&reopened.stage_path).unwrap().len(),
        receipt.staged_bytes
    );
    assert_eq!(reopened.snapshot().next_sequence, 1);
}

#[test]
fn missing_journaled_stage_bytes_fail_closed() {
    let directory = tempfile::tempdir().unwrap();
    let descriptor = descriptor();
    let path = directory.path().join("target.json");
    let target = TransferJournal::open(
        TransferRole::Target,
        descriptor.clone(),
        &path,
        MAX_STAGED_BYTES,
    )
    .unwrap();
    target.accept_target_attempt(1).unwrap();
    let chunk =
        TransferChunk::new(descriptor.transfer_id, 1, 0, 0, None, b"durable".to_vec()).unwrap();
    target.append_target_chunk(&chunk).unwrap();
    let stage_path = target.stage_path.clone();
    drop(target);
    std::fs::OpenOptions::new()
        .write(true)
        .open(&stage_path)
        .unwrap()
        .set_len(STAGE_HEADER_BYTES)
        .unwrap();
    assert!(matches!(
        TransferJournal::open(TransferRole::Target, descriptor, path, MAX_STAGED_BYTES),
        Err(ClusterError::InvalidTransfer(_))
    ));
}

#[test]
fn source_restart_uses_a_new_attempt_and_target_resets_staging() {
    let directory = tempfile::tempdir().unwrap();
    let descriptor = descriptor();
    let source_path = directory.path().join("source.json");
    let target_path = directory.path().join("target.json");
    let source = TransferJournal::open(
        TransferRole::Source,
        descriptor.clone(),
        &source_path,
        MAX_STAGED_BYTES,
    )
    .unwrap();
    let target = TransferJournal::open(
        TransferRole::Target,
        descriptor.clone(),
        &target_path,
        MAX_STAGED_BYTES,
    )
    .unwrap();
    source.begin_source_attempt().unwrap();
    assert!(!source.source_requires_restart());
    let start = target.accept_target_attempt(1).unwrap();
    source.record_target_start(&start).unwrap();
    let first = source
        .next_source_chunk(0, b"old-attempt".to_vec())
        .unwrap();
    let (_, receipt) = target.append_target_chunk(&first).unwrap();
    source.record_source_receipt(&first, &receipt).unwrap();
    drop(source);

    let restarted = TransferJournal::open(
        TransferRole::Source,
        descriptor.clone(),
        source_path,
        MAX_STAGED_BYTES,
    )
    .unwrap();
    assert!(restarted.source_requires_restart());
    assert!(restarted
        .next_source_chunk(1, b"must-restart".to_vec())
        .is_err());
    assert!(restarted.record_target_start(&receipt).is_err());
    assert!(restarted.record_source_receipt(&first, &receipt).is_err());
    assert!(restarted.mark_source_fenced(&receipt).is_err());
    assert_eq!(restarted.begin_source_attempt().unwrap(), 2);
    assert!(!restarted.source_requires_restart());
    let reset = target.accept_target_attempt(2).unwrap();
    assert_eq!(reset.next_sequence, 0);
    assert_eq!(reset.staged_bytes, STAGE_HEADER_BYTES);
    restarted.record_target_start(&reset).unwrap();
    assert_eq!(
        std::fs::metadata(&target.stage_path).unwrap().len(),
        STAGE_HEADER_BYTES
    );
    assert!(target.append_target_chunk(&first).is_err());

    let replacement = restarted
        .next_source_chunk(0, b"new-attempt".to_vec())
        .unwrap();
    assert_eq!(replacement.attempt, 2);
    assert!(target.append_target_chunk(&replacement).is_ok());
}

#[test]
fn source_restart_before_target_ack_can_resume_the_same_attempt() {
    let directory = tempfile::tempdir().unwrap();
    let descriptor = descriptor();
    let source_path = directory.path().join("source.json");
    let target_path = directory.path().join("target.json");
    let source = TransferJournal::open(
        TransferRole::Source,
        descriptor.clone(),
        &source_path,
        MAX_STAGED_BYTES,
    )
    .unwrap();
    assert_eq!(source.begin_source_attempt().unwrap(), 1);
    drop(source);

    let restarted = TransferJournal::open(
        TransferRole::Source,
        descriptor.clone(),
        source_path,
        MAX_STAGED_BYTES,
    )
    .unwrap();
    assert!(!restarted.source_requires_restart());
    assert_eq!(restarted.snapshot().attempt, 1);

    let target = TransferJournal::open(
        TransferRole::Target,
        descriptor,
        target_path,
        MAX_STAGED_BYTES,
    )
    .unwrap();
    let start = target.accept_target_attempt(1).unwrap();
    restarted.record_target_start(&start).unwrap();
    assert_eq!(
        restarted
            .next_source_chunk(0, b"resumed-before-data".to_vec())
            .unwrap()
            .attempt,
        1
    );
}

#[test]
fn target_stage_is_private_and_wrong_journal_identity_is_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let descriptor = descriptor();
    let path = directory.path().join("target.json");
    let target = TransferJournal::open(
        TransferRole::Target,
        descriptor.clone(),
        &path,
        MAX_STAGED_BYTES,
    )
    .unwrap();
    let mode = std::fs::metadata(&target.stage_path)
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o077, 0);
    drop(target);

    assert!(matches!(
        TransferJournal::open(
            TransferRole::Source,
            descriptor.clone(),
            &path,
            MAX_STAGED_BYTES
        ),
        Err(ClusterError::InvalidTransfer(_))
    ));
    let mut changed = descriptor;
    changed.target_node_id = "node-c".to_owned();
    changed.transfer_id = changed.expected_id().unwrap();
    assert!(matches!(
        TransferJournal::open(TransferRole::Target, changed, path, MAX_STAGED_BYTES),
        Err(ClusterError::InvalidTransfer(_))
    ));
}

#[test]
fn chunk_payload_and_digest_are_fail_closed() {
    let descriptor = descriptor();
    assert!(TransferChunk::new(descriptor.transfer_id, 1, 0, 0, None, Vec::new()).is_err());
    assert!(TransferChunk::new(
        descriptor.transfer_id,
        1,
        0,
        0,
        None,
        vec![0; MAX_TRANSFER_CHUNK_BYTES + 1]
    )
    .is_err());
    let mut chunk =
        TransferChunk::new(descriptor.transfer_id, 1, 0, 0, None, b"payload".to_vec()).unwrap();
    chunk.payload[0] ^= 1;
    assert!(matches!(
        chunk.verify(),
        Err(ClusterError::InvalidTransfer(_))
    ));

    let chunk = TransferChunk::new(
        descriptor.transfer_id,
        2,
        7,
        3,
        Some([4; 32]),
        b"round-trip".to_vec(),
    )
    .unwrap();
    let encoded = chunk.encoded().unwrap();
    assert_eq!(TransferChunk::decode(&encoded).unwrap(), chunk);
    for cutoff in 0..encoded.len() {
        assert!(TransferChunk::decode(&encoded[..cutoff]).is_err());
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(TransferChunk::decode(&trailing).is_err());
    let mut bad_flag = encoded;
    bad_flag[48] = 2;
    assert!(TransferChunk::decode(&bad_flag).is_err());
}

#[test]
fn same_length_stage_corruption_fails_closed_on_restart() {
    use std::io::{Read, Seek, SeekFrom};

    let directory = tempfile::tempdir().unwrap();
    let descriptor = descriptor();
    let path = directory.path().join("target.json");
    let target = TransferJournal::open(
        TransferRole::Target,
        descriptor.clone(),
        &path,
        MAX_STAGED_BYTES,
    )
    .unwrap();
    target.accept_target_attempt(1).unwrap();
    let chunk =
        TransferChunk::new(descriptor.transfer_id, 1, 0, 0, None, b"durable".to_vec()).unwrap();
    target.append_target_chunk(&chunk).unwrap();
    let stage_path = target.stage_path.clone();
    drop(target);

    let mut stage = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(stage_path)
        .unwrap();
    stage.seek(SeekFrom::End(-1)).unwrap();
    let mut byte = [0_u8; 1];
    stage.read_exact(&mut byte).unwrap();
    byte[0] ^= 1;
    stage.seek(SeekFrom::End(-1)).unwrap();
    stage.write_all(&byte).unwrap();
    stage.sync_all().unwrap();
    drop(stage);

    assert!(matches!(
        TransferJournal::open(TransferRole::Target, descriptor, path, MAX_STAGED_BYTES),
        Err(ClusterError::InvalidTransfer(_))
    ));
}

#[test]
fn target_stage_quota_is_enforced_before_writing() {
    let directory = tempfile::tempdir().unwrap();
    let descriptor = descriptor();
    let path = directory.path().join("target.json");
    let max_staged_bytes = STAGE_HEADER_BYTES + 64;
    let target = TransferJournal::open(
        TransferRole::Target,
        descriptor.clone(),
        &path,
        max_staged_bytes,
    )
    .unwrap();
    target.accept_target_attempt(1).unwrap();
    let chunk = TransferChunk::new(
        descriptor.transfer_id,
        1,
        0,
        0,
        None,
        b"too-large-after-framing".to_vec(),
    )
    .unwrap();
    assert!(matches!(
        target.append_target_chunk(&chunk),
        Err(ClusterError::InvalidTransfer(_))
    ));
    assert_eq!(
        std::fs::metadata(&target.stage_path).unwrap().len(),
        STAGE_HEADER_BYTES
    );
}

#[test]
fn empty_slot_range_can_seal_without_a_synthetic_data_chunk() {
    let directory = tempfile::tempdir().unwrap();
    let descriptor = descriptor();
    let source = TransferJournal::open(
        TransferRole::Source,
        descriptor.clone(),
        directory.path().join("source.json"),
        MAX_STAGED_BYTES,
    )
    .unwrap();
    let target = TransferJournal::open(
        TransferRole::Target,
        descriptor,
        directory.path().join("target.json"),
        MAX_STAGED_BYTES,
    )
    .unwrap();
    source.begin_source_attempt().unwrap();
    let receipt = target.accept_target_attempt(1).unwrap();
    source.record_target_start(&receipt).unwrap();
    source.mark_source_fenced(&receipt).unwrap();
    source.seal(&receipt).unwrap();
    target.seal(&receipt).unwrap();
}

#[test]
fn source_cannot_emit_data_before_target_staging_is_acknowledged() {
    let directory = tempfile::tempdir().unwrap();
    let descriptor = descriptor();
    let source = TransferJournal::open(
        TransferRole::Source,
        descriptor.clone(),
        directory.path().join("source.json"),
        MAX_STAGED_BYTES,
    )
    .unwrap();
    let target = TransferJournal::open(
        TransferRole::Target,
        descriptor,
        directory.path().join("target.json"),
        MAX_STAGED_BYTES,
    )
    .unwrap();
    source.begin_source_attempt().unwrap();
    assert!(matches!(
        source.next_source_chunk(0, b"too-early".to_vec()),
        Err(ClusterError::InvalidTransfer(_))
    ));
    let start = target.accept_target_attempt(1).unwrap();
    source.record_target_start(&start).unwrap();
    assert!(source.next_source_chunk(0, b"after-ack".to_vec()).is_ok());
}

#[test]
fn state_transitions_are_idempotent_but_late_progress_fails_closed() {
    let directory = tempfile::tempdir().unwrap();
    let descriptor = descriptor();
    let source = TransferJournal::open(
        TransferRole::Source,
        descriptor.clone(),
        directory.path().join("source.json"),
        MAX_STAGED_BYTES,
    )
    .unwrap();
    let target = TransferJournal::open(
        TransferRole::Target,
        descriptor.clone(),
        directory.path().join("target.json"),
        MAX_STAGED_BYTES,
    )
    .unwrap();
    source.begin_source_attempt().unwrap();
    let start = target.accept_target_attempt(1).unwrap();
    source.record_target_start(&start).unwrap();
    let chunk = source.next_source_chunk(0, b"copy".to_vec()).unwrap();
    let (_, receipt) = target.append_target_chunk(&chunk).unwrap();
    source.record_source_receipt(&chunk, &receipt).unwrap();
    let mut wrong_fence_receipt = receipt.clone();
    wrong_fence_receipt.staged_bytes += 1;
    assert!(source.mark_source_fenced(&wrong_fence_receipt).is_err());
    source.mark_source_fenced(&receipt).unwrap();
    source.mark_source_fenced(&receipt).unwrap();
    assert!(source
        .next_source_chunk(1, b"after-fence".to_vec())
        .is_err());
    source.seal(&receipt).unwrap();
    source.seal(&receipt).unwrap();
    target.seal(&receipt).unwrap();
    target.seal(&receipt).unwrap();
    source.mark_topology_committed(4).unwrap();
    source.mark_topology_committed(4).unwrap();
    target.mark_topology_committed(4).unwrap();
    source.finalize().unwrap();
    target.finalize().unwrap();
    source.seal(&receipt).unwrap();
    source.mark_topology_committed(4).unwrap();
    source.record_source_receipt(&chunk, &receipt).unwrap();

    let late = TransferChunk::new(
        descriptor.transfer_id,
        1,
        1,
        1,
        Some(chunk.digest),
        b"late".to_vec(),
    )
    .unwrap();
    let late_receipt = TransferReceipt {
        transfer_id: descriptor.transfer_id,
        attempt: 1,
        next_sequence: 2,
        last_round: 1,
        last_digest: Some(late.digest),
        staged_bytes: receipt.staged_bytes + 4 + late.encoded_len().unwrap() as u64,
    };
    assert!(matches!(
        source.record_source_receipt(&late, &late_receipt),
        Err(ClusterError::InvalidTransfer(_))
    ));
    assert!(matches!(
        target.append_target_chunk(&late),
        Err(ClusterError::InvalidTransfer(_))
    ));
}

#[test]
fn prepared_abort_is_durable_and_restartable_as_terminal_state() {
    let directory = tempfile::tempdir().unwrap();
    let descriptor = descriptor();
    let path = directory.path().join("target.json");
    let target = TransferJournal::open(
        TransferRole::Target,
        descriptor.clone(),
        &path,
        MAX_STAGED_BYTES,
    )
    .unwrap();
    target.abort().unwrap();
    assert!(!target.stage_path.exists());
    drop(target);

    let reopened =
        TransferJournal::open(TransferRole::Target, descriptor, path, MAX_STAGED_BYTES).unwrap();
    assert_eq!(reopened.snapshot().phase, TransferPhase::Aborted);
    assert_eq!(reopened.snapshot().attempt, 0);
    assert!(!reopened.stage_path.exists());
}

#[test]
fn a_tighter_restart_quota_does_not_mutate_existing_stage_data() {
    let directory = tempfile::tempdir().unwrap();
    let descriptor = descriptor();
    let path = directory.path().join("target.json");
    let target = TransferJournal::open(
        TransferRole::Target,
        descriptor.clone(),
        &path,
        MAX_STAGED_BYTES,
    )
    .unwrap();
    target.accept_target_attempt(1).unwrap();
    let chunk = TransferChunk::new(descriptor.transfer_id, 1, 0, 0, None, vec![7; 256]).unwrap();
    let (_, receipt) = target.append_target_chunk(&chunk).unwrap();
    let stage_path = target.stage_path.clone();
    let original_length = std::fs::metadata(&stage_path).unwrap().len();
    drop(target);

    assert!(matches!(
        TransferJournal::open(
            TransferRole::Target,
            descriptor,
            path,
            receipt.staged_bytes - 1,
        ),
        Err(ClusterError::InvalidTransfer(_))
    ));
    assert_eq!(
        std::fs::metadata(&stage_path).unwrap().len(),
        original_length
    );
}

#[test]
fn corrupted_empty_progress_is_rejected_on_restart() {
    let directory = tempfile::tempdir().unwrap();
    let descriptor = descriptor();
    let path = directory.path().join("source.json");
    let source = TransferJournal::open(
        TransferRole::Source,
        descriptor.clone(),
        &path,
        MAX_STAGED_BYTES,
    )
    .unwrap();
    let mut corrupt = source.inner.lock().clone();
    corrupt.snapshot.last_round = 1;
    source.persist(&corrupt).unwrap();
    drop(source);

    assert!(matches!(
        TransferJournal::open(TransferRole::Source, descriptor, path, MAX_STAGED_BYTES),
        Err(ClusterError::InvalidTransfer(_))
    ));
}

#[test]
fn exhausted_sequence_is_rejected_before_stage_append() {
    let directory = tempfile::tempdir().unwrap();
    let descriptor = descriptor();
    let target = TransferJournal::open(
        TransferRole::Target,
        descriptor.clone(),
        directory.path().join("target.json"),
        MAX_STAGED_BYTES,
    )
    .unwrap();
    target.accept_target_attempt(1).unwrap();
    let previous = [9; 32];
    {
        let mut state = target.inner.lock();
        state.snapshot.next_sequence = u64::MAX;
        state.snapshot.last_digest = Some(previous);
    }
    let length = std::fs::metadata(&target.stage_path).unwrap().len();
    let chunk = TransferChunk::new(
        descriptor.transfer_id,
        1,
        u64::MAX,
        0,
        Some(previous),
        b"never-appended".to_vec(),
    )
    .unwrap();
    assert!(matches!(
        target.append_target_chunk(&chunk),
        Err(ClusterError::InvalidTransfer(_))
    ));
    assert_eq!(std::fs::metadata(&target.stage_path).unwrap().len(), length);
}
