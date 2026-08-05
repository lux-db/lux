use super::transfer_record::{TransferRecordReader, TransferRecordWriter};
use super::transfer_stream::TransferChunkWriter;
use super::{
    ClusterError, TransferChunk, TransferDataKey, TransferDescriptor, TransferFinalBatch,
    TransferJournal, TransferReceipt, TransferRuntime,
};
use crate::store::Store;
use std::io::{Read, Write};
use std::time::Instant;

pub struct SourceStoreTransfer<'a, SendChunk> {
    store: &'a Store,
    source: &'a TransferJournal,
    descriptor: &'a TransferDescriptor,
    records: TransferRecordWriter<'a, TransferChunkWriter<'a, SendChunk>>,
    initial_written: bool,
    last_round: u32,
    failed: bool,
}

impl<'a, SendChunk> SourceStoreTransfer<'a, SendChunk>
where
    SendChunk: FnMut(&TransferChunk) -> Result<TransferReceipt, ClusterError>,
{
    pub fn begin(
        store: &'a Store,
        source: &'a TransferJournal,
        descriptor: &'a TransferDescriptor,
        send_chunk: SendChunk,
    ) -> Result<Self, ClusterError> {
        descriptor.validate()?;
        let snapshot = source.snapshot();
        if snapshot.descriptor != *descriptor
            || snapshot.role != super::TransferRole::Source
            || snapshot.phase != super::TransferPhase::Copying
            || snapshot.attempt == 0
            || snapshot.staged_bytes == 0
            || snapshot.next_sequence != 0
            || snapshot.last_round != 0
            || snapshot.last_digest.is_some()
            || source.source_requires_restart()
        {
            return invalid("source Store transfer requires a resumable copying journal");
        }
        let chunks = TransferChunkWriter::new(source, 0, send_chunk);
        Ok(Self {
            store,
            source,
            descriptor,
            records: TransferRecordWriter::new(chunks, store, descriptor)?,
            initial_written: false,
            last_round: 0,
            failed: false,
        })
    }

    pub fn write_initial(&mut self) -> Result<u64, ClusterError> {
        if self.failed {
            return invalid("failed Store transfer attempt must be restarted");
        }
        if self.initial_written {
            return invalid("initial Store transfer records were already written");
        }
        let result = write_initial_store_records(self.store, self.descriptor, &mut self.records)
            .and_then(|written| {
                self.records.flush()?;
                Ok(written)
            });
        let written = match result {
            Ok(written) => written,
            Err(error) => {
                self.failed = true;
                return Err(error);
            }
        };
        self.initial_written = true;
        Ok(written)
    }

    pub fn write_dirty_round(
        &mut self,
        round: u32,
        dirty: &[TransferDataKey],
    ) -> Result<u64, ClusterError> {
        if self.failed {
            return invalid("failed Store transfer attempt must be restarted");
        }
        if !self.initial_written || round <= self.last_round {
            return invalid("dirty Store transfer rounds must increase after the initial round");
        }
        let result = self
            .records
            .inner_mut()
            .begin_round(round)
            .and_then(|()| write_dirty_store_records(self.store, dirty, &mut self.records))
            .and_then(|written| {
                self.records.flush()?;
                Ok(written)
            });
        let written = match result {
            Ok(written) => written,
            Err(error) => {
                self.failed = true;
                return Err(error);
            }
        };
        self.last_round = round;
        Ok(written)
    }

    pub fn finish_and_fence(
        mut self,
        runtime: &TransferRuntime,
        final_round: u32,
        final_dirty: &TransferFinalBatch,
    ) -> Result<TransferReceipt, ClusterError> {
        if self.failed
            || !self.initial_written
            || final_round <= self.last_round
            || final_dirty.transfer_id() != self.descriptor.transfer_id
        {
            return invalid(
                "final Store transfer requires a healthy attempt, increasing round, and matching fence",
            );
        }
        self.records.inner_mut().begin_round(final_round)?;
        write_dirty_store_records(self.store, final_dirty.keys(), &mut self.records)?;
        let receipt = self.records.finish()?.finish()?;
        self.source.mark_source_fenced(&receipt)?;
        runtime.confirm_final(&self.source.snapshot())?;
        self.source.seal(&receipt)?;
        Ok(receipt)
    }
}

pub(crate) fn write_initial_store_records<W: Write>(
    store: &Store,
    descriptor: &TransferDescriptor,
    records: &mut TransferRecordWriter<'_, W>,
) -> Result<u64, ClusterError> {
    descriptor.validate()?;
    let now = Instant::now();
    let mut written = 0_u64;
    for shard in 0..store.shard_count() {
        for identity in store.transfer_identities_for_shard(shard, descriptor, now)? {
            records.write_record(&store.transfer_record(&identity, Instant::now())?)?;
            written = written.checked_add(1).ok_or_else(|| {
                ClusterError::InvalidTransfer("initial record count is exhausted".to_owned())
            })?;
        }
    }
    for identity in store.transfer_disk_identities(descriptor, now)? {
        records.write_record(&store.transfer_record(&identity, Instant::now())?)?;
        written = written.checked_add(1).ok_or_else(|| {
            ClusterError::InvalidTransfer("initial record count is exhausted".to_owned())
        })?;
    }
    Ok(written)
}

pub(crate) fn write_dirty_store_records<W: Write>(
    store: &Store,
    dirty: &[TransferDataKey],
    records: &mut TransferRecordWriter<'_, W>,
) -> Result<u64, ClusterError> {
    let mut written = 0_u64;
    for identity in dirty {
        records.write_record(&store.transfer_record(identity, Instant::now())?)?;
        written = written.checked_add(1).ok_or_else(|| {
            ClusterError::InvalidTransfer("dirty record count is exhausted".to_owned())
        })?;
    }
    Ok(written)
}

pub(crate) fn apply_target_store_records<R: Read>(
    store: &Store,
    descriptor: &TransferDescriptor,
    reader: R,
) -> Result<u64, ClusterError> {
    let mut records = TransferRecordReader::new(reader, store, descriptor)?;
    let mut applied = 0_u64;
    while let Some(record) = records.next_record()? {
        store.apply_transfer_record(record)?;
        applied = applied.checked_add(1).ok_or_else(|| {
            ClusterError::InvalidTransfer("applied record count is exhausted".to_owned())
        })?;
    }
    Ok(applied)
}

pub(crate) fn apply_sealed_target_store(
    store: &Store,
    descriptor: &TransferDescriptor,
    target: &TransferJournal,
) -> Result<u64, ClusterError> {
    apply_target_store_records(store, descriptor, target.open_target_reader()?)
}

pub fn apply_target_store_transfer(
    store: &Store,
    descriptor: &TransferDescriptor,
    target: &TransferJournal,
    receipt: &super::TransferReceipt,
) -> Result<u64, ClusterError> {
    target.prepare_target_apply(descriptor, receipt)?;
    store.clear_transfer_ranges(descriptor)?;
    let applied = apply_sealed_target_store(store, descriptor, target)?;
    target.mark_target_applied(receipt)?;
    Ok(applied)
}

fn invalid<T>(message: impl Into<String>) -> Result<T, ClusterError> {
    Err(ClusterError::InvalidTransfer(message.into()))
}

#[cfg(test)]
#[path = "transfer_coordinator_tests.rs"]
mod tests;
