use super::{
    ClusterError, TransferChunk, TransferJournal, TransferReceipt, MAX_TRANSFER_CHUNK_BYTES,
};
use std::io::Write;

pub(crate) struct TransferChunkWriter<'a, SendChunk> {
    source: &'a TransferJournal,
    send_chunk: SendChunk,
    round: u32,
    payload: Vec<u8>,
}

impl<'a, SendChunk> TransferChunkWriter<'a, SendChunk>
where
    SendChunk: FnMut(&TransferChunk) -> Result<TransferReceipt, ClusterError>,
{
    pub(crate) fn new(source: &'a TransferJournal, round: u32, send_chunk: SendChunk) -> Self {
        Self {
            source,
            send_chunk,
            round,
            payload: Vec::with_capacity(MAX_TRANSFER_CHUNK_BYTES),
        }
    }

    pub(crate) fn begin_round(&mut self, round: u32) -> Result<(), ClusterError> {
        self.flush_chunk()?;
        if round < self.round {
            return invalid("transfer stream round cannot move backward");
        }
        self.round = round;
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Result<TransferReceipt, ClusterError> {
        self.flush_chunk()?;
        let snapshot = self.source.snapshot();
        if snapshot.attempt == 0 || snapshot.next_sequence == 0 {
            return invalid("transfer stream contains no durable chunks");
        }
        Ok(TransferReceipt {
            transfer_id: snapshot.descriptor.transfer_id,
            attempt: snapshot.attempt,
            next_sequence: snapshot.next_sequence,
            last_round: snapshot.last_round,
            last_digest: snapshot.last_digest,
            staged_bytes: snapshot.staged_bytes,
        })
    }

    fn flush_chunk(&mut self) -> Result<(), ClusterError> {
        if self.payload.is_empty() {
            return Ok(());
        }
        let chunk = self
            .source
            .next_source_chunk(self.round, self.payload.clone())?;
        let receipt = (self.send_chunk)(&chunk)?;
        self.source.record_source_receipt(&chunk, &receipt)?;
        self.payload.clear();
        Ok(())
    }
}

impl<SendChunk> Write for TransferChunkWriter<'_, SendChunk>
where
    SendChunk: FnMut(&TransferChunk) -> Result<TransferReceipt, ClusterError>,
{
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        if input.is_empty() {
            return Ok(0);
        }
        if self.payload.len() == MAX_TRANSFER_CHUNK_BYTES {
            self.flush_chunk().map_err(as_io_error)?;
        }
        let available = MAX_TRANSFER_CHUNK_BYTES - self.payload.len();
        let copied = available.min(input.len());
        self.payload.extend_from_slice(&input[..copied]);
        Ok(copied)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.flush_chunk().map_err(as_io_error)
    }
}

fn as_io_error(error: ClusterError) -> std::io::Error {
    std::io::Error::other(error.to_string())
}

fn invalid<T>(message: impl Into<String>) -> Result<T, ClusterError> {
    Err(ClusterError::InvalidTransfer(message.into()))
}

#[cfg(test)]
#[path = "transfer_stream_tests.rs"]
mod tests;
