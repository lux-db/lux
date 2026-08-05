use super::transfer_runtime::TransferDataKey;
use super::ClusterError;
use std::collections::hash_map::RandomState;
use std::collections::HashSet;
use std::hash::BuildHasher;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

const DIRTY_SHARD_COUNT: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirtyStats {
    /// Identities retained in dirty buffers or reserved by in-flight writes.
    pub keys: usize,
    /// Estimated heap bytes retained by those identities.
    pub bytes: usize,
    /// The current transfer must abort because its configured bound was hit.
    pub overflowed: bool,
}

pub(super) struct DirtyTracker {
    active_buffer: AtomicUsize,
    hash_builder: RandomState,
    shards: Box<[DirtyShard]>,
    key_count: AtomicUsize,
    byte_count: AtomicUsize,
    max_keys: usize,
    max_bytes: usize,
    overflowed: AtomicBool,
}

struct DirtyShard {
    buffers: [parking_lot::Mutex<HashSet<TransferDataKey>>; 2],
}

impl DirtyTracker {
    pub(super) fn new(max_keys: usize, max_bytes: usize) -> Self {
        let shards = (0..DIRTY_SHARD_COUNT)
            .map(|_| DirtyShard {
                buffers: std::array::from_fn(|_| parking_lot::Mutex::new(HashSet::new())),
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            active_buffer: AtomicUsize::new(0),
            hash_builder: RandomState::new(),
            shards,
            key_count: AtomicUsize::new(0),
            byte_count: AtomicUsize::new(0),
            max_keys,
            max_bytes,
            overflowed: AtomicBool::new(false),
        }
    }

    pub(super) fn reserve_identity(&self, bytes: usize) -> bool {
        if self.overflowed.load(Ordering::Acquire) {
            return false;
        }
        if !reserve(&self.key_count, 1, self.max_keys) {
            self.overflowed.store(true, Ordering::Release);
            return false;
        }
        if !reserve(&self.byte_count, bytes, self.max_bytes) {
            self.key_count.fetch_sub(1, Ordering::AcqRel);
            self.overflowed.store(true, Ordering::Release);
            return false;
        }
        true
    }

    pub(super) fn release_identity(&self, bytes: usize) {
        self.key_count.fetch_sub(1, Ordering::AcqRel);
        self.byte_count.fetch_sub(bytes, Ordering::AcqRel);
    }

    pub(super) fn mark_reserved(&self, key: TransferDataKey, reserved_bytes: usize) {
        let shard_index = (self.hash_builder.hash_one(&key) as usize) & (DIRTY_SHARD_COUNT - 1);
        loop {
            let buffer_index = self.active_buffer.load(Ordering::Acquire);
            let mut buffer = self.shards[shard_index].buffers[buffer_index].lock();
            if self.active_buffer.load(Ordering::Acquire) != buffer_index {
                drop(buffer);
                continue;
            }
            if buffer.contains(&key) {
                self.release_identity(reserved_bytes);
                return;
            }
            buffer.insert(key);
            return;
        }
    }

    pub(super) fn drain_round(&self) -> Result<Vec<TransferDataKey>, ClusterError> {
        let previous = self.active_buffer.fetch_xor(1, Ordering::AcqRel);
        self.drain_buffers(std::slice::from_ref(&previous))
    }

    pub(super) fn drain_all(&self) -> Result<Vec<TransferDataKey>, ClusterError> {
        self.drain_buffers(&[0, 1])
    }

    fn drain_buffers(&self, indexes: &[usize]) -> Result<Vec<TransferDataKey>, ClusterError> {
        if self.overflowed.load(Ordering::Acquire) {
            return invalid("dirty tracking exceeded its configured memory bound");
        }
        let mut keys = Vec::new();
        let mut removed_keys = 0;
        let mut removed_bytes = 0;
        for shard in &self.shards {
            for index in indexes {
                let mut buffer = shard.buffers[*index].lock();
                let drained = std::mem::take(&mut *buffer);
                drop(buffer);
                for key in drained {
                    removed_keys += 1;
                    removed_bytes += key.tracked_bytes();
                    keys.push(key);
                }
            }
        }
        self.key_count.fetch_sub(removed_keys, Ordering::AcqRel);
        self.byte_count.fetch_sub(removed_bytes, Ordering::AcqRel);
        keys.sort_unstable();
        keys.dedup();
        Ok(keys)
    }

    pub(super) fn stats(&self) -> DirtyStats {
        DirtyStats {
            keys: self.key_count.load(Ordering::Acquire),
            bytes: self.byte_count.load(Ordering::Acquire),
            overflowed: self.overflowed.load(Ordering::Acquire),
        }
    }
}

fn reserve(counter: &AtomicUsize, amount: usize, maximum: usize) -> bool {
    counter
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            current.checked_add(amount).filter(|next| *next <= maximum)
        })
        .is_ok()
}

fn invalid<T>(message: impl Into<String>) -> Result<T, ClusterError> {
    Err(ClusterError::InvalidTransfer(message.into()))
}
