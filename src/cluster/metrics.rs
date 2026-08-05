use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

pub const ROUTE_SNAPSHOT_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouteCounterValues {
    pub owner_local_operations: u64,
    pub compatibility_forwards: u64,
    pub point_peer_frames: u64,
    pub point_peer_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouteCounterSnapshot {
    pub schema_version: u32,
    pub owner_id: String,
    pub topology_epoch: u64,
    pub execution_version: u64,
    pub counters: RouteCounterValues,
}

impl RouteCounterSnapshot {
    #[must_use]
    pub fn capture(
        owner_id: impl Into<String>,
        topology_epoch: u64,
        execution_version: u64,
        counters: &RouteCounters,
    ) -> Self {
        Self {
            schema_version: ROUTE_SNAPSHOT_SCHEMA_VERSION,
            owner_id: owner_id.into(),
            topology_epoch,
            execution_version,
            counters: counters.snapshot(),
        }
    }
}

#[repr(align(64))]
#[derive(Default)]
struct CounterShard {
    owner_local_operations: AtomicU64,
    compatibility_forwards: AtomicU64,
    point_peer_frames: AtomicU64,
    point_peer_bytes: AtomicU64,
}

/// Low-contention counters used to prove which dataplane a benchmark exercised.
///
/// Stable native point operations increment only `owner_local_operations`.
/// Compatibility forwarding and peer point traffic are tracked independently
/// and are hard failures in native certification artifacts.
pub struct RouteCounters {
    shards: Box<[CounterShard]>,
    mask: usize,
}

impl RouteCounters {
    #[must_use]
    pub fn new(shard_count: usize) -> Self {
        let shard_count = shard_count.clamp(1, 4096).next_power_of_two();
        let shards = std::iter::repeat_with(CounterShard::default)
            .take(shard_count)
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            shards,
            mask: shard_count - 1,
        }
    }

    #[inline]
    pub fn record_owner_local(&self, slot: u16) {
        self.shard(slot)
            .owner_local_operations
            .fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_compatibility_forward(&self, slot: u16) {
        self.shard(slot)
            .compatibility_forwards
            .fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_point_peer_frame(&self, slot: u16, bytes: u64) {
        let shard = self.shard(slot);
        shard.point_peer_frames.fetch_add(1, Ordering::Relaxed);
        shard.point_peer_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    #[must_use]
    pub fn snapshot(&self) -> RouteCounterValues {
        self.shards
            .iter()
            .fold(RouteCounterValues::default(), |mut values, shard| {
                values.owner_local_operations = values
                    .owner_local_operations
                    .saturating_add(shard.owner_local_operations.load(Ordering::Relaxed));
                values.compatibility_forwards = values
                    .compatibility_forwards
                    .saturating_add(shard.compatibility_forwards.load(Ordering::Relaxed));
                values.point_peer_frames = values
                    .point_peer_frames
                    .saturating_add(shard.point_peer_frames.load(Ordering::Relaxed));
                values.point_peer_bytes = values
                    .point_peer_bytes
                    .saturating_add(shard.point_peer_bytes.load(Ordering::Relaxed));
                values
            })
    }

    #[inline]
    fn shard(&self, slot: u16) -> &CounterShard {
        &self.shards[usize::from(slot) & self.mask]
    }
}

impl Default for RouteCounters {
    fn default() -> Self {
        Self::new(32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_are_exact_across_shards() {
        let counters = RouteCounters::new(8);
        for slot in 0..100 {
            counters.record_owner_local(slot);
        }
        counters.record_compatibility_forward(7);
        counters.record_point_peer_frame(9, 512);
        let snapshot = RouteCounterSnapshot::capture("node-1", 4, 8, &counters);
        assert_eq!(snapshot.counters.owner_local_operations, 100);
        assert_eq!(snapshot.counters.compatibility_forwards, 1);
        assert_eq!(snapshot.counters.point_peer_frames, 1);
        assert_eq!(snapshot.counters.point_peer_bytes, 512);
        assert_eq!(snapshot.topology_epoch, 4);
        assert_eq!(snapshot.execution_version, 8);
    }

    #[test]
    fn shard_count_is_bounded_and_power_of_two() {
        assert_eq!(RouteCounters::new(0).shards.len(), 1);
        assert_eq!(RouteCounters::new(3).shards.len(), 4);
        assert_eq!(RouteCounters::new(usize::MAX).shards.len(), 4096);
    }
}
