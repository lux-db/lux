use bytes::Bytes;
use hashbrown::HashMap;
use ordered_float::OrderedFloat;
use parking_lot::RwLock;
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::hash::{BuildHasher, Hasher};
use std::sync::atomic::{AtomicU32, AtomicUsize};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

pub static USED_MEMORY: AtomicUsize = AtomicUsize::new(0);
pub static LRU_CLOCK: AtomicU32 = AtomicU32::new(0);

/// Subtract from USED_MEMORY without underflow. Clamps to 0 instead of wrapping.
fn mem_sub(amount: usize) {
    USED_MEMORY
        .fetch_update(
            std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed,
            |current| Some(current.saturating_sub(amount)),
        )
        .ok();
}

/// Add to USED_MEMORY.
fn mem_add(amount: usize) {
    USED_MEMORY.fetch_add(amount, std::sync::atomic::Ordering::Relaxed);
}

/// Persistence error counters. Exposed via INFO command so operators can
/// monitor and alert on silent data-safety issues.
pub static PERSISTENCE_ERR_WAL_APPEND: AtomicUsize = AtomicUsize::new(0);
pub static PERSISTENCE_ERR_WAL_FSYNC: AtomicUsize = AtomicUsize::new(0);
pub static PERSISTENCE_ERR_DISK_WRITE: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StreamId {
    pub ms: u64,
    pub seq: u64,
}

impl StreamId {
    pub fn parse(s: &str) -> Option<StreamId> {
        let parts: Vec<&str> = s.splitn(2, '-').collect();
        if parts.is_empty() {
            return None;
        }
        let ms = parts[0].parse::<u64>().ok()?;
        let seq = if parts.len() > 1 {
            parts[1].parse::<u64>().ok()?
        } else {
            0
        };
        Some(StreamId { ms, seq })
    }

    pub fn zero() -> Self {
        StreamId { ms: 0, seq: 0 }
    }
}

impl std::fmt::Display for StreamId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}", self.ms, self.seq)
    }
}

pub struct PendingEntry {
    pub consumer: String,
    pub delivery_time: Instant,
    pub delivery_count: u64,
}

pub struct Consumer {
    pub pel: HashSet<StreamId>,
    pub seen_time: Instant,
}

pub struct ConsumerGroup {
    pub last_delivered_id: StreamId,
    pub consumers: std::collections::HashMap<String, Consumer>,
    pub pel: BTreeMap<StreamId, PendingEntry>,
}

pub struct StreamData {
    pub entries: BTreeMap<StreamId, Vec<(String, Bytes)>>,
    pub last_id: StreamId,
    pub groups: std::collections::HashMap<String, ConsumerGroup>,
}

#[derive(Clone, Default)]
pub(crate) struct FxBuildHasher;

impl BuildHasher for FxBuildHasher {
    type Hasher = FxHasher;
    fn build_hasher(&self) -> FxHasher {
        FxHasher(0xcbf29ce484222325)
    }
}

pub(crate) struct FxHasher(u64);

impl Hasher for FxHasher {
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 ^= b as u64;
            self.0 = self.0.wrapping_mul(0x100000001b3);
        }
    }
    fn write_usize(&mut self, _: usize) {}
    fn write_u8(&mut self, _: u8) {}
    fn write_u16(&mut self, _: u16) {}
    fn write_u32(&mut self, _: u32) {}
    fn write_u64(&mut self, _: u64) {}
    fn finish(&self) -> u64 {
        self.0
    }
}

#[allow(dead_code)]
pub const MAX_SHARDS: usize = 1024;
const WRONGTYPE: &str = "WRONGTYPE Operation against a key holding the wrong kind of value";

pub struct VectorData {
    #[allow(dead_code)]
    pub dims: u32,
    pub data: Vec<f32>,
    pub metadata: Option<String>,
}

pub struct TimeSeriesData {
    pub samples: Vec<(i64, f64)>,
    pub retention: u64,
    pub labels: Vec<(String, String)>,
}

pub enum StoreValue {
    Str(Bytes),
    List(VecDeque<Bytes>),
    Hash(HashMap<String, Bytes>),
    Set(HashSet<String>),
    SortedSet(
        BTreeMap<(OrderedFloat<f64>, String), ()>,
        HashMap<String, f64>,
    ),
    Stream(StreamData),
    Vector(VectorData),
    HyperLogLog(Vec<u8>, u64),
    TimeSeries(TimeSeriesData),
}

impl StoreValue {
    pub fn type_name(&self) -> &'static str {
        match self {
            StoreValue::Str(_) => "string",
            StoreValue::List(_) => "list",
            StoreValue::Hash(_) => "hash",
            StoreValue::Set(_) => "set",
            StoreValue::SortedSet(..) => "zset",
            StoreValue::Stream(_) => "stream",
            StoreValue::Vector(_) => "vector",
            StoreValue::HyperLogLog(..) => "string",
            StoreValue::TimeSeries(_) => "timeseries",
        }
    }
}

pub struct Entry {
    pub value: StoreValue,
    pub expires_at: Option<Instant>,
    pub lru_clock: u32,
}

impl Entry {
    #[inline(always)]
    pub fn is_expired_at(&self, now: Instant) -> bool {
        self.expires_at.is_some_and(|exp| now > exp)
    }
}

#[repr(align(128))]
pub(crate) struct Shard {
    pub(crate) data: HashMap<String, Entry, FxBuildHasher>,
    pub(crate) version: u64,
    pub(crate) used_memory: usize,
}

pub struct Store {
    config: Arc<crate::ServerConfig>,
    shards: Box<[RwLock<Shard>]>,
    pub(crate) vector_index: RwLock<crate::hnsw::HnswIndex>,
    disk_shards: Option<Box<[parking_lot::Mutex<crate::disk::DiskShard>]>>,
    wal_shards: Option<Box<[parking_lot::Mutex<crate::disk::Wal>]>>,
    pub(crate) wal_suppress: std::sync::atomic::AtomicBool,
}

#[inline(always)]
pub(crate) fn fx_hash(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[inline(always)]
fn key_str(key: &[u8]) -> &str {
    std::str::from_utf8(key).unwrap_or("")
}

#[inline(always)]
fn key_string(key: &[u8]) -> String {
    String::from_utf8_lossy(key).into_owned()
}

fn stream_entry_memory(fields: &[(String, Bytes)]) -> usize {
    16 + fields
        .iter()
        .map(|(k, v)| k.len() + v.len() + 32)
        .sum::<usize>()
}

pub fn estimate_entry_memory(key: &str, value: &StoreValue) -> usize {
    let key_overhead = key.len() + 64;
    let val_size = match value {
        StoreValue::Str(s) => s.len(),
        StoreValue::List(l) => l.iter().map(|b| b.len() + 32).sum(),
        StoreValue::Hash(h) => h.iter().map(|(k, v)| k.len() + v.len() + 64).sum(),
        StoreValue::Set(s) => s.iter().map(|m| m.len() + 32).sum(),
        StoreValue::SortedSet(_, scores) => scores.iter().map(|(m, _)| m.len() + 48).sum(),
        StoreValue::Vector(v) => {
            16 + (v.data.len() * 4) + v.metadata.as_ref().map_or(0, |m| m.len())
        }
        StoreValue::HyperLogLog(regs, _) => regs.len(),
        StoreValue::TimeSeries(ts) => {
            ts.samples.len() * 16
                + ts.labels
                    .iter()
                    .map(|(k, v)| k.len() + v.len() + 32)
                    .sum::<usize>()
        }
        StoreValue::Stream(s) => s
            .entries
            .values()
            .map(|fields| stream_entry_memory(fields))
            .sum(),
    };
    key_overhead + val_size
}

impl Store {
    /// Emit a warning from places that only have access to `self`.
    fn emit_warn(&self, event: crate::ServerWarnEvent) {
        crate::emit_warn(&self.config, event);
    }

    /// Emit an error from places that only have access to `self`.
    fn emit_error(&self, event: crate::ServerErrorEvent) {
        crate::emit_error(&self.config, event);
    }

    /// Convert low-level disk rebuild reports into public warning events.
    fn emit_disk_rebuild_report(
        config: &crate::ServerConfig,
        shard: usize,
        report: crate::disk::DiskRebuildReport,
    ) {
        let corrupted_count = report.corrupted_entries.len();
        for entry in report.corrupted_entries {
            crate::emit_warn(
                config,
                crate::ServerWarnEvent::DiskCorruptedEntrySkipped {
                    shard,
                    offset: entry.offset,
                },
            );
        }
        for error in report.parse_errors {
            crate::emit_warn(
                config,
                crate::ServerWarnEvent::DiskEntryParseFailed {
                    shard,
                    offset: error.offset,
                    error: error.error,
                },
            );
        }
        if corrupted_count > 0 {
            crate::emit_warn(
                config,
                crate::ServerWarnEvent::DiskCorruptedEntriesSkipped {
                    shard,
                    entries: corrupted_count,
                },
            );
        }
    }

    #[cfg(test)]
    pub fn new() -> Self {
        Self::new_with_config(Arc::new(crate::ServerConfig::default()))
    }

    pub fn new_with_config(config: Arc<crate::ServerConfig>) -> Self {
        let n = config.shards;
        let shards: Vec<RwLock<Shard>> = (0..n)
            .map(|_| {
                RwLock::new(Shard {
                    data: HashMap::with_hasher(FxBuildHasher),
                    version: 0,
                    used_memory: 0,
                })
            })
            .collect();

        let disk_shard_count = n.min(64);
        let (disk_shards, wal_shards) = if config.storage.mode == crate::disk::StorageMode::Tiered {
            let dir = std::path::Path::new(&config.storage.dir);
            let ds: Vec<parking_lot::Mutex<crate::disk::DiskShard>> = (0..disk_shard_count)
                .map(|i| {
                    // DiskShard records rebuild corruption locally; surface it
                    // through the configured callback while startup is still synchronous.
                    let mut shard = crate::disk::DiskShard::open(dir, i)
                        .unwrap_or_else(|e| panic!("failed to open disk shard {i}: {e}"));
                    Self::emit_disk_rebuild_report(&config, i, shard.take_rebuild_report());
                    parking_lot::Mutex::new(shard)
                })
                .collect();
            let ws: Vec<parking_lot::Mutex<crate::disk::Wal>> = (0..disk_shard_count)
                .map(|i| {
                    parking_lot::Mutex::new(
                        crate::disk::Wal::open(dir, i)
                            .unwrap_or_else(|e| panic!("failed to open WAL {i}: {e}")),
                    )
                })
                .collect();
            (Some(ds.into_boxed_slice()), Some(ws.into_boxed_slice()))
        } else {
            (None, None)
        };

        Self {
            config,
            shards: shards.into_boxed_slice(),
            vector_index: RwLock::new(crate::hnsw::HnswIndex::new(0)),
            disk_shards,
            wal_shards,
            wal_suppress: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub fn config(&self) -> &crate::ServerConfig {
        &self.config
    }

    pub fn shard_count(&self) -> usize {
        self.shards.len()
    }

    #[inline(always)]
    pub(crate) fn shard_index(&self, key: &[u8]) -> usize {
        (fx_hash(key) % self.shards.len() as u64) as usize
    }

    /// Map a key to its disk shard. Disk shards are capped at 64 (fewer than
    /// memory shards) to limit open file descriptors.
    #[inline(always)]
    fn disk_shard_index(&self, key: &[u8]) -> usize {
        match &self.disk_shards {
            Some(ds) => (fx_hash(key) % ds.len() as u64) as usize,
            None => 0,
        }
    }

    pub fn shard_for_key(&self, key: &[u8]) -> usize {
        self.shard_index(key)
    }

    pub fn shard_version(&self, idx: usize) -> u64 {
        self.shards[idx].read().version
    }

    pub fn is_tiered(&self) -> bool {
        self.disk_shards.is_some()
    }

    pub(crate) fn lock_read_shard(&self, idx: usize) -> parking_lot::RwLockReadGuard<'_, Shard> {
        self.shards[idx].read()
    }

    pub(crate) fn lock_write_shard(&self, idx: usize) -> parking_lot::RwLockWriteGuard<'_, Shard> {
        self.shards[idx].write()
    }

    /// Evict a key from memory. In tiered mode, the entry is serialized to
    /// the disk shard BEFORE being removed from memory. If the disk write
    /// fails, the entry stays in memory (no silent data loss). The shard
    /// write lock is dropped before disk I/O to avoid blocking other operations.
    pub fn evict_key(&self, shard_idx: usize, key: &str) {
        if let Some(ref disk_shards) = self.disk_shards {
            let mut shard = self.shards[shard_idx].write();
            if let Some(entry) = shard.data.get(key) {
                if matches!(entry.value, StoreValue::Vector(_)) {
                    let mem = estimate_entry_memory(key, &entry.value);
                    shard.data.remove(key);
                    shard.used_memory = shard.used_memory.saturating_sub(mem);
                    mem_sub(mem);
                    shard.version += 1;
                    return;
                }
                let now = Instant::now();
                let ttl_ms = entry
                    .expires_at
                    .map(|exp| {
                        if exp > now {
                            exp.duration_since(now).as_millis() as i64
                        } else {
                            0
                        }
                    })
                    .unwrap_or(0);
                let dump = self.entry_to_dump(key, &entry.value, ttl_ms);
                drop(shard);

                let disk_idx = (fx_hash(key.as_bytes()) % disk_shards.len() as u64) as usize;
                let mut disk = disk_shards[disk_idx].lock();
                if let Err(e) = disk.put(key, &dump) {
                    PERSISTENCE_ERR_DISK_WRITE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    self.emit_error(crate::ServerErrorEvent::DiskEvictionWriteFailed {
                        key: key.to_string(),
                        error: e.to_string(),
                    });
                    return;
                }
                if disk.should_compact() {
                    if let Err(e) = disk.compact() {
                        self.emit_error(crate::ServerErrorEvent::InlineCompactionFailed {
                            error: e.to_string(),
                        });
                    }
                }
                drop(disk);

                let mut shard = self.shards[shard_idx].write();
                if let Some(entry) = shard.data.remove(key) {
                    let mem = estimate_entry_memory(key, &entry.value);
                    shard.used_memory = shard.used_memory.saturating_sub(mem);
                    mem_sub(mem);
                    shard.version += 1;
                }
            }
        } else {
            let mut shard = self.shards[shard_idx].write();
            if let Some(entry) = shard.data.remove(key) {
                let mem = estimate_entry_memory(key, &entry.value);
                shard.used_memory = shard.used_memory.saturating_sub(mem);
                mem_sub(mem);
                shard.version += 1;
            }
        }
    }

    fn entry_to_dump(&self, key: &str, value: &StoreValue, ttl_ms: i64) -> DumpEntry {
        let dump_value = match value {
            StoreValue::Str(s) => DumpValue::Str(s.to_vec()),
            StoreValue::List(l) => DumpValue::List(l.iter().map(|b| b.to_vec()).collect()),
            StoreValue::Hash(h) => {
                DumpValue::Hash(h.iter().map(|(k, v)| (k.clone(), v.to_vec())).collect())
            }
            StoreValue::Set(s) => DumpValue::Set(s.iter().cloned().collect()),
            StoreValue::SortedSet(_, scores) => {
                DumpValue::SortedSet(scores.iter().map(|(m, s)| (m.clone(), *s)).collect())
            }
            StoreValue::Stream(s) => {
                let entries = s
                    .entries
                    .iter()
                    .map(|(id, fields)| {
                        let flds = fields
                            .iter()
                            .map(|(k, v)| (k.clone(), v.to_vec()))
                            .collect();
                        (id.to_string(), flds)
                    })
                    .collect();
                DumpValue::Stream(entries, s.last_id.to_string())
            }
            StoreValue::Vector(v) => DumpValue::Vector(v.data.clone(), v.metadata.clone()),
            StoreValue::HyperLogLog(regs, cached) => DumpValue::HyperLogLog(regs.clone(), *cached),
            StoreValue::TimeSeries(ts) => {
                DumpValue::TimeSeries(ts.samples.clone(), ts.retention, ts.labels.clone())
            }
        };
        DumpEntry {
            key: key.to_string(),
            value: dump_value,
            ttl_ms,
        }
    }

    /// Promote a cold key from disk back to memory. Called before every
    /// command (reads AND writes) to ensure the entry is hot before operating
    /// on it. Returns true if the key was found on disk and promoted.
    /// For writes like HSET/LPUSH, this preserves existing data that would
    /// otherwise be lost if the command created a new empty entry.
    pub fn try_promote(&self, key: &[u8], now: Instant) -> bool {
        let disk_shards = match &self.disk_shards {
            Some(ds) => ds,
            None => return false,
        };
        let didx = self.disk_shard_index(key);
        let key_string = std::str::from_utf8(key).unwrap_or_default();

        let mut disk = disk_shards[didx].lock();
        if !disk.contains(key_string) {
            return false;
        }

        let result = match disk.get(key_string, now) {
            Ok(Some((value, ttl))) => Some((value, ttl)),
            _ => None,
        };
        disk.remove(key_string);
        drop(disk);

        if let Some((value, ttl)) = result {
            self.load_entry(key_string.to_string(), value, ttl);
            true
        } else {
            false
        }
    }

    pub fn disk_contains(&self, key: &[u8]) -> bool {
        if let Some(ref ds) = self.disk_shards {
            let didx = self.disk_shard_index(key);
            let ks = std::str::from_utf8(key).unwrap_or_default();
            ds[didx].lock().contains_valid(ks, Instant::now())
        } else {
            false
        }
    }

    pub fn disk_key_count(&self) -> usize {
        match &self.disk_shards {
            Some(ds) => ds.iter().map(|d| d.lock().len()).sum(),
            None => 0,
        }
    }

    pub fn disk_usage_bytes(&self) -> usize {
        match &self.disk_shards {
            Some(ds) => ds.iter().map(|d| d.lock().total_size()).sum(),
            None => 0,
        }
    }

    pub fn compact_disk_shards(&self) {
        if let Some(ref ds) = self.disk_shards {
            for (i, d) in ds.iter().enumerate() {
                let mut disk = d.lock();
                if disk.should_compact() {
                    if let Err(e) = disk.compact() {
                        self.emit_error(crate::ServerErrorEvent::DiskCompactionFailed {
                            shard: i,
                            error: e.to_string(),
                        });
                    }
                }
            }
        }
    }

    /// Append a command to the per-shard WAL. Uses the key (args[1]) to
    /// determine which shard's WAL to write to. Suppressed during WAL replay
    /// and snapshot loading to prevent re-logging replayed commands.
    ///
    /// Global commands (FLUSHDB, FLUSHALL) are written to ALL WAL shards
    /// since they affect the entire keyspace.
    pub fn wal_log_command(&self, args: &[&[u8]]) {
        if self.wal_suppress.load(std::sync::atomic::Ordering::Relaxed) {
            return;
        }
        if args.is_empty() {
            return;
        }
        if let Some(ref ws) = self.wal_shards {
            let cmd = args[0];
            let is_global =
                cmd.eq_ignore_ascii_case(b"FLUSHDB") || cmd.eq_ignore_ascii_case(b"FLUSHALL");

            if is_global {
                // Write to ALL shards so replay on any shard triggers the flush.
                for w in ws.iter() {
                    let mut wal = w.lock();
                    if let Err(e) = wal.append_command(args) {
                        PERSISTENCE_ERR_WAL_APPEND
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        self.emit_error(crate::ServerErrorEvent::WalAppendFailed {
                            error: e.to_string(),
                        });
                    }
                }
            } else if args.len() >= 2 {
                let idx = self.disk_shard_index(args[1]);
                let mut wal = ws[idx].lock();
                if let Err(e) = wal.append_command(args) {
                    PERSISTENCE_ERR_WAL_APPEND.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    self.emit_error(crate::ServerErrorEvent::WalAppendFailed {
                        error: e.to_string(),
                    });
                }
            }
        }
    }

    /// Replay WAL entries by re-executing each command through the normal
    /// command dispatch. Called on startup after snapshot load to recover
    /// writes that happened between the last snapshot and the crash.
    /// WAL logging is suppressed during replay to avoid re-logging.
    pub fn replay_wal(&self, broker: &crate::pubsub::Broker) {
        let ws = match &self.wal_shards {
            Some(ws) => ws,
            None => return,
        };
        self.wal_suppress
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let mut total = 0usize;
        for (i, w) in ws.iter().enumerate() {
            let mut wal = w.lock();
            match wal.replay() {
                Ok(replay) => {
                    let corrupted_count = replay.corrupted_frames.len();
                    for frame in replay.corrupted_frames {
                        self.emit_warn(crate::ServerWarnEvent::WalCorruptedFrameSkipped {
                            shard: i,
                            stored_crc: frame.stored_crc,
                            computed_crc: frame.computed_crc,
                        });
                    }
                    if corrupted_count > 0 {
                        self.emit_warn(crate::ServerWarnEvent::WalCorruptedFramesSkipped {
                            shard: i,
                            frames: corrupted_count,
                        });
                    }
                    for cmd_args in replay.commands {
                        let refs: Vec<&[u8]> = cmd_args.iter().map(|a| a.as_slice()).collect();
                        let mut out = bytes::BytesMut::new();
                        let now = Instant::now();
                        let wal_cache = std::sync::Arc::new(parking_lot::RwLock::new(
                            crate::tables::SchemaCache::new(),
                        ));
                        crate::cmd::execute(self, &wal_cache, broker, &refs, &mut out, now);
                        total += 1;
                    }
                }
                Err(e) => self.emit_error(crate::ServerErrorEvent::WalReplayFailed {
                    shard: i,
                    error: e.to_string(),
                }),
            }
        }
        if total > 0 {
            crate::emit_info(
                &self.config,
                crate::ServerInfoEvent::WalReplayed { commands: total },
            );
        }
        self.wal_suppress
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn truncate_wal(&self) {
        if let Some(ref ws) = self.wal_shards {
            for w in ws.iter() {
                let mut wal = w.lock();
                if let Err(e) = wal.truncate() {
                    self.emit_error(crate::ServerErrorEvent::WalTruncateFailed {
                        error: e.to_string(),
                    });
                }
            }
        }
    }

    pub fn remove_from_disk(&self, key: &[u8]) {
        if let Some(ref ds) = self.disk_shards {
            let didx = self.disk_shard_index(key);
            let ks = std::str::from_utf8(key).unwrap_or_default();
            ds[didx].lock().remove(ks);
        }
    }

    pub fn dump_disk_entries(&self, now: Instant) -> Vec<DumpEntry> {
        match &self.disk_shards {
            Some(ds) => {
                let mut entries = Vec::new();
                for d in ds.iter() {
                    let mut disk = d.lock();
                    match disk.dump_all(now) {
                        Ok(mut de) => entries.append(&mut de),
                        Err(e) => {
                            self.emit_error(crate::ServerErrorEvent::SnapshotDiskDumpFailed {
                                error: e.to_string(),
                            })
                        }
                    }
                }
                entries
            }
            None => Vec::new(),
        }
    }

    /// Flush WAL data to disk. Called by a background task every 1 second
    /// (matching Redis appendfsync everysec). Trades up to 1s of data loss
    /// on power failure for significantly higher write throughput vs per-write fsync.
    pub fn fsync_wal(&self) {
        if let Some(ref ws) = self.wal_shards {
            for w in ws.iter() {
                let mut wal = w.lock();
                if let Err(e) = wal.fsync() {
                    PERSISTENCE_ERR_WAL_FSYNC.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    self.emit_error(crate::ServerErrorEvent::WalFsyncFailed {
                        error: e.to_string(),
                    });
                }
            }
        }
    }

    #[inline(always)]
    pub(crate) fn get_from_shard(
        data: &HashMap<String, Entry, FxBuildHasher>,
        key: &[u8],
        now: Instant,
    ) -> Option<Bytes> {
        let hash = fx_hash(key);
        data.raw_entry()
            .from_hash(hash, |k| k.as_bytes() == key)
            .and_then(|(_, entry)| {
                if entry.is_expired_at(now) {
                    return None;
                }
                match &entry.value {
                    StoreValue::Str(s) => Some(s.clone()),
                    _ => None,
                }
            })
    }

    #[inline(always)]
    pub(crate) fn get_and_write(
        data: &HashMap<String, Entry, FxBuildHasher>,
        key: &[u8],
        now: Instant,
        out: &mut bytes::BytesMut,
    ) {
        let hash = fx_hash(key);
        match data.raw_entry().from_hash(hash, |k| k.as_bytes() == key) {
            Some((_, entry)) if !entry.is_expired_at(now) => {
                if let StoreValue::Str(s) = &entry.value {
                    crate::resp::write_bulk_raw(out, s);
                } else {
                    crate::resp::write_null(out);
                }
            }
            _ => crate::resp::write_null(out),
        }
    }

    #[inline(always)]
    pub(crate) fn set_on_shard(
        data: &mut HashMap<String, Entry, FxBuildHasher>,
        key: &[u8],
        value: &[u8],
        ttl: Option<Duration>,
        now: Instant,
    ) {
        let hash = fx_hash(key);
        let expires_at = ttl.map(|d| now + d);
        let new_value = StoreValue::Str(Bytes::copy_from_slice(value));
        let new_size = estimate_entry_memory(key_str(key), &new_value);
        let clock = LRU_CLOCK.load(std::sync::atomic::Ordering::Relaxed);
        match data
            .raw_entry_mut()
            .from_hash(hash, |k| k.as_bytes() == key)
        {
            hashbrown::hash_map::RawEntryMut::Occupied(mut e) => {
                let old_size = estimate_entry_memory(e.key(), &e.get().value);
                let entry = e.get_mut();
                entry.value = new_value;
                entry.expires_at = expires_at;
                entry.lru_clock = clock;
                if new_size >= old_size {
                    USED_MEMORY
                        .fetch_add(new_size - old_size, std::sync::atomic::Ordering::Relaxed);
                } else {
                    USED_MEMORY
                        .fetch_sub(old_size - new_size, std::sync::atomic::Ordering::Relaxed);
                }
            }
            hashbrown::hash_map::RawEntryMut::Vacant(e) => {
                e.insert_with_hasher(
                    hash,
                    key_string(key),
                    Entry {
                        value: new_value,
                        expires_at,
                        lru_clock: clock,
                    },
                    |k| fx_hash(k.as_bytes()),
                );
                mem_add(new_size);
            }
        }
    }

    pub fn get(&self, key: &[u8], now: Instant) -> Option<Bytes> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        let result = Self::get_from_shard(&shard.data, key, now);
        if result.is_some() {
            return result;
        }
        drop(shard);
        if self.try_promote(key, now) {
            let shard = self.shards[idx].read();
            Self::get_from_shard(&shard.data, key, now)
        } else {
            None
        }
    }

    pub fn get_entry_type(&self, key: &[u8], now: Instant) -> Option<&'static str> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => Some(entry.value.type_name()),
            _ => {
                drop(shard);
                if self.try_promote(key, now) {
                    let shard = self.shards[idx].read();
                    shard.data.get(key_str(key)).map(|e| e.value.type_name())
                } else {
                    None
                }
            }
        }
    }

    pub fn sort_get_elements(&self, key: &[u8], now: Instant) -> Result<Vec<String>, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::List(list) => Ok(list
                    .iter()
                    .map(|b| String::from_utf8_lossy(b).into_owned())
                    .collect()),
                StoreValue::Set(set) => Ok(set.iter().cloned().collect()),
                StoreValue::SortedSet(tree, _) => Ok(tree.keys().map(|(_, m)| m.clone()).collect()),
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(Vec::new()),
        }
    }

    pub fn sort_store(&self, key: &[u8], values: &[String], now: Instant) {
        self.del(&[key]);
        if values.is_empty() {
            return;
        }
        let refs: Vec<&[u8]> = values.iter().map(|s| s.as_bytes()).collect();
        let _ = self.rpush(key, &refs, now);
    }

    pub fn set(&self, key: &[u8], value: &[u8], ttl: Option<Duration>, now: Instant) {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        Self::set_on_shard(&mut shard.data, key, value, ttl, now);
        self.remove_from_disk(key);
    }

    pub fn set_nx(&self, key: &[u8], value: &[u8], now: Instant) -> bool {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        let ks = key_str(key);
        if let Some(entry) = shard.data.get(ks) {
            if !entry.is_expired_at(now) {
                return false;
            }
        }
        let new_value = StoreValue::Str(Bytes::copy_from_slice(value));
        let mem = estimate_entry_memory(ks, &new_value);
        let old = shard.data.insert(
            key_string(key),
            Entry {
                value: new_value,
                expires_at: None,
                lru_clock: LRU_CLOCK.load(std::sync::atomic::Ordering::Relaxed),
            },
        );
        if let Some(old_entry) = old {
            let old_mem = estimate_entry_memory(ks, &old_entry.value);
            if mem >= old_mem {
                mem_add(mem - old_mem);
            } else {
                mem_sub(old_mem - mem);
            }
        } else {
            mem_add(mem);
        }
        true
    }

    pub fn get_set(&self, key: &[u8], value: &[u8], now: Instant) -> Option<Bytes> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        let ks = key_str(key);
        let old = shard.data.get(ks).and_then(|e| {
            if e.is_expired_at(now) {
                None
            } else {
                match &e.value {
                    StoreValue::Str(s) => Some(s.clone()),
                    _ => None,
                }
            }
        });
        let new_value = StoreValue::Str(Bytes::copy_from_slice(value));
        let mem = estimate_entry_memory(ks, &new_value);
        let old_entry = shard.data.insert(
            key_string(key),
            Entry {
                value: new_value,
                expires_at: None,
                lru_clock: LRU_CLOCK.load(std::sync::atomic::Ordering::Relaxed),
            },
        );
        if let Some(oe) = old_entry {
            let old_mem = estimate_entry_memory(ks, &oe.value);
            if mem >= old_mem {
                mem_add(mem - old_mem);
            } else {
                mem_sub(old_mem - mem);
            }
        } else {
            mem_add(mem);
        }
        old
    }

    pub fn strlen(&self, key: &[u8], now: Instant) -> i64 {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Str(s) => s.len() as i64,
                _ => 0,
            },
            _ => 0,
        }
    }

    pub fn del(&self, keys: &[&[u8]]) -> i64 {
        let now = Instant::now();
        let mut count = 0i64;
        let mut vector_keys_removed: Vec<String> = Vec::new();
        for key in keys {
            let idx = self.shard_index(key);
            let mut shard = self.shards[idx].write();
            shard.version += 1;
            if let Some(entry) = shard.data.remove(key_str(key)) {
                let expired = entry.is_expired_at(now);
                let is_vector = matches!(&entry.value, StoreValue::Vector(_));
                let mem = estimate_entry_memory(key_str(key), &entry.value);
                shard.used_memory = shard.used_memory.saturating_sub(mem);
                mem_sub(mem);
                if is_vector {
                    vector_keys_removed.push(key_str(key).to_string());
                }
                if !expired {
                    count += 1;
                }
            } else {
                drop(shard);
                if self.disk_contains(key) {
                    self.remove_from_disk(key);
                    count += 1;
                }
            }
        }
        if !vector_keys_removed.is_empty() {
            let mut index = self.vector_index.write();
            for k in &vector_keys_removed {
                index.remove(k);
            }
        }
        count
    }

    pub fn exists(&self, keys: &[&[u8]], now: Instant) -> i64 {
        let mut count = 0i64;
        for key in keys {
            let idx = self.shard_index(key);
            let shard = self.shards[idx].read();
            if let Some(entry) = shard.data.get(key_str(key)) {
                if !entry.is_expired_at(now) {
                    count += 1;
                    continue;
                }
            }
            drop(shard);
            if self.disk_contains(key) {
                count += 1;
            }
        }
        count
    }

    pub fn incr(&self, key: &[u8], delta: i64, now: Instant) -> Result<i64, String> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        let ks = key_str(key);
        let (current, expires_at) = match shard.data.get(ks) {
            Some(e) if !e.is_expired_at(now) => match &e.value {
                StoreValue::Str(s) => {
                    let s = std::str::from_utf8(s)
                        .map_err(|_| "ERR value is not an integer or out of range".to_string())?;
                    let n = s
                        .parse::<i64>()
                        .map_err(|_| "ERR value is not an integer or out of range".to_string())?;
                    (n, e.expires_at)
                }
                _ => return Err(WRONGTYPE.to_string()),
            },
            _ => (0, None),
        };
        let new_val = current
            .checked_add(delta)
            .ok_or_else(|| "ERR increment or decrement would overflow".to_string())?;
        let new_value = StoreValue::Str(Bytes::from(new_val.to_string()));
        let mem = estimate_entry_memory(ks, &new_value);
        let old_entry = shard.data.insert(
            key_string(key),
            Entry {
                value: new_value,
                expires_at,
                lru_clock: LRU_CLOCK.load(std::sync::atomic::Ordering::Relaxed),
            },
        );
        if let Some(oe) = old_entry {
            let old_mem = estimate_entry_memory(ks, &oe.value);
            if mem >= old_mem {
                mem_add(mem - old_mem);
            } else {
                mem_sub(old_mem - mem);
            }
        } else {
            mem_add(mem);
        }
        Ok(new_val)
    }

    pub fn append(&self, key: &[u8], value: &[u8], now: Instant) -> i64 {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        let ks = key_str(key);
        if let Some(entry) = shard.data.get_mut(ks) {
            if !entry.is_expired_at(now) {
                if let StoreValue::Str(s) = &entry.value {
                    let mut new_val = Vec::with_capacity(s.len() + value.len());
                    new_val.extend_from_slice(s);
                    new_val.extend_from_slice(value);
                    let len = new_val.len() as i64;
                    mem_add(value.len());
                    entry.value = StoreValue::Str(Bytes::from(new_val));
                    entry.lru_clock = LRU_CLOCK.load(std::sync::atomic::Ordering::Relaxed);
                    return len;
                }
            }
        }
        let val = Bytes::copy_from_slice(value);
        let len = val.len() as i64;
        let new_value = StoreValue::Str(val);
        let mem = estimate_entry_memory(ks, &new_value);
        let old_entry = shard.data.insert(
            key_string(key),
            Entry {
                value: new_value,
                expires_at: None,
                lru_clock: LRU_CLOCK.load(std::sync::atomic::Ordering::Relaxed),
            },
        );
        if let Some(oe) = old_entry {
            let old_mem = estimate_entry_memory(ks, &oe.value);
            if mem >= old_mem {
                mem_add(mem - old_mem);
            } else {
                mem_sub(old_mem - mem);
            }
        } else {
            mem_add(mem);
        }
        len
    }

    pub fn keys(&self, pattern: &[u8], now: Instant) -> Vec<String> {
        let pat_str = key_str(pattern);
        let matcher = GlobMatcher::new(pat_str);
        let mut result = Vec::new();
        for shard in self.shards.iter() {
            let shard = shard.read();
            for (k, e) in shard.data.iter() {
                if e.expires_at.is_none_or(|exp| now < exp) && matcher.matches(k) {
                    result.push(k.clone());
                }
            }
        }
        if let Some(ref ds) = self.disk_shards {
            for d in ds.iter() {
                let disk = d.lock();
                for k in disk.keys() {
                    if matcher.matches(k) && !result.contains(k) {
                        result.push(k.clone());
                    }
                }
            }
        }
        result
    }

    pub fn scan(
        &self,
        cursor: usize,
        pattern: &[u8],
        count: usize,
        now: Instant,
    ) -> (usize, Vec<String>) {
        let all_keys = self.keys(pattern, now);
        let start = cursor.min(all_keys.len());
        let end = (start + count).min(all_keys.len());
        let next_cursor = if end >= all_keys.len() { 0 } else { end };
        (next_cursor, all_keys[start..end].to_vec())
    }

    pub fn ttl(&self, key: &[u8], now: Instant) -> i64 {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            None => -2,
            Some(entry) => match entry.expires_at {
                None => -1,
                Some(exp) => {
                    if now > exp {
                        -2
                    } else {
                        exp.duration_since(now).as_secs() as i64
                    }
                }
            },
        }
    }

    pub fn pttl(&self, key: &[u8], now: Instant) -> i64 {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            None => -2,
            Some(entry) => match entry.expires_at {
                None => -1,
                Some(exp) => {
                    if now > exp {
                        -2
                    } else {
                        exp.duration_since(now).as_millis() as i64
                    }
                }
            },
        }
    }

    pub fn expire(&self, key: &[u8], seconds: u64, now: Instant) -> bool {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        if let Some(entry) = shard.data.get_mut(key_str(key)) {
            if !entry.is_expired_at(now) {
                entry.expires_at = Some(now + Duration::from_secs(seconds));
                return true;
            }
        }
        false
    }

    pub fn pexpire(&self, key: &[u8], millis: u64, now: Instant) -> bool {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        if let Some(entry) = shard.data.get_mut(key_str(key)) {
            if !entry.is_expired_at(now) {
                entry.expires_at = Some(now + Duration::from_millis(millis));
                return true;
            }
        }
        false
    }

    pub fn persist(&self, key: &[u8], now: Instant) -> bool {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        if let Some(entry) = shard.data.get_mut(key_str(key)) {
            if !entry.is_expired_at(now) && entry.expires_at.is_some() {
                entry.expires_at = None;
                return true;
            }
        }
        false
    }

    pub fn rename(&self, key: &[u8], new_key: &[u8], now: Instant) -> Result<(), String> {
        let old_idx = self.shard_index(key);
        let entry = {
            let mut shard = self.shards[old_idx].write();
            shard.version += 1;
            match shard.data.remove(key_str(key)) {
                Some(e) if !e.is_expired_at(now) => {
                    let mem = estimate_entry_memory(key_str(key), &e.value);
                    shard.used_memory = shard.used_memory.saturating_sub(mem);
                    mem_sub(mem);
                    e
                }
                _ => return Err("ERR no such key".to_string()),
            }
        };
        let new_idx = self.shard_index(new_key);
        let mut shard = self.shards[new_idx].write();
        shard.version += 1;
        let mem = estimate_entry_memory(key_str(new_key), &entry.value);
        shard.data.insert(key_string(new_key), entry);
        shard.used_memory += mem;
        mem_add(mem);
        Ok(())
    }

    pub fn copy_key(
        &self,
        src: &[u8],
        dst: &[u8],
        replace: bool,
        now: Instant,
    ) -> Result<bool, String> {
        let src_idx = self.shard_index(src);
        let dst_idx = self.shard_index(dst);

        let (dump_val, ttl) = {
            let shard = self.shards[src_idx].read();
            let ks = key_str(src);
            match shard.data.get(ks) {
                Some(entry) if !entry.is_expired_at(now) => {
                    let ttl = entry.expires_at.map(|exp| exp.duration_since(now));
                    let dv = match &entry.value {
                        StoreValue::Str(s) => DumpValue::Str(s.to_vec()),
                        StoreValue::List(l) => {
                            DumpValue::List(l.iter().map(|b| b.to_vec()).collect())
                        }
                        StoreValue::Hash(h) => DumpValue::Hash(
                            h.iter().map(|(k, v)| (k.clone(), v.to_vec())).collect(),
                        ),
                        StoreValue::Set(s) => DumpValue::Set(s.iter().cloned().collect()),
                        StoreValue::SortedSet(_, scores) => DumpValue::SortedSet(
                            scores.iter().map(|(m, s)| (m.clone(), *s)).collect(),
                        ),
                        StoreValue::Stream(s) => {
                            let entries: Vec<StreamDumpEntry> = s
                                .entries
                                .iter()
                                .map(|(id, fields)| {
                                    let flds: Vec<(String, Vec<u8>)> = fields
                                        .iter()
                                        .map(|(k, v)| (k.clone(), v.to_vec()))
                                        .collect();
                                    (id.to_string(), flds)
                                })
                                .collect();
                            DumpValue::Stream(entries, s.last_id.to_string())
                        }
                        StoreValue::Vector(v) => {
                            DumpValue::Vector(v.data.clone(), v.metadata.clone())
                        }
                        StoreValue::HyperLogLog(regs, cached) => {
                            DumpValue::HyperLogLog(regs.clone(), *cached)
                        }
                        StoreValue::TimeSeries(ts) => DumpValue::TimeSeries(
                            ts.samples.clone(),
                            ts.retention,
                            ts.labels.clone(),
                        ),
                    };
                    (dv, ttl)
                }
                _ => return Ok(false),
            }
        };

        if !replace {
            let shard = self.shards[dst_idx].read();
            let ks = key_str(dst);
            if let Some(entry) = shard.data.get(ks) {
                if !entry.is_expired_at(now) {
                    return Ok(false);
                }
            }
        }

        self.load_entry(key_string(dst), dump_val, ttl);
        Ok(true)
    }

    pub fn dbsize(&self, now: Instant) -> i64 {
        let mut total = 0i64;
        for shard in self.shards.iter() {
            let shard = shard.read();
            total += shard
                .data
                .values()
                .filter(|e| e.expires_at.is_none_or(|exp| now < exp))
                .count() as i64;
        }
        total += self.disk_key_count() as i64;
        total
    }

    pub fn flushdb(&self) {
        for shard in self.shards.iter() {
            let mut shard = shard.write();
            shard.version += 1;
            shard.data.clear();
            mem_sub(shard.used_memory);
            shard.used_memory = 0;
        }
        *self.vector_index.write() = crate::hnsw::HnswIndex::new(0);
        if let Some(ref ds) = self.disk_shards {
            for d in ds.iter() {
                let mut disk = d.lock();
                let keys: Vec<String> = disk.keys().cloned().collect();
                for k in keys {
                    disk.remove(&k);
                }
            }
        }
    }

    pub fn lpush(&self, key: &[u8], values: &[&[u8]], now: Instant) -> Result<i64, String> {
        let added_mem: usize = values.iter().map(|v| v.len() + 32).sum();
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        let ks = key_string(key);
        let entry = shard.data.entry(ks).or_insert_with(|| Entry {
            value: StoreValue::List(VecDeque::new()),
            expires_at: None,
            lru_clock: LRU_CLOCK.load(std::sync::atomic::Ordering::Relaxed),
        });
        if entry.is_expired_at(now) {
            entry.value = StoreValue::List(VecDeque::new());
            entry.expires_at = None;
        }
        match &mut entry.value {
            StoreValue::List(list) => {
                for v in values {
                    list.push_front(Bytes::copy_from_slice(v));
                }
                let len = list.len() as i64;
                let _ = entry;
                shard.used_memory += added_mem;
                mem_add(added_mem);
                Ok(len)
            }
            _ => Err(WRONGTYPE.to_string()),
        }
    }

    pub fn rpush(&self, key: &[u8], values: &[&[u8]], now: Instant) -> Result<i64, String> {
        let added_mem: usize = values.iter().map(|v| v.len() + 32).sum();
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        let ks = key_string(key);
        let entry = shard.data.entry(ks).or_insert_with(|| Entry {
            value: StoreValue::List(VecDeque::new()),
            expires_at: None,
            lru_clock: LRU_CLOCK.load(std::sync::atomic::Ordering::Relaxed),
        });
        if entry.is_expired_at(now) {
            entry.value = StoreValue::List(VecDeque::new());
            entry.expires_at = None;
        }
        match &mut entry.value {
            StoreValue::List(list) => {
                for v in values {
                    list.push_back(Bytes::copy_from_slice(v));
                }
                let len = list.len() as i64;
                let _ = entry;
                shard.used_memory += added_mem;
                mem_add(added_mem);
                Ok(len)
            }
            _ => Err(WRONGTYPE.to_string()),
        }
    }

    pub fn lpop(&self, key: &[u8], now: Instant) -> Option<Bytes> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        match shard.data.get_mut(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
                StoreValue::List(list) => {
                    let val = list.pop_front()?;
                    let freed = val.len() + 32;
                    shard.used_memory = shard.used_memory.saturating_sub(freed);
                    mem_sub(freed);
                    Some(val)
                }
                _ => None,
            },
            _ => None,
        }
    }

    pub fn rpop(&self, key: &[u8], now: Instant) -> Option<Bytes> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        match shard.data.get_mut(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
                StoreValue::List(list) => {
                    let val = list.pop_back()?;
                    let freed = val.len() + 32;
                    shard.used_memory = shard.used_memory.saturating_sub(freed);
                    mem_sub(freed);
                    Some(val)
                }
                _ => None,
            },
            _ => None,
        }
    }

    pub fn llen(&self, key: &[u8], now: Instant) -> Result<i64, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::List(list) => Ok(list.len() as i64),
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(0),
        }
    }

    pub fn lrange(
        &self,
        key: &[u8],
        start: i64,
        stop: i64,
        now: Instant,
    ) -> Result<Vec<Bytes>, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::List(list) => {
                    let len = list.len() as i64;
                    let s = if start < 0 {
                        (len + start).max(0) as usize
                    } else {
                        start.min(len) as usize
                    };
                    let e = if stop < 0 {
                        (len + stop + 1).max(0) as usize
                    } else {
                        (stop + 1).min(len) as usize
                    };
                    if s >= e {
                        Ok(vec![])
                    } else {
                        Ok(list.iter().skip(s).take(e - s).cloned().collect())
                    }
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(vec![]),
        }
    }

    pub fn lindex(&self, key: &[u8], index: i64, now: Instant) -> Option<Bytes> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::List(list) => {
                    let i = if index < 0 {
                        (list.len() as i64 + index) as usize
                    } else {
                        index as usize
                    };
                    list.get(i).cloned()
                }
                _ => None,
            },
            _ => None,
        }
    }

    pub fn hset(&self, key: &[u8], pairs: &[(&[u8], &[u8])], now: Instant) -> Result<i64, String> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        let ks = key_string(key);
        let entry = shard.data.entry(ks).or_insert_with(|| Entry {
            value: StoreValue::Hash(HashMap::new()),
            expires_at: None,
            lru_clock: LRU_CLOCK.load(std::sync::atomic::Ordering::Relaxed),
        });
        if entry.is_expired_at(now) {
            entry.value = StoreValue::Hash(HashMap::new());
            entry.expires_at = None;
        }
        match &mut entry.value {
            StoreValue::Hash(map) => {
                let mut added = 0i64;
                let mut mem_delta: isize = 0;
                for (field, value) in pairs {
                    let new_size = (field.len() + value.len() + 64) as isize;
                    if let Some(old_val) =
                        map.insert(key_string(field), Bytes::copy_from_slice(value))
                    {
                        mem_delta += value.len() as isize - old_val.len() as isize;
                    } else {
                        added += 1;
                        mem_delta += new_size;
                    }
                }
                if mem_delta > 0 {
                    shard.used_memory += mem_delta as usize;
                    mem_add(mem_delta as usize);
                } else if mem_delta < 0 {
                    let freed = (-mem_delta) as usize;
                    shard.used_memory = shard.used_memory.saturating_sub(freed);
                    mem_sub(freed);
                }
                Ok(added)
            }
            _ => Err(WRONGTYPE.to_string()),
        }
    }

    pub fn hget(&self, key: &[u8], field: &[u8], now: Instant) -> Option<Bytes> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Hash(map) => map.get(key_str(field)).cloned(),
                _ => None,
            },
            _ => None,
        }
    }

    pub fn hmget(&self, key: &[u8], fields: &[&[u8]], now: Instant) -> Vec<Option<Bytes>> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Hash(map) => fields
                    .iter()
                    .map(|f| map.get(key_str(f)).cloned())
                    .collect(),
                _ => fields.iter().map(|_| None).collect(),
            },
            _ => fields.iter().map(|_| None).collect(),
        }
    }

    pub fn hdel(&self, key: &[u8], fields: &[&[u8]], now: Instant) -> Result<i64, String> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        match shard.data.get_mut(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
                StoreValue::Hash(map) => {
                    let mut removed = 0i64;
                    let mut freed = 0usize;
                    for f in fields {
                        if let Some(old_val) = map.remove(key_str(f)) {
                            freed += f.len() + old_val.len() + 64;
                            removed += 1;
                        }
                    }
                    shard.used_memory = shard.used_memory.saturating_sub(freed);
                    mem_sub(freed);
                    Ok(removed)
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(0),
        }
    }

    pub fn hgetall(&self, key: &[u8], now: Instant) -> Result<Vec<(String, Bytes)>, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Hash(map) => {
                    Ok(map.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(vec![]),
        }
    }

    pub fn hkeys(&self, key: &[u8], now: Instant) -> Result<Vec<String>, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Hash(map) => Ok(map.keys().cloned().collect()),
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(vec![]),
        }
    }

    pub fn hvals(&self, key: &[u8], now: Instant) -> Result<Vec<Bytes>, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Hash(map) => Ok(map.values().cloned().collect()),
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(vec![]),
        }
    }

    pub fn hlen(&self, key: &[u8], now: Instant) -> Result<i64, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Hash(map) => Ok(map.len() as i64),
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(0),
        }
    }

    pub fn hexists(&self, key: &[u8], field: &[u8], now: Instant) -> Result<bool, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Hash(map) => Ok(map.contains_key(key_str(field))),
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(false),
        }
    }

    pub fn hincrby(
        &self,
        key: &[u8],
        field: &[u8],
        delta: i64,
        now: Instant,
    ) -> Result<i64, String> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        let ks = key_string(key);
        let entry = shard.data.entry(ks).or_insert_with(|| Entry {
            value: StoreValue::Hash(HashMap::new()),
            expires_at: None,
            lru_clock: LRU_CLOCK.load(std::sync::atomic::Ordering::Relaxed),
        });
        if entry.is_expired_at(now) {
            entry.value = StoreValue::Hash(HashMap::new());
            entry.expires_at = None;
        }
        match &mut entry.value {
            StoreValue::Hash(map) => {
                let fs = key_str(field);
                let (is_new, old_len) = match map.get(fs) {
                    Some(v) => (false, v.len()),
                    None => (true, 0),
                };
                let current: i64 = map
                    .get(fs)
                    .map(|v| {
                        std::str::from_utf8(v)
                            .ok()
                            .and_then(|s| s.parse::<i64>().ok())
                            .ok_or_else(|| "ERR hash value is not an integer".to_string())
                    })
                    .transpose()?
                    .unwrap_or(0);
                let new_val = current + delta;
                let new_bytes = Bytes::from(new_val.to_string());
                let new_len = new_bytes.len();
                map.insert(fs.to_string(), new_bytes);
                if is_new {
                    let added = field.len() + new_len + 64;
                    let _ = entry;
                    shard.used_memory += added;
                    mem_add(added);
                } else if new_len > old_len {
                    let added = new_len - old_len;
                    let _ = entry;
                    shard.used_memory += added;
                    mem_add(added);
                } else if old_len > new_len {
                    let freed = old_len - new_len;
                    let _ = entry;
                    shard.used_memory = shard.used_memory.saturating_sub(freed);
                    mem_sub(freed);
                }
                Ok(new_val)
            }
            _ => Err(WRONGTYPE.to_string()),
        }
    }

    pub fn sadd(&self, key: &[u8], members: &[&[u8]], now: Instant) -> Result<i64, String> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        let ks = key_string(key);
        let entry = shard.data.entry(ks).or_insert_with(|| Entry {
            value: StoreValue::Set(HashSet::new()),
            expires_at: None,
            lru_clock: LRU_CLOCK.load(std::sync::atomic::Ordering::Relaxed),
        });
        if entry.is_expired_at(now) {
            entry.value = StoreValue::Set(HashSet::new());
            entry.expires_at = None;
        }
        match &mut entry.value {
            StoreValue::Set(set) => {
                let mut added = 0i64;
                let mut mem_added = 0usize;
                for m in members {
                    if set.insert(key_string(m)) {
                        mem_added += m.len() + 32;
                        added += 1;
                    }
                }
                shard.used_memory += mem_added;
                mem_add(mem_added);
                Ok(added)
            }
            _ => Err(WRONGTYPE.to_string()),
        }
    }

    pub fn srem(&self, key: &[u8], members: &[&[u8]], now: Instant) -> Result<i64, String> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        match shard.data.get_mut(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
                StoreValue::Set(set) => {
                    let mut removed = 0i64;
                    let mut freed = 0usize;
                    for m in members {
                        if set.remove(key_str(m)) {
                            freed += m.len() + 32;
                            removed += 1;
                        }
                    }
                    shard.used_memory = shard.used_memory.saturating_sub(freed);
                    mem_sub(freed);
                    Ok(removed)
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(0),
        }
    }

    pub fn smembers(&self, key: &[u8], now: Instant) -> Result<Vec<String>, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Set(set) => Ok(set.iter().cloned().collect()),
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(vec![]),
        }
    }

    pub fn sismember(&self, key: &[u8], member: &[u8], now: Instant) -> Result<bool, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Set(set) => Ok(set.contains(key_str(member))),
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(false),
        }
    }

    pub fn scard(&self, key: &[u8], now: Instant) -> Result<i64, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Set(set) => Ok(set.len() as i64),
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(0),
        }
    }

    fn collect_set(&self, key: &[u8], now: Instant) -> Result<HashSet<String>, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Set(set) => Ok(set.clone()),
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(HashSet::new()),
        }
    }

    pub fn sunion(&self, keys: &[&[u8]], now: Instant) -> Result<Vec<String>, String> {
        let mut result = HashSet::new();
        for key in keys {
            result.extend(self.collect_set(key, now)?);
        }
        Ok(result.into_iter().collect())
    }

    pub fn sinter(&self, keys: &[&[u8]], now: Instant) -> Result<Vec<String>, String> {
        if keys.is_empty() {
            return Ok(vec![]);
        }
        let mut result = self.collect_set(keys[0], now)?;
        for key in &keys[1..] {
            let set = self.collect_set(key, now)?;
            result.retain(|m| set.contains(m));
        }
        Ok(result.into_iter().collect())
    }

    pub fn sdiff(&self, keys: &[&[u8]], now: Instant) -> Result<Vec<String>, String> {
        if keys.is_empty() {
            return Ok(vec![]);
        }
        let mut result = self.collect_set(keys[0], now)?;
        for key in &keys[1..] {
            let set = self.collect_set(key, now)?;
            result.retain(|m| !set.contains(m));
        }
        Ok(result.into_iter().collect())
    }

    pub fn xadd(
        &self,
        key: &[u8],
        id_input: &str,
        fields: Vec<(String, Bytes)>,
        maxlen: Option<usize>,
        now: Instant,
    ) -> Result<StreamId, String> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        let ks = key_string(key);
        let entry = shard.data.entry(ks).or_insert_with(|| Entry {
            value: StoreValue::Stream(StreamData {
                entries: BTreeMap::new(),
                last_id: StreamId::zero(),
                groups: std::collections::HashMap::new(),
            }),
            expires_at: None,
            lru_clock: LRU_CLOCK.load(std::sync::atomic::Ordering::Relaxed),
        });
        if entry.is_expired_at(now) {
            entry.value = StoreValue::Stream(StreamData {
                entries: BTreeMap::new(),
                last_id: StreamId::zero(),
                groups: std::collections::HashMap::new(),
            });
            entry.expires_at = None;
        }
        match &mut entry.value {
            StoreValue::Stream(stream) => {
                let id = if id_input == "*" {
                    let ms = SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    if ms > stream.last_id.ms {
                        StreamId { ms, seq: 0 }
                    } else {
                        StreamId {
                            ms: stream.last_id.ms,
                            seq: stream.last_id.seq + 1,
                        }
                    }
                } else {
                    let parts: Vec<&str> = id_input.splitn(2, '-').collect();
                    let ms = parts[0].parse::<u64>().map_err(|_| {
                        "ERR Invalid stream ID specified as stream command argument".to_string()
                    })?;
                    let seq = if parts.len() > 1 {
                        if parts[1] == "*" {
                            if ms == stream.last_id.ms {
                                stream.last_id.seq + 1
                            } else {
                                0
                            }
                        } else {
                            parts[1].parse::<u64>().map_err(|_| {
                                "ERR Invalid stream ID specified as stream command argument"
                                    .to_string()
                            })?
                        }
                    } else {
                        0
                    };
                    StreamId { ms, seq }
                };

                if id <= stream.last_id
                    && stream.last_id != StreamId::zero()
                    && (id.ms < stream.last_id.ms
                        || (id.ms == stream.last_id.ms && id.seq <= stream.last_id.seq))
                {
                    return Err("ERR The ID specified in XADD is equal or smaller than the target stream top item".to_string());
                }
                if id == StreamId::zero() && !stream.entries.is_empty() {
                    return Err("ERR The ID specified in XADD is equal or smaller than the target stream top item".to_string());
                }

                stream.last_id = id;
                let added: usize = stream_entry_memory(&fields);
                stream.entries.insert(id, fields);

                let mut trimmed_mem = 0usize;
                if let Some(max) = maxlen {
                    while stream.entries.len() > max {
                        if let Some((_, old_fields)) = stream.entries.pop_first() {
                            trimmed_mem += stream_entry_memory(&old_fields);
                        }
                    }
                }

                let _ = entry;
                if added > trimmed_mem {
                    shard.used_memory += added - trimmed_mem;
                    mem_add(added - trimmed_mem);
                } else if trimmed_mem > added {
                    let freed = trimmed_mem - added;
                    shard.used_memory = shard.used_memory.saturating_sub(freed);
                    mem_sub(freed);
                }

                Ok(id)
            }
            _ => Err(WRONGTYPE.to_string()),
        }
    }

    pub fn xlen(&self, key: &[u8], now: Instant) -> Result<i64, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Stream(s) => Ok(s.entries.len() as i64),
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(0),
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn xrange(
        &self,
        key: &[u8],
        start: StreamId,
        end: StreamId,
        count: Option<usize>,
        now: Instant,
    ) -> Result<Vec<(StreamId, Vec<(String, Bytes)>)>, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Stream(s) => {
                    let mut result = Vec::new();
                    for (id, fields) in s.entries.range(start..=end) {
                        result.push((*id, fields.clone()));
                        if let Some(c) = count {
                            if result.len() >= c {
                                break;
                            }
                        }
                    }
                    Ok(result)
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(vec![]),
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn xrevrange(
        &self,
        key: &[u8],
        end: StreamId,
        start: StreamId,
        count: Option<usize>,
        now: Instant,
    ) -> Result<Vec<(StreamId, Vec<(String, Bytes)>)>, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Stream(s) => {
                    let mut result = Vec::new();
                    for (id, fields) in s.entries.range(start..=end).rev() {
                        result.push((*id, fields.clone()));
                        if let Some(c) = count {
                            if result.len() >= c {
                                break;
                            }
                        }
                    }
                    Ok(result)
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(vec![]),
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn xread(
        &self,
        keys: &[String],
        ids: &[StreamId],
        count: Option<usize>,
        now: Instant,
    ) -> Result<Vec<(String, Vec<(StreamId, Vec<(String, Bytes)>)>)>, String> {
        let mut result = Vec::new();
        for (i, key) in keys.iter().enumerate() {
            let after_id = ids[i];
            let idx = self.shard_index(key.as_bytes());
            let shard = self.shards[idx].read();
            if let Some(entry) = shard.data.get(key.as_str()) {
                if !entry.is_expired_at(now) {
                    if let StoreValue::Stream(s) = &entry.value {
                        let start = StreamId {
                            ms: after_id.ms,
                            seq: after_id.seq + 1,
                        };
                        let mut entries = Vec::new();
                        for (id, fields) in s.entries.range(start..) {
                            entries.push((*id, fields.clone()));
                            if let Some(c) = count {
                                if entries.len() >= c {
                                    break;
                                }
                            }
                        }
                        if !entries.is_empty() {
                            result.push((key.clone(), entries));
                        }
                    }
                }
            }
        }
        Ok(result)
    }

    pub fn xgroup_create(
        &self,
        key: &[u8],
        group: &str,
        id: &str,
        mkstream: bool,
        now: Instant,
    ) -> Result<(), String> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        let ks = key_string(key);

        if mkstream {
            let entry = shard.data.entry(ks.clone()).or_insert_with(|| Entry {
                value: StoreValue::Stream(StreamData {
                    entries: BTreeMap::new(),
                    last_id: StreamId::zero(),
                    groups: std::collections::HashMap::new(),
                }),
                expires_at: None,
                lru_clock: LRU_CLOCK.load(std::sync::atomic::Ordering::Relaxed),
            });
            if entry.is_expired_at(now) {
                entry.value = StoreValue::Stream(StreamData {
                    entries: BTreeMap::new(),
                    last_id: StreamId::zero(),
                    groups: std::collections::HashMap::new(),
                });
                entry.expires_at = None;
            }
        }

        match shard.data.get_mut(&ks) {
            Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
                StoreValue::Stream(s) => {
                    let last_delivered_id = if id == "$" {
                        s.last_id
                    } else {
                        StreamId::parse(id).unwrap_or(StreamId::zero())
                    };
                    s.groups.insert(
                        group.to_string(),
                        ConsumerGroup {
                            last_delivered_id,
                            consumers: std::collections::HashMap::new(),
                            pel: BTreeMap::new(),
                        },
                    );
                    Ok(())
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Err("ERR The XGROUP subcommand requires the key to exist. Note that for CREATE you may want to use the MKSTREAM option to create an empty stream automatically.".to_string()),
        }
    }

    pub fn xgroup_destroy(&self, key: &[u8], group: &str, now: Instant) -> Result<bool, String> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        match shard.data.get_mut(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
                StoreValue::Stream(s) => Ok(s.groups.remove(group).is_some()),
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(false),
        }
    }

    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    pub fn xreadgroup(
        &self,
        group: &str,
        consumer: &str,
        keys: &[String],
        ids: &[String],
        count: Option<usize>,
        noack: bool,
        now: Instant,
    ) -> Result<Vec<(String, Vec<(StreamId, Vec<(String, Bytes)>)>)>, String> {
        let mut result = Vec::new();
        let inst_now = Instant::now();
        for (i, key) in keys.iter().enumerate() {
            let id_str = &ids[i];
            let idx = self.shard_index(key.as_bytes());
            let mut shard = self.shards[idx].write();
            shard.version += 1;
            if let Some(entry) = shard.data.get_mut(key.as_str()) {
                if !entry.is_expired_at(now) {
                    if let StoreValue::Stream(s) = &mut entry.value {
                        let cg = match s.groups.get_mut(group) {
                            Some(g) => g,
                            None => {
                                return Err(format!(
                                    "NOGROUP No such consumer group '{}' for key name '{}'",
                                    group, key
                                ))
                            }
                        };

                        if id_str == ">" {
                            let start = StreamId {
                                ms: cg.last_delivered_id.ms,
                                seq: cg.last_delivered_id.seq + 1,
                            };
                            let mut entries = Vec::new();
                            for (id, fields) in s.entries.range(start..) {
                                entries.push((*id, fields.clone()));
                                if !noack {
                                    cg.pel.insert(
                                        *id,
                                        PendingEntry {
                                            consumer: consumer.to_string(),
                                            delivery_time: inst_now,
                                            delivery_count: 1,
                                        },
                                    );
                                    let c = cg
                                        .consumers
                                        .entry(consumer.to_string())
                                        .or_insert_with(|| Consumer {
                                            pel: HashSet::new(),
                                            seen_time: inst_now,
                                        });
                                    c.pel.insert(*id);
                                    c.seen_time = inst_now;
                                }
                                cg.last_delivered_id = *id;
                                if let Some(c) = count {
                                    if entries.len() >= c {
                                        break;
                                    }
                                }
                            }
                            if !entries.is_empty() {
                                result.push((key.clone(), entries));
                            }
                        } else {
                            let after_id = StreamId::parse(id_str).unwrap_or(StreamId::zero());
                            let c = cg.consumers.entry(consumer.to_string()).or_insert_with(|| {
                                Consumer {
                                    pel: HashSet::new(),
                                    seen_time: inst_now,
                                }
                            });
                            let mut entries = Vec::new();
                            let pending_ids: Vec<StreamId> =
                                c.pel.iter().filter(|id| **id > after_id).cloned().collect();
                            let mut sorted: Vec<StreamId> = pending_ids;
                            sorted.sort();
                            for id in sorted {
                                if let Some(fields) = s.entries.get(&id) {
                                    entries.push((id, fields.clone()));
                                    if let Some(cnt) = count {
                                        if entries.len() >= cnt {
                                            break;
                                        }
                                    }
                                }
                            }
                            result.push((key.clone(), entries));
                        }
                    }
                }
            }
        }
        Ok(result)
    }

    pub fn xack(
        &self,
        key: &[u8],
        group: &str,
        ids: &[StreamId],
        now: Instant,
    ) -> Result<i64, String> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        match shard.data.get_mut(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
                StoreValue::Stream(s) => {
                    let cg = match s.groups.get_mut(group) {
                        Some(g) => g,
                        None => return Ok(0),
                    };
                    let mut acked = 0i64;
                    for id in ids {
                        if let Some(pe) = cg.pel.remove(id) {
                            if let Some(c) = cg.consumers.get_mut(&pe.consumer) {
                                c.pel.remove(id);
                            }
                            acked += 1;
                        }
                    }
                    Ok(acked)
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(0),
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn xpending_summary(
        &self,
        key: &[u8],
        group: &str,
        now: Instant,
    ) -> Result<(i64, Option<StreamId>, Option<StreamId>, Vec<(String, i64)>), String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Stream(s) => {
                    let cg = match s.groups.get(group) {
                        Some(g) => g,
                        None => {
                            return Err(format!(
                                "NOGROUP No such consumer group '{}' for key name '{}'",
                                group,
                                key_str(key)
                            ))
                        }
                    };
                    let count = cg.pel.len() as i64;
                    let min_id = cg.pel.keys().next().cloned();
                    let max_id = cg.pel.keys().next_back().cloned();
                    let mut consumer_counts: std::collections::HashMap<String, i64> =
                        std::collections::HashMap::new();
                    for pe in cg.pel.values() {
                        *consumer_counts.entry(pe.consumer.clone()).or_insert(0) += 1;
                    }
                    let consumers: Vec<(String, i64)> = consumer_counts.into_iter().collect();
                    Ok((count, min_id, max_id, consumers))
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Err(format!(
                "NOGROUP No such consumer group '{}' for key name '{}'",
                group,
                key_str(key)
            )),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn xpending_range(
        &self,
        key: &[u8],
        group: &str,
        start: StreamId,
        end: StreamId,
        count: usize,
        consumer_filter: Option<&str>,
        now: Instant,
    ) -> Result<Vec<(StreamId, String, u64, u64)>, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        let inst_now = Instant::now();
        match shard.data.get(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Stream(s) => {
                    let cg = match s.groups.get(group) {
                        Some(g) => g,
                        None => {
                            return Err(format!(
                                "NOGROUP No such consumer group '{}' for key name '{}'",
                                group,
                                key_str(key)
                            ))
                        }
                    };
                    let mut result = Vec::new();
                    for (id, pe) in cg.pel.range(start..=end) {
                        if let Some(cf) = consumer_filter {
                            if pe.consumer != cf {
                                continue;
                            }
                        }
                        let idle = inst_now.duration_since(pe.delivery_time).as_millis() as u64;
                        result.push((*id, pe.consumer.clone(), idle, pe.delivery_count));
                        if result.len() >= count {
                            break;
                        }
                    }
                    Ok(result)
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Err(format!(
                "NOGROUP No such consumer group '{}' for key name '{}'",
                group,
                key_str(key)
            )),
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn xclaim(
        &self,
        key: &[u8],
        group: &str,
        consumer: &str,
        min_idle_ms: u64,
        ids: &[StreamId],
        now: Instant,
    ) -> Result<Vec<(StreamId, Vec<(String, Bytes)>)>, String> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        let inst_now = Instant::now();
        match shard.data.get_mut(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
                StoreValue::Stream(s) => {
                    let cg = match s.groups.get_mut(group) {
                        Some(g) => g,
                        None => {
                            return Err(format!(
                                "NOGROUP No such consumer group '{}' for key name '{}'",
                                group,
                                key_str(key)
                            ))
                        }
                    };
                    let mut result = Vec::new();
                    for id in ids {
                        if let Some(pe) = cg.pel.get_mut(id) {
                            let idle = inst_now.duration_since(pe.delivery_time).as_millis() as u64;
                            if idle >= min_idle_ms {
                                let old_consumer = pe.consumer.clone();
                                pe.consumer = consumer.to_string();
                                pe.delivery_time = inst_now;
                                pe.delivery_count += 1;
                                if let Some(c) = cg.consumers.get_mut(&old_consumer) {
                                    c.pel.remove(id);
                                }
                                let c =
                                    cg.consumers.entry(consumer.to_string()).or_insert_with(|| {
                                        Consumer {
                                            pel: HashSet::new(),
                                            seen_time: inst_now,
                                        }
                                    });
                                c.pel.insert(*id);
                                c.seen_time = inst_now;
                                if let Some(fields) = s.entries.get(id) {
                                    result.push((*id, fields.clone()));
                                }
                            }
                        }
                    }
                    Ok(result)
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(vec![]),
        }
    }

    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    pub fn xautoclaim(
        &self,
        key: &[u8],
        group: &str,
        consumer: &str,
        min_idle_ms: u64,
        start: StreamId,
        count: Option<usize>,
        now: Instant,
    ) -> Result<
        (
            StreamId,
            Vec<(StreamId, Vec<(String, Bytes)>)>,
            Vec<StreamId>,
        ),
        String,
    > {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        let inst_now = Instant::now();
        match shard.data.get_mut(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
                StoreValue::Stream(s) => {
                    let cg = match s.groups.get_mut(group) {
                        Some(g) => g,
                        None => {
                            return Err(format!(
                                "NOGROUP No such consumer group '{}' for key name '{}'",
                                group,
                                key_str(key)
                            ))
                        }
                    };
                    let max = count.unwrap_or(100);
                    let mut claimed = Vec::new();
                    let mut deleted_ids = Vec::new();
                    let mut next_start = StreamId::zero();
                    let pending_ids: Vec<StreamId> =
                        cg.pel.range(start..).map(|(id, _)| *id).collect();
                    for id in pending_ids {
                        if claimed.len() >= max {
                            next_start = id;
                            break;
                        }
                        if let Some(pe) = cg.pel.get_mut(&id) {
                            let idle = inst_now.duration_since(pe.delivery_time).as_millis() as u64;
                            if idle >= min_idle_ms {
                                let old_consumer = pe.consumer.clone();
                                pe.consumer = consumer.to_string();
                                pe.delivery_time = inst_now;
                                pe.delivery_count += 1;
                                if let Some(c) = cg.consumers.get_mut(&old_consumer) {
                                    c.pel.remove(&id);
                                }
                                let c =
                                    cg.consumers.entry(consumer.to_string()).or_insert_with(|| {
                                        Consumer {
                                            pel: HashSet::new(),
                                            seen_time: inst_now,
                                        }
                                    });
                                c.pel.insert(id);
                                c.seen_time = inst_now;
                                if let Some(fields) = s.entries.get(&id) {
                                    claimed.push((id, fields.clone()));
                                } else {
                                    deleted_ids.push(id);
                                }
                            }
                        }
                    }
                    Ok((next_start, claimed, deleted_ids))
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Err(format!(
                "NOGROUP No such consumer group '{}' for key name '{}'",
                group,
                key_str(key)
            )),
        }
    }

    pub fn xdel(&self, key: &[u8], ids: &[StreamId], now: Instant) -> Result<i64, String> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        match shard.data.get_mut(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
                StoreValue::Stream(s) => {
                    let mut removed = 0i64;
                    let mut freed = 0usize;
                    for id in ids {
                        if let Some(fields) = s.entries.remove(id) {
                            freed += stream_entry_memory(&fields);
                            removed += 1;
                        }
                    }
                    shard.used_memory = shard.used_memory.saturating_sub(freed);
                    mem_sub(freed);
                    Ok(removed)
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(0),
        }
    }

    pub fn xtrim(&self, key: &[u8], maxlen: usize, now: Instant) -> Result<i64, String> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        match shard.data.get_mut(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
                StoreValue::Stream(s) => {
                    let mut trimmed = 0i64;
                    let mut freed = 0usize;
                    while s.entries.len() > maxlen {
                        if let Some((_, fields)) = s.entries.pop_first() {
                            freed += stream_entry_memory(&fields);
                        }
                        trimmed += 1;
                    }
                    shard.used_memory = shard.used_memory.saturating_sub(freed);
                    mem_sub(freed);
                    Ok(trimmed)
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(0),
        }
    }

    pub fn xinfo_stream(&self, key: &[u8], now: Instant) -> Result<Vec<(String, String)>, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Stream(s) => {
                    let mut info = Vec::new();
                    info.push(("length".to_string(), s.entries.len().to_string()));
                    info.push(("last-generated-id".to_string(), s.last_id.to_string()));
                    info.push(("groups".to_string(), s.groups.len().to_string()));
                    if let Some((first_id, _)) = s.entries.iter().next() {
                        info.push(("first-entry-id".to_string(), first_id.to_string()));
                    }
                    if let Some((last_id, _)) = s.entries.iter().next_back() {
                        info.push(("last-entry-id".to_string(), last_id.to_string()));
                    }
                    Ok(info)
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Err("ERR no such key".to_string()),
        }
    }

    pub fn xinfo_groups(
        &self,
        key: &[u8],
        now: Instant,
    ) -> Result<Vec<Vec<(String, String)>>, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Stream(s) => {
                    let mut groups_info = Vec::new();
                    for (name, cg) in &s.groups {
                        let info = vec![
                            ("name".to_string(), name.clone()),
                            ("consumers".to_string(), cg.consumers.len().to_string()),
                            ("pending".to_string(), cg.pel.len().to_string()),
                            (
                                "last-delivered-id".to_string(),
                                cg.last_delivered_id.to_string(),
                            ),
                        ];
                        groups_info.push(info);
                    }
                    Ok(groups_info)
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Err("ERR no such key".to_string()),
        }
    }

    pub fn stream_last_id(&self, key: &[u8], now: Instant) -> Option<StreamId> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Stream(s) => Some(s.last_id),
                _ => None,
            },
            _ => None,
        }
    }

    #[allow(dead_code)]
    pub fn approximate_memory(&self) -> usize {
        USED_MEMORY.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn dump_all(&self, now: Instant) -> Vec<DumpEntry> {
        let mut entries = Vec::new();
        for shard in self.shards.iter() {
            let shard = shard.read();
            for (key, entry) in shard.data.iter() {
                if entry.is_expired_at(now) {
                    continue;
                }
                let ttl_ms = entry
                    .expires_at
                    .map(|exp| exp.duration_since(now).as_millis() as i64)
                    .unwrap_or(0);
                entries.push(DumpEntry {
                    key: key.clone(),
                    value: match &entry.value {
                        StoreValue::Str(s) => DumpValue::Str(s.to_vec()),
                        StoreValue::List(l) => {
                            DumpValue::List(l.iter().map(|b| b.to_vec()).collect())
                        }
                        StoreValue::Hash(h) => DumpValue::Hash(
                            h.iter().map(|(k, v)| (k.clone(), v.to_vec())).collect(),
                        ),
                        StoreValue::Set(s) => DumpValue::Set(s.iter().cloned().collect()),
                        StoreValue::SortedSet(_, scores) => DumpValue::SortedSet(
                            scores.iter().map(|(m, s)| (m.clone(), *s)).collect(),
                        ),
                        StoreValue::Stream(s) => {
                            let entries: Vec<StreamDumpEntry> = s
                                .entries
                                .iter()
                                .map(|(id, fields)| {
                                    let flds: Vec<(String, Vec<u8>)> = fields
                                        .iter()
                                        .map(|(k, v)| (k.clone(), v.to_vec()))
                                        .collect();
                                    (id.to_string(), flds)
                                })
                                .collect();
                            DumpValue::Stream(entries, s.last_id.to_string())
                        }
                        StoreValue::Vector(v) => {
                            DumpValue::Vector(v.data.clone(), v.metadata.clone())
                        }
                        StoreValue::HyperLogLog(regs, cached) => {
                            DumpValue::HyperLogLog(regs.clone(), *cached)
                        }
                        StoreValue::TimeSeries(ts) => DumpValue::TimeSeries(
                            ts.samples.clone(),
                            ts.retention,
                            ts.labels.clone(),
                        ),
                    },
                    ttl_ms,
                });
            }
        }
        let mut disk_entries = self.dump_disk_entries(now);
        entries.append(&mut disk_entries);
        entries
    }

    pub fn load_entry(&self, key: String, value: DumpValue, ttl: Option<Duration>) {
        let idx = self.shard_index(key.as_bytes());
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        let store_value = match value {
            DumpValue::Str(s) => StoreValue::Str(Bytes::from(s)),
            DumpValue::List(l) => StoreValue::List(l.into_iter().map(Bytes::from).collect()),
            DumpValue::Hash(h) => {
                StoreValue::Hash(h.into_iter().map(|(k, v)| (k, Bytes::from(v))).collect())
            }
            DumpValue::Set(s) => StoreValue::Set(s.into_iter().collect()),
            DumpValue::SortedSet(members) => {
                let mut tree = BTreeMap::new();
                let mut scores = HashMap::new();
                for (member, score) in members {
                    tree.insert((OrderedFloat(score), member.clone()), ());
                    scores.insert(member, score);
                }
                StoreValue::SortedSet(tree, scores)
            }
            DumpValue::Stream(entries_data, last_id_str) => {
                let last_id = StreamId::parse(&last_id_str).unwrap_or(StreamId::zero());
                let mut entries = BTreeMap::new();
                for (id_str, fields_data) in entries_data {
                    if let Some(id) = StreamId::parse(&id_str) {
                        let fields: Vec<(String, Bytes)> = fields_data
                            .into_iter()
                            .map(|(k, v)| (k, Bytes::from(v)))
                            .collect();
                        entries.insert(id, fields);
                    }
                }
                StoreValue::Stream(StreamData {
                    entries,
                    last_id,
                    groups: std::collections::HashMap::new(),
                })
            }
            DumpValue::Vector(data, metadata) => {
                let dims = data.len() as u32;
                let index_data = data.clone();
                let key_clone = key.clone();
                let sv = StoreValue::Vector(VectorData {
                    dims,
                    data,
                    metadata,
                });
                let expires_at = ttl.map(|d| Instant::now() + d);
                let mem = estimate_entry_memory(&key, &sv);
                shard.data.insert(
                    key,
                    Entry {
                        value: sv,
                        expires_at,
                        lru_clock: LRU_CLOCK.load(std::sync::atomic::Ordering::Relaxed),
                    },
                );
                shard.used_memory += mem;
                mem_add(mem);
                drop(shard);
                self.vector_index.write().insert(key_clone, index_data);
                return;
            }
            DumpValue::HyperLogLog(regs, cached) => StoreValue::HyperLogLog(regs, cached),
            DumpValue::TimeSeries(samples, retention, labels) => {
                StoreValue::TimeSeries(TimeSeriesData {
                    samples,
                    retention,
                    labels,
                })
            }
        };
        let expires_at = ttl.map(|d| Instant::now() + d);
        let mem = estimate_entry_memory(&key, &store_value);
        shard.data.insert(
            key,
            Entry {
                value: store_value,
                expires_at,
                lru_clock: LRU_CLOCK.load(std::sync::atomic::Ordering::Relaxed),
            },
        );
        shard.used_memory += mem;
        mem_add(mem);
    }

    pub fn getdel(&self, key: &[u8], now: Instant) -> Option<Bytes> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        let ks = key_str(key);
        match shard.data.get(ks) {
            Some(entry) if !entry.is_expired_at(now) => {
                if let StoreValue::Str(_) = &entry.value {
                    let entry = shard.data.remove(ks).unwrap();
                    let freed = estimate_entry_memory(ks, &entry.value);
                    shard.used_memory = shard.used_memory.saturating_sub(freed);
                    mem_sub(freed);
                    if let StoreValue::Str(s) = entry.value {
                        Some(s)
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn getex(
        &self,
        key: &[u8],
        ttl: Option<Duration>,
        persist: bool,
        now: Instant,
    ) -> Option<Bytes> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        let ks = key_str(key);
        match shard.data.get_mut(ks) {
            Some(entry) if !entry.is_expired_at(now) => {
                if persist {
                    entry.expires_at = None;
                } else if let Some(d) = ttl {
                    entry.expires_at = Some(now + d);
                }
                match &entry.value {
                    StoreValue::Str(s) => Some(s.clone()),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    pub fn getrange(&self, key: &[u8], start: i64, end: i64, now: Instant) -> Bytes {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => {
                if let StoreValue::Str(s) = &entry.value {
                    let len = s.len() as i64;
                    let s_i = if start < 0 {
                        (len + start).max(0) as usize
                    } else {
                        start.min(len) as usize
                    };
                    let e_i = if end < 0 {
                        (len + end).max(-1) as usize + 1
                    } else {
                        (end + 1).min(len) as usize
                    };
                    if s_i >= e_i {
                        Bytes::new()
                    } else {
                        s.slice(s_i..e_i)
                    }
                } else {
                    Bytes::new()
                }
            }
            _ => Bytes::new(),
        }
    }

    pub fn setrange(&self, key: &[u8], offset: usize, value: &[u8], now: Instant) -> i64 {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        let ks = key_string(key);
        let entry = shard.data.entry(ks).or_insert_with(|| Entry {
            value: StoreValue::Str(Bytes::new()),
            expires_at: None,
            lru_clock: LRU_CLOCK.load(std::sync::atomic::Ordering::Relaxed),
        });
        if entry.is_expired_at(now) {
            entry.value = StoreValue::Str(Bytes::new());
            entry.expires_at = None;
        }
        if let StoreValue::Str(s) = &entry.value {
            let old_len = s.len();
            let mut buf = s.to_vec();
            let needed = offset + value.len();
            if buf.len() < needed {
                buf.resize(needed, 0);
            }
            buf[offset..offset + value.len()].copy_from_slice(value);
            let new_len = buf.len();
            let len = new_len as i64;
            entry.value = StoreValue::Str(Bytes::from(buf));
            if new_len > old_len {
                let added = new_len - old_len;
                let _ = entry;
                shard.used_memory += added;
                mem_add(added);
            }
            len
        } else {
            0
        }
    }

    pub fn msetnx(&self, pairs: &[(&[u8], &[u8])], now: Instant) -> bool {
        for (key, _) in pairs {
            if self.get(key, now).is_some() {
                return false;
            }
        }
        for (key, value) in pairs {
            self.set(key, value, None, now);
        }
        true
    }

    pub fn setbit(&self, key: &[u8], offset: u64, value: u8, now: Instant) -> Result<u8, String> {
        let byte_idx = (offset / 8) as usize;
        let bit_idx = 7 - (offset % 8) as u8;
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        let ks = key_string(key);
        let entry = shard.data.entry(ks).or_insert_with(|| Entry {
            value: StoreValue::Str(Bytes::new()),
            expires_at: None,
            lru_clock: LRU_CLOCK.load(std::sync::atomic::Ordering::Relaxed),
        });
        if entry.is_expired_at(now) {
            entry.value = StoreValue::Str(Bytes::new());
            entry.expires_at = None;
        }
        match &entry.value {
            StoreValue::Str(s) => {
                let old_len = s.len();
                let mut buf = s.to_vec();
                if buf.len() <= byte_idx {
                    buf.resize(byte_idx + 1, 0);
                }
                let new_len = buf.len();
                let old = (buf[byte_idx] >> bit_idx) & 1;
                if value == 1 {
                    buf[byte_idx] |= 1 << bit_idx;
                } else {
                    buf[byte_idx] &= !(1 << bit_idx);
                }
                entry.value = StoreValue::Str(Bytes::from(buf));
                if new_len > old_len {
                    let added = new_len - old_len;
                    let _ = entry;
                    shard.used_memory += added;
                    mem_add(added);
                }
                Ok(old)
            }
            _ => Err(WRONGTYPE.to_string()),
        }
    }

    pub fn getbit(&self, key: &[u8], offset: u64, now: Instant) -> Result<u8, String> {
        let byte_idx = (offset / 8) as usize;
        let bit_idx = 7 - (offset % 8) as u8;
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Str(s) => {
                    if byte_idx >= s.len() {
                        Ok(0)
                    } else {
                        Ok((s[byte_idx] >> bit_idx) & 1)
                    }
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(0),
        }
    }

    pub fn bitcount(
        &self,
        key: &[u8],
        start: i64,
        end: i64,
        use_bit: bool,
        now: Instant,
    ) -> Result<i64, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Str(s) => {
                    if use_bit {
                        let bit_len = s.len() as i64 * 8;
                        let s_idx = if start < 0 {
                            (bit_len + start).max(0) as usize
                        } else {
                            (start as usize).min(bit_len as usize)
                        };
                        let e_idx = if end < 0 {
                            (bit_len + end).max(0) as usize
                        } else {
                            (end as usize).min(bit_len as usize - 1)
                        };
                        if s_idx > e_idx {
                            return Ok(0);
                        }
                        let mut count = 0i64;
                        for i in s_idx..=e_idx {
                            let byte_pos = i / 8;
                            let bit_pos = 7 - (i % 8);
                            if byte_pos < s.len() && (s[byte_pos] >> bit_pos) & 1 == 1 {
                                count += 1;
                            }
                        }
                        Ok(count)
                    } else {
                        let len = s.len() as i64;
                        let s_resolved = if start < 0 { len + start } else { start };
                        let e_resolved = if end < 0 { len + end } else { end };
                        if s_resolved > e_resolved {
                            return Ok(0);
                        }
                        let s_idx = s_resolved.max(0) as usize;
                        let e_idx =
                            e_resolved.max(0).min(if len > 0 { len - 1 } else { 0 }) as usize;
                        if s_idx > e_idx || s.is_empty() {
                            return Ok(0);
                        }
                        let mut count = 0i64;
                        for &byte in &s[s_idx..=e_idx] {
                            count += byte.count_ones() as i64;
                        }
                        Ok(count)
                    }
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(0),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn bitpos(
        &self,
        key: &[u8],
        bit: u8,
        start: i64,
        end: Option<i64>,
        end_given: bool,
        use_bit: bool,
        now: Instant,
    ) -> Result<i64, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Str(s) => {
                    if s.is_empty() {
                        return if bit == 1 { Ok(-1) } else { Ok(0) };
                    }
                    if use_bit {
                        let bit_len = s.len() as i64 * 8;
                        let s_idx = if start < 0 {
                            (bit_len + start).max(0) as usize
                        } else {
                            start as usize
                        };
                        let e_idx = match end {
                            Some(e) => {
                                if e < 0 {
                                    (bit_len + e).max(0) as usize
                                } else {
                                    (e as usize).min(bit_len as usize - 1)
                                }
                            }
                            None => bit_len as usize - 1,
                        };
                        if s_idx > e_idx {
                            return Ok(-1);
                        }
                        for i in s_idx..=e_idx {
                            let byte_pos = i / 8;
                            let bit_pos = 7 - (i % 8);
                            if byte_pos < s.len() {
                                let b = (s[byte_pos] >> bit_pos) & 1;
                                if b == bit {
                                    return Ok(i as i64);
                                }
                            }
                        }
                        Ok(-1)
                    } else {
                        let len = s.len() as i64;
                        let s_byte = if start < 0 {
                            (len + start).max(0) as usize
                        } else {
                            (start as usize).min(len as usize)
                        };
                        let e_byte = match end {
                            Some(e) => {
                                if e < 0 {
                                    (len + e).max(0) as usize
                                } else {
                                    (e as usize).min(len as usize - 1)
                                }
                            }
                            None => len as usize - 1,
                        };
                        if s_byte > e_byte {
                            return Ok(-1);
                        }
                        for i in s_byte..=e_byte {
                            for b in 0..8u8 {
                                let bit_val = (s[i] >> (7 - b)) & 1;
                                if bit_val == bit {
                                    return Ok((i * 8 + b as usize) as i64);
                                }
                            }
                        }
                        if bit == 0 && !end_given {
                            Ok((e_byte + 1) as i64 * 8)
                        } else {
                            Ok(-1)
                        }
                    }
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => {
                if bit == 0 {
                    Ok(0)
                } else {
                    Ok(-1)
                }
            }
        }
    }

    pub fn bitop(
        &self,
        op: &str,
        dest: &[u8],
        keys: &[&[u8]],
        now: Instant,
    ) -> Result<usize, String> {
        let mut sources: Vec<Vec<u8>> = Vec::with_capacity(keys.len());
        let mut max_len = 0usize;
        for key in keys {
            let idx = self.shard_index(key);
            let shard = self.shards[idx].read();
            match shard.data.get(key_str(key)) {
                Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                    StoreValue::Str(s) => {
                        max_len = max_len.max(s.len());
                        sources.push(s.to_vec());
                    }
                    _ => return Err(WRONGTYPE.to_string()),
                },
                _ => {
                    sources.push(Vec::new());
                }
            }
        }
        if max_len == 0 {
            self.del(&[dest]);
            return Ok(0);
        }
        let mut result = vec![0u8; max_len];
        match op {
            "AND" => {
                result.fill(0xff);
                for src in &sources {
                    for i in 0..max_len {
                        let b = if i < src.len() { src[i] } else { 0 };
                        result[i] &= b;
                    }
                }
            }
            "OR" => {
                for src in &sources {
                    for i in 0..src.len() {
                        result[i] |= src[i];
                    }
                }
            }
            "XOR" => {
                for src in &sources {
                    for i in 0..src.len() {
                        result[i] ^= src[i];
                    }
                }
            }
            "NOT" => {
                let src = &sources[0];
                for i in 0..max_len {
                    result[i] = if i < src.len() { !src[i] } else { 0xff };
                }
            }
            _ => {
                return Err(format!(
                    "ERR BITOP requires AND, OR, XOR, or NOT, got '{op}'"
                ));
            }
        }
        let len = result.len();
        self.set(dest, &result, None, now);
        Ok(len)
    }

    pub fn tsadd(
        &self,
        key: &[u8],
        timestamp: i64,
        value: f64,
        retention: Option<u64>,
        labels: Option<Vec<(String, String)>>,
        now: Instant,
    ) -> Result<i64, String> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        let ks = key_string(key);
        let entry = shard.data.entry(ks).or_insert_with(|| Entry {
            value: StoreValue::TimeSeries(TimeSeriesData {
                samples: Vec::new(),
                retention: retention.unwrap_or(0),
                labels: labels.clone().unwrap_or_default(),
            }),
            expires_at: None,
            lru_clock: LRU_CLOCK.load(std::sync::atomic::Ordering::Relaxed),
        });
        if entry.is_expired_at(now) {
            entry.value = StoreValue::TimeSeries(TimeSeriesData {
                samples: Vec::new(),
                retention: retention.unwrap_or(0),
                labels: labels.clone().unwrap_or_default(),
            });
            entry.expires_at = None;
        }
        match &mut entry.value {
            StoreValue::TimeSeries(ts) => {
                if let Some(r) = retention {
                    ts.retention = r;
                }
                if let Some(l) = labels {
                    ts.labels = l;
                }
                let pos = ts.samples.binary_search_by_key(&timestamp, |s| s.0);
                let mut added = 0usize;
                match pos {
                    Ok(i) => ts.samples[i].1 = value,
                    Err(i) => {
                        ts.samples.insert(i, (timestamp, value));
                        added = 16;
                    }
                }
                let mut trimmed = 0usize;
                if ts.retention > 0 {
                    let cutoff = timestamp - ts.retention as i64;
                    let keep_from = ts.samples.partition_point(|s| s.0 < cutoff);
                    if keep_from > 0 {
                        trimmed = keep_from * 16;
                        ts.samples.drain(..keep_from);
                    }
                }
                let _ = entry;
                if added > trimmed {
                    shard.used_memory += added - trimmed;
                    mem_add(added - trimmed);
                } else if trimmed > added {
                    let freed = trimmed - added;
                    shard.used_memory = shard.used_memory.saturating_sub(freed);
                    mem_sub(freed);
                }
                Ok(timestamp)
            }
            _ => Err(WRONGTYPE.to_string()),
        }
    }

    pub fn tsget(&self, key: &[u8], now: Instant) -> Result<Option<(i64, f64)>, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::TimeSeries(ts) => Ok(ts.samples.last().copied()),
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(None),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn tsrange(
        &self,
        key: &[u8],
        from: i64,
        to: i64,
        agg: Option<(&str, i64)>,
        count: Option<usize>,
        now: Instant,
    ) -> Result<Vec<(i64, f64)>, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::TimeSeries(ts) => {
                    let start = ts.samples.partition_point(|s| s.0 < from);
                    let end = ts.samples.partition_point(|s| s.0 <= to);
                    let slice = &ts.samples[start..end];

                    if let Some((agg_fn, bucket_ms)) = agg {
                        let result = aggregate_samples(slice, agg_fn, bucket_ms);
                        Ok(match count {
                            Some(n) => result.into_iter().take(n).collect(),
                            None => result,
                        })
                    } else {
                        Ok(match count {
                            Some(n) => slice.iter().take(n).copied().collect(),
                            None => slice.to_vec(),
                        })
                    }
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(Vec::new()),
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn tsinfo(
        &self,
        key: &[u8],
        now: Instant,
    ) -> Result<
        Option<(
            usize,
            Option<(i64, f64)>,
            Option<(i64, f64)>,
            u64,
            Vec<(String, String)>,
        )>,
        String,
    > {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::TimeSeries(ts) => Ok(Some((
                    ts.samples.len(),
                    ts.samples.first().copied(),
                    ts.samples.last().copied(),
                    ts.retention,
                    ts.labels.clone(),
                ))),
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(None),
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn tsmrange(
        &self,
        from: i64,
        to: i64,
        filters: &[(String, String)],
        agg: Option<(&str, i64)>,
        now: Instant,
    ) -> Vec<(String, Vec<(String, String)>, Vec<(i64, f64)>)> {
        let mut results = Vec::new();
        for shard in self.shards.iter() {
            let shard = shard.read();
            for (key, entry) in shard.data.iter() {
                if entry.is_expired_at(now) {
                    continue;
                }
                if let StoreValue::TimeSeries(ts) = &entry.value {
                    let matches = filters
                        .iter()
                        .all(|(fk, fv)| ts.labels.iter().any(|(lk, lv)| lk == fk && lv == fv));
                    if !matches {
                        continue;
                    }
                    let start = ts.samples.partition_point(|s| s.0 < from);
                    let end = ts.samples.partition_point(|s| s.0 <= to);
                    let slice = &ts.samples[start..end];
                    let samples = if let Some((agg_fn, bucket_ms)) = agg {
                        aggregate_samples(slice, agg_fn, bucket_ms)
                    } else {
                        slice.to_vec()
                    };
                    results.push((key.clone(), ts.labels.clone(), samples));
                }
            }
        }
        results
    }

    pub fn unlink(&self, keys: &[&[u8]]) -> i64 {
        self.del(keys)
    }

    pub fn expireat(&self, key: &[u8], timestamp: u64, now: Instant) -> bool {
        let target = std::time::UNIX_EPOCH + Duration::from_secs(timestamp);
        let now_sys = std::time::SystemTime::now();
        if target <= now_sys {
            return false;
        }
        let dur = target.duration_since(now_sys).unwrap_or(Duration::ZERO);
        self.expire(key, dur.as_secs(), now)
    }

    pub fn pexpireat(&self, key: &[u8], timestamp_ms: u64, now: Instant) -> bool {
        let target = std::time::UNIX_EPOCH + Duration::from_millis(timestamp_ms);
        let now_sys = std::time::SystemTime::now();
        if target <= now_sys {
            return false;
        }
        let dur = target.duration_since(now_sys).unwrap_or(Duration::ZERO);
        self.pexpire(key, dur.as_millis() as u64, now)
    }

    pub fn expiretime(&self, key: &[u8], now: Instant) -> i64 {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            None => -2,
            Some(entry) if entry.is_expired_at(now) => -2,
            Some(entry) => match entry.expires_at {
                None => -1,
                Some(exp) => {
                    let remaining = exp.duration_since(now);
                    let now_unix = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default();
                    (now_unix.as_secs() + remaining.as_secs()) as i64
                }
            },
        }
    }

    pub fn pexpiretime(&self, key: &[u8], now: Instant) -> i64 {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            None => -2,
            Some(entry) if entry.is_expired_at(now) => -2,
            Some(entry) => match entry.expires_at {
                None => -1,
                Some(exp) => {
                    let remaining = exp.duration_since(now);
                    let now_unix = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default();
                    (now_unix.as_millis() + remaining.as_millis()) as i64
                }
            },
        }
    }

    pub fn lset(&self, key: &[u8], index: i64, value: &[u8], now: Instant) -> Result<(), String> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        let delta = {
            match shard.data.get_mut(key_str(key)) {
                Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
                    StoreValue::List(list) => {
                        let i = if index < 0 {
                            (list.len() as i64 + index) as usize
                        } else {
                            index as usize
                        };
                        if i >= list.len() {
                            return Err("ERR index out of range".to_string());
                        }
                        let old_len = list[i].len();
                        list[i] = Bytes::copy_from_slice(value);
                        Ok(value.len() as isize - old_len as isize)
                    }
                    _ => Err(WRONGTYPE.to_string()),
                },
                _ => Err("ERR no such key".to_string()),
            }
        }?;
        if delta > 0 {
            shard.used_memory += delta as usize;
            mem_add(delta as usize);
        } else if delta < 0 {
            let freed = (-delta) as usize;
            shard.used_memory = shard.used_memory.saturating_sub(freed);
            mem_sub(freed);
        }
        Ok(())
    }

    pub fn linsert(
        &self,
        key: &[u8],
        before: bool,
        pivot: &[u8],
        value: &[u8],
        now: Instant,
    ) -> Result<i64, String> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        match shard.data.get_mut(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
                StoreValue::List(list) => {
                    if let Some(pos) = list.iter().position(|v| v.as_ref() == pivot) {
                        let insert_at = if before { pos } else { pos + 1 };
                        let added = value.len() + 32;
                        list.insert(insert_at, Bytes::copy_from_slice(value));
                        let len = list.len() as i64;
                        let _ = entry;
                        shard.used_memory += added;
                        mem_add(added);
                        Ok(len)
                    } else {
                        Ok(-1)
                    }
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(0),
        }
    }

    pub fn lrem(&self, key: &[u8], count: i64, value: &[u8], now: Instant) -> Result<i64, String> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        match shard.data.get_mut(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
                StoreValue::List(list) => {
                    let mut removed = 0i64;
                    let elem_size = value.len() + 32;
                    if count > 0 {
                        let mut i = 0;
                        while i < list.len() && removed < count {
                            if list[i].as_ref() == value {
                                list.remove(i);
                                removed += 1;
                            } else {
                                i += 1;
                            }
                        }
                    } else if count < 0 {
                        let mut i = list.len();
                        while i > 0 && removed < count.abs() {
                            i -= 1;
                            if list[i].as_ref() == value {
                                list.remove(i);
                                removed += 1;
                            }
                        }
                    } else {
                        list.retain(|v| {
                            if v.as_ref() == value {
                                removed += 1;
                                false
                            } else {
                                true
                            }
                        });
                    }
                    let freed = removed as usize * elem_size;
                    shard.used_memory = shard.used_memory.saturating_sub(freed);
                    mem_sub(freed);
                    Ok(removed)
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(0),
        }
    }

    pub fn ltrim(&self, key: &[u8], start: i64, stop: i64, now: Instant) -> Result<(), String> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        match shard.data.get_mut(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
                StoreValue::List(list) => {
                    let len = list.len() as i64;
                    let s = if start < 0 {
                        (len + start).max(0) as usize
                    } else {
                        start.min(len) as usize
                    };
                    let e = if stop < 0 {
                        (len + stop + 1).max(0) as usize
                    } else {
                        (stop + 1).min(len) as usize
                    };
                    let before_size: usize = list.iter().map(|b| b.len() + 32).sum();
                    if s >= e {
                        list.clear();
                    } else {
                        let trimmed: VecDeque<Bytes> = list.drain(s..e).collect();
                        *list = trimmed;
                    }
                    let after_size: usize = list.iter().map(|b| b.len() + 32).sum();
                    if before_size > after_size {
                        let freed = before_size - after_size;
                        shard.used_memory = shard.used_memory.saturating_sub(freed);
                        mem_sub(freed);
                    }
                    Ok(())
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(()),
        }
    }

    pub fn lpushx(&self, key: &[u8], values: &[&[u8]], now: Instant) -> i64 {
        let added_mem: usize = values.iter().map(|v| v.len() + 32).sum();
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        let result = match shard.data.get_mut(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
                StoreValue::List(list) => {
                    for v in values {
                        list.push_front(Bytes::copy_from_slice(v));
                    }
                    Some(list.len() as i64)
                }
                _ => None,
            },
            _ => None,
        };
        if let Some(len) = result {
            shard.used_memory += added_mem;
            mem_add(added_mem);
            len
        } else {
            0
        }
    }

    pub fn rpushx(&self, key: &[u8], values: &[&[u8]], now: Instant) -> i64 {
        let added_mem: usize = values.iter().map(|v| v.len() + 32).sum();
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        let result = match shard.data.get_mut(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
                StoreValue::List(list) => {
                    for v in values {
                        list.push_back(Bytes::copy_from_slice(v));
                    }
                    Some(list.len() as i64)
                }
                _ => None,
            },
            _ => None,
        };
        if let Some(len) = result {
            shard.used_memory += added_mem;
            mem_add(added_mem);
            len
        } else {
            0
        }
    }

    pub fn lmove(
        &self,
        src: &[u8],
        dst: &[u8],
        from_left: bool,
        to_left: bool,
        now: Instant,
    ) -> Option<Bytes> {
        let src_idx = self.shard_index(src);
        let val = {
            let mut shard = self.shards[src_idx].write();
            shard.version += 1;
            match shard.data.get_mut(key_str(src)) {
                Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
                    StoreValue::List(list) => {
                        let v = if from_left {
                            list.pop_front()
                        } else {
                            list.pop_back()
                        };
                        if let Some(ref val) = v {
                            let freed = val.len() + 32;
                            shard.used_memory = shard.used_memory.saturating_sub(freed);
                            mem_sub(freed);
                        }
                        v
                    }
                    _ => None,
                },
                _ => None,
            }
        };
        if let Some(v) = &val {
            let dst_idx = self.shard_index(dst);
            let mut shard = self.shards[dst_idx].write();
            shard.version += 1;
            let ks = key_string(dst);
            let entry = shard.data.entry(ks).or_insert_with(|| Entry {
                value: StoreValue::List(VecDeque::new()),
                expires_at: None,
                lru_clock: LRU_CLOCK.load(std::sync::atomic::Ordering::Relaxed),
            });
            if entry.is_expired_at(now) {
                entry.value = StoreValue::List(VecDeque::new());
                entry.expires_at = None;
            }
            if let StoreValue::List(list) = &mut entry.value {
                let added = v.len() + 32;
                if to_left {
                    list.push_front(v.clone());
                } else {
                    list.push_back(v.clone());
                }
                shard.used_memory += added;
                mem_add(added);
            }
        }
        val
    }

    pub fn hsetnx(
        &self,
        key: &[u8],
        field: &[u8],
        value: &[u8],
        now: Instant,
    ) -> Result<bool, String> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        let ks = key_string(key);
        let entry = shard.data.entry(ks).or_insert_with(|| Entry {
            value: StoreValue::Hash(HashMap::new()),
            expires_at: None,
            lru_clock: LRU_CLOCK.load(std::sync::atomic::Ordering::Relaxed),
        });
        if entry.is_expired_at(now) {
            entry.value = StoreValue::Hash(HashMap::new());
            entry.expires_at = None;
        }
        match &mut entry.value {
            StoreValue::Hash(map) => {
                let fs = key_str(field);
                if map.contains_key(fs) {
                    Ok(false)
                } else {
                    let added = field.len() + value.len() + 64;
                    map.insert(fs.to_string(), Bytes::copy_from_slice(value));
                    shard.used_memory += added;
                    mem_add(added);
                    Ok(true)
                }
            }
            _ => Err(WRONGTYPE.to_string()),
        }
    }

    pub fn hincrbyfloat(
        &self,
        key: &[u8],
        field: &[u8],
        delta: f64,
        now: Instant,
    ) -> Result<String, String> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        let ks = key_string(key);
        let entry = shard.data.entry(ks).or_insert_with(|| Entry {
            value: StoreValue::Hash(HashMap::new()),
            expires_at: None,
            lru_clock: LRU_CLOCK.load(std::sync::atomic::Ordering::Relaxed),
        });
        if entry.is_expired_at(now) {
            entry.value = StoreValue::Hash(HashMap::new());
            entry.expires_at = None;
        }
        match &mut entry.value {
            StoreValue::Hash(map) => {
                let fs = key_str(field);
                let (is_new, old_len) = match map.get(fs) {
                    Some(v) => (false, v.len()),
                    None => (true, 0),
                };
                let current: f64 = map
                    .get(fs)
                    .map(|v| {
                        std::str::from_utf8(v)
                            .ok()
                            .and_then(|s| s.parse::<f64>().ok())
                            .ok_or_else(|| "ERR hash value is not a valid float".to_string())
                    })
                    .transpose()?
                    .unwrap_or(0.0);
                let new_val = current + delta;
                let s = format!("{}", new_val);
                let new_len = s.len();
                map.insert(fs.to_string(), Bytes::from(s.clone()));
                if is_new {
                    let added = field.len() + new_len + 64;
                    let _ = entry;
                    shard.used_memory += added;
                    mem_add(added);
                } else if new_len > old_len {
                    let added = new_len - old_len;
                    let _ = entry;
                    shard.used_memory += added;
                    mem_add(added);
                } else if old_len > new_len {
                    let freed = old_len - new_len;
                    let _ = entry;
                    shard.used_memory = shard.used_memory.saturating_sub(freed);
                    mem_sub(freed);
                }
                Ok(s)
            }
            _ => Err(WRONGTYPE.to_string()),
        }
    }

    pub fn hstrlen(&self, key: &[u8], field: &[u8], now: Instant) -> i64 {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Hash(map) => {
                    map.get(key_str(field)).map(|v| v.len() as i64).unwrap_or(0)
                }
                _ => 0,
            },
            _ => 0,
        }
    }

    pub fn spop(&self, key: &[u8], count: usize, now: Instant) -> Result<Vec<String>, String> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        match shard.data.get_mut(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
                StoreValue::Set(set) => {
                    let mut result = Vec::new();
                    let mut freed = 0usize;
                    for _ in 0..count {
                        if set.is_empty() {
                            break;
                        }
                        let member = set.iter().next().unwrap().clone();
                        freed += member.len() + 32;
                        set.remove(&member);
                        result.push(member);
                    }
                    shard.used_memory = shard.used_memory.saturating_sub(freed);
                    mem_sub(freed);
                    Ok(result)
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(vec![]),
        }
    }

    pub fn srandmember(&self, key: &[u8], count: i64, now: Instant) -> Result<Vec<String>, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Set(set) => {
                    if count == 0 || set.is_empty() {
                        return Ok(vec![]);
                    }
                    let members: Vec<&String> = set.iter().collect();
                    let abs_count = count.unsigned_abs() as usize;
                    let result: Vec<String> = members
                        .iter()
                        .take(abs_count)
                        .map(|s| (*s).clone())
                        .collect();
                    Ok(result)
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(vec![]),
        }
    }

    pub fn smove(
        &self,
        src: &[u8],
        dst: &[u8],
        member: &[u8],
        now: Instant,
    ) -> Result<bool, String> {
        let mem_size = member.len() + 32;
        let src_idx = self.shard_index(src);
        let removed = {
            let mut shard = self.shards[src_idx].write();
            shard.version += 1;
            match shard.data.get_mut(key_str(src)) {
                Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
                    StoreValue::Set(set) => {
                        let r = set.remove(key_str(member));
                        if r {
                            shard.used_memory = shard.used_memory.saturating_sub(mem_size);
                            mem_sub(mem_size);
                        }
                        r
                    }
                    _ => return Err(WRONGTYPE.to_string()),
                },
                _ => false,
            }
        };
        if !removed {
            return Ok(false);
        }
        let dst_idx = self.shard_index(dst);
        let mut shard = self.shards[dst_idx].write();
        shard.version += 1;
        let ks = key_string(dst);
        let entry = shard.data.entry(ks).or_insert_with(|| Entry {
            value: StoreValue::Set(HashSet::new()),
            expires_at: None,
            lru_clock: LRU_CLOCK.load(std::sync::atomic::Ordering::Relaxed),
        });
        if entry.is_expired_at(now) {
            entry.value = StoreValue::Set(HashSet::new());
            entry.expires_at = None;
        }
        match &mut entry.value {
            StoreValue::Set(set) => {
                if set.insert(key_string(member)) {
                    let _ = entry;
                    shard.used_memory += mem_size;
                    mem_add(mem_size);
                }
                Ok(true)
            }
            _ => Err(WRONGTYPE.to_string()),
        }
    }

    pub fn smismember(&self, key: &[u8], members: &[&[u8]], now: Instant) -> Vec<bool> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Set(set) => members.iter().map(|m| set.contains(key_str(m))).collect(),
                _ => members.iter().map(|_| false).collect(),
            },
            _ => members.iter().map(|_| false).collect(),
        }
    }

    pub fn sdiffstore(&self, dst: &[u8], keys: &[&[u8]], now: Instant) -> Result<i64, String> {
        let result = self.sdiff(keys, now)?;
        let members: Vec<&[u8]> = result.iter().map(|s| s.as_bytes()).collect();
        self.del(&[dst]);
        if !members.is_empty() {
            let member_refs: Vec<&[u8]> = members;
            self.sadd(dst, &member_refs, now)?;
        }
        Ok(result.len() as i64)
    }

    pub fn sinterstore(&self, dst: &[u8], keys: &[&[u8]], now: Instant) -> Result<i64, String> {
        let result = self.sinter(keys, now)?;
        let members: Vec<&[u8]> = result.iter().map(|s| s.as_bytes()).collect();
        self.del(&[dst]);
        if !members.is_empty() {
            self.sadd(dst, &members, now)?;
        }
        Ok(result.len() as i64)
    }

    pub fn sunionstore(&self, dst: &[u8], keys: &[&[u8]], now: Instant) -> Result<i64, String> {
        let result = self.sunion(keys, now)?;
        let members: Vec<&[u8]> = result.iter().map(|s| s.as_bytes()).collect();
        self.del(&[dst]);
        if !members.is_empty() {
            self.sadd(dst, &members, now)?;
        }
        Ok(result.len() as i64)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn zadd(
        &self,
        key: &[u8],
        members: &[(&[u8], f64)],
        nx: bool,
        xx: bool,
        gt: bool,
        lt: bool,
        ch: bool,
        now: Instant,
    ) -> Result<i64, String> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        let ks = key_string(key);
        let is_new = !shard.data.contains_key(&ks)
            || shard.data.get(&ks).is_some_and(|e| e.is_expired_at(now));
        if xx && is_new {
            return Ok(0);
        }
        let entry = shard.data.entry(ks).or_insert_with(|| Entry {
            value: StoreValue::SortedSet(BTreeMap::new(), HashMap::new()),
            expires_at: None,
            lru_clock: LRU_CLOCK.load(std::sync::atomic::Ordering::Relaxed),
        });
        if entry.is_expired_at(now) {
            entry.value = StoreValue::SortedSet(BTreeMap::new(), HashMap::new());
            entry.expires_at = None;
        }
        match &mut entry.value {
            StoreValue::SortedSet(tree, scores) => {
                let mut added = 0i64;
                let mut changed = 0i64;
                let mut mem_added = 0usize;
                for &(member, score) in members {
                    let ms = key_string(member);
                    if let Some(&old_score) = scores.get(&ms) {
                        if nx {
                            continue;
                        }
                        let update = if gt && lt {
                            score != old_score
                        } else if gt {
                            score > old_score
                        } else if lt {
                            score < old_score
                        } else {
                            true
                        };
                        if update && score != old_score {
                            tree.remove(&(OrderedFloat(old_score), ms.clone()));
                            tree.insert((OrderedFloat(score), ms.clone()), ());
                            scores.insert(ms, score);
                            changed += 1;
                        }
                    } else {
                        if xx {
                            continue;
                        }
                        tree.insert((OrderedFloat(score), ms.clone()), ());
                        scores.insert(ms, score);
                        mem_added += member.len() + 48;
                        added += 1;
                    }
                }
                shard.used_memory += mem_added;
                mem_add(mem_added);
                Ok(if ch { added + changed } else { added })
            }
            _ => Err(WRONGTYPE.to_string()),
        }
    }

    pub fn zscore(&self, key: &[u8], member: &[u8], now: Instant) -> Result<Option<f64>, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::SortedSet(_, scores) => Ok(scores.get(key_str(member)).copied()),
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(None),
        }
    }

    pub fn zrank(
        &self,
        key: &[u8],
        member: &[u8],
        reverse: bool,
        now: Instant,
    ) -> Result<Option<i64>, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::SortedSet(tree, scores) => {
                    let ms = key_str(member);
                    match scores.get(ms) {
                        Some(&score) => {
                            let key = (OrderedFloat(score), ms.to_string());
                            let forward_rank = tree.range(..&key).count();
                            if reverse {
                                Ok(Some((tree.len() - 1 - forward_rank) as i64))
                            } else {
                                Ok(Some(forward_rank as i64))
                            }
                        }
                        None => Ok(None),
                    }
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(None),
        }
    }

    pub fn zrem(&self, key: &[u8], members: &[&[u8]], now: Instant) -> Result<i64, String> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        match shard.data.get_mut(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
                StoreValue::SortedSet(tree, scores) => {
                    let mut removed = 0i64;
                    let mut freed = 0usize;
                    for m in members {
                        let ms = key_str(m);
                        if let Some(score) = scores.remove(ms) {
                            tree.remove(&(OrderedFloat(score), ms.to_string()));
                            freed += m.len() + 48;
                            removed += 1;
                        }
                    }
                    shard.used_memory = shard.used_memory.saturating_sub(freed);
                    mem_sub(freed);
                    Ok(removed)
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(0),
        }
    }

    pub fn zcard(&self, key: &[u8], now: Instant) -> Result<i64, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::SortedSet(_, scores) => Ok(scores.len() as i64),
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(0),
        }
    }

    pub fn zrange(
        &self,
        key: &[u8],
        start: i64,
        stop: i64,
        reverse: bool,
        _with_scores: bool,
        now: Instant,
    ) -> Result<Vec<(String, f64)>, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::SortedSet(tree, _) => {
                    let len = tree.len() as i64;
                    let s = if start < 0 {
                        (len + start).max(0) as usize
                    } else {
                        start.min(len) as usize
                    };
                    let e = if stop < 0 {
                        (len + stop + 1).max(0) as usize
                    } else {
                        (stop + 1).min(len) as usize
                    };
                    if s >= e {
                        return Ok(vec![]);
                    }
                    let items: Vec<(String, f64)> = if reverse {
                        tree.keys()
                            .rev()
                            .skip(s)
                            .take(e - s)
                            .map(|(score, member)| (member.clone(), score.0))
                            .collect()
                    } else {
                        tree.keys()
                            .skip(s)
                            .take(e - s)
                            .map(|(score, member)| (member.clone(), score.0))
                            .collect()
                    };
                    Ok(items)
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(vec![]),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn zrangebyscore(
        &self,
        key: &[u8],
        min: f64,
        max: f64,
        min_exclusive: bool,
        max_exclusive: bool,
        reverse: bool,
        offset: Option<usize>,
        count: Option<usize>,
        _with_scores: bool,
        now: Instant,
    ) -> Result<Vec<(String, f64)>, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::SortedSet(tree, _) => {
                    let range_start = (OrderedFloat(min), String::new());
                    let range_end = (
                        OrderedFloat(max),
                        "\u{ffff}\u{ffff}\u{ffff}\u{ffff}".to_string(),
                    );
                    let iter = tree.range(range_start..=range_end);
                    let filtered: Vec<(String, f64)> = if reverse {
                        iter.rev()
                            .filter(|((s, _), _)| {
                                let sv = s.0;
                                let lo = if min_exclusive { sv > min } else { sv >= min };
                                let hi = if max_exclusive { sv < max } else { sv <= max };
                                lo && hi
                            })
                            .map(|((s, m), _)| (m.clone(), s.0))
                            .collect()
                    } else {
                        iter.filter(|((s, _), _)| {
                            let sv = s.0;
                            let lo = if min_exclusive { sv > min } else { sv >= min };
                            let hi = if max_exclusive { sv < max } else { sv <= max };
                            lo && hi
                        })
                        .map(|((s, m), _)| (m.clone(), s.0))
                        .collect()
                    };
                    let off = offset.unwrap_or(0);
                    let cnt = count.unwrap_or(filtered.len());
                    Ok(filtered.into_iter().skip(off).take(cnt).collect())
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(vec![]),
        }
    }

    pub fn zincrby(
        &self,
        key: &[u8],
        member: &[u8],
        increment: f64,
        now: Instant,
    ) -> Result<f64, String> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        let ks = key_string(key);
        let entry = shard.data.entry(ks).or_insert_with(|| Entry {
            value: StoreValue::SortedSet(BTreeMap::new(), HashMap::new()),
            expires_at: None,
            lru_clock: LRU_CLOCK.load(std::sync::atomic::Ordering::Relaxed),
        });
        if entry.is_expired_at(now) {
            entry.value = StoreValue::SortedSet(BTreeMap::new(), HashMap::new());
            entry.expires_at = None;
        }
        match &mut entry.value {
            StoreValue::SortedSet(tree, scores) => {
                let ms = key_string(member);
                let old = scores.get(&ms).copied().unwrap_or(0.0);
                let new_score = old + increment;
                if old != 0.0 || scores.contains_key(&ms) {
                    tree.remove(&(OrderedFloat(old), ms.clone()));
                }
                tree.insert((OrderedFloat(new_score), ms.clone()), ());
                scores.insert(ms, new_score);
                Ok(new_score)
            }
            _ => Err(WRONGTYPE.to_string()),
        }
    }

    pub fn zcount(
        &self,
        key: &[u8],
        min: f64,
        max: f64,
        min_exclusive: bool,
        max_exclusive: bool,
        now: Instant,
    ) -> Result<i64, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::SortedSet(tree, _) => {
                    let range_start = (OrderedFloat(min), String::new());
                    let range_end = (
                        OrderedFloat(max),
                        "\u{ffff}\u{ffff}\u{ffff}\u{ffff}".to_string(),
                    );
                    let count = tree
                        .range(range_start..=range_end)
                        .filter(|((s, _), _)| {
                            let sv = s.0;
                            let lo = if min_exclusive { sv > min } else { sv >= min };
                            let hi = if max_exclusive { sv < max } else { sv <= max };
                            lo && hi
                        })
                        .count();
                    Ok(count as i64)
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(0),
        }
    }

    pub fn zpopmin(
        &self,
        key: &[u8],
        count: usize,
        now: Instant,
    ) -> Result<Vec<(String, f64)>, String> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        match shard.data.get_mut(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
                StoreValue::SortedSet(tree, scores) => {
                    let mut result = Vec::new();
                    let mut freed = 0usize;
                    for _ in 0..count {
                        if let Some(((score, member), _)) = tree.pop_first() {
                            freed += member.len() + 48;
                            scores.remove(&member);
                            result.push((member, score.0));
                        } else {
                            break;
                        }
                    }
                    shard.used_memory = shard.used_memory.saturating_sub(freed);
                    mem_sub(freed);
                    Ok(result)
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(vec![]),
        }
    }

    pub fn zpopmax(
        &self,
        key: &[u8],
        count: usize,
        now: Instant,
    ) -> Result<Vec<(String, f64)>, String> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        match shard.data.get_mut(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
                StoreValue::SortedSet(tree, scores) => {
                    let mut result = Vec::new();
                    let mut freed = 0usize;
                    for _ in 0..count {
                        if let Some(((score, member), _)) = tree.pop_last() {
                            freed += member.len() + 48;
                            scores.remove(&member);
                            result.push((member, score.0));
                        } else {
                            break;
                        }
                    }
                    shard.used_memory = shard.used_memory.saturating_sub(freed);
                    mem_sub(freed);
                    Ok(result)
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(vec![]),
        }
    }

    fn collect_sorted_set(&self, key: &[u8], now: Instant) -> Result<HashMap<String, f64>, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::SortedSet(_, scores) => Ok(scores.clone()),
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(HashMap::new()),
        }
    }

    pub fn zunionstore(
        &self,
        dst: &[u8],
        keys: &[&[u8]],
        weights: &[f64],
        aggregate: &str,
        now: Instant,
    ) -> Result<i64, String> {
        let mut result: HashMap<String, f64> = HashMap::new();
        for (i, key) in keys.iter().enumerate() {
            let w = weights.get(i).copied().unwrap_or(1.0);
            let set = self.collect_sorted_set(key, now)?;
            for (member, score) in set {
                let weighted = score * w;
                let entry = result.entry(member).or_insert(0.0);
                match aggregate {
                    "MIN" => *entry = entry.min(weighted),
                    "MAX" => *entry = entry.max(weighted),
                    _ => *entry += weighted,
                }
            }
        }
        let count = result.len() as i64;
        self.del(&[dst]);
        if !result.is_empty() {
            let idx = self.shard_index(dst);
            let mut shard = self.shards[idx].write();
            shard.version += 1;
            let mut tree = BTreeMap::new();
            let mut scores = HashMap::new();
            let mut mem = key_str(dst).len() + 64;
            for (member, score) in result {
                mem += member.len() + 48;
                tree.insert((OrderedFloat(score), member.clone()), ());
                scores.insert(member, score);
            }
            shard.data.insert(
                key_string(dst),
                Entry {
                    value: StoreValue::SortedSet(tree, scores),
                    expires_at: None,
                    lru_clock: LRU_CLOCK.load(std::sync::atomic::Ordering::Relaxed),
                },
            );
            shard.used_memory += mem;
            mem_add(mem);
        }
        Ok(count)
    }

    pub fn zinterstore(
        &self,
        dst: &[u8],
        keys: &[&[u8]],
        weights: &[f64],
        aggregate: &str,
        now: Instant,
    ) -> Result<i64, String> {
        if keys.is_empty() {
            self.del(&[dst]);
            return Ok(0);
        }
        let first = self.collect_sorted_set(keys[0], now)?;
        let w0 = weights.first().copied().unwrap_or(1.0);
        let mut result: HashMap<String, f64> =
            first.into_iter().map(|(m, s)| (m, s * w0)).collect();
        for (i, key) in keys[1..].iter().enumerate() {
            let w = weights.get(i + 1).copied().unwrap_or(1.0);
            let set = self.collect_sorted_set(key, now)?;
            result.retain(|member, current| {
                if let Some(&score) = set.get(member) {
                    let weighted = score * w;
                    match aggregate {
                        "MIN" => *current = current.min(weighted),
                        "MAX" => *current = current.max(weighted),
                        _ => *current += weighted,
                    }
                    true
                } else {
                    false
                }
            });
        }
        let count = result.len() as i64;
        self.del(&[dst]);
        if !result.is_empty() {
            let idx = self.shard_index(dst);
            let mut shard = self.shards[idx].write();
            shard.version += 1;
            let mut tree = BTreeMap::new();
            let mut scores = HashMap::new();
            let mut mem = key_str(dst).len() + 64;
            for (member, score) in result {
                mem += member.len() + 48;
                tree.insert((OrderedFloat(score), member.clone()), ());
                scores.insert(member, score);
            }
            shard.data.insert(
                key_string(dst),
                Entry {
                    value: StoreValue::SortedSet(tree, scores),
                    expires_at: None,
                    lru_clock: LRU_CLOCK.load(std::sync::atomic::Ordering::Relaxed),
                },
            );
            shard.used_memory += mem;
            mem_add(mem);
        }
        Ok(count)
    }

    pub fn zdiffstore(&self, dst: &[u8], keys: &[&[u8]], now: Instant) -> Result<i64, String> {
        if keys.is_empty() {
            self.del(&[dst]);
            return Ok(0);
        }
        let mut result = self.collect_sorted_set(keys[0], now)?;
        for key in &keys[1..] {
            let set = self.collect_sorted_set(key, now)?;
            result.retain(|m, _| !set.contains_key(m));
        }
        let count = result.len() as i64;
        self.del(&[dst]);
        if !result.is_empty() {
            let idx = self.shard_index(dst);
            let mut shard = self.shards[idx].write();
            shard.version += 1;
            let mut tree = BTreeMap::new();
            let mut scores = HashMap::new();
            let mut mem = key_str(dst).len() + 64;
            for (member, score) in result {
                mem += member.len() + 48;
                tree.insert((OrderedFloat(score), member.clone()), ());
                scores.insert(member, score);
            }
            shard.data.insert(
                key_string(dst),
                Entry {
                    value: StoreValue::SortedSet(tree, scores),
                    expires_at: None,
                    lru_clock: LRU_CLOCK.load(std::sync::atomic::Ordering::Relaxed),
                },
            );
            shard.used_memory += mem;
            mem_add(mem);
        }
        Ok(count)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn zrangebylex(
        &self,
        key: &[u8],
        min: &str,
        max: &str,
        offset: Option<usize>,
        count: Option<usize>,
        reverse: bool,
        now: Instant,
    ) -> Result<Vec<String>, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::SortedSet(tree, _) => {
                    let all: Vec<&String> = if reverse {
                        tree.keys().rev().map(|(_, m)| m).collect()
                    } else {
                        tree.keys().map(|(_, m)| m).collect()
                    };
                    let filtered: Vec<String> = all
                        .into_iter()
                        .filter(|m| {
                            let lo = if min == "-" {
                                true
                            } else if min.starts_with('(') {
                                m.as_str() > &min[1..]
                            } else if min.starts_with('[') {
                                m.as_str() >= &min[1..]
                            } else {
                                m.as_str() >= min
                            };
                            let hi = if max == "+" {
                                true
                            } else if max.starts_with('(') {
                                m.as_str() < &max[1..]
                            } else if max.starts_with('[') {
                                m.as_str() <= &max[1..]
                            } else {
                                m.as_str() <= max
                            };
                            lo && hi
                        })
                        .cloned()
                        .collect();
                    let off = offset.unwrap_or(0);
                    let cnt = count.unwrap_or(filtered.len());
                    Ok(filtered.into_iter().skip(off).take(cnt).collect())
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(vec![]),
        }
    }

    pub fn zmscore(
        &self,
        key: &[u8],
        members: &[&[u8]],
        now: Instant,
    ) -> Result<Vec<Option<f64>>, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::SortedSet(_, scores) => Ok(members
                    .iter()
                    .map(|m| scores.get(key_str(m)).copied())
                    .collect()),
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(members.iter().map(|_| None).collect()),
        }
    }

    pub fn expire_sweep(&self, now: Instant) {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        now.hash(&mut hasher);
        let seed = hasher.finish() as usize;

        let mut expired_vectors: Vec<String> = Vec::new();
        for (i, shard) in self.shards.iter().enumerate() {
            let should_check = {
                let shard = shard.read();
                !shard.data.is_empty()
            };
            if !should_check {
                continue;
            }

            let mut shard = shard.write();
            let keys: Vec<String> = shard
                .data
                .keys()
                .enumerate()
                .filter(|(j, _)| (*j + seed + i).is_multiple_of(5))
                .take(20)
                .map(|(_, k)| k.clone())
                .collect();
            let mut removed_any = false;
            for key in keys {
                let should_remove = shard.data.get(&key).is_some_and(|e| e.is_expired_at(now));
                if should_remove {
                    if let Some(entry) = shard.data.remove(&key) {
                        let is_vector = matches!(&entry.value, StoreValue::Vector(_));
                        let mem = estimate_entry_memory(&key, &entry.value);
                        shard.used_memory = shard.used_memory.saturating_sub(mem);
                        mem_sub(mem);
                        if is_vector {
                            expired_vectors.push(key);
                        }
                    }
                    removed_any = true;
                }
            }
            if removed_any {
                shard.version += 1;
            }
        }
        if !expired_vectors.is_empty() {
            let mut index = self.vector_index.write();
            for k in &expired_vectors {
                index.remove(k);
            }
        }
    }

    pub fn pfadd(&self, key: &[u8], elements: &[&[u8]], now: Instant) -> Result<i64, String> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        let ks = key_str(key);
        let entry = shard.data.get_mut(ks);
        match entry {
            Some(e) if e.is_expired_at(now) => {
                let old_mem = estimate_entry_memory(ks, &e.value);
                let mut regs = vec![0u8; crate::hll::HLL_REGISTERS];
                let mut changed = false;
                for elem in elements {
                    if crate::hll::hll_add(&mut regs, elem) {
                        changed = true;
                    }
                }
                let cached = crate::hll::hll_count(&regs);
                e.value = StoreValue::HyperLogLog(regs, cached);
                e.expires_at = None;
                e.lru_clock = LRU_CLOCK.load(std::sync::atomic::Ordering::Relaxed);
                let new_mem = estimate_entry_memory(ks, &e.value);
                if new_mem > old_mem {
                    let diff = new_mem - old_mem;
                    shard.used_memory += diff;
                    mem_add(diff);
                } else {
                    let diff = old_mem - new_mem;
                    shard.used_memory = shard.used_memory.saturating_sub(diff);
                    mem_sub(diff);
                }
                Ok(if changed { 1 } else { 0 })
            }
            Some(e) => match &mut e.value {
                StoreValue::HyperLogLog(regs, cached) => {
                    e.lru_clock = LRU_CLOCK.load(std::sync::atomic::Ordering::Relaxed);
                    let mut changed = false;
                    for elem in elements {
                        if crate::hll::hll_add(regs, elem) {
                            changed = true;
                        }
                    }
                    if changed {
                        *cached = crate::hll::hll_count(regs);
                    }
                    Ok(if changed { 1 } else { 0 })
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            None => {
                let mut regs = vec![0u8; crate::hll::HLL_REGISTERS];
                let mut changed = false;
                for elem in elements {
                    if crate::hll::hll_add(&mut regs, elem) {
                        changed = true;
                    }
                }
                let cached = crate::hll::hll_count(&regs);
                let sv = StoreValue::HyperLogLog(regs, cached);
                let mem = estimate_entry_memory(ks, &sv);
                shard.data.insert(
                    key_string(key),
                    Entry {
                        value: sv,
                        expires_at: None,
                        lru_clock: LRU_CLOCK.load(std::sync::atomic::Ordering::Relaxed),
                    },
                );
                shard.used_memory += mem;
                mem_add(mem);
                Ok(if changed { 1 } else { 0 })
            }
        }
    }

    pub fn pfcount(&self, keys: &[&[u8]], now: Instant) -> Result<i64, String> {
        if keys.len() == 1 {
            let idx = self.shard_index(keys[0]);
            let shard = self.shards[idx].read();
            let ks = key_str(keys[0]);
            match shard.data.get(ks) {
                Some(e) if !e.is_expired_at(now) => match &e.value {
                    StoreValue::HyperLogLog(_, cached) => Ok(*cached as i64),
                    _ => Err(WRONGTYPE.to_string()),
                },
                _ => Ok(0),
            }
        } else {
            let mut merged = vec![0u8; crate::hll::HLL_REGISTERS];
            for key in keys {
                let idx = self.shard_index(key);
                let shard = self.shards[idx].read();
                let ks = key_str(key);
                match shard.data.get(ks) {
                    Some(e) if !e.is_expired_at(now) => match &e.value {
                        StoreValue::HyperLogLog(regs, _) => {
                            crate::hll::hll_merge(&mut merged, regs);
                        }
                        _ => return Err(WRONGTYPE.to_string()),
                    },
                    _ => {}
                }
            }
            Ok(crate::hll::hll_count(&merged) as i64)
        }
    }

    pub fn pfmerge(&self, dest: &[u8], sources: &[&[u8]], now: Instant) -> Result<(), String> {
        let mut merged = vec![0u8; crate::hll::HLL_REGISTERS];
        let dest_idx = self.shard_index(dest);
        {
            let shard = self.shards[dest_idx].read();
            let ks = key_str(dest);
            if let Some(e) = shard.data.get(ks) {
                if !e.is_expired_at(now) {
                    match &e.value {
                        StoreValue::HyperLogLog(regs, _) => {
                            crate::hll::hll_merge(&mut merged, regs);
                        }
                        _ => return Err(WRONGTYPE.to_string()),
                    }
                }
            }
        }
        for src in sources {
            let idx = self.shard_index(src);
            let shard = self.shards[idx].read();
            let ks = key_str(src);
            if let Some(e) = shard.data.get(ks) {
                if !e.is_expired_at(now) {
                    match &e.value {
                        StoreValue::HyperLogLog(regs, _) => {
                            crate::hll::hll_merge(&mut merged, regs);
                        }
                        _ => return Err(WRONGTYPE.to_string()),
                    }
                }
            }
        }
        {
            let mut shard = self.shards[dest_idx].write();
            shard.version += 1;
            let ks = key_str(dest);
            let cached = crate::hll::hll_count(&merged);
            let sv = StoreValue::HyperLogLog(merged, cached);
            let new_mem = estimate_entry_memory(ks, &sv);
            if let Some(old) = shard.data.get(ks) {
                let old_mem = estimate_entry_memory(ks, &old.value);
                if new_mem > old_mem {
                    let diff = new_mem - old_mem;
                    shard.used_memory += diff;
                    mem_add(diff);
                } else {
                    let diff = old_mem - new_mem;
                    shard.used_memory = shard.used_memory.saturating_sub(diff);
                    mem_sub(diff);
                }
            } else {
                shard.used_memory += new_mem;
                mem_add(new_mem);
            }
            shard.data.insert(
                key_string(dest),
                Entry {
                    value: sv,
                    expires_at: None,
                    lru_clock: LRU_CLOCK.load(std::sync::atomic::Ordering::Relaxed),
                },
            );
        }
        Ok(())
    }

    pub fn vset(
        &self,
        key: &[u8],
        data: Vec<f32>,
        metadata: Option<String>,
        ttl: Option<Duration>,
        now: Instant,
    ) {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        let ks = key_string(key);
        let dims = data.len() as u32;
        let index_data = data.clone();
        let new_value = StoreValue::Vector(VectorData {
            dims,
            data,
            metadata,
        });
        let new_mem = estimate_entry_memory(&ks, &new_value);
        let expires_at = ttl.map(|d| now + d);
        let clock = LRU_CLOCK.load(std::sync::atomic::Ordering::Relaxed);
        if let Some(old) = shard.data.insert(
            ks.clone(),
            Entry {
                value: new_value,
                expires_at,
                lru_clock: clock,
            },
        ) {
            let old_mem = estimate_entry_memory(&ks, &old.value);
            if new_mem >= old_mem {
                mem_add(new_mem - old_mem);
            } else {
                mem_sub(old_mem - new_mem);
            }
            shard.used_memory = shard.used_memory.saturating_sub(old_mem) + new_mem;
        } else {
            mem_add(new_mem);
            shard.used_memory += new_mem;
        }
        drop(shard);
        self.vector_index.write().insert(ks, index_data);
    }

    pub fn vget(&self, key: &[u8], now: Instant) -> Option<(Vec<f32>, Option<String>)> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        let ks = key_str(key);
        match shard.data.get(ks) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Vector(v) => Some((v.data.clone(), v.metadata.clone())),
                _ => None,
            },
            _ => None,
        }
    }

    pub fn vsearch(
        &self,
        query: &[f32],
        k: usize,
        filter_key: Option<&str>,
        filter_value: Option<&str>,
        now: Instant,
    ) -> Vec<(String, f32, Option<String>)> {
        let has_filter = filter_key.is_some() && filter_value.is_some();
        let fetch_count = if has_filter { k * 10 } else { k };
        let index = self.vector_index.read();
        let candidates = index.search(query, fetch_count);
        drop(index);

        let mut results: Vec<(String, f32, Option<String>)> = Vec::new();
        for (key, sim) in candidates {
            let idx = self.shard_index(key.as_bytes());
            let shard = self.shards[idx].read();
            if let Some(entry) = shard.data.get(&key) {
                if entry.is_expired_at(now) {
                    continue;
                }
                if let StoreValue::Vector(v) = &entry.value {
                    if has_filter {
                        let fk = filter_key.unwrap();
                        let fv = filter_value.unwrap();
                        if let Some(ref meta) = v.metadata {
                            match serde_json::from_str::<serde_json::Value>(meta) {
                                Ok(obj) => {
                                    if obj.get(fk).and_then(|val| val.as_str()) != Some(fv) {
                                        continue;
                                    }
                                }
                                Err(_) => continue,
                            }
                        } else {
                            continue;
                        }
                    }
                    results.push((key, sim, v.metadata.clone()));
                    if results.len() >= k {
                        break;
                    }
                }
            }
        }
        results
    }

    pub fn vcard(&self, _now: Instant) -> usize {
        self.vector_index.read().len()
    }
}

#[inline]
fn aggregate_samples(samples: &[(i64, f64)], agg_fn: &str, bucket_ms: i64) -> Vec<(i64, f64)> {
    if samples.is_empty() || bucket_ms <= 0 {
        return Vec::new();
    }
    let first_ts = samples[0].0;
    let mut results = Vec::new();
    let mut bucket_start = (first_ts / bucket_ms) * bucket_ms;
    let mut bucket_vals: Vec<f64> = Vec::new();

    for &(ts, val) in samples {
        while ts >= bucket_start + bucket_ms {
            if !bucket_vals.is_empty() {
                results.push((bucket_start, compute_agg(&bucket_vals, agg_fn)));
                bucket_vals.clear();
            }
            bucket_start += bucket_ms;
        }
        bucket_vals.push(val);
    }
    if !bucket_vals.is_empty() {
        results.push((bucket_start, compute_agg(&bucket_vals, agg_fn)));
    }
    results
}

fn compute_agg(vals: &[f64], agg_fn: &str) -> f64 {
    match agg_fn {
        "avg" => vals.iter().sum::<f64>() / vals.len() as f64,
        "sum" => vals.iter().sum(),
        "min" => vals.iter().cloned().fold(f64::INFINITY, f64::min),
        "max" => vals.iter().cloned().fold(f64::NEG_INFINITY, f64::max),
        "count" => vals.len() as f64,
        "first" => vals[0],
        "last" => vals[vals.len() - 1],
        "range" => {
            let min = vals.iter().cloned().fold(f64::INFINITY, f64::min);
            let max = vals.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
            max - min
        }
        "std.p" => {
            let mean = vals.iter().sum::<f64>() / vals.len() as f64;
            let var = vals.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / vals.len() as f64;
            var.sqrt()
        }
        "std.s" => {
            if vals.len() < 2 {
                return 0.0;
            }
            let mean = vals.iter().sum::<f64>() / vals.len() as f64;
            let var =
                vals.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (vals.len() - 1) as f64;
            var.sqrt()
        }
        "var.p" => {
            let mean = vals.iter().sum::<f64>() / vals.len() as f64;
            vals.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / vals.len() as f64
        }
        "var.s" => {
            if vals.len() < 2 {
                return 0.0;
            }
            let mean = vals.iter().sum::<f64>() / vals.len() as f64;
            vals.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (vals.len() - 1) as f64
        }
        _ => vals.iter().sum::<f64>() / vals.len() as f64,
    }
}

pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() {
        return 0.0;
    }
    let mut dot = 0.0f32;
    let mut norm_a = 0.0f32;
    let mut norm_b = 0.0f32;
    for i in 0..a.len() {
        dot += a[i] * b[i];
        norm_a += a[i] * a[i];
        norm_b += b[i] * b[i];
    }
    let denom = norm_a.sqrt() * norm_b.sqrt();
    if denom == 0.0 {
        0.0
    } else {
        dot / denom
    }
}

pub type StreamDumpEntry = (String, Vec<(String, Vec<u8>)>);

#[derive(Debug)]
pub enum DumpValue {
    Str(Vec<u8>),
    List(Vec<Vec<u8>>),
    Hash(Vec<(String, Vec<u8>)>),
    Set(Vec<String>),
    SortedSet(Vec<(String, f64)>),
    Stream(Vec<StreamDumpEntry>, String),
    Vector(Vec<f32>, Option<String>),
    HyperLogLog(Vec<u8>, u64),
    TimeSeries(Vec<(i64, f64)>, u64, Vec<(String, String)>),
}

#[derive(Debug)]
pub struct DumpEntry {
    pub key: String,
    pub value: DumpValue,
    pub ttl_ms: i64,
}

struct GlobMatcher {
    pattern: Vec<char>,
}

impl GlobMatcher {
    fn new(pattern: &str) -> Self {
        Self {
            pattern: pattern.chars().collect(),
        }
    }

    fn matches(&self, s: &str) -> bool {
        if self.pattern.len() == 1 && self.pattern[0] == '*' {
            return true;
        }
        let s: Vec<char> = s.chars().collect();
        Self::do_match(&self.pattern, &s)
    }

    /// Iterative glob matching (linear time). Avoids the exponential
    /// backtracking of the naive recursive approach where patterns like
    /// `a*a*a*a*b` against long strings would cause CPU exhaustion.
    fn do_match(pattern: &[char], s: &[char]) -> bool {
        let mut pi = 0;
        let mut si = 0;
        let mut star_pi = usize::MAX; // pattern index of last '*'
        let mut star_si = 0; // string index when last '*' was hit

        while si < s.len() {
            if pi < pattern.len() && (pattern[pi] == '?' || pattern[pi] == s[si]) {
                pi += 1;
                si += 1;
            } else if pi < pattern.len() && pattern[pi] == '*' {
                star_pi = pi;
                star_si = si;
                pi += 1; // try matching '*' with empty string first
            } else if star_pi != usize::MAX {
                // Mismatch: backtrack to last '*' and consume one more char.
                pi = star_pi + 1;
                star_si += 1;
                si = star_si;
            } else {
                return false;
            }
        }

        // Consume trailing '*'s in pattern.
        while pi < pattern.len() && pattern[pi] == '*' {
            pi += 1;
        }
        pi == pattern.len()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn now() -> Instant {
        Instant::now()
    }

    #[test]
    fn set_get_roundtrip() {
        let store = Store::new();
        let n = now();
        store.set(b"key1", b"value1", None, n);
        assert_eq!(store.get(b"key1", n).unwrap(), &b"value1"[..]);
    }

    #[test]
    fn set_with_ttl_expires() {
        let store = Store::new();
        let n = now();
        store.set(b"key1", b"val", Some(Duration::from_millis(1)), n);
        assert!(store.get(b"key1", n).is_some());
        std::thread::sleep(Duration::from_millis(5));
        assert!(store.get(b"key1", Instant::now()).is_none());
    }

    #[test]
    fn incr_nonexistent_creates_one() {
        let store = Store::new();
        let n = now();
        let result = store.incr(b"counter", 1, n).unwrap();
        assert_eq!(result, 1);
        assert_eq!(store.get(b"counter", n).unwrap(), &b"1"[..]);
    }

    #[test]
    fn incr_then_get() {
        let store = Store::new();
        let n = now();
        store.incr(b"counter", 1, n).unwrap();
        store.incr(b"counter", 1, n).unwrap();
        store.incr(b"counter", 1, n).unwrap();
        let val = store.get(b"counter", n).unwrap();
        assert_eq!(val, &b"3"[..]);
    }

    #[test]
    fn set_ex_then_ttl() {
        let store = Store::new();
        let n = now();
        store.set(b"key1", b"val", Some(Duration::from_secs(100)), n);
        let ttl = store.ttl(b"key1", n);
        assert!(ttl > 0 && ttl <= 100);
    }

    #[test]
    fn decrby_overflow() {
        let store = Store::new();
        let n = now();
        store.set(b"key", format!("{}", i64::MIN).as_bytes(), None, n);
        let result = store.incr(b"key", -1, n);
        assert!(result.is_err());
    }

    #[test]
    fn list_push_pop() {
        let store = Store::new();
        let n = now();
        store.lpush(b"list", &[b"a", b"b", b"c"], n).unwrap();
        assert_eq!(store.llen(b"list", n).unwrap(), 3);
        assert_eq!(store.lpop(b"list", n).unwrap(), &b"c"[..]);
        assert_eq!(store.rpop(b"list", n).unwrap(), &b"a"[..]);
    }

    #[test]
    fn hash_operations() {
        let store = Store::new();
        let n = now();
        store
            .hset(
                b"myhash",
                &[(b"f1" as &[u8], b"v1" as &[u8]), (b"f2", b"v2")],
                n,
            )
            .unwrap();
        assert_eq!(store.hget(b"myhash", b"f1", n).unwrap(), &b"v1"[..]);
        assert_eq!(store.hlen(b"myhash", n).unwrap(), 2);
        store.hdel(b"myhash", &[b"f1"], n).unwrap();
        assert_eq!(store.hlen(b"myhash", n).unwrap(), 1);
    }

    #[test]
    fn set_operations() {
        let store = Store::new();
        let n = now();
        store.sadd(b"s1", &[b"a", b"b", b"c"], n).unwrap();
        store.sadd(b"s2", &[b"b", b"c", b"d"], n).unwrap();
        assert_eq!(store.scard(b"s1", n).unwrap(), 3);
        assert!(store.sismember(b"s1", b"a", n).unwrap());
        assert!(!store.sismember(b"s1", b"d", n).unwrap());
    }

    #[test]
    fn del_removes_key() {
        let store = Store::new();
        let n = now();
        store.set(b"key1", b"val", None, n);
        assert_eq!(store.del(&[b"key1"]), 1);
        assert!(store.get(b"key1", n).is_none());
    }

    #[test]
    fn exists_checks_key() {
        let store = Store::new();
        let n = now();
        store.set(b"key1", b"val", None, n);
        assert_eq!(store.exists(&[b"key1"], n), 1);
        assert_eq!(store.exists(&[b"missing"], n), 0);
    }

    #[test]
    fn rename_key() {
        let store = Store::new();
        let n = now();
        store.set(b"old", b"val", None, n);
        store.rename(b"old", b"new", n).unwrap();
        assert!(store.get(b"old", n).is_none());
        assert_eq!(store.get(b"new", n).unwrap(), &b"val"[..]);
    }

    #[test]
    fn fx_hash_consistency() {
        let h1 = fx_hash(b"hello");
        let h2 = fx_hash(b"hello");
        assert_eq!(h1, h2);
        let h3 = fx_hash(b"world");
        assert_ne!(h1, h3);
    }

    #[test]
    fn sorted_set_zadd_zscore() {
        let store = Store::new();
        let n = now();
        store
            .zadd(
                b"zs",
                &[(b"alice" as &[u8], 1.0), (b"bob", 2.0)],
                false,
                false,
                false,
                false,
                false,
                n,
            )
            .unwrap();
        assert_eq!(store.zscore(b"zs", b"alice", n).unwrap(), Some(1.0));
        assert_eq!(store.zscore(b"zs", b"bob", n).unwrap(), Some(2.0));
        assert_eq!(store.zcard(b"zs", n).unwrap(), 2);
    }

    #[test]
    fn sorted_set_zrank() {
        let store = Store::new();
        let n = now();
        store
            .zadd(
                b"zs",
                &[(b"a" as &[u8], 1.0), (b"b", 2.0), (b"c", 3.0)],
                false,
                false,
                false,
                false,
                false,
                n,
            )
            .unwrap();
        assert_eq!(store.zrank(b"zs", b"a", false, n).unwrap(), Some(0));
        assert_eq!(store.zrank(b"zs", b"c", false, n).unwrap(), Some(2));
        assert_eq!(store.zrank(b"zs", b"c", true, n).unwrap(), Some(0));
    }

    #[test]
    fn sorted_set_zrange() {
        let store = Store::new();
        let n = now();
        store
            .zadd(
                b"zs",
                &[(b"a" as &[u8], 1.0), (b"b", 2.0), (b"c", 3.0)],
                false,
                false,
                false,
                false,
                false,
                n,
            )
            .unwrap();
        let items = store.zrange(b"zs", 0, -1, false, true, n).unwrap();
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].0, "a");
        assert_eq!(items[2].0, "c");
    }

    #[test]
    fn sorted_set_zrem() {
        let store = Store::new();
        let n = now();
        store
            .zadd(
                b"zs",
                &[(b"a" as &[u8], 1.0), (b"b", 2.0)],
                false,
                false,
                false,
                false,
                false,
                n,
            )
            .unwrap();
        assert_eq!(store.zrem(b"zs", &[b"a"], n).unwrap(), 1);
        assert_eq!(store.zcard(b"zs", n).unwrap(), 1);
    }

    #[test]
    fn sorted_set_zincrby() {
        let store = Store::new();
        let n = now();
        store
            .zadd(
                b"zs",
                &[(b"a" as &[u8], 1.0)],
                false,
                false,
                false,
                false,
                false,
                n,
            )
            .unwrap();
        let new_score = store.zincrby(b"zs", b"a", 2.5, n).unwrap();
        assert!((new_score - 3.5).abs() < f64::EPSILON);
    }

    #[test]
    fn sorted_set_zpopmin_zpopmax() {
        let store = Store::new();
        let n = now();
        store
            .zadd(
                b"zs",
                &[(b"a" as &[u8], 1.0), (b"b", 2.0), (b"c", 3.0)],
                false,
                false,
                false,
                false,
                false,
                n,
            )
            .unwrap();
        let min = store.zpopmin(b"zs", 1, n).unwrap();
        assert_eq!(min[0].0, "a");
        let max = store.zpopmax(b"zs", 1, n).unwrap();
        assert_eq!(max[0].0, "c");
        assert_eq!(store.zcard(b"zs", n).unwrap(), 1);
    }

    #[test]
    fn flushdb_clears_all() {
        let store = Store::new();
        let n = now();
        store.set(b"a", b"1", None, n);
        store.set(b"b", b"2", None, n);
        assert_eq!(store.dbsize(n), 2);
        store.flushdb();
        assert_eq!(store.dbsize(n), 0);
    }

    #[test]
    fn append_creates_or_extends() {
        let store = Store::new();
        let n = now();
        assert_eq!(store.append(b"key", b"hello", n), 5);
        assert_eq!(store.append(b"key", b" world", n), 11);
        assert_eq!(store.get(b"key", n).unwrap(), &b"hello world"[..]);
    }

    #[test]
    fn setnx_only_sets_if_not_exists() {
        let store = Store::new();
        let n = now();
        assert!(store.set_nx(b"key", b"first", n));
        assert!(!store.set_nx(b"key", b"second", n));
        assert_eq!(store.get(b"key", n).unwrap(), &b"first"[..]);
    }

    #[test]
    fn persist_removes_ttl() {
        let store = Store::new();
        let n = now();
        store.set(b"key", b"val", Some(Duration::from_secs(100)), n);
        assert!(store.ttl(b"key", n) > 0);
        store.persist(b"key", n);
        assert_eq!(store.ttl(b"key", n), -1);
    }

    #[test]
    fn wrongtype_error_on_type_mismatch() {
        let store = Store::new();
        let n = now();
        store.set(b"str_key", b"hello", None, n);
        let result = store.lpush(b"str_key", &[b"val"], n);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("WRONGTYPE"));
    }

    #[test]
    fn scan_returns_all_keys_with_cursor() {
        let store = Store::new();
        let n = now();
        for i in 0..25 {
            store.set(format!("key:{i}").as_bytes(), b"v", None, n);
        }
        let mut all_keys = Vec::new();
        let mut cursor = 0usize;
        loop {
            let (next, keys) = store.scan(cursor, b"*", 10, n);
            all_keys.extend(keys);
            cursor = next;
            if cursor == 0 {
                break;
            }
        }
        assert_eq!(all_keys.len(), 25);
    }

    #[test]
    fn scan_with_pattern_filters() {
        let store = Store::new();
        let n = now();
        store.set(b"user:1", b"a", None, n);
        store.set(b"user:2", b"b", None, n);
        store.set(b"post:1", b"c", None, n);
        let keys = store.keys(b"user:*", n);
        assert_eq!(keys.len(), 2);
        assert!(keys.iter().all(|k| k.starts_with("user:")));
    }

    #[test]
    fn scan_cursor_past_end_returns_zero() {
        let store = Store::new();
        let n = now();
        store.set(b"a", b"1", None, n);
        let (next, keys) = store.scan(999, b"*", 10, n);
        assert_eq!(next, 0);
        assert!(keys.is_empty());
    }

    #[test]
    fn getset_returns_old_value() {
        let store = Store::new();
        let n = now();
        store.set(b"key", b"old", None, n);
        let old = store.get_set(b"key", b"new", n);
        assert_eq!(old.unwrap(), &b"old"[..]);
        assert_eq!(store.get(b"key", n).unwrap(), &b"new"[..]);
    }

    #[test]
    fn getdel_returns_and_removes() {
        let store = Store::new();
        let n = now();
        store.set(b"key", b"val", None, n);
        let val = store.getdel(b"key", n);
        assert_eq!(val.unwrap(), &b"val"[..]);
        assert!(store.get(b"key", n).is_none());
    }

    #[test]
    fn getex_updates_ttl() {
        let store = Store::new();
        let n = now();
        store.set(b"key", b"val", None, n);
        assert_eq!(store.ttl(b"key", n), -1);
        store.getex(b"key", Some(Duration::from_secs(100)), false, n);
        assert!(store.ttl(b"key", n) > 0);
    }

    #[test]
    fn getex_persist_removes_ttl() {
        let store = Store::new();
        let n = now();
        store.set(b"key", b"val", Some(Duration::from_secs(100)), n);
        assert!(store.ttl(b"key", n) > 0);
        store.getex(b"key", None, true, n);
        assert_eq!(store.ttl(b"key", n), -1);
    }

    #[test]
    fn getrange_slices_string() {
        let store = Store::new();
        let n = now();
        store.set(b"key", b"Hello, World!", None, n);
        assert_eq!(store.getrange(b"key", 0, 4, n), &b"Hello"[..]);
        assert_eq!(store.getrange(b"key", -6, -1, n), &b"World!"[..]);
    }

    #[test]
    fn setrange_pads_and_overwrites() {
        let store = Store::new();
        let n = now();
        store.set(b"key", b"Hello", None, n);
        store.setrange(b"key", 6, b"World", n);
        let val = store.get(b"key", n).unwrap();
        assert_eq!(val.len(), 11);
        assert_eq!(val[5], 0);
    }

    #[test]
    fn strlen_returns_length() {
        let store = Store::new();
        let n = now();
        store.set(b"key", b"hello", None, n);
        assert_eq!(store.strlen(b"key", n), 5);
        assert_eq!(store.strlen(b"missing", n), 0);
    }

    #[test]
    fn msetnx_all_or_nothing() {
        let store = Store::new();
        let n = now();
        assert!(store.msetnx(&[(b"a" as &[u8], b"1" as &[u8]), (b"b", b"2")], n));
        assert!(!store.msetnx(&[(b"b", b"3"), (b"c", b"4")], n));
        assert!(store.get(b"c", n).is_none());
    }

    #[test]
    fn expire_and_pexpire() {
        let store = Store::new();
        let n = now();
        store.set(b"key", b"val", None, n);
        assert!(store.expire(b"key", 100, n));
        assert!(store.ttl(b"key", n) > 0);
        assert!(store.pexpire(b"key", 50000, n));
        assert!(store.pttl(b"key", n) > 0);
    }

    #[test]
    fn lrange_with_negative_indices() {
        let store = Store::new();
        let n = now();
        store
            .rpush(b"list", &[b"a", b"b", b"c", b"d", b"e"], n)
            .unwrap();
        let range = store.lrange(b"list", -3, -1, n).unwrap();
        assert_eq!(range.len(), 3);
        assert_eq!(range[0], &b"c"[..]);
        assert_eq!(range[2], &b"e"[..]);
    }

    #[test]
    fn lindex_positive_and_negative() {
        let store = Store::new();
        let n = now();
        store.rpush(b"list", &[b"a", b"b", b"c"], n).unwrap();
        assert_eq!(store.lindex(b"list", 0, n).unwrap(), &b"a"[..]);
        assert_eq!(store.lindex(b"list", -1, n).unwrap(), &b"c"[..]);
        assert!(store.lindex(b"list", 99, n).is_none());
    }

    #[test]
    fn lset_updates_element() {
        let store = Store::new();
        let n = now();
        store.rpush(b"list", &[b"a", b"b", b"c"], n).unwrap();
        store.lset(b"list", 1, b"B", n).unwrap();
        assert_eq!(store.lindex(b"list", 1, n).unwrap(), &b"B"[..]);
    }

    #[test]
    fn lset_out_of_range() {
        let store = Store::new();
        let n = now();
        store.rpush(b"list", &[b"a"], n).unwrap();
        let result = store.lset(b"list", 5, b"x", n);
        assert!(result.is_err());
    }

    #[test]
    fn linsert_before_and_after() {
        let store = Store::new();
        let n = now();
        store.rpush(b"list", &[b"a", b"c"], n).unwrap();
        store.linsert(b"list", true, b"c", b"b", n).unwrap();
        let range = store.lrange(b"list", 0, -1, n).unwrap();
        assert_eq!(range.len(), 3);
        assert_eq!(range[1], &b"b"[..]);
    }

    #[test]
    fn lrem_removes_matching() {
        let store = Store::new();
        let n = now();
        store
            .rpush(b"list", &[b"a", b"b", b"a", b"c", b"a"], n)
            .unwrap();
        assert_eq!(store.lrem(b"list", 2, b"a", n).unwrap(), 2);
        assert_eq!(store.llen(b"list", n).unwrap(), 3);
    }

    #[test]
    fn ltrim_keeps_range() {
        let store = Store::new();
        let n = now();
        store
            .rpush(b"list", &[b"a", b"b", b"c", b"d", b"e"], n)
            .unwrap();
        store.ltrim(b"list", 1, 3, n).unwrap();
        let range = store.lrange(b"list", 0, -1, n).unwrap();
        assert_eq!(range.len(), 3);
        assert_eq!(range[0], &b"b"[..]);
    }

    #[test]
    fn lpushx_rpushx_only_if_exists() {
        let store = Store::new();
        let n = now();
        assert_eq!(store.lpushx(b"list", &[b"a"], n), 0);
        store.rpush(b"list", &[b"x"], n).unwrap();
        assert_eq!(store.lpushx(b"list", &[b"a"], n), 2);
        assert_eq!(store.rpushx(b"list", &[b"z"], n), 3);
    }

    #[test]
    fn lmove_between_lists() {
        let store = Store::new();
        let n = now();
        store.rpush(b"src", &[b"a", b"b", b"c"], n).unwrap();
        let val = store.lmove(b"src", b"dst", false, true, n);
        assert_eq!(val.unwrap(), &b"c"[..]);
        assert_eq!(store.llen(b"src", n).unwrap(), 2);
        assert_eq!(store.llen(b"dst", n).unwrap(), 1);
    }

    #[test]
    fn hsetnx_only_if_field_missing() {
        let store = Store::new();
        let n = now();
        assert!(store.hsetnx(b"h", b"f", b"v1", n).unwrap());
        assert!(!store.hsetnx(b"h", b"f", b"v2", n).unwrap());
        assert_eq!(store.hget(b"h", b"f", n).unwrap(), &b"v1"[..]);
    }

    #[test]
    fn hincrby_creates_and_increments() {
        let store = Store::new();
        let n = now();
        store.hincrby(b"h", b"counter", 5, n).unwrap();
        store.hincrby(b"h", b"counter", 3, n).unwrap();
        let val = store.hget(b"h", b"counter", n).unwrap();
        assert_eq!(val, &b"8"[..]);
    }

    #[test]
    fn hgetall_returns_all_pairs() {
        let store = Store::new();
        let n = now();
        store
            .hset(b"h", &[(b"a" as &[u8], b"1" as &[u8]), (b"b", b"2")], n)
            .unwrap();
        let pairs = store.hgetall(b"h", n).unwrap();
        assert_eq!(pairs.len(), 2);
    }

    #[test]
    fn smove_between_sets() {
        let store = Store::new();
        let n = now();
        store.sadd(b"s1", &[b"a", b"b"], n).unwrap();
        store.sadd(b"s2", &[b"c"], n).unwrap();
        assert!(store.smove(b"s1", b"s2", b"a", n).unwrap());
        assert_eq!(store.scard(b"s1", n).unwrap(), 1);
        assert_eq!(store.scard(b"s2", n).unwrap(), 2);
    }

    #[test]
    fn sunion_sinter_sdiff() {
        let store = Store::new();
        let n = now();
        store.sadd(b"s1", &[b"a", b"b", b"c"], n).unwrap();
        store.sadd(b"s2", &[b"b", b"c", b"d"], n).unwrap();

        let union = store.sunion(&[b"s1", b"s2"], n).unwrap();
        assert_eq!(union.len(), 4);

        let inter = store.sinter(&[b"s1", b"s2"], n).unwrap();
        assert_eq!(inter.len(), 2);

        let diff = store.sdiff(&[b"s1", b"s2"], n).unwrap();
        assert_eq!(diff.len(), 1);
        assert!(diff.contains(&"a".to_string()));
    }

    #[test]
    fn sdiffstore_sinterstore_sunionstore() {
        let store = Store::new();
        let n = now();
        store.sadd(b"s1", &[b"a", b"b"], n).unwrap();
        store.sadd(b"s2", &[b"b", b"c"], n).unwrap();

        assert_eq!(store.sunionstore(b"u", &[b"s1", b"s2"], n).unwrap(), 3);
        assert_eq!(store.sinterstore(b"i", &[b"s1", b"s2"], n).unwrap(), 1);
        assert_eq!(store.sdiffstore(b"d", &[b"s1", b"s2"], n).unwrap(), 1);
    }

    #[test]
    fn smismember_checks_multiple() {
        let store = Store::new();
        let n = now();
        store.sadd(b"s", &[b"a", b"b"], n).unwrap();
        let results = store.smismember(b"s", &[b"a", b"c", b"b"], n);
        assert_eq!(results, vec![true, false, true]);
    }

    #[test]
    fn sorted_set_zadd_xx_only_updates_existing() {
        let store = Store::new();
        let n = now();
        store
            .zadd(
                b"zs",
                &[(b"a" as &[u8], 1.0)],
                false,
                false,
                false,
                false,
                false,
                n,
            )
            .unwrap();
        let added = store
            .zadd(
                b"zs",
                &[(b"a" as &[u8], 5.0), (b"b", 2.0)],
                false,
                true,
                false,
                false,
                false,
                n,
            )
            .unwrap();
        assert_eq!(added, 0);
        assert_eq!(store.zscore(b"zs", b"a", n).unwrap(), Some(5.0));
        assert_eq!(store.zscore(b"zs", b"b", n).unwrap(), None);
    }

    #[test]
    fn sorted_set_zadd_gt_lt() {
        let store = Store::new();
        let n = now();
        store
            .zadd(
                b"zs",
                &[(b"a" as &[u8], 5.0)],
                false,
                false,
                false,
                false,
                false,
                n,
            )
            .unwrap();
        store
            .zadd(
                b"zs",
                &[(b"a" as &[u8], 3.0)],
                false,
                false,
                true,
                false,
                false,
                n,
            )
            .unwrap();
        assert_eq!(store.zscore(b"zs", b"a", n).unwrap(), Some(5.0));
        store
            .zadd(
                b"zs",
                &[(b"a" as &[u8], 3.0)],
                false,
                false,
                false,
                true,
                false,
                n,
            )
            .unwrap();
        assert_eq!(store.zscore(b"zs", b"a", n).unwrap(), Some(3.0));
    }

    #[test]
    fn sorted_set_zrangebyscore() {
        let store = Store::new();
        let n = now();
        store
            .zadd(
                b"zs",
                &[(b"a" as &[u8], 1.0), (b"b", 2.0), (b"c", 3.0), (b"d", 4.0)],
                false,
                false,
                false,
                false,
                false,
                n,
            )
            .unwrap();
        let items = store
            .zrangebyscore(b"zs", 2.0, 3.0, false, false, false, None, None, true, n)
            .unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].0, "b");
        assert_eq!(items[1].0, "c");
    }

    #[test]
    fn sorted_set_zrangebyscore_exclusive() {
        let store = Store::new();
        let n = now();
        store
            .zadd(
                b"zs",
                &[(b"a" as &[u8], 1.0), (b"b", 2.0), (b"c", 3.0)],
                false,
                false,
                false,
                false,
                false,
                n,
            )
            .unwrap();
        let items = store
            .zrangebyscore(b"zs", 1.0, 3.0, true, true, false, None, None, true, n)
            .unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].0, "b");
    }

    #[test]
    fn sorted_set_zcount() {
        let store = Store::new();
        let n = now();
        store
            .zadd(
                b"zs",
                &[(b"a" as &[u8], 1.0), (b"b", 2.0), (b"c", 3.0)],
                false,
                false,
                false,
                false,
                false,
                n,
            )
            .unwrap();
        assert_eq!(store.zcount(b"zs", 1.0, 3.0, false, false, n).unwrap(), 3);
        assert_eq!(store.zcount(b"zs", 1.0, 3.0, true, true, n).unwrap(), 1);
    }

    #[test]
    fn sorted_set_zunionstore() {
        let store = Store::new();
        let n = now();
        store
            .zadd(
                b"z1",
                &[(b"a" as &[u8], 1.0), (b"b", 2.0)],
                false,
                false,
                false,
                false,
                false,
                n,
            )
            .unwrap();
        store
            .zadd(
                b"z2",
                &[(b"b" as &[u8], 3.0), (b"c", 4.0)],
                false,
                false,
                false,
                false,
                false,
                n,
            )
            .unwrap();
        let count = store
            .zunionstore(b"out", &[b"z1", b"z2"], &[], "SUM", n)
            .unwrap();
        assert_eq!(count, 3);
        assert_eq!(store.zscore(b"out", b"b", n).unwrap(), Some(5.0));
    }

    #[test]
    fn sorted_set_zinterstore() {
        let store = Store::new();
        let n = now();
        store
            .zadd(
                b"z1",
                &[(b"a" as &[u8], 1.0), (b"b", 2.0)],
                false,
                false,
                false,
                false,
                false,
                n,
            )
            .unwrap();
        store
            .zadd(
                b"z2",
                &[(b"b" as &[u8], 3.0), (b"c", 4.0)],
                false,
                false,
                false,
                false,
                false,
                n,
            )
            .unwrap();
        let count = store
            .zinterstore(b"out", &[b"z1", b"z2"], &[], "SUM", n)
            .unwrap();
        assert_eq!(count, 1);
        assert_eq!(store.zscore(b"out", b"b", n).unwrap(), Some(5.0));
    }

    #[test]
    fn sorted_set_zdiffstore() {
        let store = Store::new();
        let n = now();
        store
            .zadd(
                b"z1",
                &[(b"a" as &[u8], 1.0), (b"b", 2.0)],
                false,
                false,
                false,
                false,
                false,
                n,
            )
            .unwrap();
        store
            .zadd(
                b"z2",
                &[(b"b" as &[u8], 3.0)],
                false,
                false,
                false,
                false,
                false,
                n,
            )
            .unwrap();
        let count = store.zdiffstore(b"out", &[b"z1", b"z2"], n).unwrap();
        assert_eq!(count, 1);
        assert_eq!(store.zscore(b"out", b"a", n).unwrap(), Some(1.0));
    }

    #[test]
    fn sorted_set_zrangebylex() {
        let store = Store::new();
        let n = now();
        store
            .zadd(
                b"zs",
                &[(b"a" as &[u8], 0.0), (b"b", 0.0), (b"c", 0.0), (b"d", 0.0)],
                false,
                false,
                false,
                false,
                false,
                n,
            )
            .unwrap();
        let items = store
            .zrangebylex(b"zs", "[b", "[d", None, None, false, n)
            .unwrap();
        assert_eq!(items, vec!["b", "c", "d"]);
        let items = store
            .zrangebylex(b"zs", "(a", "(d", None, None, false, n)
            .unwrap();
        assert_eq!(items, vec!["b", "c"]);
        let items = store
            .zrangebylex(b"zs", "-", "+", None, None, false, n)
            .unwrap();
        assert_eq!(items.len(), 4);
    }

    #[test]
    fn sorted_set_zmscore() {
        let store = Store::new();
        let n = now();
        store
            .zadd(
                b"zs",
                &[(b"a" as &[u8], 1.0), (b"b", 2.0)],
                false,
                false,
                false,
                false,
                false,
                n,
            )
            .unwrap();
        let scores = store.zmscore(b"zs", &[b"a", b"missing", b"b"], n).unwrap();
        assert_eq!(scores, vec![Some(1.0), None, Some(2.0)]);
    }

    #[test]
    fn expire_sweep_cleans_expired() {
        let store = Store::new();
        let n = now();
        store.set(b"keep", b"val", None, n);
        store.set(b"expire_me", b"val", Some(Duration::from_millis(1)), n);
        std::thread::sleep(Duration::from_millis(5));
        let later = Instant::now();
        for _ in 0..50 {
            store.expire_sweep(later);
        }
        assert!(store.get(b"keep", later).is_some());
        assert!(store.get(b"expire_me", later).is_none());
    }

    #[test]
    fn expireat_sets_absolute_expiry() {
        let store = Store::new();
        let n = now();
        store.set(b"k", b"v", None, n);
        let future_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        assert!(store.expireat(b"k", future_ts, n));
        let ttl = store.ttl(b"k", n);
        assert!(ttl > 3500 && ttl <= 3600, "TTL should be ~3600: {ttl}");
    }

    #[test]
    fn expireat_past_timestamp_fails() {
        let store = Store::new();
        let n = now();
        store.set(b"k", b"v", None, n);
        assert!(!store.expireat(b"k", 1000, n));
    }

    #[test]
    fn pexpireat_sets_ms_expiry() {
        let store = Store::new();
        let n = now();
        store.set(b"k", b"v", None, n);
        let future_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            + 60000;
        assert!(store.pexpireat(b"k", future_ms, n));
        let pttl = store.pttl(b"k", n);
        assert!(
            pttl > 50000 && pttl <= 60000,
            "PTTL should be ~60000: {pttl}"
        );
    }

    #[test]
    fn expiretime_returns_unix_timestamp() {
        let store = Store::new();
        let n = now();
        store.set(b"k", b"v", Some(Duration::from_secs(3600)), n);
        let et = store.expiretime(b"k", n);
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!(
            et > now_unix + 3500 && et <= now_unix + 3600,
            "expiretime should be ~now+3600: {et}"
        );
    }

    #[test]
    fn expiretime_no_ttl_returns_neg1() {
        let store = Store::new();
        let n = now();
        store.set(b"k", b"v", None, n);
        assert_eq!(store.expiretime(b"k", n), -1);
    }

    #[test]
    fn expiretime_missing_key_returns_neg2() {
        let store = Store::new();
        assert_eq!(store.expiretime(b"nope", now()), -2);
    }

    #[test]
    fn pexpiretime_returns_unix_ms() {
        let store = Store::new();
        let n = now();
        store.set(b"k", b"v", Some(Duration::from_secs(100)), n);
        let pet = store.pexpiretime(b"k", n);
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        assert!(
            pet > now_ms + 90000 && pet <= now_ms + 100000,
            "pexpiretime should be ~now+100s in ms: {pet}"
        );
    }

    #[test]
    fn unlink_same_as_del() {
        let store = Store::new();
        let n = now();
        store.set(b"a", b"1", None, n);
        store.set(b"b", b"2", None, n);
        assert_eq!(store.unlink(&[b"a", b"b", b"c"]), 2);
        assert!(store.get(b"a", n).is_none());
        assert!(store.get(b"b", n).is_none());
    }

    #[test]
    fn spop_removes_members() {
        let store = Store::new();
        let n = now();
        store.sadd(b"s", &[b"a", b"b", b"c"], n).unwrap();
        let popped = store.spop(b"s", 2, n).unwrap();
        assert_eq!(popped.len(), 2);
        assert_eq!(store.scard(b"s", n).unwrap(), 1);
    }

    #[test]
    fn spop_more_than_available() {
        let store = Store::new();
        let n = now();
        store.sadd(b"s", &[b"a", b"b"], n).unwrap();
        let popped = store.spop(b"s", 10, n).unwrap();
        assert_eq!(popped.len(), 2);
        assert_eq!(store.scard(b"s", n).unwrap(), 0);
    }

    #[test]
    fn shard_version_bumps_on_mutation() {
        let store = Store::new();
        let n = now();
        let idx = store.shard_for_key(b"testkey");
        let v0 = store.shard_version(idx);
        store.set(b"testkey", b"val", None, n);
        let v1 = store.shard_version(idx);
        assert!(v1 > v0, "version should increase after set: {v0} -> {v1}");
        store.del(&[b"testkey"]);
        let v2 = store.shard_version(idx);
        assert!(v2 > v1, "version should increase after del: {v1} -> {v2}");
    }

    #[test]
    fn shard_version_stable_on_reads() {
        let store = Store::new();
        let n = now();
        store.set(b"k", b"v", None, n);
        let idx = store.shard_for_key(b"k");
        let v0 = store.shard_version(idx);
        store.get(b"k", n);
        store.strlen(b"k", n);
        store.exists(&[b"k"], n);
        store.ttl(b"k", n);
        let v1 = store.shard_version(idx);
        assert_eq!(v0, v1, "reads should not bump version");
    }

    #[test]
    fn lset_bumps_version() {
        let store = Store::new();
        let n = now();
        store.rpush(b"list", &[b"a", b"b"], n).unwrap();
        let idx = store.shard_for_key(b"list");
        let v0 = store.shard_version(idx);
        store.lset(b"list", 0, b"x", n).unwrap();
        let v1 = store.shard_version(idx);
        assert!(v1 > v0, "lset bumps version");
    }

    #[test]
    fn glob_matcher_patterns() {
        let m = GlobMatcher::new("user:*");
        assert!(m.matches("user:123"));
        assert!(m.matches("user:"));
        assert!(!m.matches("post:1"));

        let m2 = GlobMatcher::new("h?llo");
        assert!(m2.matches("hello"));
        assert!(m2.matches("hallo"));
        assert!(!m2.matches("hllo"));

        let m3 = GlobMatcher::new("*");
        assert!(m3.matches("anything"));
        assert!(m3.matches(""));
    }
}
