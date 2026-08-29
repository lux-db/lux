use bytes::Bytes;
use hashbrown::{HashMap, HashSet as FxHashSet};
use ordered_float::OrderedFloat;
use parking_lot::RwLock;
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::hash::{BuildHasher, Hasher};
use std::sync::atomic::Ordering;
use std::sync::atomic::{AtomicU32, AtomicUsize};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
mod hashes;
mod sorted_sets;
mod streams;
mod timeseries;
mod vectors;

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

/// BITFIELD overflow handling for SET/INCRBY (default WRAP).
#[derive(Clone, Copy)]
pub enum BitfieldOverflow {
    Wrap,
    Sat,
    Fail,
}

/// A single BITFIELD/BITFIELD_RO sub-operation. `bits` is the field width,
/// `signed` selects i<bits> vs u<bits>, `offset` is an absolute bit offset.
pub enum BitfieldOp {
    Get {
        signed: bool,
        bits: u32,
        offset: u64,
    },
    Set {
        signed: bool,
        bits: u32,
        offset: u64,
        value: i64,
        overflow: BitfieldOverflow,
    },
    IncrBy {
        signed: bool,
        bits: u32,
        offset: u64,
        incr: i64,
        overflow: BitfieldOverflow,
    },
}

/// Read `bits` bits at `offset` from the bitmap, MSB-first, interpreting the
/// field as signed (two's complement, sign-extended) or unsigned. Bits past the
/// end of `buf` read as zero.
fn bf_read(buf: &[u8], offset: u64, bits: u32, signed: bool) -> i64 {
    let mut val: u64 = 0;
    for i in 0..bits as u64 {
        let bit_index = offset + i;
        let byte_index = (bit_index / 8) as usize;
        let shift = 7 - (bit_index % 8);
        let bit = if byte_index < buf.len() {
            (buf[byte_index] >> shift) & 1
        } else {
            0
        };
        val = (val << 1) | bit as u64;
    }
    if signed && bits < 64 && (val >> (bits - 1)) & 1 == 1 {
        (val | (!0u64 << bits)) as i64
    } else {
        val as i64
    }
}

/// Write the low `bits` bits of `value` at `offset`, MSB-first, growing `buf` to
/// fit the highest touched byte.
fn bf_write(buf: &mut Vec<u8>, offset: u64, bits: u32, value: u64) {
    let end_bit = offset + bits as u64;
    let needed = end_bit.div_ceil(8) as usize;
    if buf.len() < needed {
        buf.resize(needed, 0);
    }
    for i in 0..bits as u64 {
        let bit_index = offset + i;
        let byte_index = (bit_index / 8) as usize;
        let shift = 7 - (bit_index % 8);
        let bit = ((value >> (bits as u64 - 1 - i)) & 1) as u8;
        if bit == 1 {
            buf[byte_index] |= 1 << shift;
        } else {
            buf[byte_index] &= !(1 << shift);
        }
    }
}

/// Apply BITFIELD overflow semantics to a candidate value for a signed/unsigned
/// field of `bits` width. Returns None only for FAIL-on-overflow.
fn bf_clamp(signed: bool, bits: u32, val: i128, mode: BitfieldOverflow) -> Option<i64> {
    let (min, max): (i128, i128) = if signed {
        (-(1i128 << (bits - 1)), (1i128 << (bits - 1)) - 1)
    } else {
        (0, (1i128 << bits) - 1)
    };
    if val >= min && val <= max {
        return Some(val as i64);
    }
    match mode {
        BitfieldOverflow::Fail => None,
        BitfieldOverflow::Sat => Some(if val < min { min as i64 } else { max as i64 }),
        BitfieldOverflow::Wrap => {
            let range = 1i128 << bits;
            let mut w = val.rem_euclid(range);
            if signed && w > max {
                w -= range;
            }
            Some(w as i64)
        }
    }
}

pub struct StreamData {
    pub entries: BTreeMap<StreamId, Vec<(String, Bytes)>>,
    pub last_id: StreamId,
    pub groups: std::collections::HashMap<String, ConsumerGroup>,
}

#[derive(Clone, Copy)]
pub struct SetOptions<'a> {
    pub ttl: Option<Duration>,
    pub keep_ttl: bool,
    pub nx: bool,
    pub xx: bool,
    pub ifeq: Option<&'a [u8]>,
    pub get: bool,
    pub encrypted: bool,
}

pub(crate) struct PreparedConditionalSet {
    should_set: bool,
    old: Option<Bytes>,
    stored_value: Option<Vec<u8>>,
    expires_at: Option<Instant>,
}

impl PreparedConditionalSet {
    pub(crate) fn should_set(&self) -> bool {
        self.should_set
    }

    pub(crate) fn stored_value(&self) -> Option<&[u8]> {
        self.stored_value.as_deref()
    }

    pub(crate) fn expires_in(&self, now: Instant) -> Option<Duration> {
        self.expires_at
            .map(|deadline| deadline.saturating_duration_since(now))
    }
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
const RENAME_ENCRYPTED_ERR: &str =
    "ERR cannot relocate an encrypted key: its ciphertext is bound to the key name and would be unrecoverable at the destination; decrypt and re-set under the new key instead";

pub struct VectorData {
    #[allow(dead_code)]
    pub dims: u32,
    pub data: Vec<f32>,
    pub metadata: Option<String>,
    /// When true this vector is encrypted at rest: the in-memory `data` stays
    /// plaintext (HNSW/search need it), but it is sealed when written to the
    /// snapshot and represented as ciphertext in the mutation journal.
    pub encrypted: bool,
}

pub struct TimeSeriesData {
    pub samples: Vec<(i64, f64)>,
    pub retention: u64,
    pub labels: Vec<(String, String)>,
}

pub struct SetData {
    members: Vec<String>,
    index: HashMap<String, usize>,
}

impl SetData {
    pub fn new() -> Self {
        Self {
            members: Vec::new(),
            index: HashMap::new(),
        }
    }

    pub fn from_members<I>(members: I) -> Self
    where
        I: IntoIterator<Item = String>,
    {
        let mut set = Self::new();
        for member in members {
            set.insert(member);
        }
        set
    }

    pub fn insert(&mut self, member: String) -> bool {
        match self.index.entry(member.clone()) {
            hashbrown::hash_map::Entry::Occupied(_) => false,
            hashbrown::hash_map::Entry::Vacant(v) => {
                let idx = self.members.len();
                self.members.push(member);
                v.insert(idx);
                true
            }
        }
    }

    pub fn remove(&mut self, member: &str) -> bool {
        let Some(idx) = self.index.remove(member) else {
            return false;
        };
        self.members.swap_remove(idx);
        if let Some(swapped) = self.members.get(idx) {
            self.index.insert(swapped.clone(), idx);
        }
        true
    }

    pub fn pop(&mut self) -> Option<String> {
        let member = self.members.pop()?;
        self.index.remove(&member);
        Some(member)
    }

    pub fn contains(&self, member: &str) -> bool {
        self.index.contains_key(member)
    }

    pub fn len(&self) -> usize {
        self.members.len()
    }

    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, String> {
        self.members.iter()
    }
}

/// Hash value with optional per-field TTLs (Redis 7.4 hash-field expiration).
/// `fields` holds the data; `expiries` holds absolute unix-ms deadlines for the
/// subset of fields that have a TTL. Derefs to `fields` so value-only access
/// sites are unchanged; TTL-aware reads use the `*_live`/`purge_expired` helpers.
#[derive(Default, Clone)]
pub struct HashData {
    pub fields: HashMap<String, Bytes>,
    pub expiries: HashMap<String, i64>,
}

impl HashData {
    pub fn from_fields(fields: HashMap<String, Bytes>) -> Self {
        Self {
            fields,
            expiries: HashMap::new(),
        }
    }

    /// True when `field` carries a TTL that is at or before `now_ms`.
    pub fn field_expired(&self, field: &str, now_ms: i64) -> bool {
        self.expiries.get(field).is_some_and(|&e| e <= now_ms)
    }

    pub fn get_live(&self, field: &str, now_ms: i64) -> Option<&Bytes> {
        if self.field_expired(field, now_ms) {
            None
        } else {
            self.fields.get(field)
        }
    }

    pub fn contains_live(&self, field: &str, now_ms: i64) -> bool {
        self.fields.contains_key(field) && !self.field_expired(field, now_ms)
    }

    pub fn live_iter(&self, now_ms: i64) -> impl Iterator<Item = (&String, &Bytes)> {
        self.fields
            .iter()
            .filter(move |(k, _)| !self.field_expired(k, now_ms))
    }

    pub fn live_len(&self, now_ms: i64) -> usize {
        self.fields
            .keys()
            .filter(|k| !self.field_expired(k, now_ms))
            .count()
    }

    /// Drop fields whose TTL has passed. Returns (bytes freed, hash-now-empty).
    pub fn purge_expired(&mut self, now_ms: i64) -> (usize, bool) {
        if self.expiries.is_empty() {
            return (0, self.fields.is_empty());
        }
        let expired: Vec<String> = self
            .expiries
            .iter()
            .filter(|(_, &e)| e <= now_ms)
            .map(|(k, _)| k.clone())
            .collect();
        let mut freed = 0;
        for f in &expired {
            if let Some(v) = self.fields.remove(f) {
                freed += f.len() + v.len() + 64;
            }
            self.expiries.remove(f);
        }
        (freed, self.fields.is_empty())
    }
}

impl std::ops::Deref for HashData {
    type Target = HashMap<String, Bytes>;
    fn deref(&self) -> &Self::Target {
        &self.fields
    }
}

impl std::ops::DerefMut for HashData {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.fields
    }
}

/// Condition flag for HEXPIRE-family commands (NX/XX/GT/LT).
#[derive(Clone, Copy, PartialEq)]
pub enum HExpireCond {
    None,
    Nx,
    Xx,
    Gt,
    Lt,
}

/// Per-field result of an HTTL-family query.
pub enum HFieldTtl {
    Missing,
    NoTtl,
    ExpiresAtMs(i64),
}

/// TTL mutation requested by HGETEX for the fetched fields.
#[derive(Clone, Copy)]
pub enum HGetexTtl {
    Keep,
    Persist,
    SetMs(i64),
}

/// Wall-clock now as unix-epoch milliseconds, used for absolute hash-field TTL
/// deadlines (which must survive restarts, so they are stored as epoch-ms).
pub(crate) fn epoch_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub enum StoreValue {
    Str(Bytes),
    StrBuf(Vec<u8>),
    List(VecDeque<Bytes>),
    Hash(HashData),
    Set(SetData),
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
            StoreValue::Str(_) | StoreValue::StrBuf(_) => "string",
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

    #[inline(always)]
    pub(crate) fn string_bytes(&self) -> Option<&[u8]> {
        match self {
            StoreValue::Str(s) => Some(s),
            StoreValue::StrBuf(s) => Some(s),
            _ => None,
        }
    }

    #[inline(always)]
    pub(crate) fn string_to_bytes(&self) -> Option<Bytes> {
        match self {
            StoreValue::Str(s) => Some(s.clone()),
            StoreValue::StrBuf(s) => Some(Bytes::copy_from_slice(s)),
            _ => None,
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
    pub(crate) data: ShardData,
    pub(crate) version: u64,
    pub(crate) used_memory: usize,
}

/// Mutable counters that must belong to one embedded server instance.
///
/// These used to be process-wide statics, which made INFO, eviction, and
/// durability counters bleed across multiple Lux runtimes in one binary.
pub(crate) struct StoreMetrics {
    start_time: Instant,
    used_memory: AtomicUsize,
    lru_clock: AtomicU32,
    connected_clients: AtomicUsize,
    total_commands: AtomicUsize,
    key_count: AtomicUsize,
    persistence_err_wal_append: AtomicUsize,
    persistence_err_wal_fsync: AtomicUsize,
    persistence_err_disk_write: AtomicUsize,
}

impl StoreMetrics {
    fn new() -> Self {
        Self {
            start_time: Instant::now(),
            used_memory: AtomicUsize::new(0),
            lru_clock: AtomicU32::new(0),
            connected_clients: AtomicUsize::new(0),
            total_commands: AtomicUsize::new(0),
            key_count: AtomicUsize::new(0),
            persistence_err_wal_append: AtomicUsize::new(0),
            persistence_err_wal_fsync: AtomicUsize::new(0),
            persistence_err_disk_write: AtomicUsize::new(0),
        }
    }
}

pub struct Store {
    config: Arc<crate::ServerConfig>,
    encryption: crate::encryption::EncryptionKeyring,
    /// Short-lived API-key resolutions belong to this engine instance. Keeping
    /// this on `Store` prevents one embedded server from authenticating against
    /// another server's `auth.keys` table.
    pub(crate) api_key_cache: crate::auth::ApiKeyCache,
    shards: Box<[RwLock<Shard>]>,
    metrics: StoreMetrics,
    /// Serializes Lua script execution for this runtime without blocking other
    /// embedded Lux instances in the same process.
    script_gate: RwLock<()>,
    pub(crate) vector_indexes: RwLock<HashMap<u32, crate::hnsw::HnswIndex, FxBuildHasher>>,
    pub(crate) table_vector_indexes:
        RwLock<HashMap<(u32, String), crate::hnsw::HnswIndex, FxBuildHasher>>,
    disk_shards: Option<Box<[parking_lot::Mutex<crate::disk::DiskShard>]>>,
    /// The one ordered journal used by every new durable mutation.
    journal: Option<parking_lot::Mutex<crate::disk::Wal>>,
    /// Read-only compatibility inputs from the pre-1.0 per-shard WAL layout.
    /// They are replayed before `journal` and truncated with the next snapshot.
    legacy_wals: Box<[(usize, parking_lot::Mutex<crate::disk::Wal>)]>,
    /// Per-stream WAL positions already represented by the loaded snapshot.
    recovery_wal_checkpoints: parking_lot::Mutex<HashMap<String, crate::disk::WalCheckpoint>>,
    /// Striped commit gates keep overlapping mutations in journal/apply order
    /// without serializing independent shards behind one global writer lock.
    journal_gates: Box<[parking_lot::ReentrantMutex<()>]>,
    /// Exact sentinel used only while replaying post-snapshot mutations. It
    /// keeps snapshot entries whose wall-clock TTL elapsed during downtime
    /// visible to TTL-preserving journal commands without reviving them after
    /// recovery finishes.
    recovery_expiry_sentinel: parking_lot::Mutex<Option<Instant>>,
    pub(crate) wal_suppress: std::sync::atomic::AtomicBool,
    /// Narrower than `wal_suppress`: true only while persisted commands are
    /// being re-executed. Bootstrap and snapshot loading also suppress writes,
    /// but must not gain access to replay-only command behavior.
    replaying_wal: std::sync::atomic::AtomicBool,
    /// Once persistence enters an uncertain state, reject every later mutation
    /// until restart rather than acknowledge writes through an unsafe journal.
    journal_poisoned: std::sync::atomic::AtomicBool,
    /// Cleared when runtime shutdown begins. Mutation preparation checks this
    /// both before and after acquiring its journal domains, which turns the
    /// final shutdown sync into a real fence rather than a best-effort flush.
    accepting_mutations: std::sync::atomic::AtomicBool,
    restoring: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    journal_failures_to_inject: AtomicUsize,
    #[cfg(test)]
    journal_fsync_failures_to_inject: AtomicUsize,
    /// Set once at runtime startup; sink for typed row deltas feeding reactive
    /// live queries. Absent for embedded/replay-only stores, so emission is a
    /// cheap no-op there.
    row_delta_broker: std::sync::OnceLock<crate::pubsub::Broker>,
}

/// A fully resolved mutation ready to cross the journal boundary. The payload
/// contains every value needed by the in-memory apply phase; `commands` is the
/// exact deterministic representation recovery will execute.
pub(crate) struct JournalPlan<T> {
    commands: Vec<Vec<Vec<u8>>>,
    prepared: T,
}

pub(crate) struct PreparedRestore {
    value: DumpValue,
    ttl: Option<Duration>,
    delete_only: bool,
}

/// Keeps the affected mutation domains serialized until the caller finishes
/// applying the journaled change.
pub(crate) struct JournalCommitGuard<'a> {
    store: &'a Store,
    _guards: Vec<parking_lot::ReentrantMutexGuard<'a, ()>>,
    armed: bool,
}

impl JournalCommitGuard<'_> {
    /// Mark the journaled live apply as complete. Dropping an armed guard
    /// without reaching this point fences later mutations because recovery,
    /// rather than current memory, owns the authoritative outcome.
    pub(crate) fn complete(mut self) -> std::io::Result<()> {
        self.store.ensure_journal_healthy()?;
        self.armed = false;
        Ok(())
    }

    /// Disarm after the exact journal frame was successfully removed. This is
    /// only valid while the journal lock still excludes concurrent appenders.
    fn rolled_back(mut self) {
        self.armed = false;
    }
}

impl Drop for JournalCommitGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.store.poison_journal();
        }
    }
}

/// A mutation domain locked for deterministic preparation but not yet durable.
/// Consuming this guard through `commit` is the only way to reach the apply
/// phase; dropping it after validation fails is intentionally a no-op.
pub(crate) struct JournalPrepareGuard<'a> {
    store: &'a Store,
    guards: Vec<parking_lot::ReentrantMutexGuard<'a, ()>>,
    bypassed: bool,
}

impl<'a> JournalPrepareGuard<'a> {
    pub(crate) fn commit(self, args: &[&[u8]]) -> std::io::Result<JournalCommitGuard<'a>> {
        self.commit_batch(&[args])
    }

    pub(crate) fn commit_batch(
        self,
        commands: &[&[&[u8]]],
    ) -> std::io::Result<JournalCommitGuard<'a>> {
        let armed = !self.bypassed && !commands.is_empty();
        if armed {
            self.store.append_journal_commands(commands)?;
        }
        Ok(JournalCommitGuard {
            store: self.store,
            _guards: self.guards,
            armed,
        })
    }
}

impl<T> JournalPlan<T> {
    pub(crate) fn command(command: Vec<Vec<u8>>, prepared: T) -> Self {
        Self {
            commands: vec![command],
            prepared,
        }
    }

    pub(crate) fn batch(commands: Vec<Vec<Vec<u8>>>, prepared: T) -> Self {
        Self { commands, prepared }
    }

    pub(crate) fn no_op(prepared: T) -> Self {
        Self {
            commands: Vec::new(),
            prepared,
        }
    }
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

pub(crate) type ShardKey = Vec<u8>;
pub(crate) type ShardData = HashMap<ShardKey, Entry, FxBuildHasher>;

#[inline(always)]
fn key_str(key: &[u8]) -> &str {
    std::str::from_utf8(key).unwrap_or("")
}

#[inline(always)]
pub(crate) fn key_bytes(key: &[u8]) -> ShardKey {
    key.to_vec()
}

#[inline(always)]
fn key_string(key: &[u8]) -> String {
    match std::str::from_utf8(key) {
        Ok(key) => key.to_owned(),
        Err(_) => String::from_utf8_lossy(key).into_owned(),
    }
}

fn parse_table_vector_key(key: &str) -> Option<(&str, &str, &str)> {
    let rest = key.strip_prefix("_t:")?;
    let (table, rest) = rest.split_once(":vec:")?;
    let (field, pk) = rest.split_once(':')?;
    if table.is_empty() || field.is_empty() || pk.is_empty() {
        return None;
    }
    Some((table, field, pk))
}

fn parse_table_row_key(key: &str) -> Option<(&str, &str)> {
    let rest = key.strip_prefix("_t:")?;
    let (table, pk) = rest.split_once(":row:")?;
    if table.is_empty() || pk.is_empty() {
        return None;
    }
    Some((table, pk))
}

fn table_vector_index_name(table: &str, field: &str) -> String {
    format!("{}.{}", table, field)
}

fn table_vector_key_for_pk(table: &str, field: &str, pk: &str) -> String {
    format!("_t:{}:vec:{}:{}", table, field, pk)
}

fn encrypted_value_would_be_orphaned(value: &[u8], remaining_key_ids: &HashSet<String>) -> bool {
    crate::encryption::EncryptionKeyring::is_encrypted_value(value)
        && !crate::encryption::EncryptionKeyring::envelope_decryptable_by_any(
            value,
            remaining_key_ids,
        )
}

pub(crate) struct TableVectorCandidateQuery<'a> {
    pub table: &'a str,
    pub field: &'a str,
    pub query: &'a [f32],
    pub candidate_pks: &'a HashSet<String>,
    pub k: usize,
    pub threshold: Option<f32>,
    pub now: Instant,
}

fn stream_entry_memory(fields: &[(String, Bytes)]) -> usize {
    16 + fields
        .iter()
        .map(|(k, v)| k.len() + v.len() + 32)
        .sum::<usize>()
}

pub fn estimate_entry_memory<K: AsRef<[u8]>>(key: K, value: &StoreValue) -> usize {
    let key_overhead = key.as_ref().len() + 64;
    let val_size = match value {
        StoreValue::Str(s) => s.len(),
        StoreValue::StrBuf(s) => s.len(),
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
        let mut config = crate::ServerConfig::default();
        config.durability.policy = crate::DurabilityPolicy::Ephemeral;
        config.save_interval = Duration::ZERO;
        Self::new_with_config(Arc::new(config))
    }

    #[cfg(any(test, feature = "fuzzing"))]
    pub fn new_with_config(mut config: Arc<crate::ServerConfig>) -> Self {
        // Most unit-test fixtures override one unrelated setting on top of the
        // public defaults. Do not let those fixtures create a journal in the
        // source tree; persistence tests opt in with an isolated data_dir.
        if config.data_dir == "."
            && config.storage.mode == crate::StorageMode::Memory
            && config.durability == crate::DurabilityConfig::default()
        {
            Arc::make_mut(&mut config).durability.policy = crate::DurabilityPolicy::Ephemeral;
        }
        Self::try_new_with_config(config)
            .unwrap_or_else(|error| panic!("failed to initialize Store: {error}"))
    }

    pub(crate) fn try_new_with_config(config: Arc<crate::ServerConfig>) -> std::io::Result<Self> {
        let encryption =
            crate::encryption::EncryptionKeyring::open(&config.encryption, &config.data_dir)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
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

        let persistence_shard_count = n.min(64);
        let disk_shards = if config.storage.mode == crate::disk::StorageMode::Tiered {
            let dir = std::path::Path::new(&config.storage.dir);
            let ds: Vec<parking_lot::Mutex<crate::disk::DiskShard>> = (0..persistence_shard_count)
                .map(|i| {
                    // DiskShard records rebuild corruption locally; surface it
                    // through the configured callback while startup is still synchronous.
                    let mut shard = crate::disk::DiskShard::open(dir, i)?;
                    Self::emit_disk_rebuild_report(&config, i, shard.take_rebuild_report());
                    Ok(parking_lot::Mutex::new(shard))
                })
                .collect::<std::io::Result<_>>()?;
            Some(ds.into_boxed_slice())
        } else {
            None
        };
        let (journal, legacy_wals) = if config.durability.policy.is_persistent() {
            let dir = config.journal_dir();
            let mut legacy = Vec::new();
            for shard in 0..persistence_shard_count {
                let path = dir.join(format!("shard_{shard}/wal.lux"));
                if path.exists() {
                    legacy.push((
                        shard,
                        parking_lot::Mutex::new(crate::disk::Wal::open(&dir, shard)?),
                    ));
                }
            }
            (
                Some(parking_lot::Mutex::new(crate::disk::Wal::open_named(
                    &dir, "global",
                )?)),
                legacy.into_boxed_slice(),
            )
        } else {
            (None, Vec::new().into_boxed_slice())
        };
        let journal_gates = (0..persistence_shard_count)
            .map(|_| parking_lot::ReentrantMutex::new(()))
            .collect::<Vec<_>>()
            .into_boxed_slice();

        Ok(Self {
            config,
            encryption,
            api_key_cache: parking_lot::RwLock::new(std::collections::HashMap::new()),
            shards: shards.into_boxed_slice(),
            metrics: StoreMetrics::new(),
            script_gate: RwLock::new(()),
            vector_indexes: RwLock::new(HashMap::with_hasher(FxBuildHasher)),
            table_vector_indexes: RwLock::new(HashMap::with_hasher(FxBuildHasher)),
            disk_shards,
            journal,
            legacy_wals,
            recovery_wal_checkpoints: parking_lot::Mutex::new(HashMap::new()),
            journal_gates,
            recovery_expiry_sentinel: parking_lot::Mutex::new(None),
            wal_suppress: std::sync::atomic::AtomicBool::new(false),
            replaying_wal: std::sync::atomic::AtomicBool::new(false),
            journal_poisoned: std::sync::atomic::AtomicBool::new(false),
            accepting_mutations: std::sync::atomic::AtomicBool::new(true),
            restoring: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            journal_failures_to_inject: AtomicUsize::new(0),
            #[cfg(test)]
            journal_fsync_failures_to_inject: AtomicUsize::new(0),
            row_delta_broker: std::sync::OnceLock::new(),
        })
    }

    pub fn config(&self) -> &crate::ServerConfig {
        &self.config
    }

    pub(crate) fn encryption(&self) -> &crate::encryption::EncryptionKeyring {
        &self.encryption
    }

    pub(crate) fn begin_recovery(&self) {
        // The sentinel only needs to outlive synchronous startup replay. Its
        // exact value, rather than elapsed time, identifies staged entries.
        let sentinel = Instant::now() + Duration::from_secs(365 * 24 * 60 * 60);
        *self.recovery_expiry_sentinel.lock() = Some(sentinel);
        self.recovery_wal_checkpoints.lock().clear();
    }

    pub(crate) fn set_recovery_wal_checkpoints(
        &self,
        checkpoints: HashMap<String, crate::disk::WalCheckpoint>,
    ) {
        *self.recovery_wal_checkpoints.lock() = checkpoints;
    }

    pub(crate) fn stage_expired_recovery_entry(&self, key: String, value: DumpValue) {
        let sentinel = self
            .recovery_expiry_sentinel
            .lock()
            .expect("recovery must begin before expired entries are staged");
        let key_bytes = key.as_bytes().to_vec();
        self.load_entry(key, value, None);
        let idx = self.shard_index(&key_bytes);
        let mut shard = self.shards[idx].write();
        if let Some(entry) = shard.data.get_mut(&key_bytes) {
            entry.expires_at = Some(sentinel);
        }
    }

    pub(crate) fn finish_recovery(&self) {
        self.recovery_wal_checkpoints.lock().clear();
        let Some(sentinel) = self.recovery_expiry_sentinel.lock().take() else {
            return;
        };
        let staged: Vec<Vec<u8>> = self
            .shards
            .iter()
            .flat_map(|shard| {
                let shard = shard.read();
                shard
                    .data
                    .iter()
                    .filter(|(_, entry)| entry.expires_at == Some(sentinel))
                    .map(|(key, _)| key.clone())
                    .collect::<Vec<_>>()
            })
            .collect();
        for key in staged {
            self.del(&[key.as_slice()]);
        }
    }

    /// Rewrap any encrypted values inside a cold-tier `DumpValue` under the
    /// current keyset. Returns true if anything was re-encrypted. Mirrors the
    /// in-memory rewrap AAD slots. Vectors never cold-tier (pinned hot).
    fn reencrypt_cold_dump_value(&self, key: &str, value: &mut DumpValue) -> Result<bool, String> {
        use crate::encryption::EncryptionKeyring as E;
        let mut changed = false;
        match value {
            DumpValue::Str(v) => {
                if E::is_encrypted_value(v) {
                    *v = self.encryption().reencrypt("__lux_kv", "value", key, v)?;
                    changed = true;
                }
            }
            DumpValue::Hash(pairs, _) => {
                for (field, v) in pairs.iter_mut() {
                    if E::is_encrypted_value(v) {
                        *v = self.encryption().reencrypt("__lux_hash", field, key, v)?;
                        changed = true;
                    }
                }
            }
            DumpValue::List(items) => {
                for v in items.iter_mut() {
                    if E::is_encrypted_value(v) {
                        *v = self
                            .encryption()
                            .reencrypt("__lux_list", "element", "", v)?;
                        changed = true;
                    }
                }
            }
            DumpValue::Stream(entries, _, _) => {
                for (_id, fields) in entries.iter_mut() {
                    for (field, v) in fields.iter_mut() {
                        if E::is_encrypted_value(v) {
                            *v = self.encryption().reencrypt("__lux_stream", field, key, v)?;
                            changed = true;
                        }
                    }
                }
            }
            _ => {}
        }
        Ok(changed)
    }

    /// True if any encrypted value in a cold-tier `DumpValue` would become
    /// undecryptable without the retiring key.
    fn dump_value_would_orphan(value: &DumpValue, remaining: &HashSet<String>) -> bool {
        match value {
            DumpValue::Str(v) => encrypted_value_would_be_orphaned(v, remaining),
            DumpValue::Hash(pairs, _) => pairs
                .iter()
                .any(|(_, v)| encrypted_value_would_be_orphaned(v, remaining)),
            DumpValue::List(items) => items
                .iter()
                .any(|v| encrypted_value_would_be_orphaned(v, remaining)),
            DumpValue::Stream(entries, _, _) => entries.iter().any(|(_, fields)| {
                fields
                    .iter()
                    .any(|(_, v)| encrypted_value_would_be_orphaned(v, remaining))
            }),
            _ => false,
        }
    }

    pub(crate) fn enc_rewrap_all(&self) -> Result<usize, String> {
        let mut count = 0usize;
        for idx in 0..self.shards.len() {
            let mut shard = self.shards[idx].write();
            let mut shard_changed = false;
            let mut mem_delta: isize = 0;
            let mut disk_remove = Vec::new();
            for (key, entry) in shard.data.iter_mut() {
                if entry.is_expired_at(Instant::now()) {
                    continue;
                }
                match &mut entry.value {
                    StoreValue::Str(value) => {
                        if crate::encryption::EncryptionKeyring::is_encrypted_value(value) {
                            let key_name = key_string(key);
                            let new_value = self
                                .encryption()
                                .reencrypt("__lux_kv", "value", &key_name, value)?;
                            mem_delta += new_value.len() as isize - value.len() as isize;
                            *value = Bytes::from(new_value);
                            count += 1;
                            shard_changed = true;
                            disk_remove.push(key.clone());
                        }
                    }
                    StoreValue::StrBuf(value) => {
                        if crate::encryption::EncryptionKeyring::is_encrypted_value(value) {
                            let key_name = key_string(key);
                            let new_value = self
                                .encryption()
                                .reencrypt("__lux_kv", "value", &key_name, value)?;
                            mem_delta += new_value.len() as isize - value.len() as isize;
                            *value = new_value;
                            count += 1;
                            shard_changed = true;
                            disk_remove.push(key.clone());
                        }
                    }
                    StoreValue::Hash(map) => {
                        let key_name = key_string(key);
                        let table_row = parse_table_row_key(&key_name)
                            .map(|(table, pk)| (table.to_string(), pk.to_string()));
                        for (field, value) in map.iter_mut() {
                            if !crate::encryption::EncryptionKeyring::is_encrypted_value(value) {
                                continue;
                            }
                            let new_value = if let Some((table, pk)) = &table_row {
                                self.encryption().reencrypt(table, field, pk, value)?
                            } else {
                                self.encryption().reencrypt(
                                    "__lux_hash",
                                    field,
                                    &key_name,
                                    value,
                                )?
                            };
                            mem_delta += new_value.len() as isize - value.len() as isize;
                            *value = Bytes::from(new_value);
                            count += 1;
                            shard_changed = true;
                            disk_remove.push(key.clone());
                        }
                    }
                    StoreValue::List(list) => {
                        for elem in list.iter_mut() {
                            if !crate::encryption::EncryptionKeyring::is_encrypted_value(elem) {
                                continue;
                            }
                            let new_value =
                                self.encryption()
                                    .reencrypt("__lux_list", "element", "", elem)?;
                            mem_delta += new_value.len() as isize - elem.len() as isize;
                            *elem = Bytes::from(new_value);
                            count += 1;
                            shard_changed = true;
                            disk_remove.push(key.clone());
                        }
                    }
                    StoreValue::Stream(stream) => {
                        let key_name = key_string(key);
                        for fields in stream.entries.values_mut() {
                            for (field, value) in fields.iter_mut() {
                                if !crate::encryption::EncryptionKeyring::is_encrypted_value(value)
                                {
                                    continue;
                                }
                                let new_value = self.encryption().reencrypt(
                                    "__lux_stream",
                                    field,
                                    &key_name,
                                    value,
                                )?;
                                mem_delta += new_value.len() as isize - value.len() as isize;
                                *value = Bytes::from(new_value);
                                count += 1;
                                shard_changed = true;
                                disk_remove.push(key.clone());
                            }
                        }
                    }
                    _ => {}
                }
            }
            if shard_changed {
                shard.version += 1;
                if mem_delta > 0 {
                    shard.used_memory += mem_delta as usize;
                    self.mem_add(mem_delta as usize);
                } else if mem_delta < 0 {
                    let freed = (-mem_delta) as usize;
                    shard.used_memory = shard.used_memory.saturating_sub(freed);
                    self.mem_sub(freed);
                }
            }
            drop(shard);
            for key in disk_remove {
                self.remove_from_disk(&key);
            }
        }
        // Cold-tiered encrypted values live on disk, invisible to the in-RAM
        // pass above; rewrap them in place too so a later RETIRE can't orphan them.
        if let Some(disk_shards) = &self.disk_shards {
            for ds in disk_shards.iter() {
                let mut disk = ds.lock();
                let entries = disk
                    .dump_all(Instant::now())
                    .map_err(|e| format!("ERR rewrap cold read failed: {e}"))?;
                for mut entry in entries {
                    if self.reencrypt_cold_dump_value(&entry.key, &mut entry.value)? {
                        disk.put(&entry.key, &entry)
                            .map_err(|e| format!("ERR rewrap cold write failed: {e}"))?;
                        count += 1;
                    }
                }
            }
        }
        // Make the rewrap durable: persist re-wrapped in-memory values, re-seal
        // encrypted vectors (plaintext in RAM) under the current keyset, and
        // truncate the WAL so a restart can't replay pre-rewrap (old-key) bytes.
        crate::snapshot::save_and_truncate_wal_consistent(self)
            .map_err(|e| format!("ERR rewrap persist failed: {e}"))?;
        Ok(count)
    }

    pub(crate) fn enc_retire_key(&self, key_id: &str) -> Result<(), String> {
        let remaining = self.encryption().remaining_key_ids_without(key_id);
        if remaining.is_empty() {
            return Err("ERR ENC cannot retire the last key".to_string());
        }
        for shard in self.shards.iter() {
            let shard = shard.read();
            for entry in shard.data.values() {
                match &entry.value {
                    StoreValue::Str(value) => {
                        if encrypted_value_would_be_orphaned(value, &remaining) {
                            return Err(
                                "ERR ENC key is still required by encrypted data".to_string()
                            );
                        }
                    }
                    StoreValue::StrBuf(value) => {
                        if encrypted_value_would_be_orphaned(value, &remaining) {
                            return Err(
                                "ERR ENC key is still required by encrypted data".to_string()
                            );
                        }
                    }
                    StoreValue::Hash(map) => {
                        for value in map.values() {
                            if encrypted_value_would_be_orphaned(value, &remaining) {
                                return Err(
                                    "ERR ENC key is still required by encrypted data".to_string()
                                );
                            }
                        }
                    }
                    StoreValue::List(list) => {
                        for elem in list.iter() {
                            if encrypted_value_would_be_orphaned(elem, &remaining) {
                                return Err(
                                    "ERR ENC key is still required by encrypted data".to_string()
                                );
                            }
                        }
                    }
                    StoreValue::Stream(stream) => {
                        for fields in stream.entries.values() {
                            for (_field, value) in fields {
                                if encrypted_value_would_be_orphaned(value, &remaining) {
                                    return Err("ERR ENC key is still required by encrypted data"
                                        .to_string());
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        // Cold-tiered encrypted values are invisible to the in-RAM scan above;
        // scan the disk tier too so we never retire a key they still need.
        if let Some(disk_shards) = &self.disk_shards {
            for ds in disk_shards.iter() {
                let mut disk = ds.lock();
                let entries = disk
                    .dump_all(Instant::now())
                    .map_err(|e| format!("ERR retire cold scan failed: {e}"))?;
                for entry in &entries {
                    if Self::dump_value_would_orphan(&entry.value, &remaining) {
                        return Err("ERR ENC key is still required by encrypted data".to_string());
                    }
                }
            }
        }
        // Re-seal all at-rest data (in-memory values + plaintext-in-RAM vectors)
        // under the current keyset and truncate the WAL before removing the key,
        // so nothing persisted still references it.
        crate::snapshot::save_and_truncate_wal_consistent(self)
            .map_err(|e| format!("ERR retire persist failed: {e}"))?;
        self.encryption().retire(key_id)
    }

    fn insert_vector_indexes(&self, key: String, dims: u32, data: Vec<f32>) {
        if let Some((table, field, _)) = parse_table_vector_key(&key) {
            let table_field = table_vector_index_name(table, field);
            self.table_vector_indexes
                .write()
                .entry((dims, table_field))
                .or_insert_with(|| crate::hnsw::HnswIndex::new(dims))
                .insert(key, data);
        } else {
            self.vector_indexes
                .write()
                .entry(dims)
                .or_insert_with(|| crate::hnsw::HnswIndex::new(dims))
                .insert(key, data);
        }
    }

    fn remove_vector_indexes(&self, key: &str, dims: u32) {
        if let Some((table, field, _)) = parse_table_vector_key(key) {
            let table_field = table_vector_index_name(table, field);
            if let Some(index) = self
                .table_vector_indexes
                .write()
                .get_mut(&(dims, table_field))
            {
                index.remove(key);
            }
        } else if let Some(index) = self.vector_indexes.write().get_mut(&dims) {
            index.remove(key);
        }
    }

    /// Current instance uptime used by INFO.
    pub(crate) fn uptime_seconds(&self) -> u64 {
        self.metrics.start_time.elapsed().as_secs()
    }

    pub(crate) fn connected_clients(&self) -> usize {
        self.metrics.connected_clients.load(Ordering::Relaxed)
    }

    pub(crate) fn client_connected(&self) {
        self.metrics
            .connected_clients
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn client_disconnected(&self) {
        self.metrics
            .connected_clients
            .fetch_sub(1, Ordering::Relaxed);
    }

    pub(crate) fn total_commands(&self) -> usize {
        self.metrics.total_commands.load(Ordering::Relaxed)
    }

    pub(crate) fn add_total_commands(&self, count: usize) {
        self.metrics
            .total_commands
            .fetch_add(count, Ordering::Relaxed);
    }

    pub(crate) fn lru_clock(&self) -> u32 {
        self.metrics.lru_clock.load(Ordering::Relaxed)
    }

    pub(crate) fn set_lru_clock(&self, clock: u32) {
        self.metrics.lru_clock.store(clock, Ordering::Relaxed);
    }

    /// Subtract from this instance's memory counter without underflow.
    fn mem_sub(&self, amount: usize) {
        self.metrics
            .used_memory
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_sub(amount))
            })
            .ok();
    }

    fn mem_add(&self, amount: usize) {
        self.metrics
            .used_memory
            .fetch_add(amount, Ordering::Relaxed);
    }

    #[inline(always)]
    pub(crate) fn key_added(&self) {
        self.metrics.key_count.fetch_add(1, Ordering::Relaxed);
    }

    #[inline(always)]
    pub(crate) fn key_removed(&self) {
        self.metrics
            .key_count
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_sub(1))
            })
            .ok();
    }

    pub(crate) fn record_wal_append_error(&self) {
        self.metrics
            .persistence_err_wal_append
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_wal_fsync_error(&self) {
        self.metrics
            .persistence_err_wal_fsync
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_disk_write_error(&self) {
        self.metrics
            .persistence_err_disk_write
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn persistence_wal_append_errors(&self) -> usize {
        self.metrics
            .persistence_err_wal_append
            .load(Ordering::Relaxed)
    }

    pub(crate) fn persistence_wal_fsync_errors(&self) -> usize {
        self.metrics
            .persistence_err_wal_fsync
            .load(Ordering::Relaxed)
    }

    pub(crate) fn persistence_disk_write_errors(&self) -> usize {
        self.metrics
            .persistence_err_disk_write
            .load(Ordering::Relaxed)
    }

    pub(crate) fn script_read_guard(&self) -> parking_lot::RwLockReadGuard<'_, ()> {
        self.script_gate.read()
    }

    pub(crate) fn script_write_guard(&self) -> parking_lot::RwLockWriteGuard<'_, ()> {
        self.script_gate.write()
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

    #[inline(always)]
    fn journal_gate_index(&self, key: &[u8]) -> usize {
        (fx_hash(key) % self.journal_gates.len() as u64) as usize
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

    pub(crate) fn wal_enabled(&self) -> bool {
        self.journal.is_some()
            && !self.wal_suppress.load(Ordering::Relaxed)
            && !self.journal_poisoned.load(Ordering::Acquire)
    }

    pub(crate) fn begin_restore(&self) -> std::io::Result<()> {
        self.restoring
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| std::io::Error::other("database restore is already in progress"))
    }

    pub(crate) fn cancel_restore(&self) {
        self.restoring.store(false, Ordering::Release);
    }

    pub(crate) fn is_restoring(&self) -> bool {
        self.restoring.load(Ordering::Acquire)
    }

    fn ensure_not_restoring(&self) -> std::io::Result<()> {
        if self.is_restoring() {
            Err(std::io::Error::other("database restore is in progress"))
        } else {
            Ok(())
        }
    }

    fn ensure_journal_healthy(&self) -> std::io::Result<()> {
        if self.journal_poisoned.load(Ordering::Acquire) {
            Err(std::io::Error::other(
                "mutation journal is unavailable; restart required",
            ))
        } else {
            Ok(())
        }
    }

    pub(crate) fn begin_shutdown(&self) {
        self.accepting_mutations.store(false, Ordering::Release);
    }

    fn ensure_accepting_mutations(&self) -> std::io::Result<()> {
        if self.accepting_mutations.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(std::io::Error::other(
                "database is shutting down; mutations are no longer accepted",
            ))
        }
    }

    /// Wait for every mutation domain to leave its journal/apply section, then
    /// force the authoritative journal to stable storage. A mutation that was
    /// still waiting for a domain when shutdown began fails its second
    /// `ensure_accepting_mutations` check and cannot cross this barrier later.
    pub(crate) fn finalize_shutdown(&self) -> std::io::Result<()> {
        self.with_write_barrier(|_| self.fsync_wal_checked())
    }

    fn poison_journal(&self) {
        self.journal_poisoned.store(true, Ordering::Release);
    }

    /// True while `replay_wal` is re-applying logged commands. Gates internal
    /// replay-only commands (e.g. `LXRESTORE`) so clients can't invoke them.
    pub(crate) fn wal_replaying(&self) -> bool {
        self.replaying_wal.load(Ordering::Acquire)
    }

    /// Wire the row-delta sink (reactive live queries) at runtime startup.
    pub fn set_row_delta_broker(&self, broker: crate::pubsub::Broker) {
        let _ = self.row_delta_broker.set(broker);
    }

    /// Cheap gate for table mutation sites: is anyone watching row deltas right
    /// now? Lets callers skip building old/new row snapshots when idle.
    pub(crate) fn wants_row_deltas(&self) -> bool {
        !self.wal_suppress.load(Ordering::Relaxed)
            && self
                .row_delta_broker
                .get()
                .is_some_and(|b| b.has_any_row_delta_subs())
    }

    /// Emit a typed row delta for a table row change. Cheap no-op unless a
    /// broker is wired AND some live query is watching AND we aren't replaying
    /// the WAL. The delta carries only the changed pk; the live-query engine
    /// re-evaluates that pk against each subscription.
    pub(crate) fn emit_row_delta(&self, table: &str, pk: &str) {
        if self.wal_suppress.load(Ordering::Relaxed) {
            return;
        }
        let Some(broker) = self.row_delta_broker.get() else {
            return;
        };
        if !broker.has_any_row_delta_subs() {
            return;
        }
        broker.publish_row_delta(crate::pubsub::RowDelta {
            table: table.to_string(),
            pk: pk.to_string(),
        });
    }

    /// Decode and apply an `LXRESTORE` blob (COPY's resolved journal effect). Only
    /// honored during WAL replay.
    pub(crate) fn apply_lxrestore(&self, blob: &[u8]) -> Result<(), String> {
        crate::snapshot::decode_dump_blob(self, blob)
            .map(|_| ())
            .map_err(|e| format!("ERR LXRESTORE decode failed: {e}"))
    }

    pub(crate) fn lock_read_shard(&self, idx: usize) -> parking_lot::RwLockReadGuard<'_, Shard> {
        self.shards[idx].read()
    }

    pub(crate) fn lock_write_shard(&self, idx: usize) -> parking_lot::RwLockWriteGuard<'_, Shard> {
        self.shards[idx].write()
    }

    /// Evict a key from memory. In tiered mode, the entry is serialized to
    /// the disk shard BEFORE being removed from memory. If the disk write
    /// fails, the entry stays in memory (no silent data loss).
    pub fn evict_key(&self, shard_idx: usize, key: &[u8]) -> bool {
        // Placement changes are not journal entries, but they must serialize
        // with the logical mutation boundary. Otherwise a prepared write could
        // inspect the in-memory value, journal its effect, and then find that an
        // eviction moved the value before the apply phase.
        let _placement_guard = self.journal_gates[self.journal_gate_index(key)].lock();
        if let Some(ref disk_shards) = self.disk_shards {
            // Hold the shard lock across the disk write AND the removal so the
            // entry we serialize to disk is exactly the one we remove. Dropping
            // the lock for the disk I/O (as this used to) let a concurrent write
            // land a new value in the gap, which the unconditional remove then
            // discarded -- a silent lost update made durable by the next snapshot.
            // Lock order is shard -> disk; `try_promote` releases its disk lock
            // before taking a shard lock, so there is no AB-BA deadlock.
            let mut shard = self.shards[shard_idx].write();
            let (key_string, dump, mem) = match shard.data.get(key) {
                Some(entry) => {
                    if matches!(entry.value, StoreValue::Vector(_)) {
                        return false;
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
                    let key_string = key_string(key);
                    let dump = self.entry_to_dump(&key_string, &entry.value, ttl_ms);
                    let mem = estimate_entry_memory(key, &entry.value);
                    (key_string, dump, mem)
                }
                None => return false,
            };

            let disk_idx = (fx_hash(key) % disk_shards.len() as u64) as usize;
            let mut disk = disk_shards[disk_idx].lock();
            if let Err(e) = disk.put(&key_string, &dump) {
                self.record_disk_write_error();
                self.emit_error(crate::ServerErrorEvent::DiskEvictionWriteFailed {
                    key: key_string,
                    error: e.to_string(),
                });
                return false;
            }
            if disk.should_compact() {
                if let Err(e) = disk.compact() {
                    self.emit_error(crate::ServerErrorEvent::InlineCompactionFailed {
                        error: e.to_string(),
                    });
                }
            }
            drop(disk);

            if shard.data.remove(key).is_some() {
                self.key_removed();
                shard.used_memory = shard.used_memory.saturating_sub(mem);
                self.mem_sub(mem);
                shard.version += 1;
                return true;
            }
        } else {
            let mut shard = self.shards[shard_idx].write();
            if let Some(entry) = shard.data.remove(key) {
                self.key_removed();
                let mem = estimate_entry_memory(key, &entry.value);
                shard.used_memory = shard.used_memory.saturating_sub(mem);
                self.mem_sub(mem);
                shard.version += 1;
                return true;
            }
        }
        false
    }

    fn entry_to_dump(&self, key: &str, value: &StoreValue, ttl_ms: i64) -> DumpEntry {
        let dump_value = store_value_to_dump_value(value);
        DumpEntry {
            key: key.to_string(),
            value: dump_value,
            ttl_ms,
        }
    }

    /// Promote a cold key from disk back to memory. Called before every
    /// command (reads AND writes) to ensure the entry is hot before operating
    /// on it. Returns true if the key was found on disk and promoted. A cold
    /// read failure is surfaced rather than being indistinguishable from a
    /// missing key.
    /// For writes like HSET/LPUSH, this preserves existing data that would
    /// otherwise be lost if the command created a new empty entry.
    pub fn try_promote(&self, key: &[u8], now: Instant) -> Result<bool, String> {
        // Keep the disk-to-memory move indivisible with respect to prepared
        // writes. This is reentrant when a caller already owns the key domain.
        let _placement_guard = self.journal_gates[self.journal_gate_index(key)].lock();
        let disk_shards = match &self.disk_shards {
            Some(ds) => ds,
            None => return Ok(false),
        };
        let didx = self.disk_shard_index(key);
        let key_string = std::str::from_utf8(key).unwrap_or_default();

        let mut disk = disk_shards[didx].lock();
        if !disk.contains(key_string) {
            return Ok(false);
        }

        let result = match disk.get(key_string, now) {
            Ok(Some((value, ttl))) => Some((value, ttl)),
            Ok(None) => return Ok(false),
            Err(error) => {
                // The cold tier is part of the current live state. Once it
                // cannot be read, any mutation that treats the key as absent
                // could overwrite or omit existing data. Fence writes until
                // restart/recovery reconstructs a trustworthy view.
                self.poison_journal();
                self.emit_error(crate::ServerErrorEvent::DiskPromotionReadFailed {
                    key: key_string.to_string(),
                    error: error.to_string(),
                });
                return Err(format!(
                    "ERR cold storage read failed for key '{}': {error}",
                    String::from_utf8_lossy(key)
                ));
            }
        };
        disk.remove(key_string);
        drop(disk);

        if let Some((value, ttl)) = result {
            self.load_entry(key_string.to_string(), value, ttl);
            Ok(true)
        } else {
            Ok(false)
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

    /// Fast in-memory tracked key count used for diagnostics/INFO only.
    /// This is not a Redis-contract replacement for DBSIZE.
    pub fn tracked_key_count(&self) -> usize {
        self.metrics.key_count.load(Ordering::Relaxed)
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

    /// Commit one mutation at the authoritative journal boundary.
    ///
    /// The journal append happens before `apply`, and an append/fsync failure
    /// prevents `apply` from running. A striped gate remains held across both
    /// phases, so overlapping mutations are applied in the same order they are
    /// recovered while independent keys may still proceed concurrently.
    pub(crate) fn commit_journaled<T, F>(&self, args: &[&[u8]], apply: F) -> std::io::Result<T>
    where
        F: FnOnce() -> T,
    {
        let commit = self.begin_journaled(args)?;
        let result = apply();
        commit.complete()?;
        Ok(result)
    }

    /// Commit a raw command only when its apply phase succeeds.
    ///
    /// A generic command cannot prove success until it runs. Keep the WAL
    /// locked from append through apply so a rejected command can remove its
    /// own final frame without truncating a concurrent writer. The mutation
    /// domain guards also keep snapshots outside this decision window.
    pub(crate) fn commit_journaled_checked<T, F>(
        &self,
        args: &[&[u8]],
        apply: F,
    ) -> std::io::Result<T>
    where
        F: FnOnce() -> (T, bool),
    {
        let prepared = self.prepare_journaled(args)?;
        if prepared.bypassed {
            return Ok(apply().0);
        }

        let Some(journal) = &self.journal else {
            return Ok(apply().0);
        };
        let JournalPrepareGuard {
            store,
            guards,
            bypassed: _,
        } = prepared;
        let mut wal = journal.lock();
        let append_offset = self.append_journal_commands_locked(&mut wal, &[args])?;
        let commit = JournalCommitGuard {
            store,
            _guards: guards,
            armed: true,
        };
        let (result, committed) = apply();
        if !committed {
            if let Err(error) = wal.rollback_to(append_offset) {
                self.poison_journal();
                self.record_wal_append_error();
                self.emit_error(crate::ServerErrorEvent::WalAppendFailed {
                    error: error.to_string(),
                });
                return Err(std::io::Error::other(format!(
                    "failed to remove rejected WAL command: {error}"
                )));
            }
            commit.rolled_back();
        } else {
            commit.complete()?;
        }
        Ok(result)
    }

    /// Commit a resolved multi-effect mutation as one atomic journal append.
    pub(crate) fn commit_journaled_batch<'a, T, F>(
        &self,
        commands: &[&'a [&'a [u8]]],
        apply: F,
    ) -> std::io::Result<T>
    where
        F: FnOnce() -> T,
    {
        let commit = self.begin_journaled_batch(commands)?;
        let result = apply();
        commit.complete()?;
        Ok(result)
    }

    pub(crate) fn begin_journaled<'a>(
        &'a self,
        args: &[&[u8]],
    ) -> std::io::Result<JournalCommitGuard<'a>> {
        self.begin_journaled_batch(&[args])
    }

    pub(crate) fn begin_journaled_batch<'a>(
        &'a self,
        commands: &[&[&[u8]]],
    ) -> std::io::Result<JournalCommitGuard<'a>> {
        let prepare = self.prepare_journaled_batch(commands)?;
        prepare.commit_batch(commands)
    }

    /// Lock the mutation domains named by `route_args` while the caller resolves
    /// a deterministic journal command. No state may be changed until the
    /// returned guard is successfully consumed through `commit`.
    pub(crate) fn prepare_journaled<'a>(
        &'a self,
        route_args: &[&[u8]],
    ) -> std::io::Result<JournalPrepareGuard<'a>> {
        self.prepare_journaled_batch(&[route_args])
    }

    fn prepare_journaled_batch<'a>(
        &'a self,
        commands: &[&[&[u8]]],
    ) -> std::io::Result<JournalPrepareGuard<'a>> {
        self.ensure_accepting_mutations()?;
        self.ensure_not_restoring()?;
        self.ensure_journal_healthy()?;
        let bypassed = self.wal_suppress.load(Ordering::Relaxed)
            || self.journal.is_none()
            || commands.is_empty();
        let guards = if self.wal_suppress.load(Ordering::Relaxed) || commands.is_empty() {
            Vec::new()
        } else {
            self.journal_gate_indices(commands)
                .iter()
                .map(|&index| self.journal_gates[index].lock())
                .collect()
        };
        self.ensure_accepting_mutations()?;
        self.ensure_not_restoring()?;
        self.ensure_journal_healthy()?;
        Ok(JournalPrepareGuard {
            store: self,
            guards,
            bypassed,
        })
    }

    /// Resolve a state-dependent mutation while its routing gates are held,
    /// append the resolved recovery commands, and only then apply it.
    ///
    /// This is the boundary for generated IDs/timestamps, encrypted envelopes,
    /// conditional writes, random pops, and other operations whose durable form
    /// cannot be derived from the raw client argv alone.
    pub(crate) fn commit_prepared<P, T, E, Prepare, Apply>(
        &self,
        route_args: &[&[u8]],
        prepare: Prepare,
        apply: Apply,
    ) -> std::io::Result<Result<T, E>>
    where
        Prepare: FnOnce() -> Result<JournalPlan<P>, E>,
        Apply: FnOnce(P) -> Result<T, E>,
    {
        let prepared_journal = self.prepare_journaled(route_args)?;
        let plan = match prepare() {
            Ok(plan) => plan,
            Err(error) => return Ok(Err(error)),
        };
        let arg_refs: Vec<Vec<&[u8]>> = plan
            .commands
            .iter()
            .map(|command| command.iter().map(Vec::as_slice).collect())
            .collect();
        let command_refs: Vec<&[&[u8]]> = arg_refs.iter().map(Vec::as_slice).collect();
        let commit = prepared_journal.commit_batch(&command_refs)?;
        let result = apply(plan.prepared);
        if result.is_ok() {
            commit.complete()?;
        }
        Ok(result)
    }

    fn journal_gate_indices(&self, commands: &[&[&[u8]]]) -> Vec<usize> {
        let mut all = false;
        let mut indices = Vec::new();
        for args in commands {
            let Some(key) = self.journal_route_key(args) else {
                all = true;
                break;
            };
            indices.push(self.journal_gate_index(key));
        }
        if all {
            return (0..self.journal_gates.len()).collect();
        }
        indices.sort_unstable();
        indices.dedup();
        indices
    }

    /// Return the serialization key for commands with one unambiguous mutation
    /// domain. `None` deliberately takes the full write barrier: correctness is
    /// preferable to guessing for global, script, and unresolved multi-key work.
    fn journal_route_key<'a>(&self, args: &'a [&'a [u8]]) -> Option<&'a [u8]> {
        let cmd = *args.first()?;
        if cmd.eq_ignore_ascii_case(b"FLUSHDB")
            || cmd.eq_ignore_ascii_case(b"FLUSHALL")
            || cmd.eq_ignore_ascii_case(b"EVAL")
            || cmd.eq_ignore_ascii_case(b"EVALSHA")
            || cmd.eq_ignore_ascii_case(b"FCALL")
            || cmd.eq_ignore_ascii_case(b"MSET")
            || cmd.eq_ignore_ascii_case(b"MSETNX")
            || cmd.eq_ignore_ascii_case(b"RENAME")
            || cmd.eq_ignore_ascii_case(b"RENAMENX")
            || cmd.eq_ignore_ascii_case(b"COPY")
            || cmd.eq_ignore_ascii_case(b"SMOVE")
            || cmd.eq_ignore_ascii_case(b"LMOVE")
            || cmd.eq_ignore_ascii_case(b"RPOPLPUSH")
            || cmd.eq_ignore_ascii_case(b"BITOP")
            || cmd.eq_ignore_ascii_case(b"PFMERGE")
            || cmd.eq_ignore_ascii_case(b"SORT")
            || cmd.eq_ignore_ascii_case(b"GEOSEARCHSTORE")
            || cmd.eq_ignore_ascii_case(b"GEORADIUS")
            || cmd.eq_ignore_ascii_case(b"GEORADIUSBYMEMBER")
            || cmd.eq_ignore_ascii_case(b"SUNIONSTORE")
            || cmd.eq_ignore_ascii_case(b"SINTERSTORE")
            || cmd.eq_ignore_ascii_case(b"SDIFFSTORE")
            || cmd.eq_ignore_ascii_case(b"ZUNIONSTORE")
            || cmd.eq_ignore_ascii_case(b"ZINTERSTORE")
            || cmd.eq_ignore_ascii_case(b"ZDIFFSTORE")
            || cmd.eq_ignore_ascii_case(b"ZRANGESTORE")
        {
            return None;
        }
        if (cmd.eq_ignore_ascii_case(b"DEL") || cmd.eq_ignore_ascii_case(b"UNLINK"))
            && args.len() > 2
        {
            return None;
        }
        if cmd.eq_ignore_ascii_case(b"TCREATE")
            || cmd.eq_ignore_ascii_case(b"TROWSET")
            || cmd.eq_ignore_ascii_case(b"TDELETE")
            || cmd.eq_ignore_ascii_case(b"TDROP")
            || cmd.eq_ignore_ascii_case(b"TALTER")
            || cmd.eq_ignore_ascii_case(b"TINDEX")
            || cmd.eq_ignore_ascii_case(b"TDROPINDEX")
        {
            // Table constraints, cascades, and secondary indexes can cross
            // physical keys and tables. Keep them in one reentrant domain until
            // a future transaction layer can expose finer-grained lock sets.
            return Some(b"\0lux:tables");
        }
        if cmd.eq_ignore_ascii_case(b"ENC") {
            let subcommand = *args.get(1)?;
            if subcommand.eq_ignore_ascii_case(b"RAWSET")
                || subcommand.eq_ignore_ascii_case(b"RAWHSET")
                || subcommand.eq_ignore_ascii_case(b"RAWLPUSH")
                || subcommand.eq_ignore_ascii_case(b"RAWRPUSH")
                || subcommand.eq_ignore_ascii_case(b"RAWVSET")
            {
                return args.get(2).copied();
            }
            return None;
        }
        if cmd.eq_ignore_ascii_case(b"XGROUP") {
            return args.get(2).copied();
        }
        args.get(1).copied()
    }

    fn append_journal_commands(&self, commands: &[&[&[u8]]]) -> std::io::Result<()> {
        let Some(journal) = &self.journal else {
            return Ok(());
        };

        let mut wal = journal.lock();
        self.append_journal_commands_locked(&mut wal, commands)
            .map(|_| ())
    }

    fn append_journal_commands_locked(
        &self,
        wal: &mut crate::disk::Wal,
        commands: &[&[&[u8]]],
    ) -> std::io::Result<u64> {
        #[cfg(test)]
        if self
            .journal_failures_to_inject
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            let error = std::io::Error::other("injected journal append failure");
            self.record_wal_append_error();
            self.emit_error(crate::ServerErrorEvent::WalAppendFailed {
                error: error.to_string(),
            });
            return Err(error);
        }

        self.ensure_journal_healthy()?;
        let append_offset = wal.end_offset()?;
        if let Err(error) = wal.append_commands(commands.iter().copied()) {
            let rollback_error = wal.rollback_to(append_offset).err();
            if rollback_error.is_some() {
                self.poison_journal();
            }
            self.record_wal_append_error();
            self.emit_error(crate::ServerErrorEvent::WalAppendFailed {
                error: error.to_string(),
            });
            return Err(match rollback_error {
                Some(rollback_error) => std::io::Error::other(format!(
                    "WAL append failed ({error}); rollback also failed ({rollback_error})"
                )),
                None => error,
            });
        }
        if self.config.durability.policy.syncs_each_append() {
            if let Err(error) = self.sync_journal_locked(wal) {
                let rollback_error = wal.rollback_to(append_offset).err();
                if rollback_error.is_some() {
                    self.poison_journal();
                }
                self.record_wal_fsync_error();
                self.emit_error(crate::ServerErrorEvent::WalFsyncFailed {
                    error: error.to_string(),
                });
                return Err(match rollback_error {
                    Some(rollback_error) => std::io::Error::other(format!(
                        "WAL fsync failed ({error}); rollback also failed ({rollback_error})"
                    )),
                    None => error,
                });
            }
        }
        Ok(append_offset)
    }

    #[cfg(test)]
    pub(crate) fn inject_journal_failures(&self, count: usize) {
        self.journal_failures_to_inject
            .store(count, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn inject_journal_fsync_failures(&self, count: usize) {
        self.journal_fsync_failures_to_inject
            .store(count, Ordering::Relaxed);
    }

    fn sync_journal_locked(&self, wal: &mut crate::disk::Wal) -> std::io::Result<()> {
        #[cfg(test)]
        if self
            .journal_fsync_failures_to_inject
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return Err(std::io::Error::other("injected journal fsync failure"));
        }
        wal.fsync()
    }

    /// Replay WAL entries by re-executing each command through the normal
    /// command dispatch. Called on startup after snapshot load to recover
    /// writes that happened between the last snapshot and the crash.
    /// WAL logging is suppressed during replay to avoid re-logging.
    pub fn replay_wal(&self, broker: &crate::pubsub::Broker) -> std::io::Result<()> {
        let journal = match &self.journal {
            Some(journal) => journal,
            None => return Ok(()),
        };
        let checkpoints = self.recovery_wal_checkpoints.lock().clone();
        self.wal_suppress
            .store(true, std::sync::atomic::Ordering::Relaxed);
        self.replaying_wal.store(true, Ordering::Release);
        let mut total = 0usize;
        // Every frame observes one logical recovery instant. A PXAT deadline
        // that elapsed during downtime is therefore still visible to later
        // TTL-preserving frames at that same instant, but is expired before the
        // server accepts its first post-recovery command.
        let replay_now = Instant::now();
        let wal_cache =
            std::sync::Arc::new(parking_lot::RwLock::new(crate::tables::SchemaCache::new()));
        let result = (|| -> std::io::Result<()> {
            let mut replay_one = |name: &str,
                                  source: usize,
                                  w: &parking_lot::Mutex<crate::disk::Wal>|
             -> std::io::Result<()> {
                let mut wal = w.lock();
                match wal.replay_from(checkpoints.get(name).copied()) {
                    Ok(replay) => {
                        for cmd_args in replay.commands {
                            let refs: Vec<&[u8]> = cmd_args.iter().map(|a| a.as_slice()).collect();
                            let mut out = bytes::BytesMut::new();
                            let result = crate::cmd::execute(
                                self, &wal_cache, broker, &refs, &mut out, replay_now,
                            );
                            if !matches!(result, crate::cmd::CmdResult::Written)
                                || out.first() == Some(&b'-')
                            {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    format!(
                                        "WAL command failed during recovery: {}",
                                        String::from_utf8_lossy(&out)
                                    ),
                                ));
                            }
                            total += 1;
                        }
                        Ok(())
                    }
                    Err(e) => {
                        self.emit_error(crate::ServerErrorEvent::WalReplayFailed {
                            shard: source,
                            error: e.to_string(),
                        });
                        Err(e)
                    }
                }
            };

            // Upgrade path: everything in the old per-shard files predates every
            // frame in the global journal opened for this process.
            for (source, wal) in &self.legacy_wals {
                replay_one(&format!("shard_{source}"), *source, wal)?;
            }
            replay_one("global", 0, journal)?;
            if total > 0 {
                crate::emit_info(
                    &self.config,
                    crate::ServerInfoEvent::WalReplayed { commands: total },
                );
            }
            Ok(())
        })();
        self.replaying_wal.store(false, Ordering::Release);
        self.wal_suppress
            .store(false, std::sync::atomic::Ordering::Relaxed);
        result
    }

    /// Capture every journal position represented by a snapshot. The caller
    /// must hold the write barrier so no mutation can cross these offsets.
    pub(crate) fn wal_checkpoints(
        &self,
    ) -> std::io::Result<Vec<(String, crate::disk::WalCheckpoint)>> {
        let mut checkpoints = Vec::with_capacity(self.legacy_wals.len() + 1);
        for (source, wal) in &self.legacy_wals {
            checkpoints.push((format!("shard_{source}"), wal.lock().checkpoint()?));
        }
        if let Some(journal) = &self.journal {
            checkpoints.push(("global".to_string(), journal.lock().checkpoint()?));
        }
        Ok(checkpoints)
    }

    pub fn truncate_wal(&self) -> std::io::Result<()> {
        let mut first_error = None;
        for (_, w) in &self.legacy_wals {
            let mut wal = w.lock();
            if let Err(e) = wal.truncate() {
                self.emit_error(crate::ServerErrorEvent::WalTruncateFailed {
                    error: e.to_string(),
                });
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }
        }
        if let Some(journal) = &self.journal {
            let mut wal = journal.lock();
            if let Err(e) = wal.truncate() {
                self.emit_error(crate::ServerErrorEvent::WalTruncateFailed {
                    error: e.to_string(),
                });
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }
        }
        match first_error {
            Some(error) => {
                self.poison_journal();
                Err(error)
            }
            None => Ok(()),
        }
    }

    pub fn remove_from_disk(&self, key: &[u8]) {
        if let Some(ref ds) = self.disk_shards {
            let didx = self.disk_shard_index(key);
            let ks = std::str::from_utf8(key).unwrap_or_default();
            ds[didx].lock().remove(ks);
        }
    }

    pub fn dump_disk_entries(&self, now: Instant) -> std::io::Result<Vec<DumpEntry>> {
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
                            });
                            return Err(e);
                        }
                    }
                }
                Ok(entries)
            }
            None => Ok(Vec::new()),
        }
    }

    /// Flush WAL data to disk. `every_second` calls this on its configured
    /// interval; `always_sync` calls the same primitive after each append.
    pub fn fsync_wal(&self) {
        let _ = self.fsync_wal_checked();
    }

    pub(crate) fn fsync_wal_checked(&self) -> std::io::Result<()> {
        if let Some(journal) = &self.journal {
            let mut wal = journal.lock();
            if let Err(e) = self.sync_journal_locked(&mut wal) {
                // A periodic sync failure means the configured durability
                // window can no longer be bounded. Fence subsequent writes
                // until restart rather than continuing to acknowledge them
                // through an unhealthy persistence path.
                self.poison_journal();
                self.record_wal_fsync_error();
                self.emit_error(crate::ServerErrorEvent::WalFsyncFailed {
                    error: e.to_string(),
                });
                return Err(e);
            }
        }
        Ok(())
    }

    #[inline(always)]
    pub(crate) fn get_from_shard(data: &ShardData, key: &[u8], now: Instant) -> Option<Bytes> {
        data.get(key).and_then(|entry| {
            if entry.is_expired_at(now) {
                return None;
            }
            entry.value.string_to_bytes()
        })
    }

    #[inline(always)]
    fn user_kv_key(key: &[u8]) -> String {
        key_string(key)
    }

    #[inline(always)]
    fn user_hash_field(field: &[u8]) -> String {
        key_string(field)
    }

    #[inline(always)]
    fn is_table_storage_key(key: &[u8]) -> bool {
        key.starts_with(b"_t:")
    }

    pub(crate) fn decrypt_kv_string_value(
        &self,
        key: &[u8],
        value: Bytes,
    ) -> Result<Bytes, String> {
        if !crate::encryption::EncryptionKeyring::is_encrypted_value(&value) {
            return Ok(value);
        }
        let key_name = Self::user_kv_key(key);
        self.encryption()
            .decrypt("__lux_kv", "value", &key_name, &value)
            .map(Bytes::from)
    }

    fn encrypt_kv_string_value(&self, key: &[u8], value: &[u8]) -> Result<Vec<u8>, String> {
        let key_name = Self::user_kv_key(key);
        self.encryption()
            .encrypt("__lux_kv", "value", &key_name, value)
    }

    /// Encrypt a list element. AAD is intentionally key-independent so an
    /// envelope stays decryptable after LMOVE/RPOPLPUSH move it to another list
    /// (no re-keying). Per-value random DEK + nonce still protects each element.
    pub(crate) fn encrypt_list_element(&self, value: &[u8]) -> Result<Vec<u8>, String> {
        self.encryption()
            .encrypt("__lux_list", "element", "", value)
    }

    /// Decrypt a list element if it is an encryption envelope; pass plaintext
    /// through untouched so encrypted and plaintext elements can coexist.
    pub(crate) fn decrypt_list_element(&self, value: Bytes) -> Result<Bytes, String> {
        if !crate::encryption::EncryptionKeyring::is_encrypted_value(&value) {
            return Ok(value);
        }
        self.encryption()
            .decrypt("__lux_list", "element", "", &value)
            .map(Bytes::from)
    }

    /// Encrypt a stream entry field value. AAD binds the stream key + field.
    pub(crate) fn encrypt_stream_value(
        &self,
        key: &[u8],
        field: &[u8],
        value: &[u8],
    ) -> Result<Vec<u8>, String> {
        let key_name = Self::user_kv_key(key);
        let field_name = Self::user_hash_field(field);
        self.encryption()
            .encrypt("__lux_stream", &field_name, &key_name, value)
    }

    /// Decrypt a stream entry field value if it is an envelope.
    pub(crate) fn decrypt_stream_value(
        &self,
        key: &[u8],
        field: &[u8],
        value: Bytes,
    ) -> Result<Bytes, String> {
        if !crate::encryption::EncryptionKeyring::is_encrypted_value(&value) {
            return Ok(value);
        }
        let key_name = Self::user_kv_key(key);
        let field_name = Self::user_hash_field(field);
        self.encryption()
            .decrypt("__lux_stream", &field_name, &key_name, &value)
            .map(Bytes::from)
    }

    /// Decrypt all field values of one stream entry for output. Plaintext (and,
    /// defensively, undecryptable) values pass through unchanged.
    pub(crate) fn decrypt_stream_fields(
        &self,
        key: &[u8],
        fields: &[(String, Bytes)],
    ) -> Vec<(String, Bytes)> {
        fields
            .iter()
            .map(|(f, v)| {
                let dv = self
                    .decrypt_stream_value(key, f.as_bytes(), v.clone())
                    .unwrap_or_else(|_| v.clone());
                (f.clone(), dv)
            })
            .collect()
    }

    /// True if relocating this value to a different key would orphan encrypted
    /// data, because its AEAD AAD is bound to the key name. Lists use a
    /// key-independent AAD and vectors stay plaintext in RAM (re-sealed on the
    /// next write), so both self-heal on a move and are not blocked.
    pub(crate) fn value_has_key_bound_encryption(value: &StoreValue) -> bool {
        use crate::encryption::EncryptionKeyring as E;
        match value {
            StoreValue::Str(v) => E::is_encrypted_value(v),
            StoreValue::StrBuf(v) => E::is_encrypted_value(v),
            StoreValue::Hash(map) => map.values().any(|v| E::is_encrypted_value(v)),
            StoreValue::Stream(s) => s
                .entries
                .values()
                .any(|fields| fields.iter().any(|(_, v)| E::is_encrypted_value(v))),
            _ => false,
        }
    }

    /// Seal a vector (as little-endian f32 bytes) for at-rest storage. AAD binds
    /// the vector's storage key so envelopes can't be swapped between slots.
    pub(crate) fn encrypt_vector(&self, key: &[u8], data: &[f32]) -> Result<Vec<u8>, String> {
        let key_name = Self::user_kv_key(key);
        let mut bytes = Vec::with_capacity(data.len() * 4);
        for f in data {
            bytes.extend_from_slice(&f.to_le_bytes());
        }
        self.encryption()
            .encrypt("__lux_vec", "data", &key_name, &bytes)
    }

    /// Decrypt a sealed vector back into f32 values.
    pub(crate) fn decrypt_vector(&self, key: &[u8], envelope: &[u8]) -> Result<Vec<f32>, String> {
        let key_name = Self::user_kv_key(key);
        let bytes = self
            .encryption()
            .decrypt("__lux_vec", "data", &key_name, envelope)?;
        if !bytes.len().is_multiple_of(4) {
            return Err("ERR corrupt encrypted vector payload".to_string());
        }
        Ok(bytes
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect())
    }

    pub(crate) fn decrypt_hash_field_value(
        &self,
        key: &[u8],
        field: &[u8],
        value: Bytes,
    ) -> Result<Bytes, String> {
        if Self::is_table_storage_key(key)
            || !crate::encryption::EncryptionKeyring::is_encrypted_value(&value)
        {
            return Ok(value);
        }
        let key_name = Self::user_kv_key(key);
        let field_name = Self::user_hash_field(field);
        self.encryption()
            .decrypt("__lux_hash", &field_name, &key_name, &value)
            .map(Bytes::from)
    }

    fn encrypt_hash_field_value(
        &self,
        key: &[u8],
        field: &[u8],
        value: &[u8],
    ) -> Result<Vec<u8>, String> {
        let key_name = Self::user_kv_key(key);
        let field_name = Self::user_hash_field(field);
        self.encryption()
            .encrypt("__lux_hash", &field_name, &key_name, value)
    }

    pub(crate) fn kv_string_is_encrypted(&self, key: &[u8], now: Instant) -> bool {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        Self::get_from_shard(&shard.data, key, now)
            .as_ref()
            .is_some_and(|value| crate::encryption::EncryptionKeyring::is_encrypted_value(value))
    }

    pub(crate) fn get_raw_string(&self, key: &[u8], now: Instant) -> Option<Bytes> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        Self::get_from_shard(&shard.data, key, now)
    }

    pub(crate) fn get_kv_string(&self, key: &[u8], now: Instant) -> Result<Option<Bytes>, String> {
        self.get_raw_string(key, now)
            .map(|value| self.decrypt_kv_string_value(key, value))
            .transpose()
    }

    #[inline(always)]
    #[allow(dead_code)]
    pub(crate) fn get_and_write(
        data: &ShardData,
        key: &[u8],
        now: Instant,
        out: &mut bytes::BytesMut,
    ) {
        match data.get(key) {
            Some(entry) if !entry.is_expired_at(now) => {
                if let Some(s) = entry.value.string_bytes() {
                    crate::resp::write_bulk_raw(out, s);
                } else {
                    crate::resp::write_null(out);
                }
            }
            _ => crate::resp::write_null(out),
        }
    }

    #[inline(always)]
    pub(crate) fn get_kv_and_write_from_shard(
        &self,
        data: &ShardData,
        key: &[u8],
        now: Instant,
        out: &mut bytes::BytesMut,
    ) {
        match data.get(key) {
            Some(entry) if !entry.is_expired_at(now) => {
                if let Some(s) = entry.value.string_to_bytes() {
                    match self.decrypt_kv_string_value(key, s) {
                        Ok(value) => crate::resp::write_bulk_raw(out, &value),
                        Err(err) => crate::resp::write_error(out, &err),
                    }
                } else {
                    crate::resp::write_null(out);
                }
            }
            _ => crate::resp::write_null(out),
        }
    }

    #[inline(always)]
    pub(crate) fn set_on_shard(
        &self,
        data: &mut ShardData,
        key: &[u8],
        value: &[u8],
        ttl: Option<Duration>,
        now: Instant,
    ) {
        let hash = fx_hash(key);
        let expires_at = ttl.map(|d| now + d);
        let new_value = StoreValue::Str(Bytes::copy_from_slice(value));
        let new_size = key.len() + 64 + value.len();
        let clock = self.lru_clock();
        match data
            .raw_entry_mut()
            .from_hash(hash, |k| k.as_slice() == key)
        {
            hashbrown::hash_map::RawEntryMut::Occupied(mut e) => {
                let old_size = estimate_entry_memory(e.key(), &e.get().value);
                let entry = e.get_mut();
                entry.value = new_value;
                entry.expires_at = expires_at;
                entry.lru_clock = clock;
                if new_size >= old_size {
                    self.mem_add(new_size - old_size);
                } else {
                    self.mem_sub(old_size - new_size);
                }
            }
            hashbrown::hash_map::RawEntryMut::Vacant(e) => {
                e.insert_with_hasher(
                    hash,
                    key_bytes(key),
                    Entry {
                        value: new_value,
                        expires_at,
                        lru_clock: clock,
                    },
                    |k| fx_hash(k),
                );
                self.mem_add(new_size);
                self.key_added();
            }
        }
    }

    pub(crate) fn get_checked(&self, key: &[u8], now: Instant) -> Result<Option<Bytes>, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        let result = Self::get_from_shard(&shard.data, key, now);
        if result.is_some() {
            return Ok(result);
        }
        drop(shard);
        if self.try_promote(key, now)? {
            let shard = self.shards[idx].read();
            Ok(Self::get_from_shard(&shard.data, key, now))
        } else {
            Ok(None)
        }
    }

    pub fn get(&self, key: &[u8], now: Instant) -> Option<Bytes> {
        self.get_checked(key, now).ok().flatten()
    }

    pub fn get_entry_type(&self, key: &[u8], now: Instant) -> Option<&'static str> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        // Fast path for common ASCII/UTF-8 command keys.
        let fast = shard.data.get(key).and_then(|entry| {
            if entry.is_expired_at(now) {
                None
            } else {
                Some(entry.value.type_name())
            }
        });
        if fast.is_some() {
            return fast;
        }
        let raw = Self::get_entry_type_from_shard(&shard.data, key, now);
        if raw.is_some() {
            return raw;
        }
        drop(shard);
        if self.try_promote(key, now).unwrap_or(false) {
            let shard = self.shards[idx].read();
            shard.data.get(key).and_then(|entry| {
                if entry.is_expired_at(now) {
                    None
                } else {
                    Some(entry.value.type_name())
                }
            })
        } else {
            None
        }
    }

    #[inline(always)]
    fn get_entry_type_from_shard(
        data: &ShardData,
        key: &[u8],
        now: Instant,
    ) -> Option<&'static str> {
        let hash = fx_hash(key);
        data.raw_entry()
            .from_hash(hash, |k| k.as_slice() == key)
            .and_then(|(_, entry)| {
                if entry.is_expired_at(now) {
                    None
                } else {
                    Some(entry.value.type_name())
                }
            })
    }

    pub fn sort_get_elements(&self, key: &[u8], now: Instant) -> Result<Vec<String>, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key) {
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
        self.set_on_shard(&mut shard.data, key, value, ttl, now);
        self.remove_from_disk(key);
    }

    #[cfg(test)]
    pub fn set_conditional(
        &self,
        key: &[u8],
        value: &[u8],
        options: SetOptions<'_>,
        now: Instant,
    ) -> Result<(bool, Option<Bytes>), String> {
        let prepared = self.prepare_conditional_set(key, value, options, now)?;
        Ok(self.apply_conditional_set(key, prepared))
    }

    pub(crate) fn prepare_conditional_set(
        &self,
        key: &[u8],
        value: &[u8],
        options: SetOptions<'_>,
        now: Instant,
    ) -> Result<PreparedConditionalSet, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        let mut exists = false;
        let mut old = None;
        let mut old_expires_at = None;
        let mut existing_encrypted = false;
        let mut ifeq_matches = options.ifeq.is_none();
        if let Some(entry) = shard
            .data
            .get(key)
            .filter(|entry| !entry.is_expired_at(now))
        {
            exists = true;
            old_expires_at = entry.expires_at;
            existing_encrypted = entry
                .value
                .string_bytes()
                .is_some_and(crate::encryption::EncryptionKeyring::is_encrypted_value);
            if options.get {
                let raw = entry
                    .value
                    .string_to_bytes()
                    .ok_or_else(|| WRONGTYPE.to_string())?;
                old = Some(self.decrypt_kv_string_value(key, raw)?);
            }
            if let Some(expected) = options.ifeq {
                let raw = entry
                    .value
                    .string_to_bytes()
                    .ok_or_else(|| WRONGTYPE.to_string())?;
                let current = self.decrypt_kv_string_value(key, raw)?;
                ifeq_matches = current == expected;
            }
        }
        let should_set = if options.ifeq.is_some() {
            ifeq_matches
        } else {
            (!options.nx || !exists) && (!options.xx || exists)
        };
        let expires_at = if should_set {
            if options.keep_ttl {
                old_expires_at
            } else {
                options.ttl.map(|d| now + d)
            }
        } else {
            None
        };
        let stored_value = if should_set {
            Some(if options.encrypted || existing_encrypted {
                self.encrypt_kv_string_value(key, value)?
            } else {
                value.to_vec()
            })
        } else {
            None
        };
        Ok(PreparedConditionalSet {
            should_set,
            old,
            stored_value,
            expires_at,
        })
    }

    pub(crate) fn apply_conditional_set(
        &self,
        key: &[u8],
        prepared: PreparedConditionalSet,
    ) -> (bool, Option<Bytes>) {
        if prepared.should_set {
            let idx = self.shard_index(key);
            let mut shard = self.shards[idx].write();
            shard.version += 1;
            let stored_value = prepared
                .stored_value
                .expect("prepared SET value is present when should_set is true");
            let new_value = StoreValue::Str(Bytes::from(stored_value));
            let mem = estimate_entry_memory(key, &new_value);
            let old_entry = shard.data.insert(
                key_bytes(key),
                Entry {
                    value: new_value,
                    expires_at: prepared.expires_at,
                    lru_clock: self.lru_clock(),
                },
            );
            if let Some(old_entry) = old_entry {
                let old_mem = estimate_entry_memory(key, &old_entry.value);
                if mem >= old_mem {
                    self.mem_add(mem - old_mem);
                } else {
                    self.mem_sub(old_mem - mem);
                }
            } else {
                self.mem_add(mem);
                self.key_added();
            }
            self.remove_from_disk(key);
        }
        (prepared.should_set, prepared.old)
    }

    pub fn set_nx(&self, key: &[u8], value: &[u8], now: Instant) -> bool {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        let ks = key;
        if let Some(entry) = shard.data.get(ks) {
            if !entry.is_expired_at(now) {
                return false;
            }
        }
        let new_value = StoreValue::Str(Bytes::copy_from_slice(value));
        let mem = estimate_entry_memory(ks, &new_value);
        let old = shard.data.insert(
            key_bytes(key),
            Entry {
                value: new_value,
                expires_at: None,
                lru_clock: self.lru_clock(),
            },
        );
        if let Some(old_entry) = old {
            let old_mem = estimate_entry_memory(ks, &old_entry.value);
            if mem >= old_mem {
                self.mem_add(mem - old_mem);
            } else {
                self.mem_sub(old_mem - mem);
            }
        } else {
            self.mem_add(mem);
            self.key_added();
        }
        true
    }

    /// SETNX variant for callers that already hold the correct shard write
    /// lock. The caller owns shard versioning, WAL logging, key events, and
    /// disk invalidation when the value changes.
    pub(crate) fn set_nx_on_shard(
        &self,
        data: &mut ShardData,
        key: &[u8],
        value: &[u8],
        now: Instant,
    ) -> bool {
        let ks = key;
        if let Some(entry) = data.get(ks) {
            if !entry.is_expired_at(now) {
                return false;
            }
        }
        let new_value = StoreValue::Str(Bytes::copy_from_slice(value));
        let mem = estimate_entry_memory(ks, &new_value);
        let old = data.insert(
            key_bytes(key),
            Entry {
                value: new_value,
                expires_at: None,
                lru_clock: self.lru_clock(),
            },
        );
        if let Some(old_entry) = old {
            let old_mem = estimate_entry_memory(ks, &old_entry.value);
            if mem >= old_mem {
                self.mem_add(mem - old_mem);
            } else {
                self.mem_sub(old_mem - mem);
            }
        } else {
            self.mem_add(mem);
            self.key_added();
        }
        true
    }

    pub fn get_set(&self, key: &[u8], value: &[u8], now: Instant) -> Option<Bytes> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        let ks = key;
        let old = shard.data.get(ks).and_then(|e| {
            if e.is_expired_at(now) {
                None
            } else {
                e.value.string_to_bytes()
            }
        });
        let new_value = StoreValue::Str(Bytes::copy_from_slice(value));
        let mem = estimate_entry_memory(ks, &new_value);
        let old_entry = shard.data.insert(
            key_bytes(key),
            Entry {
                value: new_value,
                expires_at: None,
                lru_clock: self.lru_clock(),
            },
        );
        if let Some(oe) = old_entry {
            let old_mem = estimate_entry_memory(ks, &oe.value);
            if mem >= old_mem {
                self.mem_add(mem - old_mem);
            } else {
                self.mem_sub(old_mem - mem);
            }
        } else {
            self.mem_add(mem);
            self.key_added();
        }
        old
    }

    /// GETSET variant for callers that already hold the correct shard write
    /// lock. The caller owns shard versioning, WAL logging, key events, and
    /// disk invalidation.
    pub(crate) fn get_set_on_shard(
        &self,
        data: &mut ShardData,
        key: &[u8],
        value: &[u8],
        now: Instant,
    ) -> Option<Bytes> {
        let ks = key;
        let old = data.get(ks).and_then(|e| {
            if e.is_expired_at(now) {
                None
            } else {
                e.value.string_to_bytes()
            }
        });
        let new_value = StoreValue::Str(Bytes::copy_from_slice(value));
        let mem = estimate_entry_memory(ks, &new_value);
        let old_entry = data.insert(
            key_bytes(key),
            Entry {
                value: new_value,
                expires_at: None,
                lru_clock: self.lru_clock(),
            },
        );
        if let Some(oe) = old_entry {
            let old_mem = estimate_entry_memory(ks, &oe.value);
            if mem >= old_mem {
                self.mem_add(mem - old_mem);
            } else {
                self.mem_sub(old_mem - mem);
            }
        } else {
            self.mem_add(mem);
            self.key_added();
        }
        old
    }

    pub fn strlen(&self, key: &[u8], now: Instant) -> i64 {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        Self::strlen_from_shard(&shard.data, key, now)
    }

    pub(crate) fn strlen_from_shard(data: &ShardData, key: &[u8], now: Instant) -> i64 {
        match data.get(key) {
            Some(entry) if !entry.is_expired_at(now) => {
                entry.value.string_bytes().map_or(0, |s| s.len() as i64)
            }
            _ => 0,
        }
    }

    pub fn del(&self, keys: &[&[u8]]) -> i64 {
        let now = Instant::now();
        let mut count = 0i64;
        let mut vector_keys_removed: Vec<(String, u32)> = Vec::new();
        for key in keys {
            let key = *key;
            let idx = self.shard_index(key);
            let mut shard = self.shards[idx].write();
            shard.version += 1;
            if let Some(entry) = shard.data.remove(key) {
                self.key_removed();
                let expired = entry.is_expired_at(now);
                let vector_dims = match &entry.value {
                    StoreValue::Vector(v) => Some(v.dims),
                    _ => None,
                };
                let mem = estimate_entry_memory(key, &entry.value);
                shard.used_memory = shard.used_memory.saturating_sub(mem);
                self.mem_sub(mem);
                if let Some(dims) = vector_dims {
                    vector_keys_removed.push((key_string(key), dims));
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
            for (k, dims) in &vector_keys_removed {
                self.remove_vector_indexes(k, *dims);
            }
        }
        count
    }

    pub fn delifeq(&self, key: &[u8], expected: &[u8], now: Instant) -> Result<bool, String> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        let action = match shard.data.get(key) {
            Some(entry) if entry.is_expired_at(now) => Some(false),
            Some(entry) => {
                let current = entry
                    .value
                    .string_bytes()
                    .ok_or_else(|| WRONGTYPE.to_string())?;
                if current == expected {
                    Some(true)
                } else {
                    None
                }
            }
            None => None,
        };

        match action {
            Some(should_count) => {
                shard.version += 1;
                if let Some(entry) = shard.data.remove(key) {
                    self.key_removed();
                    let mem = estimate_entry_memory(key, &entry.value);
                    shard.used_memory = shard.used_memory.saturating_sub(mem);
                    self.mem_sub(mem);
                    self.remove_from_disk(key);
                }
                Ok(should_count)
            }
            None => Ok(false),
        }
    }

    pub fn exists(&self, keys: &[&[u8]], now: Instant) -> i64 {
        if keys.is_empty() {
            return 0;
        }
        let tiered = self.is_tiered();
        if keys.len() <= 8 {
            let mut count = 0i64;
            for key in keys {
                let idx = self.shard_index(key);
                let shard = self.shards[idx].read();
                let exists_in_mem = shard
                    .data
                    .get(*key)
                    .is_some_and(|entry| !entry.is_expired_at(now));
                drop(shard);
                if exists_in_mem || (tiered && self.disk_contains(key)) {
                    count += 1;
                }
            }
            return count;
        }

        // Group keys by shard so each shard lock is taken once per EXISTS call.
        let mut by_shard: HashMap<usize, Vec<&[u8]>, FxBuildHasher> =
            HashMap::with_hasher(FxBuildHasher);
        for key in keys {
            by_shard
                .entry(self.shard_index(key))
                .or_default()
                .push(*key);
        }

        let mut count = 0i64;
        let mut missing_or_expired: Vec<&[u8]> = Vec::new();

        for (idx, shard_keys) in by_shard {
            let shard = self.shards[idx].read();
            for key in shard_keys {
                let exists_in_mem = shard
                    .data
                    .get(key)
                    .is_some_and(|entry| !entry.is_expired_at(now));
                if exists_in_mem {
                    count += 1;
                } else if tiered {
                    missing_or_expired.push(key);
                }
            }
        }

        if tiered {
            for key in missing_or_expired {
                if self.disk_contains(key) {
                    count += 1;
                }
            }
        }

        count
    }

    pub(crate) fn exists_on_shard(data: &ShardData, key: &[u8], now: Instant) -> bool {
        data.get(key).is_some_and(|entry| !entry.is_expired_at(now))
    }

    pub fn incr(&self, key: &[u8], delta: i64, now: Instant) -> Result<i64, String> {
        self.try_promote(key, now)?;
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        let ks = key;
        let (current, expires_at) = match shard.data.get(ks) {
            Some(e) if !e.is_expired_at(now) => match e.value.string_bytes() {
                Some(s) => {
                    let s = std::str::from_utf8(s)
                        .map_err(|_| "ERR value is not an integer or out of range".to_string())?;
                    let n = s
                        .parse::<i64>()
                        .map_err(|_| "ERR value is not an integer or out of range".to_string())?;
                    (n, e.expires_at)
                }
                None => return Err(WRONGTYPE.to_string()),
            },
            _ => (0, None),
        };
        let new_val = current
            .checked_add(delta)
            .ok_or_else(|| "ERR increment or decrement would overflow".to_string())?;
        let new_value = StoreValue::Str(Bytes::from(new_val.to_string()));
        let mem = estimate_entry_memory(ks, &new_value);
        let old_entry = shard.data.insert(
            key_bytes(key),
            Entry {
                value: new_value,
                expires_at,
                lru_clock: self.lru_clock(),
            },
        );
        if let Some(oe) = old_entry {
            let old_mem = estimate_entry_memory(ks, &oe.value);
            if mem >= old_mem {
                self.mem_add(mem - old_mem);
            } else {
                self.mem_sub(old_mem - mem);
            }
        } else {
            self.mem_add(mem);
            self.key_added();
        }
        Ok(new_val)
    }

    pub fn append(&self, key: &[u8], value: &[u8], now: Instant) -> i64 {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        self.append_on_shard(&mut shard, key, value, now)
    }

    pub(crate) fn append_on_shard(
        &self,
        shard: &mut Shard,
        key: &[u8],
        value: &[u8],
        now: Instant,
    ) -> i64 {
        let ks = key;
        if let Some(entry) = shard.data.get_mut(ks) {
            if !entry.is_expired_at(now) {
                match &mut entry.value {
                    StoreValue::Str(s) => {
                        let mut new_val =
                            Vec::with_capacity((s.len() + value.len()).next_power_of_two());
                        new_val.extend_from_slice(s);
                        new_val.extend_from_slice(value);
                        let len = new_val.len() as i64;
                        self.mem_add(value.len());
                        entry.value = StoreValue::StrBuf(new_val);
                        entry.lru_clock = self.lru_clock();
                        return len;
                    }
                    StoreValue::StrBuf(s) => {
                        s.extend_from_slice(value);
                        let len = s.len() as i64;
                        self.mem_add(value.len());
                        entry.lru_clock = self.lru_clock();
                        return len;
                    }
                    _ => {}
                }
            }
        }
        let val = Bytes::copy_from_slice(value);
        let len = val.len() as i64;
        let new_value = StoreValue::Str(val);
        let mem = estimate_entry_memory(ks, &new_value);
        let old_entry = shard.data.insert(
            key_bytes(key),
            Entry {
                value: new_value,
                expires_at: None,
                lru_clock: self.lru_clock(),
            },
        );
        if let Some(oe) = old_entry {
            let old_mem = estimate_entry_memory(ks, &oe.value);
            if mem >= old_mem {
                self.mem_add(mem - old_mem);
            } else {
                self.mem_sub(old_mem - mem);
            }
        } else {
            self.mem_add(mem);
            self.key_added();
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
                let key = key_string(k);
                if e.expires_at.is_none_or(|exp| now < exp) && matcher.matches(&key) {
                    result.push(key);
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
        match shard.data.get(key) {
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
        match shard.data.get(key) {
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

    #[cfg(test)]
    pub fn expire(&self, key: &[u8], seconds: u64, now: Instant) -> bool {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        if let Some(entry) = shard.data.get_mut(key) {
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
        if let Some(entry) = shard.data.get_mut(key) {
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
        if let Some(entry) = shard.data.get_mut(key) {
            if !entry.is_expired_at(now) && entry.expires_at.is_some() {
                entry.expires_at = None;
                shard.version += 1;
                return true;
            }
        }
        false
    }

    pub fn rename(&self, key: &[u8], new_key: &[u8], now: Instant) -> Result<(), String> {
        let old_idx = self.shard_index(key);
        {
            // A value whose AEAD AAD is bound to the key name can't be decrypted
            // at a new key; moving it would orphan it. Refuse rather than lose it.
            let shard = self.shards[old_idx].read();
            if let Some(e) = shard.data.get(key) {
                if !e.is_expired_at(now) && Self::value_has_key_bound_encryption(&e.value) {
                    return Err(RENAME_ENCRYPTED_ERR.to_string());
                }
            }
        }
        let entry = {
            let mut shard = self.shards[old_idx].write();
            shard.version += 1;
            match shard.data.remove(key) {
                Some(e) if !e.is_expired_at(now) => {
                    self.key_removed();
                    let mem = estimate_entry_memory(key_str(key), &e.value);
                    shard.used_memory = shard.used_memory.saturating_sub(mem);
                    self.mem_sub(mem);
                    e
                }
                _ => return Err("ERR no such key".to_string()),
            }
        };
        let new_idx = self.shard_index(new_key);
        let mut shard = self.shards[new_idx].write();
        shard.version += 1;
        let mem = estimate_entry_memory(key_str(new_key), &entry.value);
        let old = shard.data.insert(key_bytes(new_key), entry);
        if old.is_none() {
            self.key_added();
        }
        shard.used_memory += mem;
        self.mem_add(mem);
        Ok(())
    }

    pub fn copy_key(
        &self,
        src: &[u8],
        dst: &[u8],
        replace: bool,
        now: Instant,
    ) -> Result<bool, String> {
        // COPY derives its destination from mutable source state. Hold the full
        // multi-key gate while reading both keys, recording the resolved value,
        // and applying it so replay observes the same source/destination order.
        let route: [&[u8]; 3] = [b"COPY", src, dst];
        let prepare = self
            .prepare_journaled(&route)
            .map_err(|e| format!("ERR WAL append failed: {e}"))?;
        let src_idx = self.shard_index(src);
        let dst_idx = self.shard_index(dst);

        let (dump_val, ttl) = {
            let shard = self.shards[src_idx].read();
            let ks = src;
            match shard.data.get(ks) {
                Some(entry) if !entry.is_expired_at(now) => {
                    if Self::value_has_key_bound_encryption(&entry.value) {
                        return Err(RENAME_ENCRYPTED_ERR.to_string());
                    }
                    let ttl = entry.expires_at.map(|exp| exp.duration_since(now));
                    let dv = store_value_to_dump_value(&entry.value);
                    (dv, ttl)
                }
                _ => return Ok(false),
            }
        };

        if !replace {
            let shard = self.shards[dst_idx].read();
            let ks = dst;
            if let Some(entry) = shard.data.get(ks) {
                if !entry.is_expired_at(now) {
                    return Ok(false);
                }
            }
        }

        // Record the resolved destination as `LXRESTORE dst <blob>`. Replaying a
        // raw COPY would re-read a mutable source and could reproduce a different
        // value. The blob captures the exact acknowledged destination state.
        let ttl_ms = ttl
            .map(|duration| i64::try_from(duration.as_millis()).unwrap_or(i64::MAX))
            .unwrap_or(-1);
        let entry = DumpEntry {
            key: key_string(dst),
            value: dump_val,
            ttl_ms,
        };
        let blob = crate::snapshot::encode_dump_blob(self, &entry)
            .map_err(|e| format!("ERR COPY encode failed: {e}"))?;
        let command: [&[u8]; 3] = [b"LXRESTORE", dst, &blob];
        let commit = prepare
            .commit(&command)
            .map_err(|e| format!("ERR WAL append failed: {e}"))?;
        self.load_entry(entry.key, entry.value, ttl);
        commit
            .complete()
            .map_err(|error| format!("ERR journal apply failed: {error}"))?;
        Ok(true)
    }

    /// DUMP: serialize the value at `key` into Lux's snapshot value format.
    /// Returns None when the key is missing/expired. The blob is Lux-internal
    /// (not RDB-compatible) and round-trips within Lux via RESTORE. Refuses
    /// key-bound-encrypted values, same as COPY.
    pub fn dump_key(&self, key: &[u8], now: Instant) -> Result<Option<Vec<u8>>, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key) {
            Some(entry) if !entry.is_expired_at(now) => {
                if Self::value_has_key_bound_encryption(&entry.value) {
                    return Err(RENAME_ENCRYPTED_ERR.to_string());
                }
                let ttl_ms = entry
                    .expires_at
                    .map(|exp| exp.duration_since(now).as_millis() as i64)
                    .unwrap_or(-1);
                let value = store_value_to_dump_value(&entry.value);
                let dentry = DumpEntry {
                    key: key_string(key),
                    value,
                    ttl_ms,
                };
                let blob = crate::snapshot::encode_dump_blob(self, &dentry)
                    .map_err(|e| format!("ERR DUMP failed: {e}"))?;
                Ok(Some(blob))
            }
            _ => Ok(None),
        }
    }

    /// Validate and fully decode RESTORE without changing state. The journal
    /// gate held by the caller keeps the BUSYKEY decision valid through apply.
    pub(crate) fn prepare_restore_key(
        &self,
        key: &[u8],
        ttl_ms: i64,
        blob: &[u8],
        replace: bool,
        absttl: bool,
        now: Instant,
    ) -> Result<PreparedRestore, String> {
        if ttl_ms < 0 {
            return Err("ERR Invalid TTL value, must be >= 0".to_string());
        }
        {
            let idx = self.shard_index(key);
            let shard = self.shards[idx].read();
            if let Some(entry) = shard.data.get(key) {
                if !entry.is_expired_at(now) && !replace {
                    return Err("BUSYKEY Target key name already exists.".to_string());
                }
            }
        }
        let (value, _embedded_ttl) = crate::snapshot::decode_dump_blob_value(self, blob)
            .map_err(|_| "ERR Bad data format".to_string())?;
        let (ttl, delete_only) = if ttl_ms == 0 {
            (None, false)
        } else if absttl {
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64;
            let remaining = ttl_ms.saturating_sub(now_ms);
            if remaining <= 0 {
                (None, true)
            } else {
                (Some(Duration::from_millis(remaining as u64)), false)
            }
        } else {
            (Some(Duration::from_millis(ttl_ms as u64)), false)
        };
        Ok(PreparedRestore {
            value,
            ttl,
            delete_only,
        })
    }

    pub(crate) fn apply_prepared_restore(&self, key: &[u8], prepared: PreparedRestore) {
        // Clear any existing value first so memory/key accounting stays exact on
        // REPLACE (load_entry only adds). A past absolute deadline is a resolved
        // delete and must never resurrect the decoded value during recovery.
        self.del(&[key]);
        if !prepared.delete_only {
            self.load_entry(key_string(key), prepared.value, prepared.ttl);
        }
    }

    pub fn dbsize(&self, now: Instant) -> i64 {
        // Redis contract: DBSIZE reports the exact number of non-expired keys
        // in the current DB at call time.
        let mut total = 0i64;
        for shard in self.shards.iter() {
            let shard = shard.read();
            total += shard
                .data
                .values()
                .filter(|e| e.expires_at.is_none_or(|exp| now < exp))
                .count() as i64;
        }
        total + self.disk_key_count() as i64
    }

    pub fn flushdb(&self) {
        for shard in self.shards.iter() {
            let mut shard = shard.write();
            shard.version += 1;
            shard.data.clear();
            self.mem_sub(shard.used_memory);
            shard.used_memory = 0;
        }
        self.metrics.key_count.store(0, Ordering::Relaxed);
        self.vector_indexes.write().clear();
        self.table_vector_indexes.write().clear();
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
        let ks = key_bytes(key);
        let entry = match shard.data.entry(ks) {
            hashbrown::hash_map::Entry::Occupied(o) => o.into_mut(),
            hashbrown::hash_map::Entry::Vacant(v) => {
                self.key_added();
                v.insert(Entry {
                    value: StoreValue::List(VecDeque::new()),
                    expires_at: None,
                    lru_clock: self.lru_clock(),
                })
            }
        };
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
                shard.version += 1;
                shard.used_memory += added_mem;
                self.mem_add(added_mem);
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
        let ks = key_bytes(key);
        let existed = shard.data.contains_key(&ks);
        let entry = shard.data.entry(ks).or_insert_with(|| Entry {
            value: StoreValue::List(VecDeque::new()),
            expires_at: None,
            lru_clock: self.lru_clock(),
        });
        if !existed {
            self.key_added();
        }
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
                self.mem_add(added_mem);
                Ok(len)
            }
            _ => Err(WRONGTYPE.to_string()),
        }
    }

    pub fn lpop(&self, key: &[u8], now: Instant) -> Option<Bytes> {
        let idx = self.shard_index(key);
        {
            let shard = self.shards[idx].read();
            let can_pop = match shard.data.get(key) {
                Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                    StoreValue::List(list) => !list.is_empty(),
                    _ => false,
                },
                _ => false,
            };
            if !can_pop {
                return None;
            }
        }
        let mut shard = self.shards[idx].write();
        let out = self.lpop_on_shard(&mut shard, key, now);
        if out.is_some() {
            shard.version += 1;
        }
        out
    }

    /// LPOP variant for callers that already hold the correct shard write lock.
    /// The caller owns shard versioning, WAL logging, key events, and disk
    /// invalidation.
    pub(crate) fn lpop_on_shard(
        &self,
        shard: &mut Shard,
        key: &[u8],
        now: Instant,
    ) -> Option<Bytes> {
        match shard.data.get_mut(key) {
            Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
                StoreValue::List(list) => {
                    let val = list.pop_front()?;
                    let freed = val.len() + 32;
                    shard.used_memory = shard.used_memory.saturating_sub(freed);
                    self.mem_sub(freed);
                    Some(val)
                }
                _ => None,
            },
            _ => None,
        }
    }

    pub fn rpop(&self, key: &[u8], now: Instant) -> Option<Bytes> {
        let idx = self.shard_index(key);
        {
            let shard = self.shards[idx].read();
            let can_pop = match shard.data.get(key) {
                Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                    StoreValue::List(list) => !list.is_empty(),
                    _ => false,
                },
                _ => false,
            };
            if !can_pop {
                return None;
            }
        }
        let mut shard = self.shards[idx].write();
        let out = match shard.data.get_mut(key) {
            Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
                StoreValue::List(list) => {
                    let val = list.pop_back()?;
                    let freed = val.len() + 32;
                    shard.used_memory = shard.used_memory.saturating_sub(freed);
                    self.mem_sub(freed);
                    Some(val)
                }
                _ => None,
            },
            _ => None,
        };
        if out.is_some() {
            shard.version += 1;
        }
        out
    }

    /// RPOP variant for callers that already hold the correct shard write lock.
    /// The caller owns shard versioning, WAL logging, key events, and disk
    /// invalidation.
    pub(crate) fn rpop_on_shard(
        &self,
        shard: &mut Shard,
        key: &[u8],
        now: Instant,
    ) -> Option<Bytes> {
        match shard.data.get_mut(key) {
            Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
                StoreValue::List(list) => {
                    let val = list.pop_back()?;
                    let freed = val.len() + 32;
                    shard.used_memory = shard.used_memory.saturating_sub(freed);
                    self.mem_sub(freed);
                    Some(val)
                }
                _ => None,
            },
            _ => None,
        }
    }

    /// LMPOP/BLMPOP core: pop up to `count` elements from the `pop_left` side of
    /// the first non-empty list among `keys`. Returns the popped key and the
    /// elements (raw, caller decrypts), or None if every key is missing/empty.
    /// Errors WRONGTYPE if a scanned key holds a non-list value (Redis matches
    /// on the first such key). Empty lists are left in place, mirroring LPOP.
    #[allow(clippy::type_complexity)]
    pub fn lmpop(
        &self,
        keys: &[&[u8]],
        pop_left: bool,
        count: usize,
        now: Instant,
    ) -> Result<Option<(Vec<u8>, Vec<Bytes>)>, String> {
        for key in keys {
            self.try_promote(key, now)?;
            let idx = self.shard_index(key);
            let mut shard = self.shards[idx].write();
            match shard.data.get(*key) {
                Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                    StoreValue::List(list) => {
                        if list.is_empty() {
                            continue;
                        }
                    }
                    _ => return Err(WRONGTYPE.to_string()),
                },
                _ => continue,
            }
            let mut items = Vec::with_capacity(count.min(1024));
            for _ in 0..count {
                let popped = if pop_left {
                    self.lpop_on_shard(&mut shard, key, now)
                } else {
                    self.rpop_on_shard(&mut shard, key, now)
                };
                match popped {
                    Some(v) => items.push(v),
                    None => break,
                }
            }
            if !items.is_empty() {
                shard.version += 1;
                drop(shard);
                self.remove_from_disk(key);
                return Ok(Some((key.to_vec(), items)));
            }
        }
        Ok(None)
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn preview_lmpop(
        &self,
        keys: &[&[u8]],
        pop_left: bool,
        count: usize,
        now: Instant,
    ) -> Result<Option<(Vec<u8>, Vec<Bytes>)>, String> {
        for key in keys {
            self.try_promote(key, now)?;
            let idx = self.shard_index(key);
            let shard = self.shards[idx].read();
            match shard
                .data
                .get(*key)
                .filter(|entry| !entry.is_expired_at(now))
            {
                Some(entry) => match &entry.value {
                    StoreValue::List(list) if list.is_empty() => continue,
                    StoreValue::List(list) => {
                        let items = if pop_left {
                            list.iter().take(count).cloned().collect()
                        } else {
                            list.iter().rev().take(count).cloned().collect()
                        };
                        return Ok(Some((key.to_vec(), items)));
                    }
                    _ => return Err(WRONGTYPE.to_string()),
                },
                None => continue,
            }
        }
        Ok(None)
    }

    pub fn llen(&self, key: &[u8], now: Instant) -> Result<i64, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key) {
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
        match shard.data.get(key) {
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
                        let mut out = Vec::with_capacity(e - s);
                        for idx in s..e {
                            if let Some(value) = list.get(idx) {
                                out.push(value.clone());
                            }
                        }
                        Ok(out)
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
        match shard.data.get(key) {
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

    pub fn sadd(&self, key: &[u8], members: &[&[u8]], now: Instant) -> Result<i64, String> {
        self.try_promote(key, now)?;
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        let ks = key_bytes(key);
        let existed = shard.data.contains_key(&ks);
        let entry = shard.data.entry(ks).or_insert_with(|| Entry {
            value: StoreValue::Set(SetData::new()),
            expires_at: None,
            lru_clock: self.lru_clock(),
        });
        if !existed {
            self.key_added();
        }
        if entry.is_expired_at(now) {
            entry.value = StoreValue::Set(SetData::new());
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
                self.mem_add(mem_added);
                Ok(added)
            }
            _ => Err(WRONGTYPE.to_string()),
        }
    }

    pub fn srem(&self, key: &[u8], members: &[&[u8]], now: Instant) -> Result<i64, String> {
        self.try_promote(key, now)?;
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        match shard.data.get_mut(key) {
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
                    self.mem_sub(freed);
                    Ok(removed)
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(0),
        }
    }

    pub fn smembers(&self, key: &[u8], now: Instant) -> Result<Vec<String>, String> {
        self.try_promote(key, now)?;
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Set(set) => Ok(set.iter().cloned().collect()),
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(vec![]),
        }
    }

    /// Resolve the members `SPOP` would remove without changing the set.
    ///
    /// The caller must hold the key's journal gate until the returned members
    /// are durably recorded and removed.
    pub(crate) fn preview_spop(
        &self,
        key: &[u8],
        count: usize,
        now: Instant,
    ) -> Result<Vec<String>, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Set(set) => Ok(set.iter().rev().take(count).cloned().collect()),
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(Vec::new()),
        }
    }

    pub fn sismember(&self, key: &[u8], member: &[u8], now: Instant) -> Result<bool, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key) {
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
        match shard.data.get(key) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Set(set) => Ok(set.len() as i64),
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(0),
        }
    }

    fn collect_set(
        &self,
        key: &[u8],
        now: Instant,
    ) -> Result<FxHashSet<String, FxBuildHasher>, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Set(set) => {
                    let mut result = FxHashSet::with_capacity_and_hasher(set.len(), FxBuildHasher);
                    result.extend(set.iter().cloned());
                    Ok(result)
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(FxHashSet::with_hasher(FxBuildHasher)),
        }
    }

    pub fn sunion(&self, keys: &[&[u8]], now: Instant) -> Result<Vec<String>, String> {
        if keys.len() == 2 {
            return self.sunion_two_keys(keys[0], keys[1], now);
        }
        let mut result = FxHashSet::with_hasher(FxBuildHasher);
        for key in keys {
            let key = *key;
            let idx = self.shard_index(key);
            let shard = self.shards[idx].read();
            match shard.data.get(key) {
                Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                    StoreValue::Set(set) => result.extend(set.iter().cloned()),
                    _ => return Err(WRONGTYPE.to_string()),
                },
                _ => {}
            }
        }
        Ok(result.into_iter().collect())
    }

    pub fn sinter(&self, keys: &[&[u8]], now: Instant) -> Result<Vec<String>, String> {
        if keys.is_empty() {
            return Ok(vec![]);
        }
        if keys.len() == 2 {
            return self.sinter_two_keys(keys[0], keys[1], now);
        }
        let mut result = self.collect_set(keys[0], now)?;
        for key in &keys[1..] {
            let key = *key;
            let idx = self.shard_index(key);
            let shard = self.shards[idx].read();
            match shard.data.get(key) {
                Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                    StoreValue::Set(set) => result.retain(|m| set.contains(m)),
                    _ => return Err(WRONGTYPE.to_string()),
                },
                _ => result.clear(),
            }
        }
        Ok(result.into_iter().collect())
    }

    pub fn sdiff(&self, keys: &[&[u8]], now: Instant) -> Result<Vec<String>, String> {
        if keys.is_empty() {
            return Ok(vec![]);
        }
        if keys.len() == 2 {
            return self.sdiff_two_keys(keys[0], keys[1], now);
        }
        let mut result = self.collect_set(keys[0], now)?;
        for key in &keys[1..] {
            let key = *key;
            let idx = self.shard_index(key);
            let shard = self.shards[idx].read();
            match shard.data.get(key) {
                Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                    StoreValue::Set(set) => result.retain(|m| !set.contains(m)),
                    _ => return Err(WRONGTYPE.to_string()),
                },
                _ => {}
            }
        }
        Ok(result.into_iter().collect())
    }

    fn sunion_two_keys(
        &self,
        key_a: &[u8],
        key_b: &[u8],
        now: Instant,
    ) -> Result<Vec<String>, String> {
        self.with_two_set_views(key_a, key_b, now, |left, right| {
            let mut union = FxHashSet::with_capacity_and_hasher(
                left.map_or(0, SetData::len) + right.map_or(0, SetData::len),
                FxBuildHasher,
            );
            if let Some(set) = left {
                union.extend(set.iter().cloned());
            }
            if let Some(set) = right {
                union.extend(set.iter().cloned());
            }
            Ok(union.into_iter().collect())
        })
    }

    fn sinter_two_keys(
        &self,
        key_a: &[u8],
        key_b: &[u8],
        now: Instant,
    ) -> Result<Vec<String>, String> {
        self.with_two_set_views(key_a, key_b, now, |left, right| {
            let (Some(left), Some(right)) = (left, right) else {
                return Ok(Vec::new());
            };
            let (small, large) = if left.len() <= right.len() {
                (left, right)
            } else {
                (right, left)
            };
            let mut out = Vec::with_capacity(small.len());
            for member in small.iter() {
                if large.contains(member) {
                    out.push(member.clone());
                }
            }
            Ok(out)
        })
    }

    fn sdiff_two_keys(
        &self,
        key_a: &[u8],
        key_b: &[u8],
        now: Instant,
    ) -> Result<Vec<String>, String> {
        self.with_two_set_views(key_a, key_b, now, |left, right| {
            let Some(left) = left else {
                return Ok(Vec::new());
            };
            let Some(right) = right else {
                return Ok(left.iter().cloned().collect());
            };
            let mut out = Vec::with_capacity(left.len());
            for member in left.iter() {
                if !right.contains(member) {
                    out.push(member.clone());
                }
            }
            Ok(out)
        })
    }

    fn with_two_set_views<R, F>(
        &self,
        key_a: &[u8],
        key_b: &[u8],
        now: Instant,
        f: F,
    ) -> Result<R, String>
    where
        F: FnOnce(Option<&SetData>, Option<&SetData>) -> Result<R, String>,
    {
        fn view_set(entry: Option<&Entry>, now: Instant) -> Result<Option<&SetData>, String> {
            match entry {
                Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                    StoreValue::Set(set) => Ok(Some(set)),
                    _ => Err(WRONGTYPE.to_string()),
                },
                _ => Ok(None),
            }
        }

        let idx_a = self.shard_index(key_a);
        let idx_b = self.shard_index(key_b);
        if idx_a == idx_b {
            let shard = self.shards[idx_a].read();
            let left = view_set(shard.data.get(key_a), now)?;
            let right = view_set(shard.data.get(key_b), now)?;
            return f(left, right);
        }

        if idx_a < idx_b {
            let shard_a = self.shards[idx_a].read();
            let shard_b = self.shards[idx_b].read();
            let left = view_set(shard_a.data.get(key_a), now)?;
            let right = view_set(shard_b.data.get(key_b), now)?;
            f(left, right)
        } else {
            let shard_b = self.shards[idx_b].read();
            let shard_a = self.shards[idx_a].read();
            let left = view_set(shard_a.data.get(key_a), now)?;
            let right = view_set(shard_b.data.get(key_b), now)?;
            f(left, right)
        }
    }

    #[allow(dead_code)]
    pub fn approximate_memory(&self) -> usize {
        self.metrics.used_memory.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub fn dump_all(&self, now: Instant) -> std::io::Result<Vec<DumpEntry>> {
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
                    key: key_string(key),
                    value: store_value_to_dump_value(&entry.value),
                    ttl_ms,
                });
            }
        }
        let mut disk_entries = self.dump_disk_entries(now)?;
        entries.append(&mut disk_entries);
        Ok(entries)
    }

    pub(crate) fn with_write_barrier<R>(
        &self,
        f: impl FnOnce(&mut [parking_lot::RwLockWriteGuard<'_, Shard>]) -> R,
    ) -> R {
        // Mutations acquire their journal domain before they append and keep it
        // through the state change. Take every domain in the same order before
        // locking shards so a snapshot cannot observe the pre-apply state and
        // then truncate an already-appended mutation from the journal.
        let _journal_guards: Vec<_> = self
            .journal_gates
            .iter()
            .map(parking_lot::ReentrantMutex::lock)
            .collect();
        let mut guards: Vec<_> = self.shards.iter().map(|shard| shard.write()).collect();
        f(&mut guards)
    }

    pub(crate) fn dump_all_from_locked_shards(
        &self,
        shards: &[parking_lot::RwLockWriteGuard<'_, Shard>],
        now: Instant,
    ) -> std::io::Result<Vec<DumpEntry>> {
        let mut entries = Vec::new();
        for shard in shards {
            for (key, entry) in shard.data.iter() {
                if entry.is_expired_at(now) {
                    continue;
                }
                let ttl_ms = entry
                    .expires_at
                    .map(|exp| exp.duration_since(now).as_millis() as i64)
                    .unwrap_or(0);
                entries.push(DumpEntry {
                    key: key_string(key),
                    value: store_value_to_dump_value(&entry.value),
                    ttl_ms,
                });
            }
        }
        let mut disk_entries = self.dump_disk_entries(now)?;
        entries.append(&mut disk_entries);
        Ok(entries)
    }

    pub fn load_entry(&self, key: String, value: DumpValue, ttl: Option<Duration>) {
        let idx = self.shard_index(key.as_bytes());
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        let key_bytes_owned = key.as_bytes().to_vec();
        let store_value = match value {
            DumpValue::Str(s) => StoreValue::Str(Bytes::from(s)),
            DumpValue::List(l) => StoreValue::List(l.into_iter().map(Bytes::from).collect()),
            DumpValue::Hash(h, expiries) => {
                let mut hd = HashData::from_fields(
                    h.into_iter().map(|(k, v)| (k, Bytes::from(v))).collect(),
                );
                hd.expiries = expiries.into_iter().collect();
                StoreValue::Hash(hd)
            }
            DumpValue::Set(s) => StoreValue::Set(SetData::from_members(s)),
            DumpValue::SortedSet(members) => {
                let mut tree = BTreeMap::new();
                let mut scores = HashMap::new();
                for (member, score) in members {
                    tree.insert((OrderedFloat(score), member.clone()), ());
                    scores.insert(member, score);
                }
                StoreValue::SortedSet(tree, scores)
            }
            DumpValue::Stream(entries_data, last_id_str, groups_data) => {
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
                let inst_now = Instant::now();
                let mut groups = std::collections::HashMap::new();
                for (group_name, last_delivered_str, consumers_data, pending_data) in groups_data {
                    let last_delivered_id =
                        StreamId::parse(&last_delivered_str).unwrap_or(StreamId::zero());
                    let mut consumers = std::collections::HashMap::new();
                    for (consumer_name, pending_ids) in consumers_data {
                        let pel = pending_ids
                            .into_iter()
                            .filter_map(|id| StreamId::parse(&id))
                            .collect();
                        consumers.insert(
                            consumer_name,
                            Consumer {
                                pel,
                                seen_time: inst_now,
                            },
                        );
                    }
                    let mut pel = BTreeMap::new();
                    for (id_str, consumer, delivery_count) in pending_data {
                        if let Some(id) = StreamId::parse(&id_str) {
                            pel.insert(
                                id,
                                PendingEntry {
                                    consumer: consumer.clone(),
                                    delivery_time: inst_now,
                                    delivery_count,
                                },
                            );
                            consumers.entry(consumer).or_insert_with(|| Consumer {
                                pel: HashSet::new(),
                                seen_time: inst_now,
                            });
                        }
                    }
                    for (id, pending) in &pel {
                        if let Some(consumer) = consumers.get_mut(&pending.consumer) {
                            consumer.pel.insert(*id);
                        }
                    }
                    groups.insert(
                        group_name,
                        ConsumerGroup {
                            last_delivered_id,
                            consumers,
                            pel,
                        },
                    );
                }
                StoreValue::Stream(StreamData {
                    entries,
                    last_id,
                    groups,
                })
            }
            DumpValue::Vector(data, metadata, encrypted) => {
                let dims = data.len() as u32;
                let index_data = data.clone();
                let key_clone = key.clone();
                let sv = StoreValue::Vector(VectorData {
                    dims,
                    data,
                    metadata,
                    encrypted,
                });
                let expires_at = ttl.map(|d| Instant::now() + d);
                let mem = estimate_entry_memory(&key, &sv);
                let old = shard.data.insert(
                    key_bytes_owned,
                    Entry {
                        value: sv,
                        expires_at,
                        lru_clock: self.lru_clock(),
                    },
                );
                if old.is_none() {
                    self.key_added();
                }
                shard.used_memory += mem;
                self.mem_add(mem);
                drop(shard);
                self.insert_vector_indexes(key_clone, dims, index_data);
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
        let old = shard.data.insert(
            key_bytes_owned,
            Entry {
                value: store_value,
                expires_at,
                lru_clock: self.lru_clock(),
            },
        );
        if old.is_none() {
            self.key_added();
        }
        shard.used_memory += mem;
        self.mem_add(mem);
    }

    pub fn getdel(&self, key: &[u8], now: Instant) -> Option<Bytes> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        let ks = key;
        match shard.data.get(ks) {
            Some(entry) if !entry.is_expired_at(now) => {
                if entry.value.string_bytes().is_some() {
                    let entry = shard.data.remove(ks).unwrap();
                    self.key_removed();
                    let freed = estimate_entry_memory(ks, &entry.value);
                    shard.used_memory = shard.used_memory.saturating_sub(freed);
                    self.mem_sub(freed);
                    entry.value.string_to_bytes()
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
        let ks = key;
        match shard.data.get_mut(ks) {
            Some(entry) if !entry.is_expired_at(now) => {
                if persist {
                    entry.expires_at = None;
                } else if let Some(d) = ttl {
                    entry.expires_at = Some(now + d);
                }
                entry.value.string_to_bytes()
            }
            _ => None,
        }
    }

    pub fn getrange(
        &self,
        key: &[u8],
        start: i64,
        end: i64,
        now: Instant,
    ) -> Result<Bytes, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key) {
            Some(entry) if !entry.is_expired_at(now) => {
                if let Some(s) = entry.value.string_bytes() {
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
                        Ok(Bytes::new())
                    } else {
                        Ok(Bytes::copy_from_slice(&s[s_i..e_i]))
                    }
                } else {
                    Err(WRONGTYPE.to_string())
                }
            }
            _ => Ok(Bytes::new()),
        }
    }

    pub fn setrange(
        &self,
        key: &[u8],
        offset: usize,
        value: &[u8],
        now: Instant,
    ) -> Result<i64, String> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        let ks = key_bytes(key);
        let expired = shard
            .data
            .get(&ks)
            .is_some_and(|entry| entry.is_expired_at(now));
        if expired {
            shard.data.remove(&ks);
            self.key_removed();
        }

        let Some(entry) = shard.data.get(&ks) else {
            if value.is_empty() {
                return Ok(0);
            }
            shard.version += 1;
            let needed = offset + value.len();
            let mut buf = vec![0; needed];
            buf[offset..needed].copy_from_slice(value);
            let new_value = StoreValue::StrBuf(buf);
            let mem = estimate_entry_memory(&ks, &new_value);
            shard.data.insert(
                ks,
                Entry {
                    value: new_value,
                    expires_at: None,
                    lru_clock: self.lru_clock(),
                },
            );
            shard.used_memory += mem;
            self.mem_add(mem);
            self.key_added();
            return Ok(needed as i64);
        };

        let (expires_at, mut buf) = {
            let Some(s) = entry.value.string_bytes() else {
                return Err(WRONGTYPE.to_string());
            };
            if value.is_empty() {
                return Ok(s.len() as i64);
            }
            (entry.expires_at, s.to_vec())
        };

        shard.version += 1;
        let needed = offset + value.len();
        if buf.len() < needed {
            buf.resize(needed, 0);
        }
        buf[offset..offset + value.len()].copy_from_slice(value);
        let len = buf.len() as i64;
        let new_value = StoreValue::StrBuf(buf);
        let mem = estimate_entry_memory(&ks, &new_value);
        let old_entry = shard.data.insert(
            ks,
            Entry {
                value: new_value,
                expires_at,
                lru_clock: self.lru_clock(),
            },
        );
        if let Some(old_entry) = old_entry {
            let old_mem = estimate_entry_memory(key, &old_entry.value);
            if mem >= old_mem {
                let added = mem - old_mem;
                shard.used_memory += added;
                self.mem_add(added);
            } else {
                let freed = old_mem - mem;
                shard.used_memory = shard.used_memory.saturating_sub(freed);
                self.mem_sub(freed);
            }
        }
        Ok(len)
    }

    pub fn msetnx(&self, pairs: &[(&[u8], &[u8])], now: Instant) -> bool {
        if !self.msetnx_would_set(pairs, now) {
            return false;
        }
        for (key, value) in pairs {
            self.set(key, value, None, now);
        }
        true
    }

    pub(crate) fn msetnx_would_set(&self, pairs: &[(&[u8], &[u8])], now: Instant) -> bool {
        pairs.iter().all(|(key, _)| self.get(key, now).is_none())
    }

    pub fn setbit(&self, key: &[u8], offset: u64, value: u8, now: Instant) -> Result<u8, String> {
        let byte_idx = (offset / 8) as usize;
        let bit_idx = 7 - (offset % 8) as u8;
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        let ks = key_bytes(key);
        let existed = shard.data.contains_key(&ks);
        let entry = shard.data.entry(ks).or_insert_with(|| Entry {
            value: StoreValue::Str(Bytes::new()),
            expires_at: None,
            lru_clock: self.lru_clock(),
        });
        if !existed {
            self.key_added();
        }
        if entry.is_expired_at(now) {
            entry.value = StoreValue::Str(Bytes::new());
            entry.expires_at = None;
        }
        match entry.value.string_bytes() {
            Some(s) => {
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
                entry.value = StoreValue::StrBuf(buf);
                if new_len > old_len {
                    let added = new_len - old_len;
                    let _ = entry;
                    shard.used_memory += added;
                    self.mem_add(added);
                }
                Ok(old)
            }
            None => Err(WRONGTYPE.to_string()),
        }
    }

    pub fn getbit(&self, key: &[u8], offset: u64, now: Instant) -> Result<u8, String> {
        let byte_idx = (offset / 8) as usize;
        let bit_idx = 7 - (offset % 8) as u8;
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key) {
            Some(entry) if !entry.is_expired_at(now) => match entry.value.string_bytes() {
                Some(s) => {
                    if byte_idx >= s.len() {
                        Ok(0)
                    } else {
                        Ok((s[byte_idx] >> bit_idx) & 1)
                    }
                }
                None => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(0),
        }
    }

    /// BITFIELD/BITFIELD_RO: apply a batch of GET/SET/INCRBY operations against
    /// the key's bitmap atomically (all under one shard lock). Returns one result
    /// per op in order (None where an OVERFLOW FAIL suppressed a SET/INCRBY).
    pub fn bitfield(
        &self,
        key: &[u8],
        ops: &[BitfieldOp],
        now: Instant,
    ) -> Result<Vec<Option<i64>>, String> {
        let has_write = ops.iter().any(|o| !matches!(o, BitfieldOp::Get { .. }));
        let idx = self.shard_index(key);

        if !has_write {
            let shard = self.shards[idx].read();
            let buf: Vec<u8> = match shard.data.get(key) {
                Some(entry) if !entry.is_expired_at(now) => match entry.value.string_bytes() {
                    Some(s) => s.to_vec(),
                    None => return Err(WRONGTYPE.to_string()),
                },
                _ => Vec::new(),
            };
            let mut results = Vec::with_capacity(ops.len());
            for op in ops {
                if let BitfieldOp::Get {
                    signed,
                    bits,
                    offset,
                } = op
                {
                    results.push(Some(bf_read(&buf, *offset, *bits, *signed)));
                }
            }
            return Ok(results);
        }

        let mut shard = self.shards[idx].write();
        shard.version += 1;
        let ks = key_bytes(key);
        let existed = shard.data.contains_key(&ks);
        let entry = shard.data.entry(ks).or_insert_with(|| Entry {
            value: StoreValue::Str(Bytes::new()),
            expires_at: None,
            lru_clock: self.lru_clock(),
        });
        if !existed {
            self.key_added();
        }
        if entry.is_expired_at(now) {
            entry.value = StoreValue::Str(Bytes::new());
            entry.expires_at = None;
        }
        let mut buf = match entry.value.string_bytes() {
            Some(s) => s.to_vec(),
            None => return Err(WRONGTYPE.to_string()),
        };
        let old_len = buf.len();
        let mut results = Vec::with_capacity(ops.len());
        for op in ops {
            match op {
                BitfieldOp::Get {
                    signed,
                    bits,
                    offset,
                } => results.push(Some(bf_read(&buf, *offset, *bits, *signed))),
                BitfieldOp::Set {
                    signed,
                    bits,
                    offset,
                    value,
                    overflow,
                } => {
                    let old = bf_read(&buf, *offset, *bits, *signed);
                    match bf_clamp(*signed, *bits, *value as i128, *overflow) {
                        Some(v) => {
                            bf_write(&mut buf, *offset, *bits, v as u64);
                            results.push(Some(old));
                        }
                        None => results.push(None),
                    }
                }
                BitfieldOp::IncrBy {
                    signed,
                    bits,
                    offset,
                    incr,
                    overflow,
                } => {
                    let old = bf_read(&buf, *offset, *bits, *signed);
                    let new = old as i128 + *incr as i128;
                    match bf_clamp(*signed, *bits, new, *overflow) {
                        Some(v) => {
                            bf_write(&mut buf, *offset, *bits, v as u64);
                            results.push(Some(v));
                        }
                        None => results.push(None),
                    }
                }
            }
        }
        let new_len = buf.len();
        entry.value = StoreValue::StrBuf(buf);
        if new_len > old_len {
            let added = new_len - old_len;
            let _ = entry;
            shard.used_memory += added;
            self.mem_add(added);
        }
        Ok(results)
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
        match shard.data.get(key) {
            Some(entry) if !entry.is_expired_at(now) => match entry.value.string_bytes() {
                Some(s) => {
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
                None => Err(WRONGTYPE.to_string()),
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
        match shard.data.get(key) {
            Some(entry) if !entry.is_expired_at(now) => match entry.value.string_bytes() {
                Some(s) => {
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
                        for (i, byte) in s.iter().enumerate().take(e_byte + 1).skip(s_byte) {
                            for b in 0..8u8 {
                                let bit_val = (*byte >> (7 - b)) & 1;
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
                None => Err(WRONGTYPE.to_string()),
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
            let key = *key;
            let idx = self.shard_index(key);
            let shard = self.shards[idx].read();
            match shard.data.get(key) {
                Some(entry) if !entry.is_expired_at(now) => match entry.value.string_bytes() {
                    Some(s) => {
                        max_len = max_len.max(s.len());
                        sources.push(s.to_vec());
                    }
                    None => return Err(WRONGTYPE.to_string()),
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

    pub fn unlink(&self, keys: &[&[u8]]) -> i64 {
        self.del(keys)
    }

    #[cfg(test)]
    pub fn expireat(&self, key: &[u8], timestamp: u64, now: Instant) -> bool {
        let target = std::time::UNIX_EPOCH + Duration::from_secs(timestamp);
        let now_sys = std::time::SystemTime::now();
        if target <= now_sys {
            return self.del(&[key]) == 1;
        }
        let dur = target.duration_since(now_sys).unwrap_or(Duration::ZERO);
        self.expire(key, dur.as_secs(), now)
    }

    #[cfg(test)]
    pub fn pexpireat(&self, key: &[u8], timestamp_ms: u64, now: Instant) -> bool {
        let target = std::time::UNIX_EPOCH + Duration::from_millis(timestamp_ms);
        let now_sys = std::time::SystemTime::now();
        if target <= now_sys {
            return self.del(&[key]) == 1;
        }
        let dur = target.duration_since(now_sys).unwrap_or(Duration::ZERO);
        self.pexpire(key, dur.as_millis() as u64, now)
    }

    pub fn expiretime(&self, key: &[u8], now: Instant) -> i64 {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key) {
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
        match shard.data.get(key) {
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
            match shard.data.get_mut(key) {
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
            self.mem_add(delta as usize);
        } else if delta < 0 {
            let freed = (-delta) as usize;
            shard.used_memory = shard.used_memory.saturating_sub(freed);
            self.mem_sub(freed);
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
        match shard.data.get_mut(key) {
            Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
                StoreValue::List(list) => {
                    if let Some(pos) = list.iter().position(|v| v.as_ref() == pivot) {
                        let insert_at = if before { pos } else { pos + 1 };
                        let added = value.len() + 32;
                        list.insert(insert_at, Bytes::copy_from_slice(value));
                        let len = list.len() as i64;
                        let _ = entry;
                        shard.used_memory += added;
                        self.mem_add(added);
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
        match shard.data.get_mut(key) {
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
                    self.mem_sub(freed);
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
        match shard.data.get_mut(key) {
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
                        self.mem_sub(freed);
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
        let result = match shard.data.get_mut(key) {
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
            self.mem_add(added_mem);
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
        let result = match shard.data.get_mut(key) {
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
            self.mem_add(added_mem);
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
            match shard.data.get_mut(src) {
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
                            self.mem_sub(freed);
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
            let ks = key_bytes(dst);
            let existed = shard.data.contains_key(&ks);
            let entry = shard.data.entry(ks).or_insert_with(|| Entry {
                value: StoreValue::List(VecDeque::new()),
                expires_at: None,
                lru_clock: self.lru_clock(),
            });
            if !existed {
                self.key_added();
            }
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
                self.mem_add(added);
            }
        }
        val
    }

    pub(crate) fn preview_lmove(
        &self,
        src: &[u8],
        dst: &[u8],
        from_left: bool,
        now: Instant,
    ) -> Result<Option<Bytes>, String> {
        self.try_promote(src, now)?;
        self.try_promote(dst, now)?;
        let dst_idx = self.shard_index(dst);
        if let Some(entry) = self.shards[dst_idx]
            .read()
            .data
            .get(dst)
            .filter(|entry| !entry.is_expired_at(now))
        {
            if !matches!(entry.value, StoreValue::List(_)) {
                return Err(WRONGTYPE.to_string());
            }
        }
        let src_idx = self.shard_index(src);
        let shard = self.shards[src_idx].read();
        match shard
            .data
            .get(src)
            .filter(|entry| !entry.is_expired_at(now))
        {
            Some(entry) => match &entry.value {
                StoreValue::List(list) => Ok(if from_left {
                    list.front().cloned()
                } else {
                    list.back().cloned()
                }),
                _ => Err(WRONGTYPE.to_string()),
            },
            None => Ok(None),
        }
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
        let ks = key_bytes(key);
        let existed = shard.data.contains_key(&ks);
        let entry = shard.data.entry(ks).or_insert_with(|| Entry {
            value: StoreValue::Hash(HashData::default()),
            expires_at: None,
            lru_clock: self.lru_clock(),
        });
        if !existed {
            self.key_added();
        }
        if entry.is_expired_at(now) {
            entry.value = StoreValue::Hash(HashData::default());
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
                    self.mem_add(added);
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
        let ks = key_bytes(key);
        let existed = shard.data.contains_key(&ks);
        let entry = shard.data.entry(ks).or_insert_with(|| Entry {
            value: StoreValue::Hash(HashData::default()),
            expires_at: None,
            lru_clock: self.lru_clock(),
        });
        if !existed {
            self.key_added();
        }
        if entry.is_expired_at(now) {
            entry.value = StoreValue::Hash(HashData::default());
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
                    self.mem_add(added);
                } else if new_len > old_len {
                    let added = new_len - old_len;
                    let _ = entry;
                    shard.used_memory += added;
                    self.mem_add(added);
                } else if old_len > new_len {
                    let freed = old_len - new_len;
                    let _ = entry;
                    shard.used_memory = shard.used_memory.saturating_sub(freed);
                    self.mem_sub(freed);
                }
                Ok(s)
            }
            _ => Err(WRONGTYPE.to_string()),
        }
    }

    pub fn hstrlen(&self, key: &[u8], field: &[u8], now: Instant) -> i64 {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Hash(map) => {
                    map.get(key_str(field)).map(|v| v.len() as i64).unwrap_or(0)
                }
                _ => 0,
            },
            _ => 0,
        }
    }

    #[cfg(test)]
    pub fn spop(&self, key: &[u8], count: usize, now: Instant) -> Result<Vec<String>, String> {
        if count == 1 {
            return Ok(self.spop_one(key, now).into_iter().collect());
        }
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        let out = match shard.data.get_mut(key) {
            Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
                StoreValue::Set(set) => {
                    let mut result = Vec::new();
                    let mut freed = 0usize;
                    for _ in 0..count {
                        let Some(member) = set.pop() else { break };
                        freed += member.len() + 32;
                        result.push(member);
                    }
                    shard.used_memory = shard.used_memory.saturating_sub(freed);
                    self.mem_sub(freed);
                    Ok(result)
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(vec![]),
        };
        if matches!(out, Ok(ref members) if !members.is_empty()) {
            shard.version += 1;
        }
        out
    }

    /// SPOP variant for callers that already hold the correct shard write lock.
    /// The caller owns shard versioning, WAL logging, key events, and disk
    /// invalidation.
    pub(crate) fn spop_on_shard(
        &self,
        shard: &mut Shard,
        key: &[u8],
        count: usize,
        now: Instant,
    ) -> Result<Vec<String>, String> {
        if count == 1 {
            return Ok(self
                .spop_one_on_shard(shard, key, now)
                .into_iter()
                .collect());
        }
        match shard.data.get_mut(key) {
            Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
                StoreValue::Set(set) => {
                    let mut result = Vec::new();
                    let mut freed = 0usize;
                    for _ in 0..count {
                        let Some(member) = set.pop() else { break };
                        freed += member.len() + 32;
                        result.push(member);
                    }
                    shard.used_memory = shard.used_memory.saturating_sub(freed);
                    self.mem_sub(freed);
                    Ok(result)
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(vec![]),
        }
    }

    #[cfg(test)]
    pub fn spop_one(&self, key: &[u8], now: Instant) -> Option<String> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        let out = self.spop_one_on_shard(&mut shard, key, now);
        if out.is_some() {
            shard.version += 1;
        }
        out
    }

    pub(crate) fn spop_one_on_shard(
        &self,
        shard: &mut Shard,
        key: &[u8],
        now: Instant,
    ) -> Option<String> {
        match shard.data.get_mut(key) {
            Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
                StoreValue::Set(set) => {
                    let member = set.pop()?;
                    let freed = member.len() + 32;
                    shard.used_memory = shard.used_memory.saturating_sub(freed);
                    self.mem_sub(freed);
                    Some(member)
                }
                _ => None,
            },
            _ => None,
        }
    }

    pub fn srandmember(&self, key: &[u8], count: i64, now: Instant) -> Result<Vec<String>, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key) {
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
        // Validate the destination type BEFORE mutating the source. Otherwise a
        // wrong-type destination returns WRONGTYPE only after the member has
        // already been removed from the source, losing it permanently.
        let dst_idx = self.shard_index(dst);
        {
            let shard = self.shards[dst_idx].read();
            if let Some(entry) = shard.data.get(dst) {
                if !entry.is_expired_at(now) && !matches!(entry.value, StoreValue::Set(_)) {
                    return Err(WRONGTYPE.to_string());
                }
            }
        }
        let src_idx = self.shard_index(src);
        let removed = {
            let mut shard = self.shards[src_idx].write();
            shard.version += 1;
            match shard.data.get_mut(src) {
                Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
                    StoreValue::Set(set) => {
                        let r = set.remove(key_str(member));
                        if r {
                            shard.used_memory = shard.used_memory.saturating_sub(mem_size);
                            self.mem_sub(mem_size);
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
        let mut shard = self.shards[dst_idx].write();
        shard.version += 1;
        let ks = key_bytes(dst);
        let existed = shard.data.contains_key(&ks);
        let entry = shard.data.entry(ks).or_insert_with(|| Entry {
            value: StoreValue::Set(SetData::new()),
            expires_at: None,
            lru_clock: self.lru_clock(),
        });
        if !existed {
            self.key_added();
        }
        if entry.is_expired_at(now) {
            entry.value = StoreValue::Set(SetData::new());
            entry.expires_at = None;
        }
        match &mut entry.value {
            StoreValue::Set(set) => {
                if set.insert(key_string(member)) {
                    let _ = entry;
                    shard.used_memory += mem_size;
                    self.mem_add(mem_size);
                }
                Ok(true)
            }
            _ => Err(WRONGTYPE.to_string()),
        }
    }

    pub(crate) fn smove_would_move(
        &self,
        src: &[u8],
        dst: &[u8],
        member: &[u8],
        now: Instant,
    ) -> Result<bool, String> {
        self.try_promote(src, now)?;
        self.try_promote(dst, now)?;
        let dst_idx = self.shard_index(dst);
        if let Some(entry) = self.shards[dst_idx]
            .read()
            .data
            .get(dst)
            .filter(|entry| !entry.is_expired_at(now))
        {
            if !matches!(entry.value, StoreValue::Set(_)) {
                return Err(WRONGTYPE.to_string());
            }
        }
        let src_idx = self.shard_index(src);
        let shard = self.shards[src_idx].read();
        match shard
            .data
            .get(src)
            .filter(|entry| !entry.is_expired_at(now))
        {
            Some(entry) => match &entry.value {
                StoreValue::Set(set) => Ok(set.contains(key_str(member))),
                _ => Err(WRONGTYPE.to_string()),
            },
            None => Ok(false),
        }
    }

    pub fn smismember(&self, key: &[u8], members: &[&[u8]], now: Instant) -> Vec<bool> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Set(set) => members.iter().map(|m| set.contains(key_str(m))).collect(),
                _ => members.iter().map(|_| false).collect(),
            },
            _ => members.iter().map(|_| false).collect(),
        }
    }

    /// Replace `dst` with `members` and journal the resolved DEL + SADD effect,
    /// independent of later changes to the source keys.
    fn write_computed_set(
        &self,
        prepare: JournalPrepareGuard<'_>,
        dst: &[u8],
        members: &[&[u8]],
        now: Instant,
    ) -> Result<i64, String> {
        let del: [&[u8]; 2] = [b"DEL", dst];
        let mut sadd: Vec<&[u8]> = Vec::with_capacity(members.len() + 2);
        if !members.is_empty() {
            sadd.push(b"SADD");
            sadd.push(dst);
            sadd.extend_from_slice(members);
        }
        let mut commands: Vec<&[&[u8]]> = vec![&del];
        if !sadd.is_empty() {
            commands.push(&sadd);
        }
        let commit = prepare
            .commit_batch(&commands)
            .map_err(|e| format!("ERR WAL append failed: {e}"))?;
        self.del(&[dst]);
        if !members.is_empty() {
            self.sadd(dst, members, now)?;
        }
        commit
            .complete()
            .map_err(|error| format!("ERR journal apply failed: {error}"))?;
        Ok(members.len() as i64)
    }

    pub fn sdiffstore(&self, dst: &[u8], keys: &[&[u8]], now: Instant) -> Result<i64, String> {
        let route: [&[u8]; 2] = [b"SDIFFSTORE", dst];
        let prepare = self
            .prepare_journaled(&route)
            .map_err(|e| format!("ERR WAL append failed: {e}"))?;
        let result = self.sdiff(keys, now)?;
        let members: Vec<&[u8]> = result.iter().map(|s| s.as_bytes()).collect();
        self.write_computed_set(prepare, dst, &members, now)
    }

    pub fn sinterstore(&self, dst: &[u8], keys: &[&[u8]], now: Instant) -> Result<i64, String> {
        let route: [&[u8]; 2] = [b"SINTERSTORE", dst];
        let prepare = self
            .prepare_journaled(&route)
            .map_err(|e| format!("ERR WAL append failed: {e}"))?;
        let result = self.sinter(keys, now)?;
        let members: Vec<&[u8]> = result.iter().map(|s| s.as_bytes()).collect();
        self.write_computed_set(prepare, dst, &members, now)
    }

    pub fn sunionstore(&self, dst: &[u8], keys: &[&[u8]], now: Instant) -> Result<i64, String> {
        let route: [&[u8]; 2] = [b"SUNIONSTORE", dst];
        let prepare = self
            .prepare_journaled(&route)
            .map_err(|e| format!("ERR WAL append failed: {e}"))?;
        let result = self.sunion(keys, now)?;
        let members: Vec<&[u8]> = result.iter().map(|s| s.as_bytes()).collect();
        self.write_computed_set(prepare, dst, &members, now)
    }

    pub fn expire_sweep(&self, now: Instant) {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        now.hash(&mut hasher);
        let seed = hasher.finish() as usize;

        for (i, shard) in self.shards.iter().enumerate() {
            let keys: Vec<ShardKey> = {
                let shard = shard.read();
                shard
                    .data
                    .keys()
                    .enumerate()
                    .filter(|(j, _)| (*j + seed + i).is_multiple_of(5))
                    .take(20)
                    .map(|(_, key)| key.clone())
                    .collect()
            };
            for key in keys {
                let _expiry_guard = self.journal_gates[self.journal_gate_index(&key)].lock();
                let vector_dims = {
                    let mut shard = shard.write();
                    if !shard
                        .data
                        .get(&key)
                        .is_some_and(|entry| entry.is_expired_at(now))
                    {
                        continue;
                    }
                    let vector_dims = if let Some(entry) = shard.data.remove(&key) {
                        self.key_removed();
                        let vector_dims = match &entry.value {
                            StoreValue::Vector(vector) => Some(vector.dims),
                            _ => None,
                        };
                        let mem = estimate_entry_memory(&key, &entry.value);
                        shard.used_memory = shard.used_memory.saturating_sub(mem);
                        self.mem_sub(mem);
                        vector_dims
                    } else {
                        None
                    };
                    shard.version += 1;
                    vector_dims
                };
                if let Some(dims) = vector_dims {
                    self.remove_vector_indexes(&key_string(&key), dims);
                }
            }
        }
    }

    pub fn pfadd(&self, key: &[u8], elements: &[&[u8]], now: Instant) -> Result<i64, String> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        let ks = key;
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
                e.lru_clock = self.lru_clock();
                let new_mem = estimate_entry_memory(ks, &e.value);
                if new_mem > old_mem {
                    let diff = new_mem - old_mem;
                    shard.used_memory += diff;
                    self.mem_add(diff);
                } else {
                    let diff = old_mem - new_mem;
                    shard.used_memory = shard.used_memory.saturating_sub(diff);
                    self.mem_sub(diff);
                }
                Ok(if changed { 1 } else { 0 })
            }
            Some(e) => match &mut e.value {
                StoreValue::HyperLogLog(regs, cached) => {
                    e.lru_clock = self.lru_clock();
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
                let old = shard.data.insert(
                    key_bytes(key),
                    Entry {
                        value: sv,
                        expires_at: None,
                        lru_clock: self.lru_clock(),
                    },
                );
                if old.is_none() {
                    self.key_added();
                }
                shard.used_memory += mem;
                self.mem_add(mem);
                Ok(if changed { 1 } else { 0 })
            }
        }
    }

    pub fn pfcount(&self, keys: &[&[u8]], now: Instant) -> Result<i64, String> {
        if keys.len() == 1 {
            let idx = self.shard_index(keys[0]);
            let shard = self.shards[idx].read();
            let ks = keys[0];
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
                let key = *key;
                let idx = self.shard_index(key);
                let shard = self.shards[idx].read();
                let ks = key;
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
            let ks = dest;
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
            let src = *src;
            let idx = self.shard_index(src);
            let shard = self.shards[idx].read();
            let ks = src;
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
            let ks = dest;
            let cached = crate::hll::hll_count(&merged);
            let sv = StoreValue::HyperLogLog(merged, cached);
            let new_mem = estimate_entry_memory(ks, &sv);
            if let Some(old) = shard.data.get(ks) {
                let old_mem = estimate_entry_memory(ks, &old.value);
                if new_mem > old_mem {
                    let diff = new_mem - old_mem;
                    shard.used_memory += diff;
                    self.mem_add(diff);
                } else {
                    let diff = old_mem - new_mem;
                    shard.used_memory = shard.used_memory.saturating_sub(diff);
                    self.mem_sub(diff);
                }
            } else {
                shard.used_memory += new_mem;
                self.mem_add(new_mem);
            }
            let old = shard.data.insert(
                key_bytes(dest),
                Entry {
                    value: sv,
                    expires_at: None,
                    lru_clock: self.lru_clock(),
                },
            );
            if old.is_none() {
                self.key_added();
            }
        }
        Ok(())
    }
}

fn store_value_to_dump_value(value: &StoreValue) -> DumpValue {
    match value {
        StoreValue::Str(s) => DumpValue::Str(s.to_vec()),
        StoreValue::StrBuf(s) => DumpValue::Str(s.clone()),
        StoreValue::List(l) => DumpValue::List(l.iter().map(|b| b.to_vec()).collect()),
        StoreValue::Hash(h) => DumpValue::Hash(
            h.fields
                .iter()
                .map(|(k, v)| (k.clone(), v.to_vec()))
                .collect(),
            h.expiries.iter().map(|(k, &ms)| (k.clone(), ms)).collect(),
        ),
        StoreValue::Set(s) => DumpValue::Set(s.iter().cloned().collect()),
        StoreValue::SortedSet(_, scores) => {
            DumpValue::SortedSet(scores.iter().map(|(m, s)| (m.clone(), *s)).collect())
        }
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
            let groups: Vec<StreamGroupDump> = s
                .groups
                .iter()
                .map(|(name, group)| {
                    let consumers = group
                        .consumers
                        .iter()
                        .map(|(consumer, data)| {
                            let mut pending: Vec<String> =
                                data.pel.iter().map(ToString::to_string).collect();
                            pending.sort();
                            (consumer.clone(), pending)
                        })
                        .collect();
                    let pending = group
                        .pel
                        .iter()
                        .map(|(id, entry)| {
                            (id.to_string(), entry.consumer.clone(), entry.delivery_count)
                        })
                        .collect();
                    (
                        name.clone(),
                        group.last_delivered_id.to_string(),
                        consumers,
                        pending,
                    )
                })
                .collect();
            DumpValue::Stream(entries, s.last_id.to_string(), groups)
        }
        StoreValue::Vector(v) => DumpValue::Vector(v.data.clone(), v.metadata.clone(), v.encrypted),
        StoreValue::HyperLogLog(regs, cached) => DumpValue::HyperLogLog(regs.clone(), *cached),
        StoreValue::TimeSeries(ts) => {
            DumpValue::TimeSeries(ts.samples.clone(), ts.retention, ts.labels.clone())
        }
    }
}

pub type StreamDumpEntry = (String, Vec<(String, Vec<u8>)>);
pub type StreamConsumerDump = (String, Vec<String>);
pub type StreamPendingDump = (String, String, u64);
pub type StreamGroupDump = (
    String,
    String,
    Vec<StreamConsumerDump>,
    Vec<StreamPendingDump>,
);

#[derive(Debug)]
pub enum DumpValue {
    Str(Vec<u8>),
    List(Vec<Vec<u8>>),
    /// Hash fields plus per-field absolute-ms TTLs (empty when no field has one).
    Hash(Vec<(String, Vec<u8>)>, Vec<(String, i64)>),
    Set(Vec<String>),
    SortedSet(Vec<(String, f64)>),
    Stream(Vec<StreamDumpEntry>, String, Vec<StreamGroupDump>),
    /// f32 data, metadata, and whether it is encrypted-at-rest (sealed in the
    /// snapshot; the in-memory copy is plaintext).
    Vector(Vec<f32>, Option<String>, bool),
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
        if self.pattern.len() > 10_000
            && self.pattern.iter().filter(|&&ch| ch == '*').count() > 1_000
        {
            return false;
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
        assert_eq!(store.strlen(b"key", n), 11);
        assert_eq!(store.getrange(b"key", 6, -1, n).unwrap(), &b"world"[..]);
    }

    #[test]
    fn dbsize_tracks_common_key_lifecycle() {
        let store = Store::new();
        let n = now();

        store.set(b"string", b"1", None, n);
        store.lpush(b"list", &[b"a"], n).unwrap();
        store.hset(b"hash", &[(b"field", b"value")], n).unwrap();
        store.sadd(b"set", &[b"member"], n).unwrap();
        store
            .zadd(
                b"zset",
                &[(b"member" as &[u8], 1.0)],
                false,
                false,
                false,
                false,
                false,
                n,
            )
            .unwrap();
        store
            .xadd(
                b"stream",
                "*",
                vec![("field".to_string(), Bytes::from_static(b"value"))],
                None,
                n,
            )
            .unwrap();

        assert_eq!(store.dbsize(n), 6);
        assert_eq!(store.del(&[b"string", b"list"]), 2);
        assert_eq!(store.dbsize(n), 4);
        store.flushdb();
        assert_eq!(store.dbsize(n), 0);
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
        assert_eq!(store.getrange(b"key", 0, 4, n).unwrap(), &b"Hello"[..]);
        assert_eq!(store.getrange(b"key", -6, -1, n).unwrap(), &b"World!"[..]);
    }

    #[test]
    fn setrange_pads_and_overwrites() {
        let store = Store::new();
        let n = now();
        store.set(b"key", b"Hello", None, n);
        store.setrange(b"key", 6, b"World", n).unwrap();
        let val = store.get(b"key", n).unwrap();
        assert_eq!(val.len(), 11);
        assert_eq!(val[5], 0);
    }

    #[test]
    fn setrange_empty_missing_does_not_create_key() {
        let store = Store::new();
        let n = now();

        assert_eq!(store.setrange(b"key", 0, b"", n).unwrap(), 0);
        assert!(store.get(b"key", n).is_none());
        assert_eq!(store.dbsize(n), 0);
    }

    #[test]
    fn range_commands_error_on_wrong_type() {
        let store = Store::new();
        let n = now();

        store.lpush(b"list", &[b"value"], n).unwrap();
        assert!(store
            .getrange(b"list", 0, -1, n)
            .unwrap_err()
            .contains("WRONGTYPE"));
        assert!(store
            .setrange(b"list", 0, b"", n)
            .unwrap_err()
            .contains("WRONGTYPE"));
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
    fn expireat_past_timestamp_deletes_key() {
        let store = Store::new();
        let n = now();
        store.set(b"k", b"v", None, n);
        assert!(store.expireat(b"k", 1000, n));
        assert!(store.get(b"k", Instant::now()).is_none());
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
    fn vector_search_indexes_are_dimension_scoped() {
        let store = Store::new();
        let n = now();
        store.vset(b"two_dim", vec![1.0, 0.0], None, None, false, n);
        store.vset(b"three_dim", vec![0.0, 1.0, 0.0], None, None, false, n);

        let two_dim = store.vsearch(&[1.0, 0.0], 1, None, None, n);
        assert_eq!(
            two_dim.first().map(|(key, _, _)| key.as_str()),
            Some("two_dim")
        );
        assert!(!two_dim.iter().any(|(key, _, _)| key == "three_dim"));

        let three_dim = store.vsearch(&[0.0, 1.0, 0.0], 1, None, None, n);
        assert_eq!(
            three_dim.first().map(|(key, _, _)| key.as_str()),
            Some("three_dim")
        );
        assert_eq!(store.vcard(n), 2);
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

    #[test]
    fn keys_matches_very_long_nested_pattern() {
        let store = Store::new();
        let n = now();
        let key = "a".repeat(50_000);
        let pattern = "*?".repeat(50_000);

        store.set(key.as_bytes(), b"1", None, n);
        assert!(store.keys(pattern.as_bytes(), n).is_empty());
    }

    #[test]
    fn legacy_shard_wals_replay_before_new_global_journal_writes() {
        let dir = tempfile::tempdir().unwrap();
        let config = Arc::new(crate::ServerConfig {
            data_dir: dir.path().to_string_lossy().to_string(),
            storage: crate::StorageConfig {
                mode: crate::StorageMode::Tiered,
                dir: dir.path().to_string_lossy().to_string(),
            },
            durability: crate::DurabilityConfig {
                policy: crate::DurabilityPolicy::EverySecond,
                ..Default::default()
            },
            ..crate::ServerConfig::default()
        });
        {
            let mut legacy = crate::disk::Wal::open(dir.path(), 0).unwrap();
            legacy
                .append_command(&[b"SET", b"legacy", b"value"])
                .unwrap();
        }

        let store = Store::new_with_config(config.clone());
        store.replay_wal(&crate::pubsub::Broker::new()).unwrap();
        assert_eq!(store.get(b"legacy", now()).unwrap(), b"value".as_slice());

        let command: [&[u8]; 3] = [b"SET", b"global", b"value"];
        store
            .commit_journaled(&command, || store.set(b"global", b"value", None, now()))
            .unwrap();
        store.fsync_wal();
        drop(store);

        assert!(dir.path().join("global/wal.lux").exists());
        let restored = Store::new_with_config(config);
        restored.replay_wal(&crate::pubsub::Broker::new()).unwrap();
        assert_eq!(restored.get(b"legacy", now()).unwrap(), b"value".as_slice());
        assert_eq!(restored.get(b"global", now()).unwrap(), b"value".as_slice());
    }

    #[test]
    fn poisoned_journal_rejects_every_later_mutation() {
        let dir = tempfile::tempdir().unwrap();
        let config = Arc::new(crate::ServerConfig {
            data_dir: dir.path().to_string_lossy().to_string(),
            durability: crate::DurabilityConfig {
                policy: crate::DurabilityPolicy::AlwaysSync,
                ..Default::default()
            },
            ..crate::ServerConfig::default()
        });
        let store = Store::new_with_config(config);
        store.poison_journal();

        let command: [&[u8]; 3] = [b"SET", b"unsafe", b"value"];
        let error = store
            .commit_journaled(&command, || store.set(b"unsafe", b"value", None, now()))
            .expect_err("a poisoned journal must fail closed");
        assert!(error.to_string().contains("restart required"));
        assert!(store.get(b"unsafe", now()).is_none());
        assert!(!store.wal_enabled());
    }

    #[test]
    fn periodic_fsync_failure_fences_later_mutations() {
        let dir = tempfile::tempdir().unwrap();
        let config = Arc::new(crate::ServerConfig {
            data_dir: dir.path().to_string_lossy().to_string(),
            durability: crate::DurabilityConfig {
                policy: crate::DurabilityPolicy::EverySecond,
                ..Default::default()
            },
            ..crate::ServerConfig::default()
        });
        let store = Store::new_with_config(config);
        let accepted: [&[u8]; 3] = [b"SET", b"accepted", b"value"];
        store
            .commit_journaled(&accepted, || store.set(b"accepted", b"value", None, now()))
            .unwrap();

        store.inject_journal_fsync_failures(1);
        let error = store
            .fsync_wal_checked()
            .expect_err("the injected periodic sync must fail");
        assert!(error.to_string().contains("injected journal fsync failure"));
        assert!(!store.wal_enabled());

        let later: [&[u8]; 3] = [b"SET", b"later", b"value"];
        let error = store
            .commit_journaled(&later, || store.set(b"later", b"value", None, now()))
            .expect_err("writes after a failed periodic sync must fail closed");
        assert!(error.to_string().contains("restart required"));
        assert!(store.get(b"later", now()).is_none());
    }

    #[test]
    fn failed_prepared_apply_poison_fences_later_mutations() {
        let dir = tempfile::tempdir().unwrap();
        let config = Arc::new(crate::ServerConfig {
            data_dir: dir.path().to_string_lossy().to_string(),
            durability: crate::DurabilityConfig {
                policy: crate::DurabilityPolicy::AlwaysSync,
                ..Default::default()
            },
            ..crate::ServerConfig::default()
        });
        let store = Store::new_with_config(config.clone());
        let route: [&[u8]; 2] = [b"SET", b"planned"];
        let result: std::io::Result<Result<(), String>> = store.commit_prepared(
            &route,
            || {
                Ok(JournalPlan::command(
                    vec![b"SET".to_vec(), b"planned".to_vec(), b"value".to_vec()],
                    (),
                ))
            },
            |()| Err("injected apply failure".to_string()),
        );
        assert_eq!(
            result.unwrap().unwrap_err(),
            "injected apply failure".to_string()
        );
        assert!(!store.wal_enabled());

        let later: [&[u8]; 3] = [b"SET", b"later", b"value"];
        let error = store
            .commit_journaled(&later, || store.set(b"later", b"value", None, now()))
            .expect_err("an indeterminate apply must fence later mutations");
        assert!(error.to_string().contains("restart required"));
        assert!(store.get(b"later", now()).is_none());
        drop(store);

        let restored = Store::new_with_config(config);
        restored.replay_wal(&crate::pubsub::Broker::new()).unwrap();
        assert_eq!(
            restored.get(b"planned", now()).unwrap(),
            b"value".as_slice()
        );
        assert!(restored.get(b"later", now()).is_none());
    }

    #[test]
    fn panicked_prepared_apply_poison_fences_later_mutations() {
        let dir = tempfile::tempdir().unwrap();
        let config = Arc::new(crate::ServerConfig {
            data_dir: dir.path().to_string_lossy().to_string(),
            durability: crate::DurabilityConfig {
                policy: crate::DurabilityPolicy::AlwaysSync,
                ..Default::default()
            },
            ..crate::ServerConfig::default()
        });
        let store = Store::new_with_config(config.clone());
        let route: [&[u8]; 2] = [b"SET", b"planned"];
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _: std::io::Result<Result<(), String>> = store.commit_prepared(
                &route,
                || {
                    Ok(JournalPlan::command(
                        vec![b"SET".to_vec(), b"planned".to_vec(), b"value".to_vec()],
                        (),
                    ))
                },
                |()| panic!("injected apply panic"),
            );
        }));
        assert!(panic.is_err());
        assert!(!store.wal_enabled());

        let later: [&[u8]; 3] = [b"SET", b"later", b"value"];
        assert!(store
            .commit_journaled(&later, || store.set(b"later", b"value", None, now()))
            .is_err());
        drop(store);

        let restored = Store::new_with_config(config);
        restored.replay_wal(&crate::pubsub::Broker::new()).unwrap();
        assert_eq!(
            restored.get(b"planned", now()).unwrap(),
            b"value".as_slice()
        );
        assert!(restored.get(b"later", now()).is_none());
    }

    #[test]
    fn panicked_checked_apply_poison_fences_later_mutations() {
        let dir = tempfile::tempdir().unwrap();
        let config = Arc::new(crate::ServerConfig {
            data_dir: dir.path().to_string_lossy().to_string(),
            durability: crate::DurabilityConfig {
                policy: crate::DurabilityPolicy::AlwaysSync,
                ..Default::default()
            },
            ..crate::ServerConfig::default()
        });
        let store = Store::new_with_config(config.clone());
        let command: [&[u8]; 3] = [b"SET", b"planned", b"value"];
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _: std::io::Result<()> =
                store.commit_journaled_checked(&command, || panic!("injected checked apply panic"));
        }));
        assert!(panic.is_err());
        assert!(!store.wal_enabled());

        let later: [&[u8]; 3] = [b"SET", b"later", b"value"];
        assert!(store
            .commit_journaled(&later, || store.set(b"later", b"value", None, now()))
            .is_err());
        drop(store);

        let restored = Store::new_with_config(config);
        restored.replay_wal(&crate::pubsub::Broker::new()).unwrap();
        assert_eq!(
            restored.get(b"planned", now()).unwrap(),
            b"value".as_slice()
        );
        assert!(restored.get(b"later", now()).is_none());
    }

    #[test]
    fn abandoned_journal_commit_guard_fences_later_mutations() {
        let dir = tempfile::tempdir().unwrap();
        let config = Arc::new(crate::ServerConfig {
            data_dir: dir.path().to_string_lossy().to_string(),
            durability: crate::DurabilityConfig {
                policy: crate::DurabilityPolicy::AlwaysSync,
                ..Default::default()
            },
            ..crate::ServerConfig::default()
        });
        let store = Store::new_with_config(config);
        let command: [&[u8]; 3] = [b"SET", b"planned", b"value"];
        let commit = store.begin_journaled(&command).unwrap();
        drop(commit);

        assert!(!store.wal_enabled());
        let later: [&[u8]; 3] = [b"SET", b"later", b"value"];
        let error = store
            .commit_journaled(&later, || store.set(b"later", b"value", None, now()))
            .expect_err("an abandoned live apply must fence later mutations");
        assert!(error.to_string().contains("restart required"));
        assert!(store.get(b"later", now()).is_none());
    }

    #[test]
    fn computed_multi_key_write_holds_source_gate_during_resolution() {
        let dir = tempfile::tempdir().unwrap();
        let config = Arc::new(crate::ServerConfig {
            data_dir: dir.path().to_string_lossy().to_string(),
            storage: crate::StorageConfig {
                mode: crate::StorageMode::Tiered,
                dir: dir.path().to_string_lossy().to_string(),
            },
            durability: crate::DurabilityConfig {
                policy: crate::DurabilityPolicy::EverySecond,
                ..Default::default()
            },
            ..crate::ServerConfig::default()
        });
        let store = Arc::new(Store::new_with_config(config));
        let n = now();
        store.sadd(b"source", &[b"before"], n).unwrap();

        let source_route: [&[u8]; 2] = [b"SADD", b"source"];
        let source_gate = store.prepare_journaled(&source_route).unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let worker_store = store.clone();
        let worker = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let result = worker_store.sunionstore(b"destination", &[b"source"], n);
            done_tx.send(result).unwrap();
        });

        started_rx.recv().unwrap();
        assert!(done_rx.recv_timeout(Duration::from_millis(50)).is_err());
        store.sadd(b"source", &[b"during"], n).unwrap();
        drop(source_gate);

        assert_eq!(done_rx.recv_timeout(Duration::from_secs(2)).unwrap(), Ok(2));
        worker.join().unwrap();
        let members = store.smembers(b"destination", n).unwrap();
        assert!(members.iter().any(|member| member == "before"));
        assert!(members.iter().any(|member| member == "during"));
    }

    #[test]
    fn tiered_eviction_waits_for_the_logical_mutation_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let config = Arc::new(crate::ServerConfig {
            data_dir: dir.path().to_string_lossy().to_string(),
            storage: crate::StorageConfig {
                mode: crate::StorageMode::Tiered,
                dir: dir.path().to_string_lossy().to_string(),
            },
            durability: crate::DurabilityConfig {
                policy: crate::DurabilityPolicy::EverySecond,
                ..Default::default()
            },
            ..crate::ServerConfig::default()
        });
        let store = Arc::new(Store::new_with_config(config));
        store.set(b"key", b"before", None, now());
        let command: [&[u8]; 3] = [b"SET", b"key", b"after"];
        let prepared = store.prepare_journaled(&command).unwrap();

        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let worker_store = store.clone();
        let shard = store.shard_for_key(b"key");
        let worker = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            done_tx.send(worker_store.evict_key(shard, b"key")).unwrap();
        });

        started_rx.recv().unwrap();
        assert!(done_rx.recv_timeout(Duration::from_millis(50)).is_err());
        let commit = prepared.commit(&command).unwrap();
        store.set(b"key", b"after", None, now());
        commit.complete().unwrap();

        assert!(done_rx.recv_timeout(Duration::from_secs(2)).unwrap());
        worker.join().unwrap();
        assert!(store.try_promote(b"key", now()).unwrap());
        assert_eq!(store.get(b"key", now()).unwrap(), b"after".as_slice());
    }

    #[test]
    fn tiered_promotion_waits_for_the_logical_mutation_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let config = Arc::new(crate::ServerConfig {
            data_dir: dir.path().to_string_lossy().to_string(),
            storage: crate::StorageConfig {
                mode: crate::StorageMode::Tiered,
                dir: dir.path().to_string_lossy().to_string(),
            },
            durability: crate::DurabilityConfig {
                policy: crate::DurabilityPolicy::EverySecond,
                ..Default::default()
            },
            ..crate::ServerConfig::default()
        });
        let store = Arc::new(Store::new_with_config(config));
        store.set(b"key", b"before", None, now());
        let shard = store.shard_for_key(b"key");
        assert!(store.evict_key(shard, b"key"));

        let command: [&[u8]; 3] = [b"SET", b"key", b"after"];
        let prepared = store.prepare_journaled(&command).unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let worker_store = store.clone();
        let worker = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            done_tx
                .send(worker_store.try_promote(b"key", now()))
                .unwrap();
        });

        started_rx.recv().unwrap();
        assert!(done_rx.recv_timeout(Duration::from_millis(50)).is_err());
        let commit = prepared.commit(&command).unwrap();
        store.set(b"key", b"after", None, now());
        commit.complete().unwrap();

        assert!(!done_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap());
        worker.join().unwrap();
        assert_eq!(store.get(b"key", now()).unwrap(), b"after".as_slice());
    }

    #[test]
    fn shutdown_barrier_waits_for_inflight_mutation_and_syncs_it() {
        let dir = tempfile::tempdir().unwrap();
        let config = Arc::new(crate::ServerConfig {
            data_dir: dir.path().to_string_lossy().into_owned(),
            durability: crate::DurabilityConfig {
                policy: crate::DurabilityPolicy::EverySecond,
                sync_interval: Duration::from_secs(1),
            },
            ..crate::ServerConfig::default()
        });
        let store = Arc::new(Store::new_with_config(config.clone()));
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let command: [&[u8]; 3] = [b"SET", b"shutdown:key", b"value"];
        let worker_store = store.clone();
        let worker = std::thread::spawn(move || {
            let apply_store = worker_store.clone();
            worker_store.commit_journaled(&command, || {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                apply_store.set(b"shutdown:key", b"value", None, now());
            })
        });

        entered_rx.recv().unwrap();
        store.begin_shutdown();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let final_store = store.clone();
        let finalizer = std::thread::spawn(move || {
            done_tx.send(final_store.finalize_shutdown()).unwrap();
        });
        assert!(done_rx.recv_timeout(Duration::from_millis(50)).is_err());

        release_tx.send(()).unwrap();
        worker.join().unwrap().unwrap();
        done_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap();
        finalizer.join().unwrap();

        let rejected: [&[u8]; 3] = [b"SET", b"shutdown:late", b"lost"];
        assert!(store
            .commit_journaled(&rejected, || {
                store.set(b"shutdown:late", b"lost", None, now())
            })
            .is_err());
        drop(store);

        let recovered = Store::new_with_config(config);
        recovered.replay_wal(&crate::pubsub::Broker::new()).unwrap();
        assert_eq!(
            recovered.get(b"shutdown:key", now()).unwrap(),
            b"value".as_slice()
        );
        assert!(recovered.get(b"shutdown:late", now()).is_none());
    }

    #[test]
    fn mutation_waiting_for_a_domain_is_rechecked_after_shutdown() {
        let store = Arc::new(Store::new());
        let command: [&[u8]; 3] = [b"SET", b"same-key", b"value"];
        let held = store.prepare_journaled(&command).unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let waiting_store = store.clone();
        let waiter = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let result = waiting_store.prepare_journaled(&command).map(drop);
            done_tx.send(result).unwrap();
        });

        started_rx.recv().unwrap();
        assert!(done_rx.recv_timeout(Duration::from_millis(50)).is_err());
        store.begin_shutdown();
        drop(held);

        let error = done_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap_err();
        assert!(error.to_string().contains("shutting down"), "{error}");
        waiter.join().unwrap();
    }
}
