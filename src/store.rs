use bytes::Bytes;
use hashbrown::HashMap;
use parking_lot::RwLock;
use std::collections::{HashSet, VecDeque};
use std::time::{Duration, Instant};

pub fn num_shards() -> usize {
    static SHARDS: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *SHARDS.get_or_init(|| {
        std::env::var("LUX_SHARDS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| {
                let cpus = std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(4);
                (cpus * 16).next_power_of_two().max(16).min(1024)
            })
    })
}
pub const MAX_SHARDS: usize = 1024;

pub enum StoreValue {
    Str(Bytes),
    List(VecDeque<Bytes>),
    Hash(HashMap<String, Bytes>),
    Set(HashSet<String>),
}

impl StoreValue {
    pub fn type_name(&self) -> &'static str {
        match self {
            StoreValue::Str(_) => "string",
            StoreValue::List(_) => "list",
            StoreValue::Hash(_) => "hash",
            StoreValue::Set(_) => "set",
        }
    }
}

pub struct Entry {
    pub value: StoreValue,
    pub expires_at: Option<Instant>,
}

impl Entry {
    #[inline(always)]
    fn is_expired_at(&self, now: Instant) -> bool {
        self.expires_at.map_or(false, |exp| now > exp)
    }
}

#[repr(align(128))]
pub(crate) struct Shard {
    pub(crate) data: HashMap<String, Entry>,
}

pub struct Store {
    shards: Box<[RwLock<Shard>]>,
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

impl Store {
    pub fn new() -> Self {
        let n = num_shards();
        let shards: Vec<RwLock<Shard>> = (0..n)
            .map(|_| {
                RwLock::new(Shard {
                    data: HashMap::new(),
                })
            })
            .collect();
        Self {
            shards: shards.into_boxed_slice(),
        }
    }

    pub fn shard_count(&self) -> usize {
        self.shards.len()
    }

    #[inline(always)]
    fn shard_index(&self, key: &[u8]) -> usize {
        (fx_hash(key) % self.shards.len() as u64) as usize
    }

    pub fn shard_for_key(&self, key: &[u8]) -> usize {
        self.shard_index(key)
    }

    pub fn lock_read_shard(&self, idx: usize) -> parking_lot::RwLockReadGuard<'_, Shard> {
        self.shards[idx].read()
    }

    pub fn lock_write_shard(&self, idx: usize) -> parking_lot::RwLockWriteGuard<'_, Shard> {
        self.shards[idx].write()
    }

    #[inline(always)]
    pub fn get_from_shard(data: &HashMap<String, Entry>, key: &[u8], now: Instant) -> Option<Bytes> {
        let hash = fx_hash(key);
        data.raw_entry()
            .from_hash(hash, |k| k.as_bytes() == key)
            .and_then(|(_, entry)| {
                if entry.is_expired_at(now) { return None; }
                match &entry.value {
                    StoreValue::Str(s) => Some(s.clone()),
                    _ => None,
                }
            })
    }

    #[inline(always)]
    pub fn get_and_write(data: &HashMap<String, Entry>, key: &[u8], now: Instant, out: &mut bytes::BytesMut) {
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
    pub fn set_on_shard(data: &mut HashMap<String, Entry>, key: &[u8], value: &[u8], ttl: Option<Duration>, now: Instant) {
        let hash = fx_hash(key);
        let expires_at = ttl.map(|d| now + d);
        match data.raw_entry_mut().from_hash(hash, |k| k.as_bytes() == key) {
            hashbrown::hash_map::RawEntryMut::Occupied(mut e) => {
                let entry = e.get_mut();
                entry.value = StoreValue::Str(Bytes::copy_from_slice(value));
                entry.expires_at = expires_at;
            }
            hashbrown::hash_map::RawEntryMut::Vacant(e) => {
                e.insert_with_hasher(hash, key_string(key), Entry {
                    value: StoreValue::Str(Bytes::copy_from_slice(value)),
                    expires_at,
                }, |k| fx_hash(k.as_bytes()));
            }
        }
    }

    pub fn get(&self, key: &[u8], now: Instant) -> Option<Bytes> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        Self::get_from_shard(&shard.data, key, now)
    }

    pub fn get_entry_type(&self, key: &[u8], now: Instant) -> Option<&'static str> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => Some(entry.value.type_name()),
            _ => None,
        }
    }

    pub fn set(&self, key: &[u8], value: &[u8], ttl: Option<Duration>, now: Instant) {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        Self::set_on_shard(&mut shard.data, key, value, ttl, now);
    }

    pub fn set_nx(&self, key: &[u8], value: &[u8], now: Instant) -> bool {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        let ks = key_str(key);
        if let Some(entry) = shard.data.get(ks) {
            if !entry.is_expired_at(now) {
                return false;
            }
        }
        shard.data.insert(
            key_string(key),
            Entry {
                value: StoreValue::Str(Bytes::copy_from_slice(value)),
                expires_at: None,
            },
        );
        true
    }

    pub fn get_set(&self, key: &[u8], value: &[u8], now: Instant) -> Option<Bytes> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
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
        shard.data.insert(
            key_string(key),
            Entry {
                value: StoreValue::Str(Bytes::copy_from_slice(value)),
                expires_at: None,
            },
        );
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
        let mut count = 0i64;
        for key in keys {
            let idx = self.shard_index(key);
            let mut shard = self.shards[idx].write();
            if shard.data.remove(key_str(key)).is_some() {
                count += 1;
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
                }
            }
        }
        count
    }

    pub fn incr(&self, key: &[u8], delta: i64, now: Instant) -> Result<i64, String> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        let ks = key_str(key);
        let (current, expires_at) = match shard.data.get(ks) {
            Some(e) if !e.is_expired_at(now) => match &e.value {
                StoreValue::Str(s) => {
                    let s = std::str::from_utf8(s).map_err(|_| {
                        "ERR value is not an integer or out of range".to_string()
                    })?;
                    let n = s.parse::<i64>().map_err(|_| {
                        "ERR value is not an integer or out of range".to_string()
                    })?;
                    (n, e.expires_at)
                }
                _ => {
                    return Err(
                        "WRONGTYPE Operation against a key holding the wrong kind of value"
                            .to_string(),
                    )
                }
            },
            _ => (0, None),
        };
        let new_val = current + delta;
        shard.data.insert(
            key_string(key),
            Entry {
                value: StoreValue::Str(Bytes::from(new_val.to_string())),
                expires_at,
            },
        );
        Ok(new_val)
    }

    pub fn append(&self, key: &[u8], value: &[u8], now: Instant) -> i64 {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        let ks = key_str(key);
        if let Some(entry) = shard.data.get_mut(ks) {
            if !entry.is_expired_at(now) {
                if let StoreValue::Str(s) = &entry.value {
                    let mut new_val = Vec::with_capacity(s.len() + value.len());
                    new_val.extend_from_slice(s);
                    new_val.extend_from_slice(value);
                    let len = new_val.len() as i64;
                    entry.value = StoreValue::Str(Bytes::from(new_val));
                    return len;
                }
            }
        }
        let val = Bytes::copy_from_slice(value);
        let len = val.len() as i64;
        shard.data.insert(
            key_string(key),
            Entry {
                value: StoreValue::Str(val),
                expires_at: None,
            },
        );
        len
    }

    pub fn keys(&self, pattern: &[u8], now: Instant) -> Vec<String> {
        let pat_str = key_str(pattern);
        let matcher = GlobMatcher::new(pat_str);
        let mut result = Vec::new();
        for shard in self.shards.iter() {
            let shard = shard.read();
            for (k, e) in shard.data.iter() {
                if e.expires_at.map_or(true, |exp| now < exp) && matcher.matches(k) {
                    result.push(k.clone());
                }
            }
        }
        result
    }

    pub fn scan(&self, cursor: usize, pattern: &[u8], count: usize, now: Instant) -> (usize, Vec<String>) {
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
                    if now > exp { -2 } else { exp.duration_since(now).as_secs() as i64 }
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
                    if now > exp { -2 } else { exp.duration_since(now).as_millis() as i64 }
                }
            },
        }
    }

    pub fn expire(&self, key: &[u8], seconds: u64, now: Instant) -> bool {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
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
            match shard.data.remove(key_str(key)) {
                Some(e) if !e.is_expired_at(now) => e,
                _ => return Err("ERR no such key".to_string()),
            }
        };
        let new_idx = self.shard_index(new_key);
        let mut shard = self.shards[new_idx].write();
        shard.data.insert(key_string(new_key), entry);
        Ok(())
    }

    pub fn dbsize(&self, now: Instant) -> i64 {
        let mut total = 0i64;
        for shard in self.shards.iter() {
            let shard = shard.read();
            total += shard.data.values().filter(|e| e.expires_at.map_or(true, |exp| now < exp)).count() as i64;
        }
        total
    }

    pub fn flushdb(&self) {
        for shard in self.shards.iter() {
            let mut shard = shard.write();
            shard.data.clear();
        }
    }

    pub fn lpush(&self, key: &[u8], values: &[&[u8]], now: Instant) -> Result<i64, String> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        let ks = key_string(key);
        let entry = shard.data.entry(ks).or_insert_with(|| Entry {
            value: StoreValue::List(VecDeque::new()),
            expires_at: None,
        });
        if entry.is_expired_at(now) {
            entry.value = StoreValue::List(VecDeque::new());
            entry.expires_at = None;
        }
        match &mut entry.value {
            StoreValue::List(list) => {
                for v in values { list.push_front(Bytes::copy_from_slice(v)); }
                Ok(list.len() as i64)
            }
            _ => Err("WRONGTYPE Operation against a key holding the wrong kind of value".to_string()),
        }
    }

    pub fn rpush(&self, key: &[u8], values: &[&[u8]], now: Instant) -> Result<i64, String> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        let ks = key_string(key);
        let entry = shard.data.entry(ks).or_insert_with(|| Entry {
            value: StoreValue::List(VecDeque::new()),
            expires_at: None,
        });
        if entry.is_expired_at(now) {
            entry.value = StoreValue::List(VecDeque::new());
            entry.expires_at = None;
        }
        match &mut entry.value {
            StoreValue::List(list) => {
                for v in values { list.push_back(Bytes::copy_from_slice(v)); }
                Ok(list.len() as i64)
            }
            _ => Err("WRONGTYPE Operation against a key holding the wrong kind of value".to_string()),
        }
    }

    pub fn lpop(&self, key: &[u8], now: Instant) -> Option<Bytes> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        match shard.data.get_mut(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
                StoreValue::List(list) => list.pop_front(),
                _ => None,
            },
            _ => None,
        }
    }

    pub fn rpop(&self, key: &[u8], now: Instant) -> Option<Bytes> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        match shard.data.get_mut(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
                StoreValue::List(list) => list.pop_back(),
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
                _ => Err("WRONGTYPE Operation against a key holding the wrong kind of value".to_string()),
            },
            _ => Ok(0),
        }
    }

    pub fn lrange(&self, key: &[u8], start: i64, stop: i64, now: Instant) -> Result<Vec<Bytes>, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::List(list) => {
                    let len = list.len() as i64;
                    let s = if start < 0 { (len + start).max(0) as usize } else { start.min(len) as usize };
                    let e = if stop < 0 { (len + stop + 1).max(0) as usize } else { (stop + 1).min(len) as usize };
                    if s >= e { Ok(vec![]) } else { Ok(list.iter().skip(s).take(e - s).cloned().collect()) }
                }
                _ => Err("WRONGTYPE Operation against a key holding the wrong kind of value".to_string()),
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
                    let i = if index < 0 { (list.len() as i64 + index) as usize } else { index as usize };
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
        let ks = key_string(key);
        let entry = shard.data.entry(ks).or_insert_with(|| Entry {
            value: StoreValue::Hash(HashMap::new()),
            expires_at: None,
        });
        if entry.is_expired_at(now) {
            entry.value = StoreValue::Hash(HashMap::new());
            entry.expires_at = None;
        }
        match &mut entry.value {
            StoreValue::Hash(map) => {
                let mut added = 0i64;
                for (field, value) in pairs {
                    if map.insert(key_string(field), Bytes::copy_from_slice(value)).is_none() { added += 1; }
                }
                Ok(added)
            }
            _ => Err("WRONGTYPE Operation against a key holding the wrong kind of value".to_string()),
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
                StoreValue::Hash(map) => fields.iter().map(|f| map.get(key_str(f)).cloned()).collect(),
                _ => fields.iter().map(|_| None).collect(),
            },
            _ => fields.iter().map(|_| None).collect(),
        }
    }

    pub fn hdel(&self, key: &[u8], fields: &[&[u8]], now: Instant) -> Result<i64, String> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        match shard.data.get_mut(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
                StoreValue::Hash(map) => {
                    let mut removed = 0i64;
                    for f in fields { if map.remove(key_str(f)).is_some() { removed += 1; } }
                    Ok(removed)
                }
                _ => Err("WRONGTYPE Operation against a key holding the wrong kind of value".to_string()),
            },
            _ => Ok(0),
        }
    }

    pub fn hgetall(&self, key: &[u8], now: Instant) -> Result<Vec<(String, Bytes)>, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Hash(map) => Ok(map.iter().map(|(k, v)| (k.clone(), v.clone())).collect()),
                _ => Err("WRONGTYPE Operation against a key holding the wrong kind of value".to_string()),
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
                _ => Err("WRONGTYPE Operation against a key holding the wrong kind of value".to_string()),
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
                _ => Err("WRONGTYPE Operation against a key holding the wrong kind of value".to_string()),
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
                _ => Err("WRONGTYPE Operation against a key holding the wrong kind of value".to_string()),
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
                _ => Err("WRONGTYPE Operation against a key holding the wrong kind of value".to_string()),
            },
            _ => Ok(false),
        }
    }

    pub fn hincrby(&self, key: &[u8], field: &[u8], delta: i64, now: Instant) -> Result<i64, String> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        let ks = key_string(key);
        let entry = shard.data.entry(ks).or_insert_with(|| Entry {
            value: StoreValue::Hash(HashMap::new()),
            expires_at: None,
        });
        if entry.is_expired_at(now) {
            entry.value = StoreValue::Hash(HashMap::new());
            entry.expires_at = None;
        }
        match &mut entry.value {
            StoreValue::Hash(map) => {
                let fs = key_str(field);
                let current: i64 = map.get(fs)
                    .map(|v| std::str::from_utf8(v).ok()
                        .and_then(|s| s.parse::<i64>().ok())
                        .ok_or_else(|| "ERR hash value is not an integer".to_string()))
                    .transpose()?
                    .unwrap_or(0);
                let new_val = current + delta;
                map.insert(fs.to_string(), Bytes::from(new_val.to_string()));
                Ok(new_val)
            }
            _ => Err("WRONGTYPE Operation against a key holding the wrong kind of value".to_string()),
        }
    }

    pub fn sadd(&self, key: &[u8], members: &[&[u8]], now: Instant) -> Result<i64, String> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        let ks = key_string(key);
        let entry = shard.data.entry(ks).or_insert_with(|| Entry {
            value: StoreValue::Set(HashSet::new()),
            expires_at: None,
        });
        if entry.is_expired_at(now) {
            entry.value = StoreValue::Set(HashSet::new());
            entry.expires_at = None;
        }
        match &mut entry.value {
            StoreValue::Set(set) => {
                let mut added = 0i64;
                for m in members { if set.insert(key_string(m)) { added += 1; } }
                Ok(added)
            }
            _ => Err("WRONGTYPE Operation against a key holding the wrong kind of value".to_string()),
        }
    }

    pub fn srem(&self, key: &[u8], members: &[&[u8]], now: Instant) -> Result<i64, String> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        match shard.data.get_mut(key_str(key)) {
            Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
                StoreValue::Set(set) => {
                    let mut removed = 0i64;
                    for m in members { if set.remove(key_str(m)) { removed += 1; } }
                    Ok(removed)
                }
                _ => Err("WRONGTYPE Operation against a key holding the wrong kind of value".to_string()),
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
                _ => Err("WRONGTYPE Operation against a key holding the wrong kind of value".to_string()),
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
                _ => Err("WRONGTYPE Operation against a key holding the wrong kind of value".to_string()),
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
                _ => Err("WRONGTYPE Operation against a key holding the wrong kind of value".to_string()),
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
                _ => Err("WRONGTYPE Operation against a key holding the wrong kind of value".to_string()),
            },
            _ => Ok(HashSet::new()),
        }
    }

    pub fn sunion(&self, keys: &[&[u8]], now: Instant) -> Result<Vec<String>, String> {
        let mut result = HashSet::new();
        for key in keys { result.extend(self.collect_set(key, now)?); }
        Ok(result.into_iter().collect())
    }

    pub fn sinter(&self, keys: &[&[u8]], now: Instant) -> Result<Vec<String>, String> {
        if keys.is_empty() { return Ok(vec![]); }
        let mut result = self.collect_set(keys[0], now)?;
        for key in &keys[1..] { let set = self.collect_set(key, now)?; result.retain(|m| set.contains(m)); }
        Ok(result.into_iter().collect())
    }

    pub fn sdiff(&self, keys: &[&[u8]], now: Instant) -> Result<Vec<String>, String> {
        if keys.is_empty() { return Ok(vec![]); }
        let mut result = self.collect_set(keys[0], now)?;
        for key in &keys[1..] { let set = self.collect_set(key, now)?; result.retain(|m| !set.contains(m)); }
        Ok(result.into_iter().collect())
    }

    pub fn approximate_memory(&self) -> usize {
        let now = Instant::now();
        let mut total = 0usize;
        for shard in self.shards.iter() {
            let shard = shard.read();
            for (key, entry) in shard.data.iter() {
                if entry.is_expired_at(now) { continue; }
                total += key.len() + 64;
                total += match &entry.value {
                    StoreValue::Str(s) => s.len(),
                    StoreValue::List(l) => l.iter().map(|b| b.len() + 32).sum(),
                    StoreValue::Hash(h) => h.iter().map(|(k, v)| k.len() + v.len() + 64).sum(),
                    StoreValue::Set(s) => s.iter().map(|m| m.len() + 32).sum(),
                };
            }
        }
        total
    }

    pub fn dump_all(&self, now: Instant) -> Vec<DumpEntry> {
        let mut entries = Vec::new();
        for shard in self.shards.iter() {
            let shard = shard.read();
            for (key, entry) in shard.data.iter() {
                if entry.is_expired_at(now) { continue; }
                let ttl_ms = entry.expires_at.map(|exp| exp.duration_since(now).as_millis() as i64).unwrap_or(0);
                entries.push(DumpEntry {
                    key: key.clone(),
                    value: match &entry.value {
                        StoreValue::Str(s) => DumpValue::Str(String::from_utf8_lossy(s).into_owned()),
                        StoreValue::List(l) => DumpValue::List(l.iter().map(|b| String::from_utf8_lossy(b).into_owned()).collect()),
                        StoreValue::Hash(h) => DumpValue::Hash(h.iter().map(|(k, v)| (k.clone(), String::from_utf8_lossy(v).into_owned())).collect()),
                        StoreValue::Set(s) => DumpValue::Set(s.iter().cloned().collect()),
                    },
                    ttl_ms,
                });
            }
        }
        entries
    }

    pub fn load_entry(&self, key: String, value: DumpValue, ttl: Option<Duration>) {
        let idx = self.shard_index(key.as_bytes());
        let mut shard = self.shards[idx].write();
        let store_value = match value {
            DumpValue::Str(s) => StoreValue::Str(Bytes::from(s)),
            DumpValue::List(l) => StoreValue::List(l.into_iter().map(Bytes::from).collect()),
            DumpValue::Hash(h) => StoreValue::Hash(h.into_iter().map(|(k, v)| (k, Bytes::from(v))).collect()),
            DumpValue::Set(s) => StoreValue::Set(s.into_iter().collect()),
        };
        let expires_at = ttl.map(|d| Instant::now() + d);
        shard.data.insert(key, Entry { value: store_value, expires_at });
    }

    pub fn expire_sweep(&self, now: Instant) {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        now.hash(&mut hasher);
        let seed = hasher.finish() as usize;

        for (i, shard) in self.shards.iter().enumerate() {
            let should_check = {
                let shard = shard.read();
                !shard.data.is_empty()
            };
            if !should_check { continue; }

            let mut shard = shard.write();
            let keys: Vec<String> = shard.data.keys()
                .enumerate()
                .filter(|(j, _)| (*j + seed + i) % 5 == 0)
                .take(20)
                .map(|(_, k)| k.clone())
                .collect();
            for key in keys {
                if let Some(entry) = shard.data.get(&key) {
                    if entry.is_expired_at(now) {
                        shard.data.remove(&key);
                    }
                }
            }
        }
    }
}

pub enum DumpValue {
    Str(String),
    List(Vec<String>),
    Hash(Vec<(String, String)>),
    Set(Vec<String>),
}

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
        Self { pattern: pattern.chars().collect() }
    }

    fn matches(&self, s: &str) -> bool {
        if self.pattern.len() == 1 && self.pattern[0] == '*' { return true; }
        let s: Vec<char> = s.chars().collect();
        Self::do_match(&self.pattern, &s, 0, 0)
    }

    fn do_match(pattern: &[char], s: &[char], pi: usize, si: usize) -> bool {
        if pi == pattern.len() && si == s.len() { return true; }
        if pi == pattern.len() { return false; }
        if pattern[pi] == '*' {
            for i in si..=s.len() { if Self::do_match(pattern, s, pi + 1, i) { return true; } }
            return false;
        }
        if si == s.len() { return false; }
        if pattern[pi] == '?' || pattern[pi] == s[si] { return Self::do_match(pattern, s, pi + 1, si + 1); }
        false
    }
}
