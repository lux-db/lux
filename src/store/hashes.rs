use super::*;

/// `(fields_added, stored_pairs)` where each stored pair is the on-disk
/// `(field, value)` bytes (value is ciphertext when the column is encrypted).
type HsetKvOutcome = (i64, Vec<(Vec<u8>, Vec<u8>)>);

impl Store {
    pub fn hset(&self, key: &[u8], pairs: &[(&[u8], &[u8])], now: Instant) -> Result<i64, String> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        self.hset_on_shard(&mut shard, key, pairs, now)
    }

    pub(crate) fn hset_kv(
        &self,
        key: &[u8],
        pairs: &[(&[u8], &[u8])],
        encrypted: bool,
        now: Instant,
    ) -> Result<HsetKvOutcome, String> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        let ks = key_bytes(key);
        let entry = match shard.data.entry(ks) {
            hashbrown::hash_map::Entry::Occupied(o) => o.into_mut(),
            hashbrown::hash_map::Entry::Vacant(v) => {
                self.key_added();
                v.insert(Entry {
                    value: StoreValue::Hash(HashMap::new()),
                    expires_at: None,
                    lru_clock: self.lru_clock(),
                })
            }
        };
        if entry.is_expired_at(now) {
            entry.value = StoreValue::Hash(HashMap::new());
            entry.expires_at = None;
        }
        match &mut entry.value {
            StoreValue::Hash(map) => {
                let mut added = 0i64;
                let mut mem_delta: isize = 0;
                let mut stored_pairs = Vec::with_capacity(pairs.len());
                for (field, value) in pairs {
                    let field_name = key_string(field);
                    let existing_encrypted = map.get(&field_name).is_some_and(|raw| {
                        crate::encryption::EncryptionKeyring::is_encrypted_value(raw)
                    });
                    let stored_value = if encrypted || existing_encrypted {
                        self.encrypt_hash_field_value(key, field, value)?
                    } else {
                        value.to_vec()
                    };
                    let new_size = (field.len() + stored_value.len() + 64) as isize;
                    if let Some(old_val) =
                        map.insert(field_name, Bytes::copy_from_slice(&stored_value))
                    {
                        mem_delta += stored_value.len() as isize - old_val.len() as isize;
                    } else {
                        added += 1;
                        mem_delta += new_size;
                    }
                    stored_pairs.push((field.to_vec(), stored_value));
                }
                if mem_delta > 0 {
                    shard.used_memory += mem_delta as usize;
                    self.mem_add(mem_delta as usize);
                } else if mem_delta < 0 {
                    let freed = (-mem_delta) as usize;
                    shard.used_memory = shard.used_memory.saturating_sub(freed);
                    self.mem_sub(freed);
                }
                Ok((added, stored_pairs))
            }
            _ => Err(WRONGTYPE.to_string()),
        }
    }

    /// HSET variant for callers that already hold the correct shard write lock.
    /// The caller owns shard versioning, WAL logging, and key events.
    pub(crate) fn hset_on_shard(
        &self,
        shard: &mut Shard,
        key: &[u8],
        pairs: &[(&[u8], &[u8])],
        now: Instant,
    ) -> Result<i64, String> {
        let ks = key_bytes(key);
        let entry = match shard.data.entry(ks) {
            hashbrown::hash_map::Entry::Occupied(o) => o.into_mut(),
            hashbrown::hash_map::Entry::Vacant(v) => {
                self.key_added();
                v.insert(Entry {
                    value: StoreValue::Hash(HashMap::new()),
                    expires_at: None,
                    lru_clock: self.lru_clock(),
                })
            }
        };
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
                    self.mem_add(mem_delta as usize);
                } else if mem_delta < 0 {
                    let freed = (-mem_delta) as usize;
                    shard.used_memory = shard.used_memory.saturating_sub(freed);
                    self.mem_sub(freed);
                }
                Ok(added)
            }
            _ => Err(WRONGTYPE.to_string()),
        }
    }

    pub fn hget(&self, key: &[u8], field: &[u8], now: Instant) -> Option<Bytes> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Hash(map) => map
                    .get(key_str(field))
                    .cloned()
                    .map(|value| self.decrypt_hash_field_value(key, field, value))
                    .transpose()
                    .ok()
                    .flatten(),
                _ => None,
            },
            _ => None,
        }
    }

    pub(crate) fn hget_from_shard(
        data: &ShardData,
        key: &[u8],
        field: &[u8],
        now: Instant,
    ) -> Option<Bytes> {
        match data.get(key) {
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
        match shard.data.get(key) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Hash(map) => fields
                    .iter()
                    .map(|f| {
                        map.get(key_str(f))
                            .cloned()
                            .and_then(|value| self.decrypt_hash_field_value(key, f, value).ok())
                    })
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
        match shard.data.get_mut(key) {
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
                    self.mem_sub(freed);
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
        match shard.data.get(key) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Hash(map) => map
                    .iter()
                    .map(|(k, v)| {
                        self.decrypt_hash_field_value(key, k.as_bytes(), v.clone())
                            .map(|value| (k.clone(), value))
                    })
                    .collect(),
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(vec![]),
        }
    }

    pub fn hkeys(&self, key: &[u8], now: Instant) -> Result<Vec<String>, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key) {
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
        match shard.data.get(key) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Hash(map) => map
                    .iter()
                    .map(|(k, v)| self.decrypt_hash_field_value(key, k.as_bytes(), v.clone()))
                    .collect(),
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(vec![]),
        }
    }

    pub fn hlen(&self, key: &[u8], now: Instant) -> Result<i64, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key) {
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
        match shard.data.get(key) {
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
        self.hincrby_on_shard(&mut shard, key, field, delta, now)
    }

    /// HINCRBY variant for callers that already hold the correct shard write
    /// lock. The caller owns shard versioning, WAL logging, and key events.
    pub(crate) fn hincrby_on_shard(
        &self,
        shard: &mut Shard,
        key: &[u8],
        field: &[u8],
        delta: i64,
        now: Instant,
    ) -> Result<i64, String> {
        let ks = key_bytes(key);
        let entry = match shard.data.entry(ks) {
            hashbrown::hash_map::Entry::Occupied(o) => o.into_mut(),
            hashbrown::hash_map::Entry::Vacant(v) => {
                self.key_added();
                v.insert(Entry {
                    value: StoreValue::Hash(HashMap::new()),
                    expires_at: None,
                    lru_clock: self.lru_clock(),
                })
            }
        };
        if entry.is_expired_at(now) {
            entry.value = StoreValue::Hash(HashMap::new());
            entry.expires_at = None;
        }
        match &mut entry.value {
            StoreValue::Hash(map) => {
                let fs = key_str(field);
                if let Some(value) = map.get_mut(fs) {
                    let old_len = value.len();
                    let current: i64 = std::str::from_utf8(value)
                        .ok()
                        .and_then(|s| s.parse::<i64>().ok())
                        .ok_or_else(|| "ERR hash value is not an integer".to_string())?;
                    let new_val = current + delta;
                    *value = Bytes::from(new_val.to_string());
                    let new_len = value.len();
                    if new_len > old_len {
                        let added = new_len - old_len;
                        shard.used_memory += added;
                        self.mem_add(added);
                    } else if old_len > new_len {
                        let freed = old_len - new_len;
                        shard.used_memory = shard.used_memory.saturating_sub(freed);
                        self.mem_sub(freed);
                    }
                    Ok(new_val)
                } else {
                    let new_val = delta;
                    let new_bytes = Bytes::from(new_val.to_string());
                    let new_len = new_bytes.len();
                    map.insert(key_string(field), new_bytes);
                    let added = field.len() + new_len + 64;
                    shard.used_memory += added;
                    self.mem_add(added);
                    Ok(new_val)
                }
            }
            _ => Err(WRONGTYPE.to_string()),
        }
    }
}
