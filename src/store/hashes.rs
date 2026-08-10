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
                    value: StoreValue::Hash(HashData::default()),
                    expires_at: None,
                    lru_clock: self.lru_clock(),
                })
            }
        };
        if entry.is_expired_at(now) {
            entry.value = StoreValue::Hash(HashData::default());
            entry.expires_at = None;
        }
        match &mut entry.value {
            StoreValue::Hash(map) => {
                map.purge_expired(epoch_ms());
                let mut added = 0i64;
                let mut mem_delta: isize = 0;
                let mut stored_pairs = Vec::with_capacity(pairs.len());
                for (field, value) in pairs {
                    let field_name = key_string(field);
                    let existing_encrypted = map.fields.get(&field_name).is_some_and(|raw| {
                        crate::encryption::EncryptionKeyring::is_encrypted_value(raw)
                    });
                    let stored_value = if encrypted || existing_encrypted {
                        self.encrypt_hash_field_value(key, field, value)?
                    } else {
                        value.to_vec()
                    };
                    let new_size = (field.len() + stored_value.len() + 64) as isize;
                    // Setting a field's value clears any TTL it had (Redis 7.4).
                    map.expiries.remove(&field_name);
                    if let Some(old_val) = map
                        .fields
                        .insert(field_name, Bytes::copy_from_slice(&stored_value))
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
                    value: StoreValue::Hash(HashData::default()),
                    expires_at: None,
                    lru_clock: self.lru_clock(),
                })
            }
        };
        if entry.is_expired_at(now) {
            entry.value = StoreValue::Hash(HashData::default());
            entry.expires_at = None;
        }
        match &mut entry.value {
            StoreValue::Hash(map) => {
                map.purge_expired(epoch_ms());
                let mut added = 0i64;
                let mut mem_delta: isize = 0;
                for (field, value) in pairs {
                    let field_name = key_string(field);
                    map.expiries.remove(&field_name);
                    if let Some(old_val) =
                        map.fields.insert(field_name, Bytes::copy_from_slice(value))
                    {
                        mem_delta += value.len() as isize - old_val.len() as isize;
                    } else {
                        added += 1;
                        mem_delta += (field.len() + value.len() + 64) as isize;
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
                    .get_live(key_str(field), epoch_ms())
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
                StoreValue::Hash(map) => map.get_live(key_str(field), epoch_ms()).cloned(),
                _ => None,
            },
            _ => None,
        }
    }

    pub fn hmget(&self, key: &[u8], fields: &[&[u8]], now: Instant) -> Vec<Option<Bytes>> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        let now_ms = epoch_ms();
        match shard.data.get(key) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Hash(map) => fields
                    .iter()
                    .map(|f| {
                        map.get_live(key_str(f), now_ms)
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
        let now_ms = epoch_ms();
        let mut drop_key = false;
        let result = match shard.data.get_mut(key) {
            Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
                StoreValue::Hash(map) => {
                    let mut removed = 0i64;
                    let mut freed = 0usize;
                    for f in fields {
                        let fname = key_str(f);
                        // An already-expired field counts as absent.
                        let expired = map.field_expired(fname, now_ms);
                        if let Some(old_val) = map.fields.remove(fname) {
                            freed += f.len() + old_val.len() + 64;
                            if !expired {
                                removed += 1;
                            }
                        }
                        map.expiries.remove(fname);
                    }
                    drop_key = map.fields.is_empty();
                    shard.used_memory = shard.used_memory.saturating_sub(freed);
                    self.mem_sub(freed);
                    Ok(removed)
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(0),
        };
        // Redis removes a hash key when its last field is deleted.
        if drop_key && shard.data.remove(key).is_some() {
            self.key_removed();
        }
        result
    }

    pub fn hgetall(&self, key: &[u8], now: Instant) -> Result<Vec<(String, Bytes)>, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        let now_ms = epoch_ms();
        match shard.data.get(key) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Hash(map) => map
                    .live_iter(now_ms)
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
        let now_ms = epoch_ms();
        match shard.data.get(key) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Hash(map) => {
                    Ok(map.live_iter(now_ms).map(|(k, _)| k.clone()).collect())
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(vec![]),
        }
    }

    pub fn hvals(&self, key: &[u8], now: Instant) -> Result<Vec<Bytes>, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        let now_ms = epoch_ms();
        match shard.data.get(key) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Hash(map) => map
                    .live_iter(now_ms)
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
                StoreValue::Hash(map) => Ok(map.live_len(epoch_ms()) as i64),
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
                StoreValue::Hash(map) => Ok(map.contains_live(key_str(field), epoch_ms())),
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
                    value: StoreValue::Hash(HashData::default()),
                    expires_at: None,
                    lru_clock: self.lru_clock(),
                })
            }
        };
        if entry.is_expired_at(now) {
            entry.value = StoreValue::Hash(HashData::default());
            entry.expires_at = None;
        }
        match &mut entry.value {
            StoreValue::Hash(map) => {
                map.purge_expired(epoch_ms());
                let fs = key_str(field);
                // Overwriting the value clears any field TTL (Redis 7.4).
                map.expiries.remove(fs);
                if let Some(value) = map.fields.get_mut(fs) {
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
                    map.fields.insert(key_string(field), new_bytes);
                    let added = field.len() + new_len + 64;
                    shard.used_memory += added;
                    self.mem_add(added);
                    Ok(new_val)
                }
            }
            _ => Err(WRONGTYPE.to_string()),
        }
    }

    // --- Hash field TTL family (Redis 7.4) ---

    /// HEXPIRE/HPEXPIRE/HEXPIREAT/HPEXPIREAT: set an absolute-ms deadline on each
    /// field, honoring NX/XX/GT/LT. Per-field result: -2 missing, 0 condition not
    /// met, 1 set, 2 deleted (deadline already at/behind now). Errors WRONGTYPE.
    pub fn hexpire_fields(
        &self,
        key: &[u8],
        fields: &[&[u8]],
        deadline_ms: i64,
        cond: HExpireCond,
        now: Instant,
    ) -> Result<Vec<i64>, String> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        let now_ms = epoch_ms();
        let mut drop_key = false;
        let out = match shard.data.get_mut(key) {
            Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
                StoreValue::Hash(map) => {
                    map.purge_expired(now_ms);
                    let mut results = Vec::with_capacity(fields.len());
                    let mut freed = 0usize;
                    for f in fields {
                        let fname = key_str(f);
                        if !map.fields.contains_key(fname) {
                            results.push(-2);
                            continue;
                        }
                        let cur = map.expiries.get(fname).copied();
                        let allowed = match cond {
                            HExpireCond::None => true,
                            HExpireCond::Nx => cur.is_none(),
                            HExpireCond::Xx => cur.is_some(),
                            HExpireCond::Gt => cur.is_some_and(|c| deadline_ms > c),
                            HExpireCond::Lt => cur.is_none_or(|c| deadline_ms < c),
                        };
                        if !allowed {
                            results.push(0);
                            continue;
                        }
                        if deadline_ms <= now_ms {
                            // Past deadline: delete the field immediately.
                            if let Some(v) = map.fields.remove(fname) {
                                freed += f.len() + v.len() + 64;
                            }
                            map.expiries.remove(fname);
                            results.push(2);
                        } else {
                            map.expiries.insert(fname.to_string(), deadline_ms);
                            results.push(1);
                        }
                    }
                    drop_key = map.fields.is_empty();
                    shard.used_memory = shard.used_memory.saturating_sub(freed);
                    self.mem_sub(freed);
                    Ok(results)
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            // Missing key: every field is missing.
            _ => Ok(fields.iter().map(|_| -2).collect()),
        };
        if drop_key && shard.data.remove(key).is_some() {
            self.key_removed();
        }
        out
    }

    /// HTTL/HPTTL/HEXPIRETIME/HPEXPIRETIME: per-field TTL state. Errors WRONGTYPE.
    pub fn httl_fields(
        &self,
        key: &[u8],
        fields: &[&[u8]],
        now: Instant,
    ) -> Result<Vec<HFieldTtl>, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        let now_ms = epoch_ms();
        match shard.data.get(key) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Hash(map) => Ok(fields
                    .iter()
                    .map(|f| {
                        let fname = key_str(f);
                        if !map.contains_live(fname, now_ms) {
                            HFieldTtl::Missing
                        } else {
                            match map.expiries.get(fname) {
                                Some(&ms) => HFieldTtl::ExpiresAtMs(ms),
                                None => HFieldTtl::NoTtl,
                            }
                        }
                    })
                    .collect()),
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(fields.iter().map(|_| HFieldTtl::Missing).collect()),
        }
    }

    /// HPERSIST: drop each field's TTL. Per-field: -2 missing, -1 no TTL, 1 removed.
    pub fn hpersist_fields(
        &self,
        key: &[u8],
        fields: &[&[u8]],
        now: Instant,
    ) -> Result<Vec<i64>, String> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        let now_ms = epoch_ms();
        match shard.data.get_mut(key) {
            Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
                StoreValue::Hash(map) => {
                    map.purge_expired(now_ms);
                    Ok(fields
                        .iter()
                        .map(|f| {
                            let fname = key_str(f);
                            if !map.fields.contains_key(fname) {
                                -2
                            } else if map.expiries.remove(fname).is_some() {
                                1
                            } else {
                                -1
                            }
                        })
                        .collect())
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(fields.iter().map(|_| -2).collect()),
        }
    }

    /// HGETDEL: return each field's (decrypted) value and delete it.
    pub fn hgetdel_fields(
        &self,
        key: &[u8],
        fields: &[&[u8]],
        now: Instant,
    ) -> Result<Vec<Option<Bytes>>, String> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        let now_ms = epoch_ms();
        let mut drop_key = false;
        let out = match shard.data.get_mut(key) {
            Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
                StoreValue::Hash(map) => {
                    map.purge_expired(now_ms);
                    let mut results = Vec::with_capacity(fields.len());
                    let mut freed = 0usize;
                    for f in fields {
                        let fname = key_str(f);
                        map.expiries.remove(fname);
                        match map.fields.remove(fname) {
                            Some(v) => {
                                freed += f.len() + v.len() + 64;
                                results.push(self.decrypt_hash_field_value(key, f, v).ok());
                            }
                            None => results.push(None),
                        }
                    }
                    drop_key = map.fields.is_empty();
                    shard.used_memory = shard.used_memory.saturating_sub(freed);
                    self.mem_sub(freed);
                    Ok(results)
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(fields.iter().map(|_| None).collect()),
        };
        if drop_key && shard.data.remove(key).is_some() {
            self.key_removed();
        }
        out
    }

    /// HGETEX: return each field's (decrypted) value, optionally mutating its TTL
    /// (persist, or set an absolute-ms deadline). A past deadline deletes the field.
    pub fn hgetex_fields(
        &self,
        key: &[u8],
        fields: &[&[u8]],
        ttl: HGetexTtl,
        now: Instant,
    ) -> Result<Vec<Option<Bytes>>, String> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        // Only a TTL mutation dirties the shard; a plain read (Keep) does not.
        if !matches!(ttl, HGetexTtl::Keep) {
            shard.version += 1;
        }
        let now_ms = epoch_ms();
        let mut drop_key = false;
        let out = match shard.data.get_mut(key) {
            Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
                StoreValue::Hash(map) => {
                    map.purge_expired(now_ms);
                    let mut results = Vec::with_capacity(fields.len());
                    let mut freed = 0usize;
                    for f in fields {
                        let fname = key_str(f);
                        let value = map
                            .fields
                            .get(fname)
                            .cloned()
                            .and_then(|v| self.decrypt_hash_field_value(key, f, v).ok());
                        if value.is_some() {
                            match ttl {
                                HGetexTtl::Keep => {}
                                HGetexTtl::Persist => {
                                    map.expiries.remove(fname);
                                }
                                HGetexTtl::SetMs(ms) => {
                                    if ms <= now_ms {
                                        if let Some(v) = map.fields.remove(fname) {
                                            freed += f.len() + v.len() + 64;
                                        }
                                        map.expiries.remove(fname);
                                    } else {
                                        map.expiries.insert(fname.to_string(), ms);
                                    }
                                }
                            }
                        }
                        results.push(value);
                    }
                    drop_key = map.fields.is_empty();
                    shard.used_memory = shard.used_memory.saturating_sub(freed);
                    self.mem_sub(freed);
                    Ok(results)
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(fields.iter().map(|_| None).collect()),
        };
        if drop_key && shard.data.remove(key).is_some() {
            self.key_removed();
        }
        out
    }
}
