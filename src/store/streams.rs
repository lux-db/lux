use super::*;

impl Store {
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
        self.xadd_on_shard(&mut shard, key, id_input, fields, maxlen, now)
    }

    /// XADD variant for callers that already hold the correct shard write lock.
    /// The caller owns shard versioning, WAL logging, and stream waiter wakeups.
    pub(crate) fn xadd_on_shard(
        &self,
        shard: &mut Shard,
        key: &[u8],
        id_input: &str,
        fields: Vec<(String, Bytes)>,
        maxlen: Option<usize>,
        now: Instant,
    ) -> Result<StreamId, String> {
        let ks = key_bytes(key);
        let entry = match shard.data.entry(ks) {
            hashbrown::hash_map::Entry::Occupied(o) => o.into_mut(),
            hashbrown::hash_map::Entry::Vacant(v) => {
                self.key_added();
                v.insert(Entry {
                    value: StoreValue::Stream(StreamData {
                        entries: BTreeMap::new(),
                        last_id: StreamId::zero(),
                        groups: std::collections::HashMap::new(),
                    }),
                    expires_at: None,
                    lru_clock: self.lru_clock(),
                })
            }
        };
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
                    self.mem_add(added - trimmed_mem);
                } else if trimmed_mem > added {
                    let freed = trimmed_mem - added;
                    shard.used_memory = shard.used_memory.saturating_sub(freed);
                    self.mem_sub(freed);
                }

                Ok(id)
            }
            _ => Err(WRONGTYPE.to_string()),
        }
    }

    pub fn xlen(&self, key: &[u8], now: Instant) -> Result<i64, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key) {
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
        match shard.data.get(key) {
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
        match shard.data.get(key) {
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
            if let Some(entry) = shard.data.get(key.as_bytes()) {
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
        let ks = key_bytes(key);

        if mkstream {
            let existed = shard.data.contains_key(&ks);
            let entry = shard.data.entry(ks.clone()).or_insert_with(|| Entry {
                value: StoreValue::Stream(StreamData {
                    entries: BTreeMap::new(),
                    last_id: StreamId::zero(),
                    groups: std::collections::HashMap::new(),
                }),
                expires_at: None,
                lru_clock: self.lru_clock(),
            });
            if !existed {
                self.key_added();
            }
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
        match shard.data.get_mut(key) {
            Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
                StoreValue::Stream(s) => Ok(s.groups.remove(group).is_some()),
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(false),
        }
    }

    pub fn xgroup_setid(
        &self,
        key: &[u8],
        group: &str,
        id: &str,
        now: Instant,
    ) -> Result<(), String> {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        match shard.data.get_mut(key) {
            Some(entry) if !entry.is_expired_at(now) => match &mut entry.value {
                StoreValue::Stream(s) => {
                    let Some(group) = s.groups.get_mut(group) else {
                        return Err(format!(
                            "NOGROUP No such consumer group '{}' for key name '{}'",
                            group,
                            key_str(key)
                        ));
                    };
                    group.last_delivered_id = if id == "$" {
                        s.last_id
                    } else {
                        StreamId::parse(id).ok_or_else(|| "ERR Invalid stream ID".to_string())?
                    };
                    Ok(())
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Err("ERR no such key".to_string()),
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
            if let Some(entry) = shard.data.get_mut(key.as_bytes()) {
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
        match shard.data.get_mut(key) {
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
        match shard.data.get(key) {
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
        match shard.data.get(key) {
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
        match shard.data.get_mut(key) {
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
        match shard.data.get_mut(key) {
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
        match shard.data.get_mut(key) {
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
                    self.mem_sub(freed);
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
        match shard.data.get_mut(key) {
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
                    self.mem_sub(freed);
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
        match shard.data.get(key) {
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
        match shard.data.get(key) {
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
        match shard.data.get(key) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::Stream(s) => Some(s.last_id),
                _ => None,
            },
            _ => None,
        }
    }
}
