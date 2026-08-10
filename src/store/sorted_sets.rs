use super::*;

impl Store {
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
        self.zadd_on_shard(&mut shard, key, members, nx, xx, gt, lt, ch, now)
    }

    /// Hot-path ZADD for a single member with default options.
    /// Equivalent to: ZADD key score member.
    pub(crate) fn zadd_single_default_on_shard(
        &self,
        shard: &mut Shard,
        key: &[u8],
        member: &[u8],
        score: f64,
        now: Instant,
    ) -> Result<i64, String> {
        let ks = key_bytes(key);
        let entry = match shard.data.entry(ks) {
            hashbrown::hash_map::Entry::Occupied(o) => o.into_mut(),
            hashbrown::hash_map::Entry::Vacant(v) => {
                self.key_added();
                v.insert(Entry {
                    value: StoreValue::SortedSet(BTreeMap::new(), HashMap::new()),
                    expires_at: None,
                    lru_clock: self.lru_clock(),
                })
            }
        };
        if entry.is_expired_at(now) {
            entry.value = StoreValue::SortedSet(BTreeMap::new(), HashMap::new());
            entry.expires_at = None;
        }
        match &mut entry.value {
            StoreValue::SortedSet(tree, scores) => {
                let member_str = key_str(member);
                if let Some(old_score) = scores.get_mut(member_str) {
                    let previous = *old_score;
                    if score != previous {
                        let key_owned = member_str.to_owned();
                        tree.remove(&(OrderedFloat(previous), key_owned.clone()));
                        tree.insert((OrderedFloat(score), key_owned), ());
                        *old_score = score;
                    }
                    Ok(0)
                } else {
                    let ms = member_str.to_owned();
                    tree.insert((OrderedFloat(score), ms.clone()), ());
                    scores.insert(ms, score);
                    let mem_added = member.len() + 48;
                    shard.used_memory += mem_added;
                    self.mem_add(mem_added);
                    Ok(1)
                }
            }
            _ => Err(WRONGTYPE.to_string()),
        }
    }

    /// ZADD variant for callers that already hold the correct shard write lock.
    /// The caller owns shard versioning, WAL logging, and key events.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn zadd_on_shard(
        &self,
        shard: &mut Shard,
        key: &[u8],
        members: &[(&[u8], f64)],
        nx: bool,
        xx: bool,
        gt: bool,
        lt: bool,
        ch: bool,
        now: Instant,
    ) -> Result<i64, String> {
        let ks = key_bytes(key);
        let entry = match shard.data.entry(ks) {
            hashbrown::hash_map::Entry::Occupied(o) => o.into_mut(),
            hashbrown::hash_map::Entry::Vacant(v) => {
                if xx {
                    return Ok(0);
                }
                self.key_added();
                v.insert(Entry {
                    value: StoreValue::SortedSet(BTreeMap::new(), HashMap::new()),
                    expires_at: None,
                    lru_clock: self.lru_clock(),
                })
            }
        };
        if xx && entry.is_expired_at(now) {
            return Ok(0);
        }
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
                    let member_str = key_str(member);
                    if let Some(old_score) = scores.get_mut(member_str) {
                        if nx {
                            continue;
                        }
                        let previous = *old_score;
                        let update = if gt && lt {
                            score != previous
                        } else if gt {
                            score > previous
                        } else if lt {
                            score < previous
                        } else {
                            true
                        };
                        if update && score != previous {
                            let key_owned = member_str.to_owned();
                            tree.remove(&(OrderedFloat(previous), key_owned.clone()));
                            tree.insert((OrderedFloat(score), key_owned), ());
                            *old_score = score;
                            changed += 1;
                        }
                    } else {
                        if xx {
                            continue;
                        }
                        let ms = member_str.to_owned();
                        tree.insert((OrderedFloat(score), ms.clone()), ());
                        scores.insert(ms, score);
                        mem_added += member.len() + 48;
                        added += 1;
                    }
                }
                shard.used_memory += mem_added;
                self.mem_add(mem_added);
                Ok(if ch { added + changed } else { added })
            }
            _ => Err(WRONGTYPE.to_string()),
        }
    }

    pub fn zscore(&self, key: &[u8], member: &[u8], now: Instant) -> Result<Option<f64>, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        Self::zscore_from_shard(&shard.data, key, member, now)
    }

    pub fn zscores(
        &self,
        key: &[u8],
        members: &[&[u8]],
        now: Instant,
    ) -> Result<Vec<Option<f64>>, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::SortedSet(_, scores) => Ok(members
                    .iter()
                    .map(|member| scores.get(key_str(member)).copied())
                    .collect()),
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(vec![None; members.len()]),
        }
    }

    pub fn zscore_with_key_state(
        &self,
        key: &[u8],
        member: &[u8],
        now: Instant,
    ) -> Result<(Option<f64>, bool), String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::SortedSet(_, scores) => {
                    Ok((scores.get(key_str(member)).copied(), true))
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok((None, false)),
        }
    }

    pub(crate) fn zscore_from_shard(
        data: &ShardData,
        key: &[u8],
        member: &[u8],
        now: Instant,
    ) -> Result<Option<f64>, String> {
        match data.get(key) {
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
        match shard.data.get(key) {
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
        match shard.data.get_mut(key) {
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
                    self.mem_sub(freed);
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
        match shard.data.get(key) {
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
        match shard.data.get(key) {
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
        match shard.data.get(key) {
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
        self.zincrby_on_shard(&mut shard, key, member, increment, now)
    }

    /// ZINCRBY variant for callers that already hold the correct shard write
    /// lock. The caller owns shard versioning, WAL logging, and key events.
    pub(crate) fn zincrby_on_shard(
        &self,
        shard: &mut Shard,
        key: &[u8],
        member: &[u8],
        increment: f64,
        now: Instant,
    ) -> Result<f64, String> {
        let ks = key_bytes(key);
        let existed = shard.data.contains_key(&ks);
        let entry = shard.data.entry(ks).or_insert_with(|| Entry {
            value: StoreValue::SortedSet(BTreeMap::new(), HashMap::new()),
            expires_at: None,
            lru_clock: self.lru_clock(),
        });
        if !existed {
            self.key_added();
        }
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
        use std::ops::Bound::{Excluded, Included};
        if min > max {
            return Ok(0);
        }
        if min == max && (min_exclusive || max_exclusive) {
            return Ok(0);
        }
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::SortedSet(tree, scores) => {
                    // Common bench/query path: whole-score-space cardinality.
                    if min.is_infinite()
                        && min.is_sign_negative()
                        && max.is_infinite()
                        && max.is_sign_positive()
                    {
                        return Ok(scores.len() as i64);
                    }
                    let start_member = String::new();
                    let end_member = "\u{10ffff}\u{10ffff}".to_string();
                    let start = if min_exclusive {
                        Excluded((OrderedFloat(min), end_member.clone()))
                    } else {
                        Included((OrderedFloat(min), start_member))
                    };
                    let end = if max_exclusive {
                        Excluded((OrderedFloat(max), String::new()))
                    } else {
                        Included((OrderedFloat(max), end_member))
                    };
                    let count = tree.range((start, end)).count();
                    Ok(count as i64)
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(0),
        }
    }

    pub fn zvisit_all_scores<F>(&self, key: &[u8], now: Instant, mut visit: F) -> Result<(), String>
    where
        F: FnMut(&str, f64),
    {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::SortedSet(tree, _) => {
                    for (score, member) in tree.keys() {
                        visit(member, score.0);
                    }
                    Ok(())
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(()),
        }
    }

    pub fn zvisit_scores_inclusive<F>(
        &self,
        key: &[u8],
        min: f64,
        max: f64,
        now: Instant,
        mut visit: F,
    ) -> Result<(), String>
    where
        F: FnMut(&str, f64),
    {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::SortedSet(tree, _) => {
                    let start = (OrderedFloat(min), String::new());
                    let end = (OrderedFloat(max), "\u{10ffff}\u{10ffff}".to_string());
                    for ((score, member), _) in tree.range(start..=end) {
                        visit(member, score.0);
                    }
                    Ok(())
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(()),
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
        match shard.data.get_mut(key) {
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
                    self.mem_sub(freed);
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
        match shard.data.get_mut(key) {
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
                    self.mem_sub(freed);
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
        match shard.data.get(key) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::SortedSet(_, scores) => Ok(scores.clone()),
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(HashMap::new()),
        }
    }

    /// Random members (with scores). Positive count returns up to `count`
    /// distinct members; negative count returns `|count|` members with repeats.
    /// Selection follows sorted-set order (mirrors the deterministic SRANDMEMBER).
    pub fn zrandmember(
        &self,
        key: &[u8],
        count: i64,
        now: Instant,
    ) -> Result<Vec<(String, f64)>, String> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        match shard.data.get(key) {
            Some(entry) if !entry.is_expired_at(now) => match &entry.value {
                StoreValue::SortedSet(tree, _scores) => {
                    if count == 0 || tree.is_empty() {
                        return Ok(vec![]);
                    }
                    let members: Vec<(String, f64)> =
                        tree.keys().map(|(s, m)| (m.clone(), s.0)).collect();
                    let abs = count.unsigned_abs() as usize;
                    if count > 0 {
                        Ok(members.into_iter().take(abs).collect())
                    } else {
                        Ok(members.iter().cloned().cycle().take(abs).collect())
                    }
                }
                _ => Err(WRONGTYPE.to_string()),
            },
            _ => Ok(vec![]),
        }
    }

    /// Weighted union of the sorted sets, as a member->score map.
    fn zunion_compute(
        &self,
        keys: &[&[u8]],
        weights: &[f64],
        aggregate: &str,
        now: Instant,
    ) -> Result<HashMap<String, f64>, String> {
        let mut result: HashMap<String, f64> = HashMap::new();
        for (i, key) in keys.iter().enumerate() {
            let w = weights.get(i).copied().unwrap_or(1.0);
            let set = self.collect_sorted_set(key, now)?;
            for (member, score) in set {
                let weighted = score * w;
                // First occurrence seeds the value; only then does aggregate
                // combine. (The old code seeded with 0.0, which broke MIN/MAX.)
                if let Some(cur) = result.get_mut(&member) {
                    match aggregate {
                        "MIN" => *cur = cur.min(weighted),
                        "MAX" => *cur = cur.max(weighted),
                        _ => *cur += weighted,
                    }
                } else {
                    result.insert(member, weighted);
                }
            }
        }
        Ok(result)
    }

    /// Weighted intersection of the sorted sets, as a member->score map.
    fn zinter_compute(
        &self,
        keys: &[&[u8]],
        weights: &[f64],
        aggregate: &str,
        now: Instant,
    ) -> Result<HashMap<String, f64>, String> {
        if keys.is_empty() {
            return Ok(HashMap::new());
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
        Ok(result)
    }

    /// Difference of the first sorted set minus the rest, as a member->score map.
    fn zdiff_compute(&self, keys: &[&[u8]], now: Instant) -> Result<HashMap<String, f64>, String> {
        if keys.is_empty() {
            return Ok(HashMap::new());
        }
        let mut result = self.collect_sorted_set(keys[0], now)?;
        for key in &keys[1..] {
            let set = self.collect_sorted_set(key, now)?;
            result.retain(|m, _| !set.contains_key(m));
        }
        Ok(result)
    }

    /// Delete `dst` and store `result` as a sorted set; returns the member count.
    fn write_computed_zset(&self, dst: &[u8], result: HashMap<String, f64>) -> Result<i64, String> {
        let count = result.len() as i64;
        self.del(&[dst]);
        let wal = self.wal_enabled();

        if result.is_empty() {
            // Self-log the clear so replay drops any prior dst on dst's own shard.
            if wal {
                self.wal_log_command(&[b"DEL", dst])
                    .map_err(|e| format!("ERR WAL append failed: {e}"))?;
            }
            return Ok(count);
        }

        let idx = self.shard_index(dst);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        let mut tree = BTreeMap::new();
        let mut scores = HashMap::new();
        let mut mem = key_str(dst).len() + 64;
        // Captured for the self-logged ZADD below (only when WAL is on).
        let mut members: Vec<String> = if wal {
            Vec::with_capacity(result.len())
        } else {
            Vec::new()
        };
        let mut score_strs: Vec<String> = if wal {
            Vec::with_capacity(result.len())
        } else {
            Vec::new()
        };
        for (member, score) in result {
            mem += member.len() + 48;
            tree.insert((OrderedFloat(score), member.clone()), ());
            if wal {
                score_strs.push(score.to_string());
                members.push(member.clone());
            }
            scores.insert(member, score);
        }
        let old = shard.data.insert(
            key_bytes(dst),
            Entry {
                value: StoreValue::SortedSet(tree, scores),
                expires_at: None,
                lru_clock: self.lru_clock(),
            },
        );
        if old.is_none() {
            self.key_added();
        }
        shard.used_memory += mem;
        self.mem_add(mem);
        drop(shard);

        // Self-log the resolved effect keyed on dst (DEL + ZADD). The raw *STORE
        // command reads source keys that may live on other WAL shards, so per-
        // shard replay could apply it before the sources are restored. Logging
        // DEL+ZADD to dst's own shard makes replay independent of source order.
        // (The raw command is skipped in execute_with_wal via command_self_logs_wal.)
        if wal {
            self.wal_log_command(&[b"DEL", dst])
                .map_err(|e| format!("ERR WAL append failed: {e}"))?;
            let mut zadd: Vec<&[u8]> = Vec::with_capacity(members.len() * 2 + 2);
            zadd.push(b"ZADD");
            zadd.push(dst);
            for (s, m) in score_strs.iter().zip(members.iter()) {
                zadd.push(s.as_bytes());
                zadd.push(m.as_bytes());
            }
            self.wal_log_command(&zadd)
                .map_err(|e| format!("ERR WAL append failed: {e}"))?;
        }
        Ok(count)
    }

    /// Sort a member->score map into Redis order: by score ascending, ties by
    /// member lexicographically.
    fn sorted_zset_result(result: HashMap<String, f64>) -> Vec<(String, f64)> {
        let mut v: Vec<(String, f64)> = result.into_iter().collect();
        v.sort_by(|a, b| {
            a.1.partial_cmp(&b.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });
        v
    }

    pub fn zunionstore(
        &self,
        dst: &[u8],
        keys: &[&[u8]],
        weights: &[f64],
        aggregate: &str,
        now: Instant,
    ) -> Result<i64, String> {
        let result = self.zunion_compute(keys, weights, aggregate, now)?;
        self.write_computed_zset(dst, result)
    }

    /// ZMPOP/BZMPOP core: pop up to `count` MIN- or MAX-scored members from the
    /// first non-empty sorted set among `keys`. Returns the popped key and the
    /// (member, score) pairs, or None when every key is missing/empty. WRONGTYPE
    /// propagates from the first non-zset key scanned.
    #[allow(clippy::type_complexity)]
    pub fn zmpop(
        &self,
        keys: &[&[u8]],
        pop_min: bool,
        count: usize,
        now: Instant,
    ) -> Result<Option<(Vec<u8>, Vec<(String, f64)>)>, String> {
        for key in keys {
            self.try_promote(key, now);
            let popped = if pop_min {
                self.zpopmin(key, count, now)
            } else {
                self.zpopmax(key, count, now)
            };
            match popped {
                Ok(items) if !items.is_empty() => return Ok(Some((key.to_vec(), items))),
                Ok(_) => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(None)
    }

    /// ZRANGESTORE: store already-resolved (member, score) pairs into `dst` as a
    /// sorted set, replacing any prior value. Reuses `write_computed_zset`, which
    /// self-logs a keyed DEL+ZADD so a sharded WAL replays it on dst's own shard
    /// (the raw command reads a src key that may live on another shard).
    pub fn zrangestore(&self, dst: &[u8], pairs: Vec<(String, f64)>) -> Result<i64, String> {
        let map: HashMap<String, f64> = pairs.into_iter().collect();
        self.write_computed_zset(dst, map)
    }

    pub fn zinterstore(
        &self,
        dst: &[u8],
        keys: &[&[u8]],
        weights: &[f64],
        aggregate: &str,
        now: Instant,
    ) -> Result<i64, String> {
        let result = self.zinter_compute(keys, weights, aggregate, now)?;
        self.write_computed_zset(dst, result)
    }

    pub fn zdiffstore(&self, dst: &[u8], keys: &[&[u8]], now: Instant) -> Result<i64, String> {
        let result = self.zdiff_compute(keys, now)?;
        self.write_computed_zset(dst, result)
    }

    /// Direct-return union (sorted). WITHSCORES is applied at the command layer.
    pub fn zunion(
        &self,
        keys: &[&[u8]],
        weights: &[f64],
        aggregate: &str,
        now: Instant,
    ) -> Result<Vec<(String, f64)>, String> {
        Ok(Self::sorted_zset_result(
            self.zunion_compute(keys, weights, aggregate, now)?,
        ))
    }

    /// Direct-return intersection (sorted).
    pub fn zinter(
        &self,
        keys: &[&[u8]],
        weights: &[f64],
        aggregate: &str,
        now: Instant,
    ) -> Result<Vec<(String, f64)>, String> {
        Ok(Self::sorted_zset_result(
            self.zinter_compute(keys, weights, aggregate, now)?,
        ))
    }

    /// Direct-return difference (sorted).
    pub fn zdiff(&self, keys: &[&[u8]], now: Instant) -> Result<Vec<(String, f64)>, String> {
        Ok(Self::sorted_zset_result(self.zdiff_compute(keys, now)?))
    }

    /// Cardinality of the intersection. `limit` of 0 means no limit.
    pub fn zintercard(&self, keys: &[&[u8]], limit: usize, now: Instant) -> Result<i64, String> {
        let count = self.zinter_compute(keys, &[], "SUM", now)?.len();
        let count = if limit == 0 { count } else { count.min(limit) };
        Ok(count as i64)
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
        match shard.data.get(key) {
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
        match shard.data.get(key) {
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
}
