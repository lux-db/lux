use super::*;

impl Store {
    #[allow(clippy::too_many_arguments)]
    pub fn vset(
        &self,
        key: &[u8],
        data: Vec<f32>,
        metadata: Option<String>,
        ttl: Option<Duration>,
        encrypted: bool,
        now: Instant,
    ) {
        let idx = self.shard_index(key);
        let mut shard = self.shards[idx].write();
        shard.version += 1;
        let ks = key_bytes(key);
        let index_key = key_string(key);
        let dims = data.len() as u32;
        let index_data = data.clone();
        let mut old_vector_dims = None;
        // Sticky encryption: overwriting an encrypted vector without the flag
        // must not silently downgrade it to plaintext-at-rest (mirrors SET).
        let encrypted = encrypted
            || matches!(
                shard.data.get(&ks).map(|e| &e.value),
                Some(StoreValue::Vector(v)) if v.encrypted
            );
        let new_value = StoreValue::Vector(VectorData {
            dims,
            data,
            metadata,
            encrypted,
        });
        let new_mem = estimate_entry_memory(&ks, &new_value);
        let expires_at = ttl.map(|d| now + d);
        let clock = self.lru_clock();
        if let Some(old) = shard.data.insert(
            ks.clone(),
            Entry {
                value: new_value,
                expires_at,
                lru_clock: clock,
            },
        ) {
            if let StoreValue::Vector(old_vector) = &old.value {
                old_vector_dims = Some(old_vector.dims);
            }
            let old_mem = estimate_entry_memory(&ks, &old.value);
            if new_mem >= old_mem {
                self.mem_add(new_mem - old_mem);
            } else {
                self.mem_sub(old_mem - new_mem);
            }
            shard.used_memory = shard.used_memory.saturating_sub(old_mem) + new_mem;
        } else {
            self.mem_add(new_mem);
            shard.used_memory += new_mem;
            self.key_added();
        }
        drop(shard);
        if let Some(old_dims) = old_vector_dims {
            self.remove_vector_indexes(&index_key, old_dims);
        }
        self.insert_vector_indexes(index_key, dims, index_data);
    }

    pub fn vget(&self, key: &[u8], now: Instant) -> Option<(Vec<f32>, Option<String>)> {
        let idx = self.shard_index(key);
        let shard = self.shards[idx].read();
        let ks = key;
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
        if has_filter {
            if filter_key == Some("table_field") {
                return self.vsearch_table_field_indexed(query, k, filter_value.unwrap(), now);
            }
            return self.vsearch_filtered_exact(
                query,
                k,
                filter_key.unwrap(),
                filter_value.unwrap(),
                now,
            );
        }
        let dims = query.len() as u32;
        let search_k = k.saturating_mul(4).max(k).max(32);
        let mut candidates = self
            .vector_indexes
            .read()
            .get(&dims)
            .map(|index| index.search(query, search_k))
            .unwrap_or_default();
        {
            let table_indexes = self.table_vector_indexes.read();
            for ((index_dims, _), index) in table_indexes.iter() {
                if *index_dims == dims {
                    candidates.extend(index.search(query, search_k));
                }
            }
        }
        candidates.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        let mut results: Vec<(String, f32, Option<String>)> = Vec::new();
        let mut seen = HashSet::new();
        for (key, sim) in candidates {
            if !seen.insert(key.clone()) {
                continue;
            }
            let idx = self.shard_index(key.as_bytes());
            let shard = self.shards[idx].read();
            if let Some(entry) = shard.data.get(key.as_bytes()) {
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

    fn vsearch_table_field_indexed(
        &self,
        query: &[f32],
        k: usize,
        table_field: &str,
        now: Instant,
    ) -> Vec<(String, f32, Option<String>)> {
        let dims = query.len() as u32;
        let search_k = k.saturating_mul(4).max(k).max(32);
        let candidates = self
            .table_vector_indexes
            .read()
            .get(&(dims, table_field.to_string()))
            .map(|index| index.search(query, search_k))
            .unwrap_or_default();

        let mut results = Vec::with_capacity(k);
        for (key, similarity) in candidates {
            let idx = self.shard_index(key.as_bytes());
            let shard = self.shards[idx].read();
            let Some(entry) = shard.data.get(key.as_bytes()) else {
                continue;
            };
            if entry.is_expired_at(now) {
                continue;
            }
            let StoreValue::Vector(vector) = &entry.value else {
                continue;
            };
            if vector.dims != dims {
                continue;
            }
            results.push((key, similarity, vector.metadata.clone()));
            if results.len() >= k {
                break;
            }
        }
        results
    }

    pub(crate) fn table_vector_search(
        &self,
        table: &str,
        field: &str,
        query: &[f32],
        k: usize,
        threshold: Option<f32>,
        now: Instant,
    ) -> Vec<(String, f32)> {
        let dims = query.len() as u32;
        let table_field = table_vector_index_name(table, field);
        let search_k = k.saturating_mul(4).max(k).max(32);
        let candidates = self
            .table_vector_indexes
            .read()
            .get(&(dims, table_field))
            .map(|index| index.search(query, search_k))
            .unwrap_or_default();

        let mut results = Vec::with_capacity(k);
        for (key, similarity) in candidates {
            if threshold.is_some_and(|min| similarity < min) {
                continue;
            }
            let Some((_, _, pk)) = parse_table_vector_key(&key) else {
                continue;
            };
            let idx = self.shard_index(key.as_bytes());
            let shard = self.shards[idx].read();
            let Some(entry) = shard.data.get(key.as_bytes()) else {
                continue;
            };
            if entry.is_expired_at(now) {
                continue;
            }
            let StoreValue::Vector(vector) = &entry.value else {
                continue;
            };
            if vector.dims != dims {
                continue;
            }
            results.push((pk.to_string(), similarity));
            if results.len() >= k {
                break;
            }
        }
        results
    }

    pub(crate) fn table_vector_search_candidates(
        &self,
        search: TableVectorCandidateQuery<'_>,
    ) -> Vec<(String, f32)> {
        let TableVectorCandidateQuery {
            table,
            field,
            query,
            candidate_pks,
            k,
            threshold,
            now,
        } = search;
        let query_norm = vector_norm(query);
        if query_norm == 0.0 || candidate_pks.is_empty() {
            return Vec::new();
        }

        let mut results = Vec::with_capacity(candidate_pks.len().min(k));
        for pk in candidate_pks {
            let key = table_vector_key_for_pk(table, field, pk);
            let idx = self.shard_index(key.as_bytes());
            let shard = self.shards[idx].read();
            let Some(entry) = shard.data.get(key.as_bytes()) else {
                continue;
            };
            if entry.is_expired_at(now) {
                continue;
            }
            let StoreValue::Vector(vector) = &entry.value else {
                continue;
            };
            if vector.dims as usize != query.len() {
                continue;
            }
            let similarity = cosine_similarity(query, query_norm, &vector.data);
            if threshold.is_some_and(|min| similarity < min) {
                continue;
            }
            results.push((pk.clone(), similarity));
        }

        results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        results.truncate(k);
        results
    }

    fn vsearch_filtered_exact(
        &self,
        query: &[f32],
        k: usize,
        filter_key: &str,
        filter_value: &str,
        now: Instant,
    ) -> Vec<(String, f32, Option<String>)> {
        let query_norm = vector_norm(query);
        if query_norm == 0.0 {
            return Vec::new();
        }

        let mut results = Vec::new();
        for shard_lock in self.shards.iter() {
            let shard = shard_lock.read();
            for (key, entry) in &shard.data {
                if entry.is_expired_at(now) {
                    continue;
                }
                let StoreValue::Vector(vector) = &entry.value else {
                    continue;
                };
                if vector.dims as usize != query.len() {
                    continue;
                }
                let Some(metadata) = &vector.metadata else {
                    continue;
                };
                if !metadata_field_matches(metadata, filter_key, filter_value) {
                    continue;
                }
                let score = cosine_similarity(query, query_norm, &vector.data);
                results.push((key_string(key), score, vector.metadata.clone()));
            }
        }

        results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        results.truncate(k);
        results
    }

    pub fn vcard(&self, _now: Instant) -> usize {
        let raw_count: usize = self
            .vector_indexes
            .read()
            .values()
            .map(crate::hnsw::HnswIndex::len)
            .sum();
        let table_count: usize = self
            .table_vector_indexes
            .read()
            .values()
            .map(crate::hnsw::HnswIndex::len)
            .sum();
        raw_count + table_count
    }
}

fn vector_norm(vector: &[f32]) -> f32 {
    vector.iter().map(|value| value * value).sum::<f32>().sqrt()
}

fn cosine_similarity(query: &[f32], query_norm: f32, vector: &[f32]) -> f32 {
    if query.len() != vector.len() {
        return 0.0;
    }
    let vector_norm = vector_norm(vector);
    if vector_norm == 0.0 {
        return 0.0;
    }
    let dot = query
        .iter()
        .zip(vector.iter())
        .map(|(left, right)| left * right)
        .sum::<f32>();
    dot / (query_norm * vector_norm)
}

fn metadata_field_matches(metadata: &str, field: &str, expected: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(metadata)
        .ok()
        .and_then(|value| {
            value
                .get(field)
                .and_then(|field| field.as_str())
                .map(str::to_owned)
        })
        .as_deref()
        == Some(expected)
}
