use super::{
    parse_table_row_key, parse_table_vector_key, store_value_to_dump_value, DumpEntry, DumpValue,
    Entry, Store,
};
use crate::cluster::transfer_record::{
    table_row_key, table_vector_key, TableVectorRecord, TransferRecord,
};
use crate::cluster::{ClusterError, TransferDataKey, TransferDescriptor};
use std::collections::HashSet;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

impl Store {
    pub(crate) fn clear_transfer_ranges(
        &self,
        descriptor: &TransferDescriptor,
    ) -> Result<u64, ClusterError> {
        descriptor.validate()?;
        let mut keys = HashSet::new();
        for shard in &self.shards {
            let shard = shard.read();
            for key in shard.data.keys() {
                if transfer_slot(key)?.is_some_and(|slot| descriptor.contains_slot(slot)) {
                    keys.insert(key.clone());
                }
            }
        }
        for entry in self.transfer_disk_entries(Instant::now())? {
            let key = entry.key.into_bytes();
            if transfer_slot(&key)?.is_some_and(|slot| descriptor.contains_slot(slot)) {
                keys.insert(key);
            }
        }
        let cleared = u64::try_from(keys.len()).map_err(|_| {
            ClusterError::InvalidTransfer("target clear count is exhausted".to_owned())
        })?;
        for key in keys {
            self.del(&[key.as_slice()]);
        }
        Ok(cleared)
    }

    pub(crate) fn transfer_identities_for_shard(
        &self,
        shard_index: usize,
        descriptor: &TransferDescriptor,
        now: Instant,
    ) -> Result<Vec<TransferDataKey>, ClusterError> {
        descriptor.validate()?;
        let Some(shard) = self.shards.get(shard_index) else {
            return invalid("transfer snapshot shard is out of range");
        };
        let shard = shard.read();
        let mut identities = HashSet::new();
        for (key, entry) in &shard.data {
            if entry.is_expired_at(now) {
                continue;
            }
            if let Some(identity) = transfer_identity(key)? {
                if descriptor.contains_slot(identity.slot()) {
                    identities.insert(identity);
                }
            }
        }
        let mut identities = identities.into_iter().collect::<Vec<_>>();
        identities.sort_unstable();
        Ok(identities)
    }

    pub(crate) fn transfer_disk_identities(
        &self,
        descriptor: &TransferDescriptor,
        now: Instant,
    ) -> Result<Vec<TransferDataKey>, ClusterError> {
        descriptor.validate()?;
        let mut identities = HashSet::new();
        for entry in self.transfer_disk_entries(now)? {
            if let Some(identity) = transfer_identity(entry.key.as_bytes())? {
                if descriptor.contains_slot(identity.slot()) {
                    identities.insert(identity);
                }
            }
        }
        let mut identities = identities.into_iter().collect::<Vec<_>>();
        identities.sort_unstable();
        Ok(identities)
    }

    pub(crate) fn transfer_record(
        &self,
        identity: &TransferDataKey,
        now: Instant,
    ) -> Result<TransferRecord, ClusterError> {
        match identity {
            TransferDataKey::Kv(key) => {
                if key.starts_with(b"_t:") {
                    return invalid("reserved table storage cannot transfer as a KV identity");
                }
                let Some((value, expires_at_ms)) = self.transfer_value(key, now)? else {
                    return Ok(TransferRecord::Delete(identity.clone()));
                };
                Ok(TransferRecord::UpsertKv {
                    key: key.clone(),
                    value,
                    expires_at_ms,
                })
            }
            TransferDataKey::TableRow { table, primary_key } => {
                let row_key = table_row_key(table, primary_key)?;
                let Some((value, expires_at_ms)) = self.transfer_value(&row_key, now)? else {
                    return Ok(TransferRecord::Delete(identity.clone()));
                };
                if !matches!(value, DumpValue::Hash(_, _)) {
                    return invalid("table-row storage is not a hash");
                }
                let mut vectors = self.transfer_table_vectors(table, primary_key, now)?;
                vectors.sort_unstable_by(|left, right| left.field.cmp(&right.field));
                Ok(TransferRecord::UpsertTableRow {
                    table: table.clone(),
                    primary_key: primary_key.clone(),
                    value,
                    expires_at_ms,
                    vectors,
                })
            }
        }
    }

    pub(crate) fn apply_transfer_record(&self, record: TransferRecord) -> Result<(), ClusterError> {
        record.validate()?;
        let now_ms = epoch_ms()?;
        match record {
            TransferRecord::Delete(TransferDataKey::Kv(key)) => {
                self.del(&[key.as_slice()]);
            }
            TransferRecord::Delete(TransferDataKey::TableRow { table, primary_key }) => {
                self.delete_table_transfer(&table, &primary_key)?;
            }
            TransferRecord::UpsertKv {
                key,
                value,
                expires_at_ms,
            } => {
                let Some(ttl) = remaining_ttl(expires_at_ms, now_ms) else {
                    self.del(&[key.as_slice()]);
                    return Ok(());
                };
                self.load_entry_bytes(key, value, ttl);
            }
            TransferRecord::UpsertTableRow {
                table,
                primary_key,
                value,
                expires_at_ms,
                vectors,
            } => {
                self.delete_table_transfer(&table, &primary_key)?;
                let Some(ttl) = remaining_ttl(expires_at_ms, now_ms) else {
                    return Ok(());
                };
                self.load_entry_bytes(table_row_key(&table, &primary_key)?, value, ttl);
                for vector in vectors {
                    let Some(ttl) = remaining_ttl(vector.expires_at_ms, now_ms) else {
                        continue;
                    };
                    self.load_entry_bytes(
                        table_vector_key(&table, &vector.field, &primary_key)?,
                        vector.value,
                        ttl,
                    );
                }
            }
        }
        Ok(())
    }

    fn transfer_value(
        &self,
        key: &[u8],
        now: Instant,
    ) -> Result<Option<(DumpValue, Option<i64>)>, ClusterError> {
        self.try_promote(key, now);
        let shard = self.shards[self.shard_index(key)].read();
        let Some(entry) = shard.data.get(key) else {
            return Ok(None);
        };
        transfer_entry(entry, now).map(Some)
    }

    fn transfer_table_vectors(
        &self,
        table: &str,
        primary_key: &[u8],
        now: Instant,
    ) -> Result<Vec<TableVectorRecord>, ClusterError> {
        let primary_key = std::str::from_utf8(primary_key).map_err(|_| {
            ClusterError::InvalidTransfer("table primary key is not UTF-8".to_owned())
        })?;
        let mut vectors = Vec::new();
        for shard in &self.shards {
            let shard = shard.read();
            for (key, entry) in &shard.data {
                let key_name = match std::str::from_utf8(key) {
                    Ok(key) => key,
                    Err(_) => continue,
                };
                let Some((candidate_table, field, candidate_primary_key)) =
                    parse_table_vector_key(key_name)
                else {
                    continue;
                };
                if candidate_table != table || candidate_primary_key != primary_key {
                    continue;
                }
                if entry.is_expired_at(now) {
                    continue;
                }
                let (value, expires_at_ms) = transfer_entry(entry, now)?;
                if !matches!(value, DumpValue::Vector(..)) {
                    return invalid("table vector sidecar storage is not a vector");
                }
                vectors.push(TableVectorRecord {
                    field: field.to_owned(),
                    value,
                    expires_at_ms,
                });
            }
        }
        Ok(vectors)
    }

    fn delete_table_transfer(&self, table: &str, primary_key: &[u8]) -> Result<(), ClusterError> {
        let primary_key_text = std::str::from_utf8(primary_key).map_err(|_| {
            ClusterError::InvalidTransfer("table primary key is not UTF-8".to_owned())
        })?;
        let mut keys = vec![table_row_key(table, primary_key)?];
        for shard in &self.shards {
            let shard = shard.read();
            for key in shard.data.keys() {
                let Ok(key_name) = std::str::from_utf8(key) else {
                    continue;
                };
                if parse_table_vector_key(key_name).is_some_and(
                    |(candidate_table, _, candidate_primary_key)| {
                        candidate_table == table && candidate_primary_key == primary_key_text
                    },
                ) {
                    keys.push(key.clone());
                }
            }
        }
        for entry in self.transfer_disk_entries(Instant::now())? {
            if parse_table_vector_key(&entry.key).is_some_and(
                |(candidate_table, _, candidate_primary_key)| {
                    candidate_table == table && candidate_primary_key == primary_key_text
                },
            ) {
                keys.push(entry.key.into_bytes());
            }
        }
        keys.sort_unstable();
        keys.dedup();
        for key in keys {
            self.del(&[key.as_slice()]);
        }
        Ok(())
    }

    fn transfer_disk_entries(&self, now: Instant) -> Result<Vec<DumpEntry>, ClusterError> {
        let Some(disk_shards) = &self.disk_shards else {
            return Ok(Vec::new());
        };
        let mut entries = Vec::new();
        for disk in disk_shards.iter() {
            entries.extend(disk.lock().dump_all(now)?);
        }
        Ok(entries)
    }
}

fn transfer_identity(key: &[u8]) -> Result<Option<TransferDataKey>, ClusterError> {
    if let Ok(key_name) = std::str::from_utf8(key) {
        if let Some((table, primary_key)) = parse_table_row_key(key_name) {
            return TransferDataKey::table_row(table, primary_key.as_bytes().to_vec()).map(Some);
        }
        if parse_table_vector_key(key_name).is_some() {
            return Ok(None);
        }
        if key_name.starts_with("_t:") {
            return Ok(None);
        }
    }
    TransferDataKey::kv(key.to_vec()).map(Some)
}

fn transfer_slot(key: &[u8]) -> Result<Option<u16>, ClusterError> {
    if let Ok(key_name) = std::str::from_utf8(key) {
        if let Some((table, primary_key)) = parse_table_row_key(key_name) {
            return TransferDataKey::table_row(table, primary_key.as_bytes().to_vec())
                .map(|identity| Some(identity.slot()));
        }
        if let Some((table, _, primary_key)) = parse_table_vector_key(key_name) {
            return TransferDataKey::table_row(table, primary_key.as_bytes().to_vec())
                .map(|identity| Some(identity.slot()));
        }
        if key_name.starts_with("_t:") {
            return Ok(None);
        }
    }
    TransferDataKey::kv(key.to_vec()).map(|identity| Some(identity.slot()))
}

fn transfer_entry(entry: &Entry, now: Instant) -> Result<(DumpValue, Option<i64>), ClusterError> {
    if entry.is_expired_at(now) {
        return invalid("expired entry cannot enter a transfer upsert");
    }
    let expires_at_ms = match entry.expires_at {
        Some(deadline) => {
            let remaining = deadline.saturating_duration_since(now);
            let remaining_ms = i64::try_from(remaining.as_millis()).map_err(|_| {
                ClusterError::InvalidTransfer("transfer TTL is too large".to_owned())
            })?;
            Some(epoch_ms()?.checked_add(remaining_ms).ok_or_else(|| {
                ClusterError::InvalidTransfer("transfer TTL deadline overflowed".to_owned())
            })?)
        }
        None => None,
    };
    Ok((store_value_to_dump_value(&entry.value), expires_at_ms))
}

fn remaining_ttl(deadline_ms: Option<i64>, now_ms: i64) -> Option<Option<Duration>> {
    match deadline_ms {
        None => Some(None),
        Some(deadline) if deadline > now_ms => {
            Some(Some(Duration::from_millis((deadline - now_ms) as u64)))
        }
        Some(_) => None,
    }
}

fn epoch_ms() -> Result<i64, ClusterError> {
    let milliseconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            ClusterError::InvalidTransfer(format!("system clock is before the Unix epoch: {error}"))
        })?
        .as_millis();
    i64::try_from(milliseconds)
        .map_err(|_| ClusterError::InvalidTransfer("system clock is out of range".to_owned()))
}

fn invalid<T>(message: impl Into<String>) -> Result<T, ClusterError> {
    Err(ClusterError::InvalidTransfer(message.into()))
}

#[cfg(test)]
#[path = "cluster_transfer_tests.rs"]
mod tests;
