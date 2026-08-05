use super::{
    parse_table_row_key, parse_table_vector_key, store_value_to_dump_value, DumpEntry, DumpValue,
    Entry, Store,
};
use crate::cluster::transfer_record::{
    table_row_key, table_vector_key, TableVectorRecord, TransferRecord,
};
use crate::cluster::{ClusterError, CompiledExecution, TransferDataKey, TransferDescriptor};
use crate::tables::{
    decode_field_def, table_install_transfer_metadata, table_prepare_transfer_row,
    table_remove_transfer_row, table_transfer_order_score, table_validate_transfer_conflicts,
    FieldType,
};
use std::collections::HashSet;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

impl Store {
    pub(crate) fn clear_transfer_ranges(
        &self,
        descriptor: &TransferDescriptor,
        execution: &CompiledExecution,
    ) -> Result<u64, ClusterError> {
        descriptor.validate()?;
        if execution.manifest().cluster_id != descriptor.cluster_id {
            return invalid("target execution metadata belongs to another cluster");
        }
        let mut identities = HashSet::new();
        for shard in &self.shards {
            let shard = shard.read();
            for key in shard.data.keys() {
                if let Some(identity) = target_transfer_identity(key)? {
                    if descriptor.contains_slot(identity.slot()) {
                        identities.insert(identity);
                    }
                }
            }
        }
        for entry in self.transfer_disk_entries(Instant::now())? {
            if let Some(identity) = target_transfer_identity(entry.key.as_bytes())? {
                if descriptor.contains_slot(identity.slot()) {
                    identities.insert(identity);
                }
            }
        }
        let cleared = u64::try_from(identities.len()).map_err(|_| {
            ClusterError::InvalidTransfer("target clear count is exhausted".to_owned())
        })?;
        let now = Instant::now();
        for identity in identities {
            match identity {
                TransferDataKey::Kv(key) => {
                    self.del(&[key.as_slice()]);
                }
                TransferDataKey::TableRow { table, primary_key } => {
                    let table_metadata = execution.table(&table).ok_or_else(|| {
                        ClusterError::InvalidTransfer(
                            "target row is absent from signed execution metadata".to_owned(),
                        )
                    })?;
                    let primary_key = std::str::from_utf8(&primary_key).map_err(|_| {
                        ClusterError::InvalidTransfer("table primary key is not UTF-8".to_owned())
                    })?;
                    table_remove_transfer_row(self, table_metadata, primary_key, now)
                        .map_err(table_error)?;
                    self.delete_table_transfer_sidecars(&table, primary_key)?;
                }
            }
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
                let DumpValue::Hash(pairs, _) = &value else {
                    return invalid("table-row storage is not a hash");
                };
                if table_row_deadline_expired(&value, epoch_ms()?)? {
                    return Ok(TransferRecord::Delete(identity.clone()));
                }
                let mut vectors = self.transfer_table_vectors(table, primary_key, now)?;
                let live_fields = pairs
                    .iter()
                    .map(|(field, _)| field.as_str())
                    .collect::<HashSet<_>>();
                vectors.retain(|vector| live_fields.contains(vector.field.as_str()));
                vectors.sort_unstable_by(|left, right| left.field.cmp(&right.field));
                let primary_key_text = std::str::from_utf8(primary_key).map_err(|_| {
                    ClusterError::InvalidTransfer("table primary key is not UTF-8".to_owned())
                })?;
                let order_score = table_transfer_order_score(self, table, primary_key_text, now)
                    .map_err(table_error)?;
                Ok(TransferRecord::UpsertTableRow {
                    table: table.clone(),
                    primary_key: primary_key.clone(),
                    order_score,
                    value,
                    expires_at_ms,
                    vectors,
                })
            }
        }
    }

    pub(crate) fn apply_transfer_record(
        &self,
        record: TransferRecord,
        execution: &CompiledExecution,
    ) -> Result<(), ClusterError> {
        record.validate()?;
        let now_ms = epoch_ms()?;
        let now = Instant::now();
        match record {
            TransferRecord::Delete(TransferDataKey::Kv(key)) => {
                self.del(&[key.as_slice()]);
            }
            TransferRecord::Delete(TransferDataKey::TableRow { table, primary_key }) => {
                let table_metadata = execution.table(&table).ok_or_else(|| {
                    ClusterError::InvalidTransfer(
                        "deleted table row is absent from signed execution metadata".to_owned(),
                    )
                })?;
                let primary_key = std::str::from_utf8(&primary_key).map_err(|_| {
                    ClusterError::InvalidTransfer("table primary key is not UTF-8".to_owned())
                })?;
                table_remove_transfer_row(self, table_metadata, primary_key, now)
                    .map_err(table_error)?;
                self.delete_table_transfer_sidecars(&table, primary_key)?;
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
                order_score,
                value,
                expires_at_ms,
                vectors,
            } => {
                let table_metadata = execution.table(&table).ok_or_else(|| {
                    ClusterError::InvalidTransfer(
                        "upserted table row is absent from signed execution metadata".to_owned(),
                    )
                })?;
                let primary_key_text = std::str::from_utf8(&primary_key).map_err(|_| {
                    ClusterError::InvalidTransfer("table primary key is not UTF-8".to_owned())
                })?;
                let Some(row_ttl) = remaining_ttl(expires_at_ms, now_ms) else {
                    table_remove_transfer_row(self, table_metadata, primary_key_text, now)
                        .map_err(table_error)?;
                    self.delete_table_transfer_sidecars(&table, primary_key_text)?;
                    return Ok(());
                };
                let DumpValue::Hash(mut raw_pairs, mut field_expiries) = value else {
                    return invalid("table-row transfer value must be a hash");
                };
                remove_expired_hash_fields(&mut raw_pairs, &mut field_expiries, now_ms)?;
                if table_row_deadline_expired(
                    &DumpValue::Hash(raw_pairs.clone(), field_expiries.clone()),
                    now_ms,
                )? {
                    table_remove_transfer_row(self, table_metadata, primary_key_text, now)
                        .map_err(table_error)?;
                    self.delete_table_transfer_sidecars(&table, primary_key_text)?;
                    return Ok(());
                }
                let metadata =
                    table_prepare_transfer_row(self, table_metadata, primary_key_text, &raw_pairs)
                        .map_err(table_error)?;
                table_validate_transfer_conflicts(
                    self,
                    table_metadata,
                    primary_key_text,
                    &metadata,
                    now,
                )
                .map_err(table_error)?;

                let mut vector_fields = HashSet::with_capacity(vectors.len());
                let mut vector_loads = Vec::with_capacity(vectors.len());
                for vector in vectors {
                    let field = table_metadata
                        .fields
                        .iter()
                        .find(|field| field.name == vector.field)
                        .ok_or_else(|| {
                            ClusterError::InvalidTransfer(
                                "table vector field is absent from signed execution metadata"
                                    .to_owned(),
                            )
                        })?;
                    let definition = decode_field_def(&field.name, &field.definition);
                    let FieldType::Vector(dimensions) = definition.field_type else {
                        return invalid("table vector sidecar belongs to a non-vector field");
                    };
                    let DumpValue::Vector(values, _, _) = &vector.value else {
                        return invalid("table vector sidecar must contain a vector");
                    };
                    if values.len() != dimensions
                        || !raw_pairs.iter().any(|(name, _)| name == &vector.field)
                    {
                        return invalid(
                            "table vector sidecar does not match its signed row projection",
                        );
                    }
                    if !vector_fields.insert(vector.field.clone()) {
                        return invalid("table row contains duplicate vector sidecars");
                    }
                    let Some(vector_ttl) = remaining_ttl(vector.expires_at_ms, now_ms) else {
                        return invalid("table vector sidecar expired during transfer");
                    };
                    vector_loads.push((vector.field, vector.value, vector_ttl));
                }
                for field in &table_metadata.fields {
                    let definition = decode_field_def(&field.name, &field.definition);
                    if matches!(definition.field_type, FieldType::Vector(_))
                        && raw_pairs.iter().any(|(name, _)| name == &field.name)
                        && !vector_fields.contains(&field.name)
                    {
                        return invalid("table vector field is missing its canonical sidecar");
                    }
                }

                table_remove_transfer_row(self, table_metadata, primary_key_text, now)
                    .map_err(table_error)?;
                self.delete_table_transfer_sidecars(&table, primary_key_text)?;
                table_install_transfer_metadata(
                    self,
                    table_metadata,
                    primary_key_text,
                    order_score,
                    &metadata,
                    now,
                )
                .map_err(table_error)?;
                for (field, value, ttl) in vector_loads {
                    self.load_entry_bytes(
                        table_vector_key(&table, &field, &primary_key)?,
                        value,
                        ttl,
                    );
                }
                self.load_entry_bytes(
                    table_row_key(&table, &primary_key)?,
                    DumpValue::Hash(raw_pairs, field_expiries),
                    row_ttl,
                );
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

    fn delete_table_transfer_sidecars(
        &self,
        table: &str,
        primary_key: &str,
    ) -> Result<(), ClusterError> {
        let mut keys = Vec::new();
        for shard in &self.shards {
            let shard = shard.read();
            for key in shard.data.keys() {
                let Ok(key_name) = std::str::from_utf8(key) else {
                    continue;
                };
                if parse_table_vector_key(key_name).is_some_and(
                    |(candidate_table, _, candidate_primary_key)| {
                        candidate_table == table && candidate_primary_key == primary_key
                    },
                ) {
                    keys.push(key.clone());
                }
            }
        }
        for entry in self.transfer_disk_entries(Instant::now())? {
            if parse_table_vector_key(&entry.key).is_some_and(
                |(candidate_table, _, candidate_primary_key)| {
                    candidate_table == table && candidate_primary_key == primary_key
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

fn target_transfer_identity(key: &[u8]) -> Result<Option<TransferDataKey>, ClusterError> {
    if let Ok(key_name) = std::str::from_utf8(key) {
        if let Some((table, _, primary_key)) = parse_table_vector_key(key_name) {
            return TransferDataKey::table_row(table, primary_key.as_bytes().to_vec()).map(Some);
        }
    }
    transfer_identity(key)
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
    let mut value = store_value_to_dump_value(&entry.value);
    if let DumpValue::Hash(pairs, expiries) = &mut value {
        remove_expired_hash_fields(pairs, expiries, epoch_ms()?)?;
    }
    Ok((value, expires_at_ms))
}

fn remove_expired_hash_fields(
    pairs: &mut Vec<(String, Vec<u8>)>,
    expiries: &mut Vec<(String, i64)>,
    now_ms: i64,
) -> Result<(), ClusterError> {
    let mut expired = HashSet::new();
    for (field, deadline) in expiries.iter() {
        if *deadline <= 0 {
            return invalid("hash field expiry deadline is invalid");
        }
        if *deadline <= now_ms {
            expired.insert(field.as_str());
        }
    }
    pairs.retain(|(field, _)| !expired.contains(field.as_str()));
    expiries.retain(|(_, deadline)| *deadline > now_ms);
    Ok(())
}

fn table_row_deadline_expired(value: &DumpValue, now_ms: i64) -> Result<bool, ClusterError> {
    let DumpValue::Hash(pairs, _) = value else {
        return invalid("table-row transfer value must be a hash");
    };
    let Some((_, deadline)) = pairs.iter().find(|(field, _)| field.as_bytes() == b"\0ttl") else {
        return Ok(false);
    };
    let deadline = std::str::from_utf8(deadline)
        .ok()
        .and_then(|deadline| deadline.parse::<u64>().ok())
        .filter(|deadline| *deadline > 0)
        .ok_or_else(|| {
            ClusterError::InvalidTransfer("table row TTL deadline is invalid".to_owned())
        })?;
    let now_ms = u64::try_from(now_ms).map_err(|_| {
        ClusterError::InvalidTransfer("system clock is before the Unix epoch".to_owned())
    })?;
    Ok(deadline <= now_ms)
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

fn table_error(message: String) -> ClusterError {
    ClusterError::InvalidTransfer(message)
}

#[cfg(test)]
#[path = "cluster_transfer_tests.rs"]
mod tests;
