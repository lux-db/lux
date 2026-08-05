use super::*;
use crate::cluster::ExecutionTable;

/// Metadata derived only from a signed execution-table projection and the raw
/// row bytes being transferred. Building this plan is side-effect free so a
/// malformed row cannot partially disturb the target's aggregate indexes.
pub(crate) struct TransferRowMetadata {
    fields: Vec<(FieldDef, String)>,
    paths: Vec<(FieldDef, String)>,
    unique_values: hashbrown::HashMap<String, Vec<String>>,
    ttl_deadline_ms: Option<u64>,
}

pub(crate) fn table_transfer_order_score(
    store: &Store,
    table: &str,
    primary_key: &str,
    now: Instant,
) -> Result<f64, String> {
    let score = store
        .zscore(ids_key(table).as_bytes(), primary_key.as_bytes(), now)?
        .ok_or_else(|| {
            format!(
                "ERR row '{}' in table '{}' is absent from the ordering index",
                primary_key, table
            )
        })?;
    if !score.is_finite() {
        return Err(format!(
            "ERR row '{}' in table '{}' has a non-finite ordering score",
            primary_key, table
        ));
    }
    Ok(score)
}

pub(crate) fn table_prepare_transfer_row(
    store: &Store,
    table: &ExecutionTable,
    primary_key: &str,
    raw_pairs: &[(String, Vec<u8>)],
) -> Result<TransferRowMetadata, String> {
    let schema = execution_table_schema(table)?;
    let raw = raw_pairs
        .iter()
        .map(|(field, value)| (field.as_str(), value.as_slice()))
        .collect::<hashbrown::HashMap<_, _>>();
    if raw.len() != raw_pairs.len() {
        return Err("ERR transferred table row contains duplicate fields".to_owned());
    }

    for field in raw.keys() {
        if field.as_bytes() == HIDDEN_TTL_FIELD
            || (table.primary_key.is_none() && *field == "id")
            || schema.iter().any(|definition| definition.name == *field)
        {
            continue;
        }
        return Err(format!(
            "ERR transferred row for table '{}' contains unknown field '{}'",
            table.name, field
        ));
    }

    let projected_primary_key = table.primary_key.as_deref().unwrap_or("id");
    let raw_primary_key = raw.get(projected_primary_key).ok_or_else(|| {
        format!(
            "ERR transferred row for table '{}' is missing primary key '{}'",
            table.name, projected_primary_key
        )
    })?;
    let decoded_primary_key = match schema
        .iter()
        .find(|field| field.name == projected_primary_key)
    {
        Some(field) => {
            decode_stored_value(store, &table.name, field, primary_key, raw_primary_key)?
        }
        None => String::from_utf8(raw_primary_key.to_vec())
            .map_err(|_| "ERR implicit table primary key is not UTF-8".to_owned())?,
    };
    if decoded_primary_key != primary_key {
        return Err(format!(
            "ERR transferred row identity does not match table '{}' primary key",
            table.name
        ));
    }

    let mut fields = Vec::new();
    let mut unique_values = hashbrown::HashMap::new();
    for definition in &schema {
        let Some(value) = raw.get(definition.name.as_str()) else {
            continue;
        };
        let decoded = decode_stored_value(store, &table.name, definition, primary_key, value)?;
        if definition.encrypted && definition.searchable || definition.unique {
            unique_values.insert(
                definition.name.clone(),
                searchable_index_values(store, &table.name, definition, &decoded)?,
            );
        }
        fields.push((definition.clone(), decoded));
    }

    let mut paths = Vec::new();
    for path in execution_path_indexes(table)? {
        let Some((root, rest)) = path.path.split_once('.') else {
            return Err("ERR signed path index is not a dot path".to_owned());
        };
        let Some(root_field) = schema.iter().find(|field| field.name == root) else {
            return Err("ERR signed path index root is absent from the schema".to_owned());
        };
        let Some(raw_root) = raw.get(root) else {
            continue;
        };
        let bytes = stored_plain_bytes(store, &table.name, root_field, primary_key, raw_root)?;
        if let Some(value) = extract_json_scalar(&root_field.field_type.decode_value(&bytes), rest)
        {
            paths.push((synthetic_path_fielddef(&path), value));
        }
    }

    let ttl_deadline_ms = match raw.get(std::str::from_utf8(HIDDEN_TTL_FIELD).unwrap_or("")) {
        Some(value) => {
            let deadline = std::str::from_utf8(value)
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|deadline| *deadline > 0)
                .ok_or_else(|| "ERR transferred row TTL deadline is invalid".to_owned())?;
            Some(deadline)
        }
        None => None,
    };

    Ok(TransferRowMetadata {
        fields,
        paths,
        unique_values,
        ttl_deadline_ms,
    })
}

pub(crate) fn table_validate_transfer_conflicts(
    store: &Store,
    table: &ExecutionTable,
    primary_key: &str,
    metadata: &TransferRowMetadata,
    now: Instant,
) -> Result<(), String> {
    for (field, value) in &metadata.fields {
        if !field.unique {
            continue;
        }
        let Some(index_values) = metadata.unique_values.get(&field.name) else {
            return Err("ERR transferred unique field has no canonical index value".to_owned());
        };
        let unique_key = uniq_key(&table.name, &field.name);
        for index_value in index_values {
            let Some(holder) = store.hget(unique_key.as_bytes(), index_value.as_bytes(), now)
            else {
                continue;
            };
            let holder = String::from_utf8_lossy(&holder);
            if holder != primary_key
                && uniq_holder_holds_value(store, &table.name, field, holder.as_ref(), value, now)
            {
                return Err(format!(
                    "ERR transferred row conflicts with table '{}' unique field '{}'",
                    table.name, field.name
                ));
            }
        }
    }
    Ok(())
}

/// Remove one row's node-local reachability metadata without applying foreign
/// key actions, logging a client WAL command, or emitting a live-query event.
/// Ownership transfer replays an authoritative range and must not mutate rows
/// outside that range as a side effect.
pub(crate) fn table_remove_transfer_row(
    store: &Store,
    table: &ExecutionTable,
    primary_key: &str,
    now: Instant,
) -> Result<bool, String> {
    let row_key = row_key_for_pk(&table.name, primary_key);
    let raw_pairs = store
        .hgetall(row_key.as_bytes(), now)?
        .into_iter()
        .map(|(field, value)| (field, value.to_vec()))
        .collect::<Vec<_>>();
    let metadata = if raw_pairs.is_empty() {
        None
    } else {
        Some(table_prepare_transfer_row(
            store,
            table,
            primary_key,
            &raw_pairs,
        )?)
    };

    if let Some(metadata) = &metadata {
        for (field, value) in &metadata.fields {
            remove_from_index(store, &table.name, field, value, primary_key, now);
            if field.unique {
                let unique_key = uniq_key(&table.name, &field.name);
                if let Some(index_values) = metadata.unique_values.get(&field.name) {
                    for index_value in index_values {
                        if store
                            .hget(unique_key.as_bytes(), index_value.as_bytes(), now)
                            .is_some_and(|holder| holder.as_ref() == primary_key.as_bytes())
                        {
                            let _ =
                                store.hdel(unique_key.as_bytes(), &[index_value.as_bytes()], now);
                        }
                    }
                }
            }
        }
        for (field, value) in &metadata.paths {
            remove_from_index(store, &table.name, field, value, primary_key, now);
        }
    }

    for field in execution_table_schema(table)? {
        if matches!(field.field_type, FieldType::Vector(_)) {
            store.del(&[table_vector_key(&table.name, &field.name, primary_key).as_bytes()]);
        }
    }
    let _ = store.zrem(
        ids_key(&table.name).as_bytes(),
        &[primary_key.as_bytes()],
        now,
    );
    clear_row_ttl(store, &table.name, primary_key, now);
    store.del(&[row_key.as_bytes()]);
    Ok(metadata.is_some())
}

/// Install aggregate metadata before the caller commits the row hash. Readers
/// validate candidates against that hash, so a failure leaves only invisible
/// orphan entries and the sealed transfer can be replayed safely.
pub(crate) fn table_install_transfer_metadata(
    store: &Store,
    table: &ExecutionTable,
    primary_key: &str,
    order_score: f64,
    metadata: &TransferRowMetadata,
    now: Instant,
) -> Result<(), String> {
    if !order_score.is_finite() {
        return Err("ERR transferred row ordering score is not finite".to_owned());
    }
    store.zadd(
        ids_key(&table.name).as_bytes(),
        &[(primary_key.as_bytes(), order_score)],
        false,
        false,
        false,
        false,
        false,
        now,
    )?;

    let schema = execution_table_schema(table)?;
    if schema
        .iter()
        .find(|field| field.primary_key)
        .is_some_and(|field| field.field_type == FieldType::Int)
        || (table.primary_key.is_none() && primary_key.parse::<i64>().is_ok())
    {
        if let Ok(identifier) = primary_key.parse::<i64>() {
            bump_seq_to_at_least(store, &table.name, identifier, now);
        }
    }

    for (field, value) in &metadata.fields {
        if !matches!(field.field_type, FieldType::Vector(_)) {
            add_to_index(store, &table.name, field, value, primary_key, now);
        }
        if field.unique {
            let index_values = metadata.unique_values.get(&field.name).ok_or_else(|| {
                "ERR transferred unique field has no canonical index value".to_owned()
            })?;
            let unique_key = uniq_key(&table.name, &field.name);
            for index_value in index_values {
                store.hset(
                    unique_key.as_bytes(),
                    &[(index_value.as_bytes(), primary_key.as_bytes())],
                    now,
                )?;
            }
        }
    }
    for (field, value) in &metadata.paths {
        add_to_index(store, &table.name, field, value, primary_key, now);
    }

    let ttl_member = ttl_member(&table.name, primary_key);
    match metadata.ttl_deadline_ms {
        Some(deadline) => {
            store.zadd(
                ttl_index_key().as_bytes(),
                &[(ttl_member.as_bytes(), deadline as f64)],
                false,
                false,
                false,
                false,
                false,
                now,
            )?;
        }
        None => {
            let _ = store.zrem(ttl_index_key().as_bytes(), &[ttl_member.as_bytes()], now);
        }
    }
    Ok(())
}

fn execution_table_schema(table: &ExecutionTable) -> Result<Vec<FieldDef>, String> {
    let schema = table
        .fields
        .iter()
        .map(|field| {
            let decoded = decode_field_def(&field.name, &field.definition);
            if encode_field_def(&decoded) != field.definition {
                return Err("ERR signed field definition is not canonical".to_owned());
            }
            Ok(decoded)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if schema
        .iter()
        .find(|field| field.primary_key)
        .map(|field| field.name.as_str())
        != table.primary_key.as_deref()
    {
        return Err("ERR signed primary-key projection is inconsistent".to_owned());
    }
    Ok(schema)
}

fn execution_path_indexes(table: &ExecutionTable) -> Result<Vec<PathIndex>, String> {
    table
        .path_indexes
        .iter()
        .map(|index| {
            parse_index_type(&index.field_type)
                .map(|field_type| PathIndex {
                    path: index.path.clone(),
                    field_type,
                })
                .ok_or_else(|| "ERR signed path-index type is invalid".to_owned())
        })
        .collect()
}
