use super::*;
use serde::{Deserialize, Serialize};

/// Durable schema context carried from the signed Cluster system node to a
/// slot owner before that owner executes a table-row command. The snapshot is
/// deliberately made from Lux's on-disk schema representation rather than a
/// second public schema model, so defaults, encryption flags, and future field
/// flags cannot silently drift between the catalog and the table executor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ClusterTableCatalog {
    schema_version: u16,
    table: String,
    schema: Vec<(String, Vec<u8>)>,
    path_indexes: Vec<(String, Vec<u8>)>,
    primary_key: String,
}

const CLUSTER_TABLE_CATALOG_SCHEMA_VERSION: u16 = 1;

/// Export one user table's authoritative catalog record for a Cluster slot
/// owner. Reserved engine tables never leave the system node.
pub(crate) fn export_cluster_table_catalog(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    now: Instant,
) -> Result<Vec<u8>, String> {
    if crate::auth::is_reserved_system_table(table) {
        return Err(format!(
            "ERR table '{}' is pinned to the Cluster system node",
            table
        ));
    }
    let fields = load_schema(store, cache, table, now)?;
    validate_cluster_table_schema(table, &fields)?;

    let mut schema = store
        .hgetall(schema_key(table).as_bytes(), now)?
        .into_iter()
        .map(|(name, value)| (name, value.to_vec()))
        .collect::<Vec<_>>();
    schema.sort_by(|left, right| left.0.cmp(&right.0));
    let mut path_indexes = store
        .hgetall(path_indexes_key(table).as_bytes(), now)
        .unwrap_or_default()
        .into_iter()
        .map(|(name, value)| (name, value.to_vec()))
        .collect::<Vec<_>>();
    path_indexes.sort_by(|left, right| left.0.cmp(&right.0));
    let primary_key = store
        .get(pk_key(table).as_bytes(), now)
        .and_then(|value| String::from_utf8(value.to_vec()).ok())
        .ok_or_else(|| format!("ERR table '{}' has no durable primary key metadata", table))?;

    let snapshot = ClusterTableCatalog {
        schema_version: CLUSTER_TABLE_CATALOG_SCHEMA_VERSION,
        table: table.to_string(),
        schema,
        path_indexes,
        primary_key,
    };
    rmp_serde::to_vec_named(&snapshot)
        .map_err(|error| format!("ERR could not encode Cluster table catalog: {error}"))
}

/// Install catalog context before replaying or executing a remote table-row
/// command. A new catalog is logged before its first row mutation and uses the
/// table name as WAL key, preserving schema-before-row replay order.
pub(crate) fn install_cluster_table_catalog(
    store: &Store,
    cache: &SharedSchemaCache,
    expected_table: &str,
    encoded: &[u8],
    now: Instant,
) -> Result<bool, String> {
    let snapshot: ClusterTableCatalog = rmp_serde::from_slice(encoded)
        .map_err(|error| format!("ERR invalid Cluster table catalog: {error}"))?;
    if snapshot.schema_version != CLUSTER_TABLE_CATALOG_SCHEMA_VERSION {
        return Err(format!(
            "ERR unsupported Cluster table catalog version {}",
            snapshot.schema_version
        ));
    }
    if snapshot.table != expected_table || !is_valid_table_name(&snapshot.table) {
        return Err("ERR Cluster table catalog does not match the routed command".to_string());
    }
    if crate::auth::is_reserved_system_table(&snapshot.table) {
        return Err("ERR reserved system catalogs cannot be installed on data nodes".to_string());
    }
    if snapshot.schema.is_empty() {
        return Err("ERR Cluster table catalog has no schema fields".to_string());
    }
    if !snapshot.schema.windows(2).all(|pair| pair[0].0 < pair[1].0)
        || !snapshot
            .path_indexes
            .windows(2)
            .all(|pair| pair[0].0 < pair[1].0)
    {
        return Err("ERR Cluster table catalog is not canonical".to_string());
    }

    let mut fields = Vec::new();
    for (name, value) in &snapshot.schema {
        if name.as_bytes() == HIDDEN_DEFAULT_TTL_FIELD {
            let ttl = std::str::from_utf8(value)
                .ok()
                .and_then(|raw| raw.parse::<u64>().ok());
            if ttl.is_none() {
                return Err("ERR Cluster table catalog has an invalid default TTL".to_string());
            }
            continue;
        }
        if !is_valid_name(name) {
            return Err(format!(
                "ERR Cluster table catalog has invalid field '{}'",
                name
            ));
        }
        let value = std::str::from_utf8(value)
            .map_err(|_| format!("ERR Cluster field '{}' is not UTF-8", name))?;
        fields.push(decode_field_def(name, value));
    }
    validate_cluster_table_schema(&snapshot.table, &fields)?;
    ensure_encryption_ready(store, &fields)?;
    let declared_pk = fields
        .iter()
        .find(|field| field.primary_key)
        .map(|field| field.name.as_str());
    if declared_pk != Some(snapshot.primary_key.as_str()) {
        return Err("ERR Cluster primary key metadata does not match the schema".to_string());
    }
    for (path, encoded_type) in &snapshot.path_indexes {
        let encoded_type = std::str::from_utf8(encoded_type)
            .map_err(|_| format!("ERR Cluster path index '{}' is not UTF-8", path))?;
        if path.split_once('.').is_none() || parse_index_type(encoded_type).is_none() {
            return Err(format!("ERR Cluster path index '{}' is invalid", path));
        }
    }

    let mut current_schema = store
        .hgetall(schema_key(&snapshot.table).as_bytes(), now)
        .unwrap_or_default()
        .into_iter()
        .map(|(name, value)| (name, value.to_vec()))
        .collect::<Vec<_>>();
    current_schema.sort_by(|left, right| left.0.cmp(&right.0));
    let mut current_paths = store
        .hgetall(path_indexes_key(&snapshot.table).as_bytes(), now)
        .unwrap_or_default()
        .into_iter()
        .map(|(name, value)| (name, value.to_vec()))
        .collect::<Vec<_>>();
    current_paths.sort_by(|left, right| left.0.cmp(&right.0));
    let current_pk = store
        .get(pk_key(&snapshot.table).as_bytes(), now)
        .map(|value| value.to_vec());
    if current_schema == snapshot.schema
        && current_paths == snapshot.path_indexes
        && current_pk.as_deref() == Some(snapshot.primary_key.as_bytes())
    {
        return Ok(false);
    }
    store
        .wal_log_command(&[b"LXCATALOG", snapshot.table.as_bytes(), encoded])
        .map_err(|error| format!("ERR WAL append failed: {error}"))?;

    if !current_schema.is_empty() {
        reconcile_cluster_table_catalog(
            store,
            cache,
            &snapshot,
            &current_schema,
            &current_paths,
            now,
        )?;
        return Ok(true);
    }

    let schema_refs = snapshot
        .schema
        .iter()
        .map(|(field, value)| (field.as_bytes(), value.as_slice()))
        .collect::<Vec<_>>();
    store.hset(schema_key(&snapshot.table).as_bytes(), &schema_refs, now)?;
    if !snapshot.path_indexes.is_empty() {
        let path_refs = snapshot
            .path_indexes
            .iter()
            .map(|(path, value)| (path.as_bytes(), value.as_slice()))
            .collect::<Vec<_>>();
        store.hset(
            path_indexes_key(&snapshot.table).as_bytes(),
            &path_refs,
            now,
        )?;
    }
    store.set(
        pk_key(&snapshot.table).as_bytes(),
        snapshot.primary_key.as_bytes(),
        None,
        now,
    );
    if store
        .get(seq_key(&snapshot.table).as_bytes(), now)
        .is_none()
    {
        store.set(seq_key(&snapshot.table).as_bytes(), b"0", None, now);
    }
    let _ = store.sadd(
        table_list_key().as_bytes(),
        &[snapshot.table.as_bytes()],
        now,
    );
    cache.write().remove(&snapshot.table);
    Ok(true)
}

fn reconcile_cluster_table_catalog(
    store: &Store,
    cache: &SharedSchemaCache,
    snapshot: &ClusterTableCatalog,
    current_schema: &[(String, Vec<u8>)],
    current_paths: &[(String, Vec<u8>)],
    now: Instant,
) -> Result<(), String> {
    let target_fields = snapshot
        .schema
        .iter()
        .filter(|(name, _)| name.as_bytes() != HIDDEN_DEFAULT_TTL_FIELD)
        .map(|(name, encoded)| {
            let encoded = std::str::from_utf8(encoded)
                .map_err(|_| format!("ERR Cluster field '{}' is not UTF-8", name))?;
            Ok((
                name.clone(),
                (encoded.to_string(), decode_field_def(name, encoded)),
            ))
        })
        .collect::<Result<std::collections::BTreeMap<_, _>, String>>()?;
    let current_fields = current_schema
        .iter()
        .filter(|(name, _)| name.as_bytes() != HIDDEN_DEFAULT_TTL_FIELD)
        .map(|(name, encoded)| {
            let encoded = std::str::from_utf8(encoded)
                .map_err(|_| format!("ERR local Cluster field '{}' is not UTF-8", name))?;
            Ok((name.clone(), encoded.to_string()))
        })
        .collect::<Result<std::collections::BTreeMap<_, _>, String>>()?;

    for (name, encoded) in &current_fields {
        if let Some((target_encoded, _)) = target_fields.get(name) {
            if encoded != target_encoded {
                return Err(format!(
                    "ERR Cluster cannot reconcile an in-place type or constraint change for '{}.{}'",
                    snapshot.table, name
                ));
            }
        }
    }

    let current_path_map = current_paths
        .iter()
        .cloned()
        .collect::<std::collections::BTreeMap<_, _>>();
    let target_path_map = snapshot
        .path_indexes
        .iter()
        .cloned()
        .collect::<std::collections::BTreeMap<_, _>>();
    // Rebuild every declared path index when a catalog changes. This is more
    // work than a metadata-only comparison, but makes replay idempotent after a
    // crash in the middle of an index backfill.
    for path in current_path_map.keys() {
        table_drop_path_index(store, cache, &snapshot.table, path, now)?;
    }

    for name in current_fields.keys() {
        if !target_fields.contains_key(name) {
            if name == &snapshot.primary_key {
                return Err("ERR Cluster cannot remove a table primary key".to_string());
            }
            table_drop_column(store, cache, &snapshot.table, name, now)?;
        }
    }
    for (name, (_, field)) in &target_fields {
        if !current_fields.contains_key(name) {
            table_add_column_def(store, cache, &snapshot.table, field.clone(), now)?;
        }
        if let Some(default) = &field.default_value {
            for primary_key in get_all_row_ids(store, &snapshot.table, now) {
                let row_key = row_key_for_pk(&snapshot.table, &primary_key);
                if store
                    .hget(row_key.as_bytes(), field.name.as_bytes(), now)
                    .is_some()
                {
                    continue;
                }
                let encoded =
                    encode_stored_value(store, &snapshot.table, field, &primary_key, default)?;
                store.hset(
                    row_key.as_bytes(),
                    &[(field.name.as_bytes(), encoded.as_slice())],
                    now,
                )?;
                add_to_index(store, &snapshot.table, field, default, &primary_key, now);
            }
        }
    }

    let schema_key = schema_key(&snapshot.table);
    match snapshot
        .schema
        .iter()
        .find(|(name, _)| name.as_bytes() == HIDDEN_DEFAULT_TTL_FIELD)
    {
        Some((_, value)) => {
            store.hset(
                schema_key.as_bytes(),
                &[(HIDDEN_DEFAULT_TTL_FIELD, value.as_slice())],
                now,
            )?;
        }
        None => {
            let _ = store.hdel(schema_key.as_bytes(), &[HIDDEN_DEFAULT_TTL_FIELD], now);
        }
    }
    for (path, encoded_type) in &target_path_map {
        let encoded_type = std::str::from_utf8(encoded_type)
            .map_err(|_| format!("ERR Cluster path index '{}' is not UTF-8", path))?;
        table_create_path_index(store, cache, &snapshot.table, path, encoded_type, now)?;
    }
    cache.write().remove(&snapshot.table);
    Ok(())
}

fn validate_cluster_table_schema(table: &str, fields: &[FieldDef]) -> Result<(), String> {
    let primary_keys = fields.iter().filter(|field| field.primary_key).count();
    if primary_keys != 1 {
        return Err(format!(
            "ERR Cluster table '{}' must declare exactly one PRIMARY KEY",
            table
        ));
    }
    if let Some(field) = fields
        .iter()
        .find(|field| field.unique && !field.primary_key)
    {
        return Err(format!(
            "ERR Cluster table '{}' cannot use secondary UNIQUE column '{}' until global constraints are supported",
            table, field.name
        ));
    }
    if let Some(field) = fields
        .iter()
        .find(|field| field.references.is_some() || matches!(field.field_type, FieldType::Ref(_)))
    {
        return Err(format!(
            "ERR Cluster table '{}' cannot use foreign key column '{}' until global constraints are supported",
            table, field.name
        ));
    }
    if let Some(field) = fields
        .iter()
        .find(|field| field.sequence_partition.is_some())
    {
        return Err(format!(
            "ERR Cluster table '{}' cannot use partitioned sequence column '{}'",
            table, field.name
        ));
    }
    Ok(())
}

pub(crate) struct PreparedClusterTableCommand {
    pub(crate) table: String,
    pub(crate) primary_key: Vec<u8>,
    pub(crate) argv: Vec<Vec<u8>>,
    pub(crate) read_only: bool,
}

/// Prepare a mutation whose target can be proven from one primary key. Generated
/// identity is resolved exactly once on the system node; broad predicates and
/// secondary conflict targets fail closed instead of accidentally touching only
/// one partition.
pub(crate) fn prepare_cluster_table_command(
    store: &Store,
    cache: &SharedSchemaCache,
    argv: &[&[u8]],
    now: Instant,
) -> Result<Option<PreparedClusterTableCommand>, String> {
    let Some(command) = argv.first() else {
        return Ok(None);
    };
    let table_index = if command.eq_ignore_ascii_case(b"TDELETE") {
        2
    } else if command.eq_ignore_ascii_case(b"TINSERT")
        || command.eq_ignore_ascii_case(b"TUPSERT")
        || command.eq_ignore_ascii_case(b"TUPDATE")
    {
        1
    } else {
        return Ok(None);
    };
    let Some(raw_table) = argv.get(table_index) else {
        return Ok(None);
    };
    let table = std::str::from_utf8(raw_table)
        .map_err(|_| "ERR table name is not valid UTF-8".to_string())?;
    if crate::auth::is_reserved_system_table(table) {
        return Ok(None);
    }
    let schema = load_schema(store, cache, table, now)?;
    validate_cluster_table_schema(table, &schema)?;
    let primary_key = schema
        .iter()
        .find(|field| field.primary_key)
        .expect("Cluster schema validation requires a primary key");
    let mut owned = argv.iter().map(|value| value.to_vec()).collect::<Vec<_>>();
    let primary_key_value = if command.eq_ignore_ascii_case(b"TINSERT") {
        let fields_end = cluster_insert_fields_end(argv)?;
        materialize_insert_primary_key(&mut owned, argv, fields_end, table, primary_key)?
    } else if command.eq_ignore_ascii_case(b"TUPSERT") {
        let (fields_end, conflict) = cluster_upsert_fields_end(argv)?;
        if conflict.is_some_and(|conflict| conflict != primary_key.name.as_bytes()) {
            return Err(format!(
                "ERR Cluster upsert conflict target must be primary key '{}'",
                primary_key.name
            ));
        }
        materialize_insert_primary_key(&mut owned, argv, fields_end, table, primary_key)?
    } else if command.eq_ignore_ascii_case(b"TUPDATE") {
        exact_update_primary_key(argv, primary_key)?
    } else {
        exact_delete_primary_key(argv, primary_key)?
    };
    let primary_key_str = std::str::from_utf8(&primary_key_value)
        .map_err(|_| "ERR Cluster primary key is not valid UTF-8".to_string())?;
    validate_value(primary_key, primary_key_str)?;

    Ok(Some(PreparedClusterTableCommand {
        table: table.to_string(),
        primary_key: primary_key_value,
        argv: owned,
        read_only: false,
    }))
}

fn materialize_insert_primary_key(
    owned: &mut Vec<Vec<u8>>,
    argv: &[&[u8]],
    fields_end: usize,
    table: &str,
    primary_key: &FieldDef,
) -> Result<Vec<u8>, String> {
    let mut value = None;
    for pair in argv[2..fields_end].chunks_exact(2) {
        if pair[0] == primary_key.name.as_bytes() {
            value = Some(pair[1].to_vec());
        }
    }
    Ok(match value {
        Some(value) => value,
        None if primary_key.field_type == FieldType::Uuid => {
            let value = generate_uuid_v7().into_bytes();
            owned.insert(fields_end, primary_key.name.as_bytes().to_vec());
            owned.insert(fields_end + 1, value.clone());
            value
        }
        None if primary_key.field_type == FieldType::Int => {
            return Err(format!(
                "ERR Cluster insert into '{}' must provide INT primary key '{}'",
                table, primary_key.name
            ));
        }
        None if primary_key.default_value.is_some() => {
            let value = resolve_default(primary_key.default_value.as_deref().unwrap_or(""));
            validate_value(primary_key, &value)?;
            let value = value.into_bytes();
            owned.insert(fields_end, primary_key.name.as_bytes().to_vec());
            owned.insert(fields_end + 1, value.clone());
            value
        }
        None => {
            return Err(format!(
                "ERR primary key column '{}' must be provided",
                primary_key.name
            ));
        }
    })
}

fn exact_update_primary_key(argv: &[&[u8]], primary_key: &FieldDef) -> Result<Vec<u8>, String> {
    let end = cluster_write_body_end(argv);
    let where_pos = argv[..end]
        .iter()
        .position(|arg| arg.eq_ignore_ascii_case(b"WHERE"))
        .ok_or_else(|| {
            "ERR Cluster update requires an exact primary-key WHERE clause".to_string()
        })?;
    if argv
        .get(2)
        .is_none_or(|arg| !arg.eq_ignore_ascii_case(b"SET"))
        || where_pos < 5
        || !(where_pos - 3).is_multiple_of(2)
        || end != where_pos + 4
        || argv[where_pos + 1] != primary_key.name.as_bytes()
        || argv[where_pos + 2] != b"="
    {
        return Err(format!(
            "ERR Cluster update must use WHERE {} = <value>",
            primary_key.name
        ));
    }
    if argv[3..where_pos]
        .chunks_exact(2)
        .any(|pair| pair[0] == primary_key.name.as_bytes())
    {
        return Err("ERR Cluster cannot change a row primary key in place".to_string());
    }
    Ok(argv[where_pos + 3].to_vec())
}

fn exact_delete_primary_key(argv: &[&[u8]], primary_key: &FieldDef) -> Result<Vec<u8>, String> {
    let end = cluster_returning_start(argv);
    let where_pos = argv[..end]
        .iter()
        .position(|arg| arg.eq_ignore_ascii_case(b"WHERE"))
        .ok_or_else(|| {
            "ERR Cluster delete requires an exact primary-key WHERE clause".to_string()
        })?;
    if argv
        .get(1)
        .is_none_or(|arg| !arg.eq_ignore_ascii_case(b"FROM"))
        || end != where_pos + 4
        || argv[where_pos + 1] != primary_key.name.as_bytes()
        || argv[where_pos + 2] != b"="
    {
        return Err(format!(
            "ERR Cluster delete must use WHERE {} = <value>",
            primary_key.name
        ));
    }
    Ok(argv[where_pos + 3].to_vec())
}

fn cluster_upsert_fields_end<'a>(
    argv: &'a [&'a [u8]],
) -> Result<(usize, Option<&'a [u8]>), String> {
    let end = cluster_write_body_end(argv);
    let on = argv[..end].windows(2).position(|pair| {
        pair[0].eq_ignore_ascii_case(b"ON") && pair[1].eq_ignore_ascii_case(b"CONFLICT")
    });
    let (fields_end, conflict) = match on {
        Some(position) if position + 3 == end => (position, Some(argv[position + 2])),
        Some(_) => return Err("ERR invalid ON CONFLICT clause".to_string()),
        None => (end, None),
    };
    if fields_end < 2 || !(fields_end - 2).is_multiple_of(2) {
        return Err("ERR wrong number of arguments for 'tupsert' command".to_string());
    }
    Ok((fields_end, conflict))
}

fn cluster_returning_start(argv: &[&[u8]]) -> usize {
    argv.iter()
        .position(|arg| arg.eq_ignore_ascii_case(b"RETURNING"))
        .unwrap_or(argv.len())
}

fn cluster_write_body_end(argv: &[&[u8]]) -> usize {
    let returning = cluster_returning_start(argv);
    if returning >= 2
        && argv[returning - 2].eq_ignore_ascii_case(b"TTL")
        && std::str::from_utf8(argv[returning - 1])
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .is_some()
    {
        returning - 2
    } else {
        returning
    }
}

/// Independently derive a peer command's logical table-row route from the
/// attached catalog. The receiver never trusts coordinator-provided slot or PK
/// metadata without recomputing both from the actual argv.
pub(crate) fn validate_cluster_routed_table_command(
    encoded_catalog: &[u8],
    argv: &[&[u8]],
    claimed_primary_key: &[u8],
) -> Result<(String, bool), String> {
    let snapshot: ClusterTableCatalog = rmp_serde::from_slice(encoded_catalog)
        .map_err(|error| format!("ERR invalid Cluster table catalog: {error}"))?;
    let command = argv
        .first()
        .ok_or_else(|| "ERR empty Cluster table command".to_string())?;
    let table_index = usize::from(command.eq_ignore_ascii_case(b"TDELETE")) + 1;
    if snapshot.schema_version != CLUSTER_TABLE_CATALOG_SCHEMA_VERSION
        || argv.get(table_index).copied() != Some(snapshot.table.as_bytes())
        || crate::auth::is_reserved_system_table(&snapshot.table)
    {
        return Err("ERR Cluster table route does not match its catalog".to_string());
    }
    let pk_field = snapshot
        .schema
        .iter()
        .filter(|(name, _)| name.as_bytes() != HIDDEN_DEFAULT_TTL_FIELD)
        .map(|(name, encoded)| {
            let encoded = std::str::from_utf8(encoded)
                .map_err(|_| "ERR Cluster schema field is not UTF-8".to_string())?;
            Ok(decode_field_def(name, encoded))
        })
        .collect::<Result<Vec<_>, String>>()?
        .into_iter()
        .find(|field| field.primary_key)
        .ok_or_else(|| "ERR Cluster table catalog has no primary key".to_string())?;
    if pk_field.name != snapshot.primary_key {
        return Err("ERR Cluster primary key metadata does not match the catalog".to_string());
    }
    let (actual_primary_key, read_only) = if command.eq_ignore_ascii_case(b"TGET")
        || command.eq_ignore_ascii_case(b"TSET")
    {
        (
            argv.get(2)
                .copied()
                .ok_or_else(|| "ERR Cluster point command has no primary key".to_string())?
                .to_vec(),
            command.eq_ignore_ascii_case(b"TGET"),
        )
    } else if command.eq_ignore_ascii_case(b"TINSERT") || command.eq_ignore_ascii_case(b"TUPSERT") {
        let fields_end = if command.eq_ignore_ascii_case(b"TINSERT") {
            cluster_insert_fields_end(argv)?
        } else {
            let (fields_end, conflict) = cluster_upsert_fields_end(argv)?;
            if conflict.is_some_and(|conflict| conflict != pk_field.name.as_bytes()) {
                return Err("ERR Cluster upsert conflict target is not the primary key".to_string());
            }
            fields_end
        };
        let mut value = None;
        for pair in argv[2..fields_end].chunks_exact(2) {
            if pair[0] == pk_field.name.as_bytes() {
                value = Some(pair[1].to_vec());
            }
        }
        (
            value.ok_or_else(|| {
                "ERR Cluster routed insert has no materialized primary key".to_string()
            })?,
            false,
        )
    } else if command.eq_ignore_ascii_case(b"TUPDATE") {
        (exact_update_primary_key(argv, &pk_field)?, false)
    } else if command.eq_ignore_ascii_case(b"TDELETE") {
        (exact_delete_primary_key(argv, &pk_field)?, false)
    } else {
        return Err("ERR command is not a routed Cluster table operation".to_string());
    };
    if actual_primary_key.as_slice() != claimed_primary_key {
        return Err("ERR Cluster routed primary key does not match argv".to_string());
    }
    Ok((snapshot.table, read_only))
}

fn cluster_insert_fields_end(argv: &[&[u8]]) -> Result<usize, String> {
    let returning = argv
        .iter()
        .position(|arg| arg.eq_ignore_ascii_case(b"RETURNING"))
        .unwrap_or(argv.len());
    let fields_end = if returning >= 2
        && argv[returning - 2].eq_ignore_ascii_case(b"TTL")
        && std::str::from_utf8(argv[returning - 1])
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .is_some()
    {
        returning - 2
    } else {
        returning
    };
    if fields_end < 2 || !(fields_end - 2).is_multiple_of(2) {
        return Err("ERR wrong number of arguments for 'tinsert' command".to_string());
    }
    Ok(fields_end)
}
