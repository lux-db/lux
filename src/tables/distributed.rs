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

pub(crate) fn export_all_cluster_table_catalogs(
    store: &Store,
    cache: &SharedSchemaCache,
    now: Instant,
) -> Result<Vec<crate::cluster::TransferCatalogProof>, String> {
    let mut tables = table_list(store, now);
    tables.sort();
    tables
        .into_iter()
        .filter(|table| !crate::auth::is_reserved_system_table(table))
        .map(|table| {
            Ok(crate::cluster::TransferCatalogProof {
                catalog: export_cluster_table_catalog(store, cache, &table, now)?,
                table,
            })
        })
        .collect()
}

/// Export canonical catalogs and exact raw row images for the logical slots in
/// one ownership-transfer route. Raw encrypted cells remain ciphertext and are
/// carried only inside the mutually authenticated peer channel.
pub(crate) fn export_cluster_transfer_data(
    store: &Store,
    cache: &SharedSchemaCache,
    owns_primary_key: &(dyn Fn(&str, &str) -> bool + Sync),
    now: Instant,
) -> Result<
    (
        Vec<crate::cluster::TransferCatalogProof>,
        Vec<crate::cluster::TransferItem>,
    ),
    String,
> {
    let mut tables = table_list(store, now);
    tables.sort();
    let mut catalogs = Vec::new();
    let mut rows = Vec::new();
    for table in tables {
        if crate::auth::is_reserved_system_table(&table) {
            continue;
        }
        let mut table_rows = Vec::new();
        for primary_key in get_all_row_ids(store, &table, now) {
            if !owns_primary_key(&table, &primary_key) {
                continue;
            }
            let row_key = row_key_for_pk(&table, &primary_key);
            let mut raw_fields = store.hgetall(row_key.as_bytes(), now)?;
            if raw_fields.is_empty() || row_map_expired(&raw_fields) {
                continue;
            }
            raw_fields.sort_by(|left, right| left.0.cmp(&right.0));
            table_rows.push(crate::cluster::TransferItem::TableRow {
                table: table.clone(),
                primary_key,
                raw_fields: raw_fields
                    .into_iter()
                    .map(|(field, value)| (field.into_bytes(), value.to_vec()))
                    .collect(),
            });
        }
        if table_rows.is_empty() {
            continue;
        }
        catalogs.push(crate::cluster::TransferCatalogProof {
            table: table.clone(),
            catalog: export_cluster_table_catalog(store, cache, &table, now)?,
        });
        rows.append(&mut table_rows);
    }
    Ok((catalogs, rows))
}

/// Prove that every catalog referenced by a source bundle is already installed
/// from the signed system node. A data owner can move its rows, but it cannot
/// use a transfer to author or rewrite schema on the target.
pub(crate) fn validate_cluster_transfer_catalogs(
    store: &Store,
    cache: &SharedSchemaCache,
    catalogs: &[crate::cluster::TransferCatalogProof],
    now: Instant,
) -> Result<std::collections::HashSet<String>, String> {
    let mut validated = std::collections::HashSet::new();
    for proof in catalogs {
        if !validated.insert(proof.table.clone()) {
            return Err("ERR duplicate Cluster transfer catalog proof".to_string());
        }
        if crate::auth::is_reserved_system_table(&proof.table) {
            return Err("ERR reserved system table cannot be transferred".to_string());
        }
        let installed =
            export_cluster_table_catalog(store, cache, &proof.table, now).map_err(|_| {
                format!(
                    "ERR Cluster catalog '{}' must be synced from the system node before transfer",
                    proof.table
                )
            })?;
        if installed != proof.catalog {
            return Err(format!(
                "ERR Cluster catalog '{}' does not match the system-node version",
                proof.table
            ));
        }
    }
    Ok(validated)
}

pub(crate) fn import_cluster_transfer_row(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    primary_key: &str,
    raw_fields: &[(Vec<u8>, Vec<u8>)],
    now: Instant,
) -> Result<(), String> {
    if raw_fields.is_empty() {
        return Err("ERR Cluster transfer row has no fields".to_string());
    }
    if !raw_fields.windows(2).all(|pair| pair[0].0 < pair[1].0) {
        return Err("ERR Cluster transfer row fields are not canonical".to_string());
    }
    let mut command = Vec::<Vec<u8>>::with_capacity(raw_fields.len() * 2 + 3);
    command.push(b"TROWSET".to_vec());
    command.push(table.as_bytes().to_vec());
    command.push(primary_key.as_bytes().to_vec());
    for (field, value) in raw_fields {
        command.push(field.clone());
        command.push(value.clone());
    }
    let command_refs = command.iter().map(Vec::as_slice).collect::<Vec<_>>();
    store
        .wal_log_command(&command_refs)
        .map_err(|error| format!("ERR WAL append failed: {error}"))?;
    let pair_refs = raw_fields
        .iter()
        .map(|(field, value)| (field.as_slice(), value.as_slice()))
        .collect::<Vec<_>>();
    table_apply_wal_row(store, cache, table, primary_key, &pair_refs, now)
}

/// Durably remove a stale physical row from a source node after cluster-wide
/// ownership commit. This bypasses logical FK actions because the row was
/// moved, not deleted from the user's database.
pub(crate) fn remove_cluster_transfer_row(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    primary_key: &str,
    now: Instant,
) -> Result<(), String> {
    if crate::auth::is_reserved_system_table(table) {
        return Err("ERR reserved system table cannot be transfer-cleaned".to_string());
    }
    store
        .wal_log_command(&[b"TROWDEL", table.as_bytes(), primary_key.as_bytes()])
        .map_err(|error| format!("ERR WAL append failed: {error}"))?;
    table_apply_wal_row_delete(store, cache, table, primary_key, now)
}

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
    exact_primary_key_from_where(&argv[where_pos + 1..end], primary_key, "update")
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
    {
        return Err(format!(
            "ERR Cluster delete must use WHERE {} = <value>",
            primary_key.name
        ));
    }
    exact_primary_key_from_where(&argv[where_pos + 1..end], primary_key, "delete")
}

/// Prove that an arbitrary AND predicate narrows to at most one shard. Extra
/// conditions (notably HTTP RLS USING filters) are evaluated atomically by the
/// owner. A primary-key equality nested inside an OR group does not qualify.
fn exact_primary_key_from_where(
    argv: &[&[u8]],
    primary_key: &FieldDef,
    operation: &str,
) -> Result<Vec<u8>, String> {
    let args = argv
        .iter()
        .map(|arg| {
            std::str::from_utf8(arg)
                .map_err(|_| format!("ERR Cluster {operation} WHERE is not valid UTF-8"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let conditions = parse_where_conditions(&args)?;
    let value = conditions
        .iter()
        .find(|condition| {
            condition.field == primary_key.name
                && condition.op == CmpOp::Eq
                && condition.or_clauses.is_empty()
        })
        .map(|condition| condition.value.as_bytes().to_vec())
        .ok_or_else(|| {
            format!(
                "ERR Cluster {operation} must include WHERE {} = <value> as an AND condition",
                primary_key.name
            )
        })?;
    Ok(value)
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

pub(crate) enum ClusterMergedTableScan {
    Count(i64),
    Select(SelectResult),
}

/// Identify a broad, read-only user-table command that must be scattered over
/// every slot owner. Reserved auth/push tables intentionally stay on node 1.
pub(crate) fn cluster_table_scan_table(argv: &[&[u8]]) -> Result<Option<String>, String> {
    let Some(command) = argv.first() else {
        return Ok(None);
    };
    let table = if command.eq_ignore_ascii_case(b"TCOUNT") {
        if argv.len() != 2 {
            return Err("ERR wrong number of arguments for 'tcount' command".to_string());
        }
        utf8_arg(argv[1], "table name")?.to_string()
    } else if command.eq_ignore_ascii_case(b"TSELECT") {
        let plan = parse_cluster_select(argv)?;
        if !plan.joins.is_empty() {
            return Err(
                "ERR Cluster distributed JOIN is not supported; query one partition by primary key or denormalize the join"
                    .to_string(),
            );
        }
        plan.table
    } else {
        return Ok(None);
    };
    if crate::auth::is_reserved_system_table(&table) {
        Ok(None)
    } else {
        Ok(Some(table))
    }
}

/// Recompute a scatter command's table from its argv and prove that the signed
/// system catalog names the same non-reserved table. Peers do this before any
/// catalog installation or data access.
pub(crate) fn validate_cluster_table_scan(
    encoded_catalog: &[u8],
    argv: &[&[u8]],
) -> Result<String, String> {
    let snapshot: ClusterTableCatalog = rmp_serde::from_slice(encoded_catalog)
        .map_err(|error| format!("ERR invalid Cluster table catalog: {error}"))?;
    let table = cluster_table_scan_table(argv)?
        .ok_or_else(|| "ERR command is not a Cluster table scan".to_string())?;
    if snapshot.schema_version != CLUSTER_TABLE_CATALOG_SCHEMA_VERSION
        || snapshot.table != table
        || crate::auth::is_reserved_system_table(&snapshot.table)
    {
        return Err("ERR Cluster table scan does not match its catalog".to_string());
    }
    Ok(table)
}

/// Run only the shard-local phase and return the peer protocol's structured
/// result. The coordinator never parses or concatenates RESP frames.
pub(crate) fn execute_cluster_table_scan(
    store: &Store,
    cache: &SharedSchemaCache,
    argv: &[&[u8]],
    now: Instant,
    decrypt_authorized: bool,
    owns_primary_key: &(dyn Fn(&str, &str) -> bool + Sync),
) -> Result<crate::cluster::TableScanPartial, String> {
    let command = argv
        .first()
        .ok_or_else(|| "ERR empty Cluster table scan".to_string())?;
    let partial = if command.eq_ignore_ascii_case(b"TCOUNT") {
        let table = cluster_table_scan_table(argv)?
            .ok_or_else(|| "ERR command is not a Cluster table scan".to_string())?;
        let _ = load_schema(store, cache, &table, now)?;
        let count = get_all_row_ids(store, &table, now)
            .into_iter()
            .filter(|primary_key| owns_primary_key(&table, primary_key))
            .filter(|primary_key| {
                let row_key = row_key_for_pk(&table, primary_key);
                store
                    .hgetall(row_key.as_bytes(), now)
                    .is_ok_and(|row| !row.is_empty() && !row_map_expired(&row))
            })
            .count() as i64;
        crate::cluster::TableScanPartial::Count(count)
    } else if command.eq_ignore_ascii_case(b"TSELECT") {
        let mut plan = parse_cluster_select(argv)?;
        plan.decrypt_authorized = decrypt_authorized;
        crate::cluster::TableScanPartial::Rows(cluster_select_shard_rows(
            store,
            cache,
            &plan,
            now,
            &|primary_key| owns_primary_key(&plan.table, primary_key),
        )?)
    } else {
        return Err("ERR command is not a Cluster table scan".to_string());
    };
    Ok(partial)
}

/// Decode every shard's structured result and apply the query's global
/// semantics once. A missing, malformed, or mismatched shard fails the whole
/// read instead of returning a plausible but incomplete answer.
pub(crate) fn merge_cluster_table_scans(
    argv: &[&[u8]],
    partials: Vec<crate::cluster::TableScanPartial>,
) -> Result<ClusterMergedTableScan, String> {
    if partials.is_empty() {
        return Err("TRYAGAIN Cluster table scan had no participating nodes".to_string());
    }
    if argv[0].eq_ignore_ascii_case(b"TCOUNT") {
        let mut total = 0i64;
        for partial in partials {
            let crate::cluster::TableScanPartial::Count(count) = partial else {
                return Err("ERR Cluster peer returned the wrong table scan result".to_string());
            };
            total = total
                .checked_add(count)
                .ok_or_else(|| "ERR Cluster table count overflow".to_string())?;
        }
        return Ok(ClusterMergedTableScan::Count(total));
    }

    let plan = parse_cluster_select(argv)?;
    let mut rows = Vec::new();
    for partial in partials {
        let crate::cluster::TableScanPartial::Rows(mut shard_rows) = partial else {
            return Err("ERR Cluster peer returned the wrong table scan result".to_string());
        };
        rows.append(&mut shard_rows);
    }
    Ok(ClusterMergedTableScan::Select(finish_cluster_select(
        &plan, rows,
    )?))
}

fn parse_cluster_select(argv: &[&[u8]]) -> Result<SelectPlan, String> {
    if argv.len() < 4 {
        return Err("ERR usage: TSELECT <cols> FROM <table> [...]".to_string());
    }
    let args = argv[1..]
        .iter()
        .map(|arg| utf8_arg(arg, "TSELECT argument"))
        .collect::<Result<Vec<_>, _>>()?;
    parse_select(&args)
}

fn utf8_arg<'a>(arg: &'a [u8], label: &str) -> Result<&'a str, String> {
    std::str::from_utf8(arg).map_err(|_| format!("ERR {label} is not valid UTF-8"))
}

#[cfg(test)]
mod distributed_tests {
    use super::*;
    use std::sync::Arc;

    fn cache() -> SharedSchemaCache {
        Arc::new(parking_lot::RwLock::new(SchemaCache::new()))
    }

    #[test]
    fn scan_catalog_is_bound_to_argv_and_distributed_joins_fail_closed() {
        let store = Store::new();
        let cache = cache();
        let now = Instant::now();
        table_create(
            &store,
            &cache,
            "orders",
            &["id STR PRIMARY KEY,", "amount INT"],
            now,
        )
        .unwrap();
        table_create(
            &store,
            &cache,
            "customers",
            &["id STR PRIMARY KEY,", "name STR"],
            now,
        )
        .unwrap();
        let catalog = export_cluster_table_catalog(&store, &cache, "orders", now).unwrap();

        assert!(validate_cluster_table_scan(&catalog, &[b"TCOUNT", b"orders"]).is_ok());
        assert!(
            validate_cluster_table_scan(&catalog, &[b"TCOUNT", b"customers"])
                .unwrap_err()
                .contains("does not match")
        );
        let join = [
            b"TSELECT".as_slice(),
            b"*",
            b"FROM",
            b"orders",
            b"o",
            b"JOIN",
            b"customers",
            b"c",
            b"ON",
            b"o.id",
            b"=",
            b"c.id",
        ];
        assert!(cluster_table_scan_table(&join)
            .unwrap_err()
            .contains("distributed JOIN"));
    }

    #[test]
    fn scan_merge_rejects_missing_or_wrong_partial_types() {
        assert!(
            merge_cluster_table_scans(&[b"TCOUNT", b"orders"], Vec::new())
                .err()
                .unwrap()
                .contains("no participating nodes")
        );
        assert!(merge_cluster_table_scans(
            &[b"TCOUNT", b"orders"],
            vec![crate::cluster::TableScanPartial::Rows(Vec::new())],
        )
        .err()
        .unwrap()
        .contains("wrong table scan result"));
    }

    #[test]
    fn point_mutation_routing_accepts_rls_and_but_not_or_only_primary_key() {
        let store = Store::new();
        let cache = cache();
        let now = Instant::now();
        table_create(
            &store,
            &cache,
            "orders",
            &["id STR PRIMARY KEY,", "owner STR,", "status STR"],
            now,
        )
        .unwrap();

        let update = [
            b"TUPDATE".as_slice(),
            b"orders",
            b"SET",
            b"status",
            b"paid",
            b"WHERE",
            b"id",
            b"=",
            b"order-1",
            b"AND",
            b"owner",
            b"=",
            b"user-1",
            b"RETURNING",
            b"*",
        ];
        let prepared = prepare_cluster_table_command(&store, &cache, &update, now)
            .unwrap()
            .unwrap();
        assert_eq!(prepared.primary_key, b"order-1");

        let delete = [
            b"TDELETE".as_slice(),
            b"FROM",
            b"orders",
            b"WHERE",
            b"owner",
            b"=",
            b"user-1",
            b"AND",
            b"id",
            b"=",
            b"order-1",
            b"RETURNING",
            b"*",
        ];
        let prepared = prepare_cluster_table_command(&store, &cache, &delete, now)
            .unwrap()
            .unwrap();
        assert_eq!(prepared.primary_key, b"order-1");

        let or_only = [
            b"TDELETE".as_slice(),
            b"FROM",
            b"orders",
            b"WHERE",
            b"owner",
            b"=",
            b"user-1",
            b"OR",
            b"id",
            b"=",
            b"order-1",
        ];
        let error = match prepare_cluster_table_command(&store, &cache, &or_only, now) {
            Ok(_) => panic!("OR-only primary-key predicate must not be routable"),
            Err(error) => error,
        };
        assert!(error.contains("as an AND condition"));
    }
}
