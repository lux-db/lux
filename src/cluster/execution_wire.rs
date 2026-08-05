use super::execution::{
    ExecutionApiKeyKind, ExecutionAuth, ExecutionGrantScope, ExecutionJwtKey, ExecutionManifest,
    ExecutionPrincipalBlockKind, ExecutionTable, CLUSTER_EXECUTION_SCHEMA_VERSION,
};
use super::{ClusterError, CLUSTER_PROTOCOL_VERSION};
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::DecodingKey;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

const MAX_EXECUTION_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;
const MAX_TABLES: usize = 4096;
const MAX_FIELDS_PER_TABLE: usize = 512;
const MAX_PATH_INDEXES_PER_TABLE: usize = 512;
const MAX_GRANTS: usize = 8192;
const MAX_API_KEYS: usize = 1024;
const MAX_JWT_KEYS: usize = 32;
const MAX_REVOCATIONS: usize = 1_000_000;
const MAX_NAME_BYTES: usize = 256;
const MAX_FIELD_DEFINITION_BYTES: usize = 4096;
const MAX_PREDICATE_BYTES: usize = 64 * 1024;
const MAX_JWK_BYTES: usize = 16 * 1024;

pub(super) fn execution_content_eq(left: &ExecutionManifest, right: &ExecutionManifest) -> bool {
    left.schema_version == right.schema_version
        && left.protocol_version == right.protocol_version
        && left.cluster_id == right.cluster_id
        && left.encryption_keyring_digest == right.encryption_keyring_digest
        && left.tables == right.tables
        && left.auth == right.auth
}

pub(super) fn manifest_digest(manifest: &ExecutionManifest) -> Result<String, ClusterError> {
    Ok(hex_digest(&Sha256::digest(canonical_manifest_bytes(
        manifest,
    )?)))
}

pub(super) fn canonical_manifest_bytes(
    manifest: &ExecutionManifest,
) -> Result<Vec<u8>, ClusterError> {
    let mut bytes = Vec::with_capacity(4096);
    bytes.extend_from_slice(b"LUX-PROJECT-CLUSTER-EXECUTION\0");
    bytes.extend_from_slice(&manifest.schema_version.to_be_bytes());
    bytes.extend_from_slice(&manifest.protocol_version.to_be_bytes());
    push_string(&mut bytes, &manifest.cluster_id)?;
    bytes.extend_from_slice(&manifest.version.to_be_bytes());
    push_optional_string(&mut bytes, manifest.previous_digest.as_deref())?;
    push_optional_string(&mut bytes, manifest.encryption_keyring_digest.as_deref())?;
    push_len(&mut bytes, manifest.tables.len())?;
    for table in &manifest.tables {
        push_string(&mut bytes, &table.name)?;
        push_optional_string(&mut bytes, table.primary_key.as_deref())?;
        push_len(&mut bytes, table.fields.len())?;
        for field in &table.fields {
            push_string(&mut bytes, &field.name)?;
            push_string(&mut bytes, &field.definition)?;
        }
        push_len(&mut bytes, table.path_indexes.len())?;
        for index in &table.path_indexes {
            push_string(&mut bytes, &index.path)?;
            push_string(&mut bytes, &index.field_type)?;
        }
        match table.default_ttl_seconds {
            Some(ttl) => {
                bytes.push(1);
                bytes.extend_from_slice(&ttl.to_be_bytes());
            }
            None => bytes.push(0),
        }
    }
    bytes.push(u8::from(manifest.auth.enabled));
    push_string(&mut bytes, &manifest.auth.issuer)?;
    bytes.extend_from_slice(&manifest.auth.access_token_ttl_seconds.to_be_bytes());
    push_len(&mut bytes, manifest.auth.api_keys.len())?;
    for key in &manifest.auth.api_keys {
        push_string(&mut bytes, &key.digest)?;
        bytes.push(match key.kind {
            ExecutionApiKeyKind::Publishable => 0,
            ExecutionApiKeyKind::Secret => 1,
        });
    }
    push_len(&mut bytes, manifest.auth.jwt_keys.len())?;
    for key in &manifest.auth.jwt_keys {
        push_string(&mut bytes, &key.kid)?;
        push_string(&mut bytes, &key.public_jwk)?;
    }
    push_len(&mut bytes, manifest.auth.grants.len())?;
    for grant in &manifest.auth.grants {
        push_string(&mut bytes, &grant.table)?;
        bytes.push(match grant.scope {
            ExecutionGrantScope::Read => 0,
            ExecutionGrantScope::Write => 1,
        });
        push_string(&mut bytes, &grant.predicate)?;
    }
    push_len(&mut bytes, manifest.auth.session_revocations.len())?;
    for revocation in &manifest.auth.session_revocations {
        push_string(&mut bytes, &revocation.session_id)?;
        bytes.extend_from_slice(&revocation.revoked_after.to_be_bytes());
        bytes.extend_from_slice(&revocation.retain_until.to_be_bytes());
    }
    push_len(&mut bytes, manifest.auth.principal_blocks.len())?;
    for block in &manifest.auth.principal_blocks {
        push_string(&mut bytes, &block.user_id)?;
        bytes.push(match block.kind {
            ExecutionPrincipalBlockKind::Banned => 0,
            ExecutionPrincipalBlockKind::Deleted => 1,
        });
        bytes.extend_from_slice(&block.blocked_at.to_be_bytes());
        match block.blocked_until {
            Some(blocked_until) => {
                bytes.push(1);
                bytes.extend_from_slice(&blocked_until.to_be_bytes());
            }
            None => bytes.push(0),
        }
        bytes.extend_from_slice(&block.retain_until.to_be_bytes());
    }
    if bytes.len() > MAX_EXECUTION_PAYLOAD_BYTES {
        return invalid("canonical execution metadata exceeds the size limit");
    }
    Ok(bytes)
}

fn push_string(bytes: &mut Vec<u8>, value: &str) -> Result<(), ClusterError> {
    push_len(bytes, value.len())?;
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

fn push_optional_string(bytes: &mut Vec<u8>, value: Option<&str>) -> Result<(), ClusterError> {
    match value {
        Some(value) => {
            bytes.push(1);
            push_string(bytes, value)
        }
        None => {
            bytes.push(0);
            Ok(())
        }
    }
}

fn push_len(bytes: &mut Vec<u8>, length: usize) -> Result<(), ClusterError> {
    let length = u32::try_from(length).map_err(|_| {
        ClusterError::InvalidExecution("canonical field exceeds u32 length".to_owned())
    })?;
    bytes.extend_from_slice(&length.to_be_bytes());
    Ok(())
}

pub(super) fn validate_manifest(manifest: &ExecutionManifest) -> Result<(), ClusterError> {
    validate_manifest_bounds(manifest)?;
    if manifest.schema_version != CLUSTER_EXECUTION_SCHEMA_VERSION {
        return invalid(format!(
            "unsupported execution schema {}",
            manifest.schema_version
        ));
    }
    if manifest.protocol_version != CLUSTER_PROTOCOL_VERSION {
        return invalid(format!(
            "unsupported cluster protocol {}",
            manifest.protocol_version
        ));
    }
    validate_identifier("cluster_id", &manifest.cluster_id)?;
    if manifest.version == 0 {
        return invalid("execution version must be greater than zero");
    }
    match (manifest.version, manifest.previous_digest.as_deref()) {
        (1, None) => {}
        (1, Some(_)) => return invalid("initial execution metadata cannot have a predecessor"),
        (_, Some(digest)) if valid_digest(digest) => {}
        _ => return invalid("execution metadata must name a valid predecessor digest"),
    }
    if manifest
        .encryption_keyring_digest
        .as_deref()
        .is_some_and(|digest| !valid_digest(digest))
    {
        return invalid("encryption keyring digest must be lowercase SHA-256");
    }
    if manifest.tables.len() > MAX_TABLES {
        return invalid(format!("execution metadata exceeds {MAX_TABLES} tables"));
    }
    if !manifest
        .tables
        .windows(2)
        .all(|tables| tables[0].name < tables[1].name)
    {
        return invalid("execution tables must be uniquely sorted by name");
    }
    let mut table_schemas = HashMap::new();
    let mut encrypted_schema = false;
    for table in &manifest.tables {
        validate_table_name(&table.name)?;
        if table.name.starts_with("auth.") || table.name.starts_with("push.") {
            return invalid(format!(
                "reserved table {} cannot enter owner execution metadata",
                table.name
            ));
        }
        table_schemas.insert(table.name.as_str(), table);
        validate_table(table, &mut encrypted_schema)?;
    }
    if encrypted_schema && manifest.encryption_keyring_digest.is_none() {
        return invalid("encrypted schemas require an encryption keyring digest");
    }
    validate_table_dependencies(&manifest.tables, &table_schemas)?;
    validate_auth(&manifest.auth, &table_schemas)?;
    Ok(())
}

pub(super) fn validate_manifest_bounds(manifest: &ExecutionManifest) -> Result<(), ClusterError> {
    if manifest.tables.len() > MAX_TABLES
        || manifest.auth.api_keys.len() > MAX_API_KEYS
        || manifest.auth.jwt_keys.len() > MAX_JWT_KEYS
        || manifest.auth.grants.len() > MAX_GRANTS
        || manifest.auth.session_revocations.len() > MAX_REVOCATIONS
        || manifest.auth.principal_blocks.len() > MAX_REVOCATIONS
    {
        return invalid("execution metadata exceeds a collection limit");
    }
    let mut bytes = 128_usize;
    add_bounded(&mut bytes, manifest.cluster_id.len())?;
    add_bounded(
        &mut bytes,
        manifest.previous_digest.as_ref().map_or(0, String::len),
    )?;
    add_bounded(
        &mut bytes,
        manifest
            .encryption_keyring_digest
            .as_ref()
            .map_or(0, String::len),
    )?;
    for table in &manifest.tables {
        if table.fields.len() > MAX_FIELDS_PER_TABLE
            || table.path_indexes.len() > MAX_PATH_INDEXES_PER_TABLE
        {
            return invalid("execution table exceeds a collection limit");
        }
        add_bounded(&mut bytes, table.name.len())?;
        add_bounded(
            &mut bytes,
            table.primary_key.as_ref().map_or(0, String::len),
        )?;
        for field in &table.fields {
            if field.definition.len() > MAX_FIELD_DEFINITION_BYTES {
                return invalid("execution field definition exceeds the size limit");
            }
            add_bounded(&mut bytes, field.name.len())?;
            add_bounded(&mut bytes, field.definition.len())?;
        }
        for index in &table.path_indexes {
            add_bounded(&mut bytes, index.path.len())?;
            add_bounded(&mut bytes, index.field_type.len())?;
        }
    }
    add_bounded(&mut bytes, manifest.auth.issuer.len())?;
    for key in &manifest.auth.api_keys {
        add_bounded(&mut bytes, key.digest.len())?;
    }
    for key in &manifest.auth.jwt_keys {
        if key.public_jwk.len() > MAX_JWK_BYTES {
            return invalid("execution JWT key exceeds the size limit");
        }
        add_bounded(&mut bytes, key.kid.len())?;
        add_bounded(&mut bytes, key.public_jwk.len())?;
    }
    for grant in &manifest.auth.grants {
        if grant.predicate.len() > MAX_PREDICATE_BYTES {
            return invalid("execution grant exceeds the size limit");
        }
        add_bounded(&mut bytes, grant.table.len())?;
        add_bounded(&mut bytes, grant.predicate.len())?;
    }
    for entry in &manifest.auth.session_revocations {
        add_bounded(&mut bytes, entry.session_id.len())?;
    }
    for entry in &manifest.auth.principal_blocks {
        add_bounded(&mut bytes, entry.user_id.len())?;
    }
    Ok(())
}

fn add_bounded(total: &mut usize, length: usize) -> Result<(), ClusterError> {
    *total = total
        .checked_add(length)
        .and_then(|value| value.checked_add(8))
        .ok_or_else(|| {
            ClusterError::InvalidExecution("execution metadata size overflows".to_owned())
        })?;
    if *total > MAX_EXECUTION_PAYLOAD_BYTES {
        return invalid("execution metadata exceeds the size limit");
    }
    Ok(())
}

fn validate_table(table: &ExecutionTable, encrypted_schema: &mut bool) -> Result<(), ClusterError> {
    if let Some(primary_key) = &table.primary_key {
        validate_name("primary key", primary_key)?;
    }
    if table.fields.is_empty() || table.fields.len() > MAX_FIELDS_PER_TABLE {
        return invalid(format!(
            "table {} must contain 1 to {MAX_FIELDS_PER_TABLE} fields",
            table.name
        ));
    }
    if !table
        .fields
        .windows(2)
        .all(|fields| fields[0].name < fields[1].name)
    {
        return invalid(format!(
            "table {} fields must be uniquely sorted by name",
            table.name
        ));
    }
    let mut declared_primary_key = None;
    for field in &table.fields {
        validate_name("field", &field.name)?;
        if field.definition.is_empty()
            || field.definition.len() > MAX_FIELD_DEFINITION_BYTES
            || field.definition.chars().any(char::is_control)
        {
            return invalid(format!(
                "table {} field {} has an invalid durable definition",
                table.name, field.name
            ));
        }
        let decoded = crate::tables::decode_field_def(&field.name, &field.definition);
        if crate::tables::encode_field_def(&decoded) != field.definition {
            return invalid(format!(
                "table {} field {} definition is not canonical",
                table.name, field.name
            ));
        }
        if decoded.primary_key && declared_primary_key.replace(field.name.as_str()).is_some() {
            return invalid(format!(
                "table {} has more than one declared primary key",
                table.name
            ));
        }
        *encrypted_schema |= decoded.encrypted;
    }
    if declared_primary_key != table.primary_key.as_deref() {
        return invalid(format!(
            "table {} primary-key projection does not match its field definitions",
            table.name
        ));
    }
    if table.path_indexes.len() > MAX_PATH_INDEXES_PER_TABLE
        || !table
            .path_indexes
            .windows(2)
            .all(|indexes| indexes[0].path < indexes[1].path)
    {
        return invalid(format!(
            "table {} path indexes must be bounded and uniquely sorted",
            table.name
        ));
    }
    for index in &table.path_indexes {
        validate_path_index(table, index)?;
    }
    if table.default_ttl_seconds == Some(0) {
        return invalid(format!("table {} has a zero default TTL", table.name));
    }
    Ok(())
}

fn validate_path_index(
    table: &ExecutionTable,
    index: &super::execution::ExecutionPathIndex,
) -> Result<(), ClusterError> {
    validate_path(&index.path)?;
    if !matches!(
        index.field_type.as_str(),
        "bool" | "float" | "int" | "str" | "timestamp"
    ) {
        return invalid(format!(
            "table {} path index {} has an invalid type",
            table.name, index.path
        ));
    }
    let root = index.path.split_once('.').map_or("", |(root, _)| root);
    let root_field = table
        .fields
        .iter()
        .find(|field| field.name == root)
        .ok_or_else(|| {
            ClusterError::InvalidExecution(format!(
                "table {} path index {} has no root field",
                table.name, index.path
            ))
        })?;
    let root_definition = crate::tables::decode_field_def(&root_field.name, &root_field.definition);
    if root_definition.encrypted
        || !matches!(
            root_definition.field_type,
            crate::tables::FieldType::Json | crate::tables::FieldType::Array
        )
    {
        return invalid(format!(
            "table {} path index {} has an ineligible root field",
            table.name, index.path
        ));
    }
    Ok(())
}

fn validate_table_dependencies(
    tables: &[ExecutionTable],
    table_schemas: &HashMap<&str, &ExecutionTable>,
) -> Result<(), ClusterError> {
    for table in tables {
        for field in &table.fields {
            let decoded = crate::tables::decode_field_def(&field.name, &field.definition);
            let referenced_table = decoded
                .references
                .as_ref()
                .map(|foreign| foreign.table.as_str());
            let legacy_reference = match &decoded.field_type {
                crate::tables::FieldType::Ref(table) => Some(table.as_str()),
                _ => None,
            };
            for dependency in referenced_table.into_iter().chain(legacy_reference) {
                if !dependency.starts_with("auth.")
                    && !dependency.starts_with("push.")
                    && !table_schemas.contains_key(dependency)
                {
                    return invalid(format!(
                        "table {} field {} references unknown table {}",
                        table.name, field.name, dependency
                    ));
                }
            }
        }
    }
    Ok(())
}

fn validate_auth(
    auth: &ExecutionAuth,
    tables: &HashMap<&str, &ExecutionTable>,
) -> Result<(), ClusterError> {
    if auth.issuer.len() > 2048 {
        return invalid("auth issuer is too large");
    }
    if auth.enabled {
        validate_issuer(&auth.issuer)?;
        if auth.access_token_ttl_seconds == 0 {
            return invalid("enabled auth requires a nonzero access-token TTL");
        }
        if auth.jwt_keys.is_empty() {
            return invalid("enabled auth requires at least one public ES256 key");
        }
    } else if !auth.issuer.is_empty()
        || auth.access_token_ttl_seconds != 0
        || !auth.jwt_keys.is_empty()
        || !auth.grants.is_empty()
        || !auth.session_revocations.is_empty()
        || !auth.principal_blocks.is_empty()
    {
        return invalid("disabled auth cannot carry user execution state");
    }
    if auth.api_keys.len() > MAX_API_KEYS
        || !auth
            .api_keys
            .windows(2)
            .all(|keys| keys[0].digest < keys[1].digest)
        || auth.api_keys.iter().any(|key| !valid_digest(&key.digest))
    {
        return invalid("API key digests must be bounded, unique, sorted lowercase SHA-256");
    }
    if auth.jwt_keys.len() > MAX_JWT_KEYS
        || !auth
            .jwt_keys
            .windows(2)
            .all(|keys| keys[0].kid < keys[1].kid)
    {
        return invalid("JWT keys must be bounded and uniquely sorted by kid");
    }
    for key in &auth.jwt_keys {
        validate_identifier("JWT kid", &key.kid)?;
        validate_public_jwk(key)?;
    }
    if auth.grants.len() > MAX_GRANTS
        || !auth
            .grants
            .windows(2)
            .all(|grants| (&grants[0].table, grants[0].scope) < (&grants[1].table, grants[1].scope))
    {
        return invalid("grants must be bounded and uniquely sorted by table and scope");
    }
    for grant in &auth.grants {
        if !tables.contains_key(grant.table.as_str()) {
            return invalid(format!("grant references unknown table {}", grant.table));
        }
        if grant.predicate.len() > MAX_PREDICATE_BYTES {
            return invalid(format!("grant on {} is too large", grant.table));
        }
        let tokens = grant.predicate.split_whitespace().collect::<Vec<_>>();
        let predicate = crate::grants::parse_predicate(&tokens).map_err(|error| {
            ClusterError::InvalidExecution(format!("grant on {} is invalid: {error}", grant.table))
        })?;
        if crate::grants::predicate_to_string(&predicate) != grant.predicate {
            return invalid(format!("grant on {} is not canonical", grant.table));
        }
        validate_grant_dependencies(&predicate, &grant.table, tables, 0)?;
    }
    validate_revocations(auth)?;
    Ok(())
}

fn validate_revocations(auth: &ExecutionAuth) -> Result<(), ClusterError> {
    if auth.session_revocations.len() > MAX_REVOCATIONS
        || !auth
            .session_revocations
            .windows(2)
            .all(|entries| entries[0].session_id < entries[1].session_id)
    {
        return invalid("session revocations must be bounded and uniquely sorted");
    }
    for entry in &auth.session_revocations {
        validate_identifier("session_id", &entry.session_id)?;
        let minimum_retention = entry
            .revoked_after
            .checked_add(auth.access_token_ttl_seconds)
            .ok_or_else(|| {
                ClusterError::InvalidExecution(format!(
                    "session {} revocation retention overflows",
                    entry.session_id
                ))
            })?;
        if entry.retain_until < minimum_retention {
            return invalid(format!(
                "session {} is not retained for the full access-token lifetime",
                entry.session_id
            ));
        }
    }
    if auth.principal_blocks.len() > MAX_REVOCATIONS
        || !auth
            .principal_blocks
            .windows(2)
            .all(|entries| entries[0].user_id < entries[1].user_id)
    {
        return invalid("principal blocks must be bounded and uniquely sorted");
    }
    for entry in &auth.principal_blocks {
        validate_identifier("user_id", &entry.user_id)?;
        let token_retention = entry
            .blocked_at
            .checked_add(auth.access_token_ttl_seconds)
            .ok_or_else(|| {
                ClusterError::InvalidExecution(format!(
                    "principal {} block retention overflows",
                    entry.user_id
                ))
            })?;
        if entry.retain_until < token_retention {
            return invalid(format!(
                "principal {} is not retained for the full access-token lifetime",
                entry.user_id
            ));
        }
        match (entry.kind, entry.blocked_until) {
            (ExecutionPrincipalBlockKind::Banned, Some(until))
                if until > entry.blocked_at && entry.retain_until >= until => {}
            (ExecutionPrincipalBlockKind::Deleted, None) => {}
            _ => {
                return invalid(format!(
                    "principal {} has inconsistent block metadata",
                    entry.user_id
                ))
            }
        }
    }
    Ok(())
}

fn validate_grant_dependencies(
    predicate: &crate::grants::Predicate,
    table_name: &str,
    tables: &HashMap<&str, &ExecutionTable>,
    depth: usize,
) -> Result<(), ClusterError> {
    let table = tables.get(table_name).ok_or_else(|| {
        ClusterError::InvalidExecution(format!("grant references unknown table {table_name}"))
    })?;
    for clause in predicate.clauses() {
        for condition in clause {
            match condition {
                crate::grants::Condition::Cmp { column, .. } => {
                    validate_grant_field(table, column)?;
                }
                crate::grants::Condition::InSubquery {
                    column, subquery, ..
                } => {
                    validate_grant_field(table, column)?;
                    if depth >= 32 {
                        return invalid("grant subquery nesting exceeds the execution limit");
                    }
                    let subquery_table = tables.get(subquery.table.as_str()).ok_or_else(|| {
                        ClusterError::InvalidExecution(format!(
                            "grant subquery references unknown table {}",
                            subquery.table
                        ))
                    })?;
                    validate_grant_field(subquery_table, &subquery.projected)?;
                    validate_grant_dependencies(
                        &subquery.inner,
                        &subquery.table,
                        tables,
                        depth + 1,
                    )?;
                }
            }
        }
    }
    Ok(())
}

fn validate_grant_field(table: &ExecutionTable, field: &str) -> Result<(), ClusterError> {
    let root = field.split('.').next().unwrap_or(field);
    if table.fields.iter().any(|candidate| candidate.name == root) {
        return Ok(());
    }
    invalid(format!(
        "grant references unknown field {}.{}",
        table.name, field
    ))
}

fn validate_public_jwk(key: &ExecutionJwtKey) -> Result<(), ClusterError> {
    if key.public_jwk.is_empty() || key.public_jwk.len() > MAX_JWK_BYTES {
        return invalid(format!("JWT key {} has an invalid size", key.kid));
    }
    let value = serde_json::from_str::<serde_json::Value>(&key.public_jwk)
        .map_err(|_| ClusterError::InvalidExecution(format!("JWT key {} is not JSON", key.kid)))?;
    let object = value.as_object().ok_or_else(|| {
        ClusterError::InvalidExecution(format!("JWT key {} is not an object", key.kid))
    })?;
    const PUBLIC_ES256_FIELDS: [&str; 7] = ["alg", "crv", "kid", "kty", "use", "x", "y"];
    if object
        .keys()
        .any(|field| !PUBLIC_ES256_FIELDS.contains(&field.as_str()))
    {
        return invalid(format!(
            "JWT key {} contains a non-public or unsupported field",
            key.kid
        ));
    }
    if object.get("kty").and_then(serde_json::Value::as_str) != Some("EC")
        || object.get("crv").and_then(serde_json::Value::as_str) != Some("P-256")
        || object.get("alg").and_then(serde_json::Value::as_str) != Some("ES256")
        || object.get("kid").and_then(serde_json::Value::as_str) != Some(key.kid.as_str())
        || object.get("use").and_then(serde_json::Value::as_str) != Some("sig")
    {
        return invalid(format!("JWT key {} is not canonical ES256", key.kid));
    }
    if serde_json::to_string(&value).ok().as_deref() != Some(key.public_jwk.as_str()) {
        return invalid(format!("JWT key {} JSON is not canonical", key.kid));
    }
    let jwk = serde_json::from_value::<Jwk>(value)
        .map_err(|_| ClusterError::InvalidExecution(format!("JWT key {} is invalid", key.kid)))?;
    DecodingKey::from_jwk(&jwk).map_err(|_| {
        ClusterError::InvalidExecution(format!("JWT key {} cannot verify tokens", key.kid))
    })?;
    Ok(())
}

fn validate_issuer(issuer: &str) -> Result<(), ClusterError> {
    let url = reqwest::Url::parse(issuer)
        .map_err(|_| ClusterError::InvalidExecution("auth issuer is not a URL".to_owned()))?;
    let host = url
        .host_str()
        .ok_or_else(|| ClusterError::InvalidExecution("auth issuer has no host".to_owned()))?;
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return invalid("non-loopback auth issuer must use HTTPS");
    }
    if url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return invalid("auth issuer cannot contain credentials, query, or fragment");
    }
    Ok(())
}

fn validate_identifier(label: &str, value: &str) -> Result<(), ClusterError> {
    if value.is_empty()
        || value.len() > MAX_NAME_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return invalid(format!("{label} is not a valid identifier"));
    }
    Ok(())
}

fn validate_name(label: &str, value: &str) -> Result<(), ClusterError> {
    if value.is_empty()
        || value.len() > MAX_NAME_BYTES
        || !value
            .chars()
            .all(|character| character.is_alphanumeric() || character == '_')
    {
        return invalid(format!("{label} is not a valid name"));
    }
    Ok(())
}

fn validate_table_name(value: &str) -> Result<(), ClusterError> {
    if value.is_empty()
        || value.len() > MAX_NAME_BYTES
        || !value
            .chars()
            .all(|character| character.is_alphanumeric() || matches!(character, '_' | '.'))
        || value.starts_with('.')
        || value.ends_with('.')
        || value.contains("..")
    {
        return invalid("table has an invalid namespace");
    }
    Ok(())
}

fn validate_path(value: &str) -> Result<(), ClusterError> {
    if value.len() > MAX_NAME_BYTES
        || value.split('.').count() < 2
        || value.split('.').any(|component| {
            component.is_empty()
                || !component
                    .chars()
                    .all(|character| character.is_alphanumeric() || character == '_')
        })
    {
        return invalid("path index has an invalid path");
    }
    Ok(())
}

fn valid_digest(value: &str) -> bool {
    decode_digest(value).is_some()
}

pub(super) fn decode_digest(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut decoded = [0_u8; 32];
    for (output, pair) in decoded.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        *output = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Some(decoded)
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn invalid<T>(message: impl Into<String>) -> Result<T, ClusterError> {
    Err(ClusterError::InvalidExecution(message.into()))
}
