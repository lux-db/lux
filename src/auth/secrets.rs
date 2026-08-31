use std::collections::HashMap;
use std::time::Instant;

use crate::store::Store;
use crate::tables::{self, SelectPlan, SelectResult, SharedSchemaCache};

use super::{
    durable_table_insert, durable_table_update_where, find_row_by_field, unix_seconds,
    AuthSecretStorageHealth, AuthSecretStorageStatus, PROVIDERS_TABLE, SETTINGS_TABLE,
    SIGNING_KEYS_TABLE,
};

pub(super) const EMAIL_POSTMARK_TOKEN_KEY: &str = "email_postmark_server_token";
const STORAGE_VERSION_KEY: &str = "auth_secret_storage_version";
const STORAGE_VERSION_PENDING: &str = "pending_v1";
const STORAGE_VERSION_CURRENT: &str = "1";
const KEY_CONFIGURATION_GUIDANCE: &str = "configure LUX_ENC_AUTO_INIT=1 (and LUX_ENC_SEAL_KEY in production) or supply LUX_ENCRYPTION_KEY/LUX_ENCRYPTION_KEYS; during rotation, retain prior data keys until ENC REWRAP completes";

#[derive(Debug)]
pub(super) struct MigrationOutcome {
    pub(super) checkpoint_required: bool,
}

pub(super) fn health(store: &Store) -> AuthSecretStorageHealth {
    let persistent = store.config().durability.policy.is_persistent();
    if !store.config().auth.enabled {
        return AuthSecretStorageHealth {
            status: AuthSecretStorageStatus::Disabled,
            mode: "disabled",
            persistent,
            snapshots_allowed: true,
            message: None,
        };
    }
    if store.auth_secret_storage_degraded() {
        return AuthSecretStorageHealth {
            status: AuthSecretStorageStatus::Degraded,
            mode: "ephemeral_plaintext",
            persistent,
            snapshots_allowed: false,
            message: Some(
                "development only: Auth secrets are held in plaintext memory and cannot be exported; configure encryption before restarting, which discards the current Auth state",
            ),
        };
    }
    if store.encryption().has_active_key() {
        return AuthSecretStorageHealth {
            status: AuthSecretStorageStatus::Ready,
            mode: "encrypted",
            persistent,
            snapshots_allowed: true,
            message: None,
        };
    }
    if persistent {
        AuthSecretStorageHealth {
            status: AuthSecretStorageStatus::Locked,
            mode: "unavailable",
            persistent,
            snapshots_allowed: false,
            message: Some(
                "persistent Auth is locked until a usable Lux encryption key is configured",
            ),
        }
    } else {
        AuthSecretStorageHealth {
            status: AuthSecretStorageStatus::Degraded,
            mode: "ephemeral_plaintext",
            persistent,
            snapshots_allowed: false,
            message: Some(
                "development only: Auth secrets are held in plaintext memory and cannot be exported; configure encryption before restarting, which discards the current Auth state",
            ),
        }
    }
}

/// Seal one auth secret with the Engine's versioned, location-bound envelope.
///
/// Ephemeral runtimes may temporarily retain plaintext in memory. Persistent
/// runtimes never accept a new plaintext secret when no active key exists.
pub(super) fn seal(
    store: &Store,
    table: &str,
    field: &str,
    primary_key: &str,
    plaintext: &str,
) -> Result<String, String> {
    if plaintext.is_empty() {
        return Ok(String::new());
    }
    if !store.encryption().has_active_key() {
        if !store.config().durability.policy.is_persistent() {
            return Ok(plaintext.to_string());
        }
        return Err(format!(
            "ERR persistent auth secrets require an active Lux encryption key; {KEY_CONFIGURATION_GUIDANCE}"
        ));
    }
    let sealed = store
        .encryption()
        .seal(table, field, primary_key, plaintext.as_bytes())?;
    String::from_utf8(sealed).map_err(|error| format!("ERR auth secret seal failed: {error}"))
}

/// Open one auth secret and verify that its envelope belongs to this exact row
/// and field. Persistent plaintext is refused even if it survived from an old
/// release; startup migration must seal it before normal reads begin.
pub(super) fn open(
    store: &Store,
    table: &str,
    field: &str,
    primary_key: &str,
    stored: &str,
) -> Result<String, String> {
    if stored.is_empty() {
        return Ok(String::new());
    }
    if !looks_like_envelope(stored) {
        if !store.config().durability.policy.is_persistent() {
            return Ok(stored.to_string());
        }
        return Err(format!(
            "ERR refusing plaintext persistent auth secret at {table}.{field}; {KEY_CONFIGURATION_GUIDANCE}"
        ));
    }
    let plaintext = store
        .encryption()
        .unseal(table, field, primary_key, stored.as_bytes())
        .map_err(|error| {
            format!(
                "ERR auth secret storage is locked at {table}.{field}: {}; {KEY_CONFIGURATION_GUIDANCE}, or restore the intact value from backup",
                error.trim_start_matches("ERR ")
            )
        })?;
    String::from_utf8(plaintext)
        .map_err(|error| format!("ERR auth secret is not valid UTF-8: {error}"))
}

/// Upgrade every legacy plaintext auth secret after snapshot/WAL recovery.
/// Each field replacement is one journaled table mutation: a crash can leave a
/// partially migrated set, but never a partially written value, and the next
/// startup resumes from the remaining plaintext fields.
pub(super) fn migrate_storage(
    store: &Store,
    cache: &SharedSchemaCache,
    now: Instant,
) -> Result<MigrationOutcome, String> {
    let marker = find_row_by_field(
        store,
        cache,
        SETTINGS_TABLE,
        "key",
        STORAGE_VERSION_KEY,
        now,
    )?
    .and_then(|row| row.get("value").cloned());
    if marker
        .as_deref()
        .is_some_and(|value| value != STORAGE_VERSION_CURRENT && value != STORAGE_VERSION_PENDING)
    {
        return Err(format!(
            "ERR unsupported auth secret storage version {}",
            marker.as_deref().unwrap_or_default()
        ));
    }

    let mut fields = Vec::new();
    for row in all_rows(store, cache, SIGNING_KEYS_TABLE, now)? {
        fields.push((
            SIGNING_KEYS_TABLE,
            "id",
            row.get("id").cloned().unwrap_or_default(),
            "private_key_encrypted",
            row.get("private_key_encrypted")
                .cloned()
                .unwrap_or_default(),
        ));
    }

    for row in all_rows(store, cache, PROVIDERS_TABLE, now)? {
        let provider = row.get("provider").cloned().unwrap_or_default();
        if provider.is_empty() {
            continue;
        }
        for field in ["client_secret", "apple_private_key"] {
            fields.push((
                PROVIDERS_TABLE,
                "provider",
                provider.clone(),
                field,
                row.get(field).cloned().unwrap_or_default(),
            ));
        }
    }

    if let Some(row) = find_row_by_field(
        store,
        cache,
        SETTINGS_TABLE,
        "key",
        EMAIL_POSTMARK_TOKEN_KEY,
        now,
    )? {
        fields.push((
            SETTINGS_TABLE,
            "key",
            EMAIL_POSTMARK_TOKEN_KEY.to_string(),
            "value",
            row.get("value").cloned().unwrap_or_default(),
        ));
    }

    // A missing version marker on an existing Auth installation means the live
    // snapshot or journal can still contain the legacy plaintext values even
    // when the final replayed row is already sealed. Record the pending state
    // before the first replacement so a crash cannot lose the requirement to
    // checkpoint that history before listener readiness.
    let has_existing_secret = fields.iter().any(|(_, _, _, _, stored)| !stored.is_empty());
    let has_plaintext = fields
        .iter()
        .any(|(_, _, _, _, stored)| !stored.is_empty() && !looks_like_envelope(stored));
    let checkpoint_required = marker.as_deref() == Some(STORAGE_VERSION_PENDING)
        || has_plaintext
        || (marker.is_none() && has_existing_secret);
    if checkpoint_required && marker.as_deref() != Some(STORAGE_VERSION_PENDING) {
        write_storage_version(store, cache, STORAGE_VERSION_PENDING, now)?;
    }

    for (table, primary_key_field, primary_key, field, stored) in fields {
        migrate_row_field(
            store,
            cache,
            table,
            primary_key_field,
            &primary_key,
            field,
            &stored,
            now,
        )?;
    }
    if checkpoint_required {
        for (table, field) in [
            (SIGNING_KEYS_TABLE, "private_key_encrypted"),
            (PROVIDERS_TABLE, "client_secret"),
            (PROVIDERS_TABLE, "apple_private_key"),
            (SETTINGS_TABLE, "value"),
        ] {
            tables::purge_string_field_indexes(store, table, field, now);
        }
    }
    Ok(MigrationOutcome {
        checkpoint_required,
    })
}

pub(super) fn mark_storage_current(
    store: &Store,
    cache: &SharedSchemaCache,
    now: Instant,
) -> Result<(), String> {
    write_storage_version(store, cache, STORAGE_VERSION_CURRENT, now)
}

fn write_storage_version(
    store: &Store,
    cache: &SharedSchemaCache,
    value: &str,
    now: Instant,
) -> Result<(), String> {
    let updated_at = unix_seconds().to_string();
    if find_row_by_field(
        store,
        cache,
        SETTINGS_TABLE,
        "key",
        STORAGE_VERSION_KEY,
        now,
    )?
    .is_some()
    {
        durable_table_update_where(
            store,
            cache,
            SETTINGS_TABLE,
            &[("value", value), ("updated_at", updated_at.as_str())],
            &["key", "=", STORAGE_VERSION_KEY],
            now,
        )?;
    } else {
        durable_table_insert(
            store,
            cache,
            SETTINGS_TABLE,
            &[
                ("key", STORAGE_VERSION_KEY),
                ("value", value),
                ("updated_at", updated_at.as_str()),
            ],
            now,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn migrate_row_field(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    primary_key_field: &str,
    primary_key: &str,
    field: &str,
    stored: &str,
    now: Instant,
) -> Result<(), String> {
    if stored.is_empty() {
        return Ok(());
    }
    if looks_like_envelope(stored) {
        open(store, table, field, primary_key, stored)?;
        return Ok(());
    }
    if !store.encryption().has_active_key() {
        if store.config().durability.policy.is_persistent() {
            return Err(format!(
                "ERR legacy plaintext auth secret at {table}.{field} requires an active Lux encryption key for migration; {KEY_CONFIGURATION_GUIDANCE}"
            ));
        }
        return Ok(());
    }
    let replacement = seal(store, table, field, primary_key, stored)?;
    durable_table_update_where(
        store,
        cache,
        table,
        &[(field, replacement.as_str())],
        &[primary_key_field, "=", primary_key],
        now,
    )?;
    Ok(())
}

fn looks_like_envelope(stored: &str) -> bool {
    crate::encryption::EncryptionKeyring::has_encrypted_value_prefix(stored.as_bytes())
}

fn all_rows(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    now: Instant,
) -> Result<Vec<HashMap<String, String>>, String> {
    let plan = SelectPlan {
        table: table.to_string(),
        alias: None,
        projections: Vec::new(),
        aggregates: Vec::new(),
        joins: Vec::new(),
        conditions: Vec::new(),
        group_by: Vec::new(),
        having: Vec::new(),
        near: None,
        order_by: None,
        limit: None,
        offset: None,
        decrypt_authorized: true,
    };
    match tables::table_select(store, cache, &plan, now)? {
        SelectResult::Rows(rows) => Ok(rows
            .into_iter()
            .map(|row| row.into_iter().collect())
            .collect()),
        SelectResult::Aggregate(_) => Err("ERR auth secret migration expected rows".to_string()),
    }
}
