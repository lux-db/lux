//! lux push: native push notifications. This module owns the engine-side
//! delivery pipeline as its own standalone, auth-independent scope: a device
//! registry (`push.devices`) keyed by an opaque `subject_id`, per-app push
//! credentials (`push.credentials`), a durable at-least-once delivery outbox
//! (`push.outbox`), and the background worker that drains it through platform
//! `Sink`s. A `subject_id` MAY be a Lux `auth.users.id` but doesn't have to be —
//! push works with Lux auth entirely off when managed by the secret key. APNs
//! and Web Push delivery share the same bounded worker and `Sink` seam.

pub(crate) mod apns;
pub(crate) mod webpush;
pub(crate) mod worker;

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::BytesMut;
use serde_json::{json, Value};

use crate::auth::{
    add_column_if_missing, create_table_if_missing, durable_table_delete_where,
    durable_table_insert, durable_table_update_where, find_row_by_field, random_id, unix_seconds,
};
use crate::resp;
use crate::store::Store;
use crate::tables::{
    self, CmpOp, Projection, SelectPlan, SelectResult, SharedSchemaCache, WhereClause,
};
use std::time::Instant;

/// Reserved `push.*` scope tables (protected + redacted by the shared reserved
/// machinery in `auth.rs`, but bootstrapped and owned here).
pub(crate) const DEVICES_TABLE: &str = "push.devices";
pub(crate) const CREDENTIALS_TABLE: &str = "push.credentials";
pub(crate) const OUTBOX_TABLE: &str = "push.outbox";

const MAX_SUBJECT_ID_BYTES: usize = 256;
const MAX_DEVICE_ID_BYTES: usize = 128;
const MAX_APP_ID_BYTES: usize = 128;
const MAX_APNS_TOKEN_BYTES: usize = 512;
const MAX_WEB_SUBSCRIPTION_BYTES: usize = 8 * 1024;
const MAX_SUBJECTS_PER_SEND: usize = 100;
const MAX_DEVICES_PER_SUBJECT: usize = 64;
const MAX_DEVICE_ROWS: usize = 100_000;
const MAX_DELIVERIES_PER_SEND: usize = 1_000;
const MAX_OUTBOX_ROWS: usize = 100_000;
const MAX_APNS_TEAM_ID_BYTES: usize = 128;
const MAX_APNS_KEY_ID_BYTES: usize = 128;
const MAX_APNS_TOPIC_BYTES: usize = 255;
const MAX_PROVIDER_PRIVATE_KEY_BYTES: usize = 16 * 1024;
const MAX_VAPID_PUBLIC_KEY_BYTES: usize = 512;
const MAX_VAPID_SUBJECT_BYTES: usize = 2_048;
pub(crate) const DEFAULT_PAGE_SIZE: usize = 100;
pub(crate) const MAX_PAGE_SIZE: usize = 1_000;
pub(crate) const MAX_PAGE_OFFSET: usize = 100_000;

/// Create the `push.*` tables if they don't exist. Called lazily on the first
/// write (register / set-credentials / send) so a project that never uses push
/// carries no `push.*` tables and no overhead. Idempotent + cheap thereafter
/// (a schema-cache hit). Push does not depend on Lux auth being enabled.
pub(crate) fn ensure_tables(
    store: &Store,
    cache: &SharedSchemaCache,
    now: Instant,
) -> Result<(), String> {
    create_table_if_missing(
        store,
        cache,
        DEVICES_TABLE,
        &[
            "id STR PRIMARY KEY,",
            // Opaque owner id. MAY be a Lux auth.users id; no FK, no existence
            // check. Set from auth.uid() on JWT self-register, or supplied
            // explicitly by a trusted secret-key caller.
            "subject_id STR,",
            "token STR,",
            "platform STR,",
            "app_id STR,",
            // Which APNs host this token was minted for. Apple issues sandbox
            // tokens to development builds and production tokens to TestFlight
            // and the App Store, and a token is only valid against its own host.
            // Empty means the registrant did not say, and delivery falls back to
            // the app credential's `environment`.
            "environment STR,",
            "created_at INT,",
            "last_seen_at INT,",
            "disabled_at INT",
        ],
        now,
    )?;
    // `environment` arrived after `push.devices` shipped, so projects that
    // registered a device on an older engine still have the original schema.
    add_column_if_missing(store, cache, DEVICES_TABLE, "environment STR", now)?;
    create_table_if_missing(
        store,
        cache,
        CREDENTIALS_TABLE,
        &[
            "app_id STR PRIMARY KEY,",
            "platform STR,",
            "apns_team_id STR,",
            "apns_key_id STR,",
            // Legacy plaintext columns remain readable for pre-encryption
            // projects. New writes go only to the ENCRYPTED replacements below.
            "apns_p8_pem STR,",
            "apns_topic STR,",
            "environment STR,",
            "vapid_public STR,",
            "vapid_private STR,",
            "vapid_subject STR,",
            "created_at INT",
        ],
        now,
    )?;
    ensure_encrypted_credential_columns(store, cache, now)?;
    create_table_if_missing(
        store,
        cache,
        OUTBOX_TABLE,
        &[
            "id STR PRIMARY KEY,",
            "subject_id STR,",
            "app_id STR,",
            "target_token STR,",
            "platform STR,",
            // Copied from the device at enqueue so the row still routes to the
            // right APNs host if the device re-registers or is deleted before
            // the worker drains it.
            "environment STR,",
            "payload STR,",
            "attempts INT,",
            "next_attempt_at INT,",
            "state STR,",
            "last_error STR,",
            "created_at INT",
        ],
        now,
    )?;
    add_column_if_missing(store, cache, OUTBOX_TABLE, "environment STR", now)?;
    Ok(())
}

fn ensure_encrypted_credential_columns(
    store: &Store,
    cache: &SharedSchemaCache,
    now: Instant,
) -> Result<(), String> {
    // Device registration and delivery remain usable without ENC, but provider
    // secrets may never be newly persisted in plaintext.
    if !store.encryption().has_active_key() {
        return Ok(());
    }
    add_column_if_missing(
        store,
        cache,
        CREDENTIALS_TABLE,
        "apns_p8_pem_encrypted STR ENCRYPTED",
        now,
    )?;
    add_column_if_missing(
        store,
        cache,
        CREDENTIALS_TABLE,
        "vapid_private_encrypted STR ENCRYPTED",
        now,
    )?;
    migrate_plaintext_credential_secrets(store, cache, now)
}

fn migrate_plaintext_credential_secrets(
    store: &Store,
    cache: &SharedSchemaCache,
    now: Instant,
) -> Result<(), String> {
    for row in select_rows(store, cache, CREDENTIALS_TABLE, Vec::new(), None, now)? {
        let fields: std::collections::HashMap<String, String> = row.into_iter().collect();
        let app_id = fields.get("app_id").cloned().unwrap_or_default();
        if app_id.is_empty() {
            continue;
        }
        let legacy_apns = fields.get("apns_p8_pem").cloned().unwrap_or_default();
        let encrypted_apns = fields
            .get("apns_p8_pem_encrypted")
            .cloned()
            .unwrap_or_default();
        if !legacy_apns.is_empty() && encrypted_apns.is_empty() {
            durable_table_update_where(
                store,
                cache,
                CREDENTIALS_TABLE,
                &[
                    ("apns_p8_pem_encrypted", legacy_apns.as_str()),
                    ("apns_p8_pem", ""),
                ],
                &["app_id", "=", app_id.as_str()],
                now,
            )?;
        }
        let legacy_vapid = fields.get("vapid_private").cloned().unwrap_or_default();
        let encrypted_vapid = fields
            .get("vapid_private_encrypted")
            .cloned()
            .unwrap_or_default();
        if !legacy_vapid.is_empty() && encrypted_vapid.is_empty() {
            durable_table_update_where(
                store,
                cache,
                CREDENTIALS_TABLE,
                &[
                    ("vapid_private_encrypted", legacy_vapid.as_str()),
                    ("vapid_private", ""),
                ],
                &["app_id", "=", app_id.as_str()],
                now,
            )?;
        }
    }
    Ok(())
}

/// One-time migration from the pre-`push.*` layout, where push data lived under
/// `auth.devices` / `auth.push_credentials` keyed by `user_id`. Copies any such
/// rows into the `push.*` scope (`user_id` -> `subject_id`). Idempotent (skips
/// rows already present) and a fast no-op when no legacy tables exist. All data
/// stays inside the engine — plaintext never leaves the store layer.
pub(crate) fn migrate_from_auth_scope(
    store: &Store,
    cache: &SharedSchemaCache,
    now: Instant,
) -> Result<(), String> {
    let legacy_creds = "auth.push_credentials";
    let legacy_devices = "auth.devices";
    let has_legacy = tables::table_schema(store, cache, legacy_creds, now).is_ok()
        || tables::table_schema(store, cache, legacy_devices, now).is_ok();
    if !has_legacy {
        return Ok(());
    }
    ensure_tables(store, cache, now)?;

    // Credentials: one row per app_id.
    for row in select_rows(store, cache, legacy_creds, Vec::new(), None, now)? {
        let m: std::collections::HashMap<String, String> = row.into_iter().collect();
        let app_id = m.get("app_id").cloned().unwrap_or_default();
        if app_id.is_empty()
            || find_row_by_field(store, cache, CREDENTIALS_TABLE, "app_id", &app_id, now)?.is_some()
        {
            continue;
        }
        let g = |k: &str| m.get(k).cloned().unwrap_or_default();
        let apns_private = g("apns_p8_pem");
        let vapid_private = g("vapid_private");
        if store.encryption().has_active_key() {
            if !apns_private.is_empty() {
                set_apns_credentials(
                    store,
                    cache,
                    &app_id,
                    &g("apns_team_id"),
                    &g("apns_key_id"),
                    &apns_private,
                    &g("apns_topic"),
                    &g("environment"),
                    now,
                )?;
            }
            if !vapid_private.is_empty() {
                set_vapid_credentials(
                    store,
                    cache,
                    &app_id,
                    &g("vapid_public"),
                    &vapid_private,
                    &g("vapid_subject"),
                    now,
                )?;
            }
        } else {
            // This copies already-plaintext legacy data; it is not a new secret
            // write surface. Reads report it unhealthy, and ensure_tables
            // migrates it into ENCRYPTED columns once ENC becomes available.
            upsert_credential_fields(
                store,
                cache,
                &app_id,
                &[
                    ("apns_team_id", g("apns_team_id").as_str()),
                    ("apns_key_id", g("apns_key_id").as_str()),
                    ("apns_p8_pem", apns_private.as_str()),
                    ("apns_topic", g("apns_topic").as_str()),
                    ("environment", g("environment").as_str()),
                    ("vapid_public", g("vapid_public").as_str()),
                    ("vapid_private", vapid_private.as_str()),
                    ("vapid_subject", g("vapid_subject").as_str()),
                ],
                now,
            )?;
        }
    }

    // Devices: user_id -> subject_id, re-keyed by token.
    for row in select_rows(store, cache, legacy_devices, Vec::new(), None, now)? {
        let m: std::collections::HashMap<String, String> = row.into_iter().collect();
        let token = m.get("token").cloned().unwrap_or_default();
        if token.is_empty()
            || find_row_by_field(store, cache, DEVICES_TABLE, "token", &token, now)?.is_some()
        {
            continue;
        }
        register_device(
            store,
            cache,
            DeviceRegistration {
                subject_id: &m.get("user_id").cloned().unwrap_or_default(),
                token: &token,
                platform: &m.get("platform").cloned().unwrap_or_else(|| "ios".into()),
                app_id: &m.get("app_id").cloned().unwrap_or_else(|| "default".into()),
                // The legacy layout had no per-device environment; delivery
                // falls back to the app credential, as it did before.
                environment: "",
                environment_source: EnvironmentSource::Trusted,
            },
            now,
        )?;
    }
    Ok(())
}

/// Cumulative + gauge counters surfaced through `INFO` so the cloud monitor can
/// scrape push activity like ops. `devices` is a live gauge; the rest are
/// monotonic counters.
pub(crate) struct PushMetrics {
    pub sends: AtomicU64,
    pub delivered: AtomicU64,
    pub failed: AtomicU64,
    pub devices: AtomicU64,
}

impl PushMetrics {
    const fn new() -> Self {
        Self {
            sends: AtomicU64::new(0),
            delivered: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            devices: AtomicU64::new(0),
        }
    }
}

static METRICS: PushMetrics = PushMetrics::new();

pub(crate) fn metrics() -> &'static PushMetrics {
    &METRICS
}

/// Resolved APNs credentials for one app, ready to build an `ApnsSink`.
pub(crate) struct ResolvedApnsCreds {
    pub creds: apns::ApnsCredentials,
    pub topic: String,
    pub environment: String,
}

/// Resolved VAPID credentials for one app, ready to build a `WebPushSink`.
pub(crate) struct ResolvedVapidCreds {
    /// base64url(uncompressed P-256 public key) — the browser `applicationServerKey`.
    pub public_key: String,
    /// PKCS8 PEM private key for signing the VAPID JWT.
    pub private_pem: String,
    /// `mailto:` or URL contact, per RFC 8292.
    pub subject: String,
}

// ---------------------------------------------------------------------------
// Device registry
// ---------------------------------------------------------------------------

/// Who supplied a device's environment. Registration is reachable with an end
/// user's own JWT, so the two are not equally trusted.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum EnvironmentSource {
    /// A secret key or operator: the project's own backend.
    Trusted,
    /// An end user self-registering with their session JWT.
    User,
}

impl EnvironmentSource {
    fn is_trusted(self) -> bool {
        self == Self::Trusted
    }
}

fn validate_bounded_text(field: &str, value: &str, max_bytes: usize) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{field} is required"));
    }
    if value.len() > max_bytes {
        return Err(format!("{field} must not exceed {max_bytes} bytes"));
    }
    if value.chars().any(char::is_control) {
        return Err(format!("{field} must not contain control characters"));
    }
    Ok(())
}

fn validate_bounded_secret(field: &str, value: &str, max_bytes: usize) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("{field} is required"));
    }
    if value.len() > max_bytes {
        return Err(format!("{field} must not exceed {max_bytes} bytes"));
    }
    if value
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\r'))
    {
        return Err(format!("{field} contains an invalid control character"));
    }
    Ok(())
}

fn validate_vapid_subject(subject: &str) -> Result<(), String> {
    if subject.trim().is_empty() {
        return Ok(());
    }
    validate_bounded_text("subject", subject, MAX_VAPID_SUBJECT_BYTES)?;
    let url = reqwest::Url::parse(subject)
        .map_err(|_| "VAPID subject must be an https URL or mailto address".to_string())?;
    if !matches!(url.scheme(), "https" | "mailto") {
        return Err("VAPID subject must be an https URL or mailto address".to_string());
    }
    Ok(())
}

fn normalized_platform(platform: &str) -> Result<&'static str, String> {
    match platform.trim().to_ascii_lowercase().as_str() {
        "ios" => Ok("ios"),
        "web" => Ok("web"),
        "desktop" => Ok("desktop"),
        _ => Err("platform must be ios, web, or desktop".to_string()),
    }
}

fn validate_apns_device_token(token: &str) -> Result<(), String> {
    validate_bounded_text("token", token, MAX_APNS_TOKEN_BYTES)?;
    if !token
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err("invalid APNs device token".to_string());
    }
    Ok(())
}

fn validate_device_token_for_lookup(token: &str) -> Result<(), String> {
    validate_bounded_text("token", token, MAX_WEB_SUBSCRIPTION_BYTES)
}

/// Normalize a caller-supplied APNs environment to what `resolve_base_url`
/// understands. Anything unrecognized is treated as unspecified rather than
/// guessed at, so delivery falls back to the app credential instead of silently
/// routing to the wrong host.
///
/// An explicit `http(s)://` base is only preserved from a trusted caller. The
/// APNs sink separately restricts it to an explicit development-only loopback
/// override; production delivery always resolves to Apple's exact hosts.
pub(crate) fn normalize_environment(environment: &str, source: EnvironmentSource) -> String {
    let trimmed = environment.trim();
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return match source {
            EnvironmentSource::Trusted => trimmed.to_string(),
            EnvironmentSource::User => String::new(),
        };
    }
    match trimmed.to_ascii_lowercase().as_str() {
        "production" | "prod" => "production".to_string(),
        "sandbox" | "development" | "dev" => "sandbox".to_string(),
        _ => String::new(),
    }
}

/// Register (or refresh) a device token for `subject_id`. A token is unique
/// across the registry: re-registering an existing token re-points it at the
/// current subject and re-activates it rather than duplicating. Returns the
/// device id.
///
/// `environment` is the APNs host the token belongs to ("sandbox" or
/// "production"); empty means unspecified. A development build and a TestFlight
/// build of the same app hold tokens for different hosts at the same time, so
/// this is per device, not per project.
pub(crate) struct DeviceRegistration<'a> {
    pub subject_id: &'a str,
    pub token: &'a str,
    pub platform: &'a str,
    pub app_id: &'a str,
    /// "sandbox", "production", or empty for unspecified.
    pub environment: &'a str,
    /// Whether `environment` came from the project's backend or from the end
    /// user's own session. Gates the explicit-host override.
    pub environment_source: EnvironmentSource,
}

pub(crate) fn register_device(
    store: &Store,
    cache: &SharedSchemaCache,
    device: DeviceRegistration<'_>,
    now: Instant,
) -> Result<String, String> {
    let DeviceRegistration {
        subject_id,
        token,
        platform,
        app_id,
        environment,
        environment_source,
    } = device;
    validate_bounded_text("subject_id", subject_id, MAX_SUBJECT_ID_BYTES)?;
    validate_bounded_text("app_id", app_id, MAX_APP_ID_BYTES)?;
    let platform = normalized_platform(platform)?;
    validate_device_token_for_lookup(token)?;
    if matches!(platform, "web" | "desktop") {
        webpush::validate_subscription_token(token)?;
    } else {
        validate_apns_device_token(token)?;
    }
    let _registry = store.push_device_registry_guard();
    ensure_tables(store, cache, now)?;
    let environment = normalize_environment(environment, environment_source);
    let now_s = unix_seconds().to_string();
    if let Some(existing) = find_row_by_field(store, cache, DEVICES_TABLE, "token", token, now)? {
        let id = existing.get("id").cloned().unwrap_or_default();
        let existing_subject = existing.get("subject_id").map(String::as_str).unwrap_or("");
        if !environment_source.is_trusted() && existing_subject != subject_id {
            return Err("device token is already registered".to_string());
        }
        let gains_active_device = existing_subject != subject_id
            || existing.get("disabled_at").is_none_or(|value| value != "0");
        if gains_active_device
            && active_device_count(store, cache, subject_id, now)? >= MAX_DEVICES_PER_SUBJECT
        {
            return Err(format!(
                "a subject may not register more than {MAX_DEVICES_PER_SUBJECT} active devices"
            ));
        }
        // A re-register that omits the environment must not erase a known one:
        // the same token cannot move hosts, so silence means "unchanged".
        let environment = if environment.is_empty() {
            existing.get("environment").cloned().unwrap_or_default()
        } else {
            environment
        };
        let where_args = if environment_source.is_trusted() {
            vec!["id", "=", id.as_str()]
        } else {
            vec!["id", "=", id.as_str(), "AND", "subject_id", "=", subject_id]
        };
        let updated = durable_table_update_where(
            store,
            cache,
            DEVICES_TABLE,
            &[
                ("subject_id", subject_id),
                ("platform", platform),
                ("app_id", app_id),
                ("environment", environment.as_str()),
                ("last_seen_at", now_s.as_str()),
                ("disabled_at", "0"),
            ],
            &where_args,
            now,
        )?;
        if updated != 1 {
            return Err("device token is already registered".to_string());
        }
        return Ok(id);
    }
    if active_device_count(store, cache, subject_id, now)? >= MAX_DEVICES_PER_SUBJECT {
        return Err(format!(
            "a subject may not register more than {MAX_DEVICES_PER_SUBJECT} active devices"
        ));
    }
    let device_rows = usize::try_from(tables::table_count(store, cache, DEVICES_TABLE, now)?)
        .map_err(|_| "invalid push device count".to_string())?;
    if device_rows >= MAX_DEVICE_ROWS {
        return Err(format!(
            "push device registry capacity of {MAX_DEVICE_ROWS} rows has been reached"
        ));
    }
    let id = random_id("dev");
    durable_table_insert(
        store,
        cache,
        DEVICES_TABLE,
        &[
            ("id", id.as_str()),
            ("subject_id", subject_id),
            ("token", token),
            ("platform", platform),
            ("app_id", app_id),
            ("environment", environment.as_str()),
            ("created_at", now_s.as_str()),
            ("last_seen_at", now_s.as_str()),
            ("disabled_at", "0"),
        ],
        now,
    )?;
    metrics().devices.fetch_add(1, Ordering::Relaxed);
    Ok(id)
}

fn active_device_count(
    store: &Store,
    cache: &SharedSchemaCache,
    subject_id: &str,
    now: Instant,
) -> Result<usize, String> {
    select_rows(
        store,
        cache,
        DEVICES_TABLE,
        vec![
            WhereClause::single("subject_id".into(), CmpOp::Eq, subject_id.into()),
            WhereClause::single("disabled_at".into(), CmpOp::Eq, "0".into()),
        ],
        Some(MAX_DEVICES_PER_SUBJECT),
        now,
    )
    .map(|rows| rows.len())
}

/// List a bounded page of a subject's active devices, omitting raw tokens.
pub(crate) fn list_devices_page(
    store: &Store,
    cache: &SharedSchemaCache,
    subject_id: &str,
    limit: Option<usize>,
    offset: Option<usize>,
    now: Instant,
) -> Result<Vec<Value>, String> {
    validate_bounded_text("subject_id", subject_id, MAX_SUBJECT_ID_BYTES)?;
    let rows = select_projected_rows_page(
        store,
        cache,
        DEVICES_TABLE,
        vec![
            WhereClause::single("subject_id".into(), CmpOp::Eq, subject_id.into()),
            WhereClause::single("disabled_at".into(), CmpOp::Eq, "0".into()),
        ],
        &[
            "id",
            "platform",
            "app_id",
            "environment",
            "created_at",
            "last_seen_at",
        ],
        SelectPage::by_id(limit, offset),
        now,
    )?;
    Ok(rows
        .into_iter()
        .map(|row| {
            let m: std::collections::HashMap<String, String> = row.into_iter().collect();
            json!({
                "id": m.get("id").cloned().unwrap_or_default(),
                "platform": m.get("platform").cloned().unwrap_or_default(),
                "app_id": m.get("app_id").cloned().unwrap_or_default(),
                "environment": m.get("environment").cloned().unwrap_or_default(),
                "created_at": m.get("created_at").cloned().unwrap_or_default(),
                "last_seen_at": m.get("last_seen_at").cloned().unwrap_or_default(),
            })
        })
        .collect())
}

/// Delete a subject's own device by id. Returns whether a row was removed.
pub(crate) fn delete_device(
    store: &Store,
    cache: &SharedSchemaCache,
    subject_id: &str,
    id: &str,
    now: Instant,
) -> Result<bool, String> {
    validate_bounded_text("subject_id", subject_id, MAX_SUBJECT_ID_BYTES)?;
    validate_bounded_text("device id", id, MAX_DEVICE_ID_BYTES)?;
    let _registry = store.push_device_registry_guard();
    let removed = durable_table_delete_where(
        store,
        cache,
        DEVICES_TABLE,
        &["id", "=", id, "AND", "subject_id", "=", subject_id],
        now,
    )?;
    if removed > 0 {
        metrics().devices.fetch_sub(1, Ordering::Relaxed);
    }
    Ok(removed > 0)
}

/// Delete any device by id (operator), regardless of subject. Returns whether a
/// row was removed.
pub(crate) fn delete_device_by_id(
    store: &Store,
    cache: &SharedSchemaCache,
    id: &str,
    now: Instant,
) -> Result<bool, String> {
    validate_bounded_text("device id", id, MAX_DEVICE_ID_BYTES)?;
    let _registry = store.push_device_registry_guard();
    let removed = durable_table_delete_where(store, cache, DEVICES_TABLE, &["id", "=", id], now)?;
    if removed > 0 {
        metrics().devices.fetch_sub(1, Ordering::Relaxed);
    }
    Ok(removed > 0)
}

/// Delete a device by token only when it belongs to `subject_id`. This is the
/// end-user cleanup path used during token rotation and logout, where the app
/// always has the APNs token but may not have received or persisted the
/// engine's internal device id yet.
pub(crate) fn delete_device_by_token_for_subject(
    store: &Store,
    cache: &SharedSchemaCache,
    subject_id: &str,
    token: &str,
    now: Instant,
) -> Result<bool, String> {
    validate_bounded_text("subject_id", subject_id, MAX_SUBJECT_ID_BYTES)?;
    validate_device_token_for_lookup(token)?;
    let _registry = store.push_device_registry_guard();
    let removed = durable_table_delete_where(
        store,
        cache,
        DEVICES_TABLE,
        &["token", "=", token, "AND", "subject_id", "=", subject_id],
        now,
    )?;
    if removed > 0 {
        metrics().devices.fetch_sub(1, Ordering::Relaxed);
    }
    Ok(removed > 0)
}

/// Delete any device by its token (operator). Used for logout-time unregister,
/// where the caller has the token but not the internal device id.
pub(crate) fn delete_device_by_token(
    store: &Store,
    cache: &SharedSchemaCache,
    token: &str,
    now: Instant,
) -> Result<bool, String> {
    validate_device_token_for_lookup(token)?;
    let _registry = store.push_device_registry_guard();
    let removed =
        durable_table_delete_where(store, cache, DEVICES_TABLE, &["token", "=", token], now)?;
    if removed > 0 {
        metrics().devices.fetch_sub(1, Ordering::Relaxed);
    }
    Ok(removed > 0)
}

// ---------------------------------------------------------------------------
// Admin reads (operator) — for the cloud dashboard
// ---------------------------------------------------------------------------

/// List a bounded page of devices across all users. Tokens are omitted.
pub(crate) fn list_all_devices_page(
    store: &Store,
    cache: &SharedSchemaCache,
    limit: usize,
    offset: usize,
    now: Instant,
) -> Result<Vec<Value>, String> {
    let rows = select_projected_rows_page(
        store,
        cache,
        DEVICES_TABLE,
        Vec::new(),
        &[
            "id",
            "subject_id",
            "platform",
            "app_id",
            "environment",
            "created_at",
            "last_seen_at",
            "disabled_at",
        ],
        SelectPage::by_id(Some(limit), Some(offset)),
        now,
    )?;
    Ok(rows
        .into_iter()
        .map(|row| {
            let m: std::collections::HashMap<String, String> = row.into_iter().collect();
            json!({
                "id": m.get("id").cloned().unwrap_or_default(),
                "subject_id": m.get("subject_id").cloned().unwrap_or_default(),
                "platform": m.get("platform").cloned().unwrap_or_default(),
                "app_id": m.get("app_id").cloned().unwrap_or_default(),
                "environment": m.get("environment").cloned().unwrap_or_default(),
                "created_at": m.get("created_at").cloned().unwrap_or_default(),
                "last_seen_at": m.get("last_seen_at").cloned().unwrap_or_default(),
                "disabled_at": m.get("disabled_at").cloned().unwrap_or_default(),
            })
        })
        .collect())
}

/// List a bounded page of dead-lettered deliveries. Target tokens are omitted.
pub(crate) fn list_dead_letters_page(
    store: &Store,
    cache: &SharedSchemaCache,
    limit: usize,
    offset: usize,
    now: Instant,
) -> Result<Vec<Value>, String> {
    let rows = select_projected_rows_page(
        store,
        cache,
        OUTBOX_TABLE,
        vec![WhereClause::single(
            "state".into(),
            CmpOp::Eq,
            "dead".into(),
        )],
        &[
            "id",
            "subject_id",
            "app_id",
            "platform",
            "environment",
            "attempts",
            "last_error",
            "created_at",
        ],
        SelectPage::by_id(Some(limit), Some(offset)),
        now,
    )?;
    Ok(rows
        .into_iter()
        .map(|row| {
            let m: std::collections::HashMap<String, String> = row.into_iter().collect();
            json!({
                "id": m.get("id").cloned().unwrap_or_default(),
                "subject_id": m.get("subject_id").cloned().unwrap_or_default(),
                "app_id": m.get("app_id").cloned().unwrap_or_default(),
                "platform": m.get("platform").cloned().unwrap_or_default(),
                "environment": m.get("environment").cloned().unwrap_or_default(),
                "attempts": m.get("attempts").cloned().unwrap_or_default(),
                "last_error": m.get("last_error").cloned().unwrap_or_default(),
                "created_at": m.get("created_at").cloned().unwrap_or_default(),
            })
        })
        .collect())
}

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

/// Upsert a subset of fields on the per-app credential row, preserving the rest.
/// APNs and Web Push (VAPID) credentials share one row per `app_id`, so setting
/// one must not clobber the other.
fn upsert_credential_fields(
    store: &Store,
    cache: &SharedSchemaCache,
    app_id: &str,
    fields: &[(&str, &str)],
    now: Instant,
) -> Result<(), String> {
    ensure_tables(store, cache, now)?;
    if find_row_by_field(store, cache, CREDENTIALS_TABLE, "app_id", app_id, now)?.is_some() {
        durable_table_update_where(
            store,
            cache,
            CREDENTIALS_TABLE,
            fields,
            &["app_id", "=", app_id],
            now,
        )?;
    } else {
        let now_s = unix_seconds().to_string();
        let mut insert: Vec<(&str, &str)> =
            vec![("app_id", app_id), ("created_at", now_s.as_str())];
        insert.extend_from_slice(fields);
        durable_table_insert(store, cache, CREDENTIALS_TABLE, &insert, now)?;
    }
    Ok(())
}

/// Upsert an app's APNs credentials (operator only). Preserves any VAPID creds.
#[allow(clippy::too_many_arguments)]
pub(crate) fn set_apns_credentials(
    store: &Store,
    cache: &SharedSchemaCache,
    app_id: &str,
    team_id: &str,
    key_id: &str,
    p8_pem: &str,
    topic: &str,
    environment: &str,
    now: Instant,
) -> Result<(), String> {
    update_apns_credentials(
        store,
        cache,
        app_id,
        team_id,
        key_id,
        Some(p8_pem),
        topic,
        environment,
        now,
    )
}

/// Update APNs metadata while preserving the existing private key when
/// `p8_pem` is omitted. New secret writes require engine encryption.
#[allow(clippy::too_many_arguments)]
pub(crate) fn update_apns_credentials(
    store: &Store,
    cache: &SharedSchemaCache,
    app_id: &str,
    team_id: &str,
    key_id: &str,
    p8_pem: Option<&str>,
    topic: &str,
    environment: &str,
    now: Instant,
) -> Result<(), String> {
    validate_bounded_text("app_id", app_id, MAX_APP_ID_BYTES)?;
    validate_bounded_text("team_id", team_id, MAX_APNS_TEAM_ID_BYTES)?;
    validate_bounded_text("key_id", key_id, MAX_APNS_KEY_ID_BYTES)?;
    validate_bounded_text("topic", topic, MAX_APNS_TOPIC_BYTES)?;
    if let Some(p8_pem) = p8_pem {
        validate_bounded_secret("p8_pem", p8_pem, MAX_PROVIDER_PRIVATE_KEY_BYTES)?;
    }
    if p8_pem.is_some() && !store.encryption().has_active_key() {
        return Err("new push secrets require ENC INIT or an active encryption key".to_string());
    }
    if let Some(p8_pem) = p8_pem {
        apns::validate_private_key(p8_pem)?;
    }
    apns::ApnsSink::resolve_base_url(environment)?;
    ensure_tables(store, cache, now)?;
    if p8_pem.is_none() {
        let existing = get_apns_credentials(store, cache, app_id, now)?;
        if existing
            .as_ref()
            .is_none_or(|credentials| credentials.creds.p8_pem.is_empty())
        {
            return Err("p8_pem is required when APNs has no existing key".to_string());
        }
    }
    let mut fields = vec![
        ("apns_team_id", team_id),
        ("apns_key_id", key_id),
        ("apns_topic", topic),
        ("environment", environment),
    ];
    if store.encryption().has_active_key() {
        fields.push(("apns_p8_pem", ""));
    }
    if let Some(p8_pem) = p8_pem {
        fields.push(("apns_p8_pem_encrypted", p8_pem));
    }
    upsert_credential_fields(store, cache, app_id, &fields, now)
}

pub(crate) fn clear_apns_credentials(
    store: &Store,
    cache: &SharedSchemaCache,
    app_id: &str,
    now: Instant,
) -> Result<(), String> {
    validate_bounded_text("app_id", app_id, MAX_APP_ID_BYTES)?;
    ensure_tables(store, cache, now)?;
    let mut fields = vec![
        ("apns_team_id", ""),
        ("apns_key_id", ""),
        ("apns_p8_pem", ""),
        ("apns_topic", ""),
        ("environment", ""),
    ];
    if store.encryption().has_active_key() {
        fields.push(("apns_p8_pem_encrypted", ""));
    }
    upsert_credential_fields(store, cache, app_id, &fields, now)
}

/// Upsert an app's Web Push (VAPID) credentials (operator only). Preserves APNs.
pub(crate) fn set_vapid_credentials(
    store: &Store,
    cache: &SharedSchemaCache,
    app_id: &str,
    public_key: &str,
    private_pem: &str,
    subject: &str,
    now: Instant,
) -> Result<(), String> {
    validate_bounded_text("app_id", app_id, MAX_APP_ID_BYTES)?;
    validate_bounded_text("public_key", public_key, MAX_VAPID_PUBLIC_KEY_BYTES)?;
    validate_bounded_secret("private_pem", private_pem, MAX_PROVIDER_PRIVATE_KEY_BYTES)?;
    validate_vapid_subject(subject)?;
    if !store.encryption().has_active_key() {
        return Err(
            "push credential writes require ENC INIT or an active encryption key".to_string(),
        );
    }
    webpush::validate_vapid_keypair(public_key, private_pem)?;
    ensure_tables(store, cache, now)?;
    upsert_credential_fields(
        store,
        cache,
        app_id,
        &[
            ("vapid_public", public_key),
            ("vapid_private", ""),
            ("vapid_private_encrypted", private_pem),
            ("vapid_subject", subject),
        ],
        now,
    )
}

pub(crate) fn rotate_vapid_credentials(
    store: &Store,
    cache: &SharedSchemaCache,
    app_id: &str,
    subject: &str,
    now: Instant,
) -> Result<String, String> {
    validate_bounded_text("app_id", app_id, MAX_APP_ID_BYTES)?;
    validate_vapid_subject(subject)?;
    let (public_key, private_pem) = webpush::generate_vapid_keypair()?;
    set_vapid_credentials(
        store,
        cache,
        app_id,
        &public_key,
        &private_pem,
        subject,
        now,
    )?;
    Ok(public_key)
}

pub(crate) fn disable_vapid_credentials(
    store: &Store,
    cache: &SharedSchemaCache,
    app_id: &str,
    now: Instant,
) -> Result<(), String> {
    validate_bounded_text("app_id", app_id, MAX_APP_ID_BYTES)?;
    ensure_tables(store, cache, now)?;
    let mut fields = vec![
        ("vapid_public", ""),
        ("vapid_private", ""),
        ("vapid_subject", ""),
    ];
    if store.encryption().has_active_key() {
        fields.push(("vapid_private_encrypted", ""));
    }
    upsert_credential_fields(store, cache, app_id, &fields, now)
}

pub(crate) fn get_vapid_credentials(
    store: &Store,
    cache: &SharedSchemaCache,
    app_id: &str,
    now: Instant,
) -> Result<Option<ResolvedVapidCreds>, String> {
    let Some(row) = find_row_by_field(store, cache, CREDENTIALS_TABLE, "app_id", app_id, now)?
    else {
        return Ok(None);
    };
    let get = |k: &str| row.get(k).cloned().unwrap_or_default();
    let public_key = get("vapid_public");
    let private_pem = {
        let encrypted = get("vapid_private_encrypted");
        if encrypted.is_empty() {
            get("vapid_private")
        } else {
            encrypted
        }
    };
    if public_key.is_empty() || private_pem.is_empty() {
        return Ok(None);
    }
    Ok(Some(ResolvedVapidCreds {
        public_key,
        private_pem,
        subject: get("vapid_subject"),
    }))
}

/// The public VAPID key for an app, if configured (safe to expose to browsers).
pub(crate) fn vapid_public_key(
    store: &Store,
    cache: &SharedSchemaCache,
    app_id: &str,
    now: Instant,
) -> Result<Option<String>, String> {
    validate_bounded_text("app_id", app_id, MAX_APP_ID_BYTES)?;
    Ok(get_vapid_credentials(store, cache, app_id, now)?.map(|c| c.public_key))
}

pub(crate) fn get_apns_credentials(
    store: &Store,
    cache: &SharedSchemaCache,
    app_id: &str,
    now: Instant,
) -> Result<Option<ResolvedApnsCreds>, String> {
    let Some(row) = find_row_by_field(store, cache, CREDENTIALS_TABLE, "app_id", app_id, now)?
    else {
        return Ok(None);
    };
    let get = |k: &str| row.get(k).cloned().unwrap_or_default();
    Ok(Some(ResolvedApnsCreds {
        creds: apns::ApnsCredentials {
            team_id: get("apns_team_id"),
            key_id: get("apns_key_id"),
            p8_pem: {
                let encrypted = get("apns_p8_pem_encrypted");
                if encrypted.is_empty() {
                    get("apns_p8_pem")
                } else {
                    encrypted
                }
            },
        },
        topic: get("apns_topic"),
        environment: get("environment"),
    }))
}

/// Secret-free operator metadata for CLI/Studio configuration and health.
pub(crate) fn credential_config(
    store: &Store,
    cache: &SharedSchemaCache,
    app_id: &str,
    now: Instant,
) -> Result<Value, String> {
    validate_bounded_text("app_id", app_id, MAX_APP_ID_BYTES)?;
    ensure_tables(store, cache, now)?;
    let row = find_row_by_field(store, cache, CREDENTIALS_TABLE, "app_id", app_id, now)?;
    let fields = row.unwrap_or_default();
    let get = |key: &str| fields.get(key).cloned().unwrap_or_default();
    let apns_encrypted = !get("apns_p8_pem_encrypted").is_empty();
    let apns_legacy = !get("apns_p8_pem").is_empty();
    let vapid_encrypted = !get("vapid_private_encrypted").is_empty();
    let vapid_legacy = !get("vapid_private").is_empty();
    let encryption_available = store.encryption().has_active_key();
    let plaintext_secrets = apns_legacy || vapid_legacy;
    let any_configured = apns_encrypted || apns_legacy || vapid_encrypted || vapid_legacy;
    let mut warnings = Vec::new();
    if plaintext_secrets {
        warnings.push(
            "legacy plaintext push secrets are readable but unhealthy; configure engine encryption to migrate them"
                .to_string(),
        );
    }
    if !encryption_available {
        warnings.push(
            "push credential changes are disabled until engine encryption is initialized"
                .to_string(),
        );
    }
    Ok(json!({
        "app_id": app_id,
        "healthy": !plaintext_secrets && (!any_configured || encryption_available),
        "encryption_available": encryption_available,
        "warnings": warnings,
        "apns": {
            "configured": apns_encrypted || apns_legacy,
            "team_id": get("apns_team_id"),
            "key_id": get("apns_key_id"),
            "topic": get("apns_topic"),
            "environment": get("environment"),
            "secret_storage": if apns_encrypted { "encrypted" } else if apns_legacy { "legacy_plaintext" } else { "none" }
        },
        "vapid": {
            "configured": vapid_encrypted || vapid_legacy,
            "public_key": get("vapid_public"),
            "subject": get("vapid_subject"),
            "secret_storage": if vapid_encrypted { "encrypted" } else if vapid_legacy { "legacy_plaintext" } else { "none" }
        }
    }))
}

// ---------------------------------------------------------------------------
// Send / enqueue
// ---------------------------------------------------------------------------

const APNS_INTERRUPTION_LEVELS: [&str; 4] = ["passive", "active", "time-sensitive", "critical"];
const APNS_PAYLOAD_LIMIT_BYTES: usize = 4096;

fn is_valid_interruption_level(level: &str) -> bool {
    APNS_INTERRUPTION_LEVELS.contains(&level)
}

fn notification_has_alert(notification: &Value) -> bool {
    [
        "title",
        "body",
        "subtitle",
        "title_loc_key",
        "subtitle_loc_key",
        "body_loc_key",
    ]
    .iter()
    .any(|field| {
        notification
            .get(field)
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty())
    })
}

fn notification_is_background(notification: &Value) -> bool {
    let content_available = notification
        .get("content_available")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let has_badge = notification.get("badge").is_some();
    let has_sound = notification.get("sound").is_some_and(|sound| match sound {
        Value::String(value) => !value.is_empty(),
        Value::Object(_) => true,
        _ => false,
    });
    content_available && !notification_has_alert(notification) && !has_badge && !has_sound
}

fn is_canonical_uuid(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    bytes.iter().enumerate().all(|(index, byte)| {
        if matches!(index, 8 | 13 | 18 | 23) {
            *byte == b'-'
        } else {
            byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
        }
    })
}

fn validate_notification(notification: &Value) -> Result<(), String> {
    let Some(object) = notification.as_object() else {
        return Err("notification must be a JSON object".to_string());
    };
    for field in [
        "title",
        "body",
        "subtitle",
        "title_loc_key",
        "subtitle_loc_key",
        "body_loc_key",
        "launch_image",
        "thread_id",
        "category",
        "image",
        "target_content_id",
        "filter_criteria",
    ] {
        if object.get(field).is_some_and(|value| !value.is_string()) {
            return Err(format!("{field} must be a string"));
        }
    }
    for field in ["title_loc_args", "subtitle_loc_args", "body_loc_args"] {
        if let Some(value) = object.get(field) {
            let valid = value
                .as_array()
                .is_some_and(|items| items.iter().all(Value::is_string));
            if !valid {
                return Err(format!("{field} must be an array of strings"));
            }
        }
    }
    for field in ["mutable_content", "content_available"] {
        if object.get(field).is_some_and(|value| !value.is_boolean()) {
            return Err(format!("{field} must be a boolean"));
        }
    }
    if let Some(badge) = object.get("badge") {
        if badge.as_i64().is_none_or(|value| value < 0) {
            return Err("badge must be a non-negative integer".to_string());
        }
    }
    if let Some(sound) = object.get("sound") {
        match sound {
            Value::String(_) => {}
            Value::Object(sound) => {
                if sound.get("critical").and_then(Value::as_bool) != Some(true) {
                    return Err("critical sound must set critical to true".to_string());
                }
                if sound
                    .get("name")
                    .and_then(Value::as_str)
                    .is_none_or(str::is_empty)
                {
                    return Err("critical sound name must be a non-empty string".to_string());
                }
                if let Some(volume) = sound.get("volume") {
                    if volume
                        .as_f64()
                        .is_none_or(|value| !(0.0..=1.0).contains(&value))
                    {
                        return Err("critical sound volume must be between 0 and 1".to_string());
                    }
                }
            }
            _ => return Err("sound must be a string or critical sound object".to_string()),
        }
    }
    let Some(value) = notification.get("interruption_level") else {
        return validate_notification_tail(notification);
    };
    let Some(level) = value.as_str() else {
        return Err("interruption_level must be a string".to_string());
    };
    if !is_valid_interruption_level(level) {
        return Err(
            "interruption_level must be passive, active, time-sensitive, or critical".to_string(),
        );
    }
    validate_notification_tail(notification)
}

fn validate_notification_tail(notification: &Value) -> Result<(), String> {
    if let Some(score) = notification.get("relevance_score") {
        if score
            .as_f64()
            .is_none_or(|value| !(0.0..=1.0).contains(&value))
        {
            return Err("relevance_score must be between 0 and 1".to_string());
        }
    }
    if notification
        .get("image")
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty())
        && !notification_has_alert(notification)
    {
        return Err(
            "image requires an alert title, subtitle, body, or localization key".to_string(),
        );
    }
    if let Some(data) = notification.get("data") {
        let Some(data) = data.as_object() else {
            return Err("data must be a JSON object".to_string());
        };
        if data.contains_key("aps") {
            return Err("data.aps is reserved by APNs".to_string());
        }
    }
    if let Some(apns) = notification.get("apns") {
        let Some(apns) = apns.as_object() else {
            return Err("apns must be a JSON object".to_string());
        };
        if let Some(collapse_id) = apns.get("collapse_id") {
            let Some(collapse_id) = collapse_id.as_str() else {
                return Err("apns.collapse_id must be a string".to_string());
            };
            if collapse_id.is_empty() {
                return Err("apns.collapse_id must not be empty".to_string());
            }
            if collapse_id.len() > 64 {
                return Err("apns.collapse_id must not exceed 64 bytes".to_string());
            }
            if collapse_id.chars().any(char::is_control) {
                return Err("apns.collapse_id must not contain control characters".to_string());
            }
        }
        if let Some(expiration) = apns.get("expiration") {
            if expiration.as_u64().is_none() {
                return Err("apns.expiration must be a non-negative integer".to_string());
            }
        }
        if let Some(priority) = apns.get("priority") {
            let priority = priority.as_u64();
            if !matches!(priority, Some(1 | 5 | 10)) {
                return Err("apns.priority must be 1, 5, or 10".to_string());
            }
            if notification_is_background(notification) && priority != Some(5) {
                return Err("background notifications require apns.priority 5".to_string());
            }
        }
    }
    let payload = serde_json::to_vec(notification)
        .map_err(|error| format!("invalid notification: {error}"))?;
    if payload.len() > APNS_PAYLOAD_LIMIT_BYTES {
        return Err(format!(
            "push payload exceeds {APNS_PAYLOAD_LIMIT_BYTES} bytes"
        ));
    }
    let apns_body = apns::apns_body_from_payload(&payload);
    if apns_body.len() > APNS_PAYLOAD_LIMIT_BYTES {
        return Err(format!(
            "APNs payload exceeds {APNS_PAYLOAD_LIMIT_BYTES} bytes"
        ));
    }
    Ok(())
}

/// Fan a notification out to all of `subject_id`'s active devices by inserting
/// one pending outbox row each. Returns the number enqueued. The worker delivers
/// asynchronously.
pub(crate) fn enqueue_send(
    store: &Store,
    cache: &SharedSchemaCache,
    subject_id: &str,
    notification: &Value,
    now: Instant,
) -> Result<usize, String> {
    enqueue_send_many(store, cache, &[subject_id], notification, now)
}

/// Fan a notification out to many subjects in one call. Returns the total number
/// of device rows enqueued across all subjects.
pub(crate) fn enqueue_send_many(
    store: &Store,
    cache: &SharedSchemaCache,
    subject_ids: &[&str],
    notification: &Value,
    now: Instant,
) -> Result<usize, String> {
    validate_notification(notification)?;
    if subject_ids.len() > MAX_SUBJECTS_PER_SEND {
        return Err(format!(
            "subject_ids must not contain more than {MAX_SUBJECTS_PER_SEND} entries"
        ));
    }
    let mut unique_subjects = BTreeSet::new();
    for subject_id in subject_ids {
        validate_bounded_text("subject_id", subject_id, MAX_SUBJECT_ID_BYTES)?;
        unique_subjects.insert(*subject_id);
    }
    let payload = serde_json::to_string(notification).unwrap_or_else(|_| "{}".to_string());
    enqueue_to_subjects(store, cache, &unique_subjects, &payload, now)
}

/// Resolve a bounded fan-out and insert it as one durable table mutation. A
/// rejected request never leaves a partially enqueued subject list behind.
fn enqueue_to_subjects(
    store: &Store,
    cache: &SharedSchemaCache,
    subject_ids: &BTreeSet<&str>,
    payload: &str,
    now: Instant,
) -> Result<usize, String> {
    ensure_tables(store, cache, now)?;
    let now_s = unix_seconds().to_string();
    let mut outbox_rows = Vec::new();
    for subject_id in subject_ids {
        let rows = select_rows(
            store,
            cache,
            DEVICES_TABLE,
            vec![
                WhereClause::single("subject_id".into(), CmpOp::Eq, (*subject_id).into()),
                WhereClause::single("disabled_at".into(), CmpOp::Eq, "0".into()),
            ],
            Some(MAX_DEVICES_PER_SUBJECT + 1),
            now,
        )?;
        if rows.len() > MAX_DEVICES_PER_SUBJECT {
            return Err(format!(
                "subject fan-out exceeds {MAX_DEVICES_PER_SUBJECT} active devices"
            ));
        }
        for row in rows {
            let fields: std::collections::HashMap<String, String> = row.into_iter().collect();
            let token = fields.get("token").cloned().unwrap_or_default();
            if token.is_empty() {
                continue;
            }
            if outbox_rows.len() >= MAX_DELIVERIES_PER_SEND {
                return Err(format!(
                    "push fan-out exceeds {MAX_DELIVERIES_PER_SEND} deliveries"
                ));
            }
            outbox_rows.push(vec![
                ("id".to_string(), random_id("out")),
                ("subject_id".to_string(), (*subject_id).to_string()),
                (
                    "app_id".to_string(),
                    fields.get("app_id").cloned().unwrap_or_default(),
                ),
                ("target_token".to_string(), token),
                (
                    "platform".to_string(),
                    fields.get("platform").cloned().unwrap_or_default(),
                ),
                (
                    "environment".to_string(),
                    fields.get("environment").cloned().unwrap_or_default(),
                ),
                ("payload".to_string(), payload.to_string()),
                ("attempts".to_string(), "0".to_string()),
                ("next_attempt_at".to_string(), now_s.clone()),
                ("state".to_string(), "pending".to_string()),
                ("last_error".to_string(), String::new()),
                ("created_at".to_string(), now_s.clone()),
            ]);
        }
    }
    if outbox_rows.is_empty() {
        return Ok(0);
    }

    let _enqueue = store.push_enqueue_guard();
    let current = usize::try_from(tables::table_count(store, cache, OUTBOX_TABLE, now)?)
        .map_err(|_| "invalid push outbox size".to_string())?;
    validate_outbox_capacity(current, outbox_rows.len())?;
    let inserted = tables::table_insert_many_returning_ttl(
        store,
        cache,
        OUTBOX_TABLE,
        &outbox_rows,
        None,
        now,
    )?
    .len();
    metrics()
        .sends
        .fetch_add(inserted as u64, Ordering::Relaxed);
    Ok(inserted)
}

fn validate_outbox_capacity(current: usize, additional: usize) -> Result<(), String> {
    if additional > MAX_OUTBOX_ROWS.saturating_sub(current) {
        Err(format!(
            "push outbox capacity of {MAX_OUTBOX_ROWS} rows has been reached"
        ))
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Shared select helper
// ---------------------------------------------------------------------------

struct SelectPage {
    limit: Option<usize>,
    offset: Option<usize>,
    order_by: Option<(String, bool)>,
}

impl SelectPage {
    fn by_id(limit: Option<usize>, offset: Option<usize>) -> Self {
        Self {
            limit,
            offset,
            order_by: Some(("id".to_string(), true)),
        }
    }
}

struct SelectView {
    projections: Vec<Projection>,
    decrypt_authorized: bool,
}

pub(crate) fn select_rows(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    conditions: Vec<WhereClause>,
    limit: Option<usize>,
    now: Instant,
) -> Result<Vec<Vec<(String, String)>>, String> {
    select_rows_page(store, cache, table, conditions, limit, None, now)
}

pub(crate) fn select_rows_page(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    conditions: Vec<WhereClause>,
    limit: Option<usize>,
    offset: Option<usize>,
    now: Instant,
) -> Result<Vec<Vec<(String, String)>>, String> {
    select_rows_page_with_projection(
        store,
        cache,
        table,
        conditions,
        SelectView {
            projections: Vec::new(),
            decrypt_authorized: true,
        },
        SelectPage {
            limit,
            offset,
            order_by: None,
        },
        now,
    )
}

fn select_projected_rows_page(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    conditions: Vec<WhereClause>,
    fields: &[&str],
    page: SelectPage,
    now: Instant,
) -> Result<Vec<Vec<(String, String)>>, String> {
    let projections = fields
        .iter()
        .map(|field| Projection {
            expr: (*field).to_string(),
            alias: None,
        })
        .collect();
    select_rows_page_with_projection(
        store,
        cache,
        table,
        conditions,
        SelectView {
            projections,
            decrypt_authorized: false,
        },
        page,
        now,
    )
}

fn select_rows_page_with_projection(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    conditions: Vec<WhereClause>,
    view: SelectView,
    page: SelectPage,
    now: Instant,
) -> Result<Vec<Vec<(String, String)>>, String> {
    // Push tables are created lazily on first write, so a project that has never
    // used push has no `push.*` tables. Treat a missing table as no rows — this
    // keeps reads (and the worker's outbox scan) quiet until push is configured.
    match tables::table_schema(store, cache, table, now) {
        Ok(_) => {}
        Err(error) if error == format!("ERR table '{table}' does not exist") => {
            return Ok(Vec::new())
        }
        Err(error) => return Err(error),
    }
    let plan = SelectPlan {
        table: table.to_string(),
        alias: None,
        projections: view.projections,
        aggregates: Vec::new(),
        joins: Vec::new(),
        conditions,
        group_by: Vec::new(),
        having: Vec::new(),
        near: None,
        order_by: page.order_by,
        limit: page.limit,
        offset: page.offset,
        decrypt_authorized: view.decrypt_authorized,
    };
    match tables::table_select(store, cache, &plan, now)? {
        SelectResult::Rows(rows) => Ok(rows),
        SelectResult::Aggregate(_) => Ok(Vec::new()),
    }
}

pub(crate) fn select_oldest_row_ids(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    conditions: Vec<WhereClause>,
    limit: usize,
    now: Instant,
) -> Result<Vec<String>, String> {
    match tables::table_schema(store, cache, table, now) {
        Ok(_) => {}
        Err(error) if error == format!("ERR table '{table}' does not exist") => {
            return Ok(Vec::new())
        }
        Err(error) => return Err(error),
    }
    let plan = SelectPlan {
        table: table.to_string(),
        alias: None,
        projections: vec![Projection {
            expr: "id".to_string(),
            alias: None,
        }],
        aggregates: Vec::new(),
        joins: Vec::new(),
        conditions,
        group_by: Vec::new(),
        having: Vec::new(),
        near: None,
        order_by: Some(("created_at".to_string(), true)),
        limit: Some(limit),
        offset: None,
        decrypt_authorized: false,
    };
    match tables::table_select(store, cache, &plan, now)? {
        SelectResult::Rows(rows) => Ok(rows
            .into_iter()
            .filter_map(|row| {
                row.into_iter()
                    .find_map(|(column, value)| (column == "id").then_some(value))
            })
            .collect()),
        SelectResult::Aggregate(_) => Ok(Vec::new()),
    }
}

// ---------------------------------------------------------------------------
// INFO
// ---------------------------------------------------------------------------

/// Append the `# Push` INFO block (scraped by the cloud monitor for metering).
pub(crate) fn append_info(out: &mut String) {
    let m = metrics();
    out.push_str("# Push\r\n");
    out.push_str(&format!(
        "push_sends_total:{}\r\n",
        m.sends.load(Ordering::Relaxed)
    ));
    out.push_str(&format!(
        "push_delivered_total:{}\r\n",
        m.delivered.load(Ordering::Relaxed)
    ));
    out.push_str(&format!(
        "push_failed_total:{}\r\n",
        m.failed.load(Ordering::Relaxed)
    ));
    out.push_str(&format!(
        "push_devices:{}\r\n",
        m.devices.load(Ordering::Relaxed)
    ));
}

// ---------------------------------------------------------------------------
// RESP command: LUX PUSH ...
// ---------------------------------------------------------------------------

/// `LUX PUSH REGISTER <subject_id> <token> <platform> <app_id> [environment]`
/// `LUX PUSH SEND <subject_id> <json>`
/// `LUX PUSH CRED <app_id> <team_id> <key_id> <topic> <environment> <p8_pem>`
/// `LUX PUSH DEVICES <subject_id> [limit] [offset]`
/// `LUX PUSH STATS`
///
/// Operator-level RESP parity for the HTTP surface. Self-logs resolved
/// `TINSERT push.*` writes via the durable helpers.
pub(crate) fn cmd_push(
    args: &[&[u8]],
    store: &Store,
    cache: &SharedSchemaCache,
    out: &mut BytesMut,
    now: Instant,
) {
    // args[0] = "LUX", args[1] = "PUSH", args[2] = subcommand
    if args.len() < 3 {
        resp::write_error(out, "ERR usage: LUX PUSH <subcommand> ...");
        return;
    }
    let sub = String::from_utf8_lossy(args[2]).to_ascii_uppercase();
    let arg = |i: usize| -> &str {
        args.get(i)
            .map(|b| std::str::from_utf8(b).unwrap_or(""))
            .unwrap_or("")
    };
    match sub.as_str() {
        "REGISTER" if args.len() >= 7 => {
            // args[7] (environment) is optional so existing callers still parse.
            let device = DeviceRegistration {
                subject_id: arg(3),
                token: arg(4),
                platform: arg(5),
                app_id: arg(6),
                environment: arg(7),
                // LUX PUSH is operator-level RESP; there is no end user here.
                environment_source: EnvironmentSource::Trusted,
            };
            match register_device(store, cache, device, now) {
                Ok(id) => resp::write_bulk(out, &id),
                Err(e) => resp::write_error(out, &normalize_err(&e)),
            }
        }
        "SEND" if args.len() >= 5 => {
            let notification: Value = serde_json::from_str(arg(4)).unwrap_or(json!({}));
            match enqueue_send(store, cache, arg(3), &notification, now) {
                Ok(n) => resp::write_integer(out, n as i64),
                Err(e) => resp::write_error(out, &normalize_err(&e)),
            }
        }
        "CRED" if args.len() >= 9 => {
            match set_apns_credentials(
                store,
                cache,
                arg(3),
                arg(4),
                arg(5),
                arg(7),
                arg(6),
                arg(8),
                now,
            ) {
                Ok(()) => resp::write_ok(out),
                Err(e) => resp::write_error(out, &normalize_err(&e)),
            }
        }
        "DEVICES" if (4..=6).contains(&args.len()) => {
            let limit = if args.len() >= 5 {
                match arg(4).parse::<usize>() {
                    Ok(limit) if (1..=MAX_PAGE_SIZE).contains(&limit) => limit,
                    _ => {
                        resp::write_error(
                            out,
                            &format!("ERR limit must be between 1 and {MAX_PAGE_SIZE}"),
                        );
                        return;
                    }
                }
            } else {
                DEFAULT_PAGE_SIZE
            };
            let offset = if args.len() >= 6 {
                match arg(5).parse::<usize>() {
                    Ok(offset) if offset <= MAX_PAGE_OFFSET => offset,
                    _ => {
                        resp::write_error(
                            out,
                            &format!("ERR offset must not exceed {MAX_PAGE_OFFSET}"),
                        );
                        return;
                    }
                }
            } else {
                0
            };
            match list_devices_page(store, cache, arg(3), Some(limit), Some(offset), now) {
                Ok(devices) => {
                    let items: Vec<String> = devices.iter().map(|d| d.to_string()).collect();
                    resp::write_bulk_array(out, &items);
                }
                Err(e) => resp::write_error(out, &normalize_err(&e)),
            }
        }
        "STATS" => {
            let m = metrics();
            resp::write_bulk_array(
                out,
                &[
                    "sends".into(),
                    m.sends.load(Ordering::Relaxed).to_string(),
                    "delivered".into(),
                    m.delivered.load(Ordering::Relaxed).to_string(),
                    "failed".into(),
                    m.failed.load(Ordering::Relaxed).to_string(),
                    "devices".into(),
                    m.devices.load(Ordering::Relaxed).to_string(),
                ],
            );
        }
        _ => resp::write_error(out, "ERR unknown or malformed LUX PUSH subcommand"),
    }
}

fn normalize_err(e: &str) -> String {
    if e.starts_with("ERR") {
        e.to_string()
    } else {
        format!("ERR {e}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{EncryptionConfig, EncryptionKeyConfig, ServerConfig};
    use std::sync::Arc;
    use EnvironmentSource::{Trusted, User};

    fn cache() -> SharedSchemaCache {
        Arc::new(parking_lot::RwLock::new(tables::SchemaCache::new()))
    }

    fn encrypted_store() -> Store {
        Store::new_with_config(Arc::new(ServerConfig {
            encryption: EncryptionConfig {
                active_key_id: Some("push-test".to_string()),
                keys: vec![EncryptionKeyConfig {
                    id: "push-test".to_string(),
                    secret: b"push-test-secret".to_vec(),
                    decrypt_only: false,
                }],
                ..Default::default()
            },
            ..ServerConfig::default()
        }))
    }

    #[test]
    fn environment_normalizes_apple_spellings() {
        for source in [Trusted, User] {
            assert_eq!(normalize_environment("production", source), "production");
            assert_eq!(normalize_environment("PROD", source), "production");
            assert_eq!(normalize_environment(" Production ", source), "production");
            assert_eq!(normalize_environment("sandbox", source), "sandbox");
            assert_eq!(normalize_environment("development", source), "sandbox");
            assert_eq!(normalize_environment("dev", source), "sandbox");
        }
    }

    #[test]
    fn notification_interruption_level_accepts_only_apns_values() {
        for level in APNS_INTERRUPTION_LEVELS {
            assert!(validate_notification(&json!({ "interruption_level": level })).is_ok());
        }
        assert!(validate_notification(&json!({ "title": "normal" })).is_ok());
        assert_eq!(
            validate_notification(&json!({ "interruption_level": "urgent" })).unwrap_err(),
            "interruption_level must be passive, active, time-sensitive, or critical"
        );
        assert_eq!(
            validate_notification(&json!({ "interruption_level": 1 })).unwrap_err(),
            "interruption_level must be a string"
        );
    }

    #[test]
    fn notification_accepts_complete_standard_apns_surface() {
        let notification = json!({
            "title_loc_key": "TITLE",
            "title_loc_args": ["Alex"],
            "subtitle_loc_key": "PROJECT",
            "subtitle_loc_args": ["Lux"],
            "body_loc_key": "BODY",
            "body_loc_args": ["Deploy"],
            "launch_image": "LaunchQuestion",
            "sound": {"critical": true, "name": "alarm.caf", "volume": 0.5},
            "badge": 1,
            "target_content_id": "question-window",
            "relevance_score": 0.9,
            "filter_criteria": "work",
            "apns": {
                "collapse_id": "agent-question",
                "expiration": 1_900_000_000,
                "priority": 10
            },
            "data": {"question": {"id": 7}, "urgent": true}
        });
        assert!(validate_notification(&notification).is_ok());
    }

    #[test]
    fn notification_rejects_invalid_apns_fields_before_enqueue() {
        let cases = [
            (json!({"badge": -1}), "badge must be a non-negative integer"),
            (
                json!({"sound": {"critical": true, "name": "default", "volume": 1.1}}),
                "critical sound volume must be between 0 and 1",
            ),
            (
                json!({"relevance_score": 2}),
                "relevance_score must be between 0 and 1",
            ),
            (
                json!({"content_available": true, "apns": {"priority": 10}}),
                "background notifications require apns.priority 5",
            ),
            (
                json!({"apns": {"collapse_id": ""}}),
                "apns.collapse_id must not be empty",
            ),
            (
                json!({"apns": {"collapse_id": "safe\r\nx-header: injected"}}),
                "apns.collapse_id must not contain control characters",
            ),
            (json!({"data": {"aps": {}}}), "data.aps is reserved by APNs"),
            (
                json!({"image": "https://example.com/image.png"}),
                "image requires an alert title, subtitle, body, or localization key",
            ),
        ];
        for (notification, expected) in cases {
            assert_eq!(
                validate_notification(&notification).unwrap_err(),
                expected,
                "notification: {notification}"
            );
        }
        assert_eq!(
            validate_notification(&json!({
                "apns": {"collapse_id": "x".repeat(65)}
            }))
            .unwrap_err(),
            "apns.collapse_id must not exceed 64 bytes"
        );
    }

    #[test]
    fn notification_rejects_payloads_larger_than_apns_limit() {
        let notification = json!({
            "title": "Too large",
            "data": {"blob": "x".repeat(APNS_PAYLOAD_LIMIT_BYTES)}
        });
        assert_eq!(
            validate_notification(&notification).unwrap_err(),
            format!("push payload exceeds {APNS_PAYLOAD_LIMIT_BYTES} bytes")
        );
        let ignored_by_apns = json!({"unknown": "x".repeat(APNS_PAYLOAD_LIMIT_BYTES)});
        assert_eq!(
            validate_notification(&ignored_by_apns).unwrap_err(),
            format!("push payload exceeds {APNS_PAYLOAD_LIMIT_BYTES} bytes")
        );
    }

    #[test]
    fn send_limits_subjects_devices_and_outbox_growth() {
        let store = Store::new();
        let cache = cache();
        let now = Instant::now();
        let subjects: Vec<String> = (0..=MAX_SUBJECTS_PER_SEND)
            .map(|index| format!("subject-{index}"))
            .collect();
        let subject_refs: Vec<&str> = subjects.iter().map(String::as_str).collect();
        assert!(
            enqueue_send_many(&store, &cache, &subject_refs, &json!({"title":"x"}), now)
                .unwrap_err()
                .contains("subject_ids")
        );

        for index in 0..MAX_DEVICES_PER_SUBJECT {
            let token = format!("device-{index}");
            register_device(
                &store,
                &cache,
                DeviceRegistration {
                    subject_id: "crowded-subject",
                    token: &token,
                    platform: "ios",
                    app_id: "default",
                    environment: "sandbox",
                    environment_source: Trusted,
                },
                now,
            )
            .unwrap();
        }
        assert!(register_device(
            &store,
            &cache,
            DeviceRegistration {
                subject_id: "crowded-subject",
                token: "one-device-too-many",
                platform: "ios",
                app_id: "default",
                environment: "sandbox",
                environment_source: Trusted,
            },
            now,
        )
        .unwrap_err()
        .contains("active devices"));
        durable_table_insert(
            &store,
            &cache,
            DEVICES_TABLE,
            &[
                ("id", "disabled-extra-device"),
                ("subject_id", "crowded-subject"),
                ("token", "disabled-extra-token"),
                ("platform", "ios"),
                ("app_id", "default"),
                ("environment", "sandbox"),
                ("created_at", "1"),
                ("last_seen_at", "1"),
                ("disabled_at", "1"),
            ],
            now,
        )
        .unwrap();
        assert!(register_device(
            &store,
            &cache,
            DeviceRegistration {
                subject_id: "crowded-subject",
                token: "disabled-extra-token",
                platform: "ios",
                app_id: "default",
                environment: "sandbox",
                environment_source: User,
            },
            now,
        )
        .unwrap_err()
        .contains("active devices"));
        register_device(
            &store,
            &cache,
            DeviceRegistration {
                subject_id: "other-subject",
                token: "operator-transfer-token",
                platform: "ios",
                app_id: "default",
                environment: "sandbox",
                environment_source: Trusted,
            },
            now,
        )
        .unwrap();
        assert!(register_device(
            &store,
            &cache,
            DeviceRegistration {
                subject_id: "crowded-subject",
                token: "operator-transfer-token",
                platform: "ios",
                app_id: "default",
                environment: "sandbox",
                environment_source: Trusted,
            },
            now,
        )
        .unwrap_err()
        .contains("active devices"));
        durable_table_insert(
            &store,
            &cache,
            DEVICES_TABLE,
            &[
                ("id", "legacy-extra-device"),
                ("subject_id", "crowded-subject"),
                ("token", "legacy-extra-token"),
                ("platform", "ios"),
                ("app_id", "default"),
                ("environment", "sandbox"),
                ("created_at", "1"),
                ("last_seen_at", "1"),
                ("disabled_at", "0"),
            ],
            now,
        )
        .unwrap();
        assert!(enqueue_send(
            &store,
            &cache,
            "crowded-subject",
            &json!({"title":"x"}),
            now,
        )
        .unwrap_err()
        .contains("subject fan-out"));
        assert_eq!(
            tables::table_count(&store, &cache, OUTBOX_TABLE, now).unwrap(),
            0
        );

        assert!(validate_outbox_capacity(MAX_OUTBOX_ROWS, 1).is_err());
        assert!(validate_outbox_capacity(MAX_OUTBOX_ROWS - 1, 1).is_ok());
        assert!(validate_outbox_capacity(usize::MAX, usize::MAX).is_err());
    }

    #[test]
    fn duplicate_subjects_enqueue_each_device_once() {
        let store = Store::new();
        let cache = cache();
        let now = Instant::now();
        register_device(
            &store,
            &cache,
            DeviceRegistration {
                subject_id: "subject",
                token: "device",
                platform: "ios",
                app_id: "default",
                environment: "sandbox",
                environment_source: Trusted,
            },
            now,
        )
        .unwrap();
        assert_eq!(
            enqueue_send_many(
                &store,
                &cache,
                &["subject", "subject"],
                &json!({"title":"x"}),
                now,
            )
            .unwrap(),
            1
        );
    }

    #[test]
    fn concurrent_users_cannot_both_claim_one_device_token() {
        let store = Arc::new(Store::new());
        let cache = cache();
        ensure_tables(&store, &cache, Instant::now()).unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let handles: Vec<_> = ["subject-a", "subject-b"]
            .into_iter()
            .map(|subject_id| {
                let store = store.clone();
                let cache = cache.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    register_device(
                        &store,
                        &cache,
                        DeviceRegistration {
                            subject_id,
                            token: "shared-device-token",
                            platform: "ios",
                            app_id: "default",
                            environment: "sandbox",
                            environment_source: User,
                        },
                        Instant::now(),
                    )
                })
            })
            .collect();
        barrier.wait();
        let outcomes: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(outcomes.iter().filter(|result| result.is_err()).count(), 1);
        assert_eq!(
            select_rows(
                &store,
                &cache,
                DEVICES_TABLE,
                vec![WhereClause::single(
                    "token".into(),
                    CmpOp::Eq,
                    "shared-device-token".into(),
                )],
                None,
                Instant::now(),
            )
            .unwrap()
            .len(),
            1
        );
    }

    // Unrecognized input must not be guessed at. Empty means "the device did
    // not say", which falls back to the app credential; picking a host here
    // would send a typo straight to the wrong one.
    #[test]
    fn unknown_environment_is_unspecified() {
        for source in [Trusted, User] {
            assert_eq!(normalize_environment("", source), "");
            assert_eq!(normalize_environment("staging", source), "");
            assert_eq!(normalize_environment("apns", source), "");
        }
    }

    #[test]
    fn explicit_base_url_survives_for_a_trusted_caller() {
        assert_eq!(
            normalize_environment("http://127.0.0.1:9000", Trusted),
            "http://127.0.0.1:9000"
        );
        assert_eq!(
            normalize_environment("https://api.push.apple.com", Trusted),
            "https://api.push.apple.com"
        );
    }

    // The delivery worker sends the APNs provider JWT as a bearer token to
    // whatever host this resolves to. `POST /v1/push/devices` accepts an end
    // user's own session, so honoring a user-supplied host would let any
    // signed-in user collect a token that is signed with the team's .p8 and
    // valid for the whole app.
    #[test]
    fn a_user_cannot_name_the_delivery_host() {
        assert_eq!(normalize_environment("http://attacker.example/", User), "");
        assert_eq!(normalize_environment("https://attacker.example/", User), "");
        assert_eq!(
            normalize_environment("  HTTP://attacker.example/", User),
            ""
        );
    }

    #[test]
    fn plaintext_push_secret_writes_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new_with_config(Arc::new(ServerConfig {
            data_dir: dir.path().to_string_lossy().into_owned(),
            ..ServerConfig::default()
        }));
        let error = update_apns_credentials(
            &store,
            &cache(),
            "default",
            "team",
            "key",
            Some("private"),
            "com.example.app",
            "sandbox",
            Instant::now(),
        )
        .unwrap_err();
        assert!(error.contains("encryption key"));
    }

    #[test]
    fn apns_metadata_update_preserves_encrypted_key_and_clear_removes_it() {
        let store = encrypted_store();
        let cache = cache();
        let now = Instant::now();
        let private_key = webpush::generate_vapid_keypair().unwrap().1;
        update_apns_credentials(
            &store,
            &cache,
            "default",
            "team",
            "key",
            Some(&private_key),
            "com.example.app",
            "sandbox",
            now,
        )
        .unwrap();
        update_apns_credentials(
            &store,
            &cache,
            "default",
            "team",
            "key-2",
            None,
            "com.example.app",
            "production",
            now,
        )
        .unwrap();
        let credentials = get_apns_credentials(&store, &cache, "default", now)
            .unwrap()
            .unwrap();
        assert_eq!(credentials.creds.p8_pem, private_key);
        assert_eq!(credentials.creds.key_id, "key-2");
        let config = credential_config(&store, &cache, "default", now).unwrap();
        assert_eq!(
            config["apns"]["secret_storage"],
            Value::String("encrypted".to_string())
        );
        assert!(!config.to_string().contains("BEGIN PRIVATE KEY"));

        clear_apns_credentials(&store, &cache, "default", now).unwrap();
        let cleared = get_apns_credentials(&store, &cache, "default", now)
            .unwrap()
            .unwrap();
        assert!(cleared.creds.p8_pem.is_empty());
    }

    #[test]
    fn malformed_provider_credentials_are_rejected_before_storage() {
        let store = encrypted_store();
        let cache = cache();
        let now = Instant::now();
        assert!(update_apns_credentials(
            &store,
            &cache,
            "default",
            "team",
            "key",
            Some("not-a-private-key"),
            "com.example.app",
            "sandbox",
            now,
        )
        .unwrap_err()
        .contains("invalid APNs"));

        let (public_key, private_pem) = webpush::generate_vapid_keypair().unwrap();
        let other_public_key = webpush::generate_vapid_keypair().unwrap().0;
        assert!(set_vapid_credentials(
            &store,
            &cache,
            "default",
            &other_public_key,
            &private_pem,
            "mailto:test@example.com",
            now,
        )
        .unwrap_err()
        .contains("do not match"));
        assert!(set_vapid_credentials(
            &store,
            &cache,
            "default",
            &public_key,
            &private_pem,
            "ftp://example.com/contact",
            now,
        )
        .unwrap_err()
        .contains("https URL or mailto"));
        assert_eq!(
            tables::table_schema(&store, &cache, CREDENTIALS_TABLE, now).unwrap_err(),
            format!("ERR table '{CREDENTIALS_TABLE}' does not exist"),
            "invalid credentials must fail before creating durable state"
        );
    }

    #[test]
    fn vapid_rotation_generates_and_encrypts_a_new_keypair() {
        let store = encrypted_store();
        let cache = cache();
        let now = Instant::now();
        let first =
            rotate_vapid_credentials(&store, &cache, "default", "mailto:test@example.com", now)
                .unwrap();
        let second =
            rotate_vapid_credentials(&store, &cache, "default", "mailto:test@example.com", now)
                .unwrap();
        assert_ne!(first, second);
        let resolved = get_vapid_credentials(&store, &cache, "default", now)
            .unwrap()
            .unwrap();
        assert_eq!(resolved.public_key, second);
        assert!(resolved.private_pem.contains("PRIVATE KEY"));
    }

    #[test]
    fn legacy_plaintext_credentials_migrate_when_encryption_is_available() {
        let store = encrypted_store();
        let cache = cache();
        let now = Instant::now();
        tables::table_create(
            &store,
            &cache,
            CREDENTIALS_TABLE,
            &[
                "app_id STR PRIMARY KEY,",
                "platform STR,",
                "apns_team_id STR,",
                "apns_key_id STR,",
                "apns_p8_pem STR,",
                "apns_topic STR,",
                "environment STR,",
                "vapid_public STR,",
                "vapid_private STR,",
                "vapid_subject STR,",
                "created_at INT",
            ],
            now,
        )
        .unwrap();
        tables::table_insert(
            &store,
            &cache,
            CREDENTIALS_TABLE,
            &[
                ("app_id", "default"),
                ("apns_p8_pem", "legacy-apns-secret"),
                ("vapid_private", "legacy-vapid-secret"),
                ("created_at", "1"),
            ],
            now,
        )
        .unwrap();
        ensure_tables(&store, &cache, now).unwrap();
        let config = credential_config(&store, &cache, "default", now).unwrap();
        assert_eq!(config["healthy"], true);
        assert_eq!(config["apns"]["secret_storage"], "encrypted");
        assert_eq!(config["vapid"]["secret_storage"], "encrypted");
        let row = find_row_by_field(&store, &cache, CREDENTIALS_TABLE, "app_id", "default", now)
            .unwrap()
            .unwrap();
        assert_eq!(row.get("apns_p8_pem").map(String::as_str), Some(""));
        assert_eq!(row.get("vapid_private").map(String::as_str), Some(""));
        assert_eq!(
            row.get("apns_p8_pem_encrypted").map(String::as_str),
            Some("legacy-apns-secret")
        );
    }
}
