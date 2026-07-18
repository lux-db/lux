//! lux push: native push notifications. This module owns the engine-side
//! delivery pipeline as its own standalone, auth-independent scope: a device
//! registry (`push.devices`) keyed by an opaque `subject_id`, per-app push
//! credentials (`push.credentials`), a durable at-least-once delivery outbox
//! (`push.outbox`), and the background worker that drains it through platform
//! `Sink`s. A `subject_id` MAY be a Lux `auth.users.id` but doesn't have to be —
//! push works with Lux auth entirely off, managed by the secret key. PR1 ships
//! the APNs sink; WebPush/FCM/HTTP plug into the same `Sink` seam later.

pub(crate) mod apns;
pub(crate) mod webpush;
pub(crate) mod worker;

use std::sync::atomic::{AtomicU64, Ordering};

use bytes::BytesMut;
use serde_json::{json, Value};

use crate::auth::{
    create_table_if_missing, durable_table_delete_where, durable_table_insert,
    durable_table_update_where, find_row_by_field, random_id, unix_seconds,
};
use crate::resp;
use crate::store::Store;
use crate::tables::{self, CmpOp, SelectPlan, SelectResult, SharedSchemaCache, WhereClause};
use std::time::Instant;

/// Reserved `push.*` scope tables (protected + redacted by the shared reserved
/// machinery in `auth.rs`, but bootstrapped and owned here).
pub(crate) const DEVICES_TABLE: &str = "push.devices";
pub(crate) const CREDENTIALS_TABLE: &str = "push.credentials";
pub(crate) const OUTBOX_TABLE: &str = "push.outbox";

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
            "created_at INT,",
            "last_seen_at INT,",
            "disabled_at INT",
        ],
        now,
    )?;
    create_table_if_missing(
        store,
        cache,
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
    )?;
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
            "payload STR,",
            "attempts INT,",
            "next_attempt_at INT,",
            "state STR,",
            "last_error STR,",
            "created_at INT",
        ],
        now,
    )?;
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
        set_apns_credentials(
            store,
            cache,
            &app_id,
            &g("apns_team_id"),
            &g("apns_key_id"),
            &g("apns_p8_pem"),
            &g("apns_topic"),
            &g("environment"),
            now,
        )?;
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
            &m.get("user_id").cloned().unwrap_or_default(),
            &token,
            &m.get("platform").cloned().unwrap_or_else(|| "ios".into()),
            &m.get("app_id").cloned().unwrap_or_else(|| "default".into()),
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

/// Register (or refresh) a device token for `subject_id`. A token is unique
/// across the registry: re-registering an existing token re-points it at the
/// current subject and re-activates it rather than duplicating. Returns the
/// device id.
pub(crate) fn register_device(
    store: &Store,
    cache: &SharedSchemaCache,
    subject_id: &str,
    token: &str,
    platform: &str,
    app_id: &str,
    now: Instant,
) -> Result<String, String> {
    ensure_tables(store, cache, now)?;
    let now_s = unix_seconds().to_string();
    if let Some(existing) = find_row_by_field(store, cache, DEVICES_TABLE, "token", token, now)? {
        let id = existing.get("id").cloned().unwrap_or_default();
        durable_table_update_where(
            store,
            cache,
            DEVICES_TABLE,
            &[
                ("subject_id", subject_id),
                ("platform", platform),
                ("app_id", app_id),
                ("last_seen_at", now_s.as_str()),
                ("disabled_at", "0"),
            ],
            &["id", "=", id.as_str()],
            now,
        )?;
        return Ok(id);
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
            ("created_at", now_s.as_str()),
            ("last_seen_at", now_s.as_str()),
            ("disabled_at", "0"),
        ],
        now,
    )?;
    metrics().devices.fetch_add(1, Ordering::Relaxed);
    Ok(id)
}

/// List a subject's active devices as JSON, omitting the raw token.
pub(crate) fn list_devices(
    store: &Store,
    cache: &SharedSchemaCache,
    subject_id: &str,
    now: Instant,
) -> Result<Vec<Value>, String> {
    let rows = select_rows(
        store,
        cache,
        DEVICES_TABLE,
        vec![
            WhereClause::single("subject_id".into(), CmpOp::Eq, subject_id.into()),
            WhereClause::single("disabled_at".into(), CmpOp::Eq, "0".into()),
        ],
        None,
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
    let removed = durable_table_delete_where(store, cache, DEVICES_TABLE, &["id", "=", id], now)?;
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

/// List every device across all users (operator view). Tokens are omitted.
pub(crate) fn list_all_devices(
    store: &Store,
    cache: &SharedSchemaCache,
    now: Instant,
) -> Result<Vec<Value>, String> {
    let rows = select_rows(store, cache, DEVICES_TABLE, Vec::new(), None, now)?;
    Ok(rows
        .into_iter()
        .map(|row| {
            let m: std::collections::HashMap<String, String> = row.into_iter().collect();
            json!({
                "id": m.get("id").cloned().unwrap_or_default(),
                "subject_id": m.get("subject_id").cloned().unwrap_or_default(),
                "platform": m.get("platform").cloned().unwrap_or_default(),
                "app_id": m.get("app_id").cloned().unwrap_or_default(),
                "created_at": m.get("created_at").cloned().unwrap_or_default(),
                "last_seen_at": m.get("last_seen_at").cloned().unwrap_or_default(),
                "disabled_at": m.get("disabled_at").cloned().unwrap_or_default(),
            })
        })
        .collect())
}

/// List dead-lettered deliveries (operator view). Target tokens are omitted.
pub(crate) fn list_dead_letters(
    store: &Store,
    cache: &SharedSchemaCache,
    now: Instant,
) -> Result<Vec<Value>, String> {
    let rows = select_rows(
        store,
        cache,
        OUTBOX_TABLE,
        vec![WhereClause::single(
            "state".into(),
            CmpOp::Eq,
            "dead".into(),
        )],
        Some(200),
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
    upsert_credential_fields(
        store,
        cache,
        app_id,
        &[
            ("apns_team_id", team_id),
            ("apns_key_id", key_id),
            ("apns_p8_pem", p8_pem),
            ("apns_topic", topic),
            ("environment", environment),
        ],
        now,
    )
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
    upsert_credential_fields(
        store,
        cache,
        app_id,
        &[
            ("vapid_public", public_key),
            ("vapid_private", private_pem),
            ("vapid_subject", subject),
        ],
        now,
    )
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
    let private_pem = get("vapid_private");
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
            p8_pem: get("apns_p8_pem"),
        },
        topic: get("apns_topic"),
        environment: get("environment"),
    }))
}

// ---------------------------------------------------------------------------
// Send / enqueue
// ---------------------------------------------------------------------------

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
    let payload = serde_json::to_string(notification).unwrap_or_else(|_| "{}".to_string());
    enqueue_to_subject(store, cache, subject_id, &payload, now)
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
    let payload = serde_json::to_string(notification).unwrap_or_else(|_| "{}".to_string());
    let mut total = 0usize;
    for subject_id in subject_ids {
        total += enqueue_to_subject(store, cache, subject_id, &payload, now)?;
    }
    Ok(total)
}

/// Insert one pending outbox row per active device of `subject_id`. `payload` is
/// the already-serialized notification JSON.
fn enqueue_to_subject(
    store: &Store,
    cache: &SharedSchemaCache,
    subject_id: &str,
    payload: &str,
    now: Instant,
) -> Result<usize, String> {
    ensure_tables(store, cache, now)?;
    let rows = select_rows(
        store,
        cache,
        DEVICES_TABLE,
        vec![
            WhereClause::single("subject_id".into(), CmpOp::Eq, subject_id.into()),
            WhereClause::single("disabled_at".into(), CmpOp::Eq, "0".into()),
        ],
        None,
        now,
    )?;
    let now_s = unix_seconds().to_string();
    let mut count = 0usize;
    for row in rows {
        let m: std::collections::HashMap<String, String> = row.into_iter().collect();
        let token = m.get("token").cloned().unwrap_or_default();
        if token.is_empty() {
            continue;
        }
        let id = random_id("out");
        durable_table_insert(
            store,
            cache,
            OUTBOX_TABLE,
            &[
                ("id", id.as_str()),
                ("subject_id", subject_id),
                ("app_id", m.get("app_id").map(String::as_str).unwrap_or("")),
                ("target_token", token.as_str()),
                (
                    "platform",
                    m.get("platform").map(String::as_str).unwrap_or(""),
                ),
                ("payload", payload),
                ("attempts", "0"),
                ("next_attempt_at", now_s.as_str()),
                ("state", "pending"),
                ("last_error", ""),
                ("created_at", now_s.as_str()),
            ],
            now,
        )?;
        count += 1;
    }
    metrics().sends.fetch_add(count as u64, Ordering::Relaxed);
    Ok(count)
}

// ---------------------------------------------------------------------------
// Shared select helper
// ---------------------------------------------------------------------------

pub(crate) fn select_rows(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    conditions: Vec<WhereClause>,
    limit: Option<usize>,
    now: Instant,
) -> Result<Vec<Vec<(String, String)>>, String> {
    // Push tables are created lazily on first write, so a project that has never
    // used push has no `push.*` tables. Treat a missing table as no rows — this
    // keeps reads (and the worker's outbox scan) quiet until push is configured.
    if tables::table_schema(store, cache, table, now).is_err() {
        return Ok(Vec::new());
    }
    let plan = SelectPlan {
        table: table.to_string(),
        alias: None,
        projections: Vec::new(),
        aggregates: Vec::new(),
        joins: Vec::new(),
        conditions,
        group_by: Vec::new(),
        having: Vec::new(),
        near: None,
        order_by: None,
        limit,
        offset: None,
        decrypt_authorized: true,
    };
    match tables::table_select(store, cache, &plan, now)? {
        SelectResult::Rows(rows) => Ok(rows),
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

/// `LUX PUSH REGISTER <subject_id> <token> <platform> <app_id>`
/// `LUX PUSH SEND <subject_id> <json>`
/// `LUX PUSH CRED <app_id> <team_id> <key_id> <topic> <environment> <p8_pem>`
/// `LUX PUSH DEVICES <subject_id>`
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
            match register_device(store, cache, arg(3), arg(4), arg(5), arg(6), now) {
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
        "DEVICES" if args.len() >= 4 => match list_devices(store, cache, arg(3), now) {
            Ok(devices) => {
                let items: Vec<String> = devices.iter().map(|d| d.to_string()).collect();
                resp::write_bulk_array(out, &items);
            }
            Err(e) => resp::write_error(out, &normalize_err(&e)),
        },
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
