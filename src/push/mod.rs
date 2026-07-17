//! lux push: native push notifications. This module owns the engine-side
//! delivery pipeline: a per-user device registry (`auth.devices`), per-app push
//! credentials (`auth.push_credentials`), a durable at-least-once delivery
//! outbox (`auth.push_outbox`), and the background worker that drains it through
//! platform `Sink`s. PR1 ships the APNs sink; WebPush/FCM/HTTP plug into the
//! same `Sink` seam later.

pub(crate) mod apns;
pub(crate) mod worker;

use std::sync::atomic::{AtomicU64, Ordering};

use bytes::BytesMut;
use serde_json::{json, Value};

use crate::auth::{
    durable_table_delete_where, durable_table_insert, durable_table_update_where,
    find_row_by_field, random_id, unix_seconds, DEVICES_TABLE, PUSH_CREDENTIALS_TABLE,
    PUSH_OUTBOX_TABLE,
};
use crate::resp;
use crate::store::Store;
use crate::tables::{self, CmpOp, SelectPlan, SelectResult, SharedSchemaCache, WhereClause};
use std::time::Instant;

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

// ---------------------------------------------------------------------------
// Device registry
// ---------------------------------------------------------------------------

/// Register (or refresh) a device token for `user_id`. A token is unique across
/// the registry: re-registering an existing token re-points it at the current
/// user and re-activates it rather than duplicating. Returns the device id.
pub(crate) fn register_device(
    store: &Store,
    cache: &SharedSchemaCache,
    user_id: &str,
    token: &str,
    platform: &str,
    app_id: &str,
    now: Instant,
) -> Result<String, String> {
    let now_s = unix_seconds().to_string();
    if let Some(existing) = find_row_by_field(store, cache, DEVICES_TABLE, "token", token, now)? {
        let id = existing.get("id").cloned().unwrap_or_default();
        durable_table_update_where(
            store,
            cache,
            DEVICES_TABLE,
            &[
                ("user_id", user_id),
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
            ("user_id", user_id),
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

/// List a user's active devices as JSON, omitting the raw token.
pub(crate) fn list_devices(
    store: &Store,
    cache: &SharedSchemaCache,
    user_id: &str,
    now: Instant,
) -> Result<Vec<Value>, String> {
    let rows = select_rows(
        store,
        cache,
        DEVICES_TABLE,
        vec![
            WhereClause::single("user_id".into(), CmpOp::Eq, user_id.into()),
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

/// Delete a user's own device by id. Returns whether a row was removed.
pub(crate) fn delete_device(
    store: &Store,
    cache: &SharedSchemaCache,
    user_id: &str,
    id: &str,
    now: Instant,
) -> Result<bool, String> {
    let removed = durable_table_delete_where(
        store,
        cache,
        DEVICES_TABLE,
        &["id", "=", id, "AND", "user_id", "=", user_id],
        now,
    )?;
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
                "user_id": m.get("user_id").cloned().unwrap_or_default(),
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
        PUSH_OUTBOX_TABLE,
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
                "user_id": m.get("user_id").cloned().unwrap_or_default(),
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

/// Upsert an app's APNs credentials (operator only). Replaces any existing row.
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
    durable_table_delete_where(
        store,
        cache,
        PUSH_CREDENTIALS_TABLE,
        &["app_id", "=", app_id],
        now,
    )?;
    let now_s = unix_seconds().to_string();
    durable_table_insert(
        store,
        cache,
        PUSH_CREDENTIALS_TABLE,
        &[
            ("app_id", app_id),
            ("platform", "ios"),
            ("apns_team_id", team_id),
            ("apns_key_id", key_id),
            ("apns_p8_pem", p8_pem),
            ("apns_topic", topic),
            ("environment", environment),
            ("created_at", now_s.as_str()),
        ],
        now,
    )?;
    Ok(())
}

pub(crate) fn get_apns_credentials(
    store: &Store,
    cache: &SharedSchemaCache,
    app_id: &str,
    now: Instant,
) -> Result<Option<ResolvedApnsCreds>, String> {
    let Some(row) = find_row_by_field(store, cache, PUSH_CREDENTIALS_TABLE, "app_id", app_id, now)?
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

/// Fan a notification out to all of `user_id`'s active devices by inserting one
/// pending outbox row each. Returns the number enqueued. The worker delivers
/// asynchronously.
pub(crate) fn enqueue_send(
    store: &Store,
    cache: &SharedSchemaCache,
    user_id: &str,
    notification: &Value,
    now: Instant,
) -> Result<usize, String> {
    let rows = select_rows(
        store,
        cache,
        DEVICES_TABLE,
        vec![
            WhereClause::single("user_id".into(), CmpOp::Eq, user_id.into()),
            WhereClause::single("disabled_at".into(), CmpOp::Eq, "0".into()),
        ],
        None,
        now,
    )?;
    let payload = serde_json::to_string(notification).unwrap_or_else(|_| "{}".to_string());
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
            PUSH_OUTBOX_TABLE,
            &[
                ("id", id.as_str()),
                ("user_id", user_id),
                ("app_id", m.get("app_id").map(String::as_str).unwrap_or("")),
                ("target_token", token.as_str()),
                (
                    "platform",
                    m.get("platform").map(String::as_str).unwrap_or(""),
                ),
                ("payload", payload.as_str()),
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

/// `LUX PUSH REGISTER <user_id> <token> <platform> <app_id>`
/// `LUX PUSH SEND <user_id> <json>`
/// `LUX PUSH CRED <app_id> <team_id> <key_id> <topic> <environment> <p8_pem>`
/// `LUX PUSH DEVICES <user_id>`
/// `LUX PUSH STATS`
///
/// Operator-level RESP parity for the HTTP surface (device registration also
/// available over HTTP with a user JWT). Self-logs resolved `TINSERT auth.*`
/// writes via the durable helpers.
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
