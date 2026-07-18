//! Delivery worker: drains the durable `push.outbox` and delivers each
//! pending row through the platform sink, applying at-least-once retry/backoff,
//! dead-lettering, and dead-token pruning. All state transitions go through the
//! durable table helpers so they are WAL-logged and survive restart.

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::auth::{durable_table_delete_where, durable_table_update_where, unix_seconds};
use crate::store::Store;
use crate::tables::{CmpOp, SharedSchemaCache, WhereClause};

use super::apns::{ApnsSink, DeliveryError, DeliveryTarget, Sink};
use super::webpush::WebPushSink;
use super::{
    get_apns_credentials, get_vapid_credentials, metrics, select_rows, DEVICES_TABLE, OUTBOX_TABLE,
};

const TICK: Duration = Duration::from_millis(500);
const BATCH: usize = 100;
const MAX_ATTEMPTS: i64 = 6;
const BACKOFF_BASE_SECS: u64 = 30;
const BACKOFF_CAP_SECS: u64 = 3600;

/// Exponential backoff for the `n`-th attempt (1-indexed), capped at 1h.
fn backoff_secs(n: i64) -> u64 {
    let shift = (n.max(1) - 1).min(20) as u32;
    (BACKOFF_BASE_SECS.saturating_mul(1u64 << shift)).min(BACKOFF_CAP_SECS)
}

/// The state transition for one delivery attempt. Pure and unit-tested; the
/// worker applies it via durable writes.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Action {
    Delivered,
    Retry {
        attempts: i64,
        next_at: u64,
        error: String,
    },
    Dead {
        attempts: i64,
        error: String,
    },
    DisableDevice {
        error: String,
    },
}

/// Decide what to do with an outbox row given its current attempt count and the
/// delivery result. Terminal errors prune the device; retryable errors back off
/// until `MAX_ATTEMPTS`, then dead-letter.
pub(crate) fn decide(attempts: i64, result: Result<(), DeliveryError>, now_secs: u64) -> Action {
    match result {
        Ok(()) => Action::Delivered,
        Err(e) if e.is_terminal() => Action::DisableDevice {
            error: e.message().to_string(),
        },
        Err(e) => {
            let n = attempts + 1;
            if n >= MAX_ATTEMPTS {
                Action::Dead {
                    attempts: n,
                    error: e.message().to_string(),
                }
            } else {
                Action::Retry {
                    attempts: n,
                    next_at: now_secs + backoff_secs(n),
                    error: e.message().to_string(),
                }
            }
        }
    }
}

/// A per-(app, platform) delivery sink. The trait uses RPITIT so it isn't
/// object-safe; an enum lets the worker hold either concrete sink.
enum AppSink {
    Apns { sink: ApnsSink, topic: String },
    Web(WebPushSink),
}

/// Spawned once in `Runtime::start`. Loops forever, delivering pending rows.
pub(crate) async fn run_delivery_worker(store: Arc<Store>, cache: SharedSchemaCache) {
    let mut sinks: HashMap<String, Arc<AppSink>> = HashMap::new();
    let mut ticker = tokio::time::interval(TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        if let Err(e) = process_pending(&store, &cache, &mut sinks).await {
            eprintln!("push delivery worker error: {e}");
        }
    }
}

async fn process_pending(
    store: &Arc<Store>,
    cache: &SharedSchemaCache,
    sinks: &mut HashMap<String, Arc<AppSink>>,
) -> Result<(), String> {
    let now = Instant::now();
    let now_secs = unix_seconds();
    let rows = select_rows(
        store,
        cache,
        OUTBOX_TABLE,
        vec![
            WhereClause::single("state".into(), CmpOp::Eq, "pending".into()),
            WhereClause::single("next_attempt_at".into(), CmpOp::Le, now_secs.to_string()),
        ],
        Some(BATCH),
        now,
    )?;

    for row in rows {
        let m: HashMap<String, String> = row.into_iter().collect();
        let id = m.get("id").cloned().unwrap_or_default();
        let token = m.get("target_token").cloned().unwrap_or_default();
        let app_id = m.get("app_id").cloned().unwrap_or_default();
        let platform = m
            .get("platform")
            .cloned()
            .unwrap_or_else(|| "ios".to_string());
        let payload = m.get("payload").cloned().unwrap_or_default();
        let attempts: i64 = m.get("attempts").and_then(|a| a.parse().ok()).unwrap_or(0);
        if id.is_empty() {
            continue;
        }

        let app_sink = match resolve_sink(store, cache, sinks, &app_id, &platform, now) {
            Ok(Some(s)) => s,
            Ok(None) => {
                apply(
                    store,
                    cache,
                    &Action::Dead {
                        attempts,
                        error: format!("no push credentials for app '{app_id}'"),
                    },
                    &id,
                    &token,
                    now,
                )?;
                continue;
            }
            Err(e) => {
                apply(
                    store,
                    cache,
                    &Action::Dead { attempts, error: e },
                    &id,
                    &token,
                    now,
                )?;
                continue;
            }
        };

        let result = match &*app_sink {
            AppSink::Apns { sink, topic } => {
                let target = DeliveryTarget {
                    token: token.clone(),
                    topic: topic.clone(),
                };
                sink.deliver(&target, payload.as_bytes()).await
            }
            AppSink::Web(sink) => {
                // The web token is the subscription JSON; topic is unused.
                let target = DeliveryTarget {
                    token: token.clone(),
                    topic: String::new(),
                };
                sink.deliver(&target, payload.as_bytes()).await
            }
        };
        let action = decide(attempts, result, unix_seconds());
        apply(store, cache, &action, &id, &token, now)?;
    }
    Ok(())
}

/// Build (or reuse a cached) sink for an app from its stored credentials.
/// `Ok(None)` means no credentials are configured; `Err` means the credential
/// material is unusable (bad `.p8`) and the row should dead-letter.
fn resolve_sink(
    store: &Arc<Store>,
    cache: &SharedSchemaCache,
    sinks: &mut HashMap<String, Arc<AppSink>>,
    app_id: &str,
    platform: &str,
    now: Instant,
) -> Result<Option<Arc<AppSink>>, String> {
    let cache_key = format!("{app_id}:{platform}");
    if let Some(existing) = sinks.get(&cache_key) {
        return Ok(Some(existing.clone()));
    }
    let app_sink = match platform {
        "web" | "desktop" => {
            let Some(vapid) = get_vapid_credentials(store, cache, app_id, now)? else {
                return Ok(None);
            };
            AppSink::Web(WebPushSink::new(vapid)?)
        }
        _ => {
            let Some(resolved) = get_apns_credentials(store, cache, app_id, now)? else {
                return Ok(None);
            };
            let base_url = ApnsSink::resolve_base_url(&resolved.environment);
            AppSink::Apns {
                sink: ApnsSink::new(base_url, resolved.creds)?,
                topic: resolved.topic,
            }
        }
    };
    let app_sink = Arc::new(app_sink);
    sinks.insert(cache_key, app_sink.clone());
    Ok(Some(app_sink))
}

fn apply(
    store: &Arc<Store>,
    cache: &SharedSchemaCache,
    action: &Action,
    id: &str,
    token: &str,
    now: Instant,
) -> Result<(), String> {
    match action {
        Action::Delivered => {
            durable_table_delete_where(store, cache, OUTBOX_TABLE, &["id", "=", id], now)?;
            metrics().delivered.fetch_add(1, Ordering::Relaxed);
        }
        Action::Retry {
            attempts,
            next_at,
            error,
        } => {
            let attempts_s = attempts.to_string();
            let next_s = next_at.to_string();
            durable_table_update_where(
                store,
                cache,
                OUTBOX_TABLE,
                &[
                    ("attempts", attempts_s.as_str()),
                    ("next_attempt_at", next_s.as_str()),
                    ("last_error", error.as_str()),
                ],
                &["id", "=", id],
                now,
            )?;
        }
        Action::Dead { attempts, error } => {
            let attempts_s = attempts.to_string();
            durable_table_update_where(
                store,
                cache,
                OUTBOX_TABLE,
                &[
                    ("state", "dead"),
                    ("attempts", attempts_s.as_str()),
                    ("last_error", error.as_str()),
                ],
                &["id", "=", id],
                now,
            )?;
            metrics().failed.fetch_add(1, Ordering::Relaxed);
        }
        Action::DisableDevice { error } => {
            let now_s = unix_seconds().to_string();
            durable_table_update_where(
                store,
                cache,
                DEVICES_TABLE,
                &[("disabled_at", now_s.as_str())],
                &["token", "=", token],
                now,
            )?;
            durable_table_update_where(
                store,
                cache,
                OUTBOX_TABLE,
                &[("state", "dead"), ("last_error", error.as_str())],
                &["id", "=", id],
                now,
            )?;
            metrics().failed.fetch_add(1, Ordering::Relaxed);
            // Best-effort gauge: a pruned device is no longer active.
            let m = metrics();
            let cur = m.devices.load(Ordering::Relaxed);
            if cur > 0 {
                m.devices.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_is_exponential_and_capped() {
        assert_eq!(backoff_secs(1), 30);
        assert_eq!(backoff_secs(2), 60);
        assert_eq!(backoff_secs(3), 120);
        assert_eq!(backoff_secs(4), 240);
        assert!(backoff_secs(20) <= BACKOFF_CAP_SECS);
    }

    #[test]
    fn ok_delivers() {
        assert_eq!(decide(0, Ok(()), 1000), Action::Delivered);
    }

    #[test]
    fn terminal_disables_device() {
        let action = decide(0, Err(DeliveryError::Terminal("unregistered".into())), 1000);
        assert_eq!(
            action,
            Action::DisableDevice {
                error: "unregistered".into()
            }
        );
    }

    #[test]
    fn retryable_backs_off_then_dead() {
        // Early attempt: schedule a retry with backoff.
        match decide(0, Err(DeliveryError::Retryable("503".into())), 1000) {
            Action::Retry {
                attempts, next_at, ..
            } => {
                assert_eq!(attempts, 1);
                assert_eq!(next_at, 1000 + 30);
            }
            other => panic!("expected retry, got {other:?}"),
        }
        // At the cap: dead-letter instead of retrying forever.
        match decide(
            MAX_ATTEMPTS - 1,
            Err(DeliveryError::Retryable("503".into())),
            1000,
        ) {
            Action::Dead { attempts, .. } => assert_eq!(attempts, MAX_ATTEMPTS),
            other => panic!("expected dead, got {other:?}"),
        }
    }
}
