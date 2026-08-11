//! Delivery worker: drains the durable `push.outbox` and delivers each
//! pending row through the platform sink, applying at-least-once retry/backoff,
//! dead-lettering, and dead-token pruning. All state transitions go through the
//! durable table helpers so they are WAL-logged and survive restart.

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::{stream, StreamExt};
use sha2::{Digest, Sha256};

use crate::auth::{durable_table_delete_where, durable_table_update_where, unix_seconds};
use crate::store::Store;
use crate::tables::{CmpOp, SharedSchemaCache, WhereClause};

use super::apns::{apns_request_id, ApnsSink, DeliveryError, DeliveryTarget, Sink};
use super::webpush::WebPushSink;
use super::{
    get_apns_credentials, get_vapid_credentials, metrics, select_oldest_row_ids, select_rows,
    DEVICES_TABLE, OUTBOX_TABLE,
};

const TICK: Duration = Duration::from_millis(500);
const BATCH: usize = 100;
const MAX_PROVIDER_CONCURRENCY: usize = 16;
const MAX_DEAD_LETTERS: usize = 10_000;
const DEAD_LETTER_PRUNE_BATCH: usize = 1_000;
const MAX_PROVIDER_ERROR_BYTES: usize = 1_024;
const MAX_ATTEMPTS: i64 = 6;
const BACKOFF_BASE_SECS: u64 = 30;
const BACKOFF_CAP_SECS: u64 = 3600;

/// Exponential backoff for the `n`-th attempt (1-indexed), capped at 1h.
fn backoff_secs(n: i64) -> u64 {
    let shift = (n.max(1) - 1).min(20) as u32;
    (BACKOFF_BASE_SECS.saturating_mul(1u64 << shift)).min(BACKOFF_CAP_SECS)
}

fn bounded_provider_error(error: &str) -> String {
    let mut bounded = String::with_capacity(error.len().min(MAX_PROVIDER_ERROR_BYTES));
    for character in error.chars() {
        let character = if character.is_control() {
            ' '
        } else {
            character
        };
        if bounded.len() + character.len_utf8() > MAX_PROVIDER_ERROR_BYTES {
            break;
        }
        bounded.push(character);
    }
    bounded
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
        Err(e) if e.invalidates_target() => Action::DisableDevice {
            error: e.message().to_string(),
        },
        Err(e) if e.is_permanent() => Action::Dead {
            attempts: attempts + 1,
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

struct DeliveryJob {
    id: String,
    token: String,
    payload: String,
    attempts: i64,
    sink: Arc<AppSink>,
}

/// Hash all sink-affecting credential fields into a stable cache identity.
/// Length-prefixing prevents boundary ambiguity. The fingerprint retains only
/// the digest rather than duplicating private signing material in the cache.
fn credential_fingerprint(kind: &str, fields: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for field in std::iter::once(kind).chain(fields.iter().copied()) {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

/// Spawned once in `Runtime::start`. Loops forever, delivering pending rows.
pub(crate) async fn run_delivery_worker(store: Arc<Store>, cache: SharedSchemaCache) {
    // Keyed by `{app_id}:{platform}:{environment}` -> (credential fingerprint,
    // sink). The fingerprint invalidates the cached sink when credentials
    // change so an updated topic/environment/key takes effect without restart.
    let mut sinks: HashMap<String, (String, Arc<AppSink>)> = HashMap::new();
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
    sinks: &mut HashMap<String, (String, Arc<AppSink>)>,
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

    let mut jobs = Vec::with_capacity(rows.len());
    for row in rows {
        let m: HashMap<String, String> = row.into_iter().collect();
        let id = m.get("id").cloned().unwrap_or_default();
        let token = m.get("target_token").cloned().unwrap_or_default();
        let app_id = m.get("app_id").cloned().unwrap_or_default();
        let platform = m
            .get("platform")
            .cloned()
            .unwrap_or_else(|| "ios".to_string());
        let environment = m.get("environment").cloned().unwrap_or_default();
        let payload = m.get("payload").cloned().unwrap_or_default();
        let attempts: i64 = m.get("attempts").and_then(|a| a.parse().ok()).unwrap_or(0);
        if id.is_empty() {
            continue;
        }

        let app_sink =
            match resolve_sink(store, cache, sinks, &app_id, &platform, &environment, now) {
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

        jobs.push(DeliveryJob {
            id,
            token,
            payload,
            attempts,
            sink: app_sink,
        });
    }

    let outcomes = collect_with_provider_limit(jobs.into_iter().map(|job| async move {
        let result = match &*job.sink {
            AppSink::Apns { sink, topic } => {
                let target = DeliveryTarget {
                    token: job.token.clone(),
                    topic: topic.clone(),
                    request_id: apns_request_id(&job.id),
                };
                sink.deliver(&target, job.payload.as_bytes()).await
            }
            AppSink::Web(sink) => {
                let target = DeliveryTarget {
                    token: job.token.clone(),
                    topic: String::new(),
                    request_id: String::new(),
                };
                sink.deliver(&target, job.payload.as_bytes()).await
            }
        };
        (job, result)
    }))
    .await;

    for (job, result) in outcomes {
        let action = decide(job.attempts, result, unix_seconds());
        apply(store, cache, &action, &job.id, &job.token, Instant::now())?;
    }
    prune_dead_letters(store, cache, Instant::now())?;
    Ok(())
}

async fn collect_with_provider_limit<I, F, T>(futures: I) -> Vec<T>
where
    I: IntoIterator<Item = F>,
    F: Future<Output = T>,
{
    stream::iter(futures)
        .buffer_unordered(MAX_PROVIDER_CONCURRENCY)
        .collect()
        .await
}

/// Keep terminal delivery history useful without allowing failed destinations
/// to grow the durable outbox forever. Only ids are projected, so cleanup does
/// not load retained notification payloads or device tokens into memory.
fn prune_dead_letters(
    store: &Arc<Store>,
    cache: &SharedSchemaCache,
    now: Instant,
) -> Result<usize, String> {
    prune_dead_letters_to(store, cache, MAX_DEAD_LETTERS, DEAD_LETTER_PRUNE_BATCH, now)
}

fn prune_dead_letters_to(
    store: &Arc<Store>,
    cache: &SharedSchemaCache,
    max_retained: usize,
    batch: usize,
    now: Instant,
) -> Result<usize, String> {
    let rows = {
        let _execution_guard = store
            .execution_read_guard()
            .map_err(|error| format!("push dead-letter scan failed: {error}"))?;
        select_oldest_row_ids(
            store,
            cache,
            OUTBOX_TABLE,
            vec![WhereClause::single(
                "state".into(),
                CmpOp::Eq,
                "dead".into(),
            )],
            max_retained.saturating_add(batch),
            now,
        )?
    };
    let remove = rows.len().saturating_sub(max_retained);
    if remove == 0 {
        return Ok(0);
    }

    let ids: Vec<String> = rows.into_iter().take(remove.min(batch)).collect();
    if ids.is_empty() {
        return Ok(0);
    }
    let mut where_tokens = Vec::with_capacity(ids.len() + 3);
    where_tokens.push("id".to_string());
    where_tokens.push("IN".to_string());
    where_tokens.push("(".to_string());
    where_tokens.extend(ids);
    where_tokens.push(")".to_string());
    let where_args: Vec<&str> = where_tokens.iter().map(String::as_str).collect();
    let _execution_guard = store
        .execution_read_guard()
        .map_err(|error| format!("push dead-letter prune failed: {error}"))?;
    let removed = durable_table_delete_where(store, cache, OUTBOX_TABLE, &where_args, now)?;
    usize::try_from(removed).map_err(|_| "invalid dead-letter prune count".to_string())
}

/// Build (or reuse a cached) sink for an app from its stored credentials.
/// `Ok(None)` means no credentials are configured; `Err` means the credential
/// material is unusable (bad `.p8`) and the row should dead-letter.
///
/// `environment` is the outbox row's APNs host, recorded from the device that
/// registered the token. One `.p8` key is valid against both hosts, so a project
/// with a development build and a TestFlight build in flight at the same time
/// gets one sink per host off the same credentials. An empty `environment` means
/// the device did not say, and the app credential decides.
fn resolve_sink(
    store: &Arc<Store>,
    cache: &SharedSchemaCache,
    sinks: &mut HashMap<String, (String, Arc<AppSink>)>,
    app_id: &str,
    platform: &str,
    environment: &str,
    now: Instant,
) -> Result<Option<Arc<AppSink>>, String> {
    let cache_key = format!("{app_id}:{platform}:{environment}");

    // Read the current credentials and derive a fingerprint. A cache hit skips
    // only the sink build (which holds the APNs provider-token cache); reading
    // the creds row is cheap. A changed fingerprint rebuilds the sink so a
    // dashboard edit (topic, environment, key, VAPID keypair) takes effect
    // immediately instead of after an engine restart.
    let (fingerprint, app_sink): (String, AppSink) = match platform {
        "web" | "desktop" => {
            let Some(vapid) = get_vapid_credentials(store, cache, app_id, now)? else {
                sinks.remove(&cache_key);
                return Ok(None);
            };
            let fp = credential_fingerprint(
                "web",
                &[&vapid.public_key, &vapid.subject, &vapid.private_pem],
            );
            if let Some((cached_fp, sink)) = sinks.get(&cache_key) {
                if *cached_fp == fp {
                    return Ok(Some(sink.clone()));
                }
            }
            (fp, AppSink::Web(WebPushSink::new(vapid)?))
        }
        _ => {
            let Some(resolved) = get_apns_credentials(store, cache, app_id, now)? else {
                sinks.remove(&cache_key);
                return Ok(None);
            };
            // The device's own environment wins. The credential's is only the
            // fallback for tokens registered without one (including every token
            // registered before `push.devices` carried the column).
            let environment = if environment.is_empty() {
                resolved.environment.as_str()
            } else {
                environment
            };
            let fp = credential_fingerprint(
                "apns",
                &[
                    environment,
                    &resolved.topic,
                    &resolved.creds.team_id,
                    &resolved.creds.key_id,
                    &resolved.creds.p8_pem,
                ],
            );
            if let Some((cached_fp, sink)) = sinks.get(&cache_key) {
                if *cached_fp == fp {
                    return Ok(Some(sink.clone()));
                }
            }
            let base_url = ApnsSink::resolve_base_url(environment)?;
            (
                fp,
                AppSink::Apns {
                    sink: ApnsSink::new(base_url, resolved.creds)?,
                    topic: resolved.topic,
                },
            )
        }
    };
    let app_sink = Arc::new(app_sink);
    sinks.insert(cache_key, (fingerprint, app_sink.clone()));
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
            let error = bounded_provider_error(error);
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
            let error = bounded_provider_error(error);
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
            let error = bounded_provider_error(error);
            let _registry = store.push_device_registry_guard();
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

    use crate::auth::durable_table_insert;
    use crate::tables::SchemaCache;
    use parking_lot::RwLock;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    #[test]
    fn backoff_is_exponential_and_capped() {
        assert_eq!(backoff_secs(1), 30);
        assert_eq!(backoff_secs(2), 60);
        assert_eq!(backoff_secs(3), 120);
        assert_eq!(backoff_secs(4), 240);
        assert!(backoff_secs(20) <= BACKOFF_CAP_SECS);
    }

    #[test]
    fn provider_errors_are_safe_and_bounded_before_storage() {
        let raw = format!("provider\r\ninjected\0{}🙂", "x".repeat(2_000));
        let bounded = bounded_provider_error(&raw);
        assert!(bounded.len() <= MAX_PROVIDER_ERROR_BYTES);
        assert!(!bounded.chars().any(char::is_control));
        assert!(bounded.starts_with("provider  injected "));
        assert!(std::str::from_utf8(bounded.as_bytes()).is_ok());
    }

    #[test]
    fn credential_fingerprints_cover_private_key_rotation_without_retaining_secrets() {
        let apns_before = credential_fingerprint(
            "apns",
            &[
                "production",
                "com.example.app",
                "TEAM",
                "KEY",
                "apns-private-a",
            ],
        );
        let apns_after = credential_fingerprint(
            "apns",
            &[
                "production",
                "com.example.app",
                "TEAM",
                "KEY",
                "apns-private-b",
            ],
        );
        let vapid_before = credential_fingerprint(
            "web",
            &["public-key", "mailto:push@example.com", "vapid-private-a"],
        );
        let vapid_after = credential_fingerprint(
            "web",
            &["public-key", "mailto:push@example.com", "vapid-private-b"],
        );

        assert_ne!(apns_before, apns_after);
        assert_ne!(vapid_before, vapid_after);
        for fingerprint in [apns_before, apns_after, vapid_before, vapid_after] {
            assert_eq!(fingerprint.len(), 64);
            assert!(!fingerprint.contains("private"));
        }
    }

    #[test]
    fn ok_delivers() {
        assert_eq!(decide(0, Ok(()), 1000), Action::Delivered);
    }

    #[test]
    fn invalid_target_disables_device() {
        let action = decide(
            0,
            Err(DeliveryError::InvalidTarget("unregistered".into())),
            1000,
        );
        assert_eq!(
            action,
            Action::DisableDevice {
                error: "unregistered".into()
            }
        );
    }

    #[test]
    fn permanent_delivery_error_dead_letters_without_disabling_device() {
        assert_eq!(
            decide(0, Err(DeliveryError::Permanent("bad payload".into())), 1000),
            Action::Dead {
                attempts: 1,
                error: "bad payload".into(),
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

    #[test]
    fn dead_letter_retention_prunes_only_the_oldest_terminal_rows() {
        let store = Arc::new(Store::new());
        let cache = Arc::new(RwLock::new(SchemaCache::new()));
        let now = Instant::now();
        super::super::ensure_tables(&store, &cache, now).unwrap();
        for (id, state, created_at) in [
            ("oldest", "dead", "1"),
            ("older", "dead", "2"),
            ("newer", "dead", "3"),
            ("newest", "dead", "4"),
            ("pending", "pending", "0"),
        ] {
            durable_table_insert(
                &store,
                &cache,
                OUTBOX_TABLE,
                &[("id", id), ("state", state), ("created_at", created_at)],
                now,
            )
            .unwrap();
        }

        assert_eq!(
            prune_dead_letters_to(&store, &cache, 2, 10, now).unwrap(),
            2
        );
        let dead = select_rows(
            &store,
            &cache,
            OUTBOX_TABLE,
            vec![WhereClause::single(
                "state".into(),
                CmpOp::Eq,
                "dead".into(),
            )],
            None,
            now,
        )
        .unwrap();
        let ids: std::collections::HashSet<String> = dead
            .into_iter()
            .filter_map(|row| {
                row.into_iter()
                    .find_map(|(column, value)| (column == "id").then_some(value))
            })
            .collect();
        assert_eq!(ids, ["newer".to_string(), "newest".to_string()].into());
        assert_eq!(
            crate::tables::table_count(&store, &cache, OUTBOX_TABLE, now).unwrap(),
            3,
            "pending rows must not be pruned"
        );
    }

    #[tokio::test]
    async fn provider_work_never_exceeds_the_concurrency_limit() {
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let futures = (0..(MAX_PROVIDER_CONCURRENCY * 3)).map(|_| {
            let active = active.clone();
            let maximum = maximum.clone();
            async move {
                let now = active.fetch_add(1, AtomicOrdering::SeqCst) + 1;
                maximum.fetch_max(now, AtomicOrdering::SeqCst);
                tokio::time::sleep(Duration::from_millis(5)).await;
                active.fetch_sub(1, AtomicOrdering::SeqCst);
            }
        });
        collect_with_provider_limit(futures).await;
        let observed = maximum.load(AtomicOrdering::SeqCst);
        assert!(observed > 1, "provider work should run concurrently");
        assert!(observed <= MAX_PROVIDER_CONCURRENCY);
    }
}
