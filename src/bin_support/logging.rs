use serde_json::{json, Value};
use std::io::Write;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, PartialEq, PartialOrd)]
pub enum Level {
    Error,
    Warn,
    Info,
    Debug,
}

impl Level {
    fn name(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
        }
    }
}

pub struct Logger {
    level: Level,
    json: bool,
}

static LOGGER: OnceLock<Logger> = OnceLock::new();

impl Logger {
    pub fn parse(level: Option<&str>, format: Option<&str>) -> Result<Self, &'static str> {
        let level = match level.unwrap_or("info") {
            "error" => Level::Error,
            "warn" => Level::Warn,
            "info" => Level::Info,
            "debug" => Level::Debug,
            _ => return Err("LUX_LOG_LEVEL must be error, warn, info, or debug"),
        };
        let json = match format.unwrap_or("text") {
            "text" => false,
            "json" => true,
            _ => return Err("LUX_LOG_FORMAT must be text or json"),
        };
        Ok(Self { level, json })
    }

    fn render(&self, level: Level, event: &str, fields: Value) -> Option<String> {
        if level > self.level {
            return None;
        }
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        // All fields come from explicit event mappings, never request bodies,
        // command arguments, credentials, key names, or arbitrary error strings.
        if self.json {
            Some(json!({"timestamp_ms": timestamp_ms, "level": level.name(), "event": event, "fields": fields}).to_string())
        } else {
            Some(format!("{timestamp_ms} {} {event} {fields}", level.name()))
        }
    }
}

pub fn init(logger: Logger) {
    let _ = LOGGER.set(logger);
}

pub fn emit(level: Level, event: &'static str, fields: Value) {
    let Some(logger) = LOGGER.get() else {
        return;
    };
    if let Some(line) = logger.render(level, event, fields) {
        // A closed log pipe must not unwind through a database operation.
        let _ = writeln!(std::io::stderr().lock(), "{line}");
    }
}

pub fn failure(event: &'static str, error: &std::io::Error) {
    // Configuration errors are authored by the startup validators. Runtime
    // errors may include application values, so retain only their OS category.
    let guidance = (error.kind() == std::io::ErrorKind::InvalidInput).then(|| error.to_string());
    emit(
        Level::Error,
        event,
        json!({"kind": format!("{:?}", error.kind()), "os_error": error.raw_os_error(), "configuration_error": guidance}),
    );
}

pub fn info(event: lux::ServerInfoEvent) {
    use lux::ServerInfoEvent::*;
    let (name, fields) = match event {
        PersistenceConfigured {
            storage_layout,
            durability,
            sync_interval_ms,
        } => (
            "persistence_configured",
            json!({"storage_layout": storage_layout.as_str(), "durability": durability.as_str(), "sync_interval_ms": sync_interval_ms}),
        ),
        TieredStorageEnabled { .. } => ("tiered_storage_enabled", json!({})),
        NoSnapshotFound => ("snapshot_absent", json!({})),
        SnapshotLoaded { keys } => ("snapshot_loaded", json!({"keys": keys})),
        SnapshotSaved { keys } => ("snapshot_saved", json!({"keys": keys})),
        WalReplayed { commands } => ("wal_replayed", json!({"commands": commands})),
        HttpReady { addr } => ("http_listening", json!({"address": addr.to_string()})),
    };
    emit(Level::Info, name, fields);
}

pub fn warn(event: lux::ServerWarnEvent) {
    use lux::ServerWarnEvent::*;
    let (name, fields) = match event {
        PushScopeMigrationFailed { .. } => (
            "push_scope_migration_failed",
            json!({"action": "inspect existing push records before relying on legacy registrations"}),
        ),
        HttpRequestFailed {
            request_id,
            operation,
            status,
            elapsed_ms,
        } => (
            "http_request_failed",
            json!({"request_id": request_id, "operation": operation, "status": status, "elapsed_ms": elapsed_ms}),
        ),
        SlowHttpRequest {
            request_id,
            operation,
            status,
            elapsed_ms,
        } => (
            "slow_http_request",
            json!({"request_id": request_id, "operation": operation, "status": status, "elapsed_ms": elapsed_ms}),
        ),
        AuthSecretStorageDegraded => (
            "auth_storage_degraded",
            json!({"action": "configure encryption before persistent use; current auth state is memory-only"}),
        ),
        DiskCorruptedEntrySkipped { shard, offset } => (
            "disk_entry_checksum_failed",
            json!({"shard": shard, "offset": offset}),
        ),
        DiskEntryParseFailed { shard, offset, .. } => (
            "disk_entry_decode_failed",
            json!({"shard": shard, "offset": offset}),
        ),
        DiskCorruptedEntriesSkipped { shard, entries } => (
            "disk_entries_skipped",
            json!({"shard": shard, "entries": entries}),
        ),
        ConnectionFailed { .. } => ("resp_connection_failed", json!({})),
    };
    emit(Level::Warn, name, fields);
}

pub fn error(event: lux::ServerErrorEvent) {
    let (name, fields) = error_fields(event);
    emit(Level::Error, name, fields);
}

fn error_fields(event: lux::ServerErrorEvent) -> (&'static str, Value) {
    use lux::ServerErrorEvent::*;
    match event {
        TableExpirationFailed { .. } => (
            "table_expiration_failed",
            json!({"rows_retained_for_retry": true}),
        ),
        PushDeliveryWorkerFailed { .. } => ("push_delivery_worker_failed", json!({})),
        SnapshotLoadFailed { .. } => (
            "snapshot_load_failed",
            json!({"action": "check data directory access and snapshot integrity"}),
        ),
        SnapshotSaveFailed {
            error_kind,
            os_error,
            ..
        } => (
            "snapshot_save_failed",
            json!({"error_kind": format!("{error_kind:?}"), "os_error": os_error, "action": "check data directory permissions and available space; previous snapshot retained"}),
        ),
        WalReplayFailed { shard, .. } => ("wal_replay_failed", json!({"shard": shard})),
        WalTruncateFailed { .. } => ("wal_truncate_failed", json!({})),
        DiskEvictionWriteFailed { .. } => (
            "disk_eviction_write_failed",
            json!({"retained_in_memory": true}),
        ),
        DiskPromotionReadFailed { .. } => (
            "disk_promotion_read_failed",
            json!({"disk_entry_retained": true}),
        ),
        InlineCompactionFailed { .. } => ("inline_compaction_failed", json!({})),
        DiskCompactionFailed { shard, .. } => ("disk_compaction_failed", json!({"shard": shard})),
        WalAppendFailed {
            error_kind,
            os_error,
            restart_required,
            ..
        } => (
            "wal_append_failed",
            json!({"mutation_rejected": true, "error_kind": format!("{error_kind:?}"), "os_error": os_error, "restart_required": restart_required}),
        ),
        SnapshotDiskDumpFailed { .. } => (
            "snapshot_disk_dump_failed",
            json!({"snapshot_aborted": true}),
        ),
        WalFsyncFailed {
            error_kind,
            os_error,
            restart_required,
            ..
        } => (
            "wal_sync_failed",
            json!({"error_kind": format!("{error_kind:?}"), "os_error": os_error, "restart_required": restart_required, "action": "check storage health and engine readiness before retrying"}),
        ),
        HttpServerFailed { .. } => ("http_server_failed", json!({})),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persistence_diagnostics_retain_typed_causes_not_raw_messages() {
        for restart_required in [false, true] {
            let (name, fields) = error_fields(lux::ServerErrorEvent::WalFsyncFailed {
                error: "private-value".to_string(),
                error_kind: std::io::ErrorKind::PermissionDenied,
                os_error: Some(13),
                restart_required,
            });
            assert_eq!(name, "wal_sync_failed");
            assert_eq!(fields["error_kind"], "PermissionDenied");
            assert_eq!(fields["os_error"], 13);
            assert_eq!(fields["restart_required"], restart_required);
            assert!(!fields.to_string().contains("private-value"));
        }
    }

    #[test]
    fn strict_log_configuration_and_levels() {
        assert!(Logger::parse(Some("verbose"), None).is_err());
        assert!(Logger::parse(None, Some("jsn")).is_err());
        let logger = Logger::parse(Some("warn"), Some("json")).unwrap();
        assert!(logger.render(Level::Info, "test", json!({})).is_none());
        for level in [Level::Warn, Level::Error] {
            let line = logger.render(level, "test", json!({"count": 2})).unwrap();
            let value: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(value["level"], level.name());
            assert_eq!(value["fields"]["count"], 2);
            assert!(!line.contains('\n'));
        }
    }

    #[test]
    fn text_output_preserves_single_line_records() {
        let logger = Logger::parse(None, None).unwrap();
        let line = logger
            .render(Level::Info, "test", json!({"detail": "one\ntwo\rthree"}))
            .unwrap();
        assert!(!line.contains(['\n', '\r']));
    }
}
