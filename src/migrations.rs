//! Engine-owned migration parsing, checksums, ledger state, and execution.
//!
//! Every surface (CLI, Cloud, and Studio) calls this contract instead of
//! maintaining its own parser or writing `__migrations` directly. A migration
//! is recorded as `applying` before its first command and advances its durable
//! command cursor after every successful command. An interrupted or failed
//! migration blocks later writes until an operator explicitly repairs it.

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use bytes::BytesMut;
use parking_lot::Mutex;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::auth::{
    add_column_if_missing, durable_table_insert, durable_table_update_where, unix_seconds,
};
use crate::cmd::CmdResult;
use crate::pubsub::Broker;
use crate::resp;
use crate::store::Store;
use crate::tables::{self, SelectPlan, SelectResult, SharedSchemaCache};

pub(crate) const LEDGER_TABLE: &str = "__migrations";
pub(crate) const API_VERSION: &str = "1";
pub(crate) const STUDIO_API_VERSION: u32 = 1;
pub(crate) const CHECKSUM_ALGORITHM: &str = "sha256";
pub(crate) const CAPABILITIES: &[&str] = &[
    "engine.exec",
    "engine.tables",
    "engine.vectors",
    "engine.streams",
    "engine.timeseries",
    "engine.realtime",
    "engine.migrations",
    "engine.snapshots.export",
    "engine.snapshots.restore",
    "engine.cluster",
    "cluster.topology.v1",
    "cluster.transfer.v1",
    "cluster.backup.parts.v1",
    "cluster.global-scans.v1",
    "cluster.http.tables.v1",
    "engine.auth.users",
    "engine.auth.sessions",
    "engine.auth.grants",
    "engine.auth.keys",
    "engine.auth.providers.google",
    "engine.auth.providers.github",
    "engine.auth.providers.apple.native",
    "engine.auth.providers.apple.web",
    "engine.push.apns",
    "engine.push.web",
    "migrations.plan",
    "migrations.apply",
    "migrations.repair",
    "migrations.sha256",
    "push.config",
    "push.apns.preserve_key",
    "push.vapid.rotate",
    "push.secrets.encrypted",
];

const STATUS_APPLYING: &str = "applying";
const STATUS_APPLIED: &str = "applied";
const STATUS_FAILED: &str = "failed";
const STATUS_ABANDONED: &str = "abandoned";

// Migration execution changes both user data and the ledger. Serialize writers
// so two concurrent callers cannot both plan against the same pre-insert state.
// Embedded servers retain isolated stores; a process-wide lock is conservative
// and keeps the contract correct without leaking state between them.
static MIGRATION_WRITE_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct MigrationRecord {
    pub filename: String,
    pub checksum: String,
    pub checksum_algorithm: String,
    pub applied_at: u64,
    pub body: String,
    pub status: String,
    pub command_count: usize,
    pub completed_commands: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PlanAction {
    Apply,
    AlreadyApplied,
    Conflict,
    Blocked,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct MigrationPlan {
    pub filename: String,
    pub checksum: String,
    pub checksum_algorithm: &'static str,
    pub command_count: usize,
    pub action: PlanAction,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct ApplyResult {
    pub migration: MigrationRecord,
    pub already_applied: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RepairAction {
    Resume { from_command: usize },
    MarkApplied,
    Abandon,
}

/// Return a safe migration filename. CLI callers normally supply a complete
/// filename; Studio may supply a human name and let the engine timestamp it.
pub(crate) fn resolve_filename(
    filename: Option<&str>,
    name: Option<&str>,
) -> Result<String, String> {
    if let Some(filename) = filename.map(str::trim).filter(|v| !v.is_empty()) {
        validate_filename(filename)?;
        return Ok(filename.to_string());
    }
    let name = name
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| "ERR filename or name is required".to_string())?;
    let slug = slugify(name);
    Ok(format!("{}_{}.lux", unix_seconds(), slug))
}

fn validate_filename(filename: &str) -> Result<(), String> {
    if filename.len() > 255
        || filename == "."
        || filename == ".."
        || filename.contains('/')
        || filename.contains('\\')
        || filename.chars().any(char::is_control)
    {
        return Err("ERR migration filename must be a safe basename".to_string());
    }
    Ok(())
}

fn slugify(name: &str) -> String {
    let mut out = String::new();
    let mut separator = false;
    for ch in name.chars().flat_map(char::to_lowercase) {
        if ch.is_ascii_alphanumeric() {
            if separator && !out.is_empty() {
                out.push('_');
            }
            out.push(ch);
            separator = false;
        } else {
            separator = true;
        }
    }
    if out.is_empty() {
        "migration".to_string()
    } else {
        out
    }
}

pub(crate) fn checksum(body: &str) -> String {
    let digest = Sha256::digest(body.as_bytes());
    format!("{digest:x}")
}

fn legacy_djb2_checksum(body: &str) -> String {
    let mut hash: u64 = 5381;
    for byte in body.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(byte as u64);
    }
    format!("{hash:016x}")
}

fn legacy_fnv1a_checksum(body: &str) -> String {
    let mut hash: u32 = 0x811c9dc5;
    for unit in body.encode_utf16() {
        hash ^= u32::from(unit);
        hash = hash.wrapping_mul(0x01000193);
    }
    format!("{hash:x}")
}

fn checksum_matches(record: &MigrationRecord, body: &str) -> bool {
    match record.checksum_algorithm.as_str() {
        CHECKSUM_ALGORITHM => record.checksum == checksum(body),
        "djb2-64" => record.checksum == legacy_djb2_checksum(body),
        "fnv1a-32-utf16" => record.checksum == legacy_fnv1a_checksum(body),
        "legacy" | "" => {
            record.checksum == legacy_djb2_checksum(body)
                || record.checksum == legacy_fnv1a_checksum(body)
        }
        _ => false,
    }
}

fn is_missing_table_error(error: &str) -> bool {
    error == format!("ERR table '{LEDGER_TABLE}' does not exist")
}

/// Strictly create or upgrade the ledger. Unexpected schema failures are
/// returned; they are never treated as proof that the table is absent.
pub(crate) fn ensure_ledger(
    store: &Store,
    cache: &SharedSchemaCache,
    now: Instant,
) -> Result<(), String> {
    match tables::table_schema(store, cache, LEDGER_TABLE, now) {
        Ok(_) => {}
        Err(error) if is_missing_table_error(&error) => {
            tables::table_create(
                store,
                cache,
                LEDGER_TABLE,
                &[
                    "filename STR PRIMARY KEY,",
                    "checksum STR,",
                    "applied_at INT,",
                    "body STR,",
                    "status STR,",
                    "checksum_algorithm STR,",
                    "command_count INT,",
                    "completed_commands INT,",
                    "error STR",
                ],
                now,
            )?;
        }
        Err(error) => return Err(format!("ERR could not inspect migration ledger: {error}")),
    }

    for spec in [
        "body STR",
        "status STR",
        "checksum_algorithm STR",
        "command_count INT",
        "completed_commands INT",
        "error STR",
    ] {
        add_column_if_missing(store, cache, LEDGER_TABLE, spec, now)?;
    }
    normalize_legacy_rows(store, cache, now)
}

fn raw_rows(
    store: &Store,
    cache: &SharedSchemaCache,
    limit: Option<usize>,
    offset: Option<usize>,
    now: Instant,
) -> Result<Vec<HashMap<String, String>>, String> {
    let plan = SelectPlan {
        table: LEDGER_TABLE.to_string(),
        alias: None,
        projections: Vec::new(),
        aggregates: Vec::new(),
        joins: Vec::new(),
        conditions: Vec::new(),
        group_by: Vec::new(),
        having: Vec::new(),
        near: None,
        order_by: Some(("applied_at".to_string(), true)),
        limit,
        offset,
        decrypt_authorized: true,
    };
    match tables::table_select(store, cache, &plan, now)? {
        SelectResult::Rows(rows) => Ok(rows
            .into_iter()
            .map(|row| row.into_iter().collect())
            .collect()),
        SelectResult::Aggregate(_) => {
            Err("ERR migration ledger query returned an aggregate".into())
        }
    }
}

fn normalize_legacy_rows(
    store: &Store,
    cache: &SharedSchemaCache,
    now: Instant,
) -> Result<(), String> {
    let rows = raw_rows(store, cache, Some(10_001), None, now)?;
    if rows.len() > 10_000 {
        return Err("ERR migration ledger exceeds the 10000-row safety limit".to_string());
    }
    let mut filenames = HashSet::new();
    for row in &rows {
        let filename = row.get("filename").cloned().unwrap_or_default();
        if filename.is_empty() {
            return Err("ERR migration ledger contains a row without a filename".to_string());
        }
        if !filenames.insert(filename.clone()) {
            return Err(format!(
                "ERR migration ledger contains duplicate filename '{filename}'"
            ));
        }
    }
    for row in rows {
        let filename = row.get("filename").cloned().unwrap_or_default();
        let body = row.get("body").cloned().unwrap_or_default();
        let command_count = parse_migration_commands(&body)
            .map(|commands| commands.len())
            .unwrap_or(0)
            .to_string();
        let status = row.get("status").map(String::as_str).unwrap_or("");
        let algorithm = row
            .get("checksum_algorithm")
            .map(String::as_str)
            .unwrap_or("");
        let completed = row
            .get("completed_commands")
            .map(String::as_str)
            .unwrap_or("");
        if status.is_empty() || algorithm.is_empty() || completed.is_empty() {
            let checksum_algorithm = if algorithm.is_empty() {
                infer_legacy_algorithm(row.get("checksum").map(String::as_str).unwrap_or(""), &body)
            } else {
                algorithm
            };
            let fields = [
                (
                    "status",
                    if status.is_empty() {
                        STATUS_APPLIED
                    } else {
                        status
                    },
                ),
                ("checksum_algorithm", checksum_algorithm),
                ("command_count", command_count.as_str()),
                (
                    "completed_commands",
                    if completed.is_empty() {
                        command_count.as_str()
                    } else {
                        completed
                    },
                ),
                ("error", row.get("error").map(String::as_str).unwrap_or("")),
            ];
            durable_table_update_where(
                store,
                cache,
                LEDGER_TABLE,
                &fields,
                &["filename", "=", filename.as_str()],
                now,
            )?;
        }
    }
    Ok(())
}

fn infer_legacy_algorithm(stored: &str, body: &str) -> &'static str {
    if stored == legacy_djb2_checksum(body) {
        "djb2-64"
    } else if stored == legacy_fnv1a_checksum(body) {
        "fnv1a-32-utf16"
    } else {
        "legacy"
    }
}

fn record_from_row(row: HashMap<String, String>) -> Result<MigrationRecord, String> {
    let parse_number = |field: &str| -> Result<u64, String> {
        let raw = row.get(field).map(String::as_str).unwrap_or("0");
        raw.parse()
            .map_err(|_| format!("ERR migration ledger has invalid {field}"))
    };
    let filename = row.get("filename").cloned().unwrap_or_default();
    if filename.is_empty() {
        return Err("ERR migration ledger contains a row without a filename".to_string());
    }
    let error = row
        .get("error")
        .cloned()
        .filter(|value| !value.is_empty() && value != "NULL");
    Ok(MigrationRecord {
        filename,
        checksum: row.get("checksum").cloned().unwrap_or_default(),
        checksum_algorithm: row
            .get("checksum_algorithm")
            .cloned()
            .unwrap_or_else(|| "legacy".to_string()),
        applied_at: parse_number("applied_at")?,
        body: row.get("body").cloned().unwrap_or_default(),
        status: row
            .get("status")
            .cloned()
            .unwrap_or_else(|| STATUS_APPLIED.to_string()),
        command_count: parse_number("command_count")? as usize,
        completed_commands: parse_number("completed_commands")? as usize,
        error,
    })
}

pub(crate) fn list(
    store: &Store,
    cache: &SharedSchemaCache,
    limit: usize,
    offset: usize,
    now: Instant,
) -> Result<Vec<MigrationRecord>, String> {
    ensure_ledger(store, cache, now)?;
    raw_rows(store, cache, Some(limit.clamp(1, 1000)), Some(offset), now)?
        .into_iter()
        .map(record_from_row)
        .collect()
}

fn all_records(
    store: &Store,
    cache: &SharedSchemaCache,
    now: Instant,
) -> Result<Vec<MigrationRecord>, String> {
    raw_rows(store, cache, Some(10_000), None, now)?
        .into_iter()
        .map(record_from_row)
        .collect()
}

fn blocker<'a>(
    records: &'a [MigrationRecord],
    except: Option<&str>,
) -> Option<&'a MigrationRecord> {
    records.iter().find(|record| {
        Some(record.filename.as_str()) != except
            && matches!(record.status.as_str(), STATUS_APPLYING | STATUS_FAILED)
    })
}

pub(crate) fn plan(
    store: &Store,
    cache: &SharedSchemaCache,
    filename: &str,
    body: &str,
    now: Instant,
) -> Result<MigrationPlan, String> {
    validate_filename(filename)?;
    ensure_ledger(store, cache, now)?;
    let commands = parse_migration_commands(body)?;
    if commands.is_empty() {
        return Err("ERR migration has no commands".to_string());
    }
    let records = all_records(store, cache, now)?;
    let wanted_checksum = checksum(body);
    let existing = records.iter().find(|record| record.filename == filename);
    let (action, reason) = if let Some(existing) = existing {
        if existing.status == STATUS_APPLIED && checksum_matches(existing, body) {
            (PlanAction::AlreadyApplied, None)
        } else if matches!(existing.status.as_str(), STATUS_APPLYING | STATUS_FAILED) {
            (
                PlanAction::Blocked,
                Some(format!(
                    "migration is {}; repair it explicitly before continuing",
                    existing.status
                )),
            )
        } else {
            (
                PlanAction::Conflict,
                Some("filename already exists with different content or state".to_string()),
            )
        }
    } else if let Some(blocked) = blocker(&records, None) {
        (
            PlanAction::Blocked,
            Some(format!(
                "{} migration '{}' must be repaired first",
                blocked.status, blocked.filename
            )),
        )
    } else {
        (PlanAction::Apply, None)
    };
    Ok(MigrationPlan {
        filename: filename.to_string(),
        checksum: wanted_checksum,
        checksum_algorithm: CHECKSUM_ALGORITHM,
        command_count: commands.len(),
        action,
        reason,
    })
}

pub(crate) fn apply<F>(
    store: &Store,
    cache: &SharedSchemaCache,
    filename: &str,
    body: &str,
    now: Instant,
    mut execute: F,
) -> Result<ApplyResult, String>
where
    F: FnMut(&[String]) -> Result<(), String>,
{
    let _write_guard = MIGRATION_WRITE_LOCK.lock();
    let planned = plan(store, cache, filename, body, now)?;
    if planned.action == PlanAction::AlreadyApplied {
        let migration = all_records(store, cache, now)?
            .into_iter()
            .find(|record| record.filename == filename)
            .ok_or_else(|| "ERR migration disappeared during apply".to_string())?;
        return Ok(ApplyResult {
            migration,
            already_applied: true,
        });
    }
    if planned.action != PlanAction::Apply {
        return Err(format!(
            "ERR migration cannot be applied: {}",
            planned.reason.unwrap_or_else(|| "conflict".to_string())
        ));
    }
    let commands = parse_migration_commands(body)?;
    let now_s = unix_seconds().to_string();
    let command_count = commands.len().to_string();
    durable_table_insert(
        store,
        cache,
        LEDGER_TABLE,
        &[
            ("filename", filename),
            ("checksum", planned.checksum.as_str()),
            ("applied_at", "0"),
            ("body", body),
            ("status", STATUS_APPLYING),
            ("checksum_algorithm", CHECKSUM_ALGORITHM),
            ("command_count", command_count.as_str()),
            ("completed_commands", "0"),
            ("error", ""),
        ],
        now,
    )?;
    execute_from(store, cache, filename, &commands, 0, now, &mut execute)?;
    durable_table_update_where(
        store,
        cache,
        LEDGER_TABLE,
        &[
            ("status", STATUS_APPLIED),
            ("applied_at", now_s.as_str()),
            ("error", ""),
        ],
        &["filename", "=", filename],
        now,
    )?;
    let migration = all_records(store, cache, now)?
        .into_iter()
        .find(|record| record.filename == filename)
        .ok_or_else(|| "ERR applied migration was not recorded".to_string())?;
    Ok(ApplyResult {
        migration,
        already_applied: false,
    })
}

fn execute_from<F>(
    store: &Store,
    cache: &SharedSchemaCache,
    filename: &str,
    commands: &[Vec<String>],
    from_command: usize,
    now: Instant,
    execute: &mut F,
) -> Result<(), String>
where
    F: FnMut(&[String]) -> Result<(), String>,
{
    for (index, command) in commands.iter().enumerate().skip(from_command) {
        if let Err(error) = execute(command) {
            let safe_error = error.chars().take(2000).collect::<String>();
            durable_table_update_where(
                store,
                cache,
                LEDGER_TABLE,
                &[("status", STATUS_FAILED), ("error", safe_error.as_str())],
                &["filename", "=", filename],
                now,
            )?;
            return Err(format!(
                "ERR migration '{filename}' failed at command {}: {error}",
                index + 1
            ));
        }
        let completed = (index + 1).to_string();
        durable_table_update_where(
            store,
            cache,
            LEDGER_TABLE,
            &[("completed_commands", completed.as_str())],
            &["filename", "=", filename],
            now,
        )?;
    }
    Ok(())
}

pub(crate) fn repair<F>(
    store: &Store,
    cache: &SharedSchemaCache,
    filename: &str,
    action: RepairAction,
    now: Instant,
    mut execute: F,
) -> Result<MigrationRecord, String>
where
    F: FnMut(&[String]) -> Result<(), String>,
{
    let _write_guard = MIGRATION_WRITE_LOCK.lock();
    validate_filename(filename)?;
    ensure_ledger(store, cache, now)?;
    let records = all_records(store, cache, now)?;
    let record = records
        .iter()
        .find(|record| record.filename == filename)
        .cloned()
        .ok_or_else(|| format!("ERR migration '{filename}' was not found"))?;
    if !matches!(record.status.as_str(), STATUS_APPLYING | STATUS_FAILED) {
        return Err(format!(
            "ERR migration '{}' is {}; only applying or failed migrations can be repaired",
            filename, record.status
        ));
    }
    match action {
        RepairAction::Resume { from_command } => {
            let commands = parse_migration_commands(&record.body)?;
            if from_command > commands.len() {
                return Err(format!(
                    "ERR from_command {from_command} exceeds command count {}",
                    commands.len()
                ));
            }
            let reviewed = from_command.to_string();
            durable_table_update_where(
                store,
                cache,
                LEDGER_TABLE,
                &[
                    ("status", STATUS_APPLYING),
                    ("completed_commands", reviewed.as_str()),
                    ("error", ""),
                ],
                &["filename", "=", filename],
                now,
            )?;
            execute_from(
                store,
                cache,
                filename,
                &commands,
                from_command,
                now,
                &mut execute,
            )?;
            let applied_at = unix_seconds().to_string();
            durable_table_update_where(
                store,
                cache,
                LEDGER_TABLE,
                &[
                    ("status", STATUS_APPLIED),
                    ("applied_at", applied_at.as_str()),
                    ("error", ""),
                ],
                &["filename", "=", filename],
                now,
            )?;
        }
        RepairAction::MarkApplied => {
            let applied_at = unix_seconds().to_string();
            let completed = record.command_count.to_string();
            durable_table_update_where(
                store,
                cache,
                LEDGER_TABLE,
                &[
                    ("status", STATUS_APPLIED),
                    ("applied_at", applied_at.as_str()),
                    ("completed_commands", completed.as_str()),
                    ("error", ""),
                ],
                &["filename", "=", filename],
                now,
            )?;
        }
        RepairAction::Abandon => {
            durable_table_update_where(
                store,
                cache,
                LEDGER_TABLE,
                &[("status", STATUS_ABANDONED), ("error", "")],
                &["filename", "=", filename],
                now,
            )?;
        }
    }
    all_records(store, cache, now)?
        .into_iter()
        .find(|record| record.filename == filename)
        .ok_or_else(|| "ERR repaired migration disappeared".to_string())
}

pub(crate) fn parse_migration_commands(content: &str) -> Result<Vec<Vec<String>>, String> {
    let (statements, saw_semicolon) = split_statements(content);
    if !saw_semicolon {
        return parse_migration_lines(content);
    }
    let mut commands = Vec::new();
    for (index, statement) in statements.iter().enumerate() {
        let statement = statement.trim();
        if statement.is_empty() {
            continue;
        }
        if statement.starts_with('[') {
            let parsed: Vec<String> = serde_json::from_str(statement).map_err(|error| {
                format!(
                    "ERR statement {} is not a valid JSON argv array: {error}",
                    index + 1
                )
            })?;
            if parsed.is_empty() {
                return Err(format!("ERR statement {} has an empty command", index + 1));
            }
            commands.push(parsed);
        } else {
            let parsed = split_command_line(statement).map_err(|error| {
                format!("ERR statement {} could not be parsed: {error}", index + 1)
            })?;
            if !parsed.is_empty() {
                commands.push(parsed);
            }
        }
    }
    Ok(commands)
}

fn split_statements(content: &str) -> (Vec<String>, bool) {
    let mut statements = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut line_comment = false;
    let mut saw_semicolon = false;
    let mut chars = content.chars().peekable();
    while let Some(ch) = chars.next() {
        if line_comment {
            if ch == '\n' {
                line_comment = false;
                current.push(' ');
            }
            continue;
        }
        match quote {
            Some(expected) => {
                current.push(ch);
                if ch == '\\' {
                    if let Some(next) = chars.next() {
                        current.push(next);
                    }
                } else if ch == expected {
                    quote = None;
                }
            }
            None if ch == '#' => line_comment = true,
            None if ch == '-' && chars.peek() == Some(&'-') => {
                chars.next();
                line_comment = true;
            }
            None if ch == '"' || ch == '\'' => {
                quote = Some(ch);
                current.push(ch);
            }
            None if ch == ';' => {
                saw_semicolon = true;
                statements.push(std::mem::take(&mut current));
            }
            None if ch == '\n' || ch == '\r' => current.push(' '),
            None => current.push(ch),
        }
    }
    if !current.trim().is_empty() {
        statements.push(current);
    }
    (statements, saw_semicolon)
}

fn parse_migration_lines(content: &str) -> Result<Vec<Vec<String>>, String> {
    let mut commands = Vec::new();
    for (index, raw) in content.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("--") {
            continue;
        }
        if line.starts_with('[') {
            let parsed: Vec<String> = serde_json::from_str(line).map_err(|error| {
                format!(
                    "ERR line {} is not a valid JSON argv array: {error}",
                    index + 1
                )
            })?;
            if parsed.is_empty() {
                return Err(format!("ERR line {} has an empty command", index + 1));
            }
            commands.push(parsed);
        } else {
            let parsed = split_command_line(line)
                .map_err(|error| format!("ERR line {} could not be parsed: {error}", index + 1))?;
            if !parsed.is_empty() {
                commands.push(parsed);
            }
        }
    }
    Ok(commands)
}

fn split_command_line(input: &str) -> Result<Vec<String>, String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        match quote {
            Some(expected) if ch == expected => quote = None,
            Some(_) if ch == '\\' => {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            Some(_) => current.push(ch),
            None if ch == '"' || ch == '\'' => quote = Some(ch),
            None if ch.is_whitespace() => {
                if !current.is_empty() {
                    args.push(std::mem::take(&mut current));
                }
            }
            None => current.push(ch),
        }
    }
    if let Some(expected) = quote {
        return Err(format!("unterminated {expected} quote"));
    }
    if !current.is_empty() {
        args.push(current);
    }
    Ok(args)
}

/// RESP parity for the engine-owned HTTP migration contract.
///
/// - `LUX MIGRATE LIST [limit] [offset]`
/// - `LUX MIGRATE PLAN <filename> <body>`
/// - `LUX MIGRATE APPLY <filename> <body>`
/// - `LUX MIGRATE REPAIR <filename> RESUME <from_command>`
/// - `LUX MIGRATE REPAIR <filename> MARK-APPLIED|ABANDON`
pub(crate) fn cmd_migrate(
    args: &[&[u8]],
    store: &Store,
    cache: &SharedSchemaCache,
    broker: &Broker,
    out: &mut BytesMut,
    now: Instant,
) {
    let arg = |index: usize| -> Result<&str, String> {
        args.get(index)
            .ok_or_else(|| "ERR missing argument".to_string())
            .and_then(|value| {
                std::str::from_utf8(value).map_err(|_| "ERR arguments must be UTF-8".to_string())
            })
    };
    let subcommand = match arg(2) {
        Ok(value) => value.to_ascii_uppercase(),
        Err(error) => {
            resp::write_error(out, &error);
            return;
        }
    };
    let result = match subcommand.as_str() {
        "LIST" => {
            let limit = arg(3)
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(100);
            let offset = arg(4)
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0);
            list(store, cache, limit, offset, now)
                .and_then(|items| serde_json::to_string(&items).map_err(|error| error.to_string()))
        }
        "PLAN" if args.len() == 5 => arg(3).and_then(|filename| {
            arg(4).and_then(|body| {
                plan(store, cache, filename, body, now)
                    .and_then(|value| serde_json::to_string(&value).map_err(|e| e.to_string()))
            })
        }),
        "APPLY" if args.len() == 5 => arg(3).and_then(|filename| {
            arg(4).and_then(|body| {
                apply(store, cache, filename, body, now, |command| {
                    execute_resp_command(store, cache, broker, command, now)
                })
                .and_then(|value| serde_json::to_string(&value).map_err(|e| e.to_string()))
            })
        }),
        "REPAIR" if args.len() >= 5 => arg(3).and_then(|filename| {
            arg(4).and_then(|raw_action| {
                let action = match raw_action.to_ascii_uppercase().as_str() {
                    "RESUME" => {
                        let from_command = arg(5)?
                            .parse::<usize>()
                            .map_err(|_| "ERR from_command must be an integer".to_string())?;
                        RepairAction::Resume { from_command }
                    }
                    "MARK-APPLIED" | "MARK_APPLIED" => RepairAction::MarkApplied,
                    "ABANDON" => RepairAction::Abandon,
                    _ => {
                        return Err("ERR repair action must be RESUME, MARK-APPLIED, or ABANDON"
                            .to_string())
                    }
                };
                repair(store, cache, filename, action, now, |command| {
                    execute_resp_command(store, cache, broker, command, now)
                })
                .and_then(|value| serde_json::to_string(&value).map_err(|e| e.to_string()))
            })
        }),
        _ => Err("ERR usage: LUX MIGRATE <LIST|PLAN|APPLY|REPAIR> ...".to_string()),
    };
    match result {
        Ok(json) => resp::write_bulk(out, &json),
        Err(error) => {
            let error = if error.starts_with("ERR") {
                error
            } else {
                format!("ERR {error}")
            };
            resp::write_error(out, &error);
        }
    }
}

fn execute_resp_command(
    store: &Store,
    cache: &SharedSchemaCache,
    broker: &Broker,
    command: &[String],
    now: Instant,
) -> Result<(), String> {
    if command
        .first()
        .is_some_and(|value| value.eq_ignore_ascii_case("LUX"))
    {
        return Err("nested LUX commands are not allowed in migrations".to_string());
    }
    let owned: Vec<Vec<u8>> = command
        .iter()
        .map(|value| value.as_bytes().to_vec())
        .collect();
    let refs: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();
    let mut command_out = BytesMut::new();
    let result = crate::cmd::execute_with_wal(store, cache, broker, &refs, &mut command_out, now);
    if command_out.first() == Some(&b'-') {
        let message = std::str::from_utf8(&command_out[1..])
            .unwrap_or("engine command failed")
            .trim_end_matches("\r\n");
        return Err(message.to_string());
    }
    if !matches!(result, CmdResult::Written) {
        return Err("blocking commands are not allowed in migrations".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn state() -> (Store, SharedSchemaCache) {
        (
            Store::new(),
            Arc::new(parking_lot::RwLock::new(tables::SchemaCache::new())),
        )
    }

    #[test]
    fn parser_handles_comments_quotes_and_json_argv() {
        let commands = parse_migration_commands(
            "-- schema\nTCREATE notes id INT, body STR;\n\
             TINSERT notes id 1 body \"semi; colon\";\n\
             [\"PING\"];\n",
        )
        .unwrap();
        assert_eq!(commands.len(), 3);
        assert_eq!(commands[1][5], "semi; colon");
        assert_eq!(commands[2], vec!["PING"]);
    }

    #[test]
    fn filename_is_a_basename_or_generated_slug() {
        assert!(resolve_filename(Some("../bad.lux"), None).is_err());
        assert_eq!(
            resolve_filename(Some("001_create.lux"), None).unwrap(),
            "001_create.lux"
        );
        let generated = resolve_filename(None, Some("Create Messages!")).unwrap();
        assert!(generated.ends_with("_create_messages.lux"));
    }

    #[test]
    fn failed_apply_is_durable_and_blocks_later_migrations() {
        let (store, cache) = state();
        let now = Instant::now();
        let error = apply(
            &store,
            &cache,
            "001_first.lux",
            "PING;\nFAIL;",
            now,
            |command| {
                if command[0] == "FAIL" {
                    Err("boom".to_string())
                } else {
                    Ok(())
                }
            },
        )
        .unwrap_err();
        assert!(error.contains("command 2"));
        let rows = list(&store, &cache, 100, 0, now).unwrap();
        assert_eq!(rows[0].status, STATUS_FAILED);
        assert_eq!(rows[0].completed_commands, 1);
        let plan = plan(&store, &cache, "002_second.lux", "PING;", now).unwrap();
        assert_eq!(plan.action, PlanAction::Blocked);
    }

    #[test]
    fn explicit_resume_uses_reviewed_command_index() {
        let (store, cache) = state();
        let now = Instant::now();
        let _ = apply(
            &store,
            &cache,
            "001_first.lux",
            "ONE;\nTWO;",
            now,
            |command| {
                if command[0] == "TWO" {
                    Err("stop".to_string())
                } else {
                    Ok(())
                }
            },
        );
        let mut seen = Vec::new();
        let repaired = repair(
            &store,
            &cache,
            "001_first.lux",
            RepairAction::Resume { from_command: 1 },
            now,
            |command| {
                seen.push(command[0].clone());
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(seen, vec!["TWO"]);
        assert_eq!(repaired.status, STATUS_APPLIED);
        assert_eq!(repaired.completed_commands, 2);
    }

    #[test]
    fn legacy_djb2_rows_upgrade_and_remain_idempotent() {
        let (store, cache) = state();
        let now = Instant::now();
        tables::table_create(
            &store,
            &cache,
            LEDGER_TABLE,
            &[
                "filename STR,",
                "checksum STR,",
                "applied_at INT,",
                "body STR",
            ],
            now,
        )
        .unwrap();
        let body = "PING;";
        tables::table_insert(
            &store,
            &cache,
            LEDGER_TABLE,
            &[
                ("filename", "001_ping.lux"),
                ("checksum", &legacy_djb2_checksum(body)),
                ("applied_at", "1"),
                ("body", body),
            ],
            now,
        )
        .unwrap();
        let planned = plan(&store, &cache, "001_ping.lux", body, now).unwrap();
        assert_eq!(planned.action, PlanAction::AlreadyApplied);
        let records = list(&store, &cache, 10, 0, now).unwrap();
        assert_eq!(records[0].checksum_algorithm, "djb2-64");
        assert_eq!(records[0].status, STATUS_APPLIED);
    }

    #[test]
    fn duplicate_legacy_filenames_fail_closed() {
        let (store, cache) = state();
        let now = Instant::now();
        tables::table_create(
            &store,
            &cache,
            LEDGER_TABLE,
            &[
                "filename STR,",
                "checksum STR,",
                "applied_at INT,",
                "body STR",
            ],
            now,
        )
        .unwrap();
        for applied_at in ["1", "2"] {
            tables::table_insert(
                &store,
                &cache,
                LEDGER_TABLE,
                &[
                    ("filename", "duplicate.lux"),
                    ("checksum", "legacy"),
                    ("applied_at", applied_at),
                    ("body", "PING;"),
                ],
                now,
            )
            .unwrap();
        }
        let error = ensure_ledger(&store, &cache, now).unwrap_err();
        assert!(error.contains("duplicate filename"));
    }

    #[test]
    fn concurrent_apply_has_one_writer_and_one_idempotent_reader() {
        let store = Arc::new(Store::new());
        let cache = Arc::new(parking_lot::RwLock::new(tables::SchemaCache::new()));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let store = store.clone();
            let cache = cache.clone();
            workers.push(std::thread::spawn(move || {
                apply(
                    &store,
                    &cache,
                    "001_once.lux",
                    "PING;",
                    Instant::now(),
                    |_| Ok(()),
                )
                .unwrap()
                .already_applied
            }));
        }
        let results: Vec<bool> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|value| **value).count(), 1);
        assert_eq!(results.iter().filter(|value| !**value).count(), 1);
    }
}
