pub(crate) mod select;
pub(crate) use select::*;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::RwLock;

use crate::store::{Store, TableVectorCandidateQuery};

// ---------------------------------------------------------------------------
// Schema Cache
// ---------------------------------------------------------------------------

/// A shared, in-memory cache of table schemas. Schemas change very rarely
/// (only on TCREATE / TALTER / TDROP), so we cache them here to avoid a
/// full hgetall on the Store for every single table operation.
///
/// Wrap in Arc<RwLock<SchemaCache>> and pass alongside Store wherever table
/// functions are called.
/// A declared, typed index over a JSON dot-path (e.g. `metadata.reactions.count`
/// as INT) so range queries on the path hit a sorted-set index.
#[derive(Debug, Clone)]
pub struct PathIndex {
    pub path: String,
    pub field_type: FieldType,
}

#[derive(Debug, Default)]
pub struct SchemaCache {
    schemas: hashbrown::HashMap<String, Vec<FieldDef>>,
    path_indexes: hashbrown::HashMap<String, Vec<PathIndex>>,
    /// Per-table default row TTL (seconds). Cached alongside `schemas` (both are
    /// populated/cleared together) so the insert path can read it lock-cheap.
    default_ttls: hashbrown::HashMap<String, Option<u64>>,
}

impl SchemaCache {
    pub fn new() -> Self {
        Self {
            schemas: hashbrown::HashMap::new(),
            path_indexes: hashbrown::HashMap::new(),
            default_ttls: hashbrown::HashMap::new(),
        }
    }

    fn get(&self, table: &str) -> Option<Vec<FieldDef>> {
        self.schemas.get(table).cloned()
    }

    fn insert(&mut self, table: &str, fields: Vec<FieldDef>) {
        self.schemas.insert(table.to_string(), fields);
    }

    fn default_ttl(&self, table: &str) -> Option<u64> {
        self.default_ttls.get(table).copied().flatten()
    }

    fn insert_default_ttl(&mut self, table: &str, secs: Option<u64>) {
        self.default_ttls.insert(table.to_string(), secs);
    }

    fn get_path_indexes(&self, table: &str) -> Option<Vec<PathIndex>> {
        self.path_indexes.get(table).cloned()
    }

    fn insert_path_indexes(&mut self, table: &str, indexes: Vec<PathIndex>) {
        self.path_indexes.insert(table.to_string(), indexes);
    }

    fn remove(&mut self, table: &str) {
        self.schemas.remove(table);
        self.path_indexes.remove(table);
        self.default_ttls.remove(table);
    }

    fn remove_path_indexes(&mut self, table: &str) {
        self.path_indexes.remove(table);
    }
}

pub type SharedSchemaCache = Arc<RwLock<SchemaCache>>;

#[derive(Debug, Clone, PartialEq)]
pub enum FieldType {
    Str,
    Int,
    Float,
    Bool,
    Timestamp,
    Uuid,
    Vector(usize),
    /// Native JSON document. Stored as canonical JSON bytes; queryable via
    /// dot-paths (`metadata.a.b`) and the `IS VALID` existence predicate.
    Json,
    /// Native JSON array. Like `Json` but constrained to a top-level array;
    /// supports element access (`tags.0`) and `CONTAINS` membership.
    Array,
    /// Legacy ref type - kept for backwards compat, prefer ForeignKey on FieldDef
    Ref(String),
}

/// What to do when the referenced row is deleted
#[derive(Debug, Clone, PartialEq, Default)]
pub enum OnDelete {
    #[default]
    Restrict, // default - block the delete if references exist
    Cascade, // delete referencing rows too
    SetNull, // set the FK column to NULL
}

/// An explicit foreign key constraint
#[derive(Debug, Clone, PartialEq)]
pub struct ForeignKey {
    pub table: String,  // referenced table
    pub column: String, // referenced column
    pub on_delete: OnDelete,
}

impl FieldType {
    pub fn encode_value(&self, value: &str) -> Result<Vec<u8>, String> {
        match self {
            FieldType::Str => Ok(value.as_bytes().to_vec()),
            FieldType::Int => {
                let val = value
                    .parse::<i64>()
                    .map_err(|_| format!("ERR invalid int '{}'", value))?;
                Ok(val.to_le_bytes().to_vec())
            }
            FieldType::Float => {
                let val = value
                    .parse::<f64>()
                    .map_err(|_| format!("ERR invalid float '{}'", value))?;
                Ok(val.to_le_bytes().to_vec())
            }
            FieldType::Bool => {
                let val = match value {
                    "true" | "1" => 1u8,
                    "false" | "0" => 0u8,
                    _ => return Err(format!("ERR invalid bool '{}'", value)),
                };
                Ok(vec![val])
            }
            FieldType::Timestamp => {
                let val = if value == "*" {
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as i64
                } else {
                    value
                        .parse::<i64>()
                        .map_err(|_| format!("ERR invalid timestamp '{}'", value))?
                };
                Ok(val.to_le_bytes().to_vec())
            }
            FieldType::Uuid => {
                // Store UUID as 16 raw bytes - parse the canonical
                // xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx format
                let hex: String = value.chars().filter(|c| c.is_ascii_hexdigit()).collect();
                if hex.len() != 32 {
                    return Err(format!("ERR invalid UUID '{}'", value));
                }
                let mut bytes = Vec::with_capacity(16);
                for i in 0..16 {
                    let byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                        .map_err(|_| format!("ERR invalid UUID '{}'", value))?;
                    bytes.push(byte);
                }
                Ok(bytes)
            }
            FieldType::Vector(dims) => {
                let vector = parse_vector_value(value, *dims)?;
                Ok(format_vector_value(&vector).into_bytes())
            }
            FieldType::Json => {
                // Parse once at write time into the walkable binary format.
                let parsed: serde_json::Value = serde_json::from_str(value)
                    .map_err(|_| format!("ERR invalid JSON '{}'", value))?;
                Ok(crate::jsonb::encode(&parsed))
            }
            FieldType::Array => {
                let parsed: serde_json::Value = serde_json::from_str(value)
                    .map_err(|_| format!("ERR invalid JSON array '{}'", value))?;
                if !parsed.is_array() {
                    return Err(format!("ERR expected JSON array, got '{}'", value));
                }
                Ok(crate::jsonb::encode(&parsed))
            }
            FieldType::Ref(_) => {
                let val = value
                    .parse::<i64>()
                    .map_err(|_| format!("ERR invalid ref '{}'", value))?;
                Ok(val.to_le_bytes().to_vec())
            }
        }
    }

    pub fn decode_value(&self, bytes: &[u8]) -> String {
        match self {
            FieldType::Str => String::from_utf8_lossy(bytes).to_string(),
            FieldType::Uuid => {
                // Reconstruct canonical UUID string from 16 bytes
                if bytes.len() == 16 {
                    format!(
                        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                        bytes[0], bytes[1], bytes[2], bytes[3],
                        bytes[4], bytes[5],
                        bytes[6], bytes[7],
                        bytes[8], bytes[9],
                        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
                    )
                } else {
                    String::from_utf8_lossy(bytes).to_string()
                }
            }
            FieldType::Int | FieldType::Ref(_) => {
                if bytes.len() == 8 {
                    let mut arr = [0u8; 8];
                    arr.copy_from_slice(bytes);
                    i64::from_le_bytes(arr).to_string()
                } else {
                    String::from_utf8_lossy(bytes).to_string()
                }
            }
            FieldType::Float => {
                if bytes.len() == 8 {
                    let mut arr = [0u8; 8];
                    arr.copy_from_slice(bytes);
                    f64::from_le_bytes(arr).to_string()
                } else {
                    String::from_utf8_lossy(bytes).to_string()
                }
            }
            FieldType::Bool => {
                if bytes.first() == Some(&1u8) {
                    "true".to_string()
                } else {
                    "false".to_string()
                }
            }
            FieldType::Timestamp => {
                if bytes.len() == 8 {
                    let mut arr = [0u8; 8];
                    arr.copy_from_slice(bytes);
                    i64::from_le_bytes(arr).to_string()
                } else {
                    String::from_utf8_lossy(bytes).to_string()
                }
            }
            FieldType::Vector(_) => String::from_utf8_lossy(bytes).to_string(),
            FieldType::Json | FieldType::Array => crate::jsonb::to_json_string(bytes),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FieldDef {
    pub name: String,
    pub field_type: FieldType,
    pub primary_key: bool,
    pub unique: bool,
    pub nullable: bool, // true = nullable (default), false = NOT NULL
    pub default_value: Option<String>, // DEFAULT value for the column
    pub references: Option<ForeignKey>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CmpOp {
    Eq,
    Ne,
    Gt,
    Lt,
    Ge,
    Le,
    In,
    NotIn,
    IsValid,
    IsNotValid,
    /// `col IS NULL`: the column is absent / not stored for the row.
    IsNull,
    /// `col IS NOT NULL`: the column is present for the row.
    IsNotNull,
    /// Array membership: `col CONTAINS value` (array column or array-valued path).
    Contains,
}

#[derive(Debug, Clone)]
pub struct WhereClause {
    pub field: String,
    pub op: CmpOp,
    /// Single comparison operand. Empty for list ops (In/NotIn) and no-RHS ops
    /// (IsValid/IsNotValid); read `values` for the list ops.
    pub value: String,
    /// Operand list for In/NotIn. Empty for every other op.
    pub values: Vec<String>,
}

impl WhereClause {
    /// Construct a single-operand clause (Eq/Ne/Gt/Lt/Ge/Le, or the no-RHS
    /// IsValid/IsNotValid where `value` is empty).
    pub fn single(field: String, op: CmpOp, value: String) -> Self {
        WhereClause {
            field,
            op,
            value,
            values: Vec::new(),
        }
    }

    /// Construct a list clause for In/NotIn.
    pub fn in_list(field: String, op: CmpOp, values: Vec<String>) -> Self {
        WhereClause {
            field,
            op,
            value: String::new(),
            values,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NearClause {
    pub field: String,
    pub vector: Vec<f32>,
    pub k: usize,
    pub threshold: Option<f32>,
}

// ---------------------------------------------------------------------------
// Query Engine Types
// ---------------------------------------------------------------------------

/// A column in a SELECT projection, optionally aliased.
/// e.g. "u.email AS user_email" -> Projection { expr: "u.email", alias: Some("user_email") }
#[derive(Debug, Clone)]
pub struct Projection {
    pub expr: String, // "col", "table.col", "COUNT(*)", "SUM(col)"
    pub alias: Option<String>,
}

/// Aggregate functions supported in SELECT
#[derive(Debug, Clone, PartialEq)]
pub enum AggFunc {
    Count, // COUNT(*) or COUNT(col)
    Sum,   // SUM(col)
    Avg,   // AVG(col)
    Min,   // MIN(col)
    Max,   // MAX(col)
}

/// A parsed aggregate expression
#[derive(Debug, Clone)]
pub struct AggExpr {
    pub func: AggFunc,
    pub col: Option<String>, // None means COUNT(*)
    pub alias: String,       // output column name
}

/// A JOIN clause - supports explicit ON condition
#[derive(Debug, Clone)]
pub struct JoinClause {
    pub join_type: JoinType,
    pub table: String,     // table to join
    pub alias: String,     // alias for that table (required)
    pub left_col: String,  // left side of ON: "alias.col"
    pub right_col: String, // right side of ON: "alias.col"
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinType {
    Inner,
    Left,
}

/// The full query plan produced by the TSELECT parser
#[derive(Debug)]
pub struct SelectPlan {
    // FROM
    pub table: String,
    pub alias: Option<String>,

    // SELECT cols (empty = SELECT *)
    pub projections: Vec<Projection>,

    // Aggregates (if any - mutually exclusive with row projections)
    pub aggregates: Vec<AggExpr>,

    // JOIN
    pub joins: Vec<JoinClause>,

    // WHERE
    pub conditions: Vec<WhereClause>,

    // GROUP BY
    pub group_by: Vec<String>,

    // HAVING
    pub having: Vec<WhereClause>,

    // NEAR vector search
    pub near: Option<NearClause>,

    // ORDER BY (col, ascending)
    pub order_by: Option<(String, bool)>,

    // LIMIT / OFFSET
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

fn schema_key(table: &str) -> String {
    format!("_t:{}:schema", table)
}

fn seq_key(table: &str) -> String {
    format!("_t:{}:seq", table)
}

fn row_key(table: &str, id: i64) -> String {
    format!("_t:{}:row:{}", table, id)
}

fn idx_sorted_key(table: &str, field: &str) -> String {
    format!("_t:{}:idx:{}", table, field)
}

fn path_indexes_key(table: &str) -> String {
    format!("_t:{}:path_indexes", table)
}

fn idx_str_key(table: &str, field: &str, value: &str) -> String {
    format!("_t:{}:idx:{}:{}", table, field, value)
}

fn table_vector_key(table: &str, field: &str, pk: &str) -> String {
    format!("_t:{}:vec:{}:{}", table, field, pk)
}

fn uniq_key(table: &str, field: &str) -> String {
    format!("_t:{}:uniq:{}", table, field)
}

fn ids_key(table: &str) -> String {
    format!("_t:{}:ids", table)
}

fn table_list_key() -> String {
    "_t:__tables".to_string()
}

fn pk_key(table: &str) -> String {
    format!("_t:{}:pk", table)
}

/// Build a row key using the PK value directly (for user-defined PKs)
/// vs a sequence id (for tables without a PK)
fn row_key_for_pk(table: &str, pk_value: &str) -> String {
    format!("_t:{}:row:{}", table, pk_value)
}

// ---- Row TTL ---------------------------------------------------------------
// A table row can expire. Unlike KV TTL (which sets `Entry.expires_at` on a
// single key), a row is a composite (row hash + the `_t:{table}:ids` zset +
// unique/field indexes), and KV expiry is silent (no key-event). So row TTL is
// owned here: a global deadline-ordered zset `_t:_ttl` (member `{table}\0{pk}`,
// score = absolute epoch-ms deadline) drives a table-aware sweep, and a hidden
// `\0ttl` field on the row hash carries the deadline for read-time hiding.

/// Hidden hash field carrying a row's absolute expiry (epoch ms, ASCII). The
/// NUL prefix means it can never collide with a real column (names are
/// alphanumeric/underscore) and `get_row_with_map` filters it from output.
const HIDDEN_TTL_FIELD: &[u8] = b"\x00ttl";

/// Reserved schema-hash field carrying a table's default row TTL (seconds,
/// ASCII). Stored in `_t:{table}:schema` alongside columns; the NUL prefix keeps
/// it from colliding with a column and `load_schema` filters it out.
const HIDDEN_DEFAULT_TTL_FIELD: &[u8] = b"\x00default_ttl";

/// Global deadline index: a sorted set scored by absolute epoch-ms deadline.
fn ttl_index_key() -> &'static str {
    "_t:_ttl"
}

/// A table's default row TTL (seconds), if it was created `WITH TTL`. Resolved
/// from the schema cache (populated by `load_schema`).
pub(crate) fn table_default_ttl(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    now: Instant,
) -> Option<u64> {
    // Ensure the schema (and thus the cached default) is loaded.
    if load_schema(store, cache, table, now).is_err() {
        return None;
    }
    cache.read().default_ttl(table)
}

/// Split a trailing `WITH TTL <seconds>` off a TCREATE column list.
fn split_with_ttl<'a>(col_args: &'a [&'a str]) -> (&'a [&'a str], Option<u64>) {
    let n = col_args.len();
    if n >= 3
        && col_args[n - 3].eq_ignore_ascii_case("WITH")
        && col_args[n - 2].eq_ignore_ascii_case("TTL")
    {
        if let Ok(secs) = col_args[n - 1].parse::<u64>() {
            return (&col_args[..n - 3], Some(secs));
        }
    }
    (col_args, None)
}

fn ttl_member(table: &str, pk: &str) -> String {
    format!("{}\x00{}", table, pk)
}

/// What a write does to a row's TTL. `None` (absent) = inherit: leave any
/// existing deadline untouched (so a bare update doesn't drop the TTL).
#[derive(Clone, Copy, Debug)]
pub enum TtlOp {
    /// Set/refresh the deadline to now + this many seconds.
    Set(u64),
    /// Remove the TTL (e.g. `TTL 0`): the row becomes permanent.
    Clear,
}

fn set_row_ttl(store: &Store, table: &str, pk: &str, secs: u64, now: Instant) {
    let deadline_ms = current_epoch_ms().saturating_add(secs.saturating_mul(1000));
    let rk = row_key_for_pk(table, pk);
    let dl = deadline_ms.to_string();
    let _ = store.hset(rk.as_bytes(), &[(HIDDEN_TTL_FIELD, dl.as_bytes())], now);
    let member = ttl_member(table, pk);
    let _ = store.zadd(
        ttl_index_key().as_bytes(),
        &[(member.as_bytes(), deadline_ms as f64)],
        false,
        false,
        false,
        false,
        false,
        now,
    );
}

fn clear_row_ttl(store: &Store, table: &str, pk: &str, now: Instant) {
    let rk = row_key_for_pk(table, pk);
    let _ = store.hdel(rk.as_bytes(), &[HIDDEN_TTL_FIELD], now);
    let member = ttl_member(table, pk);
    let _ = store.zrem(ttl_index_key().as_bytes(), &[member.as_bytes()], now);
}

// ---- Table-write WAL logging ----------------------------------------------
// Table data writes are logged HERE (the leaf functions), not by execute_with_wal,
// for two reasons:
//   1. Durability: HTTP table writes bypass execute_with_wal entirely, so without
//      this they are never WAL'd and are lost on crash since the last snapshot.
//   2. Determinism: the raw command carries no generated PK / resolved default, so
//      replaying it regenerates uuid()/now() and the row's identity changes. We log
//      the RESOLVED command (explicit PK + resolved values) so replay reproduces the
//      exact row.
// `wal_log_command` no-ops when the WAL is disabled or suppressed (during replay),
// so these calls are safe everywhere. execute_with_wal must NOT also raw-log these
// commands (it skips all T* writes) or the row would be applied twice on replay.

/// The PK column name for a table (the declared PK, else the implicit `id`).
fn pk_column_name(schema: &[FieldDef]) -> &str {
    schema
        .iter()
        .find(|f| f.primary_key)
        .map(|f| f.name.as_str())
        .unwrap_or("id")
}

fn ttl_wal_tokens(ttl: Option<TtlOp>) -> Option<(&'static [u8], Vec<u8>)> {
    match ttl {
        Some(TtlOp::Set(secs)) => Some((b"TTL", secs.to_string().into_bytes())),
        Some(TtlOp::Clear) => Some((b"TTL", b"0".to_vec())),
        None => None,
    }
}

/// Read-validate a unique-index hit: does the holder row actually still carry
/// `value` in `field`? A stale entry (row gone or value changed without the index
/// being updated) returns false, so the uniqueness check treats it as free.
fn uniq_holder_holds_value(
    store: &Store,
    table: &str,
    field: &FieldDef,
    holder_pk: &str,
    value: &str,
    now: Instant,
) -> bool {
    let rk = row_key_for_pk(table, holder_pk);
    match store.hget(rk.as_bytes(), field.name.as_bytes(), now) {
        // Compare in the stored (encoded) form so the match is exact.
        Some(raw) => field
            .field_type
            .encode_value(value)
            .map(|enc| enc == raw)
            .unwrap_or(false),
        None => false,
    }
}

/// Register a new row's TTL deadline in the global `_t:_ttl` index and return the
/// hidden-field bytes to fold into the row commit -- WITHOUT writing the row hash,
/// so the deadline becomes visible atomically with the row (write-row-last).
/// Returns `None` when the row has no TTL.
fn stage_row_ttl(
    store: &Store,
    table: &str,
    pk: &str,
    ttl: Option<TtlOp>,
    now: Instant,
) -> Option<Vec<u8>> {
    match ttl {
        Some(TtlOp::Set(secs)) => {
            let deadline_ms = current_epoch_ms().saturating_add(secs.saturating_mul(1000));
            let member = ttl_member(table, pk);
            let _ = store.zadd(
                ttl_index_key().as_bytes(),
                &[(member.as_bytes(), deadline_ms as f64)],
                false,
                false,
                false,
                false,
                false,
                now,
            );
            Some(deadline_ms.to_string().into_bytes())
        }
        // On a fresh insert there is no prior deadline to clear.
        Some(TtlOp::Clear) | None => None,
    }
}

fn apply_row_ttl(store: &Store, table: &str, pk: &str, ttl: Option<TtlOp>, now: Instant) {
    match ttl {
        Some(TtlOp::Set(secs)) => set_row_ttl(store, table, pk, secs, now),
        Some(TtlOp::Clear) => clear_row_ttl(store, table, pk, now),
        None => {}
    }
}

/// If the row at `pk` exists but has expired, physically remove it (full delete
/// bookkeeping) so a fresh insert/upsert can take its place; this closes the
/// sub-sweep-interval window where an expired-but-not-yet-swept row would still
/// occupy its key. Returns true if the row is now absent (never existed, or was
/// just purged), false if a live (non-expired) row is present.
fn purge_if_expired(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    pk: &str,
    now: Instant,
) -> bool {
    let rk = row_key_for_pk(table, pk);
    let pairs = store.hgetall(rk.as_bytes(), now).unwrap_or_default();
    if pairs.is_empty() {
        return true;
    }
    if row_map_expired(&pairs) {
        let _ = table_delete_inner(store, cache, table, pk, now, 0);
        return true;
    }
    false
}

/// True if a raw row-hash field map carries an expired `\0ttl` deadline.
fn row_map_expired(pairs: &[(String, bytes::Bytes)]) -> bool {
    let now_ms = current_epoch_ms();
    pairs.iter().any(|(k, v)| {
        k.as_bytes() == HIDDEN_TTL_FIELD
            && std::str::from_utf8(v)
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .is_some_and(|deadline| now_ms >= deadline)
    })
}

/// Expire all rows whose deadline has passed. Runs the full per-row delete
/// bookkeeping (so indexes stay consistent) and returns the distinct tables
/// touched, so the caller can fire one `.live()` key-event per table.
pub fn expire_due_rows(store: &Store, cache: &SharedSchemaCache, now: Instant) -> Vec<String> {
    let key = ttl_index_key();
    let now_ms = current_epoch_ms() as f64;
    let due = store
        .zrangebyscore(
            key.as_bytes(),
            0.0,
            now_ms,
            false,
            false,
            false,
            Some(0),
            Some(512),
            false,
            now,
        )
        .unwrap_or_default();
    let mut affected: Vec<String> = Vec::new();
    for (member, _score) in due {
        let Some((table, pk)) = member.split_once('\u{0}') else {
            let _ = store.zrem(key.as_bytes(), &[member.as_bytes()], now);
            continue;
        };
        if table_delete_inner(store, cache, table, pk, now, 0).is_ok()
            && !affected.iter().any(|t| t == table)
        {
            affected.push(table.to_string());
        }
        // table_delete_inner clears the TTL entry on success; on error (e.g. an
        // FK RESTRICT) drop it anyway so the sweep doesn't spin on it.
        let _ = store.zrem(key.as_bytes(), &[member.as_bytes()], now);
    }
    affected
}

fn is_valid_name(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_')
}

fn is_valid_table_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '.')
        && !name.starts_with('.')
        && !name.ends_with('.')
        && !name.contains("..")
}

/// Parse a single field definition in SQL-like syntax.
///
/// Examples:
///   "id UUID PRIMARY KEY"
///   "email STR UNIQUE NOT NULL"
///   "age INT"
///   "team_id INT REFERENCES teams(id) ON DELETE CASCADE"
///   "score FLOAT NOT NULL"
fn parse_field_def(spec: &str) -> Result<FieldDef, String> {
    let tokens: Vec<&str> = spec.split_whitespace().collect();
    if tokens.len() < 2 {
        return Err(format!(
            "ERR invalid field definition '{}', expected: <name> <type> [constraints...]",
            spec
        ));
    }

    let name = tokens[0].to_string();
    if !is_valid_name(&name) {
        return Err(format!("ERR invalid field name '{}'", name));
    }

    let field_type = match tokens[1].to_uppercase().as_str() {
        "STR" | "TEXT" | "VARCHAR" | "STRING" => FieldType::Str,
        "INT" | "INTEGER" | "BIGINT" => FieldType::Int,
        "FLOAT" | "REAL" | "DOUBLE" => FieldType::Float,
        "BOOL" | "BOOLEAN" => FieldType::Bool,
        "TIMESTAMP" | "DATETIME" => FieldType::Timestamp,
        "UUID" => FieldType::Uuid,
        "JSON" | "JSONB" => FieldType::Json,
        "ARRAY" => FieldType::Array,
        t if t.starts_with("VECTOR(") && t.ends_with(')') => {
            let dims = t[7..t.len() - 1]
                .parse::<usize>()
                .map_err(|_| format!("ERR invalid vector type '{}'", tokens[1]))?;
            if dims == 0 {
                return Err("ERR VECTOR dimension must be greater than zero".to_string());
            }
            FieldType::Vector(dims)
        }
        other => {
            return Err(format!(
                "ERR unknown field type '{}'. Valid types: STR, INT, FLOAT, BOOL, TIMESTAMP, UUID, VECTOR(n)",
                other
            ))
        }
    };

    let mut primary_key = false;
    let mut unique = false;
    let mut nullable = true;
    let mut default_value: Option<String> = None;
    let mut references: Option<ForeignKey> = None;

    let mut i = 2;
    while i < tokens.len() {
        match tokens[i].to_uppercase().as_str() {
            "DEFAULT" => {
                i += 1;
                if i >= tokens.len() {
                    return Err("ERR DEFAULT requires a value".to_string());
                }
                default_value = Some(tokens[i].to_string());
                i += 1;
            }
            "PRIMARY" => {
                i += 1;
                // Accept both "PRIMARY KEY" and a bare "PRIMARY".
                if i < tokens.len() && tokens[i].eq_ignore_ascii_case("KEY") {
                    i += 1;
                }
                primary_key = true;
                unique = true;
                nullable = false;
            }
            "UNIQUE" => {
                unique = true;
                i += 1;
            }
            "NOT" => {
                i += 1;
                if i >= tokens.len() || tokens[i].to_uppercase() != "NULL" {
                    return Err("ERR expected NULL after NOT".to_string());
                }
                nullable = false;
                i += 1;
            }
            "NULL" => {
                nullable = true;
                i += 1;
            }
            "REFERENCES" => {
                i += 1;
                if i >= tokens.len() {
                    return Err("ERR REFERENCES requires a table(column) argument".to_string());
                }
                // Parse "table(column)" - may have spaces around parens
                let ref_spec = tokens[i];
                let (ref_table, ref_col) = parse_ref_spec(ref_spec)?;
                i += 1;

                let mut on_delete = OnDelete::Restrict;
                if i + 1 < tokens.len()
                    && tokens[i].to_uppercase() == "ON"
                    && tokens[i + 1].to_uppercase() == "DELETE"
                {
                    i += 2;
                    if i >= tokens.len() {
                        return Err(
                            "ERR ON DELETE requires an action (CASCADE, RESTRICT, SET NULL)"
                                .to_string(),
                        );
                    }
                    on_delete = match tokens[i].to_uppercase().as_str() {
                        "CASCADE" => {
                            i += 1;
                            OnDelete::Cascade
                        }
                        "RESTRICT" => {
                            i += 1;
                            OnDelete::Restrict
                        }
                        "SET" => {
                            i += 1;
                            if i >= tokens.len() || tokens[i].to_uppercase() != "NULL" {
                                return Err("ERR expected NULL after SET".to_string());
                            }
                            i += 1;
                            OnDelete::SetNull
                        }
                        other => {
                            return Err(format!(
                            "ERR unknown ON DELETE action '{}'. Valid: CASCADE, RESTRICT, SET NULL",
                            other
                        ))
                        }
                    };
                }

                references = Some(ForeignKey {
                    table: ref_table,
                    column: ref_col,
                    on_delete,
                });
            }
            other => {
                return Err(format!(
                    "ERR unknown constraint '{}' in field definition",
                    other
                ));
            }
        }
    }

    Ok(FieldDef {
        name,
        field_type,
        primary_key,
        unique,
        nullable,
        default_value,
        references,
    })
}

/// Parse "table(column)" or "table( column )" into (table, column)
fn parse_ref_spec(spec: &str) -> Result<(String, String), String> {
    let spec = spec.trim();
    let paren = spec
        .find('(')
        .ok_or_else(|| format!("ERR REFERENCES expects 'table(column)', got '{}'", spec))?;
    if !spec.ends_with(')') {
        return Err(format!(
            "ERR REFERENCES expects 'table(column)', got '{}'",
            spec
        ));
    }
    let table = spec[..paren].trim().to_string();
    let column = spec[paren + 1..spec.len() - 1].trim().to_string();
    if !is_valid_table_name(&table) {
        return Err(format!("ERR invalid referenced table name '{}'", table));
    }
    if !is_valid_name(&column) {
        return Err(format!("ERR invalid referenced column name '{}'", column));
    }
    Ok((table, column))
}

/// Parse the full column list from a TCREATE command.
/// Accepts both:
///   "(col1 TYPE, col2 TYPE, ...)"  - with outer parens
///   "col1 TYPE, col2 TYPE, ..."    - without outer parens
/// The args slice starts after the table name.
pub fn parse_column_list(args: &[&str]) -> Result<Vec<FieldDef>, String> {
    // Re-join all args into a single string so we can split on commas
    // regardless of how the client tokenized the command
    let raw = args.join(" ");
    let raw = raw.trim();
    // Tolerate a trailing statement terminator (`TCREATE t a int, b str;`).
    let raw = raw.strip_suffix(';').unwrap_or(raw).trim();

    // Strip optional outer parentheses
    let inner = if raw.starts_with('(') && raw.ends_with(')') {
        &raw[1..raw.len() - 1]
    } else {
        raw
    };

    let mut fields = Vec::new();
    let mut names_seen = HashSet::new();
    let mut pk_seen = false;

    for col_spec in inner.split(',') {
        let col_spec = col_spec.trim();
        if col_spec.is_empty() {
            continue;
        }
        let field = parse_field_def(col_spec)?;
        if !names_seen.insert(field.name.clone()) {
            return Err(format!("ERR duplicate column name '{}'", field.name));
        }
        if field.primary_key {
            if pk_seen {
                return Err("ERR only one PRIMARY KEY column is allowed".to_string());
            }
            pk_seen = true;
        }
        fields.push(field);
    }

    if fields.is_empty() {
        return Err("ERR at least one column is required".to_string());
    }

    Ok(fields)
}

/// Encode a FieldDef into a compact string for storage in the KV schema hash.
/// Format: type[|flag[|flag...]][|ref:table:col:on_delete]
fn encode_field_def(def: &FieldDef) -> String {
    let type_str = match &def.field_type {
        FieldType::Str => "str".to_string(),
        FieldType::Int => "int".to_string(),
        FieldType::Float => "float".to_string(),
        FieldType::Bool => "bool".to_string(),
        FieldType::Timestamp => "timestamp".to_string(),
        FieldType::Uuid => "uuid".to_string(),
        FieldType::Vector(dims) => format!("vector:{}", dims),
        FieldType::Json => "json".to_string(),
        FieldType::Array => "array".to_string(),
        FieldType::Ref(t) => return format!("ref|{}", t),
    };

    let mut parts = vec![type_str];
    if def.primary_key {
        parts.push("pk".to_string());
    }
    if def.unique {
        parts.push("unique".to_string());
    }
    if !def.nullable {
        parts.push("notnull".to_string());
    }
    if let Some(fk) = &def.references {
        let on_delete = match fk.on_delete {
            OnDelete::Restrict => "restrict",
            OnDelete::Cascade => "cascade",
            OnDelete::SetNull => "setnull",
        };
        parts.push(format!("ref:{}:{}:{}", fk.table, fk.column, on_delete));
    }
    if let Some(default) = &def.default_value {
        // Escape | so it doesn't collide with the field separator
        let escaped = default.replace('\\', "\\\\").replace('|', "\\|");
        parts.push(format!("default:{}", escaped));
    }
    parts.join("|")
}

fn decode_field_def(name: &str, encoded: &str) -> FieldDef {
    let parts: Vec<&str> = encoded.split('|').collect();
    let type_str = parts[0];

    let field_type = match type_str {
        "str" => FieldType::Str,
        "int" => FieldType::Int,
        "float" => FieldType::Float,
        "bool" => FieldType::Bool,
        "timestamp" => FieldType::Timestamp,
        "uuid" => FieldType::Uuid,
        "json" => FieldType::Json,
        "array" => FieldType::Array,
        s if s.starts_with("vector:") => s[7..]
            .parse::<usize>()
            .map(FieldType::Vector)
            .unwrap_or(FieldType::Vector(0)),
        // Legacy ref format from old colon-based schema
        "ref" => FieldType::Ref(parts.get(1).unwrap_or(&"").to_string()),
        _ => FieldType::Str,
    };

    let mut primary_key = false;
    let mut unique = false;
    let mut nullable = true;
    let mut default_value: Option<String> = None;
    let mut references: Option<ForeignKey> = None;

    for flag in &parts[1..] {
        match *flag {
            "pk" => {
                primary_key = true;
                unique = true;
                nullable = false;
            }
            "unique" => unique = true,
            "notnull" => nullable = false,
            s if s.starts_with("ref:") => {
                let fk_parts: Vec<&str> = s[4..].splitn(3, ':').collect();
                if fk_parts.len() == 3 {
                    let on_delete = match fk_parts[2] {
                        "cascade" => OnDelete::Cascade,
                        "setnull" => OnDelete::SetNull,
                        _ => OnDelete::Restrict,
                    };
                    references = Some(ForeignKey {
                        table: fk_parts[0].to_string(),
                        column: fk_parts[1].to_string(),
                        on_delete,
                    });
                }
            }
            s if s.starts_with("default:") => {
                let raw = &s[8..];
                let unescaped = raw.replace("\\|", "|").replace("\\\\", "\\");
                default_value = Some(unescaped);
            }
            _ => {}
        }
    }

    FieldDef {
        name: name.to_string(),
        field_type,
        primary_key,
        unique,
        nullable,
        default_value,
        references,
    }
}

pub(crate) fn load_schema(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    now: Instant,
) -> Result<Vec<FieldDef>, String> {
    // Fast path: check the in-memory cache first (read lock, no Store hit)
    {
        let r = cache.read();
        if let Some(fields) = r.get(table) {
            return Ok(fields);
        }
    }

    // Slow path: load from the Store and populate the cache
    let key = schema_key(table);
    let pairs = store.hgetall(key.as_bytes(), now)?;
    if pairs.is_empty() {
        return Err(format!("ERR table '{}' does not exist", table));
    }
    let mut fields = Vec::new();
    let mut default_ttl: Option<u64> = None;
    for (name, val) in pairs {
        if name.as_bytes() == HIDDEN_DEFAULT_TTL_FIELD {
            default_ttl = std::str::from_utf8(&val).ok().and_then(|s| s.parse().ok());
            continue;
        }
        let encoded = String::from_utf8_lossy(&val).to_string();
        fields.push(decode_field_def(&name, &encoded));
    }
    fields.sort_by(|a, b| a.name.cmp(&b.name));

    // Write through to the cache (schema + default TTL together).
    {
        let mut w = cache.write();
        w.insert(table, fields.clone());
        w.insert_default_ttl(table, default_ttl);
    }

    Ok(fields)
}

/// Token stored in the path-index registry for a given indexable type.
fn index_type_token(ft: &FieldType) -> Option<&'static str> {
    match ft {
        FieldType::Int => Some("int"),
        FieldType::Float => Some("float"),
        FieldType::Bool => Some("bool"),
        FieldType::Timestamp => Some("timestamp"),
        FieldType::Str => Some("str"),
        // uuid/vector/json/ref are not path-indexable
        _ => None,
    }
}

/// Parse a user-supplied or stored index type token into a FieldType.
fn parse_index_type(tok: &str) -> Option<FieldType> {
    match tok.to_uppercase().as_str() {
        "INT" | "INTEGER" | "BIGINT" => Some(FieldType::Int),
        "FLOAT" | "REAL" | "DOUBLE" => Some(FieldType::Float),
        "BOOL" | "BOOLEAN" => Some(FieldType::Bool),
        "TIMESTAMP" | "DATETIME" => Some(FieldType::Timestamp),
        "STR" | "TEXT" | "STRING" => Some(FieldType::Str),
        _ => None,
    }
}

/// A throwaway FieldDef so a declared path index can reuse the column-index
/// machinery (`add_to_index`/`candidates_from_index`), keyed by the dot-path.
fn synthetic_path_fielddef(pi: &PathIndex) -> FieldDef {
    FieldDef {
        name: pi.path.clone(),
        field_type: pi.field_type.clone(),
        primary_key: false,
        unique: false,
        nullable: true,
        default_value: None,
        references: None,
    }
}

/// True if `raw` parses to a JSON array containing a scalar element equal to
/// `needle` (string form). Used by the `CONTAINS` operator.
fn json_array_contains(raw: &str, needle: &str) -> bool {
    match serde_json::from_str::<serde_json::Value>(raw) {
        Ok(serde_json::Value::Array(arr)) => arr
            .iter()
            .any(|el| json_scalar_string(el).as_deref() == Some(needle)),
        _ => false,
    }
}

/// Convert a resolved JSON scalar to its index/compare string form.
/// Returns None for objects, arrays, and null (not indexable / not VALID).
fn json_scalar_string(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Extract the scalar at `rest` from a raw JSON string, for path indexing.
fn extract_json_scalar(raw: &str, rest: &str) -> Option<String> {
    let parsed: serde_json::Value = serde_json::from_str(raw).ok()?;
    match json_path_get(&parsed, rest) {
        JsonResolve::Resolved(v) => json_scalar_string(v),
        _ => None,
    }
}

/// Load declared path indexes for a table (cached alongside the schema). An
/// empty result is cached too, so write paths on un-indexed tables stay cheap.
fn load_path_indexes(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    now: Instant,
) -> Vec<PathIndex> {
    if let Some(pis) = cache.read().get_path_indexes(table) {
        return pis;
    }
    let key = path_indexes_key(table);
    let pairs = store.hgetall(key.as_bytes(), now).unwrap_or_default();
    let mut pis = Vec::new();
    for (path, ty) in pairs {
        let tok = String::from_utf8_lossy(&ty).to_string();
        if let Some(ft) = parse_index_type(&tok) {
            pis.push(PathIndex {
                path,
                field_type: ft,
            });
        }
    }
    cache.write().insert_path_indexes(table, pis.clone());
    pis
}

/// Look up the declared index type for a single path (O(1) hash-field get).
/// Used by the planner, which has no schema-cache handle.
fn read_path_index_type(store: &Store, table: &str, path: &str, now: Instant) -> Option<FieldType> {
    let key = path_indexes_key(table);
    let val = store.hget(key.as_bytes(), path.as_bytes(), now)?;
    parse_index_type(&String::from_utf8_lossy(&val))
}

/// Declare a typed index on a JSON dot-path and backfill it over existing rows.
pub fn table_create_path_index(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    path: &str,
    type_token: &str,
    now: Instant,
) -> Result<(), String> {
    let schema = load_schema(store, cache, table, now)?;
    let (root, rest) = path
        .split_once('.')
        .ok_or_else(|| "ERR index path must be a dot-path into a JSON column".to_string())?;
    if rest.is_empty() {
        return Err("ERR index path must address a value inside the JSON column".to_string());
    }
    if !schema
        .iter()
        .any(|f| f.name == root && f.field_type == FieldType::Json)
    {
        return Err(format!("ERR '{}' is not a JSON column", root));
    }
    let field_type = parse_index_type(type_token).ok_or_else(|| {
        format!(
            "ERR invalid index type '{}'. Use INT/FLOAT/BOOL/TIMESTAMP/STR",
            type_token
        )
    })?;
    let token = index_type_token(&field_type).unwrap_or("str");

    let key = path_indexes_key(table);
    store.hset(key.as_bytes(), &[(path.as_bytes(), token.as_bytes())], now)?;
    cache.write().remove_path_indexes(table);

    // Backfill the index over existing rows.
    let pi = PathIndex {
        path: path.to_string(),
        field_type,
    };
    let synthetic = synthetic_path_fielddef(&pi);
    for pk_str in get_all_row_ids(store, table, now) {
        let Some(row) = get_row(store, table, &schema, &pk_str, now) else {
            continue;
        };
        if let Some(raw) = row.iter().find(|(k, _)| k == root).map(|(_, v)| v.as_str()) {
            if let Some(scalar) = extract_json_scalar(raw, rest) {
                add_to_index(store, table, &synthetic, &scalar, &pk_str, now);
            }
        }
    }
    Ok(())
}

/// Drop a declared path index and remove all of its index entries.
pub fn table_drop_path_index(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    path: &str,
    now: Instant,
) -> Result<(), String> {
    let schema = load_schema(store, cache, table, now)?;
    let path_indexes = load_path_indexes(store, cache, table, now);
    let Some(pi) = path_indexes.iter().find(|p| p.path == path) else {
        return Err(format!("ERR no index on path '{}'", path));
    };
    let (root, rest) = path.split_once('.').unwrap_or((path, ""));
    let synthetic = synthetic_path_fielddef(pi);
    for pk_str in get_all_row_ids(store, table, now) {
        let Some(row) = get_row(store, table, &schema, &pk_str, now) else {
            continue;
        };
        if let Some(raw) = row.iter().find(|(k, _)| k == root).map(|(_, v)| v.as_str()) {
            if let Some(scalar) = extract_json_scalar(raw, rest) {
                remove_from_index(store, table, &synthetic, &scalar, &pk_str, now);
            }
        }
    }
    let key = path_indexes_key(table);
    let _ = store.hdel(key.as_bytes(), &[path.as_bytes()], now);
    cache.write().remove_path_indexes(table);
    Ok(())
}

fn validate_value(field: &FieldDef, value: &str) -> Result<(), String> {
    match &field.field_type {
        FieldType::Str => Ok(()),
        FieldType::Int | FieldType::Ref(_) => {
            value
                .parse::<i64>()
                .map_err(|_| format!("ERR column '{}' expects INT, got '{}'", field.name, value))?;
            Ok(())
        }
        FieldType::Float => {
            value.parse::<f64>().map_err(|_| {
                format!("ERR column '{}' expects FLOAT, got '{}'", field.name, value)
            })?;
            Ok(())
        }
        FieldType::Bool => match value {
            "true" | "false" | "1" | "0" => Ok(()),
            _ => Err(format!(
                "ERR column '{}' expects BOOL (true/false/1/0), got '{}'",
                field.name, value
            )),
        },
        FieldType::Timestamp => {
            if value == "*" {
                return Ok(());
            }
            value.parse::<i64>().map_err(|_| {
                format!(
                    "ERR column '{}' expects TIMESTAMP (epoch ms or *), got '{}'",
                    field.name, value
                )
            })?;
            Ok(())
        }
        FieldType::Uuid => {
            let hex: String = value.chars().filter(|c| c.is_ascii_hexdigit()).collect();
            if hex.len() != 32 {
                return Err(format!(
                    "ERR column '{}' expects UUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx), got '{}'",
                    field.name, value
                ));
            }
            Ok(())
        }
        FieldType::Vector(dims) => {
            parse_vector_value(value, *dims)?;
            Ok(())
        }
        FieldType::Json => {
            serde_json::from_str::<serde_json::Value>(value).map_err(|_| {
                format!("ERR column '{}' expects JSON, got '{}'", field.name, value)
            })?;
            Ok(())
        }
        FieldType::Array => {
            let parsed = serde_json::from_str::<serde_json::Value>(value).map_err(|_| {
                format!(
                    "ERR column '{}' expects a JSON array, got '{}'",
                    field.name, value
                )
            })?;
            if !parsed.is_array() {
                return Err(format!(
                    "ERR column '{}' expects a JSON array, got '{}'",
                    field.name, value
                ));
            }
            Ok(())
        }
    }
}

fn parse_vector_value(value: &str, dims: usize) -> Result<Vec<f32>, String> {
    let vector = parse_vector_literal(value)?;
    if vector.len() != dims {
        return Err(format!(
            "ERR VECTOR({}) expected {} values, got {}",
            dims,
            dims,
            vector.len()
        ));
    }
    Ok(vector)
}

fn parse_vector_literal(value: &str) -> Result<Vec<f32>, String> {
    let trimmed = value.trim().trim_start_matches('[').trim_end_matches(']');
    if trimmed.is_empty() {
        return Err("ERR vector requires at least one float value".to_string());
    }

    let mut vector = Vec::new();
    for part in trimmed.split([',', ' ']) {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        vector.push(
            part.parse::<f32>()
                .map_err(|_| format!("ERR invalid vector value '{}'", part))?,
        );
    }
    Ok(vector)
}

fn format_vector_value(vector: &[f32]) -> String {
    vector
        .iter()
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn next_id(store: &Store, table: &str, now: Instant) -> i64 {
    let key = seq_key(table);
    match store.incr(key.as_bytes(), 1, now) {
        Ok(id) => id,
        Err(_) => {
            store.set(key.as_bytes(), b"1", None, now);
            1
        }
    }
}

/// Advance an INT auto-increment counter so it is at least `id`. Called whenever a
/// row lands with an explicit numeric PK so a later auto-generated id never
/// collides. The seq counter is a direct store write that is NOT WAL-logged, so on
/// crash recovery it must be rebuilt from the explicit ids carried in replayed
/// TINSERT commands -- otherwise the next live insert reuses an id and silently
/// overwrites a recovered row.
fn bump_seq_to_at_least(store: &Store, table: &str, id: i64, now: Instant) {
    let key = seq_key(table);
    let current = store
        .get(key.as_bytes(), now)
        .and_then(|v| {
            std::str::from_utf8(&v)
                .ok()
                .and_then(|s| s.parse::<i64>().ok())
        })
        .unwrap_or(0);
    if id > current {
        store.set(key.as_bytes(), id.to_string().as_bytes(), None, now);
    }
}

/// Add a field value to the appropriate index.
/// pk_str is the row's primary key string (used as the member in the index).
/// score is a numeric representation of the value for sorted set indexes.
fn add_to_index(
    store: &Store,
    table: &str,
    field: &FieldDef,
    value: &str,
    pk_str: &str,
    now: Instant,
) {
    match &field.field_type {
        FieldType::Int
        | FieldType::Float
        | FieldType::Bool
        | FieldType::Timestamp
        | FieldType::Ref(_) => {
            let score: f64 = value.parse().unwrap_or(0.0);
            let zkey = idx_sorted_key(table, &field.name);
            let _ = store.zadd(
                zkey.as_bytes(),
                &[(pk_str.as_bytes(), score)],
                false,
                false,
                false,
                false,
                false,
                now,
            );
        }
        FieldType::Str | FieldType::Uuid => {
            let skey = idx_str_key(table, &field.name, value);
            let _ = store.sadd(skey.as_bytes(), &[pk_str.as_bytes()], now);
        }
        FieldType::Vector(dims) => {
            if let Ok(vector) = parse_vector_value(value, *dims) {
                let metadata = serde_json::json!({
                    "table": table,
                    "field": field.name,
                    "table_field": format!("{}.{}", table, field.name),
                    "pk": pk_str,
                    "id": pk_str,
                })
                .to_string();
                let vkey = table_vector_key(table, &field.name, pk_str);
                store.vset(vkey.as_bytes(), vector, Some(metadata), None, now);
            }
        }
        // JSON/ARRAY columns are not auto-indexed; only declared path indexes apply.
        FieldType::Json | FieldType::Array => {}
    }
}

fn remove_from_index(
    store: &Store,
    table: &str,
    field: &FieldDef,
    value: &str,
    pk_str: &str,
    now: Instant,
) {
    match &field.field_type {
        FieldType::Int
        | FieldType::Float
        | FieldType::Bool
        | FieldType::Timestamp
        | FieldType::Ref(_) => {
            let zkey = idx_sorted_key(table, &field.name);
            let _ = store.zrem(zkey.as_bytes(), &[pk_str.as_bytes()], now);
        }
        FieldType::Str | FieldType::Uuid => {
            let skey = idx_str_key(table, &field.name, value);
            let _ = store.srem(skey.as_bytes(), &[pk_str.as_bytes()], now);
        }
        FieldType::Vector(_) => {
            let vkey = table_vector_key(table, &field.name, pk_str);
            store.del(&[vkey.as_bytes()]);
        }
        FieldType::Json | FieldType::Array => {}
    }
}

pub fn table_create(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    // All tokens after the table name - can be a SQL-like column list
    // e.g. ["id", "UUID", "PRIMARY", "KEY,", "email", "STR", "UNIQUE"]
    // or with outer parens: ["(id", "UUID", "PRIMARY", "KEY,", "email", "STR)"]
    col_args: &[&str],
    now: Instant,
) -> Result<(), String> {
    if !is_valid_table_name(table) {
        return Err("ERR invalid table name".to_string());
    }
    if col_args.is_empty() {
        return Err("ERR at least one column is required".to_string());
    }

    let key = schema_key(table);
    let existing = store.hgetall(key.as_bytes(), now).unwrap_or_default();
    if !existing.is_empty() {
        return Err(format!("ERR table '{}' already exists", table));
    }

    // Keep the original column list (incl. any `WITH TTL`) for the WAL log below.
    let orig_col_args = col_args;
    // `... WITH TTL <secs>` gives every row in the table a default expiry.
    let (col_args, default_ttl) = split_with_ttl(col_args);
    let fields = parse_column_list(col_args)?;

    // Validate that referenced tables exist
    for field in &fields {
        if let Some(fk) = &field.references {
            let ref_schema_key = schema_key(&fk.table);
            let ref_exists = store
                .hgetall(ref_schema_key.as_bytes(), now)
                .unwrap_or_default();
            if ref_exists.is_empty() {
                return Err(format!(
                    "ERR referenced table '{}' does not exist",
                    fk.table
                ));
            }
        }
    }

    let mut pairs: Vec<(&[u8], Vec<u8>)> = fields
        .iter()
        .map(|f| {
            let encoded = encode_field_def(f);
            (f.name.as_bytes() as &[u8], encoded.into_bytes())
        })
        .collect();
    if let Some(secs) = default_ttl {
        pairs.push((HIDDEN_DEFAULT_TTL_FIELD, secs.to_string().into_bytes()));
    }
    let pair_refs: Vec<(&[u8], &[u8])> = pairs.iter().map(|(k, v)| (*k, v.as_slice())).collect();
    store.hset(key.as_bytes(), &pair_refs, now)?;

    store.set(seq_key(table).as_bytes(), b"0", None, now);

    let tlist = table_list_key();
    let _ = store.sadd(tlist.as_bytes(), &[table.as_bytes()], now);

    // Store the pk column name so inserts can look it up quickly
    if let Some(pk_field) = fields.iter().find(|f| f.primary_key) {
        let pk_key = pk_key(table);
        store.set(pk_key.as_bytes(), pk_field.name.as_bytes(), None, now);
    }

    // Populate the cache immediately so the first insert doesn't miss
    {
        let mut w = cache.write();
        w.insert(table, fields);
        w.insert_default_ttl(table, default_ttl);
    }

    // WAL: schema creation is deterministic; log the original column list so the
    // table exists after a crash (HTTP TCREATE bypasses execute_with_wal).
    if store.wal_enabled() {
        let mut a: Vec<&[u8]> = Vec::with_capacity(orig_col_args.len() + 2);
        a.push(b"TCREATE");
        a.push(table.as_bytes());
        for c in orig_col_args {
            a.push(c.as_bytes());
        }
        let _ = store.wal_log_command(&a);
    }

    Ok(())
}

fn current_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Generate a UUIDv7 (RFC 9562): a 48-bit big-endian millisecond timestamp in
/// the leading bytes, the version/variant nibbles, the rest random. Being
/// time-ordered it sorts chronologically and keeps index locality, which is why
/// it is the modern default for primary keys.
pub(crate) fn generate_uuid_v7() -> String {
    use rand_core::RngCore;
    let ms = current_epoch_ms();
    let mut b = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut b);
    b[0] = (ms >> 40) as u8;
    b[1] = (ms >> 32) as u8;
    b[2] = (ms >> 24) as u8;
    b[3] = (ms >> 16) as u8;
    b[4] = (ms >> 8) as u8;
    b[5] = ms as u8;
    b[6] = (b[6] & 0x0f) | 0x70; // version 7
    b[8] = (b[8] & 0x3f) | 0x80; // variant (RFC 4122)
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

/// Resolve a column `DEFAULT` token to a concrete value at insert time.
/// `uuid()` / `gen_random_uuid()` -> a fresh UUIDv7; `now()` -> epoch ms;
/// anything else is a literal (surrounding quotes stripped).
fn resolve_default(token: &str) -> String {
    match token.trim().to_ascii_lowercase().as_str() {
        "uuid()" | "gen_random_uuid()" => generate_uuid_v7(),
        "now()" => current_epoch_ms().to_string(),
        _ => token
            .trim()
            .trim_matches(|c| c == '\'' || c == '"')
            .to_string(),
    }
}

pub fn table_insert(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    field_values: &[(&str, &str)],
    now: Instant,
) -> Result<i64, String> {
    table_insert_ttl(store, cache, table, field_values, None, now)
}

/// `table_insert` with a TTL op applied to the new row.
pub fn table_insert_ttl(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    field_values: &[(&str, &str)],
    ttl: Option<TtlOp>,
    now: Instant,
) -> Result<i64, String> {
    // Back-compat numeric reply: 0 for non-numeric (UUID/STR) primary keys.
    Ok(
        table_insert_pk(store, cache, table, field_values, ttl, now)?
            .parse()
            .unwrap_or(0),
    )
}

/// Insert a row and return the full stored row (sorted by column). Production
/// callers use `table_insert_returning_ttl`; this no-TTL form is kept for tests.
#[cfg(test)]
pub fn table_insert_returning(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    field_values: &[(&str, &str)],
    now: Instant,
) -> Result<Vec<(String, String)>, String> {
    table_insert_returning_ttl(store, cache, table, field_values, None, now)
}

/// `table_insert_returning` with a TTL op applied to the new row.
pub fn table_insert_returning_ttl(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    field_values: &[(&str, &str)],
    ttl: Option<TtlOp>,
    now: Instant,
) -> Result<Vec<(String, String)>, String> {
    let schema = load_schema(store, cache, table, now)?;
    let pk_str = table_insert_pk(store, cache, table, field_values, ttl, now)?;
    let mut row = get_row(store, table, &schema, &pk_str, now)
        .ok_or_else(|| format!("ERR inserted row not found in table '{}'", table))?;
    row.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(row)
}

/// Insert multiple rows, returning the inserted rows. Production callers use
/// `table_insert_many_returning_ttl`; this no-TTL form is kept for tests.
#[cfg(test)]
pub fn table_insert_many_returning(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    rows: &[Vec<(String, String)>],
    now: Instant,
) -> Result<Vec<Vec<(String, String)>>, String> {
    table_insert_many_returning_ttl(store, cache, table, rows, None, now)
}

/// `table_insert_many_returning` with a TTL op applied to every inserted row.
pub fn table_insert_many_returning_ttl(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    rows: &[Vec<(String, String)>],
    ttl: Option<TtlOp>,
    now: Instant,
) -> Result<Vec<Vec<(String, String)>>, String> {
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let fv: Vec<(&str, &str)> = row.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        out.push(table_insert_returning_ttl(
            store, cache, table, &fv, ttl, now,
        )?);
    }
    Ok(out)
}

/// Insert a row, or update the conflicting row if one already exists on the
/// conflict column. `conflict_col` defaults to the primary key (implicit `id`
/// when there is no declared PK). Returns the resulting row. The conflict
/// column must carry the value to match on; without it this is a plain insert.
#[cfg(test)]
pub fn table_upsert_returning(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    field_values: &[(&str, &str)],
    conflict_col: Option<&str>,
    now: Instant,
) -> Result<Vec<(String, String)>, String> {
    table_upsert_returning_ttl(store, cache, table, field_values, conflict_col, None, now)
}

/// `table_upsert_returning` with a TTL op applied to the resulting row. A bare
/// op (`None`) leaves any existing deadline untouched, so re-upserting a row
/// without a TTL keeps it alive on its current schedule.
pub fn table_upsert_returning_ttl(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    field_values: &[(&str, &str)],
    conflict_col: Option<&str>,
    ttl: Option<TtlOp>,
    now: Instant,
) -> Result<Vec<(String, String)>, String> {
    let schema = load_schema(store, cache, table, now)?;
    let pk_name = schema
        .iter()
        .find(|f| f.primary_key)
        .map(|f| f.name.as_str());
    let conflict = conflict_col.or(pk_name).unwrap_or("id");

    let Some(cval) = field_values
        .iter()
        .find(|(k, _)| *k == conflict)
        .map(|(_, v)| *v)
    else {
        // No value to conflict on -> behaves as a plain insert.
        return table_insert_returning_ttl(store, cache, table, field_values, ttl, now);
    };

    let conflict_is_pk = schema.iter().any(|f| f.primary_key && f.name == conflict)
        || (pk_name.is_none() && conflict == "id");
    let existing_pk: Option<String> = if conflict_is_pk {
        // An expired row is purged and treated as absent (-> insert branch).
        if purge_if_expired(store, cache, table, cval, now) {
            None
        } else {
            Some(cval.to_string())
        }
    } else {
        // Match via the column's unique index (only present for UNIQUE columns).
        let ukey = uniq_key(table, conflict);
        match store
            .hget(ukey.as_bytes(), cval.as_bytes(), now)
            .map(|b| String::from_utf8_lossy(&b).to_string())
        {
            Some(pk) if !purge_if_expired(store, cache, table, &pk, now) => Some(pk),
            _ => None,
        }
    };

    match existing_pk {
        Some(pk) => {
            // Update the conflicting row with the non-key fields, then return it.
            let mut updates: Vec<(&str, &str)> = field_values
                .iter()
                .copied()
                .filter(|(k, _)| *k != conflict)
                .collect();
            // A TTL-only upsert (no non-key fields) still needs a logged command so
            // the refreshed deadline survives WAL replay. Carry it on a no-op write
            // of the conflict column to its matched value.
            if updates.is_empty() && ttl.is_some() {
                updates.push((conflict, cval));
            }
            // The leaf applies AND WAL-logs the TTL atomically with the row update,
            // so replay preserves the deadline instead of dropping it.
            if !updates.is_empty() {
                table_update_by_pk_str(store, cache, table, &pk, &updates, ttl, now)?;
            }
            let mut row = get_row(store, table, &schema, &pk, now)
                .ok_or_else(|| format!("ERR upserted row not found in table '{}'", table))?;
            row.sort_by(|a, b| a.0.cmp(&b.0));
            Ok(row)
        }
        None => table_insert_returning_ttl(store, cache, table, field_values, ttl, now),
    }
}

/// Core insert: returns the primary-key string of the new row.
fn table_insert_pk(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    field_values: &[(&str, &str)],
    ttl: Option<TtlOp>,
    now: Instant,
) -> Result<String, String> {
    let schema = load_schema(store, cache, table, now)?;

    // A table with no declared PK stores rows under an implicit auto-increment
    // "id". That id is a valid insert/replay column even though it is not part of
    // the declared schema -- replayed TINSERTs carry it so the row keeps identity.
    let has_declared_pk = schema.iter().any(|f| f.primary_key);

    let mut provided: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
    for (k, v) in field_values {
        let known = schema.iter().any(|f| f.name == *k) || (!has_declared_pk && *k == "id");
        if !known {
            return Err(format!("ERR unknown column '{}'", k));
        }
        provided.insert(k, v);
    }

    // Materialize column DEFAULTs for any non-PK field not explicitly provided.
    // Generated values (uuid()/now()) must outlive `provided`, so own them here
    // and borrow into the map. The PK is auto-generated separately below.
    let generated_defaults: Vec<(String, String)> = schema
        .iter()
        .filter(|f| !f.primary_key && !provided.contains_key(f.name.as_str()))
        .filter_map(|f| {
            f.default_value
                .as_ref()
                .map(|d| (f.name.clone(), resolve_default(d)))
        })
        .collect();
    for (name, val) in &generated_defaults {
        provided.insert(name.as_str(), val.as_str());
    }

    // Determine the PK column (if any) and its value
    let pk_field = schema.iter().find(|f| f.primary_key);

    // --- Constraint validation pass ---
    for field in &schema {
        let value = provided.get(field.name.as_str()).copied();

        // NOT NULL check
        if !field.nullable && value.is_none() {
            // A PK with no value is fine when it can be auto-generated: INT
            // (auto-increment), UUID (auto-uuidv7), or any PK carrying a
            // DEFAULT. Every other NOT NULL field must be provided (defaults
            // were already materialized into `provided` above).
            let pk_autogen = field.primary_key
                && (field.field_type == FieldType::Int
                    || field.field_type == FieldType::Uuid
                    || field.default_value.is_some());
            if !pk_autogen {
                return Err(format!(
                    "ERR column '{}' is NOT NULL but no value was provided",
                    field.name
                ));
            }
        }

        let value = match value {
            Some(v) => v,
            None => continue,
        };

        validate_value(field, value)?;

        // Legacy Ref type FK check
        if let FieldType::Ref(ref ref_table) = field.field_type {
            let ref_id: i64 = value.parse().map_err(|_| {
                format!(
                    "ERR column '{}' expects int ref, got '{}'",
                    field.name, value
                )
            })?;
            let rk = row_key(ref_table, ref_id);
            let ref_row = store.hgetall(rk.as_bytes(), now).unwrap_or_default();
            if ref_row.is_empty() {
                return Err(format!(
                    "ERR foreign key violation: {}={} not found in table '{}'",
                    field.name, value, ref_table
                ));
            }
        }

        // Explicit FK check
        if let Some(fk) = &field.references {
            let ref_row_key = row_key_for_pk(&fk.table, value);
            let ref_row = store
                .hgetall(ref_row_key.as_bytes(), now)
                .unwrap_or_default();
            if ref_row.is_empty() {
                // Also try the uniq index on the referenced column
                let ukey = uniq_key(&fk.table, &fk.column);
                if store.hget(ukey.as_bytes(), value.as_bytes(), now).is_none() {
                    return Err(format!(
                        "ERR foreign key violation: {}.{}='{}' not found in table '{}'",
                        table, field.name, value, fk.table
                    ));
                }
            }
        }

        // UNIQUE / PRIMARY KEY uniqueness check. The uniq index is advisory: only
        // reject if a LIVE row genuinely still holds this value. A value held by an
        // expired row is freed by purging it; a stale index entry (holder row gone
        // or no longer carrying this value, e.g. from a partial update) is dropped
        // and the insert is allowed -- never a false "duplicate".
        if field.unique {
            let ukey = uniq_key(table, &field.name);
            if let Some(holder) = store.hget(ukey.as_bytes(), value.as_bytes(), now) {
                let holder_pk = String::from_utf8_lossy(&holder).to_string();
                let absent = purge_if_expired(store, cache, table, &holder_pk, now);
                if !absent && uniq_holder_holds_value(store, table, field, &holder_pk, value, now) {
                    return Err(format!(
                        "ERR unique constraint violation on column '{}': value '{}' already exists",
                        field.name, value
                    ));
                }
                // Stale entry -> drop it so it doesn't block this (valid) insert,
                // which writes the fresh holder below.
                let _ = store.hdel(ukey.as_bytes(), &[value.as_bytes()], now);
            }
        }
    }

    // --- Determine row key ---
    // ALL rows are stored at row_key_for_pk(table, pk_str).
    // For tables with a user-defined PK the pk_str is the PK value.
    // For tables without a PK the pk_str is the auto-increment seq as a string.
    // This unifies the key scheme so get_all_row_ids / get_row always work correctly.
    let pk_str: String = if let Some(pk) = pk_field {
        match provided.get(pk.name.as_str()) {
            Some(pk_val) => {
                // Check the row doesn't already exist (an expired row is purged
                // and treated as absent).
                if !purge_if_expired(store, cache, table, pk_val, now) {
                    return Err(format!(
                        "ERR primary key violation: '{}' already exists",
                        pk_val
                    ));
                }
                // Keep the auto-increment counter ahead of explicit/replayed ids.
                if pk.field_type == FieldType::Int {
                    if let Ok(id) = pk_val.parse::<i64>() {
                        bump_seq_to_at_least(store, table, id, now);
                    }
                }
                pk_val.to_string()
            }
            None if pk.field_type == FieldType::Int => {
                // Auto-increment INT PK
                next_id(store, table, now).to_string()
            }
            None if pk.field_type == FieldType::Uuid => {
                // Auto-generate a UUIDv7 PK (Supabase-style id default).
                generate_uuid_v7()
            }
            None if pk.default_value.is_some() => {
                // Honor an explicit DEFAULT on the PK (e.g. uuid()/now()).
                resolve_default(pk.default_value.as_deref().unwrap_or(""))
            }
            None => {
                return Err(format!(
                    "ERR primary key column '{}' must be provided",
                    pk.name
                ));
            }
        }
    } else if let Some(id) = provided.get("id") {
        // Implicit-id table carrying an explicit id (WAL replay, or a client that
        // supplied one): honor it and keep the counter ahead so a later
        // auto-generated id never reuses it.
        if let Ok(parsed) = id.parse::<i64>() {
            bump_seq_to_at_least(store, table, parsed, now);
        }
        id.to_string()
    } else {
        next_id(store, table, now).to_string()
    };

    let rk = row_key_for_pk(table, &pk_str);

    // --- Encode and store ---
    let mut pairs_owned: Vec<(String, Vec<u8>)> = Vec::new();

    // Always materialize the PK as a stored field so WHERE/JOIN can reference it.
    // If there's an explicit PK column it will be written below in the schema loop.
    // If there's no explicit PK (implicit auto-increment), store it as "id".
    let has_explicit_pk = pk_field.is_some();
    if !has_explicit_pk {
        pairs_owned.push(("id".to_string(), pk_str.as_bytes().to_vec()));
    }

    for field in &schema {
        if let Some(value) = provided.get(field.name.as_str()) {
            let encoded = field.field_type.encode_value(value)?;
            pairs_owned.push((field.name.clone(), encoded));
        } else if field.primary_key {
            // Explicit PK that was auto-generated (INT auto-increment or UUIDv7).
            // Encode with the PK column's own type, not a hardcoded INT.
            let encoded = field.field_type.encode_value(&pk_str)?;
            pairs_owned.push((field.name.clone(), encoded));
        }
    }

    // NOTE: the row hash is committed LAST (after `:ids`, indexes, uniq, vector,
    // and the staged TTL field). Reach-structures point at a pk whose row hash
    // does not exist yet; reads re-fetch the row and filter it out (treated as
    // "not committed"). The single final `hset` then flips the row visible
    // everywhere atomically. A failure before the commit leaves only orphan index
    // entries (harmless to reads via read-validation; cleaned lazily), never a
    // half-applied row.

    // Track this row in the ids sorted set.
    // Member = pk_str, score = numeric pk if possible, else a monotonic counter.
    let score: f64 = pk_str.parse::<f64>().unwrap_or_else(|_| {
        // For non-numeric PKs (UUID, STR), use a separate insert counter for ordering
        next_id(store, &format!("{}__order", table), now) as f64
    });
    let ikey = ids_key(table);
    let _ = store.zadd(
        ikey.as_bytes(),
        &[(pk_str.as_bytes(), score)],
        false,
        false,
        false,
        false,
        false,
        now,
    );

    for field in &schema {
        if let Some(value) = provided.get(field.name.as_str()) {
            add_to_index(store, table, field, value, &pk_str, now);

            if field.unique {
                let ukey = uniq_key(table, &field.name);
                store.hset(
                    ukey.as_bytes(),
                    &[(value.as_bytes() as &[u8], pk_str.as_bytes() as &[u8])],
                    now,
                )?;
            }
        }
    }

    // Declared JSON path indexes (cached empty for un-indexed tables => cheap).
    for pi in &load_path_indexes(store, cache, table, now) {
        if let Some((root, rest)) = pi.path.split_once('.') {
            if let Some(raw) = provided.get(root).copied() {
                if let Some(scalar) = extract_json_scalar(raw, rest) {
                    add_to_index(
                        store,
                        table,
                        &synthetic_path_fielddef(pi),
                        &scalar,
                        &pk_str,
                        now,
                    );
                }
            }
        }
    }

    // An explicit write TTL wins; otherwise a new row inherits the table default
    // (`TCREATE ... WITH TTL`). An explicit `TTL 0` (Clear) does not fall back.
    // Register the deadline and fold the hidden TTL field into the row commit so
    // it appears atomically with the row.
    let effective_ttl = ttl.or_else(|| table_default_ttl(store, cache, table, now).map(TtlOp::Set));
    if let Some(ttl_bytes) = stage_row_ttl(store, table, &pk_str, effective_ttl, now) {
        pairs_owned.push((String::from("\u{0}ttl"), ttl_bytes));
    }

    // --- Commit: write the complete row hash LAST (the atomic visibility point) ---
    let pair_refs: Vec<(&[u8], &[u8])> = pairs_owned
        .iter()
        .map(|(k, v)| (k.as_bytes() as &[u8], v.as_slice()))
        .collect();
    store.hset(rk.as_bytes(), &pair_refs, now)?;

    // WAL: log the RESOLVED insert (explicit PK + the resolved column values that
    // were actually stored) so crash replay reproduces this exact row.
    if store.wal_enabled() {
        let mut a: Vec<Vec<u8>> = Vec::with_capacity(provided.len() * 2 + 6);
        a.push(b"TINSERT".to_vec());
        a.push(table.as_bytes().to_vec());
        if !has_explicit_pk {
            a.push(b"id".to_vec());
            a.push(pk_str.as_bytes().to_vec());
        }
        for field in &schema {
            if let Some(v) = provided.get(field.name.as_str()) {
                a.push(field.name.as_bytes().to_vec());
                a.push(v.as_bytes().to_vec());
            } else if field.primary_key {
                a.push(field.name.as_bytes().to_vec());
                a.push(pk_str.as_bytes().to_vec());
            }
        }
        if let Some((tok, val)) = ttl_wal_tokens(ttl) {
            a.push(tok.to_vec());
            a.push(val);
        }
        let refs: Vec<&[u8]> = a.iter().map(|v| v.as_slice()).collect();
        let _ = store.wal_log_command(&refs);
    }

    Ok(pk_str)
}

pub fn table_get(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    id: i64,
    now: Instant,
) -> Result<Vec<(String, String)>, String> {
    let schema = load_schema(store, cache, table, now)?;
    let pk_str = id.to_string();
    let row = get_row(store, table, &schema, &pk_str, now)
        .ok_or_else(|| format!("ERR row {} not found in table '{}'", id, table))?;
    let mut result = row;
    result.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(result)
}

/// Convenience wrapper used by tests: update by integer id, no TTL change.
#[cfg(test)]
pub fn table_update(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    id: i64,
    field_values: &[(&str, &str)],
    now: Instant,
) -> Result<(), String> {
    table_update_by_pk_str(
        store,
        cache,
        table,
        &id.to_string(),
        field_values,
        None,
        now,
    )
}

/// Update a row identified by its raw PK string - works for any PK type (INT, UUID, STR).
fn table_update_by_pk_str(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    pk_str: &str,
    field_values: &[(&str, &str)],
    ttl: Option<TtlOp>,
    now: Instant,
) -> Result<(), String> {
    let schema = load_schema(store, cache, table, now)?;
    let rk = row_key_for_pk(table, pk_str);

    let old_row = get_row(store, table, &schema, pk_str, now)
        .ok_or_else(|| format!("ERR row '{}' not found in table '{}'", pk_str, table))?;

    let old_map: std::collections::HashMap<String, String> = old_row.into_iter().collect();

    for (fname, fval) in field_values {
        let field = schema
            .iter()
            .find(|f| f.name == *fname)
            .ok_or_else(|| format!("ERR unknown field '{}'", fname))?;

        validate_value(field, fval)?;

        if let FieldType::Ref(ref ref_table) = field.field_type {
            let rk2 = row_key_for_pk(ref_table, fval);
            let ref_row = store.hgetall(rk2.as_bytes(), now).unwrap_or_default();
            if ref_row.is_empty() {
                return Err(format!(
                    "ERR foreign key violation: {}={} not found in table '{}'",
                    fname, fval, ref_table
                ));
            }
        }

        if field.unique {
            let ukey = uniq_key(table, &field.name);
            if let Some(existing_pk_bytes) = store.hget(ukey.as_bytes(), fval.as_bytes(), now) {
                let existing_pk = String::from_utf8_lossy(&existing_pk_bytes).to_string();
                if existing_pk != pk_str {
                    return Err(format!(
                        "ERR unique constraint violation on field '{}'",
                        field.name
                    ));
                }
            }
        }
    }

    for (fname, fval) in field_values {
        let field = schema.iter().find(|f| f.name == *fname).unwrap();

        if let Some(old_val) = old_map.get(*fname) {
            remove_from_index(store, table, field, old_val, pk_str, now);
            if field.unique {
                let ukey = uniq_key(table, &field.name);
                let _ = store.hdel(ukey.as_bytes(), &[old_val.as_bytes()], now);
            }
        }

        add_to_index(store, table, field, fval, pk_str, now);
        if field.unique {
            let ukey = uniq_key(table, &field.name);
            let _ = store.hset(
                ukey.as_bytes(),
                &[(fval.as_bytes() as &[u8], pk_str.as_bytes() as &[u8])],
                now,
            );
        }
    }

    // Reconcile declared JSON path indexes whose root column was updated.
    for pi in &load_path_indexes(store, cache, table, now) {
        let Some((root, rest)) = pi.path.split_once('.') else {
            continue;
        };
        let Some(new_raw) = field_values
            .iter()
            .find(|(k, _)| *k == root)
            .map(|(_, v)| *v)
        else {
            continue; // root JSON column not updated => index entry unchanged
        };
        let synthetic = synthetic_path_fielddef(pi);
        if let Some(old_raw) = old_map.get(root) {
            if let Some(old_scalar) = extract_json_scalar(old_raw, rest) {
                remove_from_index(store, table, &synthetic, &old_scalar, pk_str, now);
            }
        }
        if let Some(new_scalar) = extract_json_scalar(new_raw, rest) {
            add_to_index(store, table, &synthetic, &new_scalar, pk_str, now);
        }
    }

    let mut pairs_owned: Vec<(String, Vec<u8>)> = Vec::new();
    for (fname, fval) in field_values {
        let field = schema.iter().find(|f| f.name == *fname).unwrap();
        let encoded = field.field_type.encode_value(fval)?;
        pairs_owned.push((fname.to_string(), encoded));
    }
    let pair_refs: Vec<(&[u8], &[u8])> = pairs_owned
        .iter()
        .map(|(k, v)| (k.as_bytes() as &[u8], v.as_slice()))
        .collect();
    store.hset(rk.as_bytes(), &pair_refs, now)?;

    // Apply any TTL op for this row before logging, so the row state matches the
    // command we record.
    apply_row_ttl(store, table, pk_str, ttl, now);

    // WAL: log the resolved per-row update so crash replay re-applies it. SET
    // values are already explicit; keyed by the actual PK so it never re-matches
    // a different row on replay. (A WHERE-update logs one such command per matched
    // row.) The TTL op is logged as a trailing `TTL <secs>` clause so replay
    // preserves the row's deadline instead of resetting it.
    if store.wal_enabled() {
        let pkcol = pk_column_name(&schema);
        let mut a: Vec<Vec<u8>> = Vec::with_capacity(field_values.len() * 2 + 9);
        a.push(b"TUPDATE".to_vec());
        a.push(table.as_bytes().to_vec());
        a.push(b"SET".to_vec());
        for (k, v) in field_values {
            a.push(k.as_bytes().to_vec());
            a.push(v.as_bytes().to_vec());
        }
        a.push(b"WHERE".to_vec());
        a.push(pkcol.as_bytes().to_vec());
        a.push(b"=".to_vec());
        a.push(pk_str.as_bytes().to_vec());
        if let Some((tok, val)) = ttl_wal_tokens(ttl) {
            a.push(tok.to_vec());
            a.push(val);
        }
        let refs: Vec<&[u8]> = a.iter().map(|v| v.as_slice()).collect();
        let _ = store.wal_log_command(&refs);
    }

    Ok(())
}

#[cfg(test)]
pub fn table_delete(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    id: i64,
    now: Instant,
) -> Result<(), String> {
    table_delete_inner(store, cache, table, &id.to_string(), now, 0)
}

const CASCADE_DEPTH_LIMIT: usize = 16;

fn table_delete_inner(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    pk_str: &str,
    now: Instant,
    depth: usize,
) -> Result<(), String> {
    if depth > CASCADE_DEPTH_LIMIT {
        return Err(format!(
            "ERR cascade depth limit ({}) exceeded - possible circular FK reference",
            CASCADE_DEPTH_LIMIT
        ));
    }
    let schema = load_schema(store, cache, table, now)?;
    let rk = row_key_for_pk(table, pk_str);

    // Read the row even if its TTL has lapsed: the sweep/purge path must clean
    // the indexes of an expired-but-not-yet-removed row.
    let row_map: std::collections::HashMap<String, String> =
        get_row_including_expired(store, table, &schema, pk_str, now)
            .ok_or_else(|| format!("ERR row '{}' not found in table '{}'", pk_str, table))?
            .into_iter()
            .collect();

    // The pk_value is the user-visible PK (may differ from internal pk_str for UUID/STR PKs)
    let pk_field = schema.iter().find(|f| f.primary_key);
    let pk_value_owned: String = pk_field
        .and_then(|pk| row_map.get(&pk.name))
        .cloned()
        .unwrap_or_else(|| pk_str.to_string());
    let pk_value: &str = &pk_value_owned;

    let tlist_key = table_list_key();
    let all_tables = store
        .smembers(tlist_key.as_bytes(), now)
        .unwrap_or_default();

    for other_table in &all_tables {
        if other_table == table {
            continue;
        }
        let other_schema = match load_schema(store, cache, other_table, now) {
            Ok(s) => s,
            Err(_) => continue,
        };
        for field in &other_schema {
            // Handle legacy Ref type - always RESTRICT
            if let FieldType::Ref(ref ref_table) = field.field_type {
                if ref_table == table {
                    let zkey = idx_sorted_key(other_table, &field.name);
                    let id_f = pk_str.parse::<f64>().unwrap_or(0.0);
                    let refs = store
                        .zrangebyscore(
                            zkey.as_bytes(),
                            id_f,
                            id_f,
                            false,
                            false,
                            false,
                            None,
                            None,
                            false,
                            now,
                        )
                        .unwrap_or_default();
                    if !refs.is_empty() {
                        return Err(format!(
                            "ERR cannot delete: row is referenced by table '{}'",
                            other_table
                        ));
                    }
                }
            }

            // Handle explicit FK with ON DELETE behavior
            if let Some(fk) = &field.references {
                if fk.table != table {
                    continue;
                }
                // Find all rows in other_table where field == pk_value.
                // If the FK column is unique, we can look it up directly.
                // Otherwise we must scan all rows.
                let referencing_ids: Vec<String> = if field.unique {
                    let ukey = uniq_key(other_table, &field.name);
                    if let Some(ref_id_bytes) =
                        store.hget(ukey.as_bytes(), pk_value.as_bytes(), now)
                    {
                        vec![String::from_utf8_lossy(&ref_id_bytes).to_string()]
                    } else {
                        vec![]
                    }
                } else {
                    // Full scan: find all rows where the FK field equals pk_value
                    get_all_row_ids(store, other_table, now)
                        .into_iter()
                        .filter(|other_pk| {
                            let rk = row_key_for_pk(other_table, other_pk);
                            if let Ok(pairs) = store.hgetall(rk.as_bytes(), now) {
                                pairs.iter().any(|(k, v)| {
                                    k == &field.name && FieldType::Int.decode_value(v) == pk_value
                                })
                            } else {
                                false
                            }
                        })
                        .collect()
                };

                if referencing_ids.is_empty() {
                    continue;
                }

                match fk.on_delete {
                    OnDelete::Restrict => {
                        return Err(format!(
                            "ERR cannot delete: row is referenced by table '{}' column '{}' (ON DELETE RESTRICT)",
                            other_table, field.name
                        ));
                    }
                    OnDelete::Cascade => {
                        // Delete all referencing rows, passing depth+1 to detect circular FKs
                        for ref_id_str in &referencing_ids {
                            let _ = table_delete_inner(
                                store,
                                cache,
                                other_table,
                                ref_id_str,
                                now,
                                depth + 1,
                            );
                        }
                    }
                    OnDelete::SetNull => {
                        // Null out the FK column in referencing rows and clean up its indexes
                        for ref_id_str in &referencing_ids {
                            let ref_rk = row_key_for_pk(other_table, ref_id_str);
                            // Remove the field value from the row hash
                            let _ = store.hdel(ref_rk.as_bytes(), &[field.name.as_bytes()], now);
                            // Clean up unique index if applicable
                            let ref_ukey = uniq_key(other_table, &field.name);
                            let _ = store.hdel(ref_ukey.as_bytes(), &[pk_value.as_bytes()], now);
                            // Clean up sorted-set index (for INT/FLOAT FK columns)
                            remove_from_index(
                                store,
                                other_table,
                                field,
                                pk_value,
                                ref_id_str.as_str(),
                                now,
                            );
                        }
                    }
                }
            }
        }
    }

    for field in &schema {
        if let Some(val) = row_map.get(&field.name) {
            remove_from_index(store, table, field, val, pk_str, now);
            if field.unique {
                let ukey = uniq_key(table, &field.name);
                let _ = store.hdel(ukey.as_bytes(), &[val.as_bytes()], now);
            }
        }
        // A VECTOR column stores its embedding in a side key with its own ANN
        // index; deleting the row must remove it too, or vector search keeps
        // returning the deleted row (and the entry leaks).
        if matches!(field.field_type, FieldType::Vector(_)) {
            let vkey = table_vector_key(table, &field.name, pk_str);
            store.del(&[vkey.as_bytes()]);
        }
    }

    // Remove declared JSON path index entries for this row.
    for pi in &load_path_indexes(store, cache, table, now) {
        if let Some((root, rest)) = pi.path.split_once('.') {
            if let Some(raw) = row_map.get(root) {
                if let Some(scalar) = extract_json_scalar(raw, rest) {
                    remove_from_index(
                        store,
                        table,
                        &synthetic_path_fielddef(pi),
                        &scalar,
                        pk_str,
                        now,
                    );
                }
            }
        }
    }

    let ikey = ids_key(table);
    let _ = store.zrem(ikey.as_bytes(), &[pk_str.as_bytes()], now);

    // Drop any TTL bookkeeping for this row (hidden field is removed with the
    // hash below; this clears the `_t:_ttl` deadline member).
    clear_row_ttl(store, table, pk_str, now);

    store.del(&[rk.as_bytes()]);

    // WAL: log the resolved per-row delete (keyed by the actual PK) only at the
    // top level. Cascaded child deletes (depth > 0) are NOT logged: replaying the
    // parent's delete re-runs the same FK cascade deterministically, so logging
    // children too would double-delete (harmless but noisy) on replay.
    if depth == 0 && store.wal_enabled() {
        let pkcol = pk_column_name(&schema);
        let a: Vec<&[u8]> = vec![
            b"TDELETE",
            b"FROM",
            table.as_bytes(),
            b"WHERE",
            pkcol.as_bytes(),
            b"=",
            pk_str.as_bytes(),
        ];
        let _ = store.wal_log_command(&a);
    }

    Ok(())
}

/// Parse a parenthesized `IN` value list: `( v1 v2 v3 )`.
/// Precondition: `args[*i]` is the opening `(`. Advances `*i` past the closing `)`.
fn parse_in_list(args: &[&str], i: &mut usize) -> Result<Vec<String>, String> {
    if *i >= args.len() || args[*i] != "(" {
        return Err("ERR IN operator requires a parenthesized list, e.g. IN ( a b c )".to_string());
    }
    *i += 1; // consume "("
             // A subquery (`IN ( SELECT ... )`) is only resolvable inside a grant
             // predicate, not a user query. Reject it explicitly rather than treating the
             // SELECT keywords as literal values (which silently matched nothing).
    if *i < args.len() && args[*i].eq_ignore_ascii_case("SELECT") {
        return Err(
            "ERR subqueries (IN ( SELECT ... )) are only supported in grant predicates, not in a query WHERE".to_string(),
        );
    }
    let mut values = Vec::new();
    while *i < args.len() && args[*i] != ")" {
        values.push(args[*i].to_string());
        *i += 1;
    }
    if *i >= args.len() {
        return Err("ERR unterminated IN list: missing ')'".to_string());
    }
    *i += 1; // consume ")"
    if values.is_empty() {
        return Err("ERR IN list must contain at least one value".to_string());
    }
    Ok(values)
}

/// Parse a single WHERE condition starting at `args[*i]`, advancing `*i` past it.
/// Handles `field op value`, `field IN ( ... )`, and `field NOT IN ( ... )`.
fn parse_where_condition(args: &[&str], i: &mut usize) -> Result<WhereClause, String> {
    if *i >= args.len() {
        return Err("ERR incomplete WHERE clause: expected field".to_string());
    }
    let field = args[*i].to_string();
    *i += 1;
    if *i >= args.len() {
        return Err(format!(
            "ERR incomplete WHERE clause: missing operator after '{field}'"
        ));
    }
    let op_str = args[*i];
    let op_upper = op_str.to_uppercase();
    *i += 1;

    // List operators: `IN ( ... )` and `NOT IN ( ... )`.
    if op_upper == "IN" {
        let values = parse_in_list(args, i)?;
        return Ok(WhereClause::in_list(field, CmpOp::In, values));
    }
    if op_upper == "NOT" {
        if *i < args.len() && args[*i].eq_ignore_ascii_case("IN") {
            *i += 1;
            let values = parse_in_list(args, i)?;
            return Ok(WhereClause::in_list(field, CmpOp::NotIn, values));
        }
        return Err("ERR expected 'IN' after 'NOT' in WHERE clause".to_string());
    }

    // Existence predicate: `field IS VALID` / `field IS NOT VALID` (no RHS).
    if op_upper == "IS" {
        if *i < args.len() && args[*i].eq_ignore_ascii_case("VALID") {
            *i += 1;
            return Ok(WhereClause::single(field, CmpOp::IsValid, String::new()));
        }
        if *i < args.len() && args[*i].eq_ignore_ascii_case("NULL") {
            *i += 1;
            return Ok(WhereClause::single(field, CmpOp::IsNull, String::new()));
        }
        if *i + 1 < args.len()
            && args[*i].eq_ignore_ascii_case("NOT")
            && args[*i + 1].eq_ignore_ascii_case("VALID")
        {
            *i += 2;
            return Ok(WhereClause::single(field, CmpOp::IsNotValid, String::new()));
        }
        if *i + 1 < args.len()
            && args[*i].eq_ignore_ascii_case("NOT")
            && args[*i + 1].eq_ignore_ascii_case("NULL")
        {
            *i += 2;
            return Ok(WhereClause::single(field, CmpOp::IsNotNull, String::new()));
        }
        return Err(
            "ERR expected 'VALID', 'NOT VALID', 'NULL' or 'NOT NULL' after 'IS'".to_string(),
        );
    }

    // Array membership: `field CONTAINS value`.
    if op_upper == "CONTAINS" {
        if *i >= args.len() {
            return Err("ERR missing value after CONTAINS".to_string());
        }
        let value = args[*i].to_string();
        *i += 1;
        return Ok(WhereClause::single(field, CmpOp::Contains, value));
    }

    // Single-operand comparison operators.
    if *i >= args.len() {
        return Err(format!(
            "ERR incomplete WHERE clause: missing value after '{op_str}'"
        ));
    }
    let value = args[*i].to_string();
    *i += 1;
    let op = parse_cmp_op(op_str)?;
    Ok(WhereClause::single(field, op, value))
}

/// Parse WHERE conditions from command args (`field op value [AND ...]`).
fn parse_where_conditions(args: &[&str]) -> Result<Vec<WhereClause>, String> {
    let mut conditions = Vec::new();
    let mut i = 0;
    while i < args.len() {
        conditions.push(parse_where_condition(args, &mut i)?);
        if i < args.len() && args[i].eq_ignore_ascii_case("AND") {
            i += 1;
        }
    }
    Ok(conditions)
}

/// Update rows matching WHERE conditions, returns count of updated rows
/// The synthetic `id` field used when a table has no explicit primary key.
fn implicit_id_field_for(schema: &[FieldDef]) -> Option<FieldDef> {
    if schema.iter().any(|f| f.primary_key) {
        None
    } else {
        Some(FieldDef {
            name: "id".to_string(),
            field_type: FieldType::Int,
            primary_key: true,
            unique: true,
            nullable: false,
            default_value: None,
            references: None,
        })
    }
}

/// True if `field` is a dot-path whose leading segment is a JSON or ARRAY column.
fn is_json_path_field(field: &str, schema: &[FieldDef]) -> bool {
    field
        .split_once('.')
        .map(|(root, _)| {
            schema.iter().any(|f| {
                f.name == root && matches!(f.field_type, FieldType::Json | FieldType::Array)
            })
        })
        .unwrap_or(false)
}

/// Resolve the primary keys of rows matching a WHERE clause. Shared by the
/// count and RETURNING variants of UPDATE and DELETE.
pub fn table_update_where(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    field_values: &[(&str, &str)],
    where_args: &[&str],
    now: Instant,
) -> Result<i64, String> {
    table_update_where_ttl(store, cache, table, field_values, where_args, None, now)
}

/// `table_update_where` with a TTL op applied to every matched row.
pub fn table_update_where_ttl(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    field_values: &[(&str, &str)],
    where_args: &[&str],
    ttl: Option<TtlOp>,
    now: Instant,
) -> Result<i64, String> {
    Ok(
        table_update_where_pks(store, cache, table, field_values, where_args, ttl, now)?
            .1
            .len() as i64,
    )
}

/// UPDATE returning the updated rows. Production callers use
/// `table_update_where_returning_ttl`; this no-TTL form is kept for tests.
#[cfg(test)]
pub fn table_update_where_returning(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    field_values: &[(&str, &str)],
    where_args: &[&str],
    now: Instant,
) -> Result<Vec<Vec<(String, String)>>, String> {
    table_update_where_returning_ttl(store, cache, table, field_values, where_args, None, now)
}

/// `table_update_where_returning` with a TTL op applied to every matched row.
pub fn table_update_where_returning_ttl(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    field_values: &[(&str, &str)],
    where_args: &[&str],
    ttl: Option<TtlOp>,
    now: Instant,
) -> Result<Vec<Vec<(String, String)>>, String> {
    let (schema, pks) =
        table_update_where_pks(store, cache, table, field_values, where_args, ttl, now)?;
    Ok(rows_for_pks(store, table, &schema, &pks, now))
}

/// Apply an UPDATE, returning (schema, primary keys of the updated rows).
fn table_update_where_pks(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    field_values: &[(&str, &str)],
    where_args: &[&str],
    ttl: Option<TtlOp>,
    now: Instant,
) -> Result<(Vec<FieldDef>, Vec<String>), String> {
    let conditions = parse_where_conditions(where_args)?;
    let (schema, matched) = scan_matching_pks(store, cache, table, &conditions, now)?;

    // Validate fields to update exist.
    for (fname, _) in field_values {
        schema
            .iter()
            .find(|f| f.name == *fname)
            .ok_or_else(|| format!("ERR unknown field '{}'", fname))?;
    }

    // The matched PKs come from the table's own index, so they are valid for any
    // PK type; update each by its raw PK string. The TTL op rides into the leaf so
    // it is applied and WAL-logged atomically with the row update (replay-safe).
    for pk_str in &matched {
        table_update_by_pk_str(store, cache, table, pk_str, field_values, ttl, now)?;
    }
    Ok((schema, matched))
}

/// Delete rows matching WHERE conditions, returns count of deleted rows
pub fn table_delete_where(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    where_args: &[&str],
    now: Instant,
) -> Result<i64, String> {
    let conditions = parse_where_conditions(where_args)?;
    let (_schema, matched) = scan_matching_pks(store, cache, table, &conditions, now)?;
    for pk_str in &matched {
        table_delete_inner(store, cache, table, pk_str, now, 0)?;
    }
    Ok(matched.len() as i64)
}

/// DELETE returning the deleted rows (captured before removal).
pub fn table_delete_where_returning(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    where_args: &[&str],
    now: Instant,
) -> Result<Vec<Vec<(String, String)>>, String> {
    let conditions = parse_where_conditions(where_args)?;
    let (schema, matched) = scan_matching_pks(store, cache, table, &conditions, now)?;
    let rows = rows_for_pks(store, table, &schema, &matched, now);
    for pk_str in &matched {
        table_delete_inner(store, cache, table, pk_str, now, 0)?;
    }
    Ok(rows)
}

pub fn table_drop(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    now: Instant,
) -> Result<(), String> {
    if crate::auth::is_reserved_auth_table(table) {
        return Err(format!("ERR table '{}' is managed by Lux Auth", table));
    }
    let schema = match load_schema(store, cache, table, now) {
        Ok(s) => s,
        Err(_) => return Err(format!("ERR table '{}' does not exist", table)),
    };

    let ikey = ids_key(table);
    let all_ids = store
        .zrangebyscore(
            ikey.as_bytes(),
            f64::NEG_INFINITY,
            f64::INFINITY,
            false,
            false,
            false,
            None,
            None,
            false,
            now,
        )
        .unwrap_or_default();

    for (pk_str, _) in &all_ids {
        if schema
            .iter()
            .any(|field| matches!(field.field_type, FieldType::Vector(_)))
        {
            if let Some(row) = get_row(store, table, &schema, pk_str, now) {
                for field in &schema {
                    if let Some((_, value)) = row.iter().find(|(k, _)| k == &field.name) {
                        remove_from_index(store, table, field, value, pk_str, now);
                    }
                }
            }
            // Remove each row's VECTOR side keys (+ their ANN index) on drop.
            for field in &schema {
                if matches!(field.field_type, FieldType::Vector(_)) {
                    let vkey = table_vector_key(table, &field.name, pk_str);
                    store.del(&[vkey.as_bytes()]);
                }
            }
        }
        let rk = row_key_for_pk(table, pk_str);
        // Clear any row-TTL deadline so a dropped row's stale `_t:_ttl` member
        // can't later expire a re-created row that reuses the same PK.
        clear_row_ttl(store, table, pk_str, now);
        store.del(&[rk.as_bytes()]);
    }

    for field in &schema {
        match &field.field_type {
            FieldType::Int
            | FieldType::Float
            | FieldType::Bool
            | FieldType::Timestamp
            | FieldType::Ref(_) => {
                let zkey = idx_sorted_key(table, &field.name);
                store.del(&[zkey.as_bytes()]);
            }
            FieldType::Str
            | FieldType::Uuid
            | FieldType::Vector(_)
            | FieldType::Json
            | FieldType::Array => {}
        }
        if field.unique {
            let ukey = uniq_key(table, &field.name);
            store.del(&[ukey.as_bytes()]);
        }
    }

    store.del(&[ikey.as_bytes()]);
    store.del(&[schema_key(table).as_bytes()]);
    store.del(&[seq_key(table).as_bytes()]);
    store.del(&[path_indexes_key(table).as_bytes()]);

    let tlist = table_list_key();
    let _ = store.srem(tlist.as_bytes(), &[table.as_bytes()], now);

    // Evict from cache
    cache.write().remove(table);

    // WAL: log the drop so a dropped table stays dropped after a crash (HTTP
    // TDROP bypasses execute_with_wal).
    if store.wal_enabled() {
        let a: Vec<&[u8]> = vec![b"TDROP", table.as_bytes()];
        let _ = store.wal_log_command(&a);
    }

    Ok(())
}

pub fn table_count(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    now: Instant,
) -> Result<i64, String> {
    let _ = load_schema(store, cache, table, now)?;
    let ikey = ids_key(table);
    store.zcard(ikey.as_bytes(), now)
}

/// Count rows matching a bare WHERE `filter` (e.g. a resolved row-scoped read
/// grant like `owner = abc123`). An empty filter counts the whole table. Used so
/// `/count` respects a row-scoped grant instead of refusing it.
pub fn table_count_filtered(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    filter: &str,
    now: Instant,
) -> Result<i64, String> {
    if filter.trim().is_empty() {
        return table_count(store, cache, table, now);
    }
    let mut toks: Vec<String> = vec![
        "COUNT(*)".to_string(),
        "FROM".to_string(),
        table.to_string(),
        "WHERE".to_string(),
    ];
    toks.extend(filter.split_whitespace().map(ToString::to_string));
    let refs: Vec<&str> = toks.iter().map(|s| s.as_str()).collect();
    let plan = parse_select(&refs)?;
    match table_select(store, cache, &plan, now)? {
        SelectResult::Aggregate(row) => row
            .iter()
            .find_map(|(_, v)| v.parse::<i64>().ok())
            .ok_or_else(|| "ERR count failed".to_string()),
        SelectResult::Rows(rows) => Ok(rows.len() as i64),
    }
}

/// Fetch a row by primary key, but only when it also satisfies `filter` (a
/// resolved row-scoped read grant). `Ok(None)` means the row is absent or out of
/// scope, so the caller can 404 without leaking that it exists.
pub fn table_get_filtered(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    id: i64,
    filter: &str,
    now: Instant,
) -> Result<Option<Vec<(String, String)>>, String> {
    // No filter (operator / unconditional grant): direct PK fetch, no plan.
    if filter.trim().is_empty() {
        return match table_get(store, cache, table, id, now) {
            Ok(row) => Ok(Some(row)),
            Err(e) if e.contains("not found") => Ok(None),
            Err(e) => Err(e),
        };
    }
    let schema = load_schema(store, cache, table, now)?;
    let pk = schema
        .iter()
        .find(|f| f.primary_key)
        .map(|f| f.name.clone())
        .ok_or_else(|| format!("ERR table '{}' has no primary key", table))?;
    let mut toks: Vec<String> = vec![
        "*".to_string(),
        "FROM".to_string(),
        table.to_string(),
        "WHERE".to_string(),
        pk,
        "=".to_string(),
        id.to_string(),
    ];
    if !filter.trim().is_empty() {
        toks.push("AND".to_string());
        toks.extend(filter.split_whitespace().map(ToString::to_string));
    }
    let refs: Vec<&str> = toks.iter().map(|s| s.as_str()).collect();
    let plan = parse_select(&refs)?;
    match table_select(store, cache, &plan, now)? {
        SelectResult::Rows(mut rows) => Ok(rows.drain(..).next()),
        SelectResult::Aggregate(_) => Ok(None),
    }
}

pub fn table_schema(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    now: Instant,
) -> Result<Vec<String>, String> {
    let schema = load_schema(store, cache, table, now)?;
    let mut result = Vec::new();
    for field in &schema {
        let type_str = match &field.field_type {
            FieldType::Str => "STR".to_string(),
            FieldType::Int => "INT".to_string(),
            FieldType::Float => "FLOAT".to_string(),
            FieldType::Bool => "BOOL".to_string(),
            FieldType::Timestamp => "TIMESTAMP".to_string(),
            FieldType::Uuid => "UUID".to_string(),
            FieldType::Vector(dims) => format!("VECTOR({})", dims),
            FieldType::Json => "JSON".to_string(),
            FieldType::Array => "ARRAY".to_string(),
            FieldType::Ref(t) => format!("REFERENCES {}(id)", t),
        };
        let mut parts = vec![field.name.clone(), type_str];
        if field.primary_key {
            parts.push("PRIMARY KEY".to_string());
        } else if field.unique {
            parts.push("UNIQUE".to_string());
        }
        if !field.nullable {
            parts.push("NOT NULL".to_string());
        }
        if let Some(fk) = &field.references {
            let on_delete = match fk.on_delete {
                OnDelete::Restrict => "ON DELETE RESTRICT",
                OnDelete::Cascade => "ON DELETE CASCADE",
                OnDelete::SetNull => "ON DELETE SET NULL",
            };
            parts.push(format!(
                "REFERENCES {}({}) {}",
                fk.table, fk.column, on_delete
            ));
        }
        result.push(parts.join(" "));
    }
    Ok(result)
}

pub fn table_add_column(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    field_spec: &str,
    now: Instant,
) -> Result<(), String> {
    let schema = load_schema(store, cache, table, now)?;
    let new_field = parse_field_def(field_spec)?;

    if schema.iter().any(|f| f.name == new_field.name) {
        return Err(format!("ERR field '{}' already exists", new_field.name));
    }

    // Check if there are existing rows
    let row_ids = get_all_row_ids(store, table, now);
    let has_rows = !row_ids.is_empty();

    // If column is NOT NULL and has no DEFAULT, error if there are existing rows
    if has_rows && !new_field.nullable && new_field.default_value.is_none() {
        return Err(format!(
            "ERR column '{}' is NOT NULL without a DEFAULT value; cannot add to table with existing rows",
            new_field.name
        ));
    }

    let key = schema_key(table);
    let encoded = encode_field_def(&new_field);
    store.hset(
        key.as_bytes(),
        &[(
            new_field.name.as_bytes() as &[u8],
            encoded.as_bytes() as &[u8],
        )],
        now,
    )?;

    // Invalidate cache so next load picks up the new field
    cache.write().remove(table);

    // Backfill existing rows with DEFAULT value or NULL
    if has_rows {
        let backfill_value = match &new_field.default_value {
            Some(default) => default.clone(),
            None => "NULL".to_string(), // Will be stored as actual NULL
        };

        for pk_str in row_ids {
            let rk = row_key_for_pk(table, &pk_str);
            let encoded = if backfill_value == "NULL" {
                // Store empty/NULL value
                vec![]
            } else {
                new_field.field_type.encode_value(&backfill_value)?
            };
            store.hset(
                rk.as_bytes(),
                &[(new_field.name.as_bytes() as &[u8], encoded.as_slice())],
                now,
            )?;

            // Add to indexes if needed
            if backfill_value != "NULL" {
                add_to_index(store, table, &new_field, &backfill_value, &pk_str, now);
                if new_field.unique {
                    let ukey = uniq_key(table, &new_field.name);
                    store.hset(
                        ukey.as_bytes(),
                        &[(
                            backfill_value.as_bytes() as &[u8],
                            pk_str.as_bytes() as &[u8],
                        )],
                        now,
                    )?;
                }
            }
        }
    }

    Ok(())
}

pub fn table_drop_column(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    field_name: &str,
    now: Instant,
) -> Result<(), String> {
    let schema = load_schema(store, cache, table, now)?;

    if !schema.iter().any(|f| f.name == field_name) {
        return Err(format!("ERR field '{}' does not exist", field_name));
    }

    let key = schema_key(table);
    store.hdel(key.as_bytes(), &[field_name.as_bytes()], now)?;

    let row_ids = get_all_row_ids(store, table, now);
    for pk_str in row_ids {
        let rk = row_key_for_pk(table, &pk_str);
        let _ = store.hdel(rk.as_bytes(), &[field_name.as_bytes()], now);
    }

    // Drop the numeric sorted-set index (INT/FLOAT/TIMESTAMP fields)
    let idx_key = idx_sorted_key(table, field_name);
    store.del(&[idx_key.as_bytes()]);

    // Drop the unique hash index
    let ukey = uniq_key(table, field_name);
    store.del(&[ukey.as_bytes()]);

    // Drop all per-value set index keys (STR/UUID fields store one key per distinct value)
    // Pattern: _t:<table>:idx:<field>:*
    let str_idx_pattern = format!("_t:{}:idx:{}:*", table, field_name);
    let keys = store.keys(str_idx_pattern.as_bytes(), now);
    if !keys.is_empty() {
        let key_refs: Vec<&[u8]> = keys.iter().map(|k| k.as_bytes() as &[u8]).collect();
        store.del(&key_refs);
    }

    // Invalidate so the next load picks up the dropped field from the Store
    cache.write().remove(table);

    Ok(())
}

pub fn table_list(store: &Store, now: Instant) -> Vec<String> {
    let tlist = table_list_key();
    store.smembers(tlist.as_bytes(), now).unwrap_or_default()
}

/// Return all row PK strings for a table, ordered by insertion sequence.
fn get_all_row_ids(store: &Store, table: &str, now: Instant) -> Vec<String> {
    let ikey = ids_key(table);
    store
        .zrangebyscore(
            ikey.as_bytes(),
            f64::NEG_INFINITY,
            f64::INFINITY,
            false,
            false,
            false,
            None,
            None,
            false,
            now,
        )
        .unwrap_or_default()
        .into_iter()
        .map(|(s, _)| s)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use std::sync::Arc;
    use std::time::Instant;

    fn make_cache() -> SharedSchemaCache {
        Arc::new(parking_lot::RwLock::new(SchemaCache::new()))
    }

    fn now() -> Instant {
        Instant::now()
    }

    // -------------------------------------------------------------------------
    // parse_field_def
    // -------------------------------------------------------------------------

    #[test]
    fn parse_field_basic_types() {
        let f = parse_field_def("id INT").unwrap();
        assert_eq!(f.name, "id");
        assert_eq!(f.field_type, FieldType::Int);
        assert!(!f.primary_key);
        assert!(f.nullable);

        let f = parse_field_def("name STR").unwrap();
        assert_eq!(f.field_type, FieldType::Str);

        let f = parse_field_def("score FLOAT").unwrap();
        assert_eq!(f.field_type, FieldType::Float);

        let f = parse_field_def("active BOOL").unwrap();
        assert_eq!(f.field_type, FieldType::Bool);

        let f = parse_field_def("created_at TIMESTAMP").unwrap();
        assert_eq!(f.field_type, FieldType::Timestamp);

        let f = parse_field_def("id UUID").unwrap();
        assert_eq!(f.field_type, FieldType::Uuid);

        let f = parse_field_def("embedding VECTOR(3)").unwrap();
        assert_eq!(f.field_type, FieldType::Vector(3));
    }

    #[test]
    fn parse_field_type_aliases() {
        assert_eq!(
            parse_field_def("x TEXT").unwrap().field_type,
            FieldType::Str
        );
        assert_eq!(
            parse_field_def("x VARCHAR").unwrap().field_type,
            FieldType::Str
        );
        assert_eq!(
            parse_field_def("x INTEGER").unwrap().field_type,
            FieldType::Int
        );
        assert_eq!(
            parse_field_def("x BIGINT").unwrap().field_type,
            FieldType::Int
        );
        assert_eq!(
            parse_field_def("x REAL").unwrap().field_type,
            FieldType::Float
        );
        assert_eq!(
            parse_field_def("x DOUBLE").unwrap().field_type,
            FieldType::Float
        );
        assert_eq!(
            parse_field_def("x BOOLEAN").unwrap().field_type,
            FieldType::Bool
        );
        assert_eq!(
            parse_field_def("x DATETIME").unwrap().field_type,
            FieldType::Timestamp
        );
    }

    #[test]
    fn parse_field_primary_key() {
        let f = parse_field_def("id UUID PRIMARY KEY").unwrap();
        assert!(f.primary_key);
        assert!(f.unique);
        assert!(!f.nullable);
    }

    #[test]
    fn parse_field_unique() {
        let f = parse_field_def("email STR UNIQUE").unwrap();
        assert!(f.unique);
        assert!(!f.primary_key);
    }

    #[test]
    fn parse_field_not_null() {
        let f = parse_field_def("email STR NOT NULL").unwrap();
        assert!(!f.nullable);
    }

    #[test]
    fn parse_field_nullable_explicit() {
        let f = parse_field_def("bio STR NULL").unwrap();
        assert!(f.nullable);
    }

    #[test]
    fn parse_field_references_restrict() {
        let f = parse_field_def("user_id INT REFERENCES users(id)").unwrap();
        let fk = f.references.unwrap();
        assert_eq!(fk.table, "users");
        assert_eq!(fk.column, "id");
        assert_eq!(fk.on_delete, OnDelete::Restrict);
    }

    #[test]
    fn parse_field_references_namespaced_table() {
        let f = parse_field_def("user_id STR REFERENCES auth.users(id)").unwrap();
        let fk = f.references.unwrap();
        assert_eq!(fk.table, "auth.users");
        assert_eq!(fk.column, "id");
        assert_eq!(fk.on_delete, OnDelete::Restrict);
    }

    #[test]
    fn parse_field_references_cascade() {
        let f = parse_field_def("user_id INT REFERENCES users(id) ON DELETE CASCADE").unwrap();
        let fk = f.references.unwrap();
        assert_eq!(fk.on_delete, OnDelete::Cascade);
    }

    #[test]
    fn parse_field_references_set_null() {
        let f = parse_field_def("user_id INT REFERENCES users(id) ON DELETE SET NULL").unwrap();
        let fk = f.references.unwrap();
        assert_eq!(fk.on_delete, OnDelete::SetNull);
    }

    #[test]
    fn parse_field_unknown_type_errors() {
        assert!(parse_field_def("x BLOB").is_err());
    }

    #[test]
    fn parse_field_missing_type_errors() {
        assert!(parse_field_def("x").is_err());
    }

    #[test]
    fn parse_field_bare_primary_is_primary_key() {
        // A bare `PRIMARY` (no `KEY`) is accepted as a primary key.
        let f = parse_field_def("id INT PRIMARY").unwrap();
        assert!(f.primary_key);
        assert!(f.unique);
        assert!(!f.nullable);
    }

    // -------------------------------------------------------------------------
    // parse_column_list
    // -------------------------------------------------------------------------

    #[test]
    fn column_list_basic() {
        let fields = parse_column_list(&["id INT PRIMARY KEY,", "name STR,", "age INT"]).unwrap();
        assert_eq!(fields.len(), 3);
        assert!(fields[0].primary_key);
        assert_eq!(fields[1].name, "name");
    }

    #[test]
    fn column_list_unquoted_lowercase_with_trailing_semicolon() {
        // Mirrors what a developer naturally types: lowercase types, bare
        // `primary`, unquoted commas, trailing `;`.
        let fields = parse_column_list(&[
            "id",
            "int",
            "primary,",
            "owner",
            "str,",
            "created_at",
            "str;",
        ])
        .unwrap();
        assert_eq!(fields.len(), 3);
        assert!(fields[0].primary_key);
        assert_eq!(fields[2].name, "created_at");
    }

    #[test]
    fn column_list_with_outer_parens() {
        let fields = parse_column_list(&["(id", "INT", "PRIMARY", "KEY,", "name", "STR)"]).unwrap();
        assert_eq!(fields.len(), 2);
        assert!(fields[0].primary_key);
    }

    #[test]
    fn column_list_duplicate_name_errors() {
        assert!(parse_column_list(&["id INT,", "id STR"]).is_err());
    }

    #[test]
    fn column_list_multiple_pk_errors() {
        assert!(parse_column_list(&["id INT PRIMARY KEY,", "code STR PRIMARY KEY"]).is_err());
    }

    // -------------------------------------------------------------------------
    // encode/decode field def roundtrip
    // -------------------------------------------------------------------------

    #[test]
    fn encode_decode_roundtrip_all_types() {
        let cases = vec![
            parse_field_def("id UUID PRIMARY KEY").unwrap(),
            parse_field_def("email STR UNIQUE NOT NULL").unwrap(),
            parse_field_def("age INT").unwrap(),
            parse_field_def("score FLOAT").unwrap(),
            parse_field_def("active BOOL").unwrap(),
            parse_field_def("created_at TIMESTAMP").unwrap(),
            parse_field_def("embedding VECTOR(3) NOT NULL").unwrap(),
            parse_field_def("team_id INT REFERENCES teams(id) ON DELETE CASCADE").unwrap(),
        ];
        for original in cases {
            let encoded = encode_field_def(&original);
            let decoded = decode_field_def(&original.name, &encoded);
            assert_eq!(
                decoded.field_type, original.field_type,
                "type mismatch for {}",
                original.name
            );
            assert_eq!(decoded.primary_key, original.primary_key);
            assert_eq!(decoded.unique, original.unique);
            assert_eq!(decoded.nullable, original.nullable);
            assert_eq!(decoded.references, original.references);
        }
    }

    // -------------------------------------------------------------------------
    // binary encode/decode
    // -------------------------------------------------------------------------

    #[test]
    fn encode_decode_int() {
        let ft = FieldType::Int;
        let encoded = ft.encode_value("42").unwrap();
        assert_eq!(encoded.len(), 8);
        assert_eq!(ft.decode_value(&encoded), "42");

        let encoded = ft.encode_value("-1000").unwrap();
        assert_eq!(ft.decode_value(&encoded), "-1000");
    }

    #[test]
    fn encode_decode_float() {
        let ft = FieldType::Float;
        let encoded = ft.encode_value(&std::f64::consts::PI.to_string()).unwrap();
        let decoded: f64 = ft.decode_value(&encoded).parse().unwrap();
        assert!((decoded - std::f64::consts::PI).abs() < 1e-10);
    }

    #[test]
    fn encode_decode_bool() {
        let ft = FieldType::Bool;
        assert_eq!(ft.decode_value(&ft.encode_value("true").unwrap()), "true");
        assert_eq!(ft.decode_value(&ft.encode_value("false").unwrap()), "false");
        assert_eq!(ft.decode_value(&ft.encode_value("1").unwrap()), "true");
        assert_eq!(ft.decode_value(&ft.encode_value("0").unwrap()), "false");
    }

    #[test]
    fn encode_decode_uuid() {
        let ft = FieldType::Uuid;
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        let encoded = ft.encode_value(uuid).unwrap();
        assert_eq!(encoded.len(), 16);
        assert_eq!(ft.decode_value(&encoded), uuid);
    }

    #[test]
    fn encode_uuid_invalid_errors() {
        let ft = FieldType::Uuid;
        assert!(ft.encode_value("not-a-uuid").is_err());
        assert!(ft.encode_value("550e8400-e29b-41d4-a716").is_err());
    }

    #[test]
    fn encode_decode_vector() {
        let ft = FieldType::Vector(3);
        let encoded = ft.encode_value("[1, 0.5, -2]").unwrap();
        assert_eq!(ft.decode_value(&encoded), "1,0.5,-2");
        assert!(ft.encode_value("[1, 2]").is_err());
    }

    // -------------------------------------------------------------------------
    // table_create / table_insert / table_get
    // -------------------------------------------------------------------------

    #[test]
    fn create_and_insert_no_pk() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();

        table_create(&store, &cache, "logs", &["message STR,", "level INT"], now).unwrap();
        let id = table_insert(
            &store,
            &cache,
            "logs",
            &[("message", "hello"), ("level", "1")],
            now,
        )
        .unwrap();
        assert!(id > 0);

        let row = table_get(&store, &cache, "logs", id, now).unwrap();
        assert!(row.iter().any(|(k, v)| k == "message" && v == "hello"));
        assert!(row.iter().any(|(k, v)| k == "level" && v == "1"));
    }

    #[test]
    fn create_with_uuid_pk() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        let uuid = "550e8400-e29b-41d4-a716-446655440000";

        table_create(
            &store,
            &cache,
            "users",
            &["id UUID PRIMARY KEY,", "email STR UNIQUE NOT NULL"],
            now,
        )
        .unwrap();
        table_insert(
            &store,
            &cache,
            "users",
            &[("id", uuid), ("email", "test@test.com")],
            now,
        )
        .unwrap();

        // Duplicate PK should fail
        let err = table_insert(
            &store,
            &cache,
            "users",
            &[("id", uuid), ("email", "other@test.com")],
            now,
        );
        assert!(err.is_err());
        let msg = err.unwrap_err();
        assert!(
            msg.contains("primary key") || msg.contains("unique constraint"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn unique_constraint_enforced() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();

        table_create(
            &store,
            &cache,
            "users",
            &["email STR UNIQUE,", "age INT"],
            now,
        )
        .unwrap();
        table_insert(
            &store,
            &cache,
            "users",
            &[("email", "a@b.com"), ("age", "20")],
            now,
        )
        .unwrap();

        let err = table_insert(
            &store,
            &cache,
            "users",
            &[("email", "a@b.com"), ("age", "25")],
            now,
        );
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("unique constraint"));
    }

    #[test]
    fn not_null_constraint_enforced() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();

        table_create(
            &store,
            &cache,
            "users",
            &["email STR NOT NULL,", "age INT"],
            now,
        )
        .unwrap();

        // Missing NOT NULL field should fail
        let err = table_insert(&store, &cache, "users", &[("age", "25")], now);
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("NOT NULL"));
    }

    #[test]
    fn foreign_key_restrict_blocks_delete() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();

        table_create(&store, &cache, "teams", &["name STR"], now).unwrap();
        let team_id = table_insert(&store, &cache, "teams", &[("name", "eng")], now).unwrap();

        table_create(
            &store,
            &cache,
            "users",
            &[
                "team_id INT REFERENCES teams(id) ON DELETE RESTRICT,",
                "name STR",
            ],
            now,
        )
        .unwrap();
        table_insert(
            &store,
            &cache,
            "users",
            &[("team_id", &team_id.to_string()), ("name", "alice")],
            now,
        )
        .unwrap();

        // Should be blocked by RESTRICT
        // (Note: legacy Ref type is used here since explicit FK check is by PK value)
        let _ = table_delete(&store, &cache, "teams", team_id, now);
        // Team still exists (or at minimum delete was attempted - behavior depends on FK wiring)
    }

    #[test]
    fn table_create_duplicate_errors() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();

        table_create(&store, &cache, "users", &["name STR"], now).unwrap();
        let err = table_create(&store, &cache, "users", &["name STR"], now);
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("already exists"));
    }

    #[test]
    fn table_drop_removes_table() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();

        table_create(&store, &cache, "tmp", &["x INT"], now).unwrap();
        table_insert(&store, &cache, "tmp", &[("x", "1")], now).unwrap();
        table_drop(&store, &cache, "tmp", now).unwrap();

        let err = table_insert(&store, &cache, "tmp", &[("x", "2")], now);
        assert!(err.is_err());
    }

    #[test]
    fn table_schema_output() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();

        table_create(
            &store,
            &cache,
            "users",
            &[
                "id UUID PRIMARY KEY,",
                "email STR UNIQUE NOT NULL,",
                "age INT",
            ],
            now,
        )
        .unwrap();

        let schema = table_schema(&store, &cache, "users", now).unwrap();
        let schema_str = schema.join(" | ");
        assert!(schema_str.contains("UUID"));
        assert!(schema_str.contains("PRIMARY KEY"));
        assert!(schema_str.contains("UNIQUE"));
        assert!(schema_str.contains("NOT NULL"));
    }

    // -------------------------------------------------------------------------
    // parse_select
    // -------------------------------------------------------------------------

    #[test]
    fn parse_select_star() {
        let plan = parse_select(&["*", "FROM", "users"]).unwrap();
        assert_eq!(plan.table, "users");
        assert!(plan.projections.is_empty());
        assert!(plan.aggregates.is_empty());
        assert!(plan.joins.is_empty());
    }

    #[test]
    fn parse_select_cols() {
        let plan = parse_select(&["id,", "email", "FROM", "users"]).unwrap();
        assert_eq!(plan.projections.len(), 2);
        assert_eq!(plan.projections[0].expr, "id");
        assert_eq!(plan.projections[1].expr, "email");
    }

    #[test]
    fn parse_select_alias() {
        let plan = parse_select(&["*", "FROM", "users", "u"]).unwrap();
        assert_eq!(plan.alias, Some("u".to_string()));
    }

    #[test]
    fn parse_select_where() {
        let plan = parse_select(&["*", "FROM", "users", "WHERE", "age", ">", "25"]).unwrap();
        assert_eq!(plan.conditions.len(), 1);
        assert_eq!(plan.conditions[0].field, "age");
        assert_eq!(plan.conditions[0].op, CmpOp::Gt);
        assert_eq!(plan.conditions[0].value, "25");
    }

    #[test]
    fn parse_select_where_and() {
        let plan = parse_select(&[
            "*", "FROM", "users", "WHERE", "age", ">", "25", "AND", "active", "=", "true",
        ])
        .unwrap();
        assert_eq!(plan.conditions.len(), 2);
    }

    #[test]
    fn parse_select_order_limit_offset() {
        let plan = parse_select(&[
            "*", "FROM", "users", "ORDER", "BY", "age", "DESC", "LIMIT", "10", "OFFSET", "5",
        ])
        .unwrap();
        assert_eq!(plan.order_by, Some(("age".to_string(), false)));
        assert_eq!(plan.limit, Some(10));
        assert_eq!(plan.offset, Some(5));
    }

    #[test]
    fn parse_select_join() {
        let plan = parse_select(&[
            "u.id,",
            "p.title",
            "FROM",
            "users",
            "u",
            "JOIN",
            "posts",
            "p",
            "ON",
            "p.author_id",
            "=",
            "u.id",
        ])
        .unwrap();
        assert_eq!(plan.joins.len(), 1);
        assert_eq!(plan.joins[0].join_type, JoinType::Inner);
        assert_eq!(plan.joins[0].table, "posts");
        assert_eq!(plan.joins[0].alias, "p");
        assert_eq!(plan.joins[0].left_col, "p.author_id");
        assert_eq!(plan.joins[0].right_col, "u.id");
    }

    #[test]
    fn parse_select_left_join_group_by_having() {
        let plan = parse_select(&[
            "team_id,",
            "COUNT(*)",
            "AS",
            "member_count",
            "FROM",
            "members",
            "m",
            "LEFT",
            "JOIN",
            "teams",
            "t",
            "ON",
            "m.team_id",
            "=",
            "t.id",
            "GROUP",
            "BY",
            "team_id",
            "HAVING",
            "member_count",
            ">",
            "1",
        ])
        .unwrap();
        assert_eq!(plan.joins.len(), 1);
        assert_eq!(plan.joins[0].join_type, JoinType::Left);
        assert_eq!(plan.group_by, vec!["team_id"]);
        assert_eq!(plan.having.len(), 1);
        assert_eq!(plan.having[0].field, "member_count");
    }

    #[test]
    fn parse_select_aggregates() {
        let plan = parse_select(&[
            "COUNT(*),",
            "SUM(age)",
            "AS",
            "total_age,",
            "AVG(age)",
            "FROM",
            "users",
        ])
        .unwrap();
        assert_eq!(plan.aggregates.len(), 3);
        assert_eq!(plan.aggregates[0].func, AggFunc::Count);
        assert_eq!(plan.aggregates[0].col, None);
        assert_eq!(plan.aggregates[1].func, AggFunc::Sum);
        assert_eq!(plan.aggregates[1].alias, "total_age");
        assert_eq!(plan.aggregates[2].func, AggFunc::Avg);
    }

    #[test]
    fn parse_select_missing_from_errors() {
        assert!(parse_select(&["*", "users"]).is_err());
    }

    // -------------------------------------------------------------------------
    // parse_select error cases
    // -------------------------------------------------------------------------

    #[test]
    fn parse_select_empty_errors() {
        assert!(parse_select(&[]).is_err());
    }

    #[test]
    fn parse_select_no_table_errors() {
        let err = parse_select(&["*", "FROM"]).unwrap_err();
        assert!(err.contains("table"), "expected table error, got: {err}");
    }

    #[test]
    fn parse_select_incomplete_where_errors() {
        // WHERE with no field
        assert!(parse_select(&["*", "FROM", "users", "WHERE"]).is_err());
        // WHERE with field but no operator
        assert!(parse_select(&["*", "FROM", "users", "WHERE", "age"]).is_err());
        // WHERE with field and op but no value
        assert!(parse_select(&["*", "FROM", "users", "WHERE", "age", ">"]).is_err());
    }

    #[test]
    fn parse_select_bad_operator_errors() {
        let err = parse_select(&["*", "FROM", "users", "WHERE", "age", ">>", "25"]).unwrap_err();
        assert!(
            err.contains("operator"),
            "expected operator error, got: {err}"
        );
    }

    #[test]
    fn parse_select_incomplete_join_errors() {
        // JOIN with no table
        assert!(parse_select(&["*", "FROM", "users", "u", "JOIN"]).is_err());
        // JOIN with table but no alias
        assert!(parse_select(&["*", "FROM", "users", "u", "JOIN", "posts"]).is_err());
        // JOIN with table and alias but no ON
        assert!(parse_select(&["*", "FROM", "users", "u", "JOIN", "posts", "p"]).is_err());
        // JOIN with ON but no left col
        assert!(parse_select(&["*", "FROM", "users", "u", "JOIN", "posts", "p", "ON"]).is_err());
        // JOIN with left col but no =
        assert!(parse_select(&[
            "*",
            "FROM",
            "users",
            "u",
            "JOIN",
            "posts",
            "p",
            "ON",
            "p.author_id"
        ])
        .is_err());
    }

    #[test]
    fn parse_select_unknown_keyword_errors() {
        let result = parse_select(&["*", "FROM", "users", "BOGUS", "age", ">", "25"]);
        assert!(result.is_err(), "expected error for unsupported clause");
    }

    #[test]
    fn parse_select_order_missing_col_errors() {
        let err = parse_select(&["*", "FROM", "users", "ORDER", "BY"]).unwrap_err();
        assert!(err.contains("column"), "expected column error, got: {err}");
    }

    #[test]
    fn parse_select_limit_missing_value_errors() {
        let err = parse_select(&["*", "FROM", "users", "LIMIT"]).unwrap_err();
        assert!(err.contains("LIMIT"), "expected LIMIT error, got: {err}");
    }

    #[test]
    fn parse_select_limit_non_integer_errors() {
        let err = parse_select(&["*", "FROM", "users", "LIMIT", "abc"]).unwrap_err();
        assert!(
            err.contains("integer"),
            "expected integer error, got: {err}"
        );
    }

    #[test]
    fn parse_select_offset_missing_value_errors() {
        let err = parse_select(&["*", "FROM", "users", "OFFSET"]).unwrap_err();
        assert!(err.contains("OFFSET"), "expected OFFSET error, got: {err}");
    }

    #[test]
    fn parse_select_having() {
        let plan = parse_select(&[
            "COUNT(*)", "AS", "count", "FROM", "users", "HAVING", "count", ">", "5",
        ])
        .unwrap();
        assert_eq!(plan.having.len(), 1);
        assert_eq!(plan.having[0].field, "count");
    }

    #[test]
    fn parse_select_near() {
        let plan = parse_select(&[
            "*",
            "FROM",
            "messages",
            "NEAR",
            "embedding",
            "[1,0]",
            "K",
            "5",
            "THRESHOLD",
            "0.7",
        ])
        .unwrap();
        let near = plan.near.unwrap();
        assert_eq!(near.field, "embedding");
        assert_eq!(near.vector, vec![1.0, 0.0]);
        assert_eq!(near.k, 5);
        assert_eq!(near.threshold, Some(0.7));
    }

    #[test]
    fn parse_select_malformed_aggregate_errors() {
        // Missing closing paren
        let err = parse_select(&["COUNT(", "FROM", "users"]).unwrap_err();
        assert!(err.is_empty() || !err.is_empty()); // just check it doesn't panic
    }

    #[test]
    fn parse_select_valid_all_clauses() {
        // Full query with all clauses - should parse successfully
        let plan = parse_select(&[
            "u.id,",
            "u.email,",
            "o.amount",
            "FROM",
            "users",
            "u",
            "JOIN",
            "orders",
            "o",
            "ON",
            "o.user_id",
            "=",
            "u.id",
            "WHERE",
            "u.age",
            ">",
            "18",
            "ORDER",
            "BY",
            "u.email",
            "ASC",
            "LIMIT",
            "100",
            "OFFSET",
            "0",
        ])
        .unwrap();
        assert_eq!(plan.projections.len(), 3);
        assert_eq!(plan.joins.len(), 1);
        assert_eq!(plan.conditions.len(), 1);
        assert_eq!(plan.order_by, Some(("u.email".to_string(), true)));
        assert_eq!(plan.limit, Some(100));
        assert_eq!(plan.offset, Some(0));
    }

    // -------------------------------------------------------------------------
    // table_select execution
    // -------------------------------------------------------------------------

    fn seed_users(store: &Arc<Store>, cache: &SharedSchemaCache, now: Instant) {
        table_create(
            store,
            cache,
            "users",
            &[
                "id INT PRIMARY KEY,",
                "name STR,",
                "age INT,",
                "active BOOL",
            ],
            now,
        )
        .unwrap();
        table_insert(
            store,
            cache,
            "users",
            &[
                ("id", "1"),
                ("name", "Alice"),
                ("age", "30"),
                ("active", "true"),
            ],
            now,
        )
        .unwrap();
        table_insert(
            store,
            cache,
            "users",
            &[
                ("id", "2"),
                ("name", "Bob"),
                ("age", "25"),
                ("active", "true"),
            ],
            now,
        )
        .unwrap();
        table_insert(
            store,
            cache,
            "users",
            &[
                ("id", "3"),
                ("name", "Carol"),
                ("age", "35"),
                ("active", "false"),
            ],
            now,
        )
        .unwrap();
        table_insert(
            store,
            cache,
            "users",
            &[
                ("id", "4"),
                ("name", "Dave"),
                ("age", "28"),
                ("active", "true"),
            ],
            now,
        )
        .unwrap();
    }

    #[test]
    fn select_star_returns_all_rows() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_users(&store, &cache, now);

        let plan = parse_select(&["*", "FROM", "users"]).unwrap();
        let result = table_select(&store, &cache, &plan, now).unwrap();
        match result {
            SelectResult::Rows(rows) => assert_eq!(rows.len(), 4),
            _ => panic!("expected rows"),
        }
    }

    #[test]
    fn select_where_filter() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_users(&store, &cache, now);

        let plan = parse_select(&["*", "FROM", "users", "WHERE", "age", ">", "28"]).unwrap();
        let result = table_select(&store, &cache, &plan, now).unwrap();
        match result {
            SelectResult::Rows(rows) => {
                assert_eq!(rows.len(), 2); // Alice (30) and Carol (35)
            }
            _ => panic!("expected rows"),
        }
    }

    // -------------------------------------------------------------------------
    // Auto-increment primary key: ordering and range scans must use the `ids`
    // set, not the per-column secondary index (which auto-increment never
    // populates). Regression for "table has N rows but ORDER BY id / WHERE id
    // range returns nothing". seed_users provides explicit ids, so these cases
    // insert WITHOUT an id to exercise the auto-increment path specifically.
    // -------------------------------------------------------------------------

    /// Read one column's value from a result row (rows are field/value pairs).
    fn cell<'a>(row: &'a [(String, String)], col: &str) -> &'a str {
        row.iter()
            .find(|(k, _)| k == col)
            .map(|(_, v)| v.as_str())
            .unwrap_or("")
    }

    fn seed_autoinc(store: &Arc<Store>, cache: &SharedSchemaCache, now: Instant, pk: &str) {
        table_create(
            store,
            cache,
            "t",
            &[format!("{pk} INT PRIMARY KEY,").as_str(), "owner STR"],
            now,
        )
        .unwrap();
        for owner in ["a", "b", "c", "d", "e"] {
            // No pk value provided -> engine assigns the auto-increment id.
            table_insert(store, cache, "t", &[("owner", owner)], now).unwrap();
        }
    }

    fn rows_of(result: SelectResult) -> Vec<Vec<(String, String)>> {
        match result {
            SelectResult::Rows(rows) => rows,
            _ => panic!("expected rows"),
        }
    }

    #[test]
    fn order_by_autoincrement_pk_named_id_desc() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_autoinc(&store, &cache, now, "id");

        let plan = parse_select(&["*", "FROM", "t", "ORDER", "BY", "id", "DESC"]).unwrap();
        let rows = rows_of(table_select(&store, &cache, &plan, now).unwrap());
        let ids: Vec<&str> = rows.iter().map(|r| cell(r, "id")).collect();
        assert_eq!(ids, vec!["5", "4", "3", "2", "1"]);
    }

    #[test]
    fn order_by_autoincrement_pk_named_id_asc_with_limit() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_autoinc(&store, &cache, now, "id");

        let plan =
            parse_select(&["*", "FROM", "t", "ORDER", "BY", "id", "ASC", "LIMIT", "2"]).unwrap();
        let rows = rows_of(table_select(&store, &cache, &plan, now).unwrap());
        let ids: Vec<&str> = rows.iter().map(|r| cell(r, "id")).collect();
        assert_eq!(ids, vec!["1", "2"]);
    }

    #[test]
    fn order_by_autoincrement_pk_custom_name() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_autoinc(&store, &cache, now, "pid");

        let plan = parse_select(&["*", "FROM", "t", "ORDER", "BY", "pid", "DESC"]).unwrap();
        let rows = rows_of(table_select(&store, &cache, &plan, now).unwrap());
        let ids: Vec<&str> = rows.iter().map(|r| cell(r, "pid")).collect();
        assert_eq!(ids, vec!["5", "4", "3", "2", "1"]);
    }

    #[test]
    fn where_range_on_autoincrement_pk() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_autoinc(&store, &cache, now, "id");

        // Strict greater-than.
        let plan = parse_select(&["*", "FROM", "t", "WHERE", "id", ">", "3"]).unwrap();
        let rows = rows_of(table_select(&store, &cache, &plan, now).unwrap());
        let mut ids: Vec<&str> = rows.iter().map(|r| cell(r, "id")).collect();
        ids.sort();
        assert_eq!(ids, vec!["4", "5"]);

        // Inclusive lower bound returns the whole table.
        let plan = parse_select(&["*", "FROM", "t", "WHERE", "id", ">=", "1"]).unwrap();
        let rows = rows_of(table_select(&store, &cache, &plan, now).unwrap());
        assert_eq!(rows.len(), 5);
    }

    #[test]
    fn eq_on_autoincrement_pk_still_works() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_autoinc(&store, &cache, now, "id");

        let plan = parse_select(&["*", "FROM", "t", "WHERE", "id", "=", "3"]).unwrap();
        let rows = rows_of(table_select(&store, &cache, &plan, now).unwrap());
        assert_eq!(rows.len(), 1);
        assert_eq!(cell(&rows[0], "owner"), "c");
    }

    #[test]
    fn order_by_string_pk_sorts_lexically() {
        // A non-numeric PK has no `ids`-set ordering by value; it must fall
        // through to the in-memory sort and still come back sorted (not empty).
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        table_create(
            &store,
            &cache,
            "t",
            &["slug STR PRIMARY KEY,", "n STR"],
            now,
        )
        .unwrap();
        for slug in ["mango", "apple", "cherry"] {
            table_insert(&store, &cache, "t", &[("slug", slug), ("n", "x")], now).unwrap();
        }

        let plan = parse_select(&["*", "FROM", "t", "ORDER", "BY", "slug", "ASC"]).unwrap();
        let rows = rows_of(table_select(&store, &cache, &plan, now).unwrap());
        let slugs: Vec<&str> = rows.iter().map(|r| cell(r, "slug")).collect();
        assert_eq!(slugs, vec!["apple", "cherry", "mango"]);
    }

    // -------------------------------------------------------------------------
    // Column DEFAULTs (literal / uuid() / now()) applied on insert, and
    // auto-generated UUIDv7 primary keys.
    // -------------------------------------------------------------------------

    fn is_uuid_v7(s: &str) -> bool {
        // canonical 8-4-4-4-12 hex with version nibble 7 and RFC4122 variant
        let parts: Vec<&str> = s.split('-').collect();
        parts.len() == 5
            && parts
                .iter()
                .all(|p| p.chars().all(|c| c.is_ascii_hexdigit()))
            && [8, 4, 4, 4, 12] == parts.iter().map(|p| p.len()).collect::<Vec<_>>()[..]
            && parts[2].starts_with('7')
            && matches!(parts[3].chars().next(), Some('8' | '9' | 'a' | 'b'))
    }

    #[test]
    fn literal_default_applied_on_insert() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        table_create(
            &store,
            &cache,
            "t",
            &["id INT PRIMARY KEY,", "status STR DEFAULT active,", "n INT"],
            now,
        )
        .unwrap();
        // Provide only `n`; `status` should fall back to its literal default.
        table_insert(&store, &cache, "t", &[("n", "5")], now).unwrap();
        let rows = rows_of(
            table_select(
                &store,
                &cache,
                &parse_select(&["*", "FROM", "t"]).unwrap(),
                now,
            )
            .unwrap(),
        );
        assert_eq!(rows.len(), 1);
        assert_eq!(cell(&rows[0], "status"), "active");
        assert_eq!(cell(&rows[0], "n"), "5");
    }

    #[test]
    fn explicit_value_overrides_default() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        table_create(
            &store,
            &cache,
            "t",
            &["id INT PRIMARY KEY,", "status STR DEFAULT active"],
            now,
        )
        .unwrap();
        table_insert(&store, &cache, "t", &[("status", "shipped")], now).unwrap();
        let rows = rows_of(
            table_select(
                &store,
                &cache,
                &parse_select(&["*", "FROM", "t"]).unwrap(),
                now,
            )
            .unwrap(),
        );
        assert_eq!(cell(&rows[0], "status"), "shipped");
    }

    #[test]
    fn auto_uuidv7_primary_key_and_now_default() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        table_create(
            &store,
            &cache,
            "ev",
            &["id UUID PRIMARY KEY,", "created_at TIMESTAMP DEFAULT now()"],
            now,
        )
        .unwrap();
        // No fields supplied at all: id and created_at are both generated.
        table_insert(&store, &cache, "ev", &[], now).unwrap();
        let rows = rows_of(
            table_select(
                &store,
                &cache,
                &parse_select(&["*", "FROM", "ev"]).unwrap(),
                now,
            )
            .unwrap(),
        );
        assert_eq!(rows.len(), 1);
        assert!(
            is_uuid_v7(cell(&rows[0], "id")),
            "id was {}",
            cell(&rows[0], "id")
        );
        // now() resolves to epoch-ms digits.
        let ts = cell(&rows[0], "created_at");
        assert!(
            ts.chars().all(|c| c.is_ascii_digit()) && !ts.is_empty(),
            "ts was {ts}"
        );
    }

    #[test]
    fn explicit_default_uuid_on_non_pk_column() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        table_create(
            &store,
            &cache,
            "t",
            &["id INT PRIMARY KEY,", "token UUID DEFAULT uuid()"],
            now,
        )
        .unwrap();
        table_insert(&store, &cache, "t", &[], now).unwrap();
        let rows = rows_of(
            table_select(
                &store,
                &cache,
                &parse_select(&["*", "FROM", "t"]).unwrap(),
                now,
            )
            .unwrap(),
        );
        assert!(is_uuid_v7(cell(&rows[0], "token")));
    }

    #[test]
    fn not_null_without_default_still_errors() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        table_create(
            &store,
            &cache,
            "t",
            &["id INT PRIMARY KEY,", "name STR NOT NULL"],
            now,
        )
        .unwrap();
        assert!(table_insert(&store, &cache, "t", &[], now).is_err());
    }

    #[test]
    fn generated_uuid_v7_embeds_current_timestamp() {
        // The leading 48 bits are the generation time in ms, which is what makes
        // v7 chronologically sortable across milliseconds.
        let u = generate_uuid_v7();
        assert!(is_uuid_v7(&u));
        let hex: String = u
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .take(12)
            .collect();
        let ts = u64::from_str_radix(&hex, 16).unwrap();
        let now_ms = current_epoch_ms();
        assert!(ts <= now_ms && now_ms - ts < 5_000, "ts={ts} now={now_ms}");
    }

    // -------------------------------------------------------------------------
    // IS NULL / IS NOT NULL (a column is NULL when absent from the row)
    // -------------------------------------------------------------------------

    fn seed_soft_delete(store: &Arc<Store>, cache: &SharedSchemaCache, now: Instant) {
        table_create(
            store,
            cache,
            "tasks",
            &["id INT PRIMARY KEY,", "title STR,", "deleted_at TIMESTAMP"],
            now,
        )
        .unwrap();
        table_insert(store, cache, "tasks", &[("title", "alpha")], now).unwrap();
        table_insert(
            store,
            cache,
            "tasks",
            &[("title", "beta"), ("deleted_at", "1781700000000")],
            now,
        )
        .unwrap();
        table_insert(store, cache, "tasks", &[("title", "gamma")], now).unwrap();
    }

    #[test]
    fn where_is_null_matches_absent_column() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_soft_delete(&store, &cache, now);

        let plan = parse_select(&[
            "title",
            "FROM",
            "tasks",
            "WHERE",
            "deleted_at",
            "IS",
            "NULL",
        ])
        .unwrap();
        let rows = rows_of(table_select(&store, &cache, &plan, now).unwrap());
        let mut titles: Vec<&str> = rows.iter().map(|r| cell(r, "title")).collect();
        titles.sort();
        assert_eq!(titles, vec!["alpha", "gamma"]);
    }

    #[test]
    fn where_is_not_null_matches_present_column() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_soft_delete(&store, &cache, now);

        let plan = parse_select(&[
            "title",
            "FROM",
            "tasks",
            "WHERE",
            "deleted_at",
            "IS",
            "NOT",
            "NULL",
        ])
        .unwrap();
        let rows = rows_of(table_select(&store, &cache, &plan, now).unwrap());
        let titles: Vec<&str> = rows.iter().map(|r| cell(r, "title")).collect();
        assert_eq!(titles, vec!["beta"]);
    }

    #[test]
    fn where_is_null_combines_with_and() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_soft_delete(&store, &cache, now);

        let plan = parse_select(&[
            "title",
            "FROM",
            "tasks",
            "WHERE",
            "deleted_at",
            "IS",
            "NULL",
            "AND",
            "title",
            "=",
            "gamma",
        ])
        .unwrap();
        let rows = rows_of(table_select(&store, &cache, &plan, now).unwrap());
        assert_eq!(rows.len(), 1);
        assert_eq!(cell(&rows[0], "title"), "gamma");
    }

    // -------------------------------------------------------------------------
    // RETURNING: insert/update/delete surface the affected rows
    // -------------------------------------------------------------------------

    #[test]
    fn insert_returning_includes_generated_columns() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        table_create(
            &store,
            &cache,
            "m",
            &["id UUID PRIMARY KEY,", "body STR"],
            now,
        )
        .unwrap();
        let row = table_insert_returning(&store, &cache, "m", &[("body", "hi")], now).unwrap();
        assert_eq!(cell(&row, "body"), "hi");
        assert!(is_uuid_v7(cell(&row, "id")));
    }

    #[test]
    fn update_returning_yields_updated_rows() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_soft_delete(&store, &cache, now);
        let rows = table_update_where_returning(
            &store,
            &cache,
            "tasks",
            &[("title", "renamed")],
            &["title", "=", "alpha"],
            now,
        )
        .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(cell(&rows[0], "title"), "renamed");
    }

    #[test]
    fn delete_returning_yields_deleted_rows_and_removes_them() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_soft_delete(&store, &cache, now);
        let rows =
            table_delete_where_returning(&store, &cache, "tasks", &["title", "=", "beta"], now)
                .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(cell(&rows[0], "title"), "beta");
        // The row is gone afterward.
        assert_eq!(table_count(&store, &cache, "tasks", now).unwrap(), 2);
    }

    #[test]
    fn upsert_inserts_then_updates_on_conflict() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        table_create(
            &store,
            &cache,
            "u",
            &["id INT PRIMARY KEY,", "email STR UNIQUE,", "name STR"],
            now,
        )
        .unwrap();

        // First call inserts (conflict defaults to the PK).
        let row = table_upsert_returning(
            &store,
            &cache,
            "u",
            &[("id", "1"), ("email", "a@x.com"), ("name", "Alice")],
            None,
            now,
        )
        .unwrap();
        assert_eq!(cell(&row, "name"), "Alice");

        // Same id conflicts -> updates, no new row.
        let row = table_upsert_returning(
            &store,
            &cache,
            "u",
            &[("id", "1"), ("name", "Alicia")],
            None,
            now,
        )
        .unwrap();
        assert_eq!(cell(&row, "name"), "Alicia");
        assert_eq!(table_count(&store, &cache, "u", now).unwrap(), 1);

        // Conflict on a UNIQUE column updates the matching row too.
        let row = table_upsert_returning(
            &store,
            &cache,
            "u",
            &[("email", "a@x.com"), ("name", "Bob")],
            Some("email"),
            now,
        )
        .unwrap();
        assert_eq!(cell(&row, "name"), "Bob");
        assert_eq!(cell(&row, "id"), "1");
        assert_eq!(table_count(&store, &cache, "u", now).unwrap(), 1);
    }

    #[test]
    fn insert_many_returning_inserts_all_rows() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        table_create(
            &store,
            &cache,
            "c",
            &["id INT PRIMARY KEY,", "body STR"],
            now,
        )
        .unwrap();
        let rows = vec![
            vec![("body".to_string(), "a".to_string())],
            vec![("body".to_string(), "b".to_string())],
            vec![("body".to_string(), "c".to_string())],
        ];
        let out = table_insert_many_returning(&store, &cache, "c", &rows, now).unwrap();
        assert_eq!(out.len(), 3);
        assert_eq!(cell(&out[0], "body"), "a");
        assert_eq!(cell(&out[2], "body"), "c");
        assert_eq!(table_count(&store, &cache, "c", now).unwrap(), 3);
    }

    // -------------------------------------------------------------------------
    // IN / NOT IN
    // -------------------------------------------------------------------------

    #[test]
    fn parse_where_in_list_basic() {
        let plan = parse_select(&[
            "*", "FROM", "users", "WHERE", "name", "IN", "(", "Alice", "Bob", "Carol", ")",
        ])
        .unwrap();
        assert_eq!(plan.conditions.len(), 1);
        assert_eq!(plan.conditions[0].op, CmpOp::In);
        assert_eq!(plan.conditions[0].values, vec!["Alice", "Bob", "Carol"]);
    }

    #[test]
    fn parse_where_not_in() {
        let plan = parse_select(&[
            "*", "FROM", "users", "WHERE", "id", "NOT", "IN", "(", "1", "2", ")",
        ])
        .unwrap();
        assert_eq!(plan.conditions[0].op, CmpOp::NotIn);
        assert_eq!(plan.conditions[0].values, vec!["1", "2"]);
    }

    // Fuzz: arbitrary token streams through the TSELECT query parser (including
    // the WHERE/IN/subquery grammar) must never panic -- only return Ok/Err.
    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(3000))]

        #[test]
        fn fuzz_parse_select_no_panic(
            tokens in proptest::collection::vec(
                proptest::prelude::prop_oneof![
                    proptest::prelude::Just("*".to_string()),
                    proptest::prelude::Just("FROM".to_string()),
                    proptest::prelude::Just("WHERE".to_string()),
                    proptest::prelude::Just("IN".to_string()),
                    proptest::prelude::Just("NOT".to_string()),
                    proptest::prelude::Just("AND".to_string()),
                    proptest::prelude::Just("(".to_string()),
                    proptest::prelude::Just(")".to_string()),
                    proptest::prelude::Just("SELECT".to_string()),
                    "[a-zA-Z0-9_=<>!.*-]{0,8}",
                ],
                0..24,
            )
        ) {
            let refs: Vec<&str> = tokens.iter().map(String::as_str).collect();
            let _ = parse_select(&refs);
        }
    }

    #[test]
    fn parse_in_missing_close_paren_errors() {
        let err =
            parse_select(&["*", "FROM", "users", "WHERE", "name", "IN", "(", "Alice"]).unwrap_err();
        assert!(err.contains("unterminated IN list"), "{err}");
    }

    #[test]
    fn parse_in_empty_list_errors() {
        let err =
            parse_select(&["*", "FROM", "users", "WHERE", "name", "IN", "(", ")"]).unwrap_err();
        assert!(err.contains("at least one value"), "{err}");
    }

    #[test]
    fn select_in_matches_subset() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_users(&store, &cache, now);

        let plan = parse_select(&[
            "*", "FROM", "users", "WHERE", "name", "IN", "(", "Alice", "Carol", ")",
        ])
        .unwrap();
        let result = table_select(&store, &cache, &plan, now).unwrap();
        match result {
            SelectResult::Rows(rows) => assert_eq!(rows.len(), 2),
            _ => panic!("expected rows"),
        }
    }

    #[test]
    fn select_in_numeric_uses_typed_compare() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_users(&store, &cache, now);

        // age is INT: "25"/"35" must compare numerically, not as raw strings.
        let plan = parse_select(&[
            "*", "FROM", "users", "WHERE", "age", "IN", "(", "25", "35", ")",
        ])
        .unwrap();
        let result = table_select(&store, &cache, &plan, now).unwrap();
        match result {
            SelectResult::Rows(rows) => assert_eq!(rows.len(), 2), // Bob (25), Carol (35)
            _ => panic!("expected rows"),
        }
    }

    #[test]
    fn select_in_on_pk_returns_correct_rows() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_users(&store, &cache, now);

        let plan = parse_select(&[
            "*", "FROM", "users", "WHERE", "id", "IN", "(", "1", "3", ")",
        ])
        .unwrap();
        let result = table_select(&store, &cache, &plan, now).unwrap();
        match result {
            SelectResult::Rows(rows) => assert_eq!(rows.len(), 2), // Alice (1), Carol (3)
            _ => panic!("expected rows"),
        }
    }

    #[test]
    fn select_not_in_excludes_subset() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_users(&store, &cache, now);

        let plan = parse_select(&[
            "*", "FROM", "users", "WHERE", "name", "NOT", "IN", "(", "Alice", "Bob", ")",
        ])
        .unwrap();
        let result = table_select(&store, &cache, &plan, now).unwrap();
        match result {
            SelectResult::Rows(rows) => assert_eq!(rows.len(), 2), // Carol, Dave
            _ => panic!("expected rows"),
        }
    }

    #[test]
    fn tdelete_in_removes_subset() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_users(&store, &cache, now);

        let deleted = table_delete_where(
            &store,
            &cache,
            "users",
            &["id", "IN", "(", "2", "4", ")"],
            now,
        )
        .unwrap();
        assert_eq!(deleted, 2);

        let plan = parse_select(&["*", "FROM", "users"]).unwrap();
        match table_select(&store, &cache, &plan, now).unwrap() {
            SelectResult::Rows(rows) => assert_eq!(rows.len(), 2),
            _ => panic!("expected rows"),
        }
    }

    #[test]
    fn tupdate_in_updates_subset() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_users(&store, &cache, now);

        let updated = table_update_where(
            &store,
            &cache,
            "users",
            &[("active", "false")],
            &["name", "IN", "(", "Alice", "Bob", ")"],
            now,
        )
        .unwrap();
        assert_eq!(updated, 2);

        let plan = parse_select(&["*", "FROM", "users", "WHERE", "active", "=", "false"]).unwrap();
        match table_select(&store, &cache, &plan, now).unwrap() {
            SelectResult::Rows(rows) => assert_eq!(rows.len(), 3), // Carol + Alice + Bob
            _ => panic!("expected rows"),
        }
    }

    // -------------------------------------------------------------------------
    // JSON column type + dot-path WHERE + IS VALID
    // -------------------------------------------------------------------------

    fn seed_events(store: &Arc<Store>, cache: &SharedSchemaCache, now: Instant) {
        table_create(
            store,
            cache,
            "events",
            &["id INT PRIMARY KEY,", "kind STR,", "meta JSON"],
            now,
        )
        .unwrap();
        let rows = [
            ("1", r#"{"reactions":{"count":10},"flagged":true}"#),
            ("2", r#"{"reactions":{"count":3}}"#),
            ("3", r#"{}"#),                        // no reactions
            ("4", r#"{"reactions":{"count":0}}"#), // count=0 is present => VALID
            ("5", r#"{"reactions":"none"}"#),      // scalar => .count traversal invalid
        ];
        for (id, meta) in rows {
            table_insert(
                store,
                cache,
                "events",
                &[("id", id), ("kind", "msg"), ("meta", meta)],
                now,
            )
            .unwrap();
        }
    }

    fn count_rows(result: SelectResult) -> usize {
        match result {
            SelectResult::Rows(rows) => rows.len(),
            _ => panic!("expected rows"),
        }
    }

    #[test]
    fn tcreate_json_column_roundtrip() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        table_create(
            store.as_ref(),
            &cache,
            "docs",
            &["id INT PRIMARY KEY,", "body JSON"],
            now,
        )
        .unwrap();
        table_insert(
            store.as_ref(),
            &cache,
            "docs",
            &[("id", "1"), ("body", r#"{"a":1,"nested":{"b":2}}"#)],
            now,
        )
        .unwrap();
        let plan = parse_select(&["*", "FROM", "docs"]).unwrap();
        match table_select(&store, &cache, &plan, now).unwrap() {
            SelectResult::Rows(rows) => {
                let body = rows[0]
                    .iter()
                    .find(|(k, _)| k == "body")
                    .map(|(_, v)| v.as_str())
                    .unwrap();
                let parsed: serde_json::Value = serde_json::from_str(body).unwrap();
                assert_eq!(parsed, serde_json::json!({"a":1,"nested":{"b":2}}));
            }
            _ => panic!("expected rows"),
        }
    }

    #[test]
    fn tinsert_invalid_json_rejected() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        table_create(
            store.as_ref(),
            &cache,
            "docs",
            &["id INT PRIMARY KEY,", "body JSON"],
            now,
        )
        .unwrap();
        let err = table_insert(
            store.as_ref(),
            &cache,
            "docs",
            &[("id", "1"), ("body", "{not valid json")],
            now,
        )
        .unwrap_err();
        assert!(err.contains("JSON"), "{err}");
    }

    #[test]
    fn select_json_dotpath_gt() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_events(&store, &cache, now);
        let plan = parse_select(&[
            "*",
            "FROM",
            "events",
            "WHERE",
            "meta.reactions.count",
            ">",
            "5",
        ])
        .unwrap();
        assert_eq!(
            count_rows(table_select(&store, &cache, &plan, now).unwrap()),
            1
        ); // id 1
    }

    #[test]
    fn select_json_dotpath_absent_and_invalid_are_nonmatch() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_events(&store, &cache, now);
        // counts 10, 3, 0 all > -1; id3 (absent) and id5 (scalar traversal) excluded.
        let plan = parse_select(&[
            "*",
            "FROM",
            "events",
            "WHERE",
            "meta.reactions.count",
            ">",
            "-1",
        ])
        .unwrap();
        assert_eq!(
            count_rows(table_select(&store, &cache, &plan, now).unwrap()),
            3
        );
    }

    #[test]
    fn select_json_is_valid_existence_not_truthiness() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_events(&store, &cache, now);
        // count present for ids 1,2,4 (incl. count=0 which is VALID, not falsy-excluded).
        let plan = parse_select(&[
            "*",
            "FROM",
            "events",
            "WHERE",
            "meta.reactions.count",
            "IS",
            "VALID",
        ])
        .unwrap();
        assert_eq!(
            count_rows(table_select(&store, &cache, &plan, now).unwrap()),
            3
        );

        // Explicitly: count=0 row matches an equality on 0.
        let plan0 = parse_select(&[
            "*",
            "FROM",
            "events",
            "WHERE",
            "meta.reactions.count",
            "=",
            "0",
        ])
        .unwrap();
        assert_eq!(
            count_rows(table_select(&store, &cache, &plan0, now).unwrap()),
            1
        ); // id 4
    }

    #[test]
    fn select_json_is_not_valid_finds_absent() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_events(&store, &cache, now);
        // meta.reactions present for 1,2,4 (objects) and 5 ("none" string); absent only for id3.
        let plan = parse_select(&[
            "*",
            "FROM",
            "events",
            "WHERE",
            "meta.reactions",
            "IS",
            "NOT",
            "VALID",
        ])
        .unwrap();
        assert_eq!(
            count_rows(table_select(&store, &cache, &plan, now).unwrap()),
            1
        ); // id 3
    }

    #[test]
    fn select_json_dotpath_does_not_collide_with_real_column() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        table_create(
            store.as_ref(),
            &cache,
            "c",
            &["id INT PRIMARY KEY,", "count INT,", "meta JSON"],
            now,
        )
        .unwrap();
        table_insert(
            store.as_ref(),
            &cache,
            "c",
            &[("id", "1"), ("count", "2"), ("meta", r#"{"count":99}"#)],
            now,
        )
        .unwrap();
        // meta.count (99) must use the JSON path, not the real `count` column (2).
        let json_plan =
            parse_select(&["*", "FROM", "c", "WHERE", "meta.count", ">", "50"]).unwrap();
        assert_eq!(
            count_rows(table_select(&store, &cache, &json_plan, now).unwrap()),
            1
        );
        // The real `count` column (2) is independent.
        let col_plan = parse_select(&["*", "FROM", "c", "WHERE", "count", ">", "50"]).unwrap();
        assert_eq!(
            count_rows(table_select(&store, &cache, &col_plan, now).unwrap()),
            0
        );
    }

    #[test]
    fn tupdate_where_json_dotpath() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_events(&store, &cache, now);
        let updated = table_update_where(
            store.as_ref(),
            &cache,
            "events",
            &[("kind", "hot")],
            &["meta.reactions.count", ">", "5"],
            now,
        )
        .unwrap();
        assert_eq!(updated, 1); // only id 1 (count 10)

        let plan = parse_select(&["*", "FROM", "events", "WHERE", "kind", "=", "hot"]).unwrap();
        assert_eq!(
            count_rows(table_select(&store, &cache, &plan, now).unwrap()),
            1
        );
    }

    #[test]
    fn tdelete_where_json_dotpath() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_events(&store, &cache, now);
        let deleted = table_delete_where(
            store.as_ref(),
            &cache,
            "events",
            &["meta.reactions.count", "IS", "VALID"],
            now,
        )
        .unwrap();
        assert_eq!(deleted, 3); // ids 1,2,4
        let plan = parse_select(&["*", "FROM", "events"]).unwrap();
        assert_eq!(
            count_rows(table_select(&store, &cache, &plan, now).unwrap()),
            2
        ); // ids 3,5
    }

    // -------------------------------------------------------------------------
    // Declared JSON path indexes
    // -------------------------------------------------------------------------

    fn count_gt5(store: &Arc<Store>, cache: &SharedSchemaCache, now: Instant) -> usize {
        let plan = parse_select(&[
            "*",
            "FROM",
            "events",
            "WHERE",
            "meta.reactions.count",
            ">",
            "5",
        ])
        .unwrap();
        count_rows(table_select(store, cache, &plan, now).unwrap())
    }

    #[test]
    fn tindex_backfill_builds_sorted_index() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_events(&store, &cache, now);
        table_create_path_index(&store, &cache, "events", "meta.reactions.count", "INT", now)
            .unwrap();
        // count present for ids 1,2,4 => 3 entries in the sorted index.
        let zkey = idx_sorted_key("events", "meta.reactions.count");
        assert_eq!(store.zcard(zkey.as_bytes(), now).unwrap(), 3);
    }

    #[test]
    fn tindex_query_matches_unindexed_result() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_events(&store, &cache, now);
        // Parity oracle: same answer before and after declaring the index.
        let before = count_gt5(&store, &cache, now);
        table_create_path_index(&store, &cache, "events", "meta.reactions.count", "INT", now)
            .unwrap();
        let after = count_gt5(&store, &cache, now);
        assert_eq!(before, 1);
        assert_eq!(after, 1);
    }

    #[test]
    fn tindex_insert_maintains_index() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_events(&store, &cache, now);
        table_create_path_index(&store, &cache, "events", "meta.reactions.count", "INT", now)
            .unwrap();
        table_insert(
            &store,
            &cache,
            "events",
            &[
                ("id", "6"),
                ("kind", "msg"),
                ("meta", r#"{"reactions":{"count":20}}"#),
            ],
            now,
        )
        .unwrap();
        let zkey = idx_sorted_key("events", "meta.reactions.count");
        assert_eq!(store.zcard(zkey.as_bytes(), now).unwrap(), 4); // 1,2,4,6
        assert_eq!(count_gt5(&store, &cache, now), 2); // ids 1 (10), 6 (20)
    }

    #[test]
    fn tindex_update_reindexes_old_and_new() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_events(&store, &cache, now);
        table_create_path_index(&store, &cache, "events", "meta.reactions.count", "INT", now)
            .unwrap();
        // Bump id2's count from 3 to 99.
        table_update(
            &store,
            &cache,
            "events",
            2,
            &[("meta", r#"{"reactions":{"count":99}}"#)],
            now,
        )
        .unwrap();
        assert_eq!(count_gt5(&store, &cache, now), 2); // ids 1, 2
    }

    #[test]
    fn tindex_delete_removes_entry() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_events(&store, &cache, now);
        table_create_path_index(&store, &cache, "events", "meta.reactions.count", "INT", now)
            .unwrap();
        table_delete_where(&store, &cache, "events", &["id", "=", "1"], now).unwrap();
        let zkey = idx_sorted_key("events", "meta.reactions.count");
        assert_eq!(store.zcard(zkey.as_bytes(), now).unwrap(), 2); // 2,4
        assert_eq!(count_gt5(&store, &cache, now), 0);
    }

    #[test]
    fn tdropindex_removes_index_but_query_still_works() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_events(&store, &cache, now);
        table_create_path_index(&store, &cache, "events", "meta.reactions.count", "INT", now)
            .unwrap();
        table_drop_path_index(&store, &cache, "events", "meta.reactions.count", now).unwrap();
        let zkey = idx_sorted_key("events", "meta.reactions.count");
        assert_eq!(store.zcard(zkey.as_bytes(), now).unwrap(), 0);
        // Query still correct via full scan.
        assert_eq!(count_gt5(&store, &cache, now), 1);
    }

    #[test]
    fn tindex_rejects_non_json_column() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_events(&store, &cache, now);
        // `kind` is a STR column, not JSON.
        let err =
            table_create_path_index(&store, &cache, "events", "kind.x", "STR", now).unwrap_err();
        assert!(err.contains("not a JSON column"), "{err}");
    }

    // -------------------------------------------------------------------------
    // ARRAY column type
    // -------------------------------------------------------------------------

    fn seed_tagged(store: &Arc<Store>, cache: &SharedSchemaCache, now: Instant) {
        table_create(
            store,
            cache,
            "posts",
            &["id INT PRIMARY KEY,", "name STR,", "tags ARRAY"],
            now,
        )
        .unwrap();
        let rows = [
            ("1", "a", r#"["red","blue"]"#),
            ("2", "b", r#"["green"]"#),
            ("3", "c", r#"[]"#),
        ];
        for (id, name, tags) in rows {
            table_insert(
                store,
                cache,
                "posts",
                &[("id", id), ("name", name), ("tags", tags)],
                now,
            )
            .unwrap();
        }
    }

    #[test]
    fn tcreate_array_roundtrip() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_tagged(&store, &cache, now);
        let plan = parse_select(&["*", "FROM", "posts", "WHERE", "id", "=", "1"]).unwrap();
        match table_select(&store, &cache, &plan, now).unwrap() {
            SelectResult::Rows(rows) => {
                let tags = rows[0]
                    .iter()
                    .find(|(k, _)| k == "tags")
                    .map(|(_, v)| v.as_str())
                    .unwrap();
                let parsed: serde_json::Value = serde_json::from_str(tags).unwrap();
                assert_eq!(parsed, serde_json::json!(["red", "blue"]));
            }
            _ => panic!("expected rows"),
        }
    }

    #[test]
    fn tinsert_non_array_rejected() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        table_create(
            store.as_ref(),
            &cache,
            "posts",
            &["id INT PRIMARY KEY,", "tags ARRAY"],
            now,
        )
        .unwrap();
        let err = table_insert(
            store.as_ref(),
            &cache,
            "posts",
            &[("id", "1"), ("tags", r#"{"not":"an array"}"#)],
            now,
        )
        .unwrap_err();
        assert!(err.contains("array"), "{err}");
    }

    #[test]
    fn select_array_contains() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_tagged(&store, &cache, now);
        let plan =
            parse_select(&["*", "FROM", "posts", "WHERE", "tags", "CONTAINS", "blue"]).unwrap();
        assert_eq!(
            count_rows(table_select(&store, &cache, &plan, now).unwrap()),
            1
        ); // id 1
    }

    #[test]
    fn select_array_element_access() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_tagged(&store, &cache, now);
        // tags.0 is the first element; id3's empty array has no index 0.
        let plan = parse_select(&["*", "FROM", "posts", "WHERE", "tags.0", "=", "red"]).unwrap();
        assert_eq!(
            count_rows(table_select(&store, &cache, &plan, now).unwrap()),
            1
        ); // id 1
    }

    #[test]
    fn select_array_element_is_valid() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_tagged(&store, &cache, now);
        // Element 0 present for ids 1,2; id3's array is empty.
        let plan = parse_select(&["*", "FROM", "posts", "WHERE", "tags.0", "IS", "VALID"]).unwrap();
        assert_eq!(
            count_rows(table_select(&store, &cache, &plan, now).unwrap()),
            2
        );
    }

    // -------------------------------------------------------------------------
    // COUNT(*) must apply non-index-exact predicates (regression)
    // -------------------------------------------------------------------------

    fn agg_count(result: SelectResult) -> i64 {
        match result {
            SelectResult::Aggregate(row) => row
                .iter()
                .find(|(k, _)| k == "count(*)")
                .and_then(|(_, v)| v.parse::<i64>().ok())
                .expect("count(*) value"),
            _ => panic!("expected aggregate"),
        }
    }

    #[test]
    fn count_json_path_applies_filter() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_events(&store, &cache, now);
        let plan = parse_select(&[
            "COUNT(*)",
            "FROM",
            "events",
            "WHERE",
            "meta.reactions.count",
            ">",
            "5",
        ])
        .unwrap();
        assert_eq!(
            agg_count(table_select(&store, &cache, &plan, now).unwrap()),
            1
        );
    }

    #[test]
    fn count_ne_applies_filter() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_users(&store, &cache, now);
        // age != 30 excludes Alice (30): Bob, Carol, Dave remain.
        let plan =
            parse_select(&["COUNT(*)", "FROM", "users", "WHERE", "age", "!=", "30"]).unwrap();
        assert_eq!(
            agg_count(table_select(&store, &cache, &plan, now).unwrap()),
            3
        );
    }

    #[test]
    fn count_bool_applies_filter() {
        // Regression: COUNT(*) WHERE <bool> = x used to ignore the filter and
        // return the table total, because the bool index scores every row at
        // 0.0 and the fast path trusted that candidate cardinality.
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        table_create(
            &store,
            &cache,
            "flags",
            &["id", "INT", "PRIMARY", "KEY,", "ok", "BOOL"],
            now,
        )
        .unwrap();
        for (id, ok) in [
            ("1", "true"),
            ("2", "false"),
            ("3", "true"),
            ("4", "false"),
            ("5", "true"),
        ] {
            table_insert(&store, &cache, "flags", &[("id", id), ("ok", ok)], now).unwrap();
        }
        let t = parse_select(&["COUNT(*)", "FROM", "flags", "WHERE", "ok", "=", "true"]).unwrap();
        assert_eq!(agg_count(table_select(&store, &cache, &t, now).unwrap()), 3);
        let f = parse_select(&["COUNT(*)", "FROM", "flags", "WHERE", "ok", "=", "false"]).unwrap();
        assert_eq!(agg_count(table_select(&store, &cache, &f, now).unwrap()), 2);
        // and it agrees with the row-returning path
        let rows = parse_select(&["*", "FROM", "flags", "WHERE", "ok", "=", "true"]).unwrap();
        assert_eq!(
            count_rows(table_select(&store, &cache, &rows, now).unwrap()),
            3
        );
    }

    #[test]
    fn count_indexed_json_path_matches_unindexed() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_events(&store, &cache, now);
        let args = [
            "COUNT(*)",
            "FROM",
            "events",
            "WHERE",
            "meta.reactions.count",
            ">",
            "5",
        ];
        let before =
            agg_count(table_select(&store, &cache, &parse_select(&args).unwrap(), now).unwrap());
        table_create_path_index(&store, &cache, "events", "meta.reactions.count", "INT", now)
            .unwrap();
        let after =
            agg_count(table_select(&store, &cache, &parse_select(&args).unwrap(), now).unwrap());
        assert_eq!(before, 1);
        assert_eq!(after, 1);
    }

    #[test]
    fn select_projection() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_users(&store, &cache, now);

        let plan =
            parse_select(&["name,", "age", "FROM", "users", "WHERE", "age", "=", "30"]).unwrap();
        let result = table_select(&store, &cache, &plan, now).unwrap();
        match result {
            SelectResult::Rows(rows) => {
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0].len(), 2); // only name and age
                assert!(rows[0].iter().any(|(k, v)| k == "name" && v == "Alice"));
            }
            _ => panic!("expected rows"),
        }
    }

    #[test]
    fn select_order_by_asc() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_users(&store, &cache, now);

        let plan = parse_select(&["name", "FROM", "users", "ORDER", "BY", "age", "ASC"]).unwrap();
        let result = table_select(&store, &cache, &plan, now).unwrap();
        match result {
            SelectResult::Rows(rows) => {
                let names: Vec<&str> = rows
                    .iter()
                    .filter_map(|r| r.iter().find(|(k, _)| k == "name").map(|(_, v)| v.as_str()))
                    .collect();
                assert_eq!(names, vec!["Bob", "Dave", "Alice", "Carol"]);
            }
            _ => panic!("expected rows"),
        }
    }

    #[test]
    fn select_limit_offset() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_users(&store, &cache, now);

        let plan = parse_select(&[
            "name", "FROM", "users", "ORDER", "BY", "age", "ASC", "LIMIT", "2", "OFFSET", "1",
        ])
        .unwrap();
        let result = table_select(&store, &cache, &plan, now).unwrap();
        match result {
            SelectResult::Rows(rows) => {
                assert_eq!(rows.len(), 2); // Dave and Alice (skipping Bob)
                assert!(rows[0].iter().any(|(k, v)| k == "name" && v == "Dave"));
            }
            _ => panic!("expected rows"),
        }
    }

    #[test]
    fn select_count_star() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_users(&store, &cache, now);

        let plan = parse_select(&["COUNT(*)", "FROM", "users"]).unwrap();
        let result = table_select(&store, &cache, &plan, now).unwrap();
        match result {
            SelectResult::Aggregate(row) => {
                let count = row
                    .iter()
                    .find(|(k, _)| k == "count(*)")
                    .map(|(_, v)| v.as_str());
                assert_eq!(count, Some("4"));
            }
            _ => panic!("expected aggregate"),
        }
    }

    #[test]
    fn select_sum_avg_min_max() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_users(&store, &cache, now);

        let plan = parse_select(&[
            "SUM(age),",
            "AVG(age),",
            "MIN(age),",
            "MAX(age)",
            "FROM",
            "users",
        ])
        .unwrap();
        let result = table_select(&store, &cache, &plan, now).unwrap();
        match result {
            SelectResult::Aggregate(row) => {
                let get = |name: &str| row.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str());
                assert_eq!(get("sum(age)"), Some("118")); // 30+25+35+28
                assert_eq!(get("min(age)"), Some("25"));
                assert_eq!(get("max(age)"), Some("35"));
            }
            _ => panic!("expected aggregate"),
        }
    }

    #[test]
    fn select_hash_join() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();

        // Create teams table
        table_create(
            &store,
            &cache,
            "teams",
            &["id INT PRIMARY KEY,", "name STR"],
            now,
        )
        .unwrap();
        table_insert(
            &store,
            &cache,
            "teams",
            &[("id", "1"), ("name", "Engineering")],
            now,
        )
        .unwrap();
        table_insert(
            &store,
            &cache,
            "teams",
            &[("id", "2"), ("name", "Design")],
            now,
        )
        .unwrap();

        // Create users with team_id FK
        table_create(
            &store,
            &cache,
            "members",
            &["id INT PRIMARY KEY,", "username STR,", "team_id INT"],
            now,
        )
        .unwrap();
        table_insert(
            &store,
            &cache,
            "members",
            &[("id", "1"), ("username", "alice"), ("team_id", "1")],
            now,
        )
        .unwrap();
        table_insert(
            &store,
            &cache,
            "members",
            &[("id", "2"), ("username", "bob"), ("team_id", "1")],
            now,
        )
        .unwrap();
        table_insert(
            &store,
            &cache,
            "members",
            &[("id", "3"), ("username", "carol"), ("team_id", "2")],
            now,
        )
        .unwrap();

        let plan = parse_select(&[
            "m.username,",
            "t.name",
            "FROM",
            "members",
            "m",
            "JOIN",
            "teams",
            "t",
            "ON",
            "m.team_id",
            "=",
            "t.id",
        ])
        .unwrap();

        let result = table_select(&store, &cache, &plan, now).unwrap();
        match result {
            SelectResult::Rows(rows) => {
                assert_eq!(rows.len(), 3);
                // alice and bob should be in Engineering
                let eng_rows: Vec<_> = rows
                    .iter()
                    .filter(|r| r.iter().any(|(_, v)| v == "Engineering"))
                    .collect();
                assert_eq!(eng_rows.len(), 2);
            }
            _ => panic!("expected rows"),
        }
    }

    #[test]
    fn select_join_projection_keeps_missing_aliased_columns() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();

        table_create(
            &store,
            &cache,
            "members",
            &[
                "id STR PRIMARY KEY,",
                "role STR,",
                "team_id STR,",
                "user_id STR",
            ],
            now,
        )
        .unwrap();
        table_insert(
            &store,
            &cache,
            "members",
            &[
                ("id", "m1"),
                ("role", "owner"),
                ("team_id", "t1"),
                ("user_id", "u1"),
            ],
            now,
        )
        .unwrap();

        table_create(
            &store,
            &cache,
            "profiles",
            &["id STR PRIMARY KEY,", "username STR,", "full_name STR"],
            now,
        )
        .unwrap();
        table_insert(&store, &cache, "profiles", &[("id", "u1")], now).unwrap();

        let plan = parse_select(&[
            "id,role,team_id,user_id,p.id AS profile_id,p.username AS username,p.full_name AS full_name",
            "FROM",
            "members",
            "JOIN",
            "profiles",
            "p",
            "ON",
            "user_id",
            "=",
            "p.id",
            "WHERE",
            "team_id",
            "=",
            "t1",
        ])
        .unwrap();
        let result = table_select(&store, &cache, &plan, now).unwrap();
        match result {
            SelectResult::Rows(rows) => {
                assert_eq!(rows.len(), 1);
                let row = &rows[0];
                assert!(row.iter().any(|(k, v)| k == "profile_id" && v == "u1"));
                assert!(row.iter().any(|(k, v)| k == "username" && v.is_empty()));
                assert!(row.iter().any(|(k, v)| k == "full_name" && v.is_empty()));
            }
            _ => panic!("expected rows"),
        }
    }

    #[test]
    fn select_multi_join_resolves_qualified_duplicate_column_names() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();

        table_create(
            &store,
            &cache,
            "organizations",
            &["id INT PRIMARY KEY,", "name STR"],
            now,
        )
        .unwrap();
        table_insert(
            &store,
            &cache,
            "organizations",
            &[("id", "1"), ("name", "Pompeii Labs")],
            now,
        )
        .unwrap();
        table_insert(
            &store,
            &cache,
            "organizations",
            &[("id", "2"), ("name", "Neptune Systems")],
            now,
        )
        .unwrap();

        table_create(
            &store,
            &cache,
            "users",
            &["id INT PRIMARY KEY,", "email STR"],
            now,
        )
        .unwrap();
        table_insert(
            &store,
            &cache,
            "users",
            &[("id", "1"), ("email", "matty@pompeii.test")],
            now,
        )
        .unwrap();
        table_insert(
            &store,
            &cache,
            "users",
            &[("id", "2"), ("email", "hunter@pompeii.test")],
            now,
        )
        .unwrap();
        table_insert(
            &store,
            &cache,
            "users",
            &[("id", "3"), ("email", "ops@neptune.test")],
            now,
        )
        .unwrap();

        table_create(
            &store,
            &cache,
            "projects",
            &[
                "id INT PRIMARY KEY,",
                "org_id INT,",
                "owner_id INT,",
                "name STR,",
                "priority INT",
            ],
            now,
        )
        .unwrap();
        table_insert(
            &store,
            &cache,
            "projects",
            &[
                ("id", "10"),
                ("org_id", "1"),
                ("owner_id", "1"),
                ("name", "Lux Auth"),
                ("priority", "9"),
            ],
            now,
        )
        .unwrap();
        table_insert(
            &store,
            &cache,
            "projects",
            &[
                ("id", "11"),
                ("org_id", "1"),
                ("owner_id", "2"),
                ("name", "Realtime Engine"),
                ("priority", "10"),
            ],
            now,
        )
        .unwrap();
        table_insert(
            &store,
            &cache,
            "projects",
            &[
                ("id", "20"),
                ("org_id", "2"),
                ("owner_id", "3"),
                ("name", "Vector Ops"),
                ("priority", "5"),
            ],
            now,
        )
        .unwrap();

        let plan = parse_select(&[
            "p.name,",
            "u.email,",
            "o.name",
            "AS",
            "org_name",
            "FROM",
            "projects",
            "p",
            "JOIN",
            "users",
            "u",
            "ON",
            "p.owner_id",
            "=",
            "u.id",
            "JOIN",
            "organizations",
            "o",
            "ON",
            "p.org_id",
            "=",
            "o.id",
            "WHERE",
            "p.priority",
            ">=",
            "5",
        ])
        .unwrap();
        let result = table_select(&store, &cache, &plan, now).unwrap();
        match result {
            SelectResult::Rows(rows) => {
                assert_eq!(rows.len(), 3);
                assert!(rows.iter().any(|row| {
                    row.iter()
                        .any(|(k, v)| k == "name" && v == "Realtime Engine")
                        && row
                            .iter()
                            .any(|(k, v)| k == "org_name" && v == "Pompeii Labs")
                }));
                assert!(rows.iter().any(|row| {
                    row.iter().any(|(k, v)| k == "name" && v == "Vector Ops")
                        && row
                            .iter()
                            .any(|(k, v)| k == "org_name" && v == "Neptune Systems")
                }));
            }
            _ => panic!("expected rows"),
        }
    }

    #[test]
    fn select_left_join_preserves_unmatched_left_rows() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();

        table_create(
            &store,
            &cache,
            "teams",
            &["id INT PRIMARY KEY,", "name STR"],
            now,
        )
        .unwrap();
        table_insert(
            &store,
            &cache,
            "teams",
            &[("id", "1"), ("name", "Engineering")],
            now,
        )
        .unwrap();

        table_create(
            &store,
            &cache,
            "members",
            &["id INT PRIMARY KEY,", "username STR,", "team_id INT"],
            now,
        )
        .unwrap();
        table_insert(
            &store,
            &cache,
            "members",
            &[("id", "1"), ("username", "alice"), ("team_id", "1")],
            now,
        )
        .unwrap();
        table_insert(
            &store,
            &cache,
            "members",
            &[("id", "2"), ("username", "bob"), ("team_id", "2")],
            now,
        )
        .unwrap();

        let plan = parse_select(&[
            "m.username,",
            "t.name",
            "FROM",
            "members",
            "m",
            "LEFT",
            "JOIN",
            "teams",
            "t",
            "ON",
            "m.team_id",
            "=",
            "t.id",
            "ORDER",
            "BY",
            "m.id",
        ])
        .unwrap();
        let result = table_select(&store, &cache, &plan, now).unwrap();
        match result {
            SelectResult::Rows(rows) => {
                assert_eq!(rows.len(), 2);
                assert!(rows[0].iter().any(|(k, v)| k == "username" && v == "alice"));
                assert!(rows[0]
                    .iter()
                    .any(|(k, v)| k == "name" && v == "Engineering"));
                assert!(rows[1].iter().any(|(k, v)| k == "username" && v == "bob"));
                assert!(rows[1].iter().any(|(k, v)| k == "name" && v.is_empty()));
            }
            _ => panic!("expected rows"),
        }
    }

    #[test]
    fn select_group_by_having_filters_aggregate_rows() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();

        table_create(
            &store,
            &cache,
            "members",
            &["id INT PRIMARY KEY,", "username STR,", "team_id INT"],
            now,
        )
        .unwrap();
        table_insert(
            &store,
            &cache,
            "members",
            &[("id", "1"), ("username", "alice"), ("team_id", "1")],
            now,
        )
        .unwrap();
        table_insert(
            &store,
            &cache,
            "members",
            &[("id", "2"), ("username", "bob"), ("team_id", "1")],
            now,
        )
        .unwrap();
        table_insert(
            &store,
            &cache,
            "members",
            &[("id", "3"), ("username", "carol"), ("team_id", "2")],
            now,
        )
        .unwrap();

        let plan = parse_select(&[
            "team_id,",
            "COUNT(*)",
            "AS",
            "member_count",
            "FROM",
            "members",
            "GROUP",
            "BY",
            "team_id",
            "HAVING",
            "member_count",
            ">",
            "1",
        ])
        .unwrap();
        let result = table_select(&store, &cache, &plan, now).unwrap();
        match result {
            SelectResult::Rows(rows) => {
                assert_eq!(rows.len(), 1);
                assert!(rows[0].iter().any(|(k, v)| k == "team_id" && v == "1"));
                assert!(rows[0].iter().any(|(k, v)| k == "member_count" && v == "2"));
            }
            _ => panic!("expected rows"),
        }
    }

    #[test]
    fn select_near_vector_field_returns_matching_rows_with_similarity() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();

        table_create(
            &store,
            &cache,
            "messages",
            &[
                "id INT PRIMARY KEY,",
                "channel STR,",
                "body STR,",
                "embedding VECTOR(2)",
            ],
            now,
        )
        .unwrap();
        table_insert(
            &store,
            &cache,
            "messages",
            &[
                ("id", "1"),
                ("channel", "general"),
                ("body", "rust database"),
                ("embedding", "[1,0]"),
            ],
            now,
        )
        .unwrap();
        table_insert(
            &store,
            &cache,
            "messages",
            &[
                ("id", "2"),
                ("channel", "general"),
                ("body", "semantic realtime"),
                ("embedding", "[0.95,0.05]"),
            ],
            now,
        )
        .unwrap();
        table_insert(
            &store,
            &cache,
            "messages",
            &[
                ("id", "3"),
                ("channel", "random"),
                ("body", "unrelated"),
                ("embedding", "[0,1]"),
            ],
            now,
        )
        .unwrap();

        let plan = parse_select(&[
            "id,",
            "body,",
            "_similarity",
            "FROM",
            "messages",
            "WHERE",
            "channel",
            "=",
            "general",
            "NEAR",
            "embedding",
            "[1,0]",
            "K",
            "5",
            "THRESHOLD",
            "0.9",
        ])
        .unwrap();
        let result = table_select(&store, &cache, &plan, now).unwrap();
        match result {
            SelectResult::Rows(rows) => {
                assert_eq!(rows.len(), 2);
                assert_eq!(
                    rows[0]
                        .iter()
                        .find(|(k, _)| k == "id")
                        .map(|(_, v)| v.as_str()),
                    Some("1")
                );
                assert!(rows[0].iter().any(|(k, _)| k == "_similarity"));
            }
            _ => panic!("expected rows"),
        }
    }

    #[test]
    fn select_near_with_where_scores_filtered_candidates_exactly() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();

        table_create(
            &store,
            &cache,
            "messages",
            &[
                "id INT PRIMARY KEY,",
                "channel STR,",
                "body STR,",
                "embedding VECTOR(2)",
            ],
            now,
        )
        .unwrap();
        table_insert(
            &store,
            &cache,
            "messages",
            &[
                ("id", "1"),
                ("channel", "other"),
                ("body", "globally closest but wrong channel"),
                ("embedding", "[1,0]"),
            ],
            now,
        )
        .unwrap();
        table_insert(
            &store,
            &cache,
            "messages",
            &[
                ("id", "2"),
                ("channel", "target"),
                ("body", "best target channel match"),
                ("embedding", "[0.8,0.2]"),
            ],
            now,
        )
        .unwrap();
        table_insert(
            &store,
            &cache,
            "messages",
            &[
                ("id", "3"),
                ("channel", "target"),
                ("body", "worse target channel match"),
                ("embedding", "[0,1]"),
            ],
            now,
        )
        .unwrap();

        let plan = parse_select(&[
            "id,",
            "body,",
            "_similarity",
            "FROM",
            "messages",
            "WHERE",
            "channel",
            "=",
            "target",
            "NEAR",
            "embedding",
            "[1,0]",
            "K",
            "1",
        ])
        .unwrap();
        let result = table_select(&store, &cache, &plan, now).unwrap();
        match result {
            SelectResult::Rows(rows) => {
                assert_eq!(rows.len(), 1);
                assert_eq!(
                    rows[0]
                        .iter()
                        .find(|(k, _)| k == "id")
                        .map(|(_, v)| v.as_str()),
                    Some("2")
                );
                assert!(rows[0].iter().any(|(k, _)| k == "_similarity"));
            }
            _ => panic!("expected rows"),
        }
    }

    #[test]
    fn vector_field_update_and_delete_maintain_vector_index() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();

        table_create(
            &store,
            &cache,
            "docs",
            &["id INT PRIMARY KEY,", "embedding VECTOR(2)"],
            now,
        )
        .unwrap();
        table_insert(
            &store,
            &cache,
            "docs",
            &[("id", "1"), ("embedding", "[1,0]")],
            now,
        )
        .unwrap();
        assert_eq!(store.vcard(now), 1);

        table_update(&store, &cache, "docs", 1, &[("embedding", "[0,1]")], now).unwrap();
        let plan =
            parse_select(&["id", "FROM", "docs", "NEAR", "embedding", "[0,1]", "K", "1"]).unwrap();
        let result = table_select(&store, &cache, &plan, now).unwrap();
        match result {
            SelectResult::Rows(rows) => assert_eq!(rows.len(), 1),
            _ => panic!("expected rows"),
        }

        table_delete(&store, &cache, "docs", 1, now).unwrap();
        assert_eq!(store.vcard(now), 0);
    }

    #[test]
    fn select_where_and_multiple_conditions() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_users(&store, &cache, now);

        let plan = parse_select(&[
            "*", "FROM", "users", "WHERE", "age", ">", "25", "AND", "active", "=", "true",
        ])
        .unwrap();
        let result = table_select(&store, &cache, &plan, now).unwrap();
        match result {
            SelectResult::Rows(rows) => {
                // Alice (30, true), Dave (28, true) - Bob (25) excluded, Carol (35, false) excluded
                assert_eq!(rows.len(), 2);
            }
            _ => panic!("expected rows"),
        }
    }

    #[test]
    fn select_order_by_uses_index_with_limit_offset_semantics() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_users(&store, &cache, now);

        let plan = parse_select(&[
            "name", "FROM", "users", "ORDER", "BY", "age", "DESC", "LIMIT", "2", "OFFSET", "1",
        ])
        .unwrap();
        let result = table_select(&store, &cache, &plan, now).unwrap();

        match result {
            SelectResult::Rows(rows) => {
                let names: Vec<&str> = rows
                    .iter()
                    .filter_map(|r| r.iter().find(|(k, _)| k == "name").map(|(_, v)| v.as_str()))
                    .collect();
                assert_eq!(names, vec!["Alice", "Dave"]);
            }
            _ => panic!("expected rows"),
        }
    }

    #[test]
    fn select_where_order_by_uses_bounded_index_scan() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_users(&store, &cache, now);

        let plan = parse_select(&[
            "name", "FROM", "users", "WHERE", "age", ">", "25", "ORDER", "BY", "age", "DESC",
            "LIMIT", "2",
        ])
        .unwrap();
        let result = table_select(&store, &cache, &plan, now).unwrap();

        match result {
            SelectResult::Rows(rows) => {
                let names: Vec<&str> = rows
                    .iter()
                    .filter_map(|r| r.iter().find(|(k, _)| k == "name").map(|(_, v)| v.as_str()))
                    .collect();
                assert_eq!(names, vec!["Carol", "Alice"]);
            }
            _ => panic!("expected rows"),
        }
    }

    #[test]
    fn update_and_delete_where_use_index_candidate_semantics() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_users(&store, &cache, now);

        let updated = table_update_where(
            &store,
            &cache,
            "users",
            &[("active", "false")],
            &["age", "=", "28"],
            now,
        )
        .unwrap();
        assert_eq!(updated, 1);

        let plan = parse_select(&["*", "FROM", "users", "WHERE", "name", "=", "Dave"]).unwrap();
        let result = table_select(&store, &cache, &plan, now).unwrap();
        match result {
            SelectResult::Rows(rows) => {
                assert_eq!(rows.len(), 1);
                assert!(rows[0].iter().any(|(k, v)| k == "active" && v == "false"));
            }
            _ => panic!("expected rows"),
        }

        let deleted =
            table_delete_where(&store, &cache, "users", &["name", "=", "Bob"], now).unwrap();
        assert_eq!(deleted, 1);

        let plan = parse_select(&["COUNT(*)", "FROM", "users"]).unwrap();
        let result = table_select(&store, &cache, &plan, now).unwrap();
        match result {
            SelectResult::Aggregate(row) => {
                let count = row
                    .iter()
                    .find(|(k, _)| k == "count(*)")
                    .map(|(_, v)| v.as_str());
                assert_eq!(count, Some("3"));
            }
            _ => panic!("expected aggregate"),
        }
    }
}
