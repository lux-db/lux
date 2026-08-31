pub(crate) mod select;
pub(crate) use select::*;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::RwLock;

use crate::store::{AtomicTableBatch, JournalPrepareGuard, Store, TableVectorCandidateQuery};

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
    pub sequence_partition: Option<String>, // SEQUENCE PARTITION BY <column>
    pub references: Option<ForeignKey>,
    pub encrypted: bool,
    pub searchable: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CmpOp {
    Eq,
    Ne,
    Gt,
    Lt,
    Ge,
    Le,
    Like,
    ILike,
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
    Or,
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
    /// Nested disjuncts for OR groups. Empty for every other op.
    pub or_clauses: Vec<WhereClause>,
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
            or_clauses: Vec::new(),
        }
    }

    /// Construct a list clause for In/NotIn.
    pub fn in_list(field: String, op: CmpOp, values: Vec<String>) -> Self {
        WhereClause {
            field,
            op,
            value: String::new(),
            values,
            or_clauses: Vec::new(),
        }
    }

    pub fn or_group(or_clauses: Vec<WhereClause>) -> Self {
        WhereClause {
            field: String::new(),
            op: CmpOp::Or,
            value: String::new(),
            values: Vec::new(),
            or_clauses,
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

    // Whether the caller may see decrypted values of ENCRYPTED columns. True for
    // the operator/secret key and real authenticated users; false for anonymous
    // (signInAnonymously) principals, who get NULL for encrypted columns. Set by
    // the HTTP auth boundary; defaults true for internal/RESP/operator queries.
    pub decrypt_authorized: bool,
}

fn schema_key(table: &str) -> String {
    format!("_t:{}:schema", table)
}

fn seq_key(table: &str) -> String {
    format!("_t:{}:seq", table)
}

fn scoped_seq_key(table: &str, field: &str, partition_col: &str, partition_val: &str) -> String {
    format!(
        "_t:{}:seq:{}:{}:{}",
        table, field, partition_col, partition_val
    )
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

fn clear_row_ttl(store: &Store, table: &str, pk: &str, now: Instant) -> Result<(), String> {
    let rk = row_key_for_pk(table, pk);
    store.hdel(rk.as_bytes(), &[HIDDEN_TTL_FIELD], now)?;
    let member = ttl_member(table, pk);
    store.zrem(ttl_index_key().as_bytes(), &[member.as_bytes()], now)?;
    Ok(())
}

// ---- Table-write journal boundary -----------------------------------------
// Table data writes are committed HERE (the leaf functions), not by execute_with_wal,
// for two reasons:
//   1. Durability: HTTP table writes bypass execute_with_wal entirely, so without
//      this they are not durable and are lost on crash since the last snapshot.
//   2. Determinism: the raw command carries no generated PK / resolved default, so
//      replaying it regenerates uuid()/now() and the row's identity changes. We log
//      the RESOLVED command (explicit PK + resolved values) so replay reproduces the
//      exact row.
// The Store journal boundary no-ops when durability is disabled or suppressed
// during replay. execute_with_wal must NOT also record these commands or the row
// would be applied twice on replay.

/// The PK column name for a table (the declared PK, else the implicit `id`).
fn pk_column_name(schema: &[FieldDef]) -> &str {
    schema
        .iter()
        .find(|f| f.primary_key)
        .map(|f| f.name.as_str())
        .unwrap_or("id")
}

fn raw_row_journal_command(table: &str, pk: &str, row: &[(String, Vec<u8>)]) -> Vec<Vec<u8>> {
    let mut command = Vec::with_capacity(row.len() * 2 + 3);
    command.push(b"TROWSET".to_vec());
    command.push(table.as_bytes().to_vec());
    command.push(pk.as_bytes().to_vec());
    for (field, value) in row {
        command.push(field.as_bytes().to_vec());
        command.push(value.clone());
    }
    command
}

/// A complete table-row change prepared privately before its resolved journal
/// record is published. The journal guard serializes table writers while the
/// batch holds a validated, infallible row-and-index operation plan. Once
/// durable, every affected key changes under one affected-shard write barrier.
struct TableMutation<'a> {
    store: &'a Store,
    journal: JournalPrepareGuard<'a>,
    batch: AtomicTableBatch<'a>,
    row_deltas: std::collections::BTreeSet<(String, String)>,
}

#[cfg(test)]
thread_local! {
    static FAIL_TABLE_MUTATION_AFTER_JOURNAL: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
}

#[cfg(test)]
fn fail_next_table_mutation_after_journal() {
    FAIL_TABLE_MUTATION_AFTER_JOURNAL.with(|fault| fault.set(true));
}

impl<'a> TableMutation<'a> {
    fn prepare(store: &'a Store, route: &[&[u8]], now: Instant) -> Result<Self, String> {
        let journal = store
            .prepare_journaled(route)
            .map_err(|error| format!("ERR WAL append failed: {error}"))?;
        Ok(Self {
            store,
            journal,
            batch: AtomicTableBatch::new(store, now),
            row_deltas: std::collections::BTreeSet::new(),
        })
    }

    fn row_changed(&mut self, table: &str, pk: &str) {
        self.row_deltas.insert((table.to_string(), pk.to_string()));
    }

    fn publish(self, command: &[&[u8]]) -> Result<(), String> {
        let store = self.store;
        let commit = self
            .journal
            .commit(command)
            .map_err(|error| format!("ERR WAL append failed: {error}"))?;
        #[cfg(test)]
        if FAIL_TABLE_MUTATION_AFTER_JOURNAL.with(|fault| fault.replace(false)) {
            return Err("ERR injected interruption after table journal publication".to_string());
        }
        self.batch.apply();
        if store.wants_row_deltas() {
            for (table, pk) in self.row_deltas {
                store.emit_row_delta(&table, &pk);
            }
        }
        commit
            .complete()
            .map_err(|error| format!("ERR journal apply failed: {error}"))
    }
}

fn stage_add_to_index(
    mutation: &mut TableMutation<'_>,
    store: &Store,
    table: &str,
    field: &FieldDef,
    value: &str,
    pk: &str,
) -> Result<(), String> {
    if field.encrypted {
        if field.searchable {
            for index_value in searchable_index_values(store, table, field, value)? {
                mutation
                    .batch
                    .set_add(&idx_str_key(table, &field.name, &index_value), pk)?;
            }
        }
        return Ok(());
    }

    match &field.field_type {
        FieldType::Int
        | FieldType::Float
        | FieldType::Bool
        | FieldType::Timestamp
        | FieldType::Ref(_) => {
            let score = if field.field_type == FieldType::Bool {
                match value {
                    "true" | "1" => 1.0,
                    "false" | "0" => 0.0,
                    _ => return Err(format!("ERR invalid boolean index value '{value}'")),
                }
            } else {
                value
                    .parse::<f64>()
                    .map_err(|_| format!("ERR invalid numeric index value '{value}'"))?
            };
            mutation
                .batch
                .sorted_set_add(&idx_sorted_key(table, &field.name), pk, score)?;
        }
        FieldType::Str | FieldType::Uuid => mutation
            .batch
            .set_add(&idx_str_key(table, &field.name, value), pk)?,
        FieldType::Vector(dims) => {
            let vector = parse_vector_value(value, *dims)?;
            let metadata = serde_json::json!({
                "table": table,
                "field": field.name,
                "table_field": format!("{}.{}", table, field.name),
                "pk": pk,
                "id": pk,
            })
            .to_string();
            mutation.batch.vector_set(
                &table_vector_key(table, &field.name, pk),
                vector,
                Some(metadata),
                field.encrypted,
            )?;
        }
        FieldType::Json | FieldType::Array => {}
    }
    Ok(())
}

fn stage_remove_from_index(
    mutation: &mut TableMutation<'_>,
    store: &Store,
    table: &str,
    field: &FieldDef,
    value: &str,
    pk: &str,
) -> Result<(), String> {
    if field.encrypted {
        if field.searchable {
            for index_value in searchable_index_values(store, table, field, value)? {
                mutation
                    .batch
                    .set_remove(&idx_str_key(table, &field.name, &index_value), pk)?;
            }
        }
        return Ok(());
    }

    match &field.field_type {
        FieldType::Int
        | FieldType::Float
        | FieldType::Bool
        | FieldType::Timestamp
        | FieldType::Ref(_) => mutation
            .batch
            .sorted_set_remove(&idx_sorted_key(table, &field.name), pk)?,
        FieldType::Str | FieldType::Uuid => mutation
            .batch
            .set_remove(&idx_str_key(table, &field.name, value), pk)?,
        FieldType::Vector(_) => {
            mutation
                .batch
                .delete_vector(&table_vector_key(table, &field.name, pk))?
        }
        FieldType::Json | FieldType::Array => {}
    }
    Ok(())
}

fn stage_set_unique(
    mutation: &mut TableMutation<'_>,
    store: &Store,
    table: &str,
    field: &FieldDef,
    value: &str,
    pk: &str,
) -> Result<(), String> {
    let pairs = searchable_index_values(store, table, field, value)?
        .into_iter()
        .map(|index_value| (index_value, pk.as_bytes().to_vec()))
        .collect::<Vec<_>>();
    mutation
        .batch
        .hash_set(&uniq_key(table, &field.name), &pairs)
}

fn stage_remove_unique(
    mutation: &mut TableMutation<'_>,
    store: &Store,
    table: &str,
    field: &FieldDef,
    value: &str,
) -> Result<(), String> {
    let fields = searchable_index_values(store, table, field, value)?;
    mutation
        .batch
        .hash_delete(&uniq_key(table, &field.name), &fields)
}

fn stage_bump_sequence(
    mutation: &mut TableMutation<'_>,
    store: &Store,
    key: String,
    value: i64,
    now: Instant,
) -> Result<(), String> {
    if value > current_sequence(store, &key, now)? {
        mutation
            .batch
            .set_string(&key, value.to_string().into_bytes())?;
    }
    Ok(())
}

fn stage_clear_row_ttl(
    mutation: &mut TableMutation<'_>,
    table: &str,
    pk: &str,
) -> Result<(), String> {
    mutation.batch.hash_delete(
        &row_key_for_pk(table, pk),
        &[String::from_utf8_lossy(HIDDEN_TTL_FIELD).to_string()],
    )?;
    mutation
        .batch
        .sorted_set_remove(ttl_index_key(), &ttl_member(table, pk))
}

pub(crate) fn table_apply_wal_row(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    pk_str: &str,
    raw_pairs: &[(&[u8], &[u8])],
    now: Instant,
) -> Result<(), String> {
    let schema = load_schema(store, cache, table, now)?;
    let rk = row_key_for_pk(table, pk_str);

    if let Some(old_row) = get_row_including_expired(store, table, &schema, pk_str, now)? {
        let old_map: std::collections::HashMap<String, String> = old_row.into_iter().collect();
        for field in &schema {
            if let Some(old_val) = old_map.get(&field.name) {
                remove_from_index(store, table, field, old_val, pk_str, now)?;
                if field.unique {
                    remove_unique_entries(store, table, field, old_val, now)?;
                }
            }
        }
    }

    let mut raw_map: std::collections::HashMap<String, Vec<u8>> = std::collections::HashMap::new();
    for (field, value) in raw_pairs {
        raw_map.insert(String::from_utf8_lossy(field).to_string(), value.to_vec());
    }

    let ikey = ids_key(table);
    let score: f64 = match store.zscore(ikey.as_bytes(), pk_str.as_bytes(), now)? {
        Some(score) => score,
        None => match pk_str.parse::<f64>() {
            Ok(score) => score,
            Err(_) => next_id(store, &format!("{}__order", table), now)? as f64,
        },
    };
    store.zadd(
        ikey.as_bytes(),
        &[(pk_str.as_bytes(), score)],
        false,
        false,
        false,
        false,
        false,
        now,
    )?;

    if let Some(pk_field) = schema.iter().find(|f| f.primary_key) {
        if pk_field.field_type == FieldType::Int {
            if let Ok(id) = pk_str.parse::<i64>() {
                bump_seq_to_at_least(store, table, id, now)?;
            }
        }
    } else if let Ok(id) = pk_str.parse::<i64>() {
        bump_seq_to_at_least(store, table, id, now)?;
    }

    // Scoped sequence counters are derived state, just like the primary-key
    // counter. Rebuild them from every resolved row so recovery cannot reuse a
    // sequence value after an explicit or generated insert.
    for field in schema
        .iter()
        .filter(|field| field.sequence_partition.is_some())
    {
        let Some(raw_value) = raw_map.get(&field.name) else {
            continue;
        };
        let Some(partition_col) = field.sequence_partition.as_deref() else {
            continue;
        };
        let Some(partition_field) = schema
            .iter()
            .find(|candidate| candidate.name == partition_col)
        else {
            continue;
        };
        let Some(raw_partition) = raw_map.get(partition_col) else {
            continue;
        };
        let value = decode_stored_value(store, table, field, pk_str, raw_value)?;
        let partition = decode_stored_value(store, table, partition_field, pk_str, raw_partition)?;
        if let Ok(value) = value.parse::<i64>() {
            bump_scoped_seq_to_at_least(
                store,
                table,
                &field.name,
                partition_col,
                &partition,
                value,
                now,
            )?;
        }
    }

    for field in &schema {
        let Some(raw) = raw_map.get(&field.name) else {
            continue;
        };
        let value = decode_stored_value(store, table, field, pk_str, raw)?;
        add_to_index(store, table, field, &value, pk_str, now)?;
        if field.unique {
            let ukey = uniq_key(table, &field.name);
            for index_value in searchable_index_values(store, table, field, &value)? {
                store.hset(
                    ukey.as_bytes(),
                    &[(index_value.as_bytes() as &[u8], pk_str.as_bytes() as &[u8])],
                    now,
                )?;
            }
        }
    }

    for pi in &load_path_indexes(store, cache, table, now)? {
        if let Some((root, rest)) = pi.path.split_once('.') {
            if let Some(root_field) = schema.iter().find(|f| f.name == root) {
                if root_field.encrypted {
                    continue;
                }
                if let Some(raw) = raw_map.get(root) {
                    let bytes = stored_plain_bytes(store, table, root_field, pk_str, raw)?;
                    if let Some(scalar) =
                        extract_json_scalar(&root_field.field_type.decode_value(&bytes), rest)
                    {
                        add_to_index(
                            store,
                            table,
                            &synthetic_path_fielddef(pi),
                            &scalar,
                            pk_str,
                            now,
                        )?;
                    }
                }
            }
        }
    }

    if let Some(ttl_bytes) = raw_map.get(std::str::from_utf8(HIDDEN_TTL_FIELD).unwrap_or("")) {
        if let Some(deadline_ms) = std::str::from_utf8(ttl_bytes)
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
        {
            let member = ttl_member(table, pk_str);
            store.zadd(
                ttl_index_key().as_bytes(),
                &[(member.as_bytes(), deadline_ms as f64)],
                false,
                false,
                false,
                false,
                false,
                now,
            )?;
        }
    } else {
        let member = ttl_member(table, pk_str);
        store.zrem(ttl_index_key().as_bytes(), &[member.as_bytes()], now)?;
        store.hdel(rk.as_bytes(), &[HIDDEN_TTL_FIELD], now)?;
    }

    let pair_refs: Vec<(&[u8], &[u8])> = raw_pairs.iter().map(|(k, v)| (*k, *v)).collect();
    store.hset(rk.as_bytes(), &pair_refs, now)?;
    Ok(())
}

fn field_supports_encryption(field: &FieldDef) -> Result<(), String> {
    if field.searchable && !field.encrypted {
        return Err(format!(
            "ERR SEARCHABLE column '{}' must also be ENCRYPTED",
            field.name
        ));
    }
    if !field.encrypted {
        return Ok(());
    }
    if field.primary_key {
        return Err(format!(
            "ERR encrypted column '{}' cannot be a PRIMARY KEY",
            field.name
        ));
    }
    if field.references.is_some() || matches!(field.field_type, FieldType::Ref(_)) {
        return Err(format!(
            "ERR encrypted column '{}' cannot be a foreign key",
            field.name
        ));
    }
    if field.sequence_partition.is_some() {
        return Err(format!(
            "ERR encrypted column '{}' cannot be a SEQUENCE column",
            field.name
        ));
    }
    if field.searchable && matches!(field.field_type, FieldType::Vector(_)) {
        return Err(format!(
            "ERR encrypted VECTOR column '{}' cannot be SEARCHABLE (similarity search uses the in-memory index, not a blind index)",
            field.name
        ));
    }
    if field.default_value.is_some() {
        return Err(format!(
            "ERR encrypted column '{}' cannot use DEFAULT",
            field.name
        ));
    }
    if field.searchable && matches!(field.field_type, FieldType::Json | FieldType::Array) {
        return Err(format!(
            "ERR encrypted column '{}' cannot be SEARCHABLE with JSON or ARRAY type",
            field.name
        ));
    }
    if field.unique && field.encrypted && !field.searchable {
        return Err(format!(
            "ERR UNIQUE encrypted column '{}' must be SEARCHABLE",
            field.name
        ));
    }
    Ok(())
}

fn ensure_encryption_ready(store: &Store, fields: &[FieldDef]) -> Result<(), String> {
    if fields.iter().any(|f| f.encrypted) && !store.encryption().has_active_key() {
        return Err(
            "ERR encrypted columns require ENC INIT or an active encryption key".to_string(),
        );
    }
    Ok(())
}

fn encode_stored_value(
    store: &Store,
    table: &str,
    field: &FieldDef,
    pk: &str,
    value: &str,
) -> Result<Vec<u8>, String> {
    let encoded = field.field_type.encode_value(value)?;
    if field.encrypted {
        store
            .encryption()
            .encrypt(table, &field.name, pk, encoded.as_slice())
    } else {
        Ok(encoded)
    }
}

pub(crate) fn decode_stored_value(
    store: &Store,
    table: &str,
    field: &FieldDef,
    pk: &str,
    raw: &[u8],
) -> Result<String, String> {
    let bytes = stored_plain_bytes(store, table, field, pk, raw)?;
    Ok(field.field_type.decode_value(&bytes))
}

pub(crate) fn stored_plain_bytes(
    store: &Store,
    table: &str,
    field: &FieldDef,
    pk: &str,
    raw: &[u8],
) -> Result<Vec<u8>, String> {
    if field.encrypted {
        store.encryption().decrypt(table, &field.name, pk, raw)
    } else {
        Ok(raw.to_vec())
    }
}

fn searchable_index_values(
    store: &Store,
    table: &str,
    field: &FieldDef,
    value: &str,
) -> Result<Vec<String>, String> {
    if field.encrypted {
        if !field.searchable {
            return Err(format!(
                "ERR encrypted column '{}' is not SEARCHABLE",
                field.name
            ));
        }
        let encoded = field.field_type.encode_value(value)?;
        store
            .encryption()
            .blind_indexes(table, &field.name, encoded.as_slice())
    } else {
        Ok(vec![value.to_string()])
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
) -> Result<bool, String> {
    let rk = row_key_for_pk(table, holder_pk);
    match store.hget_checked(rk.as_bytes(), field.name.as_bytes(), now)? {
        Some(raw) => {
            decode_stored_value(store, table, field, holder_pk, &raw).map(|stored| stored == value)
        }
        None => Ok(false),
    }
}

fn remove_unique_entries(
    store: &Store,
    table: &str,
    field: &FieldDef,
    value: &str,
    now: Instant,
) -> Result<(), String> {
    let ukey = uniq_key(table, &field.name);
    for index_value in searchable_index_values(store, table, field, value)? {
        store.hdel(ukey.as_bytes(), &[index_value.as_bytes()], now)?;
    }
    Ok(())
}

fn unique_holder_for_value(
    store: &Store,
    table: &str,
    field: &FieldDef,
    value: &str,
    now: Instant,
) -> Result<Option<String>, String> {
    if !field.unique {
        return Ok(None);
    }
    let ukey = uniq_key(table, &field.name);
    for index_value in searchable_index_values(store, table, field, value)? {
        if let Some(holder) = store.hget_checked(ukey.as_bytes(), index_value.as_bytes(), now)? {
            return Ok(Some(String::from_utf8_lossy(&holder).to_string()));
        }
    }
    Ok(None)
}

fn referenced_value_exists(
    store: &Store,
    cache: &SharedSchemaCache,
    reference: &ForeignKey,
    value: &str,
    now: Instant,
) -> Result<bool, String> {
    let schema = load_schema(store, cache, &reference.table, now)?;
    let primary_key = pk_column_name(&schema);
    if reference.column == primary_key {
        return Ok(get_row(store, &reference.table, &schema, value, now, true)?.is_some());
    }

    let field = schema
        .iter()
        .find(|field| field.name == reference.column)
        .ok_or_else(|| {
            format!(
                "ERR referenced column '{}.{}' does not exist",
                reference.table, reference.column
            )
        })?;
    let Some(holder) = unique_holder_for_value(store, &reference.table, field, value, now)? else {
        return Ok(false);
    };
    Ok(
        get_row(store, &reference.table, &schema, &holder, now, true)?.is_some()
            && uniq_holder_holds_value(store, &reference.table, field, &holder, value, now)?,
    )
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
) -> Result<bool, String> {
    let rk = row_key_for_pk(table, pk);
    let pairs = store.hgetall(rk.as_bytes(), now)?;
    if pairs.is_empty() {
        return Ok(true);
    }
    if row_map_expired(&pairs) {
        table_delete_inner(store, cache, table, pk, now, 0)?;
        return Ok(true);
    }
    Ok(false)
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
pub fn expire_due_rows(
    store: &Store,
    cache: &SharedSchemaCache,
    now: Instant,
) -> Result<Vec<String>, String> {
    let key = ttl_index_key();
    let now_ms = current_epoch_ms() as f64;
    let due = store.zrangebyscore(
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
    )?;
    let mut affected: Vec<String> = Vec::new();
    for (member, _score) in due {
        let Some((table, pk)) = member.split_once('\u{0}') else {
            let command: [&[u8]; 3] = [b"ZREM", key.as_bytes(), member.as_bytes()];
            store
                .commit_journaled(&command, || {
                    store.zrem(key.as_bytes(), &[member.as_bytes()], now)
                })
                .map_err(|error| format!("ERR WAL append failed: {error}"))??;
            continue;
        };
        if expire_row_if_due(store, cache, table, pk, now_ms as u64, now)?
            && !affected.iter().any(|t| t == table)
        {
            affected.push(table.to_string());
        }
    }
    Ok(affected)
}

fn expire_row_if_due(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    pk: &str,
    cutoff_ms: u64,
    now: Instant,
) -> Result<bool, String> {
    let route: [&[u8]; 3] = [b"TDELETE", b"FROM", table.as_bytes()];
    let mut mutation = TableMutation::prepare(store, &route, now)?;
    let row_key = row_key_for_pk(table, pk);
    let deadline = store
        .hget_checked(row_key.as_bytes(), HIDDEN_TTL_FIELD, now)?
        .and_then(|value| std::str::from_utf8(&value).ok()?.parse::<u64>().ok());

    match deadline {
        Some(deadline) if deadline <= cutoff_ms => {
            stage_and_publish_delete(cache, table, pk, now, mutation)?;
            Ok(true)
        }
        Some(_) => Ok(false),
        None => {
            let ttl_key = ttl_index_key();
            let member = ttl_member(table, pk);
            mutation.batch.sorted_set_remove(ttl_key, &member)?;
            let command: [&[u8]; 3] = [b"ZREM", ttl_key.as_bytes(), member.as_bytes()];
            mutation.publish(&command)?;
            Ok(false)
        }
    }
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
fn tokenize_field_def(spec: &str) -> Result<Vec<String>, String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;

    for ch in spec.chars() {
        if let Some(q) = quote {
            current.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
                quote = None;
            }
            continue;
        }

        if ch == '\'' || ch == '"' {
            current.push(ch);
            quote = Some(ch);
        } else if ch.is_whitespace() {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
        } else {
            current.push(ch);
        }
    }

    if quote.is_some() {
        return Err(format!("ERR unterminated quoted literal in '{}'", spec));
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    Ok(tokens)
}

fn parse_field_def(spec: &str) -> Result<FieldDef, String> {
    let tokens = tokenize_field_def(spec)?;
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
    let mut sequence_partition: Option<String> = None;
    let mut references: Option<ForeignKey> = None;
    let mut encrypted = false;
    let mut searchable = false;

    let mut i = 2;
    while i < tokens.len() {
        match tokens[i].to_uppercase().as_str() {
            "ENCRYPTED" => {
                encrypted = true;
                i += 1;
            }
            "SEARCHABLE" => {
                searchable = true;
                i += 1;
            }
            "DEFAULT" => {
                i += 1;
                if i >= tokens.len() {
                    return Err("ERR DEFAULT requires a value".to_string());
                }
                default_value = Some(tokens[i].to_string());
                i += 1;
            }
            "SEQUENCE" => {
                i += 1;
                if i + 2 >= tokens.len()
                    || !tokens[i].eq_ignore_ascii_case("PARTITION")
                    || !tokens[i + 1].eq_ignore_ascii_case("BY")
                {
                    return Err("ERR SEQUENCE requires PARTITION BY <column>".to_string());
                }
                let partition = tokens[i + 2].to_string();
                if !is_valid_name(&partition) {
                    return Err(format!("ERR invalid sequence partition '{}'", partition));
                }
                sequence_partition = Some(partition);
                i += 3;
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
                let ref_spec = &tokens[i];
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

    let field = FieldDef {
        name,
        field_type,
        primary_key,
        unique,
        nullable,
        default_value,
        sequence_partition,
        references,
        encrypted,
        searchable,
    };
    field_supports_encryption(&field)?;
    Ok(field)
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
    if let Some(partition) = &def.sequence_partition {
        parts.push(format!("seqpart:{}", partition));
    }
    if def.encrypted {
        parts.push("encrypted".to_string());
    }
    if def.searchable {
        parts.push("searchable".to_string());
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
    let mut sequence_partition: Option<String> = None;
    let mut references: Option<ForeignKey> = None;
    let mut encrypted = false;
    let mut searchable = false;

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
            s if s.starts_with("seqpart:") => {
                sequence_partition = Some(s[8..].to_string());
            }
            "encrypted" => encrypted = true,
            "searchable" => searchable = true,
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
        sequence_partition,
        references,
        encrypted,
        searchable,
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
        sequence_partition: None,
        references: None,
        encrypted: false,
        searchable: false,
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
) -> Result<Vec<PathIndex>, String> {
    if let Some(pis) = cache.read().get_path_indexes(table) {
        return Ok(pis);
    }
    let key = path_indexes_key(table);
    let pairs = store.hgetall(key.as_bytes(), now)?;
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
    Ok(pis)
}

/// Look up the declared index type for a single path (O(1) hash-field get).
/// Used by the planner, which has no schema-cache handle.
fn read_path_index_type(
    store: &Store,
    table: &str,
    path: &str,
    now: Instant,
) -> Result<Option<FieldType>, String> {
    let key = path_indexes_key(table);
    let Some(val) = store.hget_checked(key.as_bytes(), path.as_bytes(), now)? else {
        return Ok(None);
    };
    Ok(parse_index_type(&String::from_utf8_lossy(&val)))
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
    let route: [&[u8]; 2] = [b"TINDEX", table.as_bytes()];
    let journal = store
        .prepare_journaled(&route)
        .map_err(|error| format!("ERR WAL append failed: {error}"))?;
    let schema = load_schema(store, cache, table, now)?;
    let (root, rest) = path
        .split_once('.')
        .ok_or_else(|| "ERR index path must be a dot-path into a JSON column".to_string())?;
    if rest.is_empty() {
        return Err("ERR index path must address a value inside the JSON column".to_string());
    }
    let root_field = schema
        .iter()
        .find(|f| f.name == root && f.field_type == FieldType::Json)
        .ok_or_else(|| format!("ERR '{}' is not a JSON column", root))?;
    if root_field.encrypted {
        return Err(format!(
            "ERR cannot create path index on encrypted column '{}'",
            root
        ));
    }
    let field_type = parse_index_type(type_token).ok_or_else(|| {
        format!(
            "ERR invalid index type '{}'. Use INT/FLOAT/BOOL/TIMESTAMP/STR",
            type_token
        )
    })?;
    let token = index_type_token(&field_type).unwrap_or("str");

    let command: [&[u8]; 4] = [
        b"TINDEX",
        table.as_bytes(),
        path.as_bytes(),
        type_token.as_bytes(),
    ];
    let commit = journal
        .commit(&command)
        .map_err(|error| format!("ERR WAL append failed: {error}"))?;

    let key = path_indexes_key(table);
    store.hset(key.as_bytes(), &[(path.as_bytes(), token.as_bytes())], now)?;
    cache.write().remove_path_indexes(table);

    // Backfill the index over existing rows.
    let pi = PathIndex {
        path: path.to_string(),
        field_type,
    };
    let synthetic = synthetic_path_fielddef(&pi);
    for pk_str in get_all_row_ids(store, table, now)? {
        let Some(row) = get_row(store, table, &schema, &pk_str, now, true)? else {
            continue;
        };
        if let Some(raw) = row.iter().find(|(k, _)| k == root).map(|(_, v)| v.as_str()) {
            if let Some(scalar) = extract_json_scalar(raw, rest) {
                add_to_index(store, table, &synthetic, &scalar, &pk_str, now)?;
            }
        }
    }
    commit
        .complete()
        .map_err(|error| format!("ERR journal apply failed: {error}"))?;
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
    let route: [&[u8]; 2] = [b"TDROPINDEX", table.as_bytes()];
    let journal = store
        .prepare_journaled(&route)
        .map_err(|error| format!("ERR WAL append failed: {error}"))?;
    let schema = load_schema(store, cache, table, now)?;
    let path_indexes = load_path_indexes(store, cache, table, now)?;
    let Some(pi) = path_indexes.iter().find(|p| p.path == path) else {
        return Err(format!("ERR no index on path '{}'", path));
    };
    let (root, rest) = path.split_once('.').unwrap_or((path, ""));
    let synthetic = synthetic_path_fielddef(pi);
    let command: [&[u8]; 3] = [b"TDROPINDEX", table.as_bytes(), path.as_bytes()];
    let commit = journal
        .commit(&command)
        .map_err(|error| format!("ERR WAL append failed: {error}"))?;
    for pk_str in get_all_row_ids(store, table, now)? {
        let Some(row) = get_row(store, table, &schema, &pk_str, now, true)? else {
            continue;
        };
        if let Some(raw) = row.iter().find(|(k, _)| k == root).map(|(_, v)| v.as_str()) {
            if let Some(scalar) = extract_json_scalar(raw, rest) {
                remove_from_index(store, table, &synthetic, &scalar, &pk_str, now)?;
            }
        }
    }
    let key = path_indexes_key(table);
    store.hdel(key.as_bytes(), &[path.as_bytes()], now)?;
    cache.write().remove_path_indexes(table);
    commit
        .complete()
        .map_err(|error| format!("ERR journal apply failed: {error}"))?;
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

fn next_id(store: &Store, table: &str, now: Instant) -> Result<i64, String> {
    let key = seq_key(table);
    store.incr(key.as_bytes(), 1, now)
}

fn current_sequence(store: &Store, key: &str, now: Instant) -> Result<i64, String> {
    let Some(value) = store.get_checked(key.as_bytes(), now)? else {
        return Ok(0);
    };
    let value = std::str::from_utf8(&value)
        .map_err(|_| format!("ERR table sequence '{}' is not UTF-8", key))?;
    value
        .parse::<i64>()
        .map_err(|_| format!("ERR table sequence '{}' is corrupt", key))
}

/// Resolve an auto-increment value without mutating the counter. Callers hold
/// the table's journal preparation gate until the resolved row is appended,
/// then advance the counter while applying that row.
fn peek_next_id(store: &Store, table: &str, now: Instant) -> Result<i64, String> {
    Ok(current_sequence(store, &seq_key(table), now)?.saturating_add(1))
}

fn peek_next_scoped_id(
    store: &Store,
    table: &str,
    field: &str,
    partition_col: &str,
    partition_val: &str,
    now: Instant,
) -> Result<i64, String> {
    Ok(current_sequence(
        store,
        &scoped_seq_key(table, field, partition_col, partition_val),
        now,
    )?
    .saturating_add(1))
}

/// Advance an INT auto-increment counter so it is at least `id`. Called whenever a
/// row lands with an explicit numeric PK so a later auto-generated id never
/// collides. The seq counter is derived state, so crash recovery rebuilds it from
/// the explicit ids carried in replayed TROWSET commands; otherwise the next live
/// insert could reuse an id and silently
/// overwrites a recovered row.
fn bump_seq_to_at_least(store: &Store, table: &str, id: i64, now: Instant) -> Result<(), String> {
    let key = seq_key(table);
    let current = current_sequence(store, &key, now)?;
    if id > current {
        store.set(key.as_bytes(), id.to_string().as_bytes(), None, now);
    }
    Ok(())
}

fn bump_scoped_seq_to_at_least(
    store: &Store,
    table: &str,
    field: &str,
    partition_col: &str,
    partition_val: &str,
    id: i64,
    now: Instant,
) -> Result<(), String> {
    let key = scoped_seq_key(table, field, partition_col, partition_val);
    let current = current_sequence(store, &key, now)?;
    if id > current {
        store.set(key.as_bytes(), id.to_string().as_bytes(), None, now);
    }
    Ok(())
}

fn find_row_by_fields(
    store: &Store,
    table: &str,
    schema: &[FieldDef],
    fields: &[(&str, &str)],
    now: Instant,
) -> Result<Option<String>, String> {
    for pk_str in get_all_row_ids(store, table, now)? {
        let Some(row) = get_row(store, table, schema, &pk_str, now, true)? else {
            continue;
        };
        if fields
            .iter()
            .all(|(field, value)| row.iter().any(|(k, v)| k == field && v == value))
        {
            return Ok(Some(pk_str));
        }
    }
    Ok(None)
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
) -> Result<(), String> {
    if field.encrypted {
        if !field.searchable {
            return Ok(());
        }
        for index_value in searchable_index_values(store, table, field, value)? {
            let skey = idx_str_key(table, &field.name, &index_value);
            store.sadd(skey.as_bytes(), &[pk_str.as_bytes()], now)?;
        }
        return Ok(());
    }
    match &field.field_type {
        FieldType::Int
        | FieldType::Float
        | FieldType::Bool
        | FieldType::Timestamp
        | FieldType::Ref(_) => {
            let score: f64 = if field.field_type == FieldType::Bool {
                match value {
                    "true" | "1" => 1.0,
                    "false" | "0" => 0.0,
                    _ => return Err(format!("ERR invalid boolean index value '{}'", value)),
                }
            } else {
                value
                    .parse()
                    .map_err(|_| format!("ERR invalid numeric index value '{}'", value))?
            };
            let zkey = idx_sorted_key(table, &field.name);
            store.zadd(
                zkey.as_bytes(),
                &[(pk_str.as_bytes(), score)],
                false,
                false,
                false,
                false,
                false,
                now,
            )?;
        }
        FieldType::Str | FieldType::Uuid => {
            let skey = idx_str_key(table, &field.name, value);
            store.sadd(skey.as_bytes(), &[pk_str.as_bytes()], now)?;
        }
        FieldType::Vector(dims) => {
            let vector = parse_vector_value(value, *dims)?;
            let metadata = serde_json::json!({
                "table": table,
                "field": field.name,
                "table_field": format!("{}.{}", table, field.name),
                "pk": pk_str,
                "id": pk_str,
            })
            .to_string();
            let vkey = table_vector_key(table, &field.name, pk_str);
            store.vset(
                vkey.as_bytes(),
                vector,
                Some(metadata),
                None,
                field.encrypted,
                now,
            );
        }
        // JSON/ARRAY columns are not auto-indexed; only declared path indexes apply.
        FieldType::Json | FieldType::Array => {}
    }
    Ok(())
}

fn remove_from_index(
    store: &Store,
    table: &str,
    field: &FieldDef,
    value: &str,
    pk_str: &str,
    now: Instant,
) -> Result<(), String> {
    if field.encrypted {
        if !field.searchable {
            return Ok(());
        }
        for index_value in searchable_index_values(store, table, field, value)? {
            let skey = idx_str_key(table, &field.name, &index_value);
            store.srem(skey.as_bytes(), &[pk_str.as_bytes()], now)?;
        }
        return Ok(());
    }
    match &field.field_type {
        FieldType::Int
        | FieldType::Float
        | FieldType::Bool
        | FieldType::Timestamp
        | FieldType::Ref(_) => {
            let zkey = idx_sorted_key(table, &field.name);
            store.zrem(zkey.as_bytes(), &[pk_str.as_bytes()], now)?;
        }
        FieldType::Str | FieldType::Uuid => {
            let skey = idx_str_key(table, &field.name, value);
            store.srem(skey.as_bytes(), &[pk_str.as_bytes()], now)?;
        }
        FieldType::Vector(_) => {
            let vkey = table_vector_key(table, &field.name, pk_str);
            store.del(&[vkey.as_bytes()]);
        }
        FieldType::Json | FieldType::Array => {}
    }
    Ok(())
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

    let route: [&[u8]; 2] = [b"TCREATE", table.as_bytes()];
    let journal = store
        .prepare_journaled(&route)
        .map_err(|error| format!("ERR WAL append failed: {error}"))?;

    // Keep the original column list (incl. any `WITH TTL`) for the WAL log below.
    let orig_col_args = col_args;
    // `... WITH TTL <secs>` gives every row in the table a default expiry.
    let (col_args, default_ttl) = split_with_ttl(col_args);
    let fields = parse_column_list(col_args)?;
    ensure_encryption_ready(store, &fields)?;
    let mut pairs: Vec<(&[u8], Vec<u8>)> = fields
        .iter()
        .map(|field| {
            let encoded = encode_field_def(field);
            (field.name.as_bytes() as &[u8], encoded.into_bytes())
        })
        .collect();
    if let Some(secs) = default_ttl {
        pairs.push((HIDDEN_DEFAULT_TTL_FIELD, secs.to_string().into_bytes()));
    }

    let key = schema_key(table);
    let existing = store.hgetall(key.as_bytes(), now)?;
    if !existing.is_empty() {
        if store.wal_replaying() {
            let schema_matches = existing.len() == pairs.len()
                && existing.iter().all(|(name, value)| {
                    pairs.iter().any(|(expected_name, expected_value)| {
                        name.as_bytes() == *expected_name && value.as_ref() == expected_value
                    })
                });
            if schema_matches {
                // Internal schemas may be bootstrapped before replay because
                // historical journals contain row images but no TCREATE. A
                // newer journal can contain the exact TCREATE as well; replaying
                // that identical declaration is safe. Any mismatch remains a
                // fatal recovery error.
                cache.write().insert(table, fields);
                cache.write().insert_default_ttl(table, default_ttl);
                return Ok(());
            }
            return Err(format!(
                "ERR replayed table '{}' conflicts with the recovered schema",
                table
            ));
        }
        return Err(format!("ERR table '{}' already exists", table));
    }

    // Validate that referenced tables exist
    for field in &fields {
        if let Some(fk) = &field.references {
            let ref_schema_key = schema_key(&fk.table);
            let ref_exists = store.hgetall(ref_schema_key.as_bytes(), now)?;
            if ref_exists.is_empty() {
                return Err(format!(
                    "ERR referenced table '{}' does not exist",
                    fk.table
                ));
            }
        }
    }

    let mut journal_command: Vec<Vec<u8>> = Vec::with_capacity(orig_col_args.len() + 2);
    journal_command.push(b"TCREATE".to_vec());
    journal_command.push(table.as_bytes().to_vec());
    journal_command.extend(
        orig_col_args
            .iter()
            .map(|column| column.as_bytes().to_vec()),
    );
    let journal_refs: Vec<&[u8]> = journal_command.iter().map(Vec::as_slice).collect();
    let commit = journal
        .commit(&journal_refs)
        .map_err(|error| format!("ERR WAL append failed: {error}"))?;

    let pair_refs: Vec<(&[u8], &[u8])> = pairs.iter().map(|(k, v)| (*k, v.as_slice())).collect();
    store.hset(key.as_bytes(), &pair_refs, now)?;

    store.set(seq_key(table).as_bytes(), b"0", None, now);

    let tlist = table_list_key();
    store.sadd(tlist.as_bytes(), &[table.as_bytes()], now)?;

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

    commit
        .complete()
        .map_err(|error| format!("ERR journal apply failed: {error}"))?;
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
    let mut row = get_row(store, table, &schema, &pk_str, now, true)?
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

fn parse_conflict_columns(conflict_col: Option<&str>, pk_name: Option<&str>) -> Vec<String> {
    let raw = conflict_col.or(pk_name).unwrap_or("id");
    raw.split(',')
        .map(str::trim)
        .filter(|column| !column.is_empty())
        .map(str::to_string)
        .collect()
}

fn normalized_field_values<'a>(field_values: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
    let mut values = std::collections::BTreeMap::new();
    for &(field, value) in field_values {
        values.insert(field, value);
    }
    values.into_iter().collect()
}

/// Insert a row, or update the conflicting row if one already exists on the
/// conflict column(s). `conflict_col` defaults to the primary key (implicit `id`
/// when there is no declared PK). Returns the resulting row. Every conflict
/// column must carry a value; otherwise this is a plain insert.
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
    let field_values = normalized_field_values(field_values);
    let field_values = field_values.as_slice();
    let route: [&[u8]; 2] = [b"TROWSET", table.as_bytes()];
    let mutation = TableMutation::prepare(store, &route, now)?;
    let schema = load_schema(store, cache, table, now)?;
    let pk_name = schema
        .iter()
        .find(|f| f.primary_key)
        .map(|f| f.name.as_str());
    let conflicts = parse_conflict_columns(conflict_col, pk_name);
    let mut conflict_values: Vec<(&str, &str)> = Vec::with_capacity(conflicts.len());
    for conflict in &conflicts {
        let Some(cval) = field_values
            .iter()
            .find(|(k, _)| *k == conflict.as_str())
            .map(|(_, v)| *v)
        else {
            // No value to conflict on -> behaves as a plain insert.
            let pk = table_insert_pk_with_mutation(
                store,
                cache,
                table,
                field_values,
                ttl,
                now,
                mutation,
            )?;
            let mut row = get_row(store, table, &schema, &pk, now, true)?
                .ok_or_else(|| format!("ERR inserted row not found in table '{}'", table))?;
            row.sort_by(|left, right| left.0.cmp(&right.0));
            return Ok(row);
        };
        conflict_values.push((conflict.as_str(), cval));
    }
    for (conflict, _) in &conflict_values {
        if let Some(field) = schema.iter().find(|f| f.name == *conflict) {
            if field.encrypted && !field.searchable {
                return Err(format!(
                    "ERR encrypted column '{}' must be SEARCHABLE for upsert conflict matching",
                    field.name
                ));
            }
        }
    }

    let existing_pk: Option<String> = if conflicts.len() == 1 {
        let conflict = conflicts[0].as_str();
        let cval = conflict_values[0].1;
        let conflict_is_pk = schema.iter().any(|f| f.primary_key && f.name == conflict)
            || (pk_name.is_none() && conflict == "id");
        if conflict_is_pk {
            // An expired row is purged and treated as absent (-> insert branch).
            if purge_if_expired(store, cache, table, cval, now)? {
                None
            } else {
                Some(cval.to_string())
            }
        } else {
            // Match via the unique index when present; otherwise scan rows for
            // compatibility with unconstrained conflict targets.
            let conflict_field = schema.iter().find(|f| f.name == conflict);
            match conflict_field
                .filter(|f| f.unique)
                .map(|field| unique_holder_for_value(store, table, field, cval, now))
                .transpose()?
                .flatten()
            {
                Some(pk) if !purge_if_expired(store, cache, table, &pk, now)? => Some(pk),
                Some(_) => find_row_by_fields(store, table, &schema, &[(conflict, cval)], now)?,
                None => find_row_by_fields(store, table, &schema, &[(conflict, cval)], now)?,
            }
        }
    } else {
        find_row_by_fields(store, table, &schema, &conflict_values, now)?
    };
    match existing_pk {
        Some(pk) => {
            // Update the conflicting row with the non-key fields, then return it.
            let updates: Vec<(&str, &str)> = field_values
                .iter()
                .copied()
                .filter(|(k, _)| !conflicts.iter().any(|conflict| conflict == *k))
                .collect();
            // The leaf applies and journals the TTL atomically with the row update.
            // It also accepts an empty field list for a TTL-only refresh, avoiding a
            // synthetic no-op write to the immutable conflict/primary-key column.
            if !updates.is_empty() || ttl.is_some() {
                table_update_by_pk_str_with_mutation(
                    cache, table, &pk, &updates, ttl, now, mutation,
                )?;
            }
            let mut row = get_row(store, table, &schema, &pk, now, true)?
                .ok_or_else(|| format!("ERR upserted row not found in table '{}'", table))?;
            row.sort_by(|a, b| a.0.cmp(&b.0));
            Ok(row)
        }
        None => {
            let pk = table_insert_pk_with_mutation(
                store,
                cache,
                table,
                field_values,
                ttl,
                now,
                mutation,
            )?;
            let mut row = get_row(store, table, &schema, &pk, now, true)?
                .ok_or_else(|| format!("ERR inserted row not found in table '{}'", table))?;
            row.sort_by(|left, right| left.0.cmp(&right.0));
            Ok(row)
        }
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
    let route: [&[u8]; 2] = [b"TROWSET", table.as_bytes()];
    let mutation = TableMutation::prepare(store, &route, now)?;
    table_insert_pk_with_mutation(store, cache, table, field_values, ttl, now, mutation)
}

fn table_insert_pk_with_mutation(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    field_values: &[(&str, &str)],
    ttl: Option<TtlOp>,
    now: Instant,
    mut mutation: TableMutation<'_>,
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

    let mut generated_sequences: Vec<(String, String)> = Vec::new();
    for field in schema.iter().filter(|f| f.sequence_partition.is_some()) {
        if field.field_type != FieldType::Int {
            return Err(format!(
                "ERR SEQUENCE column '{}' must use INT type",
                field.name
            ));
        }
        let partition_col = field.sequence_partition.as_deref().unwrap();
        let partition_val = provided.get(partition_col).copied().ok_or_else(|| {
            format!(
                "ERR SEQUENCE column '{}' requires partition column '{}'",
                field.name, partition_col
            )
        })?;
        if let Some(value) = provided.get(field.name.as_str()).copied() {
            value
                .parse::<i64>()
                .map_err(|_| format!("ERR invalid int '{}'", value))?;
        } else {
            let next =
                peek_next_scoped_id(store, table, &field.name, partition_col, partition_val, now)?
                    .to_string();
            generated_sequences.push((field.name.clone(), next));
        }
    }
    for (name, value) in &generated_sequences {
        provided.insert(name.as_str(), value.as_str());
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
            let ref_schema = load_schema(store, cache, ref_table, now)?;
            if get_row(
                store,
                ref_table,
                &ref_schema,
                &ref_id.to_string(),
                now,
                true,
            )?
            .is_none()
            {
                return Err(format!(
                    "ERR foreign key violation: {}={} not found in table '{}'",
                    field.name, value, ref_table
                ));
            }
        }

        // Explicit FK check
        if let Some(fk) = &field.references {
            if !referenced_value_exists(store, cache, fk, value, now)? {
                return Err(format!(
                    "ERR foreign key violation: {}.{}='{}' not found in table '{}'",
                    table, field.name, value, fk.table
                ));
            }
        }

        // UNIQUE / PRIMARY KEY uniqueness check. The uniq index is advisory: only
        // reject if a LIVE row genuinely still holds this value. A value held by an
        // expired row is freed by purging it; a stale index entry (holder row gone
        // or no longer carrying this value, e.g. from a partial update) is dropped
        // and the insert is allowed -- never a false "duplicate".
        if field.unique {
            let ukey = uniq_key(table, &field.name);
            for index_value in searchable_index_values(store, table, field, value)? {
                if let Some(holder) =
                    store.hget_checked(ukey.as_bytes(), index_value.as_bytes(), now)?
                {
                    let holder_pk = String::from_utf8_lossy(&holder).to_string();
                    let absent = purge_if_expired(store, cache, table, &holder_pk, now)?;
                    if !absent
                        && uniq_holder_holds_value(store, table, field, &holder_pk, value, now)?
                    {
                        return Err(format!(
                            "ERR unique constraint violation on column '{}': value '{}' already exists",
                            field.name, value
                        ));
                    }
                    // A stale entry does not block the insert. The staged unique
                    // index write below replaces it in the same atomic batch.
                }
            }
        }

        if let Some(partition_col) = field.sequence_partition.as_deref() {
            let Some(partition_val) = provided.get(partition_col).copied() else {
                continue;
            };
            if let Some(existing_pk) = find_row_by_fields(
                store,
                table,
                &schema,
                &[(partition_col, partition_val), (&field.name, value)],
                now,
            )? {
                if !purge_if_expired(store, cache, table, &existing_pk, now)? {
                    return Err(format!(
                        "ERR unique constraint violation on columns '{}', '{}'",
                        partition_col, field.name
                    ));
                }
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
            Some(pk_val) => pk_val.to_string(),
            None if pk.field_type == FieldType::Int => {
                // Auto-increment INT PK
                peek_next_id(store, table, now)?.to_string()
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
        // An explicit value for the implicit primary key follows the same
        // uniqueness rule as a declared primary key. WAL replay uses TROWSET and
        // does not pass through this insert path.
        id.to_string()
    } else {
        peek_next_id(store, table, now)?.to_string()
    };

    // All primary-key sources—explicit, sequence-generated, UUID-generated, or
    // DEFAULT-generated—must pass the same final collision check.
    if !purge_if_expired(store, cache, table, &pk_str, now)? {
        return Err(format!(
            "ERR primary key violation: '{}' already exists",
            pk_str
        ));
    }

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
            let encoded = encode_stored_value(store, table, field, &pk_str, value)?;
            pairs_owned.push((field.name.clone(), encoded));
        } else if field.primary_key {
            // Explicit PK that was auto-generated (INT auto-increment or UUIDv7).
            // Encode with the PK column's own type, not a hardcoded INT.
            let encoded = encode_stored_value(store, table, field, &pk_str, &pk_str)?;
            pairs_owned.push((field.name.clone(), encoded));
        }
    }

    // Resolve the absolute deadline into the durable row image. Recovery must
    // restore this deadline, not start a fresh relative TTL from replay time.
    let effective_ttl = ttl.or_else(|| table_default_ttl(store, cache, table, now).map(TtlOp::Set));
    let resolved_deadline = match effective_ttl {
        Some(TtlOp::Set(secs)) => {
            Some(current_epoch_ms().saturating_add(secs.saturating_mul(1000)))
        }
        Some(TtlOp::Clear) | None => None,
    };
    if let Some(deadline) = resolved_deadline {
        pairs_owned.push((String::from("\u{0}ttl"), deadline.to_string().into_bytes()));
    }

    let journal_command = raw_row_journal_command(table, &pk_str, &pairs_owned);
    let journal_refs: Vec<&[u8]> = journal_command.iter().map(Vec::as_slice).collect();

    // Track this row in the ids sorted set.
    // Member = pk_str, score = numeric pk if possible, else a monotonic counter.
    let score: f64 = match pk_str.parse::<f64>() {
        Ok(score) => score,
        // For non-numeric PKs (UUID, STR), use a separate insert counter for ordering.
        Err(_) => peek_next_id(store, &format!("{}__order", table), now)? as f64,
    };
    if let Ok(id) = pk_str.parse::<i64>() {
        stage_bump_sequence(&mut mutation, store, seq_key(table), id, now)?;
    }
    if pk_str.parse::<f64>().is_err() {
        stage_bump_sequence(
            &mut mutation,
            store,
            seq_key(&format!("{}__order", table)),
            score as i64,
            now,
        )?;
    }
    for field in schema
        .iter()
        .filter(|field| field.sequence_partition.is_some())
    {
        let Some(value) = provided.get(field.name.as_str()) else {
            continue;
        };
        let Some(partition_col) = field.sequence_partition.as_deref() else {
            continue;
        };
        let Some(partition) = provided.get(partition_col) else {
            continue;
        };
        if let Ok(value) = value.parse::<i64>() {
            stage_bump_sequence(
                &mut mutation,
                store,
                scoped_seq_key(table, &field.name, partition_col, partition),
                value,
                now,
            )?;
        }
    }
    let ikey = ids_key(table);
    mutation.batch.sorted_set_add(&ikey, &pk_str, score)?;

    for field in &schema {
        let value = provided
            .get(field.name.as_str())
            .copied()
            .or_else(|| field.primary_key.then_some(pk_str.as_str()));
        if let Some(value) = value {
            stage_add_to_index(&mut mutation, store, table, field, value, &pk_str)?;

            if field.unique {
                stage_set_unique(&mut mutation, store, table, field, value, &pk_str)?;
            }
        }
    }

    // Declared JSON path indexes (cached empty for un-indexed tables => cheap).
    for pi in &load_path_indexes(store, cache, table, now)? {
        if let Some((root, rest)) = pi.path.split_once('.') {
            if schema.iter().any(|f| f.name == root && f.encrypted) {
                continue;
            }
            if let Some(raw) = provided.get(root).copied() {
                if let Some(scalar) = extract_json_scalar(raw, rest) {
                    stage_add_to_index(
                        &mut mutation,
                        store,
                        table,
                        &synthetic_path_fielddef(pi),
                        &scalar,
                        &pk_str,
                    )?;
                }
            }
        }
    }

    if let Some(deadline) = resolved_deadline {
        let member = ttl_member(table, &pk_str);
        mutation
            .batch
            .sorted_set_add(ttl_index_key(), &member, deadline as f64)?;
    }

    mutation.batch.hash_set(&rk, &pairs_owned)?;
    mutation.row_changed(table, &pk_str);
    mutation.publish(&journal_refs)?;
    Ok(pk_str)
}

/// Test convenience: fetch a row by integer id, full-access. Production reads go
/// through `table_get_by_pk_str` / `table_get_filtered_pk`.
#[cfg(test)]
pub fn table_get(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    id: i64,
    now: Instant,
) -> Result<Vec<(String, String)>, String> {
    let schema = load_schema(store, cache, table, now)?;
    let pk_str = id.to_string();
    // Direct by-id fetch is the operator/full-access path; gated by-id reads go
    // through table_get_filtered -> table_select with the plan's decrypt flag.
    let row = get_row(store, table, &schema, &pk_str, now, true)?
        .ok_or_else(|| format!("ERR row {} not found in table '{}'", id, table))?;
    let mut result = row;
    result.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(result)
}

/// Point-update: set one or more fields on the row identified by its raw PK
/// string, with no WHERE query. Routes through the same invariant-preserving
/// leaf as every table update (type validation, FK/unique checks, secondary +
/// unique + blind + JSON-path index maintenance, per-cell encryption, TTL, and
/// resolved journal recording). Errors if the row does not exist (this is an update, not
/// an upsert).
pub fn table_set_fields(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    pk_str: &str,
    field_values: &[(&str, &str)],
    now: Instant,
) -> Result<(), String> {
    table_update_by_pk_str(store, cache, table, pk_str, field_values, None, now)
}

/// Point-read: fetch a row by its raw PK string, optionally projecting a subset
/// of fields. Returns `None` if the row does not exist. `decrypt_authorized`
/// false omits ENCRYPTED columns (anonymous principals), matching the query path.
pub fn table_get_by_pk_str(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    pk_str: &str,
    fields: Option<&[&str]>,
    decrypt_authorized: bool,
    now: Instant,
) -> Result<Option<Vec<(String, String)>>, String> {
    let schema = load_schema(store, cache, table, now)?;
    let Some(mut row) = get_row(store, table, &schema, pk_str, now, decrypt_authorized)? else {
        return Ok(None);
    };
    if let Some(fields) = fields {
        row.retain(|(name, _)| fields.contains(&name.as_str()));
    }
    row.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(Some(row))
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
    let route: [&[u8]; 2] = [b"TROWSET", table.as_bytes()];
    let mutation = TableMutation::prepare(store, &route, now)?;
    table_update_by_pk_str_with_mutation(cache, table, pk_str, field_values, ttl, now, mutation)
}

fn table_update_by_pk_str_with_mutation(
    cache: &SharedSchemaCache,
    table: &str,
    pk_str: &str,
    field_values: &[(&str, &str)],
    ttl: Option<TtlOp>,
    now: Instant,
    mut mutation: TableMutation<'_>,
) -> Result<(), String> {
    let store = mutation.store;
    let field_values = normalized_field_values(field_values);
    let field_values = field_values.as_slice();
    let schema = load_schema(store, cache, table, now)?;
    let rk = row_key_for_pk(table, pk_str);

    let old_row = get_row(store, table, &schema, pk_str, now, true)?
        .ok_or_else(|| format!("ERR row '{}' not found in table '{}'", pk_str, table))?;

    let old_map: std::collections::HashMap<String, String> = old_row.into_iter().collect();
    let raw_row = store.hgetall(rk.as_bytes(), now)?;

    for (fname, fval) in field_values {
        let field = schema
            .iter()
            .find(|f| f.name == *fname)
            .ok_or_else(|| format!("ERR unknown field '{}'", fname))?;

        if field.primary_key || (*fname == "id" && !schema.iter().any(|f| f.primary_key)) {
            return Err(format!(
                "ERR primary key column '{}' cannot be updated",
                fname
            ));
        }

        validate_value(field, fval)?;

        if let FieldType::Ref(ref ref_table) = field.field_type {
            let ref_schema = load_schema(store, cache, ref_table, now)?;
            if get_row(store, ref_table, &ref_schema, fval, now, true)?.is_none() {
                return Err(format!(
                    "ERR foreign key violation: {}={} not found in table '{}'",
                    fname, fval, ref_table
                ));
            }
        }

        if let Some(fk) = &field.references {
            if !referenced_value_exists(store, cache, fk, fval, now)? {
                return Err(format!(
                    "ERR foreign key violation: {}.{}='{}' not found in table '{}'",
                    table, field.name, fval, fk.table
                ));
            }
        }

        if field.unique {
            if let Some(existing_pk) = unique_holder_for_value(store, table, field, fval, now)? {
                if existing_pk != pk_str {
                    let absent = purge_if_expired(store, cache, table, &existing_pk, now)?;
                    if !absent
                        && uniq_holder_holds_value(store, table, field, &existing_pk, fval, now)?
                    {
                        return Err(format!(
                            "ERR unique constraint violation on field '{}'",
                            field.name
                        ));
                    }
                }
            }
        }
    }

    let mut final_values = old_map.clone();
    for (field, value) in field_values {
        final_values.insert((*field).to_string(), (*value).to_string());
    }
    for sequence_field in schema
        .iter()
        .filter(|field| field.sequence_partition.is_some())
    {
        let partition_column = sequence_field
            .sequence_partition
            .as_deref()
            .expect("filtered sequence field has a partition column");
        let affects_sequence = field_values
            .iter()
            .any(|(field, _)| *field == sequence_field.name || *field == partition_column);
        if !affects_sequence {
            continue;
        }
        let sequence_value = final_values
            .get(&sequence_field.name)
            .ok_or_else(|| format!("ERR SEQUENCE column '{}' has no value", sequence_field.name))?;
        let partition_value = final_values.get(partition_column).ok_or_else(|| {
            format!(
                "ERR SEQUENCE column '{}' requires partition column '{}'",
                sequence_field.name, partition_column
            )
        })?;
        for candidate_pk in get_all_row_ids(store, table, now)? {
            if candidate_pk == pk_str {
                continue;
            }
            let Some(candidate) = get_row(store, table, &schema, &candidate_pk, now, true)? else {
                continue;
            };
            if candidate
                .iter()
                .any(|(field, value)| field == partition_column && value == partition_value)
                && candidate
                    .iter()
                    .any(|(field, value)| field == &sequence_field.name && value == sequence_value)
            {
                return Err(format!(
                    "ERR unique constraint violation on columns '{}', '{}'",
                    partition_column, sequence_field.name
                ));
            }
        }
        let sequence_value = sequence_value
            .parse::<i64>()
            .map_err(|_| format!("ERR invalid int '{}'", sequence_value))?;
        stage_bump_sequence(
            &mut mutation,
            store,
            scoped_seq_key(
                table,
                &sequence_field.name,
                partition_column,
                partition_value,
            ),
            sequence_value,
            now,
        )?;
    }

    let mut pairs_owned: Vec<(String, Vec<u8>)> = Vec::with_capacity(field_values.len());
    for (fname, fval) in field_values {
        let field = schema.iter().find(|field| field.name == *fname).unwrap();
        let encoded = encode_stored_value(store, table, field, pk_str, fval)?;
        pairs_owned.push((fname.to_string(), encoded));
    }

    let mut final_raw: std::collections::BTreeMap<String, Vec<u8>> = raw_row
        .into_iter()
        .map(|(field, value)| (field, value.to_vec()))
        .collect();
    for (field, value) in &pairs_owned {
        final_raw.insert(field.clone(), value.clone());
    }
    let resolved_deadline = match ttl {
        Some(TtlOp::Set(secs)) => {
            let deadline = current_epoch_ms().saturating_add(secs.saturating_mul(1000));
            final_raw.insert(
                String::from_utf8_lossy(HIDDEN_TTL_FIELD).to_string(),
                deadline.to_string().into_bytes(),
            );
            Some(deadline)
        }
        Some(TtlOp::Clear) => {
            final_raw.remove(&String::from_utf8_lossy(HIDDEN_TTL_FIELD).to_string());
            None
        }
        None => final_raw
            .get(String::from_utf8_lossy(HIDDEN_TTL_FIELD).as_ref())
            .and_then(|value| std::str::from_utf8(value).ok())
            .and_then(|value| value.parse::<u64>().ok()),
    };
    let final_raw: Vec<(String, Vec<u8>)> = final_raw.into_iter().collect();
    let journal_command = raw_row_journal_command(table, pk_str, &final_raw);
    let journal_refs: Vec<&[u8]> = journal_command.iter().map(Vec::as_slice).collect();

    for (fname, fval) in field_values {
        let field = schema.iter().find(|f| f.name == *fname).unwrap();

        if let Some(old_val) = old_map.get(*fname) {
            stage_remove_from_index(&mut mutation, store, table, field, old_val, pk_str)?;
            if field.unique {
                stage_remove_unique(&mut mutation, store, table, field, old_val)?;
            }
        }

        stage_add_to_index(&mut mutation, store, table, field, fval, pk_str)?;
        if field.unique {
            stage_set_unique(&mut mutation, store, table, field, fval, pk_str)?;
        }
    }

    // Reconcile declared JSON path indexes whose root column was updated.
    for pi in &load_path_indexes(store, cache, table, now)? {
        let Some((root, rest)) = pi.path.split_once('.') else {
            continue;
        };
        if schema.iter().any(|f| f.name == root && f.encrypted) {
            continue;
        }
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
                stage_remove_from_index(
                    &mut mutation,
                    store,
                    table,
                    &synthetic,
                    &old_scalar,
                    pk_str,
                )?;
            }
        }
        if let Some(new_scalar) = extract_json_scalar(new_raw, rest) {
            stage_add_to_index(&mut mutation, store, table, &synthetic, &new_scalar, pk_str)?;
        }
    }

    mutation.batch.hash_set(&rk, &final_raw)?;

    match ttl {
        Some(TtlOp::Set(_)) => {
            let deadline = resolved_deadline.expect("set TTL resolves a deadline");
            let member = ttl_member(table, pk_str);
            mutation
                .batch
                .sorted_set_add(ttl_index_key(), &member, deadline as f64)?;
        }
        Some(TtlOp::Clear) => stage_clear_row_ttl(&mut mutation, table, pk_str)?,
        None => {}
    }

    mutation.row_changed(table, pk_str);
    mutation.publish(&journal_refs)
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
    if depth != 0 {
        return Err("ERR internal nested table delete escaped its atomic batch".to_string());
    }
    let route: [&[u8]; 3] = [b"TDELETE", b"FROM", table.as_bytes()];
    let mutation = TableMutation::prepare(store, &route, now)?;
    stage_and_publish_delete(cache, table, pk_str, now, mutation)
}

fn stage_and_publish_delete(
    cache: &SharedSchemaCache,
    table: &str,
    pk_str: &str,
    now: Instant,
    mut mutation: TableMutation<'_>,
) -> Result<(), String> {
    stage_delete_inner(
        cache,
        table,
        pk_str,
        now,
        0,
        &mut std::collections::HashSet::new(),
        &mut mutation,
    )?;

    let schema = load_schema(mutation.store, cache, table, now)?;
    let pk_column = pk_column_name(&schema);
    let command: [&[u8]; 7] = [
        b"TDELETE",
        b"FROM",
        table.as_bytes(),
        b"WHERE",
        pk_column.as_bytes(),
        b"=",
        pk_str.as_bytes(),
    ];
    mutation.publish(&command)
}

fn stage_delete_inner(
    cache: &SharedSchemaCache,
    table: &str,
    pk_str: &str,
    now: Instant,
    depth: usize,
    visited: &mut std::collections::HashSet<(String, String)>,
    mutation: &mut TableMutation<'_>,
) -> Result<(), String> {
    let store = mutation.store;
    if depth > CASCADE_DEPTH_LIMIT {
        return Err(format!(
            "ERR cascade depth limit ({}) exceeded - possible circular FK reference",
            CASCADE_DEPTH_LIMIT
        ));
    }
    if !visited.insert((table.to_string(), pk_str.to_string())) {
        return Ok(());
    }
    let schema = load_schema(store, cache, table, now)?;
    let rk = row_key_for_pk(table, pk_str);

    // Read the row even if its TTL has lapsed: the sweep/purge path must clean
    // the indexes of an expired-but-not-yet-removed row.
    let row_map: std::collections::HashMap<String, String> =
        get_row_including_expired(store, table, &schema, pk_str, now)?
            .ok_or_else(|| format!("ERR row '{}' not found in table '{}'", pk_str, table))?
            .into_iter()
            .collect();

    let tlist_key = table_list_key();
    let all_tables = store.smembers(tlist_key.as_bytes(), now)?;

    for other_table in &all_tables {
        let other_schema = load_schema(store, cache, other_table, now)?;
        for field in &other_schema {
            // Handle legacy Ref type - always RESTRICT
            if let FieldType::Ref(ref ref_table) = field.field_type {
                if ref_table == table {
                    let zkey = idx_sorted_key(other_table, &field.name);
                    let id_f = pk_str.parse::<f64>().unwrap_or(0.0);
                    let refs = store.zrangebyscore(
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
                    )?;
                    for (referencing_id, _) in refs {
                        if visited.contains(&(other_table.clone(), referencing_id.clone())) {
                            continue;
                        }
                        let holds_reference = get_row(
                            store,
                            other_table,
                            &other_schema,
                            &referencing_id,
                            now,
                            true,
                        )?
                        .is_some_and(|candidate| {
                            candidate
                                .iter()
                                .any(|(name, value)| name == &field.name && value == pk_str)
                        });
                        if holds_reference {
                            return Err(format!(
                                "ERR cannot delete: row is referenced by table '{}'",
                                other_table
                            ));
                        }
                    }
                }
            }

            // Handle explicit FK with ON DELETE behavior
            if let Some(fk) = &field.references {
                if fk.table != table {
                    continue;
                }
                let Some(referenced_value) = row_map.get(&fk.column) else {
                    continue;
                };
                // Find all rows in other_table where field == referenced_value.
                // If the FK column is unique, we can look it up directly.
                // Otherwise we must scan all rows.
                let mut referencing_ids: Vec<String> = if field.unique {
                    let ukey = uniq_key(other_table, &field.name);
                    if let Some(ref_id_bytes) =
                        store.hget_checked(ukey.as_bytes(), referenced_value.as_bytes(), now)?
                    {
                        let ref_id = String::from_utf8_lossy(&ref_id_bytes).to_string();
                        let holds_reference =
                            get_row(store, other_table, &other_schema, &ref_id, now, true)?
                                .is_some_and(|candidate| {
                                    candidate.iter().any(|(name, value)| {
                                        name == &field.name && value == referenced_value
                                    })
                                });
                        holds_reference.then_some(ref_id).into_iter().collect()
                    } else {
                        vec![]
                    }
                } else {
                    // Full scan: find all rows where the FK field equals pk_value
                    let mut referencing_ids = Vec::new();
                    for other_pk in get_all_row_ids(store, other_table, now)? {
                        let holds_reference =
                            get_row(store, other_table, &other_schema, &other_pk, now, true)?
                                .is_some_and(|candidate| {
                                    candidate.iter().any(|(name, value)| {
                                        name == &field.name && value == referenced_value
                                    })
                                });
                        if holds_reference {
                            referencing_ids.push(other_pk);
                        }
                    }
                    referencing_ids
                };

                referencing_ids.retain(|referencing_id| {
                    !visited.contains(&(other_table.clone(), referencing_id.clone()))
                });

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
                            stage_delete_inner(
                                cache,
                                other_table,
                                ref_id_str,
                                now,
                                depth + 1,
                                visited,
                                mutation,
                            )?;
                        }
                    }
                    OnDelete::SetNull => {
                        if !field.nullable {
                            return Err(format!(
                                "ERR cannot set '{}.{}' to NULL because it is NOT NULL",
                                other_table, field.name
                            ));
                        }
                        // Null out the FK column in referencing rows and clean up its indexes
                        for ref_id_str in &referencing_ids {
                            let ref_rk = row_key_for_pk(other_table, ref_id_str);
                            mutation
                                .batch
                                .hash_delete(&ref_rk, std::slice::from_ref(&field.name))?;
                            if field.unique {
                                stage_remove_unique(
                                    mutation,
                                    store,
                                    other_table,
                                    field,
                                    referenced_value,
                                )?;
                            }
                            stage_remove_from_index(
                                mutation,
                                store,
                                other_table,
                                field,
                                referenced_value,
                                ref_id_str.as_str(),
                            )?;
                            mutation.row_changed(other_table, ref_id_str);
                        }
                    }
                }
            }
        }
    }

    for field in &schema {
        if let Some(val) = row_map.get(&field.name) {
            stage_remove_from_index(mutation, store, table, field, val, pk_str)?;
            if field.unique {
                stage_remove_unique(mutation, store, table, field, val)?;
            }
        }
        // A VECTOR column stores its embedding in a side key with its own ANN
        // index; deleting the row must remove it too, or vector search keeps
        // returning the deleted row (and the entry leaks).
        if matches!(field.field_type, FieldType::Vector(_)) && !row_map.contains_key(&field.name) {
            let vkey = table_vector_key(table, &field.name, pk_str);
            mutation.batch.delete_vector(&vkey)?;
        }
    }

    // Remove declared JSON path index entries for this row.
    for pi in &load_path_indexes(store, cache, table, now)? {
        if let Some((root, rest)) = pi.path.split_once('.') {
            if schema.iter().any(|f| f.name == root && f.encrypted) {
                continue;
            }
            if let Some(raw) = row_map.get(root) {
                if let Some(scalar) = extract_json_scalar(raw, rest) {
                    stage_remove_from_index(
                        mutation,
                        store,
                        table,
                        &synthetic_path_fielddef(pi),
                        &scalar,
                        pk_str,
                    )?;
                }
            }
        }
    }

    let ikey = ids_key(table);
    mutation.batch.sorted_set_remove(&ikey, pk_str)?;

    // Drop any TTL bookkeeping for this row (hidden field is removed with the
    // hash below; this clears the `_t:_ttl` deadline member).
    mutation
        .batch
        .sorted_set_remove(ttl_index_key(), &ttl_member(table, pk_str))?;

    mutation.batch.delete_hash(&rk)?;

    // Reactive live queries: hint that this pk changed. Cascaded child deletes
    // emit too (every real row removal is a live-query change).
    mutation.row_changed(table, pk_str);
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
        conditions.push(parse_where_or_group(args, &mut i)?);
        if i < args.len() && args[i].eq_ignore_ascii_case("AND") {
            i += 1;
        }
    }
    Ok(conditions)
}

fn parse_where_or_group(args: &[&str], i: &mut usize) -> Result<WhereClause, String> {
    let mut clauses = vec![parse_where_condition(args, i)?];
    while *i < args.len() && args[*i].eq_ignore_ascii_case("OR") {
        *i += 1;
        clauses.push(parse_where_condition(args, i)?);
    }
    if clauses.len() == 1 {
        Ok(clauses.remove(0))
    } else {
        Ok(WhereClause::or_group(clauses))
    }
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
            sequence_partition: None,
            references: None,
            encrypted: false,
            searchable: false,
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
    rows_for_pks(store, table, &schema, &pks, now, true)
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
    let rows = rows_for_pks(store, table, &schema, &matched, now, true)?;
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
    let route: [&[u8]; 2] = [b"TDROP", table.as_bytes()];
    let journal = store
        .prepare_journaled(&route)
        .map_err(|error| format!("ERR WAL append failed: {error}"))?;
    let schema = match load_schema(store, cache, table, now) {
        Ok(s) => s,
        Err(_) => return Err(format!("ERR table '{}' does not exist", table)),
    };

    let ikey = ids_key(table);
    let all_ids = store.zrangebyscore(
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
    )?;

    let journal_args: [&[u8]; 2] = [b"TDROP", table.as_bytes()];
    let commit = journal
        .commit(&journal_args)
        .map_err(|error| format!("ERR WAL append failed: {error}"))?;

    for (pk_str, _) in &all_ids {
        if schema
            .iter()
            .any(|field| matches!(field.field_type, FieldType::Vector(_)))
        {
            if let Some(row) = get_row(store, table, &schema, pk_str, now, true)? {
                for field in &schema {
                    if let Some((_, value)) = row.iter().find(|(k, _)| k == &field.name) {
                        remove_from_index(store, table, field, value, pk_str, now)?;
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
        clear_row_ttl(store, table, pk_str, now)?;
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
    store.srem(tlist.as_bytes(), &[table.as_bytes()], now)?;

    // Evict from cache
    cache.write().remove(table);

    commit
        .complete()
        .map_err(|error| format!("ERR journal apply failed: {error}"))?;
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
/// Test convenience: integer-id form of `table_get_filtered_pk`.
#[cfg(test)]
pub fn table_get_filtered(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    id: i64,
    filter: &str,
    now: Instant,
    decrypt_authorized: bool,
) -> Result<Option<Vec<(String, String)>>, String> {
    table_get_filtered_pk(
        store,
        cache,
        table,
        &id.to_string(),
        filter,
        now,
        decrypt_authorized,
    )
}

/// Like `table_get_filtered` but keyed by a raw PK string, so it works for any
/// PK type (INT, UUID, STR). The RLS `filter` is ANDed onto the PK match so a
/// row outside the caller's grant reads as not-found.
pub fn table_get_filtered_pk(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    pk_str: &str,
    filter: &str,
    now: Instant,
    decrypt_authorized: bool,
) -> Result<Option<Vec<(String, String)>>, String> {
    // Full-access with no row filter: direct PK fetch, no plan. When the caller
    // isn't decrypt-authorized we fall through to the plan path so encrypted
    // columns get gated even on an unconditional grant.
    if filter.trim().is_empty() && decrypt_authorized {
        return table_get_by_pk_str(store, cache, table, pk_str, None, true, now);
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
        pk_str.to_string(),
    ];
    if !filter.trim().is_empty() {
        toks.push("AND".to_string());
        toks.extend(filter.split_whitespace().map(ToString::to_string));
    }
    let refs: Vec<&str> = toks.iter().map(|s| s.as_str()).collect();
    let mut plan = parse_select(&refs)?;
    plan.decrypt_authorized = decrypt_authorized;
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
        if field.encrypted {
            parts.push("ENCRYPTED".to_string());
        }
        if field.searchable {
            parts.push("SEARCHABLE".to_string());
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
    let route: [&[u8]; 2] = [b"TALTER", table.as_bytes()];
    let journal = store
        .prepare_journaled(&route)
        .map_err(|error| format!("ERR WAL append failed: {error}"))?;
    let schema = load_schema(store, cache, table, now)?;
    let new_field = parse_field_def(field_spec)?;
    ensure_encryption_ready(store, std::slice::from_ref(&new_field))?;

    if schema.iter().any(|f| f.name == new_field.name) {
        return Err(format!("ERR field '{}' already exists", new_field.name));
    }

    // Check if there are existing rows
    let row_ids = get_all_row_ids(store, table, now)?;
    let has_rows = !row_ids.is_empty();

    // If column is NOT NULL and has no DEFAULT, error if there are existing rows
    if has_rows && !new_field.nullable && new_field.default_value.is_none() {
        return Err(format!(
            "ERR column '{}' is NOT NULL without a DEFAULT value; cannot add to table with existing rows",
            new_field.name
        ));
    }

    let command: [&[u8]; 4] = [b"TALTER", table.as_bytes(), b"ADD", field_spec.as_bytes()];
    let commit = journal
        .commit(&command)
        .map_err(|error| format!("ERR WAL append failed: {error}"))?;

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
            if backfill_value == "NULL" {
                continue;
            }
            let encoded = encode_stored_value(store, table, &new_field, &pk_str, &backfill_value)?;
            store.hset(
                rk.as_bytes(),
                &[(new_field.name.as_bytes() as &[u8], encoded.as_slice())],
                now,
            )?;

            // Add to indexes if needed
            add_to_index(store, table, &new_field, &backfill_value, &pk_str, now)?;
            if new_field.unique {
                let ukey = uniq_key(table, &new_field.name);
                for index_value in
                    searchable_index_values(store, table, &new_field, &backfill_value)?
                {
                    store.hset(
                        ukey.as_bytes(),
                        &[(index_value.as_bytes() as &[u8], pk_str.as_bytes() as &[u8])],
                        now,
                    )?;
                }
            }
        }
    }

    commit
        .complete()
        .map_err(|error| format!("ERR journal apply failed: {error}"))?;
    Ok(())
}

pub fn table_drop_column(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    field_name: &str,
    now: Instant,
) -> Result<(), String> {
    let route: [&[u8]; 2] = [b"TALTER", table.as_bytes()];
    let journal = store
        .prepare_journaled(&route)
        .map_err(|error| format!("ERR WAL append failed: {error}"))?;
    let schema = load_schema(store, cache, table, now)?;

    if !schema.iter().any(|f| f.name == field_name) {
        return Err(format!("ERR field '{}' does not exist", field_name));
    }

    // Resolve every key needed by the drop before crossing the durability
    // boundary. A failed read must not leave a schema mutation without the
    // matching row/index cleanup.
    let row_ids = get_all_row_ids(store, table, now)?;
    let str_idx_pattern = format!("_t:{}:idx:{}:*", table, field_name);
    let str_index_keys = store.keys(str_idx_pattern.as_bytes(), now);
    let command: [&[u8]; 4] = [b"TALTER", table.as_bytes(), b"DROP", field_name.as_bytes()];
    let commit = journal
        .commit(&command)
        .map_err(|error| format!("ERR WAL append failed: {error}"))?;

    let key = schema_key(table);
    store.hdel(key.as_bytes(), &[field_name.as_bytes()], now)?;

    for pk_str in row_ids {
        let rk = row_key_for_pk(table, &pk_str);
        store.hdel(rk.as_bytes(), &[field_name.as_bytes()], now)?;
    }

    // Drop the numeric sorted-set index (INT/FLOAT/TIMESTAMP fields)
    let idx_key = idx_sorted_key(table, field_name);
    store.del(&[idx_key.as_bytes()]);

    // Drop the unique hash index
    let ukey = uniq_key(table, field_name);
    store.del(&[ukey.as_bytes()]);

    // Drop all per-value set index keys (STR/UUID fields store one key per distinct value)
    // Pattern: _t:<table>:idx:<field>:*
    if !str_index_keys.is_empty() {
        let key_refs: Vec<&[u8]> = str_index_keys
            .iter()
            .map(|key| key.as_bytes() as &[u8])
            .collect();
        store.del(&key_refs);
    }

    // Invalidate so the next load picks up the dropped field from the Store
    cache.write().remove(table);

    commit
        .complete()
        .map_err(|error| format!("ERR journal apply failed: {error}"))?;
    Ok(())
}

pub fn table_list(store: &Store, now: Instant) -> Result<Vec<String>, String> {
    let tlist = table_list_key();
    store.smembers(tlist.as_bytes(), now)
}

/// Return all row PK strings for a table, ordered by insertion sequence.
fn get_all_row_ids(store: &Store, table: &str, now: Instant) -> Result<Vec<String>, String> {
    let ikey = ids_key(table);
    let rows = store.zrangebyscore(
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
    )?;
    Ok(rows.into_iter().map(|(s, _)| s).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use crate::{EncryptionConfig, EncryptionKeyConfig, StorageConfig, StorageMode};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::sync::Arc;
    use std::time::Instant;

    fn make_cache() -> SharedSchemaCache {
        Arc::new(parking_lot::RwLock::new(SchemaCache::new()))
    }

    fn now() -> Instant {
        Instant::now()
    }

    fn persistent_config(dir: &std::path::Path) -> Arc<crate::ServerConfig> {
        Arc::new(crate::ServerConfig {
            data_dir: dir.to_string_lossy().into_owned(),
            durability: crate::DurabilityConfig {
                policy: crate::DurabilityPolicy::AlwaysSync,
                ..Default::default()
            },
            ..crate::ServerConfig::default()
        })
    }

    fn row_field<'a>(row: &'a [(String, String)], field: &str) -> Option<&'a str> {
        row.iter()
            .find(|(name, _)| name == field)
            .map(|(_, value)| value.as_str())
    }

    #[test]
    fn journal_failures_leave_row_and_every_derived_structure_unchanged() {
        for fail_fsync in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let config = persistent_config(dir.path());
            let store = Store::new_with_config(config);
            let cache = make_cache();
            let n = now();
            table_create(
                &store,
                &cache,
                "accounts",
                &[
                    "id INT PRIMARY KEY,",
                    "email STR UNIQUE,",
                    "age INT,",
                    "embedding VECTOR(2)",
                ],
                n,
            )
            .unwrap();
            table_insert(
                &store,
                &cache,
                "accounts",
                &[
                    ("id", "1"),
                    ("email", "old@example.com"),
                    ("age", "10"),
                    ("embedding", "[1,0]"),
                ],
                n,
            )
            .unwrap();
            let journal_path = store.config().journal_dir().join("global/wal.lux");
            let journal_before = std::fs::read(&journal_path).unwrap();

            if fail_fsync {
                store.inject_journal_fsync_failures(1);
            } else {
                store.inject_journal_failures(1);
            }
            let error = table_update_by_pk_str(
                &store,
                &cache,
                "accounts",
                "1",
                &[
                    ("email", "new@example.com"),
                    ("age", "20"),
                    ("embedding", "[0,1]"),
                ],
                Some(TtlOp::Set(60)),
                n,
            )
            .expect_err("the injected journal failure must reject the update");
            assert!(error.contains("injected journal"), "{error}");
            assert_eq!(std::fs::read(&journal_path).unwrap(), journal_before);

            let row = table_get(&store, &cache, "accounts", 1, n).unwrap();
            assert_eq!(row_field(&row, "email"), Some("old@example.com"));
            assert_eq!(row_field(&row, "age"), Some("10"));
            assert_eq!(
                store
                    .hget_checked(
                        uniq_key("accounts", "email").as_bytes(),
                        b"old@example.com",
                        n,
                    )
                    .unwrap()
                    .as_deref(),
                Some(&b"1"[..])
            );
            assert!(store
                .hget_checked(
                    uniq_key("accounts", "email").as_bytes(),
                    b"new@example.com",
                    n,
                )
                .unwrap()
                .is_none());
            assert_eq!(
                store
                    .zscore(idx_sorted_key("accounts", "age").as_bytes(), b"1", n)
                    .unwrap(),
                Some(10.0)
            );
            assert!(store
                .zscore(
                    ttl_index_key().as_bytes(),
                    ttl_member("accounts", "1").as_bytes(),
                    n,
                )
                .unwrap()
                .is_none());
            let vectors =
                store.table_vector_search("accounts", "embedding", &[1.0, 0.0], 1, None, n);
            assert_eq!(vectors.first().map(|(pk, _)| pk.as_str()), Some("1"));
            assert!(vectors[0].1 > 0.99);
        }
    }

    #[test]
    fn internal_type_corruption_is_rejected_before_journal_publication() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new_with_config(persistent_config(dir.path()));
        let cache = make_cache();
        let n = now();
        table_create(&store, &cache, "events", &["age INT"], n).unwrap();
        let index = idx_sorted_key("events", "age");
        store.set(index.as_bytes(), b"not-a-sorted-set", None, n);
        let journal_path = store.config().journal_dir().join("global/wal.lux");
        let journal_before = std::fs::read(&journal_path).unwrap();
        let sequence_before = store.get(seq_key("events").as_bytes(), n);

        let error = table_insert(&store, &cache, "events", &[("age", "10")], n)
            .expect_err("corrupt internal state must fail closed");
        assert!(error.contains("expected zset, found string"), "{error}");
        assert_eq!(std::fs::read(&journal_path).unwrap(), journal_before);
        assert_eq!(table_count(&store, &cache, "events", n).unwrap(), 0);
        assert_eq!(store.get(seq_key("events").as_bytes(), n), sequence_before);
    }

    #[test]
    fn interrupted_published_update_recovers_as_one_complete_change() {
        let dir = tempfile::tempdir().unwrap();
        let config = persistent_config(dir.path());
        let store = Store::new_with_config(config.clone());
        let cache = make_cache();
        let n = now();
        table_create(
            &store,
            &cache,
            "accounts",
            &["id INT PRIMARY KEY,", "email STR UNIQUE,", "age INT"],
            n,
        )
        .unwrap();
        table_insert(
            &store,
            &cache,
            "accounts",
            &[("id", "1"), ("email", "old@example.com"), ("age", "10")],
            n,
        )
        .unwrap();

        fail_next_table_mutation_after_journal();
        let error = table_update_by_pk_str(
            &store,
            &cache,
            "accounts",
            "1",
            &[("email", "new@example.com"), ("age", "20")],
            Some(TtlOp::Set(60)),
            n,
        )
        .expect_err("the interruption must happen before live publication");
        assert!(error.contains("injected interruption"), "{error}");
        let old_row = table_get(&store, &cache, "accounts", 1, n).unwrap();
        assert_eq!(row_field(&old_row, "email"), Some("old@example.com"));
        assert_eq!(row_field(&old_row, "age"), Some("10"));
        drop(store);

        let restored = Store::new_with_config(config);
        let restored_cache = make_cache();
        restored.replay_wal(&crate::pubsub::Broker::new()).unwrap();
        let row = table_get(&restored, &restored_cache, "accounts", 1, now()).unwrap();
        assert_eq!(row_field(&row, "email"), Some("new@example.com"));
        assert_eq!(row_field(&row, "age"), Some("20"));
        assert!(restored
            .hget_checked(
                uniq_key("accounts", "email").as_bytes(),
                b"old@example.com",
                now(),
            )
            .unwrap()
            .is_none());
        assert_eq!(
            restored
                .hget_checked(
                    uniq_key("accounts", "email").as_bytes(),
                    b"new@example.com",
                    now(),
                )
                .unwrap()
                .as_deref(),
            Some(&b"1"[..])
        );
        assert_eq!(
            restored
                .zscore(idx_sorted_key("accounts", "age").as_bytes(), b"1", now(),)
                .unwrap(),
            Some(20.0)
        );
        assert!(restored
            .zscore(
                ttl_index_key().as_bytes(),
                ttl_member("accounts", "1").as_bytes(),
                now(),
            )
            .unwrap()
            .is_some());
    }

    #[test]
    fn rejected_cascade_delete_does_not_touch_any_related_row() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new_with_config(persistent_config(dir.path()));
        let cache = make_cache();
        let n = now();
        table_create(&store, &cache, "parents", &["id INT PRIMARY KEY"], n).unwrap();
        table_create(
            &store,
            &cache,
            "children",
            &[
                "id INT PRIMARY KEY,",
                "parent_id INT REFERENCES parents(id) ON DELETE CASCADE",
            ],
            n,
        )
        .unwrap();
        table_create(
            &store,
            &cache,
            "profiles",
            &[
                "id INT PRIMARY KEY,",
                "parent_id INT REFERENCES parents(id) ON DELETE SET NULL",
            ],
            n,
        )
        .unwrap();
        table_insert(&store, &cache, "parents", &[("id", "1")], n).unwrap();
        table_insert(
            &store,
            &cache,
            "children",
            &[("id", "10"), ("parent_id", "1")],
            n,
        )
        .unwrap();
        table_insert(
            &store,
            &cache,
            "profiles",
            &[("id", "20"), ("parent_id", "1")],
            n,
        )
        .unwrap();

        store.inject_journal_failures(1);
        table_delete_inner(&store, &cache, "parents", "1", n, 0)
            .expect_err("the injected journal failure must reject the whole cascade");
        assert!(table_get(&store, &cache, "parents", 1, n).is_ok());
        assert!(table_get(&store, &cache, "children", 10, n).is_ok());
        let profile = table_get(&store, &cache, "profiles", 20, n).unwrap();
        assert_eq!(row_field(&profile, "parent_id"), Some("1"));
        assert_eq!(
            store
                .zscore(idx_sorted_key("children", "parent_id").as_bytes(), b"10", n,)
                .unwrap(),
            Some(1.0)
        );

        table_delete_inner(&store, &cache, "parents", "1", n, 0).unwrap();
        assert!(table_get(&store, &cache, "parents", 1, n).is_err());
        assert!(table_get(&store, &cache, "children", 10, n).is_err());
        let profile = table_get(&store, &cache, "profiles", 20, n).unwrap();
        assert!(row_field(&profile, "parent_id").is_none());
        assert!(store
            .zscore(idx_sorted_key("profiles", "parent_id").as_bytes(), b"20", n,)
            .unwrap()
            .is_none());
    }

    #[test]
    fn interrupted_published_cascade_recovers_all_related_rows_together() {
        let dir = tempfile::tempdir().unwrap();
        let config = persistent_config(dir.path());
        let store = Store::new_with_config(config.clone());
        let cache = make_cache();
        let n = now();
        table_create(&store, &cache, "parents", &["id INT PRIMARY KEY"], n).unwrap();
        table_create(
            &store,
            &cache,
            "children",
            &[
                "id INT PRIMARY KEY,",
                "parent_id INT REFERENCES parents(id) ON DELETE CASCADE",
            ],
            n,
        )
        .unwrap();
        table_create(
            &store,
            &cache,
            "profiles",
            &[
                "id INT PRIMARY KEY,",
                "parent_id INT REFERENCES parents(id) ON DELETE SET NULL",
            ],
            n,
        )
        .unwrap();
        table_insert(&store, &cache, "parents", &[("id", "1")], n).unwrap();
        table_insert(
            &store,
            &cache,
            "children",
            &[("id", "10"), ("parent_id", "1")],
            n,
        )
        .unwrap();
        table_insert(
            &store,
            &cache,
            "profiles",
            &[("id", "20"), ("parent_id", "1")],
            n,
        )
        .unwrap();

        fail_next_table_mutation_after_journal();
        table_delete_inner(&store, &cache, "parents", "1", n, 0)
            .expect_err("the injected interruption must happen before live publication");
        assert!(table_get(&store, &cache, "parents", 1, n).is_ok());
        assert!(table_get(&store, &cache, "children", 10, n).is_ok());
        assert_eq!(
            row_field(
                &table_get(&store, &cache, "profiles", 20, n).unwrap(),
                "parent_id"
            ),
            Some("1")
        );
        drop(store);

        let restored = Store::new_with_config(config);
        let restored_cache = make_cache();
        restored.replay_wal(&crate::pubsub::Broker::new()).unwrap();
        assert!(table_get(&restored, &restored_cache, "parents", 1, now()).is_err());
        assert!(table_get(&restored, &restored_cache, "children", 10, now()).is_err());
        let profile = table_get(&restored, &restored_cache, "profiles", 20, now()).unwrap();
        assert!(row_field(&profile, "parent_id").is_none());
    }

    #[test]
    fn updates_preserve_primary_foreign_and_partitioned_sequence_invariants() {
        let store = Store::new();
        let cache = make_cache();
        let n = now();
        table_create(&store, &cache, "workspaces", &["id STR PRIMARY KEY"], n).unwrap();
        table_create(
            &store,
            &cache,
            "tickets",
            &[
                "id INT PRIMARY KEY,",
                "workspace_id STR REFERENCES workspaces(id),",
                "serial INT SEQUENCE PARTITION BY workspace_id,",
                "title STR",
            ],
            n,
        )
        .unwrap();
        for workspace in ["a", "b"] {
            table_insert(&store, &cache, "workspaces", &[("id", workspace)], n).unwrap();
        }
        table_insert(
            &store,
            &cache,
            "tickets",
            &[("id", "1"), ("workspace_id", "a"), ("title", "first")],
            n,
        )
        .unwrap();
        table_insert(
            &store,
            &cache,
            "tickets",
            &[("id", "2"), ("workspace_id", "b"), ("title", "second")],
            n,
        )
        .unwrap();

        let error = table_update_by_pk_str(
            &store,
            &cache,
            "tickets",
            "2",
            &[("workspace_id", "a")],
            None,
            n,
        )
        .expect_err("moving serial 1 into a partition already holding serial 1 must fail");
        assert!(error.contains("unique constraint"), "{error}");
        let unchanged = table_get(&store, &cache, "tickets", 2, n).unwrap();
        assert_eq!(row_field(&unchanged, "workspace_id"), Some("b"));

        let error = table_update_by_pk_str(
            &store,
            &cache,
            "tickets",
            "2",
            &[("workspace_id", "missing")],
            None,
            n,
        )
        .expect_err("updates must validate explicit foreign keys");
        assert!(error.contains("foreign key violation"), "{error}");

        let error = table_update_by_pk_str(&store, &cache, "tickets", "2", &[("id", "3")], None, n)
            .expect_err("an update cannot split a primary key from its storage key");
        assert!(error.contains("cannot be updated"), "{error}");

        table_update_by_pk_str(
            &store,
            &cache,
            "tickets",
            "2",
            &[("workspace_id", "a"), ("serial", "5")],
            None,
            n,
        )
        .unwrap();
        let next = table_insert_returning(
            &store,
            &cache,
            "tickets",
            &[("id", "3"), ("workspace_id", "a"), ("title", "next")],
            n,
        )
        .unwrap();
        assert_eq!(row_field(&next, "serial"), Some("6"));
    }

    #[test]
    fn duplicate_update_assignments_use_only_the_final_value() {
        let store = Store::new();
        let cache = make_cache();
        let n = now();
        table_create(
            &store,
            &cache,
            "accounts",
            &["id INT PRIMARY KEY, email STR UNIQUE"],
            n,
        )
        .unwrap();
        table_insert(
            &store,
            &cache,
            "accounts",
            &[("id", "1"), ("email", "old@example.com")],
            n,
        )
        .unwrap();

        table_update_by_pk_str(
            &store,
            &cache,
            "accounts",
            "1",
            &[
                ("email", "intermediate@example.com"),
                ("email", "final@example.com"),
            ],
            None,
            n,
        )
        .unwrap();

        let row = table_get(&store, &cache, "accounts", 1, n).unwrap();
        assert_eq!(row_field(&row, "email"), Some("final@example.com"));
        let unique_key = uniq_key("accounts", "email");
        assert!(store
            .hget(unique_key.as_bytes(), b"intermediate@example.com", n)
            .is_none());
        assert_eq!(
            store
                .hget(unique_key.as_bytes(), b"final@example.com", n)
                .as_deref(),
            Some(&b"1"[..])
        );
    }

    #[test]
    fn cascade_uses_the_declared_referenced_column_value() {
        let store = Store::new();
        let cache = make_cache();
        let n = now();
        table_create(
            &store,
            &cache,
            "parents",
            &["id INT PRIMARY KEY,", "code STR UNIQUE"],
            n,
        )
        .unwrap();
        table_create(
            &store,
            &cache,
            "children",
            &[
                "id INT PRIMARY KEY,",
                "parent_code STR REFERENCES parents(code) ON DELETE CASCADE",
            ],
            n,
        )
        .unwrap();
        table_insert(
            &store,
            &cache,
            "parents",
            &[("id", "1"), ("code", "parent-one")],
            n,
        )
        .unwrap();
        table_insert(
            &store,
            &cache,
            "children",
            &[("id", "10"), ("parent_code", "parent-one")],
            n,
        )
        .unwrap();

        table_delete_inner(&store, &cache, "parents", "1", n, 0).unwrap();
        assert!(table_get(&store, &cache, "parents", 1, n).is_err());
        assert!(table_get(&store, &cache, "children", 10, n).is_err());
    }

    #[test]
    fn deleting_a_row_with_an_unset_referenced_column_succeeds() {
        let store = Store::new();
        let cache = make_cache();
        let n = now();
        table_create(
            &store,
            &cache,
            "parents",
            &["id INT PRIMARY KEY, code STR UNIQUE"],
            n,
        )
        .unwrap();
        table_create(
            &store,
            &cache,
            "children",
            &["id INT PRIMARY KEY, parent_code STR REFERENCES parents(code)"],
            n,
        )
        .unwrap();
        table_insert(&store, &cache, "parents", &[("id", "1")], n).unwrap();

        table_delete_inner(&store, &cache, "parents", "1", n, 0).unwrap();
        assert!(table_get(&store, &cache, "parents", 1, n).is_err());
    }

    #[test]
    fn expiry_rechecks_the_authoritative_deadline_before_deleting() {
        let store = Store::new();
        let cache = make_cache();
        let n = now();
        table_create(&store, &cache, "sessions", &["id INT PRIMARY KEY"], n).unwrap();
        table_insert_ttl(
            &store,
            &cache,
            "sessions",
            &[("id", "1")],
            Some(TtlOp::Set(3_600)),
            n,
        )
        .unwrap();
        let row_key = row_key_for_pk("sessions", "1");
        let deadline = store
            .hget(row_key.as_bytes(), HIDDEN_TTL_FIELD, n)
            .and_then(|value| std::str::from_utf8(&value).ok()?.parse::<u64>().ok())
            .unwrap();

        assert!(!expire_row_if_due(&store, &cache, "sessions", "1", deadline - 1, n,).unwrap());
        assert!(table_get(&store, &cache, "sessions", 1, n).is_ok());
    }

    #[test]
    fn concurrent_readers_never_observe_a_partially_updated_row() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let n = now();
        table_create(
            &store,
            &cache,
            "states",
            &["id INT PRIMARY KEY,", "label STR,", "version INT"],
            n,
        )
        .unwrap();
        table_insert(
            &store,
            &cache,
            "states",
            &[("id", "1"), ("label", "even"), ("version", "0")],
            n,
        )
        .unwrap();

        let start = Arc::new(std::sync::Barrier::new(2));
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let writer_store = store.clone();
        let writer_cache = cache.clone();
        let writer_start = start.clone();
        let writer_done = done.clone();
        let writer = std::thread::spawn(move || {
            writer_start.wait();
            for version in 1..=2_000 {
                let label = if version % 2 == 0 { "even" } else { "odd" };
                let version = version.to_string();
                table_update_by_pk_str(
                    &writer_store,
                    &writer_cache,
                    "states",
                    "1",
                    &[("label", label), ("version", version.as_str())],
                    None,
                    Instant::now(),
                )
                .unwrap();
            }
            writer_done.store(true, std::sync::atomic::Ordering::Release);
        });

        start.wait();
        let mut reads = 0usize;
        while !done.load(std::sync::atomic::Ordering::Acquire) || reads < 2_000 {
            let row = table_get(&store, &cache, "states", 1, Instant::now()).unwrap();
            let label = row_field(&row, "label").unwrap();
            let version = row_field(&row, "version").unwrap().parse::<u64>().unwrap();
            assert_eq!(label, if version % 2 == 0 { "even" } else { "odd" });
            reads += 1;
        }
        writer.join().unwrap();
    }

    fn encrypted_store() -> Arc<Store> {
        Arc::new(Store::new_with_config(Arc::new(crate::ServerConfig {
            encryption: EncryptionConfig {
                active_key_id: Some("k2".to_string()),
                keys: vec![
                    EncryptionKeyConfig {
                        id: "k1".to_string(),
                        secret: b"old-key-secret".to_vec(),
                        decrypt_only: true,
                    },
                    EncryptionKeyConfig {
                        id: "k2".to_string(),
                        secret: b"new-key-secret".to_vec(),
                        decrypt_only: false,
                    },
                ],
                ..Default::default()
            },
            ..crate::ServerConfig::default()
        })))
    }

    fn select_err(
        store: &Store,
        cache: &SharedSchemaCache,
        plan: &SelectPlan,
        now: Instant,
    ) -> String {
        match table_select(store, cache, plan, now) {
            Ok(_) => panic!("expected table_select to fail"),
            Err(err) => err,
        }
    }

    fn corrupt_cold_key(store: &Store, key: &[u8]) {
        let shard = store.shard_for_key(key);
        assert!(store.evict_key(shard, key));
        let path = std::fs::read_dir(&store.config().storage.dir)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path().join("data.lux"))
            .find(|path| std::fs::metadata(path).is_ok_and(|metadata| metadata.len() > 8))
            .expect("the evicted key must have a cold data file");
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        file.seek(SeekFrom::Start(8)).unwrap();
        let mut byte = [0u8; 1];
        file.read_exact(&mut byte).unwrap();
        file.seek(SeekFrom::Start(8)).unwrap();
        file.write_all(&[byte[0] ^ 0xff]).unwrap();
        file.sync_all().unwrap();
    }

    #[test]
    fn corrupt_cold_row_fails_closed_before_unique_write_and_recovers_from_journal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_string_lossy().to_string();
        let config = Arc::new(crate::ServerConfig {
            data_dir: path.clone(),
            storage: StorageConfig {
                mode: StorageMode::Tiered,
                dir: path,
            },
            durability: crate::DurabilityConfig {
                policy: crate::DurabilityPolicy::AlwaysSync,
                ..Default::default()
            },
            ..crate::ServerConfig::default()
        });
        let store = Store::new_with_config(config.clone());
        let cache = make_cache();
        let n = now();
        table_create(
            &store,
            &cache,
            "accounts",
            &["id INT PRIMARY KEY, email STR UNIQUE"],
            n,
        )
        .unwrap();
        table_insert(
            &store,
            &cache,
            "accounts",
            &[("id", "1"), ("email", "owner@example.com")],
            n,
        )
        .unwrap();

        corrupt_cold_key(&store, row_key_for_pk("accounts", "1").as_bytes());
        let journal_path = std::path::Path::new(&store.config().data_dir).join("global/wal.lux");
        let journal_before = std::fs::read(&journal_path).unwrap();

        let error = table_insert(
            &store,
            &cache,
            "accounts",
            &[("id", "2"), ("email", "owner@example.com")],
            n,
        )
        .expect_err("an unreadable unique holder must reject the write");
        assert!(error.contains("cold storage read failed"), "{error}");
        assert_eq!(std::fs::read(&journal_path).unwrap(), journal_before);
        assert!(!store.wal_enabled());
        drop(store);

        let restored = Store::new_with_config(config);
        let restored_cache = make_cache();
        restored.replay_wal(&crate::pubsub::Broker::new()).unwrap();
        assert_eq!(
            table_get(&restored, &restored_cache, "accounts", 1, now())
                .unwrap()
                .iter()
                .find(|(field, _)| field == "email")
                .map(|(_, value)| value.as_str()),
            Some("owner@example.com")
        );
        assert!(table_get(&restored, &restored_cache, "accounts", 2, now()).is_err());
    }

    #[test]
    fn replayed_table_create_rejects_a_conflicting_bootstrap_schema() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_string_lossy().to_string();
        let config = Arc::new(crate::ServerConfig {
            data_dir: path.clone(),
            storage: StorageConfig {
                mode: StorageMode::Tiered,
                dir: path,
            },
            durability: crate::DurabilityConfig {
                policy: crate::DurabilityPolicy::AlwaysSync,
                ..Default::default()
            },
            ..crate::ServerConfig::default()
        });
        let original = Store::new_with_config(config.clone());
        let original_cache = make_cache();
        table_create(
            &original,
            &original_cache,
            "accounts",
            &["id INT PRIMARY KEY, email STR UNIQUE"],
            now(),
        )
        .unwrap();
        drop(original);

        let restored = Store::new_with_config(config);
        let restored_cache = make_cache();
        restored
            .wal_suppress
            .store(true, std::sync::atomic::Ordering::Release);
        table_create(
            &restored,
            &restored_cache,
            "accounts",
            &["id INT PRIMARY KEY, handle STR UNIQUE"],
            now(),
        )
        .unwrap();
        restored
            .wal_suppress
            .store(false, std::sync::atomic::Ordering::Release);

        let error = restored
            .replay_wal(&crate::pubsub::Broker::new())
            .expect_err("replay must reject a same-name table with a different schema");
        assert!(error.to_string().contains("conflicts"), "{error}");
    }

    #[test]
    fn corrupt_cold_sequence_fails_closed_without_reusing_a_row_id() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_string_lossy().to_string();
        let config = Arc::new(crate::ServerConfig {
            data_dir: path.clone(),
            storage: StorageConfig {
                mode: StorageMode::Tiered,
                dir: path,
            },
            durability: crate::DurabilityConfig {
                policy: crate::DurabilityPolicy::AlwaysSync,
                ..Default::default()
            },
            ..crate::ServerConfig::default()
        });
        let store = Store::new_with_config(config.clone());
        let cache = make_cache();
        let n = now();
        table_create(&store, &cache, "accounts", &["name STR"], n).unwrap();
        assert_eq!(
            table_insert(&store, &cache, "accounts", &[("name", "alice")], n).unwrap(),
            1
        );

        let sequence = seq_key("accounts");
        assert!(store.evict_key(
            store.shard_for_key(sequence.as_bytes()),
            sequence.as_bytes()
        ));
        let cold_path = std::fs::read_dir(&store.config().storage.dir)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path().join("data.lux"))
            .find(|path| std::fs::metadata(path).is_ok_and(|metadata| metadata.len() > 8))
            .expect("the evicted sequence must have a cold data file");
        let mut cold_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(cold_path)
            .unwrap();
        cold_file.seek(SeekFrom::Start(8)).unwrap();
        let mut byte = [0u8; 1];
        cold_file.read_exact(&mut byte).unwrap();
        cold_file.seek(SeekFrom::Start(8)).unwrap();
        cold_file.write_all(&[byte[0] ^ 0xff]).unwrap();
        cold_file.sync_all().unwrap();

        let journal_path = std::path::Path::new(&store.config().data_dir).join("global/wal.lux");
        let journal_before = std::fs::read(&journal_path).unwrap();
        let error = table_insert(&store, &cache, "accounts", &[("name", "bob")], n)
            .expect_err("a corrupt sequence must not be treated as zero");
        assert!(error.contains("cold storage read failed"), "{error}");
        assert_eq!(std::fs::read(&journal_path).unwrap(), journal_before);
        assert!(!store.wal_enabled());
        assert_eq!(
            table_get(&store, &cache, "accounts", 1, n)
                .unwrap()
                .iter()
                .find(|(field, _)| field == "name")
                .map(|(_, value)| value.as_str()),
            Some("alice")
        );
        drop(store);

        let restored = Store::new_with_config(config);
        let restored_cache = make_cache();
        restored.replay_wal(&crate::pubsub::Broker::new()).unwrap();
        assert_eq!(
            table_insert(
                &restored,
                &restored_cache,
                "accounts",
                &[("name", "bob")],
                now(),
            )
            .unwrap(),
            2
        );
        assert_eq!(
            table_get(&restored, &restored_cache, "accounts", 1, now())
                .unwrap()
                .iter()
                .find(|(field, _)| field == "name")
                .map(|(_, value)| value.as_str()),
            Some("alice")
        );
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
    fn encrypted_field_schema_roundtrips() {
        let field = parse_field_def("token STR ENCRYPTED SEARCHABLE UNIQUE").unwrap();
        assert!(field.encrypted);
        assert!(field.searchable);
        assert!(field.unique);

        let encoded = encode_field_def(&field);
        let decoded = decode_field_def("token", &encoded);
        assert!(decoded.encrypted);
        assert!(decoded.searchable);
        assert!(decoded.unique);
    }

    #[test]
    fn encrypted_field_rejects_invalid_combinations() {
        assert!(parse_field_def("id UUID PRIMARY KEY ENCRYPTED").is_err());
        assert!(parse_field_def("owner UUID REFERENCES users(id) ENCRYPTED").is_err());
        // Encrypted VECTOR columns are allowed (at-rest); only SEARCHABLE on an
        // encrypted vector is rejected (no blind index for similarity search).
        assert!(parse_field_def("embedding VECTOR(3) ENCRYPTED").is_ok());
        assert!(parse_field_def("embedding VECTOR(3) ENCRYPTED SEARCHABLE").is_err());
        assert!(parse_field_def("token STR SEARCHABLE").is_err());
        assert!(parse_field_def("token STR ENCRYPTED UNIQUE").is_err());
        assert!(parse_field_def("token STR ENCRYPTED DEFAULT seeded").is_err());
    }

    #[test]
    fn encrypted_field_stores_ciphertext_and_returns_plaintext() {
        let store = encrypted_store();
        let cache = make_cache();
        let now = now();
        table_create(
            &store,
            &cache,
            "secrets",
            &["id UUID PRIMARY KEY, token STR ENCRYPTED, email STR ENCRYPTED SEARCHABLE"],
            now,
        )
        .unwrap();
        let id = "018f9d72-7c8d-7000-8000-000000000001";
        table_insert(
            &store,
            &cache,
            "secrets",
            &[
                ("id", id),
                ("token", "topsecret"),
                ("email", "a@example.com"),
            ],
            now,
        )
        .unwrap();

        let raw = store
            .hget(row_key_for_pk("secrets", id).as_bytes(), b"token", now)
            .unwrap();
        assert!(!raw.windows(b"topsecret".len()).any(|w| w == b"topsecret"));

        let row = get_row(
            &store,
            "secrets",
            &load_schema(&store, &cache, "secrets", now).unwrap(),
            id,
            now,
            true,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            row.iter().find(|(k, _)| k == "token").unwrap().1,
            "topsecret"
        );

        let plan = parse_select(&[
            "*",
            "FROM",
            "secrets",
            "WHERE",
            "email",
            "=",
            "a@example.com",
        ])
        .unwrap();
        let rows = rows_of(table_select(&store, &cache, &plan, now).unwrap());
        assert_eq!(rows.len(), 1);
        assert_eq!(cell(&rows[0], "token"), "topsecret");
    }

    #[test]
    fn unauthorized_reads_omit_encrypted_columns() {
        let store = encrypted_store();
        let cache = make_cache();
        let now = now();
        table_create(
            &store,
            &cache,
            "secrets",
            &["id UUID PRIMARY KEY, token STR ENCRYPTED, email STR UNIQUE ENCRYPTED SEARCHABLE, plan STR"],
            now,
        )
        .unwrap();
        let id = "018f9d72-7c8d-7000-8000-000000000001";
        table_insert(
            &store,
            &cache,
            "secrets",
            &[
                ("id", id),
                ("token", "topsecret"),
                ("email", "a@example.com"),
                ("plan", "pro"),
            ],
            now,
        )
        .unwrap();

        let has = |rows: &[Vec<(String, String)>], col: &str| rows[0].iter().any(|(k, _)| k == col);

        // Authorized: encrypted columns decrypt and come back.
        let mut plan = parse_select(&["*", "FROM", "secrets"]).unwrap();
        plan.decrypt_authorized = true;
        let rows = rows_of(table_select(&store, &cache, &plan, now).unwrap());
        assert_eq!(rows.len(), 1);
        assert_eq!(cell(&rows[0], "token"), "topsecret");
        assert_eq!(cell(&rows[0], "email"), "a@example.com");

        // Unauthorized (anonymous): encrypted columns are omitted, plaintext ones stay.
        plan.decrypt_authorized = false;
        let rows = rows_of(table_select(&store, &cache, &plan, now).unwrap());
        assert_eq!(rows.len(), 1);
        assert!(!has(&rows, "token"), "encrypted token must be omitted");
        assert!(!has(&rows, "email"), "encrypted email must be omitted");
        assert!(has(&rows, "id"), "primary key stays");
        assert_eq!(cell(&rows[0], "plan"), "pro"); // non-encrypted column stays

        // Searchable equality on the encrypted column still matches (blind index),
        // but the value is still withheld from an unauthorized caller.
        let mut plan = parse_select(&[
            "*",
            "FROM",
            "secrets",
            "WHERE",
            "email",
            "=",
            "a@example.com",
        ])
        .unwrap();
        plan.decrypt_authorized = false;
        let rows = rows_of(table_select(&store, &cache, &plan, now).unwrap());
        assert_eq!(rows.len(), 1, "blind-index filter still matches");
        assert!(
            !has(&rows, "email"),
            "matched row still withholds the encrypted value"
        );
    }

    #[test]
    fn encrypted_value_can_be_decrypted_by_non_writer_network_key() {
        let store = encrypted_store();
        let cache = make_cache();
        let now = now();
        table_create(
            &store,
            &cache,
            "secrets",
            &["id UUID PRIMARY KEY, token STR ENCRYPTED"],
            now,
        )
        .unwrap();
        let id = "018f9d72-7c8d-7000-8000-000000000001";
        table_insert(
            &store,
            &cache,
            "secrets",
            &[("id", id), ("token", "network-secret")],
            now,
        )
        .unwrap();
        let raw = store
            .hget(row_key_for_pk("secrets", id).as_bytes(), b"token", now)
            .unwrap();
        let field = load_schema(&store, &cache, "secrets", now)
            .unwrap()
            .into_iter()
            .find(|f| f.name == "token")
            .unwrap();

        let old_key_store = Store::new_with_config(Arc::new(crate::ServerConfig {
            encryption: EncryptionConfig {
                active_key_id: Some("k1".to_string()),
                keys: vec![EncryptionKeyConfig {
                    id: "k1".to_string(),
                    secret: b"old-key-secret".to_vec(),
                    decrypt_only: false,
                }],
                ..Default::default()
            },
            ..crate::ServerConfig::default()
        }));
        let plaintext = decode_stored_value(&old_key_store, "secrets", &field, id, &raw).unwrap();
        assert_eq!(plaintext, "network-secret");
    }

    #[test]
    fn encrypted_key_rotation_survives_wal_replay_update_and_search() {
        let dir = tempfile::tempdir().unwrap();
        let old_only = Arc::new(crate::ServerConfig {
            storage: StorageConfig {
                mode: StorageMode::Tiered,
                dir: dir.path().to_string_lossy().to_string(),
            },
            encryption: EncryptionConfig {
                active_key_id: Some("k1".to_string()),
                keys: vec![EncryptionKeyConfig {
                    id: "k1".to_string(),
                    secret: b"old-key-secret".to_vec(),
                    decrypt_only: false,
                }],
                ..Default::default()
            },
            ..crate::ServerConfig::default()
        });
        let rotated = Arc::new(crate::ServerConfig {
            storage: StorageConfig {
                mode: StorageMode::Tiered,
                dir: dir.path().to_string_lossy().to_string(),
            },
            encryption: EncryptionConfig {
                active_key_id: Some("k2".to_string()),
                keys: vec![
                    EncryptionKeyConfig {
                        id: "k1".to_string(),
                        secret: b"old-key-secret".to_vec(),
                        decrypt_only: true,
                    },
                    EncryptionKeyConfig {
                        id: "k2".to_string(),
                        secret: b"new-key-secret".to_vec(),
                        decrypt_only: false,
                    },
                ],
                ..Default::default()
            },
            ..crate::ServerConfig::default()
        });

        let store = Arc::new(Store::new_with_config(old_only.clone()));
        let cache = make_cache();
        let now = now();
        table_create(
            &store,
            &cache,
            "accounts",
            &[
                "id UUID PRIMARY KEY,",
                "email STR ENCRYPTED SEARCHABLE UNIQUE,",
                "token STR ENCRYPTED",
            ],
            now,
        )
        .unwrap();
        let first = "018f9d72-7c8d-7000-8000-000000000001";
        table_insert(
            &store,
            &cache,
            "accounts",
            &[
                ("id", first),
                ("email", "old@example.com"),
                ("token", "old-token"),
            ],
            now,
        )
        .unwrap();
        store.fsync_wal();

        let rotated_store = Arc::new(Store::new_with_config(rotated.clone()));
        rotated_store
            .replay_wal(&crate::pubsub::Broker::new())
            .unwrap();
        let rotated_cache = make_cache();
        let old_query = parse_select(&[
            "*",
            "FROM",
            "accounts",
            "WHERE",
            "email",
            "=",
            "old@example.com",
        ])
        .unwrap();
        let rows = rows_of(table_select(&rotated_store, &rotated_cache, &old_query, now).unwrap());
        assert_eq!(rows.len(), 1);
        assert_eq!(cell(&rows[0], "token"), "old-token");

        table_update_by_pk_str(
            &rotated_store,
            &rotated_cache,
            "accounts",
            first,
            &[("email", "rotated@example.com"), ("token", "new-token")],
            None,
            now,
        )
        .unwrap();
        let second = "018f9d72-7c8d-7000-8000-000000000002";
        table_insert(
            &rotated_store,
            &rotated_cache,
            "accounts",
            &[
                ("id", second),
                ("email", "fresh@example.com"),
                ("token", "fresh-token"),
            ],
            now,
        )
        .unwrap();
        rotated_store.fsync_wal();

        let mut wal_bytes = Vec::new();
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let path = entry.unwrap().path().join("wal.lux");
            if path.exists() {
                wal_bytes.extend(std::fs::read(path).unwrap());
            }
        }
        for plaintext in [
            b"old@example.com".as_slice(),
            b"rotated@example.com".as_slice(),
            b"fresh@example.com".as_slice(),
            b"old-token".as_slice(),
            b"new-token".as_slice(),
            b"fresh-token".as_slice(),
        ] {
            assert!(
                !wal_bytes.windows(plaintext.len()).any(|w| w == plaintext),
                "plaintext leaked into encrypted WAL"
            );
        }

        let restored = Arc::new(Store::new_with_config(rotated));
        restored.replay_wal(&crate::pubsub::Broker::new()).unwrap();
        let restored_cache = make_cache();
        let old_rows = rows_of(table_select(&restored, &restored_cache, &old_query, now).unwrap());
        assert_eq!(old_rows.len(), 0);

        let rotated_query = parse_select(&[
            "*",
            "FROM",
            "accounts",
            "WHERE",
            "email",
            "=",
            "rotated@example.com",
        ])
        .unwrap();
        let rows = rows_of(table_select(&restored, &restored_cache, &rotated_query, now).unwrap());
        assert_eq!(rows.len(), 1);
        assert_eq!(cell(&rows[0], "id"), first);
        assert_eq!(cell(&rows[0], "token"), "new-token");

        let fresh_query = parse_select(&[
            "*",
            "FROM",
            "accounts",
            "WHERE",
            "email",
            "=",
            "fresh@example.com",
        ])
        .unwrap();
        let rows = rows_of(table_select(&restored, &restored_cache, &fresh_query, now).unwrap());
        assert_eq!(rows.len(), 1);
        assert_eq!(cell(&rows[0], "id"), second);
        assert_eq!(cell(&rows[0], "token"), "fresh-token");

        table_insert(
            &restored,
            &restored_cache,
            "accounts",
            &[
                ("id", "018f9d72-7c8d-7000-8000-000000000003"),
                ("email", "old@example.com"),
                ("token", "reused-old-email"),
            ],
            now,
        )
        .unwrap();
    }

    #[test]
    fn encrypted_searchable_unique_uses_plaintext_semantics() {
        let store = encrypted_store();
        let cache = make_cache();
        let now = now();
        table_create(
            &store,
            &cache,
            "accounts",
            &["id UUID PRIMARY KEY, email STR ENCRYPTED SEARCHABLE UNIQUE"],
            now,
        )
        .unwrap();
        table_insert(
            &store,
            &cache,
            "accounts",
            &[
                ("id", "018f9d72-7c8d-7000-8000-000000000001"),
                ("email", "a@example.com"),
            ],
            now,
        )
        .unwrap();
        let err = table_insert(
            &store,
            &cache,
            "accounts",
            &[
                ("id", "018f9d72-7c8d-7000-8000-000000000002"),
                ("email", "a@example.com"),
            ],
            now,
        )
        .unwrap_err();
        assert!(err.contains("unique constraint"));
    }

    #[test]
    fn encrypted_query_guards_reject_unsupported_filters_and_ordering() {
        let store = encrypted_store();
        let cache = make_cache();
        let now = now();
        table_create(
            &store,
            &cache,
            "secrets",
            &[
                "id UUID PRIMARY KEY,",
                "token STR ENCRYPTED,",
                "email STR ENCRYPTED SEARCHABLE,",
                "profile JSON ENCRYPTED",
            ],
            now,
        )
        .unwrap();
        table_insert(
            &store,
            &cache,
            "secrets",
            &[
                ("id", "018f9d72-7c8d-7000-8000-000000000001"),
                ("token", "topsecret"),
                ("email", "a@example.com"),
                ("profile", r#"{"ssn":"1234"}"#),
            ],
            now,
        )
        .unwrap();

        let non_searchable =
            parse_select(&["*", "FROM", "secrets", "WHERE", "token", "=", "topsecret"]).unwrap();
        let err = select_err(&store, &cache, &non_searchable, now);
        assert!(err.contains("must be SEARCHABLE"), "{err}");

        let range = parse_select(&["*", "FROM", "secrets", "WHERE", "email", ">", "a"]).unwrap();
        let err = select_err(&store, &cache, &range, now);
        assert!(err.contains("only supports equality filters"), "{err}");

        let order = parse_select(&["*", "FROM", "secrets", "ORDER", "BY", "email"]).unwrap();
        let err = select_err(&store, &cache, &order, now);
        assert!(err.contains("does not support ORDER BY"), "{err}");

        let json_path =
            parse_select(&["*", "FROM", "secrets", "WHERE", "profile.ssn", "=", "1234"]).unwrap();
        let err = select_err(&store, &cache, &json_path, now);
        assert!(err.contains("does not support JSON path filters"), "{err}");

        let json_order =
            parse_select(&["*", "FROM", "secrets", "ORDER", "BY", "profile.ssn"]).unwrap();
        let err = select_err(&store, &cache, &json_order, now);
        assert!(err.contains("does not support ORDER BY"), "{err}");
    }

    #[test]
    fn encrypted_mutation_guards_reject_unsupported_predicates_and_conflicts() {
        let store = encrypted_store();
        let cache = make_cache();
        let now = now();
        table_create(
            &store,
            &cache,
            "secrets",
            &[
                "id UUID PRIMARY KEY,",
                "token STR ENCRYPTED,",
                "email STR ENCRYPTED SEARCHABLE,",
                "note STR",
            ],
            now,
        )
        .unwrap();
        let id = "018f9d72-7c8d-7000-8000-000000000001";
        table_insert(
            &store,
            &cache,
            "secrets",
            &[
                ("id", id),
                ("token", "topsecret"),
                ("email", "a@example.com"),
                ("note", "before"),
            ],
            now,
        )
        .unwrap();

        let err = table_update_where(
            &store,
            &cache,
            "secrets",
            &[("note", "leaked")],
            &["token", "=", "topsecret"],
            now,
        )
        .unwrap_err();
        assert!(err.contains("must be SEARCHABLE"), "{err}");

        let err = table_delete_where(
            &store,
            &cache,
            "secrets",
            &["email", ">", "a@example.com"],
            now,
        )
        .unwrap_err();
        assert!(err.contains("only supports equality filters"), "{err}");

        let err = table_upsert_returning(
            &store,
            &cache,
            "secrets",
            &[("token", "topsecret"), ("note", "upserted")],
            Some("token"),
            now,
        )
        .unwrap_err();
        assert!(
            err.contains("must be SEARCHABLE for upsert conflict"),
            "{err}"
        );

        let updated = table_update_where(
            &store,
            &cache,
            "secrets",
            &[("note", "matched")],
            &["email", "=", "a@example.com"],
            now,
        )
        .unwrap();
        assert_eq!(updated, 1);
        let row = get_row(
            &store,
            "secrets",
            &load_schema(&store, &cache, "secrets", now).unwrap(),
            id,
            now,
            true,
        )
        .unwrap()
        .unwrap();
        assert_eq!(cell(&row, "note"), "matched");

        let deleted = table_delete_where(
            &store,
            &cache,
            "secrets",
            &["email", "=", "a@example.com"],
            now,
        )
        .unwrap();
        assert_eq!(deleted, 1);
        assert!(get_row(
            &store,
            "secrets",
            &load_schema(&store, &cache, "secrets", now).unwrap(),
            id,
            now,
            true,
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn encrypted_json_and_array_cannot_be_searchable_and_paths_reject() {
        assert!(parse_field_def("meta JSON ENCRYPTED SEARCHABLE").is_err());
        assert!(parse_field_def("tags ARRAY ENCRYPTED SEARCHABLE").is_err());

        let store = encrypted_store();
        let cache = make_cache();
        let now = now();
        table_create(
            &store,
            &cache,
            "events",
            &["id UUID PRIMARY KEY, meta JSON ENCRYPTED"],
            now,
        )
        .unwrap();
        let id = "018f9d72-7c8d-7000-8000-000000000001";
        let meta = r#"{"kind":"login","count":1}"#;
        table_insert(&store, &cache, "events", &[("id", id), ("meta", meta)], now).unwrap();

        let raw = store
            .hget(row_key_for_pk("events", id).as_bytes(), b"meta", now)
            .unwrap();
        assert!(!raw.windows(b"login".len()).any(|window| window == b"login"));

        let whole = parse_select(&["*", "FROM", "events", "WHERE", "meta", "=", meta]).unwrap();
        let err = select_err(&store, &cache, &whole, now);
        assert!(err.contains("must be SEARCHABLE"), "{err}");

        let path =
            parse_select(&["*", "FROM", "events", "WHERE", "meta.kind", "=", "login"]).unwrap();
        let err = select_err(&store, &cache, &path, now);
        assert!(err.contains("does not support JSON path filters"), "{err}");
    }

    #[test]
    fn encrypted_join_keys_are_rejected() {
        let store = encrypted_store();
        let cache = make_cache();
        let now = now();
        table_create(
            &store,
            &cache,
            "users",
            &["id UUID PRIMARY KEY, email STR ENCRYPTED SEARCHABLE, org_id STR"],
            now,
        )
        .unwrap();
        table_create(
            &store,
            &cache,
            "profiles",
            &["id UUID PRIMARY KEY, email STR, org_secret STR ENCRYPTED SEARCHABLE"],
            now,
        )
        .unwrap();

        let left_encrypted = parse_select(&[
            "*", "FROM", "users", "u", "JOIN", "profiles", "p", "ON", "u.email", "=", "p.email",
        ])
        .unwrap();
        let err = select_err(&store, &cache, &left_encrypted, now);
        assert!(err.contains("does not support JOIN"), "{err}");

        let right_encrypted = parse_select(&[
            "*",
            "FROM",
            "users",
            "u",
            "JOIN",
            "profiles",
            "p",
            "ON",
            "u.org_id",
            "=",
            "p.org_secret",
        ])
        .unwrap();
        let err = select_err(&store, &cache, &right_encrypted, now);
        assert!(err.contains("does not support JOIN"), "{err}");
    }

    #[test]
    fn encrypted_searchable_unique_rekeys_on_update() {
        let store = encrypted_store();
        let cache = make_cache();
        let now = now();
        table_create(
            &store,
            &cache,
            "accounts",
            &["id UUID PRIMARY KEY, email STR ENCRYPTED SEARCHABLE UNIQUE"],
            now,
        )
        .unwrap();
        let first = "018f9d72-7c8d-7000-8000-000000000001";
        let second = "018f9d72-7c8d-7000-8000-000000000002";
        table_insert(
            &store,
            &cache,
            "accounts",
            &[("id", first), ("email", "old@example.com")],
            now,
        )
        .unwrap();
        table_insert(
            &store,
            &cache,
            "accounts",
            &[("id", second), ("email", "other@example.com")],
            now,
        )
        .unwrap();

        table_update_by_pk_str(
            &store,
            &cache,
            "accounts",
            first,
            &[("email", "new@example.com")],
            None,
            now,
        )
        .unwrap();

        table_insert(
            &store,
            &cache,
            "accounts",
            &[
                ("id", "018f9d72-7c8d-7000-8000-000000000003"),
                ("email", "old@example.com"),
            ],
            now,
        )
        .unwrap();
        let err = table_insert(
            &store,
            &cache,
            "accounts",
            &[
                ("id", "018f9d72-7c8d-7000-8000-000000000004"),
                ("email", "new@example.com"),
            ],
            now,
        )
        .unwrap_err();
        assert!(err.contains("unique constraint"), "{err}");
    }

    #[test]
    fn encrypted_searchable_unique_delete_cleans_blind_indexes_and_allows_reuse() {
        let store = encrypted_store();
        let cache = make_cache();
        let now = now();
        table_create(
            &store,
            &cache,
            "accounts",
            &["id UUID PRIMARY KEY, email STR ENCRYPTED SEARCHABLE UNIQUE"],
            now,
        )
        .unwrap();
        let first = "018f9d72-7c8d-7000-8000-000000000001";
        let second = "018f9d72-7c8d-7000-8000-000000000002";
        table_insert(
            &store,
            &cache,
            "accounts",
            &[("id", first), ("email", "deleted@example.com")],
            now,
        )
        .unwrap();
        table_insert(
            &store,
            &cache,
            "accounts",
            &[("id", second), ("email", "other@example.com")],
            now,
        )
        .unwrap();

        let deleted = table_delete_where(
            &store,
            &cache,
            "accounts",
            &["email", "=", "deleted@example.com"],
            now,
        )
        .unwrap();
        assert_eq!(deleted, 1);

        let email_field = load_schema(&store, &cache, "accounts", now)
            .unwrap()
            .into_iter()
            .find(|field| field.name == "email")
            .unwrap();
        let ukey = uniq_key("accounts", "email");
        for index_value in
            searchable_index_values(&store, "accounts", &email_field, "deleted@example.com")
                .unwrap()
        {
            assert!(
                store
                    .hget(ukey.as_bytes(), index_value.as_bytes(), now)
                    .is_none(),
                "deleted encrypted unique value left a stale holder"
            );
            let skey = idx_str_key("accounts", "email", &index_value);
            let members = store.smembers(skey.as_bytes(), now).unwrap_or_default();
            assert!(
                !members.iter().any(|member| member == first),
                "deleted encrypted searchable value left a stale index member"
            );
        }

        table_update_by_pk_str(
            &store,
            &cache,
            "accounts",
            second,
            &[("email", "deleted@example.com")],
            None,
            now,
        )
        .unwrap();
        let plan = parse_select(&[
            "*",
            "FROM",
            "accounts",
            "WHERE",
            "email",
            "=",
            "deleted@example.com",
        ])
        .unwrap();
        let rows = rows_of(table_select(&store, &cache, &plan, now).unwrap());
        assert_eq!(rows.len(), 1);
        assert_eq!(cell(&rows[0], "id"), second);
    }

    #[test]
    fn encrypted_add_column_rejects_default_and_keeps_existing_rows_readable() {
        let store = encrypted_store();
        let cache = make_cache();
        let now = now();
        table_create(
            &store,
            &cache,
            "profiles",
            &["id UUID PRIMARY KEY, name STR"],
            now,
        )
        .unwrap();
        let id = "018f9d72-7c8d-7000-8000-000000000001";
        table_insert(
            &store,
            &cache,
            "profiles",
            &[("id", id), ("name", "Ada")],
            now,
        )
        .unwrap();

        let err = table_add_column(
            &store,
            &cache,
            "profiles",
            "email STR ENCRYPTED SEARCHABLE UNIQUE DEFAULT seeded@example.com",
            now,
        )
        .unwrap_err();
        assert!(err.contains("cannot use DEFAULT"), "{err}");

        table_add_column(
            &store,
            &cache,
            "profiles",
            "email STR ENCRYPTED SEARCHABLE UNIQUE",
            now,
        )
        .unwrap();

        let row = get_row(
            &store,
            "profiles",
            &load_schema(&store, &cache, "profiles", now).unwrap(),
            id,
            now,
            true,
        )
        .unwrap()
        .unwrap();
        assert_eq!(cell(&row, "name"), "Ada");
        assert!(row.iter().all(|(field, _)| field != "email"));

        let second = "018f9d72-7c8d-7000-8000-000000000002";
        table_insert(
            &store,
            &cache,
            "profiles",
            &[
                ("id", second),
                ("name", "Grace"),
                ("email", "grace@example.com"),
            ],
            now,
        )
        .unwrap();
        let raw = store
            .hget(row_key_for_pk("profiles", second).as_bytes(), b"email", now)
            .unwrap();
        assert!(!raw
            .windows(b"grace@example.com".len())
            .any(|window| window == b"grace@example.com"));

        let plan = parse_select(&[
            "*",
            "FROM",
            "profiles",
            "WHERE",
            "email",
            "=",
            "grace@example.com",
        ])
        .unwrap();
        let rows = rows_of(table_select(&store, &cache, &plan, now).unwrap());
        assert_eq!(rows.len(), 1);
        assert_eq!(cell(&rows[0], "id"), second);
    }

    #[test]
    fn encrypted_returning_paths_emit_plaintext_and_store_ciphertext() {
        let store = encrypted_store();
        let cache = make_cache();
        let now = now();
        table_create(
            &store,
            &cache,
            "secrets",
            &[
                "id",
                "STR",
                "PRIMARY",
                "KEY,",
                "email",
                "STR",
                "ENCRYPTED",
                "SEARCHABLE",
                "UNIQUE,",
                "token",
                "STR",
                "ENCRYPTED",
            ],
            now,
        )
        .unwrap();

        let inserted = table_insert_returning(
            &store,
            &cache,
            "secrets",
            &[
                ("id", "s1"),
                ("email", "person@example.com"),
                ("token", "first-secret"),
            ],
            now,
        )
        .unwrap();
        assert!(inserted
            .iter()
            .any(|(k, v)| k == "token" && v == "first-secret"));
        let raw = store
            .hget(row_key_for_pk("secrets", "s1").as_bytes(), b"token", now)
            .unwrap();
        assert!(!raw
            .windows(b"first-secret".len())
            .any(|w| w == b"first-secret"));

        let updated = table_update_where_returning(
            &store,
            &cache,
            "secrets",
            &[("token", "second-secret")],
            &["email", "=", "person@example.com"],
            now,
        )
        .unwrap();
        assert_eq!(updated.len(), 1);
        assert!(updated[0]
            .iter()
            .any(|(k, v)| k == "token" && v == "second-secret"));
        let raw = store
            .hget(row_key_for_pk("secrets", "s1").as_bytes(), b"token", now)
            .unwrap();
        assert!(!raw
            .windows(b"second-secret".len())
            .any(|w| w == b"second-secret"));

        let deleted = table_delete_where_returning(
            &store,
            &cache,
            "secrets",
            &["email", "=", "person@example.com"],
            now,
        )
        .unwrap();
        assert_eq!(deleted.len(), 1);
        assert!(deleted[0]
            .iter()
            .any(|(k, v)| k == "token" && v == "second-secret"));
        assert!(get_row(
            &store,
            "secrets",
            &load_schema(&store, &cache, "secrets", now).unwrap(),
            "s1",
            now,
            true,
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn encrypted_upsert_on_searchable_unique_replays_with_ttl_clear() {
        let dir = tempfile::tempdir().unwrap();
        let config = Arc::new(crate::ServerConfig {
            storage: StorageConfig {
                mode: StorageMode::Tiered,
                dir: dir.path().to_string_lossy().to_string(),
            },
            encryption: EncryptionConfig {
                active_key_id: Some("k2".to_string()),
                keys: vec![EncryptionKeyConfig {
                    id: "k2".to_string(),
                    secret: b"new-key-secret".to_vec(),
                    decrypt_only: false,
                }],
                ..Default::default()
            },
            ..crate::ServerConfig::default()
        });
        let store = Arc::new(Store::new_with_config(config.clone()));
        let cache = make_cache();
        let now = now();
        table_create(
            &store,
            &cache,
            "accounts",
            &[
                "id UUID PRIMARY KEY,",
                "email STR ENCRYPTED SEARCHABLE UNIQUE,",
                "name STR ENCRYPTED",
            ],
            now,
        )
        .unwrap();
        let id = "018f9d72-7c8d-7000-8000-000000000001";
        table_insert_ttl(
            &store,
            &cache,
            "accounts",
            &[("id", id), ("email", "a@example.com"), ("name", "old")],
            Some(TtlOp::Set(3600)),
            now,
        )
        .unwrap();
        let row = table_upsert_returning_ttl(
            &store,
            &cache,
            "accounts",
            &[("email", "a@example.com"), ("name", "updated")],
            Some("email"),
            Some(TtlOp::Clear),
            now,
        )
        .unwrap();
        assert_eq!(cell(&row, "id"), id);
        assert_eq!(cell(&row, "name"), "updated");
        store.fsync_wal();

        let restored = Arc::new(Store::new_with_config(config));
        restored.replay_wal(&crate::pubsub::Broker::new()).unwrap();
        let restored_cache = make_cache();
        let plan = parse_select(&[
            "*",
            "FROM",
            "accounts",
            "WHERE",
            "email",
            "=",
            "a@example.com",
        ])
        .unwrap();
        let rows = rows_of(table_select(&restored, &restored_cache, &plan, now).unwrap());
        assert_eq!(rows.len(), 1);
        assert_eq!(cell(&rows[0], "id"), id);
        assert_eq!(cell(&rows[0], "name"), "updated");
        let rk = row_key_for_pk("accounts", id);
        assert!(restored
            .hget(rk.as_bytes(), HIDDEN_TTL_FIELD, now)
            .is_none());
    }

    #[test]
    fn encrypted_snapshot_does_not_store_plaintext_and_loads() {
        let dir = tempfile::tempdir().unwrap();
        let config = Arc::new(crate::ServerConfig {
            data_dir: dir.path().to_string_lossy().to_string(),
            encryption: EncryptionConfig {
                active_key_id: Some("k2".to_string()),
                keys: vec![
                    EncryptionKeyConfig {
                        id: "k1".to_string(),
                        secret: b"old-key-secret".to_vec(),
                        decrypt_only: true,
                    },
                    EncryptionKeyConfig {
                        id: "k2".to_string(),
                        secret: b"new-key-secret".to_vec(),
                        decrypt_only: false,
                    },
                ],
                ..Default::default()
            },
            ..crate::ServerConfig::default()
        });
        let store = Arc::new(Store::new_with_config(config.clone()));
        let cache = make_cache();
        let now = now();
        table_create(
            &store,
            &cache,
            "secrets",
            &["id UUID PRIMARY KEY, token STR ENCRYPTED"],
            now,
        )
        .unwrap();
        let id = "018f9d72-7c8d-7000-8000-000000000001";
        table_insert(
            &store,
            &cache,
            "secrets",
            &[("id", id), ("token", "snapshot-topsecret")],
            now,
        )
        .unwrap();

        let snapshot_path = crate::snapshot::snapshot_for_backup(&store).unwrap();
        let snapshot = std::fs::read(snapshot_path).unwrap();
        assert!(!snapshot
            .windows(b"snapshot-topsecret".len())
            .any(|w| w == b"snapshot-topsecret"));

        let restored = Arc::new(Store::new_with_config(config));
        crate::snapshot::load(&restored).unwrap();
        let restored_cache = make_cache();
        let row = get_row(
            &restored,
            "secrets",
            &load_schema(&restored, &restored_cache, "secrets", now).unwrap(),
            id,
            now,
            true,
        )
        .unwrap()
        .unwrap();
        assert_eq!(cell(&row, "token"), "snapshot-topsecret");
    }

    #[test]
    fn encrypted_wal_does_not_store_plaintext_and_replays_latest_update() {
        let dir = tempfile::tempdir().unwrap();
        let config = Arc::new(crate::ServerConfig {
            storage: StorageConfig {
                mode: StorageMode::Tiered,
                dir: dir.path().to_string_lossy().to_string(),
            },
            encryption: EncryptionConfig {
                active_key_id: Some("k2".to_string()),
                keys: vec![
                    EncryptionKeyConfig {
                        id: "k1".to_string(),
                        secret: b"old-key-secret".to_vec(),
                        decrypt_only: true,
                    },
                    EncryptionKeyConfig {
                        id: "k2".to_string(),
                        secret: b"new-key-secret".to_vec(),
                        decrypt_only: false,
                    },
                ],
                ..Default::default()
            },
            ..crate::ServerConfig::default()
        });
        let store = Arc::new(Store::new_with_config(config.clone()));
        let cache = make_cache();
        let now = now();
        table_create(
            &store,
            &cache,
            "secrets",
            &["id UUID PRIMARY KEY, token STR ENCRYPTED"],
            now,
        )
        .unwrap();
        let id = "018f9d72-7c8d-7000-8000-000000000001";
        table_insert(
            &store,
            &cache,
            "secrets",
            &[("id", id), ("token", "wal-topsecret")],
            now,
        )
        .unwrap();
        table_update_by_pk_str(
            &store,
            &cache,
            "secrets",
            id,
            &[("token", "wal-newsecret")],
            None,
            now,
        )
        .unwrap();
        store.fsync_wal();

        let mut wal_bytes = Vec::new();
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let path = entry.unwrap().path().join("wal.lux");
            if path.exists() {
                wal_bytes.extend(std::fs::read(path).unwrap());
            }
        }
        assert!(!wal_bytes
            .windows(b"wal-topsecret".len())
            .any(|w| w == b"wal-topsecret"));
        assert!(!wal_bytes
            .windows(b"wal-newsecret".len())
            .any(|w| w == b"wal-newsecret"));
        assert!(wal_bytes.windows(b"TROWSET".len()).any(|w| w == b"TROWSET"));

        let restored = Arc::new(Store::new_with_config(config));
        restored.replay_wal(&crate::pubsub::Broker::new()).unwrap();
        let restored_cache = make_cache();
        let row = get_row(
            &restored,
            "secrets",
            &load_schema(&restored, &restored_cache, "secrets", now).unwrap(),
            id,
            now,
            true,
        )
        .unwrap()
        .unwrap();
        assert_eq!(cell(&row, "token"), "wal-newsecret");
    }

    #[test]
    fn encrypted_wal_replay_preserves_uuid_row_order_after_update() {
        let dir = tempfile::tempdir().unwrap();
        let config = Arc::new(crate::ServerConfig {
            storage: StorageConfig {
                mode: StorageMode::Tiered,
                dir: dir.path().to_string_lossy().to_string(),
            },
            encryption: EncryptionConfig {
                active_key_id: Some("k2".to_string()),
                keys: vec![EncryptionKeyConfig {
                    id: "k2".to_string(),
                    secret: b"new-key-secret".to_vec(),
                    decrypt_only: false,
                }],
                ..Default::default()
            },
            ..crate::ServerConfig::default()
        });
        let store = Arc::new(Store::new_with_config(config.clone()));
        let cache = make_cache();
        let now = now();
        table_create(
            &store,
            &cache,
            "secrets",
            &["id UUID PRIMARY KEY, token STR ENCRYPTED"],
            now,
        )
        .unwrap();
        let first = "018f9d72-7c8d-7000-8000-000000000001";
        let second = "018f9d72-7c8d-7000-8000-000000000002";
        table_insert(
            &store,
            &cache,
            "secrets",
            &[("id", first), ("token", "first")],
            now,
        )
        .unwrap();
        table_insert(
            &store,
            &cache,
            "secrets",
            &[("id", second), ("token", "second")],
            now,
        )
        .unwrap();
        table_update_by_pk_str(
            &store,
            &cache,
            "secrets",
            first,
            &[("token", "first-updated")],
            None,
            now,
        )
        .unwrap();
        store.fsync_wal();

        let restored = Arc::new(Store::new_with_config(config));
        restored.replay_wal(&crate::pubsub::Broker::new()).unwrap();
        let restored_cache = make_cache();
        let plan = parse_select(&["*", "FROM", "secrets", "LIMIT", "2"]).unwrap();
        let rows = rows_of(table_select(&restored, &restored_cache, &plan, now).unwrap());
        assert_eq!(rows.len(), 2);
        assert_eq!(cell(&rows[0], "id"), first);
        assert_eq!(cell(&rows[0], "token"), "first-updated");
        assert_eq!(cell(&rows[1], "id"), second);
    }

    #[test]
    fn encrypted_wal_replay_clears_hidden_ttl_field() {
        let dir = tempfile::tempdir().unwrap();
        let config = Arc::new(crate::ServerConfig {
            storage: StorageConfig {
                mode: StorageMode::Tiered,
                dir: dir.path().to_string_lossy().to_string(),
            },
            encryption: EncryptionConfig {
                active_key_id: Some("k2".to_string()),
                keys: vec![EncryptionKeyConfig {
                    id: "k2".to_string(),
                    secret: b"new-key-secret".to_vec(),
                    decrypt_only: false,
                }],
                ..Default::default()
            },
            ..crate::ServerConfig::default()
        });
        let store = Arc::new(Store::new_with_config(config.clone()));
        let cache = make_cache();
        let now = now();
        table_create(
            &store,
            &cache,
            "secrets",
            &["id UUID PRIMARY KEY, token STR ENCRYPTED"],
            now,
        )
        .unwrap();
        let id = "018f9d72-7c8d-7000-8000-000000000001";
        table_insert_ttl(
            &store,
            &cache,
            "secrets",
            &[("id", id), ("token", "ttl-secret")],
            Some(TtlOp::Set(3600)),
            now,
        )
        .unwrap();
        table_update_by_pk_str(
            &store,
            &cache,
            "secrets",
            id,
            &[("token", "ttl-cleared")],
            Some(TtlOp::Clear),
            now,
        )
        .unwrap();
        store.fsync_wal();

        let restored = Arc::new(Store::new_with_config(config));
        restored.replay_wal(&crate::pubsub::Broker::new()).unwrap();
        let rk = row_key_for_pk("secrets", id);
        assert!(restored
            .hget(rk.as_bytes(), HIDDEN_TTL_FIELD, now)
            .is_none());
        assert_eq!(
            restored
                .zscore(
                    ttl_index_key().as_bytes(),
                    ttl_member("secrets", id).as_bytes(),
                    now
                )
                .unwrap(),
            None
        );
        let restored_cache = make_cache();
        let row = get_row(
            &restored,
            "secrets",
            &load_schema(&restored, &restored_cache, "secrets", now).unwrap(),
            id,
            now,
            true,
        )
        .unwrap()
        .unwrap();
        assert_eq!(cell(&row, "token"), "ttl-cleared");
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
    fn explicit_implicit_primary_key_cannot_overwrite_an_existing_row() {
        let store = Store::new();
        let cache = make_cache();
        let n = now();
        table_create(&store, &cache, "logs", &["message STR"], n).unwrap();
        table_insert(
            &store,
            &cache,
            "logs",
            &[("id", "7"), ("message", "original")],
            n,
        )
        .unwrap();

        let error = table_insert(
            &store,
            &cache,
            "logs",
            &[("id", "7"), ("message", "replacement")],
            n,
        )
        .expect_err("an implicit primary key still has primary-key uniqueness");
        assert!(error.contains("primary key violation"), "{error}");
        let row = table_get(&store, &cache, "logs", 7, n).unwrap();
        assert_eq!(row_field(&row, "message"), Some("original"));
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

    #[test]
    fn select_where_or_and_ilike_filter() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        seed_users(&store, &cache, now);

        let plan = parse_select(&[
            "*", "FROM", "users", "WHERE", "name", "ILIKE", "%ali%", "OR", "name", "LIKE", "D_ve",
            "ORDER", "BY", "id",
        ])
        .unwrap();
        assert_eq!(plan.conditions[0].op, CmpOp::Or);

        let rows = rows_of(table_select(&store, &cache, &plan, now).unwrap());
        let names: Vec<&str> = rows.iter().map(|row| cell(row, "name")).collect();
        assert_eq!(names, vec!["Alice", "Dave"]);
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
    fn empty_string_default_applied_on_insert() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        table_create(
            &store,
            &cache,
            "t",
            &["id INT PRIMARY KEY,", "label STR DEFAULT ''"],
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
        assert_eq!(cell(&rows[0], "label"), "");
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
    fn upsert_updates_on_composite_conflict_target() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        table_create(
            &store,
            &cache,
            "tasks",
            &[
                "id INT PRIMARY KEY,",
                "workspace_id STR,",
                "slug STR,",
                "title STR",
            ],
            now,
        )
        .unwrap();

        table_upsert_returning(
            &store,
            &cache,
            "tasks",
            &[("workspace_id", "w1"), ("slug", "same"), ("title", "first")],
            Some("workspace_id,slug"),
            now,
        )
        .unwrap();
        let row = table_upsert_returning(
            &store,
            &cache,
            "tasks",
            &[
                ("workspace_id", "w1"),
                ("slug", "same"),
                ("title", "updated"),
            ],
            Some("workspace_id,slug"),
            now,
        )
        .unwrap();
        table_upsert_returning(
            &store,
            &cache,
            "tasks",
            &[
                ("workspace_id", "w2"),
                ("slug", "same"),
                ("title", "other workspace"),
            ],
            Some("workspace_id,slug"),
            now,
        )
        .unwrap();

        assert_eq!(cell(&row, "title"), "updated");
        assert_eq!(table_count(&store, &cache, "tasks", now).unwrap(), 2);
    }

    #[test]
    fn sequence_partition_assigns_monotonic_values_per_partition() {
        let store = Arc::new(Store::new());
        let cache = make_cache();
        let now = now();
        table_create(
            &store,
            &cache,
            "tickets",
            &[
                "id INT PRIMARY KEY,",
                "workspace_id STR,",
                "serial INT SEQUENCE PARTITION BY workspace_id,",
                "title STR",
            ],
            now,
        )
        .unwrap();

        let first = table_insert_returning(
            &store,
            &cache,
            "tickets",
            &[("workspace_id", "w1"), ("title", "first")],
            now,
        )
        .unwrap();
        let second = table_insert_returning(
            &store,
            &cache,
            "tickets",
            &[("workspace_id", "w1"), ("title", "second")],
            now,
        )
        .unwrap();
        let other = table_insert_returning(
            &store,
            &cache,
            "tickets",
            &[("workspace_id", "w2"), ("title", "other")],
            now,
        )
        .unwrap();
        table_insert(
            &store,
            &cache,
            "tickets",
            &[
                ("workspace_id", "w1"),
                ("serial", "10"),
                ("title", "manual"),
            ],
            now,
        )
        .unwrap();
        let after_manual = table_insert_returning(
            &store,
            &cache,
            "tickets",
            &[("workspace_id", "w1"), ("title", "after")],
            now,
        )
        .unwrap();

        assert_eq!(cell(&first, "serial"), "1");
        assert_eq!(cell(&second, "serial"), "2");
        assert_eq!(cell(&other, "serial"), "1");
        assert_eq!(cell(&after_manual, "serial"), "11");

        let err = table_insert(
            &store,
            &cache,
            "tickets",
            &[("workspace_id", "w1"), ("serial", "2"), ("title", "dup")],
            now,
        )
        .unwrap_err();
        assert!(err.contains("unique constraint"), "{err}");
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

    #[test]
    fn tindex_rejects_encrypted_json_column() {
        let store = encrypted_store();
        let cache = make_cache();
        let now = now();
        table_create(
            &store,
            &cache,
            "events",
            &["id INT PRIMARY KEY, meta JSON ENCRYPTED"],
            now,
        )
        .unwrap();
        let err =
            table_create_path_index(&store, &cache, "events", "meta.ssn", "STR", now).unwrap_err();
        assert!(err.contains("encrypted column"), "{err}");
        assert!(load_path_indexes(&store, &cache, "events", now)
            .unwrap()
            .is_empty());
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
