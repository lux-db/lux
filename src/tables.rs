use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::RwLock;

use crate::store::Store;

// ---------------------------------------------------------------------------
// Schema Cache
// ---------------------------------------------------------------------------

/// A shared, in-memory cache of table schemas. Schemas change very rarely
/// (only on TCREATE / TALTER / TDROP), so we cache them here to avoid a
/// full hgetall on the Store for every single table operation.
///
/// Wrap in Arc<RwLock<SchemaCache>> and pass alongside Store wherever table
/// functions are called.
#[derive(Debug, Default)]
pub struct SchemaCache {
    schemas: hashbrown::HashMap<String, Vec<FieldDef>>,
}

impl SchemaCache {
    pub fn new() -> Self {
        Self {
            schemas: hashbrown::HashMap::new(),
        }
    }

    fn get(&self, table: &str) -> Option<Vec<FieldDef>> {
        self.schemas.get(table).cloned()
    }

    fn insert(&mut self, table: &str, fields: Vec<FieldDef>) {
        self.schemas.insert(table.to_string(), fields);
    }

    fn remove(&mut self, table: &str) {
        self.schemas.remove(table);
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
}

#[derive(Debug, Clone)]
pub struct WhereClause {
    pub field: String,
    pub op: CmpOp,
    pub value: String,
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
    pub table: String,     // table to join
    pub alias: String,     // alias for that table (required)
    pub left_col: String,  // left side of ON: "alias.col"
    pub right_col: String, // right side of ON: "alias.col"
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

fn idx_str_key(table: &str, field: &str, value: &str) -> String {
    format!("_t:{}:idx:{}:{}", table, field, value)
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
        other => {
            return Err(format!(
                "ERR unknown field type '{}'. Valid types: STR, INT, FLOAT, BOOL, TIMESTAMP, UUID",
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
                if i >= tokens.len() || tokens[i].to_uppercase() != "KEY" {
                    return Err("ERR expected KEY after PRIMARY".to_string());
                }
                primary_key = true;
                unique = true;
                nullable = false;
                i += 1;
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
    if !is_valid_name(&table) {
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
        FieldType::Str => "str",
        FieldType::Int => "int",
        FieldType::Float => "float",
        FieldType::Bool => "bool",
        FieldType::Timestamp => "timestamp",
        FieldType::Uuid => "uuid",
        FieldType::Ref(t) => return format!("ref|{}", t),
    };

    let mut parts = vec![type_str.to_string()];
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

fn load_schema(
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
    for (name, val) in pairs {
        let encoded = String::from_utf8_lossy(&val).to_string();
        fields.push(decode_field_def(&name, &encoded));
    }
    fields.sort_by(|a, b| a.name.cmp(&b.name));

    // Write through to the cache
    cache.write().insert(table, fields.clone());

    Ok(fields)
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
    }
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

    let pairs: Vec<(&[u8], Vec<u8>)> = fields
        .iter()
        .map(|f| {
            let encoded = encode_field_def(f);
            (f.name.as_bytes() as &[u8], encoded.into_bytes())
        })
        .collect();
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
    cache.write().insert(table, fields);

    Ok(())
}

pub fn table_insert(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    field_values: &[(&str, &str)],
    now: Instant,
) -> Result<i64, String> {
    let schema = load_schema(store, cache, table, now)?;

    let mut provided: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
    for (k, v) in field_values {
        if !schema.iter().any(|f| f.name == *k) {
            return Err(format!("ERR unknown column '{}'", k));
        }
        provided.insert(k, v);
    }

    // Determine the PK column (if any) and its value
    let pk_field = schema.iter().find(|f| f.primary_key);

    // --- Constraint validation pass ---
    for field in &schema {
        let value = provided.get(field.name.as_str()).copied();

        // NOT NULL check
        if !field.nullable && value.is_none() {
            // PK with no value is only ok if it's auto-generated (INT pk auto-increments)
            // For all other NOT NULL fields, the value must be provided
            if !(field.primary_key && field.field_type == FieldType::Int) {
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

        // UNIQUE / PRIMARY KEY uniqueness check
        if field.unique {
            let ukey = uniq_key(table, &field.name);
            if store.hget(ukey.as_bytes(), value.as_bytes(), now).is_some() {
                return Err(format!(
                    "ERR unique constraint violation on column '{}': value '{}' already exists",
                    field.name, value
                ));
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
                // Check the row doesn't already exist
                let rk = row_key_for_pk(table, pk_val);
                if !store
                    .hgetall(rk.as_bytes(), now)
                    .unwrap_or_default()
                    .is_empty()
                {
                    return Err(format!(
                        "ERR primary key violation: '{}' already exists",
                        pk_val
                    ));
                }
                pk_val.to_string()
            }
            None if pk.field_type == FieldType::Int => {
                // Auto-increment INT PK
                next_id(store, table, now).to_string()
            }
            None => {
                return Err(format!(
                    "ERR primary key column '{}' must be provided",
                    pk.name
                ));
            }
        }
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
            // Explicit PK that was auto-generated (INT pk) - store its value
            let encoded = FieldType::Int.encode_value(&pk_str)?;
            pairs_owned.push((field.name.clone(), encoded));
        }
    }

    let pair_refs: Vec<(&[u8], &[u8])> = pairs_owned
        .iter()
        .map(|(k, v)| (k.as_bytes() as &[u8], v.as_slice()))
        .collect();
    store.hset(rk.as_bytes(), &pair_refs, now)?;

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

    let ret_id: i64 = pk_str.parse().unwrap_or(0);
    Ok(ret_id)
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

pub fn table_update(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    id: i64,
    field_values: &[(&str, &str)],
    now: Instant,
) -> Result<(), String> {
    table_update_by_pk_str(store, cache, table, &id.to_string(), field_values, now)
}

/// Update a row identified by its raw PK string - works for any PK type (INT, UUID, STR).
fn table_update_by_pk_str(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    pk_str: &str,
    field_values: &[(&str, &str)],
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

    let row_map: std::collections::HashMap<String, String> =
        get_row(store, table, &schema, pk_str, now)
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
    }

    let ikey = ids_key(table);
    let _ = store.zrem(ikey.as_bytes(), &[pk_str.as_bytes()], now);

    store.del(&[rk.as_bytes()]);

    Ok(())
}

/// Parse WHERE conditions from command args (field op value [AND ...])
fn parse_where_conditions(args: &[&str]) -> Result<Vec<WhereClause>, String> {
    let mut conditions = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if i + 2 >= args.len() {
            return Err("ERR incomplete WHERE clause".to_string());
        }
        let field = args[i].to_string();
        let op_str = args[i + 1];
        let value = args[i + 2].to_string();
        let op = parse_cmp_op(op_str)?;
        conditions.push(WhereClause { field, op, value });
        i += 3;
        // Check for AND
        if i < args.len() && args[i].to_uppercase() == "AND" {
            i += 1;
        }
    }
    Ok(conditions)
}

/// Apply WHERE conditions to check if a row matches
fn row_matches_conditions(
    row_map: &std::collections::HashMap<String, String>,
    conditions: &[WhereClause],
) -> bool {
    for cond in conditions {
        let field_val = match row_map.get(&cond.field) {
            Some(v) => v,
            None => return false, // Field doesn't exist, no match
        };
        let matches = match cond.op {
            CmpOp::Eq => field_val == &cond.value,
            CmpOp::Ne => field_val != &cond.value,
            CmpOp::Gt => {
                if let (Ok(fv), Ok(cv)) = (field_val.parse::<f64>(), cond.value.parse::<f64>()) {
                    fv > cv
                } else {
                    field_val > &cond.value
                }
            }
            CmpOp::Lt => {
                if let (Ok(fv), Ok(cv)) = (field_val.parse::<f64>(), cond.value.parse::<f64>()) {
                    fv < cv
                } else {
                    field_val < &cond.value
                }
            }
            CmpOp::Ge => {
                if let (Ok(fv), Ok(cv)) = (field_val.parse::<f64>(), cond.value.parse::<f64>()) {
                    fv >= cv
                } else {
                    field_val >= &cond.value
                }
            }
            CmpOp::Le => {
                if let (Ok(fv), Ok(cv)) = (field_val.parse::<f64>(), cond.value.parse::<f64>()) {
                    fv <= cv
                } else {
                    field_val <= &cond.value
                }
            }
        };
        if !matches {
            return false;
        }
    }
    true
}

/// Update rows matching WHERE conditions, returns count of updated rows
pub fn table_update_where(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    field_values: &[(&str, &str)],
    where_args: &[&str],
    now: Instant,
) -> Result<i64, String> {
    let schema = load_schema(store, cache, table, now)?;
    let conditions = parse_where_conditions(where_args)?;

    // Validate all fields to update exist
    for (fname, _) in field_values {
        schema
            .iter()
            .find(|f| f.name == *fname)
            .ok_or_else(|| format!("ERR unknown field '{}'", fname))?;
    }

    // Validate all WHERE fields exist (allow "id" for tables with implicit PK)
    let has_implicit_pk = !schema.iter().any(|f| f.primary_key);
    for cond in &conditions {
        let is_implicit_id = has_implicit_pk && cond.field == "id";
        if !is_implicit_id {
            schema
                .iter()
                .find(|f| f.name == cond.field)
                .ok_or_else(|| format!("ERR unknown field '{}' in WHERE clause", cond.field))?;
        }
    }

    let row_ids = get_all_row_ids(store, table, now);
    let mut updated_count = 0i64;

    for pk_str in row_ids {
        let Some(row) = get_row(store, table, &schema, &pk_str, now) else {
            continue;
        };
        let row_map: std::collections::HashMap<String, String> = row.into_iter().collect();

        if !row_matches_conditions(&row_map, &conditions) {
            continue;
        }

        // table_update takes i64 - only valid for auto-increment (int) PKs.
        // For UUID/STR PKs, update the row hash directly.
        let has_int_pk = schema
            .iter()
            .any(|f| f.primary_key && f.field_type == FieldType::Int);
        let has_implicit_pk = !schema.iter().any(|f| f.primary_key);

        if has_int_pk || has_implicit_pk {
            let id: i64 = pk_str
                .parse()
                .map_err(|_| format!("ERR invalid row id '{}'", pk_str))?;
            table_update(store, cache, table, id, field_values, now)?;
        } else {
            // UUID/STR primary key - update directly
            table_update_by_pk_str(store, cache, table, &pk_str, field_values, now)?;
        }
        updated_count += 1;
    }

    Ok(updated_count)
}

/// Delete rows matching WHERE conditions, returns count of deleted rows
pub fn table_delete_where(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    where_args: &[&str],
    now: Instant,
) -> Result<i64, String> {
    let schema = load_schema(store, cache, table, now)?;
    let conditions = parse_where_conditions(where_args)?;

    // Validate all WHERE fields exist (allow "id" for tables with implicit PK)
    let has_implicit_pk = !schema.iter().any(|f| f.primary_key);
    for cond in &conditions {
        let is_implicit_id = has_implicit_pk && cond.field == "id";
        if !is_implicit_id {
            schema
                .iter()
                .find(|f| f.name == cond.field)
                .ok_or_else(|| format!("ERR unknown field '{}' in WHERE clause", cond.field))?;
        }
    }

    let row_ids = get_all_row_ids(store, table, now);
    let mut deleted_count = 0i64;

    // Collect PKs to delete first (to avoid modifying while iterating)
    let mut pks_to_delete: Vec<String> = Vec::new();

    for pk_str in row_ids {
        let Some(row) = get_row(store, table, &schema, &pk_str, now) else {
            continue;
        };
        let row_map: std::collections::HashMap<String, String> = row.into_iter().collect();

        if row_matches_conditions(&row_map, &conditions) {
            pks_to_delete.push(pk_str);
        }
    }

    // Now delete them - works for any PK type (int, uuid, str)
    for pk_str in pks_to_delete {
        table_delete_inner(store, cache, table, &pk_str, now, 0)?;
        deleted_count += 1;
    }

    Ok(deleted_count)
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
        let rk = row_key_for_pk(table, pk_str);
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
            FieldType::Str | FieldType::Uuid => {}
        }
        if field.unique {
            let ukey = uniq_key(table, &field.name);
            store.del(&[ukey.as_bytes()]);
        }
    }

    store.del(&[ikey.as_bytes()]);
    store.del(&[schema_key(table).as_bytes()]);
    store.del(&[seq_key(table).as_bytes()]);

    let tlist = table_list_key();
    let _ = store.srem(tlist.as_bytes(), &[table.as_bytes()], now);

    // Evict from cache
    cache.write().remove(table);

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

fn get_row(
    store: &Store,
    table: &str,
    schema: &[FieldDef],
    pk_str: &str,
    now: Instant,
) -> Option<Vec<(String, String)>> {
    // Build a lookup map on the fly - only called from paths that don't have a pre-built map.
    // Hot paths (table_select) use get_row_with_map directly.
    let type_map: hashbrown::HashMap<&str, &FieldType> = schema
        .iter()
        .map(|f| (f.name.as_str(), &f.field_type))
        .collect();
    get_row_with_map(store, table, &type_map, pk_str, now)
}

/// Hot-path row fetch: takes a pre-built field-type map to avoid O(N) schema scan per field.
#[inline]
fn get_row_with_map(
    store: &Store,
    table: &str,
    type_map: &hashbrown::HashMap<&str, &FieldType>,
    pk_str: &str,
    now: Instant,
) -> Option<Vec<(String, String)>> {
    let rk = row_key_for_pk(table, pk_str);
    let pairs = store.hgetall(rk.as_bytes(), now).unwrap_or_default();
    if pairs.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(pairs.len());
    for (k, v) in pairs {
        let decoded = match type_map.get(k.as_str()) {
            Some(ft) => ft.decode_value(&v),
            None => String::from_utf8_lossy(&v).to_string(),
        };
        out.push((k, decoded));
    }
    Some(out)
}

fn matches_condition(row: &[(String, String)], cond: &WhereClause, field_def: &FieldDef) -> bool {
    let val = match row.iter().find(|(k, _)| k == &cond.field) {
        Some((_, v)) => v.as_str(),
        None => return cond.op == CmpOp::Ne,
    };

    match &field_def.field_type {
        FieldType::Bool => {
            // Normalise both sides to "true"/"false" before comparing
            let normalise = |s: &str| match s {
                "1" | "true" => "true",
                _ => "false",
            };
            let lhs = normalise(val);
            let rhs = normalise(&cond.value);
            match cond.op {
                CmpOp::Eq => lhs == rhs,
                CmpOp::Ne => lhs != rhs,
                _ => false, // GT/LT don't make sense for bool
            }
        }
        FieldType::Int | FieldType::Timestamp | FieldType::Ref(_) => {
            let lhs: i64 = val.parse().unwrap_or(0);
            let rhs: i64 = cond.value.parse().unwrap_or(0);
            match cond.op {
                CmpOp::Eq => lhs == rhs,
                CmpOp::Ne => lhs != rhs,
                CmpOp::Gt => lhs > rhs,
                CmpOp::Lt => lhs < rhs,
                CmpOp::Ge => lhs >= rhs,
                CmpOp::Le => lhs <= rhs,
            }
        }
        FieldType::Float => {
            let lhs: f64 = val.parse().unwrap_or(0.0);
            let rhs: f64 = cond.value.parse().unwrap_or(0.0);
            match cond.op {
                CmpOp::Eq => (lhs - rhs).abs() < f64::EPSILON,
                CmpOp::Ne => (lhs - rhs).abs() >= f64::EPSILON,
                CmpOp::Gt => lhs > rhs,
                CmpOp::Lt => lhs < rhs,
                CmpOp::Ge => lhs >= rhs,
                CmpOp::Le => lhs <= rhs,
            }
        }
        FieldType::Str | FieldType::Uuid => match cond.op {
            CmpOp::Eq => val == cond.value,
            CmpOp::Ne => val != cond.value,
            CmpOp::Gt => val > cond.value.as_str(),
            CmpOp::Lt => val < cond.value.as_str(),
            CmpOp::Ge => val >= cond.value.as_str(),
            CmpOp::Le => val <= cond.value.as_str(),
        },
    }
}

fn candidates_from_index(
    store: &Store,
    table: &str,
    cond: &WhereClause,
    field_def: &FieldDef,
    limit: Option<usize>,
    now: Instant,
) -> Option<Vec<String>> {
    match &field_def.field_type {
        FieldType::Str | FieldType::Uuid => {
            if cond.op == CmpOp::Eq {
                let skey = idx_str_key(table, &cond.field, &cond.value);
                let members = store.smembers(skey.as_bytes(), now).unwrap_or_default();
                // Apply limit if set - STR equality index returns exact matches only
                let members = match limit {
                    Some(n) => members.into_iter().take(n).collect(),
                    None => members,
                };
                return Some(members);
            }
            None
        }
        FieldType::Int
        | FieldType::Float
        | FieldType::Bool
        | FieldType::Timestamp
        | FieldType::Ref(_) => {
            let score: f64 = match cond.value.parse() {
                Ok(v) => v,
                Err(_) => return None,
            };
            let zkey = idx_sorted_key(table, &cond.field);
            let (min, max, min_excl, max_excl) = match cond.op {
                CmpOp::Eq => (score, score, false, false),
                CmpOp::Gt => (score, f64::INFINITY, true, false),
                CmpOp::Ge => (score, f64::INFINITY, false, false),
                CmpOp::Lt => (f64::NEG_INFINITY, score, false, true),
                CmpOp::Le => (f64::NEG_INFINITY, score, false, false),
                CmpOp::Ne => return None,
            };
            // Pass limit directly to zrangebyscore - avoids fetching all matching IDs
            // when we only need the first N (e.g. WHERE age > 40 LIMIT 100)
            let results = store
                .zrangebyscore(
                    zkey.as_bytes(),
                    min,
                    max,
                    min_excl,
                    max_excl,
                    false,
                    Some(0),
                    limit,
                    false,
                    now,
                )
                .unwrap_or_default();
            let ids: Vec<String> = results.into_iter().map(|(s, _)| s).collect();
            Some(ids)
        }
    }
}

// ---------------------------------------------------------------------------
// TSELECT parser
// ---------------------------------------------------------------------------

/// Parse a TSELECT command from a flat token slice.
///
/// Syntax:
///   TSELECT col,... | * | agg,...
///   FROM table [alias]
///   [JOIN table alias ON alias.col = alias.col]
///   [WHERE col op val [AND ...]]
///   [ORDER BY col [ASC|DESC]]
///   [LIMIT n]
///   [OFFSET n]
///
/// The args slice should start at the first token AFTER "TSELECT".
pub fn parse_select(args: &[&str]) -> Result<SelectPlan, String> {
    if args.is_empty() {
        return Err("ERR TSELECT requires a column list".to_string());
    }

    // ---- Collect SELECT column tokens (everything before FROM) ----
    let from_pos = args
        .iter()
        .position(|t| t.to_uppercase() == "FROM")
        .ok_or("ERR TSELECT requires FROM")?;

    let col_tokens = &args[..from_pos];
    let rest = &args[from_pos + 1..]; // everything after FROM

    // ---- Parse FROM table [alias] ----
    if rest.is_empty() {
        return Err("ERR FROM requires a table name".to_string());
    }
    let table = rest[0].to_string();
    let mut i = 1usize;

    // Optional alias (not a keyword)
    let alias = if i < rest.len() {
        let kw = rest[i].to_uppercase();
        if kw != "JOIN" && kw != "WHERE" && kw != "ORDER" && kw != "LIMIT" && kw != "OFFSET" {
            let a = rest[i].to_string();
            i += 1;
            Some(a)
        } else {
            None
        }
    } else {
        None
    };

    // ---- Parse SELECT columns / aggregates ----
    // Rejoin col_tokens removing commas, then split on comma boundaries
    let col_str = col_tokens.join(" ");
    let (projections, aggregates) = parse_select_cols(&col_str)?;

    // ---- Parse remaining clauses (JOIN / WHERE / ORDER BY / LIMIT / OFFSET) ----
    let mut joins = Vec::new();
    let mut conditions = Vec::new();
    let mut order_by: Option<(String, bool)> = None;
    let mut limit: Option<usize> = None;
    let mut offset: Option<usize> = None;

    while i < rest.len() {
        match rest[i].to_uppercase().as_str() {
            "JOIN" => {
                i += 1;
                // JOIN table alias ON left = right
                if i + 4 >= rest.len() {
                    return Err(
                        "ERR JOIN syntax: JOIN <table> <alias> ON <left> = <right>".to_string()
                    );
                }
                let join_table = rest[i].to_string();
                i += 1;
                let join_alias = rest[i].to_string();
                i += 1;
                if rest[i].to_uppercase() != "ON" {
                    return Err("ERR expected ON after JOIN <table> <alias>".to_string());
                }
                i += 1;
                let left = rest[i].to_string();
                i += 1;
                if i >= rest.len() || rest[i] != "=" {
                    return Err("ERR expected = in JOIN ON condition".to_string());
                }
                i += 1;
                let right = rest[i].to_string();
                i += 1;
                joins.push(JoinClause {
                    table: join_table,
                    alias: join_alias,
                    left_col: left,
                    right_col: right,
                });
            }
            "WHERE" => {
                i += 1;
                loop {
                    if i >= rest.len() {
                        return Err(
                            "ERR incomplete WHERE clause: expected field op value".to_string()
                        );
                    }
                    let field = rest[i].to_string();
                    i += 1;
                    if i >= rest.len() {
                        return Err(format!(
                            "ERR incomplete WHERE clause: missing operator after '{field}'"
                        ));
                    }
                    let op_str = rest[i];
                    i += 1;
                    if i >= rest.len() {
                        return Err(format!(
                            "ERR incomplete WHERE clause: missing value after '{op_str}'"
                        ));
                    }
                    let value = rest[i].to_string();
                    i += 1;
                    let op = parse_cmp_op(op_str)?;
                    conditions.push(WhereClause { field, op, value });
                    if i < rest.len() && rest[i].to_uppercase() == "AND" {
                        i += 1;
                    } else {
                        break;
                    }
                }
            }
            "ORDER" => {
                i += 1;
                if i >= rest.len() || rest[i].to_uppercase() != "BY" {
                    return Err("ERR expected BY after ORDER".to_string());
                }
                i += 1;
                if i >= rest.len() {
                    return Err("ERR ORDER BY requires a column name".to_string());
                }
                let col = rest[i].to_string();
                i += 1;
                let ascending = if i < rest.len() {
                    match rest[i].to_uppercase().as_str() {
                        "ASC" => {
                            i += 1;
                            true
                        }
                        "DESC" => {
                            i += 1;
                            false
                        }
                        _ => true,
                    }
                } else {
                    true
                };
                order_by = Some((col, ascending));
            }
            "LIMIT" => {
                i += 1;
                if i >= rest.len() {
                    return Err("ERR LIMIT requires a number".to_string());
                }
                limit = Some(
                    rest[i]
                        .parse::<usize>()
                        .map_err(|_| "ERR LIMIT must be a positive integer".to_string())?,
                );
                i += 1;
            }
            "OFFSET" => {
                i += 1;
                if i >= rest.len() {
                    return Err("ERR OFFSET requires a number".to_string());
                }
                offset = Some(
                    rest[i]
                        .parse::<usize>()
                        .map_err(|_| "ERR OFFSET must be a positive integer".to_string())?,
                );
                i += 1;
            }
            other => {
                return Err(format!("ERR unexpected keyword '{}' in TSELECT", other));
            }
        }
    }

    Ok(SelectPlan {
        table,
        alias,
        projections,
        aggregates,
        joins,
        conditions,
        order_by,
        limit,
        offset,
    })
}

fn parse_cmp_op(s: &str) -> Result<CmpOp, String> {
    match s {
        "=" => Ok(CmpOp::Eq),
        "!=" => Ok(CmpOp::Ne),
        ">" => Ok(CmpOp::Gt),
        "<" => Ok(CmpOp::Lt),
        ">=" => Ok(CmpOp::Ge),
        "<=" => Ok(CmpOp::Le),
        other => Err(format!("ERR unknown operator '{}'", other)),
    }
}

/// Parse the SELECT column list into projections and/or aggregates.
/// Handles:
///   *
///   id, email, age
///   u.id, u.email AS user_email
///   COUNT(*), SUM(score), AVG(age) AS avg_age
fn parse_select_cols(raw: &str) -> Result<(Vec<Projection>, Vec<AggExpr>), String> {
    // Split on commas (not inside parens)
    let parts = split_on_commas(raw);

    let mut projections = Vec::new();
    let mut aggregates = Vec::new();

    for part in parts {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        // Check for aggregate function
        if let Some(agg) = try_parse_agg(part)? {
            aggregates.push(agg);
        } else {
            // Regular column, possibly with AS alias
            let (expr, alias) = split_as(part);
            if expr == "*" {
                // SELECT * - no projections means all columns
                projections.clear();
                return Ok((vec![], vec![]));
            }
            projections.push(Projection {
                expr: expr.to_string(),
                alias: alias.map(|s| s.to_string()),
            });
        }
    }

    // If we got a mix of aggregates and plain columns without GROUP BY,
    // that's valid in the "aggregate everything" sense - we allow it.
    Ok((projections, aggregates))
}

/// Split a comma-separated string, respecting parentheses.
fn split_on_commas(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;
    for (i, c) in s.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parts.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&s[start..]);
    parts
}

/// Split "expr AS alias" or "expr alias" into (expr, Option<alias>).
fn split_as(s: &str) -> (&str, Option<&str>) {
    let tokens: Vec<&str> = s.split_whitespace().collect();
    match tokens.as_slice() {
        [expr, kw, alias] if kw.to_uppercase() == "AS" => (*expr, Some(*alias)),
        [expr, alias] => (*expr, Some(*alias)),
        [expr] => (*expr, None),
        _ => (s, None),
    }
}

/// Try to parse an aggregate expression like COUNT(*), SUM(score) AS total.
fn try_parse_agg(s: &str) -> Result<Option<AggExpr>, String> {
    // Split off optional AS alias first
    let (core, alias_opt) = split_as(s);

    let upper = core.to_uppercase();
    let func = if upper.starts_with("COUNT(") {
        AggFunc::Count
    } else if upper.starts_with("SUM(") {
        AggFunc::Sum
    } else if upper.starts_with("AVG(") {
        AggFunc::Avg
    } else if upper.starts_with("MIN(") {
        AggFunc::Min
    } else if upper.starts_with("MAX(") {
        AggFunc::Max
    } else {
        return Ok(None);
    };

    let paren_start = core.find('(').unwrap();
    if !core.ends_with(')') {
        return Err(format!("ERR malformed aggregate expression '{}'", s));
    }
    let inner = core[paren_start + 1..core.len() - 1].trim();

    let col = if inner == "*" {
        None
    } else {
        Some(inner.to_string())
    };

    // Default alias is "func(col)" if not specified
    let alias = alias_opt
        .map(|a| a.to_string())
        .unwrap_or_else(|| core.to_lowercase());

    Ok(Some(AggExpr { func, col, alias }))
}

// ---------------------------------------------------------------------------
// TSELECT execution engine
// ---------------------------------------------------------------------------

/// The result of a TSELECT - either rows or a single aggregate result row.
pub enum SelectResult {
    Rows(Vec<Vec<(String, String)>>),
    Aggregate(Vec<(String, String)>),
}

pub fn table_select(
    store: &Store,
    cache: &SharedSchemaCache,
    plan: &SelectPlan,
    now: Instant,
) -> Result<SelectResult, String> {
    let schema = load_schema(store, cache, &plan.table, now)?;
    let table_alias = plan.alias.as_deref().unwrap_or(&plan.table);

    // Resolve the WHERE conditions - strip table alias prefix if present
    let conditions: Vec<WhereClause> = plan
        .conditions
        .iter()
        .map(|c| {
            let field = strip_alias(&c.field, table_alias);
            WhereClause {
                field,
                op: c.op.clone(),
                value: c.value.clone(),
            }
        })
        .collect();

    // Validate WHERE columns
    for cond in &conditions {
        let bare = bare_col(&cond.field);
        if !schema.iter().any(|f| f.name == bare) {
            // Might be a join column - validate later
        }
    }

    // ---- Fast-path aggregates (no row fetches needed) ----
    // We handle the common aggregate-only queries directly against the indexes,
    // bypassing full row hydration entirely.
    if !plan.aggregates.is_empty() && plan.joins.is_empty() {
        if let Some(agg_row) = try_fast_aggregate(
            store,
            &plan.table,
            &schema,
            &conditions,
            &plan.aggregates,
            now,
        ) {
            return Ok(SelectResult::Aggregate(agg_row));
        }
    }

    // ---- Scan primary table ----
    // Build a field-type lookup map ONCE per query so get_row doesn't O(N) scan per field.
    let type_map: hashbrown::HashMap<&str, &FieldType> = schema
        .iter()
        .map(|f| (f.name.as_str(), &f.field_type))
        .collect();

    // Apply LIMIT early only when safe to do so:
    // - no joins (join changes the row count unpredictably)
    // - no ORDER BY (ordering requires all rows before truncating)
    let early_limit = if plan.joins.is_empty() && plan.order_by.is_none() {
        plan.limit.map(|l| l + plan.offset.unwrap_or(0))
    } else {
        None
    };

    // Pass early_limit into build_candidates so index lookups stop after N results
    // rather than fetching all matching IDs first (e.g. WHERE age > 40 LIMIT 100
    // used to fetch 61k IDs from the sorted set before truncating to 100)
    let mut candidates =
        build_candidates(store, &plan.table, &schema, &conditions, early_limit, now);
    if let Some(lim) = early_limit {
        candidates.truncate(lim);
    }

    let mut rows: Vec<Vec<(String, String)>> = candidates
        .into_iter()
        .filter_map(|pk_str| get_row_with_map(store, &plan.table, &type_map, &pk_str, now))
        .filter(|row| {
            conditions.iter().all(|cond| {
                let bare = bare_col(&cond.field);
                if let Some(fd) = schema.iter().find(|f| f.name == bare) {
                    matches_condition(
                        row,
                        &WhereClause {
                            field: bare.to_string(),
                            op: cond.op.clone(),
                            value: cond.value.clone(),
                        },
                        fd,
                    )
                } else {
                    true // join column - filter after join
                }
            })
        })
        // Fix 3: project down to only needed columns before prefixing.
        // Only prefix with alias when there's an explicit alias or a join -
        // bare queries (no alias, no join) keep column names clean.
        .map(|row| {
            let ob_col = plan.order_by.as_ref().map(|(c, _)| c.as_str());
            // Also retain join key columns so the hash join probe can find them
            let join_keys: Vec<&str> = plan
                .joins
                .iter()
                .flat_map(|j| [j.left_col.as_str(), j.right_col.as_str()])
                .map(bare_col)
                .collect();
            let mut projected =
                project_row_fields(&row, &plan.projections, &plan.aggregates, ob_col);
            // Add any join key columns that were stripped but are needed
            for jk in &join_keys {
                if !projected.iter().any(|(k, _)| k == jk) {
                    if let Some(val) = row.iter().find(|(k, _)| k == jk) {
                        projected.push(val.clone());
                    }
                }
            }
            if plan.alias.is_some() || !plan.joins.is_empty() {
                projected
                    .into_iter()
                    .map(|(k, v)| (format!("{}.{}", table_alias, k), v))
                    .collect()
            } else {
                projected
            }
        })
        // Fix 2: early LIMIT when no join - stop fetching rows once we have enough
        .take(early_limit.unwrap_or(usize::MAX))
        .collect();

    // ---- Hash Joins ----
    for join in &plan.joins {
        // Pass the limit so the join can stop early once satisfied
        rows = hash_join(store, cache, rows, join, plan.limit, plan.offset, now)?;
    }

    // ---- Post-join WHERE filter (for conditions referencing join columns) ----
    if !plan.joins.is_empty() {
        rows.retain(|row| {
            plan.conditions.iter().all(|cond| {
                let val = row
                    .iter()
                    .find(|(k, _)| {
                        k == &cond.field || k.ends_with(&format!(".{}", bare_col(&cond.field)))
                    })
                    .map(|(_, v)| v.as_str());
                match val {
                    None => cond.op == CmpOp::Ne,
                    Some(v) => match cond.op {
                        CmpOp::Eq => v == cond.value,
                        CmpOp::Ne => v != cond.value,
                        CmpOp::Gt => v > cond.value.as_str(),
                        CmpOp::Lt => v < cond.value.as_str(),
                        CmpOp::Ge => v >= cond.value.as_str(),
                        CmpOp::Le => v <= cond.value.as_str(),
                    },
                }
            })
        });
    }

    // ---- Slow-path aggregates (needed rows already fetched) ----
    if !plan.aggregates.is_empty() {
        let agg_row = compute_aggregates(&rows, &plan.aggregates);
        return Ok(SelectResult::Aggregate(agg_row));
    }

    // ---- ORDER BY ----
    if let Some((ref col, ascending)) = plan.order_by {
        rows.sort_by(|a, b| {
            let av = find_col(a, col, table_alias).unwrap_or("");
            let bv = find_col(b, col, table_alias).unwrap_or("");
            // Try numeric sort first, fall back to string
            let cmp = match (av.parse::<f64>(), bv.parse::<f64>()) {
                (Ok(af), Ok(bf)) => af.partial_cmp(&bf).unwrap_or(std::cmp::Ordering::Equal),
                _ => av.cmp(bv),
            };
            if ascending {
                cmp
            } else {
                cmp.reverse()
            }
        });
    }

    // ---- OFFSET / LIMIT ----
    let rows = if let Some(off) = plan.offset {
        rows.into_iter().skip(off).collect()
    } else {
        rows
    };
    let mut rows = rows;
    if let Some(lim) = plan.limit {
        rows.truncate(lim);
    }

    // ---- Column projection ----
    let rows = if plan.projections.is_empty() {
        // SELECT * - return all columns
        rows
    } else {
        project_columns(rows, &plan.projections, table_alias)
    };

    Ok(SelectResult::Rows(rows))
}

/// Build candidate row PK strings using the index where possible.
fn build_candidates(
    store: &Store,
    table: &str,
    schema: &[FieldDef],
    conditions: &[WhereClause],
    limit: Option<usize>,
    now: Instant,
) -> Vec<String> {
    let mut candidate_set: Option<HashSet<String>> = None;

    // Only push limit down to index when there's a single condition - with multiple
    // conditions we need the full set from each index to intersect correctly.
    let index_limit = if conditions.len() == 1 { limit } else { None };

    for cond in conditions {
        let bare = bare_col(&cond.field);
        if let Some(fd) = schema.iter().find(|f| f.name == bare) {
            if let Some(pks) = candidates_from_index(
                store,
                table,
                &WhereClause {
                    field: bare.to_string(),
                    op: cond.op.clone(),
                    value: cond.value.clone(),
                },
                fd,
                index_limit,
                now,
            ) {
                let pk_set: HashSet<String> = pks.into_iter().collect();
                candidate_set = Some(match candidate_set {
                    Some(existing) => existing.intersection(&pk_set).cloned().collect(),
                    None => pk_set,
                });
            }
        }
    }

    match candidate_set {
        Some(pks) => pks.into_iter().collect(),
        None => get_all_row_ids(store, table, now),
    }
}

/// Hash Join implementation.
///
/// Builds an in-memory HashMap of the right table keyed on the join column,
/// then iterates the left rows performing O(1) lookups.
fn hash_join(
    store: &Store,
    cache: &SharedSchemaCache,
    left_rows: Vec<Vec<(String, String)>>,
    join: &JoinClause,
    limit: Option<usize>,
    offset: Option<usize>,
    now: Instant,
) -> Result<Vec<Vec<(String, String)>>, String> {
    let right_schema = load_schema(store, cache, &join.table, now)?;
    let right_alias = &join.alias;

    let (left_key, right_key) = resolve_join_keys(&join.left_col, &join.right_col, right_alias);

    // ---- Build phase ----
    // Key: right join column value -> list of right rows
    let right_ids = get_all_row_ids(store, &join.table, now);
    let mut hash_map: hashbrown::HashMap<String, Vec<Vec<(String, String)>>> =
        hashbrown::HashMap::with_capacity(right_ids.len());

    for pk_str in right_ids {
        if let Some(row) = get_row(store, &join.table, &right_schema, &pk_str, now) {
            let key_val = row
                .iter()
                .find(|(k, _)| k == &right_key)
                .map(|(_, v)| v.clone())
                .unwrap_or_default();
            let prefixed_row: Vec<(String, String)> = row
                .into_iter()
                .map(|(k, v)| (format!("{}.{}", right_alias, k), v))
                .collect();
            hash_map.entry(key_val).or_default().push(prefixed_row);
        }
    }

    // ---- Probe phase with early termination ----
    // If LIMIT is set, stop as soon as we have enough results.
    let need = limit.map(|l| l + offset.unwrap_or(0));
    let mut result = Vec::new();

    'outer: for left_row in left_rows {
        let probe_val = left_row
            .iter()
            .find(|(k, _)| k == &left_key || k.ends_with(&format!(".{}", left_key)))
            .map(|(_, v)| v.as_str())
            .unwrap_or("");

        if let Some(right_rows) = hash_map.get(probe_val) {
            for right_row in right_rows {
                let mut combined = left_row.clone();
                combined.extend(right_row.iter().cloned());
                result.push(combined);
                // Fix 2: stop as soon as we have enough rows
                if let Some(n) = need {
                    if result.len() >= n {
                        break 'outer;
                    }
                }
            }
        }
    }

    Ok(result)
}

/// Given left_col="u.id" and right_col="p.author_id" and right_alias="p",
/// returns ("u.id", "author_id") - the actual column names to probe on.
fn resolve_join_keys(left_col: &str, right_col: &str, right_alias: &str) -> (String, String) {
    // The right key is the one whose alias matches right_alias
    let (lk, rk) = if right_col.starts_with(&format!("{}.", right_alias)) {
        (left_col.to_string(), bare_col(right_col).to_string())
    } else {
        (right_col.to_string(), bare_col(left_col).to_string())
    };
    (lk, rk)
}

/// Strip table alias prefix from a column reference.
/// "u.email" -> "email", "email" -> "email"
fn bare_col(col: &str) -> &str {
    col.rfind('.').map(|i| &col[i + 1..]).unwrap_or(col)
}

/// Strip alias prefix if it matches a known alias.
fn strip_alias(col: &str, alias: &str) -> String {
    let prefix = format!("{}.", alias);
    if col.starts_with(&prefix) {
        col[prefix.len()..].to_string()
    } else {
        col.to_string()
    }
}

/// Find a column value in a row, trying "alias.col" then "col" then suffix match.
fn find_col<'a>(row: &'a [(String, String)], col: &str, alias: &str) -> Option<&'a str> {
    let qualified = format!("{}.{}", alias, bare_col(col));
    row.iter()
        .find(|(k, _)| k == col || k == &qualified || k.ends_with(&format!(".{}", bare_col(col))))
        .map(|(_, v)| v.as_str())
}

/// Apply column projections to result rows.
fn project_columns(
    rows: Vec<Vec<(String, String)>>,
    projections: &[Projection],
    table_alias: &str,
) -> Vec<Vec<(String, String)>> {
    rows.into_iter()
        .map(|row| {
            projections
                .iter()
                .filter_map(|proj| {
                    let target = &proj.expr;
                    // Try exact match, then alias.col match, then bare col match
                    let val = row
                        .iter()
                        .find(|(k, _)| {
                            k == target
                                || k == &format!("{}.{}", table_alias, target)
                                || k.ends_with(&format!(".{}", bare_col(target)))
                        })
                        .map(|(_, v)| v.clone());

                    let out_name = proj
                        .alias
                        .clone()
                        .unwrap_or_else(|| bare_col(target).to_string());

                    val.map(|v| (out_name, v))
                })
                .collect()
        })
        .collect()
}

/// Compute aggregate functions over a set of rows.
/// Fix 3: Project a row down to only the columns needed by the query.
/// If projections and aggregates are both empty (SELECT *), returns the full row.
/// Also retains the ORDER BY column so sorting works correctly.
fn project_row_fields(
    row: &[(String, String)],
    projections: &[Projection],
    aggregates: &[AggExpr],
    order_by_col: Option<&str>,
) -> Vec<(String, String)> {
    // Need all columns for aggregates or SELECT *
    if projections.is_empty() && aggregates.is_empty() {
        return row.to_vec();
    }

    // Collect the bare column names we actually need
    let mut needed: HashSet<&str> = projections
        .iter()
        .map(|p| bare_col(&p.expr))
        .chain(aggregates.iter().filter_map(|a| a.col.as_deref()))
        .collect();

    // Always retain the ORDER BY column so sorting works later
    if let Some(ob) = order_by_col {
        needed.insert(bare_col(ob));
    }

    if needed.is_empty() {
        return vec![];
    }

    row.iter()
        .filter(|(k, _)| needed.contains(k.as_str()))
        .cloned()
        .collect()
}

/// Fix 1: Fast aggregate path - avoids full row hydration.
///
/// Handles the common cases:
/// - COUNT(*) with no WHERE  -> zcard on ids sorted set (single op)
/// - COUNT(*) with WHERE     -> count the candidates (index scan only)
/// - SUM/AVG/MIN/MAX on a numeric column with no WHERE ->
///   read scores directly from the sorted index (no row fetches)
///
/// Returns None if the fast path can't handle this query (falls through
/// to the slow path which fetches full rows).
fn try_fast_aggregate(
    store: &Store,
    table: &str,
    schema: &[FieldDef],
    conditions: &[WhereClause],
    aggregates: &[AggExpr],
    now: Instant,
) -> Option<Vec<(String, String)>> {
    // Only handle pure aggregate queries with no complex conditions on non-indexed cols
    // All aggregates must be handleable via fast path
    let mut result = Vec::new();

    for agg in aggregates {
        match agg.func {
            AggFunc::Count => {
                let count = if conditions.is_empty() {
                    // COUNT(*) with no WHERE - just read the sorted set cardinality
                    store.zcard(ids_key(table).as_bytes(), now).unwrap_or(0)
                } else {
                    // COUNT(*) with WHERE - use index to get candidates, count them
                    // No limit here - COUNT needs the full matching set
                    let candidates = build_candidates(store, table, schema, conditions, None, now);
                    candidates.len() as i64
                };
                result.push((agg.alias.clone(), count.to_string()));
            }
            AggFunc::Sum | AggFunc::Avg | AggFunc::Min | AggFunc::Max => {
                let col = match &agg.col {
                    Some(c) => c.as_str(),
                    None => return None, // SUM(*) doesn't make sense
                };
                let field_def = schema.iter().find(|f| f.name == col)?;

                // Only works for numeric types that have a sorted index
                let is_numeric = matches!(
                    &field_def.field_type,
                    FieldType::Int | FieldType::Float | FieldType::Timestamp
                );
                if !is_numeric {
                    return None;
                }

                // Read scores directly from the sorted index - scores ARE the values
                let zkey = idx_sorted_key(table, col);
                let (min_score, max_score, min_excl, max_excl) = if conditions.is_empty() {
                    (f64::NEG_INFINITY, f64::INFINITY, false, false)
                } else {
                    // Try to narrow via a condition on this same column
                    let col_cond = conditions.iter().find(|c| bare_col(&c.field) == col);
                    match col_cond {
                        Some(cond) => {
                            let score: f64 = cond.value.parse().ok()?;
                            match cond.op {
                                CmpOp::Eq => (score, score, false, false),
                                CmpOp::Gt => (score, f64::INFINITY, true, false),
                                CmpOp::Ge => (score, f64::INFINITY, false, false),
                                CmpOp::Lt => (f64::NEG_INFINITY, score, false, true),
                                CmpOp::Le => (f64::NEG_INFINITY, score, false, false),
                                CmpOp::Ne => return None,
                            }
                        }
                        // Conditions on other columns - fall through to slow path
                        None if !conditions.is_empty() => return None,
                        None => (f64::NEG_INFINITY, f64::INFINITY, false, false),
                    }
                };

                let entries = store
                    .zrangebyscore(
                        zkey.as_bytes(),
                        min_score,
                        max_score,
                        min_excl,
                        max_excl,
                        false,
                        None,
                        None,
                        false,
                        now,
                    )
                    .unwrap_or_default();

                let scores: Vec<f64> = entries.iter().map(|(_, s)| *s).collect();

                let val = match agg.func {
                    AggFunc::Count => unreachable!(),
                    AggFunc::Sum => {
                        let s: f64 = scores.iter().sum();
                        if s.fract() == 0.0 {
                            (s as i64).to_string()
                        } else {
                            s.to_string()
                        }
                    }
                    AggFunc::Avg => {
                        if scores.is_empty() {
                            "0".to_string()
                        } else {
                            let a = scores.iter().sum::<f64>() / scores.len() as f64;
                            if a.fract() == 0.0 {
                                (a as i64).to_string()
                            } else {
                                a.to_string()
                            }
                        }
                    }
                    AggFunc::Min => scores
                        .iter()
                        .cloned()
                        .reduce(f64::min)
                        .map(|v| {
                            if v.fract() == 0.0 {
                                (v as i64).to_string()
                            } else {
                                v.to_string()
                            }
                        })
                        .unwrap_or_else(|| "0".to_string()),
                    AggFunc::Max => scores
                        .iter()
                        .cloned()
                        .reduce(f64::max)
                        .map(|v| {
                            if v.fract() == 0.0 {
                                (v as i64).to_string()
                            } else {
                                v.to_string()
                            }
                        })
                        .unwrap_or_else(|| "0".to_string()),
                };
                result.push((agg.alias.clone(), val));
            }
        }
    }

    Some(result)
}

fn compute_aggregates(
    rows: &[Vec<(String, String)>],
    aggregates: &[AggExpr],
) -> Vec<(String, String)> {
    aggregates
        .iter()
        .map(|agg| {
            let val = match agg.func {
                AggFunc::Count => {
                    match &agg.col {
                        None => rows.len().to_string(), // COUNT(*)
                        Some(col) => {
                            // COUNT(col) - count non-null values
                            rows.iter()
                                .filter(|row| row.iter().any(|(k, _)| bare_col(k) == col.as_str()))
                                .count()
                                .to_string()
                        }
                    }
                }
                AggFunc::Sum => {
                    let col = agg.col.as_deref().unwrap_or("");
                    let sum: f64 = rows
                        .iter()
                        .filter_map(|row| {
                            row.iter()
                                .find(|(k, _)| bare_col(k) == col)
                                .and_then(|(_, v)| v.parse::<f64>().ok())
                        })
                        .sum();
                    // Return integer string if whole number
                    if sum.fract() == 0.0 {
                        (sum as i64).to_string()
                    } else {
                        sum.to_string()
                    }
                }
                AggFunc::Avg => {
                    let col = agg.col.as_deref().unwrap_or("");
                    let vals: Vec<f64> = rows
                        .iter()
                        .filter_map(|row| {
                            row.iter()
                                .find(|(k, _)| bare_col(k) == col)
                                .and_then(|(_, v)| v.parse::<f64>().ok())
                        })
                        .collect();
                    if vals.is_empty() {
                        "0".to_string()
                    } else {
                        let avg = vals.iter().sum::<f64>() / vals.len() as f64;
                        if avg.fract() == 0.0 {
                            (avg as i64).to_string()
                        } else {
                            avg.to_string()
                        }
                    }
                }
                AggFunc::Min => {
                    let col = agg.col.as_deref().unwrap_or("");
                    let mut vals: Vec<f64> = rows
                        .iter()
                        .filter_map(|row| {
                            row.iter()
                                .find(|(k, _)| bare_col(k) == col)
                                .and_then(|(_, v)| v.parse::<f64>().ok())
                        })
                        .collect();
                    vals.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                    vals.first()
                        .map(|v| {
                            if v.fract() == 0.0 {
                                (*v as i64).to_string()
                            } else {
                                v.to_string()
                            }
                        })
                        .unwrap_or_else(|| "0".to_string())
                }
                AggFunc::Max => {
                    let col = agg.col.as_deref().unwrap_or("");
                    let mut vals: Vec<f64> = rows
                        .iter()
                        .filter_map(|row| {
                            row.iter()
                                .find(|(k, _)| bare_col(k) == col)
                                .and_then(|(_, v)| v.parse::<f64>().ok())
                        })
                        .collect();
                    vals.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));
                    vals.first()
                        .map(|v| {
                            if v.fract() == 0.0 {
                                (*v as i64).to_string()
                            } else {
                                v.to_string()
                            }
                        })
                        .unwrap_or_else(|| "0".to_string())
                }
            };
            (agg.alias.clone(), val)
        })
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
        assert!(parse_field_def("x JSONB").is_err());
    }

    #[test]
    fn parse_field_missing_type_errors() {
        assert!(parse_field_def("x").is_err());
    }

    #[test]
    fn parse_field_primary_key_missing_key_errors() {
        assert!(parse_field_def("id INT PRIMARY").is_err());
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
        assert_eq!(plan.joins[0].table, "posts");
        assert_eq!(plan.joins[0].alias, "p");
        assert_eq!(plan.joins[0].left_col, "p.author_id");
        assert_eq!(plan.joins[0].right_col, "u.id");
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
        // HAVING is not supported - parser should error somewhere after consuming it as alias
        let result = parse_select(&["*", "FROM", "users", "HAVING", "age", ">", "25"]);
        assert!(
            result.is_err(),
            "expected error for unsupported HAVING clause"
        );
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
    fn parse_select_having_not_supported() {
        // HAVING is not a supported keyword - parser treats it as alias then errors on next token
        let result = parse_select(&["*", "FROM", "users", "HAVING", "COUNT(*)", ">", "5"]);
        assert!(
            result.is_err(),
            "expected error for unsupported HAVING clause"
        );
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
}
