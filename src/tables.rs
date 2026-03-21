use std::collections::HashSet;
use std::time::Instant;

use crate::store::Store;

#[derive(Debug, Clone, PartialEq)]
pub enum FieldType {
    Str,
    Int,
    Float,
    Ref(String),
}

#[derive(Debug, Clone)]
pub struct FieldDef {
    pub name: String,
    pub field_type: FieldType,
    pub unique: bool,
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

pub struct QueryPlan {
    pub conditions: Vec<WhereClause>,
    pub join_field: Option<String>,
    pub order_by: Option<(String, bool)>,
    pub limit: Option<usize>,
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

fn is_valid_name(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_')
}

fn parse_field_def(spec: &str) -> Result<FieldDef, String> {
    let parts: Vec<&str> = spec.splitn(3, ':').collect();
    if parts.len() < 2 {
        return Err(format!(
            "ERR invalid field spec '{}', expected field:type",
            spec
        ));
    }
    let name = parts[0].to_string();
    if !is_valid_name(&name) {
        return Err(format!("ERR invalid field name '{}'", name));
    }
    let type_str = parts[1];
    let mut unique = false;

    let field_type = if type_str.starts_with("ref(") && type_str.ends_with(')') {
        let ref_table = &type_str[4..type_str.len() - 1];
        if !is_valid_name(ref_table) {
            return Err(format!("ERR invalid referenced table name '{}'", ref_table));
        }
        FieldType::Ref(ref_table.to_string())
    } else {
        match type_str {
            "str" => FieldType::Str,
            "int" => FieldType::Int,
            "float" => FieldType::Float,
            _ => return Err(format!("ERR unknown field type '{}'", type_str)),
        }
    };

    if parts.len() == 3 {
        match parts[2] {
            "unique" => unique = true,
            _ => return Err(format!("ERR unknown field modifier '{}'", parts[2])),
        }
    }

    Ok(FieldDef {
        name,
        field_type,
        unique,
    })
}

fn encode_field_def(def: &FieldDef) -> String {
    let type_str = match &def.field_type {
        FieldType::Str => "str".to_string(),
        FieldType::Int => "int".to_string(),
        FieldType::Float => "float".to_string(),
        FieldType::Ref(t) => format!("ref:{}", t),
    };
    if def.unique {
        format!("{}:unique", type_str)
    } else {
        type_str
    }
}

fn decode_field_def(name: &str, encoded: &str) -> FieldDef {
    let parts: Vec<&str> = encoded.splitn(2, ':').collect();
    let (type_str, rest) = (parts[0], parts.get(1).copied().unwrap_or(""));

    let (field_type, unique) = match type_str {
        "str" => (FieldType::Str, rest == "unique"),
        "int" => (FieldType::Int, rest == "unique"),
        "float" => (FieldType::Float, rest == "unique"),
        "ref" => (FieldType::Ref(rest.to_string()), false),
        _ => (FieldType::Str, false),
    };

    FieldDef {
        name: name.to_string(),
        field_type,
        unique,
    }
}

fn load_schema(store: &Store, table: &str, now: Instant) -> Result<Vec<FieldDef>, String> {
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
    Ok(fields)
}

fn validate_value(field: &FieldDef, value: &str) -> Result<(), String> {
    match &field.field_type {
        FieldType::Str => Ok(()),
        FieldType::Int | FieldType::Ref(_) => {
            value
                .parse::<i64>()
                .map_err(|_| format!("ERR field '{}' expects int, got '{}'", field.name, value))?;
            Ok(())
        }
        FieldType::Float => {
            value.parse::<f64>().map_err(|_| {
                format!("ERR field '{}' expects float, got '{}'", field.name, value)
            })?;
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

fn add_to_index(store: &Store, table: &str, field: &FieldDef, value: &str, id: i64, now: Instant) {
    let id_str = id.to_string();
    match &field.field_type {
        FieldType::Int | FieldType::Float | FieldType::Ref(_) => {
            let score: f64 = value.parse().unwrap_or(0.0);
            let zkey = idx_sorted_key(table, &field.name);
            let _ = store.zadd(
                zkey.as_bytes(),
                &[(id_str.as_bytes(), score)],
                false,
                false,
                false,
                false,
                false,
                now,
            );
        }
        FieldType::Str => {
            let skey = idx_str_key(table, &field.name, value);
            let _ = store.sadd(skey.as_bytes(), &[id_str.as_bytes()], now);
        }
    }
}

fn remove_from_index(
    store: &Store,
    table: &str,
    field: &FieldDef,
    value: &str,
    id: i64,
    now: Instant,
) {
    let id_str = id.to_string();
    match &field.field_type {
        FieldType::Int | FieldType::Float | FieldType::Ref(_) => {
            let zkey = idx_sorted_key(table, &field.name);
            let _ = store.zrem(zkey.as_bytes(), &[id_str.as_bytes()], now);
        }
        FieldType::Str => {
            let skey = idx_str_key(table, &field.name, value);
            let _ = store.srem(skey.as_bytes(), &[id_str.as_bytes()], now);
        }
    }
}

pub fn table_create(
    store: &Store,
    table: &str,
    field_specs: &[&str],
    now: Instant,
) -> Result<(), String> {
    if !is_valid_name(table) {
        return Err("ERR invalid table name".to_string());
    }
    if field_specs.is_empty() {
        return Err("ERR at least one field is required".to_string());
    }

    let key = schema_key(table);
    let existing = store.hgetall(key.as_bytes(), now).unwrap_or_default();
    if !existing.is_empty() {
        return Err(format!("ERR table '{}' already exists", table));
    }

    let mut fields = Vec::new();
    let mut names_seen = HashSet::new();
    for spec in field_specs {
        let field = parse_field_def(spec)?;
        if !names_seen.insert(field.name.clone()) {
            return Err(format!("ERR duplicate field name '{}'", field.name));
        }
        fields.push(field);
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

    Ok(())
}

pub fn table_insert(
    store: &Store,
    table: &str,
    field_values: &[(&str, &str)],
    now: Instant,
) -> Result<i64, String> {
    let schema = load_schema(store, table, now)?;

    let mut provided: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
    for (k, v) in field_values {
        if !schema.iter().any(|f| f.name == *k) {
            return Err(format!("ERR unknown field '{}'", k));
        }
        provided.insert(k, v);
    }

    for field in &schema {
        let value = match provided.get(field.name.as_str()) {
            Some(v) => *v,
            None => continue,
        };

        validate_value(field, value)?;

        if let FieldType::Ref(ref ref_table) = field.field_type {
            let ref_id: i64 = value.parse().unwrap();
            let rk = row_key(ref_table, ref_id);
            let ref_row = store.hgetall(rk.as_bytes(), now).unwrap_or_default();
            if ref_row.is_empty() {
                return Err(format!(
                    "ERR foreign key violation: {}={} not found in table '{}'",
                    field.name, value, ref_table
                ));
            }
        }

        if field.unique {
            let ukey = uniq_key(table, &field.name);
            if let Some(existing) = store.hget(ukey.as_bytes(), value.as_bytes(), now) {
                let _ = existing;
                return Err(format!(
                    "ERR unique constraint violation on field '{}'",
                    field.name
                ));
            }
        }
    }

    let id = next_id(store, table, now);
    let rk = row_key(table, id);

    let mut pairs_owned: Vec<(String, String)> = Vec::new();
    for field in &schema {
        if let Some(value) = provided.get(field.name.as_str()) {
            pairs_owned.push((field.name.clone(), value.to_string()));
        }
    }

    let pair_refs: Vec<(&[u8], &[u8])> = pairs_owned
        .iter()
        .map(|(k, v)| (k.as_bytes() as &[u8], v.as_bytes() as &[u8]))
        .collect();
    store.hset(rk.as_bytes(), &pair_refs, now)?;

    let id_str = id.to_string();
    let ikey = ids_key(table);
    let _ = store.zadd(
        ikey.as_bytes(),
        &[(id_str.as_bytes(), id as f64)],
        false,
        false,
        false,
        false,
        false,
        now,
    );

    for field in &schema {
        if let Some(value) = provided.get(field.name.as_str()) {
            add_to_index(store, table, field, value, id, now);

            if field.unique {
                let ukey = uniq_key(table, &field.name);
                store.hset(
                    ukey.as_bytes(),
                    &[(value.as_bytes() as &[u8], id_str.as_bytes() as &[u8])],
                    now,
                )?;
            }
        }
    }

    Ok(id)
}

pub fn table_get(
    store: &Store,
    table: &str,
    id: i64,
    now: Instant,
) -> Result<Vec<(String, String)>, String> {
    let _schema = load_schema(store, table, now)?;
    let rk = row_key(table, id);
    let pairs = store.hgetall(rk.as_bytes(), now)?;
    if pairs.is_empty() {
        return Err(format!("ERR row {} not found in table '{}'", id, table));
    }
    let mut result: Vec<(String, String)> = pairs
        .into_iter()
        .map(|(k, v)| (k, String::from_utf8_lossy(&v).to_string()))
        .collect();
    result.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(result)
}

pub fn table_update(
    store: &Store,
    table: &str,
    id: i64,
    field_values: &[(&str, &str)],
    now: Instant,
) -> Result<(), String> {
    let schema = load_schema(store, table, now)?;
    let rk = row_key(table, id);
    let old_pairs = store.hgetall(rk.as_bytes(), now)?;
    if old_pairs.is_empty() {
        return Err(format!("ERR row {} not found in table '{}'", id, table));
    }

    let old_map: std::collections::HashMap<String, String> = old_pairs
        .into_iter()
        .map(|(k, v)| (k, String::from_utf8_lossy(&v).to_string()))
        .collect();

    for (fname, fval) in field_values {
        let field = schema
            .iter()
            .find(|f| f.name == *fname)
            .ok_or_else(|| format!("ERR unknown field '{}'", fname))?;

        validate_value(field, fval)?;

        if let FieldType::Ref(ref ref_table) = field.field_type {
            let ref_id: i64 = fval.parse().unwrap();
            let rk2 = row_key(ref_table, ref_id);
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
            if let Some(existing_id_bytes) = store.hget(ukey.as_bytes(), fval.as_bytes(), now) {
                let existing_id_str = String::from_utf8_lossy(&existing_id_bytes).to_string();
                let existing_id: i64 = existing_id_str.parse().unwrap_or(-1);
                if existing_id != id {
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
            remove_from_index(store, table, field, old_val, id, now);
            if field.unique {
                let ukey = uniq_key(table, &field.name);
                let _ = store.hdel(ukey.as_bytes(), &[old_val.as_bytes()], now);
            }
        }

        add_to_index(store, table, field, fval, id, now);
        if field.unique {
            let ukey = uniq_key(table, &field.name);
            let id_str = id.to_string();
            let _ = store.hset(
                ukey.as_bytes(),
                &[(fval.as_bytes() as &[u8], id_str.as_bytes() as &[u8])],
                now,
            );
        }
    }

    let pair_refs: Vec<(&[u8], &[u8])> = field_values
        .iter()
        .map(|(k, v)| (k.as_bytes() as &[u8], v.as_bytes() as &[u8]))
        .collect();
    store.hset(rk.as_bytes(), &pair_refs, now)?;

    Ok(())
}

pub fn table_delete(store: &Store, table: &str, id: i64, now: Instant) -> Result<(), String> {
    let schema = load_schema(store, table, now)?;
    let rk = row_key(table, id);
    let pairs = store.hgetall(rk.as_bytes(), now)?;
    if pairs.is_empty() {
        return Err(format!("ERR row {} not found in table '{}'", id, table));
    }

    let row_map: std::collections::HashMap<String, String> = pairs
        .into_iter()
        .map(|(k, v)| (k, String::from_utf8_lossy(&v).to_string()))
        .collect();

    let tlist_key = table_list_key();
    let all_tables = store
        .smembers(tlist_key.as_bytes(), now)
        .unwrap_or_default();
    for other_table in &all_tables {
        if other_table == table {
            continue;
        }
        let other_schema = match load_schema(store, other_table, now) {
            Ok(s) => s,
            Err(_) => continue,
        };
        for field in &other_schema {
            if let FieldType::Ref(ref ref_table) = field.field_type {
                if ref_table == table {
                    let zkey = idx_sorted_key(other_table, &field.name);
                    let id_f = id as f64;
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
                            "ERR cannot delete row {}: referenced by table '{}'",
                            id, other_table
                        ));
                    }
                }
            }
        }
    }

    for field in &schema {
        if let Some(val) = row_map.get(&field.name) {
            remove_from_index(store, table, field, val, id, now);
            if field.unique {
                let ukey = uniq_key(table, &field.name);
                let _ = store.hdel(ukey.as_bytes(), &[val.as_bytes()], now);
            }
        }
    }

    let ikey = ids_key(table);
    let id_str = id.to_string();
    let _ = store.zrem(ikey.as_bytes(), &[id_str.as_bytes()], now);

    store.del(&[rk.as_bytes()]);

    Ok(())
}

pub fn table_drop(store: &Store, table: &str, now: Instant) -> Result<(), String> {
    let schema = match load_schema(store, table, now) {
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

    for (id_str, _) in &all_ids {
        let id: i64 = id_str.parse().unwrap_or(0);
        let rk = row_key(table, id);
        store.del(&[rk.as_bytes()]);
    }

    for field in &schema {
        match &field.field_type {
            FieldType::Int | FieldType::Float | FieldType::Ref(_) => {
                let zkey = idx_sorted_key(table, &field.name);
                store.del(&[zkey.as_bytes()]);
            }
            FieldType::Str => {}
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

    Ok(())
}

pub fn table_count(store: &Store, table: &str, now: Instant) -> Result<i64, String> {
    let _ = load_schema(store, table, now)?;
    let ikey = ids_key(table);
    store.zcard(ikey.as_bytes(), now)
}

pub fn table_schema(store: &Store, table: &str, now: Instant) -> Result<Vec<String>, String> {
    let schema = load_schema(store, table, now)?;
    let mut result = Vec::new();
    for field in &schema {
        let type_str = match &field.field_type {
            FieldType::Str => "str".to_string(),
            FieldType::Int => "int".to_string(),
            FieldType::Float => "float".to_string(),
            FieldType::Ref(t) => format!("ref({})", t),
        };
        let mut desc = format!("{}:{}", field.name, type_str);
        if field.unique {
            desc.push_str(":unique");
        }
        result.push(desc);
    }
    Ok(result)
}

pub fn table_list(store: &Store, now: Instant) -> Vec<String> {
    let tlist = table_list_key();
    store.smembers(tlist.as_bytes(), now).unwrap_or_default()
}

fn get_all_row_ids(store: &Store, table: &str, now: Instant) -> Vec<i64> {
    let ikey = ids_key(table);
    let items = store
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
    items
        .iter()
        .filter_map(|(s, _)| s.parse::<i64>().ok())
        .collect()
}

fn get_row(store: &Store, table: &str, id: i64, now: Instant) -> Option<Vec<(String, String)>> {
    let rk = row_key(table, id);
    let pairs = store.hgetall(rk.as_bytes(), now).unwrap_or_default();
    if pairs.is_empty() {
        return None;
    }
    Some(
        pairs
            .into_iter()
            .map(|(k, v)| (k, String::from_utf8_lossy(&v).to_string()))
            .collect(),
    )
}

fn matches_condition(row: &[(String, String)], cond: &WhereClause, field_def: &FieldDef) -> bool {
    let val = match row.iter().find(|(k, _)| k == &cond.field) {
        Some((_, v)) => v.as_str(),
        None => return cond.op == CmpOp::Ne,
    };

    match &field_def.field_type {
        FieldType::Int | FieldType::Ref(_) => {
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
        FieldType::Str => match cond.op {
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
    now: Instant,
) -> Option<Vec<i64>> {
    match &field_def.field_type {
        FieldType::Str => {
            if cond.op == CmpOp::Eq {
                let skey = idx_str_key(table, &cond.field, &cond.value);
                let members = store.smembers(skey.as_bytes(), now).unwrap_or_default();
                let ids: Vec<i64> = members
                    .iter()
                    .filter_map(|s| s.parse::<i64>().ok())
                    .collect();
                return Some(ids);
            }
            None
        }
        FieldType::Int | FieldType::Float | FieldType::Ref(_) => {
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
            let results = store
                .zrangebyscore(
                    zkey.as_bytes(),
                    min,
                    max,
                    min_excl,
                    max_excl,
                    false,
                    None,
                    None,
                    false,
                    now,
                )
                .unwrap_or_default();
            let ids: Vec<i64> = results
                .iter()
                .filter_map(|(s, _)| s.parse::<i64>().ok())
                .collect();
            Some(ids)
        }
    }
}

pub type QueryRow = (i64, Vec<(String, String)>);

pub fn table_query(
    store: &Store,
    table: &str,
    plan: &QueryPlan,
    now: Instant,
) -> Result<Vec<QueryRow>, String> {
    let schema = load_schema(store, table, now)?;

    for cond in &plan.conditions {
        if !schema.iter().any(|f| f.name == cond.field) {
            return Err(format!(
                "ERR unknown field '{}' in WHERE clause",
                cond.field
            ));
        }
    }

    let mut candidate_ids: Option<Vec<i64>> = None;

    for cond in &plan.conditions {
        let field_def = schema.iter().find(|f| f.name == cond.field).unwrap();
        if let Some(ids) = candidates_from_index(store, table, cond, field_def, now) {
            let id_set: HashSet<i64> = ids.into_iter().collect();
            candidate_ids = Some(match candidate_ids {
                Some(existing) => existing
                    .into_iter()
                    .filter(|id| id_set.contains(id))
                    .collect(),
                None => id_set.into_iter().collect(),
            });
        }
    }

    let ids = match candidate_ids {
        Some(ids) => ids,
        None => get_all_row_ids(store, table, now),
    };

    let mut results: Vec<(i64, Vec<(String, String)>)> = Vec::new();
    for id in ids {
        let row = match get_row(store, table, id, now) {
            Some(r) => r,
            None => continue,
        };

        let mut passes = true;
        for cond in &plan.conditions {
            let field_def = schema.iter().find(|f| f.name == cond.field).unwrap();
            if !matches_condition(&row, cond, field_def) {
                passes = false;
                break;
            }
        }
        if passes {
            results.push((id, row));
        }
    }

    if let Some((ref order_field, ascending)) = plan.order_by {
        let field_def = schema.iter().find(|f| f.name == *order_field);
        results.sort_by(|a, b| {
            let av =
                a.1.iter()
                    .find(|(k, _)| k == order_field)
                    .map(|(_, v)| v.as_str())
                    .unwrap_or("");
            let bv =
                b.1.iter()
                    .find(|(k, _)| k == order_field)
                    .map(|(_, v)| v.as_str())
                    .unwrap_or("");
            let cmp = if let Some(fd) = field_def {
                match &fd.field_type {
                    FieldType::Int | FieldType::Ref(_) => {
                        let ai: i64 = av.parse().unwrap_or(0);
                        let bi: i64 = bv.parse().unwrap_or(0);
                        ai.cmp(&bi)
                    }
                    FieldType::Float => {
                        let af: f64 = av.parse().unwrap_or(0.0);
                        let bf: f64 = bv.parse().unwrap_or(0.0);
                        af.partial_cmp(&bf).unwrap_or(std::cmp::Ordering::Equal)
                    }
                    FieldType::Str => av.cmp(bv),
                }
            } else {
                av.cmp(bv)
            };
            if ascending {
                cmp
            } else {
                cmp.reverse()
            }
        });
    }

    if let Some(limit) = plan.limit {
        results.truncate(limit);
    }

    if let Some(ref join_field_name) = plan.join_field {
        let field_def = schema
            .iter()
            .find(|f| f.name == *join_field_name)
            .ok_or_else(|| format!("ERR unknown field '{}' for JOIN", join_field_name))?;
        let ref_table = match &field_def.field_type {
            FieldType::Ref(t) => t.clone(),
            _ => {
                return Err(format!(
                    "ERR field '{}' is not a ref() field",
                    join_field_name
                ))
            }
        };

        let ref_schema = load_schema(store, &ref_table, now)?;

        for (_, row) in results.iter_mut() {
            let ref_id_str = row
                .iter()
                .find(|(k, _)| k == join_field_name)
                .map(|(_, v)| v.clone())
                .unwrap_or_default();
            let ref_id: i64 = ref_id_str.parse().unwrap_or(0);
            if let Some(ref_row) = get_row(store, &ref_table, ref_id, now) {
                for (rk, rv) in ref_row {
                    row.push((format!("{}.{}", ref_table, rk), rv));
                }
            }
        }
        let _ = ref_schema;
    }

    Ok(results)
}

pub fn parse_query_args(args: &[&str], start: usize) -> Result<QueryPlan, String> {
    let mut conditions = Vec::new();
    let mut join_field = None;
    let mut order_by = None;
    let mut limit = None;
    let mut i = start;

    while i < args.len() {
        let keyword = args[i].to_uppercase();
        match keyword.as_str() {
            "WHERE" => {
                i += 1;
                loop {
                    if i + 2 >= args.len() {
                        return Err("ERR incomplete WHERE clause".to_string());
                    }
                    let field = args[i].to_string();
                    let op_str = args[i + 1];
                    let value = args[i + 2].to_string();
                    let op = match op_str {
                        "=" => CmpOp::Eq,
                        "!=" => CmpOp::Ne,
                        ">" => CmpOp::Gt,
                        "<" => CmpOp::Lt,
                        ">=" => CmpOp::Ge,
                        "<=" => CmpOp::Le,
                        _ => return Err(format!("ERR unknown operator '{}'", op_str)),
                    };
                    conditions.push(WhereClause { field, op, value });
                    i += 3;
                    if i < args.len() && args[i].to_uppercase() == "AND" {
                        i += 1;
                    } else {
                        break;
                    }
                }
            }
            "JOIN" => {
                i += 1;
                if i >= args.len() {
                    return Err("ERR JOIN requires a field name".to_string());
                }
                join_field = Some(args[i].to_string());
                i += 1;
            }
            "ORDER" => {
                i += 1;
                if i >= args.len() || args[i].to_uppercase() != "BY" {
                    return Err("ERR expected BY after ORDER".to_string());
                }
                i += 1;
                if i >= args.len() {
                    return Err("ERR ORDER BY requires a field name".to_string());
                }
                let field = args[i].to_string();
                i += 1;
                let ascending = if i < args.len() {
                    let dir = args[i].to_uppercase();
                    if dir == "ASC" {
                        i += 1;
                        true
                    } else if dir == "DESC" {
                        i += 1;
                        false
                    } else {
                        true
                    }
                } else {
                    true
                };
                order_by = Some((field, ascending));
            }
            "LIMIT" => {
                i += 1;
                if i >= args.len() {
                    return Err("ERR LIMIT requires a number".to_string());
                }
                let n: usize = args[i]
                    .parse()
                    .map_err(|_| "ERR LIMIT value must be a positive integer".to_string())?;
                limit = Some(n);
                i += 1;
            }
            _ => {
                return Err(format!("ERR unexpected keyword '{}'", args[i]));
            }
        }
    }

    Ok(QueryPlan {
        conditions,
        join_field,
        order_by,
        limit,
    })
}
