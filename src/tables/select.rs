use super::*;

/// Candidate count at or above which a full scan fans its per-row work out
/// across cores (below this, the rayon overhead isn't worth it).
const PARALLEL_SCAN_MIN: usize = 1024;

pub(crate) fn get_row(
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
pub(crate) fn get_row_with_map(
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

/// Type-aware equality between a stored value and a candidate, mirroring the
/// per-type `Eq` semantics of `matches_condition`. Used by `IN`/`NOT IN`.
pub(crate) fn elem_eq(field_type: &FieldType, lhs: &str, rhs: &str) -> bool {
    match field_type {
        FieldType::Bool => {
            let normalise = |s: &str| matches!(s, "1" | "true");
            normalise(lhs) == normalise(rhs)
        }
        FieldType::Int | FieldType::Timestamp | FieldType::Ref(_) => {
            lhs.parse::<i64>().unwrap_or(0) == rhs.parse::<i64>().unwrap_or(0)
        }
        FieldType::Float => {
            (lhs.parse::<f64>().unwrap_or(0.0) - rhs.parse::<f64>().unwrap_or(0.0)).abs()
                < f64::EPSILON
        }
        FieldType::Str
        | FieldType::Uuid
        | FieldType::Vector(_)
        | FieldType::Json
        | FieldType::Array => lhs == rhs,
    }
}

/// Result of walking a dotted path into a JSON value.
pub(crate) enum JsonResolve<'a> {
    /// Every segment resolved to a present value (which may be JSON null).
    Resolved(&'a serde_json::Value),
    /// A key (or array index) along the path was missing.
    Absent,
    /// A segment tried to descend into a scalar/null (e.g. `a.b` where `a` is 5).
    Invalid,
}

/// Walk a dotted path (`a.b.c`) into a JSON value. Numeric segments index into
/// arrays (`tags.0`). Absent vs Invalid are distinguished but both mean
/// "not VALID" / non-match for filtering.
pub(crate) fn json_path_get<'a>(root: &'a serde_json::Value, path: &str) -> JsonResolve<'a> {
    let mut cur = root;
    for seg in path.split('.') {
        match cur {
            serde_json::Value::Object(map) => match map.get(seg) {
                Some(v) => cur = v,
                None => return JsonResolve::Absent,
            },
            serde_json::Value::Array(arr) => match seg.parse::<usize>() {
                Ok(idx) => match arr.get(idx) {
                    Some(v) => cur = v,
                    None => return JsonResolve::Absent,
                },
                Err(_) => return JsonResolve::Invalid,
            },
            _ => return JsonResolve::Invalid,
        }
    }
    JsonResolve::Resolved(cur)
}

/// Evaluate a WHERE condition whose field is a `jsoncol.dotted.path`.
/// Semantics: an unresolved/null path is a non-match for every comparison op
/// (never an error); `IS VALID` means the path resolves to a present, non-null
/// value (existence, NOT truthiness, so 0/false/"" are VALID).
pub(crate) fn eval_json_path_condition(
    row: &[(String, String)],
    root: &str,
    path: &str,
    cond: &WhereClause,
) -> bool {
    let raw = match row.iter().find(|(k, _)| k == root) {
        Some((_, v)) => v.as_str(),
        None => return cond.op == CmpOp::IsNotValid,
    };
    let parsed: serde_json::Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(_) => return cond.op == CmpOp::IsNotValid,
    };
    let resolved = json_path_get(&parsed, path);
    let present_non_null = matches!(&resolved, JsonResolve::Resolved(v) if !v.is_null());

    match cond.op {
        CmpOp::IsValid => return present_non_null,
        CmpOp::IsNotValid => return !present_non_null,
        CmpOp::Contains => {
            return matches!(
                &resolved,
                JsonResolve::Resolved(serde_json::Value::Array(arr))
                    if arr.iter().any(|el| json_scalar_string(el).as_deref()
                        == Some(cond.value.as_str()))
            );
        }
        _ => {}
    }

    // Every comparison implicitly requires VALID.
    if !present_non_null {
        return false;
    }
    let JsonResolve::Resolved(v) = resolved else {
        return false;
    };
    // Only JSON scalars are comparable; objects/arrays are non-matching.
    let actual = match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        _ => return false,
    };
    match cond.op {
        CmpOp::In => cond
            .values
            .iter()
            .any(|rhs| compare_condition_value(&actual, &CmpOp::Eq, rhs)),
        CmpOp::NotIn => !cond
            .values
            .iter()
            .any(|rhs| compare_condition_value(&actual, &CmpOp::Eq, rhs)),
        _ => compare_condition_value(&actual, &cond.op, &cond.value),
    }
}

/// Compare a resolved binary-JSON scalar against a condition, matching the
/// text-path semantics exactly (reuses `compare_condition_value`).
pub(crate) fn eval_scalar_binary(v: &crate::jsonb::JsonbRef, cond: &WhereClause) -> bool {
    use crate::jsonb::JsonbRef;
    let actual: String = match v {
        JsonbRef::Str(s) => (*s).to_string(),
        JsonbRef::I64(i) => i.to_string(),
        JsonbRef::F64(f) => serde_json::Number::from_f64(*f)
            .map(|n| n.to_string())
            .unwrap_or_default(),
        JsonbRef::Bool(b) => if *b { "true" } else { "false" }.to_string(),
        _ => return false,
    };
    match cond.op {
        CmpOp::In => cond
            .values
            .iter()
            .any(|rhs| compare_condition_value(&actual, &CmpOp::Eq, rhs)),
        CmpOp::NotIn => !cond
            .values
            .iter()
            .any(|rhs| compare_condition_value(&actual, &CmpOp::Eq, rhs)),
        _ => compare_condition_value(&actual, &cond.op, &cond.value),
    }
}

/// Evaluate a JSON dot-path condition directly against the stored binary bytes
/// (zero-alloc walk; no `serde_json::Value` tree). `raw` is the column's bytes.
pub(crate) fn eval_json_path_binary(raw: Option<&[u8]>, path: &str, cond: &WhereClause) -> bool {
    use crate::jsonb::{get_path, JsonbRef, Resolve};
    let Some(raw) = raw else {
        return cond.op == CmpOp::IsNotValid;
    };
    let resolved = get_path(raw, path);
    let present = matches!(&resolved, Resolve::Found(v) if !v.is_null());
    match cond.op {
        CmpOp::IsValid => return present,
        CmpOp::IsNotValid => return !present,
        CmpOp::Contains => {
            return matches!(
                &resolved,
                Resolve::Found(JsonbRef::Array(arr)) if crate::jsonb::array_contains(arr, &cond.value)
            );
        }
        _ => {}
    }
    if !present {
        return false;
    }
    match resolved {
        Resolve::Found(v) => eval_scalar_binary(&v, cond),
        _ => false,
    }
}

/// Evaluate a condition on a whole JSON/ARRAY column (no dot-path) against the
/// stored binary. Handles CONTAINS membership and whole-document equality.
pub(crate) fn eval_json_whole_binary(raw: Option<&[u8]>, cond: &WhereClause) -> bool {
    let Some(raw) = raw else {
        return cond.op == CmpOp::Ne;
    };
    match cond.op {
        CmpOp::Contains => crate::jsonb::array_contains(raw, &cond.value),
        CmpOp::Eq => crate::jsonb::to_json_string(raw) == cond.value,
        CmpOp::Ne => crate::jsonb::to_json_string(raw) != cond.value,
        _ => false,
    }
}

/// Store-driven WHERE evaluation: fetches only the fields a condition needs
/// (HGET, not full-row HGETALL) and walks JSON columns as binary. Lets the scan
/// filter cheaply and hydrate the full row only for survivors.
pub(crate) fn row_passes_conditions(
    store: &Store,
    table: &str,
    schema: &[FieldDef],
    implicit_id: Option<&FieldDef>,
    pk: &str,
    conditions: &[WhereClause],
    now: Instant,
) -> bool {
    let rk = row_key_for_pk(table, pk);
    conditions.iter().all(|cond| {
        // JSON/ARRAY dot-path => walk the stored binary.
        if let Some((root, rest)) = cond.field.split_once('.') {
            if schema.iter().any(|f| {
                f.name == root && matches!(f.field_type, FieldType::Json | FieldType::Array)
            }) {
                let raw = store.hget(rk.as_bytes(), root.as_bytes(), now);
                return eval_json_path_binary(raw.as_deref(), rest, cond);
            }
        }
        let bare = bare_col(&cond.field);
        if let Some(fd) = schema.iter().find(|f| f.name == bare) {
            if matches!(fd.field_type, FieldType::Json | FieldType::Array) {
                let raw = store.hget(rk.as_bytes(), bare.as_bytes(), now);
                return eval_json_whole_binary(raw.as_deref(), cond);
            }
            return match store.hget(rk.as_bytes(), bare.as_bytes(), now) {
                Some(b) => {
                    let val = fd.field_type.decode_value(&b);
                    let row = [(bare.to_string(), val)];
                    matches_condition(
                        &row,
                        &WhereClause {
                            field: bare.to_string(),
                            op: cond.op.clone(),
                            value: cond.value.clone(),
                            values: cond.values.clone(),
                        },
                        fd,
                    )
                }
                None => matches!(cond.op, CmpOp::Ne | CmpOp::IsNull),
            };
        }
        if bare == "id" {
            if let Some(fd) = implicit_id {
                return match store.hget(rk.as_bytes(), b"id", now) {
                    Some(b) => {
                        let val = fd.field_type.decode_value(&b);
                        let row = [("id".to_string(), val)];
                        matches_condition(
                            &row,
                            &WhereClause {
                                field: "id".to_string(),
                                op: cond.op.clone(),
                                value: cond.value.clone(),
                                values: cond.values.clone(),
                            },
                            fd,
                        )
                    }
                    None => matches!(cond.op, CmpOp::Ne | CmpOp::IsNull),
                };
            }
            return true;
        }
        // Unknown column (e.g. a join column) - not filtered at this stage.
        true
    })
}

pub(crate) fn matches_condition(
    row: &[(String, String)],
    cond: &WhereClause,
    field_def: &FieldDef,
) -> bool {
    let val = match row.iter().find(|(k, _)| k == &cond.field) {
        Some((_, v)) => v.as_str(),
        // Column absent from the row: it is NULL. `!=` and `IS NULL` match;
        // everything else (including `IS NOT NULL`) does not.
        None => return matches!(cond.op, CmpOp::Ne | CmpOp::IsNull),
    };

    // List-membership and VALID/NULL ops are handled before the per-type comparison.
    match cond.op {
        // Column is present, so it is not NULL.
        CmpOp::IsNull => return false,
        CmpOp::IsNotNull => return true,
        CmpOp::In => {
            return cond
                .values
                .iter()
                .any(|v| elem_eq(&field_def.field_type, val, v))
        }
        CmpOp::NotIn => {
            return !cond
                .values
                .iter()
                .any(|v| elem_eq(&field_def.field_type, val, v))
        }
        // VALID applies to JSON dot-paths, which are intercepted before this fn.
        // On a plain scalar column there is no path to resolve, so non-match.
        CmpOp::IsValid | CmpOp::IsNotValid => return false,
        // CONTAINS on a whole ARRAY/JSON column: membership over array elements.
        CmpOp::Contains => return json_array_contains(val, &cond.value),
        _ => {}
    }

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
                _ => false,
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
                _ => false,
            }
        }
        FieldType::Str
        | FieldType::Uuid
        | FieldType::Vector(_)
        | FieldType::Json
        | FieldType::Array => match cond.op {
            CmpOp::Eq => val == cond.value,
            CmpOp::Ne => val != cond.value,
            CmpOp::Gt => val > cond.value.as_str(),
            CmpOp::Lt => val < cond.value.as_str(),
            CmpOp::Ge => val >= cond.value.as_str(),
            CmpOp::Le => val <= cond.value.as_str(),
            _ => false,
        },
    }
}

pub(crate) fn candidates_from_index(
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
        // JSON/ARRAY columns carry only declared path indexes, handled separately.
        FieldType::Vector(_) | FieldType::Json | FieldType::Array => None,
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
                CmpOp::Ne
                | CmpOp::In
                | CmpOp::NotIn
                | CmpOp::IsValid
                | CmpOp::IsNotValid
                | CmpOp::IsNull
                | CmpOp::IsNotNull
                | CmpOp::Contains => return None,
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

pub(crate) fn candidates_from_implicit_id(
    store: &Store,
    table: &str,
    cond: &WhereClause,
    limit: Option<usize>,
    now: Instant,
) -> Option<Vec<String>> {
    let score: f64 = match cond.value.parse() {
        Ok(v) => v,
        Err(_) => return None,
    };
    let (min, max, min_excl, max_excl) = match cond.op {
        CmpOp::Eq => (score, score, false, false),
        CmpOp::Gt => (score, f64::INFINITY, true, false),
        CmpOp::Ge => (score, f64::INFINITY, false, false),
        CmpOp::Lt => (f64::NEG_INFINITY, score, false, true),
        CmpOp::Le => (f64::NEG_INFINITY, score, false, false),
        CmpOp::Ne
        | CmpOp::In
        | CmpOp::NotIn
        | CmpOp::IsValid
        | CmpOp::IsNotValid
        | CmpOp::IsNull
        | CmpOp::IsNotNull
        | CmpOp::Contains => return None,
    };

    let results = store
        .zrangebyscore(
            ids_key(table).as_bytes(),
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
    Some(results.into_iter().map(|(s, _)| s).collect())
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
        if !is_select_clause_keyword(rest[i]) {
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
    let mut group_by = Vec::new();
    let mut having = Vec::new();
    let mut near: Option<NearClause> = None;
    let mut order_by: Option<(String, bool)> = None;
    let mut limit: Option<usize> = None;
    let mut offset: Option<usize> = None;

    while i < rest.len() {
        match rest[i].to_uppercase().as_str() {
            "JOIN" | "LEFT" => {
                let join_type = if rest[i].eq_ignore_ascii_case("LEFT") {
                    i += 1;
                    if i >= rest.len() || !rest[i].eq_ignore_ascii_case("JOIN") {
                        return Err("ERR expected JOIN after LEFT".to_string());
                    }
                    JoinType::Left
                } else {
                    JoinType::Inner
                };
                i += 1;
                // JOIN table alias ON left = right
                if i + 3 >= rest.len() {
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
                    join_type,
                    table: join_table,
                    alias: join_alias,
                    left_col: left,
                    right_col: right,
                });
            }
            "WHERE" => {
                i += 1;
                loop {
                    conditions.push(parse_where_condition(rest, &mut i)?);
                    if i < rest.len() && rest[i].eq_ignore_ascii_case("AND") {
                        i += 1;
                    } else {
                        break;
                    }
                }
            }
            "GROUP" => {
                i += 1;
                if i >= rest.len() || rest[i].to_uppercase() != "BY" {
                    return Err("ERR expected BY after GROUP".to_string());
                }
                i += 1;
                if i >= rest.len() || is_select_clause_keyword(rest[i]) {
                    return Err("ERR GROUP BY requires at least one column".to_string());
                }
                while i < rest.len() && !is_select_clause_keyword(rest[i]) {
                    for col in rest[i].split(',') {
                        let col = col.trim();
                        if !col.is_empty() {
                            group_by.push(col.to_string());
                        }
                    }
                    i += 1;
                }
            }
            "HAVING" => {
                i += 1;
                loop {
                    if i >= rest.len() || is_select_clause_keyword(rest[i]) {
                        return Err(
                            "ERR incomplete HAVING clause: expected field op value".to_string()
                        );
                    }
                    let field = rest[i].trim_end_matches(',').to_string();
                    i += 1;
                    if i >= rest.len() {
                        return Err(format!(
                            "ERR incomplete HAVING clause: missing operator after '{field}'"
                        ));
                    }
                    let op_str = rest[i];
                    i += 1;
                    if i >= rest.len() {
                        return Err(format!(
                            "ERR incomplete HAVING clause: missing value after '{op_str}'"
                        ));
                    }
                    let value = rest[i].trim_end_matches(',').to_string();
                    i += 1;
                    let op = parse_cmp_op(op_str)?;
                    having.push(WhereClause::single(field, op, value));
                    if i < rest.len() && rest[i].to_uppercase() == "AND" {
                        i += 1;
                    } else {
                        break;
                    }
                }
            }
            "NEAR" => {
                i += 1;
                if i + 3 >= rest.len() {
                    return Err(
                        "ERR NEAR syntax: NEAR <field> <vector> K <n> [THRESHOLD <score>]"
                            .to_string(),
                    );
                }
                let field = rest[i].to_string();
                i += 1;
                let vector_token = rest[i];
                i += 1;
                if i >= rest.len() || !rest[i].eq_ignore_ascii_case("K") {
                    return Err("ERR NEAR requires K <n>".to_string());
                }
                i += 1;
                if i >= rest.len() {
                    return Err("ERR NEAR K requires a value".to_string());
                }
                let k = rest[i]
                    .parse::<usize>()
                    .map_err(|_| "ERR NEAR K must be a positive integer".to_string())?;
                if k == 0 {
                    return Err("ERR NEAR K must be greater than zero".to_string());
                }
                i += 1;
                let mut threshold = None;
                if i < rest.len() && rest[i].eq_ignore_ascii_case("THRESHOLD") {
                    i += 1;
                    if i >= rest.len() {
                        return Err("ERR NEAR THRESHOLD requires a value".to_string());
                    }
                    threshold = Some(
                        rest[i]
                            .parse::<f32>()
                            .map_err(|_| "ERR NEAR THRESHOLD must be a float".to_string())?,
                    );
                    i += 1;
                }
                let vector = parse_vector_literal(vector_token)?;
                near = Some(NearClause {
                    field,
                    vector,
                    k,
                    threshold,
                });
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
        group_by,
        having,
        near,
        order_by,
        limit,
        offset,
    })
}

pub(crate) fn is_select_clause_keyword(token: &str) -> bool {
    matches!(
        token.to_uppercase().as_str(),
        "JOIN" | "LEFT" | "WHERE" | "GROUP" | "HAVING" | "NEAR" | "ORDER" | "LIMIT" | "OFFSET"
    )
}

pub(crate) fn parse_cmp_op(s: &str) -> Result<CmpOp, String> {
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
pub(crate) fn parse_select_cols(raw: &str) -> Result<(Vec<Projection>, Vec<AggExpr>), String> {
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
pub(crate) fn split_on_commas(s: &str) -> Vec<&str> {
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
pub(crate) fn split_as(s: &str) -> (&str, Option<&str>) {
    let tokens: Vec<&str> = s.split_whitespace().collect();
    match tokens.as_slice() {
        [expr, kw, alias] if kw.to_uppercase() == "AS" => (*expr, Some(*alias)),
        [expr, alias] => (*expr, Some(*alias)),
        [expr] => (*expr, None),
        _ => (s, None),
    }
}

/// Try to parse an aggregate expression like COUNT(*), SUM(score) AS total.
pub(crate) fn try_parse_agg(s: &str) -> Result<Option<AggExpr>, String> {
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

pub(crate) struct TableScan {
    row_ids: Vec<String>,
    order_satisfied: bool,
    pagination_satisfied: bool,
}

pub(crate) struct TableScanPlan<'a> {
    conditions: &'a [WhereClause],
    order_by: Option<&'a (String, bool)>,
    limit: Option<usize>,
    offset: Option<usize>,
    allow_order_pushdown: bool,
    early_limit: Option<usize>,
}

pub(crate) struct OrderScan<'a> {
    column: &'a str,
    ascending: bool,
    min: f64,
    max: f64,
    min_exclusive: bool,
    max_exclusive: bool,
    offset: Option<usize>,
    limit: Option<usize>,
}

#[derive(Clone, Copy)]
pub(crate) struct ScoreRange {
    min: f64,
    max: f64,
    min_exclusive: bool,
    max_exclusive: bool,
}

pub(crate) struct TableVectorMatch {
    pk: String,
    similarity: f32,
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
                values: c.values.clone(),
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
    if !plan.aggregates.is_empty()
        && plan.joins.is_empty()
        && plan.group_by.is_empty()
        && plan.having.is_empty()
    {
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
    let implicit_id_field = if schema.iter().any(|f| f.primary_key) {
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
    };

    // Apply LIMIT early only when safe to do so:
    // - no joins (join changes the row count unpredictably)
    // - no ORDER BY (ordering requires all rows before truncating)
    let early_limit = if plan.joins.is_empty() && plan.order_by.is_none() && plan.near.is_none() {
        plan.limit.map(|l| l + plan.offset.unwrap_or(0))
    } else {
        None
    };

    let mut scan = plan_table_scan(
        store,
        &plan.table,
        &schema,
        TableScanPlan {
            conditions: &conditions,
            order_by: plan.order_by.as_ref(),
            limit: plan.limit,
            offset: plan.offset,
            allow_order_pushdown: plan.joins.is_empty(),
            early_limit,
        },
        now,
    );

    let near_candidate_pks = if plan.near.is_some() && !conditions.is_empty() {
        let mut candidates = HashSet::new();
        for pk_str in &scan.row_ids {
            let Some(row) = get_row_with_map(store, &plan.table, &type_map, pk_str, now) else {
                continue;
            };
            if row_matches_base_conditions(&row, &schema, implicit_id_field.as_ref(), &conditions) {
                candidates.insert(pk_str.clone());
            }
        }
        Some(candidates)
    } else {
        None
    };

    let vector_matches = match &plan.near {
        Some(near) => Some(table_vector_candidates(
            store,
            &plan.table,
            &schema,
            near,
            near_candidate_pks.as_ref(),
            now,
        )?),
        None => None,
    };

    let vector_similarity: Option<hashbrown::HashMap<String, f32>> =
        vector_matches.as_ref().map(|matches| {
            matches
                .iter()
                .map(|hit| (hit.pk.clone(), hit.similarity))
                .collect()
        });
    if let Some(matches) = vector_matches.as_ref() {
        let scan_ids: HashSet<String> = scan.row_ids.iter().cloned().collect();
        if plan.order_by.is_none() {
            scan.row_ids = matches
                .iter()
                .filter(|hit| scan_ids.contains(&hit.pk))
                .map(|hit| hit.pk.clone())
                .collect();
            scan.order_satisfied = true;
        } else if let Some(similarity) = vector_similarity.as_ref() {
            scan.row_ids.retain(|pk| similarity.contains_key(pk));
        }
    }

    // Per-candidate work: filter (per-field reads + zero-alloc JSON binary
    // walk), hydrate survivors, then project. Read-only over `store` (shard read
    // locks), so it's `Sync` and safe to fan out across cores.
    let process = |pk_str: String| -> Option<Vec<(String, String)>> {
        if !row_passes_conditions(
            store,
            &plan.table,
            &schema,
            implicit_id_field.as_ref(),
            &pk_str,
            &conditions,
            now,
        ) {
            return None;
        }
        let mut row = get_row_with_map(store, &plan.table, &type_map, &pk_str, now)?;
        if let Some(similarity) = vector_similarity
            .as_ref()
            .and_then(|scores| scores.get(&pk_str))
        {
            row.push(("_similarity".to_string(), similarity.to_string()));
        }
        let ob_col = plan.order_by.as_ref().map(|(c, _)| c.as_str());
        // Also retain join key and WHERE columns so the hash join probe and
        // post-join filters can find them after projection pushdown.
        let join_keys: Vec<&str> = plan
            .joins
            .iter()
            .flat_map(|j| [j.left_col.as_str(), j.right_col.as_str()])
            .map(bare_col)
            .collect();
        let condition_keys: Vec<&str> = plan
            .conditions
            .iter()
            .map(|condition| bare_col(&condition.field))
            .collect();
        let mut projected = if plan.group_by.is_empty() {
            project_row_fields(&row, &plan.projections, &plan.aggregates, ob_col)
        } else {
            row.clone()
        };
        for jk in join_keys.iter().chain(condition_keys.iter()) {
            if !projected.iter().any(|(k, _)| k == jk) {
                if let Some(val) = row.iter().find(|(k, _)| k == jk) {
                    projected.push(val.clone());
                }
            }
        }
        Some(if plan.alias.is_some() || !plan.joins.is_empty() {
            projected
                .into_iter()
                .map(|(k, v)| (format!("{}.{}", table_alias, k), v))
                .collect()
        } else {
            projected
        })
    };

    // A big full scan (no early LIMIT to exploit) is embarrassingly parallel —
    // fan the filter+hydrate+project out across cores. rayon's indexed collect
    // preserves scan order, so ORDER BY pushdown and pagination stay correct.
    let mut rows: Vec<Vec<(String, String)>> =
        if early_limit.is_none() && scan.row_ids.len() >= PARALLEL_SCAN_MIN {
            use rayon::prelude::*;
            scan.row_ids.into_par_iter().filter_map(&process).collect()
        } else {
            scan.row_ids
                .into_iter()
                .filter_map(&process)
                .take(early_limit.unwrap_or(usize::MAX))
                .collect()
        };

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
                    None => matches!(cond.op, CmpOp::Ne | CmpOp::IsNull),
                    // IN / NOT IN carry their operands in `values`, not `value`;
                    // compare_condition_value only knows scalar ops and would
                    // return false for them, dropping every joined row (e.g. a
                    // grant predicate `col IN (subquery)` on a joined query).
                    Some(v) => match cond.op {
                        CmpOp::In => cond
                            .values
                            .iter()
                            .any(|x| compare_condition_value(v, &CmpOp::Eq, x)),
                        CmpOp::NotIn => !cond
                            .values
                            .iter()
                            .any(|x| compare_condition_value(v, &CmpOp::Eq, x)),
                        _ => compare_condition_value(v, &cond.op, &cond.value),
                    },
                }
            })
        });
    }

    // ---- Slow-path aggregates (needed rows already fetched) ----
    if !plan.aggregates.is_empty() {
        if !plan.group_by.is_empty() {
            let mut grouped = compute_grouped_rows(&rows, &plan.group_by, &plan.aggregates);
            if !plan.having.is_empty() {
                grouped.retain(|row| matches_all_having(row, &plan.having));
            }
            if let Some((ref col, ascending)) = plan.order_by {
                grouped.sort_by(|a, b| {
                    let av = find_col(a, col, table_alias).unwrap_or("");
                    let bv = find_col(b, col, table_alias).unwrap_or("");
                    let cmp = compare_result_values(av, bv);
                    if ascending {
                        cmp
                    } else {
                        cmp.reverse()
                    }
                });
            }
            let grouped = if let Some(off) = plan.offset {
                grouped.into_iter().skip(off).collect()
            } else {
                grouped
            };
            let mut grouped = grouped;
            if let Some(lim) = plan.limit {
                grouped.truncate(lim);
            }
            return Ok(SelectResult::Rows(grouped));
        }
        let agg_row = compute_aggregates(&rows, &plan.aggregates);
        if !plan.having.is_empty() && !matches_all_having(&agg_row, &plan.having) {
            return Ok(SelectResult::Rows(Vec::new()));
        }
        return Ok(SelectResult::Aggregate(agg_row));
    }

    // ---- ORDER BY ----
    if !scan.order_satisfied {
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
    }

    // ---- OFFSET / LIMIT ----
    let rows = if !scan.pagination_satisfied {
        if let Some(off) = plan.offset {
            rows.into_iter().skip(off).collect()
        } else {
            rows
        }
    } else {
        rows
    };
    let mut rows = rows;
    if !scan.pagination_satisfied {
        if let Some(lim) = plan.limit {
            rows.truncate(lim);
        }
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

pub(crate) fn plan_table_scan(
    store: &Store,
    table: &str,
    schema: &[FieldDef],
    plan: TableScanPlan<'_>,
    now: Instant,
) -> TableScan {
    if plan.allow_order_pushdown {
        if let Some((order_col, ascending)) = plan.order_by {
            let order_col = bare_col(order_col);
            if let Some(range) = score_range_from_conditions(order_col, plan.conditions) {
                let pushed_offset = Some(plan.offset.unwrap_or(0));
                let pushed_limit = Some(plan.limit.unwrap_or(usize::MAX));

                if let Some(row_ids) = candidates_from_order_index(
                    store,
                    table,
                    schema,
                    OrderScan {
                        column: order_col,
                        ascending: *ascending,
                        min: range.min,
                        max: range.max,
                        min_exclusive: range.min_exclusive,
                        max_exclusive: range.max_exclusive,
                        offset: pushed_offset,
                        limit: pushed_limit,
                    },
                    now,
                ) {
                    return TableScan {
                        row_ids,
                        order_satisfied: true,
                        pagination_satisfied: plan.limit.is_some() || plan.offset.is_some(),
                    };
                }
            }
        }
    }

    let candidate_set =
        build_candidate_set(store, table, schema, plan.conditions, plan.early_limit, now);

    if plan.allow_order_pushdown {
        if let Some((order_col, ascending)) = plan.order_by {
            let can_push_pagination = candidate_set.is_none() && plan.conditions.is_empty();
            let pushed_offset = can_push_pagination.then_some(plan.offset.unwrap_or(0));
            let pushed_limit = can_push_pagination.then_some(plan.limit.unwrap_or(usize::MAX));

            if let Some(mut row_ids) = candidates_from_order_index(
                store,
                table,
                schema,
                OrderScan {
                    column: bare_col(order_col),
                    ascending: *ascending,
                    min: f64::NEG_INFINITY,
                    max: f64::INFINITY,
                    min_exclusive: false,
                    max_exclusive: false,
                    offset: pushed_offset,
                    limit: pushed_limit,
                },
                now,
            ) {
                if let Some(set) = candidate_set.as_ref() {
                    row_ids.retain(|pk| set.contains(pk));
                }
                return TableScan {
                    row_ids,
                    order_satisfied: true,
                    pagination_satisfied: can_push_pagination
                        && (plan.limit.is_some() || plan.offset.is_some()),
                };
            }
        }
    }

    let mut row_ids = match candidate_set {
        Some(pks) => pks.into_iter().collect(),
        None => get_all_row_ids(store, table, now),
    };
    if let Some(lim) = plan.early_limit {
        row_ids.truncate(lim);
    }
    TableScan {
        row_ids,
        order_satisfied: false,
        pagination_satisfied: false,
    }
}

pub(crate) fn table_vector_candidates(
    store: &Store,
    table: &str,
    schema: &[FieldDef],
    near: &NearClause,
    candidate_pks: Option<&HashSet<String>>,
    now: Instant,
) -> Result<Vec<TableVectorMatch>, String> {
    let field_name = bare_col(&near.field);
    let field = schema
        .iter()
        .find(|field| field.name == field_name)
        .ok_or_else(|| format!("ERR unknown vector field '{}'", near.field))?;
    let FieldType::Vector(dims) = field.field_type else {
        return Err(format!("ERR field '{}' is not a VECTOR column", near.field));
    };
    if near.vector.len() != dims {
        return Err(format!(
            "ERR VECTOR({}) expected {} query values, got {}",
            dims,
            dims,
            near.vector.len()
        ));
    }

    let results = match candidate_pks {
        Some(candidates) => store.table_vector_search_candidates(TableVectorCandidateQuery {
            table,
            field: &field.name,
            query: &near.vector,
            candidate_pks: candidates,
            k: near.k,
            threshold: near.threshold,
            now,
        }),
        None => store.table_vector_search(
            table,
            &field.name,
            &near.vector,
            near.k,
            near.threshold,
            now,
        ),
    };

    let mut matches = Vec::with_capacity(results.len());
    for (pk, similarity) in results {
        matches.push(TableVectorMatch { pk, similarity });
    }
    Ok(matches)
}

pub(crate) fn row_matches_base_conditions(
    row: &[(String, String)],
    schema: &[FieldDef],
    implicit_id_field: Option<&FieldDef>,
    conditions: &[WhereClause],
) -> bool {
    conditions.iter().all(|cond| {
        // JSON dot-path: `jsoncol.a.b` where the leading segment is a JSON
        // column. Must run BEFORE bare_col, which would collapse the path to
        // its leaf and silently match every row.
        if let Some((root, path)) = cond.field.split_once('.') {
            if schema.iter().any(|f| {
                f.name == root && matches!(f.field_type, FieldType::Json | FieldType::Array)
            }) {
                return eval_json_path_condition(row, root, path, cond);
            }
        }
        let bare = bare_col(&cond.field);
        if let Some(fd) = schema.iter().find(|f| f.name == bare) {
            matches_condition(
                row,
                &WhereClause {
                    field: bare.to_string(),
                    op: cond.op.clone(),
                    value: cond.value.clone(),
                    values: cond.values.clone(),
                },
                fd,
            )
        } else if bare == "id" {
            if let Some(fd) = implicit_id_field {
                matches_condition(
                    row,
                    &WhereClause {
                        field: bare.to_string(),
                        op: cond.op.clone(),
                        value: cond.value.clone(),
                        values: cond.values.clone(),
                    },
                    fd,
                )
            } else {
                true
            }
        } else {
            true
        }
    })
}

pub(crate) fn score_range_from_conditions(
    order_col: &str,
    conditions: &[WhereClause],
) -> Option<ScoreRange> {
    let mut range = ScoreRange {
        min: f64::NEG_INFINITY,
        max: f64::INFINITY,
        min_exclusive: false,
        max_exclusive: false,
    };

    for cond in conditions {
        if bare_col(&cond.field) != order_col {
            return None;
        }
        let score = cond.value.parse::<f64>().ok()?;
        match cond.op {
            CmpOp::Eq => {
                range.min = score;
                range.max = score;
                range.min_exclusive = false;
                range.max_exclusive = false;
            }
            CmpOp::Gt => {
                if score > range.min || (score == range.min && !range.min_exclusive) {
                    range.min = score;
                    range.min_exclusive = true;
                }
            }
            CmpOp::Ge => {
                if score > range.min {
                    range.min = score;
                    range.min_exclusive = false;
                }
            }
            CmpOp::Lt => {
                if score < range.max || (score == range.max && !range.max_exclusive) {
                    range.max = score;
                    range.max_exclusive = true;
                }
            }
            CmpOp::Le => {
                if score < range.max {
                    range.max = score;
                    range.max_exclusive = false;
                }
            }
            CmpOp::Ne
            | CmpOp::In
            | CmpOp::NotIn
            | CmpOp::IsValid
            | CmpOp::IsNotValid
            | CmpOp::IsNull
            | CmpOp::IsNotNull
            | CmpOp::Contains => return None,
        }
    }

    Some(range)
}

/// Build candidate row PK strings using condition indexes where possible.
pub(crate) fn build_candidates(
    store: &Store,
    table: &str,
    schema: &[FieldDef],
    conditions: &[WhereClause],
    limit: Option<usize>,
    now: Instant,
) -> Vec<String> {
    match build_candidate_set(store, table, schema, conditions, limit, now) {
        Some(pks) => pks.into_iter().collect(),
        None => get_all_row_ids(store, table, now),
    }
}

/// True when range-scanning or ordering `col` should use the table's `ids`
/// sorted set rather than a per-column secondary index.
///
/// The `ids` set holds every row keyed by its primary key, with the numeric PK
/// as the score, so it is the authoritative, always-populated index for the
/// primary key column. The per-column index (`idx_sorted_key`) is only written
/// by `add_to_index` when a value is explicitly supplied to TINSERT, so an
/// auto-increment INT primary key has no entries there and any range/order over
/// it would otherwise come back empty. This covers both the implicit auto-
/// increment `id` (no declared PK) and an explicit INT primary key of any name.
pub(crate) fn pk_served_by_ids_set(schema: &[FieldDef], col: &str) -> bool {
    let has_explicit_pk = schema.iter().any(|f| f.primary_key);
    if !has_explicit_pk {
        return col == "id";
    }
    schema
        .iter()
        .any(|f| f.primary_key && f.name == col && matches!(f.field_type, FieldType::Int))
}

pub(crate) fn build_candidate_set(
    store: &Store,
    table: &str,
    schema: &[FieldDef],
    conditions: &[WhereClause],
    limit: Option<usize>,
    now: Instant,
) -> Option<HashSet<String>> {
    let mut candidate_set: Option<HashSet<String>> = None;

    // Only push limit down to index when there's a single condition - with multiple
    // conditions we need the full set from each index to intersect correctly.
    let index_limit = if conditions.len() == 1 { limit } else { None };

    for cond in conditions {
        // JSON dot-path: use a declared path index if one exists (O(log n) range
        // scan), otherwise leave the candidate set unnarrowed (the row-level
        // filter applies the predicate on a full scan).
        if is_json_path_field(&cond.field, schema) {
            if let Some(ft) = read_path_index_type(store, table, &cond.field, now) {
                let synthetic = FieldDef {
                    name: cond.field.clone(),
                    field_type: ft,
                    primary_key: false,
                    unique: false,
                    nullable: true,
                    default_value: None,
                    references: None,
                };
                if let Some(pks) =
                    candidates_from_index(store, table, cond, &synthetic, index_limit, now)
                {
                    let pk_set: HashSet<String> = pks.into_iter().collect();
                    candidate_set = Some(match candidate_set {
                        Some(existing) => existing.intersection(&pk_set).cloned().collect(),
                        None => pk_set,
                    });
                }
            }
            continue;
        }
        let bare = bare_col(&cond.field);
        let primary_key_candidate = schema
            .iter()
            .find(|f| f.primary_key && f.name == bare)
            .filter(|pk| cond.op == CmpOp::Eq && validate_value(pk, &cond.value).is_ok());
        if primary_key_candidate.is_some() {
            let row_exists = !store
                .hgetall(row_key_for_pk(table, &cond.value).as_bytes(), now)
                .unwrap_or_default()
                .is_empty();
            let pk_set: HashSet<String> =
                row_exists.then(|| cond.value.clone()).into_iter().collect();
            candidate_set = Some(match candidate_set {
                Some(existing) => existing.intersection(&pk_set).cloned().collect(),
                None => pk_set,
            });
        } else if pk_served_by_ids_set(schema, bare) {
            if let Some(pks) = candidates_from_implicit_id(
                store,
                table,
                &WhereClause {
                    field: "id".to_string(),
                    op: cond.op.clone(),
                    value: cond.value.clone(),
                    values: cond.values.clone(),
                },
                index_limit,
                now,
            ) {
                let pk_set: HashSet<String> = pks.into_iter().collect();
                candidate_set = Some(match candidate_set {
                    Some(existing) => existing.intersection(&pk_set).cloned().collect(),
                    None => pk_set,
                });
            }
        } else if let Some(fd) = schema.iter().find(|f| f.name == bare) {
            if let Some(pks) = candidates_from_index(
                store,
                table,
                &WhereClause {
                    field: bare.to_string(),
                    op: cond.op.clone(),
                    value: cond.value.clone(),
                    values: cond.values.clone(),
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

    candidate_set
}

pub(crate) fn candidates_from_order_index(
    store: &Store,
    table: &str,
    schema: &[FieldDef],
    scan: OrderScan<'_>,
    now: Instant,
) -> Option<Vec<String>> {
    let zkey = if pk_served_by_ids_set(schema, scan.column) {
        ids_key(table)
    } else {
        let field = schema.iter().find(|f| f.name == scan.column)?;
        match &field.field_type {
            FieldType::Int
            | FieldType::Float
            | FieldType::Bool
            | FieldType::Timestamp
            | FieldType::Ref(_) => idx_sorted_key(table, scan.column),
            FieldType::Str
            | FieldType::Uuid
            | FieldType::Vector(_)
            | FieldType::Json
            | FieldType::Array => return None,
        }
    };

    let rows = store
        .zrangebyscore(
            zkey.as_bytes(),
            scan.min,
            scan.max,
            scan.min_exclusive,
            scan.max_exclusive,
            !scan.ascending,
            scan.offset,
            scan.limit,
            false,
            now,
        )
        .unwrap_or_default();
    Some(rows.into_iter().map(|(pk, _)| pk).collect())
}

/// Hash Join implementation.
///
/// Builds an in-memory HashMap of the right table keyed on the join column,
/// then iterates the left rows performing O(1) lookups.
pub(crate) fn hash_join(
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
        } else if join.join_type == JoinType::Left {
            let mut combined = left_row.clone();
            combined.extend(
                right_schema
                    .iter()
                    .map(|field| (format!("{}.{}", right_alias, field.name), String::new())),
            );
            result.push(combined);
            if let Some(n) = need {
                if result.len() >= n {
                    break 'outer;
                }
            }
        }
    }

    Ok(result)
}

/// Given left_col="u.id" and right_col="p.author_id" and right_alias="p",
/// returns ("u.id", "author_id") - the actual column names to probe on.
pub(crate) fn resolve_join_keys(
    left_col: &str,
    right_col: &str,
    right_alias: &str,
) -> (String, String) {
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
pub(crate) fn bare_col(col: &str) -> &str {
    col.rfind('.').map(|i| &col[i + 1..]).unwrap_or(col)
}

/// Strip alias prefix if it matches a known alias.
pub(crate) fn strip_alias(col: &str, alias: &str) -> String {
    let prefix = format!("{}.", alias);
    if col.starts_with(&prefix) {
        col[prefix.len()..].to_string()
    } else {
        col.to_string()
    }
}

/// Find a column value in a row, preferring exact qualified matches before
/// falling back to bare-column matches.
pub(crate) fn find_col<'a>(row: &'a [(String, String)], col: &str, alias: &str) -> Option<&'a str> {
    let qualified = format!("{}.{}", alias, bare_col(col));
    if let Some((_, value)) = row.iter().find(|(k, _)| k == col) {
        return Some(value);
    }
    if let Some((_, value)) = row.iter().find(|(k, _)| k == &qualified) {
        return Some(value);
    }
    if col.contains('.') {
        return None;
    }
    row.iter()
        .find(|(k, _)| k == bare_col(col) || k.ends_with(&format!(".{}", bare_col(col))))
        .map(|(_, value)| value.as_str())
}

pub(crate) fn compare_result_values(a: &str, b: &str) -> std::cmp::Ordering {
    match (a.parse::<f64>(), b.parse::<f64>()) {
        (Ok(af), Ok(bf)) => af.partial_cmp(&bf).unwrap_or(std::cmp::Ordering::Equal),
        _ => a.cmp(b),
    }
}

/// Apply column projections to result rows.
pub(crate) fn project_columns(
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
                    let qualified = format!("{}.{}", table_alias, bare_col(target));
                    let val = row
                        .iter()
                        .find(|(k, _)| k == target)
                        .or_else(|| row.iter().find(|(k, _)| k == &qualified))
                        .or_else(|| {
                            if target.contains('.') {
                                None
                            } else {
                                row.iter().find(|(k, _)| {
                                    k == bare_col(target)
                                        || k.ends_with(&format!(".{}", bare_col(target)))
                                })
                            }
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
pub(crate) fn project_row_fields(
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
/// True when every WHERE condition is answered *exactly* by an index, so a
/// COUNT can trust the candidate-set cardinality without re-checking rows.
/// Conservative: anything not clearly exact (JSON paths, `!=`, IN, IS VALID,
/// CONTAINS, unindexed columns) returns false so the caller filters instead.
pub(crate) fn count_is_exact_via_index(
    store: &Store,
    table: &str,
    schema: &[FieldDef],
    conditions: &[WhereClause],
    now: Instant,
) -> bool {
    conditions.iter().all(|c| {
        if is_json_path_field(&c.field, schema) {
            // A declared path index makes the candidate set exact for the ops
            // the index can serve: numeric ranges/eq (sorted set) or str eq (set).
            return match read_path_index_type(store, table, &c.field, now) {
                Some(FieldType::Str) => c.op == CmpOp::Eq,
                Some(_) => matches!(
                    c.op,
                    CmpOp::Eq | CmpOp::Gt | CmpOp::Ge | CmpOp::Lt | CmpOp::Le
                ),
                None => false,
            };
        }
        let bare = bare_col(&c.field);
        if bare == "id" && !schema.iter().any(|f| f.primary_key) {
            return matches!(
                c.op,
                CmpOp::Eq | CmpOp::Gt | CmpOp::Ge | CmpOp::Lt | CmpOp::Le
            );
        }
        match schema.iter().find(|f| f.name == bare) {
            // Bool is intentionally excluded: its sorted index stores every row
            // at score 0.0 (`"true"`/`"false"` don't parse as f64), so the
            // candidate set is never narrowed and its cardinality can't be
            // trusted for a COUNT. Fall through to a row-rechecking count.
            Some(fd) => matches!(
                (&fd.field_type, &c.op),
                (
                    FieldType::Int | FieldType::Float | FieldType::Timestamp | FieldType::Ref(_),
                    CmpOp::Eq | CmpOp::Gt | CmpOp::Ge | CmpOp::Lt | CmpOp::Le
                ) | (FieldType::Str | FieldType::Uuid, CmpOp::Eq)
            ),
            None => false,
        }
    })
}

/// Count candidate rows that satisfy the predicate. Filters via per-field
/// reads + zero-alloc JSON binary walk, without hydrating full rows.
pub(crate) fn count_matching_rows(
    store: &Store,
    table: &str,
    schema: &[FieldDef],
    conditions: &[WhereClause],
    now: Instant,
) -> i64 {
    let implicit = implicit_id_field_for(schema);
    let candidates = build_candidates(store, table, schema, conditions, None, now);
    let passes = |pk: &String| {
        row_passes_conditions(store, table, schema, implicit.as_ref(), pk, conditions, now)
    };
    // A big filtered count is the canonical bulk-scan query — fan the per-row
    // predicate check across cores (read-only over `store`).
    if candidates.len() >= PARALLEL_SCAN_MIN {
        use rayon::prelude::*;
        candidates.par_iter().filter(|pk| passes(pk)).count() as i64
    } else {
        candidates.iter().filter(|pk| passes(pk)).count() as i64
    }
}

pub(crate) fn try_fast_aggregate(
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
                } else if count_is_exact_via_index(store, table, schema, conditions, now) {
                    // Candidate set is an exact match set - cardinality is the answer.
                    build_candidates(store, table, schema, conditions, None, now).len() as i64
                } else {
                    // Predicate isn't index-exact (JSON path, !=, IN, ...) - the
                    // candidate set may be a superset, so re-check each row.
                    count_matching_rows(store, table, schema, conditions, now)
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
                                CmpOp::Ne
                                | CmpOp::In
                                | CmpOp::NotIn
                                | CmpOp::IsValid
                                | CmpOp::IsNotValid
                                | CmpOp::IsNull
                                | CmpOp::IsNotNull
                                | CmpOp::Contains => return None,
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

pub(crate) fn compute_aggregates(
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

#[derive(Clone)]
pub(crate) enum AggAccumulator {
    Count(usize),
    Sum(f64),
    Avg { sum: f64, count: usize },
    Min(Option<f64>),
    Max(Option<f64>),
}

impl AggAccumulator {
    fn new(func: &AggFunc) -> Self {
        match func {
            AggFunc::Count => AggAccumulator::Count(0),
            AggFunc::Sum => AggAccumulator::Sum(0.0),
            AggFunc::Avg => AggAccumulator::Avg { sum: 0.0, count: 0 },
            AggFunc::Min => AggAccumulator::Min(None),
            AggFunc::Max => AggAccumulator::Max(None),
        }
    }

    fn ingest(&mut self, row: &[(String, String)], agg: &AggExpr) {
        match self {
            AggAccumulator::Count(count) => match &agg.col {
                None => *count += 1,
                Some(col) => {
                    if row.iter().any(|(key, _)| bare_col(key) == col.as_str()) {
                        *count += 1;
                    }
                }
            },
            AggAccumulator::Sum(sum) => {
                if let Some(value) = aggregate_numeric_value(row, agg) {
                    *sum += value;
                }
            }
            AggAccumulator::Avg { sum, count } => {
                if let Some(value) = aggregate_numeric_value(row, agg) {
                    *sum += value;
                    *count += 1;
                }
            }
            AggAccumulator::Min(min) => {
                if let Some(value) = aggregate_numeric_value(row, agg) {
                    *min = Some(min.map_or(value, |current| current.min(value)));
                }
            }
            AggAccumulator::Max(max) => {
                if let Some(value) = aggregate_numeric_value(row, agg) {
                    *max = Some(max.map_or(value, |current| current.max(value)));
                }
            }
        }
    }

    fn finish(&self) -> String {
        match self {
            AggAccumulator::Count(count) => count.to_string(),
            AggAccumulator::Sum(sum) => format_numeric(*sum),
            AggAccumulator::Avg { sum, count } => {
                if *count == 0 {
                    "0".to_string()
                } else {
                    format_numeric(*sum / *count as f64)
                }
            }
            AggAccumulator::Min(value) | AggAccumulator::Max(value) => {
                value.map(format_numeric).unwrap_or_else(|| "0".to_string())
            }
        }
    }
}

pub(crate) fn aggregate_numeric_value(row: &[(String, String)], agg: &AggExpr) -> Option<f64> {
    let col = agg.col.as_deref()?;
    row.iter()
        .find(|(key, _)| bare_col(key) == col)
        .and_then(|(_, value)| value.parse::<f64>().ok())
}

pub(crate) fn format_numeric(value: f64) -> String {
    if value.fract() == 0.0 {
        (value as i64).to_string()
    } else {
        value.to_string()
    }
}

pub(crate) fn compute_grouped_rows(
    rows: &[Vec<(String, String)>],
    group_by: &[String],
    aggregates: &[AggExpr],
) -> Vec<Vec<(String, String)>> {
    let mut groups: hashbrown::HashMap<Vec<String>, Vec<AggAccumulator>> =
        hashbrown::HashMap::new();

    for row in rows {
        let key: Vec<String> = group_by
            .iter()
            .map(|col| {
                row.iter()
                    .find(|(k, _)| k == col || k.ends_with(&format!(".{}", bare_col(col))))
                    .map(|(_, v)| v.clone())
                    .unwrap_or_default()
            })
            .collect();
        let accumulators = groups.entry(key).or_insert_with(|| {
            aggregates
                .iter()
                .map(|agg| AggAccumulator::new(&agg.func))
                .collect()
        });
        for (accumulator, aggregate) in accumulators.iter_mut().zip(aggregates) {
            accumulator.ingest(row, aggregate);
        }
    }

    let mut out = Vec::with_capacity(groups.len());
    for (key, accumulators) in groups {
        let mut row = Vec::with_capacity(group_by.len() + aggregates.len());
        for (idx, col) in group_by.iter().enumerate() {
            row.push((
                bare_col(col).to_string(),
                key.get(idx).cloned().unwrap_or_default(),
            ));
        }
        row.extend(
            aggregates
                .iter()
                .zip(accumulators.iter())
                .map(|(aggregate, accumulator)| (aggregate.alias.clone(), accumulator.finish())),
        );
        out.push(row);
    }
    out
}

pub(crate) fn matches_all_having(row: &[(String, String)], having: &[WhereClause]) -> bool {
    having.iter().all(|cond| {
        let actual = row
            .iter()
            .find(|(k, _)| k == &cond.field || k.eq_ignore_ascii_case(&cond.field))
            .map(|(_, v)| v.as_str());
        match actual {
            None => matches!(cond.op, CmpOp::Ne | CmpOp::IsNull),
            Some(value) => compare_condition_value(value, &cond.op, &cond.value),
        }
    })
}

pub(crate) fn compare_condition_value(actual: &str, op: &CmpOp, expected: &str) -> bool {
    // The caller only reaches here with a present value, which is never NULL.
    match op {
        CmpOp::IsNull => return false,
        CmpOp::IsNotNull => return true,
        _ => {}
    }
    if let (Ok(a), Ok(e)) = (actual.parse::<f64>(), expected.parse::<f64>()) {
        return match op {
            CmpOp::Eq => a == e,
            CmpOp::Ne => a != e,
            CmpOp::Gt => a > e,
            CmpOp::Lt => a < e,
            CmpOp::Ge => a >= e,
            CmpOp::Le => a <= e,
            _ => false,
        };
    }
    match op {
        CmpOp::Eq => actual == expected,
        CmpOp::Ne => actual != expected,
        CmpOp::Gt => actual > expected,
        CmpOp::Lt => actual < expected,
        CmpOp::Ge => actual >= expected,
        CmpOp::Le => actual <= expected,
        _ => false,
    }
}

pub(crate) fn scan_matching_pks(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    conditions: &[WhereClause],
    now: Instant,
) -> Result<(Vec<FieldDef>, Vec<String>), String> {
    let schema = load_schema(store, cache, table, now)?;

    // Validate WHERE fields (allow "id" for implicit-PK tables and JSON dot-paths).
    let has_implicit_pk = !schema.iter().any(|f| f.primary_key);
    for cond in conditions {
        let is_implicit_id = has_implicit_pk && cond.field == "id";
        if !is_implicit_id && !is_json_path_field(&cond.field, &schema) {
            schema
                .iter()
                .find(|f| f.name == cond.field)
                .ok_or_else(|| format!("ERR unknown field '{}' in WHERE clause", cond.field))?;
        }
    }
    let implicit_id = implicit_id_field_for(&schema);

    let row_ids = plan_table_scan(
        store,
        table,
        &schema,
        TableScanPlan {
            conditions,
            order_by: None,
            limit: None,
            offset: None,
            allow_order_pushdown: false,
            early_limit: None,
        },
        now,
    )
    .row_ids;

    let mut matched = Vec::new();
    for pk_str in row_ids {
        let Some(row) = get_row(store, table, &schema, &pk_str, now) else {
            continue;
        };
        if row_matches_base_conditions(&row, &schema, implicit_id.as_ref(), conditions) {
            matched.push(pk_str);
        }
    }
    Ok((schema, matched))
}

/// Fetch and column-sort the rows for a set of primary keys.
pub(crate) fn rows_for_pks(
    store: &Store,
    table: &str,
    schema: &[FieldDef],
    pks: &[String],
    now: Instant,
) -> Vec<Vec<(String, String)>> {
    pks.iter()
        .filter_map(|pk| {
            get_row(store, table, schema, pk, now).map(|mut r| {
                r.sort_by(|a, b| a.0.cmp(&b.0));
                r
            })
        })
        .collect()
}

/// True if `v` is safe to emit as a single bare WHERE token (no whitespace and
/// no characters that would break `IN ( ... )` tokenization).
fn is_token_safe(v: &str) -> bool {
    !v.is_empty()
        && !v
            .chars()
            .any(|c| c.is_whitespace() || c == '(' || c == ')' || c == '\'')
}

/// Scan `table` for rows matching `conditions` and collect the distinct values
/// of one `projected` column. Used to resolve a grant subquery to a membership
/// set. When `projected` is the primary key (not a stored hash field), the row's
/// pk is used. Capped to avoid unbounded membership sets.
pub(crate) fn scan_projected_column(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    conditions: &[WhereClause],
    projected: &str,
    now: Instant,
) -> Result<Vec<String>, String> {
    const MAX_MEMBERSHIP: usize = 100_000;
    let (schema, pks) = scan_matching_pks(store, cache, table, conditions, now)?;

    // Validate the projected column exists (allow "id" on implicit-PK tables).
    let has_implicit_pk = !schema.iter().any(|f| f.primary_key);
    let projected_is_id = has_implicit_pk && projected == "id";
    let projected_is_pk = schema.iter().any(|f| f.primary_key && f.name == projected);
    if !projected_is_id && !projected_is_pk && !schema.iter().any(|f| f.name == projected) {
        return Err(format!(
            "ERR grant subquery selects unknown column '{projected}' from '{table}'"
        ));
    }

    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut out = Vec::new();
    for pk in &pks {
        let value = if projected_is_id || projected_is_pk {
            // The pk *is* the projected value (it may not be a stored field).
            Some(pk.clone())
        } else {
            get_row(store, table, &schema, pk, now).and_then(|row| {
                row.into_iter()
                    .find(|(k, _)| k == projected)
                    .map(|(_, v)| v)
            })
        };
        if let Some(v) = value {
            // Fail closed on values that aren't safe as a single WHERE token. The
            // membership set is enforced both as a re-tokenized `IN ( a b c )`
            // string (read/write) and as discrete tokens (live); a value with
            // whitespace or parens/quotes could split and over-match (an RLS
            // escalation), so such a value is excluded from the set entirely.
            // Membership keys are ids/slugs in practice, so this never triggers.
            if !is_token_safe(&v) {
                continue;
            }
            if seen.insert(v.clone()) {
                if out.len() >= MAX_MEMBERSHIP {
                    return Err(format!(
                        "ERR grant subquery on '{table}' matched more than {MAX_MEMBERSHIP} rows"
                    ));
                }
                out.push(v);
            }
        }
    }
    Ok(out)
}
