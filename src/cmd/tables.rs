use bytes::BytesMut;
use std::time::Instant;

use crate::resp;
use crate::store::Store;
use crate::tables::{self, SelectResult, SharedSchemaCache};

use super::{arg_str, CmdResult};

/// Split a trailing `RETURNING * | col [col ...]` (commas optional) off a
/// command. Returns the args before RETURNING and the projection, where a
/// projection of `["*"]` (or an empty list) means "all columns".
fn split_returning<'a>(args: &'a [&'a [u8]]) -> (&'a [&'a [u8]], Option<Vec<String>>) {
    let Some(idx) = args
        .iter()
        .position(|a| arg_str(a).eq_ignore_ascii_case("RETURNING"))
    else {
        return (args, None);
    };
    let cols: Vec<String> = args[idx + 1..]
        .iter()
        .flat_map(|a| {
            arg_str(a)
                .split(',')
                .map(|s| s.trim().to_string())
                .collect::<Vec<_>>()
        })
        .filter(|s| !s.is_empty())
        .collect();
    let cols = if cols.is_empty() || cols.iter().any(|c| c == "*") {
        vec!["*".to_string()]
    } else {
        cols
    };
    (&args[..idx], Some(cols))
}

/// Split a trailing `ON CONFLICT <col>` off a command, returning the remaining
/// args and the conflict column (if present).
fn split_on_conflict<'a>(args: &'a [&'a [u8]]) -> (&'a [&'a [u8]], Option<String>) {
    for i in 0..args.len() {
        if i + 1 < args.len()
            && arg_str(args[i]).eq_ignore_ascii_case("ON")
            && arg_str(args[i + 1]).eq_ignore_ascii_case("CONFLICT")
        {
            let col = args.get(i + 2).map(|a| arg_str(a).to_string());
            return (&args[..i], col);
        }
    }
    (args, None)
}

/// Split a trailing `TTL <seconds>` off a write command, returning the
/// remaining args and the TTL op. `TTL 0` clears any existing TTL; a positive
/// value sets/refreshes it. Must be stripped before `ON CONFLICT` (upsert) and
/// before WHERE detection (update), and after RETURNING — i.e. `TTL` is the last
/// clause except for a trailing RETURNING. (Like `RETURNING`/`ON CONFLICT`, a
/// literal column named `ttl` at the tail would collide; use the HTTP `?ttl=`
/// form to avoid that.)
fn split_ttl<'a>(args: &'a [&'a [u8]]) -> (&'a [&'a [u8]], Option<tables::TtlOp>) {
    let n = args.len();
    if n >= 2 && arg_str(args[n - 2]).eq_ignore_ascii_case("TTL") {
        if let Ok(secs) = arg_str(args[n - 1]).parse::<u64>() {
            let op = if secs == 0 {
                tables::TtlOp::Clear
            } else {
                tables::TtlOp::Set(secs)
            };
            return (&args[..n - 2], Some(op));
        }
    }
    (args, None)
}

/// Write rows (optionally projected to `projection`) as a RESP array-of-rows,
/// each row a flat array of field/value pairs, matching TSELECT's shape.
fn write_rows(out: &mut BytesMut, rows: &[Vec<(String, String)>], projection: &[String]) {
    let all = matches!(projection, [c] if c == "*");
    resp::write_array_header(out, rows.len());
    for row in rows {
        let fields: Vec<&(String, String)> = if all {
            row.iter().collect()
        } else {
            projection
                .iter()
                .filter_map(|c| row.iter().find(|(k, _)| k == c))
                .collect()
        };
        resp::write_array_header(out, fields.len() * 2);
        for (k, v) in fields {
            resp::write_bulk(out, k);
            resp::write_bulk(out, v);
        }
    }
}

pub fn cmd_tcreate(
    args: &[&[u8]],
    store: &Store,
    cache: &SharedSchemaCache,
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    if args.len() < 3 {
        resp::write_error(
            out,
            "ERR usage: TCREATE <table> <col> <TYPE> [constraints], ...",
        );
        return CmdResult::Written;
    }
    let table = arg_str(args[1]);
    if let Some(err) = crate::auth::reserved_table_mutation_error(args, store) {
        resp::write_error(out, &err);
        return CmdResult::Written;
    }
    // Everything after the table name is the SQL-like column list
    let col_args: Vec<&str> = args[2..].iter().map(|a| arg_str(a)).collect();
    match tables::table_create(store, cache, table, &col_args, now) {
        Ok(()) => resp::write_ok(out),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_tinsert(
    args: &[&[u8]],
    store: &Store,
    cache: &SharedSchemaCache,
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    let (args, returning) = split_returning(args);
    let (args, ttl) = split_ttl(args);
    // Allow `TINSERT table` with no field pairs: a row whose columns are all
    // auto-generated (uuid PK, DEFAULT now(), etc.) is fully valid.
    if args.len() < 2 || !(args.len() - 2).is_multiple_of(2) {
        resp::write_error(out, "ERR wrong number of arguments for 'tinsert' command");
        return CmdResult::Written;
    }
    let table = arg_str(args[1]);
    if let Some(err) = crate::auth::reserved_table_mutation_error(args, store) {
        resp::write_error(out, &err);
        return CmdResult::Written;
    }
    let mut field_values: Vec<(&str, &str)> = Vec::new();
    let mut i = 2;
    while i + 1 < args.len() {
        field_values.push((arg_str(args[i]), arg_str(args[i + 1])));
        i += 2;
    }
    match returning {
        Some(proj) => {
            match tables::table_insert_returning_ttl(store, cache, table, &field_values, ttl, now) {
                Ok(row) => write_rows(out, &[row], &proj),
                Err(e) => resp::write_error(out, &e),
            }
        }
        None => match tables::table_insert_ttl(store, cache, table, &field_values, ttl, now) {
            Ok(id) => resp::write_integer(out, id),
            Err(e) => resp::write_error(out, &e),
        },
    }
    CmdResult::Written
}

pub fn cmd_tupsert(
    args: &[&[u8]],
    store: &Store,
    cache: &SharedSchemaCache,
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    // TUPSERT <table> <col> <val> ... [ON CONFLICT <col>] [TTL <secs>] [RETURNING *|cols]
    let (args, returning) = split_returning(args);
    let (args, ttl) = split_ttl(args);
    let (args, conflict_col) = split_on_conflict(args);
    if args.len() < 2 || !(args.len() - 2).is_multiple_of(2) {
        resp::write_error(out, "ERR wrong number of arguments for 'tupsert' command");
        return CmdResult::Written;
    }
    let table = arg_str(args[1]);
    if let Some(err) = crate::auth::reserved_table_mutation_error(args, store) {
        resp::write_error(out, &err);
        return CmdResult::Written;
    }
    let mut field_values: Vec<(&str, &str)> = Vec::new();
    let mut i = 2;
    while i + 1 < args.len() {
        field_values.push((arg_str(args[i]), arg_str(args[i + 1])));
        i += 2;
    }
    // Upsert always returns the resulting row; RETURNING can project it.
    let proj = returning.unwrap_or_else(|| vec!["*".to_string()]);
    match tables::table_upsert_returning_ttl(
        store,
        cache,
        table,
        &field_values,
        conflict_col.as_deref(),
        ttl,
        now,
    ) {
        Ok(row) => write_rows(out, &[row], &proj),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_tupdate(
    args: &[&[u8]],
    store: &Store,
    cache: &SharedSchemaCache,
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    // TUPDATE <table> SET <col> <val> [<col> <val> ...] WHERE <conditions> [TTL <secs>] [RETURNING ...]
    // Minimum: TUPDATE users SET name John WHERE id = 1
    let (args, returning) = split_returning(args);
    let (args, ttl) = split_ttl(args);
    if args.len() < 7 {
        resp::write_error(
            out,
            "ERR usage: TUPDATE <table> SET <col> <val> ... WHERE <conditions>",
        );
        return CmdResult::Written;
    }

    let table = arg_str(args[1]);
    if let Some(err) = crate::auth::reserved_table_mutation_error(args, store) {
        resp::write_error(out, &err);
        return CmdResult::Written;
    }

    // Find WHERE keyword position
    let mut where_pos = None;
    for (i, arg) in args.iter().enumerate() {
        if arg_str(arg).to_uppercase() == "WHERE" {
            where_pos = Some(i);
            break;
        }
    }

    let where_pos = match where_pos {
        Some(p) if p >= 4 && p + 3 < args.len() => p,
        _ => {
            resp::write_error(
                out,
                "ERR usage: TUPDATE <table> SET <col> <val> ... WHERE <conditions>",
            );
            return CmdResult::Written;
        }
    };

    // Parse SET clause: between "SET" (args[2]) and WHERE
    if arg_str(args[2]).to_uppercase() != "SET" {
        resp::write_error(out, "ERR expected SET after table name");
        return CmdResult::Written;
    }

    let mut field_values: Vec<(&str, &str)> = Vec::new();
    let mut i = 3;
    while i + 1 < where_pos {
        field_values.push((arg_str(args[i]), arg_str(args[i + 1])));
        i += 2;
    }

    if field_values.is_empty() {
        resp::write_error(out, "ERR no fields to update");
        return CmdResult::Written;
    }

    // Parse WHERE clause
    let where_args: Vec<&str> = args[where_pos + 1..].iter().map(|a| arg_str(a)).collect();

    match returning {
        Some(proj) => match tables::table_update_where_returning_ttl(
            store,
            cache,
            table,
            &field_values,
            &where_args,
            ttl,
            now,
        ) {
            Ok(rows) => write_rows(out, &rows, &proj),
            Err(e) => resp::write_error(out, &e),
        },
        None => match tables::table_update_where_ttl(
            store,
            cache,
            table,
            &field_values,
            &where_args,
            ttl,
            now,
        ) {
            Ok(count) => resp::write_integer(out, count),
            Err(e) => resp::write_error(out, &e),
        },
    }
    CmdResult::Written
}

pub fn cmd_tdelete(
    args: &[&[u8]],
    store: &Store,
    cache: &SharedSchemaCache,
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    // TDELETE FROM <table> WHERE <conditions> [RETURNING ...]
    // Minimum: TDELETE FROM users WHERE id = 1
    let (args, returning) = split_returning(args);
    if args.len() < 6 {
        resp::write_error(out, "ERR usage: TDELETE FROM <table> WHERE <conditions>");
        return CmdResult::Written;
    }

    if arg_str(args[1]).to_uppercase() != "FROM" {
        resp::write_error(out, "ERR expected FROM");
        return CmdResult::Written;
    }

    let table = arg_str(args[2]);
    if let Some(err) = crate::auth::reserved_table_mutation_error(args, store) {
        resp::write_error(out, &err);
        return CmdResult::Written;
    }

    // Find WHERE keyword
    let mut where_pos = None;
    for (i, arg) in args.iter().enumerate().skip(3) {
        if arg_str(arg).to_uppercase() == "WHERE" {
            where_pos = Some(i);
            break;
        }
    }

    let where_pos = match where_pos {
        Some(p) if p + 3 < args.len() => p,
        _ => {
            resp::write_error(out, "ERR incomplete WHERE clause");
            return CmdResult::Written;
        }
    };

    // Parse WHERE clause
    let where_args: Vec<&str> = args[where_pos + 1..].iter().map(|a| arg_str(a)).collect();

    match returning {
        Some(proj) => {
            match tables::table_delete_where_returning(store, cache, table, &where_args, now) {
                Ok(rows) => write_rows(out, &rows, &proj),
                Err(e) => resp::write_error(out, &e),
            }
        }
        None => match tables::table_delete_where(store, cache, table, &where_args, now) {
            Ok(count) => resp::write_integer(out, count),
            Err(e) => resp::write_error(out, &e),
        },
    }
    CmdResult::Written
}

pub fn cmd_tdrop(
    args: &[&[u8]],
    store: &Store,
    cache: &SharedSchemaCache,
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    if args.len() != 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'tdrop' command");
        return CmdResult::Written;
    }
    let table = arg_str(args[1]);
    if let Some(err) = crate::auth::reserved_table_mutation_error(args, store) {
        resp::write_error(out, &err);
        return CmdResult::Written;
    }
    match tables::table_drop(store, cache, table, now) {
        Ok(()) => resp::write_ok(out),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_tindex(
    args: &[&[u8]],
    store: &Store,
    cache: &SharedSchemaCache,
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    if args.len() != 4 {
        resp::write_error(out, "ERR usage: TINDEX <table> <json.path> <TYPE>");
        return CmdResult::Written;
    }
    let table = arg_str(args[1]);
    if let Some(err) = crate::auth::reserved_table_mutation_error(args, store) {
        resp::write_error(out, &err);
        return CmdResult::Written;
    }
    let path = arg_str(args[2]);
    let type_token = arg_str(args[3]);
    match tables::table_create_path_index(store, cache, table, path, type_token, now) {
        Ok(()) => resp::write_ok(out),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_tdropindex(
    args: &[&[u8]],
    store: &Store,
    cache: &SharedSchemaCache,
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    if args.len() != 3 {
        resp::write_error(out, "ERR usage: TDROPINDEX <table> <json.path>");
        return CmdResult::Written;
    }
    let table = arg_str(args[1]);
    if let Some(err) = crate::auth::reserved_table_mutation_error(args, store) {
        resp::write_error(out, &err);
        return CmdResult::Written;
    }
    let path = arg_str(args[2]);
    match tables::table_drop_path_index(store, cache, table, path, now) {
        Ok(()) => resp::write_ok(out),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

/// GRANT <read[, write]> ON <table> [WHERE <predicate>] - operator-issued.
pub fn cmd_grant(
    args: &[&[u8]],
    store: &Store,
    cache: &SharedSchemaCache,
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    let toks: Vec<&str> = args[1..].iter().map(|a| arg_str(a)).collect();
    match crate::grants::parse_grant(&toks) {
        Ok(grant) => match crate::auth::put_grant(store, cache, &grant, now) {
            Ok(()) => resp::write_ok(out),
            Err(e) => resp::write_error(out, &e),
        },
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

/// REVOKE <read[, write]> ON <table> - operator-issued.
pub fn cmd_revoke(
    args: &[&[u8]],
    store: &Store,
    cache: &SharedSchemaCache,
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    let toks: Vec<&str> = args[1..].iter().map(|a| arg_str(a)).collect();
    match crate::grants::parse_revoke(&toks) {
        Ok((table, scopes)) => {
            for scope in scopes {
                if let Err(e) = crate::auth::delete_grant(store, cache, &table, scope, now) {
                    resp::write_error(out, &e);
                    return CmdResult::Written;
                }
            }
            resp::write_ok(out);
        }
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_tcount(
    args: &[&[u8]],
    store: &Store,
    cache: &SharedSchemaCache,
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    if args.len() != 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'tcount' command");
        return CmdResult::Written;
    }
    let table = arg_str(args[1]);
    match tables::table_count(store, cache, table, now) {
        Ok(n) => resp::write_integer(out, n),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_tschema(
    args: &[&[u8]],
    store: &Store,
    cache: &SharedSchemaCache,
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    if args.len() != 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'tschema' command");
        return CmdResult::Written;
    }
    let table = arg_str(args[1]);
    match tables::table_schema(store, cache, table, now) {
        Ok(fields) => {
            resp::write_array_header(out, fields.len());
            for f in fields {
                resp::write_bulk(out, &f);
            }
        }
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_talter(
    args: &[&[u8]],
    store: &Store,
    cache: &SharedSchemaCache,
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    if args.len() < 4 {
        resp::write_error(out, "ERR wrong number of arguments for 'talter' command");
        return CmdResult::Written;
    }
    let table = arg_str(args[1]);
    if let Some(err) = crate::auth::reserved_table_mutation_error(args, store) {
        resp::write_error(out, &err);
        return CmdResult::Written;
    }
    let action = arg_str(args[2]).to_uppercase();
    match action.as_str() {
        "ADD" => {
            // Join all tokens after ADD into one space-separated field spec
            // e.g. TALTER users ADD price FLOAT DEFAULT 9.99
            let field_spec = args[3..]
                .iter()
                .map(|a| arg_str(a))
                .collect::<Vec<_>>()
                .join(" ");
            match tables::table_add_column(store, cache, table, &field_spec, now) {
                Ok(()) => resp::write_ok(out),
                Err(e) => resp::write_error(out, &e),
            }
        }
        "DROP" => {
            let field_name = arg_str(args[3]);
            match tables::table_drop_column(store, cache, table, field_name, now) {
                Ok(()) => resp::write_ok(out),
                Err(e) => resp::write_error(out, &e),
            }
        }
        _ => resp::write_error(
            out,
            &format!(
                "ERR unknown TALTER action '{}', expected ADD or DROP",
                action
            ),
        ),
    }
    CmdResult::Written
}

pub fn cmd_tselect(
    args: &[&[u8]],
    store: &Store,
    cache: &SharedSchemaCache,
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    if args.len() < 4 {
        resp::write_error(out, "ERR usage: TSELECT <cols> FROM <table> [...]");
        return CmdResult::Written;
    }
    // args[0] = "TSELECT", rest is the query
    let str_args: Vec<&str> = args[1..].iter().map(|a| arg_str(a)).collect();
    let plan = match tables::parse_select(&str_args) {
        Ok(p) => p,
        Err(e) => {
            resp::write_error(out, &e);
            return CmdResult::Written;
        }
    };
    match tables::table_select(store, cache, &plan, now) {
        Ok(SelectResult::Rows(rows)) => {
            resp::write_array_header(out, rows.len());
            for row in rows {
                resp::write_array_header(out, row.len() * 2);
                for (k, v) in row {
                    resp::write_bulk(out, &k);
                    resp::write_bulk(out, &v);
                }
            }
        }
        Ok(SelectResult::Aggregate(row)) => {
            // Single aggregate result row
            resp::write_array_header(out, 1);
            resp::write_array_header(out, row.len() * 2);
            for (k, v) in row {
                resp::write_bulk(out, &k);
                resp::write_bulk(out, &v);
            }
        }
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_tlist(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() != 1 {
        resp::write_error(out, "ERR wrong number of arguments for 'tlist' command");
        return CmdResult::Written;
    }
    let tables = tables::table_list(store, now);
    resp::write_array_header(out, tables.len());
    for t in tables {
        resp::write_bulk(out, &t);
    }
    CmdResult::Written
}
