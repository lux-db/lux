use bytes::BytesMut;
use std::time::Instant;

use crate::resp;
use crate::store::Store;
use crate::tables::{self, SelectResult, SharedSchemaCache};

use super::{arg_str, CmdResult};

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
    if args.len() < 4 || !(args.len() - 2).is_multiple_of(2) {
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
    match tables::table_insert(store, cache, table, &field_values, now) {
        Ok(id) => resp::write_integer(out, id),
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
    // TUPDATE <table> SET <col> <val> [<col> <val> ...] WHERE <conditions>
    // Minimum: TUPDATE users SET name John WHERE id = 1
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

    match tables::table_update_where(store, cache, table, &field_values, &where_args, now) {
        Ok(count) => resp::write_integer(out, count),
        Err(e) => resp::write_error(out, &e),
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
    // TDELETE FROM <table> WHERE <conditions>
    // Minimum: TDELETE FROM users WHERE id = 1
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

    match tables::table_delete_where(store, cache, table, &where_args, now) {
        Ok(count) => resp::write_integer(out, count),
        Err(e) => resp::write_error(out, &e),
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
    if let Some(err) = crate::auth::reserved_table_access_error(table) {
        resp::write_error(out, &err);
        return CmdResult::Written;
    }
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
    if let Some(err) = crate::auth::reserved_table_access_error(table) {
        resp::write_error(out, &err);
        return CmdResult::Written;
    }
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
    if let Some(err) = crate::auth::reserved_plan_access_error(&plan) {
        resp::write_error(out, &err);
        return CmdResult::Written;
    }
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
