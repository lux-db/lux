use bytes::BytesMut;
use std::time::Instant;

use crate::resp;
use crate::store::Store;
use crate::tables;

use super::{arg_str, CmdResult};

pub fn cmd_tcreate(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'tcreate' command");
        return CmdResult::Written;
    }
    let table = arg_str(args[1]);
    let field_specs: Vec<&str> = args[2..].iter().map(|a| arg_str(a)).collect();
    match tables::table_create(store, table, &field_specs, now) {
        Ok(()) => resp::write_ok(out),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_tinsert(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 4 || !(args.len() - 2).is_multiple_of(2) {
        resp::write_error(out, "ERR wrong number of arguments for 'tinsert' command");
        return CmdResult::Written;
    }
    let table = arg_str(args[1]);
    let mut field_values: Vec<(&str, &str)> = Vec::new();
    let mut i = 2;
    while i + 1 < args.len() {
        field_values.push((arg_str(args[i]), arg_str(args[i + 1])));
        i += 2;
    }
    match tables::table_insert(store, table, &field_values, now) {
        Ok(id) => resp::write_integer(out, id),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_tget(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() != 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'tget' command");
        return CmdResult::Written;
    }
    let table = arg_str(args[1]);
    let id: i64 = match arg_str(args[2]).parse() {
        Ok(v) => v,
        Err(_) => {
            resp::write_error(out, "ERR invalid row id");
            return CmdResult::Written;
        }
    };
    match tables::table_get(store, table, id, now) {
        Ok(pairs) => {
            resp::write_array_header(out, pairs.len() * 2);
            for (k, v) in pairs {
                resp::write_bulk(out, &k);
                resp::write_bulk(out, &v);
            }
        }
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_tquery(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'tquery' command");
        return CmdResult::Written;
    }
    let table = arg_str(args[1]);
    let str_args: Vec<&str> = args.iter().map(|a| arg_str(a)).collect();
    let plan = match tables::parse_query_args(&str_args, 2) {
        Ok(p) => p,
        Err(e) => {
            resp::write_error(out, &e);
            return CmdResult::Written;
        }
    };
    match tables::table_query(store, table, &plan, now) {
        Ok(results) => {
            resp::write_array_header(out, results.len());
            for (id, row) in results {
                resp::write_array_header(out, 1 + row.len() * 2);
                resp::write_integer(out, id);
                for (k, v) in row {
                    resp::write_bulk(out, &k);
                    resp::write_bulk(out, &v);
                }
            }
        }
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_tupdate(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 5 || !(args.len() - 3).is_multiple_of(2) {
        resp::write_error(out, "ERR wrong number of arguments for 'tupdate' command");
        return CmdResult::Written;
    }
    let table = arg_str(args[1]);
    let id: i64 = match arg_str(args[2]).parse() {
        Ok(v) => v,
        Err(_) => {
            resp::write_error(out, "ERR invalid row id");
            return CmdResult::Written;
        }
    };
    let mut field_values: Vec<(&str, &str)> = Vec::new();
    let mut i = 3;
    while i + 1 < args.len() {
        field_values.push((arg_str(args[i]), arg_str(args[i + 1])));
        i += 2;
    }
    match tables::table_update(store, table, id, &field_values, now) {
        Ok(()) => resp::write_ok(out),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_tdel(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() != 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'tdel' command");
        return CmdResult::Written;
    }
    let table = arg_str(args[1]);
    let id: i64 = match arg_str(args[2]).parse() {
        Ok(v) => v,
        Err(_) => {
            resp::write_error(out, "ERR invalid row id");
            return CmdResult::Written;
        }
    };
    match tables::table_delete(store, table, id, now) {
        Ok(()) => resp::write_ok(out),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_tdrop(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() != 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'tdrop' command");
        return CmdResult::Written;
    }
    let table = arg_str(args[1]);
    match tables::table_drop(store, table, now) {
        Ok(()) => resp::write_ok(out),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_tcount(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() != 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'tcount' command");
        return CmdResult::Written;
    }
    let table = arg_str(args[1]);
    match tables::table_count(store, table, now) {
        Ok(n) => resp::write_integer(out, n),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_tschema(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() != 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'tschema' command");
        return CmdResult::Written;
    }
    let table = arg_str(args[1]);
    match tables::table_schema(store, table, now) {
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
