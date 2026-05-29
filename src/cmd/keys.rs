use bytes::BytesMut;
use std::time::Instant;

use crate::resp;
use crate::store::{Store, StoreValue};

use super::{arg_str, cmd_eq, parse_i64, parse_u64, CmdResult};

pub fn cmd_del(args: &[&[u8]], store: &Store, out: &mut BytesMut, _now: Instant) -> CmdResult {
    if args.len() < 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'del' command");
        return CmdResult::Written;
    }
    resp::write_integer(out, store.del(&args[1..]));
    CmdResult::Written
}

pub fn cmd_unlink(args: &[&[u8]], store: &Store, out: &mut BytesMut, _now: Instant) -> CmdResult {
    if args.len() < 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'unlink' command");
        return CmdResult::Written;
    }
    resp::write_integer(out, store.unlink(&args[1..]));
    CmdResult::Written
}

pub fn cmd_exists(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'exists' command");
        return CmdResult::Written;
    }
    resp::write_integer(out, store.exists(&args[1..], now));
    CmdResult::Written
}

pub fn cmd_keys(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'keys' command");
        return CmdResult::Written;
    }
    let keys = store.keys(args[1], now);
    resp::write_bulk_array(out, &keys);
    CmdResult::Written
}

pub fn cmd_scan(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'scan' command");
        return CmdResult::Written;
    }
    let cursor = parse_u64(args[1]).unwrap_or(0) as usize;
    let mut pattern: &[u8] = b"*";
    let mut count = 10usize;
    let mut type_filter: Option<&str> = None;
    let mut i = 2;
    while i < args.len() {
        if cmd_eq(args[i], b"MATCH") && i + 1 < args.len() {
            pattern = args[i + 1];
            i += 2;
        } else if cmd_eq(args[i], b"COUNT") && i + 1 < args.len() {
            count = parse_u64(args[i + 1]).unwrap_or(10) as usize;
            i += 2;
        } else if cmd_eq(args[i], b"TYPE") && i + 1 < args.len() {
            type_filter = Some(arg_str(args[i + 1]));
            i += 2;
        } else {
            i += 1;
        }
    }
    let (next_cursor, all_keys) = store.scan(cursor, pattern, count, now);
    let keys: Vec<String> = if let Some(tf) = type_filter {
        all_keys
            .into_iter()
            .filter(|k| store.get_entry_type(k.as_bytes(), now) == Some(tf))
            .collect()
    } else {
        all_keys
    };
    resp::write_array_header(out, 2);
    resp::write_bulk(out, &next_cursor.to_string());
    resp::write_bulk_array(out, &keys);
    CmdResult::Written
}

pub fn cmd_type(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'type' command");
        return CmdResult::Written;
    }
    match store.get_entry_type(args[1], now) {
        Some(t) => resp::write_simple(out, t),
        None => resp::write_simple(out, "none"),
    }
    CmdResult::Written
}

pub fn cmd_rename(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'rename' command");
        return CmdResult::Written;
    }
    match store.rename(args[1], args[2], now) {
        Ok(()) => resp::write_ok(out),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_renamenx(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'renamenx' command");
        return CmdResult::Written;
    }
    if store.get(args[2], now).is_some() {
        resp::write_integer(out, 0);
    } else {
        match store.rename(args[1], args[2], now) {
            Ok(()) => resp::write_integer(out, 1),
            Err(e) => resp::write_error(out, &e),
        }
    }
    CmdResult::Written
}

pub fn cmd_randomkey(
    _args: &[&[u8]],
    store: &Store,
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    let mut found = None;
    for i in 0..store.shard_count() {
        let shard = store.lock_read_shard(i);
        if let Some((k, entry)) = shard.data.iter().next() {
            if !entry.is_expired_at(now) {
                found = Some(k.clone());
                break;
            }
        }
    }
    match found {
        Some(k) => resp::write_bulk(out, &k),
        None => resp::write_null(out),
    }
    CmdResult::Written
}

pub fn cmd_copy(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'copy' command");
        return CmdResult::Written;
    }
    let mut replace = false;
    let mut i = 3;
    while i < args.len() {
        if cmd_eq(args[i], b"REPLACE") {
            replace = true;
            i += 1;
        } else if cmd_eq(args[i], b"DESTINATION") || cmd_eq(args[i], b"DB") {
            i += 1;
            if i >= args.len() {
                resp::write_error(out, "ERR syntax error");
                return CmdResult::Written;
            }
            match parse_i64(args[i]) {
                Ok(0) => {
                    i += 1;
                }
                Ok(_) => {
                    resp::write_error(out, "ERR invalid DB index");
                    return CmdResult::Written;
                }
                Err(_) => {
                    resp::write_error(out, "ERR value is not an integer or out of range");
                    return CmdResult::Written;
                }
            }
        } else {
            resp::write_error(out, "ERR syntax error");
            return CmdResult::Written;
        }
    }
    match store.copy_key(args[1], args[2], replace, now) {
        Ok(copied) => resp::write_integer(out, if copied { 1 } else { 0 }),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_ttl(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'ttl' command");
        return CmdResult::Written;
    }
    resp::write_integer(out, store.ttl(args[1], now));
    CmdResult::Written
}

pub fn cmd_pttl(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'pttl' command");
        return CmdResult::Written;
    }
    resp::write_integer(out, store.pttl(args[1], now));
    CmdResult::Written
}

pub fn cmd_expire(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'expire' command");
        return CmdResult::Written;
    }
    match parse_u64(args[2]) {
        Ok(secs) => resp::write_integer(
            out,
            if store.expire(args[1], secs, now) {
                1
            } else {
                0
            },
        ),
        Err(_) => resp::write_error(out, "ERR value is not an integer or out of range"),
    }
    CmdResult::Written
}

pub fn cmd_pexpire(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'pexpire' command");
        return CmdResult::Written;
    }
    match parse_u64(args[2]) {
        Ok(ms) => resp::write_integer(
            out,
            if store.pexpire(args[1], ms, now) {
                1
            } else {
                0
            },
        ),
        Err(_) => resp::write_error(out, "ERR value is not an integer or out of range"),
    }
    CmdResult::Written
}

pub fn cmd_expireat(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'expireat' command");
        return CmdResult::Written;
    }
    match parse_u64(args[2]) {
        Ok(ts) => resp::write_integer(
            out,
            if store.expireat(args[1], ts, now) {
                1
            } else {
                0
            },
        ),
        Err(_) => resp::write_error(out, "ERR value is not an integer or out of range"),
    }
    CmdResult::Written
}

pub fn cmd_pexpireat(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'pexpireat' command");
        return CmdResult::Written;
    }
    match parse_u64(args[2]) {
        Ok(ts) => resp::write_integer(
            out,
            if store.pexpireat(args[1], ts, now) {
                1
            } else {
                0
            },
        ),
        Err(_) => resp::write_error(out, "ERR value is not an integer or out of range"),
    }
    CmdResult::Written
}

pub fn cmd_expiretime(
    args: &[&[u8]],
    store: &Store,
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    if args.len() < 2 {
        resp::write_error(out, "ERR wrong number of arguments");
        return CmdResult::Written;
    }
    resp::write_integer(out, store.expiretime(args[1], now));
    CmdResult::Written
}

pub fn cmd_pexpiretime(
    args: &[&[u8]],
    store: &Store,
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    if args.len() < 2 {
        resp::write_error(out, "ERR wrong number of arguments");
        return CmdResult::Written;
    }
    resp::write_integer(out, store.pexpiretime(args[1], now));
    CmdResult::Written
}

pub fn cmd_persist(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'persist' command");
        return CmdResult::Written;
    }
    resp::write_integer(out, if store.persist(args[1], now) { 1 } else { 0 });
    CmdResult::Written
}

pub fn cmd_dbsize(_args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    resp::write_integer(out, store.dbsize(now));
    CmdResult::Written
}

pub fn cmd_flushdb(_args: &[&[u8]], store: &Store, out: &mut BytesMut, _now: Instant) -> CmdResult {
    store.flushdb();
    resp::write_ok(out);
    CmdResult::Written
}

pub fn cmd_object(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() > 2 && cmd_eq(args[1], b"REFCOUNT") {
        resp::write_integer(out, 1);
    } else if args.len() > 2 && cmd_eq(args[1], b"ENCODING") {
        let key = args[2];
        let idx = store.shard_for_key(key);
        let shard = store.lock_read_shard(idx);
        let ks = arg_str(key);
        match shard.data.get(ks) {
            Some(entry) if !entry.is_expired_at(now) => {
                let enc = match &entry.value {
                    StoreValue::Str(s) => {
                        if let Ok(ss) = std::str::from_utf8(s) {
                            if ss.parse::<i64>().is_ok() {
                                "int"
                            } else if s.len() <= 44 {
                                "embstr"
                            } else {
                                "raw"
                            }
                        } else {
                            "raw"
                        }
                    }
                    StoreValue::StrBuf(s) => {
                        if let Ok(ss) = std::str::from_utf8(s) {
                            if ss.parse::<i64>().is_ok() {
                                "int"
                            } else if s.len() <= 44 {
                                "embstr"
                            } else {
                                "raw"
                            }
                        } else {
                            "raw"
                        }
                    }
                    StoreValue::List(l) => {
                        if l.len() <= 128 {
                            "listpack"
                        } else {
                            "quicklist"
                        }
                    }
                    StoreValue::Hash(h) => {
                        if h.len() < 128 && h.iter().all(|(k, v)| k.len() <= 64 && v.len() <= 64) {
                            "listpack"
                        } else {
                            "hashtable"
                        }
                    }
                    StoreValue::Set(s) => {
                        if s.iter().all(|m| m.parse::<i64>().is_ok()) && s.len() <= 512 {
                            "intset"
                        } else if s.len() < 128 {
                            "listpack"
                        } else {
                            "hashtable"
                        }
                    }
                    StoreValue::SortedSet(_, scores) => {
                        if scores.len() < 128 {
                            "listpack"
                        } else {
                            "skiplist"
                        }
                    }
                    StoreValue::Stream(_) => "stream",
                    StoreValue::Vector(_) => "raw",
                    StoreValue::HyperLogLog(..) => "raw",
                    StoreValue::TimeSeries(_) => "timeseries",
                };
                resp::write_bulk(out, enc);
            }
            _ => resp::write_error(out, "ERR no such key"),
        }
    } else if args.len() > 2 && cmd_eq(args[1], b"IDLETIME") {
        resp::write_integer(out, 0);
    } else {
        resp::write_ok(out);
    }
    CmdResult::Written
}

pub fn cmd_memory(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() > 2 && cmd_eq(args[1], b"USAGE") {
        let key = args[2];
        let idx = store.shard_for_key(key);
        let shard = store.lock_read_shard(idx);
        let ks = arg_str(key);
        match shard.data.get(ks) {
            Some(entry) if !entry.is_expired_at(now) => {
                let size = ks.len()
                    + 64
                    + match &entry.value {
                        StoreValue::Str(s) => s.len() + 16,
                        StoreValue::StrBuf(s) => s.len() + 16,
                        StoreValue::List(l) => l.iter().map(|b| b.len() + 16).sum::<usize>(),
                        StoreValue::Hash(h) => {
                            h.iter().map(|(k, v)| k.len() + v.len() + 32).sum::<usize>()
                        }
                        StoreValue::Set(s) => s.iter().map(|m| m.len() + 16).sum::<usize>(),
                        StoreValue::SortedSet(_, scores) => {
                            scores.iter().map(|(m, _)| m.len() + 48).sum::<usize>()
                        }
                        StoreValue::Stream(s) => s
                            .entries
                            .values()
                            .map(|fields| {
                                16 + fields
                                    .iter()
                                    .map(|(k, v)| k.len() + v.len() + 32)
                                    .sum::<usize>()
                            })
                            .sum::<usize>(),
                        StoreValue::Vector(v) => {
                            16 + (v.data.len() * 4) + v.metadata.as_ref().map_or(0, |m| m.len())
                        }
                        StoreValue::HyperLogLog(regs, _) => regs.len(),
                        StoreValue::TimeSeries(ts) => ts.samples.len() * 16,
                    };
                resp::write_integer(out, size as i64);
            }
            _ => resp::write_null(out),
        }
    } else {
        resp::write_ok(out);
    }
    CmdResult::Written
}
