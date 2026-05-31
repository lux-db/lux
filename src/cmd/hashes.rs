use bytes::BytesMut;
use std::time::Instant;

use crate::resp;
use crate::store::{Store, StoreValue};

use super::{arg_str, cmd_eq, parse_i64, parse_u64, CmdResult};

const INTEGER_ERR: &str = "ERR value is not an integer or out of range";

fn parse_usize_arg(arg: &[u8], out: &mut BytesMut) -> Option<usize> {
    match parse_u64(arg).ok().and_then(|n| usize::try_from(n).ok()) {
        Some(n) => Some(n),
        None => {
            resp::write_error(out, INTEGER_ERR);
            None
        }
    }
}

pub fn cmd_hset(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    let is_hmset = cmd_eq(args[0], b"HMSET");
    if args.len() < 4 || !(args.len() - 2).is_multiple_of(2) {
        let cmd_name = if is_hmset { "hmset" } else { "hset" };
        resp::write_error(
            out,
            &format!("ERR wrong number of arguments for '{}' command", cmd_name),
        );
        return CmdResult::Written;
    }
    let result = if args.len() == 4 {
        let pair = [(args[2], args[3])];
        store.hset(args[1], &pair, now)
    } else {
        let pairs: Vec<(&[u8], &[u8])> = args[2..].chunks(2).map(|c| (c[0], c[1])).collect();
        store.hset(args[1], &pairs, now)
    };
    match result {
        Ok(n) => {
            if is_hmset {
                resp::write_ok(out);
            } else {
                resp::write_integer(out, n);
            }
        }
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_hsetnx(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 4 {
        resp::write_error(out, "ERR wrong number of arguments for 'hsetnx' command");
        return CmdResult::Written;
    }
    match store.hsetnx(args[1], args[2], args[3], now) {
        Ok(b) => resp::write_integer(out, if b { 1 } else { 0 }),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_hget(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'hget' command");
        return CmdResult::Written;
    }
    resp::write_optional_bulk_raw(out, &store.hget(args[1], args[2], now));
    CmdResult::Written
}

pub fn cmd_hmget(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'hmget' command");
        return CmdResult::Written;
    }
    let results = store.hmget(args[1], &args[2..], now);
    resp::write_array_header(out, results.len());
    for val in &results {
        resp::write_optional_bulk_raw(out, val);
    }
    CmdResult::Written
}

pub fn cmd_hdel(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'hdel' command");
        return CmdResult::Written;
    }
    match store.hdel(args[1], &args[2..], now) {
        Ok(n) => resp::write_integer(out, n),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_hgetall(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'hgetall' command");
        return CmdResult::Written;
    }
    match store.hgetall(args[1], now) {
        Ok(pairs) => {
            resp::write_array_header(out, pairs.len() * 2);
            for (k, v) in &pairs {
                resp::write_bulk(out, k);
                resp::write_bulk_raw(out, v);
            }
        }
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_hkeys(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'hkeys' command");
        return CmdResult::Written;
    }
    match store.hkeys(args[1], now) {
        Ok(keys) => resp::write_bulk_array(out, &keys),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_hvals(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'hvals' command");
        return CmdResult::Written;
    }
    match store.hvals(args[1], now) {
        Ok(vals) => resp::write_bulk_array_raw(out, &vals),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_hlen(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'hlen' command");
        return CmdResult::Written;
    }
    match store.hlen(args[1], now) {
        Ok(n) => resp::write_integer(out, n),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_hexists(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'hexists' command");
        return CmdResult::Written;
    }
    match store.hexists(args[1], args[2], now) {
        Ok(b) => resp::write_integer(out, if b { 1 } else { 0 }),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_hincrby(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 4 {
        resp::write_error(out, "ERR wrong number of arguments for 'hincrby' command");
        return CmdResult::Written;
    }
    match parse_i64(args[3]) {
        Ok(delta) => match store.hincrby(args[1], args[2], delta, now) {
            Ok(n) => resp::write_integer(out, n),
            Err(e) => resp::write_error(out, &e),
        },
        Err(_) => resp::write_error(out, "ERR value is not an integer or out of range"),
    }
    CmdResult::Written
}

pub fn cmd_hincrbyfloat(
    args: &[&[u8]],
    store: &Store,
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    if args.len() < 4 {
        resp::write_error(
            out,
            "ERR wrong number of arguments for 'hincrbyfloat' command",
        );
        return CmdResult::Written;
    }
    let delta: f64 = match arg_str(args[3]).parse() {
        Ok(d) => d,
        Err(_) => {
            resp::write_error(out, "ERR value is not a valid float");
            return CmdResult::Written;
        }
    };
    match store.hincrbyfloat(args[1], args[2], delta, now) {
        Ok(s) => resp::write_bulk(out, &s),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_hstrlen(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'hstrlen' command");
        return CmdResult::Written;
    }
    resp::write_integer(out, store.hstrlen(args[1], args[2], now));
    CmdResult::Written
}

pub fn cmd_hrandfield(
    args: &[&[u8]],
    store: &Store,
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    if args.len() < 2 {
        resp::write_error(
            out,
            "ERR wrong number of arguments for 'hrandfield' command",
        );
        return CmdResult::Written;
    }
    let count = if args.len() > 2 {
        match parse_i64(args[2]) {
            Ok(c) => c,
            Err(_) => {
                resp::write_error(out, "ERR value is not an integer or out of range");
                return CmdResult::Written;
            }
        }
    } else {
        0
    };
    let with_values = args.len() > 3 && cmd_eq(args[3], b"WITHVALUES");
    let allow_dup = count < 0;
    let abs_count = match count.checked_abs() {
        Some(v) if with_values && v > i64::MAX / 2 => {
            resp::write_error(out, "ERR value is out of range");
            return CmdResult::Written;
        }
        Some(v) => v as usize,
        None => {
            resp::write_error(out, "ERR value is out of range");
            return CmdResult::Written;
        }
    };
    let idx = store.shard_for_key(args[1]);
    let shard = store.lock_read_shard(idx);
    let ks = arg_str(args[1]);
    match shard.data.get(ks) {
        Some(entry) if !entry.is_expired_at(now) => {
            if let StoreValue::Hash(map) = &entry.value {
                if args.len() <= 2 {
                    let all: Vec<_> = map.iter().collect();
                    if all.is_empty() {
                        resp::write_null(out);
                    } else {
                        let seed = now.elapsed().as_nanos() as usize;
                        let idx = if all.is_empty() { 0 } else { seed % all.len() };
                        resp::write_bulk(out, all[idx].0);
                    }
                } else if abs_count == 0 {
                    resp::write_array_header(out, 0);
                } else {
                    let all: Vec<_> = map.iter().collect();
                    let seed = now.elapsed().as_nanos() as usize;
                    let n = if allow_dup {
                        abs_count
                    } else {
                        abs_count.min(all.len())
                    };
                    let mut fields = Vec::with_capacity(n.min(all.len() * 2));
                    if allow_dup {
                        for i in 0..n {
                            let idx = if all.is_empty() {
                                0
                            } else {
                                (seed.wrapping_add(i * 7919)) % all.len()
                            };
                            fields.push(all[idx]);
                        }
                    } else {
                        let start = if all.is_empty() { 0 } else { seed % all.len() };
                        for i in 0..n {
                            fields.push(all[(start + i) % all.len()]);
                        }
                    }
                    if with_values {
                        resp::write_array_header(out, fields.len() * 2);
                        for (k, v) in &fields {
                            resp::write_bulk(out, k);
                            resp::write_bulk_raw(out, v);
                        }
                    } else {
                        resp::write_array_header(out, fields.len());
                        for (k, _) in &fields {
                            resp::write_bulk(out, k);
                        }
                    }
                }
            } else {
                resp::write_error(out, "WRONGTYPE");
            }
        }
        _ => {
            if args.len() <= 2 {
                resp::write_null(out);
            } else {
                resp::write_array_header(out, 0);
            }
        }
    }
    CmdResult::Written
}

pub fn cmd_hscan(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 3 {
        resp::write_error(out, "ERR wrong number of arguments");
        return CmdResult::Written;
    }
    let cursor = match parse_usize_arg(args[2], out) {
        Some(cursor) => cursor,
        None => return CmdResult::Written,
    };
    let mut count = 10usize;
    let mut pattern: Option<&[u8]> = None;
    let mut novalues = false;
    let mut i = 3;
    while i < args.len() {
        if cmd_eq(args[i], b"COUNT") && i + 1 < args.len() {
            count = match parse_usize_arg(args[i + 1], out) {
                Some(count) if count > 0 => count,
                Some(_) => {
                    resp::write_error(out, INTEGER_ERR);
                    return CmdResult::Written;
                }
                None => return CmdResult::Written,
            };
            i += 2;
        } else if cmd_eq(args[i], b"MATCH") && i + 1 < args.len() {
            pattern = Some(args[i + 1]);
            i += 2;
        } else if cmd_eq(args[i], b"NOVALUES") {
            novalues = true;
            i += 1;
        } else {
            resp::write_error(out, "ERR syntax error");
            return CmdResult::Written;
        }
    }
    let pat_str = pattern.map(|p| arg_str(p).to_string());
    let idx = store.shard_for_key(args[1]);
    let shard = store.lock_read_shard(idx);
    let ks = arg_str(args[1]);
    match shard.data.get(ks) {
        Some(entry) if !entry.is_expired_at(now) => {
            if cmd_eq(args[0], b"HSCAN") {
                if let StoreValue::Hash(map) = &entry.value {
                    let all: Vec<_> = map.iter().collect();
                    let s = cursor.min(all.len());
                    let e = (s + count).min(all.len());
                    let next = if e >= all.len() { 0 } else { e };
                    let filtered: Vec<_> = all[s..e]
                        .iter()
                        .filter(|(k, _)| match &pat_str {
                            Some(p) => glob_match(p, k),
                            None => true,
                        })
                        .collect();
                    resp::write_array_header(out, 2);
                    resp::write_bulk(out, &next.to_string());
                    if novalues {
                        resp::write_array_header(out, filtered.len());
                        for (k, _) in &filtered {
                            resp::write_bulk(out, k);
                        }
                    } else {
                        resp::write_array_header(out, filtered.len() * 2);
                        for (k, v) in &filtered {
                            resp::write_bulk(out, k);
                            resp::write_bulk_raw(out, v);
                        }
                    }
                } else {
                    resp::write_error(out, "WRONGTYPE");
                }
            } else if let StoreValue::Set(set) = &entry.value {
                let all: Vec<_> = set.iter().collect();
                let s = cursor.min(all.len());
                let e = (s + count).min(all.len());
                let next = if e >= all.len() { 0 } else { e };
                let filtered: Vec<_> = all[s..e]
                    .iter()
                    .filter(|m| match &pat_str {
                        Some(p) => glob_match(p, m),
                        None => true,
                    })
                    .collect();
                resp::write_array_header(out, 2);
                resp::write_bulk(out, &next.to_string());
                resp::write_array_header(out, filtered.len());
                for m in &filtered {
                    resp::write_bulk(out, m);
                }
            } else {
                resp::write_error(out, "WRONGTYPE");
            }
        }
        _ => {
            resp::write_array_header(out, 2);
            resp::write_bulk(out, "0");
            resp::write_array_header(out, 0);
        }
    }
    CmdResult::Written
}

fn glob_match(pattern: &str, s: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let p: Vec<char> = pattern.chars().collect();
    let s: Vec<char> = s.chars().collect();
    do_glob(&p, &s, 0, 0)
}

fn do_glob(p: &[char], s: &[char], pi: usize, si: usize) -> bool {
    if pi == p.len() && si == s.len() {
        return true;
    }
    if pi == p.len() {
        return false;
    }
    if p[pi] == '*' {
        for i in si..=s.len() {
            if do_glob(p, s, pi + 1, i) {
                return true;
            }
        }
        return false;
    }
    if si == s.len() {
        return false;
    }
    if p[pi] == '?' || p[pi] == s[si] {
        return do_glob(p, s, pi + 1, si + 1);
    }
    false
}
