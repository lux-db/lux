use bytes::{Bytes, BytesMut};
use std::time::{Duration, Instant};

use crate::resp;
use crate::store::{Entry, Store, StoreValue};

use super::{arg_str, cmd_eq, parse_i64, parse_u64, CmdResult};

const INTEGER_ERR: &str = "ERR value is not an integer or out of range";

fn parse_i64_arg(arg: &[u8], out: &mut BytesMut) -> Option<i64> {
    match parse_i64(arg) {
        Ok(n) => Some(n),
        Err(_) => {
            resp::write_error(out, INTEGER_ERR);
            None
        }
    }
}

fn parse_u64_arg(arg: &[u8], out: &mut BytesMut) -> Option<u64> {
    match parse_u64(arg) {
        Ok(n) => Some(n),
        Err(_) => {
            resp::write_error(out, INTEGER_ERR);
            None
        }
    }
}

fn parse_positive_ttl(arg: &[u8], command: &str, out: &mut BytesMut) -> Option<u64> {
    match parse_u64(arg) {
        Ok(0) => {
            resp::write_error(
                out,
                &format!("ERR invalid expire time in '{command}' command"),
            );
            None
        }
        Ok(n) => Some(n),
        Err(_) => {
            resp::write_error(out, INTEGER_ERR);
            None
        }
    }
}

pub fn cmd_set(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'set' command");
        return CmdResult::Written;
    }
    let mut ttl = None;
    let mut nx = false;
    let mut xx = false;
    let mut i = 3;
    while i < args.len() {
        if cmd_eq(args[i], b"EX") {
            if i + 1 >= args.len() {
                resp::write_error(out, "ERR syntax error");
                return CmdResult::Written;
            }
            let secs = match parse_positive_ttl(args[i + 1], "set", out) {
                Some(secs) => secs,
                None => return CmdResult::Written,
            };
            ttl = Some(Duration::from_secs(secs));
            i += 2;
        } else if cmd_eq(args[i], b"PX") {
            if i + 1 >= args.len() {
                resp::write_error(out, "ERR syntax error");
                return CmdResult::Written;
            }
            let ms = match parse_positive_ttl(args[i + 1], "set", out) {
                Some(ms) => ms,
                None => return CmdResult::Written,
            };
            ttl = Some(Duration::from_millis(ms));
            i += 2;
        } else if cmd_eq(args[i], b"PXAT") {
            if i + 1 >= args.len() {
                resp::write_error(out, "ERR syntax error");
                return CmdResult::Written;
            }
            match parse_u64(args[i + 1]) {
                Ok(expiry_ms) => {
                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    ttl = Some(Duration::from_millis(expiry_ms.saturating_sub(now_ms)));
                }
                Err(_) => {
                    resp::write_error(out, "ERR value is not an integer or out of range");
                    return CmdResult::Written;
                }
            }
            i += 2;
        } else if cmd_eq(args[i], b"NX") {
            nx = true;
            i += 1;
        } else if cmd_eq(args[i], b"XX") {
            xx = true;
            i += 1;
        } else {
            resp::write_error(out, "ERR syntax error");
            return CmdResult::Written;
        }
    }
    if nx {
        if store.set_nx(args[1], args[2], now) {
            resp::write_ok(out);
        } else {
            resp::write_null(out);
        }
    } else if xx {
        if store.get(args[1], now).is_some() {
            store.set(args[1], args[2], ttl, now);
            resp::write_ok(out);
        } else {
            resp::write_null(out);
        }
    } else {
        store.set(args[1], args[2], ttl, now);
        resp::write_ok(out);
    }
    CmdResult::Written
}

pub fn cmd_setnx(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'setnx' command");
        return CmdResult::Written;
    }
    resp::write_integer(
        out,
        if store.set_nx(args[1], args[2], now) {
            1
        } else {
            0
        },
    );
    CmdResult::Written
}

pub fn cmd_setex(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 4 {
        resp::write_error(out, "ERR wrong number of arguments for 'setex' command");
        return CmdResult::Written;
    }
    match parse_i64(args[2]) {
        Ok(secs) if secs <= 0 => {
            resp::write_error(out, "ERR invalid expire time in 'setex' command")
        }
        Ok(secs) => {
            store.set(
                args[1],
                args[3],
                Some(Duration::from_secs(secs as u64)),
                now,
            );
            resp::write_ok(out);
        }
        Err(_) => resp::write_error(out, "ERR value is not an integer or out of range"),
    }
    CmdResult::Written
}

pub fn cmd_psetex(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 4 {
        resp::write_error(out, "ERR wrong number of arguments for 'psetex' command");
        return CmdResult::Written;
    }
    let ms = match parse_positive_ttl(args[2], "psetex", out) {
        Some(ms) => ms,
        None => return CmdResult::Written,
    };
    store.set(args[1], args[3], Some(Duration::from_millis(ms)), now);
    resp::write_ok(out);
    CmdResult::Written
}

pub fn cmd_get(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'get' command");
        return CmdResult::Written;
    }
    resp::write_optional_bulk_raw(out, &store.get(args[1], now));
    CmdResult::Written
}

pub fn cmd_getset(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'getset' command");
        return CmdResult::Written;
    }
    resp::write_optional_bulk_raw(out, &store.get_set(args[1], args[2], now));
    CmdResult::Written
}

pub fn cmd_getdel(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() != 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'getdel' command");
        return CmdResult::Written;
    }
    resp::write_optional_bulk_raw(out, &store.getdel(args[1], now));
    CmdResult::Written
}

pub fn cmd_getex(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'getex' command");
        return CmdResult::Written;
    }
    let mut ttl = None;
    let mut persist = false;
    let mut option_seen = false;
    let mut i = 2;
    while i < args.len() {
        if cmd_eq(args[i], b"EX") && i + 1 < args.len() {
            if option_seen {
                resp::write_error(out, "ERR syntax error");
                return CmdResult::Written;
            }
            let secs = match parse_positive_ttl(args[i + 1], "getex", out) {
                Some(secs) => secs,
                None => return CmdResult::Written,
            };
            ttl = Some(Duration::from_secs(secs));
            option_seen = true;
            i += 2;
        } else if cmd_eq(args[i], b"PX") && i + 1 < args.len() {
            if option_seen {
                resp::write_error(out, "ERR syntax error");
                return CmdResult::Written;
            }
            let ms = match parse_positive_ttl(args[i + 1], "getex", out) {
                Some(ms) => ms,
                None => return CmdResult::Written,
            };
            ttl = Some(Duration::from_millis(ms));
            option_seen = true;
            i += 2;
        } else if cmd_eq(args[i], b"EXAT") && i + 1 < args.len() {
            if option_seen {
                resp::write_error(out, "ERR syntax error");
                return CmdResult::Written;
            }
            let ts = match parse_u64_arg(args[i + 1], out) {
                Some(ts) => ts,
                None => return CmdResult::Written,
            };
            let now_ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            ttl = Some(Duration::from_secs(ts.saturating_sub(now_ts)));
            option_seen = true;
            i += 2;
        } else if cmd_eq(args[i], b"PXAT") && i + 1 < args.len() {
            if option_seen {
                resp::write_error(out, "ERR syntax error");
                return CmdResult::Written;
            }
            let ts = match parse_u64_arg(args[i + 1], out) {
                Some(ts) => ts,
                None => return CmdResult::Written,
            };
            let now_ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            ttl = Some(Duration::from_millis(ts.saturating_sub(now_ts)));
            option_seen = true;
            i += 2;
        } else if cmd_eq(args[i], b"PERSIST") {
            if option_seen {
                resp::write_error(out, "ERR syntax error");
                return CmdResult::Written;
            }
            persist = true;
            option_seen = true;
            i += 1;
        } else {
            resp::write_error(out, "ERR syntax error");
            return CmdResult::Written;
        }
    }
    resp::write_optional_bulk_raw(out, &store.getex(args[1], ttl, persist, now));
    CmdResult::Written
}

pub fn cmd_getrange(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 4 {
        resp::write_error(out, "ERR wrong number of arguments for 'getrange' command");
        return CmdResult::Written;
    }
    let start = match parse_i64_arg(args[2], out) {
        Some(n) => n,
        None => return CmdResult::Written,
    };
    let end = match parse_i64_arg(args[3], out) {
        Some(n) => n,
        None => return CmdResult::Written,
    };
    let val = store.getrange(args[1], start, end, now);
    resp::write_bulk_raw(out, &val);
    CmdResult::Written
}

pub fn cmd_setrange(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 4 {
        resp::write_error(out, "ERR wrong number of arguments for 'setrange' command");
        return CmdResult::Written;
    }
    let offset_u64 = match parse_u64_arg(args[2], out) {
        Some(n) => n,
        None => return CmdResult::Written,
    };
    let offset = match usize::try_from(offset_u64) {
        Ok(offset) => offset,
        Err(_) => {
            resp::write_error(out, INTEGER_ERR);
            return CmdResult::Written;
        }
    };
    if offset.checked_add(args[3].len()).is_none() {
        resp::write_error(out, INTEGER_ERR);
        return CmdResult::Written;
    }
    resp::write_integer(out, store.setrange(args[1], offset, args[3], now));
    CmdResult::Written
}

pub fn cmd_mget(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'mget' command");
        return CmdResult::Written;
    }
    resp::write_array_header(out, args.len() - 1);
    for key in &args[1..] {
        resp::write_optional_bulk_raw(out, &store.get(key, now));
    }
    CmdResult::Written
}

pub fn cmd_mset(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 3 || !(args.len() - 1).is_multiple_of(2) {
        resp::write_error(out, "ERR wrong number of arguments for 'mset' command");
        return CmdResult::Written;
    }
    let mut i = 1;
    while i < args.len() {
        store.set(args[i], args[i + 1], None, now);
        i += 2;
    }
    resp::write_ok(out);
    CmdResult::Written
}

pub fn cmd_msetnx(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 3 || !(args.len() - 1).is_multiple_of(2) {
        resp::write_error(out, "ERR wrong number of arguments for 'msetnx' command");
        return CmdResult::Written;
    }
    let pairs: Vec<(&[u8], &[u8])> = args[1..].chunks(2).map(|c| (c[0], c[1])).collect();
    resp::write_integer(out, if store.msetnx(&pairs, now) { 1 } else { 0 });
    CmdResult::Written
}

pub fn cmd_strlen(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'strlen' command");
        return CmdResult::Written;
    }
    resp::write_integer(out, store.strlen(args[1], now));
    CmdResult::Written
}

pub fn cmd_append(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'append' command");
        return CmdResult::Written;
    }
    resp::write_integer(out, store.append(args[1], args[2], now));
    CmdResult::Written
}

pub fn cmd_incr(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() != 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'incr' command");
        return CmdResult::Written;
    }
    match store.incr(args[1], 1, now) {
        Ok(n) => resp::write_integer(out, n),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_decr(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() != 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'decr' command");
        return CmdResult::Written;
    }
    match store.incr(args[1], -1, now) {
        Ok(n) => resp::write_integer(out, n),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_incrby(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'incrby' command");
        return CmdResult::Written;
    }
    match parse_i64(args[2]) {
        Ok(delta) => match store.incr(args[1], delta, now) {
            Ok(n) => resp::write_integer(out, n),
            Err(e) => resp::write_error(out, &e),
        },
        Err(_) => resp::write_error(out, "ERR value is not an integer or out of range"),
    }
    CmdResult::Written
}

pub fn cmd_decrby(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'decrby' command");
        return CmdResult::Written;
    }
    match parse_i64(args[2]) {
        Ok(delta) => match store.incr(args[1], -delta, now) {
            Ok(n) => resp::write_integer(out, n),
            Err(e) => resp::write_error(out, &e),
        },
        Err(_) => resp::write_error(out, "ERR value is not an integer or out of range"),
    }
    CmdResult::Written
}

pub fn cmd_incrbyfloat(
    args: &[&[u8]],
    store: &Store,
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    if args.len() != 3 {
        resp::write_error(
            out,
            "ERR wrong number of arguments for 'incrbyfloat' command",
        );
        return CmdResult::Written;
    }
    let delta_str = arg_str(args[2]);
    if delta_str.contains(' ') {
        resp::write_error(out, "ERR value is not a valid float");
        return CmdResult::Written;
    }
    let delta: f64 = match delta_str.parse::<f64>() {
        Ok(d) if d.is_nan() || d.is_infinite() => {
            resp::write_error(out, "ERR increment would produce NaN or Infinity");
            return CmdResult::Written;
        }
        Ok(d) => d,
        Err(_) => {
            resp::write_error(out, "ERR value is not a valid float");
            return CmdResult::Written;
        }
    };
    let idx = store.shard_for_key(args[1]);
    let mut shard = store.lock_write_shard(idx);
    let ks = args[1];
    let current: f64 = match shard.data.get(ks) {
        Some(e) if !e.is_expired_at(now) => match &e.value {
            StoreValue::Str(s) => {
                let ss = std::str::from_utf8(s).unwrap_or("");
                if ss.contains(' ') {
                    resp::write_error(out, "ERR value is not a valid float");
                    return CmdResult::Written;
                }
                match ss.parse::<f64>() {
                    Ok(v) if v.is_nan() || v.is_infinite() => {
                        resp::write_error(out, "ERR value is not a valid float");
                        return CmdResult::Written;
                    }
                    Ok(v) => v,
                    Err(_) => {
                        resp::write_error(out, "ERR value is not a valid float");
                        return CmdResult::Written;
                    }
                }
            }
            _ => {
                resp::write_error(
                    out,
                    "WRONGTYPE Operation against a key holding the wrong kind of value",
                );
                return CmdResult::Written;
            }
        },
        _ => 0.0,
    };
    let new_val = current + delta;
    if new_val.is_nan() || new_val.is_infinite() {
        resp::write_error(out, "ERR increment would produce NaN or Infinity");
        return CmdResult::Written;
    }
    let new_str = if new_val.fract() == 0.0 && new_val.abs() < 1e15 {
        format!("{}", new_val as i64)
    } else {
        format!("{}", new_val)
    };
    let expires_at = shard.data.get(ks).and_then(|e| e.expires_at);
    shard.version += 1;
    shard.data.insert(
        ks.to_vec(),
        Entry {
            value: StoreValue::Str(Bytes::from(new_str.clone())),
            expires_at,
            lru_clock: store.lru_clock(),
        },
    );
    resp::write_bulk(out, &new_str);
    CmdResult::Written
}
