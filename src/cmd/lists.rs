use bytes::{Bytes, BytesMut};
use std::time::{Duration, Instant};

use crate::pubsub::Broker;
use crate::resp;
use crate::store::{Store, StoreValue};

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

fn parse_list_side(arg: &[u8], out: &mut BytesMut) -> Option<bool> {
    if cmd_eq(arg, b"LEFT") {
        Some(true)
    } else if cmd_eq(arg, b"RIGHT") {
        Some(false)
    } else {
        resp::write_error(out, "ERR syntax error");
        None
    }
}

fn parse_block_timeout(arg: &[u8], out: &mut BytesMut) -> Option<Duration> {
    match arg_str(arg).parse::<f64>() {
        Ok(secs) if secs >= 0.0 && secs.is_finite() && secs <= u64::MAX as f64 => {
            Some(if secs == 0.0 {
                Duration::from_secs(300)
            } else {
                Duration::from_secs_f64(secs)
            })
        }
        _ => {
            resp::write_error(out, "ERR timeout is not a float or out of range");
            None
        }
    }
}

pub fn cmd_lpush(
    args: &[&[u8]],
    store: &Store,
    _broker: &Broker,
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    if args.len() < 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'lpush' command");
        return CmdResult::Written;
    }
    match store.lpush(args[1], &args[2..], now) {
        Ok(n) => {
            resp::write_integer(out, n);
            let key_s = arg_str(args[1]);
            if _broker.has_list_waiters(key_s) {
                let shard_idx = store.shard_for_key(args[1]);
                let mut shard = store.lock_write_shard(shard_idx);
                _broker.drain_list_waiters(key_s, &mut shard.data, now);
            }
        }
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_rpush(
    args: &[&[u8]],
    store: &Store,
    _broker: &Broker,
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    if args.len() < 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'rpush' command");
        return CmdResult::Written;
    }
    match store.rpush(args[1], &args[2..], now) {
        Ok(n) => {
            resp::write_integer(out, n);
            let key_s = arg_str(args[1]);
            if _broker.has_list_waiters(key_s) {
                let shard_idx = store.shard_for_key(args[1]);
                let mut shard = store.lock_write_shard(shard_idx);
                _broker.drain_list_waiters(key_s, &mut shard.data, now);
            }
        }
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_lpushx(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'lpushx' command");
        return CmdResult::Written;
    }
    resp::write_integer(out, store.lpushx(args[1], &args[2..], now));
    CmdResult::Written
}

pub fn cmd_rpushx(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'rpushx' command");
        return CmdResult::Written;
    }
    resp::write_integer(out, store.rpushx(args[1], &args[2..], now));
    CmdResult::Written
}

pub fn cmd_lpop(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 2 || args.len() > 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'lpop' command");
        return CmdResult::Written;
    }
    if args.len() == 3 {
        let count = match parse_i64(args[2]) {
            Ok(c) if c < 0 => {
                resp::write_error(out, "ERR value is not an integer or out of range");
                return CmdResult::Written;
            }
            Ok(c) => c as usize,
            Err(_) => {
                resp::write_error(out, "ERR value is not an integer or out of range");
                return CmdResult::Written;
            }
        };
        let idx = store.shard_for_key(args[1]);
        let mut shard = store.lock_write_shard(idx);
        shard.version += 1;
        let ks = args[1];
        match shard.data.get_mut(ks) {
            Some(entry) if !entry.is_expired_at(now) => {
                if let StoreValue::List(list) = &mut entry.value {
                    if count == 0 {
                        resp::write_array_header(out, 0);
                    } else {
                        let n = count.min(list.len());
                        let items: Vec<Bytes> = (0..n).filter_map(|_| list.pop_front()).collect();
                        resp::write_array_header(out, items.len());
                        for item in &items {
                            resp::write_bulk_raw(out, item);
                        }
                    }
                } else {
                    resp::write_error(
                        out,
                        "WRONGTYPE Operation against a key holding the wrong kind of value",
                    );
                }
            }
            _ => resp::write_null_array(out),
        }
    } else {
        resp::write_optional_bulk_raw(out, &store.lpop(args[1], now));
    }
    CmdResult::Written
}

pub fn cmd_rpop(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 2 || args.len() > 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'rpop' command");
        return CmdResult::Written;
    }
    if args.len() == 3 {
        let count = match parse_i64(args[2]) {
            Ok(c) if c < 0 => {
                resp::write_error(out, "ERR value is not an integer or out of range");
                return CmdResult::Written;
            }
            Ok(c) => c as usize,
            Err(_) => {
                resp::write_error(out, "ERR value is not an integer or out of range");
                return CmdResult::Written;
            }
        };
        let idx = store.shard_for_key(args[1]);
        let mut shard = store.lock_write_shard(idx);
        shard.version += 1;
        let ks = args[1];
        match shard.data.get_mut(ks) {
            Some(entry) if !entry.is_expired_at(now) => {
                if let StoreValue::List(list) = &mut entry.value {
                    if count == 0 {
                        resp::write_array_header(out, 0);
                    } else {
                        let n = count.min(list.len());
                        let items: Vec<Bytes> = (0..n).filter_map(|_| list.pop_back()).collect();
                        resp::write_array_header(out, items.len());
                        for item in &items {
                            resp::write_bulk_raw(out, item);
                        }
                    }
                } else {
                    resp::write_error(
                        out,
                        "WRONGTYPE Operation against a key holding the wrong kind of value",
                    );
                }
            }
            _ => resp::write_null_array(out),
        }
    } else {
        resp::write_optional_bulk_raw(out, &store.rpop(args[1], now));
    }
    CmdResult::Written
}

pub fn cmd_llen(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'llen' command");
        return CmdResult::Written;
    }
    match store.llen(args[1], now) {
        Ok(n) => resp::write_integer(out, n),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_lrange(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 4 {
        resp::write_error(out, "ERR wrong number of arguments for 'lrange' command");
        return CmdResult::Written;
    }
    let start = match parse_i64_arg(args[2], out) {
        Some(n) => n,
        None => return CmdResult::Written,
    };
    let stop = match parse_i64_arg(args[3], out) {
        Some(n) => n,
        None => return CmdResult::Written,
    };
    match store.lrange(args[1], start, stop, now) {
        Ok(items) => resp::write_bulk_array_raw(out, &items),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_lindex(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'lindex' command");
        return CmdResult::Written;
    }
    let index = match parse_i64_arg(args[2], out) {
        Some(n) => n,
        None => return CmdResult::Written,
    };
    resp::write_optional_bulk_raw(out, &store.lindex(args[1], index, now));
    CmdResult::Written
}

pub fn cmd_lset(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 4 {
        resp::write_error(out, "ERR wrong number of arguments for 'lset' command");
        return CmdResult::Written;
    }
    let index = match parse_i64_arg(args[2], out) {
        Some(n) => n,
        None => return CmdResult::Written,
    };
    match store.lset(args[1], index, args[3], now) {
        Ok(()) => resp::write_ok(out),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_linsert(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 5 {
        resp::write_error(out, "ERR wrong number of arguments for 'linsert' command");
        return CmdResult::Written;
    }
    let before = if cmd_eq(args[2], b"BEFORE") {
        true
    } else if cmd_eq(args[2], b"AFTER") {
        false
    } else {
        resp::write_error(out, "ERR syntax error");
        return CmdResult::Written;
    };
    match store.linsert(args[1], before, args[3], args[4], now) {
        Ok(n) => resp::write_integer(out, n),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_lrem(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 4 {
        resp::write_error(out, "ERR wrong number of arguments for 'lrem' command");
        return CmdResult::Written;
    }
    let count = match parse_i64_arg(args[2], out) {
        Some(n) => n,
        None => return CmdResult::Written,
    };
    match store.lrem(args[1], count, args[3], now) {
        Ok(n) => resp::write_integer(out, n),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_ltrim(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 4 {
        resp::write_error(out, "ERR wrong number of arguments for 'ltrim' command");
        return CmdResult::Written;
    }
    match store.ltrim(
        args[1],
        match parse_i64_arg(args[2], out) {
            Some(n) => n,
            None => return CmdResult::Written,
        },
        match parse_i64_arg(args[3], out) {
            Some(n) => n,
            None => return CmdResult::Written,
        },
        now,
    ) {
        Ok(()) => resp::write_ok(out),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_lpos(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'lpos' command");
        return CmdResult::Written;
    }
    let key = args[1];
    let element = args[2];
    let mut rank = 1i64;
    let mut count = None::<usize>;
    let mut maxlen = 0usize;
    let mut i = 3;
    while i < args.len() {
        if cmd_eq(args[i], b"RANK") && i + 1 < args.len() {
            rank = match parse_i64_arg(args[i + 1], out) {
                Some(n) => n,
                None => return CmdResult::Written,
            };
            if rank == 0 {
                resp::write_error(out, "ERR RANK can't be zero: use 1 to start from the first match, 2 from the second ... or use negative to start from the end of the list");
                return CmdResult::Written;
            }
            if rank == i64::MIN {
                resp::write_error(out, "ERR value is out of range");
                return CmdResult::Written;
            }
            i += 2;
        } else if cmd_eq(args[i], b"COUNT") && i + 1 < args.len() {
            let c = match parse_u64_arg(args[i + 1], out) {
                Some(n) => n as usize,
                None => return CmdResult::Written,
            };
            count = Some(c);
            i += 2;
        } else if cmd_eq(args[i], b"MAXLEN") && i + 1 < args.len() {
            maxlen = match parse_u64_arg(args[i + 1], out) {
                Some(n) => n as usize,
                None => return CmdResult::Written,
            };
            i += 2;
        } else {
            resp::write_error(out, "ERR syntax error");
            return CmdResult::Written;
        }
    }
    let idx = store.shard_for_key(key);
    let shard = store.lock_read_shard(idx);
    let ks = key;
    match shard.data.get(ks) {
        Some(entry) if !entry.is_expired_at(now) => {
            if let StoreValue::List(list) = &entry.value {
                let list_len = list.len();
                let mut matches = Vec::new();
                if rank > 0 {
                    let scan_len = if maxlen > 0 {
                        maxlen.min(list_len)
                    } else {
                        list_len
                    };
                    let mut found = 0i64;
                    for (j, item) in list.iter().take(scan_len).enumerate() {
                        if item.as_ref() == element {
                            found += 1;
                            if found >= rank {
                                matches.push(j as i64);
                                if let Some(c) = count {
                                    if c > 0 && matches.len() >= c {
                                        break;
                                    }
                                } else {
                                    break;
                                }
                            }
                        }
                    }
                } else {
                    let start = if maxlen > 0 && maxlen < list_len {
                        list_len - maxlen
                    } else {
                        0
                    };
                    let mut found = 0i64;
                    for j in (start..list_len).rev() {
                        if list[j].as_ref() == element {
                            found += 1;
                            if found >= rank.abs() {
                                matches.push(j as i64);
                                if let Some(c) = count {
                                    if c > 0 && matches.len() >= c {
                                        break;
                                    }
                                } else {
                                    break;
                                }
                            }
                        }
                    }
                }
                if count.is_some() {
                    resp::write_array_header(out, matches.len());
                    for m in &matches {
                        resp::write_integer(out, *m);
                    }
                } else if matches.is_empty() {
                    resp::write_null(out);
                } else {
                    resp::write_integer(out, matches[0]);
                }
            } else {
                resp::write_error(out, "WRONGTYPE");
            }
        }
        _ => {
            if count.is_some() {
                resp::write_array_header(out, 0);
            } else {
                resp::write_null(out);
            }
        }
    }
    CmdResult::Written
}

pub fn cmd_lmove(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 5 {
        resp::write_error(out, "ERR wrong number of arguments for 'lmove' command");
        return CmdResult::Written;
    }
    let src_left = match parse_list_side(args[3], out) {
        Some(side) => side,
        None => return CmdResult::Written,
    };
    let dst_left = match parse_list_side(args[4], out) {
        Some(side) => side,
        None => return CmdResult::Written,
    };
    resp::write_optional_bulk_raw(out, &store.lmove(args[1], args[2], src_left, dst_left, now));
    CmdResult::Written
}

pub fn cmd_rpoplpush(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'rpoplpush' command");
        return CmdResult::Written;
    }
    resp::write_optional_bulk_raw(out, &store.lmove(args[1], args[2], false, true, now));
    CmdResult::Written
}

pub fn cmd_blpop(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 3 {
        resp::write_error(
            out,
            &format!(
                "ERR wrong number of arguments for '{}' command",
                arg_str(args[0]).to_lowercase()
            ),
        );
        return CmdResult::Written;
    }
    let pop_left = cmd_eq(args[0], b"BLPOP");
    let timeout = match parse_block_timeout(args[args.len() - 1], out) {
        Some(timeout) => timeout,
        None => return CmdResult::Written,
    };
    let keys: Vec<String> = args[1..args.len() - 1]
        .iter()
        .map(|k| arg_str(k).to_string())
        .collect();

    for key in &keys {
        let val = if pop_left {
            store.lpop(key.as_bytes(), now)
        } else {
            store.rpop(key.as_bytes(), now)
        };
        if let Some(v) = val {
            resp::write_array_header(out, 2);
            resp::write_bulk(out, key);
            resp::write_bulk_raw(out, &v);
            return CmdResult::Written;
        }
    }

    CmdResult::BlockPop {
        keys,
        timeout,
        pop_left,
    }
}

pub fn cmd_blmove(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 6 {
        resp::write_error(out, "ERR wrong number of arguments for 'blmove' command");
        return CmdResult::Written;
    }
    let src = arg_str(args[1]).to_string();
    let dst = arg_str(args[2]).to_string();
    let src_left = match parse_list_side(args[3], out) {
        Some(side) => side,
        None => return CmdResult::Written,
    };
    let dst_left = match parse_list_side(args[4], out) {
        Some(side) => side,
        None => return CmdResult::Written,
    };
    let timeout = match parse_block_timeout(args[5], out) {
        Some(timeout) => timeout,
        None => return CmdResult::Written,
    };

    if let Some(v) = store.lmove(args[1], args[2], src_left, dst_left, now) {
        resp::write_bulk_raw(out, &v);
        return CmdResult::Written;
    }

    CmdResult::BlockMove {
        src,
        dst,
        src_left,
        dst_left,
        timeout,
    }
}
