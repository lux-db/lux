use bytes::{Bytes, BytesMut};
use std::time::{Duration, Instant};

use crate::pubsub::Broker;
use crate::resp;
use crate::store::{JournalPlan, Store, StoreValue};

use super::{arg_str, cmd_eq, parse_i64, parse_u64, CmdResult};

const INTEGER_ERR: &str = "ERR value is not an integer or out of range";
type ListPopResult = Option<(Vec<u8>, Vec<Bytes>)>;

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

/// Decrypt a list element for output, passing plaintext (and, defensively, any
/// value we cannot decrypt) through unchanged.
fn decrypt_out(store: &Store, raw: Bytes) -> Bytes {
    store.decrypt_list_element(raw.clone()).unwrap_or(raw)
}

/// Shared LPUSH/RPUSH body. Supports a trailing `ENCRYPTED` flag (mirrors
/// `SET ... ENCRYPTED`): each pushed element is sealed as an envelope and the
/// resolved ciphertext crosses the journal as `ENC RAWLPUSH/RAWRPUSH` so
/// replay is deterministic (envelopes carry random nonces).
fn push_list(
    args: &[&[u8]],
    store: &Store,
    _broker: &Broker,
    out: &mut BytesMut,
    now: Instant,
    front: bool,
) -> CmdResult {
    let name = if front { "lpush" } else { "rpush" };
    let encrypted = args.last().is_some_and(|a| cmd_eq(a, b"ENCRYPTED"));
    let end = if encrypted {
        args.len() - 1
    } else {
        args.len()
    };
    if end < 3 {
        resp::write_error(
            out,
            &format!("ERR wrong number of arguments for '{name}' command"),
        );
        return CmdResult::Written;
    }
    let stored: Vec<Vec<u8>> = if encrypted {
        match args[2..end]
            .iter()
            .map(|v| store.encrypt_list_element(v))
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(s) => s,
            Err(e) => {
                resp::write_error(out, &e);
                return CmdResult::Written;
            }
        }
    } else {
        args[2..end].iter().map(|v| v.to_vec()).collect()
    };
    let journal_args = if encrypted {
        let raw_cmd: &[u8] = if front { b"RAWLPUSH" } else { b"RAWRPUSH" };
        let mut command = vec![b"ENC".to_vec(), raw_cmd.to_vec(), args[1].to_vec()];
        command.extend(stored.iter().cloned());
        Some(command)
    } else {
        None
    };
    let stored_refs: Vec<&[u8]> = stored.iter().map(Vec::as_slice).collect();
    let res = if let Some(journal_args) = &journal_args {
        let journal_refs: Vec<&[u8]> = journal_args.iter().map(Vec::as_slice).collect();
        match store.commit_journaled_checked(&journal_refs, || {
            let result = if front {
                store.lpush(args[1], &stored_refs, now)
            } else {
                store.rpush(args[1], &stored_refs, now)
            };
            let committed = result.is_ok();
            (result, committed)
        }) {
            Ok(result) => result,
            Err(e) => {
                resp::write_error(out, &format!("ERR WAL append failed: {e}"));
                return CmdResult::Written;
            }
        }
    } else {
        if front {
            store.lpush(args[1], &stored_refs, now)
        } else {
            store.rpush(args[1], &stored_refs, now)
        }
    };
    match res {
        Ok(n) => resp::write_integer(out, n),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_lpush(
    args: &[&[u8]],
    store: &Store,
    broker: &Broker,
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    if args.len() < 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'lpush' command");
        return CmdResult::Written;
    }
    push_list(args, store, broker, out, now, true)
}

pub fn cmd_rpush(
    args: &[&[u8]],
    store: &Store,
    broker: &Broker,
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    if args.len() < 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'rpush' command");
        return CmdResult::Written;
    }
    push_list(args, store, broker, out, now, false)
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
                            resp::write_bulk_raw(out, &decrypt_out(store, item.clone()));
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
        resp::write_optional_bulk_raw(
            out,
            &store.lpop(args[1], now).map(|b| decrypt_out(store, b)),
        );
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
                            resp::write_bulk_raw(out, &decrypt_out(store, item.clone()));
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
        resp::write_optional_bulk_raw(
            out,
            &store.rpop(args[1], now).map(|b| decrypt_out(store, b)),
        );
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
        Ok(items) => {
            let dec: Vec<Bytes> = items.into_iter().map(|b| decrypt_out(store, b)).collect();
            resp::write_bulk_array_raw(out, &dec);
        }
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
    resp::write_optional_bulk_raw(
        out,
        &store
            .lindex(args[1], index, now)
            .map(|b| decrypt_out(store, b)),
    );
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

/// Resolve, journal, and apply a list move under the same mutation gates.
fn journaled_list_move(
    store: &Store,
    src: &[u8],
    dst: &[u8],
    src_left: bool,
    dst_left: bool,
    now: Instant,
) -> Result<Option<Bytes>, String> {
    let route: [&[u8]; 3] = [b"LMOVE", src, dst];
    store
        .commit_prepared(
            &route,
            || {
                let moved = store.preview_lmove(src, dst, src_left, now)?;
                let Some(moved) = moved else {
                    return Ok(JournalPlan::no_op(None));
                };
                let pop = if src_left { b"LPOP" } else { b"RPOP" };
                let push = if dst_left { b"LPUSH" } else { b"RPUSH" };
                Ok(JournalPlan::batch(
                    vec![
                        vec![pop.to_vec(), src.to_vec()],
                        vec![push.to_vec(), dst.to_vec(), moved.to_vec()],
                    ],
                    Some(moved),
                ))
            },
            |expected| {
                let Some(expected) = expected else {
                    return Ok(None);
                };
                let actual = store.lmove(src, dst, src_left, dst_left, now);
                if actual.as_ref() != Some(&expected) {
                    return Err("ERR list move changed while committing".to_string());
                }
                Ok(actual)
            },
        )
        .map_err(|error| format!("ERR WAL append failed: {error}"))?
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
    match journaled_list_move(store, args[1], args[2], src_left, dst_left, now) {
        Ok(Some(v)) => {
            resp::write_bulk_raw(out, &decrypt_out(store, v));
        }
        Ok(None) => resp::write_null(out),
        Err(error) => resp::write_error(out, &error),
    }
    CmdResult::Written
}

pub fn cmd_rpoplpush(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'rpoplpush' command");
        return CmdResult::Written;
    }
    match journaled_list_move(store, args[1], args[2], false, true, now) {
        Ok(Some(v)) => {
            resp::write_bulk_raw(out, &decrypt_out(store, v));
        }
        Ok(None) => resp::write_null(out),
        Err(error) => resp::write_error(out, &error),
    }
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
    let key_refs: Vec<&[u8]> = args[1..args.len() - 1].to_vec();
    match journaled_lmpop(store, &key_refs, pop_left, 1, now) {
        Ok(Some((key, mut items))) => {
            let v = items
                .pop()
                .expect("journaled single list pop returned one item");
            resp::write_array_header(out, 2);
            resp::write_bulk_raw(out, &key);
            resp::write_bulk_raw(out, &decrypt_out(store, v));
            return CmdResult::Written;
        }
        Ok(None) => {}
        Err(error) => {
            resp::write_error(out, &error);
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

    // Immediately-satisfiable BLMOVE moves like LMOVE, so it must be logged the
    // same way (it isn't classified as a write command, so execute_with_wal never
    // logs it). Self-log the resolved pop+push keyed per-key. The blocked path
    // (CmdResult::BlockMove) is logged when the waiter is later satisfied.
    match journaled_list_move(store, args[1], args[2], src_left, dst_left, now) {
        Ok(Some(v)) => {
            resp::write_bulk_raw(out, &decrypt_out(store, v));
            return CmdResult::Written;
        }
        Ok(None) => {}
        Err(error) => {
            resp::write_error(out, &error);
            return CmdResult::Written;
        }
    }

    CmdResult::BlockMove {
        src,
        dst,
        src_left,
        dst_left,
        timeout,
    }
}

/// Parse the shared tail of LMPOP/BLMPOP starting at the numkeys argument index
/// `base`: `numkeys key [key ...] <LEFT|RIGHT> [COUNT count]`.
fn parse_lmpop_args<'a>(
    args: &'a [&'a [u8]],
    base: usize,
    out: &mut BytesMut,
) -> Option<(Vec<&'a [u8]>, bool, usize)> {
    let numkeys = match parse_u64(args[base]) {
        Ok(n) if n >= 1 => n as usize,
        _ => {
            resp::write_error(out, "ERR numkeys should be greater than 0");
            return None;
        }
    };
    let dir_idx = base + 1 + numkeys;
    if dir_idx >= args.len() {
        resp::write_error(out, "ERR syntax error");
        return None;
    }
    let keys: Vec<&[u8]> = args[base + 1..base + 1 + numkeys].to_vec();
    let pop_left = if cmd_eq(args[dir_idx], b"LEFT") {
        true
    } else if cmd_eq(args[dir_idx], b"RIGHT") {
        false
    } else {
        resp::write_error(out, "ERR syntax error");
        return None;
    };
    let mut count = 1usize;
    let rest = &args[dir_idx + 1..];
    if !rest.is_empty() {
        if rest.len() == 2 && cmd_eq(rest[0], b"COUNT") {
            match parse_u64(rest[1]) {
                Ok(n) if n >= 1 => count = n as usize,
                _ => {
                    resp::write_error(out, "ERR count should be greater than 0");
                    return None;
                }
            }
        } else {
            resp::write_error(out, "ERR syntax error");
            return None;
        }
    }
    Some((keys, pop_left, count))
}

/// Write the LMPOP/BLMPOP success reply: `[key, [elements...]]`.
fn write_lmpop_reply(store: &Store, out: &mut BytesMut, key: &[u8], items: &[Bytes]) {
    resp::write_array_header(out, 2);
    resp::write_bulk_raw(out, key);
    resp::write_array_header(out, items.len());
    for item in items {
        resp::write_bulk_raw(out, &decrypt_out(store, item.clone()));
    }
}

pub(crate) fn journaled_lmpop(
    store: &Store,
    keys: &[&[u8]],
    pop_left: bool,
    count: usize,
    now: Instant,
) -> Result<ListPopResult, String> {
    let route: [&[u8]; 1] = [b"LMPOP"];
    store
        .commit_prepared(
            &route,
            || {
                let expected = store.preview_lmpop(keys, pop_left, count, now)?;
                let Some((key, items)) = &expected else {
                    return Ok(JournalPlan::no_op(None));
                };
                let command = if pop_left { b"LPOP" } else { b"RPOP" };
                Ok(JournalPlan::command(
                    vec![
                        command.to_vec(),
                        key.clone(),
                        items.len().to_string().into_bytes(),
                    ],
                    expected,
                ))
            },
            |expected| {
                let Some(expected) = expected else {
                    return Ok(None);
                };
                let actual = store.lmpop(keys, pop_left, count, now)?;
                if actual.as_ref() != Some(&expected) {
                    return Err("ERR list pop changed while committing".to_string());
                }
                Ok(actual)
            },
        )
        .map_err(|error| format!("ERR WAL append failed: {error}"))?
}

pub fn cmd_lmpop(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    // LMPOP numkeys key [key ...] <LEFT|RIGHT> [COUNT count]
    if args.len() < 4 {
        resp::write_error(out, "ERR wrong number of arguments for 'lmpop' command");
        return CmdResult::Written;
    }
    let Some((keys, pop_left, count)) = parse_lmpop_args(args, 1, out) else {
        return CmdResult::Written;
    };
    match journaled_lmpop(store, &keys, pop_left, count, now) {
        Ok(Some((key, items))) => {
            write_lmpop_reply(store, out, &key, &items);
        }
        Ok(None) => resp::write_null_array(out),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_blmpop(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    // BLMPOP timeout numkeys key [key ...] <LEFT|RIGHT> [COUNT count]
    if args.len() < 5 {
        resp::write_error(out, "ERR wrong number of arguments for 'blmpop' command");
        return CmdResult::Written;
    }
    let timeout = match parse_block_timeout(args[1], out) {
        Some(t) => t,
        None => return CmdResult::Written,
    };
    let Some((keys, pop_left, count)) = parse_lmpop_args(args, 2, out) else {
        return CmdResult::Written;
    };
    // Immediately satisfiable -> behave like LMPOP and journal the resolved effect.
    match journaled_lmpop(store, &keys, pop_left, count, now) {
        Ok(Some((key, items))) => {
            write_lmpop_reply(store, out, &key, &items);
            return CmdResult::Written;
        }
        Ok(None) => {}
        Err(e) => {
            resp::write_error(out, &e);
            return CmdResult::Written;
        }
    }
    let owned_keys: Vec<String> = keys.iter().map(|k| arg_str(k).to_string()).collect();
    CmdResult::BlockListMPop {
        keys: owned_keys,
        pop_left,
        count,
        timeout,
    }
}

pub fn cmd_brpoplpush(
    args: &[&[u8]],
    store: &Store,
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    // BRPOPLPUSH src dst timeout == BLMOVE src dst RIGHT LEFT timeout.
    if args.len() != 4 {
        resp::write_error(
            out,
            "ERR wrong number of arguments for 'brpoplpush' command",
        );
        return CmdResult::Written;
    }
    let src = arg_str(args[1]).to_string();
    let dst = arg_str(args[2]).to_string();
    let timeout = match parse_block_timeout(args[3], out) {
        Some(t) => t,
        None => return CmdResult::Written,
    };
    let (src_left, dst_left) = (false, true);
    match journaled_list_move(store, args[1], args[2], src_left, dst_left, now) {
        Ok(Some(v)) => {
            resp::write_bulk_raw(out, &decrypt_out(store, v));
            return CmdResult::Written;
        }
        Ok(None) => {}
        Err(error) => {
            resp::write_error(out, &error);
            return CmdResult::Written;
        }
    }
    CmdResult::BlockMove {
        src,
        dst,
        src_left,
        dst_left,
        timeout,
    }
}
