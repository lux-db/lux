use bytes::{Bytes, BytesMut};
use std::time::{Duration, Instant};

use crate::resp;
use crate::store::{Entry, SetOptions, Store, StoreValue};

use super::{arg_str, cmd_eq, parse_i64, parse_u64, CmdResult};

const INTEGER_ERR: &str = "ERR value is not an integer or out of range";
const VALUE_TOO_LARGE_ERR: &str = "ERR string exceeds maximum allowed size";

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
    let mut keep_ttl = false;
    let mut nx = false;
    let mut xx = false;
    let mut get = false;
    let mut ifeq = None;
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
            keep_ttl = false;
            i += 2;
        } else if cmd_eq(args[i], b"EXAT") {
            if i + 1 >= args.len() {
                resp::write_error(out, "ERR syntax error");
                return CmdResult::Written;
            }
            match parse_u64(args[i + 1]) {
                Ok(expiry_secs) => {
                    let now_secs = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    ttl = Some(Duration::from_secs(expiry_secs.saturating_sub(now_secs)));
                    keep_ttl = false;
                }
                Err(_) => {
                    resp::write_error(out, "ERR value is not an integer or out of range");
                    return CmdResult::Written;
                }
            }
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
            keep_ttl = false;
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
                    keep_ttl = false;
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
        } else if cmd_eq(args[i], b"GET") {
            get = true;
            i += 1;
        } else if cmd_eq(args[i], b"IFEQ") {
            if i + 1 >= args.len() {
                resp::write_error(out, "ERR syntax error");
                return CmdResult::Written;
            }
            ifeq = Some(args[i + 1]);
            i += 2;
        } else if cmd_eq(args[i], b"KEEPTTL") {
            if ttl.is_some() {
                resp::write_error(out, "ERR syntax error");
                return CmdResult::Written;
            }
            keep_ttl = true;
            i += 1;
        } else {
            resp::write_error(out, "ERR syntax error");
            return CmdResult::Written;
        }
    }
    if (nx && xx) || (ifeq.is_some() && (nx || xx)) {
        resp::write_error(out, "ERR syntax error");
        return CmdResult::Written;
    }
    let options = SetOptions {
        ttl,
        keep_ttl,
        nx,
        xx,
        ifeq,
        get,
    };
    match store.set_conditional(args[1], args[2], options, now) {
        Ok((set, old)) => {
            if get {
                resp::write_optional_bulk_raw(out, &old);
            } else if set {
                resp::write_ok(out);
            } else {
                resp::write_null(out);
            }
        }
        Err(err) => resp::write_error(out, &err),
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

pub fn cmd_delifeq(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() != 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'delifeq' command");
        return CmdResult::Written;
    }
    match store.delifeq(args[1], args[2], now) {
        Ok(deleted) => resp::write_integer(out, if deleted { 1 } else { 0 }),
        Err(err) => resp::write_error(out, &err),
    }
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
    match store.getrange(args[1], start, end, now) {
        Ok(val) => resp::write_bulk_raw(out, &val),
        Err(err) => resp::write_error(out, &err),
    }
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
    match offset.checked_add(args[3].len()) {
        None => {
            resp::write_error(out, INTEGER_ERR);
            return CmdResult::Written;
        }
        // Cap the resulting string so SETRANGE at a huge offset can't balloon a
        // value past the configured request ceiling and exhaust memory.
        Some(end) if end > store.config().max_resp_request => {
            resp::write_error(out, VALUE_TOO_LARGE_ERR);
            return CmdResult::Written;
        }
        Some(_) => {}
    }
    match store.setrange(args[1], offset, args[3], now) {
        Ok(len) => resp::write_integer(out, len),
        Err(err) => resp::write_error(out, &err),
    }
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

pub fn cmd_lcs(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'lcs' command");
        return CmdResult::Written;
    }

    let mut len_only = false;
    let mut idx = false;
    let mut with_match_len = false;
    let mut min_match_len = 0usize;
    let mut i = 3;
    while i < args.len() {
        if cmd_eq(args[i], b"LEN") {
            len_only = true;
            i += 1;
        } else if cmd_eq(args[i], b"IDX") {
            idx = true;
            i += 1;
        } else if cmd_eq(args[i], b"WITHMATCHLEN") {
            with_match_len = true;
            i += 1;
        } else if cmd_eq(args[i], b"MINMATCHLEN") {
            if i + 1 >= args.len() {
                resp::write_error(out, "ERR syntax error");
                return CmdResult::Written;
            }
            let Some(value) = parse_u64_arg(args[i + 1], out) else {
                return CmdResult::Written;
            };
            let Ok(value) = usize::try_from(value) else {
                resp::write_error(out, INTEGER_ERR);
                return CmdResult::Written;
            };
            min_match_len = value;
            i += 2;
        } else {
            resp::write_error(out, "ERR syntax error");
            return CmdResult::Written;
        }
    }

    if (len_only && idx) || (!idx && (with_match_len || min_match_len > 0)) {
        resp::write_error(out, "ERR syntax error");
        return CmdResult::Written;
    }

    let left = match store.getrange(args[1], 0, -1, now) {
        Ok(value) => value,
        Err(err) => {
            resp::write_error(out, &err);
            return CmdResult::Written;
        }
    };
    let right = match store.getrange(args[2], 0, -1, now) {
        Ok(value) => value,
        Err(err) => {
            resp::write_error(out, &err);
            return CmdResult::Written;
        }
    };
    let (lcs, pairs) = lcs_bytes(&left, &right);

    if len_only {
        resp::write_integer(out, lcs.len() as i64);
    } else if idx {
        write_lcs_idx(out, &pairs, lcs.len(), min_match_len, with_match_len);
    } else {
        resp::write_bulk_raw(out, &lcs);
    }
    CmdResult::Written
}

fn lcs_bytes(left: &[u8], right: &[u8]) -> (Vec<u8>, Vec<(usize, usize)>) {
    let m = left.len();
    let n = right.len();
    let mut dp = vec![0usize; (m + 1) * (n + 1)];
    let at = |i: usize, j: usize| i * (n + 1) + j;

    for i in 1..=m {
        for j in 1..=n {
            dp[at(i, j)] = if left[i - 1] == right[j - 1] {
                dp[at(i - 1, j - 1)] + 1
            } else {
                dp[at(i - 1, j)].max(dp[at(i, j - 1)])
            };
        }
    }

    let mut i = m;
    let mut j = n;
    let mut bytes = Vec::with_capacity(dp[at(m, n)]);
    let mut pairs = Vec::with_capacity(dp[at(m, n)]);
    while i > 0 && j > 0 {
        if left[i - 1] == right[j - 1] {
            bytes.push(left[i - 1]);
            pairs.push((i - 1, j - 1));
            i -= 1;
            j -= 1;
        } else if dp[at(i - 1, j)] > dp[at(i, j - 1)] {
            i -= 1;
        } else {
            j -= 1;
        }
    }
    bytes.reverse();
    pairs.reverse();

    (bytes, pairs)
}

fn write_lcs_idx(
    out: &mut BytesMut,
    pairs: &[(usize, usize)],
    lcs_len: usize,
    min_match_len: usize,
    with_match_len: bool,
) {
    let mut ranges: Vec<(usize, usize, usize, usize)> = Vec::new();
    for &(left, right) in pairs {
        match ranges.last_mut() {
            Some((_, left_end, _, right_end))
                if left == *left_end + 1 && right == *right_end + 1 =>
            {
                *left_end = left;
                *right_end = right;
            }
            _ => ranges.push((left, left, right, right)),
        }
    }

    let ranges: Vec<_> = ranges
        .into_iter()
        .rev()
        .filter(|(left_start, left_end, _, _)| left_end - left_start + 1 >= min_match_len)
        .collect();

    resp::write_array_header(out, 4);
    resp::write_bulk(out, "matches");
    resp::write_array_header(out, ranges.len());
    for (left_start, left_end, right_start, right_end) in ranges {
        resp::write_array_header(out, if with_match_len { 3 } else { 2 });
        resp::write_array_header(out, 2);
        resp::write_integer(out, left_start as i64);
        resp::write_integer(out, left_end as i64);
        resp::write_array_header(out, 2);
        resp::write_integer(out, right_start as i64);
        resp::write_integer(out, right_end as i64);
        if with_match_len {
            resp::write_integer(out, (left_end - left_start + 1) as i64);
        }
    }
    resp::write_bulk(out, "len");
    resp::write_integer(out, lcs_len as i64);
}

pub fn cmd_append(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'append' command");
        return CmdResult::Written;
    }
    // Cap repeated APPENDs so a value can't be grown without bound past the
    // configured request ceiling (each call is RESP-bounded, the running total is not).
    let projected = (store.strlen(args[1], now) as usize).saturating_add(args[2].len());
    if projected > store.config().max_resp_request {
        resp::write_error(out, VALUE_TOO_LARGE_ERR);
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
