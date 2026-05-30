use bytes::BytesMut;
use std::time::{Duration, Instant};

use crate::resp;
use crate::store::{Store, StoreValue};

use super::{arg_str, cmd_eq, format_float, parse_i64, parse_u64, CmdResult};

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

fn parse_usize_arg(arg: &[u8], out: &mut BytesMut) -> Option<usize> {
    match parse_u64(arg).ok().and_then(|n| usize::try_from(n).ok()) {
        Some(n) => Some(n),
        None => {
            resp::write_error(out, INTEGER_ERR);
            None
        }
    }
}

fn parse_score_bound(s: &str, _is_max: bool) -> Result<(f64, bool), String> {
    if s == "-inf" || s == "-" {
        Ok((f64::NEG_INFINITY, false))
    } else if s == "+inf" || s == "+" {
        Ok((f64::INFINITY, false))
    } else if let Some(rest) = s.strip_prefix('(') {
        match rest.parse::<f64>() {
            Ok(v) if v.is_finite() => Ok((v, true)),
            _ => Err("ERR min or max is not a float".to_string()),
        }
    } else {
        match s.parse::<f64>() {
            Ok(v) if v.is_finite() => Ok((v, false)),
            _ => Err("ERR min or max is not a float".to_string()),
        }
    }
}

fn parse_limit(
    args: &[&[u8]],
    i: usize,
    out: &mut BytesMut,
) -> Option<(Option<usize>, Option<usize>)> {
    if i + 2 >= args.len() {
        resp::write_error(out, "ERR syntax error");
        return None;
    }
    let offset = parse_usize_arg(args[i + 1], out)?;
    let count = parse_usize_arg(args[i + 2], out)?;
    Some((Some(offset), Some(count)))
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
    match p[pi] {
        '*' => do_glob(p, s, pi + 1, si) || (si < s.len() && do_glob(p, s, pi, si + 1)),
        '?' => si < s.len() && do_glob(p, s, pi + 1, si + 1),
        c => si < s.len() && c == s[si] && do_glob(p, s, pi + 1, si + 1),
    }
}

fn parse_zstore_numkeys(arg: &[u8], out: &mut BytesMut) -> Option<usize> {
    let numkeys = match parse_u64(arg) {
        Ok(n) => n,
        Err(_) => {
            resp::write_error(out, "ERR value is not an integer or out of range");
            return None;
        }
    };
    let numkeys = match usize::try_from(numkeys) {
        Ok(n) if n > 0 => n,
        _ => {
            resp::write_error(
                out,
                "ERR at least 1 input key is needed for ZUNIONSTORE/ZINTERSTORE/ZDIFFSTORE",
            );
            return None;
        }
    };
    Some(numkeys)
}

fn parse_zstore_options(
    args: &[&[u8]],
    numkeys: usize,
    out: &mut BytesMut,
) -> Option<(Vec<f64>, String)> {
    let mut weights = Vec::new();
    let mut aggregate = "SUM".to_string();
    let mut i = 0;
    while i < args.len() {
        if cmd_eq(args[i], b"WEIGHTS") {
            i += 1;
            if i + numkeys > args.len() {
                resp::write_error(out, "ERR syntax error");
                return None;
            }
            for weight_arg in &args[i..i + numkeys] {
                match arg_str(weight_arg).parse::<f64>() {
                    Ok(weight) if weight.is_finite() => weights.push(weight),
                    _ => {
                        resp::write_error(out, "ERR weight value is not a float");
                        return None;
                    }
                }
            }
            i += numkeys;
        } else if cmd_eq(args[i], b"AGGREGATE") {
            if i + 1 >= args.len() {
                resp::write_error(out, "ERR syntax error");
                return None;
            }
            let mode = arg_str(args[i + 1]).to_uppercase();
            if matches!(mode.as_str(), "SUM" | "MIN" | "MAX") {
                aggregate = mode;
                i += 2;
            } else {
                resp::write_error(out, "ERR syntax error");
                return None;
            }
        } else {
            resp::write_error(out, "ERR syntax error");
            return None;
        }
    }
    Some((weights, aggregate))
}

fn write_zset_result(out: &mut BytesMut, items: &[(String, f64)], with_scores: bool) {
    if with_scores {
        resp::write_array_header(out, items.len() * 2);
        for (m, s) in items {
            resp::write_bulk(out, m);
            resp::write_bulk(out, &format_float(*s));
        }
    } else {
        resp::write_array_header(out, items.len());
        for (m, _) in items {
            resp::write_bulk(out, m);
        }
    }
}

pub fn cmd_zadd(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 4 {
        resp::write_error(out, "ERR wrong number of arguments for 'zadd' command");
        return CmdResult::Written;
    }
    let mut nx = false;
    let mut xx = false;
    let mut gt = false;
    let mut lt = false;
    let mut ch = false;
    let mut i = 2;
    while i < args.len() {
        if cmd_eq(args[i], b"NX") {
            nx = true;
            i += 1;
        } else if cmd_eq(args[i], b"XX") {
            xx = true;
            i += 1;
        } else if cmd_eq(args[i], b"GT") {
            gt = true;
            i += 1;
        } else if cmd_eq(args[i], b"LT") {
            lt = true;
            i += 1;
        } else if cmd_eq(args[i], b"CH") {
            ch = true;
            i += 1;
        } else {
            break;
        }
    }
    if nx && xx {
        resp::write_error(
            out,
            "ERR XX and NX options at the same time are not compatible",
        );
        return CmdResult::Written;
    }
    if nx && gt {
        resp::write_error(
            out,
            "ERR GT, LT, and NX options at the same time are not compatible",
        );
        return CmdResult::Written;
    }
    if nx && lt {
        resp::write_error(
            out,
            "ERR GT, LT, and NX options at the same time are not compatible",
        );
        return CmdResult::Written;
    }
    if gt && lt {
        resp::write_error(
            out,
            "ERR GT, LT, and NX options at the same time are not compatible",
        );
        return CmdResult::Written;
    }
    if !(args.len() - i).is_multiple_of(2) || i >= args.len() {
        resp::write_error(out, "ERR syntax error");
        return CmdResult::Written;
    }
    let mut members = Vec::new();
    while i + 1 < args.len() {
        let score: f64 = match arg_str(args[i]).parse::<f64>() {
            Ok(s) if s.is_nan() => {
                resp::write_error(out, "ERR value is not a valid float");
                return CmdResult::Written;
            }
            Ok(s) => s,
            Err(_) => {
                resp::write_error(out, "ERR value is not a valid float");
                return CmdResult::Written;
            }
        };
        members.push((args[i + 1], score));
        i += 2;
    }
    match store.zadd(args[1], &members, nx, xx, gt, lt, ch, now) {
        Ok(n) => resp::write_integer(out, n),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_zscore(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() != 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'zscore' command");
        return CmdResult::Written;
    }
    match store.zscore(args[1], args[2], now) {
        Ok(Some(s)) => {
            let ss = format_float(s);
            resp::write_bulk(out, &ss);
        }
        Ok(None) => resp::write_null(out),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_zmscore(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'zmscore' command");
        return CmdResult::Written;
    }
    let members: Vec<&[u8]> = args[2..].to_vec();
    match store.zmscore(args[1], &members, now) {
        Ok(scores) => {
            resp::write_array_header(out, scores.len());
            for s in &scores {
                match s {
                    Some(v) => resp::write_bulk(out, &format_float(*v)),
                    None => resp::write_null(out),
                }
            }
        }
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_zrank(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() != 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'zrank' command");
        return CmdResult::Written;
    }
    match store.zrank(args[1], args[2], false, now) {
        Ok(Some(r)) => resp::write_integer(out, r),
        Ok(None) => resp::write_null(out),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_zrevrank(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() != 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'zrevrank' command");
        return CmdResult::Written;
    }
    match store.zrank(args[1], args[2], true, now) {
        Ok(Some(r)) => resp::write_integer(out, r),
        Ok(None) => resp::write_null(out),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_zrem(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'zrem' command");
        return CmdResult::Written;
    }
    let members: Vec<&[u8]> = args[2..].to_vec();
    match store.zrem(args[1], &members, now) {
        Ok(n) => resp::write_integer(out, n),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_zcard(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() != 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'zcard' command");
        return CmdResult::Written;
    }
    match store.zcard(args[1], now) {
        Ok(n) => resp::write_integer(out, n),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_zcount(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() != 4 {
        resp::write_error(out, "ERR wrong number of arguments for 'zcount' command");
        return CmdResult::Written;
    }
    let (min, min_ex) = match parse_score_bound(arg_str(args[2]), false) {
        Ok(bound) => bound,
        Err(e) => {
            resp::write_error(out, &e);
            return CmdResult::Written;
        }
    };
    let (max, max_ex) = match parse_score_bound(arg_str(args[3]), true) {
        Ok(bound) => bound,
        Err(e) => {
            resp::write_error(out, &e);
            return CmdResult::Written;
        }
    };
    match store.zcount(args[1], min, max, min_ex, max_ex, now) {
        Ok(n) => resp::write_integer(out, n),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_zlexcount(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() != 4 {
        resp::write_error(out, "ERR wrong number of arguments for 'zlexcount' command");
        return CmdResult::Written;
    }
    match store.zrangebylex(
        args[1],
        arg_str(args[2]),
        arg_str(args[3]),
        None,
        None,
        false,
        now,
    ) {
        Ok(items) => resp::write_integer(out, items.len() as i64),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_zincrby(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() != 4 {
        resp::write_error(out, "ERR wrong number of arguments for 'zincrby' command");
        return CmdResult::Written;
    }
    let increment: f64 = match arg_str(args[2]).parse::<f64>() {
        Ok(d) if d.is_nan() => {
            resp::write_error(out, "ERR value is not a valid float");
            return CmdResult::Written;
        }
        Ok(d) => d,
        Err(_) => {
            resp::write_error(out, "ERR value is not a valid float");
            return CmdResult::Written;
        }
    };
    match store.zincrby(args[1], args[3], increment, now) {
        Ok(s) => {
            let ss = format_float(s);
            resp::write_bulk(out, &ss);
        }
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_zrange(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 4 {
        resp::write_error(out, "ERR wrong number of arguments for 'zrange' command");
        return CmdResult::Written;
    }
    let mut reverse = false;
    let mut with_scores = false;
    let mut byscore = false;
    let mut bylex = false;
    let mut offset: Option<usize> = None;
    let mut count: Option<usize> = None;
    let mut i = 4;
    while i < args.len() {
        if cmd_eq(args[i], b"REV") {
            reverse = true;
            i += 1;
        } else if cmd_eq(args[i], b"WITHSCORES") {
            with_scores = true;
            i += 1;
        } else if cmd_eq(args[i], b"BYSCORE") {
            byscore = true;
            i += 1;
        } else if cmd_eq(args[i], b"BYLEX") {
            bylex = true;
            i += 1;
        } else if cmd_eq(args[i], b"LIMIT") {
            let parsed = match parse_limit(args, i, out) {
                Some(parsed) => parsed,
                None => return CmdResult::Written,
            };
            offset = parsed.0;
            count = parsed.1;
            i += 3;
        } else {
            resp::write_error(out, "ERR syntax error");
            return CmdResult::Written;
        }
    }
    if byscore {
        let (min, min_ex) = match parse_score_bound(arg_str(args[2]), false) {
            Ok(bound) => bound,
            Err(e) => {
                resp::write_error(out, &e);
                return CmdResult::Written;
            }
        };
        let (max, max_ex) = match parse_score_bound(arg_str(args[3]), true) {
            Ok(bound) => bound,
            Err(e) => {
                resp::write_error(out, &e);
                return CmdResult::Written;
            }
        };
        match store.zrangebyscore(
            args[1],
            min,
            max,
            min_ex,
            max_ex,
            reverse,
            offset,
            count,
            with_scores,
            now,
        ) {
            Ok(items) => write_zset_result(out, &items, with_scores),
            Err(e) => resp::write_error(out, &e),
        }
    } else if bylex {
        match store.zrangebylex(
            args[1],
            arg_str(args[2]),
            arg_str(args[3]),
            offset,
            count,
            reverse,
            now,
        ) {
            Ok(items) => {
                resp::write_array_header(out, items.len());
                for m in &items {
                    resp::write_bulk(out, m);
                }
            }
            Err(e) => resp::write_error(out, &e),
        }
    } else {
        let start = match parse_i64_arg(args[2], out) {
            Some(start) => start,
            None => return CmdResult::Written,
        };
        let stop = match parse_i64_arg(args[3], out) {
            Some(stop) => stop,
            None => return CmdResult::Written,
        };
        match store.zrange(args[1], start, stop, reverse, with_scores, now) {
            Ok(items) => write_zset_result(out, &items, with_scores),
            Err(e) => resp::write_error(out, &e),
        }
    }
    CmdResult::Written
}

pub fn cmd_zrevrange(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 4 {
        resp::write_error(out, "ERR wrong number of arguments for 'zrevrange' command");
        return CmdResult::Written;
    }
    let with_scores = if args.len() > 4 {
        if args.len() == 5 && cmd_eq(args[4], b"WITHSCORES") {
            true
        } else {
            resp::write_error(out, "ERR syntax error");
            return CmdResult::Written;
        }
    } else {
        false
    };
    let start = match parse_i64_arg(args[2], out) {
        Some(start) => start,
        None => return CmdResult::Written,
    };
    let stop = match parse_i64_arg(args[3], out) {
        Some(stop) => stop,
        None => return CmdResult::Written,
    };
    match store.zrange(args[1], start, stop, true, with_scores, now) {
        Ok(items) => write_zset_result(out, &items, with_scores),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_zrangebyscore(
    args: &[&[u8]],
    store: &Store,
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    if args.len() < 4 {
        resp::write_error(
            out,
            "ERR wrong number of arguments for 'zrangebyscore' command",
        );
        return CmdResult::Written;
    }
    let (min, min_ex) = match parse_score_bound(arg_str(args[2]), false) {
        Ok(bound) => bound,
        Err(e) => {
            resp::write_error(out, &e);
            return CmdResult::Written;
        }
    };
    let (max, max_ex) = match parse_score_bound(arg_str(args[3]), true) {
        Ok(bound) => bound,
        Err(e) => {
            resp::write_error(out, &e);
            return CmdResult::Written;
        }
    };
    let mut with_scores = false;
    let mut offset: Option<usize> = None;
    let mut count: Option<usize> = None;
    let mut i = 4;
    while i < args.len() {
        if cmd_eq(args[i], b"WITHSCORES") {
            with_scores = true;
            i += 1;
        } else if cmd_eq(args[i], b"LIMIT") {
            let parsed = match parse_limit(args, i, out) {
                Some(parsed) => parsed,
                None => return CmdResult::Written,
            };
            offset = parsed.0;
            count = parsed.1;
            i += 3;
        } else {
            resp::write_error(out, "ERR syntax error");
            return CmdResult::Written;
        }
    }
    match store.zrangebyscore(
        args[1],
        min,
        max,
        min_ex,
        max_ex,
        false,
        offset,
        count,
        with_scores,
        now,
    ) {
        Ok(items) => write_zset_result(out, &items, with_scores),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_zrevrangebyscore(
    args: &[&[u8]],
    store: &Store,
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    if args.len() < 4 {
        resp::write_error(
            out,
            "ERR wrong number of arguments for 'zrevrangebyscore' command",
        );
        return CmdResult::Written;
    }
    let (max, max_ex) = match parse_score_bound(arg_str(args[2]), true) {
        Ok(bound) => bound,
        Err(e) => {
            resp::write_error(out, &e);
            return CmdResult::Written;
        }
    };
    let (min, min_ex) = match parse_score_bound(arg_str(args[3]), false) {
        Ok(bound) => bound,
        Err(e) => {
            resp::write_error(out, &e);
            return CmdResult::Written;
        }
    };
    let mut with_scores = false;
    let mut offset: Option<usize> = None;
    let mut count: Option<usize> = None;
    let mut i = 4;
    while i < args.len() {
        if cmd_eq(args[i], b"WITHSCORES") {
            with_scores = true;
            i += 1;
        } else if cmd_eq(args[i], b"LIMIT") {
            let parsed = match parse_limit(args, i, out) {
                Some(parsed) => parsed,
                None => return CmdResult::Written,
            };
            offset = parsed.0;
            count = parsed.1;
            i += 3;
        } else {
            resp::write_error(out, "ERR syntax error");
            return CmdResult::Written;
        }
    }
    match store.zrangebyscore(
        args[1],
        min,
        max,
        min_ex,
        max_ex,
        true,
        offset,
        count,
        with_scores,
        now,
    ) {
        Ok(items) => write_zset_result(out, &items, with_scores),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_zrangebylex(
    args: &[&[u8]],
    store: &Store,
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    if args.len() < 4 {
        resp::write_error(
            out,
            "ERR wrong number of arguments for 'zrangebylex' command",
        );
        return CmdResult::Written;
    }
    let mut offset: Option<usize> = None;
    let mut count: Option<usize> = None;
    let mut i = 4;
    while i < args.len() {
        if cmd_eq(args[i], b"LIMIT") {
            let parsed = match parse_limit(args, i, out) {
                Some(parsed) => parsed,
                None => return CmdResult::Written,
            };
            offset = parsed.0;
            count = parsed.1;
            i += 3;
        } else {
            resp::write_error(out, "ERR syntax error");
            return CmdResult::Written;
        }
    }
    match store.zrangebylex(
        args[1],
        arg_str(args[2]),
        arg_str(args[3]),
        offset,
        count,
        false,
        now,
    ) {
        Ok(items) => {
            resp::write_array_header(out, items.len());
            for m in &items {
                resp::write_bulk(out, m);
            }
        }
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_zrevrangebylex(
    args: &[&[u8]],
    store: &Store,
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    if args.len() < 4 {
        resp::write_error(
            out,
            "ERR wrong number of arguments for 'zrevrangebylex' command",
        );
        return CmdResult::Written;
    }
    let mut offset: Option<usize> = None;
    let mut count: Option<usize> = None;
    let mut i = 4;
    while i < args.len() {
        if cmd_eq(args[i], b"LIMIT") {
            let parsed = match parse_limit(args, i, out) {
                Some(parsed) => parsed,
                None => return CmdResult::Written,
            };
            offset = parsed.0;
            count = parsed.1;
            i += 3;
        } else {
            resp::write_error(out, "ERR syntax error");
            return CmdResult::Written;
        }
    }
    match store.zrangebylex(
        args[1],
        arg_str(args[3]),
        arg_str(args[2]),
        offset,
        count,
        true,
        now,
    ) {
        Ok(items) => {
            resp::write_array_header(out, items.len());
            for m in &items {
                resp::write_bulk(out, m);
            }
        }
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_zpopmin(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'zpopmin' command");
        return CmdResult::Written;
    }
    let count = if args.len() > 2 {
        match parse_usize_arg(args[2], out) {
            Some(count) => count,
            None => return CmdResult::Written,
        }
    } else {
        1
    };
    match store.zpopmin(args[1], count, now) {
        Ok(items) => {
            if args.len() <= 2 && items.len() <= 1 {
                if items.is_empty() {
                    resp::write_array_header(out, 0);
                } else {
                    resp::write_array_header(out, 2);
                    resp::write_bulk(out, &items[0].0);
                    resp::write_bulk(out, &format_float(items[0].1));
                }
            } else {
                resp::write_array_header(out, items.len() * 2);
                for (m, s) in &items {
                    resp::write_bulk(out, m);
                    resp::write_bulk(out, &format_float(*s));
                }
            }
        }
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_zpopmax(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'zpopmax' command");
        return CmdResult::Written;
    }
    let count = if args.len() > 2 {
        match parse_usize_arg(args[2], out) {
            Some(count) => count,
            None => return CmdResult::Written,
        }
    } else {
        1
    };
    match store.zpopmax(args[1], count, now) {
        Ok(items) => {
            if args.len() <= 2 && items.len() <= 1 {
                if items.is_empty() {
                    resp::write_array_header(out, 0);
                } else {
                    resp::write_array_header(out, 2);
                    resp::write_bulk(out, &items[0].0);
                    resp::write_bulk(out, &format_float(items[0].1));
                }
            } else {
                resp::write_array_header(out, items.len() * 2);
                for (m, s) in &items {
                    resp::write_bulk(out, m);
                    resp::write_bulk(out, &format_float(*s));
                }
            }
        }
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_zunionstore(
    args: &[&[u8]],
    store: &Store,
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    if args.len() < 4 {
        resp::write_error(
            out,
            "ERR wrong number of arguments for 'zunionstore' command",
        );
        return CmdResult::Written;
    }
    let numkeys = match parse_zstore_numkeys(args[2], out) {
        Some(numkeys) => numkeys,
        None => return CmdResult::Written,
    };
    if 3 + numkeys > args.len() {
        resp::write_error(out, "ERR syntax error");
        return CmdResult::Written;
    }
    let keys: Vec<&[u8]> = args[3..3 + numkeys].to_vec();
    for key in &keys {
        store.try_promote(key, now);
    }
    let (weights, aggregate) = match parse_zstore_options(&args[3 + numkeys..], numkeys, out) {
        Some(parsed) => parsed,
        None => return CmdResult::Written,
    };
    match store.zunionstore(args[1], &keys, &weights, &aggregate, now) {
        Ok(n) => resp::write_integer(out, n),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_zinterstore(
    args: &[&[u8]],
    store: &Store,
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    if args.len() < 4 {
        resp::write_error(
            out,
            "ERR wrong number of arguments for 'zinterstore' command",
        );
        return CmdResult::Written;
    }
    let numkeys = match parse_zstore_numkeys(args[2], out) {
        Some(numkeys) => numkeys,
        None => return CmdResult::Written,
    };
    if 3 + numkeys > args.len() {
        resp::write_error(out, "ERR syntax error");
        return CmdResult::Written;
    }
    let keys: Vec<&[u8]> = args[3..3 + numkeys].to_vec();
    for key in &keys {
        store.try_promote(key, now);
    }
    let (weights, aggregate) = match parse_zstore_options(&args[3 + numkeys..], numkeys, out) {
        Some(parsed) => parsed,
        None => return CmdResult::Written,
    };
    match store.zinterstore(args[1], &keys, &weights, &aggregate, now) {
        Ok(n) => resp::write_integer(out, n),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_zdiffstore(
    args: &[&[u8]],
    store: &Store,
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    if args.len() < 4 {
        resp::write_error(
            out,
            "ERR wrong number of arguments for 'zdiffstore' command",
        );
        return CmdResult::Written;
    }
    let numkeys = match parse_zstore_numkeys(args[2], out) {
        Some(numkeys) => numkeys,
        None => return CmdResult::Written,
    };
    if 3 + numkeys > args.len() {
        resp::write_error(out, "ERR syntax error");
        return CmdResult::Written;
    }
    if 3 + numkeys != args.len() {
        resp::write_error(out, "ERR syntax error");
        return CmdResult::Written;
    }
    let keys: Vec<&[u8]> = args[3..3 + numkeys].to_vec();
    for key in &keys {
        store.try_promote(key, now);
    }
    match store.zdiffstore(args[1], &keys, now) {
        Ok(n) => resp::write_integer(out, n),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_zremrangebyrank(
    args: &[&[u8]],
    store: &Store,
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    if args.len() != 4 {
        resp::write_error(
            out,
            "ERR wrong number of arguments for 'zremrangebyrank' command",
        );
        return CmdResult::Written;
    }
    let start = match parse_i64_arg(args[2], out) {
        Some(start) => start,
        None => return CmdResult::Written,
    };
    let stop = match parse_i64_arg(args[3], out) {
        Some(stop) => stop,
        None => return CmdResult::Written,
    };
    match store.zrange(args[1], start, stop, false, true, now) {
        Ok(items) => {
            let members: Vec<&[u8]> = items.iter().map(|(m, _)| m.as_bytes()).collect();
            match store.zrem(args[1], &members, now) {
                Ok(n) => resp::write_integer(out, n),
                Err(e) => resp::write_error(out, &e),
            }
        }
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_zremrangebyscore(
    args: &[&[u8]],
    store: &Store,
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    if args.len() != 4 {
        resp::write_error(
            out,
            "ERR wrong number of arguments for 'zremrangebyscore' command",
        );
        return CmdResult::Written;
    }
    let (min, min_ex) = match parse_score_bound(arg_str(args[2]), false) {
        Ok(bound) => bound,
        Err(e) => {
            resp::write_error(out, &e);
            return CmdResult::Written;
        }
    };
    let (max, max_ex) = match parse_score_bound(arg_str(args[3]), true) {
        Ok(bound) => bound,
        Err(e) => {
            resp::write_error(out, &e);
            return CmdResult::Written;
        }
    };
    match store.zrangebyscore(
        args[1], min, max, min_ex, max_ex, false, None, None, true, now,
    ) {
        Ok(items) => {
            let members: Vec<&[u8]> = items.iter().map(|(m, _)| m.as_bytes()).collect();
            match store.zrem(args[1], &members, now) {
                Ok(n) => resp::write_integer(out, n),
                Err(e) => resp::write_error(out, &e),
            }
        }
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_zremrangebylex(
    args: &[&[u8]],
    store: &Store,
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    if args.len() != 4 {
        resp::write_error(
            out,
            "ERR wrong number of arguments for 'zremrangebylex' command",
        );
        return CmdResult::Written;
    }
    match store.zrangebylex(
        args[1],
        arg_str(args[2]),
        arg_str(args[3]),
        None,
        None,
        false,
        now,
    ) {
        Ok(items) => {
            let members: Vec<&[u8]> = items.iter().map(|m| m.as_bytes()).collect();
            match store.zrem(args[1], &members, now) {
                Ok(n) => resp::write_integer(out, n),
                Err(e) => resp::write_error(out, &e),
            }
        }
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_zscan(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'zscan' command");
        return CmdResult::Written;
    }
    let cursor = match parse_usize_arg(args[2], out) {
        Some(cursor) => cursor,
        None => return CmdResult::Written,
    };
    let mut count = 10usize;
    let mut pattern: Option<&str> = None;
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
            pattern = Some(arg_str(args[i + 1]));
            i += 2;
        } else {
            resp::write_error(out, "ERR syntax error");
            return CmdResult::Written;
        }
    }
    let idx = store.shard_for_key(args[1]);
    let shard = store.lock_read_shard(idx);
    let ks = arg_str(args[1]);
    match shard.data.get(ks) {
        Some(entry) if !entry.is_expired_at(now) => {
            if let StoreValue::SortedSet(tree, _) = &entry.value {
                let all: Vec<_> = tree
                    .keys()
                    .filter(|(_, member)| pattern.is_none_or(|p| glob_match(p, member)))
                    .collect();
                let s = cursor.min(all.len());
                let e = (s + count).min(all.len());
                let next = if e >= all.len() { 0 } else { e };
                resp::write_array_header(out, 2);
                resp::write_bulk(out, &next.to_string());
                resp::write_array_header(out, (e - s) * 2);
                for (score, member) in &all[s..e] {
                    resp::write_bulk(out, member);
                    resp::write_bulk(out, &format_float(score.0));
                }
            } else {
                resp::write_error(
                    out,
                    "WRONGTYPE Operation against a key holding the wrong kind of value",
                );
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

pub fn cmd_bzpopmin(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
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
    let is_min = cmd_eq(args[0], b"BZPOPMIN");
    let timeout_secs: f64 = arg_str(args[args.len() - 1]).parse().unwrap_or(0.0);
    let keys: Vec<&[u8]> = args[1..args.len() - 1].to_vec();

    for key in &keys {
        let result = if is_min {
            store.zpopmin(key, 1, now)
        } else {
            store.zpopmax(key, 1, now)
        };
        if let Ok(items) = result {
            if !items.is_empty() {
                let (member, score) = &items[0];
                resp::write_array_header(out, 3);
                resp::write_bulk_raw(out, key);
                resp::write_bulk(out, member);
                resp::write_bulk(out, &format_float(*score));
                return CmdResult::Written;
            }
        }
    }

    let timeout = if timeout_secs <= 0.0 {
        Duration::from_secs(300)
    } else {
        Duration::from_secs_f64(timeout_secs)
    };
    let owned_keys: Vec<String> = keys.iter().map(|k| arg_str(k).to_string()).collect();
    CmdResult::BlockZPop {
        keys: owned_keys,
        timeout,
        pop_min: is_min,
    }
}
