use bytes::BytesMut;
use std::time::{Duration, Instant};

use crate::resp;
use crate::store::{Store, StoreValue};

use super::{arg_str, cmd_eq, format_float, parse_i64, parse_u64, CmdResult};

fn parse_score_bound(s: &str, is_max: bool) -> (f64, bool) {
    if s == "-inf" || s == "-" {
        (f64::NEG_INFINITY, false)
    } else if s == "+inf" || s == "+" {
        (f64::INFINITY, false)
    } else if let Some(rest) = s.strip_prefix('(') {
        (
            rest.parse::<f64>().unwrap_or(if is_max {
                f64::INFINITY
            } else {
                f64::NEG_INFINITY
            }),
            true,
        )
    } else {
        (
            s.parse::<f64>().unwrap_or(if is_max {
                f64::INFINITY
            } else {
                f64::NEG_INFINITY
            }),
            false,
        )
    }
}

fn parse_zstore_options(args: &[&[u8]]) -> (Vec<f64>, &'static str) {
    let mut weights = Vec::new();
    let mut aggregate = "SUM";
    let mut i = 0;
    while i < args.len() {
        if cmd_eq(args[i], b"WEIGHTS") {
            i += 1;
            while i < args.len() && !cmd_eq(args[i], b"AGGREGATE") {
                weights.push(arg_str(args[i]).parse::<f64>().unwrap_or(1.0));
                i += 1;
            }
        } else if cmd_eq(args[i], b"AGGREGATE") && i + 1 < args.len() {
            aggregate = if cmd_eq(args[i + 1], b"MIN") {
                "MIN"
            } else if cmd_eq(args[i + 1], b"MAX") {
                "MAX"
            } else {
                "SUM"
            };
            i += 2;
        } else {
            i += 1;
        }
    }
    (weights, aggregate)
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
    if args.len() == 4 {
        let score: f64 = match arg_str(args[2]).parse::<f64>() {
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
        match store.zadd_single_default(args[1], args[3], score, now) {
            Ok(count) => resp::write_integer(out, count),
            Err(error) => resp::write_error(out, &error),
        };
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
    if nx && (gt || lt) {
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
    let mut members = Vec::with_capacity((args.len() - i) / 2);
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
    match store.zmscore(args[1], &args[2..], now) {
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
    match store.zrem(args[1], &args[2..], now) {
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
    let (min, min_ex) = parse_score_bound(arg_str(args[2]), false);
    let (max, max_ex) = parse_score_bound(arg_str(args[3]), true);
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
    if args.len() == 4 {
        let start = parse_i64(args[2]).unwrap_or(0);
        let stop = parse_i64(args[3]).unwrap_or(-1);
        match store.zrange(args[1], start, stop, false, false, now) {
            Ok(items) => write_zset_result(out, &items, false),
            Err(e) => resp::write_error(out, &e),
        }
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
        } else if cmd_eq(args[i], b"LIMIT") && i + 2 < args.len() {
            offset = Some(parse_u64(args[i + 1]).unwrap_or(0) as usize);
            count = Some(parse_u64(args[i + 2]).unwrap_or(0) as usize);
            i += 3;
        } else {
            i += 1;
        }
    }
    if byscore {
        let (min, min_ex) = parse_score_bound(arg_str(args[2]), false);
        let (max, max_ex) = parse_score_bound(arg_str(args[3]), true);
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
        let start = parse_i64(args[2]).unwrap_or(0);
        let stop = parse_i64(args[3]).unwrap_or(-1);
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
    let with_scores = args.len() > 4 && cmd_eq(args[4], b"WITHSCORES");
    let start = parse_i64(args[2]).unwrap_or(0);
    let stop = parse_i64(args[3]).unwrap_or(-1);
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
    let (min, min_ex) = parse_score_bound(arg_str(args[2]), false);
    let (max, max_ex) = parse_score_bound(arg_str(args[3]), true);
    let mut with_scores = false;
    let mut offset: Option<usize> = None;
    let mut count: Option<usize> = None;
    let mut i = 4;
    while i < args.len() {
        if cmd_eq(args[i], b"WITHSCORES") {
            with_scores = true;
            i += 1;
        } else if cmd_eq(args[i], b"LIMIT") && i + 2 < args.len() {
            offset = Some(parse_u64(args[i + 1]).unwrap_or(0) as usize);
            count = Some(parse_u64(args[i + 2]).unwrap_or(0) as usize);
            i += 3;
        } else {
            i += 1;
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
    let (max, max_ex) = parse_score_bound(arg_str(args[2]), true);
    let (min, min_ex) = parse_score_bound(arg_str(args[3]), false);
    let mut with_scores = false;
    let mut offset: Option<usize> = None;
    let mut count: Option<usize> = None;
    let mut i = 4;
    while i < args.len() {
        if cmd_eq(args[i], b"WITHSCORES") {
            with_scores = true;
            i += 1;
        } else if cmd_eq(args[i], b"LIMIT") && i + 2 < args.len() {
            offset = Some(parse_u64(args[i + 1]).unwrap_or(0) as usize);
            count = Some(parse_u64(args[i + 2]).unwrap_or(0) as usize);
            i += 3;
        } else {
            i += 1;
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
        if cmd_eq(args[i], b"LIMIT") && i + 2 < args.len() {
            offset = Some(parse_u64(args[i + 1]).unwrap_or(0) as usize);
            count = Some(parse_u64(args[i + 2]).unwrap_or(0) as usize);
            i += 3;
        } else {
            i += 1;
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
        if cmd_eq(args[i], b"LIMIT") && i + 2 < args.len() {
            offset = Some(parse_u64(args[i + 1]).unwrap_or(0) as usize);
            count = Some(parse_u64(args[i + 2]).unwrap_or(0) as usize);
            i += 3;
        } else {
            i += 1;
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
        parse_u64(args[2]).unwrap_or(1) as usize
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
        parse_u64(args[2]).unwrap_or(1) as usize
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
    let numkeys = parse_u64(args[2]).unwrap_or(0) as usize;
    if 3 + numkeys > args.len() {
        resp::write_error(out, "ERR syntax error");
        return CmdResult::Written;
    }
    let (weights, aggregate) = parse_zstore_options(&args[3 + numkeys..]);
    match store.zunionstore(args[1], &args[3..3 + numkeys], &weights, aggregate, now) {
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
    let numkeys = parse_u64(args[2]).unwrap_or(0) as usize;
    if 3 + numkeys > args.len() {
        resp::write_error(out, "ERR syntax error");
        return CmdResult::Written;
    }
    let (weights, aggregate) = parse_zstore_options(&args[3 + numkeys..]);
    match store.zinterstore(args[1], &args[3..3 + numkeys], &weights, aggregate, now) {
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
    let numkeys = parse_u64(args[2]).unwrap_or(0) as usize;
    if 3 + numkeys > args.len() {
        resp::write_error(out, "ERR syntax error");
        return CmdResult::Written;
    }
    match store.zdiffstore(args[1], &args[3..3 + numkeys], now) {
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
    let start = parse_i64(args[2]).unwrap_or(0);
    let stop = parse_i64(args[3]).unwrap_or(-1);
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
    let (min, min_ex) = parse_score_bound(arg_str(args[2]), false);
    let (max, max_ex) = parse_score_bound(arg_str(args[3]), true);
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
    let cursor = parse_u64(args[2]).unwrap_or(0) as usize;
    let mut count = 10usize;
    let mut i = 3;
    while i < args.len() {
        if cmd_eq(args[i], b"COUNT") && i + 1 < args.len() {
            count = parse_u64(args[i + 1]).unwrap_or(10) as usize;
            i += 2;
        } else {
            i += 1;
        }
    }
    let idx = store.shard_for_key(args[1]);
    let shard = store.lock_read_shard(idx);
    let ks = arg_str(args[1]);
    match shard.data.get(ks) {
        Some(entry) if !entry.is_expired_at(now) => {
            if let StoreValue::SortedSet(tree, _) = &entry.value {
                let all: Vec<_> = tree.keys().collect();
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
    let keys = &args[1..args.len() - 1];
    for key in keys {
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
