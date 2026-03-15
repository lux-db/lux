use bytes::BytesMut;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use crate::pubsub::Broker;
use crate::resp;
use crate::store::Store;
use crate::{CONNECTED_CLIENTS, TOTAL_COMMANDS, START_TIME};

pub enum CmdResult {
    Written,
    Authenticated,
    Subscribe { channels: Vec<String> },
    Publish { channel: String, message: String },
}

fn is_restricted() -> bool {
    std::env::var("LUX_RESTRICTED").map_or(false, |v| v == "1" || v == "true")
}

#[inline(always)]
fn cmd_eq(input: &[u8], expected: &[u8]) -> bool {
    input.len() == expected.len()
        && input.iter().zip(expected).all(|(a, b)| a.to_ascii_uppercase() == *b)
}

#[inline(always)]
fn arg_str(arg: &[u8]) -> &str {
    std::str::from_utf8(arg).unwrap_or("")
}

fn parse_u64(arg: &[u8]) -> Result<u64, ()> {
    arg_str(arg).parse::<u64>().map_err(|_| ())
}

fn parse_i64(arg: &[u8]) -> Result<i64, ()> {
    arg_str(arg).parse::<i64>().map_err(|_| ())
}

pub fn execute(
    store: &Store,
    _broker: &Broker,
    args: &[&[u8]],
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    if args.is_empty() {
        resp::write_error(out, "ERR no command");
        return CmdResult::Written;
    }

    let cmd = args[0];

    if cmd_eq(cmd, b"AUTH") {
        if args.len() < 2 {
            resp::write_error(out, "ERR wrong number of arguments for 'auth' command");
            return CmdResult::Written;
        }
        let expected = std::env::var("LUX_PASSWORD").unwrap_or_default();
        if expected.is_empty() {
            resp::write_error(out, "ERR Client sent AUTH, but no password is set");
        } else if arg_str(args[1]) == expected {
            resp::write_ok(out);
            return CmdResult::Authenticated;
        } else {
            resp::write_error(out, "WRONGPASS invalid password");
        }
        return CmdResult::Written;
    }

    if (cmd_eq(cmd, b"KEYS") || cmd_eq(cmd, b"FLUSHALL") || cmd_eq(cmd, b"FLUSHDB") || cmd_eq(cmd, b"DEBUG")) && is_restricted() {
        resp::write_error(out, "ERR command disabled in restricted mode");
        return CmdResult::Written;
    }

    if cmd_eq(cmd, b"PING") {
        if args.len() > 1 {
            resp::write_bulk_raw(out, args[1]);
        } else {
            resp::write_pong(out);
        }
    } else if cmd_eq(cmd, b"ECHO") {
        if args.len() < 2 {
            resp::write_error(out, "ERR wrong number of arguments for 'echo' command");
        } else {
            resp::write_bulk_raw(out, args[1]);
        }
    } else if cmd_eq(cmd, b"SET") {
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
                match parse_u64(args[i + 1]) {
                    Ok(s) => ttl = Some(Duration::from_secs(s)),
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
                match parse_u64(args[i + 1]) {
                    Ok(ms) => ttl = Some(Duration::from_millis(ms)),
                    Err(_) => {
                        resp::write_error(out, "ERR value is not an integer or out of range");
                        return CmdResult::Written;
                    }
                }
                i += 2;
            } else if cmd_eq(args[i], b"NX") {
                nx = true; i += 1;
            } else if cmd_eq(args[i], b"XX") {
                xx = true; i += 1;
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
    } else if cmd_eq(cmd, b"SETNX") {
        if args.len() < 3 {
            resp::write_error(out, "ERR wrong number of arguments for 'setnx' command");
            return CmdResult::Written;
        }
        resp::write_integer(out, if store.set_nx(args[1], args[2], now) { 1 } else { 0 });
    } else if cmd_eq(cmd, b"SETEX") {
        if args.len() < 4 {
            resp::write_error(out, "ERR wrong number of arguments for 'setex' command");
            return CmdResult::Written;
        }
        match parse_u64(args[2]) {
            Ok(secs) => {
                store.set(args[1], args[3], Some(Duration::from_secs(secs)), now);
                resp::write_ok(out);
            }
            Err(_) => resp::write_error(out, "ERR value is not an integer or out of range"),
        }
    } else if cmd_eq(cmd, b"PSETEX") {
        if args.len() < 4 {
            resp::write_error(out, "ERR wrong number of arguments for 'psetex' command");
            return CmdResult::Written;
        }
        match parse_u64(args[2]) {
            Ok(ms) => {
                store.set(args[1], args[3], Some(Duration::from_millis(ms)), now);
                resp::write_ok(out);
            }
            Err(_) => resp::write_error(out, "ERR value is not an integer or out of range"),
        }
    } else if cmd_eq(cmd, b"GET") {
        if args.len() < 2 {
            resp::write_error(out, "ERR wrong number of arguments for 'get' command");
            return CmdResult::Written;
        }
        resp::write_optional_bulk_raw(out, &store.get(args[1], now));
    } else if cmd_eq(cmd, b"GETSET") {
        if args.len() < 3 {
            resp::write_error(out, "ERR wrong number of arguments for 'getset' command");
            return CmdResult::Written;
        }
        resp::write_optional_bulk_raw(out, &store.get_set(args[1], args[2], now));
    } else if cmd_eq(cmd, b"MGET") {
        if args.len() < 2 {
            resp::write_error(out, "ERR wrong number of arguments for 'mget' command");
            return CmdResult::Written;
        }
        resp::write_array_header(out, args.len() - 1);
        for key in &args[1..] {
            resp::write_optional_bulk_raw(out, &store.get(key, now));
        }
    } else if cmd_eq(cmd, b"MSET") {
        if args.len() < 3 || (args.len() - 1) % 2 != 0 {
            resp::write_error(out, "ERR wrong number of arguments for 'mset' command");
            return CmdResult::Written;
        }
        let mut i = 1;
        while i < args.len() {
            store.set(args[i], args[i + 1], None, now);
            i += 2;
        }
        resp::write_ok(out);
    } else if cmd_eq(cmd, b"STRLEN") {
        if args.len() < 2 {
            resp::write_error(out, "ERR wrong number of arguments for 'strlen' command");
            return CmdResult::Written;
        }
        resp::write_integer(out, store.strlen(args[1], now));
    } else if cmd_eq(cmd, b"DEL") {
        if args.len() < 2 {
            resp::write_error(out, "ERR wrong number of arguments for 'del' command");
            return CmdResult::Written;
        }
        let keys: Vec<&[u8]> = args[1..].to_vec();
        resp::write_integer(out, store.del(&keys));
    } else if cmd_eq(cmd, b"EXISTS") {
        if args.len() < 2 {
            resp::write_error(out, "ERR wrong number of arguments for 'exists' command");
            return CmdResult::Written;
        }
        let keys: Vec<&[u8]> = args[1..].to_vec();
        resp::write_integer(out, store.exists(&keys, now));
    } else if cmd_eq(cmd, b"INCR") {
        if args.len() < 2 {
            resp::write_error(out, "ERR wrong number of arguments for 'incr' command");
            return CmdResult::Written;
        }
        match store.incr(args[1], 1, now) {
            Ok(n) => resp::write_integer(out, n),
            Err(e) => resp::write_error(out, &e),
        }
    } else if cmd_eq(cmd, b"DECR") {
        if args.len() < 2 {
            resp::write_error(out, "ERR wrong number of arguments for 'decr' command");
            return CmdResult::Written;
        }
        match store.incr(args[1], -1, now) {
            Ok(n) => resp::write_integer(out, n),
            Err(e) => resp::write_error(out, &e),
        }
    } else if cmd_eq(cmd, b"INCRBY") {
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
    } else if cmd_eq(cmd, b"DECRBY") {
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
    } else if cmd_eq(cmd, b"APPEND") {
        if args.len() < 3 {
            resp::write_error(out, "ERR wrong number of arguments for 'append' command");
            return CmdResult::Written;
        }
        resp::write_integer(out, store.append(args[1], args[2], now));
    } else if cmd_eq(cmd, b"KEYS") {
        if args.len() < 2 {
            resp::write_error(out, "ERR wrong number of arguments for 'keys' command");
            return CmdResult::Written;
        }
        let keys = store.keys(args[1], now);
        resp::write_bulk_array(out, &keys);
    } else if cmd_eq(cmd, b"SCAN") {
        if args.len() < 2 {
            resp::write_error(out, "ERR wrong number of arguments for 'scan' command");
            return CmdResult::Written;
        }
        let cursor = parse_u64(args[1]).unwrap_or(0) as usize;
        let mut pattern: &[u8] = b"*";
        let mut count = 10usize;
        let mut i = 2;
        while i < args.len() {
            if cmd_eq(args[i], b"MATCH") {
                if i + 1 < args.len() {
                    pattern = args[i + 1];
                    i += 2;
                } else {
                    i += 1;
                }
            } else if cmd_eq(args[i], b"COUNT") {
                if i + 1 < args.len() {
                    count = parse_u64(args[i + 1]).unwrap_or(10) as usize;
                    i += 2;
                } else {
                    i += 1;
                }
            } else {
                i += 1;
            }
        }
        let (next_cursor, keys) = store.scan(cursor, pattern, count, now);
        resp::write_array_header(out, 2);
        resp::write_bulk(out, &next_cursor.to_string());
        resp::write_bulk_array(out, &keys);
    } else if cmd_eq(cmd, b"TTL") {
        if args.len() < 2 {
            resp::write_error(out, "ERR wrong number of arguments for 'ttl' command");
            return CmdResult::Written;
        }
        resp::write_integer(out, store.ttl(args[1], now));
    } else if cmd_eq(cmd, b"PTTL") {
        if args.len() < 2 {
            resp::write_error(out, "ERR wrong number of arguments for 'pttl' command");
            return CmdResult::Written;
        }
        resp::write_integer(out, store.pttl(args[1], now));
    } else if cmd_eq(cmd, b"EXPIRE") {
        if args.len() < 3 {
            resp::write_error(out, "ERR wrong number of arguments for 'expire' command");
            return CmdResult::Written;
        }
        match parse_u64(args[2]) {
            Ok(secs) => resp::write_integer(out, if store.expire(args[1], secs, now) { 1 } else { 0 }),
            Err(_) => resp::write_error(out, "ERR value is not an integer or out of range"),
        }
    } else if cmd_eq(cmd, b"PEXPIRE") {
        if args.len() < 3 {
            resp::write_error(out, "ERR wrong number of arguments for 'pexpire' command");
            return CmdResult::Written;
        }
        match parse_u64(args[2]) {
            Ok(ms) => resp::write_integer(out, if store.pexpire(args[1], ms, now) { 1 } else { 0 }),
            Err(_) => resp::write_error(out, "ERR value is not an integer or out of range"),
        }
    } else if cmd_eq(cmd, b"PERSIST") {
        if args.len() < 2 {
            resp::write_error(out, "ERR wrong number of arguments for 'persist' command");
            return CmdResult::Written;
        }
        resp::write_integer(out, if store.persist(args[1], now) { 1 } else { 0 });
    } else if cmd_eq(cmd, b"TYPE") {
        if args.len() < 2 {
            resp::write_error(out, "ERR wrong number of arguments for 'type' command");
            return CmdResult::Written;
        }
        match store.get_entry_type(args[1], now) {
            Some(t) => resp::write_simple(out, t),
            None => resp::write_simple(out, "none"),
        }
    } else if cmd_eq(cmd, b"RENAME") {
        if args.len() < 3 {
            resp::write_error(out, "ERR wrong number of arguments for 'rename' command");
            return CmdResult::Written;
        }
        match store.rename(args[1], args[2], now) {
            Ok(()) => resp::write_ok(out),
            Err(e) => resp::write_error(out, &e),
        }
    } else if cmd_eq(cmd, b"DBSIZE") {
        resp::write_integer(out, store.dbsize(now));
    } else if cmd_eq(cmd, b"FLUSHDB") || cmd_eq(cmd, b"FLUSHALL") {
        store.flushdb();
        resp::write_ok(out);
    } else if cmd_eq(cmd, b"LPUSH") {
        if args.len() < 3 {
            resp::write_error(out, "ERR wrong number of arguments for 'lpush' command");
            return CmdResult::Written;
        }
        let vals: Vec<&[u8]> = args[2..].to_vec();
        match store.lpush(args[1], &vals, now) {
            Ok(n) => resp::write_integer(out, n),
            Err(e) => resp::write_error(out, &e),
        }
    } else if cmd_eq(cmd, b"RPUSH") {
        if args.len() < 3 {
            resp::write_error(out, "ERR wrong number of arguments for 'rpush' command");
            return CmdResult::Written;
        }
        let vals: Vec<&[u8]> = args[2..].to_vec();
        match store.rpush(args[1], &vals, now) {
            Ok(n) => resp::write_integer(out, n),
            Err(e) => resp::write_error(out, &e),
        }
    } else if cmd_eq(cmd, b"LPOP") {
        if args.len() < 2 {
            resp::write_error(out, "ERR wrong number of arguments for 'lpop' command");
            return CmdResult::Written;
        }
        resp::write_optional_bulk_raw(out, &store.lpop(args[1], now));
    } else if cmd_eq(cmd, b"RPOP") {
        if args.len() < 2 {
            resp::write_error(out, "ERR wrong number of arguments for 'rpop' command");
            return CmdResult::Written;
        }
        resp::write_optional_bulk_raw(out, &store.rpop(args[1], now));
    } else if cmd_eq(cmd, b"LLEN") {
        if args.len() < 2 {
            resp::write_error(out, "ERR wrong number of arguments for 'llen' command");
            return CmdResult::Written;
        }
        match store.llen(args[1], now) {
            Ok(n) => resp::write_integer(out, n),
            Err(e) => resp::write_error(out, &e),
        }
    } else if cmd_eq(cmd, b"LRANGE") {
        if args.len() < 4 {
            resp::write_error(out, "ERR wrong number of arguments for 'lrange' command");
            return CmdResult::Written;
        }
        let start = parse_i64(args[2]).unwrap_or(0);
        let stop = parse_i64(args[3]).unwrap_or(-1);
        match store.lrange(args[1], start, stop, now) {
            Ok(items) => resp::write_bulk_array_raw(out, &items),
            Err(e) => resp::write_error(out, &e),
        }
    } else if cmd_eq(cmd, b"LINDEX") {
        if args.len() < 3 {
            resp::write_error(out, "ERR wrong number of arguments for 'lindex' command");
            return CmdResult::Written;
        }
        let index = parse_i64(args[2]).unwrap_or(0);
        resp::write_optional_bulk_raw(out, &store.lindex(args[1], index, now));
    } else if cmd_eq(cmd, b"HSET") || cmd_eq(cmd, b"HMSET") {
        if args.len() < 4 || (args.len() - 2) % 2 != 0 {
            let cmd_name = if cmd_eq(cmd, b"HMSET") { "hmset" } else { "hset" };
            resp::write_error(out, &format!("ERR wrong number of arguments for '{}' command", cmd_name));
            return CmdResult::Written;
        }
        let pairs: Vec<(&[u8], &[u8])> = args[2..]
            .chunks(2)
            .map(|c| (c[0], c[1]))
            .collect();
        match store.hset(args[1], &pairs, now) {
            Ok(n) => {
                if cmd_eq(cmd, b"HMSET") {
                    resp::write_ok(out);
                } else {
                    resp::write_integer(out, n);
                }
            }
            Err(e) => resp::write_error(out, &e),
        }
    } else if cmd_eq(cmd, b"HGET") {
        if args.len() < 3 {
            resp::write_error(out, "ERR wrong number of arguments for 'hget' command");
            return CmdResult::Written;
        }
        resp::write_optional_bulk_raw(out, &store.hget(args[1], args[2], now));
    } else if cmd_eq(cmd, b"HMGET") {
        if args.len() < 3 {
            resp::write_error(out, "ERR wrong number of arguments for 'hmget' command");
            return CmdResult::Written;
        }
        let fields: Vec<&[u8]> = args[2..].to_vec();
        let results = store.hmget(args[1], &fields, now);
        resp::write_array_header(out, results.len());
        for val in &results {
            resp::write_optional_bulk_raw(out, val);
        }
    } else if cmd_eq(cmd, b"HDEL") {
        if args.len() < 3 {
            resp::write_error(out, "ERR wrong number of arguments for 'hdel' command");
            return CmdResult::Written;
        }
        let fields: Vec<&[u8]> = args[2..].to_vec();
        match store.hdel(args[1], &fields, now) {
            Ok(n) => resp::write_integer(out, n),
            Err(e) => resp::write_error(out, &e),
        }
    } else if cmd_eq(cmd, b"HGETALL") {
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
    } else if cmd_eq(cmd, b"HKEYS") {
        if args.len() < 2 {
            resp::write_error(out, "ERR wrong number of arguments for 'hkeys' command");
            return CmdResult::Written;
        }
        match store.hkeys(args[1], now) {
            Ok(keys) => resp::write_bulk_array(out, &keys),
            Err(e) => resp::write_error(out, &e),
        }
    } else if cmd_eq(cmd, b"HVALS") {
        if args.len() < 2 {
            resp::write_error(out, "ERR wrong number of arguments for 'hvals' command");
            return CmdResult::Written;
        }
        match store.hvals(args[1], now) {
            Ok(vals) => resp::write_bulk_array_raw(out, &vals),
            Err(e) => resp::write_error(out, &e),
        }
    } else if cmd_eq(cmd, b"HLEN") {
        if args.len() < 2 {
            resp::write_error(out, "ERR wrong number of arguments for 'hlen' command");
            return CmdResult::Written;
        }
        match store.hlen(args[1], now) {
            Ok(n) => resp::write_integer(out, n),
            Err(e) => resp::write_error(out, &e),
        }
    } else if cmd_eq(cmd, b"HEXISTS") {
        if args.len() < 3 {
            resp::write_error(out, "ERR wrong number of arguments for 'hexists' command");
            return CmdResult::Written;
        }
        match store.hexists(args[1], args[2], now) {
            Ok(b) => resp::write_integer(out, if b { 1 } else { 0 }),
            Err(e) => resp::write_error(out, &e),
        }
    } else if cmd_eq(cmd, b"HINCRBY") {
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
    } else if cmd_eq(cmd, b"SADD") {
        if args.len() < 3 {
            resp::write_error(out, "ERR wrong number of arguments for 'sadd' command");
            return CmdResult::Written;
        }
        let members: Vec<&[u8]> = args[2..].to_vec();
        match store.sadd(args[1], &members, now) {
            Ok(n) => resp::write_integer(out, n),
            Err(e) => resp::write_error(out, &e),
        }
    } else if cmd_eq(cmd, b"SREM") {
        if args.len() < 3 {
            resp::write_error(out, "ERR wrong number of arguments for 'srem' command");
            return CmdResult::Written;
        }
        let members: Vec<&[u8]> = args[2..].to_vec();
        match store.srem(args[1], &members, now) {
            Ok(n) => resp::write_integer(out, n),
            Err(e) => resp::write_error(out, &e),
        }
    } else if cmd_eq(cmd, b"SMEMBERS") {
        if args.len() < 2 {
            resp::write_error(out, "ERR wrong number of arguments for 'smembers' command");
            return CmdResult::Written;
        }
        match store.smembers(args[1], now) {
            Ok(members) => resp::write_bulk_array(out, &members),
            Err(e) => resp::write_error(out, &e),
        }
    } else if cmd_eq(cmd, b"SISMEMBER") {
        if args.len() < 3 {
            resp::write_error(out, "ERR wrong number of arguments for 'sismember' command");
            return CmdResult::Written;
        }
        match store.sismember(args[1], args[2], now) {
            Ok(b) => resp::write_integer(out, if b { 1 } else { 0 }),
            Err(e) => resp::write_error(out, &e),
        }
    } else if cmd_eq(cmd, b"SCARD") {
        if args.len() < 2 {
            resp::write_error(out, "ERR wrong number of arguments for 'scard' command");
            return CmdResult::Written;
        }
        match store.scard(args[1], now) {
            Ok(n) => resp::write_integer(out, n),
            Err(e) => resp::write_error(out, &e),
        }
    } else if cmd_eq(cmd, b"SUNION") {
        if args.len() < 2 {
            resp::write_error(out, "ERR wrong number of arguments for 'sunion' command");
            return CmdResult::Written;
        }
        let keys: Vec<&[u8]> = args[1..].to_vec();
        match store.sunion(&keys, now) {
            Ok(members) => resp::write_bulk_array(out, &members),
            Err(e) => resp::write_error(out, &e),
        }
    } else if cmd_eq(cmd, b"SINTER") {
        if args.len() < 2 {
            resp::write_error(out, "ERR wrong number of arguments for 'sinter' command");
            return CmdResult::Written;
        }
        let keys: Vec<&[u8]> = args[1..].to_vec();
        match store.sinter(&keys, now) {
            Ok(members) => resp::write_bulk_array(out, &members),
            Err(e) => resp::write_error(out, &e),
        }
    } else if cmd_eq(cmd, b"SDIFF") {
        if args.len() < 2 {
            resp::write_error(out, "ERR wrong number of arguments for 'sdiff' command");
            return CmdResult::Written;
        }
        let keys: Vec<&[u8]> = args[1..].to_vec();
        match store.sdiff(&keys, now) {
            Ok(members) => resp::write_bulk_array(out, &members),
            Err(e) => resp::write_error(out, &e),
        }
    } else if cmd_eq(cmd, b"SAVE") {
        match crate::snapshot::save(store) {
            Ok(n) => resp::write_simple(out, &format!("OK ({n} keys saved)")),
            Err(e) => resp::write_error(out, &format!("ERR snapshot failed: {e}")),
        }
    } else if cmd_eq(cmd, b"INFO") {
        let section = if args.len() > 1 {
            arg_str(args[1]).to_lowercase()
        } else {
            "all".to_string()
        };
        let info = build_info(store, &section, now);
        resp::write_bulk(out, &info);
    } else if cmd_eq(cmd, b"CONFIG") {
        if args.len() > 1 && cmd_eq(args[1], b"GET") {
            resp::write_array_header(out, 0);
        } else {
            resp::write_ok(out);
        }
    } else if cmd_eq(cmd, b"CLIENT") {
        resp::write_ok(out);
    } else if cmd_eq(cmd, b"SELECT") {
        resp::write_ok(out);
    } else if cmd_eq(cmd, b"COMMAND") {
        if args.len() > 1 && cmd_eq(args[1], b"DOCS") {
            resp::write_array_header(out, 0);
        } else {
            resp::write_ok(out);
        }
    } else if cmd_eq(cmd, b"PUBLISH") {
        if args.len() < 3 {
            resp::write_error(out, "ERR wrong number of arguments for 'publish' command");
            return CmdResult::Written;
        }
        return CmdResult::Publish {
            channel: arg_str(args[1]).to_string(),
            message: arg_str(args[2]).to_string(),
        };
    } else if cmd_eq(cmd, b"SUBSCRIBE") {
        if args.len() < 2 {
            resp::write_error(out, "ERR wrong number of arguments for 'subscribe' command");
            return CmdResult::Written;
        }
        return CmdResult::Subscribe {
            channels: args[1..].iter().map(|a| arg_str(a).to_string()).collect(),
        };
    } else {
        resp::write_error(out, &format!("ERR unknown command '{}'", arg_str(cmd)));
    }
    CmdResult::Written
}

fn build_info(store: &Store, _section: &str, now: Instant) -> String {
    let uptime = START_TIME
        .get()
        .map(|t| t.elapsed().as_secs())
        .unwrap_or(0);
    let restricted = is_restricted();
    let powered_by = if restricted { "\r\npowered_by:LuxDB Cloud (luxdb.dev)" } else { "" };
    format!(
        "# Server\r\n\
         lux_version:{}\r\n\
         shards:{}\r\n\
         uptime_in_seconds:{}\r\n\
         {powered_by}\
         \r\n\
         # Clients\r\n\
         connected_clients:{}\r\n\
         \r\n\
         # Stats\r\n\
         total_commands_processed:{}\r\n\
         \r\n\
         # Memory\r\n\
         used_memory_bytes:{}\r\n\
         \r\n\
         # Keyspace\r\n\
         keys:{}\r\n",
        env!("CARGO_PKG_VERSION"),
        store.shard_count(),
        uptime,
        CONNECTED_CLIENTS.load(Ordering::Relaxed),
        TOTAL_COMMANDS.load(Ordering::Relaxed),
        store.approximate_memory(),
        store.dbsize(now)
    )
}
