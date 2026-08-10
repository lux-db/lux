use bytes::BytesMut;
use std::time::Instant;

use crate::resp;
use crate::store::{epoch_ms, HExpireCond, HFieldTtl, HGetexTtl, Store, StoreValue};

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
    let encrypted = args.last().is_some_and(|arg| cmd_eq(arg, b"ENCRYPTED"));
    let end = if encrypted {
        args.len() - 1
    } else {
        args.len()
    };
    if end < 4 || !(end - 2).is_multiple_of(2) {
        let cmd_name = if is_hmset { "hmset" } else { "hset" };
        resp::write_error(
            out,
            &format!("ERR wrong number of arguments for '{}' command", cmd_name),
        );
        return CmdResult::Written;
    }
    let pairs: Vec<(&[u8], &[u8])> = args[2..end].chunks(2).map(|c| (c[0], c[1])).collect();
    let fields: Vec<&[u8]> = pairs.iter().map(|(field, _)| *field).collect();
    let should_self_log = encrypted || store.hash_fields_need_encryption(args[1], &fields, now);
    let result = if should_self_log {
        store
            .hset_kv(args[1], &pairs, encrypted, now)
            .map(|(added, stored_pairs)| (added, Some(stored_pairs)))
    } else {
        store.hset(args[1], &pairs, now).map(|added| (added, None))
    };
    match result {
        Ok((n, stored_pairs)) => {
            if should_self_log && store.wal_enabled() {
                if let Some(stored_pairs) = stored_pairs {
                    let mut owned: Vec<Vec<u8>> = Vec::with_capacity(3 + stored_pairs.len() * 2);
                    owned.push(b"ENC".to_vec());
                    owned.push(b"RAWHSET".to_vec());
                    owned.push(args[1].to_vec());
                    for (field, value) in stored_pairs {
                        owned.push(field);
                        owned.push(value);
                    }
                    let refs: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();
                    if let Err(e) = store.wal_log_command(&refs) {
                        resp::write_error(out, &format!("ERR WAL append failed: {e}"));
                        return CmdResult::Written;
                    }
                }
            }
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
    let ks = args[1];
    match shard.data.get(ks) {
        Some(entry) if !entry.is_expired_at(now) => {
            if let StoreValue::Hash(map) = &entry.value {
                let now_ms = crate::store::epoch_ms();
                if args.len() <= 2 {
                    let all: Vec<_> = map.live_iter(now_ms).collect();
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
                    let all: Vec<_> = map.live_iter(now_ms).collect();
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
    let ks = args[1];
    match shard.data.get(ks) {
        Some(entry) if !entry.is_expired_at(now) => {
            if cmd_eq(args[0], b"HSCAN") {
                if let StoreValue::Hash(map) = &entry.value {
                    let all: Vec<_> = map.live_iter(crate::store::epoch_ms()).collect();
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
                            match store.decrypt_hash_field_value(ks, k.as_bytes(), (*v).clone()) {
                                Ok(value) => resp::write_bulk_raw(out, &value),
                                Err(err) => {
                                    resp::write_error(out, &err);
                                    return CmdResult::Written;
                                }
                            }
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

// --- Hash field TTL family (Redis 7.4) ---

/// The four HEXPIRE setters differ only in unit and relative/absolute base.
#[derive(Clone, Copy)]
enum ExpireUnit {
    Seconds,
    Millis,
    SecondsAt,
    MillisAt,
}

/// The four HTTL queries differ only in how the deadline is formatted.
#[derive(Clone, Copy)]
enum TtlForm {
    Seconds,
    Millis,
    ExpireSeconds,
    ExpireMillis,
}

/// Parse a trailing `FIELDS <numfields> <field>...` clause starting at `at`.
fn parse_fields_clause<'a>(
    args: &'a [&'a [u8]],
    at: usize,
    out: &mut BytesMut,
) -> Option<Vec<&'a [u8]>> {
    if at >= args.len() || !cmd_eq(args[at], b"FIELDS") {
        resp::write_error(
            out,
            "ERR Mandatory keyword FIELDS is missing or not at the right position",
        );
        return None;
    }
    let numfields = match args.get(at + 1).and_then(|a| parse_u64(a).ok()) {
        Some(n) if n >= 1 => n as usize,
        _ => {
            resp::write_error(out, "ERR Parameter `numFields` should be greater than 0");
            return None;
        }
    };
    let start = at + 2;
    if start + numfields != args.len() {
        resp::write_error(
            out,
            "ERR The `numFields` parameter must match the number of arguments",
        );
        return None;
    }
    Some(args[start..start + numfields].to_vec())
}

fn cmd_hexpire_generic(
    args: &[&[u8]],
    store: &Store,
    out: &mut BytesMut,
    now: Instant,
    unit: ExpireUnit,
) -> CmdResult {
    // H(P)EXPIRE(AT) key ttl [NX|XX|GT|LT] FIELDS numfields field [field...]
    if args.len() < 6 {
        resp::write_error(out, "ERR wrong number of arguments");
        return CmdResult::Written;
    }
    let ttl = match parse_i64(args[2]) {
        Ok(v) => v,
        Err(_) => {
            resp::write_error(out, INTEGER_ERR);
            return CmdResult::Written;
        }
    };
    let mut i = 3;
    let cond = if cmd_eq(args[i], b"NX") {
        i += 1;
        HExpireCond::Nx
    } else if cmd_eq(args[i], b"XX") {
        i += 1;
        HExpireCond::Xx
    } else if cmd_eq(args[i], b"GT") {
        i += 1;
        HExpireCond::Gt
    } else if cmd_eq(args[i], b"LT") {
        i += 1;
        HExpireCond::Lt
    } else {
        HExpireCond::None
    };
    let Some(fields) = parse_fields_clause(args, i, out) else {
        return CmdResult::Written;
    };
    let now_ms = epoch_ms();
    let deadline_ms = match unit {
        ExpireUnit::Seconds => now_ms.saturating_add(ttl.saturating_mul(1000)),
        ExpireUnit::Millis => now_ms.saturating_add(ttl),
        ExpireUnit::SecondsAt => ttl.saturating_mul(1000),
        ExpireUnit::MillisAt => ttl,
    };
    match store.hexpire_fields(args[1], &fields, deadline_ms, cond, now) {
        Ok(results) => {
            // Self-log a resolved HPEXPIREAT (absolute deadline) so a relative
            // TTL doesn't re-anchor to replay time. Keyed on the hash key.
            if store.wal_enabled() {
                let dl = deadline_ms.to_string();
                let nf = fields.len().to_string();
                let mut owned: Vec<Vec<u8>> =
                    vec![b"HPEXPIREAT".to_vec(), args[1].to_vec(), dl.into_bytes()];
                match cond {
                    HExpireCond::None => {}
                    HExpireCond::Nx => owned.push(b"NX".to_vec()),
                    HExpireCond::Xx => owned.push(b"XX".to_vec()),
                    HExpireCond::Gt => owned.push(b"GT".to_vec()),
                    HExpireCond::Lt => owned.push(b"LT".to_vec()),
                }
                owned.push(b"FIELDS".to_vec());
                owned.push(nf.into_bytes());
                owned.extend(fields.iter().map(|f| f.to_vec()));
                let refs: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();
                if let Err(e) = store.wal_log_command(&refs) {
                    resp::write_error(out, &format!("ERR WAL append failed: {e}"));
                    return CmdResult::Written;
                }
            }
            resp::write_array_header(out, results.len());
            for r in results {
                resp::write_integer(out, r);
            }
        }
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_hexpire(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    cmd_hexpire_generic(args, store, out, now, ExpireUnit::Seconds)
}
pub fn cmd_hpexpire(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    cmd_hexpire_generic(args, store, out, now, ExpireUnit::Millis)
}
pub fn cmd_hexpireat(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    cmd_hexpire_generic(args, store, out, now, ExpireUnit::SecondsAt)
}
pub fn cmd_hpexpireat(
    args: &[&[u8]],
    store: &Store,
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    cmd_hexpire_generic(args, store, out, now, ExpireUnit::MillisAt)
}

fn cmd_httl_generic(
    args: &[&[u8]],
    store: &Store,
    out: &mut BytesMut,
    now: Instant,
    form: TtlForm,
) -> CmdResult {
    // H(P)TTL / H(P)EXPIRETIME key FIELDS numfields field [field...]
    if args.len() < 5 {
        resp::write_error(out, "ERR wrong number of arguments");
        return CmdResult::Written;
    }
    let Some(fields) = parse_fields_clause(args, 2, out) else {
        return CmdResult::Written;
    };
    match store.httl_fields(args[1], &fields, now) {
        Ok(results) => {
            let now_ms = epoch_ms();
            resp::write_array_header(out, results.len());
            for r in results {
                let v = match r {
                    HFieldTtl::Missing => -2,
                    HFieldTtl::NoTtl => -1,
                    HFieldTtl::ExpiresAtMs(ms) => match form {
                        TtlForm::Seconds => (ms - now_ms + 999).div_euclid(1000).max(0),
                        TtlForm::Millis => (ms - now_ms).max(0),
                        TtlForm::ExpireSeconds => ms.div_euclid(1000),
                        TtlForm::ExpireMillis => ms,
                    },
                };
                resp::write_integer(out, v);
            }
        }
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_httl(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    cmd_httl_generic(args, store, out, now, TtlForm::Seconds)
}
pub fn cmd_hpttl(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    cmd_httl_generic(args, store, out, now, TtlForm::Millis)
}
pub fn cmd_hexpiretime(
    args: &[&[u8]],
    store: &Store,
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    cmd_httl_generic(args, store, out, now, TtlForm::ExpireSeconds)
}
pub fn cmd_hpexpiretime(
    args: &[&[u8]],
    store: &Store,
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    cmd_httl_generic(args, store, out, now, TtlForm::ExpireMillis)
}

pub fn cmd_hpersist(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 5 {
        resp::write_error(out, "ERR wrong number of arguments");
        return CmdResult::Written;
    }
    let Some(fields) = parse_fields_clause(args, 2, out) else {
        return CmdResult::Written;
    };
    match store.hpersist_fields(args[1], &fields, now) {
        Ok(results) => {
            resp::write_array_header(out, results.len());
            for r in results {
                resp::write_integer(out, r);
            }
        }
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_hgetdel(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 5 {
        resp::write_error(out, "ERR wrong number of arguments for 'hgetdel' command");
        return CmdResult::Written;
    }
    let Some(fields) = parse_fields_clause(args, 2, out) else {
        return CmdResult::Written;
    };
    match store.hgetdel_fields(args[1], &fields, now) {
        Ok(values) => {
            resp::write_array_header(out, values.len());
            for v in &values {
                resp::write_optional_bulk_raw(out, v);
            }
        }
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_hgetex(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    // HGETEX key [EX s|PX ms|EXAT unix-s|PXAT unix-ms|PERSIST] FIELDS n field...
    if args.len() < 5 {
        resp::write_error(out, "ERR wrong number of arguments for 'hgetex' command");
        return CmdResult::Written;
    }
    let now_ms = epoch_ms();
    let mut i = 2;
    let ttl = if cmd_eq(args[i], b"PERSIST") {
        i += 1;
        HGetexTtl::Persist
    } else if let Some(unit) = if cmd_eq(args[i], b"EX") {
        Some(ExpireUnit::Seconds)
    } else if cmd_eq(args[i], b"PX") {
        Some(ExpireUnit::Millis)
    } else if cmd_eq(args[i], b"EXAT") {
        Some(ExpireUnit::SecondsAt)
    } else if cmd_eq(args[i], b"PXAT") {
        Some(ExpireUnit::MillisAt)
    } else {
        None
    } {
        let amount = match args.get(i + 1).map(|a| parse_i64(a)) {
            Some(Ok(v)) => v,
            _ => {
                resp::write_error(out, INTEGER_ERR);
                return CmdResult::Written;
            }
        };
        i += 2;
        let ms = match unit {
            ExpireUnit::Seconds => now_ms.saturating_add(amount.saturating_mul(1000)),
            ExpireUnit::Millis => now_ms.saturating_add(amount),
            ExpireUnit::SecondsAt => amount.saturating_mul(1000),
            ExpireUnit::MillisAt => amount,
        };
        HGetexTtl::SetMs(ms)
    } else {
        HGetexTtl::Keep
    };
    let Some(fields) = parse_fields_clause(args, i, out) else {
        return CmdResult::Written;
    };
    match store.hgetex_fields(args[1], &fields, ttl, now) {
        Ok(values) => {
            // A TTL mutation must be logged (keyed on the hash key) as a resolved
            // absolute effect, so replay is deterministic. A plain read is not.
            if store.wal_enabled() {
                let nf = fields.len().to_string();
                let logged: Option<Vec<Vec<u8>>> = match ttl {
                    HGetexTtl::Keep => None,
                    HGetexTtl::Persist => {
                        let mut o = vec![
                            b"HPERSIST".to_vec(),
                            args[1].to_vec(),
                            b"FIELDS".to_vec(),
                            nf.into_bytes(),
                        ];
                        o.extend(fields.iter().map(|f| f.to_vec()));
                        Some(o)
                    }
                    HGetexTtl::SetMs(ms) => {
                        let mut o = vec![
                            b"HPEXPIREAT".to_vec(),
                            args[1].to_vec(),
                            ms.to_string().into_bytes(),
                            b"FIELDS".to_vec(),
                            nf.into_bytes(),
                        ];
                        o.extend(fields.iter().map(|f| f.to_vec()));
                        Some(o)
                    }
                };
                if let Some(owned) = logged {
                    let refs: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();
                    if let Err(e) = store.wal_log_command(&refs) {
                        resp::write_error(out, &format!("ERR WAL append failed: {e}"));
                        return CmdResult::Written;
                    }
                }
            }
            resp::write_array_header(out, values.len());
            for v in &values {
                resp::write_optional_bulk_raw(out, v);
            }
        }
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}
