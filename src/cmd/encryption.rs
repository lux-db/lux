use bytes::BytesMut;
use std::time::{Duration, Instant};

use crate::resp;
use crate::store::Store;

use super::{cmd_eq, parse_u64, CmdResult};

pub fn cmd_enc(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 2 {
        resp::write_error(
            out,
            "ERR usage: ENC <STATUS|INIT|LIST|ROTATE|REWRAP|RETIRE>",
        );
        return CmdResult::Written;
    }
    if cmd_eq(args[1], b"STATUS") {
        let status = store.encryption().status();
        resp::write_array_header(out, 8);
        resp::write_bulk(out, "initialized");
        resp::write_integer(out, if status.initialized { 1 } else { 0 });
        resp::write_bulk(out, "active_key_id");
        match status.active_key_id {
            Some(id) => resp::write_bulk(out, &id),
            None => resp::write_null(out),
        }
        resp::write_bulk(out, "key_count");
        resp::write_integer(out, status.key_count as i64);
        resp::write_bulk(out, "persisted");
        resp::write_integer(out, if status.persisted { 1 } else { 0 });
        return CmdResult::Written;
    }
    if cmd_eq(args[1], b"LIST") {
        let keys = store.encryption().list();
        resp::write_array_header(out, keys.len());
        for key in keys {
            resp::write_array_header(out, 4);
            resp::write_bulk(out, "id");
            resp::write_bulk(out, &key.id);
            resp::write_bulk(out, "status");
            resp::write_bulk(out, key.status);
        }
        return CmdResult::Written;
    }
    if cmd_eq(args[1], b"INIT") {
        let key_id = parse_keyid(args, 2, out);
        let Some(key_id) = key_id else {
            return CmdResult::Written;
        };
        match store.encryption().init(key_id) {
            Ok(id) => resp::write_bulk(out, &id),
            Err(err) => resp::write_error(out, &err),
        }
        return CmdResult::Written;
    }
    if cmd_eq(args[1], b"ROTATE") {
        let key_id = parse_keyid(args, 2, out);
        let Some(key_id) = key_id else {
            return CmdResult::Written;
        };
        match store.encryption().rotate(key_id) {
            Ok(id) => resp::write_bulk(out, &id),
            Err(err) => resp::write_error(out, &err),
        }
        return CmdResult::Written;
    }
    if cmd_eq(args[1], b"REWRAP") {
        match store.enc_rewrap_all() {
            Ok(count) => resp::write_integer(out, count as i64),
            Err(err) => resp::write_error(out, &err),
        }
        return CmdResult::Written;
    }
    if cmd_eq(args[1], b"RETIRE") {
        if args.len() != 3 {
            resp::write_error(out, "ERR usage: ENC RETIRE <key_id>");
            return CmdResult::Written;
        }
        match store.enc_retire_key(std::str::from_utf8(args[2]).unwrap_or("")) {
            Ok(()) => resp::write_ok(out),
            Err(err) => resp::write_error(out, &err),
        }
        return CmdResult::Written;
    }
    if cmd_eq(args[1], b"RAWSET") {
        return cmd_rawset(args, store, out, now);
    }
    if cmd_eq(args[1], b"RAWHSET") {
        return cmd_rawhset(args, store, out, now);
    }
    if cmd_eq(args[1], b"RAWLPUSH") {
        return cmd_rawlpush(args, store, out, now, true);
    }
    if cmd_eq(args[1], b"RAWRPUSH") {
        return cmd_rawlpush(args, store, out, now, false);
    }
    if cmd_eq(args[1], b"RAWVSET") {
        return cmd_rawvset(args, store, out, now);
    }
    resp::write_error(out, "ERR unknown ENC subcommand");
    CmdResult::Written
}

fn parse_keyid<'a>(args: &[&'a [u8]], start: usize, out: &mut BytesMut) -> Option<Option<&'a str>> {
    if args.len() == start {
        return Some(None);
    }
    if args.len() == start + 2 && cmd_eq(args[start], b"KEYID") {
        return Some(Some(std::str::from_utf8(args[start + 1]).unwrap_or("")));
    }
    resp::write_error(out, "ERR usage: ENC INIT|ROTATE [KEYID <id>]");
    None
}

fn cmd_rawset(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 4 {
        resp::write_error(
            out,
            "ERR usage: ENC RAWSET <key> <ciphertext> [SET options]",
        );
        return CmdResult::Written;
    }
    let mut ttl = None;
    let mut i = 4;
    while i < args.len() {
        if cmd_eq(args[i], b"EX") && i + 1 < args.len() {
            let Ok(secs) = parse_u64(args[i + 1]) else {
                resp::write_error(out, "ERR value is not an integer or out of range");
                return CmdResult::Written;
            };
            ttl = Some(Duration::from_secs(secs));
            i += 2;
        } else if cmd_eq(args[i], b"PX") && i + 1 < args.len() {
            let Ok(ms) = parse_u64(args[i + 1]) else {
                resp::write_error(out, "ERR value is not an integer or out of range");
                return CmdResult::Written;
            };
            ttl = Some(Duration::from_millis(ms));
            i += 2;
        } else if cmd_eq(args[i], b"EXAT") && i + 1 < args.len() {
            // Absolute epoch-seconds deadline -> remaining duration (0 if past,
            // so the value replays as already-expired, matching SET ... EXAT).
            let Ok(secs) = parse_u64(args[i + 1]) else {
                resp::write_error(out, "ERR value is not an integer or out of range");
                return CmdResult::Written;
            };
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            ttl = Some(Duration::from_secs(secs.saturating_sub(now_secs)));
            i += 2;
        } else if cmd_eq(args[i], b"PXAT") && i + 1 < args.len() {
            let Ok(ms) = parse_u64(args[i + 1]) else {
                resp::write_error(out, "ERR value is not an integer or out of range");
                return CmdResult::Written;
            };
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            ttl = Some(Duration::from_millis(ms.saturating_sub(now_ms)));
            i += 2;
        } else if cmd_eq(args[i], b"NX")
            || cmd_eq(args[i], b"XX")
            || cmd_eq(args[i], b"KEEPTTL")
            || cmd_eq(args[i], b"GET")
        {
            i += 1;
        } else if cmd_eq(args[i], b"IFEQ") && i + 1 < args.len() {
            i += 2;
        } else {
            resp::write_error(out, "ERR syntax error");
            return CmdResult::Written;
        }
    }
    store.set(args[2], args[3], ttl, now);
    resp::write_ok(out);
    CmdResult::Written
}

fn cmd_rawhset(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 5 || !(args.len() - 3).is_multiple_of(2) {
        resp::write_error(out, "ERR usage: ENC RAWHSET <key> <field> <ciphertext> ...");
        return CmdResult::Written;
    }
    let pairs: Vec<(&[u8], &[u8])> = args[3..].chunks(2).map(|c| (c[0], c[1])).collect();
    match store.hset(args[2], &pairs, now) {
        Ok(_) => resp::write_ok(out),
        Err(err) => resp::write_error(out, &err),
    }
    CmdResult::Written
}

/// Replay form of an encrypted LPUSH/RPUSH: stores the already-sealed envelope
/// elements verbatim (no re-encryption). `front` selects LPUSH vs RPUSH.
fn cmd_rawlpush(
    args: &[&[u8]],
    store: &Store,
    out: &mut BytesMut,
    now: Instant,
    front: bool,
) -> CmdResult {
    if args.len() < 4 {
        resp::write_error(out, "ERR usage: ENC RAWLPUSH|RAWRPUSH <key> <element> ...");
        return CmdResult::Written;
    }
    let res = if front {
        store.lpush(args[2], &args[3..], now)
    } else {
        store.rpush(args[2], &args[3..], now)
    };
    match res {
        Ok(_) => resp::write_ok(out),
        Err(err) => resp::write_error(out, &err),
    }
    CmdResult::Written
}

/// Replay form of an encrypted VSET: decrypts the sealed payload back to f32 and
/// re-inserts (rebuilding the in-memory index), preserving the encrypted flag.
fn cmd_rawvset(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 4 {
        resp::write_error(
            out,
            "ERR usage: ENC RAWVSET <key> <ciphertext> [META <m>] [EX <s>]",
        );
        return CmdResult::Written;
    }
    let key = args[2];
    let data = match store.decrypt_vector(key, args[3]) {
        Ok(d) => d,
        Err(err) => {
            resp::write_error(out, &err);
            return CmdResult::Written;
        }
    };
    let mut metadata = None;
    let mut ttl = None;
    let mut i = 4;
    while i < args.len() {
        if cmd_eq(args[i], b"META") && i + 1 < args.len() {
            metadata = Some(String::from_utf8_lossy(args[i + 1]).to_string());
            i += 2;
        } else if cmd_eq(args[i], b"EX") && i + 1 < args.len() {
            if let Ok(s) = parse_u64(args[i + 1]) {
                ttl = Some(Duration::from_secs(s));
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    store.vset(key, data, metadata, ttl, true, now);
    resp::write_ok(out);
    CmdResult::Written
}
