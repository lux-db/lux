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
