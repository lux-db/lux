use bytes::BytesMut;
use std::time::Instant;

use crate::resp;
use crate::store::Store;

use super::{arg_str, cmd_eq, parse_i64, CmdResult};

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

pub fn cmd_setbit(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() != 4 {
        resp::write_error(out, "ERR wrong number of arguments for 'setbit' command");
        return CmdResult::Written;
    }
    let offset = match parse_i64(args[2]) {
        Ok(o) if o >= 0 => o as u64,
        _ => {
            resp::write_error(out, "ERR bit offset is not an integer or out of range");
            return CmdResult::Written;
        }
    };
    let value = match args[3] {
        b"0" => 0u8,
        b"1" => 1u8,
        _ => {
            resp::write_error(out, "ERR bit is not an integer or out of range");
            return CmdResult::Written;
        }
    };
    match store.setbit(args[1], offset, value, now) {
        Ok(old) => resp::write_integer(out, old as i64),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_getbit(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() != 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'getbit' command");
        return CmdResult::Written;
    }
    let offset = match parse_i64(args[2]) {
        Ok(o) if o >= 0 => o as u64,
        _ => {
            resp::write_error(out, "ERR bit offset is not an integer or out of range");
            return CmdResult::Written;
        }
    };
    match store.getbit(args[1], offset, now) {
        Ok(bit) => resp::write_integer(out, bit as i64),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_bitcount(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'bitcount' command");
        return CmdResult::Written;
    }
    let (start, end, use_bit) = if args.len() >= 4 {
        let s = match parse_i64(args[2]) {
            Ok(v) => v,
            Err(_) => {
                resp::write_error(out, "ERR value is not an integer or out of range");
                return CmdResult::Written;
            }
        };
        let e = match parse_i64(args[3]) {
            Ok(v) => v,
            Err(_) => {
                resp::write_error(out, "ERR value is not an integer or out of range");
                return CmdResult::Written;
            }
        };
        let bit_mode = if args.len() >= 5 {
            if cmd_eq(args[4], b"BIT") {
                true
            } else if cmd_eq(args[4], b"BYTE") {
                false
            } else {
                resp::write_error(out, "ERR syntax error");
                return CmdResult::Written;
            }
        } else {
            false
        };
        (s, e, bit_mode)
    } else if args.len() == 3 {
        resp::write_error(out, "ERR syntax error");
        return CmdResult::Written;
    } else {
        (0i64, -1i64, false)
    };
    match store.bitcount(args[1], start, end, use_bit, now) {
        Ok(n) => resp::write_integer(out, n),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_bitpos(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'bitpos' command");
        return CmdResult::Written;
    }
    let bit = match args[2] {
        b"0" => 0u8,
        b"1" => 1u8,
        _ => {
            resp::write_error(out, "ERR bit is not an integer or out of range");
            return CmdResult::Written;
        }
    };
    let start = if args.len() >= 4 {
        match parse_i64_arg(args[3], out) {
            Some(start) => start,
            None => return CmdResult::Written,
        }
    } else {
        0
    };
    let end = if args.len() >= 5 {
        match parse_i64_arg(args[4], out) {
            Some(end) => Some(end),
            None => return CmdResult::Written,
        }
    } else {
        None
    };
    let use_bit = if args.len() >= 6 {
        if cmd_eq(args[5], b"BIT") {
            true
        } else if cmd_eq(args[5], b"BYTE") {
            false
        } else {
            resp::write_error(out, "ERR syntax error");
            return CmdResult::Written;
        }
    } else {
        false
    };
    let end_given = args.len() >= 5;
    match store.bitpos(args[1], bit, start, end, end_given, use_bit, now) {
        Ok(pos) => resp::write_integer(out, pos),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_bitop(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 4 {
        resp::write_error(out, "ERR wrong number of arguments for 'bitop' command");
        return CmdResult::Written;
    }
    let op = arg_str(args[1]).to_uppercase();
    if !matches!(op.as_str(), "AND" | "OR" | "XOR" | "NOT") {
        resp::write_error(
            out,
            &format!("ERR BITOP requires AND, OR, XOR, or NOT, got '{op}'"),
        );
        return CmdResult::Written;
    }
    let dest = args[2];
    let src_keys: Vec<&[u8]> = args[3..].to_vec();
    for key in &src_keys {
        store.try_promote(key, now);
    }

    if op == "NOT" && src_keys.len() != 1 {
        resp::write_error(out, "ERR BITOP NOT requires one and only one key");
        return CmdResult::Written;
    }

    match store.bitop(&op, dest, &src_keys, now) {
        Ok(len) => resp::write_integer(out, len as i64),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}
