use bytes::BytesMut;
use std::time::Instant;

use crate::resp;
use crate::store::Store;

use super::{arg_str, cmd_eq, parse_i64, CmdResult};

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
        parse_i64(args[3]).unwrap_or(0)
    } else {
        0
    };
    let end = if args.len() >= 5 {
        Some(parse_i64(args[4]).unwrap_or(-1))
    } else {
        None
    };
    let use_bit = if args.len() >= 6 {
        cmd_eq(args[5], b"BIT")
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
    let op = if cmd_eq(args[1], b"AND") {
        "AND"
    } else if cmd_eq(args[1], b"OR") {
        "OR"
    } else if cmd_eq(args[1], b"XOR") {
        "XOR"
    } else if cmd_eq(args[1], b"NOT") {
        "NOT"
    } else {
        arg_str(args[1])
    };
    let dest = args[2];
    let src_keys = &args[3..];

    if op == "NOT" && src_keys.len() != 1 {
        resp::write_error(out, "ERR BITOP NOT requires one and only one key");
        return CmdResult::Written;
    }

    match store.bitop(op, dest, src_keys, now) {
        Ok(len) => resp::write_integer(out, len as i64),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}
