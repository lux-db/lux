use bytes::BytesMut;
use std::time::Instant;

use crate::resp;
use crate::store::{BitfieldOp, BitfieldOverflow, Store};

use super::{arg_str, cmd_eq, parse_i64, CmdResult};

const INTEGER_ERR: &str = "ERR value is not an integer or out of range";
const ENCRYPTED_BITOP_ERR: &str =
    "ERR bit operations are not supported on encrypted values (they would operate on ciphertext)";

/// Reject a bit operation touching an encrypted string. Bit ops read/write the
/// raw stored bytes, which for an encrypted value are the ciphertext envelope:
/// a write corrupts it irrecoverably and a read returns meaningless answers.
fn reject_encrypted_bitop(store: &Store, key: &[u8], now: Instant, out: &mut BytesMut) -> bool {
    if store.kv_string_is_encrypted(key, now) {
        resp::write_error(out, ENCRYPTED_BITOP_ERR);
        true
    } else {
        false
    }
}

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
    if reject_encrypted_bitop(store, args[1], now, out) {
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
    // A bit offset implies a byte string of (offset/8 + 1) bytes. Cap it so a
    // huge SETBIT offset can't allocate an enormous backing string.
    if (offset / 8) as usize + 1 > store.config().max_resp_request {
        resp::write_error(out, "ERR bit offset is not an integer or out of range");
        return CmdResult::Written;
    }
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
    if reject_encrypted_bitop(store, args[1], now, out) {
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
    if args.len() >= 2 && reject_encrypted_bitop(store, args[1], now, out) {
        return CmdResult::Written;
    }
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
    if reject_encrypted_bitop(store, args[1], now, out) {
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
    // Refuse if the destination or any source is encrypted: BITOP would either
    // overwrite an encrypted key with a plaintext result or compute over an
    // envelope. Guard before any mutation.
    if reject_encrypted_bitop(store, dest, now, out) {
        return CmdResult::Written;
    }
    for key in &src_keys {
        if reject_encrypted_bitop(store, key, now, out) {
            return CmdResult::Written;
        }
    }
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

const BITFIELD_TYPE_ERR: &str = "ERR Invalid bitfield type. Use something like i16 u8. Note that u64 is not supported but i64 is.";
const BITFIELD_OFFSET_ERR: &str = "ERR bit offset is not an integer or out of range";

fn parse_bitfield_type(arg: &[u8]) -> Result<(bool, u32), String> {
    if arg.is_empty() {
        return Err(BITFIELD_TYPE_ERR.to_string());
    }
    let signed = match arg[0] {
        b'i' | b'I' => true,
        b'u' | b'U' => false,
        _ => return Err(BITFIELD_TYPE_ERR.to_string()),
    };
    let bits: u32 = std::str::from_utf8(&arg[1..])
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| BITFIELD_TYPE_ERR.to_string())?;
    let ok = if signed {
        (1..=64).contains(&bits)
    } else {
        (1..=63).contains(&bits)
    };
    if !ok {
        return Err(BITFIELD_TYPE_ERR.to_string());
    }
    Ok((signed, bits))
}

fn parse_bitfield_offset(arg: &[u8], bits: u32, max_bytes: usize) -> Result<u64, String> {
    let (mult, digits) = match arg.first() {
        Some(b'#') => (true, &arg[1..]),
        _ => (false, arg),
    };
    let n: u64 = std::str::from_utf8(digits)
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| BITFIELD_OFFSET_ERR.to_string())?;
    let offset = if mult {
        n.checked_mul(bits as u64)
            .ok_or_else(|| BITFIELD_OFFSET_ERR.to_string())?
    } else {
        n
    };
    // Cap the implied backing-string size so a huge offset can't drive a giant
    // allocation (mirrors SETBIT).
    let end = offset
        .checked_add(bits as u64)
        .ok_or_else(|| BITFIELD_OFFSET_ERR.to_string())?;
    if (end / 8) as usize + 1 > max_bytes {
        return Err(BITFIELD_OFFSET_ERR.to_string());
    }
    Ok(offset)
}

pub fn cmd_bitfield(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    bitfield_impl(args, store, out, now, false)
}

pub fn cmd_bitfield_ro(
    args: &[&[u8]],
    store: &Store,
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    bitfield_impl(args, store, out, now, true)
}

fn bitfield_impl(
    args: &[&[u8]],
    store: &Store,
    out: &mut BytesMut,
    now: Instant,
    readonly: bool,
) -> CmdResult {
    let name = if readonly { "bitfield_ro" } else { "bitfield" };
    if args.len() < 2 {
        resp::write_error(
            out,
            &format!("ERR wrong number of arguments for '{name}' command"),
        );
        return CmdResult::Written;
    }
    if reject_encrypted_bitop(store, args[1], now, out) {
        return CmdResult::Written;
    }
    let max_bytes = store.config().max_resp_request;
    let mut ops: Vec<BitfieldOp> = Vec::new();
    let mut overflow = BitfieldOverflow::Wrap;
    let mut i = 2;
    macro_rules! bail {
        ($msg:expr) => {{
            resp::write_error(out, $msg);
            return CmdResult::Written;
        }};
    }
    while i < args.len() {
        if cmd_eq(args[i], b"GET") {
            if i + 2 >= args.len() {
                bail!("ERR syntax error");
            }
            let (signed, bits) = match parse_bitfield_type(args[i + 1]) {
                Ok(t) => t,
                Err(e) => bail!(&e),
            };
            let offset = match parse_bitfield_offset(args[i + 2], bits, max_bytes) {
                Ok(o) => o,
                Err(e) => bail!(&e),
            };
            ops.push(BitfieldOp::Get {
                signed,
                bits,
                offset,
            });
            i += 3;
        } else if !readonly && cmd_eq(args[i], b"SET") {
            if i + 3 >= args.len() {
                bail!("ERR syntax error");
            }
            let (signed, bits) = match parse_bitfield_type(args[i + 1]) {
                Ok(t) => t,
                Err(e) => bail!(&e),
            };
            let offset = match parse_bitfield_offset(args[i + 2], bits, max_bytes) {
                Ok(o) => o,
                Err(e) => bail!(&e),
            };
            let value = match parse_i64(args[i + 3]) {
                Ok(v) => v,
                Err(_) => bail!("ERR value is not an integer or out of range"),
            };
            ops.push(BitfieldOp::Set {
                signed,
                bits,
                offset,
                value,
                overflow,
            });
            i += 4;
        } else if !readonly && cmd_eq(args[i], b"INCRBY") {
            if i + 3 >= args.len() {
                bail!("ERR syntax error");
            }
            let (signed, bits) = match parse_bitfield_type(args[i + 1]) {
                Ok(t) => t,
                Err(e) => bail!(&e),
            };
            let offset = match parse_bitfield_offset(args[i + 2], bits, max_bytes) {
                Ok(o) => o,
                Err(e) => bail!(&e),
            };
            let incr = match parse_i64(args[i + 3]) {
                Ok(v) => v,
                Err(_) => bail!("ERR value is not an integer or out of range"),
            };
            ops.push(BitfieldOp::IncrBy {
                signed,
                bits,
                offset,
                incr,
                overflow,
            });
            i += 4;
        } else if !readonly && cmd_eq(args[i], b"OVERFLOW") {
            if i + 1 >= args.len() {
                bail!("ERR syntax error");
            }
            overflow = if cmd_eq(args[i + 1], b"WRAP") {
                BitfieldOverflow::Wrap
            } else if cmd_eq(args[i + 1], b"SAT") {
                BitfieldOverflow::Sat
            } else if cmd_eq(args[i + 1], b"FAIL") {
                BitfieldOverflow::Fail
            } else {
                bail!("ERR Invalid OVERFLOW type specified");
            };
            i += 2;
        } else if readonly {
            bail!("ERR BITFIELD_RO only supports the GET subcommand");
        } else {
            bail!("ERR syntax error");
        }
    }
    match store.bitfield(args[1], &ops, now) {
        Ok(results) => {
            resp::write_array_header(out, results.len());
            for r in &results {
                match r {
                    Some(v) => resp::write_integer(out, *v),
                    None => resp::write_null(out),
                }
            }
        }
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}
