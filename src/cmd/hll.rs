use bytes::BytesMut;
use std::time::Instant;

use crate::resp;
use crate::store::Store;

use super::CmdResult;

pub fn cmd_pfadd(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'pfadd' command");
        return CmdResult::Written;
    }
    let key = args[1];
    match store.pfadd(key, &args[2..], now) {
        Ok(changed) => resp::write_integer(out, changed),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_pfcount(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'pfcount' command");
        return CmdResult::Written;
    }
    match store.pfcount(&args[1..], now) {
        Ok(count) => resp::write_integer(out, count),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_pfmerge(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'pfmerge' command");
        return CmdResult::Written;
    }
    let dest = args[1];
    match store.pfmerge(dest, &args[2..], now) {
        Ok(()) => resp::write_ok(out),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}
