use bytes::{Bytes, BytesMut};
use std::time::Instant;

use crate::resp;
use crate::store::Store;

use super::{arg_str, CmdResult};

pub fn cmd_publish(args: &[&[u8]], _store: &Store, out: &mut BytesMut, _now: Instant) -> CmdResult {
    if args.len() < 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'publish' command");
        return CmdResult::Written;
    }
    CmdResult::Publish {
        channel: arg_str(args[1]).to_string(),
        message: Bytes::copy_from_slice(args[2]),
    }
}

pub fn cmd_subscribe(
    args: &[&[u8]],
    _store: &Store,
    out: &mut BytesMut,
    _now: Instant,
) -> CmdResult {
    if args.len() < 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'subscribe' command");
        return CmdResult::Written;
    }
    CmdResult::Subscribe {
        channels: args[1..].iter().map(|a| arg_str(a).to_string()).collect(),
    }
}

pub fn cmd_unsubscribe(
    _args: &[&[u8]],
    _store: &Store,
    out: &mut BytesMut,
    _now: Instant,
) -> CmdResult {
    resp::write_ok(out);
    CmdResult::Written
}

pub fn cmd_psubscribe(
    args: &[&[u8]],
    _store: &Store,
    out: &mut BytesMut,
    _now: Instant,
) -> CmdResult {
    if args.len() < 2 {
        resp::write_error(
            out,
            "ERR wrong number of arguments for 'psubscribe' command",
        );
        return CmdResult::Written;
    }
    CmdResult::PSubscribe {
        patterns: args[1..].iter().map(|a| arg_str(a).to_string()).collect(),
    }
}

pub fn cmd_punsubscribe(
    _args: &[&[u8]],
    _store: &Store,
    out: &mut BytesMut,
    _now: Instant,
) -> CmdResult {
    resp::write_ok(out);
    CmdResult::Written
}

pub fn cmd_ksub(args: &[&[u8]], _store: &Store, out: &mut BytesMut, _now: Instant) -> CmdResult {
    if args.len() < 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'ksub' command");
        return CmdResult::Written;
    }
    CmdResult::KSubscribe {
        patterns: args[1..].iter().map(|a| arg_str(a).to_string()).collect(),
    }
}

pub fn cmd_kunsub(args: &[&[u8]], _store: &Store, _out: &mut BytesMut, _now: Instant) -> CmdResult {
    if args.len() < 2 {
        return CmdResult::KUnsubscribe {
            patterns: Vec::new(),
        };
    }
    CmdResult::KUnsubscribe {
        patterns: args[1..].iter().map(|a| arg_str(a).to_string()).collect(),
    }
}
