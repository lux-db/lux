use bytes::{Bytes, BytesMut};
use std::time::Instant;

use crate::pubsub::Broker;
use crate::resp;
use crate::store::Store;

use super::{arg_str, cmd_eq, CmdResult};

/// PUBSUB CHANNELS [pattern] | NUMSUB [channel ...] | NUMPAT | HELP.
pub fn cmd_pubsub(args: &[&[u8]], broker: &Broker, out: &mut BytesMut) -> CmdResult {
    if args.len() < 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'pubsub' command");
        return CmdResult::Written;
    }
    if cmd_eq(args[1], b"CHANNELS") {
        let pattern = if args.len() >= 3 {
            Some(arg_str(args[2]))
        } else {
            None
        };
        let channels = broker.pubsub_channels(pattern);
        resp::write_array_header(out, channels.len());
        for ch in &channels {
            resp::write_bulk(out, ch);
        }
    } else if cmd_eq(args[1], b"NUMSUB") {
        let chans = &args[2..];
        resp::write_array_header(out, chans.len() * 2);
        for ch in chans {
            resp::write_bulk_raw(out, ch);
            resp::write_integer(out, broker.pubsub_numsub(arg_str(ch)));
        }
    } else if cmd_eq(args[1], b"NUMPAT") {
        resp::write_integer(out, broker.pubsub_numpat());
    } else if cmd_eq(args[1], b"HELP") {
        let help = [
            "PUBSUB CHANNELS [<pattern>]",
            "    Return the currently active channels matching a <pattern> (default: all).",
            "PUBSUB NUMSUB [<channel> ...]",
            "    Return the number of subscribers for the specified channels (excluding patterns).",
            "PUBSUB NUMPAT",
            "    Return the number of subscriptions to patterns.",
            "PUBSUB HELP",
            "    Print this help.",
        ];
        resp::write_array_header(out, help.len());
        for line in help {
            resp::write_bulk(out, line);
        }
    } else {
        resp::write_error(
            out,
            &format!(
                "ERR Unknown PUBSUB subcommand or wrong number of arguments for '{}'",
                arg_str(args[1])
            ),
        );
    }
    CmdResult::Written
}

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
