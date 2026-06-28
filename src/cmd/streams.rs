use bytes::{Bytes, BytesMut};
use std::time::{Duration, Instant};

use crate::pubsub::Broker;
use crate::resp;
use crate::store::{Store, StreamId};

use super::{arg_str, cmd_eq, parse_u64, CmdResult};

fn write_stream_entries(out: &mut BytesMut, entries: &[(StreamId, Vec<(String, Bytes)>)]) {
    resp::write_array_header(out, entries.len());
    for (id, fields) in entries {
        resp::write_array_header(out, 2);
        resp::write_bulk(out, &id.to_string());
        resp::write_array_header(out, fields.len() * 2);
        for (k, v) in fields {
            resp::write_bulk(out, k);
            resp::write_bulk_raw(out, v);
        }
    }
}

#[allow(clippy::type_complexity)]
fn write_xread_result(
    out: &mut BytesMut,
    result: &[(String, Vec<(StreamId, Vec<(String, Bytes)>)>)],
) {
    resp::write_array_header(out, result.len());
    for (key, entries) in result {
        resp::write_array_header(out, 2);
        resp::write_bulk(out, key);
        write_stream_entries(out, entries);
    }
}

fn xadd_id_arg_index(args: &[&[u8]]) -> Option<usize> {
    let mut i = 2;
    while i < args.len() {
        if cmd_eq(args[i], b"MAXLEN") || cmd_eq(args[i], b"MINID") {
            i += 1;
            if i < args.len() && args[i] == b"~" {
                i += 1;
            }
            if i < args.len() {
                i += 1;
            }
        } else if cmd_eq(args[i], b"NOMKSTREAM") {
            i += 1;
        } else {
            break;
        }
    }
    (i < args.len()).then_some(i)
}

fn log_resolved_xadd(store: &Store, args: &[&[u8]], id: StreamId, out: &mut BytesMut) -> bool {
    if !store.wal_enabled() {
        return true;
    }
    let Some(id_idx) = xadd_id_arg_index(args) else {
        return true;
    };
    let mut owned: Vec<Vec<u8>> = args.iter().map(|arg| arg.to_vec()).collect();
    owned[id_idx] = id.to_string().into_bytes();
    let refs: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();
    match store.wal_log_command(&refs) {
        Ok(()) => true,
        Err(e) => {
            resp::write_error(out, &format!("ERR WAL append failed: {e}"));
            false
        }
    }
}

pub fn cmd_xadd(
    args: &[&[u8]],
    store: &Store,
    _broker: &Broker,
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    if args.len() < 5 {
        resp::write_error(out, "ERR wrong number of arguments for 'xadd' command");
        return CmdResult::Written;
    }
    let mut i = 2;
    let mut maxlen: Option<usize> = None;
    while i < args.len() {
        if cmd_eq(args[i], b"MAXLEN") {
            i += 1;
            if i < args.len() && args[i] == b"~" {
                i += 1;
            }
            if i < args.len() {
                maxlen = parse_u64(args[i]).ok().map(|n| n as usize);
            }
            i += 1;
        } else if cmd_eq(args[i], b"NOMKSTREAM") {
            i += 1;
        } else {
            break;
        }
    }
    if i >= args.len() {
        resp::write_error(out, "ERR wrong number of arguments for 'xadd' command");
        return CmdResult::Written;
    }
    let id_input = arg_str(args[i]);
    i += 1;
    if (args.len() - i) < 2 || !(args.len() - i).is_multiple_of(2) {
        resp::write_error(out, "ERR wrong number of arguments for 'xadd' command");
        return CmdResult::Written;
    }
    let mut fields = Vec::new();
    while i + 1 < args.len() {
        fields.push((
            arg_str(args[i]).to_string(),
            Bytes::copy_from_slice(args[i + 1]),
        ));
        i += 2;
    }
    match store.xadd(args[1], id_input, fields, maxlen, now) {
        Ok(id) => {
            if !log_resolved_xadd(store, args, id, out) {
                return CmdResult::Written;
            }
            resp::write_bulk(out, &id.to_string());
            _broker.wake_stream_waiters(arg_str(args[1]));
        }
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_xlen(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'xlen' command");
        return CmdResult::Written;
    }
    match store.xlen(args[1], now) {
        Ok(n) => resp::write_integer(out, n),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_xrange(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 4 {
        resp::write_error(out, "ERR wrong number of arguments for 'xrange' command");
        return CmdResult::Written;
    }
    let start = if arg_str(args[2]) == "-" {
        StreamId { ms: 0, seq: 0 }
    } else {
        StreamId::parse(arg_str(args[2])).unwrap_or(StreamId { ms: 0, seq: 0 })
    };
    let end = if arg_str(args[3]) == "+" {
        StreamId {
            ms: u64::MAX,
            seq: u64::MAX,
        }
    } else {
        StreamId::parse(arg_str(args[3])).unwrap_or(StreamId {
            ms: u64::MAX,
            seq: u64::MAX,
        })
    };
    let count = if args.len() > 5 && cmd_eq(args[4], b"COUNT") {
        parse_u64(args[5]).ok().map(|n| n as usize)
    } else {
        None
    };
    match store.xrange(args[1], start, end, count, now) {
        Ok(entries) => write_stream_entries(out, &entries),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_xrevrange(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 4 {
        resp::write_error(out, "ERR wrong number of arguments for 'xrevrange' command");
        return CmdResult::Written;
    }
    let end = if arg_str(args[2]) == "+" {
        StreamId {
            ms: u64::MAX,
            seq: u64::MAX,
        }
    } else {
        StreamId::parse(arg_str(args[2])).unwrap_or(StreamId {
            ms: u64::MAX,
            seq: u64::MAX,
        })
    };
    let start = if arg_str(args[3]) == "-" {
        StreamId { ms: 0, seq: 0 }
    } else {
        StreamId::parse(arg_str(args[3])).unwrap_or(StreamId { ms: 0, seq: 0 })
    };
    let count = if args.len() > 5 && cmd_eq(args[4], b"COUNT") {
        parse_u64(args[5]).ok().map(|n| n as usize)
    } else {
        None
    };
    match store.xrevrange(args[1], end, start, count, now) {
        Ok(entries) => write_stream_entries(out, &entries),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_xread(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 4 {
        resp::write_error(out, "ERR wrong number of arguments for 'xread' command");
        return CmdResult::Written;
    }
    let mut i = 1;
    let mut count: Option<usize> = None;
    let mut block: Option<u64> = None;
    while i < args.len() {
        if cmd_eq(args[i], b"COUNT") && i + 1 < args.len() {
            count = parse_u64(args[i + 1]).ok().map(|n| n as usize);
            i += 2;
        } else if cmd_eq(args[i], b"BLOCK") && i + 1 < args.len() {
            block = parse_u64(args[i + 1]).ok();
            i += 2;
        } else if cmd_eq(args[i], b"STREAMS") {
            i += 1;
            break;
        } else {
            i += 1;
        }
    }
    let remaining = args.len() - i;
    if remaining == 0 || !remaining.is_multiple_of(2) {
        resp::write_error(out, "ERR Unbalanced 'xread' list of streams: for each stream key an ID or '$' must be specified.");
        return CmdResult::Written;
    }
    let half = remaining / 2;
    let keys: Vec<String> = args[i..i + half]
        .iter()
        .map(|k| arg_str(k).to_string())
        .collect();
    let id_strs: Vec<String> = args[i + half..]
        .iter()
        .map(|k| arg_str(k).to_string())
        .collect();

    let ids: Vec<StreamId> = id_strs
        .iter()
        .enumerate()
        .map(|(idx, s)| {
            if s == "$" {
                store
                    .stream_last_id(keys[idx].as_bytes(), now)
                    .unwrap_or(StreamId::zero())
            } else {
                StreamId::parse(s).unwrap_or(StreamId::zero())
            }
        })
        .collect();

    match store.xread(&keys, &ids, count, now) {
        Ok(result) if !result.is_empty() => {
            write_xread_result(out, &result);
        }
        Ok(_) => {
            if let Some(block_ms) = block {
                let timeout = if block_ms == 0 {
                    Duration::from_secs(300)
                } else {
                    Duration::from_millis(block_ms)
                };
                return CmdResult::BlockStreamRead {
                    keys,
                    ids: id_strs,
                    group: None,
                    count,
                    noack: false,
                    timeout,
                };
            }
            resp::write_null_array(out);
        }
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_xgroup(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'xgroup' command");
        return CmdResult::Written;
    }
    if cmd_eq(args[1], b"CREATE") {
        if args.len() < 5 {
            resp::write_error(
                out,
                "ERR wrong number of arguments for 'xgroup|create' command",
            );
            return CmdResult::Written;
        }
        let mkstream = args.len() > 5 && cmd_eq(args[5], b"MKSTREAM");
        match store.xgroup_create(args[2], arg_str(args[3]), arg_str(args[4]), mkstream, now) {
            Ok(()) => resp::write_ok(out),
            Err(e) => resp::write_error(out, &e),
        }
    } else if cmd_eq(args[1], b"DESTROY") {
        if args.len() < 4 {
            resp::write_error(
                out,
                "ERR wrong number of arguments for 'xgroup|destroy' command",
            );
            return CmdResult::Written;
        }
        match store.xgroup_destroy(args[2], arg_str(args[3]), now) {
            Ok(removed) => resp::write_integer(out, if removed { 1 } else { 0 }),
            Err(e) => resp::write_error(out, &e),
        }
    } else if cmd_eq(args[1], b"SETID") {
        if args.len() < 5 {
            resp::write_error(
                out,
                "ERR wrong number of arguments for 'xgroup|setid' command",
            );
            return CmdResult::Written;
        }
        match store.xgroup_setid(args[2], arg_str(args[3]), arg_str(args[4]), now) {
            Ok(()) => resp::write_ok(out),
            Err(e) => resp::write_error(out, &e),
        }
    } else if cmd_eq(args[1], b"CREATECONSUMER") {
        resp::write_integer(out, 1);
    } else if cmd_eq(args[1], b"DELCONSUMER") {
        resp::write_integer(out, 0);
    } else {
        resp::write_error(
            out,
            &format!("ERR unknown subcommand '{}'", arg_str(args[1])),
        );
    }
    CmdResult::Written
}

pub fn cmd_xreadgroup(
    args: &[&[u8]],
    store: &Store,
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    if args.len() < 7 {
        resp::write_error(
            out,
            "ERR wrong number of arguments for 'xreadgroup' command",
        );
        return CmdResult::Written;
    }
    let mut i = 1;
    let mut group_name = "";
    let mut consumer_name = "";
    let mut count: Option<usize> = None;
    let mut block: Option<u64> = None;
    let mut noack = false;
    if cmd_eq(args[i], b"GROUP") && i + 2 < args.len() {
        group_name = arg_str(args[i + 1]);
        consumer_name = arg_str(args[i + 2]);
        i += 3;
    }
    while i < args.len() {
        if cmd_eq(args[i], b"COUNT") && i + 1 < args.len() {
            count = parse_u64(args[i + 1]).ok().map(|n| n as usize);
            i += 2;
        } else if cmd_eq(args[i], b"BLOCK") && i + 1 < args.len() {
            block = parse_u64(args[i + 1]).ok();
            i += 2;
        } else if cmd_eq(args[i], b"NOACK") {
            noack = true;
            i += 1;
        } else if cmd_eq(args[i], b"STREAMS") {
            i += 1;
            break;
        } else {
            i += 1;
        }
    }
    let remaining = args.len() - i;
    if remaining == 0 || !remaining.is_multiple_of(2) {
        resp::write_error(out, "ERR Unbalanced 'xreadgroup' list of streams: for each stream key an ID or '>' must be specified.");
        return CmdResult::Written;
    }
    let half = remaining / 2;
    let keys: Vec<String> = args[i..i + half]
        .iter()
        .map(|k| arg_str(k).to_string())
        .collect();
    let id_strs: Vec<String> = args[i + half..]
        .iter()
        .map(|k| arg_str(k).to_string())
        .collect();

    match store.xreadgroup(
        group_name,
        consumer_name,
        &keys,
        &id_strs,
        count,
        noack,
        now,
    ) {
        Ok(result) => {
            let has_data = result.iter().any(|(_, entries)| !entries.is_empty());
            if has_data || block.is_none() {
                if result.is_empty() && id_strs.iter().all(|s| s == ">") {
                    resp::write_null_array(out);
                } else {
                    write_xread_result(out, &result);
                }
            } else if let Some(block_ms) = block {
                let timeout = if block_ms == 0 {
                    Duration::from_secs(300)
                } else {
                    Duration::from_millis(block_ms)
                };
                return CmdResult::BlockStreamRead {
                    keys,
                    ids: id_strs,
                    group: Some((group_name.to_string(), consumer_name.to_string())),
                    count,
                    noack,
                    timeout,
                };
            }
        }
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_xack(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 4 {
        resp::write_error(out, "ERR wrong number of arguments for 'xack' command");
        return CmdResult::Written;
    }
    let ids: Vec<StreamId> = args[3..]
        .iter()
        .filter_map(|a| StreamId::parse(arg_str(a)))
        .collect();
    match store.xack(args[1], arg_str(args[2]), &ids, now) {
        Ok(n) => resp::write_integer(out, n),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_xpending(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'xpending' command");
        return CmdResult::Written;
    }
    if args.len() == 3 {
        match store.xpending_summary(args[1], arg_str(args[2]), now) {
            Ok((count, min, max, consumers)) => {
                resp::write_array_header(out, 4);
                resp::write_integer(out, count);
                match min {
                    Some(id) => resp::write_bulk(out, &id.to_string()),
                    None => resp::write_null(out),
                }
                match max {
                    Some(id) => resp::write_bulk(out, &id.to_string()),
                    None => resp::write_null(out),
                }
                if consumers.is_empty() {
                    resp::write_null_array(out);
                } else {
                    resp::write_array_header(out, consumers.len());
                    for (name, cnt) in &consumers {
                        resp::write_array_header(out, 2);
                        resp::write_bulk(out, name);
                        resp::write_bulk(out, &cnt.to_string());
                    }
                }
            }
            Err(e) => resp::write_error(out, &e),
        }
    } else {
        let mut i = 3;
        let mut consumer_filter: Option<&str> = None;
        if cmd_eq(args[i], b"IDLE") && i + 1 < args.len() {
            i += 2;
        }
        let start = if i < args.len() {
            if arg_str(args[i]) == "-" {
                StreamId::zero()
            } else {
                StreamId::parse(arg_str(args[i])).unwrap_or(StreamId::zero())
            }
        } else {
            StreamId::zero()
        };
        i += 1;
        let end = if i < args.len() {
            if arg_str(args[i]) == "+" {
                StreamId {
                    ms: u64::MAX,
                    seq: u64::MAX,
                }
            } else {
                StreamId::parse(arg_str(args[i])).unwrap_or(StreamId {
                    ms: u64::MAX,
                    seq: u64::MAX,
                })
            }
        } else {
            StreamId {
                ms: u64::MAX,
                seq: u64::MAX,
            }
        };
        i += 1;
        let count_val = if i < args.len() {
            parse_u64(args[i]).unwrap_or(10) as usize
        } else {
            10
        };
        i += 1;
        if i < args.len() {
            consumer_filter = Some(arg_str(args[i]));
        }
        match store.xpending_range(
            args[1],
            arg_str(args[2]),
            start,
            end,
            count_val,
            consumer_filter,
            now,
        ) {
            Ok(entries) => {
                resp::write_array_header(out, entries.len());
                for (id, consumer, idle, count) in &entries {
                    resp::write_array_header(out, 4);
                    resp::write_bulk(out, &id.to_string());
                    resp::write_bulk(out, consumer);
                    resp::write_integer(out, *idle as i64);
                    resp::write_integer(out, *count as i64);
                }
            }
            Err(e) => resp::write_error(out, &e),
        }
    }
    CmdResult::Written
}

pub fn cmd_xclaim(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 6 {
        resp::write_error(out, "ERR wrong number of arguments for 'xclaim' command");
        return CmdResult::Written;
    }
    let min_idle = parse_u64(args[4]).unwrap_or(0);
    let ids: Vec<StreamId> = args[5..]
        .iter()
        .filter_map(|a| StreamId::parse(arg_str(a)))
        .collect();
    match store.xclaim(
        args[1],
        arg_str(args[2]),
        arg_str(args[3]),
        min_idle,
        &ids,
        now,
    ) {
        Ok(entries) => write_stream_entries(out, &entries),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_xautoclaim(
    args: &[&[u8]],
    store: &Store,
    out: &mut BytesMut,
    now: Instant,
) -> CmdResult {
    if args.len() < 6 {
        resp::write_error(
            out,
            "ERR wrong number of arguments for 'xautoclaim' command",
        );
        return CmdResult::Written;
    }
    let min_idle = parse_u64(args[4]).unwrap_or(0);
    let start = StreamId::parse(arg_str(args[5])).unwrap_or(StreamId::zero());
    let count = if args.len() > 7 && cmd_eq(args[6], b"COUNT") {
        parse_u64(args[7]).ok().map(|n| n as usize)
    } else {
        None
    };
    match store.xautoclaim(
        args[1],
        arg_str(args[2]),
        arg_str(args[3]),
        min_idle,
        start,
        count,
        now,
    ) {
        Ok((next_start, entries, deleted)) => {
            resp::write_array_header(out, 3);
            resp::write_bulk(out, &next_start.to_string());
            write_stream_entries(out, &entries);
            resp::write_array_header(out, deleted.len());
            for id in &deleted {
                resp::write_bulk(out, &id.to_string());
            }
        }
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_xdel(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'xdel' command");
        return CmdResult::Written;
    }
    let ids: Vec<StreamId> = args[2..]
        .iter()
        .filter_map(|a| StreamId::parse(arg_str(a)))
        .collect();
    match store.xdel(args[1], &ids, now) {
        Ok(n) => resp::write_integer(out, n),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_xtrim(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 4 {
        resp::write_error(out, "ERR wrong number of arguments for 'xtrim' command");
        return CmdResult::Written;
    }
    let mut i = 2;
    if cmd_eq(args[i], b"MAXLEN") {
        i += 1;
    }
    if i < args.len() && args[i] == b"~" {
        i += 1;
    }
    let maxlen = if i < args.len() {
        parse_u64(args[i]).unwrap_or(0) as usize
    } else {
        0
    };
    match store.xtrim(args[1], maxlen, now) {
        Ok(n) => resp::write_integer(out, n),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_xinfo(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 3 {
        resp::write_error(out, "ERR wrong number of arguments for 'xinfo' command");
        return CmdResult::Written;
    }
    if cmd_eq(args[1], b"STREAM") {
        match store.xinfo_stream(args[2], now) {
            Ok(info) => {
                resp::write_array_header(out, info.len() * 2);
                for (k, v) in &info {
                    resp::write_bulk(out, k);
                    resp::write_bulk(out, v);
                }
            }
            Err(e) => resp::write_error(out, &e),
        }
    } else if cmd_eq(args[1], b"GROUPS") {
        match store.xinfo_groups(args[2], now) {
            Ok(groups) => {
                resp::write_array_header(out, groups.len());
                for group_info in &groups {
                    resp::write_array_header(out, group_info.len() * 2);
                    for (k, v) in group_info {
                        resp::write_bulk(out, k);
                        resp::write_bulk(out, v);
                    }
                }
            }
            Err(e) => resp::write_error(out, &e),
        }
    } else {
        resp::write_error(
            out,
            &format!("ERR unknown subcommand '{}'", arg_str(args[1])),
        );
    }
    CmdResult::Written
}
