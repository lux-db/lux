use bytes::BytesMut;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::resp;
use crate::store::Store;

use super::{arg_str, cmd_eq, parse_i64, CmdResult};

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

pub fn cmd_tsadd(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 4 {
        resp::write_error(out, "ERR wrong number of arguments for 'tsadd' command");
        return CmdResult::Written;
    }
    let key = args[1];
    let timestamp = if args[2] == b"*" {
        now_ms()
    } else {
        match parse_i64(args[2]) {
            Ok(t) => t,
            Err(_) => {
                resp::write_error(out, "ERR invalid timestamp");
                return CmdResult::Written;
            }
        }
    };
    let value: f64 = match arg_str(args[3]).parse() {
        Ok(v) => v,
        Err(_) => {
            resp::write_error(out, "ERR value is not a valid float");
            return CmdResult::Written;
        }
    };

    let mut retention = None;
    let mut labels = None;
    let mut i = 4;
    while i < args.len() {
        if cmd_eq(args[i], b"RETENTION") && i + 1 < args.len() {
            retention = Some(parse_i64(args[i + 1]).unwrap_or(0) as u64);
            i += 2;
        } else if cmd_eq(args[i], b"LABELS") {
            let mut lbls = Vec::new();
            i += 1;
            while i + 1 < args.len() && !cmd_eq(args[i], b"RETENTION") {
                lbls.push((
                    arg_str(args[i]).to_string(),
                    arg_str(args[i + 1]).to_string(),
                ));
                i += 2;
            }
            labels = Some(lbls);
        } else {
            resp::write_error(out, "ERR syntax error");
            return CmdResult::Written;
        }
    }

    let mut journal_args: Vec<Vec<u8>> = args.iter().map(|arg| arg.to_vec()).collect();
    journal_args[2] = timestamp.to_string().into_bytes();
    let refs: Vec<&[u8]> = journal_args.iter().map(Vec::as_slice).collect();
    let _commit = match store.begin_journaled(&refs) {
        Ok(commit) => commit,
        Err(e) => {
            resp::write_error(out, &format!("ERR WAL append failed: {e}"));
            return CmdResult::Written;
        }
    };
    match store.tsadd(key, timestamp, value, retention, labels, now) {
        Ok(ts) => {
            resp::write_integer(out, ts);
        }
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_tsmadd(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 4 || !(args.len() - 1).is_multiple_of(3) {
        resp::write_error(out, "ERR wrong number of arguments for 'tsmadd' command");
        return CmdResult::Written;
    }
    let count = (args.len() - 1) / 3;
    let mut resolved = Vec::with_capacity(count);
    let mut journal_commands = Vec::with_capacity(count);
    let mut i = 1;
    while i + 2 < args.len() {
        let timestamp = if args[i + 1] == b"*" {
            now_ms()
        } else {
            parse_i64(args[i + 1]).unwrap_or(0)
        };
        let value: f64 = arg_str(args[i + 2]).parse().unwrap_or(0.0);
        journal_commands.push(vec![
            b"TSADD".to_vec(),
            args[i].to_vec(),
            timestamp.to_string().into_bytes(),
            args[i + 2].to_vec(),
        ]);
        resolved.push((args[i], timestamp, value));
        i += 3;
    }
    let argv_refs: Vec<Vec<&[u8]>> = journal_commands
        .iter()
        .map(|command| command.iter().map(Vec::as_slice).collect())
        .collect();
    let command_refs: Vec<&[&[u8]]> = argv_refs.iter().map(Vec::as_slice).collect();
    let _commit = match store.begin_journaled_batch(&command_refs) {
        Ok(commit) => commit,
        Err(e) => {
            resp::write_error(out, &format!("ERR WAL append failed: {e}"));
            return CmdResult::Written;
        }
    };
    resp::write_array_header(out, count);
    for (key, timestamp, value) in resolved {
        match store.tsadd(key, timestamp, value, None, None, now) {
            Ok(ts) => resp::write_integer(out, ts),
            Err(e) => resp::write_error(out, &e),
        }
    }
    CmdResult::Written
}

pub fn cmd_tsget(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() != 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'tsget' command");
        return CmdResult::Written;
    }
    match store.tsget(args[1], now) {
        Ok(Some((ts, val))) => {
            resp::write_array_header(out, 2);
            resp::write_integer(out, ts);
            resp::write_bulk(out, &format!("{val}"));
        }
        Ok(None) => resp::write_null_array(out),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_tsrange(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 4 {
        resp::write_error(out, "ERR wrong number of arguments for 'tsrange' command");
        return CmdResult::Written;
    }
    let key = args[1];
    let from = if args[2] == b"-" {
        i64::MIN
    } else {
        parse_i64(args[2]).unwrap_or(0)
    };
    let to = if args[3] == b"+" {
        i64::MAX
    } else {
        parse_i64(args[3]).unwrap_or(i64::MAX)
    };

    let mut agg_fn = None;
    let mut agg_bucket = 0i64;
    let mut count = None;
    let mut i = 4;
    while i < args.len() {
        if cmd_eq(args[i], b"AGGREGATION") && i + 2 < args.len() {
            agg_fn = Some(arg_str(args[i + 1]).to_lowercase());
            agg_bucket = parse_i64(args[i + 2]).unwrap_or(0);
            i += 3;
        } else if cmd_eq(args[i], b"COUNT") && i + 1 < args.len() {
            count = Some(parse_i64(args[i + 1]).unwrap_or(0) as usize);
            i += 2;
        } else {
            i += 1;
        }
    }

    let agg = agg_fn.as_deref().map(|f| (f, agg_bucket));
    match store.tsrange(key, from, to, agg, count, now) {
        Ok(samples) => {
            resp::write_array_header(out, samples.len());
            for (ts, val) in &samples {
                resp::write_array_header(out, 2);
                resp::write_integer(out, *ts);
                resp::write_bulk(out, &format!("{val}"));
            }
        }
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}

pub fn cmd_tsmrange(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 5 {
        resp::write_error(out, "ERR wrong number of arguments for 'tsmrange' command");
        return CmdResult::Written;
    }
    let from = if args[1] == b"-" {
        i64::MIN
    } else {
        parse_i64(args[1]).unwrap_or(0)
    };
    let to = if args[2] == b"+" {
        i64::MAX
    } else {
        parse_i64(args[2]).unwrap_or(i64::MAX)
    };

    let mut filters = Vec::new();
    let mut agg_fn = None;
    let mut agg_bucket = 0i64;
    let mut i = 3;
    while i < args.len() {
        if cmd_eq(args[i], b"FILTER") {
            i += 1;
            while i < args.len()
                && !cmd_eq(args[i], b"AGGREGATION")
                && !cmd_eq(args[i], b"WITHLABELS")
            {
                let s = arg_str(args[i]);
                if let Some(eq) = s.find('=') {
                    filters.push((s[..eq].to_string(), s[eq + 1..].to_string()));
                }
                i += 1;
            }
        } else if cmd_eq(args[i], b"AGGREGATION") && i + 2 < args.len() {
            agg_fn = Some(arg_str(args[i + 1]).to_lowercase());
            agg_bucket = parse_i64(args[i + 2]).unwrap_or(0);
            i += 3;
        } else {
            i += 1;
        }
    }

    let agg = agg_fn.as_deref().map(|f| (f, agg_bucket));
    let results = store.tsmrange(from, to, &filters, agg, now);
    resp::write_array_header(out, results.len());
    for (key, labels, samples) in &results {
        resp::write_array_header(out, 3);
        resp::write_bulk(out, key);
        resp::write_array_header(out, labels.len());
        for (lk, lv) in labels {
            resp::write_array_header(out, 2);
            resp::write_bulk(out, lk);
            resp::write_bulk(out, lv);
        }
        resp::write_array_header(out, samples.len());
        for (ts, val) in samples {
            resp::write_array_header(out, 2);
            resp::write_integer(out, *ts);
            resp::write_bulk(out, &format!("{val}"));
        }
    }
    CmdResult::Written
}

pub fn cmd_tsinfo(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() != 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'tsinfo' command");
        return CmdResult::Written;
    }
    match store.tsinfo(args[1], now) {
        Ok(Some((count, first, last, retention, labels))) => {
            let field_count = 4 + if !labels.is_empty() { 1 } else { 0 };
            resp::write_array_header(out, field_count * 2);
            resp::write_bulk(out, "totalSamples");
            resp::write_integer(out, count as i64);
            resp::write_bulk(out, "firstTimestamp");
            resp::write_integer(out, first.map(|s| s.0).unwrap_or(0));
            resp::write_bulk(out, "lastTimestamp");
            resp::write_integer(out, last.map(|s| s.0).unwrap_or(0));
            resp::write_bulk(out, "retentionTime");
            resp::write_integer(out, retention as i64);
            if !labels.is_empty() {
                resp::write_bulk(out, "labels");
                resp::write_array_header(out, labels.len());
                for (k, v) in &labels {
                    resp::write_array_header(out, 2);
                    resp::write_bulk(out, k);
                    resp::write_bulk(out, v);
                }
            }
        }
        Ok(None) => resp::write_error(out, "ERR TSDB: the key does not exist"),
        Err(e) => resp::write_error(out, &e),
    }
    CmdResult::Written
}
