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

/// Persist a TSADD to the WAL with the RESOLVED timestamp, so a server-generated
/// `*` timestamp stays stable across a WAL-only crash recovery (otherwise replay
/// re-runs `*` against the recovery-time clock and produces a different sample).
/// `args[2]` is the timestamp slot. Returns false (and writes the error) on WAL
/// failure; the caller must stop.
fn log_resolved_tsadd(store: &Store, args: &[&[u8]], ts: i64, out: &mut BytesMut) -> bool {
    if !store.wal_enabled() {
        return true;
    }
    let mut owned: Vec<Vec<u8>> = args.iter().map(|arg| arg.to_vec()).collect();
    owned[2] = ts.to_string().into_bytes();
    let refs: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();
    match store.wal_log_command(&refs) {
        Ok(()) => true,
        Err(e) => {
            resp::write_error(out, &format!("ERR WAL append failed: {e}"));
            false
        }
    }
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

    match store.tsadd(key, timestamp, value, retention, labels, now) {
        Ok(ts) => {
            if !log_resolved_tsadd(store, args, ts, out) {
                return CmdResult::Written;
            }
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
    resp::write_array_header(out, count);
    let mut i = 1;
    while i + 2 < args.len() {
        let key = args[i];
        let timestamp = if args[i + 1] == b"*" {
            now_ms()
        } else {
            parse_i64(args[i + 1]).unwrap_or(0)
        };
        let value: f64 = arg_str(args[i + 2]).parse().unwrap_or(0.0);
        match store.tsadd(key, timestamp, value, None, None, now) {
            Ok(ts) => {
                // Self-log each sample with its RESOLVED timestamp (see
                // log_resolved_tsadd) so `*` samples survive WAL replay unchanged.
                if store.wal_enabled() {
                    let ts_s = ts.to_string();
                    let entry: [&[u8]; 4] = [b"TSADD", key, ts_s.as_bytes(), args[i + 2]];
                    if let Err(e) = store.wal_log_command(&entry) {
                        resp::write_error(out, &format!("ERR WAL append failed: {e}"));
                        i += 3;
                        continue;
                    }
                }
                resp::write_integer(out, ts);
            }
            Err(e) => resp::write_error(out, &e),
        }
        i += 3;
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
