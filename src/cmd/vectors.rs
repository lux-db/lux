use bytes::BytesMut;
use std::time::{Duration, Instant};

use crate::resp;
use crate::store::Store;

use super::{arg_str, cmd_eq, parse_u64, CmdResult};

fn parse_f32(arg: &[u8]) -> Result<f32, ()> {
    arg_str(arg).parse::<f32>().map_err(|_| ())
}

fn epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

pub fn cmd_vset(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 4 {
        resp::write_error(out, "ERR wrong number of arguments for 'vset' command");
        return CmdResult::Written;
    }
    let key = args[1];
    let dims = match parse_u64(args[2]) {
        Ok(d) if d > 0 => d as usize,
        _ => {
            resp::write_error(out, "ERR invalid dimension count");
            return CmdResult::Written;
        }
    };
    if args.len() < 3 + dims {
        resp::write_error(out, "ERR not enough float values for specified dimensions");
        return CmdResult::Written;
    }
    let mut data = Vec::with_capacity(dims);
    for i in 0..dims {
        match parse_f32(args[3 + i]) {
            Ok(f) => data.push(f),
            Err(_) => {
                resp::write_error(out, "ERR value is not a valid float");
                return CmdResult::Written;
            }
        }
    }
    let mut i = 3 + dims;
    let mut metadata = None;
    let mut ttl = None;
    let mut expires_at_ms = None;
    let mut encrypted = false;
    while i < args.len() {
        if cmd_eq(args[i], b"ENCRYPTED") {
            encrypted = true;
            i += 1;
        } else if cmd_eq(args[i], b"META") {
            if i + 1 >= args.len() {
                resp::write_error(out, "ERR syntax error");
                return CmdResult::Written;
            }
            metadata = Some(arg_str(args[i + 1]).to_string());
            i += 2;
        } else if cmd_eq(args[i], b"EX") {
            if i + 1 >= args.len() {
                resp::write_error(out, "ERR syntax error");
                return CmdResult::Written;
            }
            match parse_u64(args[i + 1]) {
                Ok(s) => {
                    ttl = Some(Duration::from_secs(s));
                    expires_at_ms = ttl.map(|duration| {
                        epoch_ms()
                            .saturating_add(u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
                    });
                }
                Err(_) => {
                    resp::write_error(out, "ERR value is not an integer or out of range");
                    return CmdResult::Written;
                }
            }
            i += 2;
        } else if cmd_eq(args[i], b"PX") {
            if i + 1 >= args.len() {
                resp::write_error(out, "ERR syntax error");
                return CmdResult::Written;
            }
            match parse_u64(args[i + 1]) {
                Ok(ms) => {
                    ttl = Some(Duration::from_millis(ms));
                    expires_at_ms = Some(epoch_ms().saturating_add(ms));
                }
                Err(_) => {
                    resp::write_error(out, "ERR value is not an integer or out of range");
                    return CmdResult::Written;
                }
            }
            i += 2;
        } else if cmd_eq(args[i], b"PXAT") {
            if i + 1 >= args.len() {
                resp::write_error(out, "ERR syntax error");
                return CmdResult::Written;
            }
            match parse_u64(args[i + 1]) {
                Ok(deadline) => {
                    ttl = Some(Duration::from_millis(deadline.saturating_sub(epoch_ms())));
                    expires_at_ms = Some(deadline);
                }
                Err(_) => {
                    resp::write_error(out, "ERR value is not an integer or out of range");
                    return CmdResult::Written;
                }
            }
            i += 2;
        } else {
            resp::write_error(out, "ERR syntax error");
            return CmdResult::Written;
        }
    }
    // Encrypted vectors keep plaintext in RAM but journal the sealed payload as
    // ENC RAWVSET so the journal carries no plaintext f32.
    let sealed = if encrypted {
        match store.encrypt_vector(key, &data) {
            Ok(c) => Some(c),
            Err(e) => {
                resp::write_error(out, &e);
                return CmdResult::Written;
            }
        }
    } else {
        None
    };
    let mut journal_args = if let Some(ct) = sealed {
        vec![b"ENC".to_vec(), b"RAWVSET".to_vec(), key.to_vec(), ct]
    } else {
        let mut command = Vec::with_capacity(3 + dims + 4);
        command.push(b"VSET".to_vec());
        command.push(key.to_vec());
        command.push(args[2].to_vec());
        command.extend(args[3..3 + dims].iter().map(|arg| arg.to_vec()));
        command
    };
    if let Some(m) = &metadata {
        journal_args.push(b"META".to_vec());
        journal_args.push(m.as_bytes().to_vec());
    }
    if let Some(deadline) = expires_at_ms {
        journal_args.push(b"PXAT".to_vec());
        journal_args.push(deadline.to_string().into_bytes());
    }
    let refs: Vec<&[u8]> = journal_args.iter().map(Vec::as_slice).collect();
    let _commit = match store.begin_journaled(&refs) {
        Ok(commit) => commit,
        Err(e) => {
            resp::write_error(out, &format!("ERR WAL append failed: {e}"));
            return CmdResult::Written;
        }
    };
    store.vset(key, data, metadata, ttl, encrypted, now);
    resp::write_ok(out);
    CmdResult::Written
}

pub fn cmd_vget(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() != 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'vget' command");
        return CmdResult::Written;
    }
    match store.vget(args[1], now) {
        Some((data, metadata)) => {
            let meta_count = 1;
            resp::write_array_header(out, 1 + data.len() + meta_count);
            resp::write_integer(out, data.len() as i64);
            for f in &data {
                resp::write_bulk(out, &format!("{}", f));
            }
            match metadata {
                Some(m) => resp::write_bulk(out, &m),
                None => resp::write_null(out),
            }
        }
        None => resp::write_null(out),
    }
    CmdResult::Written
}

pub fn cmd_vsearch(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() < 4 {
        resp::write_error(out, "ERR wrong number of arguments for 'vsearch' command");
        return CmdResult::Written;
    }
    let dims = match parse_u64(args[1]) {
        Ok(d) if d > 0 => d as usize,
        _ => {
            resp::write_error(out, "ERR invalid dimension count");
            return CmdResult::Written;
        }
    };
    if args.len() < 2 + dims {
        resp::write_error(out, "ERR not enough float values for specified dimensions");
        return CmdResult::Written;
    }
    let mut query = Vec::with_capacity(dims);
    for i in 0..dims {
        match parse_f32(args[2 + i]) {
            Ok(f) => query.push(f),
            Err(_) => {
                resp::write_error(out, "ERR value is not a valid float");
                return CmdResult::Written;
            }
        }
    }
    let mut i = 2 + dims;
    let mut filter_key = None;
    let mut filter_value = None;
    let mut include_meta = false;
    if i >= args.len() || !cmd_eq(args[i], b"K") {
        resp::write_error(out, "ERR missing K parameter");
        return CmdResult::Written;
    }
    i += 1;
    if i >= args.len() {
        resp::write_error(out, "ERR missing K value");
        return CmdResult::Written;
    }
    let k: usize = match parse_u64(args[i]) {
        Ok(val) if val > 0 => val as usize,
        _ => {
            resp::write_error(out, "ERR invalid K value");
            return CmdResult::Written;
        }
    };
    i += 1;
    while i < args.len() {
        if cmd_eq(args[i], b"FILTER") {
            if i + 2 >= args.len() {
                resp::write_error(out, "ERR FILTER requires key and value arguments");
                return CmdResult::Written;
            }
            filter_key = Some(arg_str(args[i + 1]).to_string());
            filter_value = Some(arg_str(args[i + 2]).to_string());
            i += 3;
        } else if cmd_eq(args[i], b"META") {
            include_meta = true;
            i += 1;
        } else {
            resp::write_error(out, "ERR syntax error");
            return CmdResult::Written;
        }
    }
    let results = store.vsearch(
        &query,
        k,
        filter_key.as_deref(),
        filter_value.as_deref(),
        now,
    );
    resp::write_array_header(out, results.len());
    for (key, score, metadata) in &results {
        if include_meta {
            resp::write_array_header(out, 3);
        } else {
            resp::write_array_header(out, 2);
        }
        resp::write_bulk(out, key);
        resp::write_bulk(out, &format!("{}", score));
        if include_meta {
            match metadata {
                Some(m) => resp::write_bulk(out, m),
                None => resp::write_null(out),
            }
        }
    }
    CmdResult::Written
}

pub fn cmd_vcard(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    if args.len() != 1 {
        resp::write_error(out, "ERR wrong number of arguments for 'vcard' command");
        return CmdResult::Written;
    }
    let _ = args;
    resp::write_integer(out, store.vcard(now) as i64);
    CmdResult::Written
}
