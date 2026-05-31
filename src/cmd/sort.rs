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

pub fn cmd_sort(args: &[&[u8]], store: &Store, out: &mut BytesMut, now: Instant) -> CmdResult {
    let readonly = cmd_eq(args[0], b"SORT_RO");
    if args.len() < 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'sort' command");
        return CmdResult::Written;
    }
    let key = args[1];
    let mut by: Option<String> = None;
    let mut get_patterns: Vec<String> = Vec::new();
    let mut desc = false;
    let mut alpha = false;
    let mut limit_offset: i64 = 0;
    let mut limit_count: i64 = -1;
    let mut store_key: Option<&[u8]> = None;

    let mut i = 2;
    while i < args.len() {
        if cmd_eq(args[i], b"BY") {
            if i + 1 >= args.len() {
                resp::write_error(out, "ERR syntax error");
                return CmdResult::Written;
            }
            by = Some(arg_str(args[i + 1]).to_string());
            i += 2;
        } else if cmd_eq(args[i], b"GET") {
            if i + 1 >= args.len() {
                resp::write_error(out, "ERR syntax error");
                return CmdResult::Written;
            }
            get_patterns.push(arg_str(args[i + 1]).to_string());
            i += 2;
        } else if cmd_eq(args[i], b"LIMIT") {
            if i + 2 >= args.len() {
                resp::write_error(out, "ERR syntax error");
                return CmdResult::Written;
            }
            limit_offset = match parse_i64_arg(args[i + 1], out) {
                Some(offset) if offset >= 0 => offset,
                Some(_) => {
                    resp::write_error(out, INTEGER_ERR);
                    return CmdResult::Written;
                }
                None => return CmdResult::Written,
            };
            limit_count = match parse_i64_arg(args[i + 2], out) {
                Some(count) if count >= 0 => count,
                Some(_) => {
                    resp::write_error(out, INTEGER_ERR);
                    return CmdResult::Written;
                }
                None => return CmdResult::Written,
            };
            i += 3;
        } else if cmd_eq(args[i], b"ASC") {
            desc = false;
            i += 1;
        } else if cmd_eq(args[i], b"DESC") {
            desc = true;
            i += 1;
        } else if cmd_eq(args[i], b"ALPHA") {
            alpha = true;
            i += 1;
        } else if cmd_eq(args[i], b"STORE") {
            if readonly {
                resp::write_error(out, "ERR syntax error");
                return CmdResult::Written;
            }
            if i + 1 >= args.len() {
                resp::write_error(out, "ERR syntax error");
                return CmdResult::Written;
            }
            store_key = Some(args[i + 1]);
            i += 2;
        } else {
            resp::write_error(out, "ERR syntax error");
            return CmdResult::Written;
        }
    }

    let elements = match store.sort_get_elements(key, now) {
        Ok(elems) => elems,
        Err(e) => {
            resp::write_error(out, &e);
            return CmdResult::Written;
        }
    };

    let by_constant = by.as_ref().is_some_and(|p| !p.contains('*'));
    let nosort = by.as_deref() == Some("nosort") || (by_constant && !alpha);
    let by_effective = if by_constant { None } else { by.clone() };

    let mut items: Vec<(String, f64, String)> = Vec::with_capacity(elements.len());
    for elem in &elements {
        let sort_key = if nosort {
            0.0
        } else if let Some(ref pat) = by_effective {
            let lookup_key = pat.replace('*', elem);
            if let Some(arrow) = lookup_key.find("->") {
                let hkey = &lookup_key[..arrow];
                let field = &lookup_key[arrow + 2..];
                match store.hget(hkey.as_bytes(), field.as_bytes(), now) {
                    Some(v) => {
                        let s = std::str::from_utf8(&v).unwrap_or("");
                        match s.parse::<f64>() {
                            Ok(f) => f,
                            Err(_) if !alpha => {
                                resp::write_error(
                                    out,
                                    "ERR One or more scores can't be converted into double",
                                );
                                return CmdResult::Written;
                            }
                            Err(_) => 0.0,
                        }
                    }
                    None => 0.0,
                }
            } else {
                match store.get(lookup_key.as_bytes(), now) {
                    Some(v) => {
                        let s = std::str::from_utf8(&v).unwrap_or("");
                        match s.parse::<f64>() {
                            Ok(f) => f,
                            Err(_) if !alpha => {
                                resp::write_error(
                                    out,
                                    "ERR One or more scores can't be converted into double",
                                );
                                return CmdResult::Written;
                            }
                            Err(_) => 0.0,
                        }
                    }
                    None => 0.0,
                }
            }
        } else if alpha {
            0.0
        } else {
            match elem.parse::<f64>() {
                Ok(v) => v,
                Err(_) => {
                    resp::write_error(out, "ERR One or more scores can't be converted into double");
                    return CmdResult::Written;
                }
            }
        };
        items.push((elem.clone(), sort_key, elem.clone()));
    }

    if nosort && desc {
        items.reverse();
    } else if !nosort {
        if alpha {
            if let Some(ref pat) = by_effective {
                items.sort_by(|a, b| {
                    let ak = lookup_sort_string(store, pat, &a.0, now);
                    let bk = lookup_sort_string(store, pat, &b.0, now);
                    if desc {
                        bk.cmp(&ak)
                    } else {
                        ak.cmp(&bk)
                    }
                });
            } else {
                items.sort_by(|a, b| if desc { b.0.cmp(&a.0) } else { a.0.cmp(&b.0) });
            }
        } else {
            items.sort_by(|a, b| {
                let cmp = a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal);
                if desc {
                    cmp.reverse()
                } else {
                    cmp
                }
            });
            if !desc {
                let mut j = 0;
                while j < items.len() {
                    let mut k = j + 1;
                    while k < items.len() && items[k].1 == items[j].1 {
                        k += 1;
                    }
                    if k - j > 1 {
                        items[j..k].sort_by(|a, b| a.0.cmp(&b.0));
                    }
                    j = k;
                }
            }
        }
    }

    let start = if limit_offset < 0 {
        0usize
    } else {
        (limit_offset as usize).min(items.len())
    };
    let count = if limit_count < 0 {
        items.len()
    } else {
        limit_count as usize
    };
    let end = (start + count).min(items.len());
    let sliced = &items[start..end];

    if get_patterns.is_empty() {
        if let Some(sk) = store_key {
            let values: Vec<String> = sliced.iter().map(|(e, _, _)| e.clone()).collect();
            store.sort_store(sk, &values, now);
            resp::write_integer(out, values.len() as i64);
        } else {
            resp::write_array_header(out, sliced.len());
            for (elem, _, _) in sliced {
                resp::write_bulk(out, elem);
            }
        }
    } else {
        let result_count = sliced.len() * get_patterns.len();
        if let Some(sk) = store_key {
            let mut values: Vec<String> = Vec::with_capacity(result_count);
            for (elem, _, _) in sliced {
                for pat in &get_patterns {
                    values.push(resolve_get(store, pat, elem, now));
                }
            }
            store.sort_store(sk, &values, now);
            resp::write_integer(out, values.len() as i64);
        } else {
            resp::write_array_header(out, result_count);
            for (elem, _, _) in sliced {
                for pat in &get_patterns {
                    let val = resolve_get(store, pat, elem, now);
                    if val.is_empty() {
                        resp::write_null(out);
                    } else {
                        resp::write_bulk(out, &val);
                    }
                }
            }
        }
    }
    CmdResult::Written
}

fn resolve_get(store: &Store, pattern: &str, elem: &str, now: Instant) -> String {
    if pattern == "#" {
        return elem.to_string();
    }
    let lookup_key = pattern.replace('*', elem);
    if let Some(arrow) = lookup_key.find("->") {
        let field = &lookup_key[arrow + 2..];
        if !field.is_empty() {
            let hkey = &lookup_key[..arrow];
            return store
                .hget(hkey.as_bytes(), field.as_bytes(), now)
                .map(|v| String::from_utf8_lossy(&v).into_owned())
                .unwrap_or_default();
        }
    }
    store
        .get(lookup_key.as_bytes(), now)
        .map(|v| String::from_utf8_lossy(&v).into_owned())
        .unwrap_or_default()
}

fn lookup_sort_string(store: &Store, pattern: &str, elem: &str, now: Instant) -> String {
    let lookup_key = pattern.replace('*', elem);
    if let Some(arrow) = lookup_key.find("->") {
        let hkey = &lookup_key[..arrow];
        let field = &lookup_key[arrow + 2..];
        store
            .hget(hkey.as_bytes(), field.as_bytes(), now)
            .map(|v| String::from_utf8_lossy(&v).into_owned())
            .unwrap_or_default()
    } else {
        store
            .get(lookup_key.as_bytes(), now)
            .map(|v| String::from_utf8_lossy(&v).into_owned())
            .unwrap_or_default()
    }
}
