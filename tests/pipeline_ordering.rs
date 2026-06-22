mod common;
use common::LuxServer;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn resp_cmd(args: &[&str]) -> Vec<u8> {
    let mut buf = format!("*{}\r\n", args.len());
    for arg in args {
        buf.push_str(&format!("${}\r\n{}\r\n", arg.len(), arg));
    }
    buf.into_bytes()
}

fn read_n_responses(stream: &mut TcpStream, n: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(4096);
    let mut buf = [0u8; 8192];
    loop {
        let count = count_complete_responses(&data);
        if count >= n {
            return data;
        }
        match stream.read(&mut buf) {
            Ok(0) => return data,
            Ok(len) => data.extend_from_slice(&buf[..len]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return data,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => return data,
            Err(_) => return data,
        }
    }
}

fn count_complete_responses(data: &[u8]) -> usize {
    let mut count = 0;
    let mut i = 0;
    while i < data.len() {
        match data[i] {
            b'+' | b'-' | b':' => match memchr(b'\n', &data[i..]) {
                Some(pos) => {
                    i += pos + 1;
                    count += 1;
                }
                None => return count,
            },
            b'$' => match memchr(b'\n', &data[i..]) {
                Some(pos) => {
                    let len_bytes = &data[i + 1..i + pos - 1];
                    if let Ok(s) = std::str::from_utf8(len_bytes) {
                        if let Ok(len) = s.parse::<i64>() {
                            i += pos + 1;
                            if len < 0 {
                                count += 1;
                            } else {
                                let end = i + len as usize + 2;
                                if end > data.len() {
                                    return count;
                                }
                                i = end;
                                count += 1;
                            }
                        } else {
                            return count;
                        }
                    } else {
                        return count;
                    }
                }
                None => return count,
            },
            _ => {
                i += 1;
            }
        }
    }
    count
}

fn memchr(needle: u8, haystack: &[u8]) -> Option<usize> {
    haystack.iter().position(|&b| b == needle)
}

fn extract_two_bulk_integers(data: &[u8]) -> Option<(i64, i64)> {
    let mut vals = Vec::with_capacity(2);
    let mut i = 0;
    while i < data.len() && vals.len() < 2 {
        if data[i] == b'$' {
            if let Some(nl) = memchr(b'\n', &data[i..]) {
                let len_str = std::str::from_utf8(&data[i + 1..i + nl - 1]).ok()?;
                let len: i64 = len_str.parse().ok()?;
                i += nl + 1;
                if len < 0 {
                    return None;
                }
                let end = i + len as usize;
                if end > data.len() {
                    return None;
                }
                let val_str = std::str::from_utf8(&data[i..end]).ok()?;
                vals.push(val_str.parse::<i64>().ok()?);
                i = end + 2;
            } else {
                return None;
            }
        } else {
            i += 1;
        }
    }
    if vals.len() == 2 {
        Some((vals[0], vals[1]))
    } else {
        None
    }
}

fn extract_bulk_strings(data: &[u8]) -> Vec<String> {
    let mut vals = Vec::new();
    let mut i = 0;
    while i < data.len() {
        if data[i] != b'$' {
            i += 1;
            continue;
        }
        let Some(nl) = memchr(b'\n', &data[i..]) else {
            break;
        };
        let Ok(len_str) = std::str::from_utf8(&data[i + 1..i + nl - 1]) else {
            break;
        };
        let Ok(len) = len_str.parse::<i64>() else {
            break;
        };
        i += nl + 1;
        if len < 0 {
            vals.push(String::new());
            continue;
        }
        let end = i + len as usize;
        if end > data.len() {
            break;
        }
        vals.push(String::from_utf8_lossy(&data[i..end]).into_owned());
        i = end + 2;
    }
    vals
}

#[test]
fn pipeline_set_ordering_simple_path() {
    let iterations: i64 = 10_000;
    let num_readers = 4;

    let server = LuxServer::builder().shards(2).start();
    let addr = format!("127.0.0.1:{}", server.port());

    {
        let mut conn = TcpStream::connect(&addr).unwrap();
        conn.set_nodelay(true).unwrap();
        conn.write_all(&resp_cmd(&["SET", "a", "0"])).unwrap();
        conn.write_all(&resp_cmd(&["SET", "b", "0"])).unwrap();
        read_n_responses(&mut conn, 2);
    }

    let stop = Arc::new(AtomicBool::new(false));
    let violations = Arc::new(AtomicUsize::new(0));
    let samples = Arc::new(AtomicUsize::new(0));
    let max_a_seen = Arc::new(AtomicI64::new(0));

    let readers: Vec<_> = (0..num_readers)
        .map(|_| {
            let addr = addr.clone();
            let stop = stop.clone();
            let violations = violations.clone();
            let samples = samples.clone();
            let max_a = max_a_seen.clone();
            thread::spawn(move || {
                let mut conn = TcpStream::connect(&addr).unwrap();
                conn.set_nodelay(true).unwrap();
                conn.set_read_timeout(Some(Duration::from_millis(50))).ok();
                let pipeline = {
                    let mut p = resp_cmd(&["GET", "a"]);
                    p.extend_from_slice(&resp_cmd(&["GET", "b"]));
                    p
                };
                while !stop.load(Ordering::Relaxed) {
                    if conn.write_all(&pipeline).is_err() {
                        break;
                    }
                    let data = read_n_responses(&mut conn, 2);
                    if let Some((a, b)) = extract_two_bulk_integers(&data) {
                        samples.fetch_add(1, Ordering::Relaxed);
                        max_a.fetch_max(a, Ordering::Relaxed);
                        if a > b {
                            violations.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            })
        })
        .collect();

    thread::sleep(Duration::from_millis(50));

    {
        let mut conn = TcpStream::connect(&addr).unwrap();
        conn.set_nodelay(true).unwrap();
        for i in 1..=iterations {
            let is = i.to_string();
            let mut pipeline = resp_cmd(&["SET", "b", &is]);
            pipeline.extend_from_slice(&resp_cmd(&["SET", "a", &is]));
            conn.write_all(&pipeline).unwrap();
            read_n_responses(&mut conn, 2);
        }
    }

    stop.store(true, Ordering::Relaxed);
    for r in readers {
        let _ = r.join();
    }

    let v = violations.load(Ordering::Relaxed);
    let s = samples.load(Ordering::Relaxed);
    let max = max_a_seen.load(Ordering::Relaxed);

    assert!(
        s >= 100,
        "readers only took {s} samples - test is not meaningful (need >= 100)"
    );
    assert!(
        max > 0,
        "readers never saw a > 0 - writer may not have overlapped with readers"
    );
    assert_eq!(
        v, 0,
        "FAIL: pipeline ordering violated {v} times in {s} samples \
         (writer did {iterations} iterations, readers saw max a={max})"
    );
    eprintln!("pipeline_set_ordering_simple_path: {s} samples, max a={max}, 0 violations");
}

#[test]
fn pipeline_mixed_commands_ordering() {
    let iterations: i64 = 10_000;
    let num_readers = 4;

    let server = LuxServer::builder().shards(2).start();
    let addr = format!("127.0.0.1:{}", server.port());

    {
        let mut conn = TcpStream::connect(&addr).unwrap();
        conn.set_nodelay(true).unwrap();
        conn.write_all(&resp_cmd(&["SET", "x", "0"])).unwrap();
        conn.write_all(&resp_cmd(&["SET", "y", "0"])).unwrap();
        read_n_responses(&mut conn, 2);
    }

    let stop = Arc::new(AtomicBool::new(false));
    let violations = Arc::new(AtomicUsize::new(0));
    let samples = Arc::new(AtomicUsize::new(0));
    let max_x_seen = Arc::new(AtomicI64::new(0));

    let readers: Vec<_> = (0..num_readers)
        .map(|_| {
            let addr = addr.clone();
            let stop = stop.clone();
            let violations = violations.clone();
            let samples = samples.clone();
            let max_x = max_x_seen.clone();
            thread::spawn(move || {
                let mut conn = TcpStream::connect(&addr).unwrap();
                conn.set_nodelay(true).unwrap();
                conn.set_read_timeout(Some(Duration::from_millis(50))).ok();
                let pipeline = {
                    let mut p = resp_cmd(&["GET", "x"]);
                    p.extend_from_slice(&resp_cmd(&["GET", "y"]));
                    p
                };
                while !stop.load(Ordering::Relaxed) {
                    if conn.write_all(&pipeline).is_err() {
                        break;
                    }
                    let data = read_n_responses(&mut conn, 2);
                    if let Some((x, y)) = extract_two_bulk_integers(&data) {
                        samples.fetch_add(1, Ordering::Relaxed);
                        max_x.fetch_max(x, Ordering::Relaxed);
                        if x > y {
                            violations.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            })
        })
        .collect();

    thread::sleep(Duration::from_millis(50));

    {
        let mut conn = TcpStream::connect(&addr).unwrap();
        conn.set_nodelay(true).unwrap();
        for i in 1..=iterations {
            let is = i.to_string();
            let mut pipeline = resp_cmd(&["SET", "y", &is]);
            pipeline.extend_from_slice(&resp_cmd(&["SETEX", "x", "3600", &is]));
            conn.write_all(&pipeline).unwrap();
            read_n_responses(&mut conn, 2);
        }
    }

    stop.store(true, Ordering::Relaxed);
    for r in readers {
        let _ = r.join();
    }

    let v = violations.load(Ordering::Relaxed);
    let s = samples.load(Ordering::Relaxed);
    let max = max_x_seen.load(Ordering::Relaxed);

    assert!(
        s >= 100,
        "readers only took {s} samples - test is not meaningful (need >= 100)"
    );
    assert!(
        max > 0,
        "readers never saw x > 0 - writer may not have overlapped with readers"
    );
    assert_eq!(
        v, 0,
        "FAIL: mixed pipeline ordering violated {v} times in {s} samples \
         (writer did {iterations} iterations, readers saw max x={max})"
    );
    eprintln!("pipeline_mixed_commands_ordering: {s} samples, max x={max}, 0 violations");
}

#[test]
fn pipeline_high_contention_ordering() {
    let num_writers = 4;
    let iterations_per_writer: i64 = 5_000;

    let server = LuxServer::builder().shards(2).start();
    let addr = format!("127.0.0.1:{}", server.port());

    for i in 0..num_writers {
        let mut conn = TcpStream::connect(&addr).unwrap();
        let ka = format!("w{i}a");
        let kb = format!("w{i}b");
        conn.write_all(&resp_cmd(&["SET", &ka, "0"])).unwrap();
        conn.write_all(&resp_cmd(&["SET", &kb, "0"])).unwrap();
        read_n_responses(&mut conn, 2);
    }

    let stop = Arc::new(AtomicBool::new(false));
    let total_violations = Arc::new(AtomicUsize::new(0));
    let total_samples = Arc::new(AtomicUsize::new(0));

    let readers: Vec<_> = (0..num_writers)
        .map(|w| {
            let addr = addr.clone();
            let stop = stop.clone();
            let violations = total_violations.clone();
            let samples = total_samples.clone();
            thread::spawn(move || {
                let mut conn = TcpStream::connect(&addr).unwrap();
                conn.set_nodelay(true).unwrap();
                conn.set_read_timeout(Some(Duration::from_millis(50))).ok();
                let ka = format!("w{w}a");
                let kb = format!("w{w}b");
                let pipeline = {
                    let mut p = resp_cmd(&["GET", &ka]);
                    p.extend_from_slice(&resp_cmd(&["GET", &kb]));
                    p
                };
                while !stop.load(Ordering::Relaxed) {
                    if conn.write_all(&pipeline).is_err() {
                        break;
                    }
                    let data = read_n_responses(&mut conn, 2);
                    if let Some((a, b)) = extract_two_bulk_integers(&data) {
                        samples.fetch_add(1, Ordering::Relaxed);
                        if a > b {
                            violations.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            })
        })
        .collect();

    thread::sleep(Duration::from_millis(50));

    let writers: Vec<_> = (0..num_writers)
        .map(|w| {
            let addr = addr.clone();
            thread::spawn(move || {
                let mut conn = TcpStream::connect(&addr).unwrap();
                conn.set_nodelay(true).unwrap();
                let ka = format!("w{w}a");
                let kb = format!("w{w}b");
                for i in 1..=iterations_per_writer {
                    let is = i.to_string();
                    let mut pipeline = resp_cmd(&["SET", &kb, &is]);
                    pipeline.extend_from_slice(&resp_cmd(&["SET", &ka, &is]));
                    conn.write_all(&pipeline).unwrap();
                    read_n_responses(&mut conn, 2);
                }
            })
        })
        .collect();

    for w in writers {
        w.join().unwrap();
    }

    stop.store(true, Ordering::Relaxed);
    for r in readers {
        let _ = r.join();
    }

    let v = total_violations.load(Ordering::Relaxed);
    let s = total_samples.load(Ordering::Relaxed);

    assert!(
        s >= 100,
        "readers only took {s} samples across {num_writers} pairs"
    );
    assert_eq!(
        v, 0,
        "FAIL: high contention ordering violated {v} times in {s} samples \
         ({num_writers} writer/reader pairs, {iterations_per_writer} iterations each)"
    );
    eprintln!(
        "pipeline_high_contention_ordering: {s} samples across {num_writers} pairs, 0 violations"
    );
}

#[test]
fn large_memory_pipeline_preserves_response_order() {
    let commands = 160usize;

    let server = LuxServer::builder().shards(16).start();
    let addr = format!("127.0.0.1:{}", server.port());
    let mut conn = TcpStream::connect(&addr).unwrap();
    conn.set_nodelay(true).unwrap();

    let mut writes = Vec::new();
    for i in 0..commands {
        let key = format!("scatter:{i}");
        let value = format!("value:{i}");
        writes.extend_from_slice(&resp_cmd(&["SET", &key, &value]));
    }
    conn.write_all(&writes).unwrap();
    let write_response = read_n_responses(&mut conn, commands);
    assert_eq!(count_complete_responses(&write_response), commands);

    let mut reads = Vec::new();
    let expected: Vec<String> = (0..commands).rev().map(|i| format!("value:{i}")).collect();
    for i in (0..commands).rev() {
        let key = format!("scatter:{i}");
        reads.extend_from_slice(&resp_cmd(&["GET", &key]));
    }
    conn.write_all(&reads).unwrap();
    let read_response = read_n_responses(&mut conn, commands);
    let values = extract_bulk_strings(&read_response);

    assert_eq!(values, expected);
}
