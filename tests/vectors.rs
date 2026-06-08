use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::process::{Child, Command};
use std::time::Duration;

fn start_server(port: u16) -> Child {
    let mut child = Command::new(env!("CARGO_BIN_EXE_lux"))
        .env("LUX_PORT", port.to_string())
        .env("LUX_SAVE_INTERVAL", "0")
        .env("LUX_DATA_DIR", format!("/tmp/lux-test-{}", port))
        .spawn()
        .expect("failed to start lux");
    for _ in 0..100 {
        if TcpStream::connect(format!("127.0.0.1:{port}")).is_ok() {
            return child;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("lux did not start within 5 seconds on port {port}");
}

fn send(stream: &mut TcpStream, args: &[&str]) -> String {
    let mut cmd = format!("*{}\r\n", args.len());
    for a in args {
        cmd.push_str(&format!("${}\r\n{}\r\n", a.len(), a));
    }
    stream.write_all(cmd.as_bytes()).unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    read_response(&mut reader)
}

fn read_response(reader: &mut BufReader<TcpStream>) -> String {
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let line = line.trim_end().to_string();

    if line.starts_with('+') || line.starts_with('-') || line.starts_with(':') {
        return line;
    }
    if let Some(rest) = line.strip_prefix('$') {
        let len: i64 = rest.parse().unwrap();
        if len < 0 {
            return "$-1".to_string();
        }
        let mut buf = vec![0u8; (len + 2) as usize];
        reader.read_exact(&mut buf).expect("read bulk");
        let s = String::from_utf8_lossy(&buf[..len as usize]).to_string();
        return format!("${}", s);
    }
    if let Some(rest) = line.strip_prefix('*') {
        let count: i64 = rest.parse().unwrap();
        if count < 0 {
            return "*-1".to_string();
        }
        let mut items = Vec::new();
        for _ in 0..count {
            items.push(read_response(reader));
        }
        return format!("*{} [{}]", count, items.join(", "));
    }
    line
}

use std::io::Read as IoRead;

#[test]
fn vset_and_vget_basic() {
    let port = 16400;
    let mut child = start_server(port);
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    let r = send(&mut s, &["VSET", "myvec", "3", "1.0", "0.5", "0.25"]);
    assert_eq!(r, "+OK");

    let r = send(&mut s, &["VGET", "myvec"]);
    assert!(r.starts_with("*"), "expected array: {}", r);
    assert!(
        r.contains("$3") || r.contains(":3"),
        "expected dim=3: {}",
        r
    );

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn vset_with_metadata() {
    let port = 16401;
    let mut child = start_server(port);
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    let r = send(
        &mut s,
        &[
            "VSET",
            "v1",
            "2",
            "1.0",
            "0.0",
            "META",
            r#"{"type":"test"}"#,
        ],
    );
    assert_eq!(r, "+OK");

    let r = send(&mut s, &["VGET", "v1"]);
    assert!(r.contains("test"), "expected metadata: {}", r);

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn vset_with_ttl() {
    let port = 16402;
    let mut child = start_server(port);
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    let r = send(&mut s, &["VSET", "expire_me", "2", "1.0", "0.0", "EX", "1"]);
    assert_eq!(r, "+OK");

    let r = send(&mut s, &["VGET", "expire_me"]);
    assert!(r.starts_with("*"), "should exist: {}", r);

    std::thread::sleep(Duration::from_millis(1500));

    let r = send(&mut s, &["VGET", "expire_me"]);
    assert!(r.contains("-1"), "should be expired: {}", r);

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn vcard_counts_vectors() {
    let port = 16403;
    let mut child = start_server(port);
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    let r = send(&mut s, &["VCARD"]);
    assert_eq!(r, ":0");

    send(&mut s, &["VSET", "a", "2", "1.0", "0.0"]);
    send(&mut s, &["VSET", "b", "2", "0.0", "1.0"]);
    send(&mut s, &["VSET", "c", "2", "1.0", "1.0"]);

    let r = send(&mut s, &["VCARD"]);
    assert_eq!(r, ":3");

    send(&mut s, &["DEL", "b"]);
    let r = send(&mut s, &["VCARD"]);
    assert_eq!(r, ":2");

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn vsearch_returns_nearest() {
    let port = 16404;
    let mut child = start_server(port);
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    send(&mut s, &["VSET", "x_axis", "3", "1.0", "0.0", "0.0"]);
    send(&mut s, &["VSET", "y_axis", "3", "0.0", "1.0", "0.0"]);
    send(&mut s, &["VSET", "near_x", "3", "0.9", "0.1", "0.0"]);
    send(&mut s, &["VSET", "diagonal", "3", "0.707", "0.707", "0.0"]);

    let r = send(&mut s, &["VSEARCH", "3", "1.0", "0.0", "0.0", "K", "2"]);
    assert!(r.contains("x_axis"), "x_axis should be first: {}", r);
    assert!(r.contains("near_x"), "near_x should be second: {}", r);
    assert!(
        !r.contains("y_axis"),
        "y_axis should not be in top 2: {}",
        r
    );

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn vsearch_with_metadata_filter() {
    let port = 16405;
    let mut child = start_server(port);
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    send(
        &mut s,
        &[
            "VSET",
            "cat1",
            "2",
            "1.0",
            "0.0",
            "META",
            r#"{"animal":"cat"}"#,
        ],
    );
    send(
        &mut s,
        &[
            "VSET",
            "dog1",
            "2",
            "0.9",
            "0.1",
            "META",
            r#"{"animal":"dog"}"#,
        ],
    );
    send(
        &mut s,
        &[
            "VSET",
            "cat2",
            "2",
            "0.8",
            "0.2",
            "META",
            r#"{"animal":"cat"}"#,
        ],
    );

    let r = send(
        &mut s,
        &[
            "VSEARCH", "2", "1.0", "0.0", "K", "10", "FILTER", "animal", "cat",
        ],
    );
    assert!(r.contains("cat1"), "should find cat1: {}", r);
    assert!(r.contains("cat2"), "should find cat2: {}", r);
    assert!(!r.contains("dog1"), "should not find dog1: {}", r);

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn vsearch_filter_finds_match_beyond_unfiltered_top_k_window() {
    let port = 16410;
    let mut child = start_server(port);
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    for i in 0..25 {
        let x = format!("1.{}", i);
        let y = format!("0.{}", i);
        send(
            &mut s,
            &[
                "VSET",
                &format!("dog:{i}"),
                "2",
                &x,
                &y,
                "META",
                r#"{"animal":"dog"}"#,
            ],
        );
    }
    send(
        &mut s,
        &[
            "VSET",
            "cat:far",
            "2",
            "0.0",
            "1.0",
            "META",
            r#"{"animal":"cat"}"#,
        ],
    );

    let r = send(
        &mut s,
        &[
            "VSEARCH", "2", "1.0", "0.0", "K", "1", "FILTER", "animal", "cat",
        ],
    );
    assert!(r.contains("cat:far"), "filtered result was missed: {r}");

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn vsearch_with_meta_flag() {
    let port = 16406;
    let mut child = start_server(port);
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    send(
        &mut s,
        &[
            "VSET",
            "v1",
            "2",
            "1.0",
            "0.0",
            "META",
            r#"{"name":"hello"}"#,
        ],
    );

    let r = send(&mut s, &["VSEARCH", "2", "1.0", "0.0", "K", "1", "META"]);
    assert!(
        r.contains("hello"),
        "META flag should include metadata: {}",
        r
    );

    let r = send(&mut s, &["VSEARCH", "2", "1.0", "0.0", "K", "1"]);
    assert!(!r.contains("hello"), "without META, no metadata: {}", r);

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn vset_dimension_mismatch() {
    let port = 16407;
    let mut child = start_server(port);
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    let r = send(&mut s, &["VSET", "bad", "3", "1.0", "0.0"]);
    assert!(r.starts_with("-"), "should error on dim mismatch: {}", r);

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn vset_overwrites_existing() {
    let port = 16408;
    let mut child = start_server(port);
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    send(&mut s, &["VSET", "v", "2", "1.0", "0.0"]);
    send(&mut s, &["VSET", "v", "2", "0.0", "1.0"]);

    let r = send(&mut s, &["VCARD"]);
    assert_eq!(r, ":1", "overwrite should not create duplicate");

    let r = send(&mut s, &["VSEARCH", "2", "0.0", "1.0", "K", "1"]);
    assert!(r.contains("v"), "should find updated vector");

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn vector_type_command() {
    let port = 16409;
    let mut child = start_server(port);
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    send(&mut s, &["VSET", "typed", "2", "1.0", "0.0"]);
    let r = send(&mut s, &["TYPE", "typed"]);
    assert_eq!(r, "+vector");

    child.kill().ok();
    child.wait().ok();
}
