mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

fn resp_cmd(args: &[&str]) -> Vec<u8> {
    let mut buf = format!("*{}\r\n", args.len());
    for arg in args {
        buf.push_str(&format!("${}\r\n{}\r\n", arg.len(), arg));
    }
    buf.into_bytes()
}

fn read_all(stream: &mut TcpStream) -> String {
    let mut data = Vec::with_capacity(4096);
    let mut buf = [0u8; 8192];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(len) => data.extend_from_slice(&buf[..len]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&data).to_string()
}

fn send(stream: &mut TcpStream, args: &[&str]) -> String {
    stream.write_all(&resp_cmd(args)).unwrap();
    thread::sleep(Duration::from_millis(50));
    read_all(stream)
}

fn assert_has(resp: &str, needle: &str) {
    assert!(resp.contains(needle), "missing {needle:?}: {resp}");
}

fn assert_error(resp: &str) {
    assert!(resp.starts_with("-ERR"), "expected error, got: {resp}");
}

struct LuxServer {
    child: std::process::Child,
    tmpdir: std::path::PathBuf,
}

impl Drop for LuxServer {
    fn drop(&mut self) {
        common::terminate_child(&mut self.child);
        let _ = std::fs::remove_dir_all(&self.tmpdir);
    }
}

fn start_lux(port: u16) -> LuxServer {
    let tmpdir = std::env::temp_dir().join(format!(
        "lux_keystrings_test_{}_{}",
        std::process::id(),
        port
    ));
    std::fs::create_dir_all(&tmpdir).unwrap();
    let child = common::lux_command(env!("CARGO_BIN_EXE_lux"))
        .env("LUX_PORT", port.to_string())
        .env("LUX_SHARDS", "4")
        .env("LUX_SAVE_INTERVAL", "0")
        .env("LUX_DATA_DIR", tmpdir.to_str().unwrap())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("failed to start lux");

    let server = LuxServer { child, tmpdir };
    for _ in 0..40 {
        if TcpStream::connect(format!("127.0.0.1:{port}")).is_ok() {
            return server;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("lux did not start on port {port}");
}

fn connect(port: u16) -> TcpStream {
    let stream = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    stream.set_nodelay(true).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    stream
}

#[test]
fn string_command_surface() {
    let port = 17830;
    let _server = start_lux(port);
    let mut conn = connect(port);

    assert_has(&send(&mut conn, &["SET", "s", "hello"]), "+OK");
    assert_has(&send(&mut conn, &["GET", "s"]), "hello");
    assert_has(&send(&mut conn, &["APPEND", "s", "-world"]), ":11");
    assert_has(&send(&mut conn, &["STRLEN", "s"]), ":11");
    assert_has(&send(&mut conn, &["GETRANGE", "s", "0", "4"]), "hello");
    assert_has(&send(&mut conn, &["SETRANGE", "s", "6", "Lux"]), ":11");
    assert_has(&send(&mut conn, &["GET", "s"]), "hello-Luxld");
    assert_has(&send(&mut conn, &["GETSET", "s", "old"]), "hello-Luxld");
    assert_has(&send(&mut conn, &["GETDEL", "s"]), "old");
    assert_has(&send(&mut conn, &["GET", "s"]), "$-1");

    assert_has(&send(&mut conn, &["MSET", "a", "1", "b", "2"]), "+OK");
    assert_has(&send(&mut conn, &["MGET", "a", "b", "missing"]), "*3");
    assert_has(&send(&mut conn, &["MSETNX", "a", "x", "c", "3"]), ":0");
    assert_has(&send(&mut conn, &["MSETNX", "c", "3", "d", "4"]), ":1");
}

#[test]
fn numeric_string_commands_and_set_options() {
    let port = 17831;
    let _server = start_lux(port);
    let mut conn = connect(port);

    assert_has(&send(&mut conn, &["INCR", "n"]), ":1");
    assert_has(&send(&mut conn, &["INCRBY", "n", "9"]), ":10");
    assert_has(&send(&mut conn, &["DECR", "n"]), ":9");
    assert_has(&send(&mut conn, &["DECRBY", "n", "4"]), ":5");
    assert_has(&send(&mut conn, &["INCRBYFLOAT", "f", "1.25"]), "1.25");

    assert_has(&send(&mut conn, &["SET", "nx", "first", "NX"]), "+OK");
    assert_has(&send(&mut conn, &["SET", "nx", "second", "NX"]), "$-1");
    assert_has(&send(&mut conn, &["SET", "nx", "second", "XX"]), "+OK");
    assert_has(&send(&mut conn, &["GET", "nx"]), "second");

    assert_has(&send(&mut conn, &["SETEX", "ttl:s", "10", "v"]), "+OK");
    assert_has(&send(&mut conn, &["PSETEX", "ttl:p", "10000", "v"]), "+OK");
    assert_has(&send(&mut conn, &["GETEX", "ttl:s", "PERSIST"]), "v");
}

#[test]
fn string_commands_reject_invalid_arguments_without_mutating_state() {
    let port = 17834;
    let _server = start_lux(port);
    let mut conn = connect(port);

    assert_has(&send(&mut conn, &["SET", "s", "hello"]), "+OK");
    assert_error(&send(&mut conn, &["GETRANGE", "s", "nope", "1"]));
    assert_error(&send(&mut conn, &["GETRANGE", "s", "0", "nope"]));
    assert_error(&send(&mut conn, &["SETRANGE", "s", "nope", "X"]));
    assert_error(&send(
        &mut conn,
        &["SETRANGE", "s", "18446744073709551615", "X"],
    ));
    assert_has(&send(&mut conn, &["GET", "s"]), "hello");

    assert_has(&send(&mut conn, &["SET", "ttl", "original"]), "+OK");
    for cmd in [
        vec!["SET", "ttl", "replacement", "EX", "nope"],
        vec!["SET", "ttl", "replacement", "EX", "0"],
        vec!["SET", "ttl", "replacement", "PX", "nope"],
        vec!["SET", "ttl", "replacement", "PX", "0"],
        vec!["GETEX", "ttl", "EX", "nope"],
        vec!["GETEX", "ttl", "EX", "0"],
        vec!["GETEX", "ttl", "PX", "nope"],
        vec!["GETEX", "ttl", "PERSIST", "EX", "10"],
        vec!["GETEX", "ttl", "EX", "10", "PX", "10"],
    ] {
        assert_error(&send(&mut conn, &cmd));
    }
    assert_has(&send(&mut conn, &["GET", "ttl"]), "original");
    assert_has(&send(&mut conn, &["TTL", "ttl"]), ":-1");

    assert_has(&send(&mut conn, &["SET", "psetex", "keep"]), "+OK");
    assert_error(&send(&mut conn, &["PSETEX", "psetex", "0", "new"]));
    assert_error(&send(&mut conn, &["PSETEX", "psetex", "nope", "new"]));
    assert_has(&send(&mut conn, &["GET", "psetex"]), "keep");
}

#[test]
fn key_command_surface() {
    let port = 17832;
    let _server = start_lux(port);
    let mut conn = connect(port);

    send(&mut conn, &["SET", "k1", "v1"]);
    send(&mut conn, &["SET", "k2", "v2"]);
    send(&mut conn, &["LPUSH", "list", "a"]);

    assert_has(&send(&mut conn, &["EXISTS", "k1", "missing"]), ":1");
    assert_has(&send(&mut conn, &["TYPE", "list"]), "list");
    assert_has(&send(&mut conn, &["KEYS", "k*"]), "k1");
    assert_has(
        &send(&mut conn, &["SCAN", "0", "MATCH", "k*", "COUNT", "10"]),
        "*2",
    );
    assert_has(&send(&mut conn, &["RANDOMKEY"]), "$");
    assert_has(&send(&mut conn, &["OBJECT", "ENCODING", "k1"]), "embstr");
    assert_has(&send(&mut conn, &["MEMORY", "USAGE", "k1"]), ":");

    assert_has(&send(&mut conn, &["COPY", "k1", "k3"]), ":1");
    assert_has(&send(&mut conn, &["GET", "k3"]), "v1");
    assert_has(&send(&mut conn, &["RENAME", "k3", "renamed"]), "+OK");
    assert_has(&send(&mut conn, &["RENAMENX", "renamed", "k1"]), ":0");
    assert_has(&send(&mut conn, &["RENAMENX", "renamed", "fresh"]), ":1");
    assert_has(&send(&mut conn, &["DEL", "fresh", "missing"]), ":1");
    assert_has(&send(&mut conn, &["UNLINK", "k2"]), ":1");
}

#[test]
fn scan_rejects_invalid_cursor_and_options() {
    let port = 17835;
    let _server = start_lux(port);
    let mut conn = connect(port);

    send(&mut conn, &["SET", "k1", "v1"]);
    send(&mut conn, &["SET", "k2", "v2"]);

    for cmd in [
        vec!["SCAN", "nope"],
        vec!["SCAN", "0", "COUNT", "nope"],
        vec!["SCAN", "0", "COUNT", "0"],
        vec!["SCAN", "0", "UNKNOWN"],
    ] {
        assert_error(&send(&mut conn, &cmd));
    }

    assert_has(
        &send(&mut conn, &["SCAN", "0", "MATCH", "k*", "COUNT", "10"]),
        "*2",
    );
}

#[test]
fn expire_ttl_and_persist_surface() {
    let port = 17833;
    let _server = start_lux(port);
    let mut conn = connect(port);

    send(&mut conn, &["SET", "exp", "v"]);
    assert_has(&send(&mut conn, &["EXPIRE", "exp", "10"]), ":1");
    assert_has(&send(&mut conn, &["TTL", "exp"]), ":");
    assert_has(&send(&mut conn, &["PTTL", "exp"]), ":");
    assert_has(&send(&mut conn, &["EXPIRETIME", "exp"]), ":");
    assert_has(&send(&mut conn, &["PEXPIRETIME", "exp"]), ":");
    assert_has(&send(&mut conn, &["PERSIST", "exp"]), ":1");
    assert_has(&send(&mut conn, &["TTL", "exp"]), ":-1");
    assert_has(&send(&mut conn, &["PEXPIRE", "exp", "10000"]), ":1");
    assert_has(
        &send(&mut conn, &["PEXPIREAT", "exp", "9999999999999"]),
        ":1",
    );
    assert_has(&send(&mut conn, &["EXPIREAT", "exp", "9999999999"]), ":1");
}
