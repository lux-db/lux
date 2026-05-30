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

fn send_and_read(stream: &mut TcpStream, args: &[&str]) -> String {
    stream.write_all(&resp_cmd(args)).unwrap();
    thread::sleep(Duration::from_millis(50));
    read_all(stream)
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
    let tmpdir =
        std::env::temp_dir().join(format!("lux_bitops_test_{}_{}", std::process::id(), port));
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
fn setbit_getbit_bitcount_and_bitpos() {
    let port = 17810;
    let _server = start_lux(port);
    let mut conn = connect(port);

    assert!(send_and_read(&mut conn, &["SETBIT", "bits", "1", "1"]).contains(":0"));
    assert!(send_and_read(&mut conn, &["SETBIT", "bits", "9", "1"]).contains(":0"));
    assert!(send_and_read(&mut conn, &["GETBIT", "bits", "1"]).contains(":1"));
    assert!(send_and_read(&mut conn, &["GETBIT", "bits", "2"]).contains(":0"));
    assert!(send_and_read(&mut conn, &["BITCOUNT", "bits"]).contains(":2"));
    assert!(send_and_read(&mut conn, &["BITCOUNT", "bits", "0", "7", "BIT"]).contains(":1"));
    assert!(send_and_read(&mut conn, &["BITPOS", "bits", "1"]).contains(":1"));
    assert!(send_and_read(&mut conn, &["BITPOS", "bits", "0", "0", "7", "BIT"]).contains(":0"));
}

#[test]
fn bitop_and_or_xor_not() {
    let port = 17811;
    let _server = start_lux(port);
    let mut conn = connect(port);

    send_and_read(&mut conn, &["SETBIT", "a", "0", "1"]);
    send_and_read(&mut conn, &["SETBIT", "a", "2", "1"]);
    send_and_read(&mut conn, &["SETBIT", "b", "2", "1"]);
    send_and_read(&mut conn, &["SETBIT", "b", "3", "1"]);

    assert!(send_and_read(&mut conn, &["BITOP", "AND", "and", "a", "b"]).contains(":1"));
    assert!(send_and_read(&mut conn, &["GETBIT", "and", "2"]).contains(":1"));
    assert!(send_and_read(&mut conn, &["GETBIT", "and", "0"]).contains(":0"));

    assert!(send_and_read(&mut conn, &["BITOP", "OR", "or", "a", "b"]).contains(":1"));
    assert!(send_and_read(&mut conn, &["GETBIT", "or", "0"]).contains(":1"));
    assert!(send_and_read(&mut conn, &["GETBIT", "or", "3"]).contains(":1"));

    assert!(send_and_read(&mut conn, &["BITOP", "XOR", "xor", "a", "b"]).contains(":1"));
    assert!(send_and_read(&mut conn, &["GETBIT", "xor", "2"]).contains(":0"));

    assert!(send_and_read(&mut conn, &["BITOP", "NOT", "not", "a"]).contains(":1"));
    assert!(send_and_read(&mut conn, &["GETBIT", "not", "1"]).contains(":1"));
}

#[test]
fn bitop_reports_syntax_and_type_errors() {
    let port = 17812;
    let _server = start_lux(port);
    let mut conn = connect(port);

    let bad_bit = send_and_read(&mut conn, &["SETBIT", "bits", "0", "2"]);
    assert!(bad_bit.contains("ERR bit is not"), "bad bit: {bad_bit}");

    let bad_offset = send_and_read(&mut conn, &["GETBIT", "bits", "-1"]);
    assert!(
        bad_offset.contains("ERR bit offset"),
        "bad offset: {bad_offset}"
    );

    let bad_not = send_and_read(&mut conn, &["BITOP", "NOT", "dst", "a", "b"]);
    assert!(
        bad_not.contains("BITOP NOT requires"),
        "bad NOT arity: {bad_not}"
    );

    send_and_read(&mut conn, &["LPUSH", "list", "x"]);
    let wrongtype = send_and_read(&mut conn, &["GETBIT", "list", "0"]);
    assert!(wrongtype.contains("WRONGTYPE"), "wrong type: {wrongtype}");
}

#[test]
fn bit_commands_reject_invalid_ranges_without_mutating_destination() {
    let port = 17813;
    let _server = start_lux(port);
    let mut conn = connect(port);

    send_and_read(&mut conn, &["SETBIT", "src", "0", "1"]);
    send_and_read(&mut conn, &["SETBIT", "dest", "0", "1"]);

    for cmd in [
        vec!["BITPOS", "src", "1", "nope"],
        vec!["BITPOS", "src", "1", "0", "nope"],
        vec!["BITPOS", "src", "1", "0", "-1", "NOPE"],
        vec!["BITOP", "BADOP", "dest", "missing"],
    ] {
        let resp = send_and_read(&mut conn, &cmd);
        assert!(
            resp.starts_with("-ERR"),
            "expected error for {cmd:?}, got: {resp}"
        );
    }

    let resp = send_and_read(&mut conn, &["GETBIT", "dest", "0"]);
    assert!(
        resp.contains(":1"),
        "invalid BITOP should not delete destination: {resp}"
    );
}
