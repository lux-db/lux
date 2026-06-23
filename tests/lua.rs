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

fn find_lux_binary() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let profile_dir = exe.parent()?.parent()?;
    let same_profile = profile_dir.join("lux");
    if same_profile.exists() {
        return Some(same_profile);
    }
    let target_dir = profile_dir.parent()?;
    let release = target_dir.join("release").join("lux");
    if release.exists() {
        return Some(release);
    }
    let debug = target_dir.join("debug").join("lux");
    if debug.exists() {
        return Some(debug);
    }
    None
}

struct LuxServer {
    child: std::process::Child,
    tmpdir: std::path::PathBuf,
}

impl Drop for LuxServer {
    fn drop(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
        let _ = std::fs::remove_dir_all(&self.tmpdir);
    }
}

fn start_lux(port: u16) -> LuxServer {
    let bin = find_lux_binary().expect("no lux binary found");
    let tmpdir = std::env::temp_dir().join(format!("lux_lua_test_{}_{}", std::process::id(), port));
    std::fs::create_dir_all(&tmpdir).unwrap();
    let child = std::process::Command::new(&bin)
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
        .set_read_timeout(Some(Duration::from_millis(2000)))
        .unwrap();
    stream
}

#[test]
fn eval_return_integer() {
    let port: u16 = 17300;
    let _server = start_lux(port);
    let mut conn = connect(port);
    let resp = send_and_read(&mut conn, &["EVAL", "return 42", "0"]);
    assert!(resp.contains(":42"), "returns 42: {resp}");
}

#[test]
fn eval_return_string() {
    let port: u16 = 17301;
    let _server = start_lux(port);
    let mut conn = connect(port);
    let resp = send_and_read(&mut conn, &["EVAL", "return 'hello'", "0"]);
    assert!(resp.contains("hello"), "returns hello: {resp}");
}

#[test]
fn eval_redis_call_set_get() {
    let port: u16 = 17302;
    let _server = start_lux(port);
    let mut conn = connect(port);
    let resp = send_and_read(
        &mut conn,
        &[
            "EVAL",
            "redis.call('SET', KEYS[1], ARGV[1]); return redis.call('GET', KEYS[1])",
            "1",
            "mykey",
            "myval",
        ],
    );
    assert!(resp.contains("myval"), "get returns myval: {resp}");
}

#[test]
fn eval_keys_and_argv() {
    let port: u16 = 17303;
    let _server = start_lux(port);
    let mut conn = connect(port);
    let resp = send_and_read(&mut conn, &["EVAL", "return KEYS[1]", "1", "testkey"]);
    assert!(resp.contains("testkey"), "KEYS[1] = testkey: {resp}");

    let resp = send_and_read(&mut conn, &["EVAL", "return ARGV[1]", "0", "argval"]);
    assert!(resp.contains("argval"), "ARGV[1] = argval: {resp}");
}

#[test]
fn evalsha_after_script_load() {
    let port: u16 = 17304;
    let _server = start_lux(port);
    let mut conn = connect(port);
    let resp = send_and_read(&mut conn, &["SCRIPT", "LOAD", "return 99"]);
    let sha = resp
        .lines()
        .find(|l| l.len() > 10 && !l.starts_with('$'))
        .unwrap_or("")
        .trim();
    let resp = send_and_read(&mut conn, &["EVALSHA", sha, "0"]);
    assert!(resp.contains(":99"), "evalsha returns 99: {resp}");
}

#[test]
fn pipelined_evalsha_does_not_deadlock() {
    let port: u16 = 17310;
    let _server = start_lux(port);
    let mut conn = connect(port);
    let resp = send_and_read(&mut conn, &["SCRIPT", "LOAD", "return 123"]);
    let sha = resp
        .lines()
        .find(|l| l.len() > 10 && !l.starts_with('$'))
        .unwrap_or("")
        .trim();

    let mut pipeline = resp_cmd(&["EVALSHA", sha, "0"]);
    pipeline.extend_from_slice(&resp_cmd(&["PING"]));
    conn.write_all(&pipeline).unwrap();
    thread::sleep(Duration::from_millis(50));
    let resp = read_all(&mut conn);
    assert!(resp.contains(":123"), "evalsha response: {resp}");
    assert!(resp.contains("PONG"), "ping response: {resp}");
}

#[test]
fn evalsha_noscript_error() {
    let port: u16 = 17305;
    let _server = start_lux(port);
    let mut conn = connect(port);
    let resp = send_and_read(
        &mut conn,
        &["EVALSHA", "0000000000000000000000000000000000000000", "0"],
    );
    assert!(resp.contains("NOSCRIPT"), "noscript error: {resp}");
}

#[test]
fn script_exists() {
    let port: u16 = 17306;
    let _server = start_lux(port);
    let mut conn = connect(port);
    send_and_read(&mut conn, &["SCRIPT", "LOAD", "return 1"]);
    let resp = send_and_read(
        &mut conn,
        &[
            "SCRIPT",
            "EXISTS",
            "e0e1f9fabfc9d4800c877a703b823ac0578ff831",
        ],
    );
    assert!(
        resp.contains(":1") || resp.contains(":0"),
        "exists response: {resp}"
    );
}

#[test]
fn script_flush() {
    let port: u16 = 17307;
    let _server = start_lux(port);
    let mut conn = connect(port);
    send_and_read(&mut conn, &["SCRIPT", "LOAD", "return 1"]);
    let resp = send_and_read(&mut conn, &["SCRIPT", "FLUSH"]);
    assert!(resp.contains("OK"), "flush ok: {resp}");
}

#[test]
fn eval_error_handling() {
    let port: u16 = 17308;
    let _server = start_lux(port);
    let mut conn = connect(port);
    let resp = send_and_read(&mut conn, &["EVAL", "this is not valid lua", "0"]);
    assert!(resp.contains("ERR"), "error response: {resp}");
}

#[test]
fn eval_return_table() {
    let port: u16 = 17309;
    let _server = start_lux(port);
    let mut conn = connect(port);
    let resp = send_and_read(&mut conn, &["EVAL", "return {1, 2, 3}", "0"]);
    assert!(resp.contains(":1"), "contains 1: {resp}");
    assert!(resp.contains(":2"), "contains 2: {resp}");
    assert!(resp.contains(":3"), "contains 3: {resp}");
}
