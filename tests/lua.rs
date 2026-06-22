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
    let target_dir = exe.parent()?.parent()?.parent()?;
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

#[test]
fn eval_sandbox_removes_dangerous_globals() {
    let port: u16 = 17310;
    let _server = start_lux(port);
    let mut conn = connect(port);
    // Each of these globals must be nil inside a script: no filesystem, process,
    // bytecode loading, native modules, or debug introspection from user Lua.
    for g in [
        "os",
        "io",
        "package",
        "require",
        "dofile",
        "loadfile",
        "load",
        "loadstring",
        "debug",
        "collectgarbage",
    ] {
        let src = format!("return type({g})");
        let resp = send_and_read(&mut conn, &["EVAL", &src, "0"]);
        assert!(
            resp.contains("nil"),
            "global `{g}` should be sandboxed to nil, got: {resp}"
        );
    }
}

#[test]
fn eval_call_aborts_but_pcall_returns_error_table() {
    let port: u16 = 17311;
    let _server = start_lux(port);
    let mut conn = connect(port);
    // redis.pcall on a failing command returns an error table; the script keeps running.
    let resp = send_and_read(
        &mut conn,
        &[
            "EVAL",
            "local r = redis.pcall('NOPE'); if type(r) == 'table' and r.err then return 'caught' else return 'leaked' end",
            "0",
        ],
    );
    assert!(
        resp.contains("caught"),
        "pcall should return an error table, not abort: {resp}"
    );
    // redis.call on the same failing command aborts the script with a RESP error.
    let resp = send_and_read(&mut conn, &["EVAL", "redis.call('NOPE'); return 1", "0"]);
    assert!(
        resp.starts_with('-'),
        "call on a bad command should abort with an error reply: {resp}"
    );
}

#[test]
fn eval_cmsgpack_unpack_rejects_oversized_declared_length() {
    let port: u16 = 17313;
    let _server = start_lux(port);
    let mut conn = connect(port);
    // Array32 marker (0xdd) declaring ~4 billion elements with no payload: the
    // container-length cap must reject it (error), never pre-allocate or spin.
    let src = "local ok = pcall(function() return cmsgpack.unpack(string.char(0xdd, 0xff, 0xff, 0xff, 0xff)) end); if ok then return 'unbounded' else return 'rejected' end";
    let resp = send_and_read(&mut conn, &["EVAL", src, "0"]);
    assert!(
        resp.contains("rejected"),
        "oversized msgpack container length must be rejected: {resp}"
    );
}

#[test]
fn eval_denies_admin_and_control_commands() {
    let port: u16 = 17312;
    let _server = start_lux(port);
    let mut conn = connect(port);
    for cmd in ["SAVE", "BGSAVE", "MULTI", "SUBSCRIBE", "WATCH"] {
        let src = format!("return redis.call('{cmd}')");
        let resp = send_and_read(&mut conn, &["EVAL", &src, "0"]);
        assert!(
            resp.to_lowercase().contains("not allowed"),
            "`{cmd}` must be denied from scripts: {resp}"
        );
    }
}
