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

fn start_lux_with_password(port: u16, password: &str) -> LuxServer {
    let bin = find_lux_binary().expect("no lux binary found");
    let tmpdir =
        std::env::temp_dir().join(format!("lux_auth_test_{}_{}", std::process::id(), port));
    std::fs::create_dir_all(&tmpdir).unwrap();
    let child = std::process::Command::new(&bin)
        .env("LUX_PORT", port.to_string())
        .env("LUX_SHARDS", "4")
        .env("LUX_SAVE_INTERVAL", "0")
        .env("LUX_DATA_DIR", tmpdir.to_str().unwrap())
        .env("LUX_PASSWORD", password)
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
fn commands_rejected_without_auth() {
    let port: u16 = 16600;
    let _server = start_lux_with_password(port, "secret123");
    let mut conn = connect(port);

    let resp = send_and_read(&mut conn, &["SET", "k", "v"]);
    assert!(resp.contains("NOAUTH"), "should reject: {resp}");

    let resp = send_and_read(&mut conn, &["GET", "k"]);
    assert!(resp.contains("NOAUTH"), "still rejected: {resp}");
}

#[test]
fn ping_allowed_without_auth() {
    let port: u16 = 16601;
    let _server = start_lux_with_password(port, "secret123");
    let mut conn = connect(port);

    let resp = send_and_read(&mut conn, &["PING"]);
    assert!(resp.contains("PONG"), "PING allowed: {resp}");
}

#[test]
fn auth_wrong_password_rejected() {
    let port: u16 = 16602;
    let _server = start_lux_with_password(port, "secret123");
    let mut conn = connect(port);

    let resp = send_and_read(&mut conn, &["AUTH", "wrongpass"]);
    assert!(resp.contains("WRONGPASS"), "bad password: {resp}");

    let resp = send_and_read(&mut conn, &["SET", "k", "v"]);
    assert!(resp.contains("NOAUTH"), "still locked out: {resp}");
}

#[test]
fn auth_correct_password_allows_commands() {
    let port: u16 = 16603;
    let _server = start_lux_with_password(port, "secret123");
    let mut conn = connect(port);

    let resp = send_and_read(&mut conn, &["AUTH", "secret123"]);
    assert!(resp.contains("+OK"), "auth success: {resp}");

    let resp = send_and_read(&mut conn, &["SET", "k", "v"]);
    assert!(resp.contains("+OK"), "command works after auth: {resp}");

    let resp = send_and_read(&mut conn, &["GET", "k"]);
    assert!(resp.contains("v"), "value readable: {resp}");
}

#[test]
fn auth_is_per_connection() {
    let port: u16 = 16604;
    let _server = start_lux_with_password(port, "secret123");
    let mut conn1 = connect(port);
    let mut conn2 = connect(port);

    send_and_read(&mut conn1, &["AUTH", "secret123"]);
    send_and_read(&mut conn1, &["SET", "k", "fromconn1"]);

    let resp = send_and_read(&mut conn2, &["GET", "k"]);
    assert!(resp.contains("NOAUTH"), "conn2 not authenticated: {resp}");

    send_and_read(&mut conn2, &["AUTH", "secret123"]);
    let resp = send_and_read(&mut conn2, &["GET", "k"]);
    assert!(
        resp.contains("fromconn1"),
        "conn2 can read after auth: {resp}"
    );
}

#[test]
fn auth_missing_args() {
    let port: u16 = 16605;
    let _server = start_lux_with_password(port, "secret123");
    let mut conn = connect(port);

    let resp = send_and_read(&mut conn, &["AUTH"]);
    assert!(
        resp.contains("ERR wrong number"),
        "AUTH needs password arg: {resp}"
    );
}

#[test]
fn hello_allowed_without_auth() {
    let port: u16 = 16606;
    let _server = start_lux_with_password(port, "secret123");
    let mut conn = connect(port);

    let resp = send_and_read(&mut conn, &["HELLO"]);
    assert!(resp.contains("lux"), "HELLO allowed pre-auth: {resp}");
}

#[test]
fn hello_with_auth_authenticates() {
    let port: u16 = 16607;
    let _server = start_lux_with_password(port, "secret123");
    let mut conn = connect(port);

    let resp = send_and_read(&mut conn, &["HELLO", "3", "AUTH", "default", "secret123"]);
    assert!(resp.contains("lux"), "HELLO returns server info: {resp}");

    let resp = send_and_read(&mut conn, &["SET", "k", "v"]);
    assert!(resp.contains("+OK"), "authenticated via HELLO: {resp}");
}

#[test]
fn hello_with_wrong_password_rejected() {
    let port: u16 = 16608;
    let _server = start_lux_with_password(port, "secret123");
    let mut conn = connect(port);

    let resp = send_and_read(&mut conn, &["HELLO", "3", "AUTH", "default", "wrongpass"]);
    assert!(resp.contains("WRONGPASS"), "bad password in HELLO: {resp}");

    let resp = send_and_read(&mut conn, &["SET", "k", "v"]);
    assert!(resp.contains("NOAUTH"), "still locked out: {resp}");
}
