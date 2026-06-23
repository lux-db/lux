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
    let tmpdir =
        std::env::temp_dir().join(format!("lux_blocking_test_{}_{}", std::process::id(), port));
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
fn blpop_immediate_pop() {
    let port: u16 = 17100;
    let _server = start_lux(port);
    let mut conn = connect(port);
    send_and_read(&mut conn, &["RPUSH", "mylist", "hello"]);
    let resp = send_and_read(&mut conn, &["BLPOP", "mylist", "1"]);
    assert!(resp.contains("mylist"), "key name: {resp}");
    assert!(resp.contains("hello"), "value: {resp}");
}

#[test]
fn brpop_immediate_pop() {
    let port: u16 = 17101;
    let _server = start_lux(port);
    let mut conn = connect(port);
    send_and_read(&mut conn, &["RPUSH", "mylist", "a", "b", "c"]);
    let resp = send_and_read(&mut conn, &["BRPOP", "mylist", "1"]);
    assert!(resp.contains("mylist"), "key name: {resp}");
    assert!(resp.contains("c"), "value (last): {resp}");
}

#[test]
fn blpop_timeout() {
    let port: u16 = 17102;
    let _server = start_lux(port);
    let mut conn = connect(port);
    conn.set_read_timeout(Some(Duration::from_millis(5000)))
        .unwrap();
    let resp = send_and_read(&mut conn, &["BLPOP", "empty", "1"]);
    assert!(resp.contains("*-1"), "null array on timeout: {resp}");
}

#[test]
fn blpop_woken_by_lpush() {
    let port: u16 = 17103;
    let _server = start_lux(port);
    let mut blocker = connect(port);
    blocker
        .set_read_timeout(Some(Duration::from_millis(5000)))
        .unwrap();

    blocker
        .write_all(&resp_cmd(&["BLPOP", "wakekey", "5"]))
        .unwrap();
    thread::sleep(Duration::from_millis(200));

    let mut pusher = connect(port);
    send_and_read(&mut pusher, &["LPUSH", "wakekey", "woken"]);

    thread::sleep(Duration::from_millis(200));
    let resp = read_all(&mut blocker);
    assert!(resp.contains("wakekey"), "key: {resp}");
    assert!(resp.contains("woken"), "value: {resp}");
}

#[test]
fn blpop_multi_key() {
    let port: u16 = 17104;
    let _server = start_lux(port);
    let mut conn = connect(port);
    send_and_read(&mut conn, &["RPUSH", "list2", "val2"]);
    let resp = send_and_read(&mut conn, &["BLPOP", "list1", "list2", "1"]);
    assert!(resp.contains("list2"), "key: {resp}");
    assert!(resp.contains("val2"), "value: {resp}");
}

#[test]
fn blmove_immediate() {
    let port: u16 = 17105;
    let _server = start_lux(port);
    let mut conn = connect(port);
    send_and_read(&mut conn, &["RPUSH", "src", "item"]);
    let resp = send_and_read(&mut conn, &["BLMOVE", "src", "dst", "LEFT", "RIGHT", "1"]);
    assert!(resp.contains("item"), "moved value: {resp}");
    let resp2 = send_and_read(&mut conn, &["LRANGE", "dst", "0", "-1"]);
    assert!(resp2.contains("item"), "dst has item: {resp2}");
}

#[test]
fn bzpopmin_wait_does_not_block_other_clients() {
    let port: u16 = 17106;
    let _server = start_lux(port);
    let mut blocker = connect(port);
    blocker
        .set_read_timeout(Some(Duration::from_millis(5000)))
        .unwrap();

    blocker
        .write_all(&resp_cmd(&["BZPOPMIN", "marker", "5"]))
        .unwrap();
    thread::sleep(Duration::from_millis(200));

    let mut observer = connect(port);
    let pong = send_and_read(&mut observer, &["PING"]);
    assert!(pong.contains("PONG"), "PING while blocked: {pong}");

    let mut pusher = connect(port);
    send_and_read(&mut pusher, &["ZADD", "marker", "1", "wake"]);

    let resp = read_all(&mut blocker);
    assert!(resp.contains("marker"), "key: {resp}");
    assert!(resp.contains("wake"), "member: {resp}");
}
