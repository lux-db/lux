mod common;

use std::io::{BufRead, BufReader, Read, Write};
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
        return format!("${s}");
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
        return format!("*{count} [{}]", items.join(", "));
    }
    line
}

fn send(stream: &mut TcpStream, args: &[&str]) -> String {
    stream.write_all(&resp_cmd(args)).unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    read_response(&mut reader)
}

fn connect(port: u16) -> TcpStream {
    let stream = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    stream.set_nodelay(true).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
}

fn wait_for_port(port: u16) {
    for _ in 0..80 {
        if TcpStream::connect(format!("127.0.0.1:{port}")).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("lux did not start on port {port}");
}

struct LuxServer {
    port: u16,
    child: std::process::Child,
    tmpdir: std::path::PathBuf,
}

impl LuxServer {
    fn start_tiered(port: u16, maxmemory: &str) -> Self {
        let tmpdir =
            std::env::temp_dir().join(format!("lux_reliability_{}_{}", std::process::id(), port));
        let _ = std::fs::remove_dir_all(&tmpdir);
        std::fs::create_dir_all(&tmpdir).unwrap();
        let child = Self::spawn(port, &tmpdir, maxmemory);
        wait_for_port(port);
        Self {
            port,
            child,
            tmpdir,
        }
    }

    fn spawn(port: u16, tmpdir: &std::path::Path, maxmemory: &str) -> std::process::Child {
        common::lux_command(env!("CARGO_BIN_EXE_lux"))
            .env("LUX_PORT", port.to_string())
            .env("LUX_SHARDS", "4")
            .env("LUX_SAVE_INTERVAL", "0")
            .env("LUX_MAXMEMORY", maxmemory)
            .env("LUX_MAXMEMORY_POLICY", "allkeys-lru")
            .env("LUX_STORAGE_MODE", "tiered")
            .env("LUX_STORAGE_DIR", tmpdir.join("storage").to_str().unwrap())
            .env("LUX_DATA_DIR", tmpdir.to_str().unwrap())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("failed to start lux")
    }

    fn conn(&self) -> TcpStream {
        connect(self.port)
    }

    fn crash_and_restart(&mut self, maxmemory: &str) {
        self.child.kill().ok();
        self.child.wait().ok();
        thread::sleep(Duration::from_millis(300));
        self.child = Self::spawn(self.port, &self.tmpdir, maxmemory);
        wait_for_port(self.port);
    }
}

impl Drop for LuxServer {
    fn drop(&mut self) {
        common::terminate_child(&mut self.child);
        let _ = std::fs::remove_dir_all(&self.tmpdir);
    }
}

#[test]
fn tiered_mixed_datatypes_survive_eviction_snapshot_wal_and_crash() {
    let mut server = LuxServer::start_tiered(17850, "128kb");
    let mut conn = server.conn();

    assert_eq!(send(&mut conn, &["SET", "str", "alive"]), "+OK");
    assert!(send(&mut conn, &["HSET", "hash", "a", "1", "b", "2"]).contains(":2"));
    assert!(send(&mut conn, &["RPUSH", "list", "a", "b", "c"]).contains(":3"));
    assert!(send(&mut conn, &["SADD", "set", "x", "y", "z"]).contains(":3"));
    assert!(send(&mut conn, &["ZADD", "zset", "1.5", "alpha", "2.5", "beta"]).contains(":2"));
    assert!(send(&mut conn, &["XADD", "stream", "1-0", "field", "value"]).contains("1-0"));
    assert_eq!(
        send(&mut conn, &["XGROUP", "CREATE", "stream", "g", "0"]),
        "+OK"
    );
    let read = send(
        &mut conn,
        &["XREADGROUP", "GROUP", "g", "c", "STREAMS", "stream", ">"],
    );
    assert!(
        read.contains("value"),
        "stream pending setup failed: {read}"
    );
    assert!(send(&mut conn, &["PFADD", "hll", "a", "b", "c", "d"]).contains(":1"));
    assert!(send(&mut conn, &["TSADD", "ts", "1000", "42.5"]).contains(":1000"));
    assert_eq!(
        send(
            &mut conn,
            &[
                "VSET",
                "vec",
                "3",
                "1.0",
                "0.0",
                "0.0",
                "META",
                r#"{"kind":"sentinel"}"#,
            ],
        ),
        "+OK"
    );

    let filler = "x".repeat(8192);
    for i in 0..80 {
        assert_eq!(
            send(&mut conn, &["SET", &format!("filler:{i}"), &filler]),
            "+OK"
        );
    }

    let cold = send(&mut conn, &["GET", "str"]);
    assert!(
        cold.contains("alive"),
        "tiered cold read before restart: {cold}"
    );

    let save = send(&mut conn, &["SAVE"]);
    assert!(save.contains("OK"), "SAVE failed before crash: {save}");

    assert_eq!(
        send(&mut conn, &["SET", "wal_only", "after_snapshot"]),
        "+OK"
    );
    drop(conn);

    server.crash_and_restart("20mb");
    let mut conn = server.conn();

    assert!(send(&mut conn, &["GET", "str"]).contains("alive"));
    assert!(send(&mut conn, &["HGET", "hash", "b"]).contains("2"));
    assert!(send(&mut conn, &["LRANGE", "list", "0", "-1"]).contains("c"));
    assert!(send(&mut conn, &["SISMEMBER", "set", "y"]).contains(":1"));
    assert!(send(&mut conn, &["ZSCORE", "zset", "beta"]).contains("2.5"));
    assert!(send(&mut conn, &["XLEN", "stream"]).contains(":1"));
    assert!(send(&mut conn, &["XPENDING", "stream", "g"]).contains(":1"));
    assert!(send(&mut conn, &["PFCOUNT", "hll"]).contains(":4"));
    assert!(send(&mut conn, &["TSGET", "ts"]).contains("42.5"));
    assert!(send(&mut conn, &["VGET", "vec"]).contains("sentinel"));
    assert!(send(&mut conn, &["GET", "wal_only"]).contains("after_snapshot"));
}

#[test]
fn malformed_resp_storm_does_not_crash_server() {
    let server = LuxServer::start_tiered(17851, "1mb");

    for i in 0..250 {
        let mut conn = server.conn();
        let payload = match i % 5 {
            0 => b"*3\r\n$3\r\nSET\r\n$1\r\na\r\n$999\r\nshort\r\n".to_vec(),
            1 => b"*2\r\n$4\r\nHSET\r\n$1\r\nh\r\n".to_vec(),
            2 => b"*4\r\n$4\r\nXADD\r\n$1\r\ns\r\n$6\r\nbad-id\r\n$1\r\nf\r\n".to_vec(),
            3 => vec![0xff, 0x00, b'*', b'9', b'\r', b'\n', b'?', b'\r', b'\n'],
            _ => format!("not resp at all {i}\r\n").into_bytes(),
        };
        let _ = conn.write_all(&payload);
    }

    let mut conn = server.conn();
    let pong = send(&mut conn, &["PING"]);
    assert_eq!(
        pong, "+PONG",
        "server stopped responding after malformed storm"
    );

    let ok = send(&mut conn, &["SET", "still", "works"]);
    assert_eq!(ok, "+OK", "server should still accept normal writes");
    assert!(send(&mut conn, &["GET", "still"]).contains("works"));
}

#[test]
fn malformed_resp_protocol_error_closes_only_bad_connection() {
    let server = LuxServer::start_tiered(17857, "1mb");
    let mut bad = server.conn();
    bad.write_all(b"*1048577\r\n").unwrap();

    let mut reader = BufReader::new(bad.try_clone().unwrap());
    let error = read_response(&mut reader);
    assert!(
        error.contains("RESP array count exceeds maximum"),
        "malformed client should receive protocol error, got: {error}"
    );

    let mut good = server.conn();
    assert_eq!(send(&mut good, &["PING"]), "+PONG");
    assert_eq!(send(&mut good, &["SET", "after_bad_resp", "ok"]), "+OK");
    assert!(send(&mut good, &["GET", "after_bad_resp"]).contains("ok"));
}

fn manual_snapshot_command_does_not_double_replay_wal(port: u16, command: &str) {
    let mut server = LuxServer::start_tiered(port, "1mb");
    let mut conn = server.conn();

    for _ in 0..10 {
        assert!(send(&mut conn, &["INCR", "counter"]).starts_with(':'));
    }
    let before = send(&mut conn, &["GET", "counter"]);
    assert!(before.contains("10"), "counter before snapshot: {before}");

    let snapshot = send(&mut conn, &[command]);
    assert!(
        snapshot.contains("OK") || snapshot.contains("Background saving started"),
        "{command} failed: {snapshot}"
    );
    drop(conn);

    server.crash_and_restart("1mb");
    let mut conn = server.conn();
    let after = send(&mut conn, &["GET", "counter"]);
    assert!(
        after.contains("10"),
        "{command} must not leave stale WAL frames that double-apply INCR after restart: {after}"
    );
}

#[test]
fn manual_save_truncates_wal_after_successful_snapshot() {
    manual_snapshot_command_does_not_double_replay_wal(17853, "SAVE");
}

#[test]
fn manual_bgsave_truncates_wal_after_successful_snapshot() {
    manual_snapshot_command_does_not_double_replay_wal(17854, "BGSAVE");
}

#[test]
fn concurrent_tiered_writers_survive_restart_with_consistent_counter() {
    let mut server = LuxServer::start_tiered(17852, "256kb");
    let addr = format!("127.0.0.1:{}", server.port);
    let workers = 6;
    let per_worker = 80;

    let handles: Vec<_> = (0..workers)
        .map(|worker| {
            let addr = addr.clone();
            thread::spawn(move || {
                let mut conn = TcpStream::connect(addr).unwrap();
                conn.set_nodelay(true).unwrap();
                conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                for i in 0..per_worker {
                    let key = format!("w:{worker}:{i}");
                    assert_eq!(
                        send(&mut conn, &["SET", &key, &format!("value:{worker}:{i}")]),
                        "+OK"
                    );
                    assert!(send(
                        &mut conn,
                        &["HSET", &format!("h:{worker}"), &i.to_string(), "v"]
                    )
                    .starts_with(':'));
                    assert!(
                        send(&mut conn, &["SADD", &format!("s:{worker}"), &i.to_string()])
                            .starts_with(':')
                    );
                    assert!(send(&mut conn, &["INCR", "global_counter"]).starts_with(':'));
                    if i % 10 == 0 {
                        assert!(send(&mut conn, &["GET", &key]).contains("value"));
                    }
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }

    let mut conn = server.conn();
    let expected = (workers * per_worker).to_string();
    let before_restart_counter = send(&mut conn, &["GET", "global_counter"]);
    assert!(
        before_restart_counter.contains(&expected),
        "counter should include all concurrent increments before restart; expected {expected}, got {before_restart_counter}"
    );
    assert!(send(&mut conn, &["SAVE"]).contains("OK"));
    drop(conn);

    server.crash_and_restart("20mb");
    let mut conn = server.conn();
    let after_restart_counter = send(&mut conn, &["GET", "global_counter"]);
    assert!(
        after_restart_counter.contains(&expected),
        "counter should survive restart; expected {expected}, got {after_restart_counter}"
    );
    assert!(send(&mut conn, &["GET", "w:0:0"]).contains("value:0:0"));
    assert!(send(&mut conn, &["GET", "w:5:79"]).contains("value:5:79"));
    assert!(send(&mut conn, &["HLEN", "h:3"]).contains(":80"));
    assert!(send(&mut conn, &["SCARD", "s:4"]).contains(":80"));
}
