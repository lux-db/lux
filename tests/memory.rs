use std::io::{BufRead, BufReader, Read as IoRead, Write};
use std::net::TcpStream;
use std::process::{Child, Command};
use std::time::Duration;

struct TestServer {
    child: Child,
}

impl TestServer {
    fn kill(&mut self) -> std::io::Result<()> {
        self.child.kill()
    }

    fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        self.child.wait()
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_server(port: u16) -> TestServer {
    let child = Command::new(env!("CARGO_BIN_EXE_lux"))
        .env("LUX_PORT", port.to_string())
        .env("LUX_SAVE_INTERVAL", "0")
        .env("LUX_MAXMEMORY", "64mb")
        .env("LUX_DATA_DIR", format!("/tmp/lux-test-mem-{}", port))
        .spawn()
        .expect("failed to start lux");
    let mut server = TestServer { child };
    let addr = format!("127.0.0.1:{port}");
    for _ in 0..100 {
        if TcpStream::connect(&addr).is_ok() {
            return server;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = server.kill();
    panic!("lux did not start on port {port}");
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

fn get_used_memory(stream: &mut TcpStream) -> u64 {
    let info = send(stream, &["INFO"]);
    for line in info.lines() {
        if let Some(rest) = line.strip_prefix("used_memory_bytes:") {
            return rest.trim().parse().unwrap_or(0);
        }
    }
    0
}

/// Memory counter stays sane after adding and deleting collection data.
#[test]
fn memory_no_underflow_on_collection_delete() {
    let port = 16600;
    let mut child = start_server(port);
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    // Add list data
    for i in 0..100 {
        send(&mut s, &["LPUSH", "mylist", &format!("item-{}", i)]);
    }

    // Add hash data
    for i in 0..100 {
        send(
            &mut s,
            &[
                "HSET",
                "myhash",
                &format!("field-{}", i),
                &format!("value-{}", i),
            ],
        );
    }

    // Add set data
    for i in 0..100 {
        send(&mut s, &["SADD", "myset", &format!("member-{}", i)]);
    }

    // Add sorted set data
    for i in 0..100 {
        send(
            &mut s,
            &[
                "ZADD",
                "myzset",
                &format!("{}", i),
                &format!("member-{}", i),
            ],
        );
    }

    let mem_before_delete = get_used_memory(&mut s);
    assert!(mem_before_delete > 0, "memory should be tracked after adds");
    assert!(
        mem_before_delete < 1_000_000_000,
        "memory should be reasonable, got {}",
        mem_before_delete
    );

    // Delete all keys
    send(&mut s, &["DEL", "mylist", "myhash", "myset", "myzset"]);

    let mem_after_delete = get_used_memory(&mut s);
    assert!(
        mem_after_delete < 1_000_000_000,
        "memory should not underflow after delete, got {}",
        mem_after_delete
    );
    assert!(
        mem_after_delete < mem_before_delete,
        "memory should decrease after delete: before={}, after={}",
        mem_before_delete,
        mem_after_delete
    );

    // Verify we can still write (not OOM)
    let r = send(&mut s, &["SET", "canary", "alive"]);
    assert!(
        r.contains("OK"),
        "should be able to write after delete, got: {}",
        r
    );

    child.kill().ok();
    child.wait().ok();
}

/// Memory counter decreases when elements are popped or removed.
#[test]
fn memory_tracks_collection_removals() {
    let port = 16601;
    let mut child = start_server(port);
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    // Fill a list
    for i in 0..200 {
        send(&mut s, &["RPUSH", "poplist", &format!("item-{}", i)]);
    }
    let mem_full = get_used_memory(&mut s);

    // Pop half
    for _ in 0..100 {
        send(&mut s, &["LPOP", "poplist"]);
    }
    let mem_half = get_used_memory(&mut s);
    assert!(
        mem_half < mem_full,
        "memory should decrease after pops: full={}, half={}",
        mem_full,
        mem_half
    );

    // SREM from a set
    for i in 0..50 {
        send(&mut s, &["SADD", "remset", &format!("m-{}", i)]);
    }
    let mem_set_full = get_used_memory(&mut s);
    for i in 0..50 {
        send(&mut s, &["SREM", "remset", &format!("m-{}", i)]);
    }
    let mem_set_empty = get_used_memory(&mut s);
    assert!(
        mem_set_empty < mem_set_full,
        "memory should decrease after srem: full={}, empty={}",
        mem_set_full,
        mem_set_empty
    );

    // No underflow
    assert!(
        mem_set_empty < 1_000_000_000,
        "no underflow: {}",
        mem_set_empty
    );

    child.kill().ok();
    child.wait().ok();
}

/// Memory counter does not underflow when list-only keys are deleted.
#[test]
fn memory_no_underflow_list_then_del() {
    let port = 16602;
    let mut child = start_server(port);
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    for i in 0..500 {
        send(&mut s, &["RPUSH", "biglist", &format!("value-{:04}", i)]);
    }

    send(&mut s, &["DEL", "biglist"]);

    let mem = get_used_memory(&mut s);
    assert!(
        mem < 1_000_000_000,
        "memory must not underflow after DEL of list-only key, got {}",
        mem
    );

    // Must be able to write
    let r = send(&mut s, &["SET", "test", "works"]);
    assert!(r.contains("OK"), "writes should work, got: {}", r);

    child.kill().ok();
    child.wait().ok();
}
