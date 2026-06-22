//! Crash injection / chaos tests for the persistence layer.
//!
//! These tests start real Lux server processes and kill them at various
//! points to verify data integrity after recovery. They cover scenarios
//! that unit tests cannot: actual process crashes, WAL replay across
//! restarts, snapshot + WAL interaction, and concurrent data type recovery.

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
    // Read until we have a complete RESP response rather than sleeping and hoping.
    // Set a generous timeout so slow restarts don't cause spurious failures.
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut data = Vec::with_capacity(256);
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                data.extend_from_slice(&buf[..n]);
                // A complete simple RESP response ends with \r\n.
                // For bulk strings we need to check we got the full payload too,
                // but for our purposes (GET returns +OK, $N\r\n...\r\n, or $-1\r\n)
                // checking for a trailing \r\n on a non-empty buffer is sufficient.
                if data.ends_with(b"\r\n") {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(_) => break,
        }
    }
    // Restore the normal read timeout.
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    String::from_utf8_lossy(&data).to_string()
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

fn connect(port: u16) -> TcpStream {
    let stream = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    stream.set_nodelay(true).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    stream
}

fn wait_for_port(port: u16) {
    for _ in 0..40 {
        if TcpStream::connect(format!("127.0.0.1:{port}")).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("server did not start on port {port}");
}

struct TestServer {
    port: u16,
    child: std::process::Child,
    tmpdir: std::path::PathBuf,
}

impl TestServer {
    fn start(port: u16) -> Self {
        Self::start_with_opts(port, "100kb", "0")
    }

    fn start_with_opts(port: u16, maxmemory: &str, save_interval: &str) -> Self {
        let bin = find_lux_binary().expect("no lux binary found");
        let tmpdir = std::env::temp_dir().join(format!("lux_crash_test_{port}"));
        let _ = std::fs::remove_dir_all(&tmpdir);
        std::fs::create_dir_all(&tmpdir).unwrap();

        let child = std::process::Command::new(&bin)
            .env("LUX_PORT", port.to_string())
            .env("LUX_SHARDS", "4")
            .env("LUX_MAXMEMORY", maxmemory)
            .env("LUX_MAXMEMORY_POLICY", "allkeys-lru")
            .env("LUX_STORAGE_MODE", "tiered")
            .env("LUX_STORAGE_DIR", tmpdir.join("storage").to_str().unwrap())
            .env("LUX_DATA_DIR", tmpdir.to_str().unwrap())
            .env("LUX_SAVE_INTERVAL", save_interval)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("failed to start lux");

        wait_for_port(port);
        TestServer {
            port,
            child,
            tmpdir,
        }
    }

    /// Kill the server without graceful shutdown (simulates crash / power loss).
    fn kill(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
        thread::sleep(Duration::from_millis(300));
    }

    /// Restart the server against the same data directory.
    fn restart(&mut self) {
        self.restart_with_memory("10mb");
    }

    fn restart_with_memory(&mut self, maxmemory: &str) {
        // Ensure old process is dead.
        self.child.kill().ok();
        self.child.wait().ok();
        thread::sleep(Duration::from_millis(500));

        let bin = find_lux_binary().expect("no lux binary found");
        self.child = std::process::Command::new(&bin)
            .env("LUX_PORT", self.port.to_string())
            .env("LUX_SHARDS", "4")
            .env("LUX_MAXMEMORY", maxmemory)
            .env("LUX_MAXMEMORY_POLICY", "allkeys-lru")
            .env("LUX_STORAGE_MODE", "tiered")
            .env(
                "LUX_STORAGE_DIR",
                self.tmpdir.join("storage").to_str().unwrap(),
            )
            .env("LUX_DATA_DIR", self.tmpdir.to_str().unwrap())
            .env("LUX_SAVE_INTERVAL", "0")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("failed to restart lux");

        wait_for_port(self.port);
    }

    fn conn(&self) -> TcpStream {
        connect(self.port)
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
        let _ = std::fs::remove_dir_all(&self.tmpdir);
    }
}

fn fill_memory(conn: &mut TcpStream, count: usize) {
    let val = "x".repeat(10000);
    for i in 0..count {
        send(conn, &["SET", &format!("filler:{i}"), &val]);
    }
}

// ---------------------------------------------------------------------------
// Test: Kill mid-write, verify WAL recovery of all data types
// ---------------------------------------------------------------------------
#[test]
fn crash_recovery_all_types() {
    let mut srv = TestServer::start(17200);
    let mut c = srv.conn();

    // Write every data type.
    send(&mut c, &["SET", "str_key", "string_value"]);
    send(&mut c, &["HSET", "hash_key", "f1", "v1", "f2", "v2"]);
    send(&mut c, &["LPUSH", "list_key", "a", "b", "c"]);
    send(&mut c, &["SADD", "set_key", "x", "y", "z"]);
    send(&mut c, &["ZADD", "zset_key", "1.5", "m1", "2.5", "m2"]);
    send(&mut c, &["XADD", "stream_key", "*", "field1", "val1"]);
    send(&mut c, &["PFADD", "hll_key", "a", "b", "c", "d"]);
    send(&mut c, &["TSADD", "ts_key", "*", "42.5"]);
    drop(c);

    // Hard kill (no graceful shutdown).
    srv.kill();
    srv.restart();

    let mut c = srv.conn();

    // Verify every type survived.
    let resp = send(&mut c, &["GET", "str_key"]);
    assert!(resp.contains("string_value"), "string recovery: {resp}");

    let resp = send(&mut c, &["HGETALL", "hash_key"]);
    assert!(resp.contains("f1"), "hash recovery f1: {resp}");
    assert!(resp.contains("v2"), "hash recovery v2: {resp}");

    let resp = send(&mut c, &["LRANGE", "list_key", "0", "-1"]);
    assert!(resp.contains("a"), "list recovery a: {resp}");
    assert!(resp.contains("c"), "list recovery c: {resp}");

    let resp = send(&mut c, &["SMEMBERS", "set_key"]);
    assert!(resp.contains("x"), "set recovery x: {resp}");
    assert!(resp.contains("z"), "set recovery z: {resp}");

    let resp = send(&mut c, &["ZRANGE", "zset_key", "0", "-1", "WITHSCORES"]);
    assert!(resp.contains("m1"), "zset recovery m1: {resp}");
    assert!(resp.contains("2.5"), "zset recovery score: {resp}");

    let resp = send(&mut c, &["XLEN", "stream_key"]);
    assert!(resp.contains(":1"), "stream recovery: {resp}");

    let resp = send(&mut c, &["PFCOUNT", "hll_key"]);
    assert!(resp.contains(":4"), "hll recovery: {resp}");

    let resp = send(&mut c, &["TSRANGE", "ts_key", "-", "+"]);
    assert!(resp.contains("42.5"), "timeseries recovery: {resp}");
}

// ---------------------------------------------------------------------------
// Test: Writes performed inside a Lua script survive a crash (WAL-only, no
// snapshot). EVAL logs effects, not the script, so the logged KV writes replay.
// ---------------------------------------------------------------------------
#[test]
fn crash_recovery_lua_script_writes() {
    let mut srv = TestServer::start(17207);
    let mut c = srv.conn();

    // A script that performs several KV writes via redis.call. None of these go
    // through the top-level dispatch, so before the fix they were never WAL-logged.
    let script = "redis.call('SET', KEYS[1], ARGV[1]); \
         redis.call('HSET', KEYS[2], 'f', ARGV[2]); \
         redis.call('RPUSH', KEYS[3], 'a', 'b', 'c'); \
         return 'ok'";
    let resp = send(
        &mut c,
        &[
            "EVAL", script, "3", "lua_str", "lua_hash", "lua_list", "hello", "world",
        ],
    );
    assert!(resp.contains("ok"), "eval ran: {resp}");
    drop(c);

    // Hard kill before any snapshot (save_interval=0), then recover from WAL only.
    srv.kill();
    srv.restart();

    let mut c = srv.conn();
    let resp = send(&mut c, &["GET", "lua_str"]);
    assert!(resp.contains("hello"), "lua SET survived crash: {resp}");
    let resp = send(&mut c, &["HGET", "lua_hash", "f"]);
    assert!(resp.contains("world"), "lua HSET survived crash: {resp}");
    let resp = send(&mut c, &["LRANGE", "lua_list", "0", "-1"]);
    assert!(
        resp.contains("a") && resp.contains("c"),
        "lua RPUSH survived crash: {resp}"
    );
}

// ---------------------------------------------------------------------------
// Test: Crash after snapshot, before WAL truncate -- both sources recover
// ---------------------------------------------------------------------------
#[test]
fn crash_after_snapshot_before_wal_truncate() {
    let mut srv = TestServer::start(17201);
    let mut c = srv.conn();

    // Phase 1: write data and snapshot it.
    send(&mut c, &["SET", "snap_key", "snap_value"]);
    send(&mut c, &["SAVE"]);

    // Phase 2: write more data (goes only to WAL, not snapshot).
    send(&mut c, &["SET", "wal_key", "wal_value"]);
    send(&mut c, &["SET", "snap_key", "updated_value"]);
    drop(c);

    // Kill: snapshot has snap_key=snap_value, WAL has wal_key + snap_key update.
    srv.kill();
    srv.restart();

    let mut c = srv.conn();

    // snap_key should have the WAL-replayed update, not the snapshot value.
    let resp = send(&mut c, &["GET", "snap_key"]);
    assert!(
        resp.contains("updated_value"),
        "WAL should override snapshot: {resp}"
    );

    // wal_key should exist from WAL replay.
    let resp = send(&mut c, &["GET", "wal_key"]);
    assert!(resp.contains("wal_value"), "WAL-only key recovery: {resp}");
}

// ---------------------------------------------------------------------------
// Test: Crash during MULTI/EXEC -- partial transaction should not corrupt
// ---------------------------------------------------------------------------
#[test]
fn crash_during_multi_exec() {
    let mut srv = TestServer::start(17202);
    let mut c = srv.conn();

    // Write some baseline data.
    send(&mut c, &["SET", "before_tx", "safe"]);

    // Start a MULTI but kill before EXEC completes all commands.
    // Since each command in MULTI is individually WAL'd on EXEC,
    // a crash mid-EXEC means some commands are in WAL and some aren't.
    send(&mut c, &["MULTI"]);
    send(&mut c, &["SET", "tx_key1", "tx_val1"]);
    send(&mut c, &["SET", "tx_key2", "tx_val2"]);
    send(&mut c, &["SET", "tx_key3", "tx_val3"]);
    send(&mut c, &["EXEC"]);

    // Immediately kill (some WAL writes may not have been fsync'd).
    drop(c);
    srv.kill();
    srv.restart();

    let mut c = srv.conn();

    // Baseline data should always survive.
    let resp = send(&mut c, &["GET", "before_tx"]);
    assert!(resp.contains("safe"), "pre-tx data recovery: {resp}");

    // Transaction keys: they may or may not all survive depending on
    // fsync timing, but the database should NOT be corrupted. Whatever
    // keys exist should have correct values, and missing keys should
    // return nil (not garbage).
    for (key, expected) in [
        ("tx_key1", "tx_val1"),
        ("tx_key2", "tx_val2"),
        ("tx_key3", "tx_val3"),
    ] {
        let resp = send(&mut c, &["GET", key]);
        // Either the key exists with the right value, or it's nil.
        assert!(
            resp.contains(expected) || resp.contains("$-1"),
            "tx key '{key}' should be correct or nil, got: {resp}"
        );
    }
}

// ---------------------------------------------------------------------------
// Test: Multiple crash/restart cycles don't accumulate corruption
// ---------------------------------------------------------------------------
#[test]
fn repeated_crash_restart_cycles() {
    let mut srv = TestServer::start(17203);

    for cycle in 0..3 {
        let mut c = srv.conn();
        // Write unique data each cycle.
        send(
            &mut c,
            &["SET", &format!("cycle_{cycle}"), &format!("value_{cycle}")],
        );
        // Also update a shared key to test overwrite recovery.
        send(&mut c, &["SET", "shared_key", &format!("cycle_{cycle}")]);
        drop(c);
        srv.kill();
        srv.restart();
    }

    let mut c = srv.conn();

    // Shared key should have the latest cycle's value.
    let resp = send(&mut c, &["GET", "shared_key"]);
    assert!(
        resp.contains("cycle_2"),
        "shared key should have last cycle value: {resp}"
    );

    // All cycle-specific keys should exist (WAL replay across restarts).
    for cycle in 0..3 {
        let resp = send(&mut c, &["GET", &format!("cycle_{cycle}")]);
        assert!(
            resp.contains(&format!("value_{cycle}")),
            "cycle {cycle} key missing: {resp}"
        );
    }
}

// ---------------------------------------------------------------------------
// Test: Crash with mix of hot and cold data -- both survive
// ---------------------------------------------------------------------------
#[test]
fn crash_with_hot_and_cold_data() {
    let mut srv = TestServer::start(17204);
    let mut c = srv.conn();

    // Write a key that will be evicted to cold storage.
    send(&mut c, &["SET", "cold_key", "cold_value"]);
    fill_memory(&mut c, 20); // push cold_key to disk

    // Write a key that stays hot (recent, in memory).
    send(&mut c, &["SET", "hot_key", "hot_value"]);
    drop(c);

    srv.kill();
    srv.restart();

    let mut c = srv.conn();

    // Hot key should survive via WAL.
    let resp = send(&mut c, &["GET", "hot_key"]);
    assert!(resp.contains("hot_value"), "hot key recovery: {resp}");

    // Cold key should survive via disk shard.
    let resp = send(&mut c, &["GET", "cold_key"]);
    assert!(resp.contains("cold_value"), "cold key recovery: {resp}");
}

// ---------------------------------------------------------------------------
// Test: Crash after DEL -- deleted keys should NOT reappear
// ---------------------------------------------------------------------------
#[test]
fn crash_after_delete() {
    let mut srv = TestServer::start(17205);
    let mut c = srv.conn();

    send(&mut c, &["SET", "keep_me", "yes"]);
    send(&mut c, &["SET", "delete_me", "no"]);
    send(&mut c, &["DEL", "delete_me"]);
    drop(c);

    srv.kill();
    srv.restart();

    let mut c = srv.conn();

    let resp = send(&mut c, &["GET", "keep_me"]);
    assert!(resp.contains("yes"), "kept key recovery: {resp}");

    let resp = send(&mut c, &["GET", "delete_me"]);
    assert!(
        resp.contains("$-1"),
        "deleted key should NOT reappear: {resp}"
    );
}

// ---------------------------------------------------------------------------
// Test: Crash after FLUSHDB -- database should be empty after recovery
// ---------------------------------------------------------------------------
#[test]
fn crash_after_flushdb() {
    let mut srv = TestServer::start(17206);
    let mut c = srv.conn();

    send(&mut c, &["SET", "k1", "v1"]);
    send(&mut c, &["SET", "k2", "v2"]);
    send(&mut c, &["SAVE"]); // snapshot k1, k2
    send(&mut c, &["FLUSHDB"]); // WAL records the flush
    drop(c);

    srv.kill();
    srv.restart();

    let mut c = srv.conn();
    let resp = send(&mut c, &["DBSIZE"]);
    assert!(resp.contains(":0"), "FLUSHDB should survive crash: {resp}");
}

// ---------------------------------------------------------------------------
// Test: Rapid writes then immediate kill -- stress the WAL buffer
// ---------------------------------------------------------------------------
#[test]
fn rapid_writes_then_crash() {
    let mut srv = TestServer::start(17207);
    let mut c = srv.conn();

    // Pipeline 100 writes as fast as possible.
    let mut batch = Vec::new();
    for i in 0..100 {
        batch.extend_from_slice(&resp_cmd(&[
            "SET",
            &format!("rapid:{i}"),
            &format!("val:{i}"),
        ]));
    }
    c.write_all(&batch).unwrap();
    thread::sleep(Duration::from_millis(200));
    read_all(&mut c); // drain responses
    drop(c);

    srv.kill();
    srv.restart();

    let mut c = srv.conn();

    // Due to the 1s fsync window, some of the last writes may be lost.
    // But whatever survived should have correct values (no corruption).
    let mut recovered = 0;
    for i in 0..100 {
        let resp = send(&mut c, &["GET", &format!("rapid:{i}")]);
        if resp.contains(&format!("val:{i}")) {
            recovered += 1;
        } else {
            // Should be nil, not garbage.
            assert!(
                resp.contains("$-1"),
                "key rapid:{i} should be nil or correct, got: {resp}"
            );
        }
    }
    // At least some writes should have survived (WAL was flushed to OS buffer).
    assert!(
        recovered > 0,
        "at least some rapid writes should survive crash"
    );
}

// ---------------------------------------------------------------------------
// Test: WAL file with corrupted frames -- server should start and skip them
// ---------------------------------------------------------------------------
#[test]
fn corrupted_wal_frames_skipped_on_startup() {
    let mut srv = TestServer::start(17208);
    let mut c = srv.conn();

    send(&mut c, &["SET", "good_key", "good_value"]);
    // Wait for WAL flush.
    thread::sleep(Duration::from_secs(2));
    drop(c);
    srv.kill();

    // Corrupt the WAL files by appending garbage.
    let storage_dir = srv.tmpdir.join("storage");
    if storage_dir.exists() {
        for entry in std::fs::read_dir(&storage_dir).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                let wal_path = entry.path().join("wal.lux");
                if wal_path.exists() {
                    let mut f = std::fs::OpenOptions::new()
                        .append(true)
                        .open(&wal_path)
                        .unwrap();
                    // Write a valid-looking frame_len but corrupt crc + payload.
                    f.write_all(&50u32.to_le_bytes()).unwrap();
                    f.write_all(&[0xDE, 0xAD, 0xBE, 0xEF]).unwrap(); // bad crc
                    f.write_all(&[0xFF; 46]).unwrap(); // garbage payload
                    f.flush().unwrap();
                }
            }
        }
    }

    // Server should start despite corrupted WAL frames.
    srv.restart();
    let mut c = srv.conn();

    // The valid key should have been recovered (it was fsync'd before corruption).
    let resp = send(&mut c, &["GET", "good_key"]);
    assert!(
        resp.contains("good_value"),
        "valid key should survive WAL corruption: {resp}"
    );

    // Server should be functional.
    send(&mut c, &["SET", "new_key", "new_value"]);
    let resp = send(&mut c, &["GET", "new_key"]);
    assert!(
        resp.contains("new_value"),
        "server should be functional after WAL corruption: {resp}"
    );
}

// ---------------------------------------------------------------------------
// Test: Persistence error counters are exposed via INFO
// ---------------------------------------------------------------------------
#[test]
fn info_exposes_persistence_counters() {
    let srv = TestServer::start(17209);
    let mut c = srv.conn();

    let resp = send(&mut c, &["INFO"]);
    assert!(
        resp.contains("persistence_err_wal_append:0"),
        "should have WAL append counter: {resp}"
    );
    assert!(
        resp.contains("persistence_err_wal_fsync:0"),
        "should have WAL fsync counter: {resp}"
    );
    assert!(
        resp.contains("persistence_err_disk_write:0"),
        "should have disk write counter: {resp}"
    );
}

// ---------------------------------------------------------------------------
// Test: row TTL survives a snapshot + restart with ABSOLUTE deadlines.
// A future deadline is preserved (row present); a lapsed deadline stays expired
// (the row is not resurrected with a fresh TTL); the sweep index + hidden field
// round-trip so the PK is reusable afterwards.
// ---------------------------------------------------------------------------
#[test]
fn row_ttl_survives_restart() {
    let mut srv = TestServer::start(17280);
    let mut c = srv.conn();

    send(
        &mut c,
        &["TCREATE", "pres", "user_id STR PRIMARY KEY,", "room STR"],
    );
    send(
        &mut c,
        &[
            "TINSERT", "pres", "user_id", "keep", "room", "main", "TTL", "60",
        ],
    );
    send(
        &mut c,
        &[
            "TINSERT", "pres", "user_id", "gone", "room", "main", "TTL", "1",
        ],
    );
    send(&mut c, &["SAVE"]);
    drop(c);

    // Kill, let `gone`'s 1s deadline lapse during downtime, then restart.
    srv.kill();
    thread::sleep(Duration::from_millis(1300));
    srv.restart();
    let mut c = srv.conn();
    thread::sleep(Duration::from_millis(300)); // let the post-restart sweep run

    let resp = send(&mut c, &["TSELECT", "*", "FROM", "pres"]);
    assert!(
        resp.contains("keep"),
        "long-TTL row should survive restart: {resp}"
    );
    assert!(
        !resp.contains("gone"),
        "lapsed-deadline row must not be resurrected with a fresh TTL: {resp}"
    );

    // Indexes round-tripped: the expired PK is reusable.
    let resp = send(
        &mut c,
        &["TINSERT", "pres", "user_id", "gone", "room", "again"],
    );
    assert!(
        !resp.starts_with('-'),
        "expired PK reusable after restart: {resp}"
    );
}

// Row TTL recovered purely from WAL replay (no snapshot since the write). The
// WAL stores the relative command, so replay REFRESHES the deadline -- exactly
// like KV EXPIRE/SETEX. The guarantee here is: the row survives recovery and its
// TTL is still active (it expires again). Absolute deadline preservation is a
// snapshot-only guarantee, covered by `row_ttl_survives_restart`.
#[test]
fn row_ttl_active_after_wal_replay() {
    let mut srv = TestServer::start(17281);
    let mut c = srv.conn();
    send(
        &mut c,
        &["TCREATE", "pres", "user_id STR PRIMARY KEY,", "room STR"],
    );
    send(
        &mut c,
        &[
            "TINSERT", "pres", "user_id", "keep", "room", "main", "TTL", "60",
        ],
    );
    send(
        &mut c,
        &[
            "TINSERT", "pres", "user_id", "gone", "room", "main", "TTL", "2",
        ],
    );
    // NO SAVE -> recovery is from WAL replay only.
    drop(c);
    srv.kill();
    srv.restart();
    let mut c = srv.conn();

    // Both rows survive recovery (gone's TTL was refreshed by replay).
    let resp = send(&mut c, &["TSELECT", "*", "FROM", "pres"]);
    assert!(
        resp.contains("keep"),
        "long-TTL row should survive WAL replay: {resp}"
    );
    assert!(
        resp.contains("gone"),
        "short-TTL row should survive WAL replay: {resp}"
    );

    // The TTL is still active: `gone` expires on its refreshed schedule, `keep` stays.
    thread::sleep(Duration::from_millis(2600));
    let resp = send(&mut c, &["TSELECT", "*", "FROM", "pres"]);
    assert!(
        resp.contains("keep"),
        "long-TTL row should still be present: {resp}"
    );
    assert!(
        !resp.contains("gone"),
        "short-TTL row should expire after WAL replay refreshed its TTL: {resp}"
    );
}

// A row with an auto-generated UUID primary key must keep the SAME id across a
// WAL-replay recovery. The table layer logs the RESOLVED insert (explicit uuid),
// so replay reproduces the exact row instead of regenerating it. This also guards
// against double-logging: a double-apply would yield two rows and fail the
// full-output equality check below.
#[test]
fn wal_replay_preserves_autogenerated_uuid_pk() {
    let mut srv = TestServer::start(17282);
    let mut c = srv.conn();
    send(
        &mut c,
        &["TCREATE", "u", "id UUID PRIMARY KEY,", "name STR"],
    );
    send(&mut c, &["TINSERT", "u", "name", "alice"]); // auto-uuid PK, NO snapshot
    let before = send(&mut c, &["TSELECT", "*", "FROM", "u"]);
    drop(c);

    srv.kill();
    srv.restart(); // recovery is WAL replay only
    let mut c = srv.conn();
    let after = send(&mut c, &["TSELECT", "*", "FROM", "u"]);

    assert_eq!(
        before, after,
        "auto-uuid PK identity must be stable across WAL replay"
    );
}

// Snapshot TTLs are absolute deadlines (V3): a key that expires DURING downtime
// must stay gone after restart, not resurrect with a fresh TTL. Regression for
// the relative-remaining-ms snapshot bug. (SAVE truncates the WAL, so recovery
// is from the snapshot only -- the path under test.)
#[test]
fn snapshot_ttl_expires_across_downtime() {
    let mut srv = TestServer::start(17283);
    let mut c = srv.conn();

    send(&mut c, &["SET", "short", "v", "EX", "2"]); // expires during downtime
    send(&mut c, &["SET", "long", "v", "EX", "3600"]); // should survive
    send(&mut c, &["SET", "forever", "v"]); // no TTL, survives
    send(&mut c, &["SAVE"]);
    drop(c);

    srv.kill();
    thread::sleep(Duration::from_millis(2500)); // past `short`'s 2s deadline
    srv.restart();
    let mut c = srv.conn();

    let resp = send(&mut c, &["GET", "short"]);
    assert!(
        resp.contains("$-1") || resp.trim() == "$-1",
        "key past its deadline must NOT resurrect across downtime: {resp}"
    );
    let resp = send(&mut c, &["GET", "long"]);
    assert!(resp.contains("v"), "long-TTL key should survive: {resp}");
    let resp = send(&mut c, &["GET", "forever"]);
    assert!(resp.contains("v"), "no-TTL key should survive: {resp}");

    // `long`'s TTL should be ~unchanged (deadline preserved), not reset to 3600
    // from restart -- but it was only down ~2.5s, so just assert it's still set.
    let resp = send(&mut c, &["TTL", "long"]);
    assert!(
        !resp.contains(":-1"),
        "long key must still have a TTL: {resp}"
    );
}
