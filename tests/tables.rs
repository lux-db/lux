use std::io::{BufRead, BufReader, Read as IoRead, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command};
use std::time::Duration;

fn start_server() -> (u16, Child) {
    // Allocate a port and bring the server up, retrying on a fresh port if the
    // bind loses a race to another parallel test binary. alloc_port drops its
    // listener before lux rebinds the port, so under full-suite concurrency a
    // sibling can steal it in the gap -- the classic ephemeral-port TOCTOU.
    for _ in 0..10 {
        let port = alloc_port();
        let data_dir = std::env::temp_dir().join(format!(
            "lux-test-{}-{}-{}",
            std::process::id(),
            port,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&data_dir).expect("create unique test data dir");

        let mut child = Command::new(env!("CARGO_BIN_EXE_lux"))
            .env("LUX_PORT", port.to_string())
            .env("LUX_SAVE_INTERVAL", "0")
            .env("LUX_DATA_DIR", &data_dir)
            .spawn()
            .expect("failed to start lux");

        if server_ready(port, &mut child) {
            return (port, child);
        }

        // Lost the port race (lux exited on bind) -- clean up and retry.
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&data_dir);
    }
    panic!("server did not start after 10 attempts");
}

fn alloc_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral test port")
        .local_addr()
        .expect("read ephemeral test port")
        .port()
}

/// Wait until the server answers PING on `port`, or the child exits (failed to
/// bind). Confirming PONG proves we reached *our* lux, not whatever process won
/// the port race.
fn server_ready(port: u16, child: &mut Child) -> bool {
    for _ in 0..60 {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return false;
        }
        if let Ok(mut stream) = TcpStream::connect(format!("127.0.0.1:{port}")) {
            stream
                .set_read_timeout(Some(Duration::from_millis(500)))
                .ok();
            if stream.write_all(b"*1\r\n$4\r\nPING\r\n").is_ok() {
                let mut buf = [0u8; 16];
                if let Ok(n) = stream.read(&mut buf) {
                    if buf[..n].windows(4).any(|w| w == b"PONG") {
                        return true;
                    }
                }
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
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

#[test]
fn tcreate_and_tschema() {
    let (port, mut child) = start_server();
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    let r = send(
        &mut s,
        &[
            "TCREATE",
            "users",
            "name STR,",
            "age INT,",
            "email STR UNIQUE",
        ],
    );
    assert_eq!(r, "+OK", "tcreate should succeed: {}", r);

    let r = send(&mut s, &["TSCHEMA", "users"]);
    assert!(r.contains("name"), "schema should contain name: {}", r);
    assert!(r.contains("age"), "schema should contain age: {}", r);
    assert!(r.contains("email"), "schema should contain email: {}", r);
    assert!(r.contains("UNIQUE"), "schema should mention UNIQUE: {}", r);

    let r = send(&mut s, &["TCREATE", "users", "foo STR"]);
    assert!(r.starts_with('-'), "duplicate table should error: {}", r);

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn internal_table_namespace_is_protected_from_raw_kv() {
    let (port, mut child) = start_server();
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    // Create a table + row -> populates internal `_t:acct:*` keys.
    assert_eq!(send(&mut s, &["TCREATE", "acct", "name STR"]), "+OK");
    let r = send(&mut s, &["TINSERT", "acct", "name", "alice"]);
    assert!(!r.starts_with('-'), "tinsert should succeed: {}", r);

    // Enumeration must not leak the internal namespace.
    let keys = send(&mut s, &["KEYS", "*"]);
    assert!(!keys.contains("_t:"), "KEYS leaked internal keys: {}", keys);
    let keys = send(&mut s, &["KEYS", "_t:*"]);
    assert!(!keys.contains("_t:"), "KEYS _t:* leaked: {}", keys);

    // Raw KV read/write/delete of `_t:` keys is rejected (the bypass we closed).
    for cmd in [
        vec!["GET", "_t:acct:seq"],
        vec!["HGETALL", "_t:acct:schema"],
        vec!["HSET", "_t:acct:row:x", "f", "v"],
        vec!["DEL", "_t:acct:seq"],
    ] {
        let r = send(&mut s, &cmd);
        assert!(
            r.contains("reserved internal namespace"),
            "{:?} should be rejected, got: {}",
            cmd,
            r
        );
    }

    // The table API still works (it reaches `_t:` via the store, not commands).
    let r = send(&mut s, &["TSELECT", "*", "FROM", "acct"]);
    assert!(
        r.contains("alice"),
        "table API should still read the row: {}",
        r
    );

    // Pipelined attack: a forbidden read + a normal write in one send. The fast
    // batch path used to slip `_t:` reads through; the first must be rejected,
    // the second must still run, and order must be preserved.
    let mut p = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    p.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    p.write_all(
        b"*2\r\n$3\r\nGET\r\n$11\r\n_t:acct:seq\r\n*3\r\n$3\r\nSET\r\n$2\r\nk2\r\n$1\r\nv\r\n",
    )
    .unwrap();
    let mut pr = BufReader::new(p.try_clone().unwrap());
    let r1 = read_response(&mut pr);
    let r2 = read_response(&mut pr);
    assert!(
        r1.starts_with('-') && r1.contains("reserved"),
        "pipelined _t: read should be rejected: {}",
        r1
    );
    assert!(
        r2.contains("OK"),
        "pipelined normal write should run: {}",
        r2
    );

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn tinsert_and_tselect() {
    let (port, mut child) = start_server();
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    send(&mut s, &["TCREATE", "users", "name STR,", "age INT"]);

    let r = send(&mut s, &["TINSERT", "users", "name", "alice", "age", "30"]);
    assert_eq!(r, ":1");
    let r = send(&mut s, &["TINSERT", "users", "name", "bob", "age", "31"]);
    assert_eq!(r, ":2");

    let r = send(
        &mut s,
        &["TSELECT", "*", "FROM", "users", "WHERE", "id", "=", "1"],
    );
    assert!(r.contains("alice"), "should find alice: {}", r);
    assert!(r.contains("30"), "should find age 30: {}", r);
    assert!(!r.contains("bob"), "id=1 should not return bob: {}", r);

    let r = send(
        &mut s,
        &["TSELECT", "*", "FROM", "users", "WHERE", "id", "=", "2"],
    );
    assert!(r.contains("bob"), "should find bob by implicit id: {}", r);
    assert!(!r.contains("alice"), "id=2 should not return alice: {}", r);

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn tinsert_auto_increment() {
    let (port, mut child) = start_server();
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    send(&mut s, &["TCREATE", "items", "name STR"]);

    let r1 = send(&mut s, &["TINSERT", "items", "name", "a"]);
    assert_eq!(r1, ":1");

    let r2 = send(&mut s, &["TINSERT", "items", "name", "b"]);
    assert_eq!(r2, ":2");

    let r3 = send(&mut s, &["TINSERT", "items", "name", "c"]);
    assert_eq!(r3, ":3");

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn unique_constraint_violation() {
    let (port, mut child) = start_server();
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    send(&mut s, &["TCREATE", "users", "email STR UNIQUE"]);

    let r = send(&mut s, &["TINSERT", "users", "email", "a@b.com"]);
    assert_eq!(r, ":1");

    let r = send(&mut s, &["TINSERT", "users", "email", "a@b.com"]);
    assert!(r.starts_with('-'), "duplicate unique should error: {}", r);
    assert!(r.contains("unique"), "error should mention unique: {}", r);

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn foreign_key_validation() {
    let (port, mut child) = start_server();
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    send(&mut s, &["TCREATE", "users", "name STR"]);
    send(
        &mut s,
        &[
            "TCREATE",
            "posts",
            "title STR,",
            "user_id INT REFERENCES users(id)",
        ],
    );

    send(&mut s, &["TINSERT", "users", "name", "alice"]);

    let r = send(
        &mut s,
        &["TINSERT", "posts", "title", "hello", "user_id", "1"],
    );
    assert_eq!(r, ":1");

    let r = send(
        &mut s,
        &["TINSERT", "posts", "title", "bad", "user_id", "999"],
    );
    assert!(r.starts_with('-'), "invalid FK should error: {}", r);
    assert!(r.contains("foreign key"), "error should mention FK: {}", r);

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn tselect_where_equality_and_range() {
    let (port, mut child) = start_server();
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    send(&mut s, &["TCREATE", "users", "name STR,", "age INT"]);
    send(&mut s, &["TINSERT", "users", "name", "alice", "age", "25"]);
    send(&mut s, &["TINSERT", "users", "name", "bob", "age", "30"]);
    send(&mut s, &["TINSERT", "users", "name", "carol", "age", "35"]);

    let r = send(
        &mut s,
        &["TSELECT", "*", "FROM", "users", "WHERE", "name", "=", "bob"],
    );
    assert!(r.contains("bob"), "should find bob: {}", r);
    assert!(!r.contains("alice"), "should not find alice: {}", r);

    let r = send(
        &mut s,
        &["TSELECT", "*", "FROM", "users", "WHERE", "age", ">", "28"],
    );
    assert!(r.contains("bob"), "bob age 30 > 28: {}", r);
    assert!(r.contains("carol"), "carol age 35 > 28: {}", r);
    assert!(!r.contains("alice"), "alice age 25 not > 28: {}", r);

    let r = send(
        &mut s,
        &["TSELECT", "*", "FROM", "users", "WHERE", "age", ">=", "30"],
    );
    assert!(r.contains("bob"), "bob age 30 >= 30: {}", r);
    assert!(r.contains("carol"), "carol age 35 >= 30: {}", r);

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn tselect_order_by_and_limit() {
    let (port, mut child) = start_server();
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    send(&mut s, &["TCREATE", "users", "name STR,", "age INT"]);
    send(&mut s, &["TINSERT", "users", "name", "alice", "age", "25"]);
    send(&mut s, &["TINSERT", "users", "name", "bob", "age", "30"]);
    send(&mut s, &["TINSERT", "users", "name", "carol", "age", "35"]);

    let r = send(
        &mut s,
        &[
            "TSELECT", "*", "FROM", "users", "ORDER", "BY", "age", "DESC", "LIMIT", "2",
        ],
    );
    assert!(r.contains("carol"), "carol should be in top 2 desc: {}", r);
    assert!(r.contains("bob"), "bob should be in top 2 desc: {}", r);
    assert!(
        !r.contains("alice"),
        "alice should not be in top 2 desc: {}",
        r
    );

    let r = send(
        &mut s,
        &[
            "TSELECT", "*", "FROM", "users", "ORDER", "BY", "age", "ASC", "LIMIT", "1",
        ],
    );
    assert!(r.contains("alice"), "alice should be first asc: {}", r);
    assert!(!r.contains("bob"), "bob should not be in limit 1: {}", r);

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn tselect_with_join() {
    let (port, mut child) = start_server();
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    send(&mut s, &["TCREATE", "users", "name STR,", "email STR"]);
    send(&mut s, &["TCREATE", "posts", "title STR,", "user_id INT"]);

    send(
        &mut s,
        &[
            "TINSERT",
            "users",
            "name",
            "alice",
            "email",
            "alice@test.com",
        ],
    );
    send(
        &mut s,
        &["TINSERT", "posts", "title", "hello_world", "user_id", "1"],
    );

    let r = send(
        &mut s,
        &[
            "TSELECT",
            "*",
            "FROM",
            "posts",
            "p",
            "JOIN",
            "users",
            "u",
            "ON",
            "u.id",
            "=",
            "p.user_id",
        ],
    );
    assert!(
        r.contains("hello_world"),
        "should contain post title: {}",
        r
    );
    assert!(
        r.contains("alice"),
        "should contain joined user name: {}",
        r
    );

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn tselect_join_with_in_filter() {
    // Regression: a `col IN (...)` WHERE on a joined query (e.g. an injected
    // grant predicate `team_id IN (subquery)`) was evaluated as false in the
    // post-join filter, dropping every row.
    let (port, mut child) = start_server();
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    send(
        &mut s,
        &["TCREATE", "teams", "id INT PRIMARY KEY,", "name STR"],
    );
    send(
        &mut s,
        &[
            "TCREATE",
            "members",
            "id INT PRIMARY KEY,",
            "team_id INT,",
            "user_id STR",
        ],
    );
    send(&mut s, &["TINSERT", "teams", "id", "1", "name", "acme"]);
    send(
        &mut s,
        &[
            "TINSERT", "members", "id", "1", "team_id", "1", "user_id", "alice",
        ],
    );

    let base = [
        "TSELECT", "t.name", "FROM", "members", "JOIN", "teams", "t", "ON", "team_id", "=", "t.id",
        "WHERE", "team_id",
    ];

    // IN containing the row's team => row returned.
    let mut q = base.to_vec();
    q.extend(["IN", "(", "1", "2", ")"]);
    let r = send(&mut s, &q);
    assert!(r.contains("acme"), "join + IN should return the row: {r}");

    // IN excluding the row's team => empty.
    let mut q = base.to_vec();
    q.extend(["IN", "(", "99", ")"]);
    let r = send(&mut s, &q);
    assert!(
        !r.contains("acme"),
        "join + IN excluding team => empty: {r}"
    );

    // NOT IN excluding a different team => row returned.
    let mut q = base.to_vec();
    q.extend(["NOT", "IN", "(", "2", ")"]);
    let r = send(&mut s, &q);
    assert!(
        r.contains("acme"),
        "join + NOT IN should return the row: {r}"
    );

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn tselect_near_vector_field() {
    let (port, mut child) = start_server();
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    send(
        &mut s,
        &[
            "TCREATE",
            "messages",
            "id INT PRIMARY KEY,",
            "channel STR,",
            "body STR,",
            "embedding VECTOR(2)",
        ],
    );
    send(
        &mut s,
        &[
            "TINSERT",
            "messages",
            "id",
            "1",
            "channel",
            "general",
            "body",
            "hello",
            "embedding",
            "[1,0]",
        ],
    );
    send(
        &mut s,
        &[
            "TINSERT",
            "messages",
            "id",
            "2",
            "channel",
            "random",
            "body",
            "other",
            "embedding",
            "[0,1]",
        ],
    );

    let r = send(
        &mut s,
        &[
            "TSELECT",
            "id,",
            "body,",
            "_similarity",
            "FROM",
            "messages",
            "WHERE",
            "channel",
            "=",
            "general",
            "NEAR",
            "embedding",
            "[1,0]",
            "K",
            "5",
            "THRESHOLD",
            "0.9",
        ],
    );
    assert!(r.contains("hello"), "near query should find hello: {}", r);
    assert!(
        r.contains("_similarity"),
        "near query should include similarity: {}",
        r
    );
    assert!(
        !r.contains("other"),
        "where filter should still apply: {}",
        r
    );

    let r = send(&mut s, &["VCARD"]);
    assert_eq!(r, ":2");
    send(
        &mut s,
        &["TDELETE", "FROM", "messages", "WHERE", "id", "=", "1"],
    );
    let r = send(&mut s, &["VCARD"]);
    assert_eq!(r, ":1");

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn tupdate_where() {
    let (port, mut child) = start_server();
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    send(&mut s, &["TCREATE", "users", "name STR,", "age INT"]);
    send(&mut s, &["TINSERT", "users", "name", "alice", "age", "25"]);
    send(&mut s, &["TINSERT", "users", "name", "bob", "age", "25"]);

    // Single row update
    let r = send(
        &mut s,
        &[
            "TUPDATE", "users", "SET", "age", "26", "WHERE", "name", "=", "alice",
        ],
    );
    assert_eq!(r, ":1", "should update 1 row: {}", r);

    let r = send(
        &mut s,
        &[
            "TSELECT", "*", "FROM", "users", "WHERE", "name", "=", "alice",
        ],
    );
    assert!(r.contains("26"), "alice age should be 26: {}", r);

    // Bulk update
    let r = send(
        &mut s,
        &[
            "TUPDATE", "users", "SET", "age", "99", "WHERE", "age", "=", "25",
        ],
    );
    assert_eq!(r, ":1", "should update 1 row (bob): {}", r);

    // Type error
    let r = send(
        &mut s,
        &[
            "TUPDATE",
            "users",
            "SET",
            "age",
            "notanumber",
            "WHERE",
            "name",
            "=",
            "alice",
        ],
    );
    assert!(r.starts_with('-'), "type violation should error: {}", r);

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn tdelete_with_fk_check() {
    let (port, mut child) = start_server();
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    send(&mut s, &["TCREATE", "users", "name STR"]);
    send(
        &mut s,
        &[
            "TCREATE",
            "posts",
            "title STR,",
            "user_id INT REFERENCES users(id)",
        ],
    );
    send(&mut s, &["TINSERT", "users", "name", "alice"]);
    send(
        &mut s,
        &["TINSERT", "posts", "title", "hello", "user_id", "1"],
    );

    // Should be blocked by FK constraint
    let r = send(
        &mut s,
        &["TDELETE", "FROM", "users", "WHERE", "id", "=", "1"],
    );
    assert!(
        r.starts_with('-'),
        "should not delete referenced row: {}",
        r
    );
    assert!(
        r.contains("referenced"),
        "error should mention reference: {}",
        r
    );

    // Delete child first
    let r = send(
        &mut s,
        &["TDELETE", "FROM", "posts", "WHERE", "id", "=", "1"],
    );
    assert_eq!(r, ":1", "should delete post: {}", r);

    // Now parent can be deleted
    let r = send(
        &mut s,
        &["TDELETE", "FROM", "users", "WHERE", "id", "=", "1"],
    );
    assert_eq!(r, ":1", "should delete user: {}", r);

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn tdrop_table() {
    let (port, mut child) = start_server();
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    send(&mut s, &["TCREATE", "temp", "x STR"]);
    send(&mut s, &["TINSERT", "temp", "x", "hello"]);

    let r = send(&mut s, &["TDROP", "temp"]);
    assert_eq!(r, "+OK");

    let r = send(&mut s, &["TSELECT", "*", "FROM", "temp"]);
    assert!(
        r.starts_with('-'),
        "table should not exist after drop: {}",
        r
    );

    let r = send(&mut s, &["TLIST"]);
    assert!(!r.contains("temp"), "temp should not appear in list: {}", r);

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn tcount_rows() {
    let (port, mut child) = start_server();
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    send(&mut s, &["TCREATE", "items", "name STR"]);

    let r = send(&mut s, &["TCOUNT", "items"]);
    assert_eq!(r, ":0");

    send(&mut s, &["TINSERT", "items", "name", "a"]);
    send(&mut s, &["TINSERT", "items", "name", "b"]);

    let r = send(&mut s, &["TCOUNT", "items"]);
    assert_eq!(r, ":2");

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn tlist_tables() {
    let (port, mut child) = start_server();
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    let r = send(&mut s, &["TLIST"]);
    assert_eq!(r, "*0 []");

    send(&mut s, &["TCREATE", "users", "name STR"]);
    send(&mut s, &["TCREATE", "posts", "title STR"]);

    let r = send(&mut s, &["TLIST"]);
    assert!(r.contains("users"), "should list users: {}", r);
    assert!(r.contains("posts"), "should list posts: {}", r);

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn type_validation() {
    let (port, mut child) = start_server();
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    send(&mut s, &["TCREATE", "data", "score INT,", "rating FLOAT"]);

    let r = send(&mut s, &["TINSERT", "data", "score", "notanumber"]);
    assert!(r.starts_with('-'), "string into int should error: {}", r);

    let r = send(&mut s, &["TINSERT", "data", "rating", "notafloat"]);
    assert!(r.starts_with('-'), "string into float should error: {}", r);

    let r = send(
        &mut s,
        &["TINSERT", "data", "score", "42", "rating", "3.14"],
    );
    assert_eq!(r, ":1");

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn talter_add_column_backfill() {
    let (port, mut child) = start_server();
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    send(&mut s, &["TCREATE", "users", "name STR"]);
    send(&mut s, &["TINSERT", "users", "name", "alice"]);
    send(&mut s, &["TINSERT", "users", "name", "bob"]);

    // Add nullable column - should succeed and backfill with null
    let r = send(&mut s, &["TALTER", "users", "ADD", "age INT"]);
    assert_eq!(r, "+OK", "should add nullable column: {}", r);

    // Add column with DEFAULT - should backfill existing rows
    let r = send(
        &mut s,
        &["TALTER", "users", "ADD", "active BOOL DEFAULT true"],
    );
    assert_eq!(r, "+OK", "should add column with default: {}", r);

    let r = send(
        &mut s,
        &[
            "TSELECT", "*", "FROM", "users", "WHERE", "name", "=", "alice",
        ],
    );
    assert!(
        r.contains("true"),
        "alice should have active=true from default: {}",
        r
    );

    // Add NOT NULL column without default on non-empty table - should error
    let r = send(&mut s, &["TALTER", "users", "ADD", "email STR NOT NULL"]);
    assert!(
        r.starts_with('-'),
        "NOT NULL without DEFAULT on non-empty table should error: {}",
        r
    );

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn on_delete_cascade() {
    let (port, mut child) = start_server();
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    send(&mut s, &["TCREATE", "users", "name STR"]);
    send(
        &mut s,
        &[
            "TCREATE",
            "posts",
            "title STR,",
            "user_id INT REFERENCES users(id) ON DELETE CASCADE",
        ],
    );

    send(&mut s, &["TINSERT", "users", "name", "alice"]);
    send(&mut s, &["TINSERT", "users", "name", "bob"]);
    send(
        &mut s,
        &["TINSERT", "posts", "title", "post1", "user_id", "1"],
    );
    send(
        &mut s,
        &["TINSERT", "posts", "title", "post2", "user_id", "1"],
    );
    send(
        &mut s,
        &["TINSERT", "posts", "title", "post3", "user_id", "2"],
    );

    // Deleting alice (id=1) should cascade delete post1, post2 but not post3
    let r = send(
        &mut s,
        &["TDELETE", "FROM", "users", "WHERE", "id", "=", "1"],
    );
    assert_eq!(r, ":1", "should delete 1 user: {}", r);

    let r = send(&mut s, &["TCOUNT", "posts"]);
    assert_eq!(
        r, ":1",
        "cascade should have deleted 2 posts, leaving 1: {}",
        r
    );

    let r = send(&mut s, &["TSELECT", "*", "FROM", "posts"]);
    assert!(r.contains("post3"), "bob's post should remain: {}", r);
    assert!(!r.contains("post1"), "alice post1 should be gone: {}", r);
    assert!(!r.contains("post2"), "alice post2 should be gone: {}", r);

    child.kill().ok();
    child.wait().ok();
}

// AUDIT PROBE: ON DELETE CASCADE must work for a non-INT (UUID) foreign key. The
// cascade scan decodes child FK bytes as FieldType::Int regardless of the column's
// real type (tables/mod.rs:2469), so a UUID FK never matches -> cascade is a no-op
// and children are orphaned (referential-integrity corruption).
#[test]
#[ignore = "FK cascade/restrict/set-null broken for non-INT FKs until fixed"]
fn on_delete_cascade_uuid_fk() {
    let (port, mut child) = start_server();
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    send(
        &mut s,
        &["TCREATE", "u", "id UUID PRIMARY KEY,", "name STR"],
    );
    send(
        &mut s,
        &[
            "TCREATE",
            "p",
            "id UUID PRIMARY KEY,",
            "author UUID REFERENCES u(id) ON DELETE CASCADE",
        ],
    );
    send(
        &mut s,
        &[
            "TINSERT",
            "u",
            "id",
            "11111111-1111-7111-8111-111111111111",
            "name",
            "a",
        ],
    );
    send(
        &mut s,
        &[
            "TINSERT",
            "p",
            "id",
            "22222222-2222-7222-8222-222222222222",
            "author",
            "11111111-1111-7111-8111-111111111111",
        ],
    );

    send(
        &mut s,
        &[
            "TDELETE",
            "FROM",
            "u",
            "WHERE",
            "id",
            "=",
            "11111111-1111-7111-8111-111111111111",
        ],
    );

    // The child post must be cascade-deleted with its parent.
    let r = send(&mut s, &["TCOUNT", "p"]);
    assert_eq!(
        r, ":0",
        "UUID FK cascade must delete the child (orphaned if not): {r}"
    );

    child.kill().ok();
    child.wait().ok();
}

// AUDIT PROBE: SMOVE must not remove the member from the source when the
// destination is the wrong type. The store removes from src BEFORE validating dst
// (store/mod.rs:3858+), so a WRONGTYPE dst loses the element from src entirely.
#[test]
#[ignore = "SMOVE loses source member on wrong-type dst until fixed"]
fn smove_wrong_type_dst_preserves_source() {
    let (port, mut child) = start_server();
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    send(&mut s, &["SET", "dstk", "hello"]); // dst is a string, not a set
    send(&mut s, &["SADD", "srck", "m"]);
    let mv = send(&mut s, &["SMOVE", "srck", "dstk", "m"]); // should error, no mutation
    assert!(
        mv.to_ascii_uppercase().contains("WRONGTYPE") || mv.starts_with('-'),
        "SMOVE to wrong-type dst should error: {mv:?}"
    );
    let members = send(&mut s, &["SMEMBERS", "srck"]);
    assert!(
        members.contains('m'),
        "member must remain in source after a failed SMOVE: {members:?}"
    );

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn on_delete_set_null() {
    let (port, mut child) = start_server();
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    send(&mut s, &["TCREATE", "teams", "name STR"]);
    send(
        &mut s,
        &[
            "TCREATE",
            "members",
            "name STR,",
            "team_id INT REFERENCES teams(id) ON DELETE SET NULL",
        ],
    );

    send(&mut s, &["TINSERT", "teams", "name", "engineering"]);
    send(
        &mut s,
        &["TINSERT", "members", "name", "alice", "team_id", "1"],
    );
    send(
        &mut s,
        &["TINSERT", "members", "name", "bob", "team_id", "1"],
    );

    // Delete the team - should set null on both members
    let r = send(
        &mut s,
        &["TDELETE", "FROM", "teams", "WHERE", "id", "=", "1"],
    );
    assert_eq!(r, ":1", "should delete team: {}", r);

    // Members should still exist
    let r = send(&mut s, &["TCOUNT", "members"]);
    assert_eq!(r, ":2", "both members should still exist: {}", r);

    // team_id should be null/absent on alice's row
    let r = send(
        &mut s,
        &[
            "TSELECT", "*", "FROM", "members", "WHERE", "name", "=", "alice",
        ],
    );
    assert!(r.contains("alice"), "alice should still exist: {}", r);
    assert!(
        !r.contains("team_id"),
        "alice team_id should be null/absent: {}",
        r
    );

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn talter_drop_column() {
    let (port, mut child) = start_server();
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    send(
        &mut s,
        &["TCREATE", "users", "name STR,", "age INT,", "email STR"],
    );
    send(
        &mut s,
        &[
            "TINSERT",
            "users",
            "name",
            "alice",
            "age",
            "30",
            "email",
            "alice@test.com",
        ],
    );
    send(
        &mut s,
        &[
            "TINSERT",
            "users",
            "name",
            "bob",
            "age",
            "25",
            "email",
            "bob@test.com",
        ],
    );

    let r = send(&mut s, &["TALTER", "users", "DROP", "email"]);
    assert_eq!(r, "+OK", "drop column should succeed: {}", r);

    // Schema should no longer have email
    let r = send(&mut s, &["TSCHEMA", "users"]);
    assert!(
        !r.contains("email"),
        "schema should not have email after drop: {}",
        r
    );
    assert!(r.contains("name"), "schema should still have name: {}", r);

    // Existing rows should not have email field
    let r = send(&mut s, &["TSELECT", "*", "FROM", "users"]);
    assert!(
        !r.contains("alice@test.com"),
        "email value should be gone: {}",
        r
    );
    assert!(r.contains("alice"), "name should still be there: {}", r);

    // New inserts work without email
    let r = send(&mut s, &["TINSERT", "users", "name", "carol", "age", "28"]);
    assert_eq!(r, ":3", "insert after drop should work: {}", r);

    // Drop non-existent column should error
    let r = send(&mut s, &["TALTER", "users", "DROP", "nonexistent"]);
    assert!(
        r.starts_with('-'),
        "drop non-existent column should error: {}",
        r
    );

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn talter_cache_consistency() {
    let (port, mut child) = start_server();
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    send(&mut s, &["TCREATE", "items", "name STR"]);
    send(&mut s, &["TINSERT", "items", "name", "widget"]);

    // Alter to add a column with default - uses multi-token field spec
    let r = send(
        &mut s,
        &["TALTER", "items", "ADD", "price FLOAT DEFAULT 9.99"],
    );
    assert_eq!(r, "+OK", "alter should succeed: {}", r);

    // Insert after alter uses the new column
    let r = send(
        &mut s,
        &["TINSERT", "items", "name", "gadget", "price", "19.99"],
    );
    assert_eq!(r, ":2", "insert after alter should work: {}", r);

    // Pre-alter row should have the default value backfilled
    let r = send(
        &mut s,
        &[
            "TSELECT", "*", "FROM", "items", "WHERE", "name", "=", "widget",
        ],
    );
    assert!(
        r.contains("9.99"),
        "pre-alter row should have default price: {}",
        r
    );

    // Post-alter row has explicit value
    let r = send(
        &mut s,
        &[
            "TSELECT", "*", "FROM", "items", "WHERE", "name", "=", "gadget",
        ],
    );
    assert!(
        r.contains("19.99"),
        "post-alter row should have explicit price: {}",
        r
    );

    // Second alter - immediately insert to verify cache was re-invalidated
    let r = send(
        &mut s,
        &["TALTER", "items", "ADD", "active BOOL DEFAULT true"],
    );
    assert_eq!(r, "+OK", "second alter should succeed: {}", r);
    let r = send(
        &mut s,
        &[
            "TINSERT",
            "items",
            "name",
            "thingamajig",
            "price",
            "4.99",
            "active",
            "false",
        ],
    );
    assert_eq!(r, ":3", "insert after second alter should work: {}", r);
    let r = send(
        &mut s,
        &[
            "TSELECT",
            "*",
            "FROM",
            "items",
            "WHERE",
            "name",
            "=",
            "thingamajig",
        ],
    );
    assert!(
        r.contains("false"),
        "thingamajig should have active=false: {}",
        r
    );

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn tupdate_unique_constraint() {
    let (port, mut child) = start_server();
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    send(
        &mut s,
        &["TCREATE", "users", "email STR UNIQUE,", "name STR"],
    );
    send(
        &mut s,
        &[
            "TINSERT",
            "users",
            "email",
            "alice@test.com",
            "name",
            "alice",
        ],
    );
    send(
        &mut s,
        &["TINSERT", "users", "email", "bob@test.com", "name", "bob"],
    );

    // Updating to a value already held by another row should error
    let r = send(
        &mut s,
        &[
            "TUPDATE",
            "users",
            "SET",
            "email",
            "alice@test.com",
            "WHERE",
            "name",
            "=",
            "bob",
        ],
    );
    assert!(
        r.starts_with('-'),
        "update to duplicate unique value should error: {}",
        r
    );
    assert!(
        r.to_lowercase().contains("unique"),
        "error should mention unique: {}",
        r
    );

    // Verify bob's email was NOT changed
    let r = send(
        &mut s,
        &["TSELECT", "*", "FROM", "users", "WHERE", "name", "=", "bob"],
    );
    assert!(
        r.contains("bob@test.com"),
        "bob email should be unchanged: {}",
        r
    );

    // Updating to a new unique value should succeed
    let r = send(
        &mut s,
        &[
            "TUPDATE",
            "users",
            "SET",
            "email",
            "bobby@test.com",
            "WHERE",
            "name",
            "=",
            "bob",
        ],
    );
    assert_eq!(r, ":1", "update to new unique value should succeed: {}", r);

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn tdelete_tupdate_no_matches() {
    let (port, mut child) = start_server();
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    send(&mut s, &["TCREATE", "users", "name STR,", "age INT"]);
    send(&mut s, &["TINSERT", "users", "name", "alice", "age", "30"]);

    // Delete with no matching rows should return :0, not an error
    let r = send(
        &mut s,
        &["TDELETE", "FROM", "users", "WHERE", "id", "=", "9999"],
    );
    assert_eq!(r, ":0", "delete with no matches should return 0: {}", r);

    // Update with no matching rows should return :0, not an error
    let r = send(
        &mut s,
        &[
            "TUPDATE", "users", "SET", "age", "99", "WHERE", "name", "=", "nobody",
        ],
    );
    assert_eq!(r, ":0", "update with no matches should return 0: {}", r);

    // Original row untouched
    let r = send(&mut s, &["TCOUNT", "users"]);
    assert_eq!(r, ":1", "count should still be 1: {}", r);

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn tselect_comparison_operators() {
    let (port, mut child) = start_server();
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    send(&mut s, &["TCREATE", "items", "name STR,", "score INT"]);
    send(&mut s, &["TINSERT", "items", "name", "a", "score", "10"]);
    send(&mut s, &["TINSERT", "items", "name", "b", "score", "20"]);
    send(&mut s, &["TINSERT", "items", "name", "c", "score", "30"]);
    send(&mut s, &["TINSERT", "items", "name", "d", "score", "20"]);

    // != operator - excludes score=20 (b and d), includes a and c
    let r = send(
        &mut s,
        &[
            "TSELECT", "*", "FROM", "items", "WHERE", "score", "!=", "20",
        ],
    );
    // RESP response starts with *N where N is row count
    assert!(
        r.starts_with("*2"),
        "!= 20 should return exactly 2 rows: {}",
        r
    );
    assert!(r.contains("$a"), "!= should include a: {}", r);
    assert!(r.contains("$c"), "!= should include c: {}", r);
    assert!(!r.contains("$b"), "!= should exclude b: {}", r);
    assert!(!r.contains("$d"), "!= should exclude d: {}", r);

    // < operator - only a (score=10)
    let r = send(
        &mut s,
        &["TSELECT", "*", "FROM", "items", "WHERE", "score", "<", "20"],
    );
    assert!(
        r.starts_with("*1"),
        "< 20 should return exactly 1 row: {}",
        r
    );
    assert!(r.contains("$a"), "< 20 should include a: {}", r);

    // <= operator - a (10), b (20), d (20) = 3 rows
    let r = send(
        &mut s,
        &[
            "TSELECT", "*", "FROM", "items", "WHERE", "score", "<=", "20",
        ],
    );
    assert!(
        r.starts_with("*3"),
        "<= 20 should return 3 rows (a, b, d): {}",
        r
    );

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn tselect_offset_without_limit() {
    let (port, mut child) = start_server();
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    send(&mut s, &["TCREATE", "items", "name STR"]);
    send(&mut s, &["TINSERT", "items", "name", "alpha"]);
    send(&mut s, &["TINSERT", "items", "name", "beta"]);
    send(&mut s, &["TINSERT", "items", "name", "gamma"]);
    send(&mut s, &["TINSERT", "items", "name", "delta"]);
    send(&mut s, &["TINSERT", "items", "name", "epsilon"]);

    // OFFSET 2 without LIMIT should skip first 2, return remaining 3
    let r = send(
        &mut s,
        &[
            "TSELECT", "*", "FROM", "items", "ORDER", "BY", "id", "OFFSET", "2",
        ],
    );
    assert!(!r.contains("alpha"), "offset 2 should skip alpha: {}", r);
    assert!(!r.contains("beta"), "offset 2 should skip beta: {}", r);
    assert!(r.contains("gamma"), "offset 2 should include gamma: {}", r);
    assert!(r.contains("delta"), "offset 2 should include delta: {}", r);
    assert!(
        r.contains("epsilon"),
        "offset 2 should include epsilon: {}",
        r
    );

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn tselect_error_cases() {
    let (port, mut child) = start_server();
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    // TSELECT on non-existent table
    let r = send(&mut s, &["TSELECT", "*", "FROM", "ghost"]);
    assert!(
        r.starts_with('-'),
        "tselect on non-existent table should error: {}",
        r
    );

    // TCOUNT on non-existent table
    let r = send(&mut s, &["TCOUNT", "ghost"]);
    assert!(
        r.starts_with('-'),
        "tcount on non-existent table should error: {}",
        r
    );

    // TSCHEMA on non-existent table
    let r = send(&mut s, &["TSCHEMA", "ghost"]);
    assert!(
        r.starts_with('-'),
        "tschema on non-existent table should error: {}",
        r
    );

    // TINSERT with unknown column name
    send(&mut s, &["TCREATE", "users", "name STR"]);
    let r = send(
        &mut s,
        &["TINSERT", "users", "name", "alice", "nonexistent", "value"],
    );
    assert!(
        r.starts_with('-'),
        "insert with unknown column should error: {}",
        r
    );

    // TCREATE with FK referencing a non-existent table
    let r = send(
        &mut s,
        &[
            "TCREATE",
            "posts",
            "title STR,",
            "user_id INT REFERENCES ghost(id)",
        ],
    );
    assert!(
        r.starts_with('-'),
        "fk to non-existent table should error: {}",
        r
    );

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn tselect_aggregates_integration() {
    let (port, mut child) = start_server();
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    send(&mut s, &["TCREATE", "scores", "name STR,", "val INT"]);
    send(&mut s, &["TINSERT", "scores", "name", "a", "val", "10"]);
    send(&mut s, &["TINSERT", "scores", "name", "b", "val", "20"]);
    send(&mut s, &["TINSERT", "scores", "name", "c", "val", "30"]);

    // COUNT(*)
    let r = send(&mut s, &["TSELECT", "COUNT(*)", "FROM", "scores"]);
    assert!(r.contains("3"), "COUNT(*) should return 3: {}", r);

    // COUNT(*) with WHERE
    let r = send(
        &mut s,
        &[
            "TSELECT", "COUNT(*)", "FROM", "scores", "WHERE", "val", ">", "15",
        ],
    );
    assert!(
        r.contains("2"),
        "COUNT(*) WHERE val > 15 should return 2: {}",
        r
    );

    // SUM
    let r = send(&mut s, &["TSELECT", "SUM(val)", "FROM", "scores"]);
    assert!(r.contains("60"), "SUM(val) should return 60: {}", r);

    // AVG
    let r = send(&mut s, &["TSELECT", "AVG(val)", "FROM", "scores"]);
    assert!(r.contains("20"), "AVG(val) should return 20: {}", r);

    // MIN
    let r = send(&mut s, &["TSELECT", "MIN(val)", "FROM", "scores"]);
    assert!(r.contains("10"), "MIN(val) should return 10: {}", r);

    // MAX
    let r = send(&mut s, &["TSELECT", "MAX(val)", "FROM", "scores"]);
    assert!(r.contains("30"), "MAX(val) should return 30: {}", r);

    child.kill().ok();
    child.wait().ok();
}

// --- Row TTL ---------------------------------------------------------------

#[test]
fn ttl_row_expires_and_frees_pk() {
    let (port, mut child) = start_server();
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    assert_eq!(
        send(
            &mut s,
            &["TCREATE", "pres", "user_id STR PRIMARY KEY,", "room STR"]
        ),
        "+OK"
    );
    let r = send(
        &mut s,
        &[
            "TINSERT", "pres", "user_id", "u1", "room", "main", "TTL", "1",
        ],
    );
    assert!(!r.starts_with('-'), "tinsert ttl: {}", r);

    let r = send(&mut s, &["TSELECT", "*", "FROM", "pres"]);
    assert!(
        r.contains("u1"),
        "row should be present before expiry: {}",
        r
    );
    // hidden ttl field must not leak into the projection
    assert!(!r.contains("ttl"), "hidden ttl field leaked: {}", r);

    std::thread::sleep(Duration::from_millis(1400));

    let r = send(&mut s, &["TSELECT", "*", "FROM", "pres"]);
    assert!(
        r.starts_with("*0"),
        "table should be empty after expiry: {}",
        r
    );

    // No orphan: the PK is reusable and a fresh insert (no TTL) survives.
    let r = send(
        &mut s,
        &["TINSERT", "pres", "user_id", "u1", "room", "again"],
    );
    assert!(
        !r.starts_with('-'),
        "PK should be reusable after expiry: {}",
        r
    );
    let r = send(&mut s, &["TSELECT", "*", "FROM", "pres"]);
    assert!(
        r.contains("again"),
        "reinserted row should be present: {}",
        r
    );

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn ttl_bare_update_keeps_deadline() {
    let (port, mut child) = start_server();
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    assert_eq!(
        send(
            &mut s,
            &["TCREATE", "pres", "user_id STR PRIMARY KEY,", "room STR"]
        ),
        "+OK"
    );
    send(
        &mut s,
        &[
            "TINSERT", "pres", "user_id", "u1", "room", "main", "TTL", "1",
        ],
    );
    // A bare update (no TTL) must leave the deadline untouched.
    let r = send(
        &mut s,
        &[
            "TUPDATE", "pres", "SET", "room", "moved", "WHERE", "user_id", "=", "u1",
        ],
    );
    assert!(!r.starts_with('-'), "tupdate: {}", r);

    std::thread::sleep(Duration::from_millis(1400));
    let r = send(&mut s, &["TSELECT", "*", "FROM", "pres"]);
    assert!(
        r.starts_with("*0"),
        "row should still expire after a bare update: {}",
        r
    );

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn ttl_zero_clears_deadline() {
    let (port, mut child) = start_server();
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    assert_eq!(
        send(
            &mut s,
            &["TCREATE", "pres", "user_id STR PRIMARY KEY,", "room STR"]
        ),
        "+OK"
    );
    send(
        &mut s,
        &[
            "TINSERT", "pres", "user_id", "u1", "room", "main", "TTL", "1",
        ],
    );
    // TTL 0 clears the deadline -> the row becomes permanent.
    let r = send(
        &mut s,
        &[
            "TUPDATE", "pres", "SET", "room", "kept", "WHERE", "user_id", "=", "u1", "TTL", "0",
        ],
    );
    assert!(!r.starts_with('-'), "tupdate ttl 0: {}", r);

    std::thread::sleep(Duration::from_millis(1400));
    let r = send(&mut s, &["TSELECT", "*", "FROM", "pres"]);
    assert!(
        r.contains("kept"),
        "row should survive after TTL 0 cleared it: {}",
        r
    );

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn ttl_upsert_refresh_keeps_alive() {
    let (port, mut child) = start_server();
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    assert_eq!(
        send(
            &mut s,
            &["TCREATE", "pres", "user_id STR PRIMARY KEY,", "x STR"]
        ),
        "+OK"
    );
    // Re-upsert with TTL faster than it expires -> the row stays alive.
    for i in 0..6 {
        let r = send(
            &mut s,
            &[
                "TUPSERT",
                "pres",
                "user_id",
                "u1",
                "x",
                &i.to_string(),
                "ON",
                "CONFLICT",
                "user_id",
                "TTL",
                "1",
            ],
        );
        assert!(!r.starts_with('-'), "tupsert refresh: {}", r);
        std::thread::sleep(Duration::from_millis(300));
    }
    let r = send(&mut s, &["TSELECT", "*", "FROM", "pres"]);
    assert!(
        r.contains("u1"),
        "refreshed row should still be alive: {}",
        r
    );

    // Stop refreshing -> it expires.
    std::thread::sleep(Duration::from_millis(1400));
    let r = send(&mut s, &["TSELECT", "*", "FROM", "pres"]);
    assert!(
        r.starts_with("*0"),
        "row should expire once refresh stops: {}",
        r
    );

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn ttl_table_default_applies() {
    let (port, mut child) = start_server();
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    // WITH TTL gives every row a default expiry.
    assert_eq!(
        send(
            &mut s,
            &[
                "TCREATE",
                "pres",
                "user_id STR PRIMARY KEY,",
                "room STR",
                "WITH",
                "TTL",
                "1"
            ]
        ),
        "+OK"
    );
    // No explicit TTL -> inherits the table default.
    let r = send(
        &mut s,
        &["TINSERT", "pres", "user_id", "u1", "room", "main"],
    );
    assert!(!r.starts_with('-'), "tinsert: {}", r);
    std::thread::sleep(Duration::from_millis(1400));
    let r = send(&mut s, &["TSELECT", "*", "FROM", "pres"]);
    assert!(r.starts_with("*0"), "default-TTL row should expire: {}", r);

    // Explicit TTL 0 opts a row out of the table default -> permanent.
    let r = send(
        &mut s,
        &[
            "TINSERT", "pres", "user_id", "u2", "room", "main", "TTL", "0",
        ],
    );
    assert!(!r.starts_with('-'), "tinsert ttl 0: {}", r);
    std::thread::sleep(Duration::from_millis(1400));
    let r = send(&mut s, &["TSELECT", "*", "FROM", "pres"]);
    assert!(
        r.contains("u2"),
        "TTL 0 should override the table default: {}",
        r
    );

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn ttl_unique_value_reusable_after_expiry() {
    let (port, mut child) = start_server();
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    assert_eq!(
        send(
            &mut s,
            &["TCREATE", "u", "id STR PRIMARY KEY,", "email STR UNIQUE"]
        ),
        "+OK"
    );
    let r = send(
        &mut s,
        &["TINSERT", "u", "id", "a1", "email", "x@y.com", "TTL", "1"],
    );
    assert!(!r.starts_with('-'), "insert: {}", r);
    std::thread::sleep(Duration::from_millis(1400));

    // A different PK can reuse the expired row's UNIQUE value (its unique-index
    // entry was purged with the row).
    let r = send(&mut s, &["TINSERT", "u", "id", "a2", "email", "x@y.com"]);
    assert!(
        !r.starts_with('-'),
        "unique value should be reusable after expiry: {}",
        r
    );
    let r = send(&mut s, &["TSELECT", "*", "FROM", "u"]);
    assert!(r.contains("a2"), "reinserted row present: {}", r);

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn raw_kv_cannot_mutate_auth_internals() {
    let (port, mut child) = start_server();
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    // Raw KV mutation of Lux Auth internal keys must be rejected (defense-in-depth
    // against bypassing the auth API via raw HSET/DEL on _t:auth.*).
    let r = send(
        &mut s,
        &["HSET", "_t:auth.users:row:x", "encrypted_password", "pwned"],
    );
    assert!(
        r.starts_with('-'),
        "raw HSET of _t:auth.* must be blocked: {}",
        r
    );
    let r = send(&mut s, &["DEL", "_t:auth.users:row:x"]);
    assert!(
        r.starts_with('-'),
        "raw DEL of _t:auth.* must be blocked: {}",
        r
    );
    // Normal keys are unaffected.
    let r = send(&mut s, &["SET", "normal_key", "ok"]);
    assert!(!r.starts_with('-'), "normal key write should work: {}", r);

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn ttl_table_drop_clears_stale_deadline() {
    let (port, mut child) = start_server();
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    // Row with a 1s TTL, then drop the table.
    assert_eq!(
        send(
            &mut s,
            &[
                "TCREATE",
                "pres",
                "user_id STR PRIMARY KEY,",
                "room STR",
                "WITH",
                "TTL",
                "1"
            ]
        ),
        "+OK"
    );
    send(&mut s, &["TINSERT", "pres", "user_id", "u1", "room", "a"]);
    assert_eq!(send(&mut s, &["TDROP", "pres"]), "+OK");

    // Recreate WITHOUT a TTL and reinsert the same PK (permanent row).
    assert_eq!(
        send(
            &mut s,
            &["TCREATE", "pres", "user_id STR PRIMARY KEY,", "room STR"]
        ),
        "+OK"
    );
    send(&mut s, &["TINSERT", "pres", "user_id", "u1", "room", "b"]);

    // Past the dropped table's original deadline: the re-created row must survive
    // (the stale _t:_ttl member was cleared on drop).
    std::thread::sleep(Duration::from_millis(1400));
    let r = send(&mut s, &["TSELECT", "*", "FROM", "pres"]);
    assert!(
        r.contains("u1") && r.contains("b"),
        "re-created row must survive a dropped table's stale TTL: {}",
        r
    );

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn vector_index_cleaned_on_delete_and_drop() {
    let (port, mut child) = start_server();
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    let near = |s: &mut TcpStream| {
        send(
            s,
            &[
                "TSELECT",
                "id",
                "FROM",
                "docs",
                "NEAR",
                "emb",
                "[1,0]",
                "K",
                "10",
                "THRESHOLD",
                "0.1",
            ],
        )
    };

    send(
        &mut s,
        &["TCREATE", "docs", "id INT PRIMARY KEY,", "emb VECTOR(2)"],
    );
    send(&mut s, &["TINSERT", "docs", "id", "1", "emb", "[1,0]"]);
    send(&mut s, &["TINSERT", "docs", "id", "2", "emb", "[0,1]"]);

    // Delete row 1: it must be gone from the table AND from vector search.
    send(
        &mut s,
        &["TDELETE", "FROM", "docs", "WHERE", "id", "=", "1"],
    );
    let gone = send(
        &mut s,
        &["TSELECT", "*", "FROM", "docs", "WHERE", "id", "=", "1"],
    );
    assert!(gone.starts_with("*0"), "row 1 should be deleted: {}", gone);

    // Drop the table, then recreate it empty. A leaked vector index from the old
    // table would make a NEAR search on the fresh empty table return ghosts.
    send(&mut s, &["TDROP", "docs"]);
    send(
        &mut s,
        &["TCREATE", "docs", "id INT PRIMARY KEY,", "emb VECTOR(2)"],
    );
    let r = near(&mut s);
    assert!(
        r.starts_with("*0"),
        "fresh table after drop must have no orphaned vectors: {}",
        r
    );

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn unique_constraint_still_correct_after_writes() {
    let (port, mut child) = start_server();
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    send(
        &mut s,
        &["TCREATE", "u", "id INT PRIMARY KEY,", "email STR UNIQUE"],
    );
    let r = send(&mut s, &["TINSERT", "u", "id", "1", "email", "a@x.com"]);
    assert!(!r.starts_with('-'), "first insert ok: {}", r);

    // A genuine duplicate must still be rejected.
    let r = send(&mut s, &["TINSERT", "u", "id", "2", "email", "a@x.com"]);
    assert!(
        r.starts_with('-'),
        "duplicate email must be rejected: {}",
        r
    );

    // After deleting the holder, the value is free again (self-heals).
    send(&mut s, &["TDELETE", "FROM", "u", "WHERE", "id", "=", "1"]);
    let r = send(&mut s, &["TINSERT", "u", "id", "3", "email", "a@x.com"]);
    assert!(
        !r.starts_with('-'),
        "email reusable after holder deleted: {}",
        r
    );

    // And that new holder is now authoritative (rejects another dup).
    let r = send(&mut s, &["TINSERT", "u", "id", "4", "email", "a@x.com"]);
    assert!(r.starts_with('-'), "new holder enforces uniqueness: {}", r);

    child.kill().ok();
    child.wait().ok();
}
