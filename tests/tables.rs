use std::io::{BufRead, BufReader, Read as IoRead, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

fn start_server(port: u16) -> Child {
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

    let child = Command::new(env!("CARGO_BIN_EXE_lux"))
        .env("LUX_PORT", port.to_string())
        .env("LUX_SAVE_INTERVAL", "0")
        .env("LUX_DATA_DIR", data_dir)
        .spawn()
        .expect("failed to start lux");
    wait_for_port(port);
    child
}

fn alloc_port() -> u16 {
    static NEXT_PORT: OnceLock<AtomicU16> = OnceLock::new();
    let start = 20_000 + (std::process::id() % 20_000) as u16;
    let next = NEXT_PORT.get_or_init(|| AtomicU16::new(start));
    loop {
        let port = next.fetch_add(1, Ordering::Relaxed);
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

fn wait_for_port(port: u16) {
    for _ in 0..60 {
        if TcpStream::connect(format!("127.0.0.1:{port}")).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("server did not start on port {port}");
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
    let port = alloc_port();
    let mut child = start_server(port);
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
fn tinsert_and_tselect() {
    let port = alloc_port();
    let mut child = start_server(port);
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    send(&mut s, &["TCREATE", "users", "name STR,", "age INT"]);

    let r = send(&mut s, &["TINSERT", "users", "name", "alice", "age", "30"]);
    assert_eq!(r, ":1");

    let r = send(
        &mut s,
        &["TSELECT", "*", "FROM", "users", "WHERE", "id", "=", "1"],
    );
    assert!(r.contains("alice"), "should find alice: {}", r);
    assert!(r.contains("30"), "should find age 30: {}", r);

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn tinsert_auto_increment() {
    let port = alloc_port();
    let mut child = start_server(port);
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
    let port = alloc_port();
    let mut child = start_server(port);
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
    let port = alloc_port();
    let mut child = start_server(port);
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
    let port = alloc_port();
    let mut child = start_server(port);
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
    let port = alloc_port();
    let mut child = start_server(port);
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
    let port = alloc_port();
    let mut child = start_server(port);
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
fn tupdate_where() {
    let port = alloc_port();
    let mut child = start_server(port);
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
    let port = alloc_port();
    let mut child = start_server(port);
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
    let port = alloc_port();
    let mut child = start_server(port);
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
    let port = alloc_port();
    let mut child = start_server(port);
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
    let port = alloc_port();
    let mut child = start_server(port);
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
    let port = alloc_port();
    let mut child = start_server(port);
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
    let port = alloc_port();
    let mut child = start_server(port);
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
    let port = alloc_port();
    let mut child = start_server(port);
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

#[test]
fn on_delete_set_null() {
    let port = alloc_port();
    let mut child = start_server(port);
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
    let port = alloc_port();
    let mut child = start_server(port);
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
    let port = alloc_port();
    let mut child = start_server(port);
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
    let port = alloc_port();
    let mut child = start_server(port);
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
    let port = alloc_port();
    let mut child = start_server(port);
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
    let port = alloc_port();
    let mut child = start_server(port);
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
    let port = alloc_port();
    let mut child = start_server(port);
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
    let port = alloc_port();
    let mut child = start_server(port);
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
    let port = alloc_port();
    let mut child = start_server(port);
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
