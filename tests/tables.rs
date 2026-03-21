use std::io::{BufRead, BufReader, Read as IoRead, Write};
use std::net::TcpStream;
use std::process::{Child, Command};
use std::time::Duration;

fn start_server(port: u16) -> Child {
    let child = Command::new(env!("CARGO_BIN_EXE_lux"))
        .env("LUX_PORT", port.to_string())
        .env("LUX_SAVE_INTERVAL", "0")
        .env("LUX_DATA_DIR", format!("/tmp/lux-test-{}", port))
        .spawn()
        .expect("failed to start lux");
    std::thread::sleep(Duration::from_millis(500));
    child
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
    let port = 16500;
    let mut child = start_server(port);
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    let r = send(
        &mut s,
        &[
            "TCREATE",
            "users",
            "name:str",
            "age:int",
            "email:str:unique",
        ],
    );
    assert_eq!(r, "+OK");

    let r = send(&mut s, &["TSCHEMA", "users"]);
    assert!(
        r.contains("name:str"),
        "schema should contain name:str: {}",
        r
    );
    assert!(
        r.contains("age:int"),
        "schema should contain age:int: {}",
        r
    );
    assert!(
        r.contains("email:str:unique"),
        "schema should contain email:str:unique: {}",
        r
    );

    let r = send(&mut s, &["TCREATE", "users", "foo:str"]);
    assert!(r.starts_with('-'), "duplicate table should error: {}", r);

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn tinsert_and_tget() {
    let port = 16501;
    let mut child = start_server(port);
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    send(&mut s, &["TCREATE", "users", "name:str", "age:int"]);

    let r = send(&mut s, &["TINSERT", "users", "name", "alice", "age", "30"]);
    assert_eq!(r, ":1");

    let r = send(&mut s, &["TGET", "users", "1"]);
    assert!(r.contains("alice"), "should find alice: {}", r);
    assert!(r.contains("30"), "should find age 30: {}", r);

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn tinsert_auto_increment() {
    let port = 16502;
    let mut child = start_server(port);
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    send(&mut s, &["TCREATE", "items", "name:str"]);

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
    let port = 16503;
    let mut child = start_server(port);
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    send(&mut s, &["TCREATE", "users", "email:str:unique"]);

    let r = send(&mut s, &["TINSERT", "users", "email", "a@b.com"]);
    assert_eq!(r, ":1");

    let r = send(&mut s, &["TINSERT", "users", "email", "a@b.com"]);
    assert!(r.starts_with('-'), "duplicate unique should error: {}", r);
    assert!(
        r.contains("unique constraint"),
        "error should mention unique: {}",
        r
    );

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn foreign_key_validation() {
    let port = 16504;
    let mut child = start_server(port);
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    send(&mut s, &["TCREATE", "users", "name:str"]);
    send(
        &mut s,
        &["TCREATE", "posts", "title:str", "user_id:ref(users)"],
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
fn tquery_where_equality_and_range() {
    let port = 16505;
    let mut child = start_server(port);
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    send(&mut s, &["TCREATE", "users", "name:str", "age:int"]);
    send(&mut s, &["TINSERT", "users", "name", "alice", "age", "25"]);
    send(&mut s, &["TINSERT", "users", "name", "bob", "age", "30"]);
    send(&mut s, &["TINSERT", "users", "name", "carol", "age", "35"]);

    let r = send(&mut s, &["TQUERY", "users", "WHERE", "name", "=", "bob"]);
    assert!(r.contains("bob"), "should find bob: {}", r);
    assert!(!r.contains("alice"), "should not find alice: {}", r);

    let r = send(&mut s, &["TQUERY", "users", "WHERE", "age", ">", "28"]);
    assert!(r.contains("bob"), "bob age 30 > 28: {}", r);
    assert!(r.contains("carol"), "carol age 35 > 28: {}", r);
    assert!(!r.contains("alice"), "alice age 25 not > 28: {}", r);

    let r = send(&mut s, &["TQUERY", "users", "WHERE", "age", ">=", "30"]);
    assert!(r.contains("bob"), "bob age 30 >= 30: {}", r);
    assert!(r.contains("carol"), "carol age 35 >= 30: {}", r);

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn tquery_order_by_and_limit() {
    let port = 16506;
    let mut child = start_server(port);
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    send(&mut s, &["TCREATE", "users", "name:str", "age:int"]);
    send(&mut s, &["TINSERT", "users", "name", "alice", "age", "25"]);
    send(&mut s, &["TINSERT", "users", "name", "bob", "age", "30"]);
    send(&mut s, &["TINSERT", "users", "name", "carol", "age", "35"]);

    let r = send(
        &mut s,
        &[
            "TQUERY", "users", "ORDER", "BY", "age", "DESC", "LIMIT", "2",
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
        &["TQUERY", "users", "ORDER", "BY", "age", "ASC", "LIMIT", "1"],
    );
    assert!(r.contains("alice"), "alice should be first asc: {}", r);
    assert!(!r.contains("bob"), "bob should not be in limit 1: {}", r);

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn tquery_with_join() {
    let port = 16507;
    let mut child = start_server(port);
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    send(&mut s, &["TCREATE", "users", "name:str", "email:str"]);
    send(
        &mut s,
        &["TCREATE", "posts", "title:str", "user_id:ref(users)"],
    );

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

    let r = send(&mut s, &["TQUERY", "posts", "JOIN", "user_id"]);
    assert!(
        r.contains("hello_world"),
        "should contain post title: {}",
        r
    );
    assert!(
        r.contains("users.name"),
        "should contain joined field prefix: {}",
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
fn tupdate_row() {
    let port = 16508;
    let mut child = start_server(port);
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    send(&mut s, &["TCREATE", "users", "name:str", "age:int"]);
    send(&mut s, &["TINSERT", "users", "name", "alice", "age", "25"]);

    let r = send(&mut s, &["TUPDATE", "users", "1", "age", "26"]);
    assert_eq!(r, "+OK");

    let r = send(&mut s, &["TGET", "users", "1"]);
    assert!(r.contains("26"), "age should be updated to 26: {}", r);

    let r = send(&mut s, &["TUPDATE", "users", "1", "age", "notanumber"]);
    assert!(r.starts_with('-'), "type violation should error: {}", r);

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn tdel_with_fk_check() {
    let port = 16509;
    let mut child = start_server(port);
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    send(&mut s, &["TCREATE", "users", "name:str"]);
    send(
        &mut s,
        &["TCREATE", "posts", "title:str", "user_id:ref(users)"],
    );
    send(&mut s, &["TINSERT", "users", "name", "alice"]);
    send(
        &mut s,
        &["TINSERT", "posts", "title", "hello", "user_id", "1"],
    );

    let r = send(&mut s, &["TDEL", "users", "1"]);
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

    let r = send(&mut s, &["TDEL", "posts", "1"]);
    assert_eq!(r, "+OK");

    let r = send(&mut s, &["TDEL", "users", "1"]);
    assert_eq!(r, "+OK");

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn tdrop_table() {
    let port = 16510;
    let mut child = start_server(port);
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    send(&mut s, &["TCREATE", "temp", "x:str"]);
    send(&mut s, &["TINSERT", "temp", "x", "hello"]);

    let r = send(&mut s, &["TDROP", "temp"]);
    assert_eq!(r, "+OK");

    let r = send(&mut s, &["TGET", "temp", "1"]);
    assert!(r.starts_with('-'), "table should not exist: {}", r);

    let r = send(&mut s, &["TLIST"]);
    assert!(!r.contains("temp"), "temp should not appear in list: {}", r);

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn tcount_rows() {
    let port = 16511;
    let mut child = start_server(port);
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    send(&mut s, &["TCREATE", "items", "name:str"]);

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
    let port = 16512;
    let mut child = start_server(port);
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    let r = send(&mut s, &["TLIST"]);
    assert_eq!(r, "*0 []");

    send(&mut s, &["TCREATE", "users", "name:str"]);
    send(&mut s, &["TCREATE", "posts", "title:str"]);

    let r = send(&mut s, &["TLIST"]);
    assert!(r.contains("users"), "should list users: {}", r);
    assert!(r.contains("posts"), "should list posts: {}", r);

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn type_validation() {
    let port = 16513;
    let mut child = start_server(port);
    let mut s = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    send(&mut s, &["TCREATE", "data", "score:int", "rating:float"]);

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
