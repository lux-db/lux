mod common;
use common::LuxServer;
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

fn send(stream: &mut TcpStream, args: &[&str]) {
    stream.write_all(&resp_cmd(args)).unwrap();
}

#[test]
fn ksub_basic_event_delivery() {
    let server = LuxServer::start();
    let mut sub_conn = server.conn();
    let mut writer = server.conn();

    let resp = send_and_read(&mut sub_conn, &["KSUB", "user:*"]);
    assert!(resp.contains("ksub"), "ksub confirmation: {resp}");
    assert!(resp.contains("user:*"), "pattern in response: {resp}");

    send_and_read(&mut writer, &["SET", "user:1", "alice"]);
    thread::sleep(Duration::from_millis(100));
    let resp = read_all(&mut sub_conn);
    assert!(resp.contains("kmessage"), "kmessage type: {resp}");
    assert!(resp.contains("user:*"), "pattern: {resp}");
    assert!(resp.contains("user:1"), "key: {resp}");
    assert!(resp.contains("set"), "operation: {resp}");
}

#[test]
fn ksub_pattern_filtering() {
    let server = LuxServer::start();
    let mut sub_conn = server.conn();
    let mut writer = server.conn();

    send(&mut sub_conn, &["KSUB", "user:*"]);
    thread::sleep(Duration::from_millis(100));
    read_all(&mut sub_conn);

    send_and_read(&mut writer, &["SET", "orders:1", "foo"]);
    thread::sleep(Duration::from_millis(100));
    let resp = read_all(&mut sub_conn);
    assert!(
        resp.is_empty(),
        "should not receive non-matching key: {resp}"
    );

    send_and_read(&mut writer, &["SET", "user:2", "bob"]);
    thread::sleep(Duration::from_millis(100));
    let resp = read_all(&mut sub_conn);
    assert!(
        resp.contains("kmessage"),
        "should receive matching key: {resp}"
    );
    assert!(resp.contains("user:2"), "key in event: {resp}");
}

#[test]
fn ksub_multiple_patterns() {
    let server = LuxServer::start();
    let mut sub_conn = server.conn();
    let mut writer = server.conn();

    send(&mut sub_conn, &["KSUB", "user:*", "order:*"]);
    thread::sleep(Duration::from_millis(100));
    read_all(&mut sub_conn);

    send_and_read(&mut writer, &["SET", "user:1", "alice"]);
    thread::sleep(Duration::from_millis(100));
    let resp = read_all(&mut sub_conn);
    assert!(resp.contains("user:1"), "user key event: {resp}");

    send_and_read(&mut writer, &["SET", "order:1", "pizza"]);
    thread::sleep(Duration::from_millis(100));
    let resp = read_all(&mut sub_conn);
    assert!(resp.contains("order:1"), "order key event: {resp}");
}

#[test]
fn kunsub_stops_events() {
    let server = LuxServer::start();
    let mut sub_conn = server.conn();
    let mut writer = server.conn();

    send(&mut sub_conn, &["KSUB", "key:*"]);
    thread::sleep(Duration::from_millis(100));
    read_all(&mut sub_conn);

    send_and_read(&mut writer, &["SET", "key:1", "v1"]);
    thread::sleep(Duration::from_millis(100));
    let resp = read_all(&mut sub_conn);
    assert!(
        resp.contains("kmessage"),
        "should receive before unsub: {resp}"
    );

    send(&mut sub_conn, &["KUNSUB", "key:*"]);
    thread::sleep(Duration::from_millis(100));
    let resp = read_all(&mut sub_conn);
    assert!(resp.contains("kunsub"), "kunsub confirmation: {resp}");

    send_and_read(&mut writer, &["SET", "key:2", "v2"]);
    thread::sleep(Duration::from_millis(100));
    let resp = read_all(&mut sub_conn);
    assert!(
        !resp.contains("kmessage"),
        "should not receive after unsub: {resp}"
    );
}

#[test]
fn ksub_hset_event() {
    let server = LuxServer::start();
    let mut sub_conn = server.conn();
    let mut writer = server.conn();

    send(&mut sub_conn, &["KSUB", "user:*"]);
    thread::sleep(Duration::from_millis(100));
    read_all(&mut sub_conn);

    send_and_read(&mut writer, &["HSET", "user:2", "name", "bob"]);
    thread::sleep(Duration::from_millis(100));
    let resp = read_all(&mut sub_conn);
    assert!(resp.contains("kmessage"), "hset event: {resp}");
    assert!(resp.contains("user:2"), "key: {resp}");
    assert!(resp.contains("hset"), "operation: {resp}");
}

#[test]
fn ksub_del_event() {
    let server = LuxServer::start();
    let mut sub_conn = server.conn();
    let mut writer = server.conn();

    send_and_read(&mut writer, &["SET", "user:1", "alice"]);

    send(&mut sub_conn, &["KSUB", "user:*"]);
    thread::sleep(Duration::from_millis(100));
    read_all(&mut sub_conn);

    send_and_read(&mut writer, &["DEL", "user:1"]);
    thread::sleep(Duration::from_millis(100));
    let resp = read_all(&mut sub_conn);
    assert!(resp.contains("kmessage"), "del event: {resp}");
    assert!(resp.contains("user:1"), "key: {resp}");
    assert!(resp.contains("del"), "operation: {resp}");
}

// --- Table change events ------------------------------------------------------
//
// Table writes emit a key event keyed on the *table name*, not on the underlying
// `_t:<table>:row:<pk>` storage key, which stays sealed behind the reserved
// namespace guard. `.live()` rides on this contract and nothing pinned it, so an
// SDK that subscribed to `_t:<table>:row:*` matched nothing and failed silently.

#[test]
fn table_writes_emit_key_event_on_table_name() {
    let server = LuxServer::start();
    let mut sub_conn = server.conn();
    let mut writer = server.conn();

    let created = send_and_read(
        &mut writer,
        &["TCREATE", "notes", "slug STR PRIMARY KEY,", "body STR"],
    );
    assert!(created.starts_with("+OK"), "tcreate: {created}");
    send_and_read(&mut sub_conn, &["KSUB", "notes"]);

    let inserted = send_and_read(
        &mut writer,
        &["TINSERT", "notes", "slug", "n1", "body", "hello"],
    );
    // A STR primary key returns :0 (an INT autoincrement PK would return the new
    // id), so assert the row actually landed rather than a specific reply.
    assert!(!inserted.starts_with('-'), "tinsert: {inserted}");
    let selected = send_and_read(&mut writer, &["TSELECT", "*", "FROM", "notes"]);
    assert!(selected.contains("n1"), "row should exist: {selected}");
    thread::sleep(Duration::from_millis(150));
    let resp = read_all(&mut sub_conn);
    assert!(resp.contains("kmessage"), "insert event: {resp}");
    assert!(
        resp.contains("notes"),
        "table name is the event key: {resp}"
    );
    assert!(resp.contains("tinsert"), "operation: {resp}");

    let updated = send_and_read(
        &mut writer,
        &[
            "TUPDATE", "notes", "SET", "body", "changed", "WHERE", "slug", "=", "n1",
        ],
    );
    assert!(
        updated.starts_with(":1"),
        "tupdate should touch 1 row: {updated}"
    );
    thread::sleep(Duration::from_millis(150));
    let resp = read_all(&mut sub_conn);
    assert!(resp.contains("tupdate"), "update event: {resp}");

    let deleted = send_and_read(
        &mut writer,
        &["TDELETE", "FROM", "notes", "WHERE", "slug", "=", "n1"],
    );
    assert!(
        deleted.starts_with(":1"),
        "tdelete should remove 1 row: {deleted}"
    );
    thread::sleep(Duration::from_millis(150));
    let resp = read_all(&mut sub_conn);
    assert!(resp.contains("tdelete"), "delete event: {resp}");
    assert!(
        !resp.contains("\nFROM\r\n") && !resp.contains("$4\r\nFROM"),
        "delete must key on the table, not the literal FROM: {resp}"
    );
}

#[test]
fn ksub_row_storage_keys_stay_sealed() {
    let server = LuxServer::start();

    // The row keyspace is engine-internal. Clients watch tables through `.live()`;
    // reaching for `_t:` gets a clear error rather than a subscription that
    // silently never fires.
    for pattern in [
        "_t:notes:row:*",
        "_t:notes:row:n1",
        "_t:auth.users:row:*",
        "_t:push.credentials:row:*",
        "_t:notes:schema",
        "_t:notes:idx:body:*",
        "_t:__tables",
        "_t:*",
    ] {
        let mut conn = server.conn();
        let resp = send_and_read(&mut conn, &["KSUB", pattern]);
        assert!(
            resp.starts_with("-ERR") && resp.contains("reserved"),
            "{pattern} must be rejected: {resp}"
        );
    }
}

#[test]
fn reserved_namespace_stays_closed_for_raw_kv() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    let created = send_and_read(
        &mut conn,
        &["TCREATE", "notes", "slug STR PRIMARY KEY,", "body STR"],
    );
    assert!(created.starts_with("+OK"), "tcreate: {created}");
    let inserted = send_and_read(&mut conn, &["TINSERT", "notes", "slug", "n1", "body", "x"]);
    assert!(!inserted.starts_with("-ERR"), "tinsert: {inserted}");

    for args in [
        vec!["GET", "_t:notes:row:n1"],
        vec!["HGETALL", "_t:notes:row:n1"],
        vec!["DEL", "_t:notes:row:n1"],
        vec!["SET", "_t:notes:row:n2", "forged"],
        vec!["HGETALL", "_t:auth.users:row:1"],
        vec!["EXISTS", "_t:notes:schema"],
    ] {
        let mut probe = server.conn();
        let resp = send_and_read(&mut probe, &args);
        assert!(
            resp.starts_with("-ERR") && resp.contains("reserved"),
            "{args:?} must stay blocked: {resp}"
        );
    }
}
