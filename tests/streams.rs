mod common;
use common::{read_all, resp_cmd, send_and_read, LuxServer};
use std::io::Write;
use std::thread;
use std::time::Duration;

#[test]
fn xadd_and_xlen() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    let resp = send_and_read(&mut conn, &["XADD", "mystream", "*", "name", "alice"]);
    assert!(resp.contains("-"), "stream id contains dash: {resp}");
    send_and_read(&mut conn, &["XADD", "mystream", "*", "name", "bob"]);
    let resp = send_and_read(&mut conn, &["XLEN", "mystream"]);
    assert!(resp.contains(":2"), "xlen is 2: {resp}");
}

#[test]
fn xrange_returns_entries() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    send_and_read(&mut conn, &["XADD", "s", "*", "k", "v1"]);
    send_and_read(&mut conn, &["XADD", "s", "*", "k", "v2"]);
    let resp = send_and_read(&mut conn, &["XRANGE", "s", "-", "+"]);
    assert!(resp.contains("v1"), "contains v1: {resp}");
    assert!(resp.contains("v2"), "contains v2: {resp}");
}

#[test]
fn xread_returns_new_entries() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    send_and_read(&mut conn, &["XADD", "s", "*", "f", "a"]);
    send_and_read(&mut conn, &["XADD", "s", "*", "f", "b"]);
    let resp = send_and_read(&mut conn, &["XREAD", "STREAMS", "s", "0-0"]);
    assert!(resp.contains("a"), "contains a: {resp}");
    assert!(resp.contains("b"), "contains b: {resp}");
}

#[test]
fn xgroup_create_and_xreadgroup() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    send_and_read(&mut conn, &["XADD", "s", "*", "f", "v1"]);
    send_and_read(&mut conn, &["XADD", "s", "*", "f", "v2"]);
    let resp = send_and_read(&mut conn, &["XGROUP", "CREATE", "s", "grp1", "0"]);
    assert!(resp.contains("OK"), "group created: {resp}");
    let resp = send_and_read(
        &mut conn,
        &[
            "XREADGROUP",
            "GROUP",
            "grp1",
            "consumer1",
            "STREAMS",
            "s",
            ">",
        ],
    );
    assert!(resp.contains("v1"), "readgroup gets v1: {resp}");
    assert!(resp.contains("v2"), "readgroup gets v2: {resp}");
}

#[test]
fn xack_removes_pending() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    let id_resp = send_and_read(&mut conn, &["XADD", "s", "1-1", "f", "v"]);
    send_and_read(&mut conn, &["XGROUP", "CREATE", "s", "g", "0"]);
    send_and_read(
        &mut conn,
        &["XREADGROUP", "GROUP", "g", "c", "STREAMS", "s", ">"],
    );
    let resp = send_and_read(&mut conn, &["XACK", "s", "g", "1-1"]);
    assert!(resp.contains(":1"), "acked 1: {resp}");
    let _ = id_resp;
}

#[test]
fn xdel_removes_entry() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    send_and_read(&mut conn, &["XADD", "s", "1-1", "f", "v1"]);
    send_and_read(&mut conn, &["XADD", "s", "2-1", "f", "v2"]);
    let resp = send_and_read(&mut conn, &["XDEL", "s", "1-1"]);
    assert!(resp.contains(":1"), "deleted 1: {resp}");
    let resp = send_and_read(&mut conn, &["XLEN", "s"]);
    assert!(resp.contains(":1"), "len is 1: {resp}");
}

#[test]
fn xgroup_mkstream() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    let resp = send_and_read(
        &mut conn,
        &["XGROUP", "CREATE", "newstream", "grp", "$", "MKSTREAM"],
    );
    assert!(resp.contains("OK"), "mkstream group created: {resp}");
    let resp = send_and_read(&mut conn, &["XLEN", "newstream"]);
    assert!(resp.contains(":0"), "empty stream: {resp}");
}

#[test]
fn xread_block_woken() {
    let server = LuxServer::start();
    let mut blocker = server.conn();
    blocker
        .set_read_timeout(Some(Duration::from_millis(5000)))
        .unwrap();

    send_and_read(
        &mut blocker,
        &["XGROUP", "CREATE", "bs", "g", "$", "MKSTREAM"],
    );

    blocker
        .write_all(&resp_cmd(&["XREAD", "BLOCK", "5000", "STREAMS", "bs", "$"]))
        .unwrap();
    thread::sleep(Duration::from_millis(200));

    let mut pusher = server.conn();
    send_and_read(&mut pusher, &["XADD", "bs", "*", "msg", "hello"]);

    thread::sleep(Duration::from_millis(300));
    let resp = read_all(&mut blocker);
    assert!(resp.contains("hello"), "block read got message: {resp}");
}

#[test]
fn xpending_summary() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    send_and_read(&mut conn, &["XADD", "s", "1-1", "f", "v"]);
    send_and_read(&mut conn, &["XGROUP", "CREATE", "s", "g", "0"]);
    send_and_read(
        &mut conn,
        &["XREADGROUP", "GROUP", "g", "c", "STREAMS", "s", ">"],
    );
    let resp = send_and_read(&mut conn, &["XPENDING", "s", "g"]);
    assert!(resp.contains(":1"), "1 pending: {resp}");
}

#[test]
fn xtrim_limits_length() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    for i in 0..10 {
        send_and_read(&mut conn, &["XADD", "s", "*", "i", &i.to_string()]);
    }
    let resp = send_and_read(&mut conn, &["XTRIM", "s", "MAXLEN", "5"]);
    assert!(resp.contains(":5"), "trimmed 5: {resp}");
    let resp = send_and_read(&mut conn, &["XLEN", "s"]);
    assert!(resp.contains(":5"), "len is 5: {resp}");
}
