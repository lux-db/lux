mod common;
use common::{read_all, resp_cmd, send_and_read, LuxServer};
use std::io::Write;
use std::thread;
use std::time::Duration;

#[test]
fn blpop_immediate_pop() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    send_and_read(&mut conn, &["RPUSH", "mylist", "hello"]);
    let resp = send_and_read(&mut conn, &["BLPOP", "mylist", "1"]);
    assert!(resp.contains("mylist"), "key name: {resp}");
    assert!(resp.contains("hello"), "value: {resp}");
}

#[test]
fn brpop_immediate_pop() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    send_and_read(&mut conn, &["RPUSH", "mylist", "a", "b", "c"]);
    let resp = send_and_read(&mut conn, &["BRPOP", "mylist", "1"]);
    assert!(resp.contains("mylist"), "key name: {resp}");
    assert!(resp.contains("c"), "value (last): {resp}");
}

#[test]
fn blpop_timeout() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    conn.set_read_timeout(Some(Duration::from_millis(5000)))
        .unwrap();
    let resp = send_and_read(&mut conn, &["BLPOP", "empty", "1"]);
    assert!(resp.contains("*-1"), "null array on timeout: {resp}");
}

#[test]
fn blpop_woken_by_lpush() {
    let server = LuxServer::start();
    let mut blocker = server.conn();
    blocker
        .set_read_timeout(Some(Duration::from_millis(5000)))
        .unwrap();

    blocker
        .write_all(&resp_cmd(&["BLPOP", "wakekey", "5"]))
        .unwrap();
    thread::sleep(Duration::from_millis(200));

    let mut pusher = server.conn();
    send_and_read(&mut pusher, &["LPUSH", "wakekey", "woken"]);

    thread::sleep(Duration::from_millis(200));
    let resp = read_all(&mut blocker);
    assert!(resp.contains("wakekey"), "key: {resp}");
    assert!(resp.contains("woken"), "value: {resp}");
}

#[test]
fn blpop_multi_key() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    send_and_read(&mut conn, &["RPUSH", "list2", "val2"]);
    let resp = send_and_read(&mut conn, &["BLPOP", "list1", "list2", "1"]);
    assert!(resp.contains("list2"), "key: {resp}");
    assert!(resp.contains("val2"), "value: {resp}");
}

#[test]
fn blmove_immediate() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    send_and_read(&mut conn, &["RPUSH", "src", "item"]);
    let resp = send_and_read(&mut conn, &["BLMOVE", "src", "dst", "LEFT", "RIGHT", "1"]);
    assert!(resp.contains("item"), "moved value: {resp}");
    let resp2 = send_and_read(&mut conn, &["LRANGE", "dst", "0", "-1"]);
    assert!(resp2.contains("item"), "dst has item: {resp2}");
}

#[test]
fn bzpopmin_wait_does_not_block_other_clients() {
    let server = LuxServer::start();
    let mut blocker = server.conn();
    blocker
        .set_read_timeout(Some(Duration::from_millis(5000)))
        .unwrap();

    blocker
        .write_all(&resp_cmd(&["BZPOPMIN", "marker", "5"]))
        .unwrap();
    thread::sleep(Duration::from_millis(200));

    let mut observer = server.conn();
    let pong = send_and_read(&mut observer, &["PING"]);
    assert!(pong.contains("PONG"), "PING while blocked: {pong}");

    let mut pusher = server.conn();
    send_and_read(&mut pusher, &["ZADD", "marker", "1", "wake"]);

    let resp = read_all(&mut blocker);
    assert!(resp.contains("marker"), "key: {resp}");
    assert!(resp.contains("wake"), "member: {resp}");
}
