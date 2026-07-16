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
fn lmpop_left_right_and_count() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    send_and_read(&mut conn, &["RPUSH", "l1", "a", "b", "c"]);
    let r = send_and_read(&mut conn, &["LMPOP", "1", "l1", "LEFT"]);
    assert!(r.contains("l1") && r.contains("a"), "lmpop left: {r}");
    // RIGHT COUNT 2 pops c then b.
    let r = send_and_read(&mut conn, &["LMPOP", "1", "l1", "RIGHT", "COUNT", "2"]);
    assert!(r.contains("c") && r.contains("b"), "lmpop right count: {r}");
    // list now empty -> nil array.
    let r = send_and_read(&mut conn, &["LMPOP", "1", "l1", "LEFT"]);
    assert!(r.contains("*-1"), "empty list -> nil: {r}");
}

#[test]
fn lmpop_first_non_empty_and_errors() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    send_and_read(&mut conn, &["RPUSH", "b", "x"]);
    // a is missing, b has x -> pop from b.
    let r = send_and_read(&mut conn, &["LMPOP", "2", "a", "b", "LEFT"]);
    assert!(r.contains("b") && r.contains("x"), "first non-empty: {r}");
    // wrong type in the scan.
    send_and_read(&mut conn, &["SET", "str", "v"]);
    let r = send_and_read(&mut conn, &["LMPOP", "1", "str", "LEFT"]);
    assert!(r.contains("WRONGTYPE"), "wrongtype: {r}");
    // numkeys 0 and bad direction are errors.
    assert!(send_and_read(&mut conn, &["LMPOP", "0", "LEFT"]).contains("ERR"));
    assert!(send_and_read(&mut conn, &["LMPOP", "1", "b", "SIDEWAYS"]).contains("ERR"));
}

#[test]
fn blmpop_immediate_and_timeout() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    send_and_read(&mut conn, &["RPUSH", "q", "one"]);
    let r = send_and_read(&mut conn, &["BLMPOP", "1", "1", "q", "LEFT"]);
    assert!(
        r.contains("q") && r.contains("one"),
        "blmpop immediate: {r}"
    );
    let r = send_and_read(&mut conn, &["BLMPOP", "0.1", "1", "empty", "LEFT"]);
    assert!(r.contains("*-1"), "blmpop timeout -> nil: {r}");
}

#[test]
fn blmpop_woken_by_push() {
    let server = LuxServer::start();
    let mut blocker = server.conn();
    blocker
        .set_read_timeout(Some(Duration::from_millis(5000)))
        .unwrap();
    blocker
        .write_all(&resp_cmd(&[
            "BLMPOP", "5", "2", "bk1", "bk2", "LEFT", "COUNT", "3",
        ]))
        .unwrap();
    thread::sleep(Duration::from_millis(200));
    let mut pusher = server.conn();
    send_and_read(&mut pusher, &["RPUSH", "bk2", "w1", "w2"]);
    thread::sleep(Duration::from_millis(200));
    let resp = read_all(&mut blocker);
    assert!(resp.contains("bk2"), "woken key: {resp}");
    assert!(
        resp.contains("w1") && resp.contains("w2"),
        "woken values: {resp}"
    );
}

#[test]
fn brpoplpush_immediate_and_woken() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    send_and_read(&mut conn, &["RPUSH", "s", "a", "b"]);
    // Moves the tail (b) to the head of d.
    let r = send_and_read(&mut conn, &["BRPOPLPUSH", "s", "d", "1"]);
    assert!(r.contains("b"), "brpoplpush moved tail: {r}");
    assert!(send_and_read(&mut conn, &["LRANGE", "d", "0", "-1"]).contains("b"));

    let mut blocker = server.conn();
    blocker
        .set_read_timeout(Some(Duration::from_millis(5000)))
        .unwrap();
    blocker
        .write_all(&resp_cmd(&["BRPOPLPUSH", "bsrc", "bdst", "5"]))
        .unwrap();
    thread::sleep(Duration::from_millis(200));
    let mut pusher = server.conn();
    send_and_read(&mut pusher, &["RPUSH", "bsrc", "moved"]);
    thread::sleep(Duration::from_millis(200));
    let resp = read_all(&mut blocker);
    assert!(resp.contains("moved"), "woken move: {resp}");
    assert!(send_and_read(&mut pusher, &["LRANGE", "bdst", "0", "-1"]).contains("moved"));
}
