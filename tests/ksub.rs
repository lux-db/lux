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
