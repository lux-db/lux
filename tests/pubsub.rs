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

fn resp_cmd_raw(args: &[&[u8]]) -> Vec<u8> {
    let mut buf = format!("*{}\r\n", args.len()).into_bytes();
    for arg in args {
        buf.extend_from_slice(format!("${}\r\n", arg.len()).as_bytes());
        buf.extend_from_slice(arg);
        buf.extend_from_slice(b"\r\n");
    }
    buf
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

fn read_all_bytes(stream: &mut TcpStream) -> Vec<u8> {
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
    data
}

fn send_and_read(stream: &mut TcpStream, args: &[&str]) -> String {
    stream.write_all(&resp_cmd(args)).unwrap();
    thread::sleep(Duration::from_millis(50));
    read_all(stream)
}

fn send(stream: &mut TcpStream, args: &[&str]) {
    stream.write_all(&resp_cmd(args)).unwrap();
}

fn send_raw(stream: &mut TcpStream, args: &[&[u8]]) {
    stream.write_all(&resp_cmd_raw(args)).unwrap();
}

#[test]
fn subscribe_confirms_channel() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    let resp = send_and_read(&mut conn, &["SUBSCRIBE", "mychan"]);
    assert!(resp.contains("subscribe"), "subscribe confirmation: {resp}");
    assert!(resp.contains("mychan"), "channel name: {resp}");
    assert!(resp.contains(":1"), "subscription count: {resp}");
}

#[test]
fn subscribe_multiple_channels() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    let resp = send_and_read(&mut conn, &["SUBSCRIBE", "ch1", "ch2", "ch3"]);
    assert!(resp.contains("ch1"), "ch1: {resp}");
    assert!(resp.contains("ch2"), "ch2: {resp}");
    assert!(resp.contains("ch3"), "ch3: {resp}");
    assert!(resp.contains(":3"), "3 subscriptions: {resp}");
}

#[test]
fn publish_returns_subscriber_count() {
    let server = LuxServer::start();
    let mut pub_conn = server.conn();

    let resp = send_and_read(&mut pub_conn, &["PUBLISH", "nochan", "msg"]);
    assert!(resp.contains(":0"), "no subscribers: {resp}");
}

#[test]
fn publish_delivers_message_to_subscriber() {
    let server = LuxServer::start();
    let mut sub_conn = server.conn();
    let mut pub_conn = server.conn();

    send(&mut sub_conn, &["SUBSCRIBE", "events"]);
    thread::sleep(Duration::from_millis(100));
    read_all(&mut sub_conn);

    send_and_read(&mut pub_conn, &["PUBLISH", "events", "hello_world"]);
    thread::sleep(Duration::from_millis(100));
    let resp = read_all(&mut sub_conn);
    assert!(resp.contains("message"), "message type: {resp}");
    assert!(resp.contains("events"), "channel name: {resp}");
    assert!(resp.contains("hello_world"), "payload: {resp}");
}

#[test]
fn publish_preserves_binary_payload_bytes() {
    let server = LuxServer::start();
    let mut sub_conn = server.conn();
    let mut pub_conn = server.conn();

    send(&mut sub_conn, &["SUBSCRIBE", "events"]);
    thread::sleep(Duration::from_millis(100));
    let _ = read_all_bytes(&mut sub_conn);

    let payload: &[u8] = b"\x00\xff\x80msgpack\x00\x01";
    send_raw(&mut pub_conn, &[b"PUBLISH", b"events", payload]);
    thread::sleep(Duration::from_millis(100));
    let _ = read_all_bytes(&mut pub_conn);

    let resp = read_all_bytes(&mut sub_conn);
    assert!(
        resp.windows(b"message".len()).any(|w| w == b"message"),
        "message type missing: {resp:?}"
    );
    assert!(
        resp.windows(b"events".len()).any(|w| w == b"events"),
        "channel missing: {resp:?}"
    );

    let mut needle = format!("${}\r\n", payload.len()).into_bytes();
    needle.extend_from_slice(payload);
    needle.extend_from_slice(b"\r\n");
    assert!(
        resp.windows(needle.len()).any(|w| w == needle.as_slice()),
        "binary payload not preserved exactly: {resp:?}"
    );
}

#[test]
fn publish_to_correct_channel_only() {
    let server = LuxServer::start();
    let mut sub_conn = server.conn();
    let mut pub_conn = server.conn();

    send(&mut sub_conn, &["SUBSCRIBE", "chan_a"]);
    thread::sleep(Duration::from_millis(100));
    read_all(&mut sub_conn);

    send_and_read(&mut pub_conn, &["PUBLISH", "chan_b", "wrong_channel"]);
    thread::sleep(Duration::from_millis(100));
    let resp = read_all(&mut sub_conn);
    assert!(
        resp.is_empty(),
        "should not receive message for other channel: {resp}"
    );
}

#[test]
fn unsubscribe_stops_delivery() {
    let server = LuxServer::start();
    let mut sub_conn = server.conn();
    let mut pub_conn = server.conn();

    send(&mut sub_conn, &["SUBSCRIBE", "events"]);
    thread::sleep(Duration::from_millis(100));
    read_all(&mut sub_conn);

    send(&mut sub_conn, &["UNSUBSCRIBE", "events"]);
    thread::sleep(Duration::from_millis(100));
    read_all(&mut sub_conn);

    send_and_read(&mut pub_conn, &["PUBLISH", "events", "after_unsub"]);
    thread::sleep(Duration::from_millis(100));
    let resp = read_all(&mut sub_conn);
    assert!(
        !resp.contains("after_unsub"),
        "should not receive after unsubscribe: {resp}"
    );
}

#[test]
fn subscriber_rejects_non_pubsub_commands() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send(&mut conn, &["SUBSCRIBE", "ch"]);
    thread::sleep(Duration::from_millis(100));
    read_all(&mut conn);

    let resp = send_and_read(&mut conn, &["SET", "k", "v"]);
    assert!(
        resp.contains("ERR"),
        "non-pubsub command rejected in sub mode: {resp}"
    );
}

#[test]
fn ping_allowed_in_subscribe_mode() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send(&mut conn, &["SUBSCRIBE", "ch"]);
    thread::sleep(Duration::from_millis(100));
    read_all(&mut conn);

    let resp = send_and_read(&mut conn, &["PING"]);
    assert!(resp.contains("PONG"), "PING in sub mode: {resp}");
}

#[test]
fn multiple_subscribers_receive_message() {
    let server = LuxServer::start();
    let mut sub1 = server.conn();
    let mut sub2 = server.conn();
    let mut pub_conn = server.conn();

    send(&mut sub1, &["SUBSCRIBE", "shared"]);
    send(&mut sub2, &["SUBSCRIBE", "shared"]);
    thread::sleep(Duration::from_millis(100));
    read_all(&mut sub1);
    read_all(&mut sub2);

    let resp = send_and_read(&mut pub_conn, &["PUBLISH", "shared", "broadcast"]);
    assert!(resp.contains(":2"), "2 subscribers: {resp}");

    thread::sleep(Duration::from_millis(100));
    let r1 = read_all(&mut sub1);
    let r2 = read_all(&mut sub2);
    assert!(r1.contains("broadcast"), "sub1 received: {r1}");
    assert!(r2.contains("broadcast"), "sub2 received: {r2}");
}

#[test]
fn unsubscribe_all_exits_sub_mode() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send(&mut conn, &["SUBSCRIBE", "ch1", "ch2"]);
    thread::sleep(Duration::from_millis(100));
    read_all(&mut conn);

    send(&mut conn, &["UNSUBSCRIBE"]);
    thread::sleep(Duration::from_millis(100));
    let resp = read_all(&mut conn);
    assert!(resp.contains(":0"), "zero subscriptions: {resp}");

    let resp = send_and_read(&mut conn, &["SET", "k", "v"]);
    assert!(
        resp.contains("+OK"),
        "normal commands work after unsubscribe all: {resp}"
    );
}
