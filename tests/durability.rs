//! Process-level tests for the public durability policy.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

mod common;
use common::{send, LuxServer};

fn restore_snapshot(port: u16, dump: &[u8]) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let headers = format!(
        "POST /v1/restore HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
        dump.len()
    );
    stream.write_all(headers.as_bytes()).unwrap();
    stream.write_all(dump).unwrap();

    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    String::from_utf8_lossy(&response).into_owned()
}

#[test]
fn memory_layout_defaults_to_every_second_and_recovers() {
    let mut server = LuxServer::start();
    let mut connection = server.conn();

    let info = send(&mut connection, &["INFO"]);
    assert!(info.contains("storage_layout:memory"), "{info}");
    assert!(info.contains("durability:every_second"), "{info}");
    assert!(info.contains("wal_enabled:true"), "{info}");

    assert!(send(&mut connection, &["SET", "durable:key", "value"]).contains("+OK"));
    drop(connection);
    thread::sleep(Duration::from_millis(1_100));
    server.restart();

    let mut connection = server.conn();
    let value = send(&mut connection, &["GET", "durable:key"]);
    assert!(
        value.contains("value"),
        "acknowledged value was lost: {value}"
    );
}

#[test]
fn always_sync_recovers_memory_write_after_immediate_kill() {
    let mut server = LuxServer::builder()
        .env("LUX_DURABILITY", "always_sync")
        .start();
    let mut connection = server.conn();

    assert!(send(&mut connection, &["SET", "sync:key", "value"]).contains("+OK"));
    drop(connection);
    server.restart();

    let mut connection = server.conn();
    let value = send(&mut connection, &["GET", "sync:key"]);
    assert!(
        value.contains("value"),
        "acknowledged value was lost: {value}"
    );
}

#[test]
fn explicit_ephemeral_mode_creates_no_journal_and_recovers_nothing() {
    let mut server = LuxServer::builder()
        .env("LUX_DURABILITY", "ephemeral")
        .start();
    let mut connection = server.conn();

    let info = send(&mut connection, &["INFO"]);
    assert!(info.contains("durability:ephemeral"), "{info}");
    assert!(info.contains("wal_enabled:false"), "{info}");
    assert!(send(&mut connection, &["SET", "temporary:key", "value"]).contains("+OK"));
    assert!(!server.data_dir().join("journal").exists());
    drop(connection);

    server.restart();
    let mut connection = server.conn();
    assert_eq!(send(&mut connection, &["GET", "temporary:key"]), "$-1\r\n");
}

#[test]
fn memory_restore_cannot_replay_stale_post_snapshot_writes() {
    let mut server = LuxServer::builder().http().start();
    let mut connection = server.conn();

    assert!(send(&mut connection, &["SET", "restored:key", "baseline"]).contains("+OK"));
    assert!(send(&mut connection, &["SAVE"]).contains("+OK"));
    let snapshot = std::fs::read(server.data_dir().join("lux.dat")).unwrap();

    assert!(send(&mut connection, &["SET", "stale:key", "must-not-replay"]).contains("+OK"));
    drop(connection);
    thread::sleep(Duration::from_millis(1_100));

    let response = restore_snapshot(server.http_port(), &snapshot);
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    server.restart();

    let mut connection = server.conn();
    assert!(
        send(&mut connection, &["GET", "restored:key"]).contains("baseline"),
        "restored snapshot was not loaded"
    );
    assert_eq!(send(&mut connection, &["GET", "stale:key"]), "$-1\r\n");
}
