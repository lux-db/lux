//! RESP-over-TCP encryption round-trips. These exercise the real server read
//! dispatch (including the shard-local read fast-path), which the in-crate unit
//! tests bypass by going through the slow executor directly.

mod common;
use common::{send_and_read, LuxServer};

#[test]
fn resp_encrypted_values_roundtrip_over_tcp() {
    let server = LuxServer::builder().env("LUX_ENC_AUTO_INIT", "1").start();
    let mut c = server.conn();

    // String: regression for the fast read path decrypting GET.
    send_and_read(&mut c, &["SET", "tok", "string-secret", "ENCRYPTED"]);
    assert!(
        send_and_read(&mut c, &["GET", "tok"]).contains("string-secret"),
        "encrypted GET must decrypt over TCP"
    );

    // STRLEN must report the plaintext length, not the ciphertext envelope size.
    assert!(
        send_and_read(&mut c, &["STRLEN", "tok"]).contains("13"),
        "encrypted STRLEN must report plaintext length over TCP"
    );

    // Hash field.
    send_and_read(&mut c, &["HSET", "h", "f", "hash-secret", "ENCRYPTED"]);
    assert!(
        send_and_read(&mut c, &["HGET", "h", "f"]).contains("hash-secret"),
        "encrypted HGET must decrypt over TCP"
    );
    let hgetall = send_and_read(&mut c, &["HGETALL", "h"]);
    assert!(
        hgetall.contains("hash-secret"),
        "encrypted HGETALL must decrypt over TCP: {hgetall}"
    );

    // List elements: LRANGE/LINDEX go through the read fast-path.
    send_and_read(
        &mut c,
        &["RPUSH", "l", "list-secret-a", "list-secret-b", "ENCRYPTED"],
    );
    let lr = send_and_read(&mut c, &["LRANGE", "l", "0", "-1"]);
    assert!(
        lr.contains("list-secret-a") && lr.contains("list-secret-b"),
        "encrypted LRANGE must decrypt over TCP: {lr}"
    );
    assert!(send_and_read(&mut c, &["LINDEX", "l", "0"]).contains("list-secret-a"));
    // LPOP (write path) also decrypts.
    assert!(send_and_read(&mut c, &["LPOP", "l"]).contains("list-secret-a"));

    // LMOVE relocates an encrypted element to another key and it still decrypts.
    send_and_read(&mut c, &["RPUSH", "src", "move-secret", "ENCRYPTED"]);
    send_and_read(&mut c, &["LMOVE", "src", "dst", "LEFT", "RIGHT"]);
    assert!(
        send_and_read(&mut c, &["LRANGE", "dst", "0", "-1"]).contains("move-secret"),
        "encrypted element must survive LMOVE across keys"
    );

    // Stream field values: XRANGE goes through the read fast-path.
    send_and_read(
        &mut c,
        &["XADD", "s", "*", "payload", "stream-secret", "ENCRYPTED"],
    );
    assert!(
        send_and_read(&mut c, &["XRANGE", "s", "-", "+"]).contains("stream-secret"),
        "encrypted XRANGE must decrypt over TCP"
    );
}
