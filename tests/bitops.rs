mod common;
use common::{send_and_read, LuxServer};

#[test]
fn setbit_getbit_bitcount_and_bitpos() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    assert!(send_and_read(&mut conn, &["SETBIT", "bits", "1", "1"]).contains(":0"));
    assert!(send_and_read(&mut conn, &["SETBIT", "bits", "9", "1"]).contains(":0"));
    assert!(send_and_read(&mut conn, &["GETBIT", "bits", "1"]).contains(":1"));
    assert!(send_and_read(&mut conn, &["GETBIT", "bits", "2"]).contains(":0"));
    assert!(send_and_read(&mut conn, &["BITCOUNT", "bits"]).contains(":2"));
    assert!(send_and_read(&mut conn, &["BITCOUNT", "bits", "0", "7", "BIT"]).contains(":1"));
    assert!(send_and_read(&mut conn, &["BITPOS", "bits", "1"]).contains(":1"));
    assert!(send_and_read(&mut conn, &["BITPOS", "bits", "0", "0", "7", "BIT"]).contains(":0"));
}

#[test]
fn bitop_and_or_xor_not() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(&mut conn, &["SETBIT", "a", "0", "1"]);
    send_and_read(&mut conn, &["SETBIT", "a", "2", "1"]);
    send_and_read(&mut conn, &["SETBIT", "b", "2", "1"]);
    send_and_read(&mut conn, &["SETBIT", "b", "3", "1"]);

    assert!(send_and_read(&mut conn, &["BITOP", "AND", "and", "a", "b"]).contains(":1"));
    assert!(send_and_read(&mut conn, &["GETBIT", "and", "2"]).contains(":1"));
    assert!(send_and_read(&mut conn, &["GETBIT", "and", "0"]).contains(":0"));

    assert!(send_and_read(&mut conn, &["BITOP", "OR", "or", "a", "b"]).contains(":1"));
    assert!(send_and_read(&mut conn, &["GETBIT", "or", "0"]).contains(":1"));
    assert!(send_and_read(&mut conn, &["GETBIT", "or", "3"]).contains(":1"));

    assert!(send_and_read(&mut conn, &["BITOP", "XOR", "xor", "a", "b"]).contains(":1"));
    assert!(send_and_read(&mut conn, &["GETBIT", "xor", "2"]).contains(":0"));

    assert!(send_and_read(&mut conn, &["BITOP", "NOT", "not", "a"]).contains(":1"));
    assert!(send_and_read(&mut conn, &["GETBIT", "not", "1"]).contains(":1"));
}

#[test]
fn bitop_reports_syntax_and_type_errors() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    let bad_bit = send_and_read(&mut conn, &["SETBIT", "bits", "0", "2"]);
    assert!(bad_bit.contains("ERR bit is not"), "bad bit: {bad_bit}");

    let bad_offset = send_and_read(&mut conn, &["GETBIT", "bits", "-1"]);
    assert!(
        bad_offset.contains("ERR bit offset"),
        "bad offset: {bad_offset}"
    );

    let bad_not = send_and_read(&mut conn, &["BITOP", "NOT", "dst", "a", "b"]);
    assert!(
        bad_not.contains("BITOP NOT requires"),
        "bad NOT arity: {bad_not}"
    );

    send_and_read(&mut conn, &["LPUSH", "list", "x"]);
    let wrongtype = send_and_read(&mut conn, &["GETBIT", "list", "0"]);
    assert!(wrongtype.contains("WRONGTYPE"), "wrong type: {wrongtype}");
}

#[test]
fn bit_commands_reject_invalid_ranges_without_mutating_destination() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(&mut conn, &["SETBIT", "src", "0", "1"]);
    send_and_read(&mut conn, &["SETBIT", "dest", "0", "1"]);

    for cmd in [
        vec!["BITPOS", "src", "1", "nope"],
        vec!["BITPOS", "src", "1", "0", "nope"],
        vec!["BITPOS", "src", "1", "0", "-1", "NOPE"],
        vec!["BITOP", "BADOP", "dest", "missing"],
    ] {
        let resp = send_and_read(&mut conn, &cmd);
        assert!(
            resp.starts_with("-ERR"),
            "expected error for {cmd:?}, got: {resp}"
        );
    }

    let resp = send_and_read(&mut conn, &["GETBIT", "dest", "0"]);
    assert!(
        resp.contains(":1"),
        "invalid BITOP should not delete destination: {resp}"
    );
}
