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

#[test]
fn bitfield_set_get_incrby() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    // SET returns the previous value (0), GET reads it back.
    let r = send_and_read(&mut conn, &["BITFIELD", "bf", "SET", "u8", "0", "255"]);
    assert!(r.contains(":0"), "SET returns old value 0: {r}");
    let r = send_and_read(&mut conn, &["BITFIELD", "bf", "GET", "u8", "0"]);
    assert!(r.contains(":255"), "GET u8@0 = 255: {r}");

    // INCRBY returns the new value.
    let r = send_and_read(&mut conn, &["BITFIELD", "bf", "INCRBY", "u8", "8", "10"]);
    assert!(r.contains(":10"), "INCRBY new value: {r}");

    // Multiple ops in one call return an array in order.
    let r = send_and_read(
        &mut conn,
        &["BITFIELD", "bf", "SET", "u8", "0", "1", "GET", "u8", "0"],
    );
    // SET returns old (255), GET returns new (1).
    assert!(r.contains(":255"), "multi SET old: {r}");
    assert!(r.contains(":1"), "multi GET new: {r}");
}

#[test]
fn bitfield_signed_and_hash_offset() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    // i8 = -1 is stored as 0xFF and read back sign-extended.
    send_and_read(&mut conn, &["BITFIELD", "s", "SET", "i8", "#0", "-1"]);
    let r = send_and_read(&mut conn, &["BITFIELD", "s", "GET", "i8", "#0"]);
    assert!(r.contains(":-1"), "i8 sign-extended: {r}");
    // #1 with i8 addresses the second 8-bit field (bit offset 8).
    send_and_read(&mut conn, &["BITFIELD", "s", "SET", "i8", "#1", "5"]);
    let r = send_and_read(&mut conn, &["BITFIELD", "s", "GET", "u8", "8"]);
    assert!(r.contains(":5"), "hash offset addresses field 1: {r}");
}

#[test]
fn bitfield_overflow_modes() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    // WRAP (default): u8 255 + 10 wraps to 9.
    send_and_read(&mut conn, &["BITFIELD", "w", "SET", "u8", "0", "255"]);
    let r = send_and_read(&mut conn, &["BITFIELD", "w", "INCRBY", "u8", "0", "10"]);
    assert!(r.contains(":9"), "WRAP overflow: {r}");

    // SAT: saturates to 255.
    send_and_read(&mut conn, &["BITFIELD", "sa", "SET", "u8", "0", "250"]);
    let r = send_and_read(
        &mut conn,
        &[
            "BITFIELD", "sa", "OVERFLOW", "SAT", "INCRBY", "u8", "0", "100",
        ],
    );
    assert!(r.contains(":255"), "SAT overflow: {r}");

    // FAIL: returns nil, value unchanged.
    send_and_read(&mut conn, &["BITFIELD", "f", "SET", "u8", "0", "250"]);
    let r = send_and_read(
        &mut conn,
        &[
            "BITFIELD", "f", "OVERFLOW", "FAIL", "INCRBY", "u8", "0", "100",
        ],
    );
    assert!(r.contains("$-1") || r.contains("*-1"), "FAIL -> nil: {r}");
    let r = send_and_read(&mut conn, &["BITFIELD", "f", "GET", "u8", "0"]);
    assert!(r.contains(":250"), "FAIL left value unchanged: {r}");
}

#[test]
fn bitfield_ro_and_errors() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    send_and_read(&mut conn, &["BITFIELD", "r", "SET", "u16", "0", "1000"]);
    // BITFIELD_RO allows GET.
    let r = send_and_read(&mut conn, &["BITFIELD_RO", "r", "GET", "u16", "0"]);
    assert!(r.contains(":1000"), "RO GET: {r}");
    // BITFIELD_RO rejects SET.
    let r = send_and_read(&mut conn, &["BITFIELD_RO", "r", "SET", "u16", "0", "1"]);
    assert!(r.contains("-ERR"), "RO rejects SET: {r}");
    // Bad type and bad offset.
    assert!(send_and_read(&mut conn, &["BITFIELD", "r", "GET", "x8", "0"]).contains("-ERR"));
    assert!(send_and_read(&mut conn, &["BITFIELD", "r", "GET", "u64", "0"]).contains("-ERR"));
    assert!(send_and_read(&mut conn, &["BITFIELD", "r", "GET", "u8", "notanum"]).contains("-ERR"));
}
