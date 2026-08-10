mod common;
use common::{send, LuxServer};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

fn assert_has(resp: &str, needle: &str) {
    assert!(resp.contains(needle), "missing {needle:?}: {resp}");
}

/// Binary-safe single-command send: returns the raw bytes of one RESP reply
/// (including a bulk string's binary payload, which `send`'s lossy UTF-8 would
/// corrupt). Needed for DUMP/RESTORE round-trips.
fn send_b(conn: &mut TcpStream, args: &[&[u8]]) -> Vec<u8> {
    let mut cmd = Vec::new();
    cmd.extend_from_slice(format!("*{}\r\n", args.len()).as_bytes());
    for a in args {
        cmd.extend_from_slice(format!("${}\r\n", a.len()).as_bytes());
        cmd.extend_from_slice(a);
        cmd.extend_from_slice(b"\r\n");
    }
    conn.write_all(&cmd).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut reply = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        conn.read_exact(&mut byte).unwrap();
        reply.push(byte[0]);
        if reply.len() >= 2 && reply[reply.len() - 2] == b'\r' && reply[reply.len() - 1] == b'\n' {
            break;
        }
    }
    if reply[0] == b'$' {
        let len: i64 = std::str::from_utf8(&reply[1..reply.len() - 2])
            .unwrap()
            .parse()
            .unwrap();
        if len >= 0 {
            let mut rest = vec![0u8; len as usize + 2]; // payload + trailing CRLF
            conn.read_exact(&mut rest).unwrap();
            reply.extend_from_slice(&rest);
        }
    }
    reply
}

/// Extract the payload bytes from a `$<len>\r\n<payload>\r\n` bulk reply.
fn bulk_payload(reply: &[u8]) -> Vec<u8> {
    let nl = reply.windows(2).position(|w| w == b"\r\n").unwrap();
    let len: usize = std::str::from_utf8(&reply[1..nl]).unwrap().parse().unwrap();
    reply[nl + 2..nl + 2 + len].to_vec()
}

// Commands that used to fake `+OK` must return an honest response of the correct
// RESP type (a real value, or a clear unsupported error) so clients aren't misled.
#[test]
fn stub_commands_return_honest_responses() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    // WAIT reports 0 replicas as an integer (no replication), not +OK.
    assert_has(&send(&mut conn, &["WAIT", "0", "0"]), ":0");
    // COMMAND COUNT returns a real, non-zero integer count.
    let count = send(&mut conn, &["COMMAND", "COUNT"]);
    assert!(
        count.starts_with(':') && count.trim() != ":0",
        "COMMAND COUNT should be a real integer: {count:?}"
    );
    // COMMAND (bare) and COMMAND INFO return an array shape, not +OK.
    assert_has(&send(&mut conn, &["COMMAND"]), "*");
    assert_has(&send(&mut conn, &["COMMAND", "INFO", "GET"]), "*");
    // COMMAND GETKEYS can't be faked, so it errors rather than returning +OK.
    assert_has(
        &send(&mut conn, &["COMMAND", "GETKEYS", "SET", "k", "v"]),
        "-ERR",
    );
    // SELECT 0 is OK; other indexes and non-integers are honest errors.
    assert_has(&send(&mut conn, &["SELECT", "0"]), "+OK");
    assert_has(&send(&mut conn, &["SELECT", "1"]), "-ERR");
    assert_has(&send(&mut conn, &["SELECT", "notanint"]), "-ERR");
    // SWAPDB is unsupported (single database) rather than a fake OK.
    assert_has(&send(&mut conn, &["SWAPDB", "0", "1"]), "-ERR");
    // RESET replies with the +RESET status line.
    assert_has(&send(&mut conn, &["RESET"]), "+RESET");
    // LATENCY RESET is an integer; reporting forms are arrays.
    assert_has(&send(&mut conn, &["LATENCY", "RESET"]), ":0");
    assert_has(&send(&mut conn, &["LATENCY", "HISTORY", "event"]), "*0");
    // FUNCTION LIST is honestly empty; other subcommands are unsupported.
    assert_has(&send(&mut conn, &["FUNCTION", "LIST"]), "*0");
    assert_has(&send(&mut conn, &["FUNCTION", "STATS"]), "-ERR");
    // DUMP of a missing key returns a nil bulk (not an error).
    assert_has(&send(&mut conn, &["DUMP", "k"]), "$-1");
    // MIGRATE and WAITAOF return explicit unsupported errors, not fake OK.
    assert_has(
        &send(&mut conn, &["MIGRATE", "h", "6379", "k", "0", "100"]),
        "-ERR",
    );
    assert_has(&send(&mut conn, &["WAITAOF", "1", "0", "0"]), "-ERR");
}

#[test]
fn dump_restore_roundtrips_within_lux() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    // String round-trip to a different key (binary-safe).
    send_b(&mut conn, &[b"SET", b"s", b"hello"]);
    let dump = send_b(&mut conn, &[b"DUMP", b"s"]);
    assert_eq!(dump[0], b'$', "DUMP returns a bulk payload");
    let payload = bulk_payload(&dump);
    assert_eq!(
        send_b(&mut conn, &[b"RESTORE", b"s2", b"0", &payload]),
        b"+OK\r\n"
    );
    assert_eq!(bulk_payload(&send_b(&mut conn, &[b"GET", b"s2"])), b"hello");

    // RESTORE onto an existing key requires REPLACE (existence check precedes decode).
    let busy = send_b(&mut conn, &[b"RESTORE", b"s2", b"0", &payload]);
    assert!(
        String::from_utf8_lossy(&busy).contains("BUSYKEY"),
        "busykey: {:?}",
        String::from_utf8_lossy(&busy)
    );
    assert_eq!(
        send_b(&mut conn, &[b"RESTORE", b"s2", b"0", &payload, b"REPLACE"]),
        b"+OK\r\n"
    );

    // A collection type round-trips too.
    send_b(&mut conn, &[b"RPUSH", b"l", b"a", b"b", b"c"]);
    let ldump = bulk_payload(&send_b(&mut conn, &[b"DUMP", b"l"]));
    assert_eq!(
        send_b(&mut conn, &[b"RESTORE", b"l2", b"0", &ldump]),
        b"+OK\r\n"
    );
    // Elements are ASCII, so the string helper (which parses arrays) can read them.
    let range = send(&mut conn, &["LRANGE", "l2", "0", "-1"]);
    assert!(
        range.contains('a') && range.contains('b') && range.contains('c'),
        "list restored: {range:?}"
    );

    // TTL is honored.
    assert_eq!(
        send_b(&mut conn, &[b"RESTORE", b"s3", b"100000", &payload]),
        b"+OK\r\n"
    );
    let pttl = String::from_utf8_lossy(&send_b(&mut conn, &[b"PTTL", b"s3"])).into_owned();
    assert!(
        pttl.starts_with(':') && !pttl.contains("-1"),
        "restored TTL set: {pttl:?}"
    );

    // Bad payload on a fresh key is rejected (passes existence check, fails decode).
    let bad = send_b(&mut conn, &[b"RESTORE", b"bad", b"0", b"not-a-dump"]);
    assert!(
        String::from_utf8_lossy(&bad).contains("ERR"),
        "bad payload rejected: {:?}",
        String::from_utf8_lossy(&bad)
    );
}

#[test]
fn touch_counts_existing_keys() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    send(&mut conn, &["MSET", "a", "1", "b", "2"]);
    // two exist, one missing, and a duplicate counts twice (Redis semantics).
    assert_has(&send(&mut conn, &["TOUCH", "a", "b", "missing", "a"]), ":3");
    assert_has(&send(&mut conn, &["TOUCH", "nope"]), ":0");
}

#[test]
fn client_getname_and_setname_are_session_local() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    let mut other = server.conn();

    assert_has(&send(&mut conn, &["CLIENT", "GETNAME"]), "$-1");
    assert_has(&send(&mut conn, &["CLIENT", "SETNAME", "worker-a"]), "+OK");
    assert_has(&send(&mut conn, &["CLIENT", "GETNAME"]), "worker-a");
    assert_has(&send(&mut other, &["CLIENT", "GETNAME"]), "$-1");
}

#[test]
fn client_setinfo_is_tolerated_for_ioredis() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    assert_has(
        &send(&mut conn, &["CLIENT", "SETINFO", "LIB-NAME", "ioredis"]),
        "+OK",
    );
    assert_has(
        &send(&mut conn, &["CLIENT", "SETINFO", "LIB-VER", "5.0.0"]),
        "+OK",
    );
}

#[test]
fn info_reports_blocking_waiter_counters() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    let info = send(&mut conn, &["INFO"]);
    assert_has(&info, "blocked_list_waiters:");
    assert_has(&info, "blocked_stream_waiters:");
}
