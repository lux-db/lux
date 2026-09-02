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
    read_b(conn)
}

fn read_b(conn: &mut TcpStream) -> Vec<u8> {
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

#[test]
fn redis_cli_pipe_sentinel_after_a_blank_line_is_processed() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    let magic = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x80\x81\x82\x83\x84\x85\xfc\xfd\xfe\xff";
    let mut request =
        b"*3\r\n$3\r\nSET\r\n$8\r\ncli:pipe\r\n$1\r\n1\r\n\r\n*2\r\n$4\r\nECHO\r\n$20\r\n".to_vec();
    request.extend_from_slice(magic);
    request.extend_from_slice(b"\r\n");
    conn.write_all(&request).unwrap();

    let first = read_b(&mut conn);
    assert_eq!(first, b"+OK\r\n");
    let sentinel = read_b(&mut conn);
    assert_eq!(bulk_payload(&sentinel), magic);
    assert_eq!(send_b(&mut conn, &[b"PING"]), b"+PONG\r\n");
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
    // Metadata forms are not implemented, so they fail rather than claiming
    // there are no registered commands.
    assert_has(&send(&mut conn, &["COMMAND"]), "-ERR");
    assert_has(&send(&mut conn, &["COMMAND", "INFO", "GET"]), "-ERR");
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
    // RESET cannot safely clear connection-local state in the generic command
    // layer, so it fails instead of claiming the reset happened.
    assert_has(&send(&mut conn, &["RESET"]), "-ERR");
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
    // Unsupported administrative compatibility commands never return fake OKs.
    assert_has(&send(&mut conn, &["DEBUG", "HELP"]), "-ERR");
    assert_has(
        &send(&mut conn, &["CONFIG", "SET", "appendonly", "yes"]),
        "-ERR",
    );
    assert_has(&send(&mut conn, &["CONFIG", "RESETSTAT"]), "-ERR");
    assert_has(&send(&mut conn, &["CLIENT", "PAUSE", "100"]), "-ERR");
    assert_has(&send(&mut conn, &["OBJECT", "IDLETIME", "k"]), "-ERR");
    assert_has(&send(&mut conn, &["MEMORY", "STATS"]), "-ERR");
}

#[test]
fn quit_closes_the_network_connection_after_replying() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    assert_has(&send(&mut conn, &["QUIT"]), "+OK");
    let mut byte = [0_u8; 1];
    assert_eq!(
        conn.read(&mut byte).unwrap(),
        0,
        "QUIT must close the socket"
    );
}

#[test]
fn quit_inside_a_transaction_is_one_error_reply() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    assert_has(&send(&mut conn, &["MULTI"]), "+OK");
    assert_has(&send(&mut conn, &["QUIT"]), "+QUEUED");
    let exec = send(&mut conn, &["EXEC"]);
    assert!(
        exec.starts_with("*1\r\n-ERR QUIT is not allowed inside a transaction"),
        "queued QUIT should produce exactly one error element: {exec:?}"
    );
    assert!(!exec.contains("+OK"), "queued QUIT must not claim success");
    assert_has(&send(&mut conn, &["PING"]), "+PONG");
}

#[test]
fn save_commands_report_real_completion_and_lastsave_time() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    assert_eq!(send(&mut conn, &["LASTSAVE"]).trim(), ":0");
    send(&mut conn, &["SET", "saved", "value"]);

    let save = send(&mut conn, &["BGSAVE"]);
    assert!(
        save.contains("Background saving started"),
        "BGSAVE must acknowledge the accepted background job: {save:?}"
    );

    let mut lastsave = send(&mut conn, &["LASTSAVE"]);
    for _ in 0..100 {
        if lastsave.trim() != ":0" {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
        lastsave = send(&mut conn, &["LASTSAVE"]);
    }
    let timestamp: u64 = lastsave
        .trim()
        .strip_prefix(':')
        .expect("LASTSAVE integer response")
        .parse()
        .expect("LASTSAVE timestamp");
    assert!(timestamp > 0, "completed snapshot should have a timestamp");
    assert!(
        timestamp
            <= std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        "LASTSAVE must not report a future timestamp"
    );
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
    assert_has(
        &send(&mut conn, &["CLIENT", "SETINFO", "unknown", "value"]),
        "-ERR",
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
