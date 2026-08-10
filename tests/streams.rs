mod common;
use common::{read_all, resp_cmd, send_and_read, LuxServer};
use std::io::Write;
use std::thread;
use std::time::Duration;

#[test]
fn xadd_and_xlen() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    let resp = send_and_read(&mut conn, &["XADD", "mystream", "*", "name", "alice"]);
    assert!(resp.contains("-"), "stream id contains dash: {resp}");
    send_and_read(&mut conn, &["XADD", "mystream", "*", "name", "bob"]);
    let resp = send_and_read(&mut conn, &["XLEN", "mystream"]);
    assert!(resp.contains(":2"), "xlen is 2: {resp}");
}

#[test]
fn xrange_returns_entries() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    send_and_read(&mut conn, &["XADD", "s", "*", "k", "v1"]);
    send_and_read(&mut conn, &["XADD", "s", "*", "k", "v2"]);
    let resp = send_and_read(&mut conn, &["XRANGE", "s", "-", "+"]);
    assert!(resp.contains("v1"), "contains v1: {resp}");
    assert!(resp.contains("v2"), "contains v2: {resp}");
}

#[test]
fn xread_returns_new_entries() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    send_and_read(&mut conn, &["XADD", "s", "*", "f", "a"]);
    send_and_read(&mut conn, &["XADD", "s", "*", "f", "b"]);
    let resp = send_and_read(&mut conn, &["XREAD", "STREAMS", "s", "0-0"]);
    assert!(resp.contains("a"), "contains a: {resp}");
    assert!(resp.contains("b"), "contains b: {resp}");
}

#[test]
fn xgroup_create_and_xreadgroup() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    send_and_read(&mut conn, &["XADD", "s", "*", "f", "v1"]);
    send_and_read(&mut conn, &["XADD", "s", "*", "f", "v2"]);
    let resp = send_and_read(&mut conn, &["XGROUP", "CREATE", "s", "grp1", "0"]);
    assert!(resp.contains("OK"), "group created: {resp}");
    let resp = send_and_read(
        &mut conn,
        &[
            "XREADGROUP",
            "GROUP",
            "grp1",
            "consumer1",
            "STREAMS",
            "s",
            ">",
        ],
    );
    assert!(resp.contains("v1"), "readgroup gets v1: {resp}");
    assert!(resp.contains("v2"), "readgroup gets v2: {resp}");
}

#[test]
fn xgroup_setid_moves_group_cursor() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    send_and_read(&mut conn, &["XADD", "s", "1-0", "f", "v1"]);
    send_and_read(&mut conn, &["XADD", "s", "2-0", "f", "v2"]);
    send_and_read(&mut conn, &["XGROUP", "CREATE", "s", "g", "0"]);

    let resp = send_and_read(&mut conn, &["XGROUP", "SETID", "s", "g", "1-0"]);
    assert!(resp.contains("OK"), "setid ok: {resp}");
    let resp = send_and_read(
        &mut conn,
        &["XREADGROUP", "GROUP", "g", "c", "STREAMS", "s", ">"],
    );
    assert!(!resp.contains("v1"), "setid skipped v1: {resp}");
    assert!(resp.contains("v2"), "setid reads v2: {resp}");
}

#[test]
fn xack_removes_pending() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    let id_resp = send_and_read(&mut conn, &["XADD", "s", "1-1", "f", "v"]);
    send_and_read(&mut conn, &["XGROUP", "CREATE", "s", "g", "0"]);
    send_and_read(
        &mut conn,
        &["XREADGROUP", "GROUP", "g", "c", "STREAMS", "s", ">"],
    );
    let resp = send_and_read(&mut conn, &["XACK", "s", "g", "1-1"]);
    assert!(resp.contains(":1"), "acked 1: {resp}");
    let _ = id_resp;
}

#[test]
fn xdel_removes_entry() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    send_and_read(&mut conn, &["XADD", "s", "1-1", "f", "v1"]);
    send_and_read(&mut conn, &["XADD", "s", "2-1", "f", "v2"]);
    let resp = send_and_read(&mut conn, &["XDEL", "s", "1-1"]);
    assert!(resp.contains(":1"), "deleted 1: {resp}");
    let resp = send_and_read(&mut conn, &["XLEN", "s"]);
    assert!(resp.contains(":1"), "len is 1: {resp}");
}

#[test]
fn xgroup_mkstream() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    let resp = send_and_read(
        &mut conn,
        &["XGROUP", "CREATE", "newstream", "grp", "$", "MKSTREAM"],
    );
    assert!(resp.contains("OK"), "mkstream group created: {resp}");
    let resp = send_and_read(&mut conn, &["XLEN", "newstream"]);
    assert!(resp.contains(":0"), "empty stream: {resp}");
}

#[test]
fn xread_block_woken() {
    let server = LuxServer::start();
    let mut blocker = server.conn();
    blocker
        .set_read_timeout(Some(Duration::from_millis(5000)))
        .unwrap();

    send_and_read(
        &mut blocker,
        &["XGROUP", "CREATE", "bs", "g", "$", "MKSTREAM"],
    );

    blocker
        .write_all(&resp_cmd(&["XREAD", "BLOCK", "5000", "STREAMS", "bs", "$"]))
        .unwrap();
    thread::sleep(Duration::from_millis(200));

    let mut pusher = server.conn();
    send_and_read(&mut pusher, &["XADD", "bs", "*", "msg", "hello"]);

    thread::sleep(Duration::from_millis(300));
    let resp = read_all(&mut blocker);
    assert!(resp.contains("hello"), "block read got message: {resp}");
}

#[test]
fn xread_block_timeout_removes_stream_waiter() {
    let server = LuxServer::start();
    let mut blocker = server.conn();
    blocker
        .set_read_timeout(Some(Duration::from_millis(1000)))
        .unwrap();

    blocker
        .write_all(&resp_cmd(&[
            "XREAD",
            "BLOCK",
            "75",
            "STREAMS",
            "timeout-stream",
            "$",
        ]))
        .unwrap();
    thread::sleep(Duration::from_millis(25));

    let mut observer = server.conn();
    let info = send_and_read(&mut observer, &["INFO"]);
    assert!(
        info.contains("blocked_stream_waiters:1"),
        "stream waiter should be registered while XREAD is blocked: {info}"
    );

    let resp = read_all(&mut blocker);
    assert!(
        resp.contains("*-1"),
        "XREAD timeout returns null array: {resp}"
    );

    let info = send_and_read(&mut observer, &["INFO"]);
    assert!(
        info.contains("blocked_stream_waiters:0"),
        "timed-out XREAD waiter must be removed: {info}"
    );
}

#[test]
fn repeated_xread_block_timeouts_do_not_accumulate_waiters() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    conn.set_read_timeout(Some(Duration::from_millis(1000)))
        .unwrap();

    for _ in 0..5 {
        let resp = send_and_read(
            &mut conn,
            &["XREAD", "BLOCK", "25", "STREAMS", "churn-stream", "$"],
        );
        assert!(
            resp.contains("*-1"),
            "XREAD timeout returns null array: {resp}"
        );
    }

    let info = send_and_read(&mut conn, &["INFO"]);
    assert!(
        info.contains("blocked_stream_waiters:0"),
        "stream waiters should not leak across timeout churn: {info}"
    );
}

#[test]
fn xpending_summary() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    send_and_read(&mut conn, &["XADD", "s", "1-1", "f", "v"]);
    send_and_read(&mut conn, &["XGROUP", "CREATE", "s", "g", "0"]);
    send_and_read(
        &mut conn,
        &["XREADGROUP", "GROUP", "g", "c", "STREAMS", "s", ">"],
    );
    let resp = send_and_read(&mut conn, &["XPENDING", "s", "g"]);
    assert!(resp.contains(":1"), "1 pending: {resp}");
}

#[test]
fn xtrim_limits_length() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    for i in 0..10 {
        send_and_read(&mut conn, &["XADD", "s", "*", "i", &i.to_string()]);
    }
    let resp = send_and_read(&mut conn, &["XTRIM", "s", "MAXLEN", "5"]);
    assert!(resp.contains(":5"), "trimmed 5: {resp}");
    let resp = send_and_read(&mut conn, &["XLEN", "s"]);
    assert!(resp.contains(":5"), "len is 5: {resp}");
}

#[test]
fn xgroup_create_duplicate_returns_busygroup() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    send_and_read(&mut conn, &["XADD", "s", "*", "f", "v"]);
    let ok = send_and_read(&mut conn, &["XGROUP", "CREATE", "s", "g", "0"]);
    assert!(ok.contains("OK"), "first create ok: {ok}");
    let dup = send_and_read(&mut conn, &["XGROUP", "CREATE", "s", "g", "0"]);
    assert!(
        dup.contains("BUSYGROUP"),
        "duplicate group must return BUSYGROUP: {dup}"
    );
}

#[test]
fn xgroup_create_mkstream_makes_empty_stream() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    // key does not exist yet; MKSTREAM creates it
    let resp = send_and_read(&mut conn, &["XGROUP", "CREATE", "ns", "g", "$", "MKSTREAM"]);
    assert!(resp.contains("OK"), "mkstream create ok: {resp}");
    let len = send_and_read(&mut conn, &["XLEN", "ns"]);
    assert!(len.contains(":0"), "mkstream stream is empty: {len}");
    // without MKSTREAM on a missing key -> error
    let err = send_and_read(&mut conn, &["XGROUP", "CREATE", "missing", "g", "$"]);
    assert!(
        err.contains("requires the key to exist") || err.contains("MKSTREAM"),
        "missing key without MKSTREAM errors: {err}"
    );
}

#[test]
fn xgroup_createconsumer_accounting() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    send_and_read(&mut conn, &["XADD", "s", "*", "f", "v"]);
    send_and_read(&mut conn, &["XGROUP", "CREATE", "s", "g", "0"]);
    let first = send_and_read(&mut conn, &["XGROUP", "CREATECONSUMER", "s", "g", "c1"]);
    assert!(first.contains(":1"), "new consumer returns 1: {first}");
    let again = send_and_read(&mut conn, &["XGROUP", "CREATECONSUMER", "s", "g", "c1"]);
    assert!(again.contains(":0"), "existing consumer returns 0: {again}");
    // consumer shows up in XINFO CONSUMERS with 0 pending
    let info = send_and_read(&mut conn, &["XINFO", "CONSUMERS", "s", "g"]);
    assert!(info.contains("c1"), "consumer listed: {info}");
    assert!(info.contains("pending"), "has pending field: {info}");
}

#[test]
fn xgroup_delconsumer_returns_pending_and_removes() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    send_and_read(&mut conn, &["XADD", "s", "*", "f", "v1"]);
    send_and_read(&mut conn, &["XADD", "s", "*", "f", "v2"]);
    send_and_read(&mut conn, &["XGROUP", "CREATE", "s", "g", "0"]);
    // c1 reads both -> 2 pending
    send_and_read(
        &mut conn,
        &["XREADGROUP", "GROUP", "g", "c1", "STREAMS", "s", ">"],
    );
    let before = send_and_read(&mut conn, &["XINFO", "GROUPS", "s"]);
    assert!(before.contains("pending"), "groups info shape: {before}");
    // delconsumer returns the 2 pending it owned
    let del = send_and_read(&mut conn, &["XGROUP", "DELCONSUMER", "s", "g", "c1"]);
    assert!(
        del.contains(":2"),
        "delconsumer returns owned pending count: {del}"
    );
    // consumer is gone
    let info = send_and_read(&mut conn, &["XINFO", "CONSUMERS", "s", "g"]);
    assert!(info.contains("*0"), "no consumers left: {info}");
    // group PEL drained
    let summary = send_and_read(&mut conn, &["XPENDING", "s", "g"]);
    assert!(summary.contains(":0"), "group pending drained: {summary}");
}

#[test]
fn xgroup_consumer_ops_missing_group_return_nogroup() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    send_and_read(&mut conn, &["XADD", "s", "*", "f", "v"]);
    // no group created
    let cc = send_and_read(&mut conn, &["XGROUP", "CREATECONSUMER", "s", "nope", "c1"]);
    assert!(cc.contains("NOGROUP"), "createconsumer missing group: {cc}");
    let dc = send_and_read(&mut conn, &["XGROUP", "DELCONSUMER", "s", "nope", "c1"]);
    assert!(dc.contains("NOGROUP"), "delconsumer missing group: {dc}");
    let xi = send_and_read(&mut conn, &["XINFO", "CONSUMERS", "s", "nope"]);
    assert!(
        xi.contains("NOGROUP"),
        "xinfo consumers missing group: {xi}"
    );
}

#[test]
fn xinfo_consumers_empty_group_is_empty_array() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    send_and_read(&mut conn, &["XADD", "s", "*", "f", "v"]);
    send_and_read(&mut conn, &["XGROUP", "CREATE", "s", "g", "0"]);
    let info = send_and_read(&mut conn, &["XINFO", "CONSUMERS", "s", "g"]);
    assert!(
        info.contains("*0"),
        "empty group -> empty consumers array: {info}"
    );
}

#[test]
fn xgroup_help_returns_array() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    let help = send_and_read(&mut conn, &["XGROUP", "HELP"]);
    assert!(help.contains("CREATE"), "help mentions CREATE: {help}");
    assert!(
        help.contains("DELCONSUMER"),
        "help mentions DELCONSUMER: {help}"
    );
}
