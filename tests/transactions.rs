mod common;
use common::{send_and_read, LuxServer};

#[test]
fn multi_set_get_exec_returns_array() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    let resp = send_and_read(&mut conn, &["MULTI"]);
    assert!(resp.contains("+OK"), "MULTI: {resp}");

    let resp = send_and_read(&mut conn, &["SET", "txkey", "txval"]);
    assert!(resp.contains("+QUEUED"), "SET queued: {resp}");

    let resp = send_and_read(&mut conn, &["GET", "txkey"]);
    assert!(resp.contains("+QUEUED"), "GET queued: {resp}");

    let resp = send_and_read(&mut conn, &["EXEC"]);
    assert!(resp.contains("*2"), "EXEC array: {resp}");
    assert!(resp.contains("+OK"), "EXEC contains SET OK: {resp}");
    assert!(resp.contains("txval"), "EXEC contains GET result: {resp}");
}

#[test]
fn multi_discard_clears_queue() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(&mut conn, &["MULTI"]);
    send_and_read(&mut conn, &["SET", "dkey", "dval"]);
    let resp = send_and_read(&mut conn, &["DISCARD"]);
    assert!(resp.contains("+OK"), "DISCARD: {resp}");

    let resp = send_and_read(&mut conn, &["GET", "dkey"]);
    assert!(resp.contains("$-1"), "key should not exist: {resp}");
}

#[test]
fn watch_no_conflict_succeeds() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(&mut conn, &["SET", "wkey", "orig"]);
    send_and_read(&mut conn, &["WATCH", "wkey"]);
    send_and_read(&mut conn, &["MULTI"]);
    send_and_read(&mut conn, &["SET", "wkey", "updated"]);
    let resp = send_and_read(&mut conn, &["EXEC"]);
    assert!(resp.contains("*1"), "EXEC should succeed: {resp}");

    let resp = send_and_read(&mut conn, &["GET", "wkey"]);
    assert!(resp.contains("updated"), "value should be updated: {resp}");
}

#[test]
fn watch_conflict_aborts_exec() {
    let server = LuxServer::start();
    let mut conn1 = server.conn();
    let mut conn2 = server.conn();

    send_and_read(&mut conn1, &["SET", "ckey", "orig"]);
    send_and_read(&mut conn1, &["WATCH", "ckey"]);
    send_and_read(&mut conn1, &["MULTI"]);
    send_and_read(&mut conn1, &["SET", "ckey", "from_tx"]);

    send_and_read(&mut conn2, &["SET", "ckey", "from_other"]);

    let resp = send_and_read(&mut conn1, &["EXEC"]);
    assert!(resp.contains("*-1"), "EXEC should return nil array: {resp}");

    let resp = send_and_read(&mut conn1, &["GET", "ckey"]);
    assert!(
        resp.contains("from_other"),
        "value should be from other client: {resp}"
    );
}

#[test]
fn nested_multi_returns_error() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(&mut conn, &["MULTI"]);
    let resp = send_and_read(&mut conn, &["MULTI"]);
    assert!(
        resp.contains("ERR Command 'multi' not allowed inside a transaction"),
        "nested MULTI: {resp}"
    );
    let resp = send_and_read(&mut conn, &["EXEC"]);
    assert!(resp.contains("EXECABORT"), "EXEC after error: {resp}");
}

#[test]
fn subscribe_inside_multi_returns_error() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(&mut conn, &["MULTI"]);
    let resp = send_and_read(&mut conn, &["SUBSCRIBE", "chan"]);
    assert!(
        resp.contains("ERR Command 'subscribe' not allowed inside a transaction"),
        "SUBSCRIBE in MULTI should error: {resp}"
    );
    let resp = send_and_read(&mut conn, &["EXEC"]);
    assert!(
        resp.contains("EXECABORT"),
        "EXEC after SUBSCRIBE error: {resp}"
    );
}

#[test]
fn empty_multi_exec_returns_empty_array() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(&mut conn, &["MULTI"]);
    let resp = send_and_read(&mut conn, &["EXEC"]);
    assert!(resp.contains("*0"), "empty EXEC: {resp}");
}

#[test]
fn watch_unwatch_exec_succeeds_despite_conflict() {
    let server = LuxServer::start();
    let mut conn1 = server.conn();
    let mut conn2 = server.conn();

    send_and_read(&mut conn1, &["SET", "ukey", "orig"]);
    send_and_read(&mut conn1, &["WATCH", "ukey"]);
    send_and_read(&mut conn1, &["UNWATCH"]);

    send_and_read(&mut conn2, &["SET", "ukey", "changed"]);

    send_and_read(&mut conn1, &["MULTI"]);
    send_and_read(&mut conn1, &["SET", "ukey", "from_tx"]);
    let resp = send_and_read(&mut conn1, &["EXEC"]);
    assert!(
        resp.contains("*1"),
        "EXEC should succeed after UNWATCH: {resp}"
    );

    let resp = send_and_read(&mut conn1, &["GET", "ukey"]);
    assert!(resp.contains("from_tx"), "value should be from tx: {resp}");
}

#[test]
fn exec_without_multi_returns_error() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    let resp = send_and_read(&mut conn, &["EXEC"]);
    assert!(
        resp.contains("ERR EXEC without MULTI"),
        "EXEC error: {resp}"
    );
}

#[test]
fn discard_without_multi_returns_error() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    let resp = send_and_read(&mut conn, &["DISCARD"]);
    assert!(
        resp.contains("ERR DISCARD without MULTI"),
        "DISCARD error: {resp}"
    );
}

#[test]
fn watch_inside_multi_returns_error() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(&mut conn, &["MULTI"]);
    let resp = send_and_read(&mut conn, &["WATCH", "somekey"]);
    assert!(
        resp.contains("ERR Command 'watch' not allowed inside a transaction"),
        "WATCH in MULTI: {resp}"
    );
    let resp = send_and_read(&mut conn, &["EXEC"]);
    assert!(resp.contains("EXECABORT"), "EXEC after WATCH error: {resp}");
}

#[test]
fn multi_incr_exec_returns_results() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(&mut conn, &["SET", "counter", "10"]);
    send_and_read(&mut conn, &["MULTI"]);
    send_and_read(&mut conn, &["INCR", "counter"]);
    send_and_read(&mut conn, &["INCR", "counter"]);
    let resp = send_and_read(&mut conn, &["EXEC"]);
    assert!(resp.contains("*2"), "EXEC array of 2: {resp}");
    assert!(resp.contains(":11"), "first INCR result: {resp}");
    assert!(resp.contains(":12"), "second INCR result: {resp}");
}

#[test]
fn bad_args_in_multi_not_queued() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(&mut conn, &["MULTI"]);
    let resp = send_and_read(&mut conn, &["SET", "only_key"]);
    assert!(
        resp.contains("ERR wrong number"),
        "bad args should error: {resp}"
    );

    send_and_read(&mut conn, &["SET", "ok_key", "ok_val"]);
    let resp = send_and_read(&mut conn, &["EXEC"]);
    assert!(
        resp.contains("EXECABORT"),
        "EXEC should abort after bad args: {resp}"
    );
}

#[test]
fn watch_multi_keys_one_modified_aborts() {
    let server = LuxServer::start();
    let mut conn1 = server.conn();
    let mut conn2 = server.conn();

    send_and_read(&mut conn1, &["SET", "x", "30"]);
    send_and_read(&mut conn1, &["WATCH", "a", "b", "x", "k", "z"]);

    send_and_read(&mut conn2, &["SET", "x", "40"]);

    send_and_read(&mut conn1, &["MULTI"]);
    send_and_read(&mut conn1, &["PING"]);
    let resp = send_and_read(&mut conn1, &["EXEC"]);
    assert!(
        resp.contains("*-1"),
        "modifying 1 of 5 watched keys should abort: {resp}"
    );
}

#[test]
fn execabort_clears_multi_state() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(&mut conn, &["MULTI"]);
    send_and_read(&mut conn, &["SET", "foo", "bar"]);
    send_and_read(&mut conn, &["NOTACOMMAND"]);
    send_and_read(&mut conn, &["SET", "foo2", "bar2"]);
    let resp = send_and_read(&mut conn, &["EXEC"]);
    assert!(resp.contains("EXECABORT"), "should abort: {resp}");

    let resp = send_and_read(&mut conn, &["PING"]);
    assert!(resp.contains("PONG"), "should be back to normal: {resp}");
}

#[test]
fn after_successful_exec_watch_is_cleared() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(&mut conn, &["SET", "x", "30"]);
    send_and_read(&mut conn, &["WATCH", "x"]);
    send_and_read(&mut conn, &["MULTI"]);
    send_and_read(&mut conn, &["PING"]);
    let resp = send_and_read(&mut conn, &["EXEC"]);
    assert!(resp.contains("PONG"), "first EXEC: {resp}");

    send_and_read(&mut conn, &["SET", "x", "40"]);
    send_and_read(&mut conn, &["MULTI"]);
    send_and_read(&mut conn, &["PING"]);
    let resp = send_and_read(&mut conn, &["EXEC"]);
    assert!(
        resp.contains("PONG"),
        "second EXEC should succeed, watch was cleared: {resp}"
    );
}

#[test]
fn after_failed_exec_watch_is_cleared() {
    let server = LuxServer::start();
    let mut conn1 = server.conn();
    let mut conn2 = server.conn();

    send_and_read(&mut conn1, &["SET", "x", "30"]);
    send_and_read(&mut conn1, &["WATCH", "x"]);
    send_and_read(&mut conn2, &["SET", "x", "40"]);
    send_and_read(&mut conn1, &["MULTI"]);
    send_and_read(&mut conn1, &["PING"]);
    let resp = send_and_read(&mut conn1, &["EXEC"]);
    assert!(resp.contains("*-1"), "first EXEC aborted: {resp}");

    send_and_read(&mut conn2, &["SET", "x", "50"]);
    send_and_read(&mut conn1, &["MULTI"]);
    send_and_read(&mut conn1, &["PING"]);
    let resp = send_and_read(&mut conn1, &["EXEC"]);
    assert!(
        resp.contains("PONG"),
        "second EXEC should succeed, watch cleared after abort: {resp}"
    );
}

#[test]
fn unwatch_with_nothing_watched() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    let resp = send_and_read(&mut conn, &["UNWATCH"]);
    assert!(resp.contains("+OK"), "UNWATCH on fresh connection: {resp}");
}

#[test]
fn flushall_invalidates_watch_on_existing_key() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(&mut conn, &["SET", "x", "30"]);
    send_and_read(&mut conn, &["WATCH", "x"]);
    send_and_read(&mut conn, &["FLUSHALL"]);
    send_and_read(&mut conn, &["MULTI"]);
    send_and_read(&mut conn, &["PING"]);
    let resp = send_and_read(&mut conn, &["EXEC"]);
    assert!(
        resp.contains("*-1"),
        "FLUSHALL should invalidate watch: {resp}"
    );
}

#[test]
fn flushdb_invalidates_watch_on_existing_key() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(&mut conn, &["SET", "x", "30"]);
    send_and_read(&mut conn, &["WATCH", "x"]);
    send_and_read(&mut conn, &["FLUSHDB"]);
    send_and_read(&mut conn, &["MULTI"]);
    send_and_read(&mut conn, &["PING"]);
    let resp = send_and_read(&mut conn, &["EXEC"]);
    assert!(
        resp.contains("*-1"),
        "FLUSHDB should invalidate watch: {resp}"
    );
}

#[test]
fn expire_touches_watched_key() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(&mut conn, &["SET", "x", "foo"]);
    send_and_read(&mut conn, &["WATCH", "x"]);
    send_and_read(&mut conn, &["EXPIRE", "x", "10"]);
    send_and_read(&mut conn, &["MULTI"]);
    send_and_read(&mut conn, &["PING"]);
    let resp = send_and_read(&mut conn, &["EXEC"]);
    assert!(
        resp.contains("*-1"),
        "EXPIRE should touch watched key: {resp}"
    );
}

#[test]
fn discard_clears_watch_dirty_flag() {
    let server = LuxServer::start();
    let mut conn1 = server.conn();
    let mut conn2 = server.conn();

    send_and_read(&mut conn1, &["SET", "x", "10"]);
    send_and_read(&mut conn1, &["WATCH", "x"]);
    send_and_read(&mut conn2, &["SET", "x", "10"]);
    send_and_read(&mut conn1, &["MULTI"]);
    send_and_read(&mut conn1, &["DISCARD"]);

    send_and_read(&mut conn1, &["MULTI"]);
    send_and_read(&mut conn1, &["INCR", "x"]);
    let resp = send_and_read(&mut conn1, &["EXEC"]);
    assert!(
        resp.contains(":11"),
        "DISCARD should clear dirty flag, INCR should work: {resp}"
    );
}

#[test]
fn discard_fully_unwatches_keys() {
    let server = LuxServer::start();
    let mut conn1 = server.conn();
    let mut conn2 = server.conn();

    send_and_read(&mut conn1, &["SET", "x", "10"]);
    send_and_read(&mut conn1, &["WATCH", "x"]);
    send_and_read(&mut conn2, &["SET", "x", "10"]);
    send_and_read(&mut conn1, &["MULTI"]);
    send_and_read(&mut conn1, &["DISCARD"]);

    send_and_read(&mut conn2, &["SET", "x", "10"]);

    send_and_read(&mut conn1, &["MULTI"]);
    send_and_read(&mut conn1, &["INCR", "x"]);
    let resp = send_and_read(&mut conn1, &["EXEC"]);
    assert!(
        resp.contains(":11"),
        "DISCARD should unwatch, second write should not conflict: {resp}"
    );
}

#[test]
fn flushall_watch_multi_keys_stability() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(&mut conn, &["MSET", "a", "a", "b", "b"]);
    send_and_read(&mut conn, &["WATCH", "b", "a"]);
    send_and_read(&mut conn, &["FLUSHALL"]);
    let resp = send_and_read(&mut conn, &["PING"]);
    assert!(resp.contains("PONG"), "should not crash: {resp}");
    let resp = send_and_read(&mut conn, &["UNWATCH"]);
    assert!(resp.contains("+OK"), "UNWATCH after FLUSHALL: {resp}");
}

#[test]
fn unknown_command_in_multi_causes_execabort() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(&mut conn, &["MULTI"]);
    send_and_read(&mut conn, &["SET", "foo1", "bar1"]);
    let resp = send_and_read(&mut conn, &["TOTALLYNOTACOMMAND"]);
    assert!(resp.contains("ERR unknown command"), "unknown cmd: {resp}");
    send_and_read(&mut conn, &["SET", "foo2", "bar2"]);
    let resp = send_and_read(&mut conn, &["EXEC"]);
    assert!(resp.contains("EXECABORT"), "EXEC should abort: {resp}");

    let resp = send_and_read(&mut conn, &["EXISTS", "foo1"]);
    assert!(resp.contains(":0"), "foo1 should not exist: {resp}");
    let resp = send_and_read(&mut conn, &["EXISTS", "foo2"]);
    assert!(resp.contains(":0"), "foo2 should not exist: {resp}");
}

#[test]
fn watch_multiple_calls_accumulate() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(&mut conn, &["WATCH", "x", "y", "z"]);
    send_and_read(&mut conn, &["WATCH", "k"]);
    send_and_read(&mut conn, &["MULTI"]);
    send_and_read(&mut conn, &["PING"]);
    let resp = send_and_read(&mut conn, &["EXEC"]);
    assert!(
        resp.contains("PONG"),
        "multiple WATCH calls, no conflict: {resp}"
    );
}

#[test]
fn multi_with_mixed_data_types() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(&mut conn, &["MULTI"]);
    send_and_read(&mut conn, &["SET", "str", "hello"]);
    send_and_read(&mut conn, &["LPUSH", "list", "a", "b"]);
    send_and_read(&mut conn, &["SADD", "set", "x", "y"]);
    send_and_read(&mut conn, &["HSET", "hash", "f1", "v1"]);
    send_and_read(&mut conn, &["ZADD", "zset", "1", "m1"]);
    let resp = send_and_read(&mut conn, &["EXEC"]);
    assert!(resp.contains("*5"), "5 commands in array: {resp}");
    assert!(resp.contains("+OK"), "SET result: {resp}");

    let resp = send_and_read(&mut conn, &["GET", "str"]);
    assert!(resp.contains("hello"), "string was set: {resp}");
    let resp = send_and_read(&mut conn, &["LLEN", "list"]);
    assert!(resp.contains(":2"), "list has 2 items: {resp}");
    let resp = send_and_read(&mut conn, &["SCARD", "set"]);
    assert!(resp.contains(":2"), "set has 2 members: {resp}");
}

#[test]
fn publish_inside_multi_exec() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send_and_read(&mut conn, &["MULTI"]);
    send_and_read(&mut conn, &["PUBLISH", "chan", "msg"]);
    let resp = send_and_read(&mut conn, &["EXEC"]);
    assert!(resp.contains("*1"), "EXEC array: {resp}");
    assert!(resp.contains(":0"), "PUBLISH returns 0 subscribers: {resp}");
}

#[test]
fn watch_on_nonexistent_key_then_create_aborts() {
    let server = LuxServer::start();
    let mut conn1 = server.conn();
    let mut conn2 = server.conn();

    send_and_read(&mut conn1, &["DEL", "newkey"]);
    send_and_read(&mut conn1, &["WATCH", "newkey"]);

    send_and_read(&mut conn2, &["SET", "newkey", "created"]);

    send_and_read(&mut conn1, &["MULTI"]);
    send_and_read(&mut conn1, &["PING"]);
    let resp = send_and_read(&mut conn1, &["EXEC"]);
    assert!(
        resp.contains("*-1"),
        "creating a watched nonexistent key should abort: {resp}"
    );
}
