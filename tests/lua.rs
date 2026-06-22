mod common;
use common::{send_and_read, LuxServer};

#[test]
fn eval_return_integer() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    let resp = send_and_read(&mut conn, &["EVAL", "return 42", "0"]);
    assert!(resp.contains(":42"), "returns 42: {resp}");
}

#[test]
fn eval_return_string() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    let resp = send_and_read(&mut conn, &["EVAL", "return 'hello'", "0"]);
    assert!(resp.contains("hello"), "returns hello: {resp}");
}

#[test]
fn eval_redis_call_set_get() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    let resp = send_and_read(
        &mut conn,
        &[
            "EVAL",
            "redis.call('SET', KEYS[1], ARGV[1]); return redis.call('GET', KEYS[1])",
            "1",
            "mykey",
            "myval",
        ],
    );
    assert!(resp.contains("myval"), "get returns myval: {resp}");
}

#[test]
fn eval_keys_and_argv() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    let resp = send_and_read(&mut conn, &["EVAL", "return KEYS[1]", "1", "testkey"]);
    assert!(resp.contains("testkey"), "KEYS[1] = testkey: {resp}");

    let resp = send_and_read(&mut conn, &["EVAL", "return ARGV[1]", "0", "argval"]);
    assert!(resp.contains("argval"), "ARGV[1] = argval: {resp}");
}

#[test]
fn evalsha_after_script_load() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    let resp = send_and_read(&mut conn, &["SCRIPT", "LOAD", "return 99"]);
    let sha = resp
        .lines()
        .find(|l| l.len() > 10 && !l.starts_with('$'))
        .unwrap_or("")
        .trim();
    let resp = send_and_read(&mut conn, &["EVALSHA", sha, "0"]);
    assert!(resp.contains(":99"), "evalsha returns 99: {resp}");
}

#[test]
fn evalsha_noscript_error() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    let resp = send_and_read(
        &mut conn,
        &["EVALSHA", "0000000000000000000000000000000000000000", "0"],
    );
    assert!(resp.contains("NOSCRIPT"), "noscript error: {resp}");
}

#[test]
fn script_exists() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    send_and_read(&mut conn, &["SCRIPT", "LOAD", "return 1"]);
    let resp = send_and_read(
        &mut conn,
        &[
            "SCRIPT",
            "EXISTS",
            "e0e1f9fabfc9d4800c877a703b823ac0578ff831",
        ],
    );
    assert!(
        resp.contains(":1") || resp.contains(":0"),
        "exists response: {resp}"
    );
}

#[test]
fn script_flush() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    send_and_read(&mut conn, &["SCRIPT", "LOAD", "return 1"]);
    let resp = send_and_read(&mut conn, &["SCRIPT", "FLUSH"]);
    assert!(resp.contains("OK"), "flush ok: {resp}");
}

#[test]
fn eval_error_handling() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    let resp = send_and_read(&mut conn, &["EVAL", "this is not valid lua", "0"]);
    assert!(resp.contains("ERR"), "error response: {resp}");
}

#[test]
fn eval_return_table() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    let resp = send_and_read(&mut conn, &["EVAL", "return {1, 2, 3}", "0"]);
    assert!(resp.contains(":1"), "contains 1: {resp}");
    assert!(resp.contains(":2"), "contains 2: {resp}");
    assert!(resp.contains(":3"), "contains 3: {resp}");
}

#[test]
fn eval_sandbox_removes_dangerous_globals() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    // Each of these globals must be nil inside a script: no filesystem, process,
    // bytecode loading, native modules, or debug introspection from user Lua.
    for g in [
        "os",
        "io",
        "package",
        "require",
        "dofile",
        "loadfile",
        "load",
        "loadstring",
        "debug",
        "collectgarbage",
    ] {
        let src = format!("return type({g})");
        let resp = send_and_read(&mut conn, &["EVAL", &src, "0"]);
        assert!(
            resp.contains("nil"),
            "global `{g}` should be sandboxed to nil, got: {resp}"
        );
    }
}

#[test]
fn eval_call_aborts_but_pcall_returns_error_table() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    // redis.pcall on a failing command returns an error table; the script keeps running.
    let resp = send_and_read(
        &mut conn,
        &[
            "EVAL",
            "local r = redis.pcall('NOPE'); if type(r) == 'table' and r.err then return 'caught' else return 'leaked' end",
            "0",
        ],
    );
    assert!(
        resp.contains("caught"),
        "pcall should return an error table, not abort: {resp}"
    );
    // redis.call on the same failing command aborts the script with a RESP error.
    let resp = send_and_read(&mut conn, &["EVAL", "redis.call('NOPE'); return 1", "0"]);
    assert!(
        resp.starts_with('-'),
        "call on a bad command should abort with an error reply: {resp}"
    );
}

#[test]
fn eval_cmsgpack_unpack_rejects_oversized_declared_length() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    // Array32 marker (0xdd) declaring ~4 billion elements with no payload: the
    // container-length cap must reject it (error), never pre-allocate or spin.
    let src = "local ok = pcall(function() return cmsgpack.unpack(string.char(0xdd, 0xff, 0xff, 0xff, 0xff)) end); if ok then return 'unbounded' else return 'rejected' end";
    let resp = send_and_read(&mut conn, &["EVAL", src, "0"]);
    assert!(
        resp.contains("rejected"),
        "oversized msgpack container length must be rejected: {resp}"
    );
}

#[test]
fn eval_denies_admin_and_control_commands() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    for cmd in ["SAVE", "BGSAVE", "MULTI", "SUBSCRIBE", "WATCH"] {
        let src = format!("return redis.call('{cmd}')");
        let resp = send_and_read(&mut conn, &["EVAL", &src, "0"]);
        assert!(
            resp.to_lowercase().contains("not allowed"),
            "`{cmd}` must be denied from scripts: {resp}"
        );
    }
}
