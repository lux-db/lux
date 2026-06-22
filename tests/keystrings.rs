mod common;
use common::{send, LuxServer};

fn assert_has(resp: &str, needle: &str) {
    assert!(resp.contains(needle), "missing {needle:?}: {resp}");
}

fn assert_error(resp: &str) {
    assert!(resp.starts_with("-ERR"), "expected error, got: {resp}");
}

#[test]
fn string_command_surface() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    assert_has(&send(&mut conn, &["SET", "s", "hello"]), "+OK");
    assert_has(&send(&mut conn, &["GET", "s"]), "hello");
    assert_has(&send(&mut conn, &["APPEND", "s", "-world"]), ":11");
    assert_has(&send(&mut conn, &["STRLEN", "s"]), ":11");
    assert_has(&send(&mut conn, &["GETRANGE", "s", "0", "4"]), "hello");
    assert_has(&send(&mut conn, &["SETRANGE", "s", "6", "Lux"]), ":11");
    assert_has(&send(&mut conn, &["GET", "s"]), "hello-Luxld");
    assert_has(&send(&mut conn, &["GETSET", "s", "old"]), "hello-Luxld");
    assert_has(&send(&mut conn, &["GETDEL", "s"]), "old");
    assert_has(&send(&mut conn, &["GET", "s"]), "$-1");

    assert_has(&send(&mut conn, &["MSET", "a", "1", "b", "2"]), "+OK");
    assert_has(&send(&mut conn, &["MGET", "a", "b", "missing"]), "*3");
    assert_has(&send(&mut conn, &["MSETNX", "a", "x", "c", "3"]), ":0");
    assert_has(&send(&mut conn, &["MSETNX", "c", "3", "d", "4"]), ":1");
}

#[test]
fn numeric_string_commands_and_set_options() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    assert_has(&send(&mut conn, &["INCR", "n"]), ":1");
    assert_has(&send(&mut conn, &["INCRBY", "n", "9"]), ":10");
    assert_has(&send(&mut conn, &["DECR", "n"]), ":9");
    assert_has(&send(&mut conn, &["DECRBY", "n", "4"]), ":5");
    assert_has(&send(&mut conn, &["INCRBYFLOAT", "f", "1.25"]), "1.25");

    assert_has(&send(&mut conn, &["SET", "nx", "first", "NX"]), "+OK");
    assert_has(&send(&mut conn, &["SET", "nx", "second", "NX"]), "$-1");
    assert_has(&send(&mut conn, &["SET", "nx", "second", "XX"]), "+OK");
    assert_has(&send(&mut conn, &["GET", "nx"]), "second");

    assert_has(&send(&mut conn, &["SETEX", "ttl:s", "10", "v"]), "+OK");
    assert_has(&send(&mut conn, &["PSETEX", "ttl:p", "10000", "v"]), "+OK");
    assert_has(&send(&mut conn, &["GETEX", "ttl:s", "PERSIST"]), "v");
}

#[test]
fn string_commands_reject_invalid_arguments_without_mutating_state() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    assert_has(&send(&mut conn, &["SET", "s", "hello"]), "+OK");
    assert_error(&send(&mut conn, &["GETRANGE", "s", "nope", "1"]));
    assert_error(&send(&mut conn, &["GETRANGE", "s", "0", "nope"]));
    assert_error(&send(&mut conn, &["SETRANGE", "s", "nope", "X"]));
    assert_error(&send(
        &mut conn,
        &["SETRANGE", "s", "18446744073709551615", "X"],
    ));
    assert_has(&send(&mut conn, &["GET", "s"]), "hello");

    assert_has(&send(&mut conn, &["SET", "ttl", "original"]), "+OK");
    for cmd in [
        vec!["SET", "ttl", "replacement", "EX", "nope"],
        vec!["SET", "ttl", "replacement", "EX", "0"],
        vec!["SET", "ttl", "replacement", "PX", "nope"],
        vec!["SET", "ttl", "replacement", "PX", "0"],
        vec!["GETEX", "ttl", "EX", "nope"],
        vec!["GETEX", "ttl", "EX", "0"],
        vec!["GETEX", "ttl", "PX", "nope"],
        vec!["GETEX", "ttl", "PERSIST", "EX", "10"],
        vec!["GETEX", "ttl", "EX", "10", "PX", "10"],
    ] {
        assert_error(&send(&mut conn, &cmd));
    }
    assert_has(&send(&mut conn, &["GET", "ttl"]), "original");
    assert_has(&send(&mut conn, &["TTL", "ttl"]), ":-1");

    assert_has(&send(&mut conn, &["SET", "psetex", "keep"]), "+OK");
    assert_error(&send(&mut conn, &["PSETEX", "psetex", "0", "new"]));
    assert_error(&send(&mut conn, &["PSETEX", "psetex", "nope", "new"]));
    assert_has(&send(&mut conn, &["GET", "psetex"]), "keep");
}

#[test]
fn key_command_surface() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send(&mut conn, &["SET", "k1", "v1"]);
    send(&mut conn, &["SET", "k2", "v2"]);
    send(&mut conn, &["LPUSH", "list", "a"]);

    assert_has(&send(&mut conn, &["EXISTS", "k1", "missing"]), ":1");
    assert_has(&send(&mut conn, &["TYPE", "list"]), "list");
    assert_has(&send(&mut conn, &["KEYS", "k*"]), "k1");
    assert_has(
        &send(&mut conn, &["SCAN", "0", "MATCH", "k*", "COUNT", "10"]),
        "*2",
    );
    assert_has(&send(&mut conn, &["RANDOMKEY"]), "$");
    assert_has(&send(&mut conn, &["OBJECT", "ENCODING", "k1"]), "embstr");
    assert_has(&send(&mut conn, &["MEMORY", "USAGE", "k1"]), ":");

    assert_has(&send(&mut conn, &["COPY", "k1", "k3"]), ":1");
    assert_has(&send(&mut conn, &["GET", "k3"]), "v1");
    assert_has(&send(&mut conn, &["RENAME", "k3", "renamed"]), "+OK");
    assert_has(&send(&mut conn, &["RENAMENX", "renamed", "k1"]), ":0");
    assert_has(&send(&mut conn, &["RENAMENX", "renamed", "fresh"]), ":1");
    assert_has(&send(&mut conn, &["DEL", "fresh", "missing"]), ":1");
    assert_has(&send(&mut conn, &["UNLINK", "k2"]), ":1");
}

#[test]
fn scan_rejects_invalid_cursor_and_options() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send(&mut conn, &["SET", "k1", "v1"]);
    send(&mut conn, &["SET", "k2", "v2"]);

    for cmd in [
        vec!["SCAN", "nope"],
        vec!["SCAN", "0", "COUNT", "nope"],
        vec!["SCAN", "0", "COUNT", "0"],
        vec!["SCAN", "0", "UNKNOWN"],
    ] {
        assert_error(&send(&mut conn, &cmd));
    }

    assert_has(
        &send(&mut conn, &["SCAN", "0", "MATCH", "k*", "COUNT", "10"]),
        "*2",
    );
}

#[test]
fn expire_ttl_and_persist_surface() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    send(&mut conn, &["SET", "exp", "v"]);
    assert_has(&send(&mut conn, &["EXPIRE", "exp", "10"]), ":1");
    assert_has(&send(&mut conn, &["TTL", "exp"]), ":");
    assert_has(&send(&mut conn, &["PTTL", "exp"]), ":");
    assert_has(&send(&mut conn, &["EXPIRETIME", "exp"]), ":");
    assert_has(&send(&mut conn, &["PEXPIRETIME", "exp"]), ":");
    assert_has(&send(&mut conn, &["PERSIST", "exp"]), ":1");
    assert_has(&send(&mut conn, &["TTL", "exp"]), ":-1");
    assert_has(&send(&mut conn, &["PEXPIRE", "exp", "10000"]), ":1");
    assert_has(
        &send(&mut conn, &["PEXPIREAT", "exp", "9999999999999"]),
        ":1",
    );
    assert_has(&send(&mut conn, &["EXPIREAT", "exp", "9999999999"]), ":1");
}
