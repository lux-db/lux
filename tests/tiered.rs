use std::net::TcpStream;

mod common;
use common::{send, LuxServer};

fn fill_memory(conn: &mut TcpStream, count: usize) {
    let val = "x".repeat(10000);
    for i in 0..count {
        send(conn, &["SET", &format!("filler:{i}"), &val]);
    }
}

#[test]
fn tiered_cold_string_read() {
    let srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();
    send(&mut c, &["SET", "mykey", "myvalue"]);
    fill_memory(&mut c, 20);
    let resp = send(&mut c, &["GET", "mykey"]);
    assert!(resp.contains("myvalue"), "cold GET failed: {resp}");
}

#[test]
fn tiered_cold_hash_read() {
    let srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();
    send(
        &mut c,
        &["HSET", "myhash", "f1", "v1", "f2", "v2", "f3", "v3"],
    );
    fill_memory(&mut c, 20);
    let resp = send(&mut c, &["HGETALL", "myhash"]);
    assert!(resp.contains("f1"), "cold HGETALL missing f1: {resp}");
    assert!(resp.contains("v2"), "cold HGETALL missing v2: {resp}");
    assert!(resp.contains("f3"), "cold HGETALL missing f3: {resp}");
}

#[test]
fn tiered_cold_list_read() {
    let srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();
    send(&mut c, &["LPUSH", "mylist", "a", "b", "c"]);
    fill_memory(&mut c, 20);
    let resp = send(&mut c, &["LRANGE", "mylist", "0", "-1"]);
    assert!(resp.contains("a"), "cold LRANGE missing a: {resp}");
    assert!(resp.contains("b"), "cold LRANGE missing b: {resp}");
    assert!(resp.contains("c"), "cold LRANGE missing c: {resp}");
}

#[test]
fn tiered_cold_set_read() {
    let srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();
    send(&mut c, &["SADD", "myset", "x", "y", "z"]);
    fill_memory(&mut c, 20);
    let resp = send(&mut c, &["SMEMBERS", "myset"]);
    assert!(resp.contains("x"), "cold SMEMBERS missing x: {resp}");
    assert!(resp.contains("y"), "cold SMEMBERS missing y: {resp}");
}

#[test]
fn tiered_cold_sorted_set_read() {
    let srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();
    send(&mut c, &["ZADD", "myzset", "1.5", "alpha", "2.5", "beta"]);
    fill_memory(&mut c, 20);
    let resp = send(&mut c, &["ZRANGE", "myzset", "0", "-1", "WITHSCORES"]);
    assert!(resp.contains("alpha"), "cold ZRANGE missing alpha: {resp}");
    assert!(resp.contains("beta"), "cold ZRANGE missing beta: {resp}");
}

#[test]
fn tiered_cold_key_mutation() {
    let srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();
    send(&mut c, &["HSET", "h", "f1", "v1", "f2", "v2"]);
    fill_memory(&mut c, 20);
    send(&mut c, &["HSET", "h", "f3", "v3"]);
    let resp = send(&mut c, &["HGETALL", "h"]);
    assert!(resp.contains("f1"), "mutation lost f1: {resp}");
    assert!(resp.contains("f2"), "mutation lost f2: {resp}");
    assert!(resp.contains("f3"), "mutation missing f3: {resp}");
}

#[test]
fn tiered_cold_list_mutation() {
    let srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();
    send(&mut c, &["LPUSH", "l", "a", "b", "c"]);
    fill_memory(&mut c, 20);
    send(&mut c, &["LPUSH", "l", "d"]);
    let resp = send(&mut c, &["LLEN", "l"]);
    assert!(resp.contains(":4"), "LLEN should be 4: {resp}");
}

#[test]
fn tiered_cold_incr() {
    let srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();
    send(&mut c, &["SET", "counter", "100"]);
    fill_memory(&mut c, 20);
    let resp = send(&mut c, &["INCR", "counter"]);
    assert!(
        resp.contains(":101"),
        "INCR cold counter should be 101: {resp}"
    );
}

#[test]
fn tiered_del_cold_key() {
    let srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();
    send(&mut c, &["SET", "delme", "exists"]);
    fill_memory(&mut c, 20);
    let del_resp = send(&mut c, &["DEL", "delme"]);
    assert!(
        del_resp.contains(":1"),
        "DEL cold key should return 1: {del_resp}"
    );
    let exists_resp = send(&mut c, &["EXISTS", "delme"]);
    assert!(
        exists_resp.contains(":0"),
        "EXISTS after DEL should be 0: {exists_resp}"
    );
}

#[test]
fn tiered_exists_cold_key() {
    let srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();
    send(&mut c, &["SET", "ekey", "val"]);
    fill_memory(&mut c, 20);
    let resp = send(&mut c, &["EXISTS", "ekey"]);
    assert!(resp.contains(":1"), "EXISTS cold key should be 1: {resp}");
}

#[test]
fn tiered_type_cold_key() {
    let srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();
    send(&mut c, &["HSET", "tyh", "f", "v"]);
    fill_memory(&mut c, 20);
    let resp = send(&mut c, &["TYPE", "tyh"]);
    assert!(resp.contains("hash"), "TYPE cold hash: {resp}");
}

#[test]
fn tiered_keys_includes_cold() {
    let srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();
    send(&mut c, &["SET", "coldpattern:1", "a"]);
    send(&mut c, &["SET", "coldpattern:2", "b"]);
    fill_memory(&mut c, 20);
    let resp = send(&mut c, &["KEYS", "coldpattern:*"]);
    assert!(
        resp.contains("coldpattern:1"),
        "KEYS should include cold key 1: {resp}"
    );
    assert!(
        resp.contains("coldpattern:2"),
        "KEYS should include cold key 2: {resp}"
    );
}

#[test]
fn tiered_dbsize_includes_cold() {
    let srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();
    for i in 0..10 {
        send(&mut c, &["SET", &format!("dbkey:{i}"), "val"]);
    }
    fill_memory(&mut c, 20);
    let resp = send(&mut c, &["DBSIZE"]);
    let size: i64 = resp
        .trim()
        .strip_prefix(':')
        .unwrap_or("0")
        .trim()
        .parse()
        .unwrap_or(0);
    assert!(size >= 30, "DBSIZE should include cold keys: {size}");
}

#[test]
fn tiered_wal_crash_recovery() {
    let mut srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();
    send(&mut c, &["SET", "wal_str", "survives"]);
    send(&mut c, &["HSET", "wal_hash", "f1", "v1", "f2", "v2"]);
    send(&mut c, &["LPUSH", "wal_list", "a", "b", "c"]);
    send(&mut c, &["SADD", "wal_set", "x", "y"]);
    send(&mut c, &["ZADD", "wal_zset", "1", "m1", "2", "m2"]);
    drop(c);

    srv.restart();
    let mut c = srv.conn();

    let resp = send(&mut c, &["GET", "wal_str"]);
    assert!(resp.contains("survives"), "WAL string recovery: {resp}");

    let resp = send(&mut c, &["HGETALL", "wal_hash"]);
    assert!(resp.contains("f1"), "WAL hash recovery f1: {resp}");
    assert!(resp.contains("v2"), "WAL hash recovery v2: {resp}");

    let resp = send(&mut c, &["LRANGE", "wal_list", "0", "-1"]);
    assert!(resp.contains("a"), "WAL list recovery: {resp}");

    let resp = send(&mut c, &["SMEMBERS", "wal_set"]);
    assert!(resp.contains("x"), "WAL set recovery: {resp}");

    let resp = send(&mut c, &["ZRANGE", "wal_zset", "0", "-1"]);
    assert!(resp.contains("m1"), "WAL zset recovery: {resp}");
}

#[test]
fn tiered_wal_overwrite_ordering() {
    let mut srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();
    send(&mut c, &["SET", "ow", "first"]);
    send(&mut c, &["SET", "ow", "second"]);
    send(&mut c, &["SET", "ow", "third"]);
    drop(c);

    srv.restart();
    let mut c = srv.conn();
    let resp = send(&mut c, &["GET", "ow"]);
    assert!(
        resp.contains("third"),
        "overwrite should be 'third': {resp}"
    );
}

#[test]
fn tiered_wal_set_then_del() {
    let mut srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();
    send(&mut c, &["SET", "delwal", "exists"]);
    send(&mut c, &["DEL", "delwal"]);
    drop(c);

    srv.restart();
    let mut c = srv.conn();
    let resp = send(&mut c, &["EXISTS", "delwal"]);
    assert!(
        resp.contains(":0"),
        "DEL'd key should stay deleted after WAL replay: {resp}"
    );
}

#[test]
fn tiered_snapshot_includes_cold() {
    let mut srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();
    send(&mut c, &["SET", "snapcold", "value"]);
    fill_memory(&mut c, 20);
    let exists = send(&mut c, &["EXISTS", "snapcold"]);
    assert!(exists.contains(":1"), "key should exist (cold): {exists}");
    send(&mut c, &["SAVE"]);
    drop(c);

    srv.restart();
    let mut c = srv.conn();
    let resp = send(&mut c, &["GET", "snapcold"]);
    assert!(
        resp.contains("value"),
        "cold key should survive snapshot+restart: {resp}"
    );
}

#[test]
fn tiered_flushdb_clears_disk() {
    let srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();
    send(&mut c, &["SET", "fkey", "fval"]);
    fill_memory(&mut c, 20);
    send(&mut c, &["FLUSHDB"]);
    let resp = send(&mut c, &["DBSIZE"]);
    assert!(
        resp.contains(":0"),
        "FLUSHDB should clear everything: {resp}"
    );
    let resp = send(&mut c, &["EXISTS", "fkey"]);
    assert!(
        resp.contains(":0"),
        "flushed cold key should not exist: {resp}"
    );
}
