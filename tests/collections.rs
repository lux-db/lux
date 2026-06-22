mod common;
use common::{send, LuxServer};

fn assert_has(resp: &str, needle: &str) {
    assert!(resp.contains(needle), "missing {needle:?}: {resp}");
}

#[test]
fn hash_command_surface() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    assert_has(&send(&mut conn, &["HSET", "h", "a", "1", "b", "2"]), ":2");
    assert_has(&send(&mut conn, &["HGET", "h", "a"]), "1");
    assert_has(&send(&mut conn, &["HMGET", "h", "a", "missing", "b"]), "*3");
    assert_has(&send(&mut conn, &["HGETALL", "h"]), "a");
    assert_has(&send(&mut conn, &["HKEYS", "h"]), "a");
    assert_has(&send(&mut conn, &["HVALS", "h"]), "2");
    assert_has(&send(&mut conn, &["HLEN", "h"]), ":2");
    assert_has(&send(&mut conn, &["HEXISTS", "h", "a"]), ":1");
    assert_has(&send(&mut conn, &["HSTRLEN", "h", "a"]), ":1");
    assert_has(&send(&mut conn, &["HSETNX", "h", "a", "new"]), ":0");
    assert_has(&send(&mut conn, &["HINCRBY", "h", "n", "3"]), ":3");
    assert_has(&send(&mut conn, &["HINCRBYFLOAT", "h", "f", "1.5"]), "1.5");
    assert_has(
        &send(&mut conn, &["HRANDFIELD", "h", "2", "WITHVALUES"]),
        "*4",
    );
    assert_has(
        &send(&mut conn, &["HSCAN", "h", "0", "MATCH", "*", "COUNT", "10"]),
        "*2",
    );
    assert_has(&send(&mut conn, &["HDEL", "h", "a", "b"]), ":2");
}

#[test]
fn hscan_rejects_invalid_cursor_and_options() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    assert_has(&send(&mut conn, &["HSET", "h", "a", "1", "b", "2"]), ":2");

    for cmd in [
        vec!["HSCAN", "h", "nope"],
        vec!["HSCAN", "h", "0", "COUNT", "nope"],
        vec!["HSCAN", "h", "0", "COUNT", "0"],
        vec!["HSCAN", "h", "0", "UNKNOWN"],
    ] {
        let resp = send(&mut conn, &cmd);
        assert!(
            resp.starts_with("-ERR"),
            "expected error for {cmd:?}, got: {resp}"
        );
    }

    assert_has(
        &send(&mut conn, &["HSCAN", "h", "0", "MATCH", "*", "COUNT", "10"]),
        "*2",
    );
}

#[test]
fn list_command_surface() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    assert_has(&send(&mut conn, &["LPUSH", "l", "b", "a"]), ":2");
    assert_has(&send(&mut conn, &["RPUSH", "l", "c", "d"]), ":4");
    assert_has(&send(&mut conn, &["LLEN", "l"]), ":4");
    assert_has(&send(&mut conn, &["LINDEX", "l", "0"]), "a");
    assert_has(
        &send(&mut conn, &["LINSERT", "l", "BEFORE", "c", "x"]),
        ":5",
    );
    assert_has(&send(&mut conn, &["LPOS", "l", "x"]), ":2");
    assert_has(&send(&mut conn, &["LRANGE", "l", "0", "-1"]), "x");
    assert_has(&send(&mut conn, &["LSET", "l", "0", "first"]), "+OK");
    assert_has(&send(&mut conn, &["LREM", "l", "1", "x"]), ":1");
    assert_has(&send(&mut conn, &["LTRIM", "l", "0", "2"]), "+OK");
    assert_has(&send(&mut conn, &["RPOPLPUSH", "l", "other"]), "c");
    assert_has(
        &send(&mut conn, &["LMOVE", "other", "l", "LEFT", "RIGHT"]),
        "c",
    );
    assert_has(&send(&mut conn, &["LPOP", "l"]), "first");
    assert_has(&send(&mut conn, &["RPOP", "l"]), "c");
}

#[test]
fn list_commands_reject_invalid_arguments_without_mutating_state() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    assert_has(&send(&mut conn, &["RPUSH", "l", "a", "b", "a", "c"]), ":4");
    assert_has(&send(&mut conn, &["RPUSH", "dst", "d"]), ":1");

    for cmd in [
        vec!["LRANGE", "l", "nope", "-1"],
        vec!["LRANGE", "l", "0", "nope"],
        vec!["LINDEX", "l", "nope"],
        vec!["LSET", "l", "nope", "x"],
        vec!["LREM", "l", "nope", "a"],
        vec!["LTRIM", "l", "nope", "-1"],
        vec!["LTRIM", "l", "0", "nope"],
        vec!["LPOS", "l", "a", "RANK", "nope"],
        vec!["LPOS", "l", "a", "COUNT", "nope"],
        vec!["LPOS", "l", "a", "MAXLEN", "nope"],
        vec!["LPOS", "l", "a", "BADOPT"],
        vec!["LINSERT", "l", "MIDDLE", "a", "x"],
        vec!["LMOVE", "l", "dst", "MIDDLE", "LEFT"],
        vec!["LMOVE", "l", "dst", "LEFT", "MIDDLE"],
        vec!["BLMOVE", "l", "dst", "LEFT", "MIDDLE", "0"],
        vec!["BLMOVE", "l", "dst", "LEFT", "RIGHT", "nope"],
        vec!["BLPOP", "l", "nope"],
    ] {
        let resp = send(&mut conn, &cmd);
        assert!(
            resp.starts_with("-ERR"),
            "expected error for {cmd:?}, got: {resp}"
        );
    }

    assert_has(&send(&mut conn, &["LLEN", "l"]), ":4");
    assert_has(&send(&mut conn, &["LRANGE", "l", "0", "-1"]), "a");
    assert_has(&send(&mut conn, &["LRANGE", "l", "0", "-1"]), "c");
    assert_has(&send(&mut conn, &["LLEN", "dst"]), ":1");
    assert_has(&send(&mut conn, &["LRANGE", "dst", "0", "-1"]), "d");
}

#[test]
fn set_command_surface() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    assert_has(
        &send(&mut conn, &["SADD", "a", "one", "two", "three"]),
        ":3",
    );
    assert_has(
        &send(&mut conn, &["SADD", "b", "two", "three", "four"]),
        ":3",
    );
    assert_has(&send(&mut conn, &["SCARD", "a"]), ":3");
    assert_has(&send(&mut conn, &["SISMEMBER", "a", "one"]), ":1");
    assert_has(&send(&mut conn, &["SMISMEMBER", "a", "one", "nope"]), "*2");
    assert_has(&send(&mut conn, &["SMEMBERS", "a"]), "one");
    assert_has(&send(&mut conn, &["SRANDMEMBER", "a", "2"]), "*2");
    assert_has(&send(&mut conn, &["SINTER", "a", "b"]), "two");
    assert_has(&send(&mut conn, &["SUNION", "a", "b"]), "four");
    assert_has(&send(&mut conn, &["SDIFF", "a", "b"]), "one");
    assert_has(&send(&mut conn, &["SINTERCARD", "2", "a", "b"]), ":2");
    assert_has(&send(&mut conn, &["SUNIONSTORE", "u", "a", "b"]), ":4");
    assert_has(&send(&mut conn, &["SINTERSTORE", "i", "a", "b"]), ":2");
    assert_has(&send(&mut conn, &["SDIFFSTORE", "d", "a", "b"]), ":1");
    assert_has(&send(&mut conn, &["SMOVE", "a", "b", "one"]), ":1");
    assert_has(
        &send(&mut conn, &["SSCAN", "b", "0", "MATCH", "*", "COUNT", "10"]),
        "*2",
    );
    assert_has(&send(&mut conn, &["SPOP", "b"]), "$");
    assert_has(&send(&mut conn, &["SADD", "b", "removable"]), ":1");
    assert_has(&send(&mut conn, &["SREM", "b", "removable"]), ":1");
}

#[test]
fn set_count_commands_reject_invalid_arguments_without_mutating_state() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    assert_has(&send(&mut conn, &["SADD", "s", "a", "b", "c"]), ":3");
    assert_has(&send(&mut conn, &["SADD", "t", "b", "c"]), ":2");

    for cmd in [
        vec!["SPOP", "s", "nope"],
        vec!["SRANDMEMBER", "s", "nope"],
        vec!["SINTERCARD", "2", "s", "t", "LIMIT", "nope"],
    ] {
        let resp = send(&mut conn, &cmd);
        assert!(
            resp.starts_with("-ERR"),
            "expected error for {cmd:?}, got: {resp}"
        );
    }

    assert_has(&send(&mut conn, &["SCARD", "s"]), ":3");
    assert_has(&send(&mut conn, &["SMEMBERS", "s"]), "a");
    assert_has(&send(&mut conn, &["SMEMBERS", "s"]), "b");
    assert_has(&send(&mut conn, &["SMEMBERS", "s"]), "c");
}

#[test]
fn sorted_set_command_surface() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    assert_has(
        &send(
            &mut conn,
            &["ZADD", "z", "1", "one", "2", "two", "3", "three"],
        ),
        ":3",
    );
    assert_has(&send(&mut conn, &["ZADD", "z", "NX", "4", "four"]), ":1");
    assert_has(&send(&mut conn, &["ZADD", "z", "XX", "5", "four"]), ":0");
    assert_has(&send(&mut conn, &["ZSCORE", "z", "four"]), "5");
    assert_has(&send(&mut conn, &["ZMSCORE", "z", "one", "missing"]), "*2");
    assert_has(&send(&mut conn, &["ZRANK", "z", "one"]), ":0");
    assert_has(&send(&mut conn, &["ZREVRANK", "z", "four"]), ":0");
    assert_has(&send(&mut conn, &["ZCARD", "z"]), ":4");
    assert_has(&send(&mut conn, &["ZCOUNT", "z", "1", "5"]), ":4");
    assert_has(&send(&mut conn, &["ZINCRBY", "z", "2", "one"]), "3");
    assert_has(
        &send(&mut conn, &["ZRANGE", "z", "0", "-1", "WITHSCORES"]),
        "one",
    );
    assert_has(&send(&mut conn, &["ZREVRANGE", "z", "0", "1"]), "four");
    assert_has(&send(&mut conn, &["ZRANGEBYSCORE", "z", "2", "5"]), "two");
    assert_has(
        &send(&mut conn, &["ZREVRANGEBYSCORE", "z", "5", "2"]),
        "four",
    );
    assert_has(&send(&mut conn, &["ZPOPMIN", "z", "1"]), "*2");
    assert_has(&send(&mut conn, &["ZPOPMAX", "z", "1"]), "*2");

    assert_has(&send(&mut conn, &["ZADD", "za", "1", "a", "2", "b"]), ":2");
    assert_has(&send(&mut conn, &["ZADD", "zb", "2", "b", "3", "c"]), ":2");
    assert_has(
        &send(&mut conn, &["ZUNIONSTORE", "zu", "2", "za", "zb"]),
        ":3",
    );
    assert_has(
        &send(&mut conn, &["ZINTERSTORE", "zi", "2", "za", "zb"]),
        ":1",
    );
    assert_has(
        &send(&mut conn, &["ZDIFFSTORE", "zd", "2", "za", "zb"]),
        ":1",
    );
    assert_has(
        &send(
            &mut conn,
            &["ZSCAN", "zu", "0", "MATCH", "*", "COUNT", "10"],
        ),
        "*2",
    );
    assert_has(&send(&mut conn, &["ZREM", "zu", "a"]), ":1");
    assert_has(
        &send(&mut conn, &["ZREMRANGEBYSCORE", "zu", "0", "10"]),
        ":2",
    );

    assert_has(
        &send(&mut conn, &["ZADD", "lex", "0", "a", "0", "b", "0", "c"]),
        ":3",
    );
    assert_has(&send(&mut conn, &["ZLEXCOUNT", "lex", "-", "+"]), ":3");
    assert_has(&send(&mut conn, &["ZRANGEBYLEX", "lex", "-", "+"]), "a");
    assert_has(&send(&mut conn, &["ZREVRANGEBYLEX", "lex", "+", "-"]), "c");
    assert_has(
        &send(&mut conn, &["ZREMRANGEBYLEX", "lex", "[a", "[b"]),
        ":2",
    );
}

#[test]
fn sorted_set_store_rejects_invalid_arguments_without_mutating_destination() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    assert_has(&send(&mut conn, &["ZADD", "za", "1", "a", "2", "b"]), ":2");
    assert_has(&send(&mut conn, &["ZADD", "zb", "2", "b", "3", "c"]), ":2");
    assert_has(
        &send(&mut conn, &["ZUNIONSTORE", "dest", "2", "za", "zb"]),
        ":3",
    );

    for cmd in [
        vec!["ZUNIONSTORE", "dest", "nope", "za", "zb"],
        vec!["ZUNIONSTORE", "dest", "0"],
        vec!["ZUNIONSTORE", "dest", "3", "za", "zb"],
        vec![
            "ZUNIONSTORE",
            "dest",
            "2",
            "za",
            "zb",
            "WEIGHTS",
            "nope",
            "1",
        ],
        vec!["ZUNIONSTORE", "dest", "2", "za", "zb", "WEIGHTS", "1"],
        vec![
            "ZUNIONSTORE",
            "dest",
            "2",
            "za",
            "zb",
            "AGGREGATE",
            "MEDIAN",
        ],
        vec!["ZUNIONSTORE", "dest", "2", "za", "zb", "UNKNOWN"],
        vec![
            "ZINTERSTORE",
            "dest",
            "2",
            "za",
            "zb",
            "WEIGHTS",
            "1",
            "nope",
        ],
        vec!["ZDIFFSTORE", "dest", "0"],
        vec!["ZDIFFSTORE", "dest", "1", "za", "EXTRA"],
    ] {
        let resp = send(&mut conn, &cmd);
        assert!(
            resp.starts_with("-ERR"),
            "expected error for {cmd:?}, got: {resp}"
        );
    }

    assert_has(&send(&mut conn, &["ZCARD", "dest"]), ":3");
    assert_has(&send(&mut conn, &["ZSCORE", "dest", "b"]), "4");

    assert_has(
        &send(
            &mut conn,
            &[
                "ZUNIONSTORE",
                "weighted",
                "2",
                "za",
                "zb",
                "WEIGHTS",
                "2",
                "3",
                "AGGREGATE",
                "MAX",
            ],
        ),
        ":3",
    );
    assert_has(&send(&mut conn, &["ZSCORE", "weighted", "c"]), "9");
}

#[test]
fn sorted_set_commands_reject_invalid_arguments_without_mutating_state() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    assert_has(
        &send(
            &mut conn,
            &["ZADD", "z", "1", "one", "2", "two", "3", "three"],
        ),
        ":3",
    );

    for cmd in [
        vec!["ZPOPMIN", "z", "nope"],
        vec!["ZPOPMAX", "z", "nope"],
        vec!["ZREMRANGEBYRANK", "z", "nope", "1"],
        vec!["ZREMRANGEBYRANK", "z", "0", "nope"],
        vec!["ZREMRANGEBYSCORE", "z", "nope", "2"],
        vec!["ZREMRANGEBYSCORE", "z", "1", "nope"],
        vec!["ZRANGE", "z", "nope", "-1"],
        vec!["ZRANGE", "z", "0", "nope"],
        vec!["ZRANGE", "z", "0", "-1", "LIMIT", "nope", "1"],
        vec!["ZRANGE", "z", "0", "-1", "LIMIT", "0", "nope"],
        vec!["ZRANGEBYSCORE", "z", "nope", "3"],
        vec!["ZRANGEBYSCORE", "z", "1", "3", "LIMIT", "nope", "1"],
        vec!["ZSCAN", "z", "nope"],
        vec!["ZSCAN", "z", "0", "COUNT", "nope"],
        vec!["ZSCAN", "z", "0", "COUNT", "0"],
        vec!["ZSCAN", "z", "0", "UNKNOWN"],
    ] {
        let resp = send(&mut conn, &cmd);
        assert!(
            resp.starts_with("-ERR"),
            "expected error for {cmd:?}, got: {resp}"
        );
    }

    assert_has(&send(&mut conn, &["ZCARD", "z"]), ":3");
    assert_has(&send(&mut conn, &["ZSCORE", "z", "one"]), "1");
    assert_has(&send(&mut conn, &["ZSCORE", "z", "two"]), "2");
    assert_has(&send(&mut conn, &["ZSCORE", "z", "three"]), "3");
}
