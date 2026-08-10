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
fn sorted_set_direct_setops() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    assert_has(
        &send(&mut conn, &["ZADD", "za", "10", "a", "20", "b"]),
        ":2",
    );
    assert_has(
        &send(&mut conn, &["ZADD", "zb", "25", "b", "30", "c"]),
        ":2",
    );

    // ZUNION: 3 distinct members, sorted by score ascending (a=10, c=30, b=45).
    assert_has(&send(&mut conn, &["ZUNION", "2", "za", "zb"]), "*3");
    assert_has(
        &send(&mut conn, &["ZUNION", "2", "za", "zb", "WITHSCORES"]),
        "*6",
    );
    // Default SUM: b = 20 + 25 = 45.
    assert_has(
        &send(&mut conn, &["ZUNION", "2", "za", "zb", "WITHSCORES"]),
        "45",
    );
    // AGGREGATE MIN: b = min(20, 25) = 20. (The old union code seeded 0.0, which
    // would have made every MIN score 0 -- this guards that fix.)
    assert_has(
        &send(
            &mut conn,
            &["ZUNION", "2", "za", "zb", "AGGREGATE", "MIN", "WITHSCORES"],
        ),
        "20",
    );
    // AGGREGATE MAX: b = max(20, 25) = 25.
    assert_has(
        &send(
            &mut conn,
            &["ZUNION", "2", "za", "zb", "AGGREGATE", "MAX", "WITHSCORES"],
        ),
        "25",
    );
    // WEIGHTS: b = 20*1 + 25*2 = 70.
    assert_has(
        &send(
            &mut conn,
            &["ZUNION", "2", "za", "zb", "WEIGHTS", "1", "2", "WITHSCORES"],
        ),
        "70",
    );

    // ZINTER: only b is in both; SUM score 45.
    assert_has(&send(&mut conn, &["ZINTER", "2", "za", "zb"]), "*1");
    assert_has(
        &send(&mut conn, &["ZINTER", "2", "za", "zb", "WITHSCORES"]),
        "45",
    );

    // ZDIFF: a is only in za.
    assert_has(&send(&mut conn, &["ZDIFF", "2", "za", "zb"]), "a");
    assert_has(
        &send(&mut conn, &["ZDIFF", "2", "za", "zb", "WITHSCORES"]),
        "10",
    );

    // ZINTERCARD: intersection size, honoring LIMIT.
    assert_has(&send(&mut conn, &["ZINTERCARD", "2", "za", "zb"]), ":1");
    assert_has(
        &send(&mut conn, &["ZINTERCARD", "2", "za", "zb", "LIMIT", "5"]),
        ":1",
    );

    // Empty / missing keys.
    assert_has(&send(&mut conn, &["ZUNION", "1", "nope"]), "*0");
    assert_has(&send(&mut conn, &["ZINTERCARD", "1", "nope"]), ":0");

    // Direct set-ops are reads: sources are untouched, no destination created.
    assert_has(&send(&mut conn, &["ZCARD", "za"]), ":2");
    assert_has(&send(&mut conn, &["ZCARD", "zb"]), ":2");

    // Arity / syntax errors.
    assert_has(&send(&mut conn, &["ZUNION", "2", "za"]), "-ERR");
    assert_has(
        &send(&mut conn, &["ZINTERCARD", "2", "za", "zb", "BOGUS"]),
        "-ERR",
    );
}

#[test]
fn sorted_set_zrandmember() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    assert_has(
        &send(&mut conn, &["ZADD", "z", "1", "a", "2", "b", "3", "c"]),
        ":3",
    );

    // No count: a single member as a bulk string.
    let one = send(&mut conn, &["ZRANDMEMBER", "z"]);
    assert!(
        one.starts_with('$'),
        "single member is a bulk string: {one:?}"
    );
    assert!(
        one.contains('a') || one.contains('b') || one.contains('c'),
        "returns a member: {one:?}"
    );
    // Positive count: up to N distinct members.
    assert_has(&send(&mut conn, &["ZRANDMEMBER", "z", "2"]), "*2");
    assert_has(&send(&mut conn, &["ZRANDMEMBER", "z", "5"]), "*3"); // capped at set size
                                                                    // Negative count: |N| members WITH repeats allowed.
    assert_has(&send(&mut conn, &["ZRANDMEMBER", "z", "-5"]), "*5");
    // WITHSCORES: flat [member, score, ...].
    let ws = send(&mut conn, &["ZRANDMEMBER", "z", "2", "WITHSCORES"]);
    assert_has(&ws, "*4");
    // Missing key: nil without count, empty array with count.
    assert_has(&send(&mut conn, &["ZRANDMEMBER", "missing"]), "$-1");
    assert_has(&send(&mut conn, &["ZRANDMEMBER", "missing", "3"]), "*0");
    // Zero count is an empty array.
    assert_has(&send(&mut conn, &["ZRANDMEMBER", "z", "0"]), "*0");

    // Wrong type + syntax errors.
    assert_has(&send(&mut conn, &["SET", "str", "x"]), "+OK");
    assert_has(&send(&mut conn, &["ZRANDMEMBER", "str"]), "-WRONGTYPE");
    assert_has(&send(&mut conn, &["ZRANDMEMBER", "z", "2", "NOPE"]), "-ERR");
    assert_has(&send(&mut conn, &["ZRANDMEMBER", "z", "notanint"]), "-ERR");
}

#[test]
fn sorted_set_zmpop() {
    let server = LuxServer::start();
    let mut conn = server.conn();

    assert_has(
        &send(&mut conn, &["ZADD", "z1", "1", "a", "2", "b", "3", "c"]),
        ":3",
    );
    assert_has(&send(&mut conn, &["ZADD", "z2", "5", "x"]), ":1");

    // Pops from the first non-empty key (skips the missing one), MIN, default COUNT 1.
    let r = send(&mut conn, &["ZMPOP", "2", "empty", "z1", "MIN"]);
    assert_has(&r, "z1");
    assert_has(&r, "a");
    // MIN COUNT 2 pops the next two (b, c).
    let r2 = send(&mut conn, &["ZMPOP", "1", "z1", "MIN", "COUNT", "2"]);
    assert_has(&r2, "b");
    assert_has(&r2, "c");
    // z1 is now empty, so it falls through to z2 with MAX.
    let r3 = send(&mut conn, &["ZMPOP", "2", "z1", "z2", "MAX"]);
    assert_has(&r3, "z2");
    assert_has(&r3, "x");
    // All input keys empty -> nil array.
    assert_has(&send(&mut conn, &["ZMPOP", "2", "z1", "z2", "MIN"]), "*-1");

    // Syntax / arity errors.
    assert_has(&send(&mut conn, &["ZMPOP", "1", "z1"]), "-ERR"); // no MIN/MAX
    assert_has(&send(&mut conn, &["ZMPOP", "1", "z1", "SIDEWAYS"]), "-ERR");
    assert_has(&send(&mut conn, &["ZMPOP", "0", "MIN"]), "-ERR"); // numkeys 0
    assert_has(
        &send(&mut conn, &["ZMPOP", "1", "z1", "MIN", "COUNT", "0"]),
        "-ERR",
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

#[test]
fn sorted_set_zrangestore() {
    let server = LuxServer::start();
    let mut conn = server.conn();
    send(
        &mut conn,
        &["ZADD", "src", "1", "a", "2", "b", "3", "c", "4", "d"],
    );

    // By index: store first two into dst.
    assert_has(
        &send(&mut conn, &["ZRANGESTORE", "dst", "src", "0", "1"]),
        ":2",
    );
    let r = send(&mut conn, &["ZRANGE", "dst", "0", "-1", "WITHSCORES"]);
    assert_has(&r, "a");
    assert_has(&r, "b");
    assert!(!r.contains("\nc\r"), "dst should not contain c: {r}");

    // BYSCORE with LIMIT, overwrites dst.
    assert_has(
        &send(
            &mut conn,
            &["ZRANGESTORE", "dst", "src", "2", "4", "BYSCORE"],
        ),
        ":3",
    );
    let r = send(&mut conn, &["ZRANGE", "dst", "0", "-1"]);
    assert_has(&r, "b");
    assert_has(&r, "d");

    // Scores are preserved from src.
    assert_has(&send(&mut conn, &["ZSCORE", "dst", "c"]), "3");

    // Empty result deletes dst and returns 0.
    assert_has(
        &send(
            &mut conn,
            &["ZRANGESTORE", "dst", "src", "100", "200", "BYSCORE"],
        ),
        ":0",
    );
    assert_has(&send(&mut conn, &["EXISTS", "dst"]), ":0");

    // Missing src -> empty -> 0.
    assert_has(
        &send(&mut conn, &["ZRANGESTORE", "d2", "nosrc", "0", "-1"]),
        ":0",
    );

    // LIMIT without BYSCORE/BYLEX is an error.
    assert_has(
        &send(
            &mut conn,
            &["ZRANGESTORE", "d3", "src", "0", "-1", "LIMIT", "0", "1"],
        ),
        "-ERR",
    );
}

#[test]
fn hash_field_ttl_set_query_persist() {
    let server = LuxServer::start();
    let mut c = server.conn();
    send(&mut c, &["HSET", "h", "f1", "a", "f2", "b", "f3", "cc"]);
    let future = "99999999999999"; // absolute ms, far future
                                   // Set a TTL on f1.
    assert_has(
        &send(&mut c, &["HPEXPIREAT", "h", future, "FIELDS", "1", "f1"]),
        ":1",
    );
    // HPEXPIRETIME echoes the absolute deadline.
    assert_has(
        &send(&mut c, &["HPEXPIRETIME", "h", "FIELDS", "1", "f1"]),
        future,
    );
    // f2 has no TTL (-1), a missing field is -2.
    let ttl = send(&mut c, &["HTTL", "h", "FIELDS", "2", "f2", "nope"]);
    assert_has(&ttl, ":-1");
    assert_has(&ttl, ":-2");
    // Field still present/readable, counted in HLEN.
    assert_has(&send(&mut c, &["HGET", "h", "f1"]), "a");
    assert_has(&send(&mut c, &["HLEN", "h"]), ":3");
    // HPERSIST drops the TTL (1), then reports -1; a missing field is -2.
    assert_has(&send(&mut c, &["HPERSIST", "h", "FIELDS", "1", "f1"]), ":1");
    let p = send(&mut c, &["HPERSIST", "h", "FIELDS", "2", "f1", "nope"]);
    assert_has(&p, ":-1");
    assert_has(&p, ":-2");
}

#[test]
fn hash_field_ttl_expires_and_removes_key() {
    let server = LuxServer::start();
    let mut c = server.conn();
    send(&mut c, &["HSET", "h", "a", "1", "b", "2"]);
    // A past absolute deadline deletes the field immediately (returns 2).
    assert_has(
        &send(&mut c, &["HEXPIREAT", "h", "1", "FIELDS", "1", "a"]),
        ":2",
    );
    assert!(
        send(&mut c, &["HEXISTS", "h", "a"]).contains(":0"),
        "a gone"
    );
    assert_has(&send(&mut c, &["HLEN", "h"]), ":1");
    // A short TTL then a pause: lazy filtering hides it on read.
    send(&mut c, &["HPEXPIRE", "h", "60", "FIELDS", "1", "b"]);
    std::thread::sleep(std::time::Duration::from_millis(160));
    // Field-level: the expired field is hidden from reads and from the length.
    assert!(
        send(&mut c, &["HGET", "h", "b"]).contains("$-1"),
        "b expired -> nil"
    );
    assert_has(&send(&mut c, &["HLEN", "h"]), ":0");
    // The emptied hash key is reclaimed on the next write that touches it
    // (lazy, since a read holds only a shared lock).
    send(&mut c, &["HDEL", "h", "b"]);
    assert!(
        send(&mut c, &["EXISTS", "h"]).contains(":0"),
        "key reclaimed after a write"
    );
}

#[test]
fn hash_field_ttl_conditions_and_hset_clears() {
    let server = LuxServer::start();
    let mut c = server.conn();
    send(&mut c, &["HSET", "h", "f", "v"]);
    let future = "99999999999999";
    assert_has(
        &send(
            &mut c,
            &["HPEXPIREAT", "h", future, "NX", "FIELDS", "1", "f"],
        ),
        ":1",
    );
    // NX fails now that a TTL exists.
    assert_has(
        &send(
            &mut c,
            &["HPEXPIREAT", "h", future, "NX", "FIELDS", "1", "f"],
        ),
        ":0",
    );
    // GT with a smaller deadline is rejected.
    assert_has(
        &send(
            &mut c,
            &["HPEXPIREAT", "h", "1000", "GT", "FIELDS", "1", "f"],
        ),
        ":0",
    );
    // Overwriting the value via HSET clears the field TTL.
    send(&mut c, &["HSET", "h", "f", "v2"]);
    assert_has(&send(&mut c, &["HTTL", "h", "FIELDS", "1", "f"]), ":-1");
}

#[test]
fn hash_getex_and_getdel() {
    let server = LuxServer::start();
    let mut c = server.conn();
    send(&mut c, &["HSET", "h", "a", "1", "b", "2", "c", "3"]);
    // Plain HGETEX reads without changing TTL; missing field is nil.
    let r = send(&mut c, &["HGETEX", "h", "FIELDS", "2", "a", "missing"]);
    assert_has(&r, "1");
    assert_has(&r, "$-1");
    // HGETEX EX sets a TTL.
    send(&mut c, &["HGETEX", "h", "EX", "1000", "FIELDS", "1", "a"]);
    assert!(!send(&mut c, &["HTTL", "h", "FIELDS", "1", "a"]).contains(":-1"));
    // HGETEX PERSIST removes it.
    send(&mut c, &["HGETEX", "h", "PERSIST", "FIELDS", "1", "a"]);
    assert_has(&send(&mut c, &["HTTL", "h", "FIELDS", "1", "a"]), ":-1");
    // HGETDEL returns values and deletes the fields.
    let d = send(&mut c, &["HGETDEL", "h", "FIELDS", "2", "b", "c"]);
    assert_has(&d, "2");
    assert_has(&d, "3");
    assert!(send(&mut c, &["HEXISTS", "h", "b"]).contains(":0"));
    assert_has(&send(&mut c, &["HLEN", "h"]), ":1");
}

#[test]
fn hash_field_ttl_wrongtype_and_missing_key() {
    let server = LuxServer::start();
    let mut c = server.conn();
    send(&mut c, &["SET", "s", "x"]);
    assert_has(
        &send(&mut c, &["HEXPIRE", "s", "100", "FIELDS", "1", "f"]),
        "WRONGTYPE",
    );
    assert_has(
        &send(&mut c, &["HGETDEL", "s", "FIELDS", "1", "f"]),
        "WRONGTYPE",
    );
    // Missing key: every field reports -2.
    assert_has(&send(&mut c, &["HTTL", "nope", "FIELDS", "1", "f"]), ":-2");
    assert_has(
        &send(&mut c, &["HEXPIRE", "nope", "100", "FIELDS", "1", "f"]),
        ":-2",
    );
}
