//! Crash injection / chaos tests for the persistence layer.
//!
//! These tests start real Lux server processes and kill them at various
//! points to verify data integrity after recovery. They cover scenarios
//! that unit tests cannot: actual process crashes, WAL replay across
//! restarts, snapshot + WAL interaction, and concurrent data type recovery.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

mod common;
use common::{read_all, resp_cmd, LuxServer};

fn send(stream: &mut TcpStream, args: &[&str]) -> String {
    stream.write_all(&resp_cmd(args)).unwrap();
    // Read until we have a complete RESP response rather than sleeping and hoping.
    // Set a generous timeout so slow restarts don't cause spurious failures.
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut data = Vec::with_capacity(256);
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                data.extend_from_slice(&buf[..n]);
                // A complete simple RESP response ends with \r\n.
                // For bulk strings we need to check we got the full payload too,
                // but for our purposes (GET returns +OK, $N\r\n...\r\n, or $-1\r\n)
                // checking for a trailing \r\n on a non-empty buffer is sufficient.
                if data.ends_with(b"\r\n") {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(_) => break,
        }
    }
    // Restore the normal read timeout.
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    String::from_utf8_lossy(&data).to_string()
}

fn fill_memory(conn: &mut TcpStream, count: usize) {
    let val = "x".repeat(10000);
    for i in 0..count {
        send(conn, &["SET", &format!("filler:{i}"), &val]);
    }
}

// ---------------------------------------------------------------------------
// Test: Kill mid-write, verify WAL recovery of all data types
// ---------------------------------------------------------------------------
#[test]
fn crash_recovery_all_types() {
    let mut srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();

    // Write every data type.
    send(&mut c, &["SET", "str_key", "string_value"]);
    send(&mut c, &["HSET", "hash_key", "f1", "v1", "f2", "v2"]);
    send(&mut c, &["LPUSH", "list_key", "a", "b", "c"]);
    send(&mut c, &["SADD", "set_key", "x", "y", "z"]);
    send(&mut c, &["ZADD", "zset_key", "1.5", "m1", "2.5", "m2"]);
    send(&mut c, &["XADD", "stream_key", "*", "field1", "val1"]);
    send(&mut c, &["PFADD", "hll_key", "a", "b", "c", "d"]);
    send(&mut c, &["TSADD", "ts_key", "*", "42.5"]);
    drop(c);

    // Hard kill (no graceful shutdown).
    srv.kill();
    srv.restart();

    let mut c = srv.conn();

    // Verify every type survived.
    let resp = send(&mut c, &["GET", "str_key"]);
    assert!(resp.contains("string_value"), "string recovery: {resp}");

    let resp = send(&mut c, &["HGETALL", "hash_key"]);
    assert!(resp.contains("f1"), "hash recovery f1: {resp}");
    assert!(resp.contains("v2"), "hash recovery v2: {resp}");

    let resp = send(&mut c, &["LRANGE", "list_key", "0", "-1"]);
    assert!(resp.contains("a"), "list recovery a: {resp}");
    assert!(resp.contains("c"), "list recovery c: {resp}");

    let resp = send(&mut c, &["SMEMBERS", "set_key"]);
    assert!(resp.contains("x"), "set recovery x: {resp}");
    assert!(resp.contains("z"), "set recovery z: {resp}");

    let resp = send(&mut c, &["ZRANGE", "zset_key", "0", "-1", "WITHSCORES"]);
    assert!(resp.contains("m1"), "zset recovery m1: {resp}");
    assert!(resp.contains("2.5"), "zset recovery score: {resp}");

    let resp = send(&mut c, &["XLEN", "stream_key"]);
    assert!(resp.contains(":1"), "stream recovery: {resp}");

    let resp = send(&mut c, &["PFCOUNT", "hll_key"]);
    assert!(resp.contains(":4"), "hll recovery: {resp}");

    let resp = send(&mut c, &["TSRANGE", "ts_key", "-", "+"]);
    assert!(resp.contains("42.5"), "timeseries recovery: {resp}");
}

// AUDIT PROBE: XADD with a `*` server-generated ID must keep the SAME id across a
// WAL-only recovery. execute_with_wal logs the RAW command (literal `*`), so replay
// regenerates a new time-based id and the entry's identity changes.
//
// QUARANTINED repro for row TTL WAL replay drift (un-ignore when fixing). Run with:
//   cargo test --release --test crash_recovery -- --ignored xadd_star_id_stable_after_wal_replay
#[test]
fn xadd_star_id_stable_after_wal_replay() {
    let mut srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();
    let resp = send(&mut c, &["XADD", "s", "*", "f", "v"]);
    // Pull the generated id (a bulk line containing the ms-seq form `<ms>-<seq>`).
    let id = resp
        .lines()
        .map(|l| l.trim())
        .find(|l| l.contains('-') && l.chars().next().is_some_and(|ch| ch.is_ascii_digit()))
        .unwrap_or("")
        .to_string();
    assert!(!id.is_empty(), "captured an XADD id: {resp:?}");
    drop(c);

    srv.kill();
    srv.restart(); // WAL replay only
    let mut c = srv.conn();
    let range = send(&mut c, &["XRANGE", "s", "-", "+"]);
    assert!(
        range.contains(&id),
        "XADD * id must be stable across WAL replay: was {id}, after = {range:?}"
    );
}

// REGRESSION: TSADD with a `*` server-generated timestamp must keep the SAME
// timestamp across WAL replay. TSADD/TSMADD self-log the resolved timestamp
// (see log_resolved_tsadd) so replay reuses it instead of re-reading the clock.
#[test]
fn tsadd_star_timestamp_stable_after_wal_replay() {
    let mut srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();
    let resp = send(&mut c, &["TSADD", "temps", "*", "42.5"]);
    // TSADD * returns the resolved ms timestamp.
    let ts = resp
        .lines()
        .map(|l| l.trim().trim_start_matches(':'))
        .find(|l| l.len() >= 10 && l.chars().all(|ch| ch.is_ascii_digit()))
        .unwrap_or("")
        .to_string();
    assert!(!ts.is_empty(), "captured a TSADD timestamp: {resp:?}");
    drop(c);

    srv.kill();
    srv.restart(); // WAL replay only
    let mut c = srv.conn();
    let range = send(&mut c, &["TSRANGE", "temps", "-", "+"]);
    assert!(
        range.contains(&ts),
        "TSADD * timestamp must be stable across WAL replay: was {ts}, after = {range:?}"
    );
}

// PROBE (ENG-1316): ZUNIONSTORE reads source keys that may live on other WAL
// shards. Per-shard replay applies each shard fully in order, so a dst whose
// shard replays before a source's shard computes the union from empty sources.
// With many sources spread across shards, most dsts are affected.
#[test]
fn zunionstore_cross_shard_survives_wal_replay() {
    let mut srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();
    let n = 24usize;
    let srcs: Vec<String> = (0..n).map(|i| format!("src{i}")).collect();
    for (i, k) in srcs.iter().enumerate() {
        send(&mut c, &["ZADD", k, "1", &format!("m{i}")]);
    }
    let numkeys = n.to_string();
    for d in 0..10 {
        let dst = format!("dst{d}");
        let mut args: Vec<&str> = vec!["ZUNIONSTORE", &dst, &numkeys];
        args.extend(srcs.iter().map(String::as_str));
        send(&mut c, &args);
    }
    drop(c);
    srv.kill();
    srv.restart(); // WAL replay only
    let mut c = srv.conn();
    for d in 0..10 {
        let dst = format!("dst{d}");
        let card = send(&mut c, &["ZCARD", &dst]);
        assert!(
            card.contains(&format!(":{n}\r\n")),
            "dst{d} must hold all {n} union members after replay; got {card:?}"
        );
    }
}

// PROBE (ENG-1316): SMOVE adds the member to dst, which may live on a different
// WAL shard than src. A conflicting SREM on dst must stay ordered after the move.
// Under raw logging the whole move lands in src's shard and can replay after
// dst's SREM, resurrecting the member. Self-logging `SREM src` + `SADD dst` keys
// each effect to its own shard so append order is preserved on replay.
#[test]
fn smove_cross_shard_survives_wal_replay() {
    let mut srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();
    let n = 24usize;
    for i in 0..n {
        let a = format!("a{i}");
        let b = format!("b{i}");
        send(&mut c, &["SADD", &a, "m"]);
        send(&mut c, &["SMOVE", &a, &b, "m"]); // b{i} = {m}
        send(&mut c, &["SREM", &b, "m"]); // b{i} = {}
    }
    drop(c);
    srv.kill();
    srv.restart(); // WAL replay only
    let mut c = srv.conn();
    for i in 0..n {
        let a = format!("a{i}");
        let b = format!("b{i}");
        assert!(
            send(&mut c, &["SCARD", &b]).contains(":0"),
            "b{i} must be empty (SADD-then-SREM order preserved) after replay"
        );
        assert!(
            send(&mut c, &["SISMEMBER", &a, "m"]).contains(":0"),
            "a{i} must not resurrect the moved member after replay"
        );
    }
}

// PROBE (ENG-1316): LMOVE pushes the moved element onto dst, whose shard may
// differ from src's. List order is significant, so a pre-existing element on dst
// must stay ordered before the moved one. Raw logging puts the whole move in
// src's shard and can replay it before dst's own push, inverting the order.
#[test]
fn lmove_cross_shard_order_survives_wal_replay() {
    let mut srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();
    let n = 24usize;
    for i in 0..n {
        let a = format!("a{i}");
        let b = format!("b{i}");
        send(&mut c, &["RPUSH", &a, "M"]);
        send(&mut c, &["RPUSH", &b, "P"]); // b{i} = [P]
        send(&mut c, &["LMOVE", &a, &b, "LEFT", "RIGHT"]); // b{i} = [P, M]
    }
    drop(c);
    srv.kill();
    srv.restart(); // WAL replay only
    let mut c = srv.conn();
    for i in 0..n {
        let b = format!("b{i}");
        let range = send(&mut c, &["LRANGE", &b, "0", "-1"]);
        let p = range.find("\r\nP\r\n");
        let m = range.find("\r\nM\r\n");
        assert!(
            p.is_some() && m.is_some() && p < m,
            "b{i} must be [P, M] after replay; got {range:?}"
        );
    }
}

// PROBE (ENG-1316): RPOPLPUSH is LMOVE src dst RIGHT LEFT; same cross-shard
// ordering hazard on the destination push.
#[test]
fn rpoplpush_cross_shard_order_survives_wal_replay() {
    let mut srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();
    let n = 24usize;
    for i in 0..n {
        let a = format!("a{i}");
        let b = format!("b{i}");
        send(&mut c, &["RPUSH", &a, "M"]);
        send(&mut c, &["RPUSH", &b, "P"]); // b{i} = [P]
        send(&mut c, &["RPOPLPUSH", &a, &b]); // pop tail M of a, push head of b => [M, P]
    }
    drop(c);
    srv.kill();
    srv.restart(); // WAL replay only
    let mut c = srv.conn();
    for i in 0..n {
        let b = format!("b{i}");
        let range = send(&mut c, &["LRANGE", &b, "0", "-1"]);
        let m = range.find("\r\nM\r\n");
        let p = range.find("\r\nP\r\n");
        assert!(
            m.is_some() && p.is_some() && m < p,
            "b{i} must be [M, P] after replay; got {range:?}"
        );
    }
}

// PROBE (ENG-1316): an immediately-satisfiable BLMOVE moves like LMOVE and must
// be logged the same way. BLMOVE isn't classified as a write command, so
// execute_with_wal never logs it; the immediate path self-logs pop+push.
#[test]
fn blmove_immediate_cross_shard_survives_wal_replay() {
    let mut srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();
    let n = 24usize;
    for i in 0..n {
        let a = format!("a{i}");
        let b = format!("b{i}");
        send(&mut c, &["RPUSH", &a, "M"]);
        send(&mut c, &["RPUSH", &b, "P"]); // b{i} = [P]
        send(&mut c, &["BLMOVE", &a, &b, "LEFT", "RIGHT", "0"]); // src non-empty => immediate
    }
    drop(c);
    srv.kill();
    srv.restart(); // WAL replay only
    let mut c = srv.conn();
    for i in 0..n {
        let a = format!("a{i}");
        let b = format!("b{i}");
        let range = send(&mut c, &["LRANGE", &b, "0", "-1"]);
        let p = range.find("\r\nP\r\n");
        let m = range.find("\r\nM\r\n");
        assert!(
            p.is_some() && m.is_some() && p < m,
            "b{i} must be [P, M] after replay; got {range:?}"
        );
        assert!(
            send(&mut c, &["LLEN", &a]).contains(":0"),
            "a{i} must be empty after replay"
        );
    }
}

// PROBE (ENG-1317): a BLOCKED BLMOVE later satisfied by a push. The satisfying
// push is logged, but the consuming pop (src) and the deferred dst push happen
// outside the WAL. The woken handler now logs both, keyed so each lands on its
// own shard, so replay leaves the element only in dst. Cross-shard fan-out so
// each bsrc{i}/bdst{i} pair spans different disk-WAL shards.
#[test]
fn blmove_blocked_completion_survives_wal_replay() {
    let mut srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let n = 16usize;
    let port = srv.port();
    let mut blockers = Vec::new();
    for i in 0..n {
        let h = thread::spawn(move || {
            let mut b = common::connect(port);
            let src = format!("bsrc{i}");
            let dst = format!("bdst{i}");
            // Blocks on empty src until the push below wakes it.
            send(&mut b, &["BLMOVE", &src, &dst, "LEFT", "RIGHT", "5"]);
        });
        blockers.push(h);
    }
    thread::sleep(Duration::from_millis(400)); // let every BLMOVE register as a waiter
    let mut c = srv.conn();
    for i in 0..n {
        let src = format!("bsrc{i}");
        send(&mut c, &["RPUSH", &src, "V"]); // wakes the blocked BLMOVE: V moves to dst
    }
    for h in blockers {
        h.join().unwrap();
    }
    for i in 0..n {
        let dst = format!("bdst{i}");
        assert!(
            send(&mut c, &["LRANGE", &dst, "0", "-1"]).contains("V"),
            "runtime move to bdst{i} must have happened"
        );
    }
    drop(c);
    srv.kill();
    srv.restart(); // WAL replay only
    let mut c = srv.conn();
    for i in 0..n {
        let src = format!("bsrc{i}");
        let dst = format!("bdst{i}");
        assert!(
            send(&mut c, &["LRANGE", &dst, "0", "-1"]).contains("V"),
            "bdst{i} must retain the moved element after replay"
        );
        assert!(
            send(&mut c, &["LLEN", &src]).contains(":0"),
            "bsrc{i} must be empty after replay (element moved, not left behind)"
        );
    }
}

// PROBE (ENG-1317): a BLOCKED BLPOP satisfied by a later push. The push is
// logged; the waiter's consuming pop is now logged too (keyed on the popped
// key), so replay does not resurrect the element into the source list.
#[test]
fn blpop_blocked_completion_survives_wal_replay() {
    let mut srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let n = 16usize;
    let port = srv.port();
    let mut blockers = Vec::new();
    for i in 0..n {
        let h = thread::spawn(move || {
            let mut b = common::connect(port);
            let q = format!("q{i}");
            send(&mut b, &["BLPOP", &q, "5"]);
        });
        blockers.push(h);
    }
    thread::sleep(Duration::from_millis(400)); // let every BLPOP register as a waiter
    let mut c = srv.conn();
    for i in 0..n {
        let q = format!("q{i}");
        send(&mut c, &["RPUSH", &q, "V"]); // wakes the blocked BLPOP: V is consumed
    }
    for h in blockers {
        h.join().unwrap();
    }
    for i in 0..n {
        let q = format!("q{i}");
        assert!(
            send(&mut c, &["LLEN", &q]).contains(":0"),
            "q{i} must be empty at runtime (consumed by the blocked BLPOP)"
        );
    }
    drop(c);
    srv.kill();
    srv.restart(); // WAL replay only
    let mut c = srv.conn();
    for i in 0..n {
        let q = format!("q{i}");
        assert!(
            send(&mut c, &["LLEN", &q]).contains(":0"),
            "q{i} must stay empty after replay (pop was logged, not resurrected)"
        );
    }
}

// PROBE (ENG-1317): a BLOCKED BZPOPMIN satisfied by a later ZADD. handle_block_zpop
// pops straight from the store outside the WAL; the removal is now logged as a
// keyed ZREM so replay doesn't resurrect the popped member into the zset.
#[test]
fn bzpopmin_blocked_completion_survives_wal_replay() {
    let mut srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let n = 16usize;
    let port = srv.port();
    let mut blockers = Vec::new();
    for i in 0..n {
        let h = thread::spawn(move || {
            let mut b = common::connect(port);
            let z = format!("z{i}");
            send(&mut b, &["BZPOPMIN", &z, "5"]);
        });
        blockers.push(h);
    }
    thread::sleep(Duration::from_millis(400)); // let every BZPOPMIN register/poll
    let mut c = srv.conn();
    for i in 0..n {
        let z = format!("z{i}");
        send(&mut c, &["ZADD", &z, "1", "m"]); // wakes the blocked BZPOPMIN: m consumed
    }
    for h in blockers {
        h.join().unwrap();
    }
    for i in 0..n {
        let z = format!("z{i}");
        assert!(
            send(&mut c, &["ZCARD", &z]).contains(":0"),
            "z{i} must be empty at runtime (consumed by the blocked BZPOPMIN)"
        );
    }
    drop(c);
    srv.kill();
    srv.restart(); // WAL replay only
    let mut c = srv.conn();
    for i in 0..n {
        let z = format!("z{i}");
        assert!(
            send(&mut c, &["ZCARD", &z]).contains(":0"),
            "z{i} must stay empty after replay (ZREM was logged, member not resurrected)"
        );
    }
}

// PROBE (ENG-1316): COPY writes only dst but the raw command shards on src and
// re-reads src at replay, when a per-shard replay may not have rebuilt src yet
// (and dst's own writes replay in a separate shard). COPY self-logs the resolved
// dst value as a keyed `LXRESTORE dst <blob>`.
#[test]
fn copy_cross_shard_survives_wal_replay() {
    let mut srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();
    let n = 24usize;
    for i in 0..n {
        let s = format!("s{i}");
        let d = format!("d{i}");
        send(&mut c, &["SET", &s, &format!("v{i}")]);
        send(&mut c, &["SET", &d, "OLD"]); // independent write to dst's shard
        send(&mut c, &["COPY", &s, &d, "REPLACE"]); // d{i} = v{i}
    }
    // Cover a non-string type through the dump blob.
    send(&mut c, &["RPUSH", "lsrc", "l0", "l1", "l2"]);
    send(&mut c, &["COPY", "lsrc", "ldst"]);
    drop(c);
    srv.kill();
    srv.restart(); // WAL replay only
    let mut c = srv.conn();
    for i in 0..n {
        let d = format!("d{i}");
        let got = send(&mut c, &["GET", &d]);
        assert!(
            got.contains(&format!("v{i}\r")),
            "d{i} must hold the copied value (not OLD) after replay; got {got:?}"
        );
    }
    let l = send(&mut c, &["LRANGE", "ldst", "0", "-1"]);
    assert!(
        l.contains("l0") && l.contains("l1") && l.contains("l2"),
        "list COPY must survive replay through the dump blob; got {l:?}"
    );
}

// PROBE (ENG-1316): MSET writes many keys but the raw command shards on the
// first key only, so a later independent write to a non-first key can replay
// before the MSET's value for that key, losing the newer write. Self-logging a
// keyed SET per pair puts each in its own shard in append order.
#[test]
fn mset_cross_shard_survives_wal_replay() {
    let mut srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();
    let n = 24usize;
    for i in 0..n {
        let a = format!("first{i}");
        let b = format!("second{i}");
        send(&mut c, &["MSET", &a, "F", &b, "S"]);
        send(&mut c, &["SET", &b, "OVERWRITE"]); // later write to the non-first key
    }
    drop(c);
    srv.kill();
    srv.restart(); // WAL replay only
    let mut c = srv.conn();
    for i in 0..n {
        let a = format!("first{i}");
        let b = format!("second{i}");
        assert!(
            send(&mut c, &["GET", &a]).contains("F\r"),
            "first{i} must survive MSET replay"
        );
        assert!(
            send(&mut c, &["GET", &b]).contains("OVERWRITE"),
            "second{i} must reflect the later SET, not the replayed MSET value"
        );
    }
}

// ZMPOP mutates the sorted set, so the pop must survive a WAL-only restart
// (regression guard that ZMPOP is classified as a write and WAL-logged).
#[test]
fn zmpop_persists_across_wal_replay() {
    let mut srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();
    send(&mut c, &["ZADD", "z", "1", "a", "2", "b", "3", "c"]);
    send(&mut c, &["ZMPOP", "1", "z", "MIN", "COUNT", "2"]); // pops a and b
                                                             // Control: an established write on a second key, to isolate ZMPOP.
    send(&mut c, &["ZADD", "zc", "1", "a", "2", "b"]);
    send(&mut c, &["ZPOPMIN", "zc", "1"]); // pops a
    drop(c);

    srv.kill();
    srv.restart(); // WAL replay only
    let mut c = srv.conn();
    let control = send(&mut c, &["ZCARD", "zc"]);
    assert!(
        control.contains(":1"),
        "control ZPOPMIN must persist; ZCARD(zc)={control:?}"
    );
    let card = send(&mut c, &["ZCARD", "z"]);
    assert!(
        card.contains(":1"),
        "ZMPOP pop must persist across WAL replay; ZCARD={card:?}"
    );
    assert!(
        send(&mut c, &["ZSCORE", "z", "a"]).contains("$-1"),
        "popped member 'a' must stay gone after replay"
    );
    assert!(
        send(&mut c, &["ZSCORE", "z", "c"]).contains('3'),
        "unpopped member 'c' must remain after replay"
    );
}

// AUDIT PROBE: SPOP removes a RANDOM member. The raw command is WAL-logged, so
// replay re-runs SPOP and may remove a DIFFERENT member than the client saw,
// leaving the recovered set inconsistent with the acknowledged result.
#[test]
fn spop_deterministic_after_wal_replay() {
    let mut srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();
    send(
        &mut c,
        &["SADD", "myset", "a", "b", "c", "d", "e", "f", "g", "h"],
    );
    send(&mut c, &["SPOP", "myset"]);
    let mut before: Vec<String> = send(&mut c, &["SMEMBERS", "myset"])
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| l.len() == 1 && l.chars().all(|ch| ch.is_ascii_lowercase()))
        .collect();
    before.sort();
    drop(c);

    srv.kill();
    srv.restart(); // WAL replay only
    let mut c = srv.conn();
    let mut after: Vec<String> = send(&mut c, &["SMEMBERS", "myset"])
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| l.len() == 1 && l.chars().all(|ch| ch.is_ascii_lowercase()))
        .collect();
    after.sort();
    assert_eq!(
        before, after,
        "SPOP must remove the same member on replay as the client observed"
    );
}

// ---------------------------------------------------------------------------
// Test: Writes performed inside a Lua script survive a crash (WAL-only, no
// snapshot). EVAL logs effects, not the script, so the logged KV writes replay.
// ---------------------------------------------------------------------------
#[test]
fn crash_recovery_lua_script_writes() {
    let mut srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();

    // A script that performs several KV writes via redis.call. None of these go
    // through the top-level dispatch, so before the fix they were never WAL-logged.
    let script = "redis.call('SET', KEYS[1], ARGV[1]); \
         redis.call('HSET', KEYS[2], 'f', ARGV[2]); \
         redis.call('RPUSH', KEYS[3], 'a', 'b', 'c'); \
         return 'ok'";
    let resp = send(
        &mut c,
        &[
            "EVAL", script, "3", "lua_str", "lua_hash", "lua_list", "hello", "world",
        ],
    );
    assert!(resp.contains("ok"), "eval ran: {resp}");
    drop(c);

    // Hard kill before any snapshot (save_interval=0), then recover from WAL only.
    srv.kill();
    srv.restart();

    let mut c = srv.conn();
    let resp = send(&mut c, &["GET", "lua_str"]);
    assert!(resp.contains("hello"), "lua SET survived crash: {resp}");
    let resp = send(&mut c, &["HGET", "lua_hash", "f"]);
    assert!(resp.contains("world"), "lua HSET survived crash: {resp}");
    let resp = send(&mut c, &["LRANGE", "lua_list", "0", "-1"]);
    assert!(
        resp.contains("a") && resp.contains("c"),
        "lua RPUSH survived crash: {resp}"
    );
}

// ---------------------------------------------------------------------------
// Test: Crash after snapshot, before WAL truncate -- both sources recover
// ---------------------------------------------------------------------------
#[test]
fn crash_after_snapshot_before_wal_truncate() {
    let mut srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();

    // Phase 1: write data and snapshot it.
    send(&mut c, &["SET", "snap_key", "snap_value"]);
    send(&mut c, &["SAVE"]);

    // Phase 2: write more data (goes only to WAL, not snapshot).
    send(&mut c, &["SET", "wal_key", "wal_value"]);
    send(&mut c, &["SET", "snap_key", "updated_value"]);
    drop(c);

    // Kill: snapshot has snap_key=snap_value, WAL has wal_key + snap_key update.
    srv.kill();
    srv.restart();

    let mut c = srv.conn();

    // snap_key should have the WAL-replayed update, not the snapshot value.
    let resp = send(&mut c, &["GET", "snap_key"]);
    assert!(
        resp.contains("updated_value"),
        "WAL should override snapshot: {resp}"
    );

    // wal_key should exist from WAL replay.
    let resp = send(&mut c, &["GET", "wal_key"]);
    assert!(resp.contains("wal_value"), "WAL-only key recovery: {resp}");
}

// ---------------------------------------------------------------------------
// Test: Crash during MULTI/EXEC -- partial transaction should not corrupt
// ---------------------------------------------------------------------------
#[test]
fn crash_during_multi_exec() {
    let mut srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();

    // Write some baseline data.
    send(&mut c, &["SET", "before_tx", "safe"]);

    // Start a MULTI but kill before EXEC completes all commands.
    // Since each command in MULTI is individually WAL'd on EXEC,
    // a crash mid-EXEC means some commands are in WAL and some aren't.
    send(&mut c, &["MULTI"]);
    send(&mut c, &["SET", "tx_key1", "tx_val1"]);
    send(&mut c, &["SET", "tx_key2", "tx_val2"]);
    send(&mut c, &["SET", "tx_key3", "tx_val3"]);
    send(&mut c, &["EXEC"]);

    // Immediately kill (some WAL writes may not have been fsync'd).
    drop(c);
    srv.kill();
    srv.restart();

    let mut c = srv.conn();

    // Baseline data should always survive.
    let resp = send(&mut c, &["GET", "before_tx"]);
    assert!(resp.contains("safe"), "pre-tx data recovery: {resp}");

    // Transaction keys: they may or may not all survive depending on
    // fsync timing, but the database should NOT be corrupted. Whatever
    // keys exist should have correct values, and missing keys should
    // return nil (not garbage).
    for (key, expected) in [
        ("tx_key1", "tx_val1"),
        ("tx_key2", "tx_val2"),
        ("tx_key3", "tx_val3"),
    ] {
        let resp = send(&mut c, &["GET", key]);
        // Either the key exists with the right value, or it's nil.
        assert!(
            resp.contains(expected) || resp.contains("$-1"),
            "tx key '{key}' should be correct or nil, got: {resp}"
        );
    }
}

// ---------------------------------------------------------------------------
// Test: Multiple crash/restart cycles don't accumulate corruption
// ---------------------------------------------------------------------------
#[test]
fn repeated_crash_restart_cycles() {
    let mut srv = LuxServer::builder().tiered().maxmemory("100kb").start();

    for cycle in 0..3 {
        let mut c = srv.conn();
        // Write unique data each cycle.
        send(
            &mut c,
            &["SET", &format!("cycle_{cycle}"), &format!("value_{cycle}")],
        );
        // Also update a shared key to test overwrite recovery.
        send(&mut c, &["SET", "shared_key", &format!("cycle_{cycle}")]);
        drop(c);
        srv.kill();
        srv.restart();
    }

    let mut c = srv.conn();

    // Shared key should have the latest cycle's value.
    let resp = send(&mut c, &["GET", "shared_key"]);
    assert!(
        resp.contains("cycle_2"),
        "shared key should have last cycle value: {resp}"
    );

    // All cycle-specific keys should exist (WAL replay across restarts).
    for cycle in 0..3 {
        let resp = send(&mut c, &["GET", &format!("cycle_{cycle}")]);
        assert!(
            resp.contains(&format!("value_{cycle}")),
            "cycle {cycle} key missing: {resp}"
        );
    }
}

// ---------------------------------------------------------------------------
// Test: Crash with mix of hot and cold data -- both survive
// ---------------------------------------------------------------------------
#[test]
fn crash_with_hot_and_cold_data() {
    let mut srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();

    // Write a key that will be evicted to cold storage.
    send(&mut c, &["SET", "cold_key", "cold_value"]);
    fill_memory(&mut c, 20); // push cold_key to disk

    // Write a key that stays hot (recent, in memory).
    send(&mut c, &["SET", "hot_key", "hot_value"]);
    drop(c);

    srv.kill();
    srv.restart();

    let mut c = srv.conn();

    // Hot key should survive via WAL.
    let resp = send(&mut c, &["GET", "hot_key"]);
    assert!(resp.contains("hot_value"), "hot key recovery: {resp}");

    // Cold key should survive via disk shard.
    let resp = send(&mut c, &["GET", "cold_key"]);
    assert!(resp.contains("cold_value"), "cold key recovery: {resp}");
}

// ---------------------------------------------------------------------------
// Test: Crash after DEL -- deleted keys should NOT reappear
// ---------------------------------------------------------------------------
#[test]
fn crash_after_delete() {
    let mut srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();

    send(&mut c, &["SET", "keep_me", "yes"]);
    send(&mut c, &["SET", "delete_me", "no"]);
    send(&mut c, &["DEL", "delete_me"]);
    drop(c);

    srv.kill();
    srv.restart();

    let mut c = srv.conn();

    let resp = send(&mut c, &["GET", "keep_me"]);
    assert!(resp.contains("yes"), "kept key recovery: {resp}");

    let resp = send(&mut c, &["GET", "delete_me"]);
    assert!(
        resp.contains("$-1"),
        "deleted key should NOT reappear: {resp}"
    );
}

// ---------------------------------------------------------------------------
// Test: Crash after FLUSHDB -- database should be empty after recovery
// ---------------------------------------------------------------------------
#[test]
fn crash_after_flushdb() {
    let mut srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();

    send(&mut c, &["SET", "k1", "v1"]);
    send(&mut c, &["SET", "k2", "v2"]);
    send(&mut c, &["SAVE"]); // snapshot k1, k2
    send(&mut c, &["FLUSHDB"]); // WAL records the flush
    drop(c);

    srv.kill();
    srv.restart();

    let mut c = srv.conn();
    let resp = send(&mut c, &["DBSIZE"]);
    assert!(resp.contains(":0"), "FLUSHDB should survive crash: {resp}");
}

// ---------------------------------------------------------------------------
// Test: Rapid writes then immediate kill -- stress the WAL buffer
// ---------------------------------------------------------------------------
#[test]
fn rapid_writes_then_crash() {
    let mut srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();

    // Pipeline 100 writes as fast as possible.
    let mut batch = Vec::new();
    for i in 0..100 {
        batch.extend_from_slice(&resp_cmd(&[
            "SET",
            &format!("rapid:{i}"),
            &format!("val:{i}"),
        ]));
    }
    c.write_all(&batch).unwrap();
    thread::sleep(Duration::from_millis(200));
    read_all(&mut c); // drain responses
    drop(c);

    srv.kill();
    srv.restart();

    let mut c = srv.conn();

    // Due to the 1s fsync window, some of the last writes may be lost.
    // But whatever survived should have correct values (no corruption).
    let mut recovered = 0;
    for i in 0..100 {
        let resp = send(&mut c, &["GET", &format!("rapid:{i}")]);
        if resp.contains(&format!("val:{i}")) {
            recovered += 1;
        } else {
            // Should be nil, not garbage.
            assert!(
                resp.contains("$-1"),
                "key rapid:{i} should be nil or correct, got: {resp}"
            );
        }
    }
    // At least some writes should have survived (WAL was flushed to OS buffer).
    assert!(
        recovered > 0,
        "at least some rapid writes should survive crash"
    );
}

// ---------------------------------------------------------------------------
// Test: WAL file with corrupted frames -- server should start and skip them
// ---------------------------------------------------------------------------
#[test]
fn corrupted_wal_frames_skipped_on_startup() {
    let mut srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();

    send(&mut c, &["SET", "good_key", "good_value"]);
    // Wait for WAL flush.
    thread::sleep(Duration::from_secs(2));
    drop(c);
    srv.kill();

    // Corrupt the WAL files by appending garbage.
    let storage_dir = srv.data_dir().join("storage");
    if storage_dir.exists() {
        for entry in std::fs::read_dir(&storage_dir).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                let wal_path = entry.path().join("wal.lux");
                if wal_path.exists() {
                    let mut f = std::fs::OpenOptions::new()
                        .append(true)
                        .open(&wal_path)
                        .unwrap();
                    // Write a valid-looking frame_len but corrupt crc + payload.
                    f.write_all(&50u32.to_le_bytes()).unwrap();
                    f.write_all(&[0xDE, 0xAD, 0xBE, 0xEF]).unwrap(); // bad crc
                    f.write_all(&[0xFF; 46]).unwrap(); // garbage payload
                    f.flush().unwrap();
                }
            }
        }
    }

    // Server should start despite corrupted WAL frames.
    srv.restart();
    let mut c = srv.conn();

    // The valid key should have been recovered (it was fsync'd before corruption).
    let resp = send(&mut c, &["GET", "good_key"]);
    assert!(
        resp.contains("good_value"),
        "valid key should survive WAL corruption: {resp}"
    );

    // Server should be functional.
    send(&mut c, &["SET", "new_key", "new_value"]);
    let resp = send(&mut c, &["GET", "new_key"]);
    assert!(
        resp.contains("new_value"),
        "server should be functional after WAL corruption: {resp}"
    );
}

// ---------------------------------------------------------------------------
// Test: Persistence error counters are exposed via INFO
// ---------------------------------------------------------------------------
#[test]
fn info_exposes_persistence_counters() {
    let srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();

    let resp = send(&mut c, &["INFO"]);
    assert!(
        resp.contains("persistence_err_wal_append:0"),
        "should have WAL append counter: {resp}"
    );
    assert!(
        resp.contains("persistence_err_wal_fsync:0"),
        "should have WAL fsync counter: {resp}"
    );
    assert!(
        resp.contains("persistence_err_disk_write:0"),
        "should have disk write counter: {resp}"
    );
}

// ---------------------------------------------------------------------------
// Test: row TTL survives a snapshot + restart with ABSOLUTE deadlines.
// A future deadline is preserved (row present); a lapsed deadline stays expired
// (the row is not resurrected with a fresh TTL); the sweep index + hidden field
// round-trip so the PK is reusable afterwards.
// ---------------------------------------------------------------------------
#[test]
fn row_ttl_survives_restart() {
    let mut srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();

    send(
        &mut c,
        &["TCREATE", "pres", "user_id STR PRIMARY KEY,", "room STR"],
    );
    send(
        &mut c,
        &[
            "TINSERT", "pres", "user_id", "keep", "room", "main", "TTL", "60",
        ],
    );
    send(
        &mut c,
        &[
            "TINSERT", "pres", "user_id", "gone", "room", "main", "TTL", "1",
        ],
    );
    send(&mut c, &["SAVE"]);
    drop(c);

    // Kill, let `gone`'s 1s deadline lapse during downtime, then restart.
    srv.kill();
    thread::sleep(Duration::from_millis(1300));
    srv.restart();
    let mut c = srv.conn();
    thread::sleep(Duration::from_millis(300)); // let the post-restart sweep run

    let resp = send(&mut c, &["TSELECT", "*", "FROM", "pres"]);
    assert!(
        resp.contains("keep"),
        "long-TTL row should survive restart: {resp}"
    );
    assert!(
        !resp.contains("gone"),
        "lapsed-deadline row must not be resurrected with a fresh TTL: {resp}"
    );

    // Indexes round-tripped: the expired PK is reusable.
    let resp = send(
        &mut c,
        &["TINSERT", "pres", "user_id", "gone", "room", "again"],
    );
    assert!(
        !resp.starts_with('-'),
        "expired PK reusable after restart: {resp}"
    );
}

// Row TTL recovered purely from WAL replay (no snapshot since the write). The
// WAL stores the relative command, so replay REFRESHES the deadline -- exactly
// like KV EXPIRE/SETEX. The guarantee here is: the row survives recovery and its
// TTL is still active (it expires again). Absolute deadline preservation is a
// snapshot-only guarantee, covered by `row_ttl_survives_restart`.
#[test]
fn row_ttl_active_after_wal_replay() {
    let mut srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();
    send(
        &mut c,
        &["TCREATE", "pres", "user_id STR PRIMARY KEY,", "room STR"],
    );
    send(
        &mut c,
        &[
            "TINSERT", "pres", "user_id", "keep", "room", "main", "TTL", "60",
        ],
    );
    send(
        &mut c,
        &[
            "TINSERT", "pres", "user_id", "gone", "room", "main", "TTL", "2",
        ],
    );
    // NO SAVE -> recovery is from WAL replay only.
    drop(c);
    srv.kill();
    srv.restart();
    let mut c = srv.conn();

    // Both rows survive recovery (gone's TTL was refreshed by replay).
    let resp = send(&mut c, &["TSELECT", "*", "FROM", "pres"]);
    assert!(
        resp.contains("keep"),
        "long-TTL row should survive WAL replay: {resp}"
    );
    assert!(
        resp.contains("gone"),
        "short-TTL row should survive WAL replay: {resp}"
    );

    // The TTL is still active: `gone` expires on its refreshed schedule, `keep` stays.
    thread::sleep(Duration::from_millis(2600));
    let resp = send(&mut c, &["TSELECT", "*", "FROM", "pres"]);
    assert!(
        resp.contains("keep"),
        "long-TTL row should still be present: {resp}"
    );
    assert!(
        !resp.contains("gone"),
        "short-TTL row should expire after WAL replay refreshed its TTL: {resp}"
    );
}

// A TTL set by an UPDATE must survive WAL replay. The update path applies the TTL
// in the leaf and logs it as a trailing `TTL <secs>` on the TUPDATE, so replay
// re-applies it. Without that, the update's TTL is dropped on replay and the row
// lives forever. Guarantee (WAL-only, relative TTL refreshes on replay): the row
// recovers AND its TTL stays active, so it still expires.
#[test]
fn update_ttl_active_after_wal_replay() {
    let mut srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();
    send(
        &mut c,
        &["TCREATE", "pres", "user_id STR PRIMARY KEY,", "room STR"],
    );
    // Insert WITHOUT a TTL, then set the TTL via UPDATE.
    send(&mut c, &["TINSERT", "pres", "user_id", "keep", "room", "a"]);
    send(&mut c, &["TINSERT", "pres", "user_id", "gone", "room", "a"]);
    send(
        &mut c,
        &[
            "TUPDATE", "pres", "SET", "room", "b", "WHERE", "user_id", "=", "keep", "TTL", "60",
        ],
    );
    send(
        &mut c,
        &[
            "TUPDATE", "pres", "SET", "room", "b", "WHERE", "user_id", "=", "gone", "TTL", "2",
        ],
    );
    // NO SAVE -> recovery is from WAL replay only.
    drop(c);
    srv.kill();
    srv.restart();
    let mut c = srv.conn();

    // Both rows recover; the update's TTL came back with them.
    let resp = send(&mut c, &["TSELECT", "*", "FROM", "pres"]);
    assert!(resp.contains("keep"), "long-TTL row recovers: {resp}");
    assert!(resp.contains("gone"), "short-TTL row recovers: {resp}");

    // The update's TTL is still active: `gone` expires, `keep` stays. Before the
    // fix `gone` had no TTL after replay and would still be present here.
    thread::sleep(Duration::from_millis(2600));
    let resp = send(&mut c, &["TSELECT", "*", "FROM", "pres"]);
    assert!(resp.contains("keep"), "long-TTL row still present: {resp}");
    assert!(
        !resp.contains("gone"),
        "update-set TTL must survive replay and expire the row: {resp}"
    );
}

// A TTL set by an UPSERT onto an existing (conflicting) row must survive WAL
// replay. Covers both shapes: an upsert that also writes a non-key field, and a
// TTL-only refresh (no non-key fields) -- the latter previously logged no command
// at all, so its deadline vanished on replay and the row lived forever.
#[test]
fn upsert_ttl_active_after_wal_replay() {
    let mut srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();
    send(
        &mut c,
        &["TCREATE", "pres", "user_id STR PRIMARY KEY,", "room STR"],
    );
    send(&mut c, &["TINSERT", "pres", "user_id", "keep", "room", "a"]);
    send(&mut c, &["TINSERT", "pres", "user_id", "gone", "room", "a"]);
    // `keep`: upsert that also updates a field. `gone`: TTL-only upsert (conflict
    // key is the sole field) -- the case that logged nothing before the fix.
    send(
        &mut c,
        &[
            "TUPSERT", "pres", "user_id", "keep", "room", "b", "TTL", "60",
        ],
    );
    send(&mut c, &["TUPSERT", "pres", "user_id", "gone", "TTL", "2"]);
    // NO SAVE -> recovery is from WAL replay only.
    drop(c);
    srv.kill();
    srv.restart();
    let mut c = srv.conn();

    let resp = send(&mut c, &["TSELECT", "*", "FROM", "pres"]);
    assert!(resp.contains("keep"), "long-TTL row recovers: {resp}");
    assert!(
        resp.contains("gone"),
        "TTL-only-upsert row recovers: {resp}"
    );

    thread::sleep(Duration::from_millis(2600));
    let resp = send(&mut c, &["TSELECT", "*", "FROM", "pres"]);
    assert!(resp.contains("keep"), "long-TTL row still present: {resp}");
    assert!(
        !resp.contains("gone"),
        "upsert-set TTL must survive replay and expire the row: {resp}"
    );
}

// A row with an auto-generated UUID primary key must keep the SAME id across a
// WAL-replay recovery. The table layer logs the RESOLVED insert (explicit uuid),
// so replay reproduces the exact row instead of regenerating it. This also guards
// against double-logging: a double-apply would yield two rows and fail the
// full-output equality check below.
#[test]
fn wal_replay_preserves_autogenerated_uuid_pk() {
    let mut srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();
    send(
        &mut c,
        &["TCREATE", "u", "id UUID PRIMARY KEY,", "name STR"],
    );
    send(&mut c, &["TINSERT", "u", "name", "alice"]); // auto-uuid PK, NO snapshot
    let before = send(&mut c, &["TSELECT", "*", "FROM", "u"]);
    drop(c);

    srv.kill();
    srv.restart(); // recovery is WAL replay only
    let mut c = srv.conn();
    let after = send(&mut c, &["TSELECT", "*", "FROM", "u"]);

    assert_eq!(
        before, after,
        "auto-uuid PK identity must be stable across WAL replay"
    );
}

// Auto-increment INT PK sequence must survive WAL replay. The seq counter
// (_t:<table>:seq) is bumped by next_id() via a direct store.incr that is NOT
// WAL-logged; the resolved id is only carried inside the replayed TINSERT, which
// skips next_id() on the explicit-PK path. So after a WAL-only recovery the
// counter is stale and the next live insert reuses an id -> PK collision.
#[test]
fn wal_replay_restores_autoincrement_seq() {
    let mut srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();
    send(
        &mut c,
        &["TCREATE", "ai", "id INT PRIMARY KEY,", "name STR"],
    );
    send(&mut c, &["TINSERT", "ai", "name", "a"]); // id 1
    send(&mut c, &["TINSERT", "ai", "name", "b"]); // id 2
    send(&mut c, &["TINSERT", "ai", "name", "c"]); // id 3, NO snapshot
    drop(c);

    srv.kill();
    srv.restart(); // recovery is WAL replay only
    let mut c = srv.conn();

    // The next auto-increment insert must get id 4, not collide with 1.
    let reply = send(&mut c, &["TINSERT", "ai", "name", "d"]);
    assert!(
        !reply.to_ascii_lowercase().contains("err"),
        "post-replay auto-increment insert must not error: {reply}"
    );
    let rows = send(&mut c, &["TSELECT", "*", "FROM", "ai"]);
    let count = rows.matches("name").count();
    assert_eq!(
        count, 4,
        "all four rows must coexist after replay (no id reuse): {rows}"
    );
}

// A table with no declared PK uses an implicit auto-increment id. Its rows must
// survive WAL-only recovery with stable identity and no later id reuse.
#[test]
fn wal_replay_no_pk_table_implicit_id() {
    let mut srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();
    send(&mut c, &["TCREATE", "np", "name STR"]); // no PRIMARY KEY
    send(&mut c, &["TINSERT", "np", "name", "a"]);
    send(&mut c, &["TINSERT", "np", "name", "b"]);
    let before = send(&mut c, &["TSELECT", "*", "FROM", "np"]);
    drop(c);

    srv.kill();
    srv.restart(); // recovery is WAL replay only
    let mut c = srv.conn();
    let after = send(&mut c, &["TSELECT", "*", "FROM", "np"]);
    assert_eq!(before, after, "no-PK rows must be stable across WAL replay");

    send(&mut c, &["TINSERT", "np", "name", "c"]);
    let rows = send(&mut c, &["TSELECT", "*", "FROM", "np"]);
    assert_eq!(
        rows.matches("name").count(),
        3,
        "post-replay insert must not reuse an implicit id: {rows}"
    );
}

// Snapshot TTLs are absolute deadlines (V3): a key that expires DURING downtime
// must stay gone after restart, not resurrect with a fresh TTL. Regression for
// the relative-remaining-ms snapshot bug. (SAVE truncates the WAL, so recovery
// is from the snapshot only -- the path under test.)
#[test]
fn snapshot_ttl_expires_across_downtime() {
    let mut srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();

    send(&mut c, &["SET", "short", "v", "EX", "2"]); // expires during downtime
    send(&mut c, &["SET", "long", "v", "EX", "3600"]); // should survive
    send(&mut c, &["SET", "forever", "v"]); // no TTL, survives
    send(&mut c, &["SAVE"]);
    drop(c);

    srv.kill();
    thread::sleep(Duration::from_millis(2500)); // past `short`'s 2s deadline
    srv.restart();
    let mut c = srv.conn();

    let resp = send(&mut c, &["GET", "short"]);
    assert!(
        resp.contains("$-1") || resp.trim() == "$-1",
        "key past its deadline must NOT resurrect across downtime: {resp}"
    );
    let resp = send(&mut c, &["GET", "long"]);
    assert!(resp.contains("v"), "long-TTL key should survive: {resp}");
    let resp = send(&mut c, &["GET", "forever"]);
    assert!(resp.contains("v"), "no-TTL key should survive: {resp}");

    // `long`'s TTL should be ~unchanged (deadline preserved), not reset to 3600
    // from restart -- but it was only down ~2.5s, so just assert it's still set.
    let resp = send(&mut c, &["TTL", "long"]);
    assert!(
        !resp.contains(":-1"),
        "long key must still have a TTL: {resp}"
    );
}

// Hash field TTLs (ENG-1290) must survive a WAL-only restart: HPEXPIREAT is
// self-logged with its absolute deadline and replays deterministically.
#[test]
fn hash_field_ttl_survives_wal_replay() {
    let mut srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();
    send(&mut c, &["HSET", "h", "f1", "v1", "f2", "v2"]);
    send(
        &mut c,
        &["HPEXPIREAT", "h", "99999999999999", "FIELDS", "1", "f1"],
    );
    drop(c);
    srv.kill();
    srv.restart(); // WAL replay only
    let mut c = srv.conn();
    assert!(
        send(&mut c, &["HPEXPIRETIME", "h", "FIELDS", "1", "f1"]).contains("99999999999999"),
        "f1 field TTL survived WAL replay"
    );
    assert!(send(&mut c, &["HTTL", "h", "FIELDS", "1", "f2"]).contains(":-1"));
    assert!(send(&mut c, &["HGET", "h", "f1"]).contains("v1"));
}

// Field TTLs must also survive a snapshot (BGSAVE truncates the WAL, so the
// deadline has to be in the snapshot's 'h' hash record).
#[test]
fn hash_field_ttl_survives_snapshot() {
    let mut srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();
    send(&mut c, &["HSET", "h", "f1", "v1"]);
    send(
        &mut c,
        &["HPEXPIREAT", "h", "99999999999999", "FIELDS", "1", "f1"],
    );
    send(&mut c, &["BGSAVE"]); // snapshot + WAL truncate
    drop(c);
    srv.kill();
    srv.restart(); // loads from the snapshot (WAL was truncated)
    let mut c = srv.conn();
    assert!(
        send(&mut c, &["HPEXPIRETIME", "h", "FIELDS", "1", "f1"]).contains("99999999999999"),
        "f1 field TTL survived the snapshot"
    );
    assert!(send(&mut c, &["HGET", "h", "f1"]).contains("v1"));
}
