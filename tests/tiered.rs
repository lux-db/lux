use std::io::Write;
use std::net::TcpStream;
use std::sync::{Arc, Barrier};
use std::thread;

mod common;
use common::{http_request, read_all, resp_cmd, send, LuxServer};

const TIERED_MEMORY_LIMIT_BYTES: usize = 100 * 1024;

fn info_metric(info: &str, name: &str) -> usize {
    info.lines()
        .find_map(|line| line.strip_prefix(&format!("{name}:")))
        .unwrap_or_else(|| panic!("INFO is missing {name}: {info}"))
        .trim()
        .parse()
        .unwrap_or_else(|error| panic!("invalid INFO value for {name}: {error}"))
}

fn assert_tiered_ceiling(conn: &mut TcpStream) {
    let info = send(conn, &["INFO"]);
    let used_memory = info_metric(&info, "used_memory_bytes");
    assert!(
        used_memory <= TIERED_MEMORY_LIMIT_BYTES,
        "tiered memory exceeded its configured ceiling: {used_memory} > {TIERED_MEMORY_LIMIT_BYTES}\n{info}"
    );

    let hot_keys = info_metric(&info, "tracked_key_count");
    let disk_keys = info_metric(&info, "disk_keys");
    let total_keys = info_metric(&info, "tracked_total_key_count");
    assert_eq!(
        hot_keys + disk_keys,
        total_keys,
        "hot and cold INFO counters disagree\n{info}"
    );
    assert_eq!(
        send(conn, &["DBSIZE"]),
        format!(":{total_keys}\r\n"),
        "DBSIZE and INFO disagree"
    );
}

fn seed_distinct_values(conn: &mut TcpStream, count: usize, value_bytes: usize) {
    for i in 0..count {
        let value = format!("value-{i:04}-{}", "x".repeat(value_bytes));
        assert_eq!(
            send(conn, &["SET", &format!("ceiling:{i}"), &value]),
            "+OK\r\n"
        );
    }
}

fn fill_memory(conn: &mut TcpStream, count: usize) {
    let val = "x".repeat(10000);
    for i in 0..count {
        send(conn, &["SET", &format!("filler:{i}"), &val]);
    }
}

#[test]
fn tiered_repeated_promotions_preserve_values_and_memory_ceiling() {
    let srv = LuxServer::builder()
        .tiered()
        .shards(1)
        .maxmemory("100kb")
        .env("LUX_MAXMEMORY_SAMPLES", "512")
        .start();
    let mut conn = srv.conn();
    seed_distinct_values(&mut conn, 180, 2_000);
    assert_tiered_ceiling(&mut conn);

    for pass in 0..3 {
        for i in 0..180 {
            let value = format!("value-{i:04}-{}", "x".repeat(2_000));
            assert_eq!(
                send(&mut conn, &["GET", &format!("ceiling:{i}")]),
                format!("${}\r\n{value}\r\n", value.len()),
                "pass {pass} returned the wrong value for ceiling:{i}"
            );
        }
        assert_tiered_ceiling(&mut conn);
        assert!(
            info_metric(&send(&mut conn, &["INFO"]), "disk_keys") > 0,
            "the test must retain cold keys"
        );
    }
}

#[test]
fn tiered_large_multi_key_and_pipeline_reads_restore_memory_ceiling() {
    let srv = LuxServer::builder()
        .tiered()
        .shards(1)
        .maxmemory("100kb")
        .env("LUX_MAXMEMORY_SAMPLES", "512")
        .start();
    let mut conn = srv.conn();
    seed_distinct_values(&mut conn, 220, 2_000);

    let mut command = Vec::with_capacity(221);
    command.push("MGET".to_string());
    command.extend((0..220).map(|i| format!("ceiling:{i}")));
    let args: Vec<&str> = command.iter().map(String::as_str).collect();
    let response = send(&mut conn, &args);
    assert!(
        response.starts_with("*220\r\n"),
        "MGET response: {response}"
    );
    for i in 0..220 {
        assert!(
            response.contains(&format!("value-{i:04}-")),
            "MGET omitted ceiling:{i}"
        );
    }
    assert_tiered_ceiling(&mut conn);

    let mut pipeline = Vec::new();
    for i in 0..220 {
        pipeline.extend_from_slice(&resp_cmd(&["GET", &format!("ceiling:{i}")]));
    }
    conn.write_all(&pipeline).unwrap();
    let response = read_all(&mut conn);
    for i in 0..220 {
        assert!(
            response.contains(&format!("value-{i:04}-")),
            "pipeline omitted ceiling:{i}"
        );
    }
    assert_tiered_ceiling(&mut conn);
}

#[test]
fn tiered_concurrent_promotions_preserve_values_and_memory_ceiling() {
    let srv = LuxServer::builder()
        .tiered()
        .shards(4)
        .maxmemory("100kb")
        .env("LUX_MAXMEMORY_SAMPLES", "512")
        .start();
    let mut conn = srv.conn();
    seed_distinct_values(&mut conn, 160, 2_000);
    let barrier = Arc::new(Barrier::new(8));
    let port = srv.port();

    let readers: Vec<_> = (0..8)
        .map(|reader| {
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                let mut conn = common::connect(port);
                barrier.wait();
                for offset in 0..80 {
                    let i = (reader * 17 + offset) % 160;
                    let response = send(&mut conn, &["GET", &format!("ceiling:{i}")]);
                    assert!(
                        response.contains(&format!("value-{i:04}-")),
                        "concurrent read returned the wrong value for ceiling:{i}: {response}"
                    );
                }
            })
        })
        .collect();
    for reader in readers {
        reader.join().unwrap();
    }

    assert_tiered_ceiling(&mut conn);
    for i in 0..160 {
        assert!(
            send(&mut conn, &["GET", &format!("ceiling:{i}")]).contains(&format!("value-{i:04}-")),
            "concurrent promotion lost ceiling:{i}"
        );
    }
    assert_tiered_ceiling(&mut conn);
}

#[test]
fn tiered_native_data_survives_rebalancing_and_restart() {
    let mut srv = LuxServer::builder()
        .tiered()
        .shards(1)
        .http()
        .maxmemory("100kb")
        .env("LUX_MAXMEMORY_SAMPLES", "512")
        .start();
    let mut conn = srv.conn();
    assert_eq!(
        send(&mut conn, &["TCREATE", "accounts", "name STR"]),
        "+OK\r\n"
    );
    assert_eq!(
        send(&mut conn, &["TINSERT", "accounts", "name", "alice"]),
        ":1\r\n"
    );
    assert_eq!(
        send(&mut conn, &["TSADD", "temperature", "1000", "72.5"]),
        ":1000\r\n"
    );
    assert_eq!(
        send(&mut conn, &["VSET", "direction", "3", "1", "0", "0"]),
        "+OK\r\n"
    );
    seed_distinct_values(&mut conn, 100, 2_000);

    let table = send(&mut conn, &["TSELECT", "*", "FROM", "accounts"]);
    assert!(table.contains("alice"), "table row was lost: {table}");
    let series = send(&mut conn, &["TSRANGE", "temperature", "-", "+"]);
    assert!(
        series.contains("72.5"),
        "time-series sample was lost: {series}"
    );
    let vectors = send(&mut conn, &["VSEARCH", "3", "1", "0", "0", "K", "1"]);
    assert!(vectors.contains("direction"), "vector was lost: {vectors}");

    let (status, body) = http_request(srv.http_port(), "GET", "/v1/kv/ceiling:0", None, None);
    assert_eq!(status, 200, "HTTP cold read failed: {body}");
    assert!(
        body.contains("value-0000-"),
        "HTTP returned the wrong value: {body}"
    );
    assert_tiered_ceiling(&mut conn);
    drop(conn);

    srv.restart_with_maxmemory("100kb");
    let mut conn = srv.conn();
    assert_tiered_ceiling(&mut conn);
    assert!(
        send(&mut conn, &["TSELECT", "*", "FROM", "accounts"]).contains("alice"),
        "restart lost the table row"
    );
    assert!(
        send(&mut conn, &["TSRANGE", "temperature", "-", "+"]).contains("72.5"),
        "restart lost the time-series sample"
    );
    assert!(
        send(&mut conn, &["VSEARCH", "3", "1", "0", "0", "K", "1"]).contains("direction"),
        "restart lost the vector"
    );
    for i in 0..100 {
        assert!(
            send(&mut conn, &["GET", &format!("ceiling:{i}")]).contains(&format!("value-{i:04}-")),
            "restart lost ceiling:{i}"
        );
    }
    assert_tiered_ceiling(&mut conn);
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
    let pushed = send(&mut c, &["LPUSH", "l", "d"]);
    assert!(pushed.contains(":4"), "LPUSH should return 4: {pushed}");
    let resp = send(&mut c, &["LLEN", "l"]);
    assert!(resp.contains(":4"), "LLEN should be 4: {resp}");
    let values = send(&mut c, &["LRANGE", "l", "0", "-1"]);
    assert!(values.contains("d"), "LPUSH value was lost: {values}");
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
fn tiered_multi_key_commands_promote_every_input_before_mutating() {
    let srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();

    send(&mut c, &["RPUSH", "sort-source", "3", "1", "2"]);
    send(&mut c, &["RPUSH", "sort-destination", "old"]);
    fill_memory(&mut c, 20);
    let stored = send(
        &mut c,
        &["SORT", "sort-source", "STORE", "sort-destination"],
    );
    assert!(stored.contains(":3"), "cold SORT source was lost: {stored}");
    let sorted = send(&mut c, &["LRANGE", "sort-destination", "0", "-1"]);
    let one = sorted.find("\r\n1\r\n");
    let two = sorted.find("\r\n2\r\n");
    let three = sorted.find("\r\n3\r\n");
    assert!(
        one.is_some() && two.is_some() && three.is_some() && one < two && two < three,
        "cold SORT result is incomplete or unordered: {sorted}"
    );

    send(&mut c, &["SET", "rename-source", "rename-value"]);
    fill_memory(&mut c, 20);
    let renamed = send(&mut c, &["RENAME", "rename-source", "rename-destination"]);
    assert!(renamed.contains("+OK"), "cold RENAME failed: {renamed}");
    assert!(
        send(&mut c, &["GET", "rename-destination"]).contains("rename-value"),
        "cold RENAME lost its source value"
    );

    send(&mut c, &["SET", "copy-source", "copy-value"]);
    fill_memory(&mut c, 20);
    let copied = send(&mut c, &["COPY", "copy-source", "copy-destination"]);
    assert!(copied.contains(":1"), "cold COPY failed: {copied}");
    assert!(
        send(&mut c, &["GET", "copy-destination"]).contains("copy-value"),
        "cold COPY lost its source value"
    );

    send(&mut c, &["GEOADD", "geo-source", "0", "0", "origin"]);
    send(&mut c, &["ZADD", "geo-destination", "1", "old"]);
    fill_memory(&mut c, 20);
    let stored = send(
        &mut c,
        &[
            "GEORADIUS",
            "geo-source",
            "0",
            "0",
            "1",
            "km",
            "STORE",
            "geo-destination",
        ],
    );
    assert!(
        stored.contains(":1"),
        "cold GEORADIUS destination was not replaced: {stored}"
    );
    let members = send(&mut c, &["ZRANGE", "geo-destination", "0", "-1"]);
    assert!(
        members.contains("origin") && !members.contains("old"),
        "cold GEORADIUS destination retained stale data: {members}"
    );
}

#[test]
fn tiered_table_sequences_and_rows_survive_eviction_and_restart() {
    let mut srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();
    assert!(
        send(&mut c, &["TCREATE", "accounts", "name STR"]).contains("+OK"),
        "table creation failed"
    );
    assert!(
        send(&mut c, &["TINSERT", "accounts", "name", "alice"]).contains(":1"),
        "first row did not receive id 1"
    );

    // Force the schema, sequence, id set, indexes, and row hash through the
    // cold tier. A missing promotion used to reset the sequence to zero and
    // could overwrite row 1 on the next insert.
    fill_memory(&mut c, 30);
    let second = send(&mut c, &["TINSERT", "accounts", "name", "bob"]);
    assert!(
        second.contains(":2"),
        "second insert reused an id: {second}"
    );
    let rows = send(&mut c, &["TSELECT", "*", "FROM", "accounts"]);
    assert!(rows.contains("alice"), "eviction lost row 1: {rows}");
    assert!(rows.contains("bob"), "eviction lost row 2: {rows}");
    drop(c);

    srv.restart();
    let mut c = srv.conn();
    let rows = send(&mut c, &["TSELECT", "*", "FROM", "accounts"]);
    assert!(rows.contains("alice"), "restart lost row 1: {rows}");
    assert!(rows.contains("bob"), "restart lost row 2: {rows}");
    let third = send(&mut c, &["TINSERT", "accounts", "name", "carol"]);
    assert!(
        third.contains(":3"),
        "restart reused a sequence id: {third}"
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
fn tiered_cold_relative_mutation_replays_once_without_snapshot() {
    let mut srv = LuxServer::builder()
        .tiered()
        .shards(1)
        .maxmemory("100kb")
        .env("LUX_MAXMEMORY_SAMPLES", "128")
        .start();
    let mut c = srv.conn();
    assert_eq!(send(&mut c, &["INCR", "cold-counter"]), ":1\r\n");
    fill_memory(&mut c, 20);
    drop(c);

    srv.kill();
    srv.restart();
    let mut c = srv.conn();
    assert_eq!(
        send(&mut c, &["GET", "cold-counter"]),
        "$1\r\n1\r\n",
        "a cold relative mutation must not be applied once from disk and again from WAL"
    );
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
    assert_eq!(
        send(&mut c, &["DBSIZE"]),
        ":21\r\n",
        "snapshot entries must not remain duplicated in the cold index"
    );
    let resp = send(&mut c, &["GET", "snapcold"]);
    assert!(
        resp.contains("value"),
        "cold key should survive snapshot+restart: {resp}"
    );
}

#[test]
fn tiered_snapshot_does_not_resurrect_expired_cold_entry() {
    let mut srv = LuxServer::builder().tiered().maxmemory("100kb").start();
    let mut c = srv.conn();
    assert!(send(&mut c, &["PSETEX", "expires-cold", "3000", "value"]).contains("+OK"));
    fill_memory(&mut c, 20);
    assert!(send(&mut c, &["SAVE"]).contains("+OK"));
    drop(c);

    srv.kill();
    std::thread::sleep(std::time::Duration::from_millis(3500));
    srv.restart();
    let mut c = srv.conn();
    assert_eq!(
        send(&mut c, &["GET", "expires-cold"]),
        "$-1\r\n",
        "an expired snapshot value must not be promoted from a stale cold record"
    );
    drop(c);

    // Removing an entry only from the process-local cold index is insufficient:
    // another restart would rebuild that index from the same stale data file.
    srv.restart();
    let mut c = srv.conn();
    assert_eq!(send(&mut c, &["GET", "expires-cold"]), "$-1\r\n");
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
