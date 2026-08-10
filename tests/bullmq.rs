//! BullMQ compatibility regression suite.
//!
//! BullMQ is a core supported use case, and its past breakage involved the hard
//! *combination* of Lua (EVALSHA/script cache), streams + consumer groups,
//! blocking list handoff (BRPOPLPUSH), delayed-job sorted sets, and
//! multi-connection concurrency, none of which a single-command unit test
//! exercises together. This suite models BullMQ's actual Redis choreography in
//! Rust (no JS/TS) and asserts end-to-end correctness plus post-workload
//! responsiveness.
//!
//! Key layout mirrors BullMQ:
//!   q:id (counter) · q:wait / q:active (lists) · q:completed / q:failed /
//!   q:delayed (zsets) · q:job:<id> (hash) · q:events (stream)

mod common;
use common::{connect, read_all, resp_cmd, send_and_read, LuxServer};
use std::io::Write;
use std::net::TcpStream;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

// BullMQ drives every atomic multi-key mutation through a cached Lua script
// (EVALSHA). These are simplified but structurally faithful stand-ins.

/// add: INCR id, write the job hash, LPUSH onto wait, emit an `added` event.
/// KEYS = [id, wait, events]  ARGV = [data, jobkey-prefix]
const ADD_SCRIPT: &str = r#"
local jobId = redis.call('INCR', KEYS[1])
redis.call('HSET', ARGV[2] .. jobId, 'data', ARGV[1], 'state', 'waiting')
redis.call('LPUSH', KEYS[2], jobId)
redis.call('XADD', KEYS[3], '*', 'event', 'added', 'jobId', jobId)
return jobId
"#;

/// moveToCompleted: LREM from active, mark the hash, ZADD completed, emit event.
/// KEYS = [active, completed, events]  ARGV = [jobId, jobkey-prefix, score]
const COMPLETE_SCRIPT: &str = r#"
redis.call('LREM', KEYS[1], 1, ARGV[1])
redis.call('HSET', ARGV[2] .. ARGV[1], 'state', 'completed')
redis.call('ZADD', KEYS[2], ARGV[3], ARGV[1])
redis.call('XADD', KEYS[3], '*', 'event', 'completed', 'jobId', ARGV[1])
return 1
"#;

/// moveToFailed: LREM from active, mark the hash, ZADD failed, emit event.
/// KEYS = [active, failed, events]  ARGV = [jobId, jobkey-prefix, score]
const FAIL_SCRIPT: &str = r#"
redis.call('LREM', KEYS[1], 1, ARGV[1])
redis.call('HSET', ARGV[2] .. ARGV[1], 'state', 'failed')
redis.call('ZADD', KEYS[2], ARGV[3], ARGV[1])
redis.call('XADD', KEYS[3], '*', 'event', 'failed', 'jobId', ARGV[1])
return 1
"#;

/// Extract the payload of a RESP bulk (`$n\r\n<v>\r\n`) or integer (`:n\r\n`)
/// reply; None for a nil reply (`$-1`).
fn value_of(resp: &str) -> Option<String> {
    let mut lines = resp.split("\r\n");
    let header = lines.next()?;
    if let Some(int) = header.strip_prefix(':') {
        return Some(int.to_string());
    }
    if header == "$-1" || header == "*-1" {
        return None;
    }
    if header.starts_with('$') {
        return lines.next().map(|s| s.to_string());
    }
    None
}

fn script_load(conn: &mut TcpStream, body: &str) -> String {
    let resp = send_and_read(conn, &["SCRIPT", "LOAD", body]);
    value_of(&resp).expect("SCRIPT LOAD returns a sha")
}

/// Add `n` jobs via the cached add script (as BullMQ's producer would).
fn produce(conn: &mut TcpStream, add_sha: &str, n: usize) {
    for i in 0..n {
        let data = format!("job-{i}");
        let resp = send_and_read(
            conn,
            &[
                "EVALSHA", add_sha, "3", "q:id", "q:wait", "q:events", &data, "q:job:",
            ],
        );
        assert!(resp.starts_with(':'), "add returns a job id: {resp}");
    }
}

/// One worker step: blocking handoff wait->active, then the completion script.
/// Returns the processed job id, or None on timeout (empty queue).
fn process_one(conn: &mut TcpStream, complete_sha: &str, timeout: &str) -> Option<String> {
    let resp = send_and_read(conn, &["BRPOPLPUSH", "q:wait", "q:active", timeout]);
    let job = value_of(&resp)?;
    let ok = send_and_read(
        conn,
        &[
            "EVALSHA",
            complete_sha,
            "3",
            "q:active",
            "q:completed",
            "q:events",
            &job,
            "q:job:",
            &job, // score = job id (monotonic)
        ],
    );
    assert!(ok.contains(":1"), "complete script ok: {ok}");
    Some(job)
}

#[test]
fn bullmq_produce_and_drain_all_jobs() {
    let server = LuxServer::start();
    let mut c = server.conn();
    let add = script_load(&mut c, ADD_SCRIPT);
    let complete = script_load(&mut c, COMPLETE_SCRIPT);

    let n = 50;
    produce(&mut c, &add, n);

    let mut worker = server.conn();
    let mut processed = 0;
    while process_one(&mut worker, &complete, "1").is_some() {
        processed += 1;
    }
    assert_eq!(processed, n, "worker processed every job exactly once");

    // All jobs completed, nothing stuck in wait/active.
    assert!(send_and_read(&mut c, &["ZCARD", "q:completed"]).contains(&format!(":{n}")));
    assert!(
        send_and_read(&mut c, &["LLEN", "q:wait"]).contains(":0"),
        "wait drained"
    );
    assert!(
        send_and_read(&mut c, &["LLEN", "q:active"]).contains(":0"),
        "active drained"
    );
    // Two events per job (added + completed).
    assert!(send_and_read(&mut c, &["XLEN", "q:events"]).contains(&format!(":{}", n * 2)));
    // A sampled job hash reflects the terminal state.
    assert!(send_and_read(&mut c, &["HGET", "q:job:1", "state"]).contains("completed"));
}

#[test]
fn bullmq_blocking_worker_wakes_on_new_job() {
    let server = LuxServer::start();
    let mut setup = server.conn();
    let add = script_load(&mut setup, ADD_SCRIPT);
    let complete = script_load(&mut setup, COMPLETE_SCRIPT);
    let complete = Arc::new(complete);

    // Worker blocks on an empty queue (cross-connection handoff).
    let port = server.port();
    let complete_w = complete.clone();
    let handle = thread::spawn(move || {
        let mut w = connect(port);
        process_one(&mut w, &complete_w, "5")
    });

    thread::sleep(Duration::from_millis(300)); // let the worker block
    produce(&mut setup, &add, 1); // wakes the blocked BRPOPLPUSH

    let processed = handle.join().unwrap();
    assert!(
        processed.is_some(),
        "blocked worker woke and processed a job"
    );
    assert!(send_and_read(&mut setup, &["ZCARD", "q:completed"]).contains(":1"));
}

#[test]
fn bullmq_concurrent_workers_process_each_job_once() {
    let server = LuxServer::start();
    let mut setup = server.conn();
    let add = script_load(&mut setup, ADD_SCRIPT);
    let complete = Arc::new(script_load(&mut setup, COMPLETE_SCRIPT));

    let n = 90;
    produce(&mut setup, &add, n);

    let port = server.port();
    let mut handles = Vec::new();
    for _ in 0..3 {
        let complete_w = complete.clone();
        handles.push(thread::spawn(move || {
            let mut w = connect(port);
            let mut count = 0usize;
            while process_one(&mut w, &complete_w, "1").is_some() {
                count += 1;
            }
            count
        }));
    }
    let total: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
    // Atomic BRPOPLPUSH must hand each job to exactly one worker: sum == n, no
    // double-processing (which would push the sum above n).
    assert_eq!(total, n, "each job processed exactly once across workers");
    assert!(send_and_read(&mut setup, &["ZCARD", "q:completed"]).contains(&format!(":{n}")));
    assert!(send_and_read(&mut setup, &["LLEN", "q:active"]).contains(":0"));
}

#[test]
fn bullmq_events_via_consumer_group() {
    let server = LuxServer::start();
    let mut c = server.conn();
    let add = script_load(&mut c, ADD_SCRIPT);
    let complete = script_load(&mut c, COMPLETE_SCRIPT);

    let n = 10;
    produce(&mut c, &add, n);
    let mut worker = server.conn();
    while process_one(&mut worker, &complete, "1").is_some() {}

    // A consumer group reads the event stream (BullMQ's QueueEvents pattern).
    send_and_read(&mut c, &["XGROUP", "CREATE", "q:events", "listeners", "0"]);
    let read = send_and_read(
        &mut c,
        &[
            "XREADGROUP",
            "GROUP",
            "listeners",
            "c1",
            "COUNT",
            "100",
            "STREAMS",
            "q:events",
            ">",
        ],
    );
    assert!(read.contains("added"), "events include added: {read}");
    assert!(read.contains("completed"), "events include completed");
    // Everything read is pending until acked.
    let pending = send_and_read(&mut c, &["XPENDING", "q:events", "listeners"]);
    assert!(
        pending.contains(&format!(":{}", n * 2)),
        "all delivered events pending: {pending}"
    );
}

#[test]
fn bullmq_failure_path_moves_job_to_failed() {
    let server = LuxServer::start();
    let mut c = server.conn();
    let add = script_load(&mut c, ADD_SCRIPT);
    let fail = script_load(&mut c, FAIL_SCRIPT);
    produce(&mut c, &add, 1);

    // Worker grabs the job then routes it to failed instead of completed.
    let mut worker = server.conn();
    let job = value_of(&send_and_read(
        &mut worker,
        &["BRPOPLPUSH", "q:wait", "q:active", "1"],
    ))
    .expect("got a job");
    send_and_read(
        &mut worker,
        &[
            "EVALSHA", &fail, "3", "q:active", "q:failed", "q:events", &job, "q:job:", &job,
        ],
    );
    assert!(send_and_read(&mut c, &["ZCARD", "q:failed"]).contains(":1"));
    assert!(send_and_read(&mut c, &["LLEN", "q:active"]).contains(":0"));
    assert!(send_and_read(&mut c, &["HGET", &format!("q:job:{job}"), "state"]).contains("failed"));
}

#[test]
fn bullmq_delayed_jobs_promote_when_due() {
    let server = LuxServer::start();
    let mut c = server.conn();

    // BullMQ parks delayed jobs in a zset scored by due-timestamp, then a
    // promotion step moves due ones into wait. Model both with ZADD + a
    // ZRANGEBYSCORE/ZREM promotion (using integer "timestamps").
    send_and_read(
        &mut c,
        &["ZADD", "q:delayed", "100", "10", "200", "20", "300", "30"],
    );
    // "Now" = 250: jobs 10 and 20 are due.
    let due = send_and_read(&mut c, &["ZRANGEBYSCORE", "q:delayed", "-inf", "250"]);
    assert!(
        due.contains("10") && due.contains("20") && !due.contains("30"),
        "due set: {due}"
    );
    // Promote them: remove from delayed, push to wait.
    send_and_read(&mut c, &["ZREMRANGEBYSCORE", "q:delayed", "-inf", "250"]);
    send_and_read(&mut c, &["LPUSH", "q:wait", "10", "20"]);
    assert!(
        send_and_read(&mut c, &["ZCARD", "q:delayed"]).contains(":1"),
        "one still delayed"
    );
    assert!(
        send_and_read(&mut c, &["LLEN", "q:wait"]).contains(":2"),
        "two promoted to wait"
    );
}

#[test]
fn bullmq_evalsha_noscript_then_reload() {
    let server = LuxServer::start();
    let mut c = server.conn();
    // BullMQ optimistically EVALSHAs and falls back to loading on NOSCRIPT.
    let fake_sha = "ffffffffffffffffffffffffffffffffffffffff";
    let miss = send_and_read(&mut c, &["EVALSHA", fake_sha, "0"]);
    assert!(miss.contains("NOSCRIPT"), "unknown sha -> NOSCRIPT: {miss}");
    // Reload and retry succeeds.
    let sha = script_load(&mut c, "return 'ok'");
    let hit = send_and_read(&mut c, &["EVALSHA", &sha, "0"]);
    assert!(hit.contains("ok"), "reloaded script runs: {hit}");
}

#[test]
fn bullmq_server_responsive_after_workload() {
    // After a full produce/drain cycle the server must still answer promptly on
    // a fresh connection (no leaked blocked waiters, no wedged shard locks).
    let server = LuxServer::start();
    let mut c = server.conn();
    let add = script_load(&mut c, ADD_SCRIPT);
    let complete = Arc::new(script_load(&mut c, COMPLETE_SCRIPT));
    produce(&mut c, &add, 40);

    let port = server.port();
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let complete_w = complete.clone();
            thread::spawn(move || {
                let mut w = connect(port);
                while process_one(&mut w, &complete_w, "1").is_some() {}
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }

    // Fresh connection, immediate PING.
    let mut fresh = connect(port);
    fresh.write_all(&resp_cmd(&["PING"])).unwrap();
    let pong = read_all(&mut fresh);
    assert!(
        pong.contains("PONG"),
        "server responsive after workload: {pong}"
    );
    assert!(send_and_read(&mut c, &["ZCARD", "q:completed"]).contains(":40"));
}
