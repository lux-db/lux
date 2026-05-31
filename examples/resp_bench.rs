//! RESP + Embedded benchmark runner for Lux.
//!
//! Why this file exists:
//! - We need one benchmark harness that can compare multiple execution surfaces:
//!   1) Embedded API (in-process calls)
//!   2) Lux RESP server (socket protocol)
//!   3) Redis RESP server (baseline/reference)
//! - The harness needs to be deterministic enough for perf regression tracking,
//!   but flexible enough for local tuning via environment variables.
//!
//! High-level design:
//! - Build a *single logical workload plan* per command (seed + query cycles).
//! - Reuse that plan across all selected targets to maximize fairness.
//! - Execute each command for a fixed time budget and report operations/second.
//! - Optionally run multiple loops with different seeds and report medians.
//!
//! Fairness model:
//! - Every target gets the same command list and planned key/member universe.
//! - RESP targets use persistent connections and configurable pipeline depth.
//! - Embedded target consumes equivalent prepared pipelines to minimize adapter
//!   overhead differences unrelated to store logic.
//!
//! Important caveat:
//! - "Equal configuration" is not the same as "equal semantics":
//!   RESP can queue many in-flight pipeline batches, while embedded calls are
//!   still executed in-process. Use `BENCH_RESP_OUTSTANDING_PIPELINES=1` when
//!   you want RESP behavior closer to request/reply cadence.
//!
//! Output:
//! - Markdown table with per-command throughput and ratio columns.
//! - Throughput units are operations per second (formatted as K/M).
//!
//! Environment variables used by this benchmark:
//!
//! | Variable | Default | Details |
//! |---|---|---|
//! | `BENCH_DURATION_SECONDS` | `0.5` | Per-command timed benchmark duration (seconds). Must be finite and > 0. |
//! | `BENCH_COMMAND_LIMIT` | unset | Optional integer cap that truncates the command list to the first N commands (debug/iteration aid). Must be > 0 if set. |
//! | `BENCH_KEYSPACE` | `1024` | Logical key/member space used by generated workloads. Larger values reduce artificial hot-key contention. |
//! | `BENCH_RANDOM_SEED` | `0x4c55_585f_5eed` | Root RNG seed for deterministic fixture/query generation. |
//! | `BENCH_PIPELINE` | `32` | Commands per pipeline batch for RESP and embedded prepared-batch replay. Must be >= 1. |
//! | `BENCH_CLIENTS` | `1` | Parallel worker/client count per target. For RESP, this is persistent TCP connections. |
//! | `BENCH_RESP_OUTSTANDING_PIPELINES` | `4` | RESP-only in-flight pipeline batches queued before draining replies. Use `1` to behave closer to strict request/reply cadence. |
//! | `BENCH_LOG_SEEDING` | `1` | Seeding diagnostics toggle (`0` disables; any other value enables). |
//! | `BENCH_LOG_CLIENTS` | `false` | Per-client completion stats toggle. Truthy values: `1`, `true`, `yes`. |
//! | `BENCH_LOG_TIMING` | `false` | RESP write/flush/read timing breakdown toggle. Truthy values: `1`, `true`, `yes`. |
//! | `BENCH_LOOPS` | `1` | Number of full benchmark loops. Each loop uses a derived seed and random target order; final output reports medians per command/target. |
//! | `BENCH_TARGETS` | `embedded,lux,redis` | Comma-separated targets to run. Possible values: `embedded`, `lux` (aliases: `lux-resp`, `current`), `redis` (alias: `redis-resp`). |
//! | `BENCH_BUILD_MISSING_BINARIES` | `false` | If truthy, auto-builds missing Lux benchmark binary (`cargo build --release`). |
//! | `BENCH_PORT` | `6390` | Port used for spawned RESP server targets in compare mode. |
//! | `REDIS_SERVER` | `redis-server` | Path/command used to launch Redis target. |
//! | `LUX_BIN` | `target/release/lux` (with `.real` fallback) | Path to Lux binary used for RESP target and reference planning server. |
//! | `BENCH_EMBEDDED_SHARDS` | `128` | Embedded runtime shard count used when benchmarking embedded mode. |
//! | `BENCH_LUX_RUNTIME_THREADS` | `BENCH_CLIENTS` | Runtime thread count for spawned Lux RESP server. |
//! | `BENCH_LUX_RESP_BLOCK_IN_PLACE` | `1` | Passed through to Lux RESP server process for RESP execution behavior tuning. |
//!
use std::env;
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command as ProcessCommand, Stdio};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use lux::{EmbeddedClient, PreparedPipeline, ServerConfig};
use tokio::sync::Barrier as TokioBarrier;

type DynError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone, Copy)]
enum CommandId {
    // String/keyspace primitives.
    Ping,
    Set,
    Get,
    Mset,
    Msetnx,
    Mget,
    Getset,
    Getdel,
    Getex,
    Setnx,
    Setex,
    Psetex,
    Append,
    Strlen,
    Incr,
    Decr,
    Incrby,
    Decrby,
    Exists,
    Expire,
    Ttl,
    Pttl,
    Persist,
    Type,
    Dbsize,
    Scan,
    Keys,
    Randomkey,
    Rename,
    Renamenx,
    Copy,
    Bitcount,
    Bitpos,
    // List primitives.
    Lpush,
    Rpush,
    Llen,
    Lindex,
    Lrange,
    Lpop,
    Rpop,
    // Hash primitives.
    Hset,
    Hsetnx,
    Hget,
    Hmget,
    Hdel,
    Hkeys,
    Hvals,
    Hstrlen,
    Hincrby,
    Hexists,
    Hlen,
    Hgetall,
    Hscan,
    // Set primitives.
    Sadd,
    Srem,
    Sismember,
    Smismember,
    Scard,
    Smembers,
    Srandmember,
    Spop,
    Smove,
    Sscan,
    Sunion,
    Sinter,
    Sdiff,
    // Sorted set primitives.
    Zadd,
    Zscore,
    Zmscore,
    Zrank,
    Zrevrank,
    Zrem,
    Zcard,
    Zcount,
    Zrange,
    ZrangeScores,
    Zincrby,
    Zpopmin,
    Zpopmax,
    Zremrangebyrank,
    Zscan,
    // Geo primitives.
    Geoadd,
    Geopos,
    Geodist,
    GeosearchSmall,
    GeosearchLarge,
    // Stream/pubsub primitives.
    Xadd,
    Xtrim,
    Xdel,
    Xlen,
    Xrange,
    Xrevrange,
    Pfadd,
    Pfcount,
    Publish,
}

#[derive(Clone, Copy)]
struct Spec {
    label: &'static str,
    id: CommandId,
    argv: &'static [&'static str],
}

#[derive(Clone)]
struct BenchConfig {
    // Commands packed into each pipeline batch.
    // Motivation: larger batches amortize write/read syscalls and parser costs.
    pipeline: usize,
    // Parallel workers per target during timed runs.
    // Motivation: model multi-connection concurrency for RESP and multi-task
    // execution for embedded.
    resp_clients: usize,
    // Pipeline batches sent before draining replies.
    // Motivation: controls request/reply overlap for RESP. Higher values allow
    // more in-flight work before response draining.
    resp_outstanding_pipelines: usize,
    // Distinct logical keys used by query planners.
    // Motivation: reduce artificial hot-key contention in benchmark traffic.
    keyspace: usize,
    // Upper bound for fixture records seeded per command.
    // Motivation: cap setup cost while still avoiding empty-keyspace behavior.
    fixture_items: usize,
    // Prefix used for every generated key in this run.
    // Motivation: run isolation + easy SCAN pattern targeting.
    key_prefix: String,
    // Dedicated geo key used by geo commands.
    // Motivation: keep geo fixture independent from string/list/hash fixtures.
    geo_key: String,
    // Root seed for deterministic fixture/query generation.
    random_seed: u64,
    // Time budget for fixture generation per command plan.
    seed_budget: Duration,
    // Time budget for timed query execution per command.
    run_budget: Duration,
    // Verbose fixture/logging knobs.
    log_seeding: bool,
    log_clients: bool,
    log_timing: bool,
    // Optional first-N command truncation for faster iterations/debugging.
    command_limit: Option<usize>,
    // Number of full-suite runs used for median aggregation.
    bench_loops: usize,
}

struct CompareConfig {
    port: u16,
    targets: Vec<TargetSpec>,
    build_missing_binaries: bool,
    explicit_targets: bool,
}

struct TargetSpec {
    name: String,
    kind: TargetKind,
}

enum TargetKind {
    Embedded,
    LuxResp { binary: PathBuf },
    RedisResp { server: PathBuf },
}

impl TargetKind {
    fn label(&self) -> &'static str {
        match self {
            Self::Embedded => "Lux Embedded",
            Self::LuxResp { .. } => "Lux RESP",
            Self::RedisResp { .. } => "Redis RESP",
        }
    }

    fn path(&self) -> Option<&Path> {
        match self {
            Self::Embedded => None,
            Self::LuxResp { binary } => Some(binary.as_path()),
            Self::RedisResp { server } => Some(server.as_path()),
        }
    }
}

struct RatioColumn {
    header: String,
    numerator: usize,
    denominator: usize,
}

enum Mode {
    Compare { targets: Option<String> },
    Single { port: u16 },
}

struct RespConn {
    // Buffered reader over a TCP stream. We keep a tiny scratch line buffer to
    // parse RESP framing without allocating per response.
    reader: BufReader<TcpStream>,
    line_buf: Vec<u8>,
}

#[derive(Clone)]
enum BenchPlan {
    // Same encoded command each iteration.
    Static(Vec<u8>),
    // Iterates through many command variants (usually key-partitioned).
    Cycling(Vec<Vec<u8>>),
}

#[derive(Clone)]
enum QueryArgvPlan {
    Static(Vec<String>),
    Cycling(Vec<Vec<String>>),
}

struct CommandPlan {
    spec: Spec,
    // RESP seeding commands executed before timed phase.
    // Why: force each benchmark command onto a meaningful hot path.
    seed: Vec<Vec<String>>,
    // Equivalent embedded seed, precompiled once into PreparedPipeline chunks.
    // Why: avoid per-iteration argv->prepared conversion overhead in embedded.
    embedded_seed: Vec<PreparedPipeline>,
    // Timed workload plan (single static command or cycling command set).
    // Why: separates fixture creation from measured query workload.
    query: QueryArgvPlan,
}

struct SeedState {
    next: usize,
    rng: SimpleRng,
}

#[derive(Default)]
struct RespClientStats {
    completed: usize,
    batches: usize,
    write_flush: Duration,
    read: Duration,
}

struct SimpleRng {
    state: u64,
}

impl BenchPlan {
    fn command_for_client(
        &self,
        total_clients: usize,
        client_idx: usize,
        iteration: usize,
    ) -> &[u8] {
        match self {
            Self::Static(command) => command,
            Self::Cycling(commands) => {
                let n = commands.len();
                if n == 0 || total_clients <= 1 {
                    return &commands[iteration % n];
                }

                // Partition cycling plans so each client mostly operates on its own
                // slice of keys/members instead of all clients hammering the same set.
                let (start, end) = client_window(n, total_clients, client_idx);
                if start < end {
                    let span = end - start;
                    &commands[start + (iteration % span)]
                } else {
                    &commands[iteration % n]
                }
            }
        }
    }

    fn append_batch(&self, out: &mut Vec<u8>, iteration: usize, count: usize) {
        match self {
            Self::Static(command) => {
                for _ in 0..count {
                    out.extend_from_slice(command);
                }
            }
            Self::Cycling(commands) => {
                for offset in 0..count {
                    out.extend_from_slice(&commands[(iteration + offset) % commands.len()]);
                }
            }
        }
    }

    fn append_batch_for_client(
        &self,
        out: &mut Vec<u8>,
        total_clients: usize,
        client_idx: usize,
        iteration: usize,
        count: usize,
    ) {
        match self {
            Self::Static(command) => {
                for _ in 0..count {
                    out.extend_from_slice(command);
                }
            }
            Self::Cycling(_) => {
                for offset in 0..count {
                    out.extend_from_slice(self.command_for_client(
                        total_clients,
                        client_idx,
                        iteration + offset,
                    ));
                }
            }
        }
    }

    fn batch_capacity_hint(&self, pipeline: usize) -> usize {
        match self {
            Self::Static(command) => command.len().saturating_mul(pipeline),
            Self::Cycling(commands) => commands
                .iter()
                .map(Vec::len)
                .max()
                .unwrap_or(0)
                .saturating_mul(pipeline),
        }
    }
}

#[inline]
fn client_window(total_items: usize, total_clients: usize, client_idx: usize) -> (usize, usize) {
    // Deterministic contiguous partitioning, matching integer division used by
    // many sharded workload generators.
    let start = (client_idx * total_items) / total_clients;
    let end = ((client_idx + 1) * total_items) / total_clients;
    (start, end)
}

impl SimpleRng {
    fn new(seed: u64) -> Self {
        Self { state: seed.max(1) }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self
            .state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.state
    }

    fn next_value(&mut self) -> String {
        format!("value:{:016x}", self.next_u64())
    }

    fn next_coord(&mut self, min: f64, max: f64) -> f64 {
        let ratio = (self.next_u64() >> 11) as f64 / ((1u64 << 53) as f64);
        min + (max - min) * ratio
    }
}

impl RespConn {
    fn connect(port: u16) -> io::Result<Self> {
        // Low-latency defaults:
        // - TCP_NODELAY removes Nagle aggregation artifacts in small writes.
        // - Read/write timeouts prevent hangs from stalling the whole suite.
        let stream = TcpStream::connect(("127.0.0.1", port))?;
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(30)))?;
        Ok(Self {
            reader: BufReader::with_capacity(64 * 1024, stream),
            line_buf: Vec::with_capacity(128),
        })
    }

    fn command<S: AsRef<str>>(&mut self, args: &[S]) -> io::Result<()> {
        self.write_command(args)?;
        self.flush()?;
        self.read_response()
    }

    fn pipeline(&mut self, commands: &[Vec<String>]) -> io::Result<()> {
        // RESP pipeline semantics:
        // - Write N commands back-to-back.
        // - Flush once.
        // - Drain N replies in order.
        // This mirrors how pipeline users typically batch traffic.
        for command in commands {
            self.write_command(command)?;
        }
        self.flush()?;
        for _ in commands {
            self.read_response()?;
        }
        Ok(())
    }

    fn write_command<S: AsRef<str>>(&mut self, args: &[S]) -> io::Result<()> {
        let encoded = encode_command(args)?;
        self.write_encoded_command(&encoded)
    }

    fn write_encoded_command(&mut self, command: &[u8]) -> io::Result<()> {
        self.reader.get_mut().write_all(command)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.reader.get_mut().flush()
    }

    fn discard_exact(&mut self, mut len: usize) -> io::Result<()> {
        while len > 0 {
            let available = self.reader.fill_buf()?;
            if available.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed while reading RESP payload",
                ));
            }
            let consumed = available.len().min(len);
            self.reader.consume(consumed);
            len -= consumed;
        }
        Ok(())
    }

    fn read_response(&mut self) -> io::Result<()> {
        match self.read_byte()? {
            b'+' | b':' => {
                self.read_line()?;
                Ok(())
            }
            b'-' => {
                self.read_line()?;
                Err(io::Error::other(format!(
                    "server error: {}",
                    String::from_utf8_lossy(&self.line_buf)
                )))
            }
            b'$' => {
                let len = self.parse_len_line()?;
                if len >= 0 {
                    self.discard_exact(len as usize + 2)?;
                }
                Ok(())
            }
            b'*' => {
                let len = self.parse_len_line()?;
                if len >= 0 {
                    for _ in 0..len {
                        self.read_response()?;
                    }
                }
                Ok(())
            }
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected RESP prefix byte {other}"),
            )),
        }
    }

    fn read_byte(&mut self) -> io::Result<u8> {
        let available = self.reader.fill_buf()?;
        if available.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed while reading RESP prefix",
            ));
        }
        let byte = available[0];
        self.reader.consume(1);
        Ok(byte)
    }

    fn parse_len_line(&mut self) -> io::Result<i64> {
        self.read_line()?;
        parse_i64_ascii(&self.line_buf)
    }

    fn read_line(&mut self) -> io::Result<()> {
        self.line_buf.clear();
        loop {
            let available = self.reader.fill_buf()?;
            if available.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed while reading RESP line",
                ));
            }

            if let Some(pos) = available.iter().position(|&b| b == b'\n') {
                self.line_buf.extend_from_slice(&available[..pos]);
                self.reader.consume(pos + 1);
                break;
            }

            let consumed = available.len();
            self.line_buf.extend_from_slice(available);
            self.reader.consume(consumed);
        }
        if self.line_buf.ends_with(b"\r\n") {
            self.line_buf.truncate(self.line_buf.len() - 2);
        } else if self.line_buf.ends_with(b"\r") {
            self.line_buf.truncate(self.line_buf.len() - 1);
        }
        Ok(())
    }
}

fn parse_i64_ascii(bytes: &[u8]) -> io::Result<i64> {
    if bytes.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "empty integer"));
    }

    let mut idx = 0usize;
    let mut sign = 1i64;
    if bytes[0] == b'-' {
        sign = -1;
        idx = 1;
        if bytes.len() == 1 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad integer"));
        }
    }

    let mut value = 0i64;
    while idx < bytes.len() {
        let digit = bytes[idx].wrapping_sub(b'0');
        if digit > 9 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad integer"));
        }
        value = value
            .checked_mul(10)
            .and_then(|v| v.checked_add(i64::from(digit)))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "integer overflow"))?;
        idx += 1;
    }

    Ok(value * sign)
}

struct ServerProcess {
    child: Child,
    data_dir: PathBuf,
}

impl Drop for ServerProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.data_dir);
    }
}

fn specs() -> Vec<Spec> {
    // Canonical command catalog for this benchmark.
    //
    // Notes:
    // - `label` controls table display.
    // - `id` selects seed/query planning logic.
    // - `argv` is retained mostly for documentation and parity checks; actual
    //   timed plans are generated from `id` in `query_argv_plan`.
    vec![
        // Connection/protocol baseline.
        Spec {
            label: "PING",
            id: CommandId::Ping,
            argv: &["PING"],
        },
        // String command family: pure KV reads/writes and TTL modifiers.
        Spec {
            label: "SET",
            id: CommandId::Set,
            argv: &["SET", "__lux_bench_key", "__lux_bench_value"],
        },
        Spec {
            label: "GET",
            id: CommandId::Get,
            argv: &["GET", "__lux_bench_key"],
        },
        Spec {
            label: "MSET",
            id: CommandId::Mset,
            argv: &[
                "MSET",
                "__lux_bench_key1",
                "one",
                "__lux_bench_key2",
                "two",
                "__lux_bench_key3",
                "three",
            ],
        },
        Spec {
            label: "MSETNX",
            id: CommandId::Msetnx,
            argv: &[
                "MSETNX",
                "__lux_bench_key1",
                "one",
                "__lux_bench_key2",
                "two",
            ],
        },
        Spec {
            label: "MGET",
            id: CommandId::Mget,
            argv: &[
                "MGET",
                "__lux_bench_key1",
                "__lux_bench_key2",
                "__lux_bench_key3",
            ],
        },
        Spec {
            label: "GETSET",
            id: CommandId::Getset,
            argv: &["GETSET", "__lux_bench_key", "__lux_bench_new_value"],
        },
        Spec {
            label: "GETDEL",
            id: CommandId::Getdel,
            argv: &["GETDEL", "__lux_bench_key"],
        },
        Spec {
            label: "GETEX",
            id: CommandId::Getex,
            argv: &["GETEX", "__lux_bench_key", "EX", "3600"],
        },
        Spec {
            label: "SETNX (existing)",
            id: CommandId::Setnx,
            argv: &["SETNX", "__lux_bench_key", "__lux_bench_value"],
        },
        Spec {
            label: "SETEX",
            id: CommandId::Setex,
            argv: &["SETEX", "__lux_bench_key", "3600", "__lux_bench_value"],
        },
        Spec {
            label: "PSETEX",
            id: CommandId::Psetex,
            argv: &["PSETEX", "__lux_bench_key", "3600000", "__lux_bench_value"],
        },
        Spec {
            label: "APPEND",
            id: CommandId::Append,
            argv: &["APPEND", "__lux_bench_key", "x"],
        },
        Spec {
            label: "STRLEN",
            id: CommandId::Strlen,
            argv: &["STRLEN", "__lux_bench_strlen:__rand_int__"],
        },
        Spec {
            label: "INCR",
            id: CommandId::Incr,
            argv: &["INCR", "__lux_bench_counter"],
        },
        Spec {
            label: "DECR",
            id: CommandId::Decr,
            argv: &["DECR", "__lux_bench_counter"],
        },
        Spec {
            label: "INCRBY",
            id: CommandId::Incrby,
            argv: &["INCRBY", "__lux_bench_counter", "10"],
        },
        Spec {
            label: "DECRBY",
            id: CommandId::Decrby,
            argv: &["DECRBY", "__lux_bench_counter", "10"],
        },
        Spec {
            label: "EXISTS",
            id: CommandId::Exists,
            argv: &[
                "EXISTS",
                "__lux_bench_exists1",
                "__lux_bench_exists2",
                "__lux_bench_exists3",
                "__lux_bench_exists4",
            ],
        },
        Spec {
            label: "EXPIRE",
            id: CommandId::Expire,
            argv: &["EXPIRE", "__lux_bench_key", "3600"],
        },
        Spec {
            label: "TTL",
            id: CommandId::Ttl,
            argv: &["TTL", "__lux_bench_key"],
        },
        Spec {
            label: "PTTL",
            id: CommandId::Pttl,
            argv: &["PTTL", "__lux_bench_key"],
        },
        Spec {
            label: "PERSIST (ttl)",
            id: CommandId::Persist,
            argv: &["PERSIST", "__lux_bench_key"],
        },
        Spec {
            label: "TYPE",
            id: CommandId::Type,
            argv: &["TYPE", "__lux_bench_key"],
        },
        Spec {
            label: "DBSIZE",
            id: CommandId::Dbsize,
            argv: &["DBSIZE"],
        },
        Spec {
            label: "SCAN",
            id: CommandId::Scan,
            argv: &["SCAN", "0", "MATCH", "__lux_bench:string:*", "COUNT", "100"],
        },
        Spec {
            label: "KEYS",
            id: CommandId::Keys,
            argv: &["KEYS", "__lux_bench:string:*"],
        },
        Spec {
            label: "RANDOMKEY",
            id: CommandId::Randomkey,
            argv: &["RANDOMKEY"],
        },
        Spec {
            label: "RENAME",
            id: CommandId::Rename,
            argv: &["RENAME", "__lux_bench_key_src", "__lux_bench_key_dst"],
        },
        Spec {
            label: "RENAMENX",
            id: CommandId::Renamenx,
            argv: &["RENAMENX", "__lux_bench_key_src", "__lux_bench_key_dst"],
        },
        Spec {
            label: "COPY",
            id: CommandId::Copy,
            argv: &["COPY", "__lux_bench_key_src", "__lux_bench_key_dst"],
        },
        Spec {
            label: "BITCOUNT",
            id: CommandId::Bitcount,
            argv: &["BITCOUNT", "__lux_bench_key"],
        },
        Spec {
            label: "BITPOS",
            id: CommandId::Bitpos,
            argv: &["BITPOS", "__lux_bench_key", "1"],
        },
        // List command family: push/pop + positional/range reads.
        Spec {
            label: "LPUSH",
            id: CommandId::Lpush,
            argv: &["LPUSH", "__lux_bench_list", "__lux_bench_value"],
        },
        Spec {
            label: "RPUSH",
            id: CommandId::Rpush,
            argv: &["RPUSH", "__lux_bench_list", "__lux_bench_value"],
        },
        Spec {
            label: "LLEN",
            id: CommandId::Llen,
            argv: &["LLEN", "__lux_bench_list"],
        },
        Spec {
            label: "LINDEX",
            id: CommandId::Lindex,
            argv: &["LINDEX", "__lux_bench_list", "10"],
        },
        Spec {
            label: "LRANGE (10)",
            id: CommandId::Lrange,
            argv: &["LRANGE", "__lux_bench_list", "0", "9"],
        },
        Spec {
            label: "LPOP",
            id: CommandId::Lpop,
            argv: &["LPOP", "__lux_bench_list"],
        },
        Spec {
            label: "RPOP",
            id: CommandId::Rpop,
            argv: &["RPOP", "__lux_bench_list"],
        },
        // Hash command family: field updates/lookups and full/hash scans.
        Spec {
            label: "HSET",
            id: CommandId::Hset,
            argv: &["HSET", "__lux_bench_hash", "field:1", "__lux_bench_value"],
        },
        Spec {
            label: "HSETNX",
            id: CommandId::Hsetnx,
            argv: &["HSETNX", "__lux_bench_hash", "field:1", "__lux_bench_value"],
        },
        Spec {
            label: "HGET",
            id: CommandId::Hget,
            argv: &["HGET", "__lux_bench_hash", "field:1"],
        },
        Spec {
            label: "HMGET",
            id: CommandId::Hmget,
            argv: &["HMGET", "__lux_bench_hash", "field:1", "field:2", "field:3"],
        },
        Spec {
            label: "HDEL",
            id: CommandId::Hdel,
            argv: &["HDEL", "__lux_bench_hash", "field:1"],
        },
        Spec {
            label: "HKEYS",
            id: CommandId::Hkeys,
            argv: &["HKEYS", "__lux_bench_hash"],
        },
        Spec {
            label: "HVALS",
            id: CommandId::Hvals,
            argv: &["HVALS", "__lux_bench_hash"],
        },
        Spec {
            label: "HSTRLEN",
            id: CommandId::Hstrlen,
            argv: &["HSTRLEN", "__lux_bench_hash", "field:1"],
        },
        Spec {
            label: "HINCRBY",
            id: CommandId::Hincrby,
            argv: &["HINCRBY", "__lux_bench_hash", "counter", "1"],
        },
        Spec {
            label: "HEXISTS",
            id: CommandId::Hexists,
            argv: &["HEXISTS", "__lux_bench_hash", "field:1"],
        },
        Spec {
            label: "HLEN",
            id: CommandId::Hlen,
            argv: &["HLEN", "__lux_bench_hash"],
        },
        Spec {
            label: "HGETALL",
            id: CommandId::Hgetall,
            argv: &["HGETALL", "__lux_bench_hash"],
        },
        Spec {
            label: "HSCAN",
            id: CommandId::Hscan,
            argv: &["HSCAN", "__lux_bench_hash", "0", "COUNT", "100"],
        },
        // Set command family: membership/stats, random pop/read, set algebra.
        Spec {
            label: "SADD",
            id: CommandId::Sadd,
            argv: &["SADD", "__lux_bench_set", "member:1"],
        },
        Spec {
            label: "SREM",
            id: CommandId::Srem,
            argv: &["SREM", "__lux_bench_set", "member:1"],
        },
        Spec {
            label: "SISMEMBER",
            id: CommandId::Sismember,
            argv: &["SISMEMBER", "__lux_bench_set", "member:1"],
        },
        Spec {
            label: "SMISMEMBER",
            id: CommandId::Smismember,
            argv: &["SMISMEMBER", "__lux_bench_set", "member:1", "member:2", "member:3"],
        },
        Spec {
            label: "SCARD",
            id: CommandId::Scard,
            argv: &["SCARD", "__lux_bench_set"],
        },
        Spec {
            label: "SMEMBERS",
            id: CommandId::Smembers,
            argv: &["SMEMBERS", "__lux_bench_set"],
        },
        Spec {
            label: "SRANDMEMBER",
            id: CommandId::Srandmember,
            argv: &["SRANDMEMBER", "__lux_bench_set"],
        },
        Spec {
            label: "SPOP",
            id: CommandId::Spop,
            argv: &["SPOP", "__lux_bench_set"],
        },
        Spec {
            label: "SMOVE",
            id: CommandId::Smove,
            argv: &["SMOVE", "__lux_bench_set1", "__lux_bench_set2", "member:1"],
        },
        Spec {
            label: "SSCAN",
            id: CommandId::Sscan,
            argv: &["SSCAN", "__lux_bench_set", "0", "COUNT", "100"],
        },
        Spec {
            label: "SUNION",
            id: CommandId::Sunion,
            argv: &["SUNION", "__lux_bench_set1", "__lux_bench_set2"],
        },
        Spec {
            label: "SINTER",
            id: CommandId::Sinter,
            argv: &["SINTER", "__lux_bench_set1", "__lux_bench_set2"],
        },
        Spec {
            label: "SDIFF",
            id: CommandId::Sdiff,
            argv: &["SDIFF", "__lux_bench_set1", "__lux_bench_set2"],
        },
        // Sorted set command family: score updates/ranges/cardinality/pop/scan.
        Spec {
            label: "ZADD",
            id: CommandId::Zadd,
            argv: &["ZADD", "__lux_bench_zset", "1", "member:1"],
        },
        Spec {
            label: "ZSCORE",
            id: CommandId::Zscore,
            argv: &["ZSCORE", "__lux_bench_zset", "member:1"],
        },
        Spec {
            label: "ZMSCORE",
            id: CommandId::Zmscore,
            argv: &["ZMSCORE", "__lux_bench_zset", "member:1", "member:2", "member:3"],
        },
        Spec {
            label: "ZRANK",
            id: CommandId::Zrank,
            argv: &["ZRANK", "__lux_bench_zset", "member:1"],
        },
        Spec {
            label: "ZREVRANK",
            id: CommandId::Zrevrank,
            argv: &["ZREVRANK", "__lux_bench_zset", "member:1"],
        },
        Spec {
            label: "ZREM",
            id: CommandId::Zrem,
            argv: &["ZREM", "__lux_bench_zset", "member:1"],
        },
        Spec {
            label: "ZCARD",
            id: CommandId::Zcard,
            argv: &["ZCARD", "__lux_bench_zset"],
        },
        Spec {
            label: "ZCOUNT",
            id: CommandId::Zcount,
            argv: &["ZCOUNT", "__lux_bench_zset", "-inf", "+inf"],
        },
        Spec {
            label: "ZRANGE (10)",
            id: CommandId::Zrange,
            argv: &["ZRANGE", "__lux_bench_zset", "0", "9"],
        },
        Spec {
            label: "ZRANGE WITHSCORES (10)",
            id: CommandId::ZrangeScores,
            argv: &["ZRANGE", "__lux_bench_zset", "0", "9", "WITHSCORES"],
        },
        Spec {
            label: "ZINCRBY",
            id: CommandId::Zincrby,
            argv: &["ZINCRBY", "__lux_bench_zset", "1", "member:1"],
        },
        Spec {
            label: "ZPOPMIN",
            id: CommandId::Zpopmin,
            argv: &["ZPOPMIN", "__lux_bench_zset"],
        },
        Spec {
            label: "ZPOPMAX",
            id: CommandId::Zpopmax,
            argv: &["ZPOPMAX", "__lux_bench_zset"],
        },
        Spec {
            label: "ZREMRANGEBYRANK",
            id: CommandId::Zremrangebyrank,
            argv: &["ZREMRANGEBYRANK", "__lux_bench_zset", "0", "0"],
        },
        Spec {
            label: "ZSCAN",
            id: CommandId::Zscan,
            argv: &["ZSCAN", "__lux_bench_zset", "0", "COUNT", "100"],
        },
        // Geospatial command family: point updates, distance/position, geo range.
        Spec {
            label: "GEOADD (update)",
            id: CommandId::Geoadd,
            argv: &["GEOADD", "mygeo", "0", "0", "__geo_member_b__"],
        },
        Spec {
            label: "GEOPOS",
            id: CommandId::Geopos,
            argv: &["GEOPOS", "mygeo", "__geo_member_b__"],
        },
        Spec {
            label: "GEODIST",
            id: CommandId::Geodist,
            argv: &[
                "GEODIST",
                "mygeo",
                "__geo_member_a__",
                "__geo_member_b__",
                "km",
            ],
        },
        Spec {
            label: "GEOSEARCH (500km)",
            id: CommandId::GeosearchSmall,
            argv: &[
                "GEOSEARCH",
                "mygeo",
                "FROMLONLAT",
                "0",
                "0",
                "BYRADIUS",
                "500",
                "km",
                "ASC",
                "COUNT",
                "10",
            ],
        },
        Spec {
            label: "GEOSEARCH (5000km)",
            id: CommandId::GeosearchLarge,
            argv: &[
                "GEOSEARCH",
                "mygeo",
                "FROMLONLAT",
                "0",
                "0",
                "BYRADIUS",
                "5000",
                "km",
                "ASC",
                "COUNT",
                "100",
            ],
        },
        // Stream and pubsub command family.
        Spec {
            label: "XADD",
            id: CommandId::Xadd,
            argv: &["XADD", "__lux_bench_stream", "*", "field", "value"],
        },
        Spec {
            label: "XTRIM",
            id: CommandId::Xtrim,
            argv: &["XTRIM", "__lux_bench_stream", "MAXLEN", "~", "1000"],
        },
        Spec {
            label: "XDEL",
            id: CommandId::Xdel,
            argv: &["XDEL", "__lux_bench_stream", "1-0"],
        },
        Spec {
            label: "XLEN",
            id: CommandId::Xlen,
            argv: &["XLEN", "__lux_bench_stream"],
        },
        Spec {
            label: "XRANGE (10)",
            id: CommandId::Xrange,
            argv: &["XRANGE", "__lux_bench_stream", "-", "+", "COUNT", "10"],
        },
        Spec {
            label: "XREVRANGE (10)",
            id: CommandId::Xrevrange,
            argv: &["XREVRANGE", "__lux_bench_stream", "+", "-", "COUNT", "10"],
        },
        Spec {
            label: "PFADD",
            id: CommandId::Pfadd,
            argv: &["PFADD", "__lux_bench_hll", "member:1"],
        },
        Spec {
            label: "PFCOUNT",
            id: CommandId::Pfcount,
            argv: &["PFCOUNT", "__lux_bench_hll"],
        },
        Spec {
            label: "PUBLISH (no subscribers)",
            id: CommandId::Publish,
            argv: &["PUBLISH", "__lux_bench_channel", "__lux_bench_message"],
        },
    ]
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), DynError> {
    // Two modes:
    // - compare (default): spin up targets and render table
    // - single (--port): benchmark one already-running RESP endpoint
    let mode = parse_mode()?;
    let bench_cfg = bench_config()?;

    match mode {
        Mode::Single { port } => run_single(port, &bench_cfg),
        Mode::Compare { targets } => run_compare(&bench_cfg, targets.as_deref()).await,
    }
}

fn parse_mode() -> Result<Mode, DynError> {
    let mut port = None;
    let mut targets = None;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--port" => port = Some(args.next().ok_or("--port requires a value")?.parse()?),
            "--targets" => targets = Some(args.next().ok_or("--targets requires a value")?),
            "--help" | "-h" => {
                eprintln!("usage: resp_bench [--port <port>] [--targets <csv>]");
                eprintln!("  no --port: benchmark configured targets and print a comparison table");
                eprintln!(
                    "  --port: benchmark an already-running RESP server and print raw rps lines"
                );
                eprintln!("  --targets supports: embedded,lux,redis");
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other}").into()),
        }
    }

    Ok(match port {
        Some(port) => Mode::Single { port },
        None => Mode::Compare { targets },
    })
}

fn bench_config() -> Result<BenchConfig, DynError> {
    // Short-run benchmark defaults are env-driven so CI and local runs can tune
    // duration, concurrency, keyspace, and logging without code edits.
    let duration = env_f64("BENCH_DURATION_SECONDS", 0.5)?;
    if !duration.is_finite() || duration <= 0.0 {
        return Err("BENCH_DURATION_SECONDS must be a finite value greater than 0".into());
    }

    let command_limit = env::var("BENCH_COMMAND_LIMIT")
        .ok()
        .filter(|value| !value.is_empty())
        .map(|value| value.parse::<usize>())
        .transpose()?;
    if command_limit == Some(0) {
        return Err("BENCH_COMMAND_LIMIT must be greater than 0".into());
    }

    let unique = unique_suffix();
    let seed_budget = duration / 2.0;
    let run_budget = duration / 2.0;
    if !seed_budget.is_finite() || seed_budget <= 0.0 {
        return Err("seed budget must be a finite value greater than 0".into());
    }
    if !run_budget.is_finite() || run_budget <= 0.0 {
        return Err("run budget must be a finite value greater than 0".into());
    }

    // Keyspace and fixture defaults are intentionally moderate:
    // enough to avoid pathological hot-key tests, small enough to keep setup
    // times practical for short local runs.
    let keyspace = env_usize("BENCH_KEYSPACE", 1024)?.max(1);
    let fixture_items = keyspace;
    let random_seed = env_u64("BENCH_RANDOM_SEED", 0x4c55_585f_5eed)?;

    Ok(BenchConfig {
        pipeline: env_usize("BENCH_PIPELINE", 32)?.max(1),
        resp_clients: env_usize("BENCH_CLIENTS", 1)?.max(1),
        resp_outstanding_pipelines: env_usize("BENCH_RESP_OUTSTANDING_PIPELINES", 4)?.max(1),
        keyspace,
        fixture_items,
        key_prefix: format!("__lux_bench_{unique}"),
        geo_key: format!("__lux_bench_{unique}_geo"),
        random_seed,
        seed_budget: Duration::from_secs_f64(seed_budget),
        run_budget: Duration::from_secs_f64(run_budget),
        log_seeding: env::var("BENCH_LOG_SEEDING").map_or(true, |v| v != "0"),
        log_clients: env_bool("BENCH_LOG_CLIENTS", false),
        log_timing: env_bool("BENCH_LOG_TIMING", false),
        command_limit,
        bench_loops: env_usize("BENCH_LOOPS", 1)?.max(1),
    })
}

fn compare_config(targets_override: Option<&str>) -> Result<CompareConfig, DynError> {
    let root = repo_root();
    let target_env = env::var("BENCH_TARGETS").ok();
    let explicit_targets = targets_override.is_some() || target_env.is_some();
    // Default to full practical comparison set.
    let target_list = targets_override
        .or(target_env.as_deref())
        .unwrap_or("embedded,lux,redis");
    let build_missing_binaries = env_bool("BENCH_BUILD_MISSING_BINARIES", false);
    let mut targets = Vec::new();

    for raw in target_list.split(',') {
        let token = raw.trim();
        if token.is_empty() {
            continue;
        }
        targets.push(target_spec(token, build_missing_binaries, &root)?);
    }

    if targets.is_empty() {
        return Err("BENCH_TARGETS must include at least one target".into());
    }

    Ok(CompareConfig {
        port: env_u16("BENCH_PORT", 6390)?,
        targets,
        build_missing_binaries,
        explicit_targets,
    })
}

fn target_spec(
    token: &str,
    build_missing_binaries: bool,
    root: &Path,
) -> Result<TargetSpec, DynError> {
    match token.to_ascii_lowercase().as_str() {
        "embedded" | "lux-embedded" => Ok(TargetSpec {
            name: "Embedded Lux".to_string(),
            kind: TargetKind::Embedded,
        }),
        "lux" | "lux-resp" | "current" => {
            let binary = current_lux_binary(root, build_missing_binaries)?;
            Ok(TargetSpec {
                name: "Lux RESP".to_string(),
                kind: TargetKind::LuxResp { binary },
            })
        }
        "redis" | "redis-resp" => {
            let server = env_path("REDIS_SERVER", PathBuf::from("redis-server"));
            require_path_if_explicit("redis-server", &server)?;
            Ok(TargetSpec {
                name: redis_target_name(&server),
                kind: TargetKind::RedisResp { server },
            })
        }
        other => Err(format!(
            "unknown BENCH_TARGETS entry {other:?}; expected embedded,lux,redis"
        )
        .into()),
    }
}

fn current_lux_binary(root: &Path, build_missing_binaries: bool) -> Result<PathBuf, DynError> {
    let default_bin = root.join("target/release/lux");
    let mut bin = env_path("LUX_BIN", default_bin.clone());

    let real_bin = root.join("target/release/lux.real");
    if bin == default_bin && real_bin.is_file() && is_wrapper_executable(&bin) {
        bin = real_bin;
    }

    if build_missing_binaries && !bin.is_file() {
        eprintln!("Building Lux binary (release)...");
        let status = ProcessCommand::new("cargo")
            .arg("build")
            .arg("--release")
            .current_dir(root)
            .status()?;
        if !status.success() {
            return Err("cargo build --release failed".into());
        }
        bin = env_path("LUX_BIN", default_bin);
    }

    require_file("lux binary", &bin)?;
    Ok(bin)
}

fn redis_target_name(server: &Path) -> String {
    redis_version(server)
        .map(|version| format!("Redis RESP {version}"))
        .unwrap_or_else(|| "Redis RESP".to_string())
}

fn run_single(port: u16, cfg: &BenchConfig) -> Result<(), DynError> {
    // Single-target mode prints raw RPS lines for scripts that just need one
    // throughput vector.
    let specs = limited_specs(cfg);
    let mut planner = RespConn::connect(port)?;
    let plans = build_command_plans(&mut planner, cfg, &specs)?;
    let results = run_resp_suite("RESP", port, cfg, &plans)?;
    for rps in results {
        println!("{rps:.2}");
    }
    Ok(())
}

async fn run_compare(cfg: &BenchConfig, targets_override: Option<&str>) -> Result<(), DynError> {
    // Compare mode reuses one generated command plan across all targets to keep
    // workload shape identical and ratios meaningful.
    let compare = compare_config(targets_override)?;
    let specs = limited_specs(cfg);

    eprintln!("=== Lux Command Comparison ===");
    eprintln!("    runner:               native resp_bench");
    for (index, target) in compare.targets.iter().enumerate() {
        eprintln!("    target {} name:        {}", index + 1, target.name);
        eprintln!(
            "    target {} kind:        {}",
            index + 1,
            target.kind.label()
        );
        if let Some(path) = target.kind.path() {
            eprintln!("    target {} path:        {}", index + 1, path.display());
        }
    }
    eprintln!("    port:                 {}", compare.port);
    eprintln!(
        "    resp clients:         {} persistent RESP connection(s) per server",
        cfg.resp_clients
    );
    eprintln!("    pipeline:             {}", cfg.pipeline);
    eprintln!(
        "    resp outstanding:     {} pipeline batch(es) in flight per client",
        cfg.resp_outstanding_pipelines
    );
    eprintln!("    embedded read replies:yes");
    eprintln!("    keyspace:             {}", cfg.keyspace);
    eprintln!("    fixture item cap:     {}", cfg.fixture_items);
    eprintln!("    random seed:          {}", cfg.random_seed);
    eprintln!(
        "    seed budget seconds:  {:.6}",
        cfg.seed_budget.as_secs_f64()
    );
    eprintln!(
        "    run budget seconds:   {:.6}",
        cfg.run_budget.as_secs_f64()
    );
    eprintln!("    loops:                {}", cfg.bench_loops);
    eprintln!(
        "    build missing bins:   {}",
        u8::from(compare.build_missing_binaries)
    );
    eprintln!();
    // 3D accumulator:
    // [target][command] -> Vec<sample_rps_over_loops>
    let mut per_target_command_samples =
        vec![vec![Vec::<f64>::new(); specs.len()]; compare.targets.len()];
    let mut seed_rng = SimpleRng::new(cfg.random_seed ^ unique_suffix_hash());

    for loop_index in 0..cfg.bench_loops {
        let loop_seed = seed_rng.next_u64();
        let mut loop_cfg = cfg.clone();
        loop_cfg.random_seed = loop_seed;

        eprintln!(
            "Loop {}/{} seed={} ...",
            loop_index + 1,
            cfg.bench_loops,
            loop_seed
        );
        eprintln!("Generating benchmark plans...");
        let plans = build_compare_plans(&loop_cfg, &compare, &specs)?;
        eprintln!();

        // Randomize target order each loop to reduce order bias from machine
        // state drift (CPU temp, cache warmth, allocator state, etc.).
        let mut run_order: Vec<usize> = (0..compare.targets.len()).collect();
        if run_order.len() > 1 {
            let mut order_rng = SimpleRng::new(loop_seed ^ 0x9e37_79b9_7f4a_7c15);
            for i in (1..run_order.len()).rev() {
                let j = (order_rng.next_u64() as usize) % (i + 1);
                run_order.swap(i, j);
            }
            let order_names = run_order
                .iter()
                .map(|&idx| compare.targets[idx].name.as_str())
                .collect::<Vec<_>>()
                .join(" -> ");
            eprintln!("    run order:            {order_names}");
        }

        let mut loop_results = vec![Vec::new(); compare.targets.len()];
        for &target_index in &run_order {
            let target = &compare.targets[target_index];
            eprintln!("Benchmarking {}...", target.name);
            loop_results[target_index] =
                run_target(target, compare.port, target_index, &loop_cfg, &plans).await?;
        }
        eprintln!();

        for target_index in 0..compare.targets.len() {
            for command_index in 0..specs.len() {
                per_target_command_samples[target_index][command_index]
                    .push(loop_results[target_index][command_index]);
            }
        }
    }

    // Collapse per-loop samples to medians (more robust than mean vs outliers).
    let mut all_results = vec![vec![0.0; specs.len()]; compare.targets.len()];
    for target_index in 0..compare.targets.len() {
        for command_index in 0..specs.len() {
            all_results[target_index][command_index] =
                median(&mut per_target_command_samples[target_index][command_index]);
        }
    }

    let ratios = ratio_columns(&compare.targets, compare.explicit_targets);
    print!("| Command |");
    for target in &compare.targets {
        print!(" {} |", markdown_cell(&target.name));
    }
    for ratio in &ratios {
        print!(" {} |", markdown_cell(&ratio.header));
    }
    println!();

    print!("|---------|");
    for _ in &compare.targets {
        print!("-------------:|");
    }
    for _ in &ratios {
        print!("----------:|");
    }
    println!();

    for (command_index, spec) in specs.iter().enumerate() {
        print!("| {} |", spec.label);
        for result in &all_results {
            print!(" {} |", fmt_rps(result[command_index]));
        }
        for ratio in &ratios {
            print!(
                " **{}** |",
                ratio_rps(
                    all_results[ratio.numerator][command_index],
                    all_results[ratio.denominator][command_index]
                )
            );
        }
        println!();
    }

    eprintln!("Done.");
    Ok(())
}

fn unique_suffix_hash() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    nanos ^ (std::process::id() as u64)
}

fn median(values: &mut [f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mid = values.len() / 2;
    if values.len().is_multiple_of(2) {
        (values[mid - 1] + values[mid]) * 0.5
    } else {
        values[mid]
    }
}

async fn run_target(
    target: &TargetSpec,
    port: u16,
    index: usize,
    cfg: &BenchConfig,
    plans: &[CommandPlan],
) -> Result<Vec<f64>, DynError> {
    match &target.kind {
        TargetKind::Embedded => run_embedded_target(&target.name, cfg, plans).await,
        TargetKind::LuxResp { binary } => {
            let _server = start_lux_server(binary, port, &format!("lux-{index}"), cfg)?;
            run_resp_suite(&target.name, port, cfg, plans)
        }
        TargetKind::RedisResp { server } => {
            let _server = start_redis_server(server, port, &format!("redis-{index}"))?;
            run_resp_suite(&target.name, port, cfg, plans)
        }
    }
}

fn run_resp_suite(
    name: &str,
    port: u16,
    cfg: &BenchConfig,
    plans: &[CommandPlan],
) -> Result<Vec<f64>, DynError> {
    // Reuse one control connection for seed and single-client command runs.
    let mut conn = RespConn::connect(port)?;
    let mut results = Vec::with_capacity(plans.len());

    for plan in plans {
        eprintln!("  {}", plan.spec.label);
        let seed_started = Instant::now();
        seed(&mut conn, cfg, plan)
            .map_err(|err| format!("{name} seed failed for {}: {err}", plan.spec.label))?;
        let seed_elapsed = seed_started.elapsed();
        if seed_elapsed > cfg.seed_budget {
            eprintln!(
                "    [seed warning] {} exceeded seed budget: {:.6}s > {:.6}s",
                plan.spec.label,
                seed_elapsed.as_secs_f64(),
                cfg.seed_budget.as_secs_f64()
            );
        }

        // Single client path avoids thread overhead for low-concurrency runs.
        let rps = if cfg.resp_clients == 1 {
            bench(&mut conn, cfg, plan)
                .map_err(|err| format!("{name} benchmark failed for {}: {err}", plan.spec.label))?
        } else {
            bench_resp_parallel(port, cfg, plan).map_err(|err| {
                format!(
                    "{name} benchmark failed for {} with {} clients: {err}",
                    plan.spec.label, cfg.resp_clients
                )
            })?
        };
        eprintln!("    {}: {}", plan.spec.label, fmt_rps(rps));
        results.push(rps);
    }

    Ok(results)
}

fn bench_resp_parallel(port: u16, cfg: &BenchConfig, plan: &CommandPlan) -> io::Result<f64> {
    // Parallel RESP mode model:
    // - `clients` independent TCP connections
    // - each sends `pipeline` commands per batch
    // - each can keep `outstanding` batches in flight before draining replies
    //
    // The key reason this exists: realistic RESP deployments often multiplex
    // many sockets from multiple worker threads/processes.
    let clients = cfg.resp_clients.max(1);
    let encoded = bench_plan(plan)?;
    let barrier = Arc::new(Barrier::new(clients + 1));

    let mut handles = Vec::with_capacity(clients);
    for client_idx in 0..clients {
        let encoded_plan = encoded.clone();
        let barrier = Arc::clone(&barrier);
        let pipeline = cfg.pipeline;
        let outstanding = cfg.resp_outstanding_pipelines;
        let run_budget = cfg.run_budget;
        let log_timing = cfg.log_timing;
        handles.push(thread::spawn(move || -> io::Result<RespClientStats> {
            // Worker-local connection and batch buffer to avoid shared locks and
            // cross-thread false sharing.
            let mut conn = RespConn::connect(port)?;
            let mut batch_buf = Vec::with_capacity(encoded_plan.batch_capacity_hint(pipeline));
            // Ensure all worker connections are established before measurement starts.
            barrier.wait();
            let mut stats = RespClientStats::default();
            let local_started = Instant::now();
            while local_started.elapsed() < run_budget {
                let batch = pipeline;
                let rounds = outstanding;
                // "outstanding" models how many pipeline batches are queued
                // before the client drains responses.
                if log_timing {
                    let started = Instant::now();
                    for _ in 0..rounds {
                        batch_buf.clear();
                        encoded_plan.append_batch_for_client(
                            &mut batch_buf,
                            clients,
                            client_idx,
                            stats.completed,
                            batch,
                        );
                        conn.write_encoded_command(&batch_buf)?;
                        conn.flush()?;
                        stats.completed += batch;
                        stats.batches += 1;
                    }
                    stats.write_flush += started.elapsed();
                } else {
                    for _ in 0..rounds {
                        batch_buf.clear();
                        encoded_plan.append_batch_for_client(
                            &mut batch_buf,
                            clients,
                            client_idx,
                            stats.completed,
                            batch,
                        );
                        conn.write_encoded_command(&batch_buf)?;
                        conn.flush()?;
                        stats.completed += batch;
                        stats.batches += 1;
                    }
                }
                if log_timing {
                    let started = Instant::now();
                    for _ in 0..(batch * rounds) {
                        conn.read_response()?;
                    }
                    stats.read += started.elapsed();
                } else {
                    for _ in 0..(batch * rounds) {
                        conn.read_response()?;
                    }
                }
            }
            Ok(stats)
        }));
    }
    // Start measuring only after all workers are connected and waiting.
    barrier.wait();
    let started = Instant::now();

    let mut total_completed = 0usize;
    let mut per_client = Vec::with_capacity(clients);
    let mut total_batches = 0usize;
    let mut total_write_flush = Duration::ZERO;
    let mut total_read = Duration::ZERO;
    for handle in handles {
        let stats = handle
            .join()
            .map_err(|_| io::Error::other("worker thread panicked"))??;
        total_completed += stats.completed;
        total_batches += stats.batches;
        total_write_flush += stats.write_flush;
        total_read += stats.read;
        per_client.push(stats.completed);
    }

    let elapsed = started
        .elapsed()
        .as_secs_f64()
        .max(cfg.run_budget.as_secs_f64());
    if cfg.log_clients && !per_client.is_empty() {
        let min = per_client.iter().copied().min().unwrap_or(0);
        let max = per_client.iter().copied().max().unwrap_or(0);
        let avg = total_completed as f64 / per_client.len() as f64;
        eprintln!(
            "    {} clients={} total={} min={} avg={avg:.0} max={}",
            plan.spec.label, clients, total_completed, min, max
        );
        if cfg.log_timing && total_batches > 0 {
            eprintln!(
                "    {} batches={} avg_write_flush_us={:.1} avg_read_us={:.1}",
                plan.spec.label,
                total_batches,
                total_write_flush.as_secs_f64() * 1_000_000.0 / total_batches as f64,
                total_read.as_secs_f64() * 1_000_000.0 / total_batches as f64
            );
        }
    }

    Ok(if elapsed > 0.0 {
        total_completed as f64 / elapsed
    } else {
        0.0
    })
}

async fn run_embedded_target(
    name: &str,
    cfg: &BenchConfig,
    plans: &[CommandPlan],
) -> Result<Vec<f64>, DynError> {
    // Embedded mode runs an in-process Lux runtime with isolated temp storage.
    // Motivation: keep it hermetic and comparable to transient RESP servers.
    let data_dir = env::temp_dir().join(format!("lux-embedded-bench-{}", unique_suffix()));
    fs::create_dir_all(&data_dir)?;
    let config = ServerConfig {
        bind_host: "127.0.0.1".to_string(),
        port: 0,
        http_port: 0,
        max_rows: None,
        max_body: 64 * 1024 * 1024,
        max_resp_request: 64 * 1024 * 1024,
        password: String::new(),
        require_auth: false,
        allow_insecure_no_auth: true,
        restricted: false,
        shards: env_usize("BENCH_EMBEDDED_SHARDS", 128)?.max(1),
        data_dir: data_dir.to_string_lossy().to_string(),
        save_interval: Duration::ZERO,
        storage: lux::StorageConfig::default(),
        eviction: lux::EvictionConfig::default(),
        enable_resp: false,
        on_info: None,
        on_warn: None,
        on_error: None,
    };
    let handle = lux::run_with_config(config).await?;
    let client = handle.client();
    let result = run_embedded_suite(name, &client, cfg, plans).await;
    if let Err(err) = handle.shutdown_and_wait().await {
        eprintln!("    [embedded warning] shutdown failed: {err}");
    }
    let _ = fs::remove_dir_all(&data_dir);
    result
}
async fn run_embedded_suite(
    name: &str,
    client: &EmbeddedClient,
    cfg: &BenchConfig,
    plans: &[CommandPlan],
) -> Result<Vec<f64>, DynError> {
    // Mirror RESP flow: seed fixture state, then run timed query benchmark.
    let mut results = Vec::with_capacity(plans.len());

    for plan in plans {
        eprintln!("  {}", plan.spec.label);
        let seed_started = Instant::now();
        seed_embedded(client, plan)
            .await
            .map_err(|err| format!("{name} seed failed for {}: {err}", plan.spec.label))?;
        let seed_elapsed = seed_started.elapsed();
        if seed_elapsed > cfg.seed_budget {
            eprintln!(
                "    [seed warning] {} exceeded seed budget: {:.6}s > {:.6}s",
                plan.spec.label,
                seed_elapsed.as_secs_f64(),
                cfg.seed_budget.as_secs_f64()
            );
        }

        let rps = bench_embedded(client, cfg, plan)
            .await
            .map_err(|err| format!("{name} benchmark failed for {}: {err}", plan.spec.label))?;
        eprintln!("    {}: {}", plan.spec.label, fmt_rps(rps));
        results.push(rps);
    }

    Ok(results)
}

async fn seed_embedded(client: &EmbeddedClient, plan: &CommandPlan) -> Result<(), DynError> {
    for batch in &plan.embedded_seed {
        execute_embedded_batch(client, batch).await?;
    }
    Ok(())
}

fn build_compare_plans(
    cfg: &BenchConfig,
    compare: &CompareConfig,
    specs: &[Spec],
) -> Result<Vec<CommandPlan>, DynError> {
    // Plan generation strategy:
    // - Use one reference Lux RESP instance to materialize fixtures.
    // - Capture deterministic seed/query plans once.
    // - Replay the *same logical plan* across all targets.
    //
    // Why this is important:
    // - Prevents target-specific fixture drift.
    // - Keeps ratios meaningful across embedded/lux/redis.
    let reference_binary = current_lux_binary(&repo_root(), compare.build_missing_binaries)?;
    eprintln!("  reference: Lux RESP {}", reference_binary.display());
    let _server = start_lux_server(&reference_binary, compare.port, "plan", cfg)?;
    let mut conn = RespConn::connect(compare.port)?;
    build_command_plans(&mut conn, cfg, specs)
}

fn build_command_plans(
    conn: &mut RespConn,
    cfg: &BenchConfig,
    specs: &[Spec],
) -> Result<Vec<CommandPlan>, DynError> {
    specs
        .iter()
        .enumerate()
        .map(|(index, spec)| build_command_plan(conn, cfg, *spec, index))
        .collect()
}

fn build_command_plan(
    conn: &mut RespConn,
    cfg: &BenchConfig,
    spec: Spec,
    index: usize,
) -> Result<CommandPlan, DynError> {
    // Keep declared argv available for future diagnostics/linting even though
    // execution is generated from command ids.
    let _declared_argv = spec.argv;
    conn.command(&["FLUSHDB"])?;

    let mut state = SeedState {
        next: 0,
        rng: SimpleRng::new(cfg.random_seed ^ ((index as u64 + 1) * 0x9e37_79b9_7f4a_7c15)),
    };
    let mut seed = vec![argv(["FLUSHDB"])];
    let started = Instant::now();
    let fixture_limit = fixture_item_limit(cfg, spec);

    // Seed until budget or fixture cap is reached, whichever comes first.
    while started.elapsed() < cfg.seed_budget {
        let remaining = fixture_limit
            .map(|limit| limit.saturating_sub(state.next))
            .unwrap_or(usize::MAX);
        if remaining == 0 {
            break;
        }

        let batch = next_seed_commands(cfg, spec, &mut state, remaining);
        if batch.is_empty() {
            break;
        }
        conn.pipeline(&batch)?;
        seed.extend(batch);
    }

    let embedded_seed = prepare_seed_chunks(&seed, cfg.pipeline)?;
    let query = query_argv_plan(cfg, spec, state.next);
    if cfg.log_seeding {
        eprintln!(
            "  {}: fixture commands={} fixture items={} fixture cap={} query mode={} query variants={}",
            spec.label,
            seed.len(),
            state.next,
            fixture_limit.map_or_else(|| "none".to_string(), |limit| limit.to_string()),
            query_plan_mode(&query),
            query_variant_count(&query)
        );
    }

    Ok(CommandPlan {
        spec,
        seed,
        embedded_seed,
        query,
    })
}

fn prepare_seed_chunks(
    seed: &[Vec<String>],
    pipeline: usize,
) -> Result<Vec<PreparedPipeline>, DynError> {
    // Compile string argv chunks to prepared embedded pipelines so embedded
    // seeding cost mirrors RESP seeding behavior without repeated parsing.
    seed.chunks(pipeline)
        .map(|chunk| {
            let mut batch = PreparedPipeline::with_capacity(chunk.len());
            for argv in chunk {
                batch.extend(&prepared_from_strings(argv.clone())?);
            }
            Ok(batch)
        })
        .collect()
}

fn next_seed_commands(
    cfg: &BenchConfig,
    spec: Spec,
    state: &mut SeedState,
    remaining: usize,
) -> Vec<Vec<String>> {
    // Command-aware fixtures keep timed queries on realistic hot paths instead
    // of mostly nil/not-found behavior.
    if remaining == 0 {
        return Vec::new();
    }

    match spec.id {
        CommandId::Set
        | CommandId::Get
        | CommandId::Mset
        | CommandId::Msetnx
        | CommandId::Mget
        | CommandId::Getset
        | CommandId::Getdel
        | CommandId::Getex
        | CommandId::Setnx
        | CommandId::Setex
        | CommandId::Psetex
        | CommandId::Append
        | CommandId::Strlen
        | CommandId::Exists
        | CommandId::Expire
        | CommandId::Type
        | CommandId::Dbsize
        | CommandId::Scan
        | CommandId::Keys
        | CommandId::Randomkey
        | CommandId::Rename
        | CommandId::Renamenx
        | CommandId::Copy
        | CommandId::Bitcount
        | CommandId::Bitpos => vec![seed_string_chunk(cfg, state, 128.min(remaining))],
        CommandId::Ttl | CommandId::Pttl | CommandId::Persist => {
            let index = state.next;
            state.next += 1;
            vec![vec![
                "SETEX".to_string(),
                string_key(cfg, index),
                "3600".to_string(),
                state.rng.next_value(),
            ]]
        }
        CommandId::Incr | CommandId::Decr | CommandId::Incrby | CommandId::Decrby => {
            vec![seed_counter_chunk(cfg, state, 128.min(remaining))]
        }
        CommandId::Llen | CommandId::Lpop | CommandId::Rpop => {
            seed_list_keyspace_chunk(cfg, state, 128.min(remaining))
        }
        CommandId::Lindex | CommandId::Lrange => {
            seed_list_keyspace_multi_chunk(cfg, state, 64.min(remaining), 16)
        }
        CommandId::Lpush | CommandId::Rpush => {
            seed_list_keyspace_chunk(cfg, state, 128.min(remaining))
        }
        CommandId::Hset | CommandId::Hsetnx => {
            seed_hash_keyspace_chunk(cfg, state, 128.min(remaining), false)
        }
        CommandId::Hget
        | CommandId::Hmget
        | CommandId::Hdel
        | CommandId::Hkeys
        | CommandId::Hvals
        | CommandId::Hstrlen
        | CommandId::Hexists
        | CommandId::Hlen
        | CommandId::Hgetall
        | CommandId::Hscan => seed_hash_keyspace_chunk(cfg, state, 128.min(remaining), false),
        CommandId::Hincrby => seed_hash_keyspace_chunk(cfg, state, 128.min(remaining), true),
        CommandId::Sadd | CommandId::Srem => seed_set_keyspace_chunk(cfg, state, 512.min(remaining)),
        CommandId::Sismember
        | CommandId::Smismember
        | CommandId::Scard
        | CommandId::Smembers
        | CommandId::Srandmember
        | CommandId::Spop
        | CommandId::Smove
        | CommandId::Sscan => seed_set_keyspace_chunk(cfg, state, 512.min(remaining)),
        CommandId::Sunion | CommandId::Sinter | CommandId::Sdiff => {
            seed_set_pair_keyspace_chunk(cfg, state, 512.min(remaining))
        }
        CommandId::Zadd | CommandId::Zrem => seed_zset_keyspace_chunk(cfg, state, 256.min(remaining)),
        CommandId::Zscore
        | CommandId::Zmscore
        | CommandId::Zrank
        | CommandId::Zrevrank
        | CommandId::Zcard
        | CommandId::Zcount
        | CommandId::Zrange
        | CommandId::ZrangeScores
        | CommandId::Zincrby
        | CommandId::Zpopmin
        | CommandId::Zpopmax
        | CommandId::Zremrangebyrank
        | CommandId::Zscan => seed_zset_keyspace_chunk(cfg, state, 256.min(remaining)),
        CommandId::Geoadd
        | CommandId::Geopos
        | CommandId::Geodist
        | CommandId::GeosearchSmall
        | CommandId::GeosearchLarge => vec![seed_geo_chunk(cfg, state, 128.min(remaining))],
        CommandId::Xadd
        | CommandId::Xtrim
        | CommandId::Xdel
        | CommandId::Xlen
        | CommandId::Xrange
        | CommandId::Xrevrange => {
            seed_stream_keyspace_chunk(cfg, state, 128.min(remaining))
        }
        CommandId::Pfadd | CommandId::Pfcount => {
            seed_set_keyspace_chunk(cfg, state, 512.min(remaining))
        }
        _ => Vec::new(),
    }
}

fn fixture_item_limit(cfg: &BenchConfig, spec: Spec) -> Option<usize> {
    // Per-command fixture caps tune setup effort:
    // - Some commands need grouped keys (MGET/HMGET/EXISTS).
    // - Others are meaningful with fixed-size keyspaces.
    match spec.id {
        CommandId::Ping | CommandId::Publish => None,
        CommandId::Mset
        | CommandId::Msetnx
        | CommandId::Mget
        | CommandId::Hmget
        | CommandId::Smismember
        | CommandId::Zmscore => {
            Some(cfg.fixture_items.saturating_mul(3))
        }
        CommandId::Exists => Some(cfg.fixture_items.saturating_mul(4)),
        _ => Some(cfg.fixture_items),
    }
}

fn seed_string_chunk(cfg: &BenchConfig, state: &mut SeedState, count: usize) -> Vec<String> {
    // Batch with MSET for high fixture throughput; this keeps setup overhead
    // from dominating short benchmark windows.
    let start = state.next;
    state.next += count;
    let mut args = Vec::with_capacity(count * 2 + 1);
    args.push("MSET".to_string());
    for index in start..start + count {
        args.push(string_key(cfg, index));
        args.push(state.rng.next_value());
    }
    args
}

fn seed_counter_chunk(cfg: &BenchConfig, state: &mut SeedState, count: usize) -> Vec<String> {
    // Counters are initialized to 0 so INCR/DECR families benchmark the numeric
    // update path rather than implicit key creation behavior.
    let start = state.next;
    state.next += count;
    let mut args = Vec::with_capacity(count * 2 + 1);
    args.push("MSET".to_string());
    for index in start..start + count {
        args.push(counter_key(cfg, index));
        args.push("0".to_string());
    }
    args
}

fn seed_list_keyspace_chunk(
    cfg: &BenchConfig,
    state: &mut SeedState,
    count: usize,
) -> Vec<Vec<String>> {
    // One RPUSH per key creates independent list keys used by list ops.
    let start = state.next;
    state.next += count;
    (start..start + count)
        .map(|index| {
            vec![
                "RPUSH".to_string(),
                list_write_key(cfg, index),
                state.rng.next_value(),
            ]
        })
        .collect()
}

fn seed_list_keyspace_multi_chunk(
    cfg: &BenchConfig,
    state: &mut SeedState,
    count: usize,
    values_per_key: usize,
) -> Vec<Vec<String>> {
    // Multi-value list setup for LINDEX/LRANGE so those reads are meaningful
    // and do not degenerate into out-of-range or tiny-list behavior.
    let start = state.next;
    state.next += count;
    (start..start + count)
        .map(|index| {
            let mut args = Vec::with_capacity(values_per_key + 2);
            args.push("RPUSH".to_string());
            args.push(list_write_key(cfg, index));
            for offset in 0..values_per_key {
                args.push(format!("value:{index}:{offset}"));
            }
            args
        })
        .collect()
}

fn seed_hash_keyspace_chunk(
    cfg: &BenchConfig,
    state: &mut SeedState,
    count: usize,
    numeric: bool,
) -> Vec<Vec<String>> {
    // Two modes:
    // - numeric=true: creates counter fields for HINCRBY.
    // - numeric=false: creates several text fields for hash lookups/scans.
    let start = state.next;
    state.next += count;
    (start..start + count)
        .map(|index| {
            let mut args = Vec::with_capacity(8);
            args.push("HSET".to_string());
            args.push(hash_partition_key(cfg, index));
            if numeric {
                args.push(hash_counter_field(0));
                args.push("0".to_string());
            } else {
                for field in 0..3 {
                    args.push(hash_field(field));
                    args.push(format!("value:{index}:{field}"));
                }
            }
            args
        })
        .collect()
}

fn seed_set_keyspace_chunk(
    cfg: &BenchConfig,
    state: &mut SeedState,
    count: usize,
) -> Vec<Vec<String>> {
    // One member per set key keeps fixture cardinality stable and predictable.
    let start = state.next;
    state.next += count;
    (start..start + count)
        .map(|index| {
            vec![
                "SADD".to_string(),
                set_partition_key(cfg, index),
                set_member(index),
            ]
        })
        .collect()
}

fn seed_set_pair_keyspace_chunk(
    cfg: &BenchConfig,
    state: &mut SeedState,
    count: usize,
) -> Vec<Vec<String>> {
    // Pair seeding feeds binary set algebra commands (SUNION/SINTER/SDIFF).
    let start = state.next;
    state.next += count;
    let mut commands = Vec::with_capacity(count * 2);
    for index in start..start + count {
        commands.push(vec![
            "SADD".to_string(),
            set1_partition_key(cfg, index),
            set_member(index),
        ]);
        commands.push(vec![
            "SADD".to_string(),
            set2_partition_key(cfg, index),
            set_member(index),
        ]);
    }
    commands
}

fn seed_zset_keyspace_chunk(
    cfg: &BenchConfig,
    state: &mut SeedState,
    count: usize,
) -> Vec<Vec<String>> {
    // Score == index gives deterministic ordering and stable range behavior.
    let start = state.next;
    state.next += count;
    (start..start + count)
        .map(|index| {
            vec![
                "ZADD".to_string(),
                zset_partition_key(cfg, index),
                index.to_string(),
                zset_member(index),
            ]
        })
        .collect()
}

fn seed_geo_chunk(cfg: &BenchConfig, state: &mut SeedState, count: usize) -> Vec<String> {
    // Uses valid lon/lat ranges and deterministic RNG to build realistic geo
    // fixtures while remaining reproducible under a fixed seed.
    let start = state.next;
    state.next += count;
    let mut args = Vec::with_capacity(count * 3 + 2);
    args.push("GEOADD".to_string());
    args.push(cfg.geo_key.clone());
    for index in start..start + count {
        args.push(format!("{:.6}", state.rng.next_coord(-179.0, 179.0)));
        args.push(format!("{:.6}", state.rng.next_coord(-84.0, 84.0)));
        args.push(geo_member(index));
    }
    args
}

fn seed_stream_keyspace_chunk(
    cfg: &BenchConfig,
    state: &mut SeedState,
    count: usize,
) -> Vec<Vec<String>> {
    // Explicit IDs avoid server-side timestamp dependence during fixture setup.
    let start = state.next;
    state.next += count;
    (start..start + count)
        .map(|index| {
            vec![
                "XADD".to_string(),
                stream_partition_key(cfg, index),
                format!("{}-0", index + 1),
                "field".to_string(),
                format!("value:{index}"),
            ]
        })
        .collect()
}

fn argv<const N: usize>(args: [&str; N]) -> Vec<String> {
    // Tiny convenience helper used for static plans to keep call sites compact.
    args.into_iter().map(str::to_string).collect()
}

#[derive(Clone)]
enum EmbeddedBenchPlan {
    Static(PreparedPipeline),
    Cycling(Vec<PreparedPipeline>),
}

async fn bench_embedded(
    client: &EmbeddedClient,
    cfg: &BenchConfig,
    plan: &CommandPlan,
) -> Result<f64, DynError> {
    // Convert query argv plan into prepared pipelines once per command.
    let embedded_plan = embedded_bench_plan(plan)?;
    let clients = cfg.resp_clients.max(1);
    if clients > 1 {
        return bench_embedded_parallel(
            client.clone(),
            cfg.pipeline,
            cfg.run_budget,
            embedded_plan,
            clients,
        )
        .await;
    }
    let started = Instant::now();
    let deadline = started + cfg.run_budget;
    let completed =
        run_embedded_plan_until_deadline(client, cfg.pipeline, deadline, &embedded_plan).await?;

    let elapsed = started.elapsed().as_secs_f64();
    Ok(if elapsed > 0.0 {
        completed as f64 / elapsed
    } else {
        0.0
    })
}

async fn bench_embedded_parallel(
    client: EmbeddedClient,
    pipeline: usize,
    run_budget: Duration,
    embedded_plan: EmbeddedBenchPlan,
    clients: usize,
) -> Result<f64, DynError> {
    // Use a shared deadline so workers stop against the same wall-clock budget.
    // This avoids bias where late-starting workers run less work.
    let barrier = Arc::new(TokioBarrier::new(clients + 1));
    let deadline = Instant::now() + run_budget;
    let mut handles = Vec::with_capacity(clients);
    for client_idx in 0..clients {
        let client = client.clone();
        let barrier = barrier.clone();
        let plan = embedded_plan.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let worker_plan = match plan {
                EmbeddedBenchPlan::Static(command) => EmbeddedBenchPlan::Static(command),
                EmbeddedBenchPlan::Cycling(commands) => EmbeddedBenchPlan::Cycling(
                    per_client_cycling_window(&commands, clients, client_idx),
                ),
            };
            let completed =
                run_embedded_plan_until_deadline(&client, pipeline, deadline, &worker_plan).await?;
            Ok::<usize, DynError>(completed)
        }));
    }
    let started = Instant::now();
    barrier.wait().await;
    let mut total_completed = 0usize;
    for handle in handles {
        let completed = handle
            .await
            .map_err(|err| -> DynError { Box::new(err) })??;
        total_completed += completed;
    }
    let elapsed = started.elapsed().as_secs_f64();
    Ok(if elapsed > 0.0 {
        total_completed as f64 / elapsed
    } else {
        0.0
    })
}

fn per_client_cycling_window(
    commands: &[PreparedPipeline],
    total_clients: usize,
    client_idx: usize,
) -> Vec<PreparedPipeline> {
    // Embedded parallel mode mirrors RESP per-client partitioning so different
    // workers mostly touch disjoint slices of the cycling workload.
    let n = commands.len();
    if n == 0 || total_clients <= 1 {
        return commands.to_vec();
    }
    let (start, end) = client_window(n, total_clients, client_idx);
    if start < end {
        commands[start..end].to_vec()
    } else {
        commands.to_vec()
    }
}

async fn run_embedded_plan_until_deadline(
    client: &EmbeddedClient,
    pipeline: usize,
    deadline: Instant,
    plan: &EmbeddedBenchPlan,
) -> Result<usize, DynError> {
    let mut completed = 0usize;
    match plan {
        EmbeddedBenchPlan::Static(command) => {
            // Reuse one pre-expanded batch for static workloads to avoid
            // per-iteration pipeline construction overhead.
            let full_batch = repeat_prepared(command, pipeline);
            while Instant::now() < deadline {
                execute_embedded_batch(client, &full_batch).await?;
                completed += pipeline;
            }
        }
        EmbeddedBenchPlan::Cycling(commands) => {
            while Instant::now() < deadline {
                let mut batch = PreparedPipeline::with_capacity(pipeline);
                for offset in 0..pipeline {
                    batch.extend(&commands[(completed + offset) % commands.len()]);
                }
                execute_embedded_batch(client, &batch).await?;
                completed += pipeline;
            }
        }
    }
    Ok(completed)
}

fn embedded_bench_plan(plan: &CommandPlan) -> Result<EmbeddedBenchPlan, DynError> {
    // Embedded execution uses prepared pipelines to reduce client-side overhead
    // and focus measurement on store/runtime behavior.
    match &plan.query {
        QueryArgvPlan::Static(argv) => {
            prepared_from_strings(argv.clone()).map(EmbeddedBenchPlan::Static)
        }
        QueryArgvPlan::Cycling(commands) => commands
            .iter()
            .cloned()
            .map(prepared_from_strings)
            .collect::<Result<Vec<_>, _>>()
            .map(EmbeddedBenchPlan::Cycling),
    }
}

fn prepared_from_strings(args: Vec<String>) -> Result<PreparedPipeline, DynError> {
    // Convert string argv once into encoded/prepared form for fast reuse.
    let refs = args.iter().map(String::as_bytes).collect::<Vec<_>>();
    Ok(PreparedPipeline::from_argv(refs)?)
}

fn repeat_prepared(command: &PreparedPipeline, count: usize) -> PreparedPipeline {
    // Static workloads can reuse one pre-expanded pipeline buffer forever.
    let mut batch = PreparedPipeline::with_capacity(command.len() * count);
    for _ in 0..count {
        batch.extend(command);
    }
    batch
}

async fn execute_embedded_batch(
    client: &EmbeddedClient,
    batch: &PreparedPipeline,
) -> Result<(), DynError> {
    // Validate full reply cardinality to ensure we never "benchmark" partial
    // execution due to silent pipeline truncation or early return.
    let values = client.execute_prepared_pipeline(batch).await?;
    if values.len() != batch.len() {
        return Err(format!(
            "embedded pipeline reply count mismatch: expected {}, got {}",
            batch.len(),
            values.len()
        )
        .into());
    }
    Ok(())
}

fn start_lux_server(
    binary: &Path,
    port: u16,
    label: &str,
    cfg: &BenchConfig,
) -> Result<ServerProcess, DynError> {
    // Minimal Lux benchmark config: memory-only, HTTP disabled, no periodic save.
    let data_dir = env::temp_dir().join(format!("lux-resp-bench-{label}-{}", unique_suffix()));
    fs::create_dir_all(&data_dir)?;
    let runtime_threads = env::var("BENCH_LUX_RUNTIME_THREADS")
        .unwrap_or_else(|_| cfg.resp_clients.max(1).to_string());

    let mut child = ProcessCommand::new(binary)
        .env("LUX_BIND_HOST", "127.0.0.1")
        .env("LUX_PORT", port.to_string())
        .env("LUX_RUNTIME_THREADS", runtime_threads)
        .env("LUX_HTTP_PORT", "0")
        .env("LUX_SAVE_INTERVAL", "0")
        .env("LUX_STORAGE_MODE", "memory")
        .env("LUX_DATA_DIR", &data_dir)
        .env("LUX_PASSWORD", "")
        .env("LUX_RESTRICTED", "0")
        .env("LUX_ENABLE_RESP", "1")
        .env(
            "LUX_RESP_BLOCK_IN_PLACE",
            env::var("BENCH_LUX_RESP_BLOCK_IN_PLACE").unwrap_or_else(|_| "1".to_string()),
        )
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|err| format!("failed to start {}: {err}", binary.display()))?;

    wait_for_server(&mut child, port, label)?;
    Ok(ServerProcess { child, data_dir })
}

fn start_redis_server(binary: &Path, port: u16, label: &str) -> Result<ServerProcess, DynError> {
    // Disposable Redis instance with persistence disabled for throughput tests.
    let data_dir = env::temp_dir().join(format!("redis-resp-bench-{label}-{}", unique_suffix()));
    fs::create_dir_all(&data_dir)?;

    let mut child = ProcessCommand::new(binary)
        .arg("--bind")
        .arg("127.0.0.1")
        .arg("--port")
        .arg(port.to_string())
        .arg("--save")
        .arg("")
        .arg("--appendonly")
        .arg("no")
        .arg("--daemonize")
        .arg("no")
        .arg("--loglevel")
        .arg("warning")
        .arg("--dir")
        .arg(&data_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|err| format!("failed to start {}: {err}", binary.display()))?;

    wait_for_server(&mut child, port, label)?;
    Ok(ServerProcess { child, data_dir })
}

fn wait_for_server(child: &mut Child, port: u16, label: &str) -> Result<(), DynError> {
    // Poll startup with short sleeps to keep bring-up responsive while still
    // handling processes that take a moment to bind sockets.
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(10) {
        if let Some(status) = child.try_wait()? {
            return Err(
                format!("server {label} exited before accepting connections: {status}").into(),
            );
        }
        if let Ok(mut conn) = RespConn::connect(port) {
            if conn.command(&["PING"]).is_ok() {
                return Ok(());
            }
        }
        thread::sleep(Duration::from_millis(25));
    }
    Err(format!("server {label} failed to start on port {port}").into())
}

fn limited_specs(cfg: &BenchConfig) -> Vec<Spec> {
    // Debug aid: BENCH_COMMAND_LIMIT lets us iterate quickly on a subset.
    let mut specs = specs();
    if let Some(limit) = cfg.command_limit {
        specs.truncate(limit.min(specs.len()));
    }
    specs
}

fn env_path(name: &str, default: PathBuf) -> PathBuf {
    env::var_os(name).map_or(default, PathBuf::from)
}

fn env_usize(name: &str, default: usize) -> Result<usize, DynError> {
    Ok(env::var(name).map_or(Ok(default), |v| v.parse())?)
}

fn env_u16(name: &str, default: u16) -> Result<u16, DynError> {
    Ok(env::var(name).map_or(Ok(default), |v| v.parse())?)
}

fn env_u64(name: &str, default: u64) -> Result<u64, DynError> {
    Ok(env::var(name).map_or(Ok(default), |v| v.parse())?)
}

fn env_f64(name: &str, default: f64) -> Result<f64, DynError> {
    Ok(env::var(name).map_or(Ok(default), |v| v.parse())?)
}

fn env_bool(name: &str, default: bool) -> bool {
    // Accept a few human-friendly truthy forms for CLI/env ergonomics.
    env::var(name).map_or(default, |v| {
        let v = v.to_ascii_lowercase();
        v == "1" || v == "true" || v == "yes"
    })
}

fn require_file(label: &str, path: &Path) -> Result<(), DynError> {
    if path.is_file() {
        Ok(())
    } else {
        Err(format!("{label} missing/non-file: {}", path.display()).into())
    }
}

fn require_path_if_explicit(label: &str, path: &Path) -> Result<(), DynError> {
    if path.is_absolute() || path.components().count() > 1 {
        require_file(label, path)?;
    }
    Ok(())
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn redis_version(server: &Path) -> Option<String> {
    let output = ProcessCommand::new(server).arg("--version").output().ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    text.split_whitespace()
        .find_map(|part| part.strip_prefix("v=").map(str::to_string))
}

fn is_wrapper_executable(path: &Path) -> bool {
    fs::read(path).is_ok_and(|bytes| {
        let head = &bytes[..bytes.len().min(512)];
        let text = String::from_utf8_lossy(head);
        text.contains("wrapper") || text.contains(".real")
    })
}

fn unique_suffix() -> String {
    // Temporary data dir suffix: timestamp + pid keeps collisions unlikely.
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{}_{}", nanos, std::process::id())
}

fn fmt_rps(n: f64) -> String {
    // Human-readable compact formatting for Markdown tables.
    if n >= 1_000_000.0 {
        format!("{:.2}M", n / 1_000_000.0)
    } else if n >= 1_000.0 {
        format!("{:.0}K", n / 1_000.0)
    } else {
        format!("{n:.0}")
    }
}

fn ratio_rps(lhs: f64, rhs: f64) -> String {
    // Ratio reported as "X.YYx"; N/A when denominator is zero.
    if rhs > 0.0 {
        format!("{:.2}x", lhs / rhs)
    } else {
        "N/A".to_string()
    }
}

fn markdown_cell(text: &str) -> String {
    // Escape pipe characters so names cannot break table rendering.
    text.replace('|', "\\|")
}

fn ratio_columns(targets: &[TargetSpec], explicit_targets: bool) -> Vec<RatioColumn> {
    // Default two-target mode keeps historical B/A ratio output.
    if targets.len() < 2 {
        return Vec::new();
    }
    if targets.len() == 2 && !explicit_targets {
        return vec![RatioColumn {
            header: "B/A".to_string(),
            numerator: 1,
            denominator: 0,
        }];
    }

    // For explicit target lists, emit adjacent pair ratios to keep the table
    // width manageable while preserving ordered comparisons.
    (0..targets.len() - 1)
        .map(|index| RatioColumn {
            header: format!("{}/{}", targets[index].name, targets[index + 1].name),
            numerator: index,
            denominator: index + 1,
        })
        .collect()
}

fn query_argv_plan(cfg: &BenchConfig, spec: Spec, seed_items: usize) -> QueryArgvPlan {
    // Deterministic query cycles make runs reproducible across targets and reruns.
    //
    // Core idea:
    // - Build a vector of command variants parameterized by index.
    // - Use key/member partition helpers so traffic is distributed across a
    //   bounded keyspace.
    // - Keep arguments close to real command shapes used in production.
    let count = query_cycle_count(cfg, seed_items);
    match spec.id {
        // ---- Connection/protocol baseline ----
        CommandId::Ping => QueryArgvPlan::Static(argv(["PING"])),
        // ---- Strings / counters / TTLs ----
        CommandId::Set => QueryArgvPlan::Cycling(
            (0..count)
                .map(|index| {
                    vec![
                        "SET".to_string(),
                        string_key(cfg, index),
                        format!("query-value:{index}"),
                    ]
                })
                .collect(),
        ),
        CommandId::Get => cycle_one_arg("GET", count, |index| string_key(cfg, index)),
        CommandId::Mset => QueryArgvPlan::Cycling(
            (0..group_cycle_count(cfg, seed_items, 3))
                .map(|index| {
                    let base = index * 3;
                    vec![
                        "MSET".to_string(),
                        string_key(cfg, base),
                        "one".to_string(),
                        string_key(cfg, base + 1),
                        "two".to_string(),
                        string_key(cfg, base + 2),
                        "three".to_string(),
                    ]
                })
                .collect(),
        ),
        CommandId::Msetnx => QueryArgvPlan::Cycling(
            (0..group_cycle_count(cfg, seed_items, 2))
                .map(|index| {
                    let base = index * 2;
                    vec![
                        "MSETNX".to_string(),
                        string_key(cfg, base),
                        "one".to_string(),
                        string_key(cfg, base + 1),
                        "two".to_string(),
                    ]
                })
                .collect(),
        ),
        CommandId::Mget => QueryArgvPlan::Cycling(
            (0..group_cycle_count(cfg, seed_items, 3))
                .map(|index| {
                    let base = index * 3;
                    vec![
                        "MGET".to_string(),
                        string_key(cfg, base),
                        string_key(cfg, base + 1),
                        string_key(cfg, base + 2),
                    ]
                })
                .collect(),
        ),
        CommandId::Getset => QueryArgvPlan::Cycling(
            (0..count)
                .map(|index| {
                    vec![
                        "GETSET".to_string(),
                        string_key(cfg, index),
                        format!("updated:{index}"),
                    ]
                })
                .collect(),
        ),
        CommandId::Getdel => cycle_one_arg("GETDEL", count, |index| string_key(cfg, index)),
        CommandId::Getex => QueryArgvPlan::Cycling(
            (0..count)
                .map(|index| {
                    vec![
                        "GETEX".to_string(),
                        string_key(cfg, index),
                        "EX".to_string(),
                        "3600".to_string(),
                    ]
                })
                .collect(),
        ),
        CommandId::Setnx => QueryArgvPlan::Cycling(
            (0..count)
                .map(|index| {
                    vec![
                        "SETNX".to_string(),
                        string_key(cfg, index),
                        "already-exists".to_string(),
                    ]
                })
                .collect(),
        ),
        CommandId::Setex => QueryArgvPlan::Cycling(
            (0..count)
                .map(|index| {
                    vec![
                        "SETEX".to_string(),
                        string_key(cfg, index),
                        "3600".to_string(),
                        format!("query-value:{index}"),
                    ]
                })
                .collect(),
        ),
        CommandId::Psetex => QueryArgvPlan::Cycling(
            (0..count)
                .map(|index| {
                    vec![
                        "PSETEX".to_string(),
                        string_key(cfg, index),
                        "3600000".to_string(),
                        format!("query-value:{index}"),
                    ]
                })
                .collect(),
        ),
        CommandId::Append => QueryArgvPlan::Cycling(
            (0..count)
                .map(|index| {
                    vec![
                        "APPEND".to_string(),
                        string_key(cfg, index),
                        "x".to_string(),
                    ]
                })
                .collect(),
        ),
        CommandId::Strlen => cycle_one_arg("STRLEN", count, |index| string_key(cfg, index)),
        CommandId::Incr => cycle_one_arg("INCR", count, |index| counter_key(cfg, index)),
        CommandId::Decr => cycle_one_arg("DECR", count, |index| counter_key(cfg, index)),
        CommandId::Incrby => cycle_two_args(
            "INCRBY",
            count,
            |index| counter_key(cfg, index),
            |_| "10".to_string(),
        ),
        CommandId::Decrby => cycle_two_args(
            "DECRBY",
            count,
            |index| counter_key(cfg, index),
            |_| "10".to_string(),
        ),
        CommandId::Exists => QueryArgvPlan::Cycling(
            (0..group_cycle_count(cfg, seed_items, 4))
                .map(|index| {
                    let base = index * 4;
                    vec![
                        "EXISTS".to_string(),
                        string_key(cfg, base),
                        string_key(cfg, base + 1),
                        string_key(cfg, base + 2),
                        string_key(cfg, base + 3),
                    ]
                })
                .collect(),
        ),
        CommandId::Expire => cycle_two_args(
            "EXPIRE",
            count,
            |index| string_key(cfg, index),
            |_| "3600".to_string(),
        ),
        CommandId::Ttl => cycle_one_arg("TTL", count, |index| string_key(cfg, index)),
        CommandId::Pttl => cycle_one_arg("PTTL", count, |index| string_key(cfg, index)),
        CommandId::Persist => cycle_one_arg("PERSIST", count, |index| string_key(cfg, index)),
        CommandId::Type => cycle_one_arg("TYPE", count, |index| string_key(cfg, index)),
        CommandId::Dbsize => QueryArgvPlan::Static(argv(["DBSIZE"])),
        // SCAN is held static (cursor=0 + bounded COUNT) so each run measures
        // a consistent single-scan shape instead of an unbounded cursor walk.
        CommandId::Scan => QueryArgvPlan::Static(vec![
            "SCAN".to_string(),
            "0".to_string(),
            "MATCH".to_string(),
            format!("{}:string:*", cfg.key_prefix),
            "COUNT".to_string(),
            "100".to_string(),
        ]),
        CommandId::Keys => QueryArgvPlan::Static(vec![
            "KEYS".to_string(),
            format!("{}:string:*", cfg.key_prefix),
        ]),
        CommandId::Randomkey => QueryArgvPlan::Static(argv(["RANDOMKEY"])),
        CommandId::Rename => QueryArgvPlan::Cycling(
            (0..count)
                .flat_map(|index| {
                    let src = string_key(cfg, index);
                    let dst = format!("{src}:renamed");
                    [
                        vec!["RENAME".to_string(), src.clone(), dst.clone()],
                        vec!["RENAME".to_string(), dst, src],
                    ]
                })
                .collect(),
        ),
        CommandId::Renamenx => QueryArgvPlan::Cycling(
            (0..count)
                .flat_map(|index| {
                    let src = string_key(cfg, index);
                    let dst = format!("{src}:renamenx");
                    [
                        vec!["RENAMENX".to_string(), src.clone(), dst.clone()],
                        vec!["RENAMENX".to_string(), dst, src],
                    ]
                })
                .collect(),
        ),
        CommandId::Copy => QueryArgvPlan::Cycling(
            (0..count)
                .map(|index| {
                    let src = string_key(cfg, index);
                    let dst = format!("{src}:copy");
                    vec!["COPY".to_string(), src, dst]
                })
                .collect(),
        ),
        CommandId::Bitcount => cycle_one_arg("BITCOUNT", count, |index| string_key(cfg, index)),
        CommandId::Bitpos => QueryArgvPlan::Cycling(
            (0..count)
                .map(|index| vec!["BITPOS".to_string(), string_key(cfg, index), "1".to_string()])
                .collect(),
        ),
        // ---- Lists ----
        CommandId::Lpush => list_write_plan(cfg, "LPUSH", count),
        CommandId::Rpush => list_write_plan(cfg, "RPUSH", count),
        CommandId::Llen => cycle_one_arg("LLEN", count, |index| list_write_key(cfg, index)),
        CommandId::Lindex => QueryArgvPlan::Cycling(
            (0..count)
                .map(|index| {
                    vec![
                        "LINDEX".to_string(),
                        list_write_key(cfg, index),
                        "10".to_string(),
                    ]
                })
                .collect(),
        ),
        CommandId::Lrange => QueryArgvPlan::Cycling(
            (0..count)
                .map(|index| {
                    vec![
                        "LRANGE".to_string(),
                        list_write_key(cfg, index),
                        "0".to_string(),
                        "9".to_string(),
                    ]
                })
                .collect(),
        ),
        CommandId::Lpop => cycle_one_arg("LPOP", count, |index| list_write_key(cfg, index)),
        CommandId::Rpop => cycle_one_arg("RPOP", count, |index| list_write_key(cfg, index)),
        // ---- Hashes ----
        CommandId::Hset => QueryArgvPlan::Cycling(
            (0..count)
                .map(|index| {
                    vec![
                        "HSET".to_string(),
                        hash_partition_key(cfg, index),
                        hash_field(0),
                        format!("query-value:{index}"),
                    ]
                })
                .collect(),
        ),
        CommandId::Hsetnx => QueryArgvPlan::Cycling(
            (0..count)
                .map(|index| {
                    vec![
                        "HSETNX".to_string(),
                        hash_partition_key(cfg, index),
                        hash_field(0),
                        format!("query-value:{index}"),
                    ]
                })
                .collect(),
        ),
        CommandId::Hget => cycle_two_args(
            "HGET",
            count,
            |index| hash_partition_key(cfg, index),
            |_| hash_field(0),
        ),
        CommandId::Hmget => QueryArgvPlan::Cycling(
            (0..count)
                .map(|index| {
                    vec![
                        "HMGET".to_string(),
                        hash_partition_key(cfg, index),
                        hash_field(0),
                        hash_field(1),
                        hash_field(2),
                    ]
                })
                .collect(),
        ),
        CommandId::Hdel => QueryArgvPlan::Cycling(
            (0..count)
                .map(|index| {
                    vec![
                        "HDEL".to_string(),
                        hash_partition_key(cfg, index),
                        hash_field(0),
                    ]
                })
                .collect(),
        ),
        CommandId::Hkeys => {
            cycle_one_arg("HKEYS", count, |index| hash_partition_key(cfg, index))
        }
        CommandId::Hvals => {
            cycle_one_arg("HVALS", count, |index| hash_partition_key(cfg, index))
        }
        CommandId::Hstrlen => QueryArgvPlan::Cycling(
            (0..count)
                .map(|index| {
                    vec![
                        "HSTRLEN".to_string(),
                        hash_partition_key(cfg, index),
                        hash_field(0),
                    ]
                })
                .collect(),
        ),
        CommandId::Hincrby => QueryArgvPlan::Cycling(
            (0..count)
                .map(|index| {
                    vec![
                        "HINCRBY".to_string(),
                        hash_partition_key(cfg, index),
                        hash_counter_field(0),
                        "1".to_string(),
                    ]
                })
                .collect(),
        ),
        CommandId::Hexists => cycle_two_args(
            "HEXISTS",
            count,
            |index| hash_partition_key(cfg, index),
            |_| hash_field(0),
        ),
        CommandId::Hlen => cycle_one_arg("HLEN", count, |index| hash_partition_key(cfg, index)),
        CommandId::Hgetall => {
            cycle_one_arg("HGETALL", count, |index| hash_partition_key(cfg, index))
        }
        // HSCAN mirrors SCAN behavior with fixed cursor/count per hash key.
        CommandId::Hscan => QueryArgvPlan::Cycling(
            (0..count)
                .map(|index| {
                    vec![
                        "HSCAN".to_string(),
                        hash_partition_key(cfg, index),
                        "0".to_string(),
                        "COUNT".to_string(),
                        "100".to_string(),
                    ]
                })
                .collect(),
        ),
        // ---- Sets ----
        CommandId::Sadd => QueryArgvPlan::Cycling(
            (0..count)
                .map(|index| {
                    vec![
                        "SADD".to_string(),
                        set_partition_key(cfg, index),
                        format!("query-member:{index}"),
                    ]
                })
                .collect(),
        ),
        CommandId::Srem => QueryArgvPlan::Cycling(
            (0..count)
                .map(|index| {
                    vec![
                        "SREM".to_string(),
                        set_partition_key(cfg, index),
                        set_member(index),
                    ]
                })
                .collect(),
        ),
        CommandId::Sismember => cycle_two_args(
            "SISMEMBER",
            count,
            |index| set_partition_key(cfg, index),
            set_member,
        ),
        CommandId::Smismember => QueryArgvPlan::Cycling(
            (0..group_cycle_count(cfg, seed_items, 3))
                .map(|index| {
                    let base = index * 3;
                    vec![
                        "SMISMEMBER".to_string(),
                        set_partition_key(cfg, base),
                        set_member(base),
                        set_member(base + 1),
                        set_member(base + 2),
                    ]
                })
                .collect(),
        ),
        CommandId::Scard => cycle_one_arg("SCARD", count, |index| set_partition_key(cfg, index)),
        CommandId::Smembers => {
            cycle_one_arg("SMEMBERS", count, |index| set_partition_key(cfg, index))
        }
        CommandId::Srandmember => {
            cycle_one_arg("SRANDMEMBER", count, |index| set_partition_key(cfg, index))
        }
        CommandId::Spop => cycle_one_arg("SPOP", count, |index| set_partition_key(cfg, index)),
        CommandId::Smove => QueryArgvPlan::Cycling(
            (0..count)
                .map(|index| {
                    vec![
                        "SMOVE".to_string(),
                        set1_partition_key(cfg, index),
                        set2_partition_key(cfg, index),
                        set_member(index),
                    ]
                })
                .collect(),
        ),
        // SSCAN mirrors HSCAN/ZSCAN pattern to keep scan family comparable.
        CommandId::Sscan => QueryArgvPlan::Cycling(
            (0..count)
                .map(|index| {
                    vec![
                        "SSCAN".to_string(),
                        set_partition_key(cfg, index),
                        "0".to_string(),
                        "COUNT".to_string(),
                        "100".to_string(),
                    ]
                })
                .collect(),
        ),
        CommandId::Sunion => QueryArgvPlan::Cycling(
            (0..count)
                .map(|index| {
                    vec![
                        "SUNION".to_string(),
                        set1_partition_key(cfg, index),
                        set2_partition_key(cfg, index),
                    ]
                })
                .collect(),
        ),
        CommandId::Sinter => QueryArgvPlan::Cycling(
            (0..count)
                .map(|index| {
                    vec![
                        "SINTER".to_string(),
                        set1_partition_key(cfg, index),
                        set2_partition_key(cfg, index),
                    ]
                })
                .collect(),
        ),
        CommandId::Sdiff => QueryArgvPlan::Cycling(
            (0..count)
                .map(|index| {
                    vec![
                        "SDIFF".to_string(),
                        set1_partition_key(cfg, index),
                        set2_partition_key(cfg, index),
                    ]
                })
                .collect(),
        ),
        // ---- Sorted sets ----
        CommandId::Zadd => QueryArgvPlan::Cycling(
            (0..count)
                .map(|index| {
                    vec![
                        "ZADD".to_string(),
                        zset_partition_key(cfg, index),
                        index.to_string(),
                        format!("query-member:{index}"),
                    ]
                })
                .collect(),
        ),
        CommandId::Zscore => cycle_two_args(
            "ZSCORE",
            count,
            |index| zset_partition_key(cfg, index),
            zset_member,
        ),
        CommandId::Zmscore => QueryArgvPlan::Cycling(
            (0..group_cycle_count(cfg, seed_items, 3))
                .map(|index| {
                    let base = index * 3;
                    vec![
                        "ZMSCORE".to_string(),
                        zset_partition_key(cfg, base),
                        zset_member(base),
                        zset_member(base + 1),
                        zset_member(base + 2),
                    ]
                })
                .collect(),
        ),
        CommandId::Zrank => cycle_two_args(
            "ZRANK",
            count,
            |index| zset_partition_key(cfg, index),
            zset_member,
        ),
        CommandId::Zrevrank => cycle_two_args(
            "ZREVRANK",
            count,
            |index| zset_partition_key(cfg, index),
            zset_member,
        ),
        CommandId::Zrem => cycle_two_args(
            "ZREM",
            count,
            |index| zset_partition_key(cfg, index),
            zset_member,
        ),
        CommandId::Zcard => cycle_one_arg("ZCARD", count, |index| zset_partition_key(cfg, index)),
        CommandId::Zcount => QueryArgvPlan::Cycling(
            (0..count)
                .map(|index| {
                    vec![
                        "ZCOUNT".to_string(),
                        zset_partition_key(cfg, index),
                        "-inf".to_string(),
                        "+inf".to_string(),
                    ]
                })
                .collect(),
        ),
        CommandId::Zrange => QueryArgvPlan::Cycling(
            (0..count)
                .map(|index| {
                    vec![
                        "ZRANGE".to_string(),
                        zset_partition_key(cfg, index),
                        "0".to_string(),
                        "9".to_string(),
                    ]
                })
                .collect(),
        ),
        CommandId::ZrangeScores => QueryArgvPlan::Cycling(
            (0..count)
                .map(|index| {
                    vec![
                        "ZRANGE".to_string(),
                        zset_partition_key(cfg, index),
                        "0".to_string(),
                        "9".to_string(),
                        "WITHSCORES".to_string(),
                    ]
                })
                .collect(),
        ),
        CommandId::Zincrby => QueryArgvPlan::Cycling(
            (0..count)
                .map(|index| {
                    vec![
                        "ZINCRBY".to_string(),
                        zset_partition_key(cfg, index),
                        "1".to_string(),
                        zset_member(index),
                    ]
                })
                .collect(),
        ),
        CommandId::Zpopmin => {
            cycle_one_arg("ZPOPMIN", count, |index| zset_partition_key(cfg, index))
        }
        CommandId::Zpopmax => {
            cycle_one_arg("ZPOPMAX", count, |index| zset_partition_key(cfg, index))
        }
        CommandId::Zremrangebyrank => QueryArgvPlan::Cycling(
            (0..count)
                .map(|index| {
                    vec![
                        "ZREMRANGEBYRANK".to_string(),
                        zset_partition_key(cfg, index),
                        "0".to_string(),
                        "0".to_string(),
                    ]
                })
                .collect(),
        ),
        // ZSCAN intentionally uses fixed cursor/count for stable per-op shape.
        CommandId::Zscan => QueryArgvPlan::Cycling(
            (0..count)
                .map(|index| {
                    vec![
                        "ZSCAN".to_string(),
                        zset_partition_key(cfg, index),
                        "0".to_string(),
                        "COUNT".to_string(),
                        "100".to_string(),
                    ]
                })
                .collect(),
        ),
        // ---- Geo ----
        CommandId::Geoadd => QueryArgvPlan::Cycling(
            (0..count)
                .map(|index| {
                    vec![
                        "GEOADD".to_string(),
                        cfg.geo_key.clone(),
                        "0".to_string(),
                        "0".to_string(),
                        geo_member(index),
                    ]
                })
                .collect(),
        ),
        CommandId::Geopos => cycle_two_args("GEOPOS", count, |_| cfg.geo_key.clone(), geo_member),
        CommandId::Geodist => QueryArgvPlan::Cycling(
            (0..count)
                .map(|index| {
                    vec![
                        "GEODIST".to_string(),
                        cfg.geo_key.clone(),
                        geo_member(index),
                        geo_member((index + count / 2).min(seed_items.saturating_sub(1))),
                        "km".to_string(),
                    ]
                })
                .collect(),
        ),
        CommandId::GeosearchSmall => geosearch_plan(cfg, "500", "10"),
        CommandId::GeosearchLarge => geosearch_plan(cfg, "5000", "100"),
        // ---- Streams / pubsub ----
        CommandId::Xadd => QueryArgvPlan::Cycling(
            (0..count)
                .map(|index| {
                    vec![
                        "XADD".to_string(),
                        stream_partition_key(cfg, index),
                        "*".to_string(),
                        "field".to_string(),
                        "value".to_string(),
                    ]
                })
                .collect(),
        ),
        CommandId::Xtrim => QueryArgvPlan::Cycling(
            (0..count)
                .map(|index| {
                    vec![
                        "XTRIM".to_string(),
                        stream_partition_key(cfg, index),
                        "MAXLEN".to_string(),
                        "~".to_string(),
                        "1000".to_string(),
                    ]
                })
                .collect(),
        ),
        CommandId::Xdel => QueryArgvPlan::Cycling(
            (0..count)
                .map(|index| {
                    vec![
                        "XDEL".to_string(),
                        stream_partition_key(cfg, index),
                        "1-0".to_string(),
                    ]
                })
                .collect(),
        ),
        CommandId::Xlen => cycle_one_arg("XLEN", count, |index| stream_partition_key(cfg, index)),
        CommandId::Xrange => QueryArgvPlan::Cycling(
            (0..count)
                .map(|index| {
                    vec![
                        "XRANGE".to_string(),
                        stream_partition_key(cfg, index),
                        "-".to_string(),
                        "+".to_string(),
                        "COUNT".to_string(),
                        "10".to_string(),
                    ]
                })
                .collect(),
        ),
        CommandId::Xrevrange => QueryArgvPlan::Cycling(
            (0..count)
                .map(|index| {
                    vec![
                        "XREVRANGE".to_string(),
                        stream_partition_key(cfg, index),
                        "+".to_string(),
                        "-".to_string(),
                        "COUNT".to_string(),
                        "10".to_string(),
                    ]
                })
                .collect(),
        ),
        CommandId::Pfadd => QueryArgvPlan::Cycling(
            (0..count)
                .map(|index| {
                    vec![
                        "PFADD".to_string(),
                        format!("{}:hll:{:012}", cfg.key_prefix, index),
                        format!("member:{index}"),
                    ]
                })
                .collect(),
        ),
        CommandId::Pfcount => QueryArgvPlan::Cycling(
            (0..count)
                .map(|index| {
                    vec![
                        "PFCOUNT".to_string(),
                        format!("{}:hll:{:012}", cfg.key_prefix, index),
                    ]
                })
                .collect(),
        ),
        CommandId::Publish => QueryArgvPlan::Static(vec![
            "PUBLISH".to_string(),
            format!("{}:channel", cfg.key_prefix),
            "message".to_string(),
        ]),
    }
}

fn query_cycle_count(cfg: &BenchConfig, seed_items: usize) -> usize {
    // Bounded by keyspace and fixture size; never allow zero variants.
    seed_items.min(cfg.keyspace).max(1)
}

fn group_cycle_count(cfg: &BenchConfig, seed_items: usize, group_size: usize) -> usize {
    // Same as query_cycle_count but adjusted for grouped commands (e.g. MGET 3).
    (seed_items / group_size).min(cfg.keyspace).max(1)
}

fn query_plan_mode(plan: &QueryArgvPlan) -> &'static str {
    match plan {
        QueryArgvPlan::Static(_) => "static",
        QueryArgvPlan::Cycling(_) => "cycle",
    }
}

fn query_variant_count(plan: &QueryArgvPlan) -> usize {
    match plan {
        QueryArgvPlan::Static(_) => 1,
        QueryArgvPlan::Cycling(commands) => commands.len(),
    }
}

fn cycle_one_arg<F>(command: &str, count: usize, arg: F) -> QueryArgvPlan
where
    F: Fn(usize) -> String,
{
    // Generic builder for single-key/single-member command families.
    QueryArgvPlan::Cycling(
        (0..count)
            .map(|index| vec![command.to_string(), arg(index)])
            .collect(),
    )
}

fn cycle_two_args<F, G>(command: &str, count: usize, first: F, second: G) -> QueryArgvPlan
where
    F: Fn(usize) -> String,
    G: Fn(usize) -> String,
{
    // Generic builder for two-argument command families.
    QueryArgvPlan::Cycling(
        (0..count)
            .map(|index| vec![command.to_string(), first(index), second(index)])
            .collect(),
    )
}

fn list_write_plan(cfg: &BenchConfig, command: &str, count: usize) -> QueryArgvPlan {
    // Shared plan generator for LPUSH/RPUSH update workloads.
    QueryArgvPlan::Cycling(
        (0..count)
            .map(|index| {
                vec![
                    command.to_string(),
                    list_write_key(cfg, index),
                    format!("query-value:{index}"),
                ]
            })
            .collect(),
    )
}

fn geosearch_plan(cfg: &BenchConfig, radius: &str, count: &str) -> QueryArgvPlan {
    // Static GEOSEARCH with controlled radius/count to provide two difficulty
    // levels while keeping argument shape constant across runs.
    QueryArgvPlan::Static(vec![
        "GEOSEARCH".to_string(),
        cfg.geo_key.clone(),
        "FROMLONLAT".to_string(),
        "0".to_string(),
        "0".to_string(),
        "BYRADIUS".to_string(),
        radius.to_string(),
        "km".to_string(),
        "ASC".to_string(),
        "COUNT".to_string(),
        count.to_string(),
    ])
}

fn string_key(cfg: &BenchConfig, index: usize) -> String {
    // Fixed-width numeric suffixes keep lexical order stable in scans/logging.
    format!("{}:string:{index:012}", cfg.key_prefix)
}

fn counter_key(cfg: &BenchConfig, index: usize) -> String {
    format!("{}:counter:{index:012}", cfg.key_prefix)
}

fn list_write_key(cfg: &BenchConfig, index: usize) -> String {
    format!("{}:list-write:{index}", cfg.key_prefix)
}

fn hash_partition_key(cfg: &BenchConfig, index: usize) -> String {
    format!("{}:hash:{index:012}", cfg.key_prefix)
}

fn hash_field(index: usize) -> String {
    format!("field:{index}")
}

fn hash_counter_field(index: usize) -> String {
    format!("counter:{index}")
}

fn set_partition_key(cfg: &BenchConfig, index: usize) -> String {
    format!("{}:set:{index:012}", cfg.key_prefix)
}

fn set1_partition_key(cfg: &BenchConfig, index: usize) -> String {
    format!("{}:set1:{index:012}", cfg.key_prefix)
}

fn set2_partition_key(cfg: &BenchConfig, index: usize) -> String {
    format!("{}:set2:{index:012}", cfg.key_prefix)
}

fn set_member(index: usize) -> String {
    format!("member:{index}")
}

fn zset_partition_key(cfg: &BenchConfig, index: usize) -> String {
    format!("{}:zset:{index:012}", cfg.key_prefix)
}

fn zset_member(index: usize) -> String {
    format!("member:{index}")
}

fn geo_member(index: usize) -> String {
    format!("place:{index}")
}

fn stream_partition_key(cfg: &BenchConfig, index: usize) -> String {
    format!("{}:stream:{index:012}", cfg.key_prefix)
}

fn seed(conn: &mut RespConn, cfg: &BenchConfig, plan: &CommandPlan) -> io::Result<()> {
    // Replay seed in pipeline-sized chunks to minimize setup overhead.
    for chunk in plan.seed.chunks(cfg.pipeline) {
        conn.pipeline(chunk)?;
    }
    Ok(())
}

fn bench(conn: &mut RespConn, cfg: &BenchConfig, plan: &CommandPlan) -> io::Result<f64> {
    // Single-client RESP loop: write batch, flush, drain replies, repeat.
    let bench_plan = bench_plan(plan)?;
    let mut batch_buf = Vec::with_capacity(bench_plan.batch_capacity_hint(cfg.pipeline));
    let started = Instant::now();
    let mut completed = 0usize;

    while started.elapsed() < cfg.run_budget {
        let batch = cfg.pipeline;
        batch_buf.clear();
        bench_plan.append_batch(&mut batch_buf, completed, batch);
        conn.write_encoded_command(&batch_buf)?;
        conn.flush()?;
        for _ in 0..batch {
            conn.read_response()?;
        }
        completed += batch;
    }

    let elapsed = started.elapsed().as_secs_f64();
    Ok(if elapsed > 0.0 {
        completed as f64 / elapsed
    } else {
        0.0
    })
}

fn bench_plan(plan: &CommandPlan) -> io::Result<BenchPlan> {
    // Encode RESP frames once so timed loops exclude argv encoding cost.
    match &plan.query {
        QueryArgvPlan::Static(argv) => encode_command(argv).map(BenchPlan::Static),
        QueryArgvPlan::Cycling(commands) => commands
            .iter()
            .map(|argv| encode_command(argv))
            .collect::<io::Result<Vec<_>>>()
            .map(BenchPlan::Cycling),
    }
}

fn encode_command<S: AsRef<str>>(args: &[S]) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    write!(&mut out, "*{}\r\n", args.len())?;
    for arg in args {
        let bytes = arg.as_ref().as_bytes();
        write!(&mut out, "${}\r\n", bytes.len())?;
        out.write_all(bytes)?;
        out.write_all(b"\r\n")?;
    }
    Ok(out)
}
