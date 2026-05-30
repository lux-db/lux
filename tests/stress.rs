mod common;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

#[derive(Clone, Debug, PartialEq)]
enum Resp {
    Simple(String),
    Error(String),
    Int(i64),
    Bulk(Option<String>),
    Array(Vec<Resp>),
}

fn resp_cmd(args: &[String]) -> Vec<u8> {
    let mut buf = format!("*{}\r\n", args.len()).into_bytes();
    for arg in args {
        buf.extend_from_slice(format!("${}\r\n", arg.len()).as_bytes());
        buf.extend_from_slice(arg.as_bytes());
        buf.extend_from_slice(b"\r\n");
    }
    buf
}

fn read_resp(reader: &mut BufReader<TcpStream>) -> Resp {
    let mut line = String::new();
    reader.read_line(&mut line).expect("read response line");
    let line = line.trim_end_matches(['\r', '\n']).to_string();
    let Some(prefix) = line.as_bytes().first().copied() else {
        panic!("empty RESP line");
    };
    match prefix {
        b'+' => Resp::Simple(line[1..].to_string()),
        b'-' => Resp::Error(line[1..].to_string()),
        b':' => Resp::Int(line[1..].parse().expect("integer response")),
        b'$' => {
            let len: i64 = line[1..].parse().expect("bulk length");
            if len < 0 {
                Resp::Bulk(None)
            } else {
                let mut data = vec![0u8; len as usize + 2];
                reader.read_exact(&mut data).expect("read bulk body");
                Resp::Bulk(Some(
                    String::from_utf8_lossy(&data[..len as usize]).to_string(),
                ))
            }
        }
        b'*' => {
            let len: i64 = line[1..].parse().expect("array length");
            if len < 0 {
                Resp::Array(Vec::new())
            } else {
                let mut values = Vec::with_capacity(len as usize);
                for _ in 0..len {
                    values.push(read_resp(reader));
                }
                Resp::Array(values)
            }
        }
        _ => panic!("unexpected RESP line: {line:?}"),
    }
}

fn send(conn: &mut TcpStream, args: &[String]) -> Resp {
    conn.write_all(&resp_cmd(args)).expect("write command");
    let mut reader = BufReader::new(conn.try_clone().expect("clone connection"));
    read_resp(&mut reader)
}

fn cmd(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| s.to_string()).collect()
}

fn wait_for_port(port: u16) {
    for _ in 0..80 {
        if TcpStream::connect(format!("127.0.0.1:{port}")).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("lux did not start on port {port}");
}

struct LuxServer {
    port: u16,
    child: std::process::Child,
    tmpdir: std::path::PathBuf,
}

impl LuxServer {
    fn start(port: u16, tiered: bool) -> Self {
        let tmpdir = std::env::temp_dir().join(format!(
            "lux_stress_{}_{}_{}",
            std::process::id(),
            port,
            if tiered { "tiered" } else { "memory" }
        ));
        let _ = std::fs::remove_dir_all(&tmpdir);
        std::fs::create_dir_all(&tmpdir).unwrap();
        let child = Self::spawn(port, &tmpdir, tiered);
        wait_for_port(port);
        Self {
            port,
            child,
            tmpdir,
        }
    }

    fn spawn(port: u16, tmpdir: &std::path::Path, tiered: bool) -> std::process::Child {
        let mut command = common::lux_command(env!("CARGO_BIN_EXE_lux"));
        command
            .env("LUX_PORT", port.to_string())
            .env("LUX_SHARDS", "4")
            .env("LUX_SAVE_INTERVAL", "0")
            .env("LUX_DATA_DIR", tmpdir.to_str().unwrap())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        if tiered {
            command
                .env("LUX_STORAGE_MODE", "tiered")
                .env("LUX_STORAGE_DIR", tmpdir.join("storage").to_str().unwrap())
                .env("LUX_MAXMEMORY", "256kb")
                .env("LUX_MAXMEMORY_POLICY", "allkeys-lru");
        }
        command.spawn().expect("failed to start lux")
    }

    fn conn(&self) -> TcpStream {
        let stream = TcpStream::connect(format!("127.0.0.1:{}", self.port)).unwrap();
        stream.set_nodelay(true).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
    }

    fn restart(&mut self, tiered: bool) {
        common::terminate_child(&mut self.child);
        self.child = Self::spawn(self.port, &self.tmpdir, tiered);
        wait_for_port(self.port);
    }

    fn crash_and_restart(&mut self, tiered: bool) {
        self.child.kill().ok();
        self.child.wait().ok();
        self.child = Self::spawn(self.port, &self.tmpdir, tiered);
        wait_for_port(self.port);
    }
}

impl Drop for LuxServer {
    fn drop(&mut self) {
        common::terminate_child(&mut self.child);
        let _ = std::fs::remove_dir_all(&self.tmpdir);
    }
}

#[derive(Default)]
struct Model {
    strings: BTreeMap<String, String>,
    counters: BTreeMap<String, i64>,
    hashes: BTreeMap<String, BTreeMap<String, String>>,
    sets: BTreeMap<String, BTreeSet<String>>,
    lists: BTreeMap<String, VecDeque<String>>,
}

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }

    fn usize(&mut self, max: usize) -> usize {
        (self.next() as usize) % max
    }
}

fn assert_resp(actual: Resp, expected: Resp, op: usize, command: &[String], seed: u64) {
    assert_eq!(
        actual, expected,
        "stress mismatch at op {op}, seed {seed}, command {command:?}"
    );
}

fn assert_command(
    lux: &mut TcpStream,
    redis: Option<&mut TcpStream>,
    command: &[String],
    expected: Resp,
    op: usize,
    seed: u64,
) {
    assert_resp(send(lux, command), expected.clone(), op, command, seed);
    if let Some(redis) = redis {
        assert_resp(send(redis, command), expected, op, command, seed);
    }
}

fn redis_addr_from_env() -> Option<String> {
    if std::env::var("LUX_STRESS_DIFF_REDIS").ok().as_deref() != Some("1") {
        return None;
    }
    let raw = std::env::var("REDIS_URL").unwrap_or_else(|_| "127.0.0.1:6379".to_string());
    Some(
        raw.trim_start_matches("redis://")
            .trim_end_matches('/')
            .to_string(),
    )
}

fn run_model_stress(seed: u64, port: u16, tiered: bool, redis_addr: Option<String>) {
    let iters: usize = std::env::var("LUX_STRESS_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2_000);
    let prefix = format!("stress:{seed:x}:{}:", std::process::id());
    let mut rng = Rng::new(seed);
    let mut model = Model::default();
    let mut server = LuxServer::start(port, tiered);
    let mut conn = server.conn();
    let mut redis = redis_addr.map(|addr| {
        let stream = TcpStream::connect(&addr)
            .unwrap_or_else(|e| panic!("failed to connect to Redis/Valkey at {addr}: {e}"));
        stream.set_nodelay(true).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
    });

    for op in 0..iters {
        match rng.usize(14) {
            0 => {
                let key = format!("{prefix}str:{}", rng.usize(32));
                let value = format!("v:{}:{}", op, rng.usize(10_000));
                let command = vec!["SET".into(), key.clone(), value.clone()];
                model.strings.insert(key, value);
                assert_command(
                    &mut conn,
                    redis.as_mut(),
                    &command,
                    Resp::Simple("OK".into()),
                    op,
                    seed,
                );
            }
            1 => {
                let key = format!("{prefix}str:{}", rng.usize(32));
                let expected = Resp::Bulk(model.strings.get(&key).cloned());
                let command = vec!["GET".into(), key];
                assert_command(&mut conn, redis.as_mut(), &command, expected, op, seed);
            }
            2 => {
                let key = format!("{prefix}ctr:{}", rng.usize(16));
                let next = model.counters.entry(key.clone()).or_insert(0);
                *next += 1;
                let command = vec!["INCR".into(), key];
                assert_command(
                    &mut conn,
                    redis.as_mut(),
                    &command,
                    Resp::Int(*next),
                    op,
                    seed,
                );
            }
            3 => {
                let key = format!("{prefix}hash:{}", rng.usize(16));
                let field = format!("f{}", rng.usize(16));
                let value = format!("hv:{}:{}", op, rng.usize(10_000));
                let hash = model.hashes.entry(key.clone()).or_default();
                let is_new = !hash.contains_key(&field);
                hash.insert(field.clone(), value.clone());
                let command = vec!["HSET".into(), key, field, value];
                assert_command(
                    &mut conn,
                    redis.as_mut(),
                    &command,
                    Resp::Int(if is_new { 1 } else { 0 }),
                    op,
                    seed,
                );
            }
            4 => {
                let key = format!("{prefix}hash:{}", rng.usize(16));
                let field = format!("f{}", rng.usize(16));
                let expected =
                    Resp::Bulk(model.hashes.get(&key).and_then(|h| h.get(&field)).cloned());
                let command = vec!["HGET".into(), key, field];
                assert_command(&mut conn, redis.as_mut(), &command, expected, op, seed);
            }
            5 => {
                let key = format!("{prefix}set:{}", rng.usize(16));
                let member = format!("m{}", rng.usize(64));
                let set = model.sets.entry(key.clone()).or_default();
                let added = set.insert(member.clone());
                let command = vec!["SADD".into(), key, member];
                assert_command(
                    &mut conn,
                    redis.as_mut(),
                    &command,
                    Resp::Int(if added { 1 } else { 0 }),
                    op,
                    seed,
                );
            }
            6 => {
                let key = format!("{prefix}set:{}", rng.usize(16));
                let member = format!("m{}", rng.usize(64));
                let exists = model
                    .sets
                    .get(&key)
                    .is_some_and(|set| set.contains(&member));
                let command = vec!["SISMEMBER".into(), key, member];
                assert_command(
                    &mut conn,
                    redis.as_mut(),
                    &command,
                    Resp::Int(if exists { 1 } else { 0 }),
                    op,
                    seed,
                );
            }
            7 | 8 => {
                let key = format!("{prefix}list:{}", rng.usize(16));
                let value = format!("lv:{}:{}", op, rng.usize(10_000));
                let list = model.lists.entry(key.clone()).or_default();
                let left = rng.usize(2) == 0;
                if left {
                    list.push_front(value.clone());
                } else {
                    list.push_back(value.clone());
                }
                let command = vec![if left { "LPUSH" } else { "RPUSH" }.into(), key, value];
                assert_command(
                    &mut conn,
                    redis.as_mut(),
                    &command,
                    Resp::Int(list.len() as i64),
                    op,
                    seed,
                );
            }
            9 => {
                let key = format!("{prefix}list:{}", rng.usize(16));
                let left = rng.usize(2) == 0;
                let expected = model.lists.get_mut(&key).and_then(|list| {
                    if left {
                        list.pop_front()
                    } else {
                        list.pop_back()
                    }
                });
                let command = vec![if left { "LPOP" } else { "RPOP" }.into(), key];
                assert_command(
                    &mut conn,
                    redis.as_mut(),
                    &command,
                    Resp::Bulk(expected),
                    op,
                    seed,
                );
            }
            10 => {
                let key = format!("{prefix}str:{}", rng.usize(32));
                let existed = model.strings.remove(&key).is_some();
                let command = vec!["DEL".into(), key];
                assert_command(
                    &mut conn,
                    redis.as_mut(),
                    &command,
                    Resp::Int(if existed { 1 } else { 0 }),
                    op,
                    seed,
                );
            }
            11 => {
                let key = format!("{prefix}ctr:{}", rng.usize(16));
                let existed = model.counters.remove(&key).is_some();
                let command = vec!["DEL".into(), key];
                assert_command(
                    &mut conn,
                    redis.as_mut(),
                    &command,
                    Resp::Int(if existed { 1 } else { 0 }),
                    op,
                    seed,
                );
            }
            12 => {
                let key = format!("{prefix}hash:{}", rng.usize(16));
                let existed = model.hashes.remove(&key).is_some();
                let command = vec!["DEL".into(), key];
                assert_command(
                    &mut conn,
                    redis.as_mut(),
                    &command,
                    Resp::Int(if existed { 1 } else { 0 }),
                    op,
                    seed,
                );
            }
            _ => {
                let crashed = tiered && rng.usize(2) == 0;
                drop(conn);
                if crashed {
                    server.crash_and_restart(tiered);
                } else {
                    conn = server.conn();
                    let save = cmd(&["SAVE"]);
                    let saved = send(&mut conn, &save);
                    assert!(
                        matches!(saved, Resp::Simple(_)),
                        "SAVE failed at op {op}, seed {seed}: {saved:?}"
                    );
                    drop(conn);
                    server.restart(tiered);
                }
                conn = server.conn();
                verify_model(&mut conn, &model, seed);
            }
        }
    }

    verify_model(&mut conn, &model, seed);
}

fn verify_model(conn: &mut TcpStream, model: &Model, seed: u64) {
    for (key, value) in &model.strings {
        let command = vec!["GET".into(), key.clone()];
        assert_resp(
            send(conn, &command),
            Resp::Bulk(Some(value.clone())),
            usize::MAX,
            &command,
            seed,
        );
    }
    for (key, value) in &model.counters {
        let command = vec!["GET".into(), key.clone()];
        assert_resp(
            send(conn, &command),
            Resp::Bulk(Some(value.to_string())),
            usize::MAX,
            &command,
            seed,
        );
    }
    for (key, hash) in &model.hashes {
        for (field, value) in hash {
            let command = vec!["HGET".into(), key.clone(), field.clone()];
            assert_resp(
                send(conn, &command),
                Resp::Bulk(Some(value.clone())),
                usize::MAX,
                &command,
                seed,
            );
        }
    }
    for (key, set) in &model.sets {
        for member in set {
            let command = vec!["SISMEMBER".into(), key.clone(), member.clone()];
            assert_resp(
                send(conn, &command),
                Resp::Int(1),
                usize::MAX,
                &command,
                seed,
            );
        }
    }
    for (key, list) in &model.lists {
        let command = vec!["LRANGE".into(), key.clone(), "0".into(), "-1".into()];
        let expected = Resp::Array(
            list.iter()
                .map(|value| Resp::Bulk(Some(value.clone())))
                .collect(),
        );
        assert_resp(send(conn, &command), expected, usize::MAX, &command, seed);
    }
}

#[test]
fn deterministic_model_stress_memory_mode() {
    run_model_stress(0x5154_4c55_584d_454d, 17920, false, None);
}

#[test]
fn deterministic_model_stress_tiered_mode() {
    run_model_stress(0x5154_4c55_5854_4945, 17921, true, None);
}

#[test]
fn optional_redis_differential_core_subset() {
    let Some(redis_addr) = redis_addr_from_env() else {
        eprintln!("skipping Redis/Valkey differential stress; set LUX_STRESS_DIFF_REDIS=1");
        return;
    };
    run_model_stress(0x5154_4c55_5844_4946, 17922, false, Some(redis_addr));
}
