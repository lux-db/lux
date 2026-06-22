//! Shared integration-test harness.
//!
//! Every spawned server gets an OS-assigned port (never a hardcoded literal) and
//! a unique, auto-cleaned data directory (never one derived from the port). That
//! combination makes the suite collision-proof: two tests can never fight over a
//! port or clobber each other's data, even under a fully parallel runner.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;
use tempfile::TempDir;

pub fn lux_command<P: AsRef<std::ffi::OsStr>>(program: P) -> Command {
    Command::new(program)
}

pub fn terminate_child(child: &mut Child) {
    #[cfg(unix)]
    {
        let _ = Command::new("kill")
            .arg("-TERM")
            .arg(child.id().to_string())
            .status();

        for _ in 0..50 {
            match child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => thread::sleep(Duration::from_millis(20)),
                Err(_) => return,
            }
        }
    }

    child.kill().ok();
    child.wait().ok();
}

/// Locate the compiled `lux` binary, preferring release, falling back to debug.
pub fn find_lux_binary() -> std::path::PathBuf {
    let exe = std::env::current_exe().expect("current_exe");
    let target_dir = exe
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .expect("target dir");
    let release = target_dir.join("release").join("lux");
    if release.exists() {
        return release;
    }
    let debug = target_dir.join("debug").join("lux");
    if debug.exists() {
        return debug;
    }
    panic!("no lux binary found (build it first)");
}

/// Reserve `n` distinct localhost ports by holding listeners on `:0`
/// simultaneously, then releasing them. Binding all at once guarantees the
/// ports differ; releasing lets the spawned server claim them.
pub fn free_ports(n: usize) -> Vec<u16> {
    let listeners: Vec<TcpListener> = (0..n)
        .map(|_| TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port"))
        .collect();
    listeners
        .iter()
        .map(|l| l.local_addr().unwrap().port())
        .collect()
}

pub fn free_port() -> u16 {
    free_ports(1)[0]
}

/// Open a RESP client connection to a running server. Retries briefly so a
/// transient refusal (e.g. a full listen backlog while the whole suite spawns
/// servers in parallel) doesn't fail the test.
pub fn connect(port: u16) -> TcpStream {
    let addr = format!("127.0.0.1:{port}");
    let mut last_err = None;
    for attempt in 0..40 {
        match TcpStream::connect(&addr) {
            Ok(stream) => {
                stream.set_nodelay(true).ok();
                stream
                    .set_read_timeout(Some(Duration::from_millis(500)))
                    .ok();
                return stream;
            }
            Err(e) => {
                last_err = Some(e);
                thread::sleep(Duration::from_millis(25 * (attempt / 8 + 1)));
            }
        }
    }
    panic!("could not connect to lux on {addr}: {last_err:?}");
}

pub fn resp_cmd(args: &[&str]) -> Vec<u8> {
    let mut buf = format!("*{}\r\n", args.len());
    for arg in args {
        buf.push_str(&format!("${}\r\n{}\r\n", arg.len(), arg));
    }
    buf.into_bytes()
}

/// Drain whatever is currently readable on the stream (bounded by the stream's
/// read timeout).
pub fn read_all(stream: &mut TcpStream) -> String {
    let mut data = Vec::with_capacity(4096);
    let mut buf = [0u8; 8192];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(len) => data.extend_from_slice(&buf[..len]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&data).to_string()
}

/// Write a command and read the response.
pub fn send(stream: &mut TcpStream, args: &[&str]) -> String {
    stream.write_all(&resp_cmd(args)).unwrap();
    thread::sleep(Duration::from_millis(50));
    read_all(stream)
}

/// Alias kept for call sites that named this `send_and_read`.
pub fn send_and_read(stream: &mut TcpStream, args: &[&str]) -> String {
    send(stream, args)
}

/// Storage backing for a spawned server.
#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Memory,
    Tiered,
}

#[derive(Clone)]
struct Spec {
    password: Option<String>,
    http: bool,
    mode: Mode,
    shards: u32,
    save_interval: String,
    maxmemory: Option<String>,
    maxmemory_policy: Option<String>,
    env: Vec<(String, String)>,
}

impl Default for Spec {
    fn default() -> Self {
        Self {
            password: None,
            http: false,
            mode: Mode::Memory,
            shards: 4,
            save_interval: "0".to_string(),
            maxmemory: None,
            maxmemory_policy: None,
            env: Vec::new(),
        }
    }
}

pub struct LuxServerBuilder {
    spec: Spec,
}

impl LuxServerBuilder {
    pub fn password(mut self, password: &str) -> Self {
        self.spec.password = Some(password.to_string());
        self
    }

    /// Enable the HTTP listener (its port is exposed via `http_port()`).
    pub fn http(mut self) -> Self {
        self.spec.http = true;
        self
    }

    /// Use tiered (disk-backed) storage instead of in-memory.
    pub fn tiered(mut self) -> Self {
        self.spec.mode = Mode::Tiered;
        self
    }

    pub fn shards(mut self, shards: u32) -> Self {
        self.spec.shards = shards;
        self
    }

    pub fn save_interval(mut self, interval: &str) -> Self {
        self.spec.save_interval = interval.to_string();
        self
    }

    pub fn maxmemory(mut self, maxmemory: &str) -> Self {
        self.spec.maxmemory = Some(maxmemory.to_string());
        self
    }

    pub fn maxmemory_policy(mut self, policy: &str) -> Self {
        self.spec.maxmemory_policy = Some(policy.to_string());
        self
    }

    pub fn env(mut self, key: &str, value: &str) -> Self {
        self.spec.env.push((key.to_string(), value.to_string()));
        self
    }

    pub fn start(self) -> LuxServer {
        LuxServer::spawn(self.spec)
    }
}

/// A spawned Lux server with an isolated, auto-cleaned data directory.
pub struct LuxServer {
    pub port: u16,
    pub http_port: u16,
    child: Child,
    dir: TempDir,
    spec: Spec,
}

impl LuxServer {
    pub fn builder() -> LuxServerBuilder {
        LuxServerBuilder {
            spec: Spec::default(),
        }
    }

    /// Simplest server: in-memory, no auth, no HTTP.
    pub fn start() -> Self {
        Self::builder().start()
    }

    /// Tiered storage with the same crash-test defaults the suite relies on.
    pub fn start_tiered() -> Self {
        Self::builder().tiered().start()
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn http_port(&self) -> u16 {
        self.http_port
    }

    pub fn conn(&self) -> TcpStream {
        connect(self.port)
    }

    /// Path to this server's data directory (for tests that inspect on-disk
    /// state such as WAL files). The tiered storage lives under `storage/`.
    pub fn data_dir(&self) -> &Path {
        self.dir.path()
    }

    /// Kill without graceful shutdown (simulates a crash / power loss).
    pub fn kill(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
        thread::sleep(Duration::from_millis(300));
    }

    /// Restart against the same data directory on a fresh port.
    pub fn restart(&mut self) {
        self.restart_with_maxmemory("10mb");
    }

    pub fn restart_with_maxmemory(&mut self, maxmemory: &str) {
        self.child.kill().ok();
        self.child.wait().ok();
        thread::sleep(Duration::from_millis(500));
        let mut spec = self.spec.clone();
        spec.maxmemory = Some(maxmemory.to_string());
        let started = Self::spawn_with_dir(spec.clone(), self.dir.path());
        self.child = started.0;
        self.port = started.1;
        self.http_port = started.2;
        self.spec = spec;
    }

    fn spawn(spec: Spec) -> Self {
        let dir = tempfile::tempdir().expect("create temp data dir");
        let (child, port, http_port) = Self::spawn_with_dir(spec.clone(), dir.path());
        LuxServer {
            port,
            http_port,
            child,
            dir,
            spec,
        }
    }

    /// Spawn into `dir`, retrying on the rare event that a chosen ephemeral port
    /// was claimed between selection and bind.
    fn spawn_with_dir(spec: Spec, dir: &Path) -> (Child, u16, u16) {
        let bin = find_lux_binary();
        for _ in 0..5 {
            let ports = free_ports(if spec.http { 2 } else { 1 });
            let port = ports[0];
            let http_port = if spec.http { ports[1] } else { 0 };
            let mut child = build_command(&bin, &spec, dir, port, http_port)
                .spawn()
                .expect("spawn lux");
            if wait_for_ready(port, &mut child) {
                return (child, port, http_port);
            }
            child.kill().ok();
            child.wait().ok();
        }
        panic!("lux failed to start after retries");
    }
}

impl Drop for LuxServer {
    fn drop(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
        // `dir` (TempDir) cleans itself on drop.
    }
}

fn build_command(bin: &Path, spec: &Spec, dir: &Path, port: u16, http_port: u16) -> Command {
    let mut cmd = Command::new(bin);
    cmd.env("LUX_PORT", port.to_string())
        .env("LUX_SHARDS", spec.shards.to_string())
        .env("LUX_SAVE_INTERVAL", &spec.save_interval)
        .env("LUX_DATA_DIR", dir.to_str().unwrap())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if spec.http {
        cmd.env("LUX_HTTP_PORT", http_port.to_string());
    }
    if spec.mode == Mode::Tiered {
        cmd.env("LUX_STORAGE_MODE", "tiered")
            .env("LUX_STORAGE_DIR", dir.join("storage").to_str().unwrap());
    }
    if let Some(maxmemory) = &spec.maxmemory {
        cmd.env("LUX_MAXMEMORY", maxmemory);
    }
    if let Some(policy) = &spec.maxmemory_policy {
        cmd.env("LUX_MAXMEMORY_POLICY", policy);
    }
    if let Some(password) = &spec.password {
        // An empty password means "no auth" (same as not setting it).
        if !password.is_empty() {
            cmd.env("LUX_PASSWORD", password);
        }
    }
    for (key, value) in &spec.env {
        cmd.env(key, value);
    }
    cmd
}

/// Low-level spawn against a caller-owned data directory, for tests that restart
/// the server by hand (e.g. with different env between runs) while preserving
/// on-disk state. The caller manages the data dir and the child's lifetime.
pub fn spawn_lux_with_data_dir(
    resp_port: u16,
    http_port: u16,
    password: &str,
    env: &[(&str, &str)],
    data_dir: &Path,
) -> Child {
    let bin = find_lux_binary();
    let mut cmd = Command::new(&bin);
    cmd.env("LUX_PORT", resp_port.to_string())
        .env("LUX_HTTP_PORT", http_port.to_string())
        .env("LUX_SHARDS", "4")
        .env("LUX_SAVE_INTERVAL", "0")
        .env("LUX_DATA_DIR", data_dir.to_str().unwrap())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if !password.is_empty() {
        cmd.env("LUX_PASSWORD", password);
    }
    for (key, value) in env {
        cmd.env(key, value);
    }
    let mut child = cmd.spawn().expect("spawn lux");
    if !wait_for_ready(http_port, &mut child) {
        panic!("lux did not start on http port {http_port}");
    }
    child
}

/// Poll until the RESP port accepts a connection, bailing early if the child dies.
fn wait_for_ready(port: u16, child: &mut Child) -> bool {
    for _ in 0..100 {
        if let Ok(Some(_)) = child.try_wait() {
            return false;
        }
        if TcpStream::connect(format!("127.0.0.1:{port}")).is_ok() {
            return true;
        }
        thread::sleep(Duration::from_millis(50));
    }
    false
}

// ---------------------------------------------------------------------------
// HTTP client helper (for the HTTP API tests).
// ---------------------------------------------------------------------------

pub fn http_request(
    port: u16,
    method: &str,
    path: &str,
    body: Option<&str>,
    auth: Option<&str>,
) -> (u16, String) {
    http_request_with_headers(port, method, path, body, auth, &[])
}

pub fn http_request_with_headers(
    port: u16,
    method: &str,
    path: &str,
    body: Option<&str>,
    auth: Option<&str>,
    extra_headers: &[&str],
) -> (u16, String) {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    let body_str = body.unwrap_or("");
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
        body_str.len()
    );
    if let Some(token) = auth {
        req.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    for h in extra_headers {
        req.push_str(h);
        req.push_str("\r\n");
    }
    req.push_str("\r\n");
    req.push_str(body_str);

    stream.write_all(req.as_bytes()).unwrap();

    let mut response = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                response.extend_from_slice(&buf[..n]);
                if let Some(header_end) = response.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&response[..header_end]);
                    if let Some(cl_line) = headers
                        .lines()
                        .find(|l| l.to_lowercase().starts_with("content-length:"))
                    {
                        if let Some(cl) = cl_line
                            .split(':')
                            .nth(1)
                            .and_then(|v| v.trim().parse::<usize>().ok())
                        {
                            if response.len() >= header_end + 4 + cl {
                                break;
                            }
                        }
                    }
                    if headers
                        .to_lowercase()
                        .contains("transfer-encoding: chunked")
                        && response.windows(5).any(|w| w == b"0\r\n\r\n")
                    {
                        break;
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(_) => break,
        }
    }

    let resp = String::from_utf8_lossy(&response).to_string();
    let status = resp
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = resp
        .split_once("\r\n\r\n")
        .map(|x| x.1)
        .unwrap_or("")
        .to_string();
    (status, body)
}
