//! Library entry points for embedding Lux in another Rust process.
//!
//! The crate exposes the runtime surface (`ServerConfig`, `ServerHandle`,
//! `run_with_config`) and keeps command/storage internals private so embedded
//! callers cannot mutate state outside the normal command, WAL, and snapshot
//! pipeline.

mod cmd;
mod disk;
mod eviction;
mod geo;
mod hll;
mod hnsw;
mod http;
mod lua;
mod pubsub;
mod resp;
mod snapshot;
mod store;
mod tables;

use bytes::BytesMut;
use cmd::CmdResult;
use pubsub::Broker;
use resp::Parser;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use store::Store;
use tables::SharedSchemaCache;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};

pub use disk::{StorageConfig, StorageMode};
pub use eviction::{parse_eviction_policy, parse_memory_size, EvictionConfig, EvictionPolicy};

const SUB_MODE_BATCH_MAX: usize = 64;

/// Runtime configuration for an embedded Lux server.
///
/// Defaults match the standalone binary where possible. Library users can
/// override listeners, persistence, auth, eviction, and logging without relying
/// on process-wide environment variables.
#[derive(Clone)]
pub struct ServerConfig {
    /// Interface used by the RESP listener.
    pub bind_host: String,
    /// RESP port. When `enable_resp` is true, `0` asks the OS for any free port.
    pub port: u16,
    /// HTTP API port. `0` disables the HTTP API.
    pub http_port: u16,
    /// Optional row cap for HTTP table responses.
    pub max_rows: Option<usize>,
    /// Maximum accepted HTTP request body size in bytes.
    pub max_body: usize,
    /// Password used by AUTH/HELLO and HTTP bearer auth.
    pub password: String,
    /// Whether RESP connections must authenticate before non-public commands.
    pub require_auth: bool,
    /// Disables administrative commands such as SAVE/FLUSH/DEBUG.
    pub restricted: bool,
    /// Number of in-memory shards.
    pub shards: usize,
    /// Directory for snapshots and default storage subdirectories.
    pub data_dir: String,
    /// Background snapshot interval. `Duration::ZERO` disables background saves.
    pub save_interval: Duration,
    /// Persistence/storage mode configuration.
    pub storage: StorageConfig,
    /// Memory pressure eviction configuration.
    pub eviction: EvictionConfig,
    /// Enables the RESP listener. Use this instead of overloading `port = 0`.
    pub enable_resp: bool,
    /// Optional informational event sink. Library mode is silent when unset.
    pub on_info: Option<Arc<dyn Fn(ServerInfoEvent) + Send + Sync>>,
    /// Optional warning event sink for recovered or skipped conditions.
    pub on_warn: Option<Arc<dyn Fn(ServerWarnEvent) + Send + Sync>>,
    /// Optional error event sink for failed runtime operations.
    pub on_error: Option<Arc<dyn Fn(ServerErrorEvent) + Send + Sync>>,
}

impl std::fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConfig")
            .field("bind_host", &self.bind_host)
            .field("port", &self.port)
            .field("http_port", &self.http_port)
            .field("max_rows", &self.max_rows)
            .field("max_body", &self.max_body)
            .field("password", &"<redacted>")
            .field("require_auth", &self.require_auth)
            .field("restricted", &self.restricted)
            .field("shards", &self.shards)
            .field("data_dir", &self.data_dir)
            .field("save_interval", &self.save_interval)
            .field("storage", &self.storage)
            .field("eviction", &self.eviction)
            .field("enable_resp", &self.enable_resp)
            .field("on_info", &self.on_info.as_ref().map(|_| "<callback>"))
            .field("on_warn", &self.on_warn.as_ref().map(|_| "<callback>"))
            .field("on_error", &self.on_error.as_ref().map(|_| "<callback>"))
            .finish()
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_host: "0.0.0.0".to_string(),
            port: 6379,
            http_port: 0,
            max_rows: None,
            max_body: 64 * 1024 * 1024,
            password: String::new(),
            require_auth: false,
            restricted: false,
            shards: default_shard_count(),
            data_dir: ".".to_string(),
            save_interval: Duration::from_secs(60),
            storage: StorageConfig::default(),
            eviction: EvictionConfig::default(),
            enable_resp: true,
            on_info: None,
            on_warn: None,
            on_error: None,
        }
    }
}

/// Informational runtime events emitted through `ServerConfig::on_info`.
#[derive(Clone, Debug)]
pub enum ServerInfoEvent {
    /// Tiered storage was configured for this data directory.
    TieredStorageEnabled { dir: String },
    /// Snapshot file was absent during startup.
    NoSnapshotFound,
    /// Snapshot loaded successfully during startup.
    SnapshotLoaded { keys: usize },
    /// Background snapshot completed successfully.
    SnapshotSaved { keys: usize },
    /// WAL replay completed and applied at least one command.
    WalReplayed { commands: usize },
    /// HTTP listener bound successfully.
    HttpReady { addr: std::net::SocketAddr },
}

/// Warning runtime events emitted through `ServerConfig::on_warn`.
///
/// Warnings are conditions Lux recovered from, such as skipping corrupted
/// persisted data or dropping a single failed client connection.
#[derive(Clone, Debug)]
pub enum ServerWarnEvent {
    /// One checksummed WAL frame failed CRC validation and was skipped.
    WalCorruptedFrameSkipped {
        shard: usize,
        stored_crc: u32,
        computed_crc: u32,
    },
    /// Summary count for corrupted WAL frames skipped during replay.
    WalCorruptedFramesSkipped { shard: usize, frames: usize },
    /// One checksummed disk entry failed CRC validation during index rebuild.
    DiskCorruptedEntrySkipped { shard: usize, offset: u64 },
    /// One disk entry failed to deserialize during index rebuild.
    DiskEntryParseFailed {
        shard: usize,
        offset: u64,
        error: String,
    },
    /// Summary count for corrupted disk entries skipped while rebuilding.
    DiskCorruptedEntriesSkipped { shard: usize, entries: usize },
    /// RESP connection handler returned a non-reset I/O error.
    ConnectionFailed {
        peer: std::net::SocketAddr,
        error: String,
    },
}

/// Error runtime events emitted through `ServerConfig::on_error`.
///
/// Errors are failed runtime operations that may affect availability,
/// durability, or persistence.
#[derive(Clone, Debug)]
pub enum ServerErrorEvent {
    /// Snapshot load failed during startup.
    SnapshotLoadFailed { error: String },
    /// Background snapshot failed.
    SnapshotSaveFailed { error: String, path: String },
    /// WAL replay failed for a shard.
    WalReplayFailed { shard: usize, error: String },
    /// WAL truncate after snapshot failed.
    WalTruncateFailed { error: String },
    /// Eviction-to-disk failed; the key remains in memory.
    DiskEvictionWriteFailed { key: String, error: String },
    /// Opportunistic compaction on the eviction path failed.
    InlineCompactionFailed { error: String },
    /// Background disk compaction failed.
    DiskCompactionFailed { shard: usize, error: String },
    /// WAL append failed before an in-memory mutation was made durable.
    WalAppendFailed { error: String },
    /// Dumping cold data into a snapshot failed.
    SnapshotDiskDumpFailed { error: String },
    /// Periodic WAL fsync failed.
    WalFsyncFailed { error: String },
    /// HTTP server task returned an error after startup.
    HttpServerFailed { error: String },
}

/// Internal dispatch helpers keep emit sites explicit about severity while
/// preserving the library's silent-by-default behavior.
pub(crate) fn emit_info(config: &ServerConfig, event: ServerInfoEvent) {
    if let Some(on_info) = &config.on_info {
        on_info(event);
    }
}

pub(crate) fn emit_warn(config: &ServerConfig, event: ServerWarnEvent) {
    if let Some(on_warn) = &config.on_warn {
        on_warn(event);
    }
}

pub(crate) fn emit_error(config: &ServerConfig, event: ServerErrorEvent) {
    if let Some(on_error) = &config.on_error {
        on_error(event);
    }
}

impl ServerConfig {
    pub fn listen_addr(&self) -> String {
        format!("{}:{}", self.bind_host, self.port)
    }
}

pub struct ServerHandle {
    shutdown_tx: watch::Sender<bool>,
    server_task: JoinHandle<std::io::Result<()>>,
    local_addr: Option<std::net::SocketAddr>,
}

pub fn default_shard_count() -> usize {
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    (cpus * 16).next_power_of_two().clamp(16, 1024)
}

impl ServerHandle {
    pub fn local_addr(&self) -> Option<std::net::SocketAddr> {
        self.local_addr
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    pub async fn wait(self) -> std::io::Result<()> {
        match self.server_task.await {
            Ok(result) => result,
            Err(e) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("server task failed: {e}"),
            )),
        }
    }

    pub async fn shutdown_and_wait(self) -> std::io::Result<()> {
        self.shutdown();
        self.wait().await
    }
}

async fn recv_broadcast_batch(
    rx: &mut broadcast::Receiver<pubsub::Message>,
    max_batch: usize,
) -> Option<Vec<pubsub::Message>> {
    let first = loop {
        match rx.recv().await {
            Ok(msg) => break msg,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
        }
    };

    let mut batch = Vec::with_capacity(max_batch.min(8));
    batch.push(first);
    while batch.len() < max_batch {
        match rx.try_recv() {
            Ok(msg) => batch.push(msg),
            Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => continue,
            Err(tokio::sync::broadcast::error::TryRecvError::Empty) => break,
            Err(tokio::sync::broadcast::error::TryRecvError::Closed) => break,
        }
    }
    Some(batch)
}

/// Wait for a startup task to report readiness, treating a dropped sender as
/// startup failure
async fn wait_for_startup<T>(
    rx: oneshot::Receiver<std::io::Result<T>>,
    closed_message: &'static str,
) -> std::io::Result<T> {
    rx.await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, closed_message))?
}

pub async fn run() -> std::io::Result<()> {
    let handle = run_with_config(ServerConfig::default()).await?;
    handle.wait().await
}

/// Start a server and return only after startup work has completed.
///
/// Readiness means storage has initialized, any snapshot has loaded, WAL replay
/// has completed, and configured listeners have bound successfully.
pub async fn run_with_config(config: ServerConfig) -> std::io::Result<ServerHandle> {
    let listener = if config.enable_resp {
        let addr = config.listen_addr();
        Some(TcpListener::bind(&addr).await?)
    } else {
        None
    };
    let local_addr = if let Some(listener) = &listener {
        Some(listener.local_addr()?)
    } else {
        None
    };
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (ready_tx, ready_rx) = oneshot::channel();
    let server_task = tokio::spawn(server_main(listener, config, shutdown_rx, ready_tx));
    wait_for_startup(ready_rx, "server startup failed before readiness signal").await?;
    Ok(ServerHandle {
        shutdown_tx,
        server_task,
        local_addr,
    })
}

async fn server_main(
    listener: Option<TcpListener>,
    config: ServerConfig,
    mut shutdown_rx: watch::Receiver<bool>,
    ready_tx: oneshot::Sender<std::io::Result<()>>,
) -> std::io::Result<()> {
    let config = Arc::new(config);
    let store = Arc::new(Store::new_with_config(config.clone()));
    let schema_cache: SharedSchemaCache =
        std::sync::Arc::new(parking_lot::RwLock::new(tables::SchemaCache::new()));
    if config.storage.mode == StorageMode::Tiered {
        emit_info(
            &config,
            ServerInfoEvent::TieredStorageEnabled {
                dir: config.storage.dir.clone(),
            },
        );
    }
    let broker = Broker::new();
    let script_engine = Arc::new(lua::ScriptEngine::new());

    store
        .wal_suppress
        .store(true, std::sync::atomic::Ordering::Relaxed);
    match snapshot::load(&store) {
        Ok(0) => emit_info(&config, ServerInfoEvent::NoSnapshotFound),
        Ok(n) => emit_info(&config, ServerInfoEvent::SnapshotLoaded { keys: n }),
        Err(e) => emit_error(
            &config,
            ServerErrorEvent::SnapshotLoadFailed {
                error: e.to_string(),
            },
        ),
    }
    store
        .wal_suppress
        .store(false, std::sync::atomic::Ordering::Relaxed);
    store.replay_wal(&broker);

    let mut background_tasks = JoinSet::new();
    background_tasks.spawn(snapshot::background_save_loop(store.clone()));
    background_tasks.spawn(broker.clone().run_key_event_loop());

    {
        let store = store.clone();
        background_tasks.spawn(async move {
            let start = Instant::now();
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                let now = Instant::now();
                let secs = now.duration_since(start).as_secs() as u32;
                // Keep LRU aging scoped to this runtime; eviction decisions
                // should not depend on other embedded instances.
                store.set_lru_clock(secs & 0x00FF_FFFF);
                store.expire_sweep(now);
            }
        });
    }

    if config.storage.mode == StorageMode::Tiered {
        {
            let store = store.clone();
            background_tasks.spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    store.fsync_wal();
                }
            });
        }
        {
            let store = store.clone();
            background_tasks.spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                    store.compact_disk_shards();
                }
            });
        }
    }

    let mut http_startup_rx = None;
    if config.http_port > 0 {
        let http_store = store.clone();
        let http_broker = broker.clone();
        let http_cache = schema_cache.clone();
        let http_port = config.http_port;
        let max_rows = config.max_rows;
        let max_body = config.max_body;
        let (startup_tx, startup_rx) = oneshot::channel();
        http_startup_rx = Some(startup_rx);
        let on_ready = config.on_info.clone().map(|on_info| {
            Arc::new(move |addr| on_info(ServerInfoEvent::HttpReady { addr }))
                as Arc<dyn Fn(std::net::SocketAddr) + Send + Sync>
        });
        let on_error = config.on_error.clone();
        background_tasks.spawn(async move {
            if let Err(e) = http::start_http_server(
                http_port,
                http_store,
                http_broker,
                http_cache,
                max_rows,
                max_body,
                on_ready,
                Some(startup_tx),
            )
            .await
            {
                if let Some(on_error) = on_error {
                    on_error(ServerErrorEvent::HttpServerFailed {
                        error: e.to_string(),
                    });
                }
            }
        });
    }

    let mut conn_tasks = JoinSet::new();
    // HTTP binds inside its task, so wait for its one-shot before reporting the
    // whole runtime as ready to embedded callers.
    if let Some(http_startup_rx) = http_startup_rx {
        if let Err(e) = wait_for_startup(
            http_startup_rx,
            "http server startup failed before readiness signal",
        )
        .await
        {
            let ready_error = std::io::Error::new(e.kind(), e.to_string());
            let _ = ready_tx.send(Err(ready_error));
            return Err(e);
        }
    }
    let _ = ready_tx.send(Ok(()));

    if !config.enable_resp {
        let _ = shutdown_rx.changed().await;
    } else {
        let listener = listener.expect("listener must exist when RESP is enabled");
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    break;
                }
                accepted = listener.accept() => {
                    let (socket, peer) = accepted?;
                    let store = store.clone();
                    let broker = broker.clone();
                    let script_engine = script_engine.clone();
                    let schema_cache = schema_cache.clone();
                    let on_warn = config.on_warn.clone();
                    socket.set_nodelay(true).ok();

                    let require_auth = config.require_auth;
                    conn_tasks.spawn(async move {
                        store.client_connected();
                        let result = handle_connection(
                            socket,
                            peer,
                            store.clone(),
                            broker,
                            require_auth,
                            script_engine,
                            schema_cache,
                        )
                        .await;
                        store.client_disconnected();
                        if let Err(e) = result {
                            if e.kind() != std::io::ErrorKind::ConnectionReset {
                                if let Some(on_warn) = on_warn {
                                    on_warn(ServerWarnEvent::ConnectionFailed {
                                        peer,
                                        error: e.to_string(),
                                    });
                                }
                            }
                        }
                    });
                }
            }
        }
    }

    conn_tasks.abort_all();
    while conn_tasks.join_next().await.is_some() {}

    background_tasks.abort_all();
    while background_tasks.join_next().await.is_some() {}

    Ok(())
}

#[inline(always)]
fn cmd_eq_fast(input: &[u8], expected: &[u8]) -> bool {
    input.len() == expected.len()
        && input
            .iter()
            .zip(expected)
            .all(|(a, b)| a.to_ascii_uppercase() == *b)
}

#[inline(always)]
fn is_tx_cmd(cmd: &[u8]) -> bool {
    cmd_eq_fast(cmd, b"MULTI")
        || cmd_eq_fast(cmd, b"EXEC")
        || cmd_eq_fast(cmd, b"DISCARD")
        || cmd_eq_fast(cmd, b"WATCH")
        || cmd_eq_fast(cmd, b"UNWATCH")
}

#[inline(always)]
fn fire_key_events(broker: &Broker, args: &[&[u8]]) {
    if args.len() < 2 || !broker.has_key_subs() {
        return;
    }
    fire_key_events_slow(broker, args);
}

#[inline(never)]
fn fire_key_events_slow(broker: &Broker, args: &[&[u8]]) {
    let cmd = args[0];
    if !crate::eviction::is_write_command(cmd) {
        return;
    }
    if cmd_eq_fast(cmd, b"FLUSHDB") || cmd_eq_fast(cmd, b"FLUSHALL") {
        return;
    }

    if cmd_eq_fast(cmd, b"MSET") || cmd_eq_fast(cmd, b"MSETNX") {
        let mut i = 1;
        while i < args.len() {
            broker.enqueue_key_event(args[i], cmd);
            i += 2;
        }
    } else if cmd_eq_fast(cmd, b"DEL") || cmd_eq_fast(cmd, b"UNLINK") {
        for arg in &args[1..] {
            broker.enqueue_key_event(arg, cmd);
        }
    } else if cmd_eq_fast(cmd, b"RENAME") && args.len() >= 3 {
        broker.enqueue_key_event(args[1], cmd);
        broker.enqueue_key_event(args[2], cmd);
    } else {
        broker.enqueue_key_event(args[1], cmd);
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_tx_cmd(
    args: &[&[u8]],
    in_multi: &mut bool,
    tx_error: &mut bool,
    tx_queue: &mut Vec<Vec<Vec<u8>>>,
    watched: &mut Vec<(String, usize, u64)>,
    authenticated: &mut bool,
    store: &Arc<Store>,
    broker: &Broker,
    schema_cache: &SharedSchemaCache,
    write_buf: &mut BytesMut,
    now: Instant,
) -> bool {
    if cmd_eq_fast(args[0], b"MULTI") {
        if *in_multi {
            let cmd_name = std::str::from_utf8(args[0])
                .unwrap_or("multi")
                .to_lowercase();
            resp::write_error(
                write_buf,
                &format!(
                    "ERR Command '{}' not allowed inside a transaction",
                    cmd_name
                ),
            );
            *tx_error = true;
        } else {
            *in_multi = true;
            *tx_error = false;
            resp::write_ok(write_buf);
        }
        return true;
    } else if cmd_eq_fast(args[0], b"EXEC") {
        if !*in_multi {
            resp::write_error(write_buf, "ERR EXEC without MULTI");
        } else if *tx_error {
            resp::write_error(
                write_buf,
                "EXECABORT Transaction discarded because of previous errors.",
            );
        } else {
            let mut aborted = false;
            for (_, shard_idx, version) in watched.iter() {
                if store.shard_version(*shard_idx) != *version {
                    aborted = true;
                    break;
                }
            }
            if aborted {
                resp::write_null_array(write_buf);
            } else {
                let queue = std::mem::take(tx_queue);
                resp::write_array_header(write_buf, queue.len());
                for owned_args in &queue {
                    let refs: Vec<&[u8]> = owned_args.iter().map(|v| v.as_slice()).collect();
                    let cmd_result = {
                        let _guard = store.script_read_guard();
                        cmd::execute_with_wal(store, schema_cache, broker, &refs, write_buf, now)
                    };
                    match cmd_result {
                        CmdResult::Written => {}
                        CmdResult::Authenticated => {
                            *authenticated = true;
                        }
                        CmdResult::Subscribe { .. }
                        | CmdResult::PSubscribe { .. }
                        | CmdResult::KSubscribe { .. }
                        | CmdResult::KUnsubscribe { .. } => {
                            resp::write_error(
                                write_buf,
                                "ERR Command 'subscribe' not allowed inside a transaction",
                            );
                        }
                        CmdResult::Publish { channel, message } => {
                            let count = broker.publish(&channel, message);
                            resp::write_integer(write_buf, count);
                        }
                        CmdResult::BlockPop { .. }
                        | CmdResult::BlockMove { .. }
                        | CmdResult::BlockStreamRead { .. }
                        | CmdResult::BlockZPop { .. } => {
                            resp::write_error(
                                write_buf,
                                "ERR blocking commands not allowed inside a transaction",
                            );
                        }
                        CmdResult::Eval { .. } | CmdResult::ScriptOp => {
                            resp::write_error(write_buf, "ERR EVAL not supported in transaction");
                        }
                    }
                }
            }
        }
        *in_multi = false;
        *tx_error = false;
        tx_queue.clear();
        watched.clear();
        return true;
    } else if cmd_eq_fast(args[0], b"DISCARD") {
        if !*in_multi {
            resp::write_error(write_buf, "ERR DISCARD without MULTI");
        } else {
            *in_multi = false;
            *tx_error = false;
            tx_queue.clear();
            watched.clear();
            resp::write_ok(write_buf);
        }
        return true;
    } else if cmd_eq_fast(args[0], b"WATCH") {
        if *in_multi {
            resp::write_error(
                write_buf,
                "ERR Command 'watch' not allowed inside a transaction",
            );
            *tx_error = true;
        } else if args.len() < 2 {
            resp::write_error(
                write_buf,
                "ERR wrong number of arguments for 'watch' command",
            );
        } else {
            for key_bytes in &args[1..] {
                let key = std::str::from_utf8(key_bytes).unwrap_or("").to_string();
                let shard_idx = store.shard_for_key(key_bytes);
                let version = store.shard_version(shard_idx);
                watched.push((key, shard_idx, version));
            }
            resp::write_ok(write_buf);
        }
        return true;
    } else if cmd_eq_fast(args[0], b"UNWATCH") {
        watched.clear();
        resp::write_ok(write_buf);
        return true;
    }

    if *in_multi {
        if cmd_eq_fast(args[0], b"SUBSCRIBE")
            || cmd_eq_fast(args[0], b"PSUBSCRIBE")
            || cmd_eq_fast(args[0], b"KSUB")
            || cmd_eq_fast(args[0], b"KUNSUB")
        {
            resp::write_error(
                write_buf,
                &format!(
                    "ERR Command '{}' not allowed inside a transaction",
                    std::str::from_utf8(args[0])
                        .unwrap_or("subscribe")
                        .to_lowercase()
                ),
            );
            *tx_error = true;
        } else if is_blocking_cmd(args[0]) {
            resp::write_error(
                write_buf,
                &format!(
                    "ERR Command '{}' not allowed inside a transaction",
                    std::str::from_utf8(args[0])
                        .unwrap_or("unknown")
                        .to_lowercase()
                ),
            );
            *tx_error = true;
        } else if !cmd::is_known_command(args[0]) {
            let cmd_name = std::str::from_utf8(args[0])
                .unwrap_or("unknown")
                .to_lowercase();
            resp::write_error(write_buf, &format!("ERR unknown command '{cmd_name}'"));
            *tx_error = true;
        } else {
            match cmd::validate_args(args) {
                Ok(()) => {
                    let owned: Vec<Vec<u8>> = args.iter().map(|a| a.to_vec()).collect();
                    tx_queue.push(owned);
                    resp::write_queued(write_buf);
                }
                Err(e) => {
                    resp::write_error(write_buf, &e);
                    *tx_error = true;
                }
            }
        }
        return true;
    }

    false
}

#[inline(always)]
fn is_blocking_cmd(cmd: &[u8]) -> bool {
    cmd_eq_fast(cmd, b"BLPOP")
        || cmd_eq_fast(cmd, b"BRPOP")
        || cmd_eq_fast(cmd, b"BLMOVE")
        || cmd_eq_fast(cmd, b"BZPOPMIN")
        || cmd_eq_fast(cmd, b"BZPOPMAX")
        || cmd_eq_fast(cmd, b"EVAL")
        || cmd_eq_fast(cmd, b"EVALSHA")
        || cmd_eq_fast(cmd, b"SCRIPT")
}

async fn handle_connection(
    mut socket: tokio::net::TcpStream,
    _peer: std::net::SocketAddr,
    store: Arc<Store>,
    broker: Broker,
    require_auth: bool,
    script_engine: Arc<lua::ScriptEngine>,
    schema_cache: SharedSchemaCache,
) -> std::io::Result<()> {
    let mut read_buf = vec![0u8; 65536];
    let mut write_buf = BytesMut::with_capacity(65536);
    let mut pending = BytesMut::new();
    let mut subscriptions: HashMap<String, broadcast::Receiver<pubsub::Message>> = HashMap::new();
    let mut pattern_subs: HashMap<String, broadcast::Receiver<pubsub::Message>> = HashMap::new();
    let mut key_subs: HashMap<String, broadcast::Receiver<pubsub::Message>> = HashMap::new();
    let mut sub_mode = false;
    let mut authenticated = !require_auth;
    let mut in_multi = false;
    let mut tx_queue: Vec<Vec<Vec<u8>>> = Vec::new();
    let mut watched: Vec<(String, usize, u64)> = Vec::new();
    let mut tx_error = false;

    loop {
        if sub_mode {
            tokio::select! {
                result = socket.read(&mut read_buf) => {
                    let n = match result {
                        Ok(0) => return Ok(()),
                        Ok(n) => n,
                        Err(e) => return Err(e),
                    };
                    pending.extend_from_slice(&read_buf[..n]);
                    let now = Instant::now();
                    let mut parser = Parser::new(&pending);
                    while let Ok(Some(args)) = parser.parse_command() {
                        if args.is_empty() { continue; }
                        if cmd_eq_fast(args[0], b"SUBSCRIBE") {
                            for ch_bytes in &args[1..] {
                                let ch = std::str::from_utf8(ch_bytes).unwrap_or("").to_string();
                                if !subscriptions.contains_key(&ch) {
                                    let rx = broker.subscribe(&ch);
                                    subscriptions.insert(ch.clone(), rx);
                                }
                                resp::write_array_header(&mut write_buf, 3);
                                resp::write_bulk(&mut write_buf, "subscribe");
                                resp::write_bulk(&mut write_buf, &ch);
                                resp::write_integer(&mut write_buf, (subscriptions.len() + pattern_subs.len() + key_subs.len()) as i64);
                            }
                        } else if cmd_eq_fast(args[0], b"UNSUBSCRIBE") {
                            let channels: Vec<String> = if args.len() > 1 {
                                args[1..].iter().map(|a| std::str::from_utf8(a).unwrap_or("").to_string()).collect()
                            } else {
                                subscriptions.keys().cloned().collect()
                            };
                            for ch in &channels {
                                subscriptions.remove(ch);
                                resp::write_array_header(&mut write_buf, 3);
                                resp::write_bulk(&mut write_buf, "unsubscribe");
                                resp::write_bulk(&mut write_buf, ch);
                                resp::write_integer(&mut write_buf, (subscriptions.len() + pattern_subs.len() + key_subs.len()) as i64);
                            }
                            if subscriptions.is_empty() && pattern_subs.is_empty() {
                                sub_mode = false;
                            }
                        } else if cmd_eq_fast(args[0], b"PSUBSCRIBE") {
                            for pat_bytes in &args[1..] {
                                let pat = std::str::from_utf8(pat_bytes).unwrap_or("").to_string();
                                if !pattern_subs.contains_key(&pat) {
                                    let rx = broker.psubscribe(&pat);
                                    pattern_subs.insert(pat.clone(), rx);
                                }
                                resp::write_array_header(&mut write_buf, 3);
                                resp::write_bulk(&mut write_buf, "psubscribe");
                                resp::write_bulk(&mut write_buf, &pat);
                                resp::write_integer(&mut write_buf, (subscriptions.len() + pattern_subs.len() + key_subs.len()) as i64);
                            }
                        } else if cmd_eq_fast(args[0], b"PUNSUBSCRIBE") {
                            let patterns: Vec<String> = if args.len() > 1 {
                                args[1..].iter().map(|a| std::str::from_utf8(a).unwrap_or("").to_string()).collect()
                            } else {
                                pattern_subs.keys().cloned().collect()
                            };
                            for pat in &patterns {
                                pattern_subs.remove(pat);
                                resp::write_array_header(&mut write_buf, 3);
                                resp::write_bulk(&mut write_buf, "punsubscribe");
                                resp::write_bulk(&mut write_buf, pat);
                                resp::write_integer(&mut write_buf, (subscriptions.len() + pattern_subs.len() + key_subs.len()) as i64);
                            }
                            if subscriptions.is_empty() && pattern_subs.is_empty() && key_subs.is_empty() {
                                sub_mode = false;
                            }
                        } else if cmd_eq_fast(args[0], b"KSUB") {
                            if args.len() < 2 {
                                resp::write_error(&mut write_buf, "ERR wrong number of arguments for 'ksub' command");
                            } else {
                                for pat_bytes in &args[1..] {
                                    let pat = std::str::from_utf8(pat_bytes).unwrap_or("").to_string();
                                    if !key_subs.contains_key(&pat) {
                                        let rx = broker.ksubscribe(&pat);
                                        key_subs.insert(pat.clone(), rx);
                                    }
                                    resp::write_array_header(&mut write_buf, 3);
                                    resp::write_bulk(&mut write_buf, "ksub");
                                    resp::write_bulk(&mut write_buf, &pat);
                                    resp::write_integer(&mut write_buf, (subscriptions.len() + pattern_subs.len() + key_subs.len()) as i64);
                                }
                            }
                        } else if cmd_eq_fast(args[0], b"KUNSUB") {
                            let patterns: Vec<String> = if args.len() > 1 {
                                args[1..].iter().map(|a| std::str::from_utf8(a).unwrap_or("").to_string()).collect()
                            } else {
                                key_subs.keys().cloned().collect()
                            };
                            for pat in &patterns {
                                if key_subs.remove(pat).is_some() {
                                    broker.kunsub(pat);
                                }
                                resp::write_array_header(&mut write_buf, 3);
                                resp::write_bulk(&mut write_buf, "kunsub");
                                resp::write_bulk(&mut write_buf, pat);
                                resp::write_integer(&mut write_buf, (subscriptions.len() + pattern_subs.len() + key_subs.len()) as i64);
                            }
                            if subscriptions.is_empty() && pattern_subs.is_empty() && key_subs.is_empty() {
                                sub_mode = false;
                            }
                        } else if cmd_eq_fast(args[0], b"PING") {
                            if args.len() > 1 {
                                resp::write_bulk_raw(&mut write_buf, args[1]);
                            } else {
                                resp::write_pong(&mut write_buf);
                            }
                        } else {
                            resp::write_error(&mut write_buf, "ERR only SUBSCRIBE, UNSUBSCRIBE, and PING are allowed in subscribe mode");
                        }
                        let _ = now;
                    }
                    let consumed = parser.pos();
                    let _ = pending.split_to(consumed);
                    if !write_buf.is_empty() {
                        socket.write_all(&write_buf).await?;
                        write_buf.clear();
                    }
                }
                msg = async {
                    let total_subs = subscriptions.len() + pattern_subs.len() + key_subs.len();
                    if total_subs == 1 {
                        if let Some((_ch, rx)) = subscriptions.iter_mut().next() {
                            return recv_broadcast_batch(rx, SUB_MODE_BATCH_MAX).await;
                        }
                        if let Some((_pat, rx)) = pattern_subs.iter_mut().next() {
                            return recv_broadcast_batch(rx, SUB_MODE_BATCH_MAX).await;
                        }
                        if let Some((_pat, rx)) = key_subs.iter_mut().next() {
                            return recv_broadcast_batch(rx, SUB_MODE_BATCH_MAX).await;
                        }
                    }

                    for (_ch, rx) in subscriptions.iter_mut() {
                        if let Ok(msg) = rx.try_recv() {
                            return Some(vec![msg]);
                        }
                    }
                    for (_pat, rx) in pattern_subs.iter_mut() {
                        if let Ok(msg) = rx.try_recv() {
                            return Some(vec![msg]);
                        }
                    }
                    for (_pat, rx) in key_subs.iter_mut() {
                        if let Ok(msg) = rx.try_recv() {
                            return Some(vec![msg]);
                        }
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                    for (_ch, rx) in subscriptions.iter_mut() {
                        if let Ok(msg) = rx.try_recv() {
                            return Some(vec![msg]);
                        }
                    }
                    for (_pat, rx) in pattern_subs.iter_mut() {
                        if let Ok(msg) = rx.try_recv() {
                            return Some(vec![msg]);
                        }
                    }
                    for (_pat, rx) in key_subs.iter_mut() {
                        if let Ok(msg) = rx.try_recv() {
                            return Some(vec![msg]);
                        }
                    }
                    None
                } => {
                    if let Some(msgs) = msg {
                        for msg in msgs {
                            match msg.kind {
                                pubsub::MessageKind::KeyEvent => {
                                    resp::write_array_header(&mut write_buf, 4);
                                    resp::write_bulk(&mut write_buf, "kmessage");
                                    resp::write_bulk(&mut write_buf, msg.pattern.as_deref().unwrap_or(""));
                                    resp::write_bulk(&mut write_buf, &msg.channel);
                                    resp::write_bulk_raw(&mut write_buf, &msg.payload);
                                }
                                pubsub::MessageKind::PubSub => {
                                    if let Some(ref pat) = msg.pattern {
                                        resp::write_array_header(&mut write_buf, 4);
                                        resp::write_bulk(&mut write_buf, "pmessage");
                                        resp::write_bulk(&mut write_buf, pat);
                                        resp::write_bulk(&mut write_buf, &msg.channel);
                                        resp::write_bulk_raw(&mut write_buf, &msg.payload);
                                    } else {
                                        resp::write_array_header(&mut write_buf, 3);
                                        resp::write_bulk(&mut write_buf, "message");
                                        resp::write_bulk(&mut write_buf, &msg.channel);
                                        resp::write_bulk_raw(&mut write_buf, &msg.payload);
                                    }
                                }
                            }
                        }
                        socket.write_all(&write_buf).await?;
                        write_buf.clear();
                    }
                }
            }
        } else {
            let n = match socket.read(&mut read_buf).await {
                Ok(0) => return Ok(()),
                Ok(n) => n,
                Err(e) => return Err(e),
            };

            pending.extend_from_slice(&read_buf[..n]);
            let now = Instant::now();
            let mut parser = Parser::new(&pending);

            let mut commands: Vec<Vec<&[u8]>> = Vec::new();
            while let Ok(Some(args)) = parser.parse_command() {
                if args.is_empty() {
                    continue;
                }
                commands.push(args);
            }
            let consumed = parser.pos();

            let mut deferred_action: Option<CmdResult> = None;

            if commands.len() <= 1 {
                for args in &commands {
                    if !authenticated
                        && !cmd_eq_fast(args[0], b"AUTH")
                        && !cmd_eq_fast(args[0], b"HELLO")
                        && !cmd_eq_fast(args[0], b"PING")
                        && !cmd_eq_fast(args[0], b"QUIT")
                    {
                        resp::write_error(&mut write_buf, "NOAUTH Authentication required");
                        continue;
                    }
                    store.add_total_commands(1);

                    if handle_tx_cmd(
                        args,
                        &mut in_multi,
                        &mut tx_error,
                        &mut tx_queue,
                        &mut watched,
                        &mut authenticated,
                        &store,
                        &broker,
                        &schema_cache,
                        &mut write_buf,
                        now,
                    )
                    .await
                    {
                        continue;
                    }

                    let cmd_result = {
                        let _guard = store.script_read_guard();
                        cmd::execute_with_wal(
                            &store,
                            &schema_cache,
                            &broker,
                            args,
                            &mut write_buf,
                            now,
                        )
                    };
                    match cmd_result {
                        CmdResult::Written => {
                            fire_key_events(&broker, args);
                        }
                        CmdResult::Authenticated => {
                            authenticated = true;
                        }
                        CmdResult::Subscribe { channels } => {
                            for ch in &channels {
                                let rx = broker.subscribe(ch);
                                subscriptions.insert(ch.clone(), rx);
                                resp::write_array_header(&mut write_buf, 3);
                                resp::write_bulk(&mut write_buf, "subscribe");
                                resp::write_bulk(&mut write_buf, ch);
                                resp::write_integer(
                                    &mut write_buf,
                                    (subscriptions.len() + pattern_subs.len()) as i64,
                                );
                            }
                            sub_mode = true;
                            break;
                        }
                        CmdResult::PSubscribe { patterns } => {
                            for pat in &patterns {
                                let rx = broker.psubscribe(pat);
                                pattern_subs.insert(pat.clone(), rx);
                                resp::write_array_header(&mut write_buf, 3);
                                resp::write_bulk(&mut write_buf, "psubscribe");
                                resp::write_bulk(&mut write_buf, pat);
                                resp::write_integer(
                                    &mut write_buf,
                                    (subscriptions.len() + pattern_subs.len()) as i64,
                                );
                            }
                            sub_mode = true;
                            break;
                        }
                        CmdResult::KSubscribe { patterns } => {
                            for pat in &patterns {
                                if !key_subs.contains_key(pat) {
                                    let rx = broker.ksubscribe(pat);
                                    key_subs.insert(pat.clone(), rx);
                                }
                                resp::write_array_header(&mut write_buf, 3);
                                resp::write_bulk(&mut write_buf, "ksub");
                                resp::write_bulk(&mut write_buf, pat);
                                resp::write_integer(
                                    &mut write_buf,
                                    (subscriptions.len() + pattern_subs.len() + key_subs.len())
                                        as i64,
                                );
                            }
                            sub_mode = true;
                            break;
                        }
                        CmdResult::KUnsubscribe { patterns } => {
                            let pats: Vec<String> = if patterns.is_empty() {
                                key_subs.keys().cloned().collect()
                            } else {
                                patterns
                            };
                            for pat in &pats {
                                if key_subs.remove(pat).is_some() {
                                    broker.kunsub(pat);
                                }
                                resp::write_array_header(&mut write_buf, 3);
                                resp::write_bulk(&mut write_buf, "kunsub");
                                resp::write_bulk(&mut write_buf, pat);
                                resp::write_integer(
                                    &mut write_buf,
                                    (subscriptions.len() + pattern_subs.len() + key_subs.len())
                                        as i64,
                                );
                            }
                        }
                        CmdResult::Publish { channel, message } => {
                            let count = broker.publish(&channel, message);
                            resp::write_integer(&mut write_buf, count);
                        }
                        CmdResult::BlockPop { .. }
                        | CmdResult::BlockMove { .. }
                        | CmdResult::BlockStreamRead { .. }
                        | CmdResult::BlockZPop { .. } => {
                            deferred_action = Some(cmd_result);
                            break;
                        }
                        CmdResult::Eval { script, keys, argv } => {
                            handle_eval(
                                &mut write_buf,
                                &store,
                                &broker,
                                &script_engine,
                                &script,
                                &keys,
                                &argv,
                                now,
                            );
                        }
                        CmdResult::ScriptOp => {
                            let owned_args: Vec<Vec<u8>> =
                                args.iter().map(|a| a.to_vec()).collect();
                            let refs: Vec<&[u8]> =
                                owned_args.iter().map(|v| v.as_slice()).collect();
                            handle_script_op(&mut write_buf, &script_engine, &refs);
                        }
                    }
                }
            } else {
                let cmd_count = commands.len();
                store.add_total_commands(cmd_count);

                let mut has_special = in_multi;
                let mut all_single_key_rw = true;
                for args in &commands {
                    if !authenticated
                        && !cmd_eq_fast(args[0], b"AUTH")
                        && !cmd_eq_fast(args[0], b"HELLO")
                        && !cmd_eq_fast(args[0], b"PING")
                        && !cmd_eq_fast(args[0], b"QUIT")
                    {
                        has_special = true;
                        break;
                    }
                    if cmd_eq_fast(args[0], b"SUBSCRIBE")
                        || cmd_eq_fast(args[0], b"PSUBSCRIBE")
                        || cmd_eq_fast(args[0], b"KSUB")
                        || cmd_eq_fast(args[0], b"KUNSUB")
                        || cmd_eq_fast(args[0], b"PUBLISH")
                        || cmd_eq_fast(args[0], b"AUTH")
                        || is_tx_cmd(args[0])
                        || is_blocking_cmd(args[0])
                    {
                        has_special = true;
                        break;
                    }
                    if args.len() < 2
                        || cmd_eq_fast(args[0], b"MGET")
                        || cmd_eq_fast(args[0], b"MSET")
                        || cmd_eq_fast(args[0], b"DEL")
                        || cmd_eq_fast(args[0], b"EXISTS")
                        || cmd_eq_fast(args[0], b"KEYS")
                        || cmd_eq_fast(args[0], b"SCAN")
                        || cmd_eq_fast(args[0], b"FLUSHDB")
                        || cmd_eq_fast(args[0], b"FLUSHALL")
                        || cmd_eq_fast(args[0], b"DBSIZE")
                        || cmd_eq_fast(args[0], b"SAVE")
                        || cmd_eq_fast(args[0], b"INFO")
                        || cmd_eq_fast(args[0], b"RENAME")
                        || cmd_eq_fast(args[0], b"SUNION")
                        || cmd_eq_fast(args[0], b"SINTER")
                        || cmd_eq_fast(args[0], b"SDIFF")
                        || cmd_eq_fast(args[0], b"ZUNIONSTORE")
                        || cmd_eq_fast(args[0], b"ZINTERSTORE")
                        || cmd_eq_fast(args[0], b"ZDIFFSTORE")
                    {
                        all_single_key_rw = false;
                    }
                }

                if has_special || !all_single_key_rw {
                    for args in &commands {
                        if !authenticated
                            && !cmd_eq_fast(args[0], b"AUTH")
                            && !cmd_eq_fast(args[0], b"PING")
                            && !cmd_eq_fast(args[0], b"QUIT")
                        {
                            resp::write_error(&mut write_buf, "NOAUTH Authentication required");
                            continue;
                        }

                        if handle_tx_cmd(
                            args,
                            &mut in_multi,
                            &mut tx_error,
                            &mut tx_queue,
                            &mut watched,
                            &mut authenticated,
                            &store,
                            &broker,
                            &schema_cache,
                            &mut write_buf,
                            now,
                        )
                        .await
                        {
                            continue;
                        }

                        let cmd_result = {
                            let _guard = store.script_read_guard();
                            cmd::execute_with_wal(
                                &store,
                                &schema_cache,
                                &broker,
                                args,
                                &mut write_buf,
                                now,
                            )
                        };
                        match cmd_result {
                            CmdResult::Written => {
                                fire_key_events(&broker, args);
                            }
                            CmdResult::Authenticated => {
                                authenticated = true;
                            }
                            CmdResult::Subscribe { channels } => {
                                for ch in &channels {
                                    let rx = broker.subscribe(ch);
                                    subscriptions.insert(ch.clone(), rx);
                                    resp::write_array_header(&mut write_buf, 3);
                                    resp::write_bulk(&mut write_buf, "subscribe");
                                    resp::write_bulk(&mut write_buf, ch);
                                    resp::write_integer(
                                        &mut write_buf,
                                        (subscriptions.len() + pattern_subs.len()) as i64,
                                    );
                                }
                                sub_mode = true;
                                break;
                            }
                            CmdResult::PSubscribe { patterns } => {
                                for pat in &patterns {
                                    let rx = broker.psubscribe(pat);
                                    pattern_subs.insert(pat.clone(), rx);
                                    resp::write_array_header(&mut write_buf, 3);
                                    resp::write_bulk(&mut write_buf, "psubscribe");
                                    resp::write_bulk(&mut write_buf, pat);
                                    resp::write_integer(
                                        &mut write_buf,
                                        (subscriptions.len() + pattern_subs.len()) as i64,
                                    );
                                }
                                sub_mode = true;
                                break;
                            }
                            CmdResult::KSubscribe { patterns } => {
                                for pat in &patterns {
                                    if !key_subs.contains_key(pat) {
                                        let rx = broker.ksubscribe(pat);
                                        key_subs.insert(pat.clone(), rx);
                                    }
                                    resp::write_array_header(&mut write_buf, 3);
                                    resp::write_bulk(&mut write_buf, "ksub");
                                    resp::write_bulk(&mut write_buf, pat);
                                    resp::write_integer(
                                        &mut write_buf,
                                        (subscriptions.len() + pattern_subs.len() + key_subs.len())
                                            as i64,
                                    );
                                }
                                sub_mode = true;
                                break;
                            }
                            CmdResult::KUnsubscribe { patterns } => {
                                let pats: Vec<String> = if patterns.is_empty() {
                                    key_subs.keys().cloned().collect()
                                } else {
                                    patterns
                                };
                                for pat in &pats {
                                    if key_subs.remove(pat).is_some() {
                                        broker.kunsub(pat);
                                    }
                                    resp::write_array_header(&mut write_buf, 3);
                                    resp::write_bulk(&mut write_buf, "kunsub");
                                    resp::write_bulk(&mut write_buf, pat);
                                    resp::write_integer(
                                        &mut write_buf,
                                        (subscriptions.len() + pattern_subs.len() + key_subs.len())
                                            as i64,
                                    );
                                }
                            }
                            CmdResult::Publish { channel, message } => {
                                let count = broker.publish(&channel, message);
                                resp::write_integer(&mut write_buf, count);
                            }
                            CmdResult::BlockPop { .. }
                            | CmdResult::BlockMove { .. }
                            | CmdResult::BlockStreamRead { .. }
                            | CmdResult::BlockZPop { .. } => {
                                deferred_action = Some(cmd_result);
                                break;
                            }
                            CmdResult::Eval { script, keys, argv } => {
                                handle_eval(
                                    &mut write_buf,
                                    &store,
                                    &broker,
                                    &script_engine,
                                    &script,
                                    &keys,
                                    &argv,
                                    now,
                                );
                            }
                            CmdResult::ScriptOp => {
                                let owned_args: Vec<Vec<u8>> =
                                    args.iter().map(|a| a.to_vec()).collect();
                                let refs: Vec<&[u8]> =
                                    owned_args.iter().map(|v| v.as_slice()).collect();
                                handle_script_op(&mut write_buf, &script_engine, &refs);
                            }
                        }
                    }
                } else {
                    const FL_NONE: u8 = 0;
                    const FL_READ: u8 = 1;
                    const FL_WRITE: u8 = 2;

                    let mut shards: Vec<u32> = Vec::with_capacity(cmd_count);
                    let mut flags: Vec<u8> = Vec::with_capacity(cmd_count);
                    for args in &commands {
                        shards.push(store.shard_for_key(args[1]) as u32);
                        let cmd = args[0];
                        flags.push(
                            if cmd_eq_fast(cmd, b"GET")
                                || cmd_eq_fast(cmd, b"STRLEN")
                                || cmd_eq_fast(cmd, b"LLEN")
                                || cmd_eq_fast(cmd, b"SCARD")
                                || cmd_eq_fast(cmd, b"HGET")
                                || cmd_eq_fast(cmd, b"HLEN")
                                || cmd_eq_fast(cmd, b"ZCARD")
                                || cmd_eq_fast(cmd, b"ZSCORE")
                                || cmd_eq_fast(cmd, b"TTL")
                                || cmd_eq_fast(cmd, b"PTTL")
                                || cmd_eq_fast(cmd, b"TYPE")
                            {
                                FL_READ
                            } else if cmd_eq_fast(cmd, b"SET")
                                || cmd_eq_fast(cmd, b"INCR")
                                || cmd_eq_fast(cmd, b"DECR")
                                || cmd_eq_fast(cmd, b"INCRBY")
                                || cmd_eq_fast(cmd, b"DECRBY")
                                || cmd_eq_fast(cmd, b"LPUSH")
                                || cmd_eq_fast(cmd, b"RPUSH")
                                || cmd_eq_fast(cmd, b"LPOP")
                                || cmd_eq_fast(cmd, b"RPOP")
                                || cmd_eq_fast(cmd, b"SADD")
                                || cmd_eq_fast(cmd, b"SREM")
                                || cmd_eq_fast(cmd, b"SPOP")
                                || cmd_eq_fast(cmd, b"HSET")
                                || cmd_eq_fast(cmd, b"HDEL")
                                || cmd_eq_fast(cmd, b"ZADD")
                                || cmd_eq_fast(cmd, b"ZREM")
                                || cmd_eq_fast(cmd, b"ZPOPMIN")
                                || cmd_eq_fast(cmd, b"ZPOPMAX")
                            {
                                FL_WRITE
                            } else {
                                FL_NONE
                            },
                        );
                    }

                    let mut i = 0usize;
                    while i < cmd_count {
                        let shard_idx = shards[i];
                        let mut batch_end = i + 1;
                        while batch_end < cmd_count && shards[batch_end] == shard_idx {
                            batch_end += 1;
                        }

                        let batch_flags = &flags[i..batch_end];
                        let all_classified = batch_flags.iter().all(|&f| f != FL_NONE);

                        if all_classified {
                            let has_writes = batch_flags.contains(&FL_WRITE);
                            if has_writes {
                                for args in &commands[i..batch_end] {
                                    if args.len() > 1 {
                                        store.try_promote(args[1], now);
                                    }
                                    if args.len() > 1 && crate::eviction::is_write_command(args[0])
                                    {
                                        store.wal_log_command(args);
                                    }
                                }
                                {
                                    let mut shard = store.lock_write_shard(shard_idx as usize);
                                    shard.version += 1;
                                    for args in &commands[i..batch_end] {
                                        cmd::execute_on_shard(
                                            &mut shard.data,
                                            &store,
                                            &broker,
                                            args,
                                            &mut write_buf,
                                            now,
                                        );
                                    }
                                }
                                if broker.has_key_subs() {
                                    for idx in i..batch_end {
                                        if batch_flags[idx - i] == FL_WRITE {
                                            let cmd_args = &commands[idx];
                                            broker.enqueue_key_event(cmd_args[1], cmd_args[0]);
                                        }
                                    }
                                }
                            } else {
                                let shard = store.lock_read_shard(shard_idx as usize);
                                for args in &commands[i..batch_end] {
                                    cmd::execute_on_shard_read(
                                        &shard.data,
                                        args,
                                        &mut write_buf,
                                        now,
                                    );
                                }
                            }
                        } else {
                            for args in &commands[i..batch_end] {
                                cmd::execute_with_wal(
                                    &store,
                                    &schema_cache,
                                    &broker,
                                    args,
                                    &mut write_buf,
                                    now,
                                );
                                fire_key_events(&broker, args);
                            }
                        }

                        i = batch_end;
                    }
                }
            }

            drop(commands);
            let _ = pending.split_to(consumed);

            if !write_buf.is_empty() {
                socket.write_all(&write_buf).await?;
                write_buf.clear();
            }

            if let Some(action) = deferred_action {
                match action {
                    CmdResult::BlockPop {
                        keys,
                        timeout,
                        pop_left,
                    } => {
                        handle_block_pop(&mut socket, &store, &broker, &keys, timeout, pop_left)
                            .await?;
                    }
                    CmdResult::BlockMove {
                        src,
                        dst,
                        src_left,
                        dst_left,
                        timeout,
                    } => {
                        handle_block_move(
                            &mut socket,
                            &store,
                            &broker,
                            &src,
                            &dst,
                            src_left,
                            dst_left,
                            timeout,
                        )
                        .await?;
                    }
                    CmdResult::BlockStreamRead {
                        keys,
                        ids,
                        group,
                        count,
                        noack,
                        timeout,
                    } => {
                        handle_block_stream_read(
                            &mut socket,
                            &store,
                            &broker,
                            &keys,
                            &ids,
                            group,
                            count,
                            noack,
                            timeout,
                        )
                        .await?;
                    }
                    CmdResult::BlockZPop {
                        keys,
                        timeout,
                        pop_min,
                    } => {
                        handle_block_zpop(&mut socket, &store, &keys, timeout, pop_min).await?;
                    }
                    _ => {}
                }
            }
        }
    }
}

async fn handle_block_pop(
    socket: &mut tokio::net::TcpStream,
    _store: &Arc<Store>,
    broker: &Broker,
    keys: &[String],
    timeout: std::time::Duration,
    pop_left: bool,
) -> std::io::Result<()> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<(String, bytes::Bytes)>(1);
    let waiter_id = broker.next_waiter_id();

    for key in keys {
        broker.register_list_waiter(
            key,
            pubsub::BlockedPopRequest {
                tx: tx.clone(),
                pop_left,
                waiter_id,
            },
        );
    }
    drop(tx);

    let mut write_buf = BytesMut::new();
    let result = tokio::select! {
        val = rx.recv() => val,
        _ = tokio::time::sleep(timeout) => None,
    };

    match result {
        Some((key, val)) => {
            resp::write_array_header(&mut write_buf, 2);
            resp::write_bulk(&mut write_buf, &key);
            resp::write_bulk_raw(&mut write_buf, &val);
        }
        None => {
            resp::write_null_array(&mut write_buf);
        }
    }

    broker.remove_list_waiters_by_id(keys, waiter_id);

    socket.write_all(&write_buf).await
}

#[allow(clippy::too_many_arguments)]
async fn handle_block_move(
    socket: &mut tokio::net::TcpStream,
    store: &Arc<Store>,
    broker: &Broker,
    src: &str,
    dst: &str,
    src_left: bool,
    dst_left: bool,
    timeout: std::time::Duration,
) -> std::io::Result<()> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<(String, bytes::Bytes)>(1);
    let waiter_id = broker.next_waiter_id();

    broker.register_list_waiter(
        src,
        pubsub::BlockedPopRequest {
            tx: tx.clone(),
            pop_left: src_left,
            waiter_id,
        },
    );
    drop(tx);

    let mut write_buf = BytesMut::new();
    let result = tokio::select! {
        val = rx.recv() => val,
        _ = tokio::time::sleep(timeout) => None,
    };

    match result {
        Some((_key, val)) => {
            let now = Instant::now();
            let vals: &[&[u8]] = &[val.as_ref()];
            if dst_left {
                let _ = store.lpush(dst.as_bytes(), vals, now);
            } else {
                let _ = store.rpush(dst.as_bytes(), vals, now);
            }
            resp::write_bulk_raw(&mut write_buf, &val);
        }
        None => {
            resp::write_null(&mut write_buf);
        }
    }

    broker.remove_list_waiters_by_id(&[src.to_string()], waiter_id);

    socket.write_all(&write_buf).await
}

#[allow(clippy::too_many_arguments)]
async fn handle_block_stream_read(
    socket: &mut tokio::net::TcpStream,
    store: &Arc<Store>,
    broker: &Broker,
    keys: &[String],
    id_strs: &[String],
    group: Option<(String, String)>,
    count: Option<usize>,
    noack: bool,
    timeout: std::time::Duration,
) -> std::io::Result<()> {
    let now_pre = Instant::now();
    let resolved_ids: Vec<String> = id_strs
        .iter()
        .enumerate()
        .map(|(idx, s)| {
            if s == "$" {
                store
                    .stream_last_id(keys[idx].as_bytes(), now_pre)
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "0-0".to_string())
            } else {
                s.clone()
            }
        })
        .collect();

    let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);
    for key in keys {
        broker.register_stream_waiter(key, tx.clone());
    }
    drop(tx);

    let mut write_buf = BytesMut::new();
    let woken = tokio::select! {
        _ = rx.recv() => true,
        _ = tokio::time::sleep(timeout) => false,
    };

    if woken {
        let now = Instant::now();
        let result = if let Some((ref grp, ref consumer)) = group {
            store.xreadgroup(grp, consumer, keys, &resolved_ids, count, noack, now)
        } else {
            let ids: Vec<store::StreamId> = resolved_ids
                .iter()
                .map(|s| store::StreamId::parse(s).unwrap_or(store::StreamId::zero()))
                .collect();
            store.xread(keys, &ids, count, now)
        };

        match result {
            Ok(r) if !r.is_empty() => {
                write_xread_response(&mut write_buf, &r);
            }
            _ => {
                resp::write_null_array(&mut write_buf);
            }
        }
    } else {
        resp::write_null_array(&mut write_buf);
    }

    socket.write_all(&write_buf).await
}

#[allow(clippy::type_complexity)]
fn write_xread_response(
    out: &mut BytesMut,
    result: &[(String, Vec<(store::StreamId, Vec<(String, bytes::Bytes)>)>)],
) {
    resp::write_array_header(out, result.len());
    for (key, entries) in result {
        resp::write_array_header(out, 2);
        resp::write_bulk(out, key);
        resp::write_array_header(out, entries.len());
        for (id, fields) in entries {
            resp::write_array_header(out, 2);
            resp::write_bulk(out, &id.to_string());
            resp::write_array_header(out, fields.len() * 2);
            for (k, v) in fields {
                resp::write_bulk(out, k);
                resp::write_bulk_raw(out, v);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_eval(
    out: &mut BytesMut,
    store: &Arc<Store>,
    broker: &Broker,
    script_engine: &lua::ScriptEngine,
    script: &str,
    keys: &[Vec<u8>],
    argv: &[Vec<u8>],
    now: Instant,
) {
    let actual_script = if let Some(sha) = script.strip_prefix("__SHA:") {
        match script_engine.get(sha) {
            Some(s) => s,
            None => {
                resp::write_error(out, "NOSCRIPT No matching script. Use EVAL.");
                return;
            }
        }
    } else {
        script_engine.load(script);
        script.to_string()
    };

    let _guard = store.script_write_guard();
    match lua::eval(&actual_script, keys, argv, store, broker, now) {
        Ok(result) => {
            out.extend_from_slice(&result);
        }
        Err(e) => {
            resp::write_error(out, &e);
        }
    }
}

async fn handle_block_zpop(
    socket: &mut tokio::net::TcpStream,
    store: &Arc<Store>,
    keys: &[String],
    timeout: std::time::Duration,
    pop_min: bool,
) -> std::io::Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut write_buf = BytesMut::new();

    loop {
        let now = Instant::now();
        for key in keys {
            let result = if pop_min {
                store.zpopmin(key.as_bytes(), 1, now)
            } else {
                store.zpopmax(key.as_bytes(), 1, now)
            };
            if let Ok(items) = result {
                if !items.is_empty() {
                    let (member, score) = &items[0];
                    resp::write_array_header(&mut write_buf, 3);
                    resp::write_bulk(&mut write_buf, key);
                    resp::write_bulk(&mut write_buf, member);
                    let score_str = if score.fract() == 0.0 && score.abs() < 1e15 {
                        format!("{}", *score as i64)
                    } else {
                        format!("{}", score)
                    };
                    resp::write_bulk(&mut write_buf, &score_str);
                    return socket.write_all(&write_buf).await;
                }
            }
        }

        if tokio::time::Instant::now() >= deadline {
            resp::write_null_array(&mut write_buf);
            return socket.write_all(&write_buf).await;
        }

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

fn handle_script_op(out: &mut BytesMut, script_engine: &lua::ScriptEngine, args: &[&[u8]]) {
    if args.len() < 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'script' command");
        return;
    }
    let sub = std::str::from_utf8(args[1]).unwrap_or("").to_uppercase();
    match sub.as_str() {
        "LOAD" => {
            if args.len() < 3 {
                resp::write_error(
                    out,
                    "ERR wrong number of arguments for 'script|load' command",
                );
                return;
            }
            let script = std::str::from_utf8(args[2]).unwrap_or("");
            let sha = script_engine.load(script);
            resp::write_bulk(out, &sha);
        }
        "EXISTS" => {
            let count = args.len() - 2;
            resp::write_array_header(out, count);
            for arg in &args[2..] {
                let sha = std::str::from_utf8(arg).unwrap_or("").to_lowercase();
                resp::write_integer(out, if script_engine.exists(&sha) { 1 } else { 0 });
            }
        }
        "FLUSH" => {
            script_engine.flush();
            resp::write_ok(out);
        }
        _ => {
            resp::write_error(out, &format!("ERR unknown subcommand '{}'", sub));
        }
    }
}
