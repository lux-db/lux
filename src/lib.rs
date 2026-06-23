//! Library entry points for embedding Lux in another Rust process.
//!
//! The crate exposes the runtime surface (`ServerConfig`, `ServerHandle`,
//! `run_with_config`) and keeps command/storage internals private so embedded
//! callers cannot mutate state outside the normal command, WAL, and snapshot
//! pipeline.

mod auth;
mod cmd;
mod command;
mod disk;
mod embedded;
mod eviction;
#[cfg(feature = "fuzzing")]
pub mod fuzz_api;
mod geo;
mod grants;
mod hll;
mod hnsw;
mod http;
mod jsonb;
mod lua;
mod pubsub;
mod resp;
mod shard_exec;
mod snapshot;
mod store;
mod tables;

use bytes::BytesMut;
use cmd::CmdResult;
use command::{Command, CommandKind, CommandOutput, PubSubCommand, SetOption};
use pubsub::Broker;
use resp::Parser;
use shard_exec::{ShardExecutionError, ShardExecutor, ShardPipelineCommand};
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
pub use embedded::{
    EmbeddedPipeline, GeoMember, GeoPosition, GeoUnit, PreparedPipeline, RedisKeyType,
    ScoredMember, SetOptions,
};
pub use eviction::{parse_eviction_policy, parse_memory_size, EvictionConfig, EvictionPolicy};

const SUB_MODE_BATCH_MAX: usize = 64;
#[derive(Debug, Clone)]
pub enum LuxError {
    Command(String),
    InvalidCommand(String),
    Protocol(String),
    Unsupported(String),
    SubscriptionClosed,
    SubscriptionLagged(u64),
}

impl std::fmt::Display for LuxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LuxError::Command(msg) => write!(f, "{msg}"),
            LuxError::InvalidCommand(msg) => write!(f, "{msg}"),
            LuxError::Protocol(msg) => write!(f, "{msg}"),
            LuxError::Unsupported(msg) => write!(f, "{msg}"),
            LuxError::SubscriptionClosed => write!(f, "subscription closed"),
            LuxError::SubscriptionLagged(skipped) => {
                write!(f, "subscription lagged by {skipped} message(s)")
            }
        }
    }
}

impl std::error::Error for LuxError {}

/// Runtime configuration for per-project Lux Auth.
#[derive(Clone)]
pub struct AuthConfig {
    /// Enables app-user auth, reserved auth tables, and `/auth/v1/*`.
    pub enabled: bool,
    /// Issuer used in access tokens.
    pub issuer: String,
    /// Access-token lifetime.
    pub access_token_ttl: Duration,
    /// Refresh-token lifetime.
    pub refresh_token_ttl: Duration,
    /// Enables native email/password signup and sign-in.
    pub email_password_enabled: bool,
    /// Enables accountless `signInAnonymously` sessions.
    pub anonymous_enabled: bool,
    /// Optional initial publishable key material for local/bootstrap use.
    pub initial_publishable_key: Option<String>,
    /// Optional initial secret key material for local/bootstrap use.
    pub initial_secret_key: Option<String>,
}

impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthConfig")
            .field("enabled", &self.enabled)
            .field("issuer", &self.issuer)
            .field("access_token_ttl", &self.access_token_ttl)
            .field("refresh_token_ttl", &self.refresh_token_ttl)
            .field("email_password_enabled", &self.email_password_enabled)
            .field("anonymous_enabled", &self.anonymous_enabled)
            .field(
                "initial_publishable_key",
                &self.initial_publishable_key.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "initial_secret_key",
                &self.initial_secret_key.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            issuer: "http://localhost:7379/auth/v1".to_string(),
            access_token_ttl: Duration::from_secs(3600),
            refresh_token_ttl: Duration::from_secs(30 * 24 * 60 * 60),
            email_password_enabled: true,
            anonymous_enabled: true,
            initial_publishable_key: None,
            initial_secret_key: None,
        }
    }
}

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
    /// Maximum buffered RESP request bytes accepted from one connection.
    pub max_resp_request: usize,
    /// Password used by AUTH/HELLO and HTTP bearer auth.
    pub password: String,
    /// Whether RESP connections must authenticate before non-public commands.
    pub require_auth: bool,
    /// Allows unauthenticated listeners on non-loopback interfaces.
    ///
    /// This is intentionally explicit because the safe default is to reject
    /// remotely reachable unauthenticated deployments.
    pub allow_insecure_no_auth: bool,
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
    /// Per-project application auth configuration.
    pub auth: AuthConfig,
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
            .field("max_resp_request", &self.max_resp_request)
            .field("password", &"<redacted>")
            .field("require_auth", &self.require_auth)
            .field("allow_insecure_no_auth", &self.allow_insecure_no_auth)
            .field("restricted", &self.restricted)
            .field("shards", &self.shards)
            .field("data_dir", &self.data_dir)
            .field("save_interval", &self.save_interval)
            .field("storage", &self.storage)
            .field("eviction", &self.eviction)
            .field("auth", &self.auth)
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
            bind_host: "127.0.0.1".to_string(),
            port: 6379,
            http_port: 0,
            max_rows: None,
            max_body: 64 * 1024 * 1024,
            max_resp_request: 64 * 1024 * 1024,
            password: String::new(),
            require_auth: false,
            allow_insecure_no_auth: false,
            restricted: false,
            shards: default_shard_count(),
            data_dir: ".".to_string(),
            save_interval: Duration::from_secs(60),
            storage: StorageConfig::default(),
            eviction: EvictionConfig::default(),
            auth: AuthConfig::default(),
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

fn is_loopback_bind_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|addr| addr.is_loopback())
}

fn validate_listener_security(config: &ServerConfig) -> std::io::Result<()> {
    if config.allow_insecure_no_auth || is_loopback_bind_host(&config.bind_host) {
        return Ok(());
    }

    let resp_exposed_without_auth =
        config.enable_resp && (config.password.is_empty() || !config.require_auth);
    let http_exposed_without_auth = config.http_port != 0 && config.password.is_empty();
    if resp_exposed_without_auth || http_exposed_without_auth {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "refusing unauthenticated non-loopback listener; set a password or explicitly enable allow_insecure_no_auth",
        ));
    }
    Ok(())
}

fn validate_auth_config(config: &ServerConfig) -> std::io::Result<()> {
    if !config.auth.enabled {
        return Ok(());
    }
    if config.auth.issuer.trim().is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "auth issuer must not be empty when auth is enabled",
        ));
    }
    if config.auth.access_token_ttl.is_zero() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "auth access token ttl must be greater than zero",
        ));
    }
    if config.auth.refresh_token_ttl.is_zero() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "auth refresh token ttl must be greater than zero",
        ));
    }
    Ok(())
}

/// Reject shard counts that would crash or misbehave at runtime: zero shards
/// makes the `fx_hash(key) % shards.len()` routing divide by zero, and an
/// absurdly large count wastes memory on per-shard locks for no benefit.
fn validate_shard_count(config: &ServerConfig) -> std::io::Result<()> {
    if config.shards == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "shard count must be greater than zero",
        ));
    }
    if config.shards > 65_536 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "shard count must not exceed 65536",
        ));
    }
    Ok(())
}

pub struct ServerHandle {
    #[allow(dead_code)]
    runtime: Arc<Runtime>,
    shutdown_tx: watch::Sender<bool>,
    server_task: JoinHandle<std::io::Result<()>>,
    local_addr: Option<std::net::SocketAddr>,
}

/// Native client for executing Redis commands against an embedded Lux runtime.
///
/// `EmbeddedClient` has no public fields. Clone it when independent session
/// state is needed; clones share the same runtime, store, pub/sub broker, WAL,
/// and snapshot machinery.
///
/// Example:
/// ```rust,ignore
/// let client = handle.client();
/// client.set("key", "value").await?;
/// let value = client.get("key").await?;
/// ```
pub struct EmbeddedClient {
    runtime: Arc<Runtime>,
    // Clone semantics: clones share the runtime but get isolated session state.
    session: tokio::sync::Mutex<CommandSession>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum EmbeddedValue {
    Nil,
    Int(i64),
    Simple(String),
    Bulk(bytes::Bytes),
    Array(Vec<EmbeddedValue>),
    Map(Vec<(EmbeddedValue, EmbeddedValue)>),
    Error(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EmbeddedMessageKind {
    PubSub,
    KeyEvent,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmbeddedMessage {
    pub channel: String,
    pub payload: bytes::Bytes,
    pub pattern: Option<String>,
    pub kind: EmbeddedMessageKind,
}

pub struct EmbeddedSubscription {
    broker: Option<Broker>,
    receiver: Option<broadcast::Receiver<pubsub::Message>>,
    kind: EmbeddedSubscriptionKind,
}

enum EmbeddedSubscriptionKind {
    Channel(String),
    Pattern(String),
    KeyPattern(String),
}

struct Runtime {
    store: Arc<Store>,
    broker: Broker,
    shard_executor: ShardExecutor,
    schema_cache: SharedSchemaCache,
    script_engine: Arc<lua::ScriptEngine>,
    config: Arc<ServerConfig>,
}

pub fn default_shard_count() -> usize {
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    (cpus * 16).next_power_of_two().clamp(16, 1024)
}

impl ServerHandle {
    #[allow(dead_code)]
    pub(crate) fn runtime(&self) -> Arc<Runtime> {
        self.runtime.clone()
    }

    pub fn local_addr(&self) -> Option<std::net::SocketAddr> {
        self.local_addr
    }

    pub fn client(&self) -> EmbeddedClient {
        EmbeddedClient::new(self.runtime())
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    pub async fn wait(self) -> std::io::Result<()> {
        match self.server_task.await {
            Ok(result) => result,
            Err(e) => Err(std::io::Error::other(format!("server task failed: {e}"))),
        }
    }

    pub async fn shutdown_and_wait(self) -> std::io::Result<()> {
        self.shutdown();
        self.wait().await
    }
}

impl EmbeddedClient {
    fn new(runtime: Arc<Runtime>) -> Self {
        let mut session = CommandSession::new(false);
        session.authenticated = true;
        Self {
            runtime,
            session: tokio::sync::Mutex::new(session),
        }
    }

    /// Executes an arbitrary Redis command by name and string arguments, returning raw RESP bytes.
    ///
    /// Commands: Any non-blocking Redis command accepted by the embedded runtime parser.
    ///
    /// Example:
    /// ```rust,ignore
    /// let resp = client.execute("SET", &["key", "value"]).await?;
    /// ```
    pub async fn execute(&self, command: &str, args: &[&str]) -> Result<bytes::Bytes, LuxError> {
        let mut argv: Vec<Vec<u8>> = Vec::with_capacity(args.len() + 1);
        argv.push(command.as_bytes().to_vec());
        for arg in args {
            argv.push(arg.as_bytes().to_vec());
        }
        self.execute_owned(argv).await
    }

    /// Executes an arbitrary Redis command by name and string arguments, returning one parsed embedded value.
    ///
    /// Commands: Any non-blocking Redis command accepted by the embedded runtime parser.
    ///
    /// Example:
    /// ```rust,ignore
    /// let value = client.execute_value("GET", &["key"]).await?;
    /// ```
    pub async fn execute_value(
        &self,
        command: &str,
        args: &[&str],
    ) -> Result<EmbeddedValue, LuxError> {
        let resp = self.execute(command, args).await?;
        parse_single_embedded_value(&resp)
    }

    /// Executes an arbitrary Redis argv command with byte arguments, returning raw RESP bytes.
    ///
    /// Commands: Any non-blocking Redis command accepted by the embedded runtime parser.
    ///
    /// Example:
    /// ```rust,ignore
    /// let resp = client.execute_bytes(&[b"SET", b"key", b"value"]).await?;
    /// ```
    pub async fn execute_bytes(&self, argv: &[&[u8]]) -> Result<bytes::Bytes, LuxError> {
        let owned: Vec<Vec<u8>> = argv.iter().map(|a| a.to_vec()).collect();
        self.execute_owned(owned).await
    }

    /// Executes an arbitrary Redis argv command with byte arguments, returning one parsed embedded value.
    ///
    /// Commands: Any non-blocking Redis command accepted by the embedded runtime parser.
    ///
    /// Example:
    /// ```rust,ignore
    /// let value = client.execute_bytes_value(&[b"GET", b"key"]).await?;
    /// ```
    pub async fn execute_bytes_value(&self, argv: &[&[u8]]) -> Result<EmbeddedValue, LuxError> {
        let resp = self.execute_bytes(argv).await?;
        parse_single_embedded_value(&resp)
    }

    pub(crate) async fn execute_command_output(
        &self,
        command: command::Command<'_>,
    ) -> Result<CommandOutput, LuxError> {
        if let Some(output) = self.execute_command_fast_path(&command).await? {
            return Ok(output);
        }
        let resp = self.execute_owned(command.to_owned_argv()).await?;
        let value = parse_single_embedded_value(&resp)?;
        embedded_value_to_command_output(value)
    }

    pub(crate) async fn execute_command_pipeline_outputs(
        &self,
        commands: &[Command<'_>],
    ) -> Result<Vec<CommandOutput>, LuxError> {
        self.execute_command_pipeline_internal(commands, true).await
    }

    pub(crate) async fn execute_command_pipeline_discard(
        &self,
        commands: &[Command<'_>],
    ) -> Result<(), LuxError> {
        self.execute_command_pipeline_internal(commands, false)
            .await
            .map(|_| ())
    }

    async fn execute_command_pipeline_internal(
        &self,
        commands: &[Command<'_>],
        collect_outputs: bool,
    ) -> Result<Vec<CommandOutput>, LuxError> {
        if self.runtime.store.is_tiered() {
            let mut outputs = if collect_outputs {
                Vec::with_capacity(commands.len())
            } else {
                Vec::new()
            };
            for command in commands {
                let out = self.execute_command_output(command.clone()).await?;
                if collect_outputs {
                    outputs.push(out);
                }
            }
            return Ok(outputs);
        }

        let now = Instant::now();
        if !collect_outputs
            && commands
                .iter()
                .all(|command| matches!(command, Command::Publish { .. }))
        {
            for command in commands {
                if let Command::Publish { channel, message } = command {
                    let channel = std::str::from_utf8(channel).unwrap_or("");
                    self.runtime
                        .broker
                        .publish(channel, bytes::Bytes::copy_from_slice(message));
                }
            }
            self.runtime.store.add_total_commands(commands.len());
            return Ok(Vec::new());
        }

        let mut outputs = if collect_outputs {
            Vec::with_capacity(commands.len())
        } else {
            Vec::new()
        };
        let mut i = 0usize;

        while i < commands.len() {
            if matches!(commands[i], Command::MSet { .. }) {
                let mut batch_end = i + 1;
                while batch_end < commands.len()
                    && matches!(commands[batch_end], Command::MSet { .. })
                {
                    batch_end += 1;
                }
                let batch = &commands[i..batch_end];
                self.execute_mset_pipeline_batch(batch, now)?;
                if collect_outputs {
                    outputs.extend((i..batch_end).map(|_| CommandOutput::Simple("OK")));
                }
                self.runtime.store.add_total_commands(batch.len());
                i = batch_end;
                continue;
            }

            let Some((key, access)) = native_pipeline_access(&commands[i]) else {
                if !collect_outputs {
                    if let Command::Publish { channel, message } = &commands[i] {
                        let channel = std::str::from_utf8(channel).unwrap_or("");
                        self.runtime
                            .broker
                            .publish(channel, bytes::Bytes::copy_from_slice(message));
                        self.runtime.store.add_total_commands(1);
                        i += 1;
                        continue;
                    }
                }
                let out = self.execute_command_output(commands[i].clone()).await?;
                if collect_outputs {
                    outputs.push(out);
                }
                i += 1;
                continue;
            };

            let shard_idx = self.runtime.store.shard_for_key(key);
            let mut has_write = access == NativePipelineAccess::Write;
            let mut batch_end = i + 1;
            while batch_end < commands.len() {
                let Some((next_key, next_access)) = native_pipeline_access(&commands[batch_end])
                else {
                    break;
                };
                if self.runtime.store.shard_for_key(next_key) != shard_idx {
                    break;
                }
                has_write |= next_access == NativePipelineAccess::Write;
                batch_end += 1;
            }

            let batch = &commands[i..batch_end];
            let emit_key_events = self.runtime.broker.has_key_subs();
            let mut write_argvs = Vec::new();
            if has_write {
                if emit_key_events {
                    write_argvs.reserve(batch.len());
                }
                for command in batch {
                    if command_is_fast_path_write(command) {
                        ensure_write_allowed(&self.runtime.store)?;
                        if emit_key_events {
                            let argv = command.to_owned_argv();
                            let refs = argv.iter().map(Vec::as_slice).collect::<Vec<_>>();
                            self.runtime
                                .store
                                .wal_log_command(&refs)
                                .map_err(wal_lux_error)?;
                            write_argvs.push(argv);
                        } else {
                            wal_log_native_command(&self.runtime.store, command)?;
                        }
                    }
                }

                let mut shard = self.runtime.store.lock_write_shard(shard_idx);
                shard.version += 1;
                for command in batch {
                    if collect_outputs {
                        outputs.push(self.execute_native_write_on_shard(command, &mut shard, now)?);
                    } else {
                        self.execute_native_write_on_shard_discard(command, &mut shard, now)?;
                    }
                }
            } else if collect_outputs {
                let shard = self.runtime.store.lock_read_shard(shard_idx);
                for command in batch {
                    outputs.push(self.execute_native_read_on_shard(command, &shard, now)?);
                }
            } else {
                for command in batch {
                    self.execute_native_read_on_shard_discard(command)?;
                }
            }

            self.runtime.store.add_total_commands(batch.len());
            if has_write {
                for command in batch {
                    if command_is_fast_path_write(command) {
                        notify_zset_waiters_for_command(&self.runtime.broker, command);
                    }
                }
            }
            if emit_key_events {
                for argv in &write_argvs {
                    let refs = argv.iter().map(Vec::as_slice).collect::<Vec<_>>();
                    fire_key_events(&self.runtime.broker, &refs);
                }
            }

            i = batch_end;
        }

        Ok(outputs)
    }

    fn execute_mset_pipeline_batch(
        &self,
        commands: &[Command<'_>],
        now: Instant,
    ) -> Result<(), LuxError> {
        let emit_key_events = self.runtime.broker.has_key_subs();
        let store = &self.runtime.store;
        let mut pairs_by_shard: Vec<Vec<(&[u8], &[u8])>> = vec![Vec::new(); store.shard_count()];
        let mut event_keys = Vec::new();

        for command in commands {
            ensure_write_allowed(store)?;
            wal_log_native_command(store, command)?;
            let Command::MSet { pairs } = command else {
                return Err(LuxError::InvalidCommand(
                    "MSET batch contained non-MSET command".to_string(),
                ));
            };
            if emit_key_events {
                event_keys.reserve(pairs.len());
            }
            for &(key, value) in pairs {
                let idx = store.shard_for_key(key);
                pairs_by_shard[idx].push((key, value));
                if emit_key_events {
                    event_keys.push(key);
                }
            }
        }

        self.runtime
            .shard_executor
            .apply_mset_batches(pairs_by_shard, now);

        for command in commands {
            notify_zset_waiters_for_command(&self.runtime.broker, command);
        }
        if emit_key_events {
            for key in event_keys {
                self.runtime.broker.enqueue_key_event(key, b"MSET");
            }
        }

        Ok(())
    }

    fn execute_native_read_on_shard(
        &self,
        command: &Command<'_>,
        shard: &store::Shard,
        now: Instant,
    ) -> Result<CommandOutput, LuxError> {
        match command {
            Command::Get { key } => Ok(optional_bulk_output(Store::get_from_shard(
                &shard.data,
                key,
                now,
            ))),
            Command::StrLen { key } => Ok(CommandOutput::Int(Store::strlen_from_shard(
                &shard.data,
                key,
                now,
            ))),
            Command::Exists { keys } if keys.len() == 1 => Ok(CommandOutput::Int(i64::from(
                Store::exists_on_shard(&shard.data, keys[0], now),
            ))),
            Command::HGet { key, field } => Ok(optional_bulk_output(Store::hget_from_shard(
                &shard.data,
                key,
                field,
                now,
            ))),
            Command::GeoPos { key, members } => {
                geopos_output_from_shard(&shard.data, key, members, now)
            }
            Command::GeoDist {
                key,
                member_a,
                member_b,
                unit,
            } => geodist_output_from_shard(&shard.data, key, member_a, member_b, unit, now),
            _ => unreachable!("native pipeline read command was classified before dispatch"),
        }
    }

    fn execute_native_write_on_shard(
        &self,
        command: &Command<'_>,
        shard: &mut store::Shard,
        now: Instant,
    ) -> Result<CommandOutput, LuxError> {
        match command {
            Command::Get { key } => Ok(optional_bulk_output(Store::get_from_shard(
                &shard.data,
                key,
                now,
            ))),
            Command::StrLen { key } => Ok(CommandOutput::Int(Store::strlen_from_shard(
                &shard.data,
                key,
                now,
            ))),
            Command::Exists { keys } if keys.len() == 1 => Ok(CommandOutput::Int(i64::from(
                Store::exists_on_shard(&shard.data, keys[0], now),
            ))),
            Command::HGet { key, field } => Ok(optional_bulk_output(Store::hget_from_shard(
                &shard.data,
                key,
                field,
                now,
            ))),
            Command::GeoPos { key, members } => {
                geopos_output_from_shard(&shard.data, key, members, now)
            }
            Command::GeoDist {
                key,
                member_a,
                member_b,
                unit,
            } => geodist_output_from_shard(&shard.data, key, member_a, member_b, unit, now),
            Command::Set {
                key,
                value,
                options,
            } if can_fast_path_set(options) => {
                self.runtime
                    .store
                    .set_on_shard(&mut shard.data, key, value, set_ttl(options), now);
                self.runtime.store.remove_from_disk(key);
                Ok(CommandOutput::Simple("OK"))
            }
            Command::GetSet { key, value } => {
                let old = self
                    .runtime
                    .store
                    .get_set_on_shard(&mut shard.data, key, value, now);
                self.runtime.store.remove_from_disk(key);
                Ok(optional_bulk_output(old))
            }
            Command::SetNx { key, value } => {
                let changed = self
                    .runtime
                    .store
                    .set_nx_on_shard(&mut shard.data, key, value, now);
                if changed {
                    self.runtime.store.remove_from_disk(key);
                }
                Ok(CommandOutput::Int(i64::from(changed)))
            }
            Command::SetEx {
                key,
                seconds,
                value,
            } => {
                if *seconds == 0 {
                    return Err(LuxError::Command(
                        "ERR invalid expire time in 'setex' command".to_string(),
                    ));
                }
                self.runtime.store.set_on_shard(
                    &mut shard.data,
                    key,
                    value,
                    Some(Duration::from_secs(*seconds)),
                    now,
                );
                self.runtime.store.remove_from_disk(key);
                Ok(CommandOutput::Simple("OK"))
            }
            Command::PSetEx {
                key,
                milliseconds,
                value,
            } => {
                let millis = u64::try_from(*milliseconds).map_err(|_| {
                    LuxError::Command("ERR value is not an integer or out of range".to_string())
                })?;
                self.runtime.store.set_on_shard(
                    &mut shard.data,
                    key,
                    value,
                    Some(Duration::from_millis(millis)),
                    now,
                );
                self.runtime.store.remove_from_disk(key);
                Ok(CommandOutput::Simple("OK"))
            }
            Command::Append { key, value } => {
                let len = self.runtime.store.append_on_shard(shard, key, value, now);
                self.runtime.store.remove_from_disk(key);
                Ok(CommandOutput::Int(len))
            }
            Command::Incr { key } => Ok(CommandOutput::Int(
                self.runtime
                    .store
                    .incr_on_shard(&mut shard.data, key, 1, now)
                    .map_err(LuxError::Command)?,
            )),
            Command::Decr { key } => Ok(CommandOutput::Int(
                self.runtime
                    .store
                    .incr_on_shard(&mut shard.data, key, -1, now)
                    .map_err(LuxError::Command)?,
            )),
            Command::IncrBy { key, increment } => Ok(CommandOutput::Int(
                self.runtime
                    .store
                    .incr_on_shard(&mut shard.data, key, *increment, now)
                    .map_err(LuxError::Command)?,
            )),
            Command::DecrBy { key, decrement } => Ok(CommandOutput::Int(
                self.runtime
                    .store
                    .incr_on_shard(&mut shard.data, key, -*decrement, now)
                    .map_err(LuxError::Command)?,
            )),
            Command::Del { keys } | Command::Unlink { keys } if keys.len() == 1 => Ok(
                CommandOutput::Int(self.runtime.store.del_on_shard(shard, keys[0], now)),
            ),
            Command::LPush { key, values } => {
                let n = self
                    .runtime
                    .store
                    .lpush_on_shard(shard, key, values, now)
                    .map_err(LuxError::Command)?;
                self.runtime.store.remove_from_disk(key);
                self.drain_list_waiters_on_shard(key, shard, now);
                Ok(CommandOutput::Int(n))
            }
            Command::RPush { key, values } => {
                let n = self
                    .runtime
                    .store
                    .rpush_on_shard(shard, key, values, now)
                    .map_err(LuxError::Command)?;
                self.runtime.store.remove_from_disk(key);
                self.drain_list_waiters_on_shard(key, shard, now);
                Ok(CommandOutput::Int(n))
            }
            Command::LPop { key } => {
                let value = self.runtime.store.lpop_on_shard(shard, key, now);
                if value.is_some() {
                    self.runtime.store.remove_from_disk(key);
                }
                Ok(optional_bulk_output(value))
            }
            Command::RPop { key } => {
                let value = self.runtime.store.rpop_on_shard(shard, key, now);
                if value.is_some() {
                    self.runtime.store.remove_from_disk(key);
                }
                Ok(optional_bulk_output(value))
            }
            Command::HSet { key, field, value } => Ok(CommandOutput::Int(
                self.runtime
                    .store
                    .hset_on_shard(shard, key, &[(*field, *value)], now)
                    .map_err(LuxError::Command)?,
            )),
            Command::HIncrBy {
                key,
                field,
                increment,
            } => Ok(CommandOutput::Int(
                self.runtime
                    .store
                    .hincrby_on_shard(shard, key, field, *increment, now)
                    .map_err(LuxError::Command)?,
            )),
            Command::SAdd { key, members } => Ok(CommandOutput::Int(
                self.runtime
                    .store
                    .sadd_on_shard(shard, key, members, now)
                    .map_err(LuxError::Command)?,
            )),
            Command::SPop { key } => {
                let mut values = self
                    .runtime
                    .store
                    .spop_on_shard(shard, key, 1, now)
                    .map_err(LuxError::Command)?;
                if !values.is_empty() {
                    self.runtime.store.remove_from_disk(key);
                }
                Ok(match values.pop() {
                    Some(value) => CommandOutput::Bulk(bytes::Bytes::from(value)),
                    None => CommandOutput::Nil,
                })
            }
            Command::ZAdd { key, score, member } => Ok(CommandOutput::Int(
                self.runtime
                    .store
                    .zadd_on_shard(
                        shard,
                        key,
                        &[(*member, *score)],
                        false,
                        false,
                        false,
                        false,
                        false,
                        now,
                    )
                    .map_err(LuxError::Command)?,
            )),
            Command::ZIncrBy {
                key,
                increment,
                member,
            } => Ok(score_output(
                self.runtime
                    .store
                    .zincrby_on_shard(shard, key, member, *increment, now)
                    .map_err(LuxError::Command)?,
            )),
            Command::GeoAdd { key, members } => {
                if let [member] = members.as_slice() {
                    crate::geo::validate_coords(member.longitude, member.latitude)
                        .map_err(LuxError::Command)?;
                    let scored = [(
                        member.member,
                        crate::geo::geohash_encode(member.longitude, member.latitude) as f64,
                    )];
                    Ok(CommandOutput::Int(
                        self.runtime
                            .store
                            .zadd_on_shard(
                                shard, key, &scored, false, false, false, false, false, now,
                            )
                            .map_err(LuxError::Command)?,
                    ))
                } else {
                    let mut scored = Vec::with_capacity(members.len());
                    for member in members {
                        crate::geo::validate_coords(member.longitude, member.latitude)
                            .map_err(LuxError::Command)?;
                        scored.push((
                            member.member,
                            crate::geo::geohash_encode(member.longitude, member.latitude) as f64,
                        ));
                    }
                    Ok(CommandOutput::Int(
                        self.runtime
                            .store
                            .zadd_on_shard(
                                shard, key, &scored, false, false, false, false, false, now,
                            )
                            .map_err(LuxError::Command)?,
                    ))
                }
            }
            Command::XAdd { key, id, fields } => {
                require_xadd_fields(fields)?;
                let id = self
                    .runtime
                    .store
                    .xadd_on_shard(shard, key, arg_str(id), xadd_fields(fields), None, now)
                    .map_err(LuxError::Command)?;
                self.runtime.broker.wake_stream_waiters(arg_str(key));
                Ok(CommandOutput::Bulk(bytes::Bytes::from(id.to_string())))
            }
            _ => unreachable!("native pipeline write command was classified before dispatch"),
        }
    }

    fn execute_native_read_on_shard_discard(&self, command: &Command<'_>) -> Result<(), LuxError> {
        match command {
            Command::Get { .. }
            | Command::StrLen { .. }
            | Command::Exists { .. }
            | Command::HGet { .. }
            | Command::GeoPos { .. }
            | Command::GeoDist { .. } => Ok(()),
            _ => unreachable!("native pipeline read command was classified before dispatch"),
        }
    }

    fn execute_native_write_on_shard_discard(
        &self,
        command: &Command<'_>,
        shard: &mut store::Shard,
        now: Instant,
    ) -> Result<(), LuxError> {
        self.execute_native_write_on_shard(command, shard, now)
            .map(|_| ())
    }

    async fn execute_command_fast_path(
        &self,
        command: &Command<'_>,
    ) -> Result<Option<CommandOutput>, LuxError> {
        if matches!(command, Command::Raw { .. })
            || matches!(command, Command::Set { options, .. } if !can_fast_path_set(options))
        {
            return Ok(None);
        }

        let now = Instant::now();
        if command_is_fast_path_write(command) {
            ensure_write_allowed(&self.runtime.store)?;
        }
        let mut write_argv = if command_is_fast_path_write(command)
            && (self.runtime.store.wal_enabled() || self.runtime.broker.has_key_subs())
            && !matches!(command, Command::MSet { .. })
        {
            Some(command.to_owned_argv())
        } else {
            None
        };
        if let Some(argv) = &write_argv {
            let refs = argv.iter().map(Vec::as_slice).collect::<Vec<_>>();
            self.runtime
                .store
                .wal_log_command(&refs)
                .map_err(wal_lux_error)?;
        }

        let output = match command {
            Command::Ping => CommandOutput::Simple("PONG"),
            Command::Publish { channel, message } => {
                let channel = std::str::from_utf8(channel).unwrap_or("");
                CommandOutput::Int(
                    self.runtime
                        .broker
                        .publish(channel, bytes::Bytes::copy_from_slice(message)),
                )
            }
            Command::DbSize => CommandOutput::Int(self.runtime.store.dbsize(now)),
            Command::FlushDb | Command::FlushAll => {
                self.runtime.store.flushdb();
                CommandOutput::Simple("OK")
            }
            Command::Keys { pattern } => string_array(self.runtime.store.keys(pattern, now)),
            Command::RandomKey => random_key_output(&self.runtime.store, now),
            Command::Get { key } => optional_bulk_output(self.runtime.store.get(key, now)),
            Command::Set {
                key,
                value,
                options,
            } if can_fast_path_set(options) => {
                let ttl = set_ttl(options);
                self.runtime.store.set(key, value, ttl, now);
                CommandOutput::Simple("OK")
            }
            Command::GetSet { key, value } => {
                optional_bulk_output(self.runtime.store.get_set(key, value, now))
            }
            Command::SetNx { key, value } => {
                CommandOutput::Int(i64::from(self.runtime.store.set_nx(key, value, now)))
            }
            Command::SetEx {
                key,
                seconds,
                value,
            } => {
                if *seconds == 0 {
                    return Err(LuxError::Command(
                        "ERR invalid expire time in 'setex' command".to_string(),
                    ));
                }
                self.runtime
                    .store
                    .set(key, value, Some(Duration::from_secs(*seconds)), now);
                CommandOutput::Simple("OK")
            }
            Command::PSetEx {
                key,
                milliseconds,
                value,
            } => {
                let millis = u64::try_from(*milliseconds).map_err(|_| {
                    LuxError::Command("ERR value is not an integer or out of range".to_string())
                })?;
                self.runtime
                    .store
                    .set(key, value, Some(Duration::from_millis(millis)), now);
                CommandOutput::Simple("OK")
            }
            Command::MGet { keys } => CommandOutput::Array(
                keys.iter()
                    .map(|key| optional_bulk_output(self.runtime.store.get(key, now)))
                    .collect(),
            ),
            Command::MSet { .. } => {
                self.execute_mset_pipeline_batch(std::slice::from_ref(command), now)?;
                CommandOutput::Simple("OK")
            }
            Command::MSetNx { pairs } => {
                CommandOutput::Int(i64::from(self.runtime.store.msetnx(pairs, now)))
            }
            Command::Append { key, value } => {
                CommandOutput::Int(self.runtime.store.append(key, value, now))
            }
            Command::StrLen { key } => CommandOutput::Int(self.runtime.store.strlen(key, now)),
            Command::Incr { key } => CommandOutput::Int(
                self.runtime
                    .store
                    .incr(key, 1, now)
                    .map_err(LuxError::Command)?,
            ),
            Command::Decr { key } => CommandOutput::Int(
                self.runtime
                    .store
                    .incr(key, -1, now)
                    .map_err(LuxError::Command)?,
            ),
            Command::IncrBy { key, increment } => CommandOutput::Int(
                self.runtime
                    .store
                    .incr(key, *increment, now)
                    .map_err(LuxError::Command)?,
            ),
            Command::DecrBy { key, decrement } => CommandOutput::Int(
                self.runtime
                    .store
                    .incr(key, -*decrement, now)
                    .map_err(LuxError::Command)?,
            ),
            Command::Del { keys } => CommandOutput::Int(self.runtime.store.del(keys)),
            Command::Unlink { keys } => CommandOutput::Int(self.runtime.store.unlink(keys)),
            Command::Exists { keys } => CommandOutput::Int(self.runtime.store.exists(keys, now)),
            Command::Expire { key, seconds } => {
                CommandOutput::Int(i64::from(self.runtime.store.expire(key, *seconds, now)))
            }
            Command::Ttl { key } => CommandOutput::Int(self.runtime.store.ttl(key, now)),
            Command::PTtl { key } => CommandOutput::Int(self.runtime.store.pttl(key, now)),
            Command::Persist { key } => {
                CommandOutput::Int(i64::from(self.runtime.store.persist(key, now)))
            }
            Command::Type { key } => CommandOutput::Simple(
                self.runtime
                    .store
                    .get_entry_type(key, now)
                    .unwrap_or("none"),
            ),
            Command::Rename { key, new_key } => {
                self.runtime
                    .store
                    .rename(key, new_key, now)
                    .map_err(LuxError::Command)?;
                CommandOutput::Simple("OK")
            }
            Command::RenameNx { key, new_key } => {
                if self.runtime.store.get(new_key, now).is_some() {
                    CommandOutput::Int(0)
                } else {
                    self.runtime
                        .store
                        .rename(key, new_key, now)
                        .map_err(LuxError::Command)?;
                    CommandOutput::Int(1)
                }
            }
            Command::LPush { key, values } => {
                let n = self
                    .runtime
                    .store
                    .lpush(key, values, now)
                    .map_err(LuxError::Command)?;
                self.drain_list_waiters(key, now);
                CommandOutput::Int(n)
            }
            Command::RPush { key, values } => {
                let n = self
                    .runtime
                    .store
                    .rpush(key, values, now)
                    .map_err(LuxError::Command)?;
                self.drain_list_waiters(key, now);
                CommandOutput::Int(n)
            }
            Command::LPop { key } => optional_bulk_output(self.runtime.store.lpop(key, now)),
            Command::RPop { key } => optional_bulk_output(self.runtime.store.rpop(key, now)),
            Command::LLen { key } => CommandOutput::Int(
                self.runtime
                    .store
                    .llen(key, now)
                    .map_err(LuxError::Command)?,
            ),
            Command::LIndex { key, index } => {
                optional_bulk_output(self.runtime.store.lindex(key, *index, now))
            }
            Command::LRange { key, start, stop } => bytes_array(
                self.runtime
                    .store
                    .lrange(key, *start, *stop, now)
                    .map_err(LuxError::Command)?,
            ),
            Command::HSet { key, field, value } => CommandOutput::Int(
                self.runtime
                    .store
                    .hset(key, &[(*field, *value)], now)
                    .map_err(LuxError::Command)?,
            ),
            Command::HIncrBy {
                key,
                field,
                increment,
            } => CommandOutput::Int(
                self.runtime
                    .store
                    .hincrby(key, field, *increment, now)
                    .map_err(LuxError::Command)?,
            ),
            Command::HGet { key, field } => {
                optional_bulk_output(self.runtime.store.hget(key, field, now))
            }
            Command::HMGet { key, fields } => CommandOutput::Array(
                self.runtime
                    .store
                    .hmget(key, fields, now)
                    .into_iter()
                    .map(optional_bulk_output)
                    .collect(),
            ),
            Command::HDel { key, fields } => CommandOutput::Int(
                self.runtime
                    .store
                    .hdel(key, fields, now)
                    .map_err(LuxError::Command)?,
            ),
            Command::HExists { key, field } => CommandOutput::Int(i64::from(
                self.runtime
                    .store
                    .hexists(key, field, now)
                    .map_err(LuxError::Command)?,
            )),
            Command::HLen { key } => CommandOutput::Int(
                self.runtime
                    .store
                    .hlen(key, now)
                    .map_err(LuxError::Command)?,
            ),
            Command::HGetAll { key } => {
                let mut values = Vec::new();
                for (field, value) in self
                    .runtime
                    .store
                    .hgetall(key, now)
                    .map_err(LuxError::Command)?
                {
                    values.push(CommandOutput::Bulk(bytes::Bytes::from(field)));
                    values.push(CommandOutput::Bulk(value));
                }
                CommandOutput::Array(values)
            }
            Command::SAdd { key, members } => CommandOutput::Int(
                self.runtime
                    .store
                    .sadd(key, members, now)
                    .map_err(LuxError::Command)?,
            ),
            Command::SRem { key, members } => CommandOutput::Int(
                self.runtime
                    .store
                    .srem(key, members, now)
                    .map_err(LuxError::Command)?,
            ),
            Command::SMembers { key } => string_array(
                self.runtime
                    .store
                    .smembers(key, now)
                    .map_err(LuxError::Command)?,
            ),
            Command::SIsMember { key, member } => CommandOutput::Int(i64::from(
                self.runtime
                    .store
                    .sismember(key, member, now)
                    .map_err(LuxError::Command)?,
            )),
            Command::SCard { key } => CommandOutput::Int(
                self.runtime
                    .store
                    .scard(key, now)
                    .map_err(LuxError::Command)?,
            ),
            Command::SPop { key } => {
                let mut values = self
                    .runtime
                    .store
                    .spop(key, 1, now)
                    .map_err(LuxError::Command)?;
                match values.pop() {
                    Some(value) => CommandOutput::Bulk(bytes::Bytes::from(value)),
                    None => CommandOutput::Nil,
                }
            }
            Command::SUnion { keys } => string_array(
                self.runtime
                    .store
                    .sunion(keys, now)
                    .map_err(LuxError::Command)?,
            ),
            Command::SInter { keys } => string_array(
                self.runtime
                    .store
                    .sinter(keys, now)
                    .map_err(LuxError::Command)?,
            ),
            Command::SDiff { keys } => string_array(
                self.runtime
                    .store
                    .sdiff(keys, now)
                    .map_err(LuxError::Command)?,
            ),
            Command::ZAdd { key, score, member } => CommandOutput::Int(
                self.runtime
                    .store
                    .zadd(
                        key,
                        &[(*member, *score)],
                        false,
                        false,
                        false,
                        false,
                        false,
                        now,
                    )
                    .map_err(LuxError::Command)?,
            ),
            Command::ZRem { key, members } => CommandOutput::Int(
                self.runtime
                    .store
                    .zrem(key, members, now)
                    .map_err(LuxError::Command)?,
            ),
            Command::ZCard { key } => CommandOutput::Int(
                self.runtime
                    .store
                    .zcard(key, now)
                    .map_err(LuxError::Command)?,
            ),
            Command::ZScore { key, member } => optional_score_output(
                self.runtime
                    .store
                    .zscore(key, member, now)
                    .map_err(LuxError::Command)?,
            ),
            Command::ZIncrBy {
                key,
                increment,
                member,
            } => score_output(
                self.runtime
                    .store
                    .zincrby(key, member, *increment, now)
                    .map_err(LuxError::Command)?,
            ),
            Command::ZCount { key, min, max } => {
                let (min, min_exclusive) = parse_score_bound_bytes(min, false);
                let (max, max_exclusive) = parse_score_bound_bytes(max, true);
                CommandOutput::Int(
                    self.runtime
                        .store
                        .zcount(key, min, max, min_exclusive, max_exclusive, now)
                        .map_err(LuxError::Command)?,
                )
            }
            Command::ZRange {
                key,
                start,
                stop,
                with_scores,
            } => zrange_output(
                self.runtime
                    .store
                    .zrange(key, *start, *stop, false, *with_scores, now)
                    .map_err(LuxError::Command)?,
                *with_scores,
            ),
            Command::GeoAdd { key, members } => {
                if let [member] = members.as_slice() {
                    crate::geo::validate_coords(member.longitude, member.latitude)
                        .map_err(LuxError::Command)?;
                    let scored = [(
                        member.member,
                        crate::geo::geohash_encode(member.longitude, member.latitude) as f64,
                    )];
                    CommandOutput::Int(
                        self.runtime
                            .store
                            .zadd(key, &scored, false, false, false, false, false, now)
                            .map_err(LuxError::Command)?,
                    )
                } else {
                    let mut scored = Vec::with_capacity(members.len());
                    for member in members {
                        crate::geo::validate_coords(member.longitude, member.latitude)
                            .map_err(LuxError::Command)?;
                        scored.push((
                            member.member,
                            crate::geo::geohash_encode(member.longitude, member.latitude) as f64,
                        ));
                    }
                    CommandOutput::Int(
                        self.runtime
                            .store
                            .zadd(key, &scored, false, false, false, false, false, now)
                            .map_err(LuxError::Command)?,
                    )
                }
            }
            Command::GeoPos { key, members } => {
                let mut values = Vec::with_capacity(members.len());
                for member in members {
                    match self
                        .runtime
                        .store
                        .zscore(key, member, now)
                        .map_err(LuxError::Command)?
                    {
                        Some(score) => {
                            let (lon, lat) = crate::geo::geohash_decode(score as u64);
                            values.push(CommandOutput::Array(vec![
                                CommandOutput::Bulk(bytes::Bytes::from(format_geo_coord(lon))),
                                CommandOutput::Bulk(bytes::Bytes::from(format_geo_coord(lat))),
                            ]));
                        }
                        None => values.push(CommandOutput::Nil),
                    }
                }
                CommandOutput::Array(values)
            }
            Command::GeoDist {
                key,
                member_a,
                member_b,
                unit,
            } => {
                let unit = std::str::from_utf8(unit)
                    .ok()
                    .and_then(crate::geo::DistUnit::parse)
                    .ok_or_else(|| {
                        LuxError::Command(
                            "ERR unsupported unit provided. please use M, KM, FT, MI".to_string(),
                        )
                    })?;
                let Some(score_a) = self
                    .runtime
                    .store
                    .zscore(key, member_a, now)
                    .map_err(LuxError::Command)?
                else {
                    return Ok(Some(CommandOutput::Nil));
                };
                let Some(score_b) = self
                    .runtime
                    .store
                    .zscore(key, member_b, now)
                    .map_err(LuxError::Command)?
                else {
                    return Ok(Some(CommandOutput::Nil));
                };
                let (lon_a, lat_a) = crate::geo::geohash_decode(score_a as u64);
                let (lon_b, lat_b) = crate::geo::geohash_decode(score_b as u64);
                let distance = unit.from_meters(crate::geo::haversine(lon_a, lat_a, lon_b, lat_b));
                CommandOutput::Bulk(bytes::Bytes::from(format!("{distance:.4}")))
            }
            Command::XAdd { key, id, fields } => {
                require_xadd_fields(fields)?;
                let id = self
                    .runtime
                    .store
                    .xadd(key, arg_str(id), xadd_fields(fields), None, now)
                    .map_err(LuxError::Command)?;
                self.runtime.broker.wake_stream_waiters(arg_str(key));
                CommandOutput::Bulk(bytes::Bytes::from(id.to_string()))
            }
            Command::Set { .. } | Command::Raw { .. } => unreachable!("handled before fast path"),
        };

        self.runtime.store.add_total_commands(1);
        if command_is_fast_path_write(command) && !matches!(command, Command::MSet { .. }) {
            notify_zset_waiters_for_command(&self.runtime.broker, command);
        }
        if let Some(argv) = write_argv.take() {
            let refs = argv.iter().map(Vec::as_slice).collect::<Vec<_>>();
            fire_key_events(&self.runtime.broker, &refs);
        }
        Ok(Some(output))
    }

    fn drain_list_waiters(&self, key: &[u8], now: Instant) {
        if !self.runtime.broker.has_list_waiters("") {
            return;
        }
        let key_s = std::str::from_utf8(key).unwrap_or("");
        if self.runtime.broker.has_list_waiters(key_s) {
            let shard_idx = self.runtime.store.shard_for_key(key);
            let mut shard = self.runtime.store.lock_write_shard(shard_idx);
            self.drain_list_waiters_on_shard(key, &mut shard, now);
        }
    }

    fn drain_list_waiters_on_shard(&self, key: &[u8], shard: &mut store::Shard, now: Instant) {
        if !self.runtime.broker.has_list_waiters("") {
            return;
        }
        let key_s = std::str::from_utf8(key).unwrap_or("");
        if self.runtime.broker.has_list_waiters(key_s) {
            self.runtime
                .broker
                .drain_list_waiters(key_s, &mut shard.data, now);
        }
    }

    /// Executes a raw Redis command pipeline and returns raw RESP bytes for all replies.
    ///
    /// Commands: Any non-blocking Redis commands accepted by the embedded runtime parser.
    ///
    /// Example:
    /// ```rust,ignore
    /// let resp = client.pipeline(&vec![vec![b"PING".to_vec()]]).await?;
    /// ```
    pub async fn pipeline(&self, commands: &[Vec<Vec<u8>>]) -> Result<bytes::Bytes, LuxError> {
        let mut write_buf = BytesMut::with_capacity(4096);
        let mut session = self.session.lock().await;
        let now = Instant::now();
        let refs: Vec<Vec<&[u8]>> = commands
            .iter()
            .map(|cmd| cmd.iter().map(|arg| arg.as_slice()).collect())
            .collect();
        for args in &refs {
            validate_embedded_command(args)?;
        }
        let executor = CommandExecutor::new(
            self.runtime.store.clone(),
            self.runtime.broker.clone(),
            self.runtime.script_engine.clone(),
            self.runtime.schema_cache.clone(),
        );
        if let Some(action) = executor.execute_pipeline(&refs, &mut session, &mut write_buf, now) {
            let kind = match action {
                CmdResult::BlockPop { .. } => "BLPOP/BRPOP",
                CmdResult::BlockMove { .. } => "BLMOVE",
                CmdResult::BlockStreamRead { .. } => "XREAD/XREADGROUP",
                CmdResult::BlockZPop { .. } => "BZPOP*",
                _ => "unsupported",
            };
            return Err(LuxError::Unsupported(format!(
                "blocking command not supported in embedded pipeline: {kind}"
            )));
        }
        Ok(write_buf.freeze())
    }

    /// Executes a raw Redis command pipeline and returns parsed embedded values for all replies.
    ///
    /// Commands: Any non-blocking Redis commands accepted by the embedded runtime parser.
    ///
    /// Example:
    /// ```rust,ignore
    /// let values = client.pipeline_values(&vec![vec![b"PING".to_vec()]]).await?;
    /// ```
    pub async fn pipeline_values(
        &self,
        commands: &[Vec<Vec<u8>>],
    ) -> Result<Vec<EmbeddedValue>, LuxError> {
        let resp = self.pipeline(commands).await?;
        parse_embedded_values(&resp)
    }

    /// Executes `SET` and returns the parsed embedded value reply.
    ///
    /// Commands: Redis `SET`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let value = client.set_value("key", "value").await?;
    /// ```
    pub async fn set_value(&self, key: &str, value: &str) -> Result<EmbeddedValue, LuxError> {
        self.execute_value("SET", &[key, value]).await
    }

    /// Executes `GET` and returns the parsed embedded value reply.
    ///
    /// Commands: Redis `GET`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let value = client.get_value("key").await?;
    /// ```
    pub async fn get_value(&self, key: &str) -> Result<EmbeddedValue, LuxError> {
        self.execute_value("GET", &[key]).await
    }

    /// Executes `DEL` for one key and returns the parsed embedded value reply.
    ///
    /// Commands: Redis `DEL`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let value = client.del_value("key").await?;
    /// ```
    pub async fn del_value(&self, key: &str) -> Result<EmbeddedValue, LuxError> {
        self.execute_value("DEL", &[key]).await
    }

    /// Executes `INCR` and returns the parsed embedded value reply.
    ///
    /// Commands: Redis `INCR`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let value = client.incr_value("counter").await?;
    /// ```
    pub async fn incr_value(&self, key: &str) -> Result<EmbeddedValue, LuxError> {
        self.execute_value("INCR", &[key]).await
    }

    /// Creates an embedded channel subscription.
    ///
    /// Commands: Redis `SUBSCRIBE` semantics without sending the command through RESP.
    ///
    /// Example:
    /// ```rust,ignore
    /// let mut sub = client.subscribe("events");
    /// ```
    pub fn subscribe(&self, channel: &str) -> EmbeddedSubscription {
        EmbeddedSubscription::new(
            self.runtime.broker.clone(),
            self.runtime.broker.subscribe(channel),
            EmbeddedSubscriptionKind::Channel(channel.to_string()),
        )
    }

    /// Creates an embedded pattern subscription.
    ///
    /// Commands: Redis `PSUBSCRIBE` semantics without sending the command through RESP.
    ///
    /// Example:
    /// ```rust,ignore
    /// let mut sub = client.psubscribe("events:*");
    /// ```
    pub fn psubscribe(&self, pattern: &str) -> EmbeddedSubscription {
        EmbeddedSubscription::new(
            self.runtime.broker.clone(),
            self.runtime.broker.psubscribe(pattern),
            EmbeddedSubscriptionKind::Pattern(pattern.to_string()),
        )
    }

    /// Creates an embedded key-event pattern subscription.
    ///
    /// Commands: Lux key-event subscription semantics, equivalent to the embedded `KSUB` path.
    ///
    /// Example:
    /// ```rust,ignore
    /// let mut sub = client.ksubscribe("key:*");
    /// ```
    pub fn ksubscribe(&self, pattern: &str) -> EmbeddedSubscription {
        EmbeddedSubscription::new(
            self.runtime.broker.clone(),
            self.runtime.broker.ksubscribe(pattern),
            EmbeddedSubscriptionKind::KeyPattern(pattern.to_string()),
        )
    }

    /// Blocks until a value can be popped from the left side of one of the lists, or until the timeout expires.
    ///
    /// Commands: Redis `BLPOP`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let item = client.blpop(&["queue"], std::time::Duration::from_secs(1)).await?;
    /// ```
    pub async fn blpop(
        &self,
        keys: &[&str],
        timeout: Duration,
    ) -> Result<Option<(String, bytes::Bytes)>, LuxError> {
        self.blocking_list_pop(keys, timeout, true).await
    }

    /// Blocks until a value can be popped from the right side of one of the lists, or until the timeout expires.
    ///
    /// Commands: Redis `BRPOP`.
    ///
    /// Example:
    /// ```rust,ignore
    /// let item = client.brpop(&["queue"], std::time::Duration::from_secs(1)).await?;
    /// ```
    pub async fn brpop(
        &self,
        keys: &[&str],
        timeout: Duration,
    ) -> Result<Option<(String, bytes::Bytes)>, LuxError> {
        self.blocking_list_pop(keys, timeout, false).await
    }

    async fn blocking_list_pop(
        &self,
        keys: &[&str],
        timeout: Duration,
        pop_left: bool,
    ) -> Result<Option<(String, bytes::Bytes)>, LuxError> {
        if keys.is_empty() {
            return Err(LuxError::InvalidCommand(
                "blocking list pop requires at least one key".to_string(),
            ));
        }

        let command = if pop_left { "BLPOP" } else { "BRPOP" };
        let timeout_secs = timeout.as_secs_f64().to_string();
        let mut argv: Vec<Vec<u8>> = Vec::with_capacity(keys.len() + 2);
        argv.push(command.as_bytes().to_vec());
        for key in keys {
            argv.push(key.as_bytes().to_vec());
        }
        argv.push(timeout_secs.as_bytes().to_vec());

        let mut write_buf = BytesMut::with_capacity(256);
        let action = {
            let mut session = self.session.lock().await;
            let now = Instant::now();
            let refs: Vec<&[u8]> = argv.iter().map(|a| a.as_slice()).collect();
            let executor = CommandExecutor::new(
                self.runtime.store.clone(),
                self.runtime.broker.clone(),
                self.runtime.script_engine.clone(),
                self.runtime.schema_cache.clone(),
            );
            self.runtime.store.add_total_commands(1);
            executor.execute_command(&refs, &mut session, &mut write_buf, now)
        };

        if !write_buf.is_empty() {
            return parse_blocking_pop_value(&write_buf);
        }

        let Some(CmdResult::BlockPop {
            keys: owned_keys,
            timeout,
            pop_left,
        }) = action
        else {
            return Err(LuxError::Protocol(
                "blocking list pop returned an unexpected command result".to_string(),
            ));
        };

        wait_for_blocking_pop(&self.runtime.broker, &owned_keys, timeout, pop_left).await
    }

    async fn execute_owned(&self, argv: Vec<Vec<u8>>) -> Result<bytes::Bytes, LuxError> {
        let mut write_buf = BytesMut::with_capacity(4096);
        let mut session = self.session.lock().await;
        let now = Instant::now();
        let refs: Vec<&[u8]> = argv.iter().map(|a| a.as_slice()).collect();
        validate_embedded_command(&refs)?;
        let executor = CommandExecutor::new(
            self.runtime.store.clone(),
            self.runtime.broker.clone(),
            self.runtime.script_engine.clone(),
            self.runtime.schema_cache.clone(),
        );
        self.runtime.store.add_total_commands(1);
        if let Some(action) = executor.execute_command(&refs, &mut session, &mut write_buf, now) {
            let kind = match action {
                CmdResult::BlockPop { .. } => "BLPOP/BRPOP",
                CmdResult::BlockMove { .. } => "BLMOVE",
                CmdResult::BlockStreamRead { .. } => "XREAD/XREADGROUP",
                CmdResult::BlockZPop { .. } => "BZPOP*",
                _ => "unsupported",
            };
            return Err(LuxError::Unsupported(format!(
                "blocking command not supported in embedded execution: {kind}"
            )));
        }
        Ok(write_buf.freeze())
    }
}

fn validate_embedded_command(args: &[&[u8]]) -> Result<(), LuxError> {
    let parsed = command::parse(args).map_err(|e| LuxError::InvalidCommand(e.to_string()))?;
    match parsed.meta.kind {
        CommandKind::PubSub(PubSubCommand::Subscribe)
        | CommandKind::PubSub(PubSubCommand::Unsubscribe)
        | CommandKind::PubSub(PubSubCommand::PSubscribe)
        | CommandKind::PubSub(PubSubCommand::PUnsubscribe)
        | CommandKind::PubSub(PubSubCommand::KSubscribe)
        | CommandKind::PubSub(PubSubCommand::KUnsubscribe) => Err(LuxError::Unsupported(
            "subscription commands use EmbeddedClient::subscribe, psubscribe, or ksubscribe"
                .to_string(),
        )),
        CommandKind::Blocking => Err(LuxError::Unsupported(format!(
            "blocking command not supported in embedded execution: {}",
            String::from_utf8_lossy(parsed.name).to_ascii_uppercase()
        ))),
        CommandKind::PubSub(PubSubCommand::Publish)
        | CommandKind::General
        | CommandKind::Auth
        | CommandKind::Transaction => Ok(()),
    }
}

impl Clone for EmbeddedClient {
    fn clone(&self) -> Self {
        Self::new(self.runtime.clone())
    }
}

fn embedded_value_to_command_output(value: EmbeddedValue) -> Result<CommandOutput, LuxError> {
    match value {
        EmbeddedValue::Nil => Ok(CommandOutput::Nil),
        EmbeddedValue::Int(n) => Ok(CommandOutput::Int(n)),
        EmbeddedValue::Simple(s) => Ok(CommandOutput::Bulk(bytes::Bytes::from(s))),
        EmbeddedValue::Bulk(bytes) => Ok(CommandOutput::Bulk(bytes)),
        EmbeddedValue::Array(items) => Ok(CommandOutput::Array(
            items
                .into_iter()
                .map(embedded_value_to_command_output)
                .collect::<Result<Vec<_>, _>>()?,
        )),
        EmbeddedValue::Map(entries) => {
            let mut out = Vec::with_capacity(entries.len() * 2);
            for (key, value) in entries {
                out.push(embedded_value_to_command_output(key)?);
                out.push(embedded_value_to_command_output(value)?);
            }
            Ok(CommandOutput::Array(out))
        }
        EmbeddedValue::Error(msg) => Err(LuxError::Command(msg)),
    }
}

fn optional_bulk_output(value: Option<bytes::Bytes>) -> CommandOutput {
    match value {
        Some(value) => CommandOutput::Bulk(value),
        None => CommandOutput::Nil,
    }
}

fn bytes_array(values: Vec<bytes::Bytes>) -> CommandOutput {
    CommandOutput::Array(values.into_iter().map(CommandOutput::Bulk).collect())
}

fn string_array(values: Vec<String>) -> CommandOutput {
    CommandOutput::Array(
        values
            .into_iter()
            .map(|value| CommandOutput::Bulk(bytes::Bytes::from(value)))
            .collect(),
    )
}

fn optional_score_output(value: Option<f64>) -> CommandOutput {
    match value {
        Some(value) => score_output(value),
        None => CommandOutput::Nil,
    }
}

fn geopos_output_from_shard(
    data: &store::ShardData,
    key: &[u8],
    members: &[&[u8]],
    now: Instant,
) -> Result<CommandOutput, LuxError> {
    let mut values = Vec::with_capacity(members.len());
    for member in members {
        match Store::zscore_from_shard(data, key, member, now).map_err(LuxError::Command)? {
            Some(score) => {
                let (lon, lat) = crate::geo::geohash_decode(score as u64);
                values.push(CommandOutput::Array(vec![
                    CommandOutput::Bulk(bytes::Bytes::from(format_geo_coord(lon))),
                    CommandOutput::Bulk(bytes::Bytes::from(format_geo_coord(lat))),
                ]));
            }
            None => values.push(CommandOutput::Nil),
        }
    }
    Ok(CommandOutput::Array(values))
}

fn geodist_output_from_shard(
    data: &store::ShardData,
    key: &[u8],
    member_a: &[u8],
    member_b: &[u8],
    unit: &[u8],
    now: Instant,
) -> Result<CommandOutput, LuxError> {
    let unit = std::str::from_utf8(unit)
        .ok()
        .and_then(crate::geo::DistUnit::parse)
        .ok_or_else(|| {
            LuxError::Command("ERR unsupported unit provided. please use M, KM, FT, MI".to_string())
        })?;
    let Some(score_a) =
        Store::zscore_from_shard(data, key, member_a, now).map_err(LuxError::Command)?
    else {
        return Ok(CommandOutput::Nil);
    };
    let Some(score_b) =
        Store::zscore_from_shard(data, key, member_b, now).map_err(LuxError::Command)?
    else {
        return Ok(CommandOutput::Nil);
    };
    let (lon_a, lat_a) = crate::geo::geohash_decode(score_a as u64);
    let (lon_b, lat_b) = crate::geo::geohash_decode(score_b as u64);
    let distance = unit.from_meters(crate::geo::haversine(lon_a, lat_a, lon_b, lat_b));
    Ok(CommandOutput::Bulk(bytes::Bytes::from(format!(
        "{distance:.4}"
    ))))
}

fn score_output(value: f64) -> CommandOutput {
    CommandOutput::Bulk(bytes::Bytes::from(format_float(value)))
}

fn zrange_output(items: Vec<(String, f64)>, with_scores: bool) -> CommandOutput {
    let mut values = Vec::with_capacity(if with_scores {
        items.len() * 2
    } else {
        items.len()
    });
    for (member, score) in items {
        values.push(CommandOutput::Bulk(bytes::Bytes::from(member)));
        if with_scores {
            values.push(score_output(score));
        }
    }
    CommandOutput::Array(values)
}

fn random_key_output(store: &Store, now: Instant) -> CommandOutput {
    for i in 0..store.shard_count() {
        let shard = store.lock_read_shard(i);
        if let Some((key, _)) = shard
            .data
            .iter()
            .find(|(_, entry)| !entry.is_expired_at(now))
        {
            return CommandOutput::Bulk(bytes::Bytes::from(key.clone()));
        }
    }
    CommandOutput::Nil
}

fn arg_str(arg: &[u8]) -> &str {
    std::str::from_utf8(arg).unwrap_or("")
}

fn xadd_fields(fields: &[(&[u8], &[u8])]) -> Vec<(String, bytes::Bytes)> {
    fields
        .iter()
        .map(|(field, value)| {
            (
                arg_str(field).to_string(),
                bytes::Bytes::copy_from_slice(value),
            )
        })
        .collect()
}

fn require_xadd_fields(fields: &[(&[u8], &[u8])]) -> Result<(), LuxError> {
    if fields.is_empty() {
        return Err(LuxError::Command(
            "ERR wrong number of arguments for 'xadd' command".to_string(),
        ));
    }
    Ok(())
}

fn command_is_fast_path_write(command: &Command<'_>) -> bool {
    matches!(
        command,
        Command::FlushDb
            | Command::FlushAll
            | Command::Set { .. }
            | Command::GetSet { .. }
            | Command::SetNx { .. }
            | Command::SetEx { .. }
            | Command::PSetEx { .. }
            | Command::MSet { .. }
            | Command::MSetNx { .. }
            | Command::Append { .. }
            | Command::Incr { .. }
            | Command::Decr { .. }
            | Command::IncrBy { .. }
            | Command::DecrBy { .. }
            | Command::Del { .. }
            | Command::Unlink { .. }
            | Command::Expire { .. }
            | Command::Persist { .. }
            | Command::Rename { .. }
            | Command::RenameNx { .. }
            | Command::LPush { .. }
            | Command::RPush { .. }
            | Command::LPop { .. }
            | Command::RPop { .. }
            | Command::HSet { .. }
            | Command::HIncrBy { .. }
            | Command::HDel { .. }
            | Command::SAdd { .. }
            | Command::SRem { .. }
            | Command::SPop { .. }
            | Command::ZAdd { .. }
            | Command::ZRem { .. }
            | Command::ZIncrBy { .. }
            | Command::GeoAdd { .. }
            | Command::XAdd { .. }
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativePipelineAccess {
    Read,
    Write,
}

fn native_pipeline_access<'a>(command: &Command<'a>) -> Option<(&'a [u8], NativePipelineAccess)> {
    // Only simple single-shard commands are eligible for native batching.
    // Commands with multi-key routing, transaction/session behavior, or side
    // effects outside the shard lock stay on the generic path.
    let (key, op) = match command {
        Command::Get { key } => (*key, b"GET".as_slice()),
        Command::StrLen { key } => (*key, b"STRLEN".as_slice()),
        Command::HGet { key, .. } => (*key, b"HGET".as_slice()),
        Command::GeoPos { key, .. } => (*key, b"GEOPOS".as_slice()),
        Command::GeoDist { key, .. } => (*key, b"GEODIST".as_slice()),
        Command::Exists { keys } if keys.len() == 1 => (keys[0], b"EXISTS".as_slice()),
        Command::Set { key, options, .. } if can_fast_path_set(options) => {
            (*key, b"SET".as_slice())
        }
        Command::GetSet { key, .. } => (*key, b"GETSET".as_slice()),
        Command::SetNx { key, .. } => (*key, b"SETNX".as_slice()),
        Command::SetEx { key, .. } => (*key, b"SETEX".as_slice()),
        Command::PSetEx { key, .. } => (*key, b"PSETEX".as_slice()),
        Command::Append { key, .. } => (*key, b"APPEND".as_slice()),
        Command::Incr { key } => (*key, b"INCR".as_slice()),
        Command::Decr { key } => (*key, b"DECR".as_slice()),
        Command::IncrBy { key, .. } => (*key, b"INCRBY".as_slice()),
        Command::DecrBy { key, .. } => (*key, b"DECRBY".as_slice()),
        Command::LPush { key, .. } => (*key, b"LPUSH".as_slice()),
        Command::RPush { key, .. } => (*key, b"RPUSH".as_slice()),
        Command::LPop { key } => (*key, b"LPOP".as_slice()),
        Command::RPop { key } => (*key, b"RPOP".as_slice()),
        Command::HSet { key, .. } => (*key, b"HSET".as_slice()),
        Command::HIncrBy { key, .. } => (*key, b"HINCRBY".as_slice()),
        Command::SAdd { key, .. } => (*key, b"SADD".as_slice()),
        Command::SPop { key } => (*key, b"SPOP".as_slice()),
        Command::ZAdd { key, .. } => (*key, b"ZADD".as_slice()),
        Command::ZIncrBy { key, .. } => (*key, b"ZINCRBY".as_slice()),
        Command::GeoAdd { key, .. } => (*key, b"GEOADD".as_slice()),
        Command::XAdd { key, .. } => (*key, b"XADD".as_slice()),
        Command::Del { keys } | Command::Unlink { keys } if keys.len() == 1 => {
            (keys[0], b"DEL".as_slice())
        }
        _ => return None,
    };

    match cmd::pipeline_access(op) {
        cmd::PipelineAccess::Read => Some((key, NativePipelineAccess::Read)),
        cmd::PipelineAccess::Write => Some((key, NativePipelineAccess::Write)),
        cmd::PipelineAccess::General => None,
    }
}

fn wal_log_native_command(store: &Store, command: &Command<'_>) -> Result<(), LuxError> {
    if !store.wal_enabled() {
        return Ok(());
    }

    // Borrowed-argv WAL fast path. Each arm must encode the exact argv that
    // `Command::to_owned_argv` would produce so crash replay sees identical
    // command semantics without allocating owned argument vectors.
    match command {
        Command::Set {
            key,
            value,
            options,
        } => match options.as_slice() {
            [] => {
                let args = [b"SET".as_slice(), *key, *value];
                store.wal_log_command(&args).map_err(wal_lux_error)?;
            }
            [SetOption::Ex(seconds)] => {
                let seconds = seconds.to_string();
                let args = [
                    b"SET".as_slice(),
                    *key,
                    *value,
                    b"EX".as_slice(),
                    seconds.as_bytes(),
                ];
                store.wal_log_command(&args).map_err(wal_lux_error)?;
            }
            [SetOption::Px(milliseconds)] => {
                let milliseconds = milliseconds.to_string();
                let args = [
                    b"SET".as_slice(),
                    *key,
                    *value,
                    b"PX".as_slice(),
                    milliseconds.as_bytes(),
                ];
                store.wal_log_command(&args).map_err(wal_lux_error)?;
            }
            _ => wal_log_owned_command(store, command)?,
        },
        Command::GetSet { key, value } => {
            let args = [b"GETSET".as_slice(), *key, *value];
            store.wal_log_command(&args).map_err(wal_lux_error)?;
        }
        Command::SetNx { key, value } => {
            let args = [b"SETNX".as_slice(), *key, *value];
            store.wal_log_command(&args).map_err(wal_lux_error)?;
        }
        Command::SetEx {
            key,
            seconds,
            value,
        } => {
            let seconds = seconds.to_string();
            let args = [b"SETEX".as_slice(), *key, seconds.as_bytes(), *value];
            store.wal_log_command(&args).map_err(wal_lux_error)?;
        }
        Command::PSetEx {
            key,
            milliseconds,
            value,
        } => {
            let milliseconds = milliseconds.to_string();
            let args = [b"PSETEX".as_slice(), *key, milliseconds.as_bytes(), *value];
            store.wal_log_command(&args).map_err(wal_lux_error)?;
        }
        Command::MSet { pairs } => {
            let mut args = Vec::with_capacity(1 + pairs.len() * 2);
            args.push(b"MSET".as_slice());
            for (key, value) in pairs {
                args.push(*key);
                args.push(*value);
            }
            store.wal_log_command(&args).map_err(wal_lux_error)?;
        }
        Command::Append { key, value } => {
            let args = [b"APPEND".as_slice(), *key, *value];
            store.wal_log_command(&args).map_err(wal_lux_error)?;
        }
        Command::Incr { key } => {
            let args = [b"INCR".as_slice(), *key];
            store.wal_log_command(&args).map_err(wal_lux_error)?;
        }
        Command::Decr { key } => {
            let args = [b"DECR".as_slice(), *key];
            store.wal_log_command(&args).map_err(wal_lux_error)?;
        }
        Command::IncrBy { key, increment } => {
            let increment = increment.to_string();
            let args = [b"INCRBY".as_slice(), *key, increment.as_bytes()];
            store.wal_log_command(&args).map_err(wal_lux_error)?;
        }
        Command::DecrBy { key, decrement } => {
            let decrement = decrement.to_string();
            let args = [b"DECRBY".as_slice(), *key, decrement.as_bytes()];
            store.wal_log_command(&args).map_err(wal_lux_error)?;
        }
        Command::Del { keys } if keys.len() == 1 => {
            let args = [b"DEL".as_slice(), keys[0]];
            store.wal_log_command(&args).map_err(wal_lux_error)?;
        }
        Command::Unlink { keys } if keys.len() == 1 => {
            let args = [b"UNLINK".as_slice(), keys[0]];
            store.wal_log_command(&args).map_err(wal_lux_error)?;
        }
        Command::LPush { key, values } => {
            let mut args = Vec::with_capacity(values.len() + 2);
            args.push(b"LPUSH".as_slice());
            args.push(*key);
            args.extend(values.iter().copied());
            store.wal_log_command(&args).map_err(wal_lux_error)?;
        }
        Command::RPush { key, values } => {
            let mut args = Vec::with_capacity(values.len() + 2);
            args.push(b"RPUSH".as_slice());
            args.push(*key);
            args.extend(values.iter().copied());
            store.wal_log_command(&args).map_err(wal_lux_error)?;
        }
        Command::LPop { key } => {
            let args = [b"LPOP".as_slice(), *key];
            store.wal_log_command(&args).map_err(wal_lux_error)?;
        }
        Command::RPop { key } => {
            let args = [b"RPOP".as_slice(), *key];
            store.wal_log_command(&args).map_err(wal_lux_error)?;
        }
        Command::HSet { key, field, value } => {
            let args = [b"HSET".as_slice(), *key, *field, *value];
            store.wal_log_command(&args).map_err(wal_lux_error)?;
        }
        Command::HIncrBy {
            key,
            field,
            increment,
        } => {
            let increment = increment.to_string();
            let args = [b"HINCRBY".as_slice(), *key, *field, increment.as_bytes()];
            store.wal_log_command(&args).map_err(wal_lux_error)?;
        }
        Command::SAdd { key, members } => {
            let mut args = Vec::with_capacity(members.len() + 2);
            args.push(b"SADD".as_slice());
            args.push(*key);
            args.extend(members.iter().copied());
            store.wal_log_command(&args).map_err(wal_lux_error)?;
        }
        Command::SPop { key } => {
            let args = [b"SPOP".as_slice(), *key];
            store.wal_log_command(&args).map_err(wal_lux_error)?;
        }
        Command::ZAdd { key, score, member } => {
            let score = score.to_string();
            let args = [b"ZADD".as_slice(), *key, score.as_bytes(), *member];
            store.wal_log_command(&args).map_err(wal_lux_error)?;
        }
        Command::ZIncrBy {
            key,
            increment,
            member,
        } => {
            let increment = increment.to_string();
            let args = [b"ZINCRBY".as_slice(), *key, increment.as_bytes(), *member];
            store.wal_log_command(&args).map_err(wal_lux_error)?;
        }
        Command::XAdd { key, id, fields } => {
            let mut args = Vec::with_capacity(fields.len() * 2 + 3);
            args.push(b"XADD".as_slice());
            args.push(*key);
            args.push(*id);
            for (field, value) in fields {
                args.push(*field);
                args.push(*value);
            }
            store.wal_log_command(&args).map_err(wal_lux_error)?;
        }
        _ => wal_log_owned_command(store, command)?,
    }
    Ok(())
}

fn wal_lux_error(error: std::io::Error) -> LuxError {
    LuxError::Command(format!("ERR WAL append failed: {error}"))
}

fn ensure_write_allowed(store: &Store) -> Result<(), LuxError> {
    crate::eviction::evict_if_needed(store).map_err(|e| LuxError::Command(e.to_string()))
}

fn wal_log_owned_command(store: &Store, command: &Command<'_>) -> Result<(), LuxError> {
    let argv = command.to_owned_argv();
    let refs = argv.iter().map(Vec::as_slice).collect::<Vec<_>>();
    store.wal_log_command(&refs).map_err(wal_lux_error)?;
    Ok(())
}

fn can_fast_path_set(options: &[SetOption]) -> bool {
    options
        .iter()
        .all(|option| matches!(option, SetOption::Ex(_) | SetOption::Px(_)))
}

fn set_ttl(options: &[SetOption]) -> Option<Duration> {
    options.iter().find_map(|option| match option {
        SetOption::Ex(seconds) => Some(Duration::from_secs(*seconds)),
        SetOption::Px(milliseconds) => u64::try_from(*milliseconds).ok().map(Duration::from_millis),
        SetOption::Nx | SetOption::Xx | SetOption::KeepTtl => None,
    })
}

fn parse_score_bound_bytes(input: &[u8], is_max: bool) -> (f64, bool) {
    let s = std::str::from_utf8(input).unwrap_or("");
    if s == "-inf" || s == "-" {
        (f64::NEG_INFINITY, false)
    } else if s == "+inf" || s == "+" {
        (f64::INFINITY, false)
    } else if let Some(rest) = s.strip_prefix('(') {
        (
            rest.parse::<f64>().unwrap_or(if is_max {
                f64::INFINITY
            } else {
                f64::NEG_INFINITY
            }),
            true,
        )
    } else {
        (
            s.parse::<f64>().unwrap_or(if is_max {
                f64::INFINITY
            } else {
                f64::NEG_INFINITY
            }),
            false,
        )
    }
}

fn format_float(v: f64) -> String {
    if v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        format!("{v}")
    }
}

fn format_geo_coord(v: f64) -> String {
    if v == 0.0 {
        return "0".to_string();
    }
    let magnitude = v.abs().log10().floor() as usize + 1;
    let decimals = 17usize.saturating_sub(magnitude);
    let s = format!("{v:.decimals$}");
    s.trim_end_matches('0').trim_end_matches('.').to_string()
}

impl EmbeddedSubscription {
    fn new(
        broker: Broker,
        receiver: broadcast::Receiver<pubsub::Message>,
        kind: EmbeddedSubscriptionKind,
    ) -> Self {
        Self {
            broker: Some(broker),
            receiver: Some(receiver),
            kind,
        }
    }

    pub async fn recv(&mut self) -> Result<EmbeddedMessage, LuxError> {
        let receiver = self.receiver.as_mut().ok_or(LuxError::SubscriptionClosed)?;
        match receiver.recv().await {
            Ok(message) => Ok(message.into()),
            Err(broadcast::error::RecvError::Closed) => Err(LuxError::SubscriptionClosed),
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                Err(LuxError::SubscriptionLagged(skipped))
            }
        }
    }

    pub fn try_recv(&mut self) -> Result<Option<EmbeddedMessage>, LuxError> {
        let receiver = self.receiver.as_mut().ok_or(LuxError::SubscriptionClosed)?;
        match receiver.try_recv() {
            Ok(message) => Ok(Some(message.into())),
            Err(broadcast::error::TryRecvError::Empty) => Ok(None),
            Err(broadcast::error::TryRecvError::Closed) => Err(LuxError::SubscriptionClosed),
            Err(broadcast::error::TryRecvError::Lagged(skipped)) => {
                Err(LuxError::SubscriptionLagged(skipped))
            }
        }
    }

    pub fn close(mut self) {
        self.close_inner();
    }

    fn close_inner(&mut self) {
        self.receiver.take();
        if let Some(broker) = self.broker.as_ref() {
            match &self.kind {
                EmbeddedSubscriptionKind::Channel(channel) => broker.unsubscribe_channel(channel),
                EmbeddedSubscriptionKind::Pattern(pattern) => broker.punsubscribe_pattern(pattern),
                EmbeddedSubscriptionKind::KeyPattern(pattern) => broker.kunsub(pattern),
            }
        }
        self.broker.take();
    }
}

impl Drop for EmbeddedSubscription {
    fn drop(&mut self) {
        self.close_inner();
    }
}

impl From<pubsub::Message> for EmbeddedMessage {
    fn from(message: pubsub::Message) -> Self {
        let kind = match message.kind {
            pubsub::MessageKind::PubSub => EmbeddedMessageKind::PubSub,
            pubsub::MessageKind::KeyEvent => EmbeddedMessageKind::KeyEvent,
        };
        Self {
            channel: message.channel,
            payload: message.payload,
            pattern: message.pattern,
            kind,
        }
    }
}

fn parse_single_embedded_value(buf: &[u8]) -> Result<EmbeddedValue, LuxError> {
    let mut parser = RespValueParser::new(buf);
    let value = parser.parse_value()?;
    if parser.pos != buf.len() {
        return Err(LuxError::Protocol(
            "trailing bytes after RESP value".to_string(),
        ));
    }
    match value {
        EmbeddedValue::Error(msg) => Err(LuxError::Command(msg)),
        value => Ok(value),
    }
}

fn parse_embedded_values(buf: &[u8]) -> Result<Vec<EmbeddedValue>, LuxError> {
    let mut parser = RespValueParser::new(buf);
    let mut values = Vec::new();
    while parser.pos < buf.len() {
        values.push(parser.parse_value()?);
    }
    Ok(values)
}

fn parse_blocking_pop_value(buf: &[u8]) -> Result<Option<(String, bytes::Bytes)>, LuxError> {
    match parse_single_embedded_value(buf)? {
        EmbeddedValue::Nil => Ok(None),
        EmbeddedValue::Array(items) if items.len() == 2 => {
            let mut iter = items.into_iter();
            let key = match iter.next().unwrap() {
                EmbeddedValue::Bulk(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
                EmbeddedValue::Simple(value) => value,
                other => {
                    return Err(LuxError::Protocol(format!(
                        "expected blocking pop key, got {other:?}"
                    )))
                }
            };
            let value = match iter.next().unwrap() {
                EmbeddedValue::Bulk(bytes) => bytes,
                other => {
                    return Err(LuxError::Protocol(format!(
                        "expected blocking pop value, got {other:?}"
                    )))
                }
            };
            Ok(Some((key, value)))
        }
        other => Err(LuxError::Protocol(format!(
            "expected blocking pop array, got {other:?}"
        ))),
    }
}

async fn wait_for_blocking_pop(
    broker: &Broker,
    keys: &[String],
    timeout: Duration,
    pop_left: bool,
) -> Result<Option<(String, bytes::Bytes)>, LuxError> {
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

    let result = tokio::select! {
        val = rx.recv() => val,
        _ = tokio::time::sleep(timeout) => None,
    };

    broker.remove_list_waiters_by_id(keys, waiter_id);
    Ok(result)
}

struct RespValueParser<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> RespValueParser<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn parse_value(&mut self) -> Result<EmbeddedValue, LuxError> {
        let Some(prefix) = self.take_byte() else {
            return Err(LuxError::Protocol("empty RESP value".to_string()));
        };
        match prefix {
            b'+' => Ok(EmbeddedValue::Simple(self.read_line_string()?)),
            b'-' => Ok(EmbeddedValue::Error(self.read_line_string()?)),
            b':' => {
                let line = self.read_line()?;
                let n = parse_i64_ascii(line)?;
                Ok(EmbeddedValue::Int(n))
            }
            b'$' => self.parse_bulk(),
            b'*' => self.parse_array(),
            b'%' => self.parse_map(),
            _ => Err(LuxError::Protocol(format!(
                "unsupported RESP prefix byte: {prefix}"
            ))),
        }
    }

    fn parse_bulk(&mut self) -> Result<EmbeddedValue, LuxError> {
        let len = parse_i64_ascii(self.read_line()?)?;
        if len < 0 {
            return Ok(EmbeddedValue::Nil);
        }
        let len = len as usize;
        if self.pos + len + 2 > self.buf.len() {
            return Err(LuxError::Protocol("truncated RESP bulk string".to_string()));
        }
        let data = bytes::Bytes::copy_from_slice(&self.buf[self.pos..self.pos + len]);
        self.pos += len;
        self.expect_crlf()?;
        Ok(EmbeddedValue::Bulk(data))
    }

    fn parse_array(&mut self) -> Result<EmbeddedValue, LuxError> {
        let len = parse_i64_ascii(self.read_line()?)?;
        if len < 0 {
            return Ok(EmbeddedValue::Nil);
        }
        let mut values = Vec::with_capacity(len as usize);
        for _ in 0..len {
            values.push(self.parse_value()?);
        }
        Ok(EmbeddedValue::Array(values))
    }

    fn parse_map(&mut self) -> Result<EmbeddedValue, LuxError> {
        let len = parse_i64_ascii(self.read_line()?)?;
        if len < 0 {
            return Ok(EmbeddedValue::Nil);
        }
        let mut values = Vec::with_capacity(len as usize);
        for _ in 0..len {
            let key = self.parse_value()?;
            let value = self.parse_value()?;
            values.push((key, value));
        }
        Ok(EmbeddedValue::Map(values))
    }

    fn take_byte(&mut self) -> Option<u8> {
        let byte = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(byte)
    }

    fn read_line_string(&mut self) -> Result<String, LuxError> {
        Ok(String::from_utf8_lossy(self.read_line()?).into_owned())
    }

    fn read_line(&mut self) -> Result<&'a [u8], LuxError> {
        let start = self.pos;
        while self.pos + 1 < self.buf.len() {
            if self.buf[self.pos] == b'\r' && self.buf[self.pos + 1] == b'\n' {
                let line = &self.buf[start..self.pos];
                self.pos += 2;
                return Ok(line);
            }
            self.pos += 1;
        }
        Err(LuxError::Protocol(
            "missing RESP line terminator".to_string(),
        ))
    }

    fn expect_crlf(&mut self) -> Result<(), LuxError> {
        if self.pos + 1 >= self.buf.len()
            || self.buf[self.pos] != b'\r'
            || self.buf[self.pos + 1] != b'\n'
        {
            return Err(LuxError::Protocol(
                "missing RESP bulk terminator".to_string(),
            ));
        }
        self.pos += 2;
        Ok(())
    }
}

fn parse_i64_ascii(input: &[u8]) -> Result<i64, LuxError> {
    let value = std::str::from_utf8(input)
        .map_err(|_| LuxError::Protocol("RESP integer is not UTF-8".to_string()))?;
    value
        .parse::<i64>()
        .map_err(|_| LuxError::Protocol("invalid RESP integer".to_string()))
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
        .map_err(|_| std::io::Error::other(closed_message))?
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
    validate_listener_security(&config)?;
    validate_auth_config(&config)?;
    validate_shard_count(&config)?;
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
    let runtime =
        wait_for_startup(ready_rx, "server startup failed before readiness signal").await?;
    Ok(ServerHandle {
        runtime,
        shutdown_tx,
        server_task,
        local_addr,
    })
}

async fn server_main(
    listener: Option<TcpListener>,
    config: ServerConfig,
    mut shutdown_rx: watch::Receiver<bool>,
    ready_tx: oneshot::Sender<std::io::Result<Arc<Runtime>>>,
) -> std::io::Result<()> {
    let mut background_tasks = JoinSet::new();
    let runtime = Runtime::start(config, &mut background_tasks).await?;

    if let Some(http_startup_rx) = runtime.start_http_if_enabled(&mut background_tasks) {
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
    let _ = ready_tx.send(Ok(runtime.clone()));

    let mut conn_tasks = JoinSet::new();
    // HTTP binds inside its task, so wait for its one-shot before reporting the
    // whole runtime as ready to embedded callers.
    if !runtime.config.enable_resp {
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
                    let runtime = runtime.clone();
                    let on_warn = runtime.config.on_warn.clone();
                    socket.set_nodelay(true).ok();

                    conn_tasks.spawn(async move {
                        runtime.store.client_connected();
                        let result = handle_connection(socket, peer, runtime.clone()).await;
                        runtime.store.client_disconnected();
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

impl Runtime {
    async fn start(
        config: ServerConfig,
        background_tasks: &mut JoinSet<()>,
    ) -> std::io::Result<Arc<Self>> {
        let config = Arc::new(config);
        let store = Arc::new(Store::new_with_config(config.clone()));
        let schema_cache: SharedSchemaCache =
            std::sync::Arc::new(parking_lot::RwLock::new(tables::SchemaCache::new()));
        let broker = Broker::new();
        let shard_executor = ShardExecutor::new(store.clone(), broker.clone());
        let script_engine = Arc::new(lua::ScriptEngine::new());

        let runtime = Arc::new(Self {
            store,
            broker,
            shard_executor,
            schema_cache,
            script_engine,
            config,
        });

        if runtime.config.storage.mode == StorageMode::Tiered {
            emit_info(
                &runtime.config,
                ServerInfoEvent::TieredStorageEnabled {
                    dir: runtime.config.storage.dir.clone(),
                },
            );
        }

        runtime
            .store
            .wal_suppress
            .store(true, std::sync::atomic::Ordering::Relaxed);
        if runtime.config.auth.enabled {
            if let Err(e) =
                auth::bootstrap(&runtime.store, &runtime.schema_cache, &runtime.config.auth)
            {
                runtime
                    .store
                    .wal_suppress
                    .store(false, std::sync::atomic::Ordering::Relaxed);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("auth bootstrap failed: {e}"),
                ));
            }
        }
        runtime
            .store
            .wal_suppress
            .store(true, std::sync::atomic::Ordering::Relaxed);
        match snapshot::load(&runtime.store) {
            Ok(0) => emit_info(&runtime.config, ServerInfoEvent::NoSnapshotFound),
            Ok(n) => emit_info(&runtime.config, ServerInfoEvent::SnapshotLoaded { keys: n }),
            Err(e) => emit_error(
                &runtime.config,
                ServerErrorEvent::SnapshotLoadFailed {
                    error: e.to_string(),
                },
            ),
        }
        runtime
            .store
            .wal_suppress
            .store(false, std::sync::atomic::Ordering::Relaxed);
        runtime.store.replay_wal(&runtime.broker);
        if runtime.config.auth.enabled {
            runtime
                .store
                .wal_suppress
                .store(true, std::sync::atomic::Ordering::Relaxed);
            if let Err(e) =
                auth::bootstrap(&runtime.store, &runtime.schema_cache, &runtime.config.auth)
            {
                runtime
                    .store
                    .wal_suppress
                    .store(false, std::sync::atomic::Ordering::Relaxed);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("auth bootstrap failed: {e}"),
                ));
            }
            runtime
                .store
                .wal_suppress
                .store(false, std::sync::atomic::Ordering::Relaxed);
            if let Err(e) =
                auth::bootstrap_runtime(&runtime.store, &runtime.schema_cache, &runtime.config.auth)
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("auth runtime bootstrap failed: {e}"),
                ));
            }
        }

        background_tasks.spawn(snapshot::background_save_loop(runtime.store.clone()));

        {
            let store = runtime.store.clone();
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

        // Table-row TTL sweep: expire due rows (full delete bookkeeping) and fire
        // one `.live()` key-event per affected table so subscribers get a delete.
        {
            let store = runtime.store.clone();
            let cache = runtime.schema_cache.clone();
            let broker = runtime.broker.clone();
            background_tasks.spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    let now = Instant::now();
                    for table in tables::expire_due_rows(&store, &cache, now) {
                        broker.enqueue_key_event(table.as_bytes(), b"TEXPIRE");
                    }
                }
            });
        }

        if runtime.config.storage.mode == StorageMode::Tiered {
            {
                let store = runtime.store.clone();
                background_tasks.spawn(async move {
                    loop {
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        store.fsync_wal();
                    }
                });
            }
            {
                let store = runtime.store.clone();
                background_tasks.spawn(async move {
                    loop {
                        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                        store.compact_disk_shards();
                    }
                });
            }
        }

        Ok(runtime)
    }

    fn start_http_if_enabled(
        self: &Arc<Self>,
        background_tasks: &mut JoinSet<()>,
    ) -> Option<oneshot::Receiver<std::io::Result<std::net::SocketAddr>>> {
        if self.config.http_port == 0 {
            return None;
        }
        let http_store = self.store.clone();
        let http_broker = self.broker.clone();
        let http_cache = self.schema_cache.clone();
        let http_script_engine = self.script_engine.clone();
        let http_port = self.config.http_port;
        let bind_host = self.config.bind_host.clone();
        let max_rows = self.config.max_rows;
        let max_body = self.config.max_body;
        let (startup_tx, startup_rx) = oneshot::channel();
        let on_ready = self.config.on_info.clone().map(|on_info| {
            Arc::new(move |addr| on_info(ServerInfoEvent::HttpReady { addr }))
                as Arc<dyn Fn(std::net::SocketAddr) + Send + Sync>
        });
        let on_error = self.config.on_error.clone();
        background_tasks.spawn(async move {
            let http_config = http::HttpServerConfig {
                bind_host,
                http_port,
                max_rows,
                max_body,
                on_ready,
                startup_ready: Some(startup_tx),
            };
            if let Err(e) = http::start_http_server(
                http_config,
                http_store,
                http_broker,
                http_cache,
                http_script_engine,
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
        Some(startup_rx)
    }
}

#[inline(always)]
fn cmd_eq_fast(input: &[u8], expected: &[u8]) -> bool {
    cmd::cmd_eq_ci(input, expected)
}

#[inline(always)]
fn fire_key_events(broker: &Broker, args: &[&[u8]]) {
    if args.len() < 2 {
        return;
    }
    if !broker.has_key_subs() {
        return;
    }
    fire_key_events_slow(broker, args);
}

#[inline(always)]
fn wake_zset_waiters_for_key(broker: &Broker, key: &[u8]) {
    broker.wake_zset_waiters(arg_str(key));
}

fn notify_zset_waiters_for_command(broker: &Broker, command: &Command<'_>) {
    if !broker.has_zset_waiters() || !command_is_fast_path_write(command) {
        return;
    }

    match command {
        Command::FlushDb | Command::FlushAll => {}
        Command::MSet { pairs } | Command::MSetNx { pairs } => {
            for (key, _) in pairs {
                wake_zset_waiters_for_key(broker, key);
            }
        }
        Command::Del { keys } | Command::Unlink { keys } => {
            for key in keys {
                wake_zset_waiters_for_key(broker, key);
            }
        }
        Command::Rename { key, new_key } | Command::RenameNx { key, new_key } => {
            wake_zset_waiters_for_key(broker, key);
            wake_zset_waiters_for_key(broker, new_key);
        }
        Command::Set { key, .. }
        | Command::GetSet { key, .. }
        | Command::SetNx { key, .. }
        | Command::SetEx { key, .. }
        | Command::PSetEx { key, .. }
        | Command::Append { key, .. }
        | Command::Incr { key }
        | Command::Decr { key }
        | Command::IncrBy { key, .. }
        | Command::DecrBy { key, .. }
        | Command::Expire { key, .. }
        | Command::Persist { key }
        | Command::LPush { key, .. }
        | Command::RPush { key, .. }
        | Command::LPop { key }
        | Command::RPop { key }
        | Command::HSet { key, .. }
        | Command::HIncrBy { key, .. }
        | Command::HDel { key, .. }
        | Command::SAdd { key, .. }
        | Command::SRem { key, .. }
        | Command::SPop { key }
        | Command::ZAdd { key, .. }
        | Command::ZRem { key, .. }
        | Command::ZIncrBy { key, .. }
        | Command::GeoAdd { key, .. }
        | Command::XAdd { key, .. } => wake_zset_waiters_for_key(broker, key),
        _ => {}
    }
}

fn notify_zset_waiters_for_script_keys(broker: &Broker, keys: &[Vec<u8>]) {
    if !broker.has_zset_waiters() {
        return;
    }
    for key in keys {
        broker.wake_zset_waiters(arg_str(key));
    }
}

fn notify_zset_waiters_for_write(broker: &Broker, args: &[&[u8]]) {
    if !broker.has_zset_waiters() || args.len() < 2 || !crate::eviction::is_write_command(args[0]) {
        return;
    }

    let cmd = args[0];
    if cmd_eq_fast(cmd, b"FLUSHDB") || cmd_eq_fast(cmd, b"FLUSHALL") {
        return;
    }
    if cmd_eq_fast(cmd, b"EVAL") || cmd_eq_fast(cmd, b"EVALSHA") {
        let num_keys = args
            .get(2)
            .and_then(|value| arg_str(value).parse::<usize>().ok())
            .unwrap_or(0);
        let end = 3 + num_keys.min(args.len().saturating_sub(3));
        for key in &args[3..end] {
            wake_zset_waiters_for_key(broker, key);
        }
    } else if cmd_eq_fast(cmd, b"MSET") || cmd_eq_fast(cmd, b"MSETNX") {
        let mut i = 1;
        while i < args.len() {
            wake_zset_waiters_for_key(broker, args[i]);
            i += 2;
        }
    } else if cmd_eq_fast(cmd, b"DEL") || cmd_eq_fast(cmd, b"UNLINK") {
        for key in &args[1..] {
            wake_zset_waiters_for_key(broker, key);
        }
    } else if cmd_eq_fast(cmd, b"RENAME") && args.len() >= 3 {
        wake_zset_waiters_for_key(broker, args[1]);
        wake_zset_waiters_for_key(broker, args[2]);
    } else {
        wake_zset_waiters_for_key(broker, args[1]);
    }
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
    } else if cmd_eq_fast(cmd, b"TDELETE") {
        // `TDELETE FROM <table> WHERE ...` puts the literal FROM at args[1], so
        // the keyed entity is args[2]. Without this, table .live() subscribers
        // never wake on a delete (the event fires on key "FROM").
        let table = if args.len() >= 3 && cmd_eq_fast(args[1], b"FROM") {
            args[2]
        } else {
            args[1]
        };
        broker.enqueue_key_event(table, cmd);
    } else {
        broker.enqueue_key_event(args[1], cmd);
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_tx_cmd(
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
                        CmdResult::Written => {
                            notify_zset_waiters_for_write(broker, &refs);
                        }
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
            || cmd_eq_fast(args[0], b"UNSUBSCRIBE")
            || cmd_eq_fast(args[0], b"PSUBSCRIBE")
            || cmd_eq_fast(args[0], b"PUNSUBSCRIBE")
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
fn is_public_without_auth_cmd(cmd: &[u8]) -> bool {
    cmd::is_public_without_auth_command(cmd)
}

fn is_blocking_cmd(cmd: &[u8]) -> bool {
    cmd::is_blocking_command(cmd)
}

pub(crate) struct CommandSession {
    authenticated: bool,
    in_multi: bool,
    tx_queue: Vec<Vec<Vec<u8>>>,
    watched: Vec<(String, usize, u64)>,
    tx_error: bool,
    subscriptions: HashMap<String, broadcast::Receiver<pubsub::Message>>,
    pattern_subs: HashMap<String, broadcast::Receiver<pubsub::Message>>,
    key_subs: HashMap<String, broadcast::Receiver<pubsub::Message>>,
    sub_mode: bool,
}

impl CommandSession {
    pub(crate) fn new(require_auth: bool) -> Self {
        Self {
            authenticated: !require_auth,
            in_multi: false,
            tx_queue: Vec::new(),
            watched: Vec::new(),
            tx_error: false,
            subscriptions: HashMap::new(),
            pattern_subs: HashMap::new(),
            key_subs: HashMap::new(),
            sub_mode: false,
        }
    }

    fn total_subscriptions(&self) -> i64 {
        (self.subscriptions.len() + self.pattern_subs.len() + self.key_subs.len()) as i64
    }
}

pub(crate) trait ArgvSlice {
    fn argv(&self) -> &[&[u8]];
}

impl ArgvSlice for Vec<&[u8]> {
    fn argv(&self) -> &[&[u8]] {
        self.as_slice()
    }
}

impl<'a> ArgvSlice for resp::CommandArgs<'a> {
    fn argv(&self) -> &[&[u8]] {
        self.as_slice()
    }
}

pub(crate) struct CommandExecutor {
    store: Arc<Store>,
    broker: Broker,
    shard_executor: ShardExecutor,
    script_engine: Arc<lua::ScriptEngine>,
    schema_cache: SharedSchemaCache,
}

impl CommandExecutor {
    pub(crate) fn new(
        store: Arc<Store>,
        broker: Broker,
        script_engine: Arc<lua::ScriptEngine>,
        schema_cache: SharedSchemaCache,
    ) -> Self {
        let shard_executor = ShardExecutor::new(store.clone(), broker.clone());
        Self {
            store,
            broker,
            shard_executor,
            script_engine,
            schema_cache,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn execute_command(
        &self,
        args: &[&[u8]],
        session: &mut CommandSession,
        write_buf: &mut BytesMut,
        now: Instant,
    ) -> Option<CmdResult> {
        if args.is_empty() || args[0].is_empty() {
            resp::write_error(write_buf, "ERR empty command");
            return None;
        }
        if !session.authenticated && !is_public_without_auth_cmd(args[0]) {
            resp::write_error(write_buf, "NOAUTH Authentication required");
            return None;
        }

        // Reserve the internal table-storage namespace ("_t:") from direct command
        // access. This is the universal entry for both the read fast-path below
        // and the slow path (cmd::execute), so the guard must live here -- the
        // cmd::execute guard alone misses fast-path reads like GET. KEYS/SCAN take
        // a pattern and are filtered in their handlers instead.
        if !args[0].eq_ignore_ascii_case(b"KEYS") && !args[0].eq_ignore_ascii_case(b"SCAN") {
            for arg in &args[1..] {
                if arg.starts_with(b"_t:") {
                    resp::write_error(write_buf, "ERR '_t:' is a reserved internal namespace");
                    return None;
                }
            }
        }

        if handle_tx_cmd(
            args,
            &mut session.in_multi,
            &mut session.tx_error,
            &mut session.tx_queue,
            &mut session.watched,
            &mut session.authenticated,
            &self.store,
            &self.broker,
            &self.schema_cache,
            write_buf,
            now,
        ) {
            return None;
        }

        if !cmd::is_pipeline_special_command(args[0]) {
            let access = cmd::pipeline_access_for_args(args);
            if access == cmd::PipelineAccess::Read {
                let command = [ShardPipelineCommand { args, access }];
                let shard_idx = self.store.shard_for_key(args[1]);
                if let Err(err) = self
                    .shard_executor
                    .execute_pipeline_batch(shard_idx, &command, write_buf, now)
                {
                    write_shard_execution_error(write_buf, err);
                }
                return None;
            }
        }

        let cmd_result = {
            let _guard = self.store.script_read_guard();
            cmd::execute_with_wal(
                &self.store,
                &self.schema_cache,
                &self.broker,
                args,
                write_buf,
                now,
            )
        };
        self.apply_cmd_result(cmd_result, args, session, write_buf, now)
    }

    pub(crate) fn execute_pipeline<A: ArgvSlice>(
        &self,
        commands: &[A],
        session: &mut CommandSession,
        write_buf: &mut BytesMut,
        now: Instant,
    ) -> Option<CmdResult> {
        for command in commands {
            let args = command.argv();
            if args.is_empty() || args[0].is_empty() {
                resp::write_error(write_buf, "ERR empty command");
                return None;
            }
        }

        let cmd_count = commands.len();
        self.store.add_total_commands(cmd_count);

        if !session.in_multi
            && session.authenticated
            && commands.iter().all(|command| {
                let args = command.argv();
                args.len() >= 3 && cmd_eq_fast(args[0], b"PUBLISH")
            })
        {
            for command in commands {
                let args = command.argv();
                let channel = String::from_utf8_lossy(args[1]).into_owned();
                let message = bytes::Bytes::copy_from_slice(args[2]);
                let count = self.broker.publish(&channel, message);
                resp::write_integer(write_buf, count);
            }
            return None;
        }

        let mut has_special = session.in_multi;
        let mut all_single_key_rw = true;
        let mut flags: Vec<cmd::PipelineAccess> = Vec::with_capacity(cmd_count);
        for command in commands {
            let args = command.argv();
            let cmd = args[0];
            if !session.authenticated && !is_public_without_auth_cmd(cmd) {
                has_special = true;
                break;
            }
            if cmd::is_pipeline_special_command(cmd) {
                has_special = true;
                break;
            }
            // Force commands touching the reserved "_t:" namespace onto the slow
            // path, where cmd::execute's guard rejects them. The fast batch path
            // below bypasses that guard. KEYS/SCAN take a pattern and are handled
            // (filtered) on the slow path.
            if !cmd.eq_ignore_ascii_case(b"KEYS")
                && !cmd.eq_ignore_ascii_case(b"SCAN")
                && args[1..].iter().any(|a| a.starts_with(b"_t:"))
            {
                all_single_key_rw = false;
            }
            let access = cmd::pipeline_access_for_args(args);
            flags.push(access);
            if access == cmd::PipelineAccess::General {
                all_single_key_rw = false;
            }
        }

        if has_special || !all_single_key_rw {
            for command in commands {
                let args = command.argv();
                if !session.authenticated && !is_public_without_auth_cmd(args[0]) {
                    resp::write_error(write_buf, "NOAUTH Authentication required");
                    continue;
                }
                if handle_tx_cmd(
                    args,
                    &mut session.in_multi,
                    &mut session.tx_error,
                    &mut session.tx_queue,
                    &mut session.watched,
                    &mut session.authenticated,
                    &self.store,
                    &self.broker,
                    &self.schema_cache,
                    write_buf,
                    now,
                ) {
                    continue;
                }

                let cmd_result = {
                    let _guard = self.store.script_read_guard();
                    cmd::execute_with_wal(
                        &self.store,
                        &self.schema_cache,
                        &self.broker,
                        args,
                        write_buf,
                        now,
                    )
                };
                if let Some(action) =
                    self.apply_cmd_result(cmd_result, args, session, write_buf, now)
                {
                    return Some(action);
                }
            }
            return None;
        }

        let mut shards: Vec<u32> = Vec::with_capacity(cmd_count);
        for (idx, command) in commands.iter().enumerate() {
            let args = command.argv();
            shards.push(self.store.shard_for_key(args[1]) as u32);
            if idx >= flags.len() {
                flags.push(cmd::pipeline_access_for_args(args));
            }
        }

        let mut i = 0usize;
        while i < cmd_count {
            let shard_idx = shards[i] as usize;
            let mut batch_end = i + 1;
            while batch_end < cmd_count && shards[batch_end] == shards[i] {
                batch_end += 1;
            }

            if let Err(err) = self.shard_executor.execute_argv_pipeline_batch(
                shard_idx,
                &commands[i..batch_end],
                &flags[i..batch_end],
                write_buf,
                now,
            ) {
                write_shard_execution_error(write_buf, err);
                return None;
            }
            for (offset, command) in commands[i..batch_end].iter().enumerate() {
                if flags[i + offset] == cmd::PipelineAccess::Write {
                    notify_zset_waiters_for_write(&self.broker, command.argv());
                }
            }

            i = batch_end;
        }
        None
    }

    fn apply_cmd_result(
        &self,
        cmd_result: CmdResult,
        args: &[&[u8]],
        session: &mut CommandSession,
        write_buf: &mut BytesMut,
        now: Instant,
    ) -> Option<CmdResult> {
        match cmd_result {
            CmdResult::Written => {
                notify_zset_waiters_for_write(&self.broker, args);
                fire_key_events(&self.broker, args);
                None
            }
            CmdResult::Authenticated => {
                session.authenticated = true;
                None
            }
            CmdResult::Subscribe { channels } => {
                for ch in &channels {
                    let rx = self.broker.subscribe(ch);
                    session.subscriptions.insert(ch.clone(), rx);
                    resp::write_array_header(write_buf, 3);
                    resp::write_bulk(write_buf, "subscribe");
                    resp::write_bulk(write_buf, ch);
                    resp::write_integer(write_buf, session.total_subscriptions());
                }
                session.sub_mode = true;
                None
            }
            CmdResult::PSubscribe { patterns } => {
                for pat in &patterns {
                    let rx = self.broker.psubscribe(pat);
                    session.pattern_subs.insert(pat.clone(), rx);
                    resp::write_array_header(write_buf, 3);
                    resp::write_bulk(write_buf, "psubscribe");
                    resp::write_bulk(write_buf, pat);
                    resp::write_integer(write_buf, session.total_subscriptions());
                }
                session.sub_mode = true;
                None
            }
            CmdResult::KSubscribe { patterns } => {
                for pat in &patterns {
                    if !session.key_subs.contains_key(pat) {
                        let rx = self.broker.ksubscribe(pat);
                        session.key_subs.insert(pat.clone(), rx);
                    }
                    resp::write_array_header(write_buf, 3);
                    resp::write_bulk(write_buf, "ksub");
                    resp::write_bulk(write_buf, pat);
                    resp::write_integer(write_buf, session.total_subscriptions());
                }
                session.sub_mode = true;
                None
            }
            CmdResult::KUnsubscribe { patterns } => {
                let pats: Vec<String> = if patterns.is_empty() {
                    session.key_subs.keys().cloned().collect()
                } else {
                    patterns
                };
                for pat in &pats {
                    if session.key_subs.remove(pat).is_some() {
                        self.broker.kunsub(pat);
                    }
                    resp::write_array_header(write_buf, 3);
                    resp::write_bulk(write_buf, "kunsub");
                    resp::write_bulk(write_buf, pat);
                    resp::write_integer(write_buf, session.total_subscriptions());
                }
                None
            }
            CmdResult::Publish { channel, message } => {
                let count = self.broker.publish(&channel, message);
                resp::write_integer(write_buf, count);
                None
            }
            CmdResult::BlockPop { .. }
            | CmdResult::BlockMove { .. }
            | CmdResult::BlockStreamRead { .. }
            | CmdResult::BlockZPop { .. } => Some(cmd_result),
            CmdResult::Eval { script, keys, argv } => {
                handle_eval(
                    write_buf,
                    &self.store,
                    &self.broker,
                    &self.script_engine,
                    &script,
                    &keys,
                    &argv,
                    now,
                );
                notify_zset_waiters_for_script_keys(&self.broker, &keys);
                None
            }
            CmdResult::ScriptOp => {
                let owned_args: Vec<Vec<u8>> = args.iter().map(|a| a.to_vec()).collect();
                let refs: Vec<&[u8]> = owned_args.iter().map(|v| v.as_slice()).collect();
                handle_script_op(write_buf, &self.script_engine, &refs);
                None
            }
        }
    }
}

fn write_shard_execution_error(write_buf: &mut BytesMut, err: ShardExecutionError) {
    match err {
        ShardExecutionError::Command(message) => resp::write_error(write_buf, &message),
        ShardExecutionError::Eviction(message) => resp::write_error(write_buf, message),
        ShardExecutionError::Wal(message) => {
            resp::write_error(write_buf, &format!("ERR WAL append failed: {message}"))
        }
    }
}

async fn handle_connection(
    mut socket: tokio::net::TcpStream,
    _peer: std::net::SocketAddr,
    runtime: Arc<Runtime>,
) -> std::io::Result<()> {
    let store = runtime.store.clone();
    let broker = runtime.broker.clone();
    let mut read_buf = vec![0u8; 65536];
    let mut write_buf = BytesMut::with_capacity(65536);
    let mut pending = BytesMut::new();
    let max_resp_request = runtime.config.max_resp_request;
    let mut session = CommandSession::new(runtime.config.require_auth);
    let executor = CommandExecutor::new(
        runtime.store.clone(),
        runtime.broker.clone(),
        runtime.script_engine.clone(),
        runtime.schema_cache.clone(),
    );

    loop {
        if session.sub_mode {
            tokio::select! {
                result = socket.read(&mut read_buf) => {
                    let n = match result {
                        Ok(0) => return Ok(()),
                        Ok(n) => n,
                        Err(e) => return Err(e),
                    };
                    pending.extend_from_slice(&read_buf[..n]);
                    if pending.len() > max_resp_request {
                        resp::write_error(&mut write_buf, "ERR RESP request exceeds maximum");
                        socket.write_all(&write_buf).await?;
                        return Ok(());
                    }
                    let now = Instant::now();
                    let mut parser = Parser::with_max_bulk_len(&pending, max_resp_request);
                    loop {
                        let args = match parser.parse_command() {
                            Ok(Some(args)) => args,
                            Ok(None) => break,
                            Err(e) => {
                                resp::write_error(&mut write_buf, e);
                                socket.write_all(&write_buf).await?;
                                return Ok(());
                            }
                        };
                        if args.is_empty() { continue; }
                        if cmd_eq_fast(args[0], b"SUBSCRIBE") {
                            for ch_bytes in &args[1..] {
                                let ch = std::str::from_utf8(ch_bytes).unwrap_or("").to_string();
                                if !session.subscriptions.contains_key(&ch) {
                                    let rx = broker.subscribe(&ch);
                                    session.subscriptions.insert(ch.clone(), rx);
                                }
                                resp::write_array_header(&mut write_buf, 3);
                                resp::write_bulk(&mut write_buf, "subscribe");
                                resp::write_bulk(&mut write_buf, &ch);
                                resp::write_integer(&mut write_buf, session.total_subscriptions());
                            }
                        } else if cmd_eq_fast(args[0], b"UNSUBSCRIBE") {
                            let channels: Vec<String> = if args.len() > 1 {
                                args[1..].iter().map(|a| std::str::from_utf8(a).unwrap_or("").to_string()).collect()
                            } else {
                                session.subscriptions.keys().cloned().collect()
                            };
                            for ch in &channels {
                                session.subscriptions.remove(ch);
                                resp::write_array_header(&mut write_buf, 3);
                                resp::write_bulk(&mut write_buf, "unsubscribe");
                                resp::write_bulk(&mut write_buf, ch);
                                resp::write_integer(&mut write_buf, session.total_subscriptions());
                            }
                            if session.subscriptions.is_empty() && session.pattern_subs.is_empty() && session.key_subs.is_empty() {
                                session.sub_mode = false;
                            }
                        } else if cmd_eq_fast(args[0], b"PSUBSCRIBE") {
                            for pat_bytes in &args[1..] {
                                let pat = std::str::from_utf8(pat_bytes).unwrap_or("").to_string();
                                if !session.pattern_subs.contains_key(&pat) {
                                    let rx = broker.psubscribe(&pat);
                                    session.pattern_subs.insert(pat.clone(), rx);
                                }
                                resp::write_array_header(&mut write_buf, 3);
                                resp::write_bulk(&mut write_buf, "psubscribe");
                                resp::write_bulk(&mut write_buf, &pat);
                                resp::write_integer(&mut write_buf, session.total_subscriptions());
                            }
                        } else if cmd_eq_fast(args[0], b"PUNSUBSCRIBE") {
                            let patterns: Vec<String> = if args.len() > 1 {
                                args[1..].iter().map(|a| std::str::from_utf8(a).unwrap_or("").to_string()).collect()
                            } else {
                                session.pattern_subs.keys().cloned().collect()
                            };
                            for pat in &patterns {
                                session.pattern_subs.remove(pat);
                                resp::write_array_header(&mut write_buf, 3);
                                resp::write_bulk(&mut write_buf, "punsubscribe");
                                resp::write_bulk(&mut write_buf, pat);
                                resp::write_integer(&mut write_buf, session.total_subscriptions());
                            }
                            if session.subscriptions.is_empty() && session.pattern_subs.is_empty() && session.key_subs.is_empty() {
                                session.sub_mode = false;
                            }
                        } else if cmd_eq_fast(args[0], b"KSUB") {
                            if args.len() < 2 {
                                resp::write_error(&mut write_buf, "ERR wrong number of arguments for 'ksub' command");
                            } else {
                                for pat_bytes in &args[1..] {
                                    let pat = std::str::from_utf8(pat_bytes).unwrap_or("").to_string();
                                    if !session.key_subs.contains_key(&pat) {
                                        let rx = broker.ksubscribe(&pat);
                                        session.key_subs.insert(pat.clone(), rx);
                                    }
                                    resp::write_array_header(&mut write_buf, 3);
                                    resp::write_bulk(&mut write_buf, "ksub");
                                    resp::write_bulk(&mut write_buf, &pat);
                                    resp::write_integer(&mut write_buf, session.total_subscriptions());
                                }
                            }
                        } else if cmd_eq_fast(args[0], b"KUNSUB") {
                            let patterns: Vec<String> = if args.len() > 1 {
                                args[1..].iter().map(|a| std::str::from_utf8(a).unwrap_or("").to_string()).collect()
                            } else {
                                session.key_subs.keys().cloned().collect()
                            };
                            for pat in &patterns {
                                if session.key_subs.remove(pat).is_some() {
                                    broker.kunsub(pat);
                                }
                                resp::write_array_header(&mut write_buf, 3);
                                resp::write_bulk(&mut write_buf, "kunsub");
                                resp::write_bulk(&mut write_buf, pat);
                                resp::write_integer(&mut write_buf, session.total_subscriptions());
                            }
                            if session.subscriptions.is_empty() && session.pattern_subs.is_empty() && session.key_subs.is_empty() {
                                session.sub_mode = false;
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
                    let total_subs = session.subscriptions.len() + session.pattern_subs.len() + session.key_subs.len();
                    if total_subs == 1 {
                        if let Some((_ch, rx)) = session.subscriptions.iter_mut().next() {
                            return recv_broadcast_batch(rx, SUB_MODE_BATCH_MAX).await;
                        }
                        if let Some((_pat, rx)) = session.pattern_subs.iter_mut().next() {
                            return recv_broadcast_batch(rx, SUB_MODE_BATCH_MAX).await;
                        }
                        if let Some((_pat, rx)) = session.key_subs.iter_mut().next() {
                            return recv_broadcast_batch(rx, SUB_MODE_BATCH_MAX).await;
                        }
                    }

                    for (_ch, rx) in session.subscriptions.iter_mut() {
                        if let Ok(msg) = rx.try_recv() {
                            return Some(vec![msg]);
                        }
                    }
                    for (_pat, rx) in session.pattern_subs.iter_mut() {
                        if let Ok(msg) = rx.try_recv() {
                            return Some(vec![msg]);
                        }
                    }
                    for (_pat, rx) in session.key_subs.iter_mut() {
                        if let Ok(msg) = rx.try_recv() {
                            return Some(vec![msg]);
                        }
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                    for (_ch, rx) in session.subscriptions.iter_mut() {
                        if let Ok(msg) = rx.try_recv() {
                            return Some(vec![msg]);
                        }
                    }
                    for (_pat, rx) in session.pattern_subs.iter_mut() {
                        if let Ok(msg) = rx.try_recv() {
                            return Some(vec![msg]);
                        }
                    }
                    for (_pat, rx) in session.key_subs.iter_mut() {
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
            if pending.len() > max_resp_request {
                resp::write_error(&mut write_buf, "ERR RESP request exceeds maximum");
                socket.write_all(&write_buf).await?;
                return Ok(());
            }
            let now = Instant::now();
            let mut parser = Parser::with_max_bulk_len(&pending, max_resp_request);
            let mut commands: Vec<resp::CommandArgs<'_>> = Vec::new();
            loop {
                match parser.parse_command_args() {
                    Ok(Some(args)) => {
                        if !args.is_empty() {
                            commands.push(args);
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        resp::write_error(&mut write_buf, e);
                        socket.write_all(&write_buf).await?;
                        return Ok(());
                    }
                }
            }
            let consumed = parser.pos();

            let mut deferred_action: Option<CmdResult> = None;

            if commands.len() <= 1 {
                for command in &commands {
                    let args = command.argv();
                    store.add_total_commands(1);
                    if let Some(action) =
                        executor.execute_command(args, &mut session, &mut write_buf, now)
                    {
                        deferred_action = Some(action);
                        break;
                    }
                }
            } else {
                deferred_action =
                    executor.execute_pipeline(&commands, &mut session, &mut write_buf, now);
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
                        handle_block_zpop(&mut socket, &store, &broker, &keys, timeout, pop_min)
                            .await?;
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
    broker: &Broker,
    keys: &[String],
    timeout: std::time::Duration,
    pop_min: bool,
) -> std::io::Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut write_buf = BytesMut::new();

    loop {
        if write_zpop_response(store, keys, pop_min, &mut write_buf) {
            return socket.write_all(&write_buf).await;
        }

        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            resp::write_null_array(&mut write_buf);
            return socket.write_all(&write_buf).await;
        }

        let waiter_id = broker.next_waiter_id();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);
        for key in keys {
            broker.register_zset_waiter(
                key,
                pubsub::BlockedZPopRequest {
                    tx: tx.clone(),
                    waiter_id,
                },
            );
        }
        drop(tx);

        if write_zpop_response(store, keys, pop_min, &mut write_buf) {
            broker.remove_zset_waiters_by_id(keys, waiter_id);
            return socket.write_all(&write_buf).await;
        }

        let woke = tokio::select! {
            val = rx.recv() => val.is_some(),
            _ = tokio::time::sleep(remaining) => false,
        };
        broker.remove_zset_waiters_by_id(keys, waiter_id);
        if !woke {
            resp::write_null_array(&mut write_buf);
            return socket.write_all(&write_buf).await;
        }
    }
}

fn write_zpop_response(store: &Store, keys: &[String], pop_min: bool, out: &mut BytesMut) -> bool {
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
                resp::write_array_header(out, 3);
                resp::write_bulk(out, key);
                resp::write_bulk(out, member);
                let score_str = if score.fract() == 0.0 && score.abs() < 1e15 {
                    format!("{}", *score as i64)
                } else {
                    format!("{}", score)
                };
                resp::write_bulk(out, &score_str);
                return true;
            }
        }
    }
    false
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

#[cfg(test)]
mod tx_tests {
    use super::*;

    fn test_executor() -> (CommandExecutor, CommandSession) {
        let store = Arc::new(Store::new());
        let broker = Broker::new();
        let schema_cache: SharedSchemaCache =
            Arc::new(parking_lot::RwLock::new(tables::SchemaCache::new()));
        let executor = CommandExecutor::new(
            store,
            broker,
            Arc::new(lua::ScriptEngine::new()),
            schema_cache,
        );
        (executor, CommandSession::new(false))
    }

    #[test]
    fn single_key_reads_route_through_shard_executor() {
        let (executor, mut session) = test_executor();
        let mut out = BytesMut::new();

        executor.store.set(b"k", b"v", None, Instant::now());
        executor.execute_command(&[b"GET", b"k"], &mut session, &mut out, Instant::now());

        assert_eq!(&out[..], b"$1\r\nv\r\n");
    }

    #[test]
    fn pubsub_commands_are_rejected_inside_multi() {
        let store = Arc::new(Store::new());
        let broker = Broker::new();
        let schema_cache: SharedSchemaCache =
            Arc::new(parking_lot::RwLock::new(tables::SchemaCache::new()));

        for command in ["SUBSCRIBE", "UNSUBSCRIBE", "PSUBSCRIBE", "PUNSUBSCRIBE"] {
            let mut in_multi = true;
            let mut tx_error = false;
            let mut tx_queue = Vec::new();
            let mut watched = Vec::new();
            let mut authenticated = true;
            let mut out = BytesMut::new();
            let args: [&[u8]; 2] = [command.as_bytes(), b"chan"];

            assert!(handle_tx_cmd(
                &args,
                &mut in_multi,
                &mut tx_error,
                &mut tx_queue,
                &mut watched,
                &mut authenticated,
                &store,
                &broker,
                &schema_cache,
                &mut out,
                Instant::now(),
            ));

            let response = String::from_utf8_lossy(&out);
            assert!(
                response.contains(&format!(
                    "ERR Command '{}' not allowed inside a transaction",
                    command.to_ascii_lowercase()
                )),
                "{command} should be rejected, got {response}"
            );
            assert!(tx_error, "{command} should mark the transaction dirty");
            assert!(tx_queue.is_empty(), "{command} should not be queued");
        }
    }
}
