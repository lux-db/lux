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
mod durability;
mod embedded;
mod encryption;
mod eviction;
mod file_security;
#[cfg(feature = "fuzzing")]
pub mod fuzz_api;
mod geo;
mod grants;
mod hll;
mod hnsw;
mod http;
mod jsonb;
mod lua;
mod migrations;
mod pubsub;
mod push;
mod resp;
mod restore;
mod shard_exec;
mod snapshot;
mod store;
mod tables;

use bytes::BytesMut;
use cmd::CmdResult;
use command::{Command, CommandKind, CommandOutput, PubSubCommand};
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
pub use durability::{DurabilityConfig, DurabilityPolicy};
pub use embedded::{
    EmbeddedPipeline, GeoMember, GeoPosition, GeoUnit, PreparedPipeline, RedisKeyType,
    ScoredMember, SetOptions,
};
pub use encryption::{EncryptionConfig, EncryptionKeyConfig};
pub use eviction::{parse_eviction_policy, parse_memory_size, EvictionConfig, EvictionPolicy};

const SUB_MODE_BATCH_MAX: usize = 64;

/// Default grace period for work accepted before runtime shutdown begins.
pub const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

/// Result of a requested server shutdown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShutdownOutcome {
    /// Every accepted request finished inside the grace period.
    Clean,
    /// The grace period elapsed and remaining request tasks were cancelled.
    Forced,
}

/// Failure returned by the detailed shutdown API.
#[derive(Debug)]
pub enum ShutdownError {
    /// A listener or runtime task failed independently of the final sync.
    Runtime(std::io::Error),
    /// The checked final persistence barrier failed.
    Persistence(std::io::Error),
}

impl std::fmt::Display for ShutdownError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Runtime(error) => write!(f, "server runtime failed: {error}"),
            Self::Persistence(error) => write!(f, "final persistence sync failed: {error}"),
        }
    }
}

impl std::error::Error for ShutdownError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Runtime(error) | Self::Persistence(error) => Some(error),
        }
    }
}

impl From<std::io::Error> for ShutdownError {
    fn from(error: std::io::Error) -> Self {
        Self::Runtime(error)
    }
}

impl ShutdownError {
    fn into_io_error(self) -> std::io::Error {
        match self {
            Self::Runtime(error) => error,
            Self::Persistence(error) => std::io::Error::new(
                error.kind(),
                format!("final persistence sync failed: {error}"),
            ),
        }
    }
}

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
    /// When true, email/password signup creates an unconfirmed user and requires
    /// a confirmation token before password sign-in.
    pub email_confirmation_required: bool,
    /// Enables accountless `signInAnonymously` sessions.
    pub anonymous_enabled: bool,
    /// Lifetime for one-time auth flow tokens such as recovery links,
    /// confirmation links, and OAuth authorization codes.
    pub flow_token_ttl: Duration,
    /// Base URL used when Lux needs to construct auth action links and no
    /// explicit redirect target was supplied.
    pub site_url: String,
    /// Optional initial publishable key material for local/bootstrap use.
    pub initial_publishable_key: Option<String>,
    /// Optional initial secret key material for local/bootstrap use.
    pub initial_secret_key: Option<String>,
    /// Optional Cloud-managed email delivery config. This is intentionally not
    /// seeded into `auth.settings`, so managed provider secrets can live
    /// outside customer-readable project auth tables.
    pub managed_email: Option<AuthManagedEmailConfig>,
}

/// Email delivery config injected by a host environment such as Lux Cloud.
#[derive(Clone)]
pub struct AuthManagedEmailConfig {
    /// Delivery provider name. Supported today: `postmark`.
    pub provider: String,
    /// Sender address, optionally already formatted as `Name <email@example.com>`.
    pub from: String,
    /// Optional Reply-To address.
    pub reply_to: Option<String>,
    /// Postmark server token for managed delivery.
    pub postmark_server_token: Option<String>,
    /// Optional Postmark message stream. Defaults to `outbound`.
    pub postmark_message_stream: Option<String>,
}

impl std::fmt::Debug for AuthManagedEmailConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthManagedEmailConfig")
            .field("provider", &self.provider)
            .field("from", &self.from)
            .field("reply_to", &self.reply_to)
            .field(
                "postmark_server_token",
                &self.postmark_server_token.as_ref().map(|_| "<redacted>"),
            )
            .field("postmark_message_stream", &self.postmark_message_stream)
            .finish()
    }
}

impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthConfig")
            .field("enabled", &self.enabled)
            .field("issuer", &self.issuer)
            .field("access_token_ttl", &self.access_token_ttl)
            .field("refresh_token_ttl", &self.refresh_token_ttl)
            .field("email_password_enabled", &self.email_password_enabled)
            .field(
                "email_confirmation_required",
                &self.email_confirmation_required,
            )
            .field("anonymous_enabled", &self.anonymous_enabled)
            .field("flow_token_ttl", &self.flow_token_ttl)
            .field("site_url", &self.site_url)
            .field(
                "initial_publishable_key",
                &self.initial_publishable_key.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "initial_secret_key",
                &self.initial_secret_key.as_ref().map(|_| "<redacted>"),
            )
            .field("managed_email", &self.managed_email)
            .finish()
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            issuer: "http://localhost:5890/auth/v1".to_string(),
            access_token_ttl: Duration::from_secs(3600),
            refresh_token_ttl: Duration::from_secs(30 * 24 * 60 * 60),
            email_password_enabled: true,
            email_confirmation_required: false,
            anonymous_enabled: true,
            flow_token_ttl: Duration::from_secs(24 * 60 * 60),
            site_url: "http://localhost:5890".to_string(),
            initial_publishable_key: None,
            initial_secret_key: None,
            managed_email: None,
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
    /// Write acknowledgement policy, independent of the storage layout.
    pub durability: DurabilityConfig,
    /// Memory pressure eviction configuration.
    pub eviction: EvictionConfig,
    /// Per-project application auth configuration.
    pub auth: AuthConfig,
    /// Table column encryption key configuration.
    pub encryption: EncryptionConfig,
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
            .field("durability", &self.durability)
            .field("eviction", &self.eviction)
            .field("auth", &self.auth)
            .field("encryption", &self.encryption)
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
            durability: DurabilityConfig::default(),
            eviction: EvictionConfig::default(),
            auth: AuthConfig::default(),
            encryption: EncryptionConfig::default(),
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
    /// Effective storage layout and acknowledgement policy selected at startup.
    PersistenceConfigured {
        storage_layout: StorageMode,
        durability: DurabilityPolicy,
        sync_interval_ms: Option<u64>,
    },
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
/// Warnings are conditions Lux recovered from without rejecting startup or a
/// database mutation.
#[derive(Clone, Debug)]
pub enum ServerWarnEvent {
    /// Auth is explicitly running in development-only plaintext memory because
    /// durability is ephemeral and no encryption key is active.
    AuthSecretStorageDegraded,
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
    /// Promoting a cold key failed; the disk index retains the entry.
    DiskPromotionReadFailed { key: String, error: String },
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

    pub(crate) fn journal_dir(&self) -> std::path::PathBuf {
        if self.storage.mode == StorageMode::Tiered {
            std::path::PathBuf::from(&self.storage.dir)
        } else {
            std::path::Path::new(&self.data_dir).join("journal")
        }
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

    // A project key is a credential in its own right, so a key-only engine (one
    // with no LUX_PASSWORD) is authenticated and may bind a public interface.
    // Judging this by the password alone would refuse to start exactly the
    // configuration the unified credential model is moving towards.
    //
    // Publishable keys do not count for RESP: they can never use that protocol,
    // so a publishable-only engine really would be unauthenticated there.
    let resp_authenticated = (!config.password.is_empty() && config.require_auth)
        || config.auth.initial_secret_key.is_some();
    let http_authenticated = !config.password.is_empty()
        || config.auth.initial_secret_key.is_some()
        || config.auth.initial_publishable_key.is_some();

    let resp_exposed_without_auth = config.enable_resp && !resp_authenticated;
    let http_exposed_without_auth = config.http_port != 0 && !http_authenticated;
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

fn absolute_config_path(raw: &str, field: &str) -> std::io::Result<String> {
    if raw.trim().is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{field} must not be empty"),
        ));
    }
    let path = std::path::PathBuf::from(raw);
    let path = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()?.join(path)
    };
    Ok(path.to_string_lossy().into_owned())
}

fn has_persistence_state(dir: &std::path::Path) -> std::io::Result<bool> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let is_journal = name == "global" || name.starts_with("shard_");
        let is_tiered_shard = name.starts_with("shard_");
        if (is_journal && entry.path().join("wal.lux").exists())
            || (is_tiered_shard && entry.path().join("data.lux").exists())
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn verify_writable_directory(path: &std::path::Path, field: &str) -> std::io::Result<()> {
    crate::file_security::ensure_safe_dir(path).map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("cannot create {field} {}: {error}", path.display()),
        )
    })?;
    static PROBE_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let id = PROBE_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let from = path.join(format!(".lux-write-probe-{}-{id}", std::process::id()));
    let to = path.join(format!(".lux-rename-probe-{}-{id}", std::process::id()));
    let result = (|| {
        use std::io::Write as _;
        let mut file = crate::file_security::open_private_file(&from, |options| {
            options.create_new(true).write(true);
        })?;
        file.write_all(b"lux")?;
        file.sync_all()?;
        std::fs::rename(&from, &to)?;
        crate::file_security::verify_installed_file(&to, &file)?;
        crate::disk::sync_directory(path)?;
        std::fs::remove_file(&to)?;
        crate::disk::sync_directory(path)?;
        Ok::<_, std::io::Error>(())
    })();
    let _ = std::fs::remove_file(&from);
    let _ = std::fs::remove_file(&to);
    result.map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!(
                "{field} is not safely writable at {}: {error}",
                path.display()
            ),
        )
    })
}

fn resolve_and_validate_persistence(config: &mut ServerConfig) -> std::io::Result<()> {
    let policy = config.durability.policy;
    if config.storage.mode == StorageMode::Tiered && policy == DurabilityPolicy::Ephemeral {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "tiered storage requires every_second or always_sync durability",
        ));
    }
    if policy == DurabilityPolicy::EverySecond
        && (config.durability.sync_interval.is_zero()
            || config.durability.sync_interval > Duration::from_secs(1))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "every_second durability sync interval must be from 1 to 1000 ms",
        ));
    }
    if !policy.is_persistent() {
        return Ok(());
    }

    config.data_dir = absolute_config_path(&config.data_dir, "data_dir")?;
    if config.storage.mode == StorageMode::Tiered {
        config.storage.dir = absolute_config_path(&config.storage.dir, "storage dir")?;
    }

    let data_dir = std::path::Path::new(&config.data_dir);
    let memory_journal_dir = data_dir.join("journal");
    let conventional_tiered_dir = data_dir.join("storage");
    if config.storage.mode == StorageMode::Memory
        && has_persistence_state(&conventional_tiered_dir)?
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "tiered shard state exists; refusing an implicit switch to memory layout",
        ));
    }
    if config.storage.mode == StorageMode::Tiered && has_persistence_state(&memory_journal_dir)? {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "memory-layout journal state exists; refusing an implicit switch to tiered layout",
        ));
    }

    verify_writable_directory(data_dir, "data_dir")?;
    let journal_dir = config.journal_dir();
    if journal_dir != data_dir {
        verify_writable_directory(&journal_dir, "journal directory")?;
    }
    Ok(())
}

fn acquire_persistence_locks(config: &ServerConfig) -> std::io::Result<Vec<std::fs::File>> {
    if !config.durability.policy.is_persistent() {
        return Ok(Vec::new());
    }

    let mut roots = vec![std::fs::canonicalize(&config.data_dir)?];
    if config.storage.mode == StorageMode::Tiered {
        roots.push(std::fs::canonicalize(&config.storage.dir)?);
    }
    roots.sort();
    roots.dedup();
    roots
        .iter()
        .map(|root| crate::file_security::lock_state_dir(root))
        .collect()
}

fn validate_encryption_config(config: &ServerConfig) -> std::io::Result<()> {
    // Fail fast on a bad encryption config: unresolvable key material, a
    // decrypt-only active key, or persisted state that no configured seal can
    // unseal. Validate against the real data dir (not the process cwd, which
    // would strand seal/state files there) with auto-init off, since creating a
    // brand-new keyring is the store's job, not validation's.
    let validation = EncryptionConfig {
        auto_init: false,
        ..config.encryption.clone()
    };
    let keyring = crate::encryption::EncryptionKeyring::open(&validation, &config.data_dir)
        .map_err(|error| {
            let guidance = if error.contains("ENC state could not be unsealed") {
                " Check LUX_ENC_SEAL_KEY; during seal rotation, include the prior seal in LUX_ENC_SEAL_KEY_PREVIOUS."
            } else {
                ""
            };
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{error}{guidance}"),
            )
        })?;

    if config.auth.enabled && config.durability.policy.is_persistent() {
        if config.encryption.auto_init
            && config.encryption.state_path.as_deref() == Some("")
            && !keyring.has_active_key()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Auth secret storage is locked: persistent Auth cannot auto-initialize an ephemeral keyring; remove the empty LUX_ENC_STATE_PATH or supply LUX_ENCRYPTION_KEY/LUX_ENCRYPTION_KEYS",
            ));
        }
        if !keyring.has_active_key() && !config.encryption.auto_init {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Auth secret storage is locked: persistent Auth requires a usable Lux encryption key; set LUX_ENC_AUTO_INIT=1 (and LUX_ENC_SEAL_KEY in production) or supply LUX_ENCRYPTION_KEY/LUX_ENCRYPTION_KEYS. During data-key rotation, retain prior keys until ENC REWRAP completes",
            ));
        }
    }
    Ok(())
}

pub struct ServerHandle {
    #[allow(dead_code)]
    runtime: Arc<Runtime>,
    shutdown_tx: watch::Sender<Option<Duration>>,
    server_task: JoinHandle<Result<ShutdownOutcome, ShutdownError>>,
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
    store: Arc<Store>,
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
    schema_cache: SharedSchemaCache,
    script_engine: Arc<lua::ScriptEngine>,
    config: Arc<ServerConfig>,
    accepting_work: std::sync::atomic::AtomicBool,
    snapshot_worker: parking_lot::Mutex<Option<snapshot::SnapshotWorker>>,
    /// Open descriptors hold the advisory locks for every persistent root.
    /// Shutdown releases them after the final persistence barrier even when a
    /// stale embedded client keeps the otherwise-fenced runtime alive.
    persistence_locks: parking_lot::Mutex<Option<Vec<std::fs::File>>>,
}

impl Runtime {
    fn release_persistence_locks(&self) {
        self.persistence_locks.lock().take();
    }

    fn request_snapshot_shutdown(&self) {
        if let Some(worker) = self.snapshot_worker.lock().as_ref() {
            worker.request_shutdown(&self.store);
        }
    }

    fn join_snapshot_worker(&self) -> std::io::Result<()> {
        if let Some(mut worker) = self.snapshot_worker.lock().take() {
            worker.join()
        } else {
            Ok(())
        }
    }
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
        self.shutdown_with_timeout(DEFAULT_SHUTDOWN_TIMEOUT);
    }

    /// Stop accepting new work and request a bounded graceful drain.
    pub fn shutdown_with_timeout(&self, timeout: Duration) {
        self.runtime
            .accepting_work
            .store(false, std::sync::atomic::Ordering::Release);
        let _ = self.shutdown_tx.send(Some(timeout));
    }

    pub async fn wait(self) -> std::io::Result<()> {
        match self.wait_detailed().await {
            Ok(ShutdownOutcome::Clean) => Ok(()),
            Ok(ShutdownOutcome::Forced) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "graceful shutdown timed out; remaining work was cancelled",
            )),
            Err(error) => Err(error.into_io_error()),
        }
    }

    pub async fn shutdown_and_wait(self) -> std::io::Result<()> {
        self.shutdown();
        self.wait().await
    }

    /// Request shutdown with a caller-supplied grace period and preserve the
    /// clean-versus-forced result.
    pub async fn shutdown_and_wait_detailed(
        self,
        timeout: Duration,
    ) -> Result<ShutdownOutcome, ShutdownError> {
        self.shutdown_with_timeout(timeout);
        self.wait_detailed().await
    }

    /// Wait for runtime termination or an external signal future, whichever
    /// happens first. Standalone hosts use this without exposing task internals.
    pub async fn wait_or_shutdown<F>(
        mut self,
        signal: F,
        timeout: Duration,
    ) -> Result<ShutdownOutcome, ShutdownError>
    where
        F: std::future::Future<Output = ()>,
    {
        tokio::pin!(signal);
        tokio::select! {
            joined = &mut self.server_task => join_server_task(joined),
            () = &mut signal => {
                self.shutdown_with_timeout(timeout);
                join_server_task(self.server_task.await)
            }
        }
    }

    async fn wait_detailed(self) -> Result<ShutdownOutcome, ShutdownError> {
        join_server_task(self.server_task.await)
    }
}

fn join_server_task(
    joined: Result<Result<ShutdownOutcome, ShutdownError>, tokio::task::JoinError>,
) -> Result<ShutdownOutcome, ShutdownError> {
    match joined {
        Ok(result) => result,
        Err(error) => Err(ShutdownError::Runtime(std::io::Error::other(format!(
            "server task failed: {error}"
        )))),
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
        self.ensure_accepting_work()?;
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
        self.ensure_accepting_work()?;
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
            let _execution_guard = self
                .runtime
                .store
                .execution_read_guard()
                .map_err(|error| LuxError::Command(format!("database unavailable: {error}")))?;
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
            let Some((key, access)) = native_pipeline_access(&commands[i]) else {
                if !collect_outputs {
                    if let Command::Publish { channel, message } = &commands[i] {
                        let _execution_guard =
                            self.runtime.store.execution_read_guard().map_err(|error| {
                                LuxError::Command(format!("database unavailable: {error}"))
                            })?;
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

            // A typed write must cross its own command-layer journal boundary.
            // Pre-journaling a whole native batch is unsafe because an earlier
            // command can fail and prevent later commands from executing even
            // though their frames are already durable. Read-only runs remain
            // eligible for same-shard batching.
            if access == NativePipelineAccess::Write {
                let out = self.execute_command_output(commands[i].clone()).await?;
                if collect_outputs {
                    outputs.push(out);
                }
                i += 1;
                continue;
            }

            let shard_idx = self.runtime.store.shard_for_key(key);
            let mut batch_end = i + 1;
            while batch_end < commands.len() {
                let Some((next_key, next_access)) = native_pipeline_access(&commands[batch_end])
                else {
                    break;
                };
                if next_access == NativePipelineAccess::Write
                    || self.runtime.store.shard_for_key(next_key) != shard_idx
                {
                    break;
                }
                batch_end += 1;
            }

            let batch = &commands[i..batch_end];
            if collect_outputs {
                let _execution_guard =
                    self.runtime.store.execution_read_guard().map_err(|error| {
                        LuxError::Command(format!("database unavailable: {error}"))
                    })?;
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

            i = batch_end;
        }

        Ok(outputs)
    }

    fn execute_native_read_on_shard(
        &self,
        command: &Command<'_>,
        shard: &store::Shard,
        now: Instant,
    ) -> Result<CommandOutput, LuxError> {
        match command {
            Command::Get { key } => Ok(optional_bulk_output(
                Store::get_from_shard(&shard.data, key, now)
                    .map(|raw| self.runtime.store.decrypt_kv_string_value(key, raw))
                    .transpose()
                    .map_err(LuxError::Command)?,
            )),
            Command::StrLen { key } => Ok(CommandOutput::Int(
                Store::get_from_shard(&shard.data, key, now)
                    .map(|raw| self.runtime.store.decrypt_kv_string_value(key, raw))
                    .transpose()
                    .map_err(LuxError::Command)?
                    .map_or(0, |value| value.len() as i64),
            )),
            Command::Exists { keys } if keys.len() == 1 => Ok(CommandOutput::Int(i64::from(
                Store::exists_on_shard(&shard.data, keys[0], now),
            ))),
            Command::HGet { key, field } => Ok(optional_bulk_output(
                Store::hget_from_shard(&shard.data, key, field, now)
                    .map(|raw| self.runtime.store.decrypt_hash_field_value(key, field, raw))
                    .transpose()
                    .map_err(LuxError::Command)?,
            )),
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

    async fn execute_command_fast_path(
        &self,
        command: &Command<'_>,
    ) -> Result<Option<CommandOutput>, LuxError> {
        // Mutations use the command layer's authoritative, state-aware journal
        // boundary. This fast path is deliberately a read-only whitelist plus
        // PING/PUBLISH; unknown or newly added variants fall back to the shared
        // command implementation by default.
        if self.runtime.store.is_tiered()
            || matches!(command, Command::Keys { .. } | Command::RandomKey)
            || command_touches_reserved_internal_key(command)
        {
            return Ok(None);
        }

        let now = Instant::now();
        let _execution_guard = self
            .runtime
            .store
            .execution_read_guard()
            .map_err(|error| LuxError::Command(format!("database unavailable: {error}")))?;
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
            Command::Get { key } => optional_bulk_output(
                self.runtime
                    .store
                    .get_kv_string(key, now)
                    .map_err(LuxError::Command)?,
            ),
            Command::MGet { keys } => {
                let values = keys
                    .iter()
                    .map(|key| {
                        self.runtime
                            .store
                            .get_kv_string(key, now)
                            .map(optional_bulk_output)
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(LuxError::Command)?;
                CommandOutput::Array(values)
            }
            Command::StrLen { key } => CommandOutput::Int(
                self.runtime
                    .store
                    .get_kv_string(key, now)
                    .map_err(LuxError::Command)?
                    .map_or(0, |value| value.len() as i64),
            ),
            Command::Exists { keys } => CommandOutput::Int(self.runtime.store.exists(keys, now)),
            Command::Ttl { key } => CommandOutput::Int(self.runtime.store.ttl(key, now)),
            Command::PTtl { key } => CommandOutput::Int(self.runtime.store.pttl(key, now)),
            Command::Type { key } => CommandOutput::Simple(
                self.runtime
                    .store
                    .get_entry_type(key, now)
                    .unwrap_or("none"),
            ),
            Command::LLen { key } => CommandOutput::Int(
                self.runtime
                    .store
                    .llen(key, now)
                    .map_err(LuxError::Command)?,
            ),
            Command::LIndex { key, index } => {
                optional_bulk_output(self.runtime.store.lindex(key, *index, now).map(|raw| {
                    self.runtime
                        .store
                        .decrypt_list_element(raw.clone())
                        .unwrap_or(raw)
                }))
            }
            Command::LRange { key, start, stop } => bytes_array(
                self.runtime
                    .store
                    .lrange(key, *start, *stop, now)
                    .map_err(LuxError::Command)?
                    .into_iter()
                    .map(|raw| {
                        self.runtime
                            .store
                            .decrypt_list_element(raw.clone())
                            .unwrap_or(raw)
                    })
                    .collect(),
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
                let score_a = self
                    .runtime
                    .store
                    .zscore(key, member_a, now)
                    .map_err(LuxError::Command)?;
                let score_b = self
                    .runtime
                    .store
                    .zscore(key, member_b, now)
                    .map_err(LuxError::Command)?;
                match (score_a, score_b) {
                    (Some(score_a), Some(score_b)) => {
                        let (lon_a, lat_a) = crate::geo::geohash_decode(score_a as u64);
                        let (lon_b, lat_b) = crate::geo::geohash_decode(score_b as u64);
                        let distance =
                            unit.from_meters(crate::geo::haversine(lon_a, lat_a, lon_b, lat_b));
                        CommandOutput::Bulk(bytes::Bytes::from(format!("{distance:.4}")))
                    }
                    _ => CommandOutput::Nil,
                }
            }
            _ => return Ok(None),
        };

        self.runtime.store.add_total_commands(1);
        Ok(Some(output))
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
        self.ensure_accepting_work()?;
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
                CmdResult::BlockListMPop { .. } => "BLMPOP",
                CmdResult::BlockZMPop { .. } => "BZMPOP",
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
        let _execution_guard = self.runtime.store.execution_barrier_guard();
        EmbeddedSubscription::new(
            self.runtime.store.clone(),
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
        let _execution_guard = self.runtime.store.execution_barrier_guard();
        EmbeddedSubscription::new(
            self.runtime.store.clone(),
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
        let _execution_guard = self.runtime.store.execution_barrier_guard();
        EmbeddedSubscription::new(
            self.runtime.store.clone(),
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
        self.ensure_accepting_work()?;
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

        wait_for_blocking_pop(
            &self.runtime.store,
            &self.runtime.broker,
            &owned_keys,
            timeout,
            pop_left,
        )
        .await
    }

    async fn execute_owned(&self, argv: Vec<Vec<u8>>) -> Result<bytes::Bytes, LuxError> {
        self.ensure_accepting_work()?;
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
                CmdResult::BlockListMPop { .. } => "BLMPOP",
                CmdResult::BlockZMPop { .. } => "BZMPOP",
                _ => "unsupported",
            };
            return Err(LuxError::Unsupported(format!(
                "blocking command not supported in embedded execution: {kind}"
            )));
        }
        Ok(write_buf.freeze())
    }

    fn ensure_accepting_work(&self) -> Result<(), LuxError> {
        if self
            .runtime
            .accepting_work
            .load(std::sync::atomic::Ordering::Acquire)
        {
            Ok(())
        } else {
            Err(LuxError::Command(
                "SERVER shutting down; new work is not accepted".to_string(),
            ))
        }
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
        EmbeddedValue::Simple(s) => Ok(CommandOutput::SimpleOwned(s)),
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
        Command::LPush { key, .. } => (*key, b"LPUSH".as_slice()),
        Command::RPush { key, .. } => (*key, b"RPUSH".as_slice()),
        Command::LPop { key } => (*key, b"LPOP".as_slice()),
        Command::RPop { key } => (*key, b"RPOP".as_slice()),
        Command::HIncrBy { key, .. } => (*key, b"HINCRBY".as_slice()),
        Command::SAdd { key, .. } => (*key, b"SADD".as_slice()),
        Command::ZAdd { key, .. } => (*key, b"ZADD".as_slice()),
        Command::ZIncrBy { key, .. } => (*key, b"ZINCRBY".as_slice()),
        Command::GeoAdd { key, .. } => (*key, b"GEOADD".as_slice()),
        Command::SPop { .. } | Command::XAdd { .. } => return None,
        Command::Del { keys } | Command::Unlink { keys } if keys.len() == 1 => {
            (keys[0], b"DEL".as_slice())
        }
        _ => return None,
    };

    if cmd::is_reserved_internal_argument(key) {
        return None;
    }

    match cmd::pipeline_access(op) {
        cmd::PipelineAccess::Read => Some((key, NativePipelineAccess::Read)),
        cmd::PipelineAccess::Write => Some((key, NativePipelineAccess::Write)),
        cmd::PipelineAccess::General => None,
    }
}

fn command_touches_reserved_internal_key(command: &Command<'_>) -> bool {
    let reserved = cmd::is_reserved_internal_argument;
    match command {
        Command::Get { key }
        | Command::StrLen { key }
        | Command::Ttl { key }
        | Command::PTtl { key }
        | Command::Type { key }
        | Command::LLen { key }
        | Command::LIndex { key, .. }
        | Command::LRange { key, .. }
        | Command::HGet { key, .. }
        | Command::HMGet { key, .. }
        | Command::HExists { key, .. }
        | Command::HLen { key }
        | Command::HGetAll { key }
        | Command::SMembers { key }
        | Command::SIsMember { key, .. }
        | Command::SCard { key }
        | Command::ZCard { key }
        | Command::ZScore { key, .. }
        | Command::ZCount { key, .. }
        | Command::ZRange { key, .. }
        | Command::GeoPos { key, .. }
        | Command::GeoDist { key, .. } => reserved(key),
        Command::MGet { keys }
        | Command::Exists { keys }
        | Command::SUnion { keys }
        | Command::SInter { keys }
        | Command::SDiff { keys } => keys.iter().any(|key| reserved(key)),
        _ => false,
    }
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
        store: Arc<Store>,
        broker: Broker,
        receiver: broadcast::Receiver<pubsub::Message>,
        kind: EmbeddedSubscriptionKind,
    ) -> Self {
        Self {
            store,
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
        let _execution_guard = self.store.execution_barrier_guard();
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
    _store: &Store,
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
                destination: None,
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
pub async fn run_with_config(mut config: ServerConfig) -> std::io::Result<ServerHandle> {
    validate_listener_security(&config)?;
    validate_auth_config(&config)?;
    validate_shard_count(&config)?;
    resolve_and_validate_persistence(&mut config)?;
    let persistence_locks = acquire_persistence_locks(&config)?;
    validate_encryption_config(&config)?;
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
    let (shutdown_tx, shutdown_rx) = watch::channel(None);
    let (ready_tx, ready_rx) = oneshot::channel();
    let server_task = tokio::spawn(server_main(
        listener,
        config,
        persistence_locks,
        shutdown_rx,
        ready_tx,
    ));
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
    persistence_locks: Vec<std::fs::File>,
    mut shutdown_rx: watch::Receiver<Option<Duration>>,
    ready_tx: oneshot::Sender<std::io::Result<Arc<Runtime>>>,
) -> Result<ShutdownOutcome, ShutdownError> {
    let mut background_tasks = JoinSet::new();
    let runtime = match Runtime::start(config, persistence_locks, &mut background_tasks).await {
        Ok(runtime) => runtime,
        Err(error) => {
            let ready_error = std::io::Error::new(error.kind(), error.to_string());
            let _ = ready_tx.send(Err(ready_error));
            return Err(ShutdownError::Runtime(error));
        }
    };

    let mut http_task = None;
    if let Some((http_startup_rx, task)) = runtime.start_http_if_enabled(shutdown_rx.clone()) {
        http_task = Some(task);
        if let Err(e) = wait_for_startup(
            http_startup_rx,
            "http server startup failed before readiness signal",
        )
        .await
        {
            let ready_error = std::io::Error::new(e.kind(), e.to_string());
            let _ = ready_tx.send(Err(ready_error));
            return Err(ShutdownError::Runtime(e));
        }
    }
    let _ = ready_tx.send(Ok(runtime.clone()));

    let mut conn_tasks = JoinSet::new();
    // HTTP binds inside its task, so wait for its one-shot before reporting the
    // whole runtime as ready to embedded callers.
    let mut runtime_failure = None;
    let shutdown_timeout = if !runtime.config.enable_resp {
        let _ = shutdown_rx.changed().await;
        shutdown_rx.borrow().unwrap_or(DEFAULT_SHUTDOWN_TIMEOUT)
    } else {
        let listener = listener.expect("listener must exist when RESP is enabled");
        'accept: loop {
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    let timeout = if changed.is_ok() {
                        shutdown_rx.borrow().unwrap_or(DEFAULT_SHUTDOWN_TIMEOUT)
                    } else {
                        DEFAULT_SHUTDOWN_TIMEOUT
                    };
                    break 'accept timeout;
                }
                joined = conn_tasks.join_next(), if !conn_tasks.is_empty() => {
                    let _ = joined;
                }
                accepted = listener.accept() => {
                    let (socket, peer) = match accepted {
                        Ok(accepted) => accepted,
                        Err(error) => {
                            runtime_failure = Some(error);
                            break 'accept DEFAULT_SHUTDOWN_TIMEOUT;
                        }
                    };
                    let runtime = runtime.clone();
                    let on_warn = runtime.config.on_warn.clone();
                    let connection_shutdown = shutdown_rx.clone();
                    socket.set_nodelay(true).ok();

                    conn_tasks.spawn(async move {
                        runtime.store.client_connected();
                        let result = handle_connection(
                            socket,
                            peer,
                            runtime.clone(),
                            connection_shutdown,
                        )
                        .await;
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
    };

    runtime
        .accepting_work
        .store(false, std::sync::atomic::Ordering::Release);
    let shutdown_started = Instant::now();
    runtime.request_snapshot_shutdown();

    // Maintenance may itself mutate durable state. Cancel it before draining
    // accepted requests, then wait for cancellation so nothing can race the
    // final persistence barrier.
    background_tasks.abort_all();

    let mut drained = tokio::time::timeout(shutdown_timeout, async {
        while conn_tasks.join_next().await.is_some() {}
        while background_tasks.join_next().await.is_some() {}
        if let Some(task) = http_task.as_mut() {
            let _ = task.await;
        }
    })
    .await
    .is_ok();

    if !drained {
        // The grace period is over. Close the mutation boundary before
        // cancelling work so anything queued behind an in-flight mutation is
        // rejected when it wakes instead of crossing the final sync later.
        runtime.store.begin_shutdown();
        conn_tasks.abort_all();
        background_tasks.abort_all();
        if let Some(task) = &http_task {
            task.abort();
        }

        // Cancellation is cooperative. Await every owned task even after the
        // grace period so final sync can never race code still inside a
        // mutation. The Store-level shutdown fence prevents a waiting task from
        // starting a new mutation after the barrier.
        while conn_tasks.join_next().await.is_some() {}
        while background_tasks.join_next().await.is_some() {}
        if let Some(task) = http_task.as_mut() {
            let _ = task.await;
        }
    }

    let snapshot_worker_error = runtime.join_snapshot_worker().err();
    if shutdown_started.elapsed() > shutdown_timeout {
        drained = false;
    }

    // A clean drain has no request or maintenance tasks left. Closing the
    // mutation boundary here also protects against stale embedded clients.
    runtime.store.begin_shutdown();
    let final_sync = runtime.store.finalize_shutdown();
    runtime.release_persistence_locks();
    final_sync.map_err(ShutdownError::Persistence)?;

    if let Some(error) = snapshot_worker_error {
        return Err(ShutdownError::Runtime(error));
    }
    if let Some(error) = runtime_failure {
        return Err(ShutdownError::Runtime(error));
    }

    Ok(if drained {
        ShutdownOutcome::Clean
    } else {
        ShutdownOutcome::Forced
    })
}

impl Runtime {
    async fn start(
        config: ServerConfig,
        persistence_locks: Vec<std::fs::File>,
        background_tasks: &mut JoinSet<()>,
    ) -> std::io::Result<Arc<Self>> {
        restore::commit_pending_restore(&config)?;
        if config.storage.mode == StorageMode::Tiered && config.durability.policy.is_persistent() {
            // Tiered files are a derived placement cache. Recovery is driven
            // solely by the verified snapshot and ordered journal; retaining
            // the cache would duplicate snapshot keys and replay relative
            // mutations on top of their already-applied cold values.
            disk::discard_tiered_cache(std::path::Path::new(&config.storage.dir))?;
        }
        let config = Arc::new(config);
        let store = Arc::new(Store::try_new_with_config(config.clone())?);
        let schema_cache: SharedSchemaCache =
            std::sync::Arc::new(parking_lot::RwLock::new(tables::SchemaCache::new()));
        let broker = Broker::new();
        // Wire the row-delta sink so table writes feed reactive live queries.
        store.set_row_delta_broker(broker.clone());
        let script_engine = Arc::new(lua::ScriptEngine::new());

        let runtime = Arc::new(Self {
            store,
            broker,
            schema_cache,
            script_engine,
            config,
            accepting_work: std::sync::atomic::AtomicBool::new(true),
            snapshot_worker: parking_lot::Mutex::new(None),
            persistence_locks: parking_lot::Mutex::new(Some(persistence_locks)),
        });

        emit_info(
            &runtime.config,
            ServerInfoEvent::PersistenceConfigured {
                storage_layout: runtime.config.storage.mode,
                durability: runtime.config.durability.policy,
                sync_interval_ms: (runtime.config.durability.policy
                    == DurabilityPolicy::EverySecond)
                    .then(|| runtime.config.durability.sync_interval.as_millis() as u64),
            },
        );
        if auth::secret_storage_health(&runtime.store).status
            == auth::AuthSecretStorageStatus::Degraded
        {
            emit_warn(&runtime.config, ServerWarnEvent::AuthSecretStorageDegraded);
        }

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
        // lux push tables are created lazily on first use (see push::ensure_tables),
        // so a project that never uses push carries no push.* tables. On restart,
        // the `push.*` TCREATE/TINSERT commands are restored from the WAL like any
        // other write, so no eager bootstrap is needed here.
        runtime
            .store
            .wal_suppress
            .store(true, std::sync::atomic::Ordering::Relaxed);
        if runtime.config.durability.policy.is_persistent() {
            runtime.store.begin_recovery();
            match snapshot::load_for_recovery(&runtime.store) {
                Ok(0) => emit_info(&runtime.config, ServerInfoEvent::NoSnapshotFound),
                Ok(n) => emit_info(&runtime.config, ServerInfoEvent::SnapshotLoaded { keys: n }),
                Err(e) => {
                    // Refuse to start on a load failure (e.g. an encrypted value the
                    // current keyring can't decrypt) rather than coming up with a
                    // truncated dataset that the background save would then overwrite.
                    // The on-disk snapshot is left intact and recoverable; supply the
                    // correct keyring/seal and restart.
                    runtime
                        .store
                        .wal_suppress
                        .store(false, std::sync::atomic::Ordering::Relaxed);
                    emit_error(
                        &runtime.config,
                        ServerErrorEvent::SnapshotLoadFailed {
                            error: e.to_string(),
                        },
                    );
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "refusing to start: snapshot load failed, on-disk data preserved (not overwritten): {e}"
                        ),
                    ));
                }
            }
        }
        // A loaded snapshot can carry an older auth schema. Upgrade it before
        // replaying WAL entries that may already reference newer columns.
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
                    format!("auth snapshot migration failed: {e}"),
                ));
            }
        }
        runtime
            .store
            .wal_suppress
            .store(false, std::sync::atomic::Ordering::Relaxed);
        if runtime.config.durability.policy.is_persistent() {
            runtime.store.replay_wal(&runtime.broker)?;
            runtime.store.finish_recovery();
        }
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
            let auth_bootstrap = auth::bootstrap_runtime(
                &runtime.store,
                &runtime.schema_cache,
                &runtime.config.auth,
            )
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("auth runtime bootstrap failed: {e}"),
                )
            })?;
            if auth_bootstrap.secret_history_checkpoint_required {
                snapshot::save_and_truncate_wal_consistent(&runtime.store).map_err(|e| {
                    std::io::Error::new(
                        e.kind(),
                        format!("auth secret migration checkpoint failed before readiness: {e}"),
                    )
                })?;
                auth::mark_secret_storage_checkpoint_complete(
                    &runtime.store,
                    &runtime.schema_cache,
                )
                .map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("auth secret migration finalization failed: {e}"),
                    )
                })?;
            }
        }

        // One-time migration of any pre-`push.*` data (PR1 stored it under
        // `auth.*`). Runs post-replay with WAL logging on; a no-op when there is
        // no legacy data. Best-effort: a failure here must not block startup.
        if let Err(e) =
            push::migrate_from_auth_scope(&runtime.store, &runtime.schema_cache, Instant::now())
        {
            eprintln!("push scope migration skipped: {e}");
        }

        let snapshot_worker = snapshot::start_background_save_worker(runtime.store.clone())?;
        *runtime.snapshot_worker.lock() = Some(snapshot_worker);

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
                    match tables::expire_due_rows(&store, &cache, now) {
                        Ok(tables) => {
                            for table in tables {
                                broker.enqueue_key_event(table.as_bytes(), b"TEXPIRE");
                            }
                        }
                        Err(error) => {
                            eprintln!("table TTL sweep failed; rows retained for retry: {error}");
                        }
                    }
                }
            });
        }

        // lux push delivery worker: drains the durable `push.outbox` and delivers
        // to APNs/etc. Runs unconditionally — push is a standalone scope and does
        // not depend on Lux auth.
        {
            let store = runtime.store.clone();
            let cache = runtime.schema_cache.clone();
            background_tasks.spawn(push::worker::run_delivery_worker(store, cache));
        }

        if runtime.config.durability.policy == DurabilityPolicy::EverySecond {
            let store = runtime.store.clone();
            let sync_interval = runtime.config.durability.sync_interval;
            background_tasks.spawn(async move {
                loop {
                    tokio::time::sleep(sync_interval).await;
                    store.fsync_wal();
                }
            });
        }

        if runtime.config.storage.mode == StorageMode::Tiered {
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
        shutdown_rx: watch::Receiver<Option<Duration>>,
    ) -> Option<(
        oneshot::Receiver<std::io::Result<std::net::SocketAddr>>,
        JoinHandle<()>,
    )> {
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
        let task = tokio::spawn(async move {
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
                shutdown_rx,
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
        Some((startup_rx, task))
    }
}

#[inline(always)]
fn cmd_eq_fast(input: &[u8], expected: &[u8]) -> bool {
    cmd::cmd_eq_ci(input, expected)
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
    secret_credential: &mut Option<crate::auth::SecretCredential>,
    store: &Arc<Store>,
    broker: &Broker,
    script_engine: &lua::ScriptEngine,
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
            let mut transaction = match store.begin_exec_transaction() {
                Ok(transaction) => transaction,
                Err(error) => {
                    resp::write_error(write_buf, &format!("ERR transaction unavailable: {error}"));
                    *in_multi = false;
                    *tx_error = false;
                    tx_queue.clear();
                    watched.clear();
                    return true;
                }
            };
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
                let mut transaction_out = BytesMut::new();
                let mut deferred_publishes = Vec::new();
                resp::write_array_header(&mut transaction_out, queue.len());
                for (command_index, owned_args) in queue.iter().enumerate() {
                    let refs: Vec<&[u8]> = owned_args.iter().map(|v| v.as_slice()).collect();
                    let cmd_result = {
                        let _guard = store.script_read_guard();
                        cmd::execute_with_wal(
                            store,
                            schema_cache,
                            broker,
                            &refs,
                            &mut transaction_out,
                            now,
                        )
                    };
                    match cmd_result {
                        CmdResult::Written => {}
                        CmdResult::Quit => {
                            resp::write_error(
                                &mut transaction_out,
                                "ERR QUIT is not allowed inside a transaction",
                            );
                        }
                        CmdResult::Authenticated { secret } => {
                            *authenticated = true;
                            *secret_credential = secret;
                        }
                        CmdResult::Subscribe { .. }
                        | CmdResult::PSubscribe { .. }
                        | CmdResult::KSubscribe { .. }
                        | CmdResult::KUnsubscribe { .. } => {
                            resp::write_error(
                                &mut transaction_out,
                                "ERR Command 'subscribe' not allowed inside a transaction",
                            );
                        }
                        CmdResult::Publish { channel, message } => {
                            let count = broker.publish_subscriber_count(&channel);
                            resp::write_integer(&mut transaction_out, count);
                            deferred_publishes.push((channel, message));
                        }
                        CmdResult::BlockPop { .. }
                        | CmdResult::BlockMove { .. }
                        | CmdResult::BlockStreamRead { .. }
                        | CmdResult::BlockListMPop { .. }
                        | CmdResult::BlockZMPop { .. }
                        | CmdResult::BlockZPop { .. } => {
                            resp::write_error(
                                &mut transaction_out,
                                "ERR blocking commands not allowed inside a transaction",
                            );
                        }
                        CmdResult::Eval { script, keys, argv } => {
                            handle_eval(
                                &mut transaction_out,
                                store,
                                broker,
                                script_engine,
                                &script,
                                &keys,
                                &argv,
                                now,
                            );
                        }
                        CmdResult::ScriptOp => {
                            handle_script_op(&mut transaction_out, script_engine, &refs);
                        }
                    }
                    store.exec_command_applied(command_index);
                }

                let committed_effects = match transaction.commit() {
                    Ok(effects) => {
                        write_buf.extend_from_slice(&transaction_out);
                        for owned_args in &effects.key_events {
                            let refs: Vec<&[u8]> = owned_args.iter().map(Vec::as_slice).collect();
                            fire_key_events(broker, &refs);
                        }
                        for (channel, message) in deferred_publishes {
                            broker.publish(&channel, message);
                        }
                        Some(effects)
                    }
                    Err(error) => {
                        resp::write_error(write_buf, &format!("ERR WAL append failed: {error}"));
                        None
                    }
                };
                drop(transaction);

                // Blocked list clients are allowed to consume committed values
                // only after the exclusive EXEC boundary has been released.
                if let Some(effects) = committed_effects {
                    for key in effects.list_wake_keys {
                        if broker.has_list_waiters(&key) {
                            broker.drain_list_waiters(&key, store, now);
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
            let _execution_guard = match store.execution_read_guard() {
                Ok(guard) => guard,
                Err(error) => {
                    resp::write_error(write_buf, &format!("ERR database unavailable: {error}"));
                    return true;
                }
            };
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
            || cmd_eq_fast(args[0], b"SAVE")
            || cmd_eq_fast(args[0], b"BGSAVE")
        {
            resp::write_error(
                write_buf,
                &format!(
                    "ERR Command '{}' not allowed inside a transaction",
                    std::str::from_utf8(args[0])
                        .unwrap_or("command")
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
    secret_credential: Option<crate::auth::SecretCredential>,
    client_name: Option<String>,
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
            secret_credential: None,
            client_name: None,
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

fn write_client_response(args: &[&[u8]], session: &mut CommandSession, out: &mut BytesMut) {
    if args.len() < 2 {
        resp::write_error(out, "ERR wrong number of arguments for 'client' command");
        return;
    }

    if args[1].eq_ignore_ascii_case(b"SETNAME") {
        if args.len() != 3 {
            resp::write_error(
                out,
                "ERR wrong number of arguments for 'client|setname' command",
            );
            return;
        }
        session.client_name = Some(String::from_utf8_lossy(args[2]).into_owned());
        resp::write_ok(out);
    } else if args[1].eq_ignore_ascii_case(b"GETNAME") {
        if args.len() != 2 {
            resp::write_error(
                out,
                "ERR wrong number of arguments for 'client|getname' command",
            );
            return;
        }
        match session.client_name.as_deref() {
            Some(name) => resp::write_bulk(out, name),
            None => resp::write_null(out),
        }
    } else if args[1].eq_ignore_ascii_case(b"SETINFO") {
        if args.len() != 4
            || !(args[2].eq_ignore_ascii_case(b"LIB-NAME")
                || args[2].eq_ignore_ascii_case(b"LIB-VER"))
        {
            resp::write_error(
                out,
                "ERR only CLIENT SETINFO LIB-NAME and LIB-VER are supported",
            );
            return;
        }
        // Redis 7.2 clients send this metadata during connection setup. Lux does
        // not expose a client list, so accepting these two fields is an explicit
        // compatibility no-op.
        resp::write_ok(out);
    } else {
        resp::write_error(out, "ERR unsupported CLIENT subcommand");
    }
}

fn is_script_gate_bypass_command(cmd: &[u8]) -> bool {
    cmd.eq_ignore_ascii_case(b"PING")
        || cmd.eq_ignore_ascii_case(b"ECHO")
        || cmd.eq_ignore_ascii_case(b"CLIENT")
        || cmd.eq_ignore_ascii_case(b"INFO")
        || cmd.eq_ignore_ascii_case(b"TIME")
        || cmd.eq_ignore_ascii_case(b"COMMAND")
        || cmd.eq_ignore_ascii_case(b"CONFIG")
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

        // Reserve internal table/auth storage from direct command access. This
        // universal entry also covers fast-path reads; KEYS/SCAN filter results.
        if !args[0].eq_ignore_ascii_case(b"KEYS") && !args[0].eq_ignore_ascii_case(b"SCAN") {
            for arg in &args[1..] {
                if cmd::is_reserved_internal_argument(arg) {
                    resp::write_error(write_buf, "ERR reserved internal namespace");
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
            &mut session.secret_credential,
            &self.store,
            &self.broker,
            &self.script_engine,
            &self.schema_cache,
            write_buf,
            now,
        ) {
            return None;
        }

        let _execution_guard = match self.store.execution_read_guard() {
            Ok(guard) => guard,
            Err(error) => {
                resp::write_error(write_buf, &format!("ERR database unavailable: {error}"));
                return None;
            }
        };

        if args[0].eq_ignore_ascii_case(b"CLIENT") {
            write_client_response(args, session, write_buf);
            return None;
        }

        if is_script_gate_bypass_command(args[0]) {
            let cmd_result = cmd::execute_with_wal(
                &self.store,
                &self.schema_cache,
                &self.broker,
                args,
                write_buf,
                now,
            );
            return self.apply_cmd_result(cmd_result, args, session, write_buf, now);
        }

        if !cmd::is_pipeline_special_command(args[0]) {
            let access = cmd::pipeline_access_for_args(args);
            // The shard-local read fast-path reads stored bytes directly and has
            // no keyring, so it cannot decrypt. When encryption is active, fall
            // through to the slow path (cmd::execute) which decrypts on read.
            if access == cmd::PipelineAccess::Read && !self.store.encryption().has_active_key() {
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
            let _execution_guard = match self.store.execution_read_guard() {
                Ok(guard) => guard,
                Err(error) => {
                    resp::write_error(write_buf, &format!("ERR database unavailable: {error}"));
                    return None;
                }
            };
            for command in commands {
                let args = command.argv();
                let channel = String::from_utf8_lossy(args[1]).into_owned();
                let message = bytes::Bytes::copy_from_slice(args[2]);
                let count = self.broker.publish(&channel, message);
                resp::write_integer(write_buf, count);
            }
            return None;
        }

        if !session.in_multi
            && session.authenticated
            && commands.iter().all(|command| {
                let args = command.argv();
                !args.is_empty() && is_script_gate_bypass_command(args[0])
            })
        {
            let _execution_guard = match self.store.execution_read_guard() {
                Ok(guard) => guard,
                Err(error) => {
                    resp::write_error(write_buf, &format!("ERR database unavailable: {error}"));
                    return None;
                }
            };
            for command in commands {
                let args = command.argv();
                if args[0].eq_ignore_ascii_case(b"CLIENT") {
                    write_client_response(args, session, write_buf);
                    continue;
                }
                let cmd_result = cmd::execute_with_wal(
                    &self.store,
                    &self.schema_cache,
                    &self.broker,
                    args,
                    write_buf,
                    now,
                );
                if let Some(action) =
                    self.apply_cmd_result(cmd_result, args, session, write_buf, now)
                {
                    return Some(action);
                }
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
            // Force commands touching an internal namespace onto the guarded
            // slow path. KEYS/SCAN are filtered there.
            if !cmd.eq_ignore_ascii_case(b"KEYS")
                && !cmd.eq_ignore_ascii_case(b"SCAN")
                && args[1..]
                    .iter()
                    .any(|arg| cmd::is_reserved_internal_argument(arg))
            {
                all_single_key_rw = false;
            }
            let access = cmd::pipeline_access_for_args(args);
            flags.push(access);
            // Writes must cross their per-command authoritative journal
            // boundary so a rejected command cannot leave a durable frame in a
            // pre-journaled batch. Only read-only runs use shard batching.
            if access != cmd::PipelineAccess::Read {
                all_single_key_rw = false;
            }
        }

        // When encryption is active, the shard-local fast batch path can neither
        // encrypt writes nor decrypt reads (no keyring there), so force every
        // command onto the slow path (cmd::execute) which handles both.
        if has_special || !all_single_key_rw || self.store.encryption().has_active_key() {
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
                    &mut session.secret_credential,
                    &self.store,
                    &self.broker,
                    &self.script_engine,
                    &self.schema_cache,
                    write_buf,
                    now,
                ) {
                    continue;
                }

                let _execution_guard = match self.store.execution_read_guard() {
                    Ok(guard) => guard,
                    Err(error) => {
                        resp::write_error(write_buf, &format!("ERR database unavailable: {error}"));
                        continue;
                    }
                };

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
        let _execution_guard = match self.store.execution_read_guard() {
            Ok(guard) => guard,
            Err(error) => {
                resp::write_error(write_buf, &format!("ERR database unavailable: {error}"));
                return None;
            }
        };
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
                fire_key_events(&self.broker, args);
                None
            }
            CmdResult::Quit => {
                resp::write_ok(write_buf);
                Some(CmdResult::Quit)
            }
            CmdResult::Authenticated { secret } => {
                session.authenticated = true;
                session.secret_credential = secret;
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
            | CmdResult::BlockListMPop { .. }
            | CmdResult::BlockZMPop { .. }
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
        ShardExecutionError::Eviction(message) => resp::write_error(write_buf, &message),
        ShardExecutionError::Wal(message) => {
            resp::write_error(write_buf, &format!("ERR WAL append failed: {message}"))
        }
    }
}

async fn await_resp_blocking_action<F>(
    future: F,
    credential: Option<&crate::auth::SecretCredential>,
    store: &Store,
    cache: &SharedSchemaCache,
) -> std::io::Result<bool>
where
    F: std::future::Future<Output = std::io::Result<()>>,
{
    let Some(credential) = credential else {
        future.await?;
        return Ok(false);
    };
    tokio::pin!(future);
    let mut auth_tick = tokio::time::interval(std::time::Duration::from_secs(1));
    auth_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            result = &mut future => {
                result?;
                return Ok(false);
            }
            _ = auth_tick.tick() => {
                if crate::auth::revalidate_secret_credential(credential, store, cache).is_err() {
                    return Ok(true);
                }
            }
        }
    }
}

async fn handle_connection(
    mut socket: tokio::net::TcpStream,
    _peer: std::net::SocketAddr,
    runtime: Arc<Runtime>,
    mut shutdown_rx: watch::Receiver<Option<Duration>>,
) -> std::io::Result<()> {
    let store = runtime.store.clone();
    let broker = runtime.broker.clone();
    let mut read_buf = vec![0u8; 65536];
    let mut write_buf = BytesMut::with_capacity(65536);
    let mut pending = BytesMut::new();
    let max_resp_request = runtime.config.max_resp_request;
    // An engine is credential-gated by a password *or* by project keys. Checked
    // per connection rather than per command: `require_auth` is fixed at startup,
    // so without this a key-only engine (no LUX_PASSWORD) would leave RESP wide
    // open, and keys minted at runtime would never start gating it.
    let keys_require_auth =
        crate::auth::project_keys_configured(&runtime.store, &runtime.schema_cache).unwrap_or(true);
    let mut session = CommandSession::new(runtime.config.require_auth || keys_require_auth);
    let executor = CommandExecutor::new(
        runtime.store.clone(),
        runtime.broker.clone(),
        runtime.script_engine.clone(),
        runtime.schema_cache.clone(),
    );
    let mut auth_tick = tokio::time::interval(std::time::Duration::from_secs(1));
    auth_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        if shutdown_rx.borrow().is_some() {
            return Ok(());
        }
        if session.sub_mode {
            tokio::select! {
                _ = shutdown_rx.changed() => return Ok(()),
                _ = auth_tick.tick(), if session.secret_credential.is_some() => {
                    if session.secret_credential.as_ref().is_some_and(|credential| {
                        crate::auth::revalidate_secret_credential(
                            credential,
                            &runtime.store,
                            &runtime.schema_cache,
                        )
                        .is_err()
                    }) {
                        resp::write_error(&mut write_buf, "NOAUTH secret key is revoked or unavailable");
                        socket.write_all(&write_buf).await?;
                        return Ok(());
                    }
                }
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
                        let _execution_guard = store.execution_barrier_guard();
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

                    for rx in session.subscriptions.values_mut() {
                        if let Ok(msg) = rx.try_recv() {
                            return Some(vec![msg]);
                        }
                    }
                    for rx in session.pattern_subs.values_mut() {
                        if let Ok(msg) = rx.try_recv() {
                            return Some(vec![msg]);
                        }
                    }
                    for rx in session.key_subs.values_mut() {
                        if let Ok(msg) = rx.try_recv() {
                            return Some(vec![msg]);
                        }
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                    for rx in session.subscriptions.values_mut() {
                        if let Ok(msg) = rx.try_recv() {
                            return Some(vec![msg]);
                        }
                    }
                    for rx in session.pattern_subs.values_mut() {
                        if let Ok(msg) = rx.try_recv() {
                            return Some(vec![msg]);
                        }
                    }
                    for rx in session.key_subs.values_mut() {
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
            // A complete read is accepted work and may finish. The next read is
            // gated by shutdown so a persistent connection cannot start a new
            // request after the listener closes.
            let read = tokio::select! {
                _ = shutdown_rx.changed() => return Ok(()),
                _ = auth_tick.tick(), if session.secret_credential.is_some() => {
                    if session.secret_credential.as_ref().is_some_and(|credential| {
                        crate::auth::revalidate_secret_credential(
                            credential,
                            &runtime.store,
                            &runtime.schema_cache,
                        )
                        .is_err()
                    }) {
                        resp::write_error(&mut write_buf, "NOAUTH secret key is revoked or unavailable");
                        socket.write_all(&write_buf).await?;
                        return Ok(());
                    }
                    continue;
                }
                result = socket.read(&mut read_buf) => result,
            };
            let n = match read {
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
                    CmdResult::Quit => return Ok(()),
                    CmdResult::BlockPop {
                        keys,
                        timeout,
                        pop_left,
                    } => {
                        if await_resp_blocking_action(
                            handle_block_pop(
                                &mut socket,
                                &store,
                                &broker,
                                &keys,
                                timeout,
                                pop_left,
                            ),
                            session.secret_credential.as_ref(),
                            &runtime.store,
                            &runtime.schema_cache,
                        )
                        .await?
                        {
                            return Ok(());
                        }
                    }
                    CmdResult::BlockMove {
                        src,
                        dst,
                        src_left,
                        dst_left,
                        timeout,
                    } => {
                        if await_resp_blocking_action(
                            handle_block_move(
                                &mut socket,
                                &store,
                                &broker,
                                &src,
                                &dst,
                                src_left,
                                dst_left,
                                timeout,
                            ),
                            session.secret_credential.as_ref(),
                            &runtime.store,
                            &runtime.schema_cache,
                        )
                        .await?
                        {
                            return Ok(());
                        }
                    }
                    CmdResult::BlockStreamRead {
                        keys,
                        ids,
                        group,
                        count,
                        noack,
                        timeout,
                    } => {
                        if await_resp_blocking_action(
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
                            ),
                            session.secret_credential.as_ref(),
                            &runtime.store,
                            &runtime.schema_cache,
                        )
                        .await?
                        {
                            return Ok(());
                        }
                    }
                    CmdResult::BlockZPop {
                        keys,
                        timeout,
                        pop_min,
                    } => {
                        if await_resp_blocking_action(
                            handle_block_zpop(&mut socket, &store, &keys, timeout, pop_min),
                            session.secret_credential.as_ref(),
                            &runtime.store,
                            &runtime.schema_cache,
                        )
                        .await?
                        {
                            return Ok(());
                        }
                    }
                    CmdResult::BlockZMPop {
                        keys,
                        pop_min,
                        count,
                        timeout,
                    } => {
                        if await_resp_blocking_action(
                            handle_block_zmpop(&mut socket, &store, &keys, pop_min, count, timeout),
                            session.secret_credential.as_ref(),
                            &runtime.store,
                            &runtime.schema_cache,
                        )
                        .await?
                        {
                            return Ok(());
                        }
                    }
                    CmdResult::BlockListMPop {
                        keys,
                        pop_left,
                        count,
                        timeout,
                    } => {
                        if await_resp_blocking_action(
                            handle_block_lmpop(
                                &mut socket,
                                &store,
                                &keys,
                                pop_left,
                                count,
                                timeout,
                            ),
                            session.secret_credential.as_ref(),
                            &runtime.store,
                            &runtime.schema_cache,
                        )
                        .await?
                        {
                            return Ok(());
                        }
                    }
                    _ => continue,
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
                destination: None,
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
    _store: &Arc<Store>,
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
            destination: Some((dst.to_string(), dst_left)),
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
    for key in keys {
        if let Err(error) = store.try_promote(key.as_bytes(), now_pre) {
            let mut out = BytesMut::new();
            resp::write_error(&mut out, &error);
            return socket.write_all(&out).await;
        }
    }
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
    let waiter_id = broker.next_waiter_id();
    for key in keys {
        broker.register_stream_waiter(key, tx.clone(), waiter_id);
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
            Ok(_) => {
                resp::write_null_array(&mut write_buf);
            }
            Err(error) => resp::write_error(&mut write_buf, &error),
        }
    } else {
        resp::write_null_array(&mut write_buf);
    }

    broker.remove_stream_waiters_by_id(keys, waiter_id);

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

async fn handle_block_lmpop(
    socket: &mut tokio::net::TcpStream,
    store: &Arc<Store>,
    keys: &[String],
    pop_left: bool,
    count: usize,
    timeout: std::time::Duration,
) -> std::io::Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    let key_refs: Vec<&[u8]> = keys.iter().map(|k| k.as_bytes()).collect();
    let mut write_buf = BytesMut::new();

    loop {
        let now = Instant::now();
        match cmd::journaled_lmpop(store, &key_refs, pop_left, count, now) {
            Ok(Some((key, items))) => {
                resp::write_array_header(&mut write_buf, 2);
                resp::write_bulk_raw(&mut write_buf, &key);
                resp::write_array_header(&mut write_buf, items.len());
                for item in &items {
                    let decrypted = store
                        .decrypt_list_element(item.clone())
                        .unwrap_or_else(|_| item.clone());
                    resp::write_bulk_raw(&mut write_buf, &decrypted);
                }
                return socket.write_all(&write_buf).await;
            }
            Ok(None) => {}
            Err(e) => {
                resp::write_error(&mut write_buf, &e);
                return socket.write_all(&write_buf).await;
            }
        }

        if tokio::time::Instant::now() >= deadline {
            resp::write_null_array(&mut write_buf);
            return socket.write_all(&write_buf).await;
        }

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

async fn handle_block_zmpop(
    socket: &mut tokio::net::TcpStream,
    store: &Arc<Store>,
    keys: &[String],
    pop_min: bool,
    count: usize,
    timeout: std::time::Duration,
) -> std::io::Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    let key_refs: Vec<&[u8]> = keys.iter().map(|k| k.as_bytes()).collect();
    let mut write_buf = BytesMut::new();

    loop {
        let now = Instant::now();
        match cmd::journaled_zmpop(store, &key_refs, pop_min, count, now) {
            Ok(Some((key, items))) => {
                resp::write_array_header(&mut write_buf, 2);
                resp::write_bulk_raw(&mut write_buf, &key);
                resp::write_array_header(&mut write_buf, items.len());
                for (member, score) in &items {
                    resp::write_array_header(&mut write_buf, 2);
                    resp::write_bulk(&mut write_buf, member);
                    let score_str = if score.fract() == 0.0 && score.abs() < 1e15 {
                        format!("{}", *score as i64)
                    } else {
                        format!("{score}")
                    };
                    resp::write_bulk(&mut write_buf, &score_str);
                }
                return socket.write_all(&write_buf).await;
            }
            Ok(None) => {}
            Err(e) => {
                resp::write_error(&mut write_buf, &e);
                return socket.write_all(&write_buf).await;
            }
        }

        if tokio::time::Instant::now() >= deadline {
            resp::write_null_array(&mut write_buf);
            return socket.write_all(&write_buf).await;
        }

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
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
        let key_refs: Vec<&[u8]> = keys.iter().map(|key| key.as_bytes()).collect();
        if let Ok(Some((key, items))) = cmd::journaled_zmpop(store, &key_refs, pop_min, 1, now) {
            if let Some((member, score)) = items.first() {
                resp::write_array_header(&mut write_buf, 3);
                resp::write_bulk_raw(&mut write_buf, &key);
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

#[cfg(test)]
mod tx_tests {
    use super::*;

    fn executor_for(store: Arc<Store>, broker: Broker) -> CommandExecutor {
        let schema_cache: SharedSchemaCache =
            Arc::new(parking_lot::RwLock::new(tables::SchemaCache::new()));
        CommandExecutor::new(
            store,
            broker,
            Arc::new(lua::ScriptEngine::new()),
            schema_cache,
        )
    }

    fn execute(
        executor: &CommandExecutor,
        session: &mut CommandSession,
        args: &[&[u8]],
    ) -> BytesMut {
        let mut out = BytesMut::new();
        executor.execute_command(args, session, &mut out, Instant::now());
        out
    }

    fn test_executor() -> (CommandExecutor, CommandSession) {
        let store = Arc::new(Store::new());
        let broker = Broker::new();
        let executor = executor_for(store, broker);
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
        let script_engine = lua::ScriptEngine::new();
        let schema_cache: SharedSchemaCache =
            Arc::new(parking_lot::RwLock::new(tables::SchemaCache::new()));

        for command in [
            "SUBSCRIBE",
            "UNSUBSCRIBE",
            "PSUBSCRIBE",
            "PUNSUBSCRIBE",
            "SAVE",
            "BGSAVE",
        ] {
            let mut in_multi = true;
            let mut tx_error = false;
            let mut tx_queue = Vec::new();
            let mut watched = Vec::new();
            let mut authenticated = true;
            let mut secret_credential = None;
            let mut out = BytesMut::new();
            let args: [&[u8]; 2] = [command.as_bytes(), b"chan"];

            assert!(handle_tx_cmd(
                &args,
                &mut in_multi,
                &mut tx_error,
                &mut tx_queue,
                &mut watched,
                &mut authenticated,
                &mut secret_credential,
                &store,
                &broker,
                &script_engine,
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

    #[test]
    fn exec_hides_intermediate_state_from_other_clients() {
        let store = Arc::new(Store::new());
        let broker = Broker::new();
        store.set(b"left", b"before", None, Instant::now());
        store.set(b"right", b"before", None, Instant::now());

        let reached_midpoint = Arc::new(std::sync::Barrier::new(2));
        let release_transaction = Arc::new(std::sync::Barrier::new(2));
        store.set_exec_after_command_hook(Some({
            let reached_midpoint = reached_midpoint.clone();
            let release_transaction = release_transaction.clone();
            Arc::new(move |index| {
                if index == 0 {
                    reached_midpoint.wait();
                    release_transaction.wait();
                }
            })
        }));

        let writer_store = store.clone();
        let writer_broker = broker.clone();
        let writer = std::thread::spawn(move || {
            let executor = executor_for(writer_store, writer_broker);
            let mut session = CommandSession::new(false);
            execute(&executor, &mut session, &[b"MULTI"]);
            execute(&executor, &mut session, &[b"SET", b"left", b"after"]);
            execute(&executor, &mut session, &[b"SET", b"right", b"after"]);
            execute(&executor, &mut session, &[b"EXEC"])
        });

        reached_midpoint.wait();
        let reader_store = store.clone();
        let reader_broker = broker.clone();
        let (read_tx, read_rx) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let executor = executor_for(reader_store, reader_broker);
            let mut session = CommandSession::new(false);
            let out = execute(&executor, &mut session, &[b"MGET", b"left", b"right"]);
            read_tx.send(out).unwrap();
        });

        std::thread::sleep(Duration::from_millis(50));
        assert!(
            matches!(
                read_rx.try_recv(),
                Err(std::sync::mpsc::TryRecvError::Empty)
            ),
            "reader observed the transaction before EXEC committed"
        );
        release_transaction.wait();

        let exec_out = writer.join().unwrap();
        assert!(String::from_utf8_lossy(&exec_out).starts_with("*2\r\n"));
        let read_out = read_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        reader.join().unwrap();
        assert_eq!(&read_out[..], b"*2\r\n$5\r\nafter\r\n$5\r\nafter\r\n");
        store.set_exec_after_command_hook(None);
    }

    #[test]
    fn active_expiry_waits_for_exec_to_finish() {
        let store = Arc::new(Store::new());
        let broker = Broker::new();
        let started = Instant::now();
        store.set(
            b"expired",
            b"value",
            Some(Duration::from_millis(1)),
            started,
        );

        let reached_midpoint = Arc::new(std::sync::Barrier::new(2));
        let release_transaction = Arc::new(std::sync::Barrier::new(2));
        store.set_exec_after_command_hook(Some({
            let reached_midpoint = reached_midpoint.clone();
            let release_transaction = release_transaction.clone();
            Arc::new(move |index| {
                if index == 0 {
                    reached_midpoint.wait();
                    release_transaction.wait();
                }
            })
        }));

        let writer = std::thread::spawn({
            let store = store.clone();
            let broker = broker.clone();
            move || {
                let executor = executor_for(store, broker);
                let mut session = CommandSession::new(false);
                execute(&executor, &mut session, &[b"MULTI"]);
                execute(&executor, &mut session, &[b"SET", b"first", b"one"]);
                execute(&executor, &mut session, &[b"SET", b"last", b"two"]);
                execute(&executor, &mut session, &[b"EXEC"])
            }
        });

        reached_midpoint.wait();
        let (expired_tx, expired_rx) = std::sync::mpsc::channel();
        let expiry = std::thread::spawn({
            let store = store.clone();
            move || {
                store.expire_sweep(started + Duration::from_secs(1));
                expired_tx.send(()).unwrap();
            }
        });
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            matches!(
                expired_rx.try_recv(),
                Err(std::sync::mpsc::TryRecvError::Empty)
            ),
            "active expiry crossed the EXEC boundary"
        );

        release_transaction.wait();
        writer.join().unwrap();
        expired_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        expiry.join().unwrap();
        assert!(store
            .get(b"expired", started + Duration::from_secs(1))
            .is_none());
        assert_eq!(store.get(b"first", Instant::now()).unwrap(), b"one"[..]);
        assert_eq!(store.get(b"last", Instant::now()).unwrap(), b"two"[..]);
        store.set_exec_after_command_hook(None);
    }

    #[test]
    fn exec_runtime_error_keeps_other_successful_commands() {
        let (executor, mut session) = test_executor();
        execute(&executor, &mut session, &[b"SET", b"typed", b"string"]);
        execute(&executor, &mut session, &[b"MULTI"]);
        execute(&executor, &mut session, &[b"SET", b"first", b"one"]);
        execute(&executor, &mut session, &[b"LPUSH", b"typed", b"value"]);
        execute(&executor, &mut session, &[b"SET", b"last", b"two"]);
        let out = execute(&executor, &mut session, &[b"EXEC"]);
        let response = String::from_utf8_lossy(&out);
        assert!(response.starts_with("*3\r\n"), "{response}");
        assert!(response.contains("WRONGTYPE"), "{response}");
        assert_eq!(
            &execute(&executor, &mut session, &[b"MGET", b"first", b"last"])[..],
            b"*2\r\n$3\r\none\r\n$3\r\ntwo\r\n"
        );
    }

    #[test]
    fn exec_defers_publish_until_the_transaction_commits() {
        let store = Arc::new(Store::new());
        let broker = Broker::new();
        let mut receiver = broker.subscribe("events");
        let reached_publish = Arc::new(std::sync::Barrier::new(2));
        let release_transaction = Arc::new(std::sync::Barrier::new(2));
        store.set_exec_after_command_hook(Some({
            let reached_publish = reached_publish.clone();
            let release_transaction = release_transaction.clone();
            Arc::new(move |index| {
                if index == 1 {
                    reached_publish.wait();
                    release_transaction.wait();
                }
            })
        }));

        let writer = std::thread::spawn({
            let store = store.clone();
            let broker = broker.clone();
            move || {
                let executor = executor_for(store, broker);
                let mut session = CommandSession::new(false);
                execute(&executor, &mut session, &[b"MULTI"]);
                execute(&executor, &mut session, &[b"SET", b"first", b"one"]);
                execute(
                    &executor,
                    &mut session,
                    &[b"PUBLISH", b"events", b"committed"],
                );
                execute(&executor, &mut session, &[b"SET", b"last", b"two"]);
                execute(&executor, &mut session, &[b"EXEC"])
            }
        });

        reached_publish.wait();
        assert!(
            matches!(
                receiver.try_recv(),
                Err(broadcast::error::TryRecvError::Empty)
            ),
            "PUBLISH escaped before the transaction committed"
        );
        release_transaction.wait();
        let out = writer.join().unwrap();
        assert!(String::from_utf8_lossy(&out).contains(":1\r\n"));
        let message = receiver
            .try_recv()
            .expect("committed publish was not delivered");
        assert_eq!(message.payload, bytes::Bytes::from_static(b"committed"));
        store.set_exec_after_command_hook(None);
    }

    #[test]
    fn list_waiter_registered_mid_exec_receives_committed_push() {
        let store = Arc::new(Store::new());
        let broker = Broker::new();
        let reached_push = Arc::new(std::sync::Barrier::new(2));
        let release_transaction = Arc::new(std::sync::Barrier::new(2));
        store.set_exec_after_command_hook(Some({
            let reached_push = reached_push.clone();
            let release_transaction = release_transaction.clone();
            Arc::new(move |index| {
                if index == 0 {
                    reached_push.wait();
                    release_transaction.wait();
                }
            })
        }));

        let writer = std::thread::spawn({
            let store = store.clone();
            let broker = broker.clone();
            move || {
                let executor = executor_for(store, broker);
                let mut session = CommandSession::new(false);
                execute(&executor, &mut session, &[b"MULTI"]);
                execute(&executor, &mut session, &[b"LPUSH", b"jobs", b"ready"]);
                execute(&executor, &mut session, &[b"EXEC"])
            }
        });

        reached_push.wait();
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        broker.register_list_waiter(
            "jobs",
            pubsub::BlockedPopRequest {
                tx,
                pop_left: false,
                destination: None,
                waiter_id: broker.next_waiter_id(),
            },
        );
        assert!(rx.try_recv().is_err(), "list value escaped before commit");

        release_transaction.wait();
        writer.join().unwrap();
        let (key, value) = rx
            .blocking_recv()
            .expect("committed push was not delivered");
        assert_eq!(key, "jobs");
        assert_eq!(value, bytes::Bytes::from_static(b"ready"));
        store.set_exec_after_command_hook(None);
    }

    fn persistent_executor(
        root: &std::path::Path,
    ) -> (Arc<crate::ServerConfig>, Arc<Store>, CommandExecutor) {
        let config = Arc::new(crate::ServerConfig {
            data_dir: root.to_string_lossy().into_owned(),
            durability: crate::DurabilityConfig {
                policy: crate::DurabilityPolicy::AlwaysSync,
                ..Default::default()
            },
            ..Default::default()
        });
        let store = Arc::new(Store::new_with_config(config.clone()));
        let executor = executor_for(store.clone(), Broker::new());
        (config, store, executor)
    }

    #[test]
    fn snapshot_waits_for_exec_and_captures_the_committed_state() {
        let root = tempfile::tempdir().unwrap();
        let (config, store, setup_executor) = persistent_executor(root.path());
        drop(setup_executor);

        let reached_midpoint = Arc::new(std::sync::Barrier::new(2));
        let release_transaction = Arc::new(std::sync::Barrier::new(2));
        store.set_exec_after_command_hook(Some({
            let reached_midpoint = reached_midpoint.clone();
            let release_transaction = release_transaction.clone();
            Arc::new(move |index| {
                if index == 0 {
                    reached_midpoint.wait();
                    release_transaction.wait();
                }
            })
        }));

        let writer = std::thread::spawn({
            let store = store.clone();
            move || {
                let executor = executor_for(store, Broker::new());
                let mut session = CommandSession::new(false);
                execute(&executor, &mut session, &[b"MULTI"]);
                execute(&executor, &mut session, &[b"SET", b"first", b"one"]);
                execute(&executor, &mut session, &[b"SET", b"last", b"two"]);
                execute(&executor, &mut session, &[b"EXEC"])
            }
        });

        reached_midpoint.wait();
        let (snapshot_tx, snapshot_rx) = std::sync::mpsc::channel();
        let snapshot = std::thread::spawn({
            let store = store.clone();
            move || {
                snapshot_tx
                    .send(crate::snapshot::save_and_truncate_wal_consistent(&store))
                    .unwrap();
            }
        });
        assert!(
            snapshot_rx.recv_timeout(Duration::from_millis(50)).is_err(),
            "snapshot captured an intermediate EXEC state"
        );

        release_transaction.wait();
        let output = writer.join().unwrap();
        assert!(String::from_utf8_lossy(&output).starts_with("*2\r\n"));
        snapshot_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap();
        snapshot.join().unwrap();
        store.set_exec_after_command_hook(None);
        drop(store);

        let recovered = Store::new_with_config(config);
        crate::snapshot::load(&recovered).unwrap();
        recovered.replay_wal(&Broker::new()).unwrap();
        assert_eq!(recovered.get(b"first", Instant::now()).unwrap(), b"one"[..]);
        assert_eq!(recovered.get(b"last", Instant::now()).unwrap(), b"two"[..]);
    }

    #[test]
    fn failed_exec_wal_append_fails_closed_without_recovering_a_prefix() {
        let root = tempfile::tempdir().unwrap();
        let (config, store, executor) = persistent_executor(root.path());
        let mut session = CommandSession::new(false);
        execute(&executor, &mut session, &[b"MULTI"]);
        execute(&executor, &mut session, &[b"SET", b"first", b"one"]);
        execute(&executor, &mut session, &[b"SET", b"last", b"two"]);
        store.inject_journal_failures(1);
        let out = execute(&executor, &mut session, &[b"EXEC"]);
        assert!(
            String::from_utf8_lossy(&out).contains("WAL append failed"),
            "{}",
            String::from_utf8_lossy(&out)
        );
        let out = execute(&executor, &mut session, &[b"GET", b"first"]);
        assert!(
            String::from_utf8_lossy(&out).contains("database unavailable"),
            "{}",
            String::from_utf8_lossy(&out)
        );

        drop(executor);
        drop(store);
        let recovered = Store::new_with_config(config);
        recovered.replay_wal(&Broker::new()).unwrap();
        assert!(recovered.get(b"first", Instant::now()).is_none());
        assert!(recovered.get(b"last", Instant::now()).is_none());
    }

    #[test]
    fn truncated_exec_frame_recovers_none_of_the_transaction() {
        let root = tempfile::tempdir().unwrap();
        let (config, store, executor) = persistent_executor(root.path());
        let mut session = CommandSession::new(false);
        execute(&executor, &mut session, &[b"SET", b"baseline", b"safe"]);
        let wal_path = config.journal_dir().join("global/wal.lux");
        let baseline_len = std::fs::metadata(&wal_path).unwrap().len();

        execute(&executor, &mut session, &[b"MULTI"]);
        execute(&executor, &mut session, &[b"SET", b"first", b"one"]);
        execute(&executor, &mut session, &[b"SET", b"second", b"two"]);
        execute(&executor, &mut session, &[b"SET", b"third", b"three"]);
        let out = execute(&executor, &mut session, &[b"EXEC"]);
        assert!(String::from_utf8_lossy(&out).starts_with("*3\r\n"));
        let committed_len = std::fs::metadata(&wal_path).unwrap().len();
        assert!(committed_len > baseline_len);
        drop(executor);
        drop(store);

        let full = Store::new_with_config(config.clone());
        full.replay_wal(&Broker::new()).unwrap();
        assert_eq!(full.get(b"first", Instant::now()).unwrap(), b"one"[..]);
        assert_eq!(full.get(b"third", Instant::now()).unwrap(), b"three"[..]);
        drop(full);

        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&wal_path)
            .unwrap();
        file.set_len(baseline_len + (committed_len - baseline_len) / 2)
            .unwrap();
        drop(file);

        let truncated = Store::new_with_config(config);
        truncated.replay_wal(&Broker::new()).unwrap();
        assert_eq!(
            truncated.get(b"baseline", Instant::now()).unwrap(),
            b"safe"[..]
        );
        assert!(truncated.get(b"first", Instant::now()).is_none());
        assert!(truncated.get(b"second", Instant::now()).is_none());
        assert!(truncated.get(b"third", Instant::now()).is_none());
    }

    #[test]
    fn exec_runtime_error_recovery_replays_only_successful_commands() {
        let root = tempfile::tempdir().unwrap();
        let (config, store, executor) = persistent_executor(root.path());
        let mut session = CommandSession::new(false);
        execute(&executor, &mut session, &[b"SET", b"typed", b"string"]);
        execute(&executor, &mut session, &[b"MULTI"]);
        execute(&executor, &mut session, &[b"SET", b"first", b"one"]);
        execute(&executor, &mut session, &[b"LPUSH", b"typed", b"value"]);
        execute(&executor, &mut session, &[b"SET", b"last", b"two"]);
        let out = execute(&executor, &mut session, &[b"EXEC"]);
        assert!(String::from_utf8_lossy(&out).contains("WRONGTYPE"));
        drop(executor);
        drop(store);

        let recovered = Store::new_with_config(config);
        recovered.replay_wal(&Broker::new()).unwrap();
        assert_eq!(
            recovered.get(b"typed", Instant::now()).unwrap(),
            b"string"[..]
        );
        assert_eq!(recovered.get(b"first", Instant::now()).unwrap(), b"one"[..]);
        assert_eq!(recovered.get(b"last", Instant::now()).unwrap(), b"two"[..]);
    }
}

#[cfg(test)]
mod persistence_config_tests {
    use super::*;

    fn persistent_config(root: &std::path::Path, layout: StorageMode) -> ServerConfig {
        ServerConfig {
            data_dir: root.to_string_lossy().into_owned(),
            storage: StorageConfig {
                mode: layout,
                dir: root.join("storage").to_string_lossy().into_owned(),
            },
            ..Default::default()
        }
    }

    #[test]
    fn default_policy_durably_acknowledges_each_write() {
        let config = ServerConfig::default();
        assert_eq!(config.durability.policy, DurabilityPolicy::AlwaysSync);
        assert_eq!(config.durability.sync_interval, Duration::from_secs(1));
    }

    #[test]
    fn tiered_layout_cannot_claim_ephemeral_durability() {
        let root = tempfile::tempdir().unwrap();
        let mut config = persistent_config(root.path(), StorageMode::Tiered);
        config.durability.policy = DurabilityPolicy::Ephemeral;
        let error = resolve_and_validate_persistence(&mut config).unwrap_err();
        assert!(
            error.to_string().contains("tiered storage requires"),
            "{error}"
        );
    }

    #[test]
    fn every_second_interval_is_bounded() {
        let root = tempfile::tempdir().unwrap();
        for interval in [Duration::ZERO, Duration::from_millis(1_001)] {
            let mut config = persistent_config(root.path(), StorageMode::Memory);
            config.durability.policy = DurabilityPolicy::EverySecond;
            config.durability.sync_interval = interval;
            let error = resolve_and_validate_persistence(&mut config).unwrap_err();
            assert!(error.to_string().contains("1 to 1000 ms"), "{error}");
        }
    }

    #[test]
    fn persistent_layout_changes_refuse_to_hide_existing_state() {
        let tiered_root = tempfile::tempdir().unwrap();
        let tiered_shard = tiered_root.path().join("storage/shard_0");
        std::fs::create_dir_all(&tiered_shard).unwrap();
        std::fs::write(tiered_shard.join("wal.lux"), b"state").unwrap();
        let mut memory = persistent_config(tiered_root.path(), StorageMode::Memory);
        let error = resolve_and_validate_persistence(&mut memory).unwrap_err();
        assert!(error.to_string().contains("switch to memory"), "{error}");

        let memory_root = tempfile::tempdir().unwrap();
        let memory_journal = memory_root.path().join("journal/global");
        std::fs::create_dir_all(&memory_journal).unwrap();
        std::fs::write(memory_journal.join("wal.lux"), b"state").unwrap();
        let mut tiered = persistent_config(memory_root.path(), StorageMode::Tiered);
        let error = resolve_and_validate_persistence(&mut tiered).unwrap_err();
        assert!(error.to_string().contains("switch to tiered"), "{error}");

        let legacy_root = tempfile::tempdir().unwrap();
        let legacy_journal = legacy_root.path().join("journal/shard_0");
        std::fs::create_dir_all(&legacy_journal).unwrap();
        std::fs::write(legacy_journal.join("wal.lux"), b"state").unwrap();
        let mut tiered = persistent_config(legacy_root.path(), StorageMode::Tiered);
        let error = resolve_and_validate_persistence(&mut tiered).unwrap_err();
        assert!(error.to_string().contains("switch to tiered"), "{error}");
    }

    #[tokio::test]
    async fn runtime_storage_error_reaches_the_embedded_caller() {
        let root = tempfile::tempdir().unwrap();
        let storage = root.path().join("storage");
        std::fs::create_dir_all(&storage).unwrap();
        std::fs::write(storage.join("shard_0"), b"not a directory").unwrap();

        let mut config = persistent_config(root.path(), StorageMode::Tiered);
        config.enable_resp = false;
        let error = match run_with_config(config).await {
            Ok(_) => panic!("invalid storage layout unexpectedly started"),
            Err(error) => error,
        };
        assert_ne!(
            error.to_string(),
            "server startup failed before readiness signal"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn persistent_directory_cannot_be_opened_by_two_runtimes() {
        let root = tempfile::tempdir().unwrap();
        let mut config = persistent_config(root.path(), StorageMode::Memory);
        config.enable_resp = false;
        config.save_interval = Duration::ZERO;

        let first = run_with_config(config.clone()).await.unwrap();
        let error = match run_with_config(config.clone()).await {
            Ok(_) => panic!("second runtime unexpectedly acquired the persistent directory"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert!(error.to_string().contains("already in use"), "{error}");

        let stale_client = first.client();
        first.shutdown_and_wait().await.unwrap();
        run_with_config(config)
            .await
            .unwrap()
            .shutdown_and_wait()
            .await
            .unwrap();
        assert!(stale_client
            .execute_value("SET", &["after-shutdown", "rejected"])
            .await
            .is_err());
    }
}

#[cfg(test)]
mod shutdown_tests {
    use super::*;

    async fn wait_for_background_save(store: &Store) -> store::SnapshotStatus {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let status = store.snapshot_status();
                if !status.phase.in_progress() && status.last_status != "none" {
                    break status;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("background save did not finish")
    }

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn persistent_embedded_config(root: &std::path::Path) -> ServerConfig {
        ServerConfig {
            enable_resp: false,
            data_dir: root.to_string_lossy().into_owned(),
            durability: DurabilityConfig {
                policy: DurabilityPolicy::EverySecond,
                sync_interval: Duration::from_secs(1),
            },
            ..Default::default()
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn graceful_shutdown_syncs_acknowledged_every_second_write() {
        let root = tempfile::tempdir().unwrap();
        let config = persistent_embedded_config(root.path());
        let handle = run_with_config(config.clone()).await.unwrap();
        handle
            .client()
            .execute_value("SET", &["shutdown:key", "value"])
            .await
            .unwrap();

        assert_eq!(
            handle
                .shutdown_and_wait_detailed(Duration::from_secs(2))
                .await
                .unwrap(),
            ShutdownOutcome::Clean
        );

        let restarted = run_with_config(config).await.unwrap();
        assert_eq!(
            restarted
                .client()
                .execute_value("GET", &["shutdown:key"])
                .await
                .unwrap(),
            EmbeddedValue::Bulk(bytes::Bytes::from_static(b"value"))
        );
        restarted.shutdown_and_wait().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_rejects_new_embedded_work() {
        let root = tempfile::tempdir().unwrap();
        let handle = run_with_config(ServerConfig {
            enable_resp: false,
            data_dir: root.path().to_string_lossy().into_owned(),
            ..Default::default()
        })
        .await
        .unwrap();
        let client = handle.client();

        handle.shutdown_with_timeout(Duration::from_secs(2));
        let error = client.execute("PING", &[]).await.unwrap_err();
        assert!(error.to_string().contains("shutting down"), "{error}");
        handle.wait().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drain_timeout_reports_forced_shutdown() {
        use tokio::io::AsyncWriteExt as _;

        let root = tempfile::tempdir().unwrap();
        let handle = run_with_config(ServerConfig {
            port: 0,
            http_port: 0,
            data_dir: root.path().to_string_lossy().into_owned(),
            ..Default::default()
        })
        .await
        .unwrap();
        let mut connection = tokio::net::TcpStream::connect(handle.local_addr().unwrap())
            .await
            .unwrap();
        connection
            .write_all(b"*3\r\n$5\r\nBLPOP\r\n$5\r\nnever\r\n$2\r\n10\r\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(25)).await;

        assert_eq!(
            handle
                .shutdown_and_wait_detailed(Duration::from_millis(50))
                .await
                .unwrap(),
            ShutdownOutcome::Forced
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn idle_http_connection_does_not_block_clean_shutdown() {
        let root = tempfile::tempdir().unwrap();
        let http_port = free_port();
        let handle = run_with_config(ServerConfig {
            enable_resp: false,
            http_port,
            data_dir: root.path().to_string_lossy().into_owned(),
            ..Default::default()
        })
        .await
        .unwrap();
        let _connection = tokio::net::TcpStream::connect(("127.0.0.1", http_port))
            .await
            .unwrap();

        assert_eq!(
            handle
                .shutdown_and_wait_detailed(Duration::from_secs(1))
                .await
                .unwrap(),
            ShutdownOutcome::Clean
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn final_sync_failure_is_not_reported_as_clean() {
        let root = tempfile::tempdir().unwrap();
        let handle = run_with_config(persistent_embedded_config(root.path()))
            .await
            .unwrap();
        handle.runtime().store.inject_journal_fsync_failures(1);

        let error = handle
            .shutdown_and_wait_detailed(Duration::from_secs(2))
            .await
            .unwrap_err();
        assert!(
            matches!(error, ShutdownError::Persistence(_)),
            "unexpected shutdown error: {error}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn bgsave_is_single_flight_and_retains_post_capture_mutations() {
        let root = tempfile::tempdir().unwrap();
        let mut config = persistent_embedded_config(root.path());
        config.save_interval = Duration::ZERO;
        let handle = run_with_config(config.clone()).await.unwrap();
        let client = handle.client();
        client
            .execute_value("SET", &["counter", "10"])
            .await
            .unwrap();

        let captured = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        handle.runtime().store.set_snapshot_after_capture_hook({
            let captured = captured.clone();
            let release = release.clone();
            Arc::new(move || {
                captured.wait();
                release.wait();
            })
        });

        assert_eq!(
            client.execute_value("BGSAVE", &[]).await.unwrap(),
            EmbeddedValue::Simple("Background saving started".to_string())
        );
        tokio::time::timeout(
            Duration::from_secs(2),
            tokio::task::spawn_blocking(move || captured.wait()),
        )
        .await
        .expect("snapshot did not reach the post-capture boundary")
        .unwrap();

        for expected in 11..=110 {
            assert_eq!(
                client.execute_value("INCR", &["counter"]).await.unwrap(),
                EmbeddedValue::Int(expected)
            );
        }
        assert_eq!(
            client.execute_value("PING", &[]).await.unwrap(),
            EmbeddedValue::Simple("PONG".to_string())
        );
        let busy = client.execute_value("BGSAVE", &[]).await.unwrap_err();
        assert!(busy.to_string().contains("already in progress"), "{busy}");

        let info = client
            .execute_value("INFO", &["persistence"])
            .await
            .unwrap();
        let EmbeddedValue::Bulk(info) = info else {
            panic!("expected INFO bulk response");
        };
        let info = String::from_utf8_lossy(&info);
        assert!(info.contains("rdb_bgsave_in_progress:1\r\n"), "{info}");
        assert!(
            info.contains("lux_current_bgsave_phase:capturing\r\n"),
            "{info}"
        );

        tokio::task::spawn_blocking(move || release.wait())
            .await
            .unwrap();
        let status = wait_for_background_save(&handle.runtime().store).await;
        assert_eq!(status.last_status, "ok");
        assert_eq!(status.last_keys, 1);
        assert!(snapshot::last_save_unix_seconds(&handle.runtime().store)
            .unwrap()
            .is_some());

        handle.shutdown_and_wait().await.unwrap();
        let restarted = run_with_config(config).await.unwrap();
        let client = restarted.client();
        assert_eq!(
            client.execute_value("GET", &["counter"]).await.unwrap(),
            EmbeddedValue::Bulk(bytes::Bytes::from_static(b"110"))
        );
        restarted.shutdown_and_wait().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bgsave_failure_is_observable_and_does_not_advance_lastsave() {
        let root = tempfile::tempdir().unwrap();
        let mut config = persistent_embedded_config(root.path());
        config.save_interval = Duration::ZERO;
        let handle = run_with_config(config).await.unwrap();
        handle
            .client()
            .execute_value("SET", &["preserved", "snapshot"])
            .await
            .unwrap();
        handle.client().execute_value("SAVE", &[]).await.unwrap();
        let installed_before = std::fs::read(root.path().join("lux.dat")).unwrap();
        let lastsave_before = handle
            .client()
            .execute_value("LASTSAVE", &[])
            .await
            .unwrap();
        handle.runtime().store.inject_snapshot_failures(1);

        handle.client().execute_value("BGSAVE", &[]).await.unwrap();
        let status = wait_for_background_save(&handle.runtime().store).await;
        assert_eq!(status.last_status, "err");
        assert!(status.last_error.is_some());
        assert_eq!(
            std::fs::read(root.path().join("lux.dat")).unwrap(),
            installed_before,
            "a failed BGSAVE replaced the installed snapshot"
        );

        let info = handle
            .client()
            .execute_value("INFO", &["persistence"])
            .await
            .unwrap();
        let EmbeddedValue::Bulk(info) = info else {
            panic!("expected INFO bulk response");
        };
        let info = String::from_utf8_lossy(&info);
        assert!(info.contains("rdb_last_bgsave_status:err\r\n"), "{info}");
        assert!(info.contains("lux_last_bgsave_error:"), "{info}");
        assert!(!info.contains("lux_last_bgsave_error:\r\n"), "{info}");
        assert_eq!(
            handle
                .client()
                .execute_value("LASTSAVE", &[])
                .await
                .unwrap(),
            lastsave_before
        );
        handle.shutdown_and_wait().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn shutdown_waits_for_an_active_snapshot_before_final_sync() {
        let root = tempfile::tempdir().unwrap();
        let mut config = persistent_embedded_config(root.path());
        config.save_interval = Duration::ZERO;
        let handle = run_with_config(config.clone()).await.unwrap();
        handle
            .client()
            .execute_value("SET", &["before_shutdown", "durable"])
            .await
            .unwrap();

        let captured = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        handle.runtime().store.set_snapshot_after_capture_hook({
            let captured = captured.clone();
            let release = release.clone();
            Arc::new(move || {
                captured.wait();
                release.wait();
            })
        });
        handle.client().execute_value("BGSAVE", &[]).await.unwrap();
        tokio::time::timeout(
            Duration::from_secs(2),
            tokio::task::spawn_blocking(move || captured.wait()),
        )
        .await
        .expect("snapshot did not reach the post-capture boundary")
        .unwrap();

        let shutdown = tokio::spawn(async move {
            handle
                .shutdown_and_wait_detailed(Duration::from_secs(2))
                .await
        });
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert!(
            !shutdown.is_finished(),
            "shutdown returned while the snapshot thread was still active"
        );
        tokio::task::spawn_blocking(move || release.wait())
            .await
            .unwrap();
        assert_eq!(shutdown.await.unwrap().unwrap(), ShutdownOutcome::Clean);

        let restarted = run_with_config(config).await.unwrap();
        assert_eq!(
            restarted
                .client()
                .execute_value("GET", &["before_shutdown"])
                .await
                .unwrap(),
            EmbeddedValue::Bulk(bytes::Bytes::from_static(b"durable"))
        );
        restarted.shutdown_and_wait().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn scheduled_snapshots_use_the_background_worker() {
        let root = tempfile::tempdir().unwrap();
        let mut config = persistent_embedded_config(root.path());
        config.save_interval = Duration::from_millis(25);
        let handle = run_with_config(config.clone()).await.unwrap();
        handle
            .client()
            .execute_value("SET", &["scheduled", "durable"])
            .await
            .unwrap();

        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let status = handle.runtime().store.snapshot_status();
                if status.last_status == "ok" && status.last_keys == 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("scheduled snapshot did not complete");
        handle.shutdown_and_wait().await.unwrap();

        let restarted = run_with_config(config).await.unwrap();
        assert_eq!(
            restarted
                .client()
                .execute_value("GET", &["scheduled"])
                .await
                .unwrap(),
            EmbeddedValue::Bulk(bytes::Bytes::from_static(b"durable"))
        );
        restarted.shutdown_and_wait().await.unwrap();
    }

    #[test]
    fn persistent_auth_requires_a_recoverable_encryption_configuration() {
        let root = tempfile::tempdir().unwrap();
        let mut config = persistent_embedded_config(root.path());
        config.auth.enabled = true;

        let error = validate_encryption_config(&config).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("persistent Auth requires"), "{message}");
        assert!(message.contains("LUX_ENC_AUTO_INIT"), "{message}");
        assert!(message.contains("ENC REWRAP"), "{message}");

        config.encryption.auto_init = true;
        assert!(validate_encryption_config(&config).is_ok());

        config.encryption.state_path = Some(String::new());
        let error = validate_encryption_config(&config).unwrap_err();
        assert!(error.to_string().contains("ephemeral keyring"), "{error}");
    }

    #[test]
    fn seal_rotation_failure_names_the_previous_seal_recovery_path() {
        let root = tempfile::tempdir().unwrap();
        let old_seal = [7u8; 32];
        let initial = EncryptionConfig {
            auto_init: true,
            seal_secret: Some(old_seal),
            ..Default::default()
        };
        crate::encryption::EncryptionKeyring::open(&initial, root.path().to_str().unwrap())
            .unwrap();

        let mut config = persistent_embedded_config(root.path());
        config.auth.enabled = true;
        config.encryption.seal_secret = Some([8u8; 32]);
        let error = validate_encryption_config(&config).unwrap_err();
        assert!(
            error.to_string().contains("LUX_ENC_SEAL_KEY_PREVIOUS"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn ephemeral_auth_warns_and_refuses_plaintext_snapshots() {
        let root = tempfile::tempdir().unwrap();
        let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured = events.clone();
        let config = ServerConfig {
            data_dir: root.path().to_string_lossy().into_owned(),
            enable_resp: false,
            durability: DurabilityConfig {
                policy: DurabilityPolicy::Ephemeral,
                ..DurabilityConfig::default()
            },
            auth: AuthConfig {
                enabled: true,
                ..AuthConfig::default()
            },
            on_warn: Some(std::sync::Arc::new(move |event| {
                captured.lock().unwrap().push(event);
            })),
            ..ServerConfig::default()
        };

        let handle = run_with_config(config).await.unwrap();
        assert_eq!(
            auth::secret_storage_health(&handle.runtime.store).status,
            auth::AuthSecretStorageStatus::Degraded
        );
        assert!(events
            .lock()
            .unwrap()
            .iter()
            .any(|event| matches!(event, ServerWarnEvent::AuthSecretStorageDegraded)));
        let error = snapshot::save_and_truncate_wal_consistent(&handle.runtime.store).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("restart"));

        handle
            .runtime
            .store
            .encryption()
            .init(Some("late-auth-key"))
            .unwrap();
        assert!(handle.runtime.store.encryption().has_active_key());
        assert_eq!(
            auth::secret_storage_health(&handle.runtime.store).status,
            auth::AuthSecretStorageStatus::Degraded,
            "initializing encryption cannot retroactively migrate Auth rows"
        );
        let error = snapshot::save_and_truncate_wal_consistent(&handle.runtime.store).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("restart"));
        handle.shutdown_and_wait().await.unwrap();
    }

    #[tokio::test]
    async fn persistent_auth_missing_key_fails_before_readiness() {
        let root = tempfile::tempdir().unwrap();
        let mut config = persistent_embedded_config(root.path());
        config.enable_resp = false;
        config.auth.enabled = true;
        let error = match run_with_config(config).await {
            Ok(handle) => {
                handle.shutdown_and_wait().await.unwrap();
                panic!("persistent Auth unexpectedly reached readiness")
            }
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(
            error.to_string().contains("Auth secret storage is locked"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn missing_prior_data_key_fails_restart_with_rotation_guidance() {
        fn configure_key(config: &mut ServerConfig, id: &str, secret: &[u8]) {
            config.encryption = EncryptionConfig {
                active_key_id: Some(id.to_string()),
                keys: vec![EncryptionKeyConfig {
                    id: id.to_string(),
                    secret: secret.to_vec(),
                    decrypt_only: false,
                }],
                ..Default::default()
            };
        }

        let root = tempfile::tempdir().unwrap();
        let mut first = persistent_embedded_config(root.path());
        first.enable_resp = false;
        first.save_interval = Duration::ZERO;
        first.auth.enabled = true;
        configure_key(&mut first, "original", b"original-auth-data-key");
        let handle = run_with_config(first).await.unwrap();
        handle.shutdown_and_wait().await.unwrap();

        let mut rotated = persistent_embedded_config(root.path());
        rotated.enable_resp = false;
        rotated.save_interval = Duration::ZERO;
        rotated.auth.enabled = true;
        configure_key(&mut rotated, "replacement", b"replacement-auth-data-key");
        let error = match run_with_config(rotated).await {
            Ok(handle) => {
                handle.shutdown_and_wait().await.unwrap();
                panic!("restart unexpectedly discarded the prior data-key requirement")
            }
            Err(error) => error,
        };
        let message = error.to_string();
        assert!(
            message.contains("auth secret storage is locked"),
            "{message}"
        );
        assert!(message.contains("retain prior data keys"), "{message}");
        assert!(message.contains("ENC REWRAP"), "{message}");
    }
}

#[cfg(test)]
mod listener_security_tests {
    use super::*;

    /// A public-interface config with no credentials at all.
    fn public_config() -> ServerConfig {
        ServerConfig {
            bind_host: "0.0.0.0".to_string(),
            enable_resp: true,
            http_port: 8080,
            password: String::new(),
            require_auth: false,
            ..Default::default()
        }
    }

    #[test]
    fn refuses_public_listener_with_no_credentials() {
        assert!(validate_listener_security(&public_config()).is_err());
    }

    #[test]
    fn allows_public_listener_with_a_password() {
        let mut config = public_config();
        config.password = "s3cret".to_string();
        config.require_auth = true;
        assert!(validate_listener_security(&config).is_ok());
    }

    /// The key-only shape the credential model moves towards: a secret key and
    /// no password. Judging this by the password alone would refuse to boot a
    /// perfectly authenticated engine.
    #[test]
    fn allows_public_listener_with_only_a_secret_key() {
        let mut config = public_config();
        config.auth.initial_secret_key = Some("lux_sec_listener".to_string());
        assert!(
            validate_listener_security(&config).is_ok(),
            "a secret key is a credential; key-only engines must be able to bind"
        );
    }

    /// Publishable keys cannot use RESP, so a publishable-only engine really is
    /// unauthenticated there and must still be refused.
    #[test]
    fn refuses_public_resp_listener_with_only_a_publishable_key() {
        let mut config = public_config();
        config.auth.initial_publishable_key = Some("lux_pub_listener".to_string());
        assert!(validate_listener_security(&config).is_err());

        // HTTP alone is fine: publishable is a real credential there.
        config.enable_resp = false;
        assert!(validate_listener_security(&config).is_ok());
    }

    #[test]
    fn loopback_and_explicit_opt_out_still_bypass_the_check() {
        let mut config = public_config();
        config.bind_host = "127.0.0.1".to_string();
        assert!(validate_listener_security(&config).is_ok());

        let mut config = public_config();
        config.allow_insecure_no_auth = true;
        assert!(validate_listener_security(&config).is_ok());
    }
}
