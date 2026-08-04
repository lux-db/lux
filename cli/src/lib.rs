use clap::{Args, Parser, Subcommand, ValueEnum};
use colored::Colorize;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpStream};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

mod local_cluster;
use local_cluster::*;

const DEFAULT_API_URL: &str = "https://api.luxdb.dev";

#[derive(Parser)]
#[command(name = "lux", version, about = "CLI for Lux")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(long, global = true, env = "LUX_API_URL")]
    api_url: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    Init,
    /// Start a local Lux engine in Docker (Supabase-style local dev).
    Start {
        #[arg(long, help = "Recreate from a fresh data volume (drops local data)")]
        fresh: bool,
        #[arg(long, help = "Start only the engine; don't launch Lux Studio")]
        no_studio: bool,
        #[arg(
            long,
            value_name = "PORT",
            help = "Host port for the RESP API (default 6379, auto-bumps if taken)"
        )]
        resp_port: Option<u16>,
        #[arg(
            long,
            value_name = "PORT",
            help = "Host port for the HTTP API (default 5890, auto-bumps if taken)"
        )]
        http_port: Option<u16>,
        #[arg(
            long,
            value_name = "IP",
            help = "Host address for local engine and Studio ports (default 127.0.0.1)"
        )]
        bind: Option<IpAddr>,
        #[arg(
            long,
            value_name = "COUNT",
            value_parser = clap::value_parser!(u16).range(1..=16),
            help = "Run a local Cluster cluster with this many nodes (1-16)"
        )]
        nodes: Option<u16>,
    },
    /// Stop the local Lux engine.
    Stop {
        #[arg(long, help = "Also delete the local data volume (fresh DB next start)")]
        clear: bool,
    },
    /// Inspect or resize the local Cluster cluster.
    Cluster {
        #[command(subcommand)]
        action: ClusterAction,
    },
    /// Open Lux Studio (local web UI) against the running local engine.
    Studio {
        #[arg(long, help = "Don't open a browser window")]
        no_open: bool,
    },
    /// Log in to Lux Cloud with an access token. Pass the token (or set
    /// LUX_TOKEN) for non-interactive use in CI; omit to paste it interactively.
    Login {
        #[arg(help = "Access token; omit to paste interactively. Also reads LUX_TOKEN.")]
        token: Option<String>,
    },
    Logout,
    Link {
        #[arg(help = "Project name or ID")]
        project: String,
    },
    /// Remove this repository's cloud-project association.
    Unlink,
    /// Show the local runtime, linked cloud project, and active app env profile.
    Target,
    Projects,
    Status {
        #[arg(help = "Project name or ID (omit for the local engine)")]
        project: Option<String>,
        #[arg(long, help = "Show local and linked-cloud status together")]
        all: bool,
        #[arg(short = 'o', long, help = "Output format (json)")]
        output: Option<String>,
    },
    Exec {
        #[arg(help = "Project name, ID, or connection URL")]
        project: String,
        #[arg(short = 'H', long, help = "Host for direct connection")]
        host: Option<String>,
        #[arg(short, long, help = "Port for direct connection")]
        port: Option<u16>,
        #[arg(short = 'a', long, help = "Password for direct connection")]
        password: Option<String>,
        #[arg(
            trailing_var_arg = true,
            help = "Command to execute (quote wildcards: KEYS '*')"
        )]
        cmd: Vec<String>,
    },
    Logs {
        #[arg(help = "Project name or ID")]
        project: Option<String>,
        #[arg(short, long, default_value = "100")]
        lines: usize,
    },
    Create {
        #[arg(help = "Project name")]
        name: String,
        #[arg(
            short,
            long,
            default_value = "512",
            help = "Memory in MB (128, 512, 2048)"
        )]
        memory: u32,
        #[arg(long, help = "Acknowledge billing charges")]
        accept_charges: bool,
    },
    Restart {
        #[arg(help = "Project name or ID")]
        project: Option<String>,
    },
    Snapshot {
        #[arg(help = "Project name or ID")]
        project: Option<String>,
        #[arg(short, long, help = "List existing snapshots instead of creating one")]
        list: bool,
        #[arg(long, value_name = "SNAPSHOT_ID", help = "Restore a snapshot by ID")]
        restore: Option<String>,
    },
    Destroy {
        #[arg(help = "Project name or ID")]
        project: String,
        #[arg(long, help = "Acknowledge data will be permanently deleted")]
        accept_consequences: bool,
    },
    Connect {
        #[arg(help = "Project name, ID, or connection URL (lux://...)")]
        project: Option<String>,
        #[arg(short = 'H', long, help = "Host (for direct connection)")]
        host: Option<String>,
        #[arg(short, long, help = "Port (for direct connection)")]
        port: Option<u16>,
        #[arg(short = 'a', long, help = "Password (for direct connection)")]
        password: Option<String>,
    },
    /// Inspect installed component versions and available updates.
    Version {
        #[arg(help = "Cloud project name or ID (omit for local components)")]
        project: Option<String>,
        #[arg(long, help = "Show CLI, local engine, Studio, and linked cloud")]
        all: bool,
        #[arg(short = 'o', long, help = "Output format (json)")]
        output: Option<String>,
    },
    /// Update Lux components explicitly. Bare `lux update` updates the CLI.
    #[command(args_conflicts_with_subcommands = true)]
    Update {
        #[command(subcommand)]
        action: Option<UpdateAction>,
        #[arg(long, help = "Check for updates without installing")]
        check: bool,
    },
    Keys {
        #[command(subcommand)]
        action: KeysAction,
    },
    Env {
        #[command(subcommand)]
        action: EnvAction,
    },
    /// Create, apply, and inspect migrations. Bare `lux migrate [project]`
    /// applies pending migrations (same as `lux migrate run`).
    #[command(args_conflicts_with_subcommands = true)]
    Migrate {
        #[command(subcommand)]
        action: Option<MigrateAction>,
        #[command(flatten)]
        run: MigrateConn,
    },
    /// Diagnose local and cloud project setup without changing runtime state.
    Doctor {
        #[arg(help = "Project name or ID (omit for the local engine)")]
        project: Option<String>,
        #[arg(long, help = "Check local and the linked cloud project")]
        all: bool,
        #[arg(long, help = "Repair safe local filesystem configuration only")]
        fix: bool,
        #[arg(short = 'o', long, help = "Output format (json)")]
        output: Option<String>,
    },
    /// Configure APNs and Web Push for a local or cloud project.
    Push {
        #[command(subcommand)]
        action: PushAction,
    },
    Seed {
        #[command(subcommand)]
        action: SeedAction,
    },
    /// Manage the encryption keyring (ENC status/list/rotate/...).
    Enc {
        #[arg(
            long,
            help = "Project name, ID, or connection URL (omit for the local engine)"
        )]
        project: Option<String>,
        #[command(subcommand)]
        action: EncAction,
    },
    /// Configure auth (OAuth sign-in providers).
    Auth {
        #[command(subcommand)]
        action: AuthAction,
    },
    /// Generate TypeScript types from your project schema.
    Types {
        #[arg(help = "Project name or ID (omit for the local engine)")]
        project: Option<String>,
        #[arg(short = 'H', long, help = "Host (for direct connection)")]
        host: Option<String>,
        #[arg(short, long, help = "Port (for direct connection)")]
        port: Option<u16>,
        #[arg(short = 'a', long, help = "Password (for direct connection)")]
        password: Option<String>,
        #[arg(short, long, help = "Output file (default: lux/types/database.ts)")]
        out: Option<String>,
        #[arg(long, help = "Print to stdout instead of writing a file")]
        stdout: bool,
    },
}

#[derive(Subcommand)]
enum ClusterAction {
    /// Show local node health, slot ownership, and any active transition.
    Status {
        #[arg(short = 'o', long, help = "Output format (json)")]
        output: Option<String>,
    },
    /// Safely redistribute the local project across COUNT nodes.
    Resize {
        #[arg(value_name = "COUNT", value_parser = clap::value_parser!(u16).range(1..=16))]
        nodes: u16,
    },
    /// Move all data back to the system node and restore the single-node fast path.
    Consolidate,
}

#[derive(Subcommand)]
enum AuthAction {
    /// Configure an OAuth sign-in provider on the engine.
    Provider {
        #[command(subcommand)]
        action: AuthProviderAction,
    },
}

/// How to reach the target engine's admin API. Defaults to the local
/// `lux start` engine; pass --url/--password for any other self-hosted engine.
#[derive(clap::Args)]
struct EngineConn {
    #[arg(
        long,
        env = "LUX_ENGINE_URL",
        value_name = "URL",
        help = "Engine HTTP base URL (default: local engine)"
    )]
    url: Option<String>,
    #[arg(
        short = 'a',
        long,
        env = "LUX_ENGINE_PASSWORD",
        help = "Operator password / secret key (default: local engine's)"
    )]
    password: Option<String>,
}

#[derive(Subcommand)]
enum AuthProviderAction {
    /// Sign in with Apple. Upload your .p8 once; Lux mints + rotates the client
    /// secret from it, so there is no expiring secret to manage.
    Apple {
        #[arg(long, help = "Apple Team ID (web sign-in)")]
        team_id: Option<String>,
        #[arg(long, help = "Key ID of your .p8 (web sign-in)")]
        key_id: Option<String>,
        #[arg(long, help = "Services ID = web OAuth client ID (web sign-in)")]
        services_id: Option<String>,
        #[arg(
            long,
            value_name = "BUNDLE_ID",
            help = "App Bundle ID for native sign-in (repeatable)"
        )]
        bundle_id: Vec<String>,
        #[arg(
            long,
            value_name = "PATH",
            help = "Path to your AuthKey_*.p8 (web sign-in)"
        )]
        p8: Option<PathBuf>,
        #[arg(long, help = "OAuth scopes (default: name email)")]
        scopes: Option<String>,
        #[arg(long, help = "Save the config but leave the provider disabled")]
        disable: bool,
        #[command(flatten)]
        conn: EngineConn,
    },
    /// Google OAuth sign-in.
    Google {
        #[arg(long)]
        client_id: String,
        #[arg(
            long,
            help = "Required for initial setup; omit later to keep the stored secret"
        )]
        client_secret: Option<String>,
        #[arg(long, help = "Override the callback URL (default: engine callback)")]
        redirect_uri: Option<String>,
        #[arg(long)]
        scopes: Option<String>,
        #[arg(long, help = "Save the config but leave the provider disabled")]
        disable: bool,
        #[command(flatten)]
        conn: EngineConn,
    },
    /// GitHub OAuth sign-in.
    Github {
        #[arg(long)]
        client_id: String,
        #[arg(
            long,
            help = "Required for initial setup; omit later to keep the stored secret"
        )]
        client_secret: Option<String>,
        #[arg(long, help = "Override the callback URL (default: engine callback)")]
        redirect_uri: Option<String>,
        #[arg(long)]
        scopes: Option<String>,
        #[arg(long, help = "Save the config but leave the provider disabled")]
        disable: bool,
        #[command(flatten)]
        conn: EngineConn,
    },
    /// List configured providers (secrets are never returned).
    List {
        #[command(flatten)]
        conn: EngineConn,
    },
}

#[derive(Subcommand)]
enum MigrateAction {
    /// Create a new empty migration file.
    New {
        #[arg(help = "Migration name (e.g. create_users)")]
        name: String,
        #[arg(long, default_value = "lux/migrations", help = "Migration directory")]
        dir: PathBuf,
    },
    /// Show which local migrations are applied vs pending on the target.
    Status {
        #[command(flatten)]
        conn: MigrateConn,
        #[arg(
            long,
            help = "Exit 1 if any local migration is not yet applied (for CI gates)."
        )]
        check: bool,
    },
    /// Preview each local migration without applying it.
    Plan(MigrateConn),
    /// Apply pending migrations (the default action for bare `lux migrate`).
    Run(MigrateConn),
    /// Fetch migrations recorded on the target into the local migration
    /// directory (e.g. ones authored in the Lux Cloud dashboard).
    Pull(MigrateConn),
    /// Resolve an interrupted or failed migration after reviewing its progress.
    Repair {
        #[arg(help = "Exact migration filename")]
        filename: String,
        #[command(subcommand)]
        action: MigrateRepairAction,
    },
}

#[derive(Subcommand)]
enum MigrateRepairAction {
    /// Resume at an explicitly reviewed zero-based command index.
    Resume {
        #[arg(help = "Zero-based command index to execute next")]
        from_command: usize,
        #[command(flatten)]
        conn: MigrateConn,
    },
    /// Record every command as applied without executing anything.
    MarkApplied {
        #[command(flatten)]
        conn: MigrateConn,
    },
    /// Abandon the record so later migrations may proceed.
    Abandon {
        #[command(flatten)]
        conn: MigrateConn,
    },
}

#[derive(Subcommand)]
enum UpdateAction {
    /// Update the Lux CLI binary.
    Cli {
        #[arg(long, help = "Check without installing")]
        check: bool,
    },
    /// Update a local engine or cloud project.
    Engine {
        #[arg(help = "Cloud project name or ID (omit for the local engine)")]
        project: Option<String>,
        #[arg(long, help = "Check without installing")]
        check: bool,
    },
    /// Update the local Lux Studio image.
    Studio {
        #[arg(long, help = "Check without installing")]
        check: bool,
    },
}

#[derive(Subcommand)]
enum PushAction {
    /// Show secret-free provider configuration and health.
    Status {
        #[command(flatten)]
        conn: PushConn,
        #[arg(long, help = "Exit 1 when configured credentials are unhealthy")]
        check: bool,
        #[arg(short = 'o', long, help = "Output format (json)")]
        output: Option<String>,
    },
    /// Configure Apple Push Notification service.
    Apns {
        #[command(subcommand)]
        action: PushApnsAction,
    },
    /// Configure browser Web Push (VAPID).
    Vapid {
        #[command(subcommand)]
        action: PushVapidAction,
    },
}

#[derive(Subcommand)]
enum PushApnsAction {
    /// Set APNs metadata and optionally load a .p8 private key from disk.
    Set {
        #[command(flatten)]
        conn: PushConn,
        #[arg(long)]
        team_id: String,
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        topic: String,
        #[arg(long, value_enum, default_value = "sandbox")]
        environment: PushEnvironment,
        #[arg(long, value_name = "PATH", help = "APNs PKCS8 .p8 file")]
        p8_file: Option<PathBuf>,
    },
    /// Remove APNs credentials for an app.
    Clear {
        #[command(flatten)]
        conn: PushConn,
        #[arg(long, help = "Acknowledge APNs delivery will stop")]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum PushVapidAction {
    /// Enable Web Push idempotently, preserving an existing keypair.
    Enable {
        #[command(flatten)]
        conn: PushConn,
        #[arg(long, default_value = "mailto:push@luxdb.dev")]
        subject: String,
    },
    /// Rotate the keypair; existing browser subscriptions must resubscribe.
    Rotate {
        #[command(flatten)]
        conn: PushConn,
        #[arg(long, default_value = "mailto:push@luxdb.dev")]
        subject: String,
        #[arg(long, help = "Acknowledge existing subscriptions will be invalidated")]
        yes: bool,
    },
    /// Disable Web Push for an app.
    Disable {
        #[command(flatten)]
        conn: PushConn,
        #[arg(long, help = "Acknowledge Web Push delivery will stop")]
        yes: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum PushEnvironment {
    Sandbox,
    Production,
}

impl PushEnvironment {
    fn as_str(self) -> &'static str {
        match self {
            Self::Sandbox => "sandbox",
            Self::Production => "production",
        }
    }
}

#[derive(Args)]
struct PushConn {
    #[arg(help = "Cloud project name or ID (omit for the local engine)")]
    project: Option<String>,
    #[arg(long, default_value = "default")]
    app_id: String,
}

/// Shared target + directory args for `status`/`run`/`pull`. Kept flat so a
/// bare `lux migrate [project] [flags]` works as an implicit `run`.
#[derive(Args)]
struct MigrateConn {
    #[arg(help = "Project name, ID, or connection URL")]
    project: Option<String>,
    #[arg(long, default_value = "lux/migrations", help = "Migration directory")]
    dir: PathBuf,
    #[arg(short = 'H', long, help = "Host for direct connection")]
    host: Option<String>,
    #[arg(short, long, help = "Port for direct connection")]
    port: Option<u16>,
    #[arg(short = 'a', long, help = "Password for direct connection")]
    password: Option<String>,
}

#[derive(Subcommand)]
enum KeysAction {
    List {
        #[arg(help = "Project name or ID")]
        project: Option<String>,
    },
    Create {
        #[arg(long, help = "Project name or ID")]
        project: Option<String>,
        #[arg(long, help = "publishable or secret")]
        kind: String,
        #[arg(long, help = "Human-readable key name")]
        name: Option<String>,
    },
    Revoke {
        #[arg(help = "Key ID")]
        id: String,
        #[arg(long, help = "Project name or ID")]
        project: Option<String>,
    },
}

#[derive(Subcommand)]
enum EnvAction {
    /// Download a cloud project's Lux variables into a named, private profile.
    Pull {
        #[arg(help = "Project name or ID")]
        project: Option<String>,
        #[arg(long, help = "Activate the downloaded profile in .env.local")]
        use_env: bool,
    },
    /// List saved local/cloud profiles.
    Profiles,
    /// Show the profile currently merged into .env.local.
    Current,
    /// Merge a saved profile's Lux-managed keys into .env.local.
    Use {
        #[arg(help = "`local`, a cloud project name/ID, or a profile key")]
        profile: String,
    },
    /// Print a saved profile. This intentionally includes its secrets.
    Export {
        #[arg(help = "`local`, a cloud project name/ID, or a profile key")]
        profile: Option<String>,
    },
}

#[derive(Subcommand)]
enum SeedAction {
    Run {
        #[arg(help = "Project name, ID, or connection URL")]
        project: Option<String>,
        #[arg(long, default_value = "lux/seed.lux", help = "Seed file")]
        file: PathBuf,
        #[arg(short = 'H', long, help = "Host for direct connection")]
        host: Option<String>,
        #[arg(short, long, help = "Port for direct connection")]
        port: Option<u16>,
        #[arg(short = 'a', long, help = "Password for direct connection")]
        password: Option<String>,
    },
}

#[derive(Subcommand)]
enum EncAction {
    /// Show encryption status (initialized, active key, key count).
    Status,
    /// List encryption keys and their state.
    List,
    /// Initialize the keyring (no-op if `lux start` already auto-initialized it).
    Init {
        #[arg(long, help = "Explicit key id (default: generated)")]
        key_id: Option<String>,
    },
    /// Add a new active key; existing keys become decrypt-only.
    Rotate {
        #[arg(long, help = "Explicit key id (default: generated)")]
        key_id: Option<String>,
    },
    /// Re-encrypt all values under the current keyring.
    Rewrap,
    /// Remove a retired (decrypt-only) key once no data needs it.
    Retire {
        #[arg(help = "Key id to retire")]
        key_id: String,
    },
}

/// Map an `EncAction` to the engine command argv it proxies.
fn enc_command_args(action: &EncAction) -> Vec<String> {
    let mut args = vec!["ENC".to_string()];
    match action {
        EncAction::Status => args.push("STATUS".into()),
        EncAction::List => args.push("LIST".into()),
        EncAction::Init { key_id } => {
            args.push("INIT".into());
            if let Some(id) = key_id {
                args.push("KEYID".into());
                args.push(id.clone());
            }
        }
        EncAction::Rotate { key_id } => {
            args.push("ROTATE".into());
            if let Some(id) = key_id {
                args.push("KEYID".into());
                args.push(id.clone());
            }
        }
        EncAction::Rewrap => args.push("REWRAP".into()),
        EncAction::Retire { key_id } => {
            args.push("RETIRE".into());
            args.push(key_id.clone());
        }
    }
    args
}

/// `KEY=VALUE` engine env for the local `lux start` container: auth keys, ports,
/// tiered storage, and `LUX_ENC_AUTO_INIT=1` so encrypted columns work without a
/// manual `ENC INIT`.
fn local_engine_env(state: &LocalState) -> Vec<String> {
    vec![
        "LUX_AUTH_ENABLED=1".to_string(),
        format!("LUX_PASSWORD={}", state.password),
        format!("LUX_AUTH_PUBLISHABLE_KEY={}", state.publishable_key),
        format!("LUX_AUTH_SECRET_KEY={}", state.secret_key),
        "LUX_PORT=6379".to_string(),
        "LUX_HTTP_PORT=5890".to_string(),
        "LUX_BIND_HOST=0.0.0.0".to_string(),
        "LUX_DATA_DIR=/data".to_string(),
        // Tiered (WAL) storage so local-dev data survives a crash/restart;
        // memory mode only persists on periodic snapshots.
        "LUX_STORAGE_MODE=tiered".to_string(),
        "LUX_STORAGE_DIR=/data/storage".to_string(),
        format!(
            "LUX_AUTH_ISSUER=http://localhost:{}/auth/v1",
            state.http_port
        ),
        // Engine self-mints its keyring + seal into /data on first boot; the CLI
        // never handles encryption key material (unlike the auth keys above).
        "LUX_ENC_AUTO_INIT=1".to_string(),
    ]
}

#[derive(Serialize, Deserialize)]
struct Config {
    token: String,
    api_url: String,
}

#[derive(Serialize, Deserialize, Default)]
struct LocalConfig {
    project_id: Option<String>,
    project_name: Option<String>,
    /// Optional host port overrides for `lux start` (engine listens on 6379/5890
    /// inside the container; these map to the host).
    local_http_port: Option<u16>,
    local_resp_port: Option<u16>,
    /// Pin the local engine to a specific version (e.g. "0.23.0") instead of
    /// tracking `:latest`. Maps to the `ghcr.io/lux-db/lux:<version>` image.
    engine_version: Option<String>,
    /// Desired local runtime size. One preserves the ordinary standalone fast
    /// path; values above one enable Cluster and are reconciled by `lux start`.
    local_nodes: Option<u16>,
}

const ENV_PROFILE_DIR: &str = "lux/.env-profiles";
const ENV_PROFILE_INDEX: &str = "lux/.env-profiles/index.json";
const MANAGED_ENV_KEYS: &[&str] = &[
    "LUX_PROJECT_ID",
    "LUX_URL",
    "LUX_DIRECT_URL",
    "LUX_PUBLISHABLE_KEY",
    "LUX_SECRET_KEY",
    // Obsolete CLI outputs. Remove these when activating a modern profile so
    // stale aliases cannot point an application at a different target.
    "LUX_AUTH_URL",
    "LUX_HTTP_URL",
];

#[derive(Serialize, Deserialize, Clone)]
struct EnvProfile {
    key: String,
    kind: String,
    display_name: String,
    project_id: Option<String>,
    filename: String,
}

#[derive(Serialize, Deserialize, Default)]
struct EnvProfileIndex {
    active: Option<String>,
    profiles: Vec<EnvProfile>,
}

/// The engine image `lux start` should run: a pinned `engine_version` from
/// `lux/config.toml`, else `:latest`.
fn desired_engine_image(config: Option<&LocalConfig>) -> String {
    match config.and_then(|c| c.engine_version.as_deref()) {
        Some(v) if !v.trim().is_empty() => format!("ghcr.io/lux-db/lux:{}", v.trim()),
        _ => LOCAL_ENGINE_IMAGE.to_string(),
    }
}

/// Engine image `lux start` runs. `:latest` is resolved from the local cache;
/// `lux update engine` is the explicit path that checks and pulls a newer image.
const LOCAL_ENGINE_IMAGE: &str = "ghcr.io/lux-db/lux:latest";
const DEFAULT_HTTP_PORT: u16 = 5890;
const DEFAULT_RESP_PORT: u16 = 6379;

/// Lux Studio image `lux studio` runs. Existing installs use the cached image
/// until `lux update studio` explicitly pulls a newer digest. It serves the
/// local web UI and talks to the engine from the browser over the engine's
/// CORS-`*` HTTP API.
const STUDIO_IMAGE: &str = "ghcr.io/lux-db/studio:latest";
/// Default host port for Studio. Lux owns the 5890 block: 5890 = HTTP API,
/// 5891 = Studio (RESP stays on 6379 for Redis drop-in compatibility).
const DEFAULT_STUDIO_PORT: u16 = 5891;

fn default_studio_port() -> u16 {
    DEFAULT_STUDIO_PORT
}

fn default_bind_host() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

/// Persisted local-dev credentials + runtime knobs for the Docker engine. Lives
/// in the gitignored `lux/.lux-local.json` and is reused across restarts so keys
/// and data stay stable. `password` is intentionally equal to `secret_key`: the
/// engine treats a Bearer == password as the operator (full access), which is
/// exactly how the prod gateway maps a secret key. So a secret-key SDK client
/// gets operator access locally, while a publishable-key client must sign in
/// (JWT -> grant-enforced user), mirroring production.
#[derive(Serialize, Deserialize)]
struct LocalState {
    password: String,
    publishable_key: String,
    secret_key: String,
    http_port: u16,
    resp_port: u16,
    container: String,
    volume: String,
    image: String,
    #[serde(default = "default_bind_host")]
    bind_host: IpAddr,
    // serde defaults so a `.lux-local.json` written before Studio existed still
    // loads; backfilled in ensure_local_state.
    #[serde(default = "default_studio_port")]
    studio_port: u16,
    #[serde(default)]
    studio_container: String,
    #[serde(default)]
    cluster: Option<LocalClusterState>,
    #[serde(default)]
    retired_cluster_volumes: Vec<String>,
}

fn local_state_path() -> PathBuf {
    PathBuf::from("lux").join(".lux-local.json")
}

fn load_local_state() -> Option<LocalState> {
    let path = local_state_path();
    let data = std::fs::read_to_string(&path).ok()?;
    #[cfg(unix)]
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).ok();
    serde_json::from_str(&data).ok()
}

fn local_state_missing_bind_host() -> bool {
    std::fs::read_to_string(local_state_path())
        .ok()
        .and_then(|data| serde_json::from_str::<serde_json::Value>(&data).ok())
        .is_some_and(|value| value.get("bind_host").is_none())
}

fn ensure_private_dir(path: &Path) -> Result<(), String> {
    std::fs::create_dir_all(path).map_err(|e| format!("create {}: {e}", path.display()))?;
    #[cfg(unix)]
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("chmod {}: {e}", path.display()))?;
    Ok(())
}

/// Atomically replace a secret-bearing file and force owner-only permissions.
fn write_secret_file(path: &Path, data: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("lux-secret");
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let tmp = path.with_file_name(format!(".{filename}.tmp-{}-{nonce}", std::process::id()));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(&tmp)
        .map_err(|e| format!("write {}: {e}", path.display()))?;
    file.write_all(data)
        .and_then(|_| file.sync_all())
        .map_err(|e| format!("write {}: {e}", path.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("replace {}: {e}", path.display()))?;
    #[cfg(unix)]
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("chmod {}: {e}", path.display()))?;
    Ok(())
}

fn save_local_state(state: &LocalState) {
    let path = local_state_path();
    let data = serde_json::to_string_pretty(state).unwrap();
    write_secret_file(&path, data.as_bytes()).unwrap_or_else(|e| {
        eprintln!("{} {e}", "Failed to write lux/.lux-local.json:".red());
        std::process::exit(1);
    });
}

/// Hex-encode `bytes` of OS randomness. Local-dev keys don't need to be
/// cryptographic, but should be unguessable; `/dev/urandom` avoids a new crate
/// dependency (the CLI only targets unix).
fn random_hex(bytes: usize) -> String {
    use std::io::Read;
    let mut buf = vec![0u8; bytes];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .is_err()
    {
        // Fallback: derive from a per-process/time hash. Good enough for a local
        // dev credential if /dev/urandom is somehow unavailable.
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        std::process::id().hash(&mut h);
        std::time::SystemTime::now().hash(&mut h);
        let seed = h.finish().to_le_bytes();
        for (i, b) in buf.iter_mut().enumerate() {
            *b = seed[i % seed.len()] ^ (i as u8);
        }
    }
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// A stable 64-bit hash of `s` (FNV-free, std-only).
fn hash_str(s: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

/// A per-project slug for naming the Docker container/volume, so several local
/// projects don't collide on one fixed name (and clobber each other's data).
/// `<sanitized-dir>-<hash6>` keeps it readable while disambiguating two dirs
/// that share a basename (e.g. `app` in different repos). Derived from the cwd's
/// absolute path so it's stable across restarts.
fn project_slug() -> String {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let abs = std::fs::canonicalize(&cwd).unwrap_or(cwd);
    let base = abs
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("lux")
        .to_ascii_lowercase();
    let mut sanitized: String = base
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    while sanitized.contains("--") {
        sanitized = sanitized.replace("--", "-");
    }
    let sanitized = sanitized.trim_matches('-');
    let sanitized = if sanitized.is_empty() {
        "lux"
    } else {
        sanitized
    };
    format!(
        "{sanitized}-{:06x}",
        hash_str(&abs.to_string_lossy()) & 0xff_ffff
    )
}

/// True if `port` is bindable on the same host address Docker will publish.
fn port_is_free(bind_host: IpAddr, port: u16) -> bool {
    std::net::TcpListener::bind((bind_host, port)).is_ok()
}

/// Return `preferred` if free, else the next free port above it. Lets multiple
/// projects run at once: the first gets the default port, the next bumps up.
fn free_port_from(bind_host: IpAddr, preferred: u16) -> u16 {
    let mut p = preferred;
    for _ in 0..500 {
        if port_is_free(bind_host, p) {
            return p;
        }
        p = p.saturating_add(1);
        if p == 0 {
            break;
        }
    }
    preferred
}

/// Load the persisted local state, generating + saving fresh creds on first use.
fn ensure_local_state() -> LocalState {
    let missing_bind_host = local_state_missing_bind_host();
    if let Some(mut state) = load_local_state() {
        let mut dirty = missing_bind_host;
        // Follow the engine image config.toml asks for: a pinned `engine_version`,
        // else `:latest`. Re-evaluated each load so editing config.toml takes
        // effect on the next `lux start`.
        let desired_image = desired_engine_image(load_local_config().as_ref());
        if state.image != desired_image {
            state.image = desired_image;
            dirty = true;
        }
        // Backfill Studio fields for states written before Studio existed.
        if state.studio_container.is_empty() {
            state.studio_container = format!("lux-{}-studio", project_slug());
            dirty = true;
        }
        if state.studio_port == 0 {
            state.studio_port = DEFAULT_STUDIO_PORT;
            dirty = true;
        }
        if dirty {
            save_local_state(&state);
        }
        return state;
    }
    let local = load_local_config();
    let slug = project_slug();
    let state = LocalState {
        password: format!("lux_sec_local_{}", random_hex(24)),
        publishable_key: format!("lux_pub_local_{}", random_hex(24)),
        secret_key: String::new(), // filled below to equal password
        http_port: local
            .as_ref()
            .and_then(|c| c.local_http_port)
            .unwrap_or(DEFAULT_HTTP_PORT),
        resp_port: local
            .as_ref()
            .and_then(|c| c.local_resp_port)
            .unwrap_or(DEFAULT_RESP_PORT),
        container: format!("lux-{slug}"),
        volume: format!("lux-{slug}-data"),
        image: desired_engine_image(local.as_ref()),
        studio_port: DEFAULT_STUDIO_PORT,
        studio_container: format!("lux-{slug}-studio"),
        bind_host: default_bind_host(),
        cluster: None,
        retired_cluster_volumes: Vec::new(),
    };
    // secret_key == password: the operator credential and the SDK secret key are
    // the same value locally (see LocalState doc comment).
    let state = LocalState {
        secret_key: state.password.clone(),
        ..state
    };
    save_local_state(&state);
    state
}

impl LocalState {
    fn connection_ip(&self) -> IpAddr {
        if self.bind_host.is_unspecified() {
            default_bind_host()
        } else {
            self.bind_host
        }
    }

    fn connection_host(&self) -> String {
        if self.connection_ip().is_loopback() {
            "localhost".to_string()
        } else {
            self.connection_ip().to_string()
        }
    }

    fn lux_url(&self) -> String {
        format_host_url("http", &self.connection_host(), self.http_port)
    }
    fn direct_url(&self) -> String {
        format_host_url(
            &format!("lux://:{}@", self.password),
            &self.connection_host(),
            self.resp_port,
        )
    }
    /// The LUX_* lines for `.env.local` / `lux status -o env`.
    fn env_lines(&self) -> Vec<String> {
        vec![
            format!("LUX_URL={}", self.lux_url()),
            format!("LUX_DIRECT_URL={}", self.direct_url()),
            format!("LUX_PUBLISHABLE_KEY={}", self.publishable_key),
            format!("LUX_SECRET_KEY={}", self.secret_key),
        ]
    }
}

fn format_host_url(scheme: &str, host: &str, port: u16) -> String {
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    if scheme.ends_with('@') {
        format!("{scheme}{host}:{port}")
    } else {
        format!("{scheme}://{host}:{port}")
    }
}

fn docker_port_map(bind_host: IpAddr, host_port: u16, container_port: u16) -> String {
    match bind_host {
        IpAddr::V4(address) => format!("{address}:{host_port}:{container_port}"),
        IpAddr::V6(address) => format!("[{address}]:{host_port}:{container_port}"),
    }
}

/// Run a `docker` subcommand, capturing stdout. Returns Err on spawn failure or
/// a non-zero exit (with stderr).
fn docker_output(args: &[&str]) -> Result<String, String> {
    let out = std::process::Command::new("docker")
        .args(args)
        .output()
        .map_err(|e| format!("failed to run docker: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Preflight: Docker installed and the daemon reachable.
fn docker_preflight() -> Result<(), String> {
    docker_output(&["info"]).map(|_| ()).map_err(|_| {
        "Docker is not available. Install Docker Desktop and make sure it is running.".to_string()
    })
}

/// Container state: "running", "exited", "created", ... or None if absent.
fn docker_container_state(name: &str) -> Option<String> {
    docker_output(&["inspect", "-f", "{{.State.Status}}", name]).ok()
}

fn published_binding_matches(output: &str, bind_host: IpAddr, host_port: u16) -> bool {
    let mut fields = output.split_whitespace();
    let Some(host) = fields.next() else {
        return false;
    };
    let Some(port) = fields.next().and_then(|value| value.parse::<u16>().ok()) else {
        return false;
    };
    fields.next().is_none() && host.parse::<IpAddr>().ok() == Some(bind_host) && port == host_port
}

fn docker_port_binding_matches(
    container: &str,
    container_port: &str,
    bind_host: IpAddr,
    host_port: u16,
) -> bool {
    let template = format!(
        "{{{{with (index .HostConfig.PortBindings \"{container_port}\")}}}}{{{{(index . 0).HostIp}}}} {{{{(index . 0).HostPort}}}}{{{{end}}}}"
    );
    docker_output(&["inspect", "-f", &template, container])
        .is_ok_and(|output| published_binding_matches(&output, bind_host, host_port))
}

fn engine_bindings_match(state: &LocalState) -> bool {
    docker_port_binding_matches(
        &state.container,
        "6379/tcp",
        state.bind_host,
        state.resp_port,
    ) && docker_port_binding_matches(
        &state.container,
        "5890/tcp",
        state.bind_host,
        state.http_port,
    )
}

fn docker_volume_exists(name: &str) -> bool {
    docker_output(&["volume", "inspect", name]).is_ok()
}

fn docker_remote_digest(image: &str) -> Result<String, String> {
    let output = docker_output(&[
        "buildx",
        "imagetools",
        "inspect",
        image,
        "--format",
        "{{json .Manifest.Digest}}",
    ])?;
    let digest = output.trim().trim_matches('"');
    if digest.starts_with("sha256:") {
        Ok(digest.to_string())
    } else {
        Err(format!("registry returned an invalid digest for {image}"))
    }
}

fn docker_container_digest(container: &str) -> Result<String, String> {
    let image_id = docker_output(&["inspect", "-f", "{{.Image}}", container])?;
    let raw = docker_output(&[
        "image",
        "inspect",
        &image_id,
        "--format",
        "{{json .RepoDigests}}",
    ])?;
    let digests: Vec<String> =
        serde_json::from_str(&raw).map_err(|e| format!("invalid Docker image metadata: {e}"))?;
    digests
        .into_iter()
        .find_map(|value| value.split_once('@').map(|(_, digest)| digest.to_string()))
        .ok_or_else(|| format!("no repository digest recorded for container {container}"))
}

fn docker_image_digest(image: &str) -> Result<String, String> {
    let raw = docker_output(&[
        "image",
        "inspect",
        image,
        "--format",
        "{{json .RepoDigests}}",
    ])?;
    let digests: Vec<String> =
        serde_json::from_str(&raw).map_err(|e| format!("invalid Docker image metadata: {e}"))?;
    digests
        .into_iter()
        .find_map(|value| value.split_once('@').map(|(_, digest)| digest.to_string()))
        .ok_or_else(|| format!("no repository digest recorded for image {image}"))
}

#[derive(Clone, Debug, Serialize)]
struct ImageUpdateStatus {
    image: String,
    current_digest: Option<String>,
    latest_digest: Option<String>,
    update_available: Option<bool>,
    error: Option<String>,
}

fn image_update_status(container: &str, image: &str) -> ImageUpdateStatus {
    let current = docker_container_digest(container);
    let latest = docker_remote_digest(image);
    match (current, latest) {
        (Ok(current), Ok(latest)) => ImageUpdateStatus {
            image: image.to_string(),
            update_available: Some(current != latest),
            current_digest: Some(current),
            latest_digest: Some(latest),
            error: None,
        },
        (current, latest) => {
            let (current_digest, current_error) = match current {
                Ok(value) => (Some(value), None),
                Err(error) => (None, Some(error)),
            };
            let (latest_digest, latest_error) = match latest {
                Ok(value) => (Some(value), None),
                Err(error) => (None, Some(error)),
            };
            ImageUpdateStatus {
                image: image.to_string(),
                current_digest,
                latest_digest,
                update_available: None,
                error: current_error
                    .or(latest_error)
                    .or_else(|| Some("version status unavailable".to_string())),
            }
        }
    }
}

fn print_image_update_hint(label: &str, container: &str, image: &str, command: &str) {
    let status = image_update_status(container, image);
    if status.update_available == Some(true) {
        println!(
            "{} A newer {label} image is available; run {}.",
            "Update:".yellow(),
            command.cyan()
        );
    }
}

fn run_local_engine_container(state: &LocalState) -> Result<(), String> {
    let resp_map = docker_port_map(state.bind_host, state.resp_port, 6379);
    let http_map = docker_port_map(state.bind_host, state.http_port, 5890);
    let vol_map = format!("{}:/data", state.volume);
    let engine_env = local_engine_env(state);
    let mut run_args: Vec<&str> = vec![
        "run",
        "-d",
        "--name",
        &state.container,
        "-p",
        &resp_map,
        "-p",
        &http_map,
        "-v",
        &vol_map,
    ];
    for entry in &engine_env {
        run_args.push("-e");
        run_args.push(entry);
    }
    run_args.push("--restart");
    run_args.push("unless-stopped");
    run_args.push(&state.image);
    docker_output(&run_args).map(|_| ())
}

/// Merge `entries` into existing `.gitignore` content, appending only the ones
/// not already present. Returns `None` when nothing needs adding (so the caller
/// can skip the write). Pure (no IO) so it's unit-testable.
fn gitignore_merge(existing: &str, entries: &[&str]) -> Option<String> {
    let present: std::collections::HashSet<&str> = existing.lines().map(|l| l.trim()).collect();
    let missing: Vec<&str> = entries
        .iter()
        .copied()
        .filter(|e| !present.contains(e))
        .collect();
    if missing.is_empty() {
        return None;
    }
    let mut data = existing.to_string();
    if !data.is_empty() && !data.ends_with('\n') {
        data.push('\n');
    }
    for e in missing {
        data.push_str(e);
        data.push('\n');
    }
    Some(data)
}

/// Append missing entries to `.gitignore` (creating it if absent). Idempotent.
fn ensure_gitignore(entries: &[&str]) {
    let path = PathBuf::from(".gitignore");
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let Some(data) = gitignore_merge(&existing, entries) else {
        return;
    };
    std::fs::write(&path, data).ok();
}

fn profile_dir() -> PathBuf {
    PathBuf::from(ENV_PROFILE_DIR)
}

fn load_profile_index() -> Result<EnvProfileIndex, String> {
    let path = PathBuf::from(ENV_PROFILE_INDEX);
    if !path.exists() {
        return Ok(EnvProfileIndex::default());
    }
    let data =
        std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    serde_json::from_str(&data).map_err(|e| format!("parse {}: {e}", path.display()))
}

fn save_profile_index(index: &EnvProfileIndex) -> Result<(), String> {
    ensure_private_dir(&profile_dir())?;
    let data = serde_json::to_vec_pretty(index).map_err(|e| e.to_string())?;
    write_secret_file(Path::new(ENV_PROFILE_INDEX), &data)
}

fn profile_path(profile: &EnvProfile) -> PathBuf {
    profile_dir().join(&profile.filename)
}

fn profile_content(lines: &[String]) -> String {
    let mut out = lines.join("\n");
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

fn write_profile(profile: &EnvProfile, content: &str) -> Result<(), String> {
    ensure_private_dir(&profile_dir())?;
    write_secret_file(&profile_path(profile), content.as_bytes())
}

fn upsert_profile(index: &mut EnvProfileIndex, profile: EnvProfile) {
    if let Some(existing) = index.profiles.iter_mut().find(|p| p.key == profile.key) {
        *existing = profile;
    } else {
        index.profiles.push(profile);
    }
    index.profiles.sort_by(|a, b| a.key.cmp(&b.key));
}

fn env_assignment(line: &str) -> Option<(&str, &str)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let line = line.strip_prefix("export ").unwrap_or(line);
    let (key, value) = line.split_once('=')?;
    let key = key.trim();
    if key.is_empty() {
        return None;
    }
    Some((key, value))
}

fn managed_env_map(content: &str) -> HashMap<String, String> {
    content
        .lines()
        .filter_map(env_assignment)
        .filter(|(key, _)| MANAGED_ENV_KEYS.contains(key))
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

/// Replace only Lux-owned connection keys. Every unrelated line remains
/// byte-for-byte equivalent apart from the final newline.
fn merge_managed_env(existing: &str, profile: &str) -> String {
    let desired = managed_env_map(profile);
    let mut seen = HashSet::new();
    let mut output = Vec::new();

    for line in existing.lines() {
        let Some((key, _)) = env_assignment(line) else {
            output.push(line.to_string());
            continue;
        };
        if !MANAGED_ENV_KEYS.contains(&key) {
            output.push(line.to_string());
            continue;
        }
        if !seen.insert(key.to_string()) {
            continue;
        }
        if let Some(value) = desired.get(key) {
            output.push(format!("{key}={value}"));
        }
    }

    for key in MANAGED_ENV_KEYS {
        if !seen.contains(*key) {
            if let Some(value) = desired.get(*key) {
                output.push(format!("{key}={value}"));
            }
        }
    }
    while output.last().is_some_and(|line| line.is_empty()) {
        output.pop();
    }
    output.push(String::new());
    output.join("\n")
}

fn resolve_profile<'a>(index: &'a EnvProfileIndex, selector: &str) -> Option<&'a EnvProfile> {
    let normalized = selector.trim();
    index.profiles.iter().find(|profile| {
        profile.key == normalized
            || profile.display_name == normalized
            || profile.project_id.as_deref() == Some(normalized)
    })
}

fn activate_profile(index: &mut EnvProfileIndex, selector: &str) -> Result<EnvProfile, String> {
    let profile = resolve_profile(index, selector)
        .cloned()
        .ok_or_else(|| format!("profile '{selector}' not found"))?;
    let content = std::fs::read_to_string(profile_path(&profile))
        .map_err(|e| format!("read profile '{}': {e}", profile.display_name))?;
    let existing = std::fs::read_to_string(".env.local").unwrap_or_default();
    let merged = merge_managed_env(&existing, &content);
    write_secret_file(Path::new(".env.local"), merged.as_bytes())?;
    index.active = Some(profile.key.clone());
    save_profile_index(index)?;
    Ok(profile)
}

fn refresh_local_profile(state: &LocalState) -> Result<(), String> {
    ensure_gitignore(&[
        ".env.local",
        "lux/.lux-local.json",
        "lux/.env-profiles/",
        "lux/.backups/",
    ]);
    let mut index = load_profile_index()?;
    let local = EnvProfile {
        key: "local".to_string(),
        kind: "local".to_string(),
        display_name: "local".to_string(),
        project_id: None,
        filename: "local.env".to_string(),
    };
    write_profile(&local, &profile_content(&state.env_lines()))?;
    upsert_profile(&mut index, local);

    // Upgrade safely from the old single-file model: preserve any existing Lux
    // target as the active legacy profile instead of silently switching it.
    if index.active.is_none() {
        let existing = std::fs::read_to_string(".env.local").unwrap_or_default();
        let existing_keys = managed_env_map(&existing);
        if existing_keys.is_empty() {
            activate_profile(&mut index, "local")?;
            return Ok(());
        }
        let legacy = EnvProfile {
            key: "legacy".to_string(),
            kind: "legacy".to_string(),
            display_name: "legacy (.env.local)".to_string(),
            project_id: existing_keys.get("LUX_PROJECT_ID").cloned(),
            filename: "legacy.env".to_string(),
        };
        let lines: Vec<String> = MANAGED_ENV_KEYS
            .iter()
            .filter_map(|key| {
                existing_keys
                    .get(*key)
                    .map(|value| format!("{key}={value}"))
            })
            .collect();
        write_profile(&legacy, &profile_content(&lines))?;
        index.active = Some(legacy.key.clone());
        upsert_profile(&mut index, legacy);
    }
    save_profile_index(&index)
}

fn active_profile_label() -> String {
    load_profile_index()
        .ok()
        .and_then(|index| {
            let active = index.active.clone()?;
            resolve_profile(&index, &active).map(|profile| profile.display_name.clone())
        })
        .unwrap_or_else(|| "not configured".to_string())
}

fn local_status_value(state: &LocalState) -> serde_json::Value {
    let running = docker_container_state(&state.container).as_deref() == Some("running");
    let cluster = state
        .cluster
        .as_ref()
        .map(|cluster| {
            serde_json::json!({
                "enabled": true,
                "cluster_id": cluster.cluster_id,
                "epoch": cluster.epoch,
                "nodes": cluster.nodes.len(),
                "running_nodes": cluster.nodes.iter().filter(|node| {
                    docker_container_state(&node.container).as_deref() == Some("running")
                }).count(),
            })
        })
        .unwrap_or_else(|| serde_json::json!({ "enabled": false, "nodes": 1 }));
    serde_json::json!({
        "target": { "kind": "local", "name": "local" },
        "status": if running { "running" } else { "stopped" },
        "image": state.image,
        "url": state.lux_url(),
        "bind_host": state.bind_host,
        "direct_host": state.connection_host(),
        "direct_port": state.resp_port,
        "data_volume": state.volume,
        "encryption": "enabled",
        "active_env_profile": active_profile_label(),
        "cluster": cluster,
    })
}

fn print_local_status(state: &LocalState, json_output: bool) {
    let value = local_status_value(state);
    if json_output {
        println!("{}", serde_json::to_string_pretty(&value).unwrap());
        return;
    }
    let running = value["status"] == "running";
    let status = if running {
        "running".green().to_string()
    } else {
        "stopped".yellow().to_string()
    };
    println!("{} {status}", "Local engine:".bold());
    println!("{} {}", "Image:".bold(), state.image.dimmed());
    println!("{} {}", "LUX_URL:".bold(), state.lux_url());
    println!(
        "{} {} (credentials hidden)",
        "Direct:".bold(),
        format_host_url("lux", &state.connection_host(), state.resp_port)
    );
    println!("{} {}", "App env:".bold(), active_profile_label());
    println!("{} {}", "Data volume:".bold(), state.volume);
    println!("{} {}", "Encryption:".bold(), "enabled".green());
    if let Some(cluster) = &state.cluster {
        let running_nodes = cluster
            .nodes
            .iter()
            .filter(|node| docker_container_state(&node.container).as_deref() == Some("running"))
            .count();
        println!(
            "{} {} nodes ({} running), epoch {}",
            "Cluster:".bold(),
            cluster.nodes.len(),
            running_nodes,
            cluster.epoch
        );
    } else {
        println!("{} standalone fast path", "Cluster:".bold());
    }
    if !running {
        println!("\nRun {} to boot it.", "lux start".cyan());
    }
}

fn print_connection_block(state: &LocalState) {
    println!();
    println!("{}", "  Local Lux engine".bold());
    println!("  {}  {}", "LUX_URL          ".dimmed(), state.lux_url());
    println!(
        "  {}  {} (credentials hidden)",
        "Direct            ".dimmed(),
        format_host_url("lux", &state.connection_host(), state.resp_port)
    );
    println!(
        "  {}  {}",
        "App env profile   ".dimmed(),
        active_profile_label()
    );
    println!("  {}  {}", "Data volume      ".dimmed(), state.volume);
    println!("  {}  {}", "Encryption       ".dimmed(), "enabled".green());
    if let Some(cluster) = &state.cluster {
        println!(
            "  {}  {} nodes · epoch {}",
            "Cluster          ".dimmed(),
            cluster.nodes.len(),
            cluster.epoch
        );
    } else {
        println!("  {}  standalone fast path", "Cluster          ".dimmed());
    }
    println!();
    println!(
        "  Local credentials are stored in {}. Use {} to activate them.",
        "lux/.env-profiles/local.env".cyan(),
        "lux env use local".cyan()
    );
}

/// Poll the local RESP port until the engine answers an authed PING (or timeout).
fn wait_for_local_ready(state: &LocalState) -> bool {
    for _ in 0..40 {
        if let Ok(mut conn) =
            DirectConn::connect(&state.connection_host(), state.resp_port, &state.password)
        {
            if conn.exec("PING").is_ok() {
                return true;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    false
}

/// Poll until the Studio container's HTTP port accepts connections (nginx up).
fn wait_for_studio_ready(state: &LocalState) -> bool {
    let addr = std::net::SocketAddr::new(state.connection_ip(), state.studio_port);
    for _ in 0..40 {
        if std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(300))
            .is_ok()
        {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    false
}

/// The Studio display name: config.toml project_name, else the project dir name.
fn studio_project_name() -> String {
    load_local_config()
        .and_then(|c| c.project_name)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            std::env::current_dir()
                .ok()
                .and_then(|p| p.file_name().map(|s| s.to_string_lossy().to_string()))
                .unwrap_or_else(|| "local".to_string())
        })
}

/// Ensure the Lux Studio container is running against `state`'s engine, then
/// print its URL (and optionally open a browser). Assumes the engine is up.
/// Non-fatal: warns and returns on failure so callers like `lux start` keep
/// going. The SPA runs in the browser, so LUX_URL must be reachable from the
/// browser: defaults to host-visible localhost, but honors an explicit LUX_URL
/// for remote/sandbox setups. LUX_KEY is the operator secret and stays local.
fn ensure_studio(state: &mut LocalState, open_browser: bool) -> bool {
    let binding_matches = docker_port_binding_matches(
        &state.studio_container,
        "80/tcp",
        state.bind_host,
        state.studio_port,
    );
    if docker_container_state(&state.studio_container).as_deref() == Some("running")
        && binding_matches
    {
        let url = format_host_url("http", &state.connection_host(), state.studio_port);
        println!("{} {}", "Lux Studio:".bold(), url.cyan());
        print_image_update_hint(
            "Studio",
            &state.studio_container,
            STUDIO_IMAGE,
            "lux update studio",
        );
        if open_browser {
            let _ = open::that(&url);
        }
        return true;
    }
    if docker_container_state(&state.studio_container).is_some() {
        let _ = docker_output(&["rm", "-f", &state.studio_container]);
    }
    let studio_port = free_port_from(state.bind_host, state.studio_port);
    if studio_port != state.studio_port {
        state.studio_port = studio_port;
        save_local_state(state);
    }

    let port_map = docker_port_map(state.bind_host, studio_port, 80);
    // The Studio SPA runs in the browser and calls the engine directly. Normally
    // that's the host-visible localhost, but in a remote/sandbox context (e2b,
    // a dev container, an SSH port-forward) the browser can't reach the engine
    // at localhost. Honor an explicit LUX_URL so Studio points at whatever URL
    // is actually reachable from the browser; fall back to localhost otherwise.
    let engine_url = match std::env::var("LUX_URL") {
        Ok(u) if !u.trim().is_empty() => u.trim().to_string(),
        _ => state.lux_url(),
    };
    let e_url = format!("LUX_URL={engine_url}");
    let e_key = format!("LUX_KEY={}", state.secret_key);
    let e_pub = format!("LUX_PUBLISHABLE_KEY={}", state.publishable_key);
    let e_direct = format!("LUX_DIRECT_URL={}", state.direct_url());
    let e_name = format!("LUX_PROJECT_NAME={}", studio_project_name());
    // Optional: enables AI grant drafting in Studio. The browser calls OpenRouter
    // directly with this key; localhost-only.
    let or_key = std::env::var("LUX_OPENROUTER_KEY")
        .or_else(|_| std::env::var("OPENROUTER_API_KEY"))
        .unwrap_or_default();
    let e_or = format!("LUX_OPENROUTER_KEY={or_key}");
    let run_args: Vec<&str> = vec![
        "run",
        "-d",
        "--name",
        &state.studio_container,
        "-p",
        &port_map,
        "-e",
        &e_url,
        "-e",
        &e_key,
        "-e",
        &e_pub,
        "-e",
        &e_direct,
        "-e",
        &e_name,
        "-e",
        &e_or,
        "--restart",
        "unless-stopped",
        STUDIO_IMAGE,
    ];
    if let Err(e) = docker_output(&run_args) {
        eprintln!("{} Studio failed to start: {e}", "Warning:".yellow());
        return false;
    }

    print!("{}", "Waiting for Studio...".dimmed());
    std::io::stdout().flush().ok();
    if !wait_for_studio_ready(state) {
        println!(" {}", "TIMEOUT".red());
        eprintln!(
            "{} Studio did not become ready. Check {}.",
            "Warning:".yellow(),
            format!("docker logs {}", state.studio_container).cyan()
        );
        return false;
    }
    println!(" {}", "ready".green());

    let url = format_host_url("http", &state.connection_host(), studio_port);
    println!("{} {}", "Lux Studio:".bold(), url.cyan());
    println!("{} {}", "  → engine:".dimmed(), engine_url.dimmed());
    if open_browser {
        let _ = open::that(&url);
    }
    true
}

/// Apply migrations through the engine-owned contract. The engine persists
/// progress before executing commands, so a failed migration cannot be
/// silently replayed by `lux start`.
async fn apply_pending_migrations(target: &mut MigrateTarget, dir: &Path) -> usize {
    let local = get_local_migrations(dir);
    let mut applied = 0usize;
    for (filename, content) in &local {
        let plan = target
            .migration_plan(filename, content)
            .await
            .unwrap_or_else(|e| {
                eprintln!(
                    "{} Could not plan migration '{}': {e}",
                    "Error:".red(),
                    filename
                );
                std::process::exit(1);
            });
        match plan.action {
            MigrationPlanAction::AlreadyApplied => continue,
            MigrationPlanAction::Conflict | MigrationPlanAction::Blocked => {
                migration_plan_error(&plan);
                std::process::exit(1);
            }
            MigrationPlanAction::Apply => {}
        }
        print!("  {} {}...", "Applying".dimmed(), filename);
        std::io::stdout().flush().ok();
        if let Err(e) = target.migration_apply(filename, content).await {
            println!(" {}", "FAILED".red());
            eprintln!("    {} {e}", "Error:".red());
            eprintln!(
                "    Inspect progress with {}, then repair explicitly with {}.",
                "lux migrate status".cyan(),
                format!("lux migrate repair {filename} ...").cyan()
            );
            std::process::exit(1);
        }
        println!(" {}", "OK".green());
        applied += 1;
    }
    applied
}

#[derive(Deserialize)]
struct ApiResponse<T> {
    data: Option<T>,
    error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct MigrationRecord {
    filename: String,
    checksum: String,
    #[serde(default)]
    checksum_algorithm: String,
    applied_at: u64,
    #[serde(default)]
    body: String,
    status: String,
    #[serde(default)]
    command_count: usize,
    #[serde(default)]
    completed_commands: usize,
    error: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum MigrationPlanAction {
    Apply,
    AlreadyApplied,
    Conflict,
    Blocked,
}

impl MigrationPlanAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Apply => "apply",
            Self::AlreadyApplied => "already_applied",
            Self::Conflict => "conflict",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct MigrationPlan {
    filename: String,
    checksum: String,
    checksum_algorithm: String,
    command_count: usize,
    action: MigrationPlanAction,
    reason: Option<String>,
}

#[derive(Deserialize)]
struct DirectMigrationApplyResult {
    migration: MigrationRecord,
    already_applied: bool,
}

#[derive(Clone, Copy)]
enum MigrationRepairRequest {
    Resume { from_command: usize },
    MarkApplied,
    Abandon,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PushProviderConfig {
    configured: bool,
    #[serde(default)]
    team_id: String,
    #[serde(default)]
    key_id: String,
    #[serde(default)]
    topic: String,
    #[serde(default)]
    environment: String,
    #[serde(default)]
    public_key: String,
    #[serde(default)]
    subject: String,
    #[serde(default)]
    secret_storage: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PushConfigStatus {
    app_id: String,
    healthy: bool,
    encryption_available: bool,
    #[serde(default)]
    warnings: Vec<String>,
    apns: PushProviderConfig,
    vapid: PushProviderConfig,
}

#[derive(Deserialize)]
struct EnginePushConfigResponse {
    config: PushConfigStatus,
}

enum PushTarget {
    Local {
        client: reqwest::Client,
        base_url: String,
        operator_key: String,
    },
    Cloud {
        client: reqwest::Client,
        api_url: String,
        token: String,
        instance_id: String,
    },
}

impl PushTarget {
    async fn config(&self, app_id: &str) -> Result<PushConfigStatus, String> {
        match self {
            Self::Local {
                client,
                base_url,
                operator_key,
            } => {
                let url = push_url(base_url, "/v1/push/config", app_id)?;
                let response: EnginePushConfigResponse =
                    direct_push_request(client, reqwest::Method::GET, url, operator_key, None)
                        .await?;
                Ok(response.config)
            }
            Self::Cloud {
                client,
                api_url,
                token,
                instance_id,
            } => {
                let url = push_url(api_url, &format!("/push/{instance_id}/config"), app_id)?;
                cloud_management_request(client, reqwest::Method::GET, url, token, None).await
            }
        }
    }

    async fn update_apns(
        &self,
        app_id: &str,
        team_id: &str,
        key_id: &str,
        topic: &str,
        environment: PushEnvironment,
        p8_pem: Option<&str>,
    ) -> Result<PushConfigStatus, String> {
        let mut payload = serde_json::json!({
            "app_id": app_id,
            "team_id": team_id,
            "key_id": key_id,
            "topic": topic,
            "environment": environment.as_str(),
        });
        if let Some(p8_pem) = p8_pem {
            payload["p8_pem"] = serde_json::Value::String(p8_pem.to_string());
        }
        match self {
            Self::Local {
                client,
                base_url,
                operator_key,
            } => {
                let response: EnginePushConfigResponse = direct_push_request(
                    client,
                    reqwest::Method::PUT,
                    format!("{}/v1/push/config/apns", base_url.trim_end_matches('/')),
                    operator_key,
                    Some(payload),
                )
                .await?;
                Ok(response.config)
            }
            Self::Cloud {
                client,
                api_url,
                token,
                instance_id,
            } => {
                cloud_management_request(
                    client,
                    reqwest::Method::PUT,
                    format!("{api_url}/push/{instance_id}/config/apns"),
                    token,
                    Some(payload),
                )
                .await
            }
        }
    }

    async fn clear_apns(&self, app_id: &str) -> Result<PushConfigStatus, String> {
        self.delete_config("/v1/push/config/apns", "apns", app_id)
            .await
    }

    async fn configure_vapid(
        &self,
        app_id: &str,
        action: &str,
        subject: &str,
    ) -> Result<PushConfigStatus, String> {
        let payload = serde_json::json!({
            "app_id": app_id,
            "action": action,
            "subject": subject,
        });
        match self {
            Self::Local {
                client,
                base_url,
                operator_key,
            } => {
                direct_push_request::<serde_json::Value>(
                    client,
                    reqwest::Method::POST,
                    format!("{}/v1/push/config/vapid", base_url.trim_end_matches('/')),
                    operator_key,
                    Some(payload),
                )
                .await?;
                self.config(app_id).await
            }
            Self::Cloud {
                client,
                api_url,
                token,
                instance_id,
            } => {
                cloud_management_request(
                    client,
                    reqwest::Method::POST,
                    format!("{api_url}/push/{instance_id}/config/vapid"),
                    token,
                    Some(payload),
                )
                .await
            }
        }
    }

    async fn disable_vapid(&self, app_id: &str) -> Result<PushConfigStatus, String> {
        self.delete_config("/v1/push/config/vapid", "vapid", app_id)
            .await
    }

    async fn delete_config(
        &self,
        local_path: &str,
        cloud_provider: &str,
        app_id: &str,
    ) -> Result<PushConfigStatus, String> {
        match self {
            Self::Local {
                client,
                base_url,
                operator_key,
            } => {
                let url = push_url(base_url, local_path, app_id)?;
                direct_push_request::<serde_json::Value>(
                    client,
                    reqwest::Method::DELETE,
                    url,
                    operator_key,
                    None,
                )
                .await?;
                self.config(app_id).await
            }
            Self::Cloud {
                client,
                api_url,
                token,
                instance_id,
            } => {
                let url = push_url(
                    api_url,
                    &format!("/push/{instance_id}/config/{cloud_provider}"),
                    app_id,
                )?;
                cloud_management_request(client, reqwest::Method::DELETE, url, token, None).await
            }
        }
    }
}

fn push_url(base_url: &str, path: &str, app_id: &str) -> Result<String, String> {
    let mut url = reqwest::Url::parse(&format!("{}{}", base_url.trim_end_matches('/'), path))
        .map_err(|e| format!("invalid push configuration URL: {e}"))?;
    url.query_pairs_mut().append_pair("app_id", app_id);
    Ok(url.to_string())
}

async fn direct_push_request<T: DeserializeOwned>(
    client: &reqwest::Client,
    method: reqwest::Method,
    url: String,
    operator_key: &str,
    payload: Option<serde_json::Value>,
) -> Result<T, String> {
    let mut request = client
        .request(method, url)
        .header("Authorization", format!("Bearer {operator_key}"));
    if let Some(payload) = payload {
        request = request.json(&payload);
    }
    let response = request
        .send()
        .await
        .map_err(|e| format!("engine push request failed: {e}"))?;
    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|e| format!("engine push response could not be read: {e}"))?;
    let value: serde_json::Value = serde_json::from_str(&text).map_err(|e| {
        format!(
            "engine push API returned invalid JSON (HTTP {}): {e}",
            status.as_u16()
        )
    })?;
    if !status.is_success() {
        return Err(value
            .get("error")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("engine push configuration failed")
            .to_string());
    }
    serde_json::from_value(value).map_err(|e| format!("invalid engine push response: {e}"))
}

#[derive(Deserialize, Debug)]
struct Instance {
    id: String,
    name: String,
    status: String,
    region: String,
    memory_mb: u32,
    port: Option<u16>,
    worker_host: Option<String>,
    #[serde(default)]
    current_image: Option<String>,
    #[serde(default)]
    latest_image: Option<String>,
    #[serde(default)]
    current_digest: Option<String>,
    #[serde(default)]
    latest_digest: Option<String>,
    #[serde(default)]
    engine_version: Option<EngineManagementVersion>,
    #[serde(default)]
    needs_update: bool,
    #[serde(default)]
    engine_update_phase: Option<String>,
    #[serde(default)]
    engine_update_error: Option<String>,
}

#[derive(Deserialize)]
struct Workspace {
    id: String,
}

#[derive(Deserialize)]
struct Credentials {
    resp: String,
}

#[derive(Deserialize)]
struct AuthCredentials {
    publishable_key: Option<String>,
    secret_key: Option<String>,
}

#[derive(Deserialize)]
struct ProjectKey {
    id: String,
    kind: String,
    name: String,
    prefix: String,
    #[serde(default)]
    default: bool,
}

#[derive(Deserialize)]
struct ProjectKeys {
    keys: Vec<ProjectKey>,
}

#[derive(Deserialize)]
struct CreatedKey {
    key: ProjectKey,
    plain_key: String,
}

#[derive(Deserialize, Debug)]
struct Metrics {
    keys: Option<u64>,
    used_memory_bytes: Option<u64>,
    ops_per_sec: Option<u64>,
    connected_clients: Option<u64>,
}

fn config_path() -> PathBuf {
    let dir = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".lux");
    if ensure_private_dir(&dir).is_err() {
        std::fs::create_dir_all(&dir).ok();
    }
    dir.join("config.json")
}

fn load_config() -> Option<Config> {
    let path = config_path();
    let data = std::fs::read_to_string(&path).ok()?;
    #[cfg(unix)]
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).ok();
    serde_json::from_str(&data).ok()
}

fn save_config(config: &Config) {
    let path = config_path();
    let data = serde_json::to_string_pretty(config).unwrap();
    if let Err(e) = write_secret_file(&path, data.as_bytes()) {
        eprintln!("{} {e}", "Failed to save Lux credentials:".red());
        std::process::exit(1);
    }
}

fn delete_config() {
    let path = config_path();
    std::fs::remove_file(path).ok();
}

fn local_config_path() -> PathBuf {
    PathBuf::from("lux").join("config.toml")
}

fn load_local_config() -> Option<LocalConfig> {
    let path = local_config_path();
    let data = std::fs::read_to_string(&path).ok()?;
    let doc = data.parse::<toml_edit::DocumentMut>().unwrap_or_else(|e| {
        eprintln!("{} {}: {e}", "Invalid Lux config".red(), path.display());
        std::process::exit(1);
    });
    let string = |key: &str| -> Option<String> {
        let item = doc.get(key)?;
        let value = item.as_str().unwrap_or_else(|| {
            eprintln!(
                "{} {} must be a string in {}",
                "Invalid Lux config:".red(),
                key,
                path.display()
            );
            std::process::exit(1);
        });
        (!value.trim().is_empty()).then(|| value.to_string())
    };
    let port = |key: &str| -> Option<u16> {
        let item = doc.get(key)?;
        let value = item.as_integer().unwrap_or_else(|| {
            eprintln!(
                "{} {} must be an integer in {}",
                "Invalid Lux config:".red(),
                key,
                path.display()
            );
            std::process::exit(1);
        });
        u16::try_from(value).ok().or_else(|| {
            eprintln!(
                "{} {} must be between 0 and 65535 in {}",
                "Invalid Lux config:".red(),
                key,
                path.display()
            );
            std::process::exit(1);
        })
    };
    Some(LocalConfig {
        project_id: string("project_id"),
        project_name: string("project_name"),
        local_http_port: port("local_http_port"),
        local_resp_port: port("local_resp_port"),
        engine_version: string("engine_version"),
        local_nodes: port("local_nodes"),
    })
}

fn save_local_config(config: &LocalConfig) {
    let path = local_config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let mut doc = existing
        .parse::<toml_edit::DocumentMut>()
        .unwrap_or_else(|e| {
            eprintln!("{} {}: {e}", "Invalid Lux config".red(), path.display());
            std::process::exit(1);
        });
    doc["project_id"] = toml_edit::value(config.project_id.as_deref().unwrap_or(""));
    doc["project_name"] = toml_edit::value(config.project_name.as_deref().unwrap_or(""));
    match config.local_http_port {
        Some(port) => doc["local_http_port"] = toml_edit::value(i64::from(port)),
        None => {
            doc.remove("local_http_port");
        }
    }
    match config.local_resp_port {
        Some(port) => doc["local_resp_port"] = toml_edit::value(i64::from(port)),
        None => {
            doc.remove("local_resp_port");
        }
    }
    match config.local_nodes {
        Some(nodes) => doc["local_nodes"] = toml_edit::value(i64::from(nodes)),
        None => {
            doc.remove("local_nodes");
        }
    }
    match config
        .engine_version
        .as_deref()
        .filter(|v| !v.trim().is_empty())
    {
        Some(version) => doc["engine_version"] = toml_edit::value(version),
        None => {
            doc.remove("engine_version");
        }
    }
    std::fs::write(&path, doc.to_string()).unwrap_or_else(|e| {
        eprintln!("{} {e}", "Failed to write lux/config.toml:".red());
        std::process::exit(1);
    });
}

#[derive(Debug)]
struct ConnectionTarget {
    host: String,
    port: u16,
    password: String,
    name: String,
    tls: bool,
}

fn parse_connection_url(url: &str) -> ConnectionTarget {
    let tls = url.starts_with("luxs://") || url.starts_with("rediss://");
    let url = url
        .trim_start_matches("luxs://")
        .trim_start_matches("rediss://")
        .trim_start_matches("lux://")
        .trim_start_matches("redis://");
    let (auth, hostport) = if let Some(at) = url.find('@') {
        (
            Some(url[..at].trim_start_matches(':').to_string()),
            &url[at + 1..],
        )
    } else {
        (None, url)
    };
    let parts: Vec<&str> = hostport.split(':').collect();
    let host = parts.first().copied().unwrap_or("localhost").to_string();
    let port = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(6379);
    let name = format!("{host}:{port}");
    ConnectionTarget {
        host,
        port,
        password: auth.unwrap_or_default(),
        name,
        tls,
    }
}

fn linked_project() -> Option<String> {
    load_local_config()
        .and_then(|config| config.project_id.or(config.project_name))
        .filter(|value| !value.trim().is_empty())
}

fn explicit_project(project: Option<&str>) -> Option<&str> {
    project.filter(|value| !value.trim().is_empty())
}

fn require_project_arg(project: Option<&str>) -> String {
    explicit_project(project)
        .map(str::to_string)
        .unwrap_or_else(|| {
            eprintln!(
                "{} This is a cloud-only operation. Provide a project name or ID explicitly.",
                "Error:".red(),
            );
            std::process::exit(1);
        })
}

/// Resolve the target engine's HTTP base URL + operator password. Defaults to
/// the local `lux start` engine; --url/--password reach any self-hosted engine.
fn resolve_engine(conn: &EngineConn) -> (String, String) {
    if let Some(url) = &conn.url {
        let parsed = reqwest::Url::parse(url).unwrap_or_else(|_| {
            eprintln!("{}", "--url must be a valid HTTP or HTTPS URL".red());
            std::process::exit(1);
        });
        let local_http = parsed.scheme() == "http"
            && matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
        if parsed.scheme() != "https" && !local_http {
            eprintln!(
                "{}",
                "Remote provider configuration requires HTTPS; plain HTTP is allowed only for localhost."
                    .red()
            );
            std::process::exit(1);
        }
        let Some(password) = conn.password.clone() else {
            eprintln!("{}", "--password is required with --url".red());
            std::process::exit(1);
        };
        (url.trim_end_matches('/').to_string(), password)
    } else {
        let Some(state) = load_local_state() else {
            eprintln!(
                "{}",
                "No local engine found. Run `lux start` first, or pass --url/--password.".red()
            );
            std::process::exit(1);
        };
        (state.lux_url(), state.password)
    }
}

struct AppleProviderPayload {
    team_id: Option<String>,
    key_id: Option<String>,
    services_id: Option<String>,
    bundle_ids: Vec<String>,
    private_key: Option<String>,
    scopes: Option<String>,
    disable: bool,
}

fn apple_provider_payload(base: &str, config: AppleProviderPayload) -> serde_json::Value {
    let configures_web = config.team_id.is_some()
        || config.key_id.is_some()
        || config.services_id.is_some()
        || config.private_key.is_some();
    let mut body = serde_json::Map::new();
    body.insert("enabled".into(), serde_json::json!(!config.disable));
    if configures_web {
        body.insert(
            "redirect_uri".into(),
            serde_json::json!(format!("{base}/auth/v1/callback/apple")),
        );
    }
    if let Some(scopes) = config.scopes {
        body.insert("scopes".into(), serde_json::json!(scopes));
    }
    if let Some(team_id) = config.team_id {
        body.insert("apple_team_id".into(), serde_json::json!(team_id));
    }
    if let Some(key_id) = config.key_id {
        body.insert("apple_key_id".into(), serde_json::json!(key_id));
    }
    if let Some(services_id) = config.services_id {
        body.insert("apple_services_id".into(), serde_json::json!(services_id));
    }
    if !config.bundle_ids.is_empty() {
        body.insert(
            "apple_bundle_ids".into(),
            serde_json::json!(config.bundle_ids.join(",")),
        );
    }
    if let Some(private_key) = config.private_key {
        body.insert("apple_private_key".into(), serde_json::json!(private_key));
    }
    serde_json::Value::Object(body)
}

async fn handle_auth(action: AuthAction) {
    match action {
        AuthAction::Provider { action } => handle_auth_provider(action).await,
    }
}

async fn handle_auth_provider(action: AuthProviderAction) {
    match action {
        AuthProviderAction::List { conn } => {
            let (base, password) = resolve_engine(&conn);
            let res = reqwest::Client::new()
                .get(format!("{base}/auth/v1/admin/providers"))
                .bearer_auth(&password)
                .send()
                .await;
            match res {
                Ok(r) => {
                    let status = r.status();
                    let text = r.text().await.unwrap_or_default();
                    if !status.is_success() {
                        print_provider_error(status.as_u16(), &text);
                    }
                    let providers = serde_json::from_str::<serde_json::Value>(&text)
                        .ok()
                        .and_then(|v| v.get("providers").and_then(|p| p.as_array()).cloned())
                        .unwrap_or_default();
                    if providers.is_empty() {
                        println!("No providers configured.");
                    }
                    for p in providers {
                        let name = p.get("provider").and_then(|x| x.as_str()).unwrap_or("?");
                        let enabled = p.get("enabled").and_then(|x| x.as_bool()).unwrap_or(false);
                        let status = if enabled {
                            "enabled".green()
                        } else {
                            "disabled".dimmed()
                        };
                        println!("  {name:<8} {status}");
                    }
                }
                Err(e) => {
                    eprintln!("{} {e}", "Error:".red());
                    std::process::exit(1);
                }
            }
        }
        AuthProviderAction::Apple {
            team_id,
            key_id,
            services_id,
            bundle_id,
            p8,
            scopes,
            disable,
            conn,
        } => {
            let (base, password) = resolve_engine(&conn);
            let configures_web =
                team_id.is_some() || key_id.is_some() || services_id.is_some() || p8.is_some();
            if configures_web && !base.starts_with("https://") {
                eprintln!(
                    "{}",
                    "Apple web sign-in requires an HTTPS engine URL with a public domain. Pass --url or set LUX_ENGINE_URL."
                        .red()
                );
                std::process::exit(1);
            }
            // Omitting apple_private_key on update keeps the stored key.
            let private_key = p8.map(|path| {
                std::fs::read_to_string(&path).unwrap_or_else(|e| {
                    eprintln!("{} {}: {e}", "Failed to read .p8:".red(), path.display());
                    std::process::exit(1);
                })
            });
            let body = apple_provider_payload(
                &base,
                AppleProviderPayload {
                    team_id,
                    key_id,
                    services_id,
                    bundle_ids: bundle_id,
                    private_key,
                    scopes,
                    disable,
                },
            );
            put_provider(&base, &password, "apple", body).await;
        }
        AuthProviderAction::Google {
            client_id,
            client_secret,
            redirect_uri,
            scopes,
            disable,
            conn,
        } => {
            put_oauth(
                &conn,
                "google",
                client_id,
                client_secret,
                redirect_uri,
                scopes,
                disable,
            )
            .await
        }
        AuthProviderAction::Github {
            client_id,
            client_secret,
            redirect_uri,
            scopes,
            disable,
            conn,
        } => {
            put_oauth(
                &conn,
                "github",
                client_id,
                client_secret,
                redirect_uri,
                scopes,
                disable,
            )
            .await
        }
    }
}

async fn put_oauth(
    conn: &EngineConn,
    provider: &str,
    client_id: String,
    client_secret: Option<String>,
    redirect_uri: Option<String>,
    scopes: Option<String>,
    disable: bool,
) {
    let (base, password) = resolve_engine(conn);
    let redirect = redirect_uri.unwrap_or_else(|| format!("{base}/auth/v1/callback/{provider}"));
    let mut body = serde_json::Map::new();
    body.insert("enabled".into(), serde_json::json!(!disable));
    body.insert("client_id".into(), serde_json::json!(client_id));
    if let Some(client_secret) = client_secret {
        body.insert("client_secret".into(), serde_json::json!(client_secret));
    }
    body.insert("redirect_uri".into(), serde_json::json!(redirect));
    if let Some(scopes) = scopes {
        body.insert("scopes".into(), serde_json::json!(scopes));
    }
    put_provider(&base, &password, provider, serde_json::Value::Object(body)).await;
}

async fn put_provider(base: &str, password: &str, provider: &str, body: serde_json::Value) {
    let callback = body
        .get("redirect_uri")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let res = reqwest::Client::new()
        .put(format!("{base}/auth/v1/admin/providers/{provider}"))
        .bearer_auth(password)
        .json(&body)
        .send()
        .await;
    match res {
        Ok(r) => {
            let status = r.status();
            let text = r.text().await.unwrap_or_default();
            if !status.is_success() {
                print_provider_error(status.as_u16(), &text);
            }
            println!("{} {provider} provider configured", "\u{2713}".green());
            if let Some(callback) = callback {
                println!("  callback URL: {callback}");
            }
        }
        Err(e) => {
            eprintln!("{} {e}", "Error:".red());
            std::process::exit(1);
        }
    }
}

fn print_provider_error(status: u16, text: &str) -> ! {
    let message = serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string))
        .unwrap_or_else(|| format!("HTTP {status}"));
    eprintln!("{} {message}", "Error:".red());
    std::process::exit(1);
}

fn get_client(api_url_override: &Option<String>) -> (reqwest::Client, String, String) {
    let config = load_config().unwrap_or_else(|| {
        eprintln!("{}", "Not logged in. Run `lux login` first.".red());
        std::process::exit(1);
    });

    let api_url = api_url_override.clone().unwrap_or(config.api_url.clone());
    let client = reqwest::Client::new();
    (client, api_url, config.token)
}

/// A `lux_` token is scoped to one workspace. Resolve it so workspace-scoped
/// endpoints (project list/create) can name it. Exits on failure.
async fn resolve_workspace_id(client: &reqwest::Client, api_url: &str, token: &str) -> String {
    let res = client
        .get(format!("{api_url}/workspaces"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap_or_else(|e| {
            eprintln!("{} {e}", "Failed to connect:".red());
            std::process::exit(1);
        });

    let body: ApiResponse<Vec<Workspace>> = res.json().await.unwrap_or_else(|e| {
        eprintln!("{} {e}", "Failed to parse response:".red());
        std::process::exit(1);
    });

    if let Some(error) = body.error {
        eprintln!("{} {error}", "API error:".red());
        std::process::exit(1);
    }

    body.data
        .and_then(|workspaces| workspaces.into_iter().next())
        .unwrap_or_else(|| {
            eprintln!("{} No workspace found for this token.", "Error:".red());
            std::process::exit(1);
        })
        .id
}

async fn find_project(
    client: &reqwest::Client,
    api_url: &str,
    token: &str,
    name_or_id: &str,
) -> Instance {
    let workspace_id = resolve_workspace_id(client, api_url, token).await;
    let res = client
        .get(format!("{api_url}/projects?workspace_id={workspace_id}"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap_or_else(|e| {
            eprintln!("{} {e}", "Failed to connect:".red());
            std::process::exit(1);
        });

    let body: ApiResponse<Vec<Instance>> = res.json().await.unwrap_or_else(|e| {
        eprintln!("{} {e}", "Failed to parse response:".red());
        std::process::exit(1);
    });

    if let Some(error) = body.error {
        eprintln!("{} {error}", "API error:".red());
        std::process::exit(1);
    }

    let instances = body.data.unwrap_or_default();
    instances
        .into_iter()
        .find(|i| i.id == name_or_id || i.name == name_or_id)
        .unwrap_or_else(|| {
            eprintln!("{} Project '{}' not found", "Error:".red(), name_or_id);
            std::process::exit(1);
        })
}

async fn get_project_detail(
    client: &reqwest::Client,
    api_url: &str,
    token: &str,
    id: &str,
) -> Result<Instance, String> {
    cloud_management_request(
        client,
        reqwest::Method::GET,
        format!("{api_url}/projects/{id}"),
        token,
        None,
    )
    .await
}

async fn resolve_push_target(
    project: Option<&str>,
    api_url_override: &Option<String>,
) -> PushTarget {
    if let Some(project) = explicit_project(project) {
        let (client, api_url, token) = get_client(api_url_override);
        let instance = find_project(&client, &api_url, &token, project).await;
        if instance.status != "running" {
            eprintln!(
                "{} Cloud project '{}' is {}.",
                "Error:".red(),
                instance.name,
                instance.status
            );
            std::process::exit(1);
        }
        return PushTarget::Cloud {
            client,
            api_url,
            token,
            instance_id: instance.id,
        };
    }
    let state = load_local_state().unwrap_or_else(|| {
        eprintln!(
            "{} No local engine state. Run {} first.",
            "Error:".red(),
            "lux start".cyan()
        );
        std::process::exit(1);
    });
    PushTarget::Local {
        client: reqwest::Client::new(),
        base_url: state.lux_url(),
        operator_key: state.password,
    }
}

fn print_push_config(config: &PushConfigStatus, output: Option<&str>) {
    if output == Some("json") {
        println!("{}", serde_json::to_string_pretty(config).unwrap());
        return;
    }
    println!(
        "{} {} ({})",
        "Push config:".bold(),
        config.app_id,
        if config.healthy {
            "healthy".green().to_string()
        } else {
            "unhealthy".red().to_string()
        }
    );
    println!(
        "{} {}",
        "Encryption:".bold(),
        if config.encryption_available {
            "available".green().to_string()
        } else {
            "unavailable".red().to_string()
        }
    );
    println!(
        "{} {}",
        "APNs:".bold(),
        if config.apns.configured {
            format!(
                "configured — {} / {} ({}, {})",
                config.apns.team_id,
                config.apns.topic,
                config.apns.environment,
                config.apns.secret_storage
            )
        } else {
            "not configured".to_string()
        }
    );
    println!(
        "{} {}",
        "Web Push:".bold(),
        if config.vapid.configured {
            format!(
                "configured — {} ({})",
                config.vapid.subject, config.vapid.secret_storage
            )
        } else {
            "not configured".to_string()
        }
    );
    if config.vapid.configured && !config.vapid.public_key.is_empty() {
        println!("{} {}", "VAPID public key:".bold(), config.vapid.public_key);
    }
    for warning in &config.warnings {
        println!("{} {warning}", "Warning:".yellow());
    }
}

fn read_apns_key(path: &Path) -> Result<String, String> {
    let key = std::fs::read_to_string(path)
        .map_err(|e| format!("could not read APNs key {}: {e}", path.display()))?;
    if !key.contains("-----BEGIN PRIVATE KEY-----") || !key.contains("-----END PRIVATE KEY-----") {
        return Err("APNs key must be a PKCS8 PEM .p8 private key".to_string());
    }
    Ok(key)
}

#[derive(Clone, Debug, Serialize)]
struct VersionComponent {
    component: String,
    target: String,
    current: String,
    latest: String,
    update_available: Option<bool>,
    detail: String,
}

fn short_digest(value: Option<&str>) -> String {
    value
        .map(|digest| digest.chars().take(19).collect())
        .unwrap_or_else(|| "unknown".to_string())
}

async fn latest_cli_release() -> Result<(String, String), String> {
    let client = reqwest::Client::builder()
        .user_agent("lux-cli")
        .build()
        .map_err(|e| e.to_string())?;
    let response = client
        .get("https://api.github.com/repos/lux-db/lux/releases")
        .send()
        .await
        .map_err(|e| format!("release check failed: {e}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "release check failed (HTTP {})",
            response.status().as_u16()
        ));
    }
    let releases: Vec<serde_json::Value> = response
        .json()
        .await
        .map_err(|e| format!("invalid GitHub release response: {e}"))?;
    let tag = releases
        .iter()
        .filter_map(|release| release.get("tag_name")?.as_str())
        .find(|tag| tag.starts_with("cli-v"))
        .ok_or_else(|| "no Lux CLI releases found".to_string())?
        .to_string();
    let version = tag.trim_start_matches("cli-v").to_string();
    Ok((tag, version))
}

fn newer_cli_version(current: &str, latest: &str) -> bool {
    match (
        semver::Version::parse(current),
        semver::Version::parse(latest),
    ) {
        (Ok(current), Ok(latest)) => latest > current,
        _ => latest != current,
    }
}

async fn cli_version_component() -> VersionComponent {
    let current = env!("CARGO_PKG_VERSION").to_string();
    match latest_cli_release().await {
        Ok((_, latest)) => VersionComponent {
            component: "CLI".to_string(),
            target: "this binary".to_string(),
            update_available: Some(newer_cli_version(&current, &latest)),
            current,
            latest,
            detail: String::new(),
        },
        Err(error) => VersionComponent {
            component: "CLI".to_string(),
            target: "this binary".to_string(),
            current,
            latest: "unknown".to_string(),
            update_available: None,
            detail: error,
        },
    }
}

async fn local_version_components() -> Vec<VersionComponent> {
    let Some(state) = load_local_state() else {
        return vec![
            VersionComponent {
                component: "Engine".to_string(),
                target: "local".to_string(),
                current: "not initialized".to_string(),
                latest: "unknown".to_string(),
                update_available: None,
                detail: "run `lux start`".to_string(),
            },
            VersionComponent {
                component: "Studio".to_string(),
                target: "local".to_string(),
                current: "not initialized".to_string(),
                latest: "unknown".to_string(),
                update_available: None,
                detail: "run `lux studio` after starting the engine".to_string(),
            },
        ];
    };

    let engine_image = image_update_status(&state.container, &state.image);
    let engine_version = if docker_container_state(&state.container).as_deref() == Some("running") {
        DirectConn::connect(&state.connection_host(), state.resp_port, &state.password)
            .and_then(|mut conn| conn.exec("LUX VERSION"))
            .and_then(|raw| decode_json::<EngineManagementVersion>(&raw, "engine version"))
            .map(|version| version.version)
            .unwrap_or_else(|_| short_digest(engine_image.current_digest.as_deref()))
    } else {
        "stopped".to_string()
    };
    let mut components = vec![VersionComponent {
        component: "Engine".to_string(),
        target: "local".to_string(),
        current: engine_version,
        latest: short_digest(engine_image.latest_digest.as_deref()),
        update_available: engine_image.update_available,
        detail: engine_image.error.unwrap_or_else(|| {
            format!(
                "{} → {}",
                short_digest(engine_image.current_digest.as_deref()),
                short_digest(engine_image.latest_digest.as_deref())
            )
        }),
    }];
    let studio_state = docker_container_state(&state.studio_container);
    if studio_state.is_none() {
        components.push(VersionComponent {
            component: "Studio".to_string(),
            target: "local".to_string(),
            current: "not installed".to_string(),
            latest: docker_remote_digest(STUDIO_IMAGE)
                .map(|digest| short_digest(Some(&digest)))
                .unwrap_or_else(|_| "unknown".to_string()),
            update_available: None,
            detail: "run `lux studio` to install".to_string(),
        });
    } else {
        let studio_image = image_update_status(&state.studio_container, STUDIO_IMAGE);
        components.push(VersionComponent {
            component: "Studio".to_string(),
            target: "local".to_string(),
            current: short_digest(studio_image.current_digest.as_deref()),
            latest: short_digest(studio_image.latest_digest.as_deref()),
            update_available: studio_image.update_available,
            detail: studio_image.error.unwrap_or_default(),
        });
    }
    components
}

async fn cloud_version_component(
    selector: &str,
    api_url_override: &Option<String>,
) -> VersionComponent {
    let (client, api_url, token) = get_client(api_url_override);
    let project = find_project(&client, &api_url, &token, selector).await;
    match get_project_detail(&client, &api_url, &token, &project.id).await {
        Ok(detail) => {
            let management_available =
                detail.current_digest.is_some() && detail.latest_digest.is_some();
            VersionComponent {
                component: "Engine".to_string(),
                target: format!("cloud:{}", detail.name),
                current: detail
                    .engine_version
                    .as_ref()
                    .map(|version| version.version.clone())
                    .unwrap_or_else(|| short_digest(detail.current_digest.as_deref())),
                latest: short_digest(detail.latest_digest.as_deref()),
                update_available: management_available.then_some(detail.needs_update),
                detail: detail
                    .engine_update_error
                    .or(detail.engine_update_phase)
                    .unwrap_or_else(|| {
                        if management_available {
                            format!(
                                "{} → {}",
                                detail.current_image.as_deref().unwrap_or("unknown"),
                                detail.latest_image.as_deref().unwrap_or("unknown")
                            )
                        } else {
                            "safe cloud update metadata is unavailable".to_string()
                        }
                    }),
            }
        }
        Err(error) => VersionComponent {
            component: "Engine".to_string(),
            target: format!("cloud:{}", project.name),
            current: "unknown".to_string(),
            latest: "unknown".to_string(),
            update_available: None,
            detail: error,
        },
    }
}

async fn show_versions(
    project: Option<&str>,
    all: bool,
    output: Option<&str>,
    api_url_override: &Option<String>,
) {
    if output.is_some() && output != Some("json") {
        eprintln!("{} Supported version output is `json`.", "Error:".red());
        std::process::exit(1);
    }
    let mut components = Vec::new();
    if project.is_none() || all {
        components.push(cli_version_component().await);
        components.extend(local_version_components().await);
    }
    if project.is_some() || all {
        let selector = project
            .map(str::to_string)
            .or_else(linked_project)
            .unwrap_or_else(|| {
                eprintln!(
                    "{} `--all` needs a linked cloud project or an explicit project.",
                    "Error:".red()
                );
                std::process::exit(1);
            });
        components.push(cloud_version_component(&selector, api_url_override).await);
    }
    if output == Some("json") {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({ "components": components })).unwrap()
        );
        return;
    }
    println!(
        "  {:<10}  {:<24}  {:<18}  {:<18}  {}",
        "COMPONENT".dimmed(),
        "TARGET".dimmed(),
        "CURRENT".dimmed(),
        "LATEST".dimmed(),
        "STATUS".dimmed()
    );
    for component in components {
        let status = match component.update_available {
            Some(true) => "update available".yellow().to_string(),
            Some(false) => "current".green().to_string(),
            None => "unknown".dimmed().to_string(),
        };
        println!(
            "  {:<10}  {:<24}  {:<18}  {:<18}  {}",
            component.component, component.target, component.current, component.latest, status
        );
        if !component.detail.is_empty() {
            println!("  {:<10}  {}", "", component.detail.dimmed());
        }
    }
}

async fn update_cli(check: bool) -> Result<(), String> {
    let current = env!("CARGO_PKG_VERSION");
    let (latest_tag, latest_version) = latest_cli_release().await?;
    println!("{} v{current}", "Current CLI:".bold());
    if !newer_cli_version(current, &latest_version) {
        println!("{}", "CLI is already up to date.".green());
        return Ok(());
    }
    println!(
        "{} v{current} → v{latest_version}",
        "Update available:".yellow()
    );
    if check {
        println!("Run {} to install.", "lux update cli".cyan());
        return Ok(());
    }

    let os = if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        return Err("unsupported OS for self-update".to_string());
    };
    let arch = if cfg!(target_arch = "aarch64") {
        "arm64"
    } else if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else {
        return Err("unsupported architecture for self-update".to_string());
    };
    let artifact = format!("lux-cli-{os}-{arch}");
    let download_url =
        format!("https://github.com/lux-db/lux/releases/download/{latest_tag}/{artifact}.tar.gz");
    let client = reqwest::Client::builder()
        .user_agent("lux-cli")
        .build()
        .map_err(|e| e.to_string())?;
    println!("{} Downloading v{latest_version}...", "...".dimmed());
    let response = client
        .get(download_url)
        .send()
        .await
        .map_err(|e| format!("download failed: {e}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "download failed (HTTP {})",
            response.status().as_u16()
        ));
    }
    let tar_bytes = response
        .bytes()
        .await
        .map_err(|e| format!("download failed: {e}"))?;
    let current_exe =
        std::env::current_exe().map_err(|e| format!("could not determine binary path: {e}"))?;
    let tmp_dir = std::env::temp_dir().join(format!(
        "lux-cli-update-{}-{}",
        std::process::id(),
        random_hex(8)
    ));
    ensure_private_dir(&tmp_dir)
        .map_err(|e| format!("failed to create private update directory: {e}"))?;
    let tar_path = tmp_dir.join("lux-cli.tar.gz");
    std::fs::write(&tar_path, &tar_bytes).map_err(|e| format!("failed to stage update: {e}"))?;
    let status = std::process::Command::new("tar")
        .args([
            "xzf",
            tar_path.to_str().unwrap_or_default(),
            "-C",
            tmp_dir.to_str().unwrap_or_default(),
        ])
        .status()
        .map_err(|e| format!("failed to extract update: {e}"))?;
    if !status.success() {
        return Err("failed to extract update".to_string());
    }
    let new_binary = tmp_dir.join(&artifact);
    if !new_binary.is_file() {
        return Err("binary not found in release archive".to_string());
    }
    #[cfg(unix)]
    std::fs::set_permissions(&new_binary, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| format!("failed to make update executable: {e}"))?;
    std::fs::rename(&new_binary, &current_exe)
        .or_else(|_| std::fs::copy(&new_binary, &current_exe).map(|_| ()))
        .map_err(|_| "could not replace binary; try with appropriate permissions".to_string())?;
    std::fs::remove_dir_all(&tmp_dir).ok();
    println!("{} Updated CLI to v{latest_version}.", "Done.".green());
    Ok(())
}

fn pull_image(image: &str) -> Result<(), String> {
    println!("{} {}", "Pulling".bold(), image.dimmed());
    let status = std::process::Command::new("docker")
        .args(["pull", image])
        .status()
        .map_err(|e| format!("failed to run Docker: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("Docker could not pull {image}"))
    }
}

fn update_local_engine(check: bool) -> Result<(), String> {
    docker_preflight()?;
    let state = load_local_state().ok_or_else(|| "run `lux start` first".to_string())?;
    let status = image_update_status(&state.container, &state.image);
    if check {
        if status.update_available == Some(true) {
            println!(
                "{} {} → {}",
                "Engine update available:".yellow(),
                short_digest(status.current_digest.as_deref()),
                short_digest(status.latest_digest.as_deref())
            );
        } else if status.update_available == Some(false) {
            println!("{}", "Local engine is up to date.".green());
        } else {
            return Err(status
                .error
                .unwrap_or_else(|| "engine version status unavailable".to_string()));
        }
        return Ok(());
    }
    let runtime_containers = state
        .cluster
        .as_ref()
        .map(|cluster| {
            cluster
                .nodes
                .iter()
                .map(|node| node.container.clone())
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| vec![state.container.clone()]);
    let was_running = runtime_containers
        .iter()
        .any(|container| docker_container_state(container).as_deref() == Some("running"));
    let existed = runtime_containers
        .iter()
        .any(|container| docker_container_state(container).is_some());
    let before = docker_container_digest(&state.container).ok();
    pull_image(&state.image)?;
    let after = docker_image_digest(&state.image)?;
    if before.as_deref() == Some(after.as_str()) {
        println!("{}", "Local engine is already up to date.".green());
        return Ok(());
    }
    if existed {
        for container in &runtime_containers {
            if docker_container_state(container).is_some() {
                docker_output(&["rm", "-f", container])?;
            }
        }
    }
    if was_running {
        if let Some(cluster) = &state.cluster {
            ensure_local_cluster_network(cluster)?;
            for node in &cluster.nodes {
                run_local_cluster_node(&state, cluster, node)?;
                if !wait_for_local_cluster_node_tcp(&state, node) {
                    return Err(format!(
                        "updated {} did not become ready; inspect `docker logs {}`",
                        node.node_id, node.container
                    ));
                }
            }
        } else {
            run_local_engine_container(&state)?;
        }
        if !wait_for_local_ready(&state) {
            return Err(format!(
                "updated engine did not become ready; inspect `docker logs {}`",
                state.container
            ));
        }
        refresh_local_profile(&state)?;
        println!("{} Local engine updated and restarted.", "Done.".green());
    } else {
        println!(
            "{} Engine image updated; it will be used by the next `lux start`.",
            "Done.".green()
        );
    }
    Ok(())
}

fn update_local_studio(check: bool) -> Result<(), String> {
    docker_preflight()?;
    let mut state = load_local_state().ok_or_else(|| "run `lux start` first".to_string())?;
    let status = image_update_status(&state.studio_container, STUDIO_IMAGE);
    if check {
        if status.update_available == Some(true) {
            println!(
                "{} {} → {}",
                "Studio update available:".yellow(),
                short_digest(status.current_digest.as_deref()),
                short_digest(status.latest_digest.as_deref())
            );
        } else if status.update_available == Some(false) {
            println!("{}", "Studio is up to date.".green());
        } else {
            return Err(status
                .error
                .unwrap_or_else(|| "Studio version status unavailable".to_string()));
        }
        return Ok(());
    }
    let was_running = docker_container_state(&state.studio_container).as_deref() == Some("running");
    let existed = docker_container_state(&state.studio_container).is_some();
    let before = docker_container_digest(&state.studio_container).ok();
    pull_image(STUDIO_IMAGE)?;
    let after = docker_image_digest(STUDIO_IMAGE)?;
    if before.as_deref() == Some(after.as_str()) {
        println!("{}", "Studio is already up to date.".green());
        return Ok(());
    }
    if existed {
        docker_output(&["rm", "-f", &state.studio_container])?;
    }
    if was_running {
        if !ensure_studio(&mut state, false) {
            return Err("updated Studio did not become ready".to_string());
        }
        println!("{} Studio updated and restarted.", "Done.".green());
    } else {
        println!(
            "{} Studio image updated; it will be used next time.",
            "Done.".green()
        );
    }
    Ok(())
}

#[derive(Deserialize)]
struct CloudUpdateStart {
    updated: bool,
    image: String,
    snapshot_id: Option<String>,
    phase: Option<String>,
}

async fn update_cloud_engine(
    selector: &str,
    check: bool,
    api_url_override: &Option<String>,
) -> Result<(), String> {
    let (client, api_url, token) = get_client(api_url_override);
    let project = find_project(&client, &api_url, &token, selector).await;
    let detail = get_project_detail(&client, &api_url, &token, &project.id).await?;
    let safe_update_available = detail.current_digest.is_some() && detail.latest_digest.is_some();
    if !safe_update_available {
        return Err(
            "cloud safe-update metadata is unavailable; update the Cloud control plane and project engine first"
                .to_string(),
        );
    }
    if check {
        if detail.needs_update {
            println!(
                "{} {} ({})",
                "Cloud engine update available:".yellow(),
                detail.name,
                short_digest(detail.latest_digest.as_deref())
            );
        } else {
            println!("{} {} is up to date.", "Done.".green(), detail.name);
        }
        if let Some(phase) = detail.engine_update_phase {
            println!("{} {phase}", "Current update phase:".bold());
        }
        if let Some(error) = detail.engine_update_error {
            println!("{} {error}", "Previous update error:".red());
        }
        return Ok(());
    }
    let update: CloudUpdateStart = cloud_management_request(
        &client,
        reqwest::Method::POST,
        format!("{api_url}/projects/{}/update", project.id),
        &token,
        Some(serde_json::json!({})),
    )
    .await?;
    if !update.updated {
        println!(
            "{} {} already uses {}.",
            "Done.".green(),
            project.name,
            update.image
        );
        return Ok(());
    }
    println!(
        "{} Cloud update accepted for {}. A snapshot is created before deployment; failures automatically roll back.",
        "Started.".green(),
        project.name
    );
    if let Some(snapshot_id) = update.snapshot_id {
        println!("{} {snapshot_id}", "Snapshot:".bold());
    }
    if let Some(phase) = update.phase {
        println!("{} {phase}", "Phase:".bold());
    }
    println!(
        "Use {} to follow progress.",
        format!("lux status {}", project.name).cyan()
    );
    Ok(())
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

pub async fn run() {
    let cli = Cli::parse();
    let api_url_override = cli.api_url.clone();

    match cli.command {
        Commands::Init => {
            let migrations_dir = PathBuf::from("lux/migrations");
            std::fs::create_dir_all(&migrations_dir).unwrap_or_else(|e| {
                eprintln!("{} {e}", "Failed to create lux/migrations:".red());
                std::process::exit(1);
            });

            let config_path = local_config_path();
            if !config_path.exists() {
                save_local_config(&LocalConfig::default());
            }

            let env_example = PathBuf::from(".env.example");
            if !env_example.exists() {
                std::fs::write(
                    &env_example,
                    [
                        "LUX_PROJECT_ID=",
                        "LUX_URL=",
                        "LUX_DIRECT_URL=",
                        "LUX_PUBLISHABLE_KEY=",
                        "LUX_SECRET_KEY=",
                        "",
                    ]
                    .join("\n"),
                )
                .unwrap_or_else(|e| {
                    eprintln!("{} {e}", "Failed to write .env.example:".red());
                    std::process::exit(1);
                });
            }

            let seed_path = PathBuf::from("lux/seed.lux");
            if !seed_path.exists() {
                std::fs::write(&seed_path, "").unwrap_or_else(|e| {
                    eprintln!("{} {e}", "Failed to write lux/seed.lux:".red());
                    std::process::exit(1);
                });
            }

            ensure_gitignore(&[
                ".env.local",
                "lux/.lux-local.json",
                "lux/.env-profiles/",
                "lux/.backups/",
                "lux/.lux-cluster/",
            ]);

            println!("{}", "Initialized Lux project.".green());
            println!("{} {}", "Migrations:".bold(), migrations_dir.display());
            println!("{} {}", "Config:".bold(), config_path.display());
            println!();
            println!("Next: {} to boot a local engine.", "lux start".cyan());
        }

        Commands::Start {
            fresh,
            no_studio,
            resp_port: resp_port_flag,
            http_port: http_port_flag,
            bind,
            nodes,
        } => {
            if let Err(e) = docker_preflight() {
                eprintln!("{} {e}", "Error:".red());
                std::process::exit(1);
            }

            if let Some(nodes) = nodes {
                validate_local_node_count(nodes).unwrap_or_else(|error| {
                    eprintln!("{} {error}", "Error:".red());
                    std::process::exit(1);
                });
                let mut config = load_local_config().unwrap_or_default();
                config.local_nodes = Some(nodes);
                save_local_config(&config);
            }
            let desired_nodes = load_local_config()
                .and_then(|config| config.local_nodes)
                .unwrap_or(1);
            validate_local_node_count(desired_nodes).unwrap_or_else(|error| {
                eprintln!("{} {error}", "Error:".red());
                std::process::exit(1);
            });
            let mut state = ensure_local_state();
            let bind_changed = bind.is_some_and(|host| host != state.bind_host);
            if let Some(bind_host) = bind.filter(|host| *host != state.bind_host) {
                state.bind_host = bind_host;
                save_local_state(&state);
            }
            if !state.bind_host.is_loopback() {
                eprintln!(
                    "{} local engine and Studio are exposed on {}. Studio contains operator credentials; use only a trusted network.",
                    "Warning:".yellow(),
                    state.bind_host.to_string().cyan()
                );
            }
            ensure_gitignore(&[
                ".env.local",
                "lux/.lux-local.json",
                "lux/.env-profiles/",
                "lux/.backups/",
                "lux/.lux-cluster/",
            ]);

            if fresh {
                if let Some(cluster) = state.cluster.take() {
                    for node in cluster.nodes.iter().chain(cluster.retired_nodes.iter()) {
                        if docker_container_state(&node.container).is_some() {
                            let _ = docker_output(&["rm", "-f", &node.container]);
                        }
                        if docker_volume_exists(&node.volume) {
                            let _ = docker_output(&["volume", "rm", &node.volume]);
                        }
                    }
                    let _ = docker_output(&["network", "rm", &cluster.network]);
                }
                for volume in state.retired_cluster_volumes.drain(..) {
                    if docker_volume_exists(&volume) {
                        let _ = docker_output(&["volume", "rm", &volume]);
                    }
                }
                save_local_state(&state);
            }

            // Already running? Just reprint the connection block.
            let engine_running =
                docker_container_state(&state.container).as_deref() == Some("running");
            let bindings_match = engine_running && engine_bindings_match(&state);
            if engine_running && !fresh && bindings_match {
                let reconcile = if desired_nodes == 1 && state.cluster.is_some() {
                    consolidate_local_cluster(&mut state).await
                } else if desired_nodes > 1 {
                    resize_local_cluster(&mut state, desired_nodes).await
                } else {
                    Ok(())
                };
                if let Err(error) = reconcile {
                    eprintln!("{} {error}", "Cluster resize failed:".red());
                    std::process::exit(1);
                }
                println!("{}", "Local Lux engine already running.".green());
                refresh_local_profile(&state).unwrap_or_else(|e| {
                    eprintln!("{} {e}", "Failed to refresh local env profile:".red());
                    std::process::exit(1);
                });
                print_connection_block(&state);
                print_image_update_hint(
                    "engine",
                    &state.container,
                    &state.image,
                    "lux update engine",
                );
                if !no_studio {
                    ensure_studio(&mut state, false);
                }
                return;
            }

            if engine_running && !fresh && !bindings_match {
                println!(
                    "{} Recreating the local containers on {} without deleting the data volume.",
                    "Binding changed.".yellow(),
                    state.bind_host
                );
            }

            // Never leave a credential-bearing Studio container published on
            // the previous address, including when --no-studio was requested.
            if (bind_changed || (engine_running && !bindings_match))
                && docker_container_state(&state.studio_container).is_some()
            {
                let _ = docker_output(&["rm", "-f", &state.studio_container]);
            }

            // Remove any stale container (stopped, or `--fresh`).
            if docker_container_state(&state.container).is_some() {
                let _ = docker_output(&["rm", "-f", &state.container]);
            }
            let volume_existed = docker_volume_exists(&state.volume);
            if fresh && volume_existed {
                let _ = docker_output(&["volume", "rm", &state.volume]);
            }
            let fresh_volume = fresh || !volume_existed;

            // Pick free host ports if this project's configured ports are taken
            // (e.g. another local project is already running). Removing the stale
            // container above freed this project's own ports, so a same-project
            // restart keeps them; only a real conflict bumps. Persist the choice.
            // An explicit --resp-port/--http-port pins that exact host port (hard
            // error if it's taken -- the user asked for it specifically). Without
            // a flag, fall back to the configured port and auto-bump past any
            // conflict so multiple projects can run at once.
            let pin = |label: &str, p: u16| {
                if !port_is_free(state.bind_host, p) {
                    eprintln!("{} {label} port {p} is already in use", "Error:".red());
                    std::process::exit(1);
                }
                p
            };
            let resp_port = match resp_port_flag {
                Some(p) => pin("RESP", p),
                None => free_port_from(state.bind_host, state.resp_port),
            };
            let http_port = match http_port_flag {
                Some(p) => {
                    if p == resp_port {
                        eprintln!("{} --resp-port and --http-port must differ", "Error:".red());
                        std::process::exit(1);
                    }
                    pin("HTTP", p)
                }
                None => free_port_from(state.bind_host, state.http_port),
            };
            if resp_port != state.resp_port || http_port != state.http_port {
                // Only narrate auto-bumps; an explicit flag is the user's choice.
                if resp_port_flag.is_none() && http_port_flag.is_none() {
                    println!(
                        "{} ports {}/{} busy, using {}/{}",
                        "Note:".yellow(),
                        state.resp_port,
                        state.http_port,
                        resp_port,
                        http_port
                    );
                }
                state.resp_port = resp_port;
                state.http_port = http_port;
                save_local_state(&state);
            }

            // Starting uses the locally installed image. Existing projects
            // update only through `lux update engine`; Docker pulls here only
            // when the image has never been installed.
            let start_result = if desired_nodes > 1 {
                if state.cluster.is_none() {
                    initialize_local_cluster(&mut state).await
                } else {
                    start_persisted_local_cluster(&state).await
                }
            } else if state.cluster.is_some() {
                start_persisted_local_cluster(&state).await
            } else {
                run_local_engine_container(&state)
            };
            if let Err(e) = start_result {
                eprintln!("{} Failed to start container: {e}", "Error:".red());
                std::process::exit(1);
            }

            let reconcile = if desired_nodes == 1 && state.cluster.is_some() {
                consolidate_local_cluster(&mut state).await
            } else if desired_nodes > 1 {
                resize_local_cluster(&mut state, desired_nodes).await
            } else {
                Ok(())
            };
            if let Err(error) = reconcile {
                eprintln!("{} {error}", "Cluster resize failed:".red());
                std::process::exit(1);
            }

            print!("{}", "Waiting for engine...".dimmed());
            std::io::stdout().flush().ok();
            if !wait_for_local_ready(&state) {
                println!(" {}", "TIMEOUT".red());
                eprintln!(
                    "{} Engine did not become ready. Check {}.",
                    "Error:".red(),
                    format!("docker logs {}", state.container).cyan()
                );
                std::process::exit(1);
            }
            println!(" {}", "ready".green());

            // Apply migrations (idempotent). Seed only on a fresh volume, since
            // seed scripts generally aren't idempotent.
            let conn = match DirectConn::connect(
                &state.connection_host(),
                state.resp_port,
                &state.password,
            ) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("{} {e}", "Error:".red());
                    std::process::exit(1);
                }
            };
            let mut target = MigrateTarget::Direct(Box::new(conn));
            let migrations_dir = PathBuf::from("lux/migrations");
            if migrations_dir.exists() {
                let n = apply_pending_migrations(&mut target, &migrations_dir).await;
                if n > 0 {
                    println!("{} Applied {n} migration(s).", "Done.".green());
                }
            }
            let seed_path = PathBuf::from("lux/seed.lux");
            if fresh_volume
                && seed_path.exists()
                && !std::fs::read_to_string(&seed_path)
                    .unwrap_or_default()
                    .trim()
                    .is_empty()
            {
                run_command_file(&mut target, &seed_path, "Seed").await;
            }

            refresh_local_profile(&state).unwrap_or_else(|e| {
                eprintln!("{} {e}", "Failed to refresh local env profile:".red());
                std::process::exit(1);
            });
            print_connection_block(&state);
            print_image_update_hint(
                "engine",
                &state.container,
                &state.image,
                "lux update engine",
            );
            if !no_studio {
                ensure_studio(&mut state, false);
            }
        }

        Commands::Studio { no_open } => {
            if let Err(e) = docker_preflight() {
                eprintln!("{} {e}", "Error:".red());
                std::process::exit(1);
            }
            let mut state = ensure_local_state();

            // Studio needs a running engine to talk to.
            if docker_container_state(&state.container).as_deref() != Some("running") {
                eprintln!(
                    "{} The local engine isn't running. Start it first with {}.",
                    "Error:".red(),
                    "lux start".cyan()
                );
                std::process::exit(1);
            }

            ensure_studio(&mut state, !no_open);
        }

        Commands::Stop { clear } => {
            let state = load_local_state().unwrap_or_else(|| {
                eprintln!(
                    "{} No local engine state found. Nothing to stop.",
                    "Error:".red()
                );
                std::process::exit(1);
            });
            let mut stopped = false;
            let mut containers = vec![state.container.clone()];
            if let Some(cluster) = &state.cluster {
                containers.extend(
                    cluster
                        .nodes
                        .iter()
                        .chain(cluster.retired_nodes.iter())
                        .map(|node| node.container.clone()),
                );
            }
            containers.sort();
            containers.dedup();
            for container in containers {
                if docker_container_state(&container).is_some() {
                    let _ = docker_output(&["rm", "-f", &container]);
                    stopped = true;
                }
            }
            if stopped {
                println!("{} Stopped local Lux engine runtime.", "Done.".green());
            } else {
                println!("{}", "Local Lux engine is not running.".yellow());
            }
            // Tear down Studio alongside the engine if it's up.
            if !state.studio_container.is_empty()
                && docker_container_state(&state.studio_container).is_some()
            {
                let _ = docker_output(&["rm", "-f", &state.studio_container]);
                println!("{} Stopped Lux Studio.", "Done.".green());
            }
            if clear {
                let mut volumes = vec![state.volume.clone()];
                volumes.extend(state.retired_cluster_volumes.iter().cloned());
                if let Some(cluster) = &state.cluster {
                    volumes.extend(
                        cluster
                            .nodes
                            .iter()
                            .chain(cluster.retired_nodes.iter())
                            .map(|node| node.volume.clone()),
                    );
                    let _ = docker_output(&["network", "rm", &cluster.network]);
                }
                volumes.sort();
                volumes.dedup();
                for volume in volumes {
                    if docker_volume_exists(&volume) {
                        let _ = docker_output(&["volume", "rm", &volume]);
                        println!("{} Cleared data volume {}.", "Done.".green(), volume);
                    }
                }
            }
        }

        Commands::Cluster { action } => {
            if let Err(error) = docker_preflight() {
                eprintln!("{} {error}", "Error:".red());
                std::process::exit(1);
            }
            let mut state = load_local_state().unwrap_or_else(|| {
                eprintln!(
                    "{} No local runtime exists. Start one with {}.",
                    "Error:".red(),
                    "lux start".cyan()
                );
                std::process::exit(1);
            });
            match action {
                ClusterAction::Status { output } => {
                    let json_output = output.as_deref() == Some("json");
                    if output.is_some() && !json_output {
                        eprintln!(
                            "{} Supported cluster status output is `json`.",
                            "Error:".red()
                        );
                        std::process::exit(1);
                    }
                    let Some(cluster) = &state.cluster else {
                        if json_output {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&serde_json::json!({
                                    "enabled": false,
                                    "nodes": 1,
                                    "status": if docker_container_state(&state.container).as_deref() == Some("running") { "running" } else { "stopped" }
                                }))
                                .unwrap()
                            );
                        } else {
                            println!("{} standalone (1 node)", "Local cluster:".bold());
                            println!(
                                "{}",
                                "Cluster is disabled; the direct single-node fast path is active."
                                    .dimmed()
                            );
                        }
                        return;
                    };
                    let mut statuses = Vec::new();
                    for node in &cluster.nodes {
                        let container = docker_container_state(&node.container)
                            .unwrap_or_else(|| "missing".to_string());
                        let engine = if container == "running" {
                            local_cluster_status(&state, node).await.ok().map(|status| {
                                serde_json::json!({
                                    "local_node_id": status["local_node_id"],
                                    "epoch": status["current"]["epoch"],
                                    "pending_epoch": status["pending"]["epoch"],
                                    "transition": status["transition"],
                                    "transfer": status["transfer"],
                                })
                            })
                        } else {
                            None
                        };
                        statuses.push(serde_json::json!({
                            "node_id": node.node_id,
                            "container": node.container,
                            "container_status": container,
                            "management_url": local_cluster_node_url(&state, node),
                            "engine": engine,
                        }));
                    }
                    let value = serde_json::json!({
                        "enabled": true,
                        "cluster_id": cluster.cluster_id,
                        "epoch": cluster.epoch,
                        "assignments": load_local_topology(cluster).ok().map(|topology| topology.manifest.assignments),
                        "pending_resize": cluster.pending_resize.as_ref().map(|resize| serde_json::json!({
                            "desired_nodes": resize.desired_nodes,
                            "direction": resize.direction,
                        })),
                        "nodes": statuses,
                    });
                    if json_output {
                        println!("{}", serde_json::to_string_pretty(&value).unwrap());
                    } else {
                        println!(
                            "{} {} nodes · epoch {}",
                            "Local cluster:".bold(),
                            cluster.nodes.len(),
                            cluster.epoch
                        );
                        for status in value["nodes"].as_array().unwrap() {
                            let engine_epoch = status["engine"]["epoch"]
                                .as_u64()
                                .map(|epoch| format!("epoch {epoch}"))
                                .unwrap_or_else(|| "engine unavailable".to_string());
                            println!(
                                "  {}  {:<8}  {}",
                                status["node_id"].as_str().unwrap_or("unknown").bold(),
                                status["container_status"].as_str().unwrap_or("unknown"),
                                engine_epoch.dimmed()
                            );
                        }
                    }
                }
                ClusterAction::Resize { nodes } => {
                    if docker_container_state(&state.container).as_deref() != Some("running") {
                        eprintln!(
                            "{} Start the local runtime before resizing it.",
                            "Error:".red()
                        );
                        std::process::exit(1);
                    }
                    let result = if nodes == 1 {
                        consolidate_local_cluster(&mut state).await
                    } else {
                        resize_local_cluster(&mut state, nodes).await
                    };
                    if let Err(error) = result {
                        eprintln!("{} {error}", "Cluster resize failed:".red());
                        std::process::exit(1);
                    }
                    let mut config = load_local_config().unwrap_or_default();
                    config.local_nodes = Some(nodes);
                    save_local_config(&config);
                    println!(
                        "{} Local runtime now uses {nodes} node(s).",
                        "Done.".green()
                    );
                }
                ClusterAction::Consolidate => {
                    if let Err(error) = consolidate_local_cluster(&mut state).await {
                        eprintln!("{} {error}", "Cluster consolidation failed:".red());
                        std::process::exit(1);
                    }
                    let mut config = load_local_config().unwrap_or_default();
                    config.local_nodes = Some(1);
                    save_local_config(&config);
                    println!(
                        "{} All data is on the standalone system node.",
                        "Done.".green()
                    );
                }
            }
        }

        Commands::Login { token } => {
            // Non-interactive (CI): token as an argument or LUX_TOKEN env var.
            // Interactive: prompt for a paste. Env is preferred in CI so the
            // secret stays out of shell history and the process list.
            let provided = token
                .or_else(|| std::env::var("LUX_TOKEN").ok())
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty());

            let token = match provided {
                Some(token) => token,
                None => {
                    println!("{}", "Paste your Lux Cloud access token.".bold());
                    println!(
                        "Get one from your workspace's tokens page: {}",
                        "https://luxdb.dev/dashboard".cyan()
                    );
                    print!("\n{} ", "Token:".bold());
                    std::io::stdout().flush().ok();

                    let mut input = String::new();
                    std::io::stdin().read_line(&mut input).ok();
                    input.trim().to_string()
                }
            };

            if token.is_empty() {
                eprintln!("{}", "No token provided.".red());
                std::process::exit(1);
            }

            let api_url = api_url_override
                .clone()
                .unwrap_or_else(|| DEFAULT_API_URL.to_string());

            let client = reqwest::Client::new();
            let res = client
                .get(format!("{api_url}/workspaces"))
                .header("Authorization", format!("Bearer {token}"))
                .send()
                .await;

            match res {
                Ok(r) if r.status().is_success() => {
                    save_config(&Config { token, api_url });
                    println!("{}", "\nLogged in successfully.".green());
                }
                Ok(r) => {
                    eprintln!("{} HTTP {}", "Login failed:".red(), r.status());
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("{} {e}", "Connection failed:".red());
                    std::process::exit(1);
                }
            }
        }

        Commands::Logout => {
            delete_config();
            println!("{}", "Logged out.".green());
        }

        Commands::Link { project } => {
            let (client, api_url, token) = get_client(&api_url_override);
            let inst = find_project(&client, &api_url, &token, &project).await;
            let existing = load_local_config().unwrap_or_default();
            save_local_config(&LocalConfig {
                project_id: Some(inst.id.clone()),
                project_name: Some(inst.name.clone()),
                local_http_port: existing.local_http_port,
                local_resp_port: existing.local_resp_port,
                engine_version: existing.engine_version,
                local_nodes: existing.local_nodes,
            });
            println!("{} Linked to project '{}'", "Done.".green(), inst.name);
            println!("{} {}", "ID:".bold(), inst.id);
        }

        Commands::Unlink => {
            let Some(mut config) = load_local_config() else {
                eprintln!("{}", "No lux/config.toml found.".red());
                std::process::exit(1);
            };
            if config.project_id.is_none() && config.project_name.is_none() {
                println!(
                    "{}",
                    "This repository is not linked to a cloud project.".dimmed()
                );
                return;
            }
            config.project_id = None;
            config.project_name = None;
            save_local_config(&config);
            println!("{}", "Cloud project link removed.".green());
        }

        Commands::Target => {
            println!("{}", "Lux targets".bold());
            match load_local_state() {
                Some(state) => {
                    let running =
                        docker_container_state(&state.container).as_deref() == Some("running");
                    println!(
                        "{} local ({})",
                        "Local:".bold(),
                        if running { "running" } else { "stopped" }
                    );
                }
                None => println!("{} not initialized", "Local:".bold()),
            }
            match load_local_config() {
                Some(config) if config.project_id.is_some() || config.project_name.is_some() => {
                    println!(
                        "{} {}{}",
                        "Linked cloud:".bold(),
                        config.project_name.as_deref().unwrap_or("unknown"),
                        config
                            .project_id
                            .as_deref()
                            .map(|id| format!(" ({id})"))
                            .unwrap_or_default()
                    );
                }
                _ => println!("{} none", "Linked cloud:".bold()),
            }
            println!("{} {}", "App env:".bold(), active_profile_label());
            println!(
                "{}",
                "\nOmitted targets are local; a positional project name or ID is cloud.".dimmed()
            );
        }

        Commands::Projects => {
            let (client, api_url, token) = get_client(&api_url_override);
            let workspace_id = resolve_workspace_id(&client, &api_url, &token).await;

            let res = client
                .get(format!("{api_url}/projects?workspace_id={workspace_id}"))
                .header("Authorization", format!("Bearer {token}"))
                .send()
                .await
                .unwrap_or_else(|e| {
                    eprintln!("{} {e}", "Failed:".red());
                    std::process::exit(1);
                });

            let body: ApiResponse<Vec<Instance>> = res.json().await.unwrap_or_else(|e| {
                eprintln!("{} {e}", "Failed to parse response:".red());
                std::process::exit(1);
            });
            let instances = unwrap_api(body);

            if instances.is_empty() {
                println!("{}", "No projects found.".dimmed());
                return;
            }

            println!(
                "  {:<16}  {:<10}  {:<6}  {}",
                "NAME".dimmed(),
                "STATUS".dimmed(),
                "REGION".dimmed(),
                "MEMORY".dimmed()
            );

            for inst in &instances {
                let status = match inst.status.as_str() {
                    "running" => inst.status.green().to_string(),
                    "error" => inst.status.red().to_string(),
                    _ => inst.status.yellow().to_string(),
                };

                println!(
                    "  {:<16}  {:<10}  {:<6}  {}MB",
                    inst.name, status, inst.region, inst.memory_mb,
                );
            }
        }

        Commands::Status {
            project,
            all,
            output,
        } => {
            let json_output = output.as_deref() == Some("json");
            if output.is_some() && !json_output {
                eprintln!(
                    "{} Supported status output is `json`. Use `lux env export local` for env.",
                    "Error:".red()
                );
                std::process::exit(1);
            }

            if all {
                let mut values = Vec::new();
                if let Some(state) = load_local_state() {
                    if json_output {
                        values.push(local_status_value(&state));
                    } else {
                        print_local_status(&state, false);
                    }
                } else if !json_output {
                    println!("{} not initialized", "Local engine:".bold());
                }

                let Some(linked) = linked_project() else {
                    if json_output {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({ "targets": values }))
                                .unwrap()
                        );
                    } else {
                        println!("\n{} none", "Linked cloud:".bold());
                    }
                    return;
                };
                let (client, api_url, token) = get_client(&api_url_override);
                let inst = find_project(&client, &api_url, &token, &linked).await;
                let cloud = serde_json::json!({
                    "target": { "kind": "cloud", "name": inst.name, "id": inst.id },
                    "status": inst.status,
                    "region": inst.region,
                    "memory_mb": inst.memory_mb,
                });
                if json_output {
                    values.push(cloud);
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({ "targets": values }))
                            .unwrap()
                    );
                } else {
                    println!();
                    println!("{} {}", "Linked cloud:".bold(), inst.name);
                    println!("{} {}", "ID:".bold(), inst.id.dimmed());
                    println!("{} {}", "Status:".bold(), inst.status);
                    println!("{} {}", "Region:".bold(), inst.region);
                }
                return;
            }

            // No project arg -> report on the local engine (Supabase parity).
            if project.is_none() {
                let Some(state) = load_local_state() else {
                    eprintln!(
                        "{} No project specified and no local engine. Run {} or {}.",
                        "Error:".red(),
                        "lux start".bold(),
                        "lux status <project>".bold()
                    );
                    std::process::exit(1);
                };
                print_local_status(&state, json_output);
                return;
            }

            let (client, api_url, token) = get_client(&api_url_override);
            let project = require_project_arg(project.as_deref());
            let inst = find_project(&client, &api_url, &token, &project).await;

            let status = match inst.status.as_str() {
                "running" => inst.status.green().to_string(),
                "error" => inst.status.red().to_string(),
                _ => inst.status.yellow().to_string(),
            };

            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "target": { "kind": "cloud", "name": inst.name, "id": inst.id },
                        "status": inst.status,
                        "region": inst.region,
                        "memory_mb": inst.memory_mb,
                    }))
                    .unwrap()
                );
                return;
            }

            println!("{} {}", "Project:".bold(), inst.name);
            println!("{} {}", "ID:".bold(), inst.id.dimmed());
            println!("{} {status}", "Status:".bold());
            println!("{} {}", "Region:".bold(), inst.region);
            println!("{} {}MB", "Memory:".bold(), inst.memory_mb);

            if let (Some(host), Some(port)) = (&inst.worker_host, inst.port) {
                println!("{} lux://:****@{host}:{port}", "Connection:".bold());
            }

            if inst.status == "running" {
                let metrics_res = client
                    .get(format!("{api_url}/metrics/{}/latest", inst.id))
                    .header("Authorization", format!("Bearer {token}"))
                    .send()
                    .await;

                if let Ok(r) = metrics_res {
                    if let Ok(body) = r.json::<ApiResponse<Metrics>>().await {
                        if let Some(m) = body.data {
                            println!();
                            println!("{} {}", "Keys:".bold(), m.keys.unwrap_or(0));
                            println!(
                                "{} {}",
                                "Memory:".bold(),
                                format_bytes(m.used_memory_bytes.unwrap_or(0))
                            );
                            println!(
                                "{} {} ops/sec",
                                "Throughput:".bold(),
                                m.ops_per_sec.unwrap_or(0)
                            );
                            println!("{} {}", "Clients:".bold(), m.connected_clients.unwrap_or(0));
                        }
                    }
                }
            }
        }

        Commands::Exec {
            project,
            host,
            port,
            password,
            cmd,
        } => {
            if cmd.is_empty() {
                eprintln!("{}", "No command provided.".red());
                std::process::exit(1);
            }

            match exec_cli_command_args(
                &project,
                host.as_deref(),
                port,
                password.as_deref(),
                &api_url_override,
                &cmd,
            )
            .await
            {
                Ok(output) => println!("{output}"),
                Err(error) => {
                    eprintln!("{} {error}", "Error:".red());
                    std::process::exit(1);
                }
            }
        }

        Commands::Enc { project, action } => {
            // Proxies the engine's ENC subcommands. With --project (name/ID/URL)
            // it targets that instance via the CLI's cloud auth (or a direct URL);
            // otherwise it uses the local `lux start` engine's stored credentials.
            let command = enc_command_args(&action);
            let result = if let Some(project) = project {
                exec_cli_command_args(&project, None, None, None, &api_url_override, &command).await
            } else {
                let Some(state) = load_local_state() else {
                    eprintln!(
                        "{}",
                        "No local engine found. Run `lux start` first, or pass --project.".red()
                    );
                    std::process::exit(1);
                };
                exec_cli_command_args(
                    "",
                    Some("127.0.0.1"),
                    Some(state.resp_port),
                    Some(&state.password),
                    &api_url_override,
                    &command,
                )
                .await
            };
            match result {
                Ok(output) => println!("{output}"),
                Err(error) => {
                    eprintln!("{} {error}", "Error:".red());
                    std::process::exit(1);
                }
            }
        }

        Commands::Auth { action } => {
            handle_auth(action).await;
        }

        Commands::Logs { project, lines } => {
            let (client, api_url, token) = get_client(&api_url_override);
            let project = require_project_arg(project.as_deref());
            let inst = find_project(&client, &api_url, &token, &project).await;

            let res = client
                .get(format!("{api_url}/logs/{}/logs?lines={lines}", inst.id))
                .header("Authorization", format!("Bearer {token}"))
                .send()
                .await
                .unwrap_or_else(|e| {
                    eprintln!("{} {e}", "Failed:".red());
                    std::process::exit(1);
                });

            let body: ApiResponse<serde_json::Value> = res.json().await.unwrap();
            if let Some(data) = body.data {
                if let Some(logs) = data.get("logs").and_then(|v| v.as_str()) {
                    print!("{logs}");
                }
            } else if let Some(error) = body.error {
                eprintln!("{} {error}", "Error:".red());
            }
        }

        Commands::Create {
            name,
            memory,
            accept_charges,
        } => {
            let (client, api_url, token) = get_client(&api_url_override);

            let sizes_res = client
                .get(format!("{api_url}/billing/sizes"))
                .header("Authorization", format!("Bearer {token}"))
                .send()
                .await
                .unwrap_or_else(|e| {
                    eprintln!("{} {e}", "Failed:".red());
                    std::process::exit(1);
                });

            let sizes_body: ApiResponse<Vec<serde_json::Value>> = sizes_res.json().await.unwrap();
            let sizes = sizes_body.data.unwrap_or_default();

            let size = sizes
                .iter()
                .find(|s| s.get("memory_mb").and_then(|v| v.as_u64()) == Some(memory as u64))
                .unwrap_or_else(|| {
                    let available: Vec<String> = sizes
                        .iter()
                        .filter_map(|s| {
                            let mb = s.get("memory_mb")?.as_u64()?;
                            let label = s.get("label")?.as_str()?;
                            Some(format!("{mb}MB ({label})"))
                        })
                        .collect();
                    eprintln!(
                        "{} No size with {}MB. Available: {}",
                        "Error:".red(),
                        memory,
                        available.join(", ")
                    );
                    std::process::exit(1);
                });

            let price_id = size.get("price_id").and_then(|v| v.as_str()).unwrap_or("");
            let price_cents = size
                .get("price_cents")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);

            if !accept_charges {
                eprintln!(
                    "{} This will create a {}MB instance at ${}/mo.",
                    "Billing:".yellow(),
                    memory,
                    price_cents / 100
                );
                eprintln!("Run with {} to confirm.", "--accept-charges".bold());
                std::process::exit(1);
            }

            println!("{} Creating project '{}'...", "...".dimmed(), name);

            let workspace_id = resolve_workspace_id(&client, &api_url, &token).await;
            let res = client
                .post(format!("{api_url}/projects"))
                .header("Authorization", format!("Bearer {token}"))
                .json(&serde_json::json!({
                    "name": name,
                    "price_id": price_id,
                    "workspace_id": workspace_id,
                }))
                .send()
                .await
                .unwrap_or_else(|e| {
                    eprintln!("{} {e}", "Failed:".red());
                    std::process::exit(1);
                });

            let body: ApiResponse<Instance> = res.json().await.unwrap_or_else(|e| {
                eprintln!("{} {e}", "Failed to parse:".red());
                std::process::exit(1);
            });

            if let Some(error) = body.error {
                eprintln!("{} {error}", "Error:".red());
                std::process::exit(1);
            }

            if let Some(inst) = body.data {
                println!("{} Project '{}' created", "Done.".green(), inst.name);
                println!("{} {}", "ID:".bold(), inst.id);
                println!("{} {}MB", "Memory:".bold(), inst.memory_mb);
                println!("{} {}", "Region:".bold(), inst.region);
                println!(
                    "\n{} Run {} to check when it's ready",
                    "Tip:".bold(),
                    format!("lux status {}", inst.name).cyan()
                );
            }
        }

        Commands::Restart { project } => {
            let (client, api_url, token) = get_client(&api_url_override);
            let project = require_project_arg(project.as_deref());
            let inst = find_project(&client, &api_url, &token, &project).await;

            println!("{} Restarting '{}'...", "...".dimmed(), inst.name);

            let res = client
                .post(format!("{api_url}/projects/{}/restart", inst.id))
                .header("Authorization", format!("Bearer {token}"))
                .send()
                .await
                .unwrap_or_else(|e| {
                    eprintln!("{} {e}", "Failed:".red());
                    std::process::exit(1);
                });

            if res.status().is_success() {
                println!("{} Project '{}' is restarting.", "Done.".green(), inst.name);
            } else {
                let body: serde_json::Value = res.json().await.unwrap_or_default();
                let msg = body
                    .get("error")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown error");
                eprintln!("{} {msg}", "Error:".red());
            }
        }

        Commands::Snapshot {
            project,
            list,
            restore,
        } => {
            let (client, api_url, token) = get_client(&api_url_override);
            let project = require_project_arg(project.as_deref());
            let inst = find_project(&client, &api_url, &token, &project).await;

            if let Some(snapshot_id) = restore {
                println!(
                    "{} Restoring '{}' from {}...",
                    "...".dimmed(),
                    inst.name,
                    snapshot_id
                );
                let res = client
                    .post(format!(
                        "{api_url}/snapshots/{}/{}/restore",
                        inst.id, snapshot_id
                    ))
                    .header("Authorization", format!("Bearer {token}"))
                    .send()
                    .await
                    .unwrap_or_else(|e| {
                        eprintln!("{} {e}", "Failed:".red());
                        std::process::exit(1);
                    });
                if res.status().is_success() {
                    println!("{} Restore started for '{}'.", "Done.".green(), inst.name);
                } else {
                    let body: serde_json::Value = res.json().await.unwrap_or_default();
                    let msg = body
                        .get("error")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Unknown error");
                    eprintln!("{} {msg}", "Error:".red());
                }
            } else if list {
                let res = client
                    .get(format!("{api_url}/snapshots/{}", inst.id))
                    .header("Authorization", format!("Bearer {token}"))
                    .send()
                    .await
                    .unwrap_or_else(|e| {
                        eprintln!("{} {e}", "Failed:".red());
                        std::process::exit(1);
                    });
                let body: serde_json::Value = res.json().await.unwrap_or_default();
                let rows = body
                    .get("data")
                    .and_then(|d| d.as_array())
                    .cloned()
                    .unwrap_or_default();
                if rows.is_empty() {
                    println!("No snapshots for '{}'.", inst.name);
                } else {
                    println!("{:<10} {:<10} {:<26} ID", "STATUS", "SIZE", "CREATED");
                    for r in rows {
                        let status = r.get("status").and_then(|v| v.as_str()).unwrap_or("?");
                        let size = r
                            .get("file_size_bytes")
                            .and_then(|v| v.as_u64())
                            .map(format_bytes)
                            .unwrap_or_else(|| "-".to_string());
                        let created = r.get("created_at").and_then(|v| v.as_str()).unwrap_or("");
                        let id = r.get("id").and_then(|v| v.as_str()).unwrap_or("");
                        let err = r
                            .get("error_message")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let err_suffix = if err.is_empty() {
                            String::new()
                        } else {
                            format!("  {}", err.red())
                        };
                        println!("{status:<10} {size:<10} {created:<26} {id}{err_suffix}");
                    }
                }
            } else {
                println!("{} Snapshotting '{}'...", "...".dimmed(), inst.name);

                let res = client
                    .post(format!("{api_url}/snapshots/{}", inst.id))
                    .header("Authorization", format!("Bearer {token}"))
                    .send()
                    .await
                    .unwrap_or_else(|e| {
                        eprintln!("{} {e}", "Failed:".red());
                        std::process::exit(1);
                    });

                if res.status().is_success() {
                    let body: serde_json::Value = res.json().await.unwrap_or_default();
                    let id = body
                        .get("data")
                        .and_then(|d| d.get("id"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let suffix = if id.is_empty() {
                        String::new()
                    } else {
                        format!(" ({id})")
                    };
                    println!(
                        "{} Snapshot started for '{}'.{}",
                        "Done.".green(),
                        inst.name,
                        suffix
                    );
                    println!(
                        "{} {}",
                        "Tip:".bold(),
                        format!("lux snapshot {} --list", inst.name).cyan()
                    );
                } else {
                    let body: serde_json::Value = res.json().await.unwrap_or_default();
                    let msg = body
                        .get("error")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Unknown error");
                    eprintln!("{} {msg}", "Error:".red());
                }
            }
        }

        Commands::Destroy {
            project,
            accept_consequences,
        } => {
            let (client, api_url, token) = get_client(&api_url_override);
            let inst = find_project(&client, &api_url, &token, &project).await;

            if !accept_consequences {
                eprintln!(
                    "{} This will permanently delete '{}' and all its data.",
                    "Warning:".red(),
                    inst.name
                );
                eprintln!("Run with {} to confirm.", "--accept-consequences".bold());
                std::process::exit(1);
            }

            println!("{} Destroying '{}'...", "...".dimmed(), inst.name);

            let res = client
                .delete(format!("{api_url}/projects/{}", inst.id))
                .header("Authorization", format!("Bearer {token}"))
                .send()
                .await
                .unwrap_or_else(|e| {
                    eprintln!("{} {e}", "Failed:".red());
                    std::process::exit(1);
                });

            if res.status().is_success() {
                println!("{} Project '{}' destroyed.", "Done.".green(), inst.name);
            } else {
                let body: serde_json::Value = res.json().await.unwrap_or_default();
                let msg = body
                    .get("error")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown error");
                eprintln!("{} {msg}", "Error:".red());
            }
        }

        Commands::Connect {
            project,
            host,
            port,
            password,
        } => {
            let project = project.unwrap_or_default();
            let target = if is_connection_url(&project) {
                parse_connection_url(&project)
            } else if host.is_some() || port.is_some() {
                let h = host.unwrap_or_else(|| "localhost".to_string());
                let p = port.unwrap_or(6379);
                let pw = password.unwrap_or_default();
                let name = format!("{h}:{p}");
                ConnectionTarget {
                    host: h,
                    port: p,
                    password: pw,
                    name,
                    tls: false,
                }
            } else if project.is_empty() {
                eprintln!(
                    "{} Provide a project name, connection URL, or --host/--port flags",
                    "Error:".red()
                );
                std::process::exit(1);
            } else {
                let (client, api_url, token) = get_client(&api_url_override);
                let inst = find_project(&client, &api_url, &token, &project).await;

                if inst.status != "running" {
                    eprintln!(
                        "{} Project '{}' is not running (status: {})",
                        "Error:".red(),
                        inst.name,
                        inst.status
                    );
                    std::process::exit(1);
                }

                let credentials =
                    get_instance_credentials(&client, &api_url, &token, &inst.id).await;
                let mut target = parse_connection_url(&credentials.resp);
                target.name = inst.name;
                target
            };

            println!("{} {}:{}", "Connecting to".bold(), target.host, target.port);
            let mut conn = DirectConn::connect_target(&target).unwrap_or_else(|e| {
                eprintln!("{} {e}", "Connection failed:".red());
                std::process::exit(1);
            });

            println!("{} Type commands, Ctrl+C to exit.\n", "Connected.".green());

            loop {
                print!("{} ", format!("{}>", target.name).purple());
                std::io::stdout().flush().ok();

                let mut input = String::new();
                if std::io::stdin().read_line(&mut input).is_err() || input.is_empty() {
                    break;
                }

                let input = input.trim();
                if input.is_empty() {
                    continue;
                }
                if input.eq_ignore_ascii_case("quit") || input.eq_ignore_ascii_case("exit") {
                    break;
                }

                match conn.exec(input) {
                    Ok(response) => println!("{response}"),
                    Err(e) => println!("{}", e.red()),
                }
            }
        }

        Commands::Version {
            project,
            all,
            output,
        } => {
            show_versions(
                project.as_deref(),
                all,
                output.as_deref(),
                &api_url_override,
            )
            .await;
        }

        Commands::Update { action, check } => {
            let result = match action {
                None => update_cli(check).await,
                Some(UpdateAction::Cli { check }) => update_cli(check).await,
                Some(UpdateAction::Engine { project, check }) => match project {
                    Some(project) => update_cloud_engine(&project, check, &api_url_override).await,
                    None => update_local_engine(check),
                },
                Some(UpdateAction::Studio { check }) => update_local_studio(check),
            };
            if let Err(error) = result {
                eprintln!("{} {error}", "Update failed:".red());
                std::process::exit(1);
            }
        }

        Commands::Keys { action } => match action {
            KeysAction::List { project } => {
                let (client, api_url, token) = get_client(&api_url_override);
                let project = require_project_arg(project.as_deref());
                let inst = find_project(&client, &api_url, &token, &project).await;
                let keys = list_project_keys(&client, &api_url, &token, &inst.id).await;

                if keys.is_empty() {
                    println!("{}", "No active keys.".dimmed());
                    return;
                }

                println!(
                    "  {:<36}  {:<12}  {:<24}  {:<14}  {}",
                    "ID".dimmed(),
                    "KIND".dimmed(),
                    "NAME".dimmed(),
                    "PREFIX".dimmed(),
                    "DEFAULT".dimmed()
                );
                for key in keys {
                    println!(
                        "  {:<36}  {:<12}  {:<24}  {:<14}  {}",
                        key.id,
                        key.kind,
                        truncate(&key.name, 24),
                        key.prefix,
                        if key.default { "yes" } else { "no" }
                    );
                }
            }
            KeysAction::Create {
                project,
                kind,
                name,
            } => {
                if kind != "publishable" && kind != "secret" {
                    eprintln!("{}", "kind must be publishable or secret".red());
                    std::process::exit(1);
                }
                let (client, api_url, token) = get_client(&api_url_override);
                let project = require_project_arg(project.as_deref());
                let inst = find_project(&client, &api_url, &token, &project).await;
                let created =
                    create_project_key(&client, &api_url, &token, &inst.id, &kind, name).await;
                println!(
                    "{} Created {} key '{}'",
                    "Done.".green(),
                    created.key.kind,
                    created.key.name
                );
                println!();
                println!("{}", "Copy this now. It will not be shown again:".yellow());
                println!("{}", created.plain_key);
            }
            KeysAction::Revoke { id, project } => {
                let (client, api_url, token) = get_client(&api_url_override);
                let project = require_project_arg(project.as_deref());
                let inst = find_project(&client, &api_url, &token, &project).await;
                revoke_project_key(&client, &api_url, &token, &inst.id, &id).await;
                println!("{} Revoked key {}", "Done.".green(), id);
            }
        },

        Commands::Env { action } => match action {
            EnvAction::Pull { project, use_env } => {
                let (client, api_url, token) = get_client(&api_url_override);
                let project = require_project_arg(project.as_deref());
                let inst = find_project(&client, &api_url, &token, &project).await;
                let credentials =
                    get_instance_credentials(&client, &api_url, &token, &inst.id).await;
                let auth = get_auth_credentials(&client, &api_url, &token, &inst.id).await;
                let content = build_project_env(
                    &inst.id,
                    &api_url,
                    &credentials.resp,
                    auth.publishable_key.as_deref(),
                    auth.secret_key.as_deref(),
                );
                let safe_id: String = inst
                    .id
                    .chars()
                    .map(|ch| {
                        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                            ch
                        } else {
                            '_'
                        }
                    })
                    .collect();
                let profile = EnvProfile {
                    key: format!("cloud:{}", inst.id),
                    kind: "cloud".to_string(),
                    display_name: inst.name.clone(),
                    project_id: Some(inst.id.clone()),
                    filename: format!("cloud-{safe_id}.env"),
                };
                let mut index = load_profile_index().unwrap_or_else(|e| {
                    eprintln!("{} {e}", "Failed to read env profiles:".red());
                    std::process::exit(1);
                });
                write_profile(&profile, &content).unwrap_or_else(|e| {
                    eprintln!("{} {e}", "Failed to write env profile:".red());
                    std::process::exit(1);
                });
                upsert_profile(&mut index, profile.clone());
                save_profile_index(&index).unwrap_or_else(|e| {
                    eprintln!("{} {e}", "Failed to save env profiles:".red());
                    std::process::exit(1);
                });
                println!(
                    "{} Saved cloud profile '{}' without changing .env.local.",
                    "Done.".green(),
                    profile.display_name
                );
                if use_env {
                    let activated =
                        activate_profile(&mut index, &profile.key).unwrap_or_else(|e| {
                            eprintln!("{} {e}", "Failed to activate env profile:".red());
                            std::process::exit(1);
                        });
                    println!(
                        "{} .env.local now uses '{}'.",
                        "Active:".green(),
                        activated.display_name
                    );
                } else {
                    println!(
                        "Run {} to activate it.",
                        format!("lux env use {}", profile.display_name).cyan()
                    );
                }
            }
            EnvAction::Profiles => {
                let index = load_profile_index().unwrap_or_else(|e| {
                    eprintln!("{} {e}", "Failed to read env profiles:".red());
                    std::process::exit(1);
                });
                if index.profiles.is_empty() {
                    println!(
                        "{}",
                        "No env profiles. Run `lux start` or `lux env pull <project>`.".dimmed()
                    );
                    return;
                }
                println!(
                    "  {:<28}  {:<8}  {}",
                    "PROFILE".dimmed(),
                    "KIND".dimmed(),
                    "ACTIVE".dimmed()
                );
                for profile in &index.profiles {
                    println!(
                        "  {:<28}  {:<8}  {}",
                        profile.display_name,
                        profile.kind,
                        if index.active.as_deref() == Some(&profile.key) {
                            "yes"
                        } else {
                            ""
                        }
                    );
                }
            }
            EnvAction::Current => {
                println!("{}", active_profile_label());
            }
            EnvAction::Use { profile } => {
                let mut index = load_profile_index().unwrap_or_else(|e| {
                    eprintln!("{} {e}", "Failed to read env profiles:".red());
                    std::process::exit(1);
                });
                let active = activate_profile(&mut index, &profile).unwrap_or_else(|e| {
                    eprintln!("{} {e}", "Failed to activate env profile:".red());
                    std::process::exit(1);
                });
                println!(
                    "{} .env.local now uses '{}'.",
                    "Done.".green(),
                    active.display_name
                );
            }
            EnvAction::Export { profile } => {
                let index = load_profile_index().unwrap_or_else(|e| {
                    eprintln!("{} {e}", "Failed to read env profiles:".red());
                    std::process::exit(1);
                });
                let selector = profile.or_else(|| index.active.clone()).unwrap_or_else(|| {
                    eprintln!(
                        "{} Provide a profile or activate one with `lux env use`.",
                        "Error:".red()
                    );
                    std::process::exit(1);
                });
                let selected = resolve_profile(&index, &selector).unwrap_or_else(|| {
                    eprintln!("{} Profile '{}' not found.", "Error:".red(), selector);
                    std::process::exit(1);
                });
                let content = std::fs::read_to_string(profile_path(selected)).unwrap_or_else(|e| {
                    eprintln!("{} {e}", "Failed to read env profile:".red());
                    std::process::exit(1);
                });
                print!("{content}");
            }
        },

        Commands::Doctor {
            project,
            all,
            fix,
            output,
        } => {
            let healthy = run_doctor(
                project.as_deref(),
                all,
                fix,
                output.as_deref(),
                &api_url_override,
            )
            .await;
            if !healthy {
                std::process::exit(1);
            }
        }

        Commands::Push { action } => match action {
            PushAction::Status {
                conn,
                check,
                output,
            } => {
                if output.is_some() && output.as_deref() != Some("json") {
                    eprintln!("{} Supported push status output is `json`.", "Error:".red());
                    std::process::exit(1);
                }
                let target = resolve_push_target(conn.project.as_deref(), &api_url_override).await;
                let config = target.config(&conn.app_id).await.unwrap_or_else(|error| {
                    eprintln!("{} {error}", "Push status failed:".red());
                    std::process::exit(1);
                });
                print_push_config(&config, output.as_deref());
                if check && !config.healthy {
                    std::process::exit(1);
                }
            }
            PushAction::Apns { action } => match action {
                PushApnsAction::Set {
                    conn,
                    team_id,
                    key_id,
                    topic,
                    environment,
                    p8_file,
                } => {
                    let p8_pem = p8_file
                        .as_deref()
                        .map(read_apns_key)
                        .transpose()
                        .unwrap_or_else(|error| {
                            eprintln!("{} {error}", "APNs configuration failed:".red());
                            std::process::exit(1);
                        });
                    let target =
                        resolve_push_target(conn.project.as_deref(), &api_url_override).await;
                    let config = target
                        .update_apns(
                            &conn.app_id,
                            &team_id,
                            &key_id,
                            &topic,
                            environment,
                            p8_pem.as_deref(),
                        )
                        .await
                        .unwrap_or_else(|error| {
                            eprintln!("{} {error}", "APNs configuration failed:".red());
                            std::process::exit(1);
                        });
                    println!(
                        "{} APNs configured for app '{}'; private key material was not stored by the CLI.",
                        "Done.".green(),
                        conn.app_id
                    );
                    print_push_config(&config, None);
                }
                PushApnsAction::Clear { conn, yes } => {
                    if !yes {
                        eprintln!(
                            "{} Add {} to acknowledge APNs delivery will stop.",
                            "Refusing:".red(),
                            "--yes".cyan()
                        );
                        std::process::exit(1);
                    }
                    let target =
                        resolve_push_target(conn.project.as_deref(), &api_url_override).await;
                    let config = target
                        .clear_apns(&conn.app_id)
                        .await
                        .unwrap_or_else(|error| {
                            eprintln!("{} {error}", "APNs clear failed:".red());
                            std::process::exit(1);
                        });
                    println!(
                        "{} APNs disabled for app '{}'.",
                        "Done.".green(),
                        conn.app_id
                    );
                    print_push_config(&config, None);
                }
            },
            PushAction::Vapid { action } => match action {
                PushVapidAction::Enable { conn, subject } => {
                    let target =
                        resolve_push_target(conn.project.as_deref(), &api_url_override).await;
                    let config = target
                        .configure_vapid(&conn.app_id, "enable", &subject)
                        .await
                        .unwrap_or_else(|error| {
                            eprintln!("{} {error}", "Web Push configuration failed:".red());
                            std::process::exit(1);
                        });
                    println!(
                        "{} Web Push enabled for app '{}'.",
                        "Done.".green(),
                        conn.app_id
                    );
                    print_push_config(&config, None);
                }
                PushVapidAction::Rotate { conn, subject, yes } => {
                    if !yes {
                        eprintln!(
                            "{} Add {} to acknowledge existing browser subscriptions must resubscribe.",
                            "Refusing:".red(),
                            "--yes".cyan()
                        );
                        std::process::exit(1);
                    }
                    let target =
                        resolve_push_target(conn.project.as_deref(), &api_url_override).await;
                    let config = target
                        .configure_vapid(&conn.app_id, "rotate", &subject)
                        .await
                        .unwrap_or_else(|error| {
                            eprintln!("{} {error}", "VAPID rotation failed:".red());
                            std::process::exit(1);
                        });
                    println!(
                        "{} VAPID rotated for app '{}'; existing subscriptions must resubscribe.",
                        "Done.".green(),
                        conn.app_id
                    );
                    print_push_config(&config, None);
                }
                PushVapidAction::Disable { conn, yes } => {
                    if !yes {
                        eprintln!(
                            "{} Add {} to acknowledge Web Push delivery will stop.",
                            "Refusing:".red(),
                            "--yes".cyan()
                        );
                        std::process::exit(1);
                    }
                    let target =
                        resolve_push_target(conn.project.as_deref(), &api_url_override).await;
                    let config = target
                        .disable_vapid(&conn.app_id)
                        .await
                        .unwrap_or_else(|error| {
                            eprintln!("{} {error}", "Web Push disable failed:".red());
                            std::process::exit(1);
                        });
                    println!(
                        "{} Web Push disabled for app '{}'.",
                        "Done.".green(),
                        conn.app_id
                    );
                    print_push_config(&config, None);
                }
            },
        },

        Commands::Migrate { action, run } => match action.unwrap_or(MigrateAction::Run(run)) {
            MigrateAction::New { name, dir } => {
                std::fs::create_dir_all(&dir).unwrap_or_else(|e| {
                    eprintln!("{} {e}", "Failed to create migration dir:".red());
                    std::process::exit(1);
                });
                let ts = chrono::Utc::now().format("%Y%m%d%H%M%S");
                let filename = format!("{}_{}.lux", ts, name);
                let path = dir.join(&filename);
                std::fs::write(&path, "").unwrap_or_else(|e| {
                    eprintln!("{} {e}", "Failed to create file:".red());
                    std::process::exit(1);
                });
                println!("{} {}", "Created:".green(), path.display());
            }

            MigrateAction::Status {
                conn:
                    MigrateConn {
                        project,
                        dir,
                        host,
                        port,
                        password,
                    },
                check,
            } => {
                let mut target = resolve_migrate_target(
                    project.as_deref(),
                    host.as_deref(),
                    port,
                    password.as_deref(),
                    &api_url_override,
                )
                .await;
                let clean = print_migration_status(&mut target, &dir).await;
                if check && !clean {
                    std::process::exit(1);
                }
            }

            MigrateAction::Plan(MigrateConn {
                project,
                dir,
                host,
                port,
                password,
            }) => {
                let mut target = resolve_migrate_target(
                    project.as_deref(),
                    host.as_deref(),
                    port,
                    password.as_deref(),
                    &api_url_override,
                )
                .await;
                let clean = print_migration_plan(&mut target, &dir).await;
                if !clean {
                    std::process::exit(1);
                }
            }

            MigrateAction::Run(MigrateConn {
                project,
                dir,
                host,
                port,
                password,
            }) => {
                let mut target = resolve_migrate_target(
                    project.as_deref(),
                    host.as_deref(),
                    port,
                    password.as_deref(),
                    &api_url_override,
                )
                .await;
                let applied = apply_pending_migrations(&mut target, &dir).await;
                if applied == 0 {
                    println!("{}", "All migrations are applied.".green());
                    return;
                }
                println!("{} Applied {} migration(s).", "Done.".green(), applied);
            }

            MigrateAction::Pull(MigrateConn {
                project,
                dir,
                host,
                port,
                password,
            }) => {
                let mut target = resolve_migrate_target(
                    project.as_deref(),
                    host.as_deref(),
                    port,
                    password.as_deref(),
                    &api_url_override,
                )
                .await;

                let remote = target.migration_list().await.unwrap_or_else(|e| {
                    eprintln!("{} Could not list target migrations: {e}", "Error:".red());
                    std::process::exit(1);
                });
                if remote.is_empty() {
                    println!("{}", "No migrations recorded on the target.".dimmed());
                    return;
                }

                if let Err(e) = std::fs::create_dir_all(&dir) {
                    eprintln!("{} Failed to create migration dir: {}", "Error:".red(), e);
                    std::process::exit(1);
                }
                let local: HashMap<String, String> =
                    get_local_migrations(&dir).into_iter().collect();

                let mut pulled = 0usize;
                let mut skipped = 0usize;
                for record in remote.iter().filter(|record| record.status == "applied") {
                    if let Some(local_content) = local.get(&record.filename) {
                        // Already present locally. Only flag genuine divergence.
                        if !migration_checksum_matches(record, local_content) {
                            println!(
                                "  {} {} (local differs from target; keeping local)",
                                "skip".yellow(),
                                record.filename
                            );
                            skipped += 1;
                        }
                        continue;
                    }
                    if record.body.is_empty() {
                        // Applied before bodies were stored: nothing to recreate.
                        println!(
                            "  {} {} (no stored source on target)",
                            "skip".yellow(),
                            record.filename
                        );
                        skipped += 1;
                        continue;
                    }
                    let path = dir.join(&record.filename);
                    if let Err(e) = std::fs::write(&path, &record.body) {
                        eprintln!("  {} {}: {}", "FAILED".red(), record.filename, e);
                        std::process::exit(1);
                    }
                    println!("  {} {}", "pull".green(), record.filename);
                    pulled += 1;
                }

                println!(
                    "{} {} pulled, {} skipped.",
                    "Done.".green(),
                    pulled,
                    skipped
                );
            }

            MigrateAction::Repair { filename, action } => {
                let (conn, repair) = match action {
                    MigrateRepairAction::Resume { from_command, conn } => {
                        (conn, MigrationRepairRequest::Resume { from_command })
                    }
                    MigrateRepairAction::MarkApplied { conn } => {
                        (conn, MigrationRepairRequest::MarkApplied)
                    }
                    MigrateRepairAction::Abandon { conn } => {
                        (conn, MigrationRepairRequest::Abandon)
                    }
                };
                let mut target = resolve_migrate_target(
                    conn.project.as_deref(),
                    conn.host.as_deref(),
                    conn.port,
                    conn.password.as_deref(),
                    &api_url_override,
                )
                .await;
                let before = target.migration_list().await.unwrap_or_else(|e| {
                    eprintln!("{} Could not inspect migration: {e}", "Error:".red());
                    std::process::exit(1);
                });
                let record = before
                    .iter()
                    .find(|record| record.filename == filename)
                    .unwrap_or_else(|| {
                        eprintln!("{} Migration '{}' was not found.", "Error:".red(), filename);
                        std::process::exit(1);
                    });
                print_migration_record("Before", record);
                let repaired = target
                    .migration_repair(&filename, repair)
                    .await
                    .unwrap_or_else(|e| {
                        eprintln!("{} Repair failed: {e}", "Error:".red());
                        std::process::exit(1);
                    });
                print_migration_record("After", &repaired);
            }
        },

        Commands::Seed { action } => match action {
            SeedAction::Run {
                project,
                file,
                host,
                port,
                password,
            } => {
                let mut target = resolve_migrate_target(
                    project.as_deref(),
                    host.as_deref(),
                    port,
                    password.as_deref(),
                    &api_url_override,
                )
                .await;
                run_command_file(&mut target, &file, "Seed").await;
            }
        },
        Commands::Types {
            project,
            host,
            port,
            password,
            out,
            stdout,
        } => {
            let mut target = resolve_migrate_target(
                project.as_deref(),
                host.as_deref(),
                port,
                password.as_deref(),
                &api_url_override,
            )
            .await;

            let tlist = match target.exec("TLIST").await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("{} {}", "Error:".red(), e);
                    std::process::exit(1);
                }
            };

            let mut tables: Vec<TableModel> = Vec::new();
            for table in parse_resp_array(&tlist) {
                if is_system_table(&table) {
                    continue;
                }
                match target.exec(&format!("TSCHEMA {table}")).await {
                    Ok(schema) => {
                        let cols = parse_resp_array(&schema)
                            .iter()
                            .filter_map(|line| parse_field_spec(line))
                            .collect();
                        tables.push((table, cols));
                    }
                    Err(e) => {
                        eprintln!("{} reading schema for {table}: {e}", "Error:".red());
                        std::process::exit(1);
                    }
                }
            }

            if tables.is_empty() {
                eprintln!("{} no user tables found", "Warning:".yellow());
            }

            let ts = generate_types(&tables);
            if stdout {
                print!("{ts}");
            } else {
                let path = out.unwrap_or_else(|| "lux/types/database.ts".to_string());
                if let Some(parent) = std::path::Path::new(&path).parent() {
                    if !parent.as_os_str().is_empty() {
                        if let Err(e) = std::fs::create_dir_all(parent) {
                            eprintln!("{} creating {}: {e}", "Error:".red(), parent.display());
                            std::process::exit(1);
                        }
                    }
                }
                match std::fs::write(&path, &ts) {
                    Ok(()) => println!(
                        "{} wrote {} ({} table{})",
                        "✓".green(),
                        path,
                        tables.len(),
                        if tables.len() == 1 { "" } else { "s" }
                    ),
                    Err(e) => {
                        eprintln!("{} writing {path}: {e}", "Error:".red());
                        std::process::exit(1);
                    }
                }
            }
        }
    }
}

async fn run_command_file(target: &mut MigrateTarget, file: &PathBuf, label: &str) {
    let content = std::fs::read_to_string(file).unwrap_or_else(|e| {
        eprintln!(
            "{} Failed to read {}: {}",
            "Error:".red(),
            file.display(),
            e
        );
        std::process::exit(1);
    });
    let commands = parse_migration_commands(&content).unwrap_or_else(|e| {
        eprintln!("{} {}", "Error:".red(), e);
        std::process::exit(1);
    });

    if commands.is_empty() {
        println!("{} {} has no commands.", label, file.display());
        return;
    }

    println!(
        "{} {} command(s) from {}",
        "Running".bold(),
        commands.len(),
        file.display()
    );
    for command in &commands {
        if let Err(e) = target.exec_args(command).await {
            eprintln!("{} {}", "FAILED".red(), command.join(" "));
            eprintln!("{} {}", "Error:".red(), e);
            std::process::exit(1);
        }
    }
    println!("{} {} complete.", "Done.".green(), label);
}

async fn exec_command(
    client: &reqwest::Client,
    api_url: &str,
    token: &str,
    instance_id: &str,
    command: &str,
) -> Result<String, String> {
    let res = client
        .post(format!("{api_url}/console/{instance_id}/exec"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&serde_json::json!({ "command": command }))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;

    let status = res.status();
    let body: serde_json::Value = res
        .json()
        .await
        .map_err(|e| format!("invalid response: {e}"))?;

    if let Some(err) = body.get("error").and_then(|v| v.as_str()) {
        return Err(err.to_string());
    }

    if !status.is_success() {
        return Err(format!("HTTP {status}"));
    }

    Ok(format_json_value(&body))
}

async fn exec_command_args(
    client: &reqwest::Client,
    api_url: &str,
    token: &str,
    instance_id: &str,
    command: &[String],
) -> Result<String, String> {
    let res = client
        .post(format!("{api_url}/console/{instance_id}/exec"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&serde_json::json!({ "command": command }))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;

    let status = res.status();
    let body: serde_json::Value = res
        .json()
        .await
        .map_err(|e| format!("invalid response: {e}"))?;

    if let Some(err) = body.get("error").and_then(|v| v.as_str()) {
        return Err(err.to_string());
    }

    if !status.is_success() {
        return Err(format!("HTTP {status}"));
    }

    Ok(format_json_value(&body))
}

async fn exec_cli_command_args(
    project: &str,
    host: Option<&str>,
    port: Option<u16>,
    password: Option<&str>,
    api_url_override: &Option<String>,
    command: &[String],
) -> Result<String, String> {
    if host.is_some() || port.is_some() {
        let h = host.unwrap_or(project);
        let p = port.unwrap_or(6379);
        let pw = password.unwrap_or("");
        let mut conn = DirectConn::connect(h, p, pw)?;
        return conn.exec_args(command);
    }

    if is_connection_url(project) {
        let target = parse_connection_url(project);
        let mut conn = DirectConn::connect_target(&target)?;
        return conn.exec_args(command);
    }

    let (client, api_url, token) = get_client(api_url_override);
    let inst = find_project(&client, &api_url, &token, project).await;
    exec_command_args(&client, &api_url, &token, &inst.id, command).await
}

fn is_connection_url(value: &str) -> bool {
    value.starts_with("lux://")
        || value.starts_with("luxs://")
        || value.starts_with("redis://")
        || value.starts_with("rediss://")
}

async fn get_instance_credentials(
    client: &reqwest::Client,
    api_url: &str,
    token: &str,
    instance_id: &str,
) -> Credentials {
    try_get_instance_credentials(client, api_url, token, instance_id)
        .await
        .unwrap_or_else(|error| {
            eprintln!("{} {error}", "Failed:".red());
            std::process::exit(1);
        })
}

async fn try_get_instance_credentials(
    client: &reqwest::Client,
    api_url: &str,
    token: &str,
    instance_id: &str,
) -> Result<Credentials, String> {
    cloud_management_request(
        client,
        reqwest::Method::GET,
        format!("{api_url}/projects/{instance_id}/credentials"),
        token,
        None,
    )
    .await
}

async fn get_auth_credentials(
    client: &reqwest::Client,
    api_url: &str,
    token: &str,
    instance_id: &str,
) -> AuthCredentials {
    let res = client
        .get(format!("{api_url}/projects/{instance_id}/auth/credentials"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap_or_else(|e| {
            eprintln!("{} {e}", "Failed:".red());
            std::process::exit(1);
        });
    let body: ApiResponse<AuthCredentials> = res.json().await.unwrap_or_else(|e| {
        eprintln!("{} {e}", "Failed to parse response:".red());
        std::process::exit(1);
    });
    unwrap_api(body)
}

async fn list_project_keys(
    client: &reqwest::Client,
    api_url: &str,
    token: &str,
    instance_id: &str,
) -> Vec<ProjectKey> {
    let res = client
        .get(format!("{api_url}/projects/{instance_id}/auth/keys"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap_or_else(|e| {
            eprintln!("{} {e}", "Failed:".red());
            std::process::exit(1);
        });
    let body: ApiResponse<ProjectKeys> = res.json().await.unwrap_or_else(|e| {
        eprintln!("{} {e}", "Failed to parse response:".red());
        std::process::exit(1);
    });
    unwrap_api(body).keys
}

async fn create_project_key(
    client: &reqwest::Client,
    api_url: &str,
    token: &str,
    instance_id: &str,
    kind: &str,
    name: Option<String>,
) -> CreatedKey {
    let res = client
        .post(format!("{api_url}/projects/{instance_id}/auth/keys"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&serde_json::json!({ "kind": kind, "name": name }))
        .send()
        .await
        .unwrap_or_else(|e| {
            eprintln!("{} {e}", "Failed:".red());
            std::process::exit(1);
        });
    let body: ApiResponse<CreatedKey> = res.json().await.unwrap_or_else(|e| {
        eprintln!("{} {e}", "Failed to parse response:".red());
        std::process::exit(1);
    });
    unwrap_api(body)
}

async fn revoke_project_key(
    client: &reqwest::Client,
    api_url: &str,
    token: &str,
    instance_id: &str,
    key_id: &str,
) {
    let res = client
        .delete(format!(
            "{api_url}/projects/{instance_id}/auth/keys/{key_id}"
        ))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap_or_else(|e| {
            eprintln!("{} {e}", "Failed:".red());
            std::process::exit(1);
        });
    let body: ApiResponse<serde_json::Value> = res.json().await.unwrap_or_else(|e| {
        eprintln!("{} {e}", "Failed to parse response:".red());
        std::process::exit(1);
    });
    let _ = unwrap_api(body);
}

fn unwrap_api<T>(body: ApiResponse<T>) -> T {
    if let Some(error) = body.error {
        eprintln!("{} {error}", "Error:".red());
        std::process::exit(1);
    }
    body.data.unwrap_or_else(|| {
        eprintln!("{}", "API response did not include data.".red());
        std::process::exit(1);
    })
}

fn truncate(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        return value.to_string();
    }
    let mut out = value
        .chars()
        .take(max.saturating_sub(1))
        .collect::<String>();
    out.push('…');
    out
}

fn format_json_value(val: &serde_json::Value) -> String {
    match val {
        serde_json::Value::Null => "(nil)".to_string(),
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Array(arr) => arr
            .iter()
            .map(format_json_value)
            .collect::<Vec<_>>()
            .join("\n"),
        serde_json::Value::Object(_) => val.to_string(),
    }
}

fn build_project_env(
    instance_id: &str,
    api_url: &str,
    direct_url: &str,
    publishable_key: Option<&str>,
    secret_key: Option<&str>,
) -> String {
    // One primary URL. The SDK derives the auth endpoint ({LUX_URL}/auth/v1) and
    // everything else from it. LUX_DIRECT_URL is the optional escape hatch for a
    // direct (operator) connection that bypasses the gateway.
    let project_api_url = format!("{api_url}/v1/{instance_id}");
    [
        format!("LUX_PROJECT_ID={instance_id}"),
        format!("LUX_URL={project_api_url}"),
        format!("LUX_DIRECT_URL={direct_url}"),
        format!(
            "LUX_PUBLISHABLE_KEY={}",
            publishable_key.unwrap_or_default()
        ),
        format!("LUX_SECRET_KEY={}", secret_key.unwrap_or_default()),
        String::new(),
    ]
    .join("\n")
}

fn resp_encode(args: &[&str]) -> Vec<u8> {
    let mut cmd = format!("*{}\r\n", args.len());
    for a in args {
        cmd.push_str(&format!("${}\r\n{}\r\n", a.len(), a));
    }
    cmd.into_bytes()
}

fn resp_encode_strings(args: &[String]) -> Vec<u8> {
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    resp_encode(&refs)
}

fn resp_read_line<R: BufRead>(reader: &mut R) -> Result<String, String> {
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| format!("read error: {e}"))?;
    Ok(line.trim_end().to_string())
}

const RESP_MAX_DEPTH: u8 = 8;

fn resp_read_response<R: BufRead>(reader: &mut R) -> Result<String, String> {
    resp_read_response_inner(reader, 0)
}

fn resp_read_response_inner<R: BufRead>(reader: &mut R, depth: u8) -> Result<String, String> {
    if depth > RESP_MAX_DEPTH {
        return Err("RESP nesting too deep".to_string());
    }
    let line = resp_read_line(reader)?;
    if line.is_empty() {
        return Err("empty response".to_string());
    }
    let prefix = line.as_bytes()[0];
    let rest = &line[1..];

    match prefix {
        b'+' => Ok(rest.to_string()),
        b'-' => Err(rest.to_string()),
        b':' => Ok(format!("(integer) {rest}")),
        b'$' => {
            let len: i64 = rest
                .parse()
                .map_err(|_| "invalid bulk length".to_string())?;
            if len < 0 {
                return Ok("(nil)".to_string());
            }
            let mut buf = vec![0u8; (len + 2) as usize];
            reader
                .read_exact(&mut buf)
                .map_err(|e| format!("read error: {e}"))?;
            Ok(String::from_utf8_lossy(&buf[..len as usize]).to_string())
        }
        b'*' => {
            let count: i64 = rest
                .parse()
                .map_err(|_| "invalid array length".to_string())?;
            if count < 0 {
                return Ok("(empty array)".to_string());
            }
            let mut lines = Vec::new();
            for i in 0..count {
                let elem = resp_read_response_inner(reader, depth + 1)?;
                lines.push(format!("{}) {elem}", i + 1));
            }
            Ok(lines.join("\n"))
        }
        _ => Ok(line),
    }
}

enum DirectStream {
    Plain(TcpStream),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
}

impl Read for DirectStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            DirectStream::Plain(stream) => stream.read(buf),
            DirectStream::Tls(stream) => stream.read(buf),
        }
    }
}

impl Write for DirectStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            DirectStream::Plain(stream) => stream.write(buf),
            DirectStream::Tls(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            DirectStream::Plain(stream) => stream.flush(),
            DirectStream::Tls(stream) => stream.flush(),
        }
    }
}

struct DirectConn {
    reader: BufReader<DirectStream>,
}

impl DirectConn {
    fn connect(host: &str, port: u16, password: &str) -> Result<Self, String> {
        Self::connect_with_tls(host, port, password, false)
    }

    fn connect_target(target: &ConnectionTarget) -> Result<Self, String> {
        Self::connect_with_tls(&target.host, target.port, &target.password, target.tls)
    }

    fn connect_with_tls(host: &str, port: u16, password: &str, tls: bool) -> Result<Self, String> {
        let stream = TcpStream::connect(format!("{host}:{port}"))
            .map_err(|e| format!("connection failed: {e}"))?;
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .ok();
        stream
            .set_write_timeout(Some(std::time::Duration::from_secs(10)))
            .ok();
        let stream = if tls {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
            let root_store = RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            let config = ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            let server_name = ServerName::try_from(host.to_string())
                .map_err(|_| "invalid TLS host".to_string())?;
            let connection = ClientConnection::new(Arc::new(config), server_name)
                .map_err(|e| format!("TLS setup failed: {e}"))?;
            DirectStream::Tls(Box::new(StreamOwned::new(connection, stream)))
        } else {
            DirectStream::Plain(stream)
        };
        let reader = BufReader::new(stream);
        let mut conn = DirectConn { reader };

        if !password.is_empty() {
            let result = conn.exec(&format!("AUTH {password}"));
            if let Err(e) = result {
                return Err(format!("authentication failed: {e}"));
            }
        }
        Ok(conn)
    }

    fn exec(&mut self, command: &str) -> Result<String, String> {
        let parts: Vec<&str> = command.split_whitespace().collect();
        if parts.is_empty() {
            return Err("empty command".to_string());
        }
        self.reader
            .get_mut()
            .write_all(&resp_encode(&parts))
            .map_err(|e| format!("write error: {e}"))?;
        self.reader
            .get_mut()
            .flush()
            .map_err(|e| format!("write error: {e}"))?;
        resp_read_response(&mut self.reader)
    }

    fn exec_args(&mut self, args: &[String]) -> Result<String, String> {
        if args.is_empty() {
            return Err("empty command".to_string());
        }
        self.reader
            .get_mut()
            .write_all(&resp_encode_strings(args))
            .map_err(|e| format!("write error: {e}"))?;
        self.reader
            .get_mut()
            .flush()
            .map_err(|e| format!("write error: {e}"))?;
        resp_read_response(&mut self.reader)
    }
}

enum MigrateTarget {
    Cloud {
        client: reqwest::Client,
        api_url: String,
        token: String,
        instance_id: String,
    },
    Direct(Box<DirectConn>),
}

impl MigrateTarget {
    async fn exec(&mut self, command: &str) -> Result<String, String> {
        match self {
            MigrateTarget::Cloud {
                client,
                api_url,
                token,
                instance_id,
            } => exec_command(client, api_url, token, instance_id, command).await,
            MigrateTarget::Direct(conn) => conn.exec(command),
        }
    }

    async fn exec_args(&mut self, command: &[String]) -> Result<String, String> {
        match self {
            MigrateTarget::Cloud {
                client,
                api_url,
                token,
                instance_id,
            } => exec_command_args(client, api_url, token, instance_id, command).await,
            MigrateTarget::Direct(conn) => conn.exec_args(command),
        }
    }

    async fn migration_list(&mut self) -> Result<Vec<MigrationRecord>, String> {
        match self {
            MigrateTarget::Direct(conn) => {
                let args = vec![
                    "LUX".to_string(),
                    "MIGRATE".to_string(),
                    "LIST".to_string(),
                    "1000".to_string(),
                    "0".to_string(),
                ];
                decode_json(&conn.exec_args(&args)?, "migration list")
            }
            MigrateTarget::Cloud {
                client,
                api_url,
                token,
                instance_id,
            } => {
                cloud_management_request(
                    client,
                    reqwest::Method::GET,
                    format!("{api_url}/projects/{instance_id}/migrations"),
                    token,
                    None,
                )
                .await
            }
        }
    }

    async fn migration_plan(
        &mut self,
        filename: &str,
        body: &str,
    ) -> Result<MigrationPlan, String> {
        match self {
            MigrateTarget::Direct(conn) => {
                let args = vec![
                    "LUX".to_string(),
                    "MIGRATE".to_string(),
                    "PLAN".to_string(),
                    filename.to_string(),
                    body.to_string(),
                ];
                decode_json(&conn.exec_args(&args)?, "migration plan")
            }
            MigrateTarget::Cloud {
                client,
                api_url,
                token,
                instance_id,
            } => {
                cloud_management_request(
                    client,
                    reqwest::Method::POST,
                    format!("{api_url}/projects/{instance_id}/migrations/plan"),
                    token,
                    Some(serde_json::json!({ "filename": filename, "body": body })),
                )
                .await
            }
        }
    }

    async fn migration_apply(
        &mut self,
        filename: &str,
        body: &str,
    ) -> Result<MigrationRecord, String> {
        match self {
            MigrateTarget::Direct(conn) => {
                let args = vec![
                    "LUX".to_string(),
                    "MIGRATE".to_string(),
                    "APPLY".to_string(),
                    filename.to_string(),
                    body.to_string(),
                ];
                let result: DirectMigrationApplyResult =
                    decode_json(&conn.exec_args(&args)?, "migration apply")?;
                let _ = result.already_applied;
                Ok(result.migration)
            }
            MigrateTarget::Cloud {
                client,
                api_url,
                token,
                instance_id,
            } => {
                cloud_management_request(
                    client,
                    reqwest::Method::POST,
                    format!("{api_url}/projects/{instance_id}/migrations/apply"),
                    token,
                    Some(serde_json::json!({ "filename": filename, "body": body })),
                )
                .await
            }
        }
    }

    async fn migration_repair(
        &mut self,
        filename: &str,
        repair: MigrationRepairRequest,
    ) -> Result<MigrationRecord, String> {
        match self {
            MigrateTarget::Direct(conn) => {
                let mut args = vec![
                    "LUX".to_string(),
                    "MIGRATE".to_string(),
                    "REPAIR".to_string(),
                    filename.to_string(),
                ];
                match repair {
                    MigrationRepairRequest::Resume { from_command } => {
                        args.push("RESUME".to_string());
                        args.push(from_command.to_string());
                    }
                    MigrationRepairRequest::MarkApplied => {
                        args.push("MARK-APPLIED".to_string());
                    }
                    MigrationRepairRequest::Abandon => args.push("ABANDON".to_string()),
                }
                decode_json(&conn.exec_args(&args)?, "migration repair")
            }
            MigrateTarget::Cloud {
                client,
                api_url,
                token,
                instance_id,
            } => {
                let payload = match repair {
                    MigrationRepairRequest::Resume { from_command } => serde_json::json!({
                        "filename": filename,
                        "action": "resume",
                        "from_command": from_command,
                    }),
                    MigrationRepairRequest::MarkApplied => serde_json::json!({
                        "filename": filename,
                        "action": "mark_applied",
                    }),
                    MigrationRepairRequest::Abandon => serde_json::json!({
                        "filename": filename,
                        "action": "abandon",
                    }),
                };
                cloud_management_request(
                    client,
                    reqwest::Method::POST,
                    format!("{api_url}/projects/{instance_id}/migrations/repair"),
                    token,
                    Some(payload),
                )
                .await
            }
        }
    }
}

fn decode_json<T: DeserializeOwned>(raw: &str, operation: &str) -> Result<T, String> {
    serde_json::from_str(raw).map_err(|e| format!("{operation} returned invalid JSON: {e}"))
}

async fn cloud_management_request<T: DeserializeOwned>(
    client: &reqwest::Client,
    method: reqwest::Method,
    url: String,
    token: &str,
    payload: Option<serde_json::Value>,
) -> Result<T, String> {
    let mut request = client
        .request(method, url)
        .header("Authorization", format!("Bearer {token}"));
    if let Some(payload) = payload {
        request = request.json(&payload);
    }
    let response = request
        .send()
        .await
        .map_err(|e| format!("cloud request failed: {e}"))?;
    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|e| format!("cloud response could not be read: {e}"))?;
    let envelope: ApiResponse<T> = serde_json::from_str(&text).map_err(|e| {
        format!(
            "cloud management API returned invalid JSON (HTTP {}): {e}",
            status.as_u16()
        )
    })?;
    if !status.is_success() {
        return Err(envelope
            .error
            .unwrap_or_else(|| format!("cloud request failed (HTTP {})", status.as_u16())));
    }
    envelope
        .data
        .ok_or_else(|| "cloud management API returned no data".to_string())
}

async fn resolve_migrate_target(
    project: Option<&str>,
    host: Option<&str>,
    port: Option<u16>,
    password: Option<&str>,
    api_url_override: &Option<String>,
) -> MigrateTarget {
    // For local targets, fall back to the password persisted by `lux start`
    // (fixes the NOAUTH that bit Jack when no password was passed).
    let local_state = load_local_state();
    let local_pw = || local_state.as_ref().map(|s| s.password.clone());

    if host.is_some() || port.is_some() {
        let h = host.unwrap_or("localhost");
        let p = port.unwrap_or(DEFAULT_RESP_PORT);
        let owned_pw = password.map(str::to_string).or_else(local_pw);
        let pw = owned_pw.as_deref().unwrap_or("");
        match DirectConn::connect(h, p, pw) {
            Ok(conn) => return MigrateTarget::Direct(Box::new(conn)),
            Err(e) => {
                eprintln!("{} {}", "Error:".red(), e);
                std::process::exit(1);
            }
        }
    }

    let explicit = explicit_project(project);
    let project = match explicit {
        Some(p) if !p.is_empty() => p,
        _ => {
            // No project and no host/port: default to the local engine, using
            // its persisted port + password when `lux start` has run.
            let local_port = local_state
                .as_ref()
                .map(|s| s.resp_port)
                .unwrap_or(DEFAULT_RESP_PORT);
            let owned_pw = password.map(str::to_string).or_else(local_pw);
            let pw = owned_pw.as_deref().unwrap_or("");
            let local_host = local_state
                .as_ref()
                .map(LocalState::connection_host)
                .unwrap_or_else(|| "localhost".to_string());
            match DirectConn::connect(&local_host, local_port, pw) {
                Ok(conn) => return MigrateTarget::Direct(Box::new(conn)),
                Err(e) => {
                    eprintln!(
                        "{} No project specified and local connection failed: {}",
                        "Error:".red(),
                        e
                    );
                    eprintln!(
                        "Usage: {} or {}",
                        "lux migrate run <project>".bold(),
                        "lux migrate run --host <host> --port <port>".bold()
                    );
                    std::process::exit(1);
                }
            }
        }
    };

    // Check if it's a connection URL
    if is_connection_url(project) {
        let target = parse_connection_url(project);
        match DirectConn::connect_target(&target) {
            Ok(conn) => return MigrateTarget::Direct(Box::new(conn)),
            Err(e) => {
                eprintln!("{} {}", "Error:".red(), e);
                std::process::exit(1);
            }
        }
    }

    // Cloud project
    let project_owned = project.to_string();
    let project = project_owned.as_str();
    let (client, api_url, token) = get_client(api_url_override);
    let inst = find_project(&client, &api_url, &token, project).await;
    MigrateTarget::Cloud {
        client,
        api_url,
        token,
        instance_id: inst.id,
    }
}

fn migration_plan_error(plan: &MigrationPlan) {
    eprintln!(
        "{} Migration '{}' is {}: {}",
        "Error:".red(),
        plan.filename,
        plan.action.as_str(),
        plan.reason.as_deref().unwrap_or("no reason returned")
    );
    eprintln!(
        "Inspect progress with {}, then use {} if the target has a partial migration.",
        "lux migrate status".cyan(),
        format!("lux migrate repair {} ...", plan.filename).cyan()
    );
}

async fn migration_plans(
    target: &mut MigrateTarget,
    dir: &Path,
) -> Result<Vec<MigrationPlan>, String> {
    let mut plans = Vec::new();
    for (filename, body) in get_local_migrations(dir) {
        plans.push(target.migration_plan(&filename, &body).await?);
    }
    Ok(plans)
}

async fn print_migration_plan(target: &mut MigrateTarget, dir: &Path) -> bool {
    let plans = migration_plans(target, dir).await.unwrap_or_else(|e| {
        eprintln!("{} Could not plan migrations: {e}", "Error:".red());
        std::process::exit(1);
    });
    if plans.is_empty() {
        println!(
            "{} {}",
            "No migration files found in".dimmed(),
            dir.display()
        );
        return true;
    }
    println!(
        "  {:<40}  {:<16}  {:>8}  {}",
        "MIGRATION".dimmed(),
        "ACTION".dimmed(),
        "COMMANDS".dimmed(),
        "REASON".dimmed()
    );
    for plan in &plans {
        let action = match plan.action {
            MigrationPlanAction::Apply => plan.action.as_str().yellow().to_string(),
            MigrationPlanAction::AlreadyApplied => "applied".green().to_string(),
            MigrationPlanAction::Conflict | MigrationPlanAction::Blocked => {
                plan.action.as_str().red().to_string()
            }
        };
        println!(
            "  {:<40}  {:<16}  {:>8}  {}",
            plan.filename,
            action,
            plan.command_count,
            plan.reason.as_deref().unwrap_or("")
        );
    }
    !plans.iter().any(|plan| {
        matches!(
            plan.action,
            MigrationPlanAction::Conflict | MigrationPlanAction::Blocked
        )
    })
}

async fn print_migration_status(target: &mut MigrateTarget, dir: &Path) -> bool {
    let records = target.migration_list().await.unwrap_or_else(|e| {
        eprintln!("{} Could not list target migrations: {e}", "Error:".red());
        std::process::exit(1);
    });
    let plans = migration_plans(target, dir).await.unwrap_or_else(|e| {
        eprintln!("{} Could not compare local migrations: {e}", "Error:".red());
        std::process::exit(1);
    });

    println!(
        "  {:<40}  {:<12}  {:<12}  {}",
        "MIGRATION".dimmed(),
        "LOCAL".dimmed(),
        "TARGET".dimmed(),
        "PROGRESS / DETAIL".dimmed()
    );
    let mut seen = HashSet::new();
    let mut clean = true;
    for plan in &plans {
        seen.insert(plan.filename.clone());
        let record = records
            .iter()
            .find(|record| record.filename == plan.filename);
        let (target_status, detail) = match record {
            Some(record) => (record.status.clone(), migration_record_detail(record)),
            None => (
                "not_recorded".to_string(),
                plan.reason.clone().unwrap_or_default(),
            ),
        };
        let local_status = match plan.action {
            MigrationPlanAction::AlreadyApplied => "applied",
            MigrationPlanAction::Apply => "pending",
            MigrationPlanAction::Conflict => "conflict",
            MigrationPlanAction::Blocked => "blocked",
        };
        if plan.action != MigrationPlanAction::AlreadyApplied {
            clean = false;
        }
        println!(
            "  {:<40}  {:<12}  {:<12}  {}",
            plan.filename, local_status, target_status, detail
        );
    }
    for record in records
        .iter()
        .filter(|record| !seen.contains(&record.filename))
    {
        if matches!(record.status.as_str(), "applying" | "failed") {
            clean = false;
        }
        println!(
            "  {:<40}  {:<12}  {:<12}  {}",
            record.filename,
            "remote_only",
            record.status,
            migration_record_detail(record)
        );
    }
    if plans.is_empty() && records.is_empty() {
        println!("  {}", "No local or target migrations.".dimmed());
    }
    if !clean {
        eprintln!(
            "\n{} Pending, conflicting, or partial migrations require attention.",
            "Check failed:".red()
        );
    }
    clean
}

fn migration_record_detail(record: &MigrationRecord) -> String {
    let mut detail = format!(
        "{}/{} commands",
        record.completed_commands, record.command_count
    );
    if let Some(error) = record.error.as_deref().filter(|error| !error.is_empty()) {
        detail.push_str(": ");
        detail.push_str(error);
    }
    detail
}

fn print_migration_record(label: &str, record: &MigrationRecord) {
    println!(
        "{} {} — {} ({})",
        format!("{label}:").bold(),
        record.filename,
        record.status,
        migration_record_detail(record)
    );
}

fn migration_checksum_matches(record: &MigrationRecord, body: &str) -> bool {
    let algorithm = record.checksum_algorithm.as_str();
    match algorithm {
        "sha256" => record.checksum == sha256_hash(body),
        "djb2-64" => record.checksum == legacy_djb2_hash(body),
        "fnv1a-32-utf16" => record.checksum == legacy_fnv1a_hash(body),
        "legacy" | "" => {
            record.checksum == legacy_djb2_hash(body) || record.checksum == legacy_fnv1a_hash(body)
        }
        _ => false,
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct EngineManagementVersion {
    version: String,
    api_version: String,
    capabilities: Vec<String>,
}

#[derive(Serialize)]
struct DoctorCheck {
    target: String,
    check: String,
    status: String,
    detail: String,
    fixed: bool,
}

#[derive(Serialize)]
struct DoctorReport {
    healthy: bool,
    checks: Vec<DoctorCheck>,
}

fn add_doctor_check(
    checks: &mut Vec<DoctorCheck>,
    target: &str,
    check: &str,
    status: &str,
    detail: impl Into<String>,
    fixed: bool,
) {
    checks.push(DoctorCheck {
        target: target.to_string(),
        check: check.to_string(),
        status: status.to_string(),
        detail: detail.into(),
        fixed,
    });
}

async fn run_doctor(
    project: Option<&str>,
    all: bool,
    fix: bool,
    output: Option<&str>,
    api_url_override: &Option<String>,
) -> bool {
    let mut checks = Vec::new();
    let check_local = project.is_none() || all;
    let check_cloud = project.is_some() || all;
    if check_local {
        doctor_local(fix, &mut checks).await;
    }
    if check_cloud {
        let selector = project
            .map(str::to_string)
            .or_else(|| load_local_config().and_then(|config| config.project_id));
        match selector {
            Some(selector) => doctor_cloud(&selector, api_url_override, &mut checks).await,
            None => add_doctor_check(
                &mut checks,
                "cloud",
                "linked project",
                "fail",
                "`--all` needs a linked cloud project; run `lux link <project>`",
                false,
            ),
        }
    }
    let healthy = !checks.iter().any(|check| check.status == "fail");
    let report = DoctorReport { healthy, checks };
    if output == Some("json") {
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    } else {
        print_doctor_report(&report, fix);
    }
    healthy
}

async fn doctor_local(fix: bool, checks: &mut Vec<DoctorCheck>) {
    let migration_dir = Path::new("lux/migrations");
    let migration_missing = !migration_dir.is_dir();
    let mut migration_fixed = false;
    if migration_missing && fix {
        migration_fixed = std::fs::create_dir_all(migration_dir).is_ok();
    }
    add_doctor_check(
        checks,
        "local",
        "migration directory",
        if migration_dir.is_dir() {
            "pass"
        } else {
            "warn"
        },
        if migration_dir.is_dir() {
            "lux/migrations is present"
        } else {
            "lux/migrations is missing; `doctor --fix` can create it"
        },
        migration_fixed,
    );

    let ignored = [
        ".env.local",
        "lux/.lux-local.json",
        "lux/.env-profiles/",
        "lux/.backups/",
        "lux/.lux-cluster/",
    ];
    let gitignore_path = Path::new(".gitignore");
    let existing = std::fs::read_to_string(gitignore_path).unwrap_or_default();
    let missing_ignore = gitignore_merge(&existing, &ignored);
    let mut gitignore_fixed = false;
    if missing_ignore.is_some() && fix {
        ensure_gitignore(&ignored);
        gitignore_fixed = gitignore_merge(
            &std::fs::read_to_string(gitignore_path).unwrap_or_default(),
            &ignored,
        )
        .is_none();
    }
    add_doctor_check(
        checks,
        "local",
        "secret ignores",
        if missing_ignore.is_none() || gitignore_fixed {
            "pass"
        } else {
            "fail"
        },
        if missing_ignore.is_none() || gitignore_fixed {
            "Lux secret-bearing files are gitignored"
        } else {
            "Lux secret-bearing paths are missing from .gitignore"
        },
        gitignore_fixed,
    );

    let Some(state) = load_local_state() else {
        add_doctor_check(
            checks,
            "local",
            "runtime state",
            "fail",
            "lux/.lux-local.json is missing; run `lux start`",
            false,
        );
        return;
    };
    add_doctor_check(
        checks,
        "local",
        "runtime state",
        "pass",
        format!("local runtime targets {}", state.image),
        false,
    );

    let docker_available = docker_preflight().is_ok();
    add_doctor_check(
        checks,
        "local",
        "Docker",
        if docker_available { "pass" } else { "fail" },
        if docker_available {
            "Docker daemon is reachable"
        } else {
            "Docker is unavailable"
        },
        false,
    );
    let container_state = docker_container_state(&state.container);
    add_doctor_check(
        checks,
        "local",
        "engine container",
        if container_state.as_deref() == Some("running") {
            "pass"
        } else {
            "fail"
        },
        match container_state.as_deref() {
            Some(value) => format!("{} is {value}", state.container),
            None => format!("{} does not exist", state.container),
        },
        false,
    );

    if let Some(cluster) = &state.cluster {
        let artifacts = std::iter::once(cluster.controller_private_key_file.as_str())
            .chain(std::iter::once(cluster.topology_file.as_str()))
            .chain(cluster.nodes.iter().flat_map(|node| {
                [
                    node.certificate_file.as_str(),
                    node.private_key_file.as_str(),
                    node.config_file.as_str(),
                ]
            }))
            .map(|file| local_cluster_dir().join(file))
            .collect::<Vec<_>>();
        let missing = artifacts
            .iter()
            .filter(|path| !path.is_file())
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>();
        add_doctor_check(
            checks,
            "local",
            "cluster identity",
            if missing.is_empty() { "pass" } else { "fail" },
            if missing.is_empty() {
                format!(
                    "signed cluster {} has {} node identities",
                    cluster.cluster_id,
                    cluster.nodes.len()
                )
            } else {
                format!("missing cluster artifacts: {}", missing.join(", "))
            },
            false,
        );

        let mut unhealthy = Vec::new();
        let mut transitioning = cluster
            .pending_resize
            .as_ref()
            .map(|resize| {
                vec![format!(
                    "controller resize {} to {} nodes",
                    resize.direction, resize.desired_nodes
                )]
            })
            .unwrap_or_default();
        for node in &cluster.nodes {
            if docker_container_state(&node.container).as_deref() != Some("running") {
                unhealthy.push(format!("{} container is not running", node.node_id));
                continue;
            }
            match local_cluster_status(&state, node).await {
                Ok(status) => {
                    let node_cluster = status["current"]["cluster_id"].as_str();
                    let epoch = status["current"]["epoch"].as_u64();
                    if node_cluster != Some(cluster.cluster_id.as_str())
                        || epoch != Some(cluster.epoch)
                    {
                        unhealthy.push(format!(
                            "{} reports cluster {:?} epoch {:?}, expected {} epoch {}",
                            node.node_id, node_cluster, epoch, cluster.cluster_id, cluster.epoch
                        ));
                    }
                    if !status["pending"].is_null() || !status["transfer"].is_null() {
                        transitioning.push(node.node_id.clone());
                    }
                }
                Err(error) => unhealthy.push(error),
            }
        }
        add_doctor_check(
            checks,
            "local",
            "cluster convergence",
            if unhealthy.is_empty() { "pass" } else { "fail" },
            if unhealthy.is_empty() {
                format!(
                    "all {} nodes agree on committed epoch {}",
                    cluster.nodes.len(),
                    cluster.epoch
                )
            } else {
                unhealthy.join("; ")
            },
            false,
        );
        add_doctor_check(
            checks,
            "local",
            "cluster transition",
            if transitioning.is_empty() {
                "pass"
            } else {
                "warn"
            },
            if transitioning.is_empty() {
                "no topology transition is pending".to_string()
            } else {
                format!(
                    "transition state remains: {}; rerun the interrupted resize",
                    transitioning.join(", ")
                )
            },
            false,
        );
    }

    let mut profile_fixed = false;
    let profile_ok = load_profile_index().is_ok_and(|index| {
        resolve_profile(&index, "local").is_some_and(|profile| profile_path(profile).is_file())
    });
    if !profile_ok && fix {
        profile_fixed = refresh_local_profile(&state).is_ok();
    }
    add_doctor_check(
        checks,
        "local",
        "env profile",
        if profile_ok || profile_fixed {
            "pass"
        } else {
            "fail"
        },
        if profile_ok || profile_fixed {
            "saved local app environment matches runtime state"
        } else {
            "local env profile is missing or unreadable"
        },
        profile_fixed,
    );

    let conn = match DirectConn::connect(&state.connection_host(), state.resp_port, &state.password)
    {
        Ok(conn) => conn,
        Err(error) => {
            add_doctor_check(checks, "local", "engine connection", "fail", error, false);
            return;
        }
    };
    let mut target = MigrateTarget::Direct(Box::new(conn));
    doctor_engine_contract("local", &mut target, checks).await;
    doctor_migrations("local", &mut target, Path::new("lux/migrations"), checks).await;
}

async fn doctor_cloud(
    selector: &str,
    api_url_override: &Option<String>,
    checks: &mut Vec<DoctorCheck>,
) {
    let (client, api_url, token) = get_client(api_url_override);
    let instance = find_project(&client, &api_url, &token, selector).await;
    let target_name = format!("cloud:{}", instance.name);
    add_doctor_check(
        checks,
        &target_name,
        "project status",
        if instance.status == "running" {
            "pass"
        } else {
            "fail"
        },
        format!("project is {}", instance.status),
        false,
    );
    let profile_ok = load_profile_index().is_ok_and(|index| {
        index.profiles.iter().any(|profile| {
            profile.kind == "cloud"
                && profile.project_id.as_deref() == Some(instance.id.as_str())
                && profile_path(profile).is_file()
        })
    });
    add_doctor_check(
        checks,
        &target_name,
        "env profile",
        if profile_ok { "pass" } else { "warn" },
        if profile_ok {
            "saved cloud app environment is available"
        } else {
            "no saved env profile; run `lux env pull <project>`"
        },
        false,
    );
    if instance.status != "running" {
        return;
    }
    // Cloud intentionally rejects generic `LUX` commands through its console.
    // Version/capability discovery is a read-only operator check, so run it
    // against the project's authenticated direct RESP endpoint instead.
    let engine_contract = try_get_instance_credentials(&client, &api_url, &token, &instance.id)
        .await
        .and_then(|credentials| direct_engine_contract(&credentials.resp));
    record_engine_contract_check(&target_name, engine_contract, checks);

    // Migration operations keep using Cloud's dedicated management endpoints.
    let mut target = MigrateTarget::Cloud {
        client,
        api_url,
        token,
        instance_id: instance.id,
    };
    doctor_migrations(
        &target_name,
        &mut target,
        Path::new("lux/migrations"),
        checks,
    )
    .await;
}

async fn doctor_engine_contract(
    target_name: &str,
    target: &mut MigrateTarget,
    checks: &mut Vec<DoctorCheck>,
) {
    let version = target
        .exec("LUX VERSION")
        .await
        .and_then(|raw| decode_json::<EngineManagementVersion>(&raw, "engine version"));
    record_engine_contract_check(target_name, version, checks);
}

fn direct_engine_contract(url: &str) -> Result<EngineManagementVersion, String> {
    let target = parse_connection_url(url);
    let mut conn = DirectConn::connect_target(&target)?;
    let raw = conn.exec("LUX VERSION")?;
    decode_json(&raw, "engine version")
}

fn record_engine_contract_check(
    target_name: &str,
    version: Result<EngineManagementVersion, String>,
    checks: &mut Vec<DoctorCheck>,
) {
    match version {
        Ok(version) => {
            let required = ["migrations.plan", "migrations.apply", "migrations.repair"];
            let missing: Vec<&str> = required
                .iter()
                .filter(|capability| {
                    !version
                        .capabilities
                        .iter()
                        .any(|present| present == **capability)
                })
                .copied()
                .collect();
            add_doctor_check(
                checks,
                target_name,
                "engine management API",
                if missing.is_empty() { "pass" } else { "fail" },
                if missing.is_empty() {
                    format!(
                        "engine {} (management API {}) supports managed migrations",
                        version.version, version.api_version
                    )
                } else {
                    format!("engine is missing capabilities: {}", missing.join(", "))
                },
                false,
            );
        }
        Err(error) => add_doctor_check(
            checks,
            target_name,
            "engine management API",
            "fail",
            error,
            false,
        ),
    }
}

async fn doctor_migrations(
    target_name: &str,
    target: &mut MigrateTarget,
    dir: &Path,
    checks: &mut Vec<DoctorCheck>,
) {
    let records = match target.migration_list().await {
        Ok(records) => records,
        Err(error) => {
            add_doctor_check(checks, target_name, "migration state", "fail", error, false);
            return;
        }
    };
    if let Some(record) = records
        .iter()
        .find(|record| matches!(record.status.as_str(), "applying" | "failed"))
    {
        add_doctor_check(
            checks,
            target_name,
            "migration state",
            "fail",
            format!(
                "{} is {} at {}/{} commands; repair it explicitly",
                record.filename, record.status, record.completed_commands, record.command_count
            ),
            false,
        );
        return;
    }
    match migration_plans(target, dir).await {
        Ok(plans) => {
            let conflicts = plans
                .iter()
                .filter(|plan| {
                    matches!(
                        plan.action,
                        MigrationPlanAction::Conflict | MigrationPlanAction::Blocked
                    )
                })
                .count();
            let pending = plans
                .iter()
                .filter(|plan| plan.action == MigrationPlanAction::Apply)
                .count();
            add_doctor_check(
                checks,
                target_name,
                "migration state",
                if conflicts > 0 {
                    "fail"
                } else if pending > 0 {
                    "warn"
                } else {
                    "pass"
                },
                if conflicts > 0 {
                    format!("{conflicts} migration conflict(s) or blocker(s)")
                } else if pending > 0 {
                    format!("{pending} migration(s) pending")
                } else {
                    "local files and target ledger agree".to_string()
                },
                false,
            );
        }
        Err(error) => {
            add_doctor_check(checks, target_name, "migration state", "fail", error, false)
        }
    }
}

fn print_doctor_report(report: &DoctorReport, fix: bool) {
    println!(
        "  {:<24}  {:<24}  {:<7}  {}",
        "TARGET".dimmed(),
        "CHECK".dimmed(),
        "STATUS".dimmed(),
        "DETAIL".dimmed()
    );
    for check in &report.checks {
        let status = match check.status.as_str() {
            "pass" => "pass".green().to_string(),
            "warn" => "warn".yellow().to_string(),
            _ => "fail".red().to_string(),
        };
        let fixed = if check.fixed { " (fixed)" } else { "" };
        println!(
            "  {:<24}  {:<24}  {:<7}  {}{}",
            check.target, check.check, status, check.detail, fixed
        );
    }
    if report.healthy {
        println!("\n{}", "Doctor found no blocking problems.".green());
    } else {
        println!("\n{}", "Doctor found blocking problems.".red());
    }
    if !fix {
        println!(
            "{} only repairs migration directories, secret ignores, and local env profiles.",
            "`lux doctor --fix`".cyan()
        );
    }
}

fn get_local_migrations(dir: &Path) -> Vec<(String, String)> {
    if !dir.exists() {
        return vec![];
    }
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .unwrap_or_else(|_| {
            eprintln!("{}", "Failed to read lux/migrations/".red());
            std::process::exit(1);
        })
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "lux")
                .unwrap_or(false)
        })
        .map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            let content = std::fs::read_to_string(e.path()).unwrap_or_default();
            (name, content)
        })
        .collect();
    files.sort_by(|a, b| a.0.cmp(&b.0));
    files
}

// ---------------------------------------------------------------------------
// `lux types` — TypeScript codegen from the project schema (TLIST + TSCHEMA)
// ---------------------------------------------------------------------------

/// Parse a rendered array response back into its string elements. Handles both
/// the local RESP rendering ("1) a\n2) b") and the cloud rendering (plain
/// newline-joined elements). Empty/sentinel lines are skipped.
fn parse_resp_array(rendered: &str) -> Vec<String> {
    rendered
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line == "(empty array)" || line == "(nil)" {
                return None;
            }
            // Strip a leading "N) " index prefix (local RESP rendering only).
            if let Some(idx) = line.find(") ") {
                let prefix = &line[..idx];
                if !prefix.is_empty() && prefix.chars().all(|c| c.is_ascii_digit()) {
                    return Some(line[idx + 2..].to_string());
                }
            }
            Some(line.to_string())
        })
        .collect()
}

/// One generated column: (name, ts_type, nullable).
type TsColumn = (String, &'static str, bool);
/// One table model: (table_name, columns).
type TableModel = (String, Vec<TsColumn>);

/// Map a Lux column type token (STR, INT, UUID, VECTOR(384), JSON, ...) to a TS type.
fn lux_type_to_ts(token: &str) -> &'static str {
    let t = token.to_uppercase();
    if t.starts_with("VECTOR") {
        return "number[]";
    }
    match t.as_str() {
        "STR" => "string",
        "INT" | "FLOAT" => "number",
        "BOOL" => "boolean",
        "TIMESTAMP" => "number",
        "UUID" => "string",
        "JSON" => "Json",
        "ARRAY" => "Json[]",
        "REFERENCES" => "string", // legacy ref column (FK to id)
        _ => "unknown",
    }
}

/// Parse one TSCHEMA field spec ("email STR UNIQUE NOT NULL") into
/// (name, ts_type, nullable).
fn parse_field_spec(spec: &str) -> Option<TsColumn> {
    let mut tokens = spec.split_whitespace();
    let name = tokens.next()?.to_string();
    let type_token = tokens.next()?;
    let ts = lux_type_to_ts(type_token);
    let upper = spec.to_uppercase();
    // PRIMARY KEY and NOT NULL both make a column required (non-null). "SET NULL"
    // (on-delete) does not contain "NOT NULL", so this stays correct for FKs.
    let required = upper.contains("PRIMARY KEY") || upper.contains("NOT NULL");
    Some((name, ts, !required))
}

/// snake_case / dotted table name -> PascalCase interface name.
fn to_pascal_case(name: &str) -> String {
    name.split(['_', '.', '-'])
        .filter(|s| !s.is_empty())
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                Some(first) => {
                    first.to_uppercase().collect::<String>() + &chars.as_str().to_lowercase()
                }
                None => String::new(),
            }
        })
        .collect()
}

/// True if `s` is a valid bare TS identifier (else the key needs quoting).
fn is_ts_ident(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' || c == '$' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
}

/// Render the full `.ts` output: a `Json` alias, a Row interface per table,
/// and a `Database` map keyed by table name.
fn generate_types(tables: &[TableModel]) -> String {
    let mut out = String::new();
    out.push_str("// Generated by Lux — `lux types`. Do not edit by hand.\n\n");
    out.push_str(
        "export type Json =\n  | string\n  | number\n  | boolean\n  | null\n  | Json[]\n  | { [key: string]: Json };\n\n",
    );
    for (table, cols) in tables {
        let iface = to_pascal_case(table);
        out.push_str(&format!("export interface {iface} {{\n"));
        for (name, ts, nullable) in cols {
            let ty = if *nullable {
                format!("{ts} | null")
            } else {
                (*ts).to_string()
            };
            let key = if is_ts_ident(name) {
                name.clone()
            } else {
                format!("\"{name}\"")
            };
            out.push_str(&format!("  {key}: {ty};\n"));
        }
        out.push_str("}\n\n");
    }
    // A `type` alias (not an interface) so it satisfies the SDK's schema
    // constraint: `createClient<Database>(...)` then `client.from('table')`.
    out.push_str("export type Database = {\n");
    for (table, _) in tables {
        let iface = to_pascal_case(table);
        let key = if is_ts_ident(table) {
            table.clone()
        } else {
            format!("\"{table}\"")
        };
        out.push_str(&format!("  {key}: {iface};\n"));
    }
    out.push_str("};\n");
    out
}

/// True for engine-internal tables that should not appear in generated types.
fn is_system_table(name: &str) -> bool {
    name.starts_with("auth.") || name.starts_with("__") || name.starts_with("_t:")
}

fn parse_migration_commands(content: &str) -> Result<Vec<Vec<String>>, String> {
    let (statements, saw_semicolon) = split_statements(content);
    if !saw_semicolon {
        // No `;` terminator present: legacy one-command-per-line format.
        return parse_migration_lines(content);
    }
    // Statement-oriented: `;` terminates and newlines are whitespace, so one
    // statement (e.g. a TSELECT with a JOIN) can span multiple lines.
    let mut commands = Vec::new();
    for (index, stmt) in statements.iter().enumerate() {
        let s = stmt.trim();
        if s.is_empty() {
            continue;
        }
        if s.starts_with('[') {
            let parsed: Vec<String> = serde_json::from_str(s).map_err(|e| {
                format!(
                    "statement {} is not a valid JSON argv array: {e}",
                    index + 1
                )
            })?;
            if parsed.is_empty() {
                return Err(format!("statement {} has an empty command", index + 1));
            }
            commands.push(parsed);
            continue;
        }
        let parsed = split_command_line(s)
            .map_err(|e| format!("statement {} could not be parsed: {e}", index + 1))?;
        if !parsed.is_empty() {
            commands.push(parsed);
        }
    }
    Ok(commands)
}

/// Split a migration body into raw statement strings on unquoted `;`, treating
/// newlines as whitespace and stripping `#` / `--` line comments. Returns the
/// statements and whether any `;` terminator was seen (false => the caller falls
/// back to the legacy one-command-per-line format, so old migrations are
/// unaffected).
fn split_statements(content: &str) -> (Vec<String>, bool) {
    let mut statements = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut line_comment = false;
    let mut saw_semicolon = false;
    let mut chars = content.chars().peekable();
    while let Some(ch) = chars.next() {
        if line_comment {
            if ch == '\n' {
                line_comment = false;
                current.push(' ');
            }
            continue;
        }
        match quote {
            Some(q) => {
                current.push(ch);
                if ch == '\\' {
                    if let Some(next) = chars.next() {
                        current.push(next);
                    }
                } else if ch == q {
                    quote = None;
                }
            }
            None => {
                if ch == '#' {
                    line_comment = true;
                } else if ch == '-' && chars.peek() == Some(&'-') {
                    chars.next();
                    line_comment = true;
                } else if ch == '"' || ch == '\'' {
                    quote = Some(ch);
                    current.push(ch);
                } else if ch == ';' {
                    saw_semicolon = true;
                    statements.push(std::mem::take(&mut current));
                } else if ch == '\n' || ch == '\r' {
                    current.push(' ');
                } else {
                    current.push(ch);
                }
            }
        }
    }
    if !current.trim().is_empty() {
        statements.push(current);
    }
    (statements, saw_semicolon)
}

fn parse_migration_lines(content: &str) -> Result<Vec<Vec<String>>, String> {
    let mut commands = Vec::new();
    for (index, raw) in content.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("--") {
            continue;
        }
        if line.starts_with('[') {
            let parsed: Vec<String> = serde_json::from_str(line)
                .map_err(|e| format!("line {} is not a valid JSON argv array: {e}", index + 1))?;
            if parsed.is_empty() {
                return Err(format!("line {} has an empty command", index + 1));
            }
            commands.push(parsed);
            continue;
        }
        let parsed = split_command_line(line)
            .map_err(|e| format!("line {} could not be parsed: {e}", index + 1))?;
        if !parsed.is_empty() {
            commands.push(parsed);
        }
    }
    Ok(commands)
}

fn split_command_line(input: &str) -> Result<Vec<String>, String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        match quote {
            Some(q) => {
                if ch == q {
                    quote = None;
                } else if ch == '\\' {
                    if let Some(next) = chars.next() {
                        current.push(next);
                    }
                } else {
                    current.push(ch);
                }
            }
            None => {
                if ch == '"' || ch == '\'' {
                    quote = Some(ch);
                } else if ch.is_whitespace() {
                    if !current.is_empty() {
                        args.push(std::mem::take(&mut current));
                    }
                } else {
                    current.push(ch);
                }
            }
        }
    }

    if let Some(q) = quote {
        return Err(format!("unterminated {q} quote"));
    }
    if !current.is_empty() {
        args.push(current);
    }
    Ok(args)
}

fn sha256_hash(content: &str) -> String {
    let digest = Sha256::digest(content.as_bytes());
    format!("{digest:x}")
}

fn legacy_djb2_hash(content: &str) -> String {
    let mut hash: u64 = 5381;
    for byte in content.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(byte as u64);
    }
    format!("{:016x}", hash)
}

fn legacy_fnv1a_hash(content: &str) -> String {
    let mut hash: u32 = 0x811c9dc5;
    for unit in content.encode_utf16() {
        hash ^= u32::from(unit);
        hash = hash.wrapping_mul(0x01000193);
    }
    format!("{hash:x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn parses_apple_provider_options() {
        let cli = Cli::try_parse_from([
            "lux",
            "auth",
            "provider",
            "apple",
            "--bundle-id",
            "com.example.ios",
            "--services-id",
            "com.example.web",
            "--team-id",
            "TEAM123456",
            "--key-id",
            "KEY1234567",
            "--p8",
            "AuthKey.p8",
            "--url",
            "https://db.example.com",
            "--password",
            "operator-secret",
        ])
        .expect("Apple provider command parses");

        let Commands::Auth {
            action:
                AuthAction::Provider {
                    action:
                        AuthProviderAction::Apple {
                            team_id,
                            key_id,
                            services_id,
                            bundle_id,
                            p8,
                            conn,
                            ..
                        },
                },
        } = cli.command
        else {
            panic!("expected Apple provider command");
        };
        assert_eq!(team_id.as_deref(), Some("TEAM123456"));
        assert_eq!(key_id.as_deref(), Some("KEY1234567"));
        assert_eq!(services_id.as_deref(), Some("com.example.web"));
        assert_eq!(bundle_id, vec!["com.example.ios"]);
        assert_eq!(p8, Some(PathBuf::from("AuthKey.p8")));
        assert_eq!(conn.url.as_deref(), Some("https://db.example.com"));
        assert_eq!(conn.password.as_deref(), Some("operator-secret"));
    }

    #[test]
    fn provider_secret_is_optional_for_google_updates() {
        let cli = Cli::try_parse_from([
            "lux",
            "auth",
            "provider",
            "google",
            "--client-id",
            "google-client",
        ])
        .expect("Google provider update parses without re-entering the secret");

        let Commands::Auth {
            action:
                AuthAction::Provider {
                    action:
                        AuthProviderAction::Google {
                            client_id,
                            client_secret,
                            ..
                        },
                },
        } = cli.command
        else {
            panic!("expected Google provider command");
        };
        assert_eq!(client_id, "google-client");
        assert_eq!(client_secret, None);
    }

    #[test]
    fn builds_native_and_web_apple_provider_payloads() {
        let native = apple_provider_payload(
            "http://localhost:5890",
            AppleProviderPayload {
                team_id: None,
                key_id: None,
                services_id: None,
                bundle_ids: vec!["com.example.ios".into(), "com.example.macos".into()],
                private_key: None,
                scopes: None,
                disable: false,
            },
        );
        assert_eq!(
            native,
            serde_json::json!({
                "enabled": true,
                "apple_bundle_ids": "com.example.ios,com.example.macos"
            })
        );

        let web = apple_provider_payload(
            "https://db.example.com",
            AppleProviderPayload {
                team_id: Some("TEAM123456".into()),
                key_id: Some("KEY1234567".into()),
                services_id: Some("com.example.web".into()),
                bundle_ids: Vec::new(),
                private_key: Some("private-key".into()),
                scopes: Some("name email".into()),
                disable: true,
            },
        );
        assert_eq!(
            web,
            serde_json::json!({
                "enabled": false,
                "redirect_uri": "https://db.example.com/auth/v1/callback/apple",
                "scopes": "name email",
                "apple_team_id": "TEAM123456",
                "apple_key_id": "KEY1234567",
                "apple_services_id": "com.example.web",
                "apple_private_key": "private-key"
            })
        );
    }

    #[test]
    fn resp_array_strips_index_prefixes() {
        assert_eq!(
            parse_resp_array("1) authors\n2) posts\n3) post_tags"),
            vec!["authors", "posts", "post_tags"]
        );
        // Cloud rendering: plain newline-joined elements (no index prefix).
        assert_eq!(parse_resp_array("authors\nposts"), vec!["authors", "posts"]);
        // Non-array renderings produce nothing.
        assert!(parse_resp_array("(empty array)").is_empty());
        assert!(parse_resp_array("").is_empty());
        // The `) ` inside a schema line isn't mistaken for the index prefix.
        assert_eq!(
            parse_resp_array("1) author_id UUID REFERENCES authors(id) ON DELETE CASCADE"),
            vec!["author_id UUID REFERENCES authors(id) ON DELETE CASCADE"]
        );
    }

    #[test]
    fn field_spec_to_ts_column() {
        assert_eq!(
            parse_field_spec("id UUID PRIMARY KEY"),
            Some(("id".into(), "string", false))
        );
        assert_eq!(
            parse_field_spec("email STR UNIQUE NOT NULL"),
            Some(("email".into(), "string", false))
        );
        assert_eq!(
            parse_field_spec("age INT"),
            Some(("age".into(), "number", true))
        );
        assert_eq!(
            parse_field_spec("active BOOL"),
            Some(("active".into(), "boolean", true))
        );
        assert_eq!(
            parse_field_spec("meta JSON"),
            Some(("meta".into(), "Json", true))
        );
        assert_eq!(
            parse_field_spec("tags ARRAY"),
            Some(("tags".into(), "Json[]", true))
        );
        assert_eq!(
            parse_field_spec("embedding VECTOR(384)"),
            Some(("embedding".into(), "number[]", true))
        );
        // FK column: nullable (ON DELETE SET NULL must not read as NOT NULL).
        assert_eq!(
            parse_field_spec("author_id UUID REFERENCES authors(id) ON DELETE SET NULL"),
            Some(("author_id".into(), "string", true))
        );
    }

    #[test]
    fn pascal_case_table_names() {
        assert_eq!(to_pascal_case("authors"), "Authors");
        assert_eq!(to_pascal_case("post_tags"), "PostTags");
        assert_eq!(to_pascal_case("auth.users"), "AuthUsers");
    }

    #[test]
    fn generate_types_output() {
        let tables = vec![(
            "authors".to_string(),
            vec![
                ("id".to_string(), "string", false),
                ("name".to_string(), "string", false),
                ("bio".to_string(), "string", true),
            ],
        )];
        let ts = generate_types(&tables);
        assert!(ts.contains("export type Json"));
        assert!(ts.contains("export interface Authors {"));
        assert!(ts.contains("  id: string;"));
        assert!(ts.contains("  bio: string | null;"));
        assert!(ts.contains("export type Database = {"));
        assert!(ts.contains("  authors: Authors;"));
    }

    #[test]
    fn parses_lux_connection_urls_with_password() {
        let target = parse_connection_url("lux://:secret@db.example.com:10000");

        assert_eq!(target.host, "db.example.com");
        assert_eq!(target.port, 10000);
        assert_eq!(target.password, "secret");
        assert_eq!(target.name, "db.example.com:10000");
        assert!(!target.tls);
    }

    #[test]
    fn project_slug_is_stable_readable_and_unique() {
        // Stable for the same cwd across calls.
        let a = project_slug();
        let b = project_slug();
        assert_eq!(a, b);
        // Shape: `<sanitized>-<6 hex>`, lowercase/alnum/hyphen only.
        let (name, hash) = a.rsplit_once('-').expect("slug has a -<hash> suffix");
        assert_eq!(hash.len(), 6);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!name.is_empty());
        assert!(name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'));
    }

    #[test]
    fn project_slug_hash_disambiguates_same_basename() {
        // Two different absolute paths sharing a basename must not collide.
        assert_ne!(
            hash_str("/home/a/app") & 0xff_ffff,
            hash_str("/home/b/app") & 0xff_ffff
        );
    }

    #[test]
    fn free_port_returns_preferred_when_open() {
        let bind_host = default_bind_host();
        let listener = std::net::TcpListener::bind((bind_host, 0)).unwrap();
        let taken = listener.local_addr().unwrap().port();
        let chosen = free_port_from(bind_host, taken);
        assert_ne!(chosen, taken, "should not pick the bound port");
        assert!(chosen > taken);
        assert!(port_is_free(bind_host, chosen));
    }

    #[test]
    fn docker_port_maps_are_address_scoped() {
        assert_eq!(
            docker_port_map("127.0.0.1".parse().unwrap(), 5890, 5890),
            "127.0.0.1:5890:5890"
        );
        assert_eq!(
            docker_port_map("::1".parse().unwrap(), 5891, 80),
            "[::1]:5891:80"
        );
    }

    #[test]
    fn published_bindings_must_match_address_and_port() {
        let loopback = "127.0.0.1".parse().unwrap();
        assert!(published_binding_matches("127.0.0.1 5890", loopback, 5890));
        assert!(!published_binding_matches("0.0.0.0 5890", loopback, 5890));
        assert!(!published_binding_matches("127.0.0.1 5891", loopback, 5890));
        assert!(!published_binding_matches("127.0.0.1", loopback, 5890));
    }

    #[test]
    fn start_bind_flag_parses_ip_addresses() {
        let cli = Cli::try_parse_from(["lux", "start", "--bind", "192.0.2.10"]).unwrap();
        let Commands::Start { bind, .. } = cli.command else {
            panic!("expected start command");
        };
        assert_eq!(bind, Some("192.0.2.10".parse().unwrap()));
    }

    #[test]
    fn local_cluster_commands_parse_and_bound_node_counts() {
        let cli = Cli::try_parse_from(["lux", "start", "--nodes", "3"]).unwrap();
        let Commands::Start { nodes, .. } = cli.command else {
            panic!("expected start command");
        };
        assert_eq!(nodes, Some(3));

        let cli = Cli::try_parse_from(["lux", "cluster", "resize", "4"]).unwrap();
        let Commands::Cluster {
            action: ClusterAction::Resize { nodes },
        } = cli.command
        else {
            panic!("expected cluster resize command");
        };
        assert_eq!(nodes, 4);
        assert!(Cli::try_parse_from(["lux", "start", "--nodes", "0"]).is_err());
        assert!(Cli::try_parse_from(["lux", "cluster", "resize", "17"]).is_err());
    }

    #[test]
    fn balanced_cluster_assignments_cover_every_slot_once() {
        let nodes = (1..=3)
            .map(|ordinal| LocalClusterNode {
                node_id: format!("node-{ordinal}"),
                container: format!("node-{ordinal}"),
                volume: format!("volume-{ordinal}"),
                http_port: 5900 + ordinal,
                server_name: format!("node-{ordinal}.cluster.local"),
                certificate_der: String::new(),
                certificate_file: String::new(),
                private_key_file: String::new(),
                config_file: String::new(),
            })
            .collect::<Vec<_>>();
        let assignments = balanced_slot_assignments(&nodes);
        assert_eq!(assignments.first().unwrap().start, 0);
        assert_eq!(assignments.last().unwrap().end, CLUSTER_SLOT_COUNT - 1);
        for pair in assignments.windows(2) {
            assert_eq!(pair[0].end + 1, pair[1].start);
        }
        for slot in 0..CLUSTER_SLOT_COUNT {
            assert_eq!(
                assignments
                    .iter()
                    .filter(|assignment| slot >= assignment.start && slot <= assignment.end)
                    .count(),
                1
            );
        }
        let two = balanced_slot_assignments(&nodes[..2]);
        let targets = ownership_target_nodes(&two, &assignments);
        assert!(targets.contains("node-2"));
        assert!(targets.contains("node-3"));
        assert!(!targets.contains("node-1"));
    }

    #[test]
    fn parses_tls_connection_urls() {
        let target = parse_connection_url("luxs://:secret@db.example.com:6380");

        assert_eq!(target.host, "db.example.com");
        assert_eq!(target.port, 6380);
        assert_eq!(target.password, "secret");
        assert_eq!(target.name, "db.example.com:6380");
        assert!(target.tls);
    }

    #[test]
    fn parses_connection_urls_without_password_or_port() {
        let target = parse_connection_url("redis://localhost");

        assert_eq!(target.host, "localhost");
        assert_eq!(target.port, 6379);
        assert_eq!(target.password, "");
        assert_eq!(target.name, "localhost:6379");
        assert!(!target.tls);
    }

    #[test]
    fn identifies_direct_connection_urls() {
        assert!(is_connection_url("lux://:secret@localhost:10000"));
        assert!(is_connection_url("luxs://:secret@localhost:6380"));
        assert!(is_connection_url("redis://localhost"));
        assert!(is_connection_url("rediss://localhost"));
        assert!(!is_connection_url("cache"));
        assert!(!is_connection_url("localhost:10000"));
    }

    #[test]
    fn splits_command_lines_with_quotes_and_escapes() {
        let args = split_command_line(
            r#"TINSERT users name "Matty Hogan" title 'Founder CEO' note "quote: \"ok\"""#,
        )
        .expect("command should parse");

        assert_eq!(
            args,
            vec![
                "TINSERT",
                "users",
                "name",
                "Matty Hogan",
                "title",
                "Founder CEO",
                "note",
                "quote: \"ok\"",
            ]
        );
    }

    #[test]
    fn rejects_unterminated_quotes() {
        let err = split_command_line(r#"SET key "unterminated"#).unwrap_err();

        assert!(err.contains("unterminated"));
    }

    #[test]
    fn parses_migration_files_with_comments_json_and_shell_style_lines() {
        let commands = parse_migration_commands(
            r#"
            # ignored
            -- also ignored
            ["TCREATE","users","id UUID PRIMARY KEY,","email STR UNIQUE"]
            TINSERT users id usr_1 email "user@example.com"
            "#,
        )
        .expect("migration should parse");

        assert_eq!(commands.len(), 2);
        assert_eq!(commands[0][0], "TCREATE");
        assert_eq!(commands[0][2], "id UUID PRIMARY KEY,");
        assert_eq!(
            commands[1],
            vec![
                "TINSERT",
                "users",
                "id",
                "usr_1",
                "email",
                "user@example.com"
            ]
        );
    }

    #[test]
    fn rejects_invalid_json_migration_lines() {
        let err = parse_migration_commands("[\"PING\"").unwrap_err();

        assert!(err.contains("valid JSON argv array"));
    }

    #[test]
    fn grant_statement_tokenizes_to_engine_argv() {
        // A GRANT line in a .lux migration must produce exactly the argv the
        // engine's parse_grant expects (comma stays attached to the scope, and
        // auth.uid() survives as one token).
        let commands =
            parse_migration_commands("GRANT read, write ON messages WHERE user_id = auth.uid()")
                .expect("grant should parse");
        assert_eq!(commands.len(), 1);
        assert_eq!(
            commands[0],
            vec![
                "GRANT",
                "read,",
                "write",
                "ON",
                "messages",
                "WHERE",
                "user_id",
                "=",
                "auth.uid()"
            ]
        );
    }

    #[test]
    fn parses_multiline_semicolon_statements() {
        let commands = parse_migration_commands(
            "TSELECT a.id, b.title\n  FROM authors a\n  JOIN posts b ON a.id = b.author_id;\nTINSERT users id u1;",
        )
        .expect("multi-line statements should parse");
        assert_eq!(commands.len(), 2);
        assert_eq!(commands[0][0], "TSELECT");
        assert!(commands[0].iter().any(|t| t == "FROM"));
        assert!(commands[0].iter().any(|t| t == "JOIN"));
        assert_eq!(commands[1], vec!["TINSERT", "users", "id", "u1"]);
    }

    #[test]
    fn semicolon_inside_quotes_is_not_a_separator() {
        let commands = parse_migration_commands("TINSERT t id 1 note \"a; b\";")
            .expect("quoted semicolon should not split");
        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0], vec!["TINSERT", "t", "id", "1", "note", "a; b"]);
    }

    #[test]
    fn semicolon_mode_strips_line_comments() {
        let commands =
            parse_migration_commands("-- create\nTCREATE t id int; # then insert\nTINSERT t id 1;")
                .expect("comments should be stripped in statement mode");
        assert_eq!(commands.len(), 2);
        assert_eq!(commands[0], vec!["TCREATE", "t", "id", "int"]);
        assert_eq!(commands[1], vec!["TINSERT", "t", "id", "1"]);
    }

    #[test]
    fn local_migrations_are_lux_only_and_sorted() {
        let dir = std::env::temp_dir().join(format!(
            "lux-cli-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("20260202000000_second.lux"), "PING second").unwrap();
        std::fs::write(dir.join("README.md"), "ignore").unwrap();
        std::fs::write(dir.join("20260101000000_first.lux"), "PING first").unwrap();

        let migrations = get_local_migrations(&dir);
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(migrations.len(), 2);
        assert_eq!(migrations[0].0, "20260101000000_first.lux");
        assert_eq!(migrations[1].0, "20260202000000_second.lux");
    }

    #[test]
    fn formats_project_env_values() {
        let env = build_project_env(
            "inst_123",
            "https://api.luxdb.dev",
            "lux://:pw@host:10000",
            Some("lux_pub_test"),
            Some("lux_sec_test"),
        );

        assert!(env.contains("LUX_PROJECT_ID=inst_123"));
        assert!(env.contains("LUX_URL=https://api.luxdb.dev/v1/inst_123"));
        assert!(env.contains("LUX_DIRECT_URL=lux://:pw@host:10000"));
        assert!(env.contains("LUX_PUBLISHABLE_KEY=lux_pub_test"));
        assert!(env.contains("LUX_SECRET_KEY=lux_sec_test"));
        // The redundant derived URLs are no longer emitted.
        assert!(!env.contains("LUX_AUTH_URL"));
        assert!(!env.contains("LUX_HTTP_URL"));
    }

    #[test]
    fn truncates_by_chars_not_bytes() {
        assert_eq!(truncate("abcdef", 4), "abc…");
        assert_eq!(truncate("éclair", 4), "écl…");
    }

    #[test]
    fn migration_hashes_are_stable() {
        assert_eq!(
            sha256_hash("PING\n"),
            "23b8be7673546c504142529fc88346b4d2b80f3205e7872453871b0f92e072c1"
        );
        assert_eq!(legacy_djb2_hash("PING\n"), "000000310dd0051d");
        assert_eq!(legacy_fnv1a_hash("PING\n"), "8f80d239");
    }

    // ── Local engine (lux start/stop/status) ──

    fn sample_state() -> LocalState {
        LocalState {
            password: "lux_sec_local_deadbeef".to_string(),
            publishable_key: "lux_pub_local_cafef00d".to_string(),
            secret_key: "lux_sec_local_deadbeef".to_string(),
            http_port: 5890,
            resp_port: 6379,
            container: "lux-sample-abc123".to_string(),
            volume: "lux-sample-abc123-data".to_string(),
            image: LOCAL_ENGINE_IMAGE.to_string(),
            bind_host: default_bind_host(),
            studio_port: DEFAULT_STUDIO_PORT,
            studio_container: "lux-sample-abc123-studio".to_string(),
            cluster: None,
            retired_cluster_volumes: Vec::new(),
        }
    }

    #[test]
    fn local_state_urls_and_env_lines() {
        let s = sample_state();
        assert_eq!(s.lux_url(), "http://localhost:5890");
        assert_eq!(
            s.direct_url(),
            "lux://:lux_sec_local_deadbeef@localhost:6379"
        );
        let env = s.env_lines();
        assert_eq!(env[0], "LUX_URL=http://localhost:5890");
        assert_eq!(
            env[1],
            "LUX_DIRECT_URL=lux://:lux_sec_local_deadbeef@localhost:6379"
        );
        assert_eq!(env[2], "LUX_PUBLISHABLE_KEY=lux_pub_local_cafef00d");
        assert_eq!(env[3], "LUX_SECRET_KEY=lux_sec_local_deadbeef");
    }

    #[test]
    fn legacy_local_state_defaults_to_loopback() {
        let legacy = serde_json::json!({
            "password": "secret",
            "publishable_key": "publishable",
            "secret_key": "secret",
            "http_port": 5890,
            "resp_port": 6379,
            "container": "lux-test",
            "volume": "lux-test-data",
            "image": LOCAL_ENGINE_IMAGE,
            "studio_port": DEFAULT_STUDIO_PORT,
            "studio_container": "lux-test-studio"
        });
        let state: LocalState = serde_json::from_value(legacy).unwrap();
        assert_eq!(state.bind_host, default_bind_host());
        assert_eq!(state.connection_host(), "localhost");
    }

    #[test]
    fn local_state_urls_support_ipv6() {
        let state = LocalState {
            bind_host: "::1".parse().unwrap(),
            ..sample_state()
        };
        assert_eq!(state.lux_url(), "http://localhost:5890");

        let state = LocalState {
            bind_host: "2001:db8::10".parse().unwrap(),
            ..sample_state()
        };
        assert_eq!(state.lux_url(), "http://[2001:db8::10]:5890");
        assert_eq!(
            state.direct_url(),
            "lux://:lux_sec_local_deadbeef@[2001:db8::10]:6379"
        );
    }

    #[test]
    fn local_engine_env_enables_encryption_auto_init() {
        let env = local_engine_env(&sample_state());
        assert!(
            env.iter().any(|e| e == "LUX_ENC_AUTO_INIT=1"),
            "engine env must enable encryption auto-init: {env:?}"
        );
        // Auth keys still flow through as before.
        assert!(env
            .iter()
            .any(|e| e == "LUX_PASSWORD=lux_sec_local_deadbeef"));
        assert!(env.iter().any(|e| e == "LUX_STORAGE_MODE=tiered"));
    }

    #[test]
    fn enc_command_args_maps_subcommands() {
        assert_eq!(enc_command_args(&EncAction::Status), vec!["ENC", "STATUS"]);
        assert_eq!(enc_command_args(&EncAction::List), vec!["ENC", "LIST"]);
        assert_eq!(enc_command_args(&EncAction::Rewrap), vec!["ENC", "REWRAP"]);
        assert_eq!(
            enc_command_args(&EncAction::Init { key_id: None }),
            vec!["ENC", "INIT"]
        );
        assert_eq!(
            enc_command_args(&EncAction::Rotate {
                key_id: Some("k2".to_string())
            }),
            vec!["ENC", "ROTATE", "KEYID", "k2"]
        );
        assert_eq!(
            enc_command_args(&EncAction::Retire {
                key_id: "k1".to_string()
            }),
            vec!["ENC", "RETIRE", "k1"]
        );
    }

    #[test]
    fn local_state_round_trips_through_json() {
        let s = sample_state();
        let json = serde_json::to_string(&s).unwrap();
        let back: LocalState = serde_json::from_str(&json).unwrap();
        assert_eq!(back.password, s.password);
        assert_eq!(back.http_port, s.http_port);
        assert_eq!(back.resp_port, s.resp_port);
        assert_eq!(back.image, s.image);
    }

    #[test]
    fn secret_key_equals_password_for_operator_mapping() {
        // The operator credential (LUX_PASSWORD) must equal the SDK secret key so
        // a secret-key Bearer is treated as operator by the engine (prod parity).
        let s = sample_state();
        assert_eq!(s.secret_key, s.password);
        // Publishable key is distinct (deny-by-default until the user signs in).
        assert_ne!(s.publishable_key, s.secret_key);
    }

    #[test]
    fn engine_version_pins_image_else_latest() {
        // No config / no version -> track :latest.
        assert_eq!(desired_engine_image(None), LOCAL_ENGINE_IMAGE);
        let unpinned = LocalConfig::default();
        assert_eq!(desired_engine_image(Some(&unpinned)), LOCAL_ENGINE_IMAGE);

        // Pinned version -> the matching ghcr image tag.
        let pinned = LocalConfig {
            engine_version: Some("0.23.0".to_string()),
            ..LocalConfig::default()
        };
        assert_eq!(
            desired_engine_image(Some(&pinned)),
            "ghcr.io/lux-db/lux:0.23.0"
        );

        // Blank/whitespace version is ignored (back to :latest).
        let blank = LocalConfig {
            engine_version: Some("  ".to_string()),
            ..LocalConfig::default()
        };
        assert_eq!(desired_engine_image(Some(&blank)), LOCAL_ENGINE_IMAGE);
    }

    #[test]
    fn gitignore_merge_appends_only_missing() {
        // Empty file -> both entries added.
        let merged = gitignore_merge("", &[".env.local", "lux/.lux-local.json"]).unwrap();
        assert!(merged.contains(".env.local"));
        assert!(merged.contains("lux/.lux-local.json"));
        assert!(merged.ends_with('\n'));

        // One already present -> only the other is appended, no dupes.
        let merged = gitignore_merge(
            "node_modules\n.env.local\n",
            &[".env.local", "lux/.lux-local.json"],
        )
        .unwrap();
        assert_eq!(merged.matches(".env.local").count(), 1);
        assert!(merged.contains("lux/.lux-local.json"));

        // All present -> None (caller skips the write).
        assert!(gitignore_merge(
            ".env.local\nlux/.lux-local.json\n",
            &[".env.local", "lux/.lux-local.json"]
        )
        .is_none());
    }

    #[test]
    fn gitignore_merge_inserts_newline_before_appending() {
        // Existing content without a trailing newline must not get glued onto.
        let merged = gitignore_merge("dist", &[".env.local"]).unwrap();
        assert_eq!(merged, "dist\n.env.local\n");
    }

    #[test]
    fn random_hex_has_expected_length_and_charset() {
        let h = random_hex(16);
        assert_eq!(h.len(), 32); // 2 hex chars per byte
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        // Two draws should differ (astronomically unlikely to collide).
        assert_ne!(random_hex(16), random_hex(16));
    }

    #[test]
    fn toml_edit_preserves_unknown_config_and_comments() {
        let source = "# keep me\ncustom = \"future\"\nproject_id = \"old\"\n";
        let mut doc = source.parse::<toml_edit::DocumentMut>().unwrap();
        doc["project_id"] = toml_edit::value("new");
        let rendered = doc.to_string();
        assert!(rendered.contains("# keep me"));
        assert!(rendered.contains("custom = \"future\""));
        assert!(rendered.contains("project_id = \"new\""));
    }

    #[test]
    fn env_merge_preserves_unrelated_values_and_removes_stale_lux_keys() {
        let existing = "# app\nOPENROUTER_API_KEY=keep\nLUX_URL=https://old\nLUX_URL=duplicate\nLUX_AUTH_URL=https://stale\n";
        let profile = "LUX_URL=http://localhost:5890\nLUX_SECRET_KEY=secret\n";
        let merged = merge_managed_env(existing, profile);
        assert!(merged.contains("# app\n"));
        assert!(merged.contains("OPENROUTER_API_KEY=keep\n"));
        assert!(merged.contains("LUX_URL=http://localhost:5890\n"));
        assert!(merged.contains("LUX_SECRET_KEY=secret\n"));
        assert!(!merged.contains("duplicate"));
        assert!(!merged.contains("LUX_AUTH_URL"));
    }

    #[test]
    fn env_merge_does_not_claim_unknown_lux_variables() {
        let merged = merge_managed_env(
            "LUX_CUSTOM_FEATURE=keep\nOTHER=value\n",
            "LUX_URL=http://localhost:5890\n",
        );
        assert!(merged.contains("LUX_CUSTOM_FEATURE=keep"));
        assert!(merged.contains("OTHER=value"));
    }

    #[test]
    fn omitted_project_is_local_and_only_a_positional_value_is_cloud() {
        assert_eq!(explicit_project(None), None);
        assert_eq!(explicit_project(Some("")), None);
        assert_eq!(explicit_project(Some("   ")), None);
        assert_eq!(explicit_project(Some("dialog")), Some("dialog"));
        assert_eq!(explicit_project(Some("project-id")), Some("project-id"));
    }

    #[cfg(unix)]
    #[test]
    fn secret_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("lux-cli-secret-test-{}", random_hex(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("secret.env");
        write_secret_file(&path, b"LUX_SECRET_KEY=test\n").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn bare_migrate_defaults_to_run() {
        let cli = Cli::try_parse_from(["lux", "migrate"]).expect("bare migrate parses");
        match cli.command {
            Commands::Migrate { action, run } => {
                assert!(action.is_none(), "no explicit subcommand => implicit run");
                assert!(run.project.is_none());
            }
            _ => panic!("expected Migrate"),
        }
    }

    #[test]
    fn migrate_project_is_implicit_run() {
        let cli =
            Cli::try_parse_from(["lux", "migrate", "dialog"]).expect("migrate <project> parses");
        match cli.command {
            Commands::Migrate { action, run } => {
                assert!(action.is_none());
                assert_eq!(run.project.as_deref(), Some("dialog"));
            }
            _ => panic!("expected Migrate"),
        }
    }

    #[test]
    fn explicit_migrate_run_still_parses() {
        let cli =
            Cli::try_parse_from(["lux", "migrate", "run", "dialog"]).expect("migrate run parses");
        match cli.command {
            Commands::Migrate {
                action: Some(MigrateAction::Run(c)),
                ..
            } => assert_eq!(c.project.as_deref(), Some("dialog")),
            _ => panic!("expected Migrate::Run"),
        }
    }

    #[test]
    fn migrate_status_check_flag() {
        let cli = Cli::try_parse_from(["lux", "migrate", "status", "--check", "dialog"])
            .expect("migrate status --check parses");
        match cli.command {
            Commands::Migrate {
                action: Some(MigrateAction::Status { conn, check }),
                ..
            } => {
                assert!(check, "--check sets the flag");
                assert_eq!(conn.project.as_deref(), Some("dialog"));
            }
            _ => panic!("expected Migrate::Status"),
        }
    }

    #[test]
    fn migrate_plan_and_repair_commands_parse() {
        let cli = Cli::try_parse_from(["lux", "migrate", "plan", "dialog"]).expect("plan parses");
        match cli.command {
            Commands::Migrate {
                action: Some(MigrateAction::Plan(conn)),
                ..
            } => assert_eq!(conn.project.as_deref(), Some("dialog")),
            _ => panic!("expected Migrate::Plan"),
        }

        let cli = Cli::try_parse_from([
            "lux",
            "migrate",
            "repair",
            "001_create.lux",
            "resume",
            "2",
            "dialog",
        ])
        .expect("repair resume parses");
        match cli.command {
            Commands::Migrate {
                action:
                    Some(MigrateAction::Repair {
                        filename,
                        action: MigrateRepairAction::Resume { from_command, conn },
                    }),
                ..
            } => {
                assert_eq!(filename, "001_create.lux");
                assert_eq!(from_command, 2);
                assert_eq!(conn.project.as_deref(), Some("dialog"));
            }
            _ => panic!("expected Migrate::Repair::Resume"),
        }
    }

    #[test]
    fn doctor_target_grammar_is_local_by_default() {
        let cli = Cli::try_parse_from(["lux", "doctor", "--fix"]).expect("doctor parses");
        match cli.command {
            Commands::Doctor {
                project, all, fix, ..
            } => {
                assert!(project.is_none());
                assert!(!all);
                assert!(fix);
            }
            _ => panic!("expected Doctor"),
        }
    }

    #[test]
    fn cloud_doctor_contract_uses_the_direct_resp_endpoint() {
        fn read_command(stream: &mut TcpStream, suffix: &[u8]) -> Vec<u8> {
            let mut request = Vec::new();
            loop {
                let mut chunk = [0u8; 128];
                let read = stream.read(&mut chunk).unwrap();
                assert!(read > 0, "client closed before sending a complete command");
                request.extend_from_slice(&chunk[..read]);
                if request.ends_with(suffix) {
                    return request;
                }
            }
        }

        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let auth = read_command(&mut stream, b"doctor-secret\r\n");
            assert!(auth.windows(4).any(|window| window == b"AUTH"));
            stream.write_all(b"+OK\r\n").unwrap();

            let request = read_command(&mut stream, b"VERSION\r\n");
            assert!(request.windows(3).any(|window| window == b"LUX"));
            let payload = serde_json::json!({
                "version": "0.34.0",
                "api_version": "1",
                "capabilities": [
                    "migrations.plan",
                    "migrations.apply",
                    "migrations.repair"
                ]
            })
            .to_string();
            stream
                .write_all(format!("${}\r\n{payload}\r\n", payload.len()).as_bytes())
                .unwrap();
        });

        let version = direct_engine_contract(&format!("lux://:doctor-secret@127.0.0.1:{port}"))
            .expect("direct contract");
        server.join().unwrap();

        let mut checks = Vec::new();
        record_engine_contract_check("cloud:test", Ok(version), &mut checks);
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].target, "cloud:test");
        assert_eq!(checks[0].check, "engine management API");
        assert_eq!(checks[0].status, "pass");
        assert!(checks[0].detail.contains("engine 0.34.0"));
    }

    #[test]
    fn doctor_contract_reports_missing_capabilities() {
        let mut checks = Vec::new();
        record_engine_contract_check(
            "cloud:test",
            Ok(EngineManagementVersion {
                version: "0.34.0".to_string(),
                api_version: "1".to_string(),
                capabilities: vec!["migrations.plan".to_string()],
            }),
            &mut checks,
        );

        assert_eq!(checks[0].status, "fail");
        assert!(checks[0].detail.contains("migrations.apply"));
        assert!(checks[0].detail.contains("migrations.repair"));
    }

    #[test]
    fn migration_checksum_matching_supports_engine_and_legacy_ledgers() {
        let record = |algorithm: &str, checksum: String| MigrationRecord {
            filename: "001.lux".to_string(),
            checksum,
            checksum_algorithm: algorithm.to_string(),
            applied_at: 0,
            body: String::new(),
            status: "applied".to_string(),
            command_count: 1,
            completed_commands: 1,
            error: None,
        };
        let body = "PING\n";
        assert!(migration_checksum_matches(
            &record("sha256", sha256_hash(body)),
            body
        ));
        assert!(migration_checksum_matches(
            &record("djb2-64", legacy_djb2_hash(body)),
            body
        ));
        assert!(migration_checksum_matches(
            &record("fnv1a-32-utf16", legacy_fnv1a_hash(body)),
            body
        ));
        assert!(!migration_checksum_matches(
            &record("sha256", sha256_hash("PONG\n")),
            body
        ));
    }

    #[test]
    fn update_command_preserves_bare_cli_alias_and_parses_components() {
        let cli = Cli::try_parse_from(["lux", "update", "--check"]).expect("bare update parses");
        match cli.command {
            Commands::Update { action, check } => {
                assert!(action.is_none());
                assert!(check);
            }
            _ => panic!("expected Update"),
        }

        let cli = Cli::try_parse_from(["lux", "update", "engine", "dialog", "--check"])
            .expect("engine update parses");
        match cli.command {
            Commands::Update {
                action: Some(UpdateAction::Engine { project, check }),
                ..
            } => {
                assert_eq!(project.as_deref(), Some("dialog"));
                assert!(check);
            }
            _ => panic!("expected Update::Engine"),
        }

        let cli = Cli::try_parse_from(["lux", "update", "studio"]).expect("studio update parses");
        assert!(matches!(
            cli.command,
            Commands::Update {
                action: Some(UpdateAction::Studio { check: false }),
                ..
            }
        ));
    }

    #[test]
    fn version_command_supports_all_and_json() {
        let cli = Cli::try_parse_from(["lux", "version", "--all", "--output", "json"])
            .expect("version parses");
        match cli.command {
            Commands::Version {
                project,
                all,
                output,
            } => {
                assert!(project.is_none());
                assert!(all);
                assert_eq!(output.as_deref(), Some("json"));
            }
            _ => panic!("expected Version"),
        }
    }

    #[test]
    fn push_commands_keep_local_implicit_and_cloud_positional() {
        let cli = Cli::try_parse_from(["lux", "push", "status", "--app-id", "ios"])
            .expect("local push status parses");
        match cli.command {
            Commands::Push {
                action: PushAction::Status { conn, .. },
            } => {
                assert!(conn.project.is_none());
                assert_eq!(conn.app_id, "ios");
            }
            _ => panic!("expected Push::Status"),
        }

        let cli = Cli::try_parse_from([
            "lux",
            "push",
            "apns",
            "set",
            "dialog",
            "--team-id",
            "TEAM",
            "--key-id",
            "KEY",
            "--topic",
            "dev.lux.app",
            "--environment",
            "production",
            "--p8-file",
            "AuthKey.p8",
        ])
        .expect("cloud APNs setup parses");
        match cli.command {
            Commands::Push {
                action:
                    PushAction::Apns {
                        action:
                            PushApnsAction::Set {
                                conn,
                                environment,
                                p8_file,
                                ..
                            },
                    },
            } => {
                assert_eq!(conn.project.as_deref(), Some("dialog"));
                assert!(matches!(environment, PushEnvironment::Production));
                assert_eq!(p8_file.as_deref(), Some(Path::new("AuthKey.p8")));
            }
            _ => panic!("expected Push::Apns::Set"),
        }
    }

    #[test]
    fn destructive_push_commands_require_runtime_acknowledgement() {
        let cli = Cli::try_parse_from(["lux", "push", "vapid", "rotate", "--yes"])
            .expect("VAPID rotate parses");
        assert!(matches!(
            cli.command,
            Commands::Push {
                action: PushAction::Vapid {
                    action: PushVapidAction::Rotate { yes: true, .. }
                }
            }
        ));

        let cli = Cli::try_parse_from(["lux", "push", "apns", "clear"]).expect("APNs clear parses");
        assert!(matches!(
            cli.command,
            Commands::Push {
                action: PushAction::Apns {
                    action: PushApnsAction::Clear { yes: false, .. }
                }
            }
        ));
    }

    #[test]
    fn cli_update_check_never_offers_a_downgrade() {
        assert!(newer_cli_version("0.26.2", "0.27.0"));
        assert!(!newer_cli_version("0.27.0", "0.26.2"));
        assert!(!newer_cli_version("0.27.0", "0.27.0"));
    }
}
