use clap::{Parser, Subcommand};
use colored::Colorize;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;

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
    },
    /// Stop the local Lux engine.
    Stop {
        #[arg(long, help = "Also delete the local data volume (fresh DB next start)")]
        clear: bool,
    },
    /// Open Lux Studio (local web UI) against the running local engine.
    Studio {
        #[arg(long, help = "Don't open a browser window")]
        no_open: bool,
    },
    Login,
    Logout,
    Link {
        #[arg(help = "Project name or ID")]
        project: String,
    },
    Projects,
    Status {
        #[arg(help = "Project name or ID (omit for the local engine)")]
        project: Option<String>,
        #[arg(
            short = 'o',
            long,
            help = "Output format: env (prints LUX_* env lines for the local engine)"
        )]
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
    Update {
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
    Migrate {
        #[command(subcommand)]
        action: MigrateAction,
    },
    Seed {
        #[command(subcommand)]
        action: SeedAction,
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
enum MigrateAction {
    New {
        #[arg(help = "Migration name (e.g. create_users)")]
        name: String,
        #[arg(long, default_value = "lux/migrations", help = "Migration directory")]
        dir: PathBuf,
    },
    Status {
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
    },
    Run {
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
    },
    /// Fetch migrations recorded on the target into the local migration
    /// directory (e.g. ones authored in the Lux Cloud dashboard).
    Pull {
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
    },
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
    Pull {
        #[arg(help = "Project name or ID")]
        project: Option<String>,
        #[arg(short, long, default_value = ".env.local", help = "Output env file")]
        output: PathBuf,
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

#[derive(Serialize, Deserialize)]
struct Config {
    token: String,
    api_url: String,
}

#[derive(Serialize, Deserialize, Default)]
struct LocalConfig {
    project_id: Option<String>,
    project_name: Option<String>,
    /// Optional host port overrides for `lux start` (engine listens on 6379/8080
    /// inside the container; these map to the host).
    local_http_port: Option<u16>,
    local_resp_port: Option<u16>,
}

/// Engine image `lux start` pulls. Tracks `:latest` (CI publishes it on every
/// release) and `lux start` does an explicit `docker pull` each run, so local
/// dev follows the newest engine without the CLI needing a release per bump.
const LOCAL_ENGINE_IMAGE: &str = "ghcr.io/lux-db/lux:latest";
const DEFAULT_HTTP_PORT: u16 = 8080;
const DEFAULT_RESP_PORT: u16 = 6379;

/// Lux Studio image `lux studio` runs (tracks `:latest`, pulled each run, like
/// the engine image). Serves the local web UI; talks to the engine from the
/// browser over the engine's CORS-`*` HTTP API.
const STUDIO_IMAGE: &str = "ghcr.io/lux-db/studio:latest";
/// Default host port for Studio (Supabase Studio uses 54323; we follow suit).
const DEFAULT_STUDIO_PORT: u16 = 54323;

fn default_studio_port() -> u16 {
    DEFAULT_STUDIO_PORT
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
    // serde defaults so a `.lux-local.json` written before Studio existed still
    // loads; backfilled in ensure_local_state.
    #[serde(default = "default_studio_port")]
    studio_port: u16,
    #[serde(default)]
    studio_container: String,
}

fn local_state_path() -> PathBuf {
    PathBuf::from("lux").join(".lux-local.json")
}

fn load_local_state() -> Option<LocalState> {
    let data = std::fs::read_to_string(local_state_path()).ok()?;
    serde_json::from_str(&data).ok()
}

fn save_local_state(state: &LocalState) {
    let path = local_state_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let data = serde_json::to_string_pretty(state).unwrap();
    std::fs::write(path, data).unwrap_or_else(|e| {
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

/// True if `port` is bindable right now (so we can detect a port already taken
/// and pick a free one instead). Binds `0.0.0.0` to match how Docker publishes
/// ports (`-p host:container` binds all interfaces): a check against `127.0.0.1`
/// can pass while another container already holds `0.0.0.0:port` (common on
/// macOS), and then `docker run` fails to bind. `0.0.0.0` is the bind that
/// actually conflicts with Docker's, so it's the correct probe.
fn port_is_free(port: u16) -> bool {
    std::net::TcpListener::bind(("0.0.0.0", port)).is_ok()
}

/// Return `preferred` if free, else the next free port above it. Lets multiple
/// projects run at once: the first gets the default port, the next bumps up.
fn free_port_from(preferred: u16) -> u16 {
    let mut p = preferred;
    for _ in 0..500 {
        if port_is_free(p) {
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
    if let Some(mut state) = load_local_state() {
        let mut dirty = false;
        // Track the current engine image (`:latest`) even for projects created
        // before the CLI stopped pinning a specific version.
        if state.image != LOCAL_ENGINE_IMAGE {
            state.image = LOCAL_ENGINE_IMAGE.to_string();
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
        image: LOCAL_ENGINE_IMAGE.to_string(),
        studio_port: DEFAULT_STUDIO_PORT,
        studio_container: format!("lux-{slug}-studio"),
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
    fn lux_url(&self) -> String {
        format!("http://localhost:{}", self.http_port)
    }
    fn direct_url(&self) -> String {
        format!("lux://:{}@localhost:{}", self.password, self.resp_port)
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

fn docker_volume_exists(name: &str) -> bool {
    docker_output(&["volume", "inspect", name]).is_ok()
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

fn write_env_local(state: &LocalState) {
    let mut lines = state.env_lines();
    lines.push(String::new());
    std::fs::write(".env.local", lines.join("\n")).unwrap_or_else(|e| {
        eprintln!("{} {e}", "Failed to write .env.local:".red());
    });
}

fn print_connection_block(state: &LocalState) {
    println!();
    println!("{}", "  Local Lux engine".bold());
    println!("  {}  {}", "LUX_URL          ".dimmed(), state.lux_url());
    println!("  {}  {}", "LUX_DIRECT_URL   ".dimmed(), state.direct_url());
    println!(
        "  {}  {}",
        "LUX_PUBLISHABLE_KEY".dimmed(),
        state.publishable_key
    );
    println!("  {}  {}", "LUX_SECRET_KEY   ".dimmed(), state.secret_key);
    println!("  {}  {}", "Data volume      ".dimmed(), state.volume);
    println!();
    println!(
        "  Written to {}. Point the SDK at {}.",
        ".env.local".cyan(),
        "LUX_URL".cyan()
    );
}

/// Poll the local RESP port until the engine answers an authed PING (or timeout).
fn wait_for_local_ready(state: &LocalState) -> bool {
    for _ in 0..40 {
        if let Ok(mut conn) = DirectConn::connect("localhost", state.resp_port, &state.password) {
            if conn.exec("PING").is_ok() {
                return true;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    false
}

/// Poll until the Studio container's HTTP port accepts connections (nginx up).
fn wait_for_studio_ready(port: u16) -> bool {
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
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
/// going. The SPA runs in the browser, so LUX_URL is host-visible localhost;
/// LUX_KEY is the operator secret and never leaves the machine.
fn ensure_studio(state: &mut LocalState, open_browser: bool) {
    if docker_container_state(&state.studio_container).as_deref() == Some("running") {
        let url = format!("http://localhost:{}", state.studio_port);
        println!("{} {}", "Lux Studio:".bold(), url.cyan());
        if open_browser {
            let _ = open::that(&url);
        }
        return;
    }
    if docker_container_state(&state.studio_container).is_some() {
        let _ = docker_output(&["rm", "-f", &state.studio_container]);
    }
    let studio_port = free_port_from(state.studio_port);
    if studio_port != state.studio_port {
        state.studio_port = studio_port;
        save_local_state(state);
    }

    println!("{} {}", "Pulling".bold(), STUDIO_IMAGE.dimmed());
    let _ = std::process::Command::new("docker")
        .args(["pull", STUDIO_IMAGE])
        .status();

    let port_map = format!("{studio_port}:80");
    let e_url = format!("LUX_URL=http://localhost:{}", state.http_port);
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
        return;
    }

    print!("{}", "Waiting for Studio...".dimmed());
    std::io::stdout().flush().ok();
    if !wait_for_studio_ready(studio_port) {
        println!(" {}", "TIMEOUT".red());
        eprintln!(
            "{} Studio did not become ready. Check {}.",
            "Warning:".yellow(),
            format!("docker logs {}", state.studio_container).cyan()
        );
        return;
    }
    println!(" {}", "ready".green());

    let url = format!("http://localhost:{studio_port}");
    println!("{} {}", "Lux Studio:".bold(), url.cyan());
    if open_browser {
        let _ = open::that(&url);
    }
}

/// Apply pending migrations from `dir` against a local Direct target. Returns the
/// count applied. Exits the process on a migration error (mirrors `migrate run`).
async fn apply_pending_migrations(target: &mut MigrateTarget, dir: &Path) -> usize {
    ensure_migrations_table(target).await;
    let applied = get_applied_migrations(target).await;
    let local = get_local_migrations(dir);
    let pending: Vec<_> = local
        .iter()
        .filter(|(name, _)| !applied.contains(name))
        .collect();
    if pending.is_empty() {
        return 0;
    }
    println!(
        "{} {} pending migration(s)",
        "Running".bold(),
        pending.len()
    );
    for (filename, content) in &pending {
        print!("  {} {}...", "Applying".dimmed(), filename);
        std::io::stdout().flush().ok();
        let commands = parse_migration_commands(content).unwrap_or_else(|e| {
            println!(" {}", "FAILED".red());
            eprintln!("    {} {}", "Error:".red(), e);
            std::process::exit(1);
        });
        for command in &commands {
            if let Err(e) = target.exec_args(command).await {
                println!(" {}", "FAILED".red());
                eprintln!("    {} {}", "Command:".dimmed(), command.join(" "));
                eprintln!("    {} {}", "Error:".red(), e);
                std::process::exit(1);
            }
        }
        let record_cmd = vec![
            "TINSERT".to_string(),
            "__migrations".to_string(),
            "filename".to_string(),
            filename.to_string(),
            "checksum".to_string(),
            simple_hash(content),
            "applied_at".to_string(),
            chrono::Utc::now().timestamp().to_string(),
            "body".to_string(),
            content.to_string(),
        ];
        if let Err(e) = target.exec_args(&record_cmd).await {
            println!(" {}", "FAILED".red());
            eprintln!("    {} Failed to record migration: {}", "Error:".red(), e);
            std::process::exit(1);
        }
        println!(" {}", "OK".green());
    }
    pending.len()
}

#[derive(Deserialize)]
struct ApiResponse<T> {
    data: Option<T>,
    error: Option<String>,
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
    #[allow(dead_code)]
    current_image: Option<String>,
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
    std::fs::create_dir_all(&dir).ok();
    dir.join("config.json")
}

fn load_config() -> Option<Config> {
    let path = config_path();
    let data = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&data).ok()
}

fn save_config(config: &Config) {
    let path = config_path();
    let data = serde_json::to_string_pretty(config).unwrap();
    std::fs::write(path, data).ok();
}

fn delete_config() {
    let path = config_path();
    std::fs::remove_file(path).ok();
}

fn local_config_path() -> PathBuf {
    PathBuf::from("lux").join("config.toml")
}

fn load_local_config() -> Option<LocalConfig> {
    let data = std::fs::read_to_string(local_config_path()).ok()?;
    let mut config = LocalConfig::default();

    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            continue;
        };

        match key.trim() {
            "project_id" => config.project_id = parse_config_string(value),
            "project_name" => config.project_name = parse_config_string(value),
            "local_http_port" => config.local_http_port = parse_config_u16(value),
            "local_resp_port" => config.local_resp_port = parse_config_u16(value),
            _ => {}
        }
    }

    Some(config)
}

fn save_local_config(config: &LocalConfig) {
    let path = local_config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let mut data = format!(
        "project_id = \"{}\"\nproject_name = \"{}\"\n",
        escape_config_string(config.project_id.as_deref().unwrap_or("")),
        escape_config_string(config.project_name.as_deref().unwrap_or(""))
    );
    if let Some(p) = config.local_http_port {
        data.push_str(&format!("local_http_port = {p}\n"));
    }
    if let Some(p) = config.local_resp_port {
        data.push_str(&format!("local_resp_port = {p}\n"));
    }
    std::fs::write(path, data).unwrap_or_else(|e| {
        eprintln!("{} {e}", "Failed to write lux/config.toml:".red());
        std::process::exit(1);
    });
}

fn parse_config_u16(value: &str) -> Option<u16> {
    let value = value.trim();
    let value = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(value);
    value.trim().parse().ok()
}

fn parse_config_string(value: &str) -> Option<String> {
    let value = value.trim();
    let value = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(value);
    let value = value.replace("\\\"", "\"").replace("\\\\", "\\");
    if value.trim().is_empty() {
        None
    } else {
        Some(value)
    }
}

fn escape_config_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
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

fn linked_project_or(project: Option<&str>) -> Option<String> {
    if let Some(project) = project {
        if !project.trim().is_empty() {
            return Some(project.to_string());
        }
    }
    load_local_config()
        .and_then(|config| config.project_id.or(config.project_name))
        .filter(|value| !value.trim().is_empty())
}

fn require_project_arg(project: Option<&str>) -> String {
    linked_project_or(project).unwrap_or_else(|| {
        eprintln!(
            "{} Provide a project name/ID or run {} first.",
            "Error:".red(),
            "lux link <project>".bold()
        );
        std::process::exit(1);
    })
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

async fn find_project(
    client: &reqwest::Client,
    api_url: &str,
    token: &str,
    name_or_id: &str,
) -> Instance {
    let res = client
        .get(format!("{api_url}/instances"))
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

            ensure_gitignore(&[".env.local", "lux/.lux-local.json"]);

            println!("{}", "Initialized Lux project.".green());
            println!("{} {}", "Migrations:".bold(), migrations_dir.display());
            println!("{} {}", "Config:".bold(), config_path.display());
            println!();
            println!("Next: {} to boot a local engine.", "lux start".cyan());
        }

        Commands::Start { fresh, no_studio } => {
            if let Err(e) = docker_preflight() {
                eprintln!("{} {e}", "Error:".red());
                std::process::exit(1);
            }

            let mut state = ensure_local_state();
            ensure_gitignore(&[".env.local", "lux/.lux-local.json"]);

            // Already running? Just reprint the connection block.
            if docker_container_state(&state.container).as_deref() == Some("running") && !fresh {
                println!("{}", "Local Lux engine already running.".green());
                write_env_local(&state);
                print_connection_block(&state);
                if !no_studio {
                    ensure_studio(&mut state, false);
                }
                return;
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
            let resp_port = free_port_from(state.resp_port);
            let http_port = free_port_from(state.http_port);
            if resp_port != state.resp_port || http_port != state.http_port {
                println!(
                    "{} ports {}/{} busy, using {}/{}",
                    "Note:".yellow(),
                    state.resp_port,
                    state.http_port,
                    resp_port,
                    http_port
                );
                state.resp_port = resp_port;
                state.http_port = http_port;
                save_local_state(&state);
            }

            println!("{} {}", "Pulling".bold(), state.image.dimmed());
            // Pull is best-effort: `docker run` will pull too, but doing it up
            // front gives clearer progress/errors.
            let _ = std::process::Command::new("docker")
                .args(["pull", &state.image])
                .status();

            let resp_map = format!("{}:6379", state.resp_port);
            let http_map = format!("{}:8080", state.http_port);
            let vol_map = format!("{}:/data", state.volume);
            let issuer = format!(
                "LUX_AUTH_ISSUER=http://localhost:{}/auth/v1",
                state.http_port
            );
            let e_pass = format!("LUX_PASSWORD={}", state.password);
            let e_pub = format!("LUX_AUTH_PUBLISHABLE_KEY={}", state.publishable_key);
            let e_sec = format!("LUX_AUTH_SECRET_KEY={}", state.secret_key);

            let run_args: Vec<&str> = vec![
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
                "-e",
                "LUX_AUTH_ENABLED=1",
                "-e",
                &e_pass,
                "-e",
                &e_pub,
                "-e",
                &e_sec,
                "-e",
                "LUX_PORT=6379",
                "-e",
                "LUX_HTTP_PORT=8080",
                "-e",
                "LUX_BIND_HOST=0.0.0.0",
                "-e",
                "LUX_DATA_DIR=/data",
                // Tiered (WAL) storage so local-dev data survives a crash/restart;
                // memory mode only persists on periodic snapshots.
                "-e",
                "LUX_STORAGE_MODE=tiered",
                "-e",
                "LUX_STORAGE_DIR=/data/storage",
                "-e",
                &issuer,
                "--restart",
                "unless-stopped",
                &state.image,
            ];
            if let Err(e) = docker_output(&run_args) {
                eprintln!("{} Failed to start container: {e}", "Error:".red());
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
            let conn = match DirectConn::connect("localhost", state.resp_port, &state.password) {
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

            write_env_local(&state);
            print_connection_block(&state);
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
            if docker_container_state(&state.container).is_some() {
                let _ = docker_output(&["rm", "-f", &state.container]);
                println!("{} Stopped local Lux engine.", "Done.".green());
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
            if clear && docker_volume_exists(&state.volume) {
                let _ = docker_output(&["volume", "rm", &state.volume]);
                println!("{} Cleared data volume {}.", "Done.".green(), state.volume);
            }
        }

        Commands::Login => {
            println!("{}", "Paste your Lux Cloud access token.".bold());
            println!(
                "Get one from: {}",
                "https://luxdb.dev/dashboard/settings".cyan()
            );
            print!("\n{} ", "Token:".bold());
            std::io::stdout().flush().ok();

            let mut token = String::new();
            std::io::stdin().read_line(&mut token).ok();
            let token = token.trim().to_string();

            if token.is_empty() {
                eprintln!("{}", "No token provided.".red());
                std::process::exit(1);
            }

            let api_url = api_url_override
                .clone()
                .unwrap_or_else(|| DEFAULT_API_URL.to_string());

            let client = reqwest::Client::new();
            let res = client
                .get(format!("{api_url}/instances"))
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
            });
            println!("{} Linked to project '{}'", "Done.".green(), inst.name);
            println!("{} {}", "ID:".bold(), inst.id);
        }

        Commands::Projects => {
            let (client, api_url, token) = get_client(&api_url_override);

            let res = client
                .get(format!("{api_url}/instances"))
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

        Commands::Status { project, output } => {
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
                // `-o env` prints just the env lines, for `eval $(lux status -o env)`.
                if output.as_deref() == Some("env") {
                    for line in state.env_lines() {
                        println!("{line}");
                    }
                    return;
                }
                let running =
                    docker_container_state(&state.container).as_deref() == Some("running");
                let status = if running {
                    "running".green().to_string()
                } else {
                    "stopped".yellow().to_string()
                };
                println!("{} {status}", "Local engine:".bold());
                println!("{} {}", "Image:".bold(), state.image.dimmed());
                println!("{} {}", "LUX_URL:".bold(), state.lux_url());
                println!("{} {}", "Direct:".bold(), state.direct_url());
                println!("{} {}", "Data volume:".bold(), state.volume);
                if !running {
                    println!("\nRun {} to boot it.", "lux start".cyan());
                }
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

            let res = client
                .post(format!("{api_url}/instances"))
                .header("Authorization", format!("Bearer {token}"))
                .json(&serde_json::json!({
                    "name": name,
                    "price_id": price_id,
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
                .post(format!("{api_url}/instances/{}/restart", inst.id))
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
                .delete(format!("{api_url}/instances/{}", inst.id))
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

        Commands::Update { check } => {
            let current = env!("CARGO_PKG_VERSION");
            println!("{} v{current}", "Current version:".bold());
            println!("{}", "Checking for updates...".dimmed());

            let client = reqwest::Client::builder()
                .user_agent("lux-cli")
                .build()
                .unwrap();

            let res = client
                .get("https://api.github.com/repos/lux-db/lux/releases")
                .send()
                .await
                .unwrap_or_else(|e| {
                    eprintln!("{} {e}", "Failed to check for updates:".red());
                    std::process::exit(1);
                });

            let releases: Vec<serde_json::Value> = res.json().await.unwrap_or_default();
            let latest_tag = releases
                .iter()
                .filter_map(|r| r.get("tag_name")?.as_str())
                .find(|t| t.starts_with("cli-v"));

            let latest_version = match latest_tag {
                Some(tag) => tag.trim_start_matches("cli-v"),
                None => {
                    eprintln!("{}", "No Lux CLI releases found.".yellow());
                    std::process::exit(1);
                }
            };

            if latest_version == current {
                println!("{}", "Already up to date.".green());
                return;
            }

            println!(
                "{} v{current} -> v{latest_version}",
                "Update available:".yellow()
            );

            if check {
                println!("Run {} to install.", "lux update".cyan());
                return;
            }

            let os = if cfg!(target_os = "macos") {
                "macos"
            } else if cfg!(target_os = "linux") {
                "linux"
            } else {
                eprintln!("{}", "Unsupported OS for self-update.".red());
                std::process::exit(1);
            };

            let arch = if cfg!(target_arch = "aarch64") {
                "arm64"
            } else if cfg!(target_arch = "x86_64") {
                "x86_64"
            } else {
                eprintln!("{}", "Unsupported architecture for self-update.".red());
                std::process::exit(1);
            };

            let artifact = format!("lux-cli-{os}-{arch}");
            let download_url = format!(
                "https://github.com/lux-db/lux/releases/download/{}/{artifact}.tar.gz",
                latest_tag.unwrap()
            );

            println!("{} Downloading v{latest_version}...", "...".dimmed());

            let tar_bytes = client
                .get(&download_url)
                .send()
                .await
                .unwrap_or_else(|e| {
                    eprintln!("{} {e}", "Download failed:".red());
                    std::process::exit(1);
                })
                .bytes()
                .await
                .unwrap_or_else(|e| {
                    eprintln!("{} {e}", "Download failed:".red());
                    std::process::exit(1);
                });

            let current_exe = std::env::current_exe().unwrap_or_else(|e| {
                eprintln!("{} {e}", "Could not determine binary path:".red());
                std::process::exit(1);
            });

            let tmp_dir = std::env::temp_dir().join("lux-cli-update");
            std::fs::create_dir_all(&tmp_dir).ok();
            let tar_path = tmp_dir.join("lux-cli.tar.gz");
            std::fs::write(&tar_path, &tar_bytes).unwrap_or_else(|e| {
                eprintln!("{} {e}", "Failed to write temp file:".red());
                std::process::exit(1);
            });

            let status = std::process::Command::new("tar")
                .args([
                    "xzf",
                    tar_path.to_str().unwrap(),
                    "-C",
                    tmp_dir.to_str().unwrap(),
                ])
                .status()
                .unwrap_or_else(|e| {
                    eprintln!("{} {e}", "Failed to extract:".red());
                    std::process::exit(1);
                });

            if !status.success() {
                eprintln!("{}", "Failed to extract update.".red());
                std::process::exit(1);
            }

            let new_binary = tmp_dir.join(&artifact);
            if !new_binary.exists() {
                eprintln!("{} Binary not found in archive.", "Error:".red());
                std::process::exit(1);
            }

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&new_binary, std::fs::Permissions::from_mode(0o755)).ok();
            }

            std::fs::rename(&new_binary, &current_exe).unwrap_or_else(|_| {
                let copy_result = std::fs::copy(&new_binary, &current_exe);
                if copy_result.is_err() {
                    eprintln!(
                        "{} Could not replace binary. Try: sudo lux update",
                        "Permission denied:".red()
                    );
                    std::process::exit(1);
                }
            });

            std::fs::remove_dir_all(&tmp_dir).ok();
            println!("{} Updated to v{latest_version}", "Done.".green());
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
            EnvAction::Pull { project, output } => {
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
                std::fs::write(&output, content).unwrap_or_else(|e| {
                    eprintln!("{} {e}", "Failed to write env file:".red());
                    std::process::exit(1);
                });
                println!("{} Wrote {}", "Done.".green(), output.display());
            }
        },

        Commands::Migrate { action } => match action {
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
                project,
                dir,
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

                let applied = get_applied_migrations(&mut target).await;
                let local = get_local_migrations(&dir);

                if local.is_empty() {
                    println!(
                        "{} {}",
                        "No migration files found in".dimmed(),
                        dir.display()
                    );
                    return;
                }

                println!("  {:<40}  {}", "MIGRATION".dimmed(), "STATUS".dimmed());
                for (filename, _) in &local {
                    let status = if applied.contains(filename) {
                        "applied".green().to_string()
                    } else {
                        "pending".yellow().to_string()
                    };
                    println!("  {:<40}  {}", filename, status);
                }
            }

            MigrateAction::Run {
                project,
                dir,
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

                ensure_migrations_table(&mut target).await;

                let applied = get_applied_migrations(&mut target).await;
                let local = get_local_migrations(&dir);

                let pending: Vec<_> = local
                    .iter()
                    .filter(|(name, _)| !applied.contains(name))
                    .collect();

                if pending.is_empty() {
                    println!("{}", "All migrations are applied.".green());
                    return;
                }

                println!(
                    "{} {} pending migration(s)",
                    "Running".bold(),
                    pending.len()
                );

                for (filename, content) in &pending {
                    print!("  {} {}...", "Applying".dimmed(), filename);
                    std::io::stdout().flush().ok();

                    let commands = parse_migration_commands(content).unwrap_or_else(|e| {
                        println!(" {}", "FAILED".red());
                        eprintln!("    {} {}", "Error:".red(), e);
                        std::process::exit(1);
                    });

                    let mut failed = false;
                    for command in &commands {
                        if let Err(e) = target.exec_args(command).await {
                            println!(" {}", "FAILED".red());
                            eprintln!("    {} {}", "Command:".dimmed(), command.join(" "));
                            eprintln!("    {} {}", "Error:".red(), e);
                            failed = true;
                            break;
                        }
                    }

                    if failed {
                        eprintln!(
                            "\n{} Migration failed. Fix the issue and re-run.",
                            "Error:".red()
                        );
                        std::process::exit(1);
                    }

                    let checksum = simple_hash(content);
                    let record_cmd = vec![
                        "TINSERT".to_string(),
                        "__migrations".to_string(),
                        "filename".to_string(),
                        filename.to_string(),
                        "checksum".to_string(),
                        checksum,
                        "applied_at".to_string(),
                        chrono::Utc::now().timestamp().to_string(),
                        // Store the source so `lux migrate pull` can recreate the
                        // file on another machine. Passed as a single argv element,
                        // so embedded spaces/newlines are preserved verbatim.
                        "body".to_string(),
                        content.to_string(),
                    ];
                    if let Err(e) = target.exec_args(&record_cmd).await {
                        println!(" {}", "FAILED".red());
                        eprintln!("    {} Failed to record migration: {}", "Error:".red(), e);
                        std::process::exit(1);
                    }

                    println!(" {}", "OK".green());
                }

                println!(
                    "{} Applied {} migration(s).",
                    "Done.".green(),
                    pending.len()
                );
            }

            MigrateAction::Pull {
                project,
                dir,
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

                let remote = get_remote_migrations(&mut target).await;
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
                for (filename, checksum, body) in &remote {
                    if let Some(local_content) = local.get(filename) {
                        // Already present locally. Only flag genuine divergence.
                        if simple_hash(local_content) != *checksum {
                            println!(
                                "  {} {} (local differs from target; keeping local)",
                                "skip".yellow(),
                                filename
                            );
                            skipped += 1;
                        }
                        continue;
                    }
                    if body.is_empty() {
                        // Applied before bodies were stored: nothing to recreate.
                        println!(
                            "  {} {} (no stored source on target)",
                            "skip".yellow(),
                            filename
                        );
                        skipped += 1;
                        continue;
                    }
                    let path = dir.join(filename);
                    if let Err(e) = std::fs::write(&path, body) {
                        eprintln!("  {} {}: {}", "FAILED".red(), filename, e);
                        std::process::exit(1);
                    }
                    println!("  {} {}", "pull".green(), filename);
                    pulled += 1;
                }

                println!(
                    "{} {} pulled, {} skipped.",
                    "Done.".green(),
                    pulled,
                    skipped
                );
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

async fn exec_command_json(
    client: &reqwest::Client,
    api_url: &str,
    token: &str,
    instance_id: &str,
    command: &str,
) -> Result<serde_json::Value, String> {
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

    Ok(body)
}

async fn get_instance_credentials(
    client: &reqwest::Client,
    api_url: &str,
    token: &str,
    instance_id: &str,
) -> Credentials {
    let res = client
        .get(format!("{api_url}/instances/{instance_id}/credentials"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap_or_else(|e| {
            eprintln!("{} {e}", "Failed:".red());
            std::process::exit(1);
        });
    let body: ApiResponse<Credentials> = res.json().await.unwrap_or_else(|e| {
        eprintln!("{} {e}", "Failed to parse response:".red());
        std::process::exit(1);
    });
    unwrap_api(body)
}

async fn get_auth_credentials(
    client: &reqwest::Client,
    api_url: &str,
    token: &str,
    instance_id: &str,
) -> AuthCredentials {
    let res = client
        .get(format!(
            "{api_url}/instances/{instance_id}/auth/credentials"
        ))
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
        .get(format!("{api_url}/instances/{instance_id}/auth/keys"))
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
        .post(format!("{api_url}/instances/{instance_id}/auth/keys"))
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
            "{api_url}/instances/{instance_id}/auth/keys/{key_id}"
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

    /// Execute a table select command and return rows as Vec<Vec<String>>
    /// (each row is [field, value, field, value, ...]).
    fn exec_table_rows(&mut self, command: &str) -> Result<Vec<Vec<String>>, String> {
        let parts: Vec<&str> = command.split_whitespace().collect();
        self.reader
            .get_mut()
            .write_all(&resp_encode(&parts))
            .map_err(|e| format!("write error: {e}"))?;
        self.reader
            .get_mut()
            .flush()
            .map_err(|e| format!("write error: {e}"))?;

        // Read outer array (rows)
        let header = resp_read_line(&mut self.reader)?;
        if let Some(err) = header.strip_prefix('-') {
            return Err(err.to_string());
        }
        let row_count: i64 = header
            .strip_prefix('*')
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        if row_count <= 0 {
            return Ok(vec![]);
        }

        let mut rows = Vec::new();
        for _ in 0..row_count {
            // Read inner array (row fields)
            let row_header = resp_read_line(&mut self.reader)?;
            let field_count: i64 = row_header
                .strip_prefix('*')
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let mut fields = Vec::new();
            for _ in 0..field_count {
                let val = resp_read_response(&mut self.reader)?;
                // Strip "(integer) " prefix from integer values
                let val = val.strip_prefix("(integer) ").unwrap_or(&val).to_string();
                fields.push(val);
            }
            rows.push(fields);
        }
        Ok(rows)
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

    let linked = linked_project_or(project);
    let project = match linked.as_deref() {
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
            match DirectConn::connect("localhost", local_port, pw) {
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

async fn ensure_migrations_table(target: &mut MigrateTarget) {
    let needs_create = target.exec("TSCHEMA __migrations").await.is_err();
    if needs_create {
        if let Err(e) = target
            .exec("TCREATE __migrations filename TEXT, checksum TEXT, applied_at INT, body TEXT")
            .await
        {
            eprintln!(
                "{} Failed to create __migrations table: {}",
                "Error:".red(),
                e
            );
            std::process::exit(1);
        }
    } else {
        // Older instances have a __migrations table without `body` (added so
        // `lux migrate pull` can recreate migration files). Adding it is
        // idempotent: ignore the "already exists" error.
        let _ = target.exec("TALTER __migrations ADD body TEXT").await;
    }
}

async fn get_applied_migrations(target: &mut MigrateTarget) -> HashSet<String> {
    let mut applied = HashSet::new();

    match target {
        MigrateTarget::Direct(conn) => {
            if let Ok(rows) = conn
                .exec_table_rows("TSELECT * FROM __migrations ORDER BY applied_at ASC LIMIT 1000")
            {
                // Each row: ["field", value, "field", value, ...]
                for row in &rows {
                    for i in 0..row.len().saturating_sub(1) {
                        if row[i] == "filename" {
                            let name = &row[i + 1];
                            if !name.is_empty() {
                                applied.insert(name.clone());
                            }
                        }
                    }
                }
            }
        }
        MigrateTarget::Cloud {
            client,
            api_url,
            token,
            instance_id,
        } => {
            if let Ok(body) = exec_command_json(
                client,
                api_url,
                token,
                instance_id,
                "TSELECT * FROM __migrations ORDER BY applied_at ASC LIMIT 1000",
            )
            .await
            {
                // API returns [["field", "val", ...], ...]
                if let Some(rows) = body.as_array() {
                    for row in rows {
                        if let Some(fields) = row.as_array() {
                            for i in 0..fields.len().saturating_sub(1) {
                                if fields[i].as_str() == Some("filename") {
                                    if let Some(name) = fields[i + 1].as_str() {
                                        if !name.is_empty() {
                                            applied.insert(name.to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    applied
}

/// Read every migration recorded on the target as (filename, checksum, body).
/// `body` is empty for rows applied before the source was stored. Used by
/// `lux migrate pull` to recreate dashboard-authored migrations locally.
async fn get_remote_migrations(target: &mut MigrateTarget) -> Vec<(String, String, String)> {
    // Each row is a flat ["field", value, "field", value, ...] list.
    fn extract(row: &[String]) -> (String, String, String) {
        let mut filename = String::new();
        let mut checksum = String::new();
        let mut body = String::new();
        let mut i = 0;
        while i + 1 < row.len() {
            match row[i].as_str() {
                "filename" => filename = row[i + 1].clone(),
                "checksum" => checksum = row[i + 1].clone(),
                "body" => body = row[i + 1].clone(),
                _ => {}
            }
            i += 2;
        }
        (filename, checksum, body)
    }

    let mut out = Vec::new();
    match target {
        MigrateTarget::Direct(conn) => {
            if let Ok(rows) = conn
                .exec_table_rows("TSELECT * FROM __migrations ORDER BY applied_at ASC LIMIT 1000")
            {
                for row in &rows {
                    let r = extract(row);
                    if !r.0.is_empty() {
                        out.push(r);
                    }
                }
            }
        }
        MigrateTarget::Cloud {
            client,
            api_url,
            token,
            instance_id,
        } => {
            if let Ok(body) = exec_command_json(
                client,
                api_url,
                token,
                instance_id,
                "TSELECT * FROM __migrations ORDER BY applied_at ASC LIMIT 1000",
            )
            .await
            {
                if let Some(rows) = body.as_array() {
                    for row in rows {
                        if let Some(fields) = row.as_array() {
                            let flat: Vec<String> = fields
                                .iter()
                                .map(|v| v.as_str().map(str::to_string).unwrap_or_default())
                                .collect();
                            let r = extract(&flat);
                            if !r.0.is_empty() {
                                out.push(r);
                            }
                        }
                    }
                }
            }
        }
    }
    out
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

fn simple_hash(content: &str) -> String {
    let mut hash: u64 = 5381;
    for byte in content.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(byte as u64);
    }
    format!("{:016x}", hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

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
        // Bind on 0.0.0.0 (what `port_is_free` probes, matching Docker's publish
        // bind), then confirm free_port_from skips it to a higher free one.
        let listener = std::net::TcpListener::bind(("0.0.0.0", 0)).unwrap();
        let taken = listener.local_addr().unwrap().port();
        let chosen = free_port_from(taken);
        assert_ne!(chosen, taken, "should not pick the bound port");
        assert!(chosen > taken);
        assert!(port_is_free(chosen));
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
    fn simple_hash_is_stable() {
        assert_eq!(simple_hash("PING\n"), simple_hash("PING\n"));
        assert_ne!(simple_hash("PING\n"), simple_hash("PONG\n"));
    }

    // ── Local engine (lux start/stop/status) ──

    fn sample_state() -> LocalState {
        LocalState {
            password: "lux_sec_local_deadbeef".to_string(),
            publishable_key: "lux_pub_local_cafef00d".to_string(),
            secret_key: "lux_sec_local_deadbeef".to_string(),
            http_port: 8080,
            resp_port: 6379,
            container: "lux-sample-abc123".to_string(),
            volume: "lux-sample-abc123-data".to_string(),
            image: LOCAL_ENGINE_IMAGE.to_string(),
            studio_port: DEFAULT_STUDIO_PORT,
            studio_container: "lux-sample-abc123-studio".to_string(),
        }
    }

    #[test]
    fn local_state_urls_and_env_lines() {
        let s = sample_state();
        assert_eq!(s.lux_url(), "http://localhost:8080");
        assert_eq!(
            s.direct_url(),
            "lux://:lux_sec_local_deadbeef@localhost:6379"
        );
        let env = s.env_lines();
        assert_eq!(env[0], "LUX_URL=http://localhost:8080");
        assert_eq!(
            env[1],
            "LUX_DIRECT_URL=lux://:lux_sec_local_deadbeef@localhost:6379"
        );
        assert_eq!(env[2], "LUX_PUBLISHABLE_KEY=lux_pub_local_cafef00d");
        assert_eq!(env[3], "LUX_SECRET_KEY=lux_sec_local_deadbeef");
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
    fn parses_config_port_override() {
        assert_eq!(parse_config_u16("9000"), Some(9000));
        assert_eq!(parse_config_u16(" \"7777\" "), Some(7777));
        assert_eq!(parse_config_u16("notaport"), None);
    }

    #[test]
    fn local_config_round_trips_port_overrides() {
        let cfg = LocalConfig {
            project_id: Some("p".to_string()),
            project_name: Some("n".to_string()),
            local_http_port: Some(9090),
            local_resp_port: Some(6400),
        };
        // Re-parse the lines save_local_config would emit.
        let serialized = format!(
            "project_id = \"{}\"\nproject_name = \"{}\"\nlocal_http_port = {}\nlocal_resp_port = {}\n",
            cfg.project_id.as_deref().unwrap(),
            cfg.project_name.as_deref().unwrap(),
            cfg.local_http_port.unwrap(),
            cfg.local_resp_port.unwrap(),
        );
        let mut parsed = LocalConfig::default();
        for line in serialized.lines() {
            let (k, v) = line.split_once('=').unwrap();
            match k.trim() {
                "project_id" => parsed.project_id = parse_config_string(v),
                "project_name" => parsed.project_name = parse_config_string(v),
                "local_http_port" => parsed.local_http_port = parse_config_u16(v),
                "local_resp_port" => parsed.local_resp_port = parse_config_u16(v),
                _ => {}
            }
        }
        assert_eq!(parsed.local_http_port, Some(9090));
        assert_eq!(parsed.local_resp_port, Some(6400));
    }
}
