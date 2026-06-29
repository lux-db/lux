fn main() -> std::io::Result<()> {
    let mut runtime = tokio::runtime::Builder::new_multi_thread();
    runtime.enable_all();
    if let Some(worker_threads) = runtime_threads_from_env() {
        runtime.worker_threads(worker_threads);
    }
    runtime.build()?.block_on(async_main())
}

fn runtime_threads_from_env() -> Option<usize> {
    std::env::var("LUX_RUNTIME_THREADS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|&value| value > 0)
}

async fn async_main() -> std::io::Result<()> {
    let password = std::env::var("LUX_PASSWORD").unwrap_or_default();
    let restricted = std::env::var("LUX_RESTRICTED").is_ok_and(|v| {
        let v = v.to_ascii_lowercase();
        v == "1" || v == "true"
    });
    let require_auth = !password.is_empty();

    let shards = std::env::var("LUX_SHARDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(lux::default_shard_count);

    let data_dir = std::env::var("LUX_DATA_DIR").unwrap_or_else(|_| ".".to_string());
    let storage_mode = match std::env::var("LUX_STORAGE_MODE")
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "tiered" => lux::StorageMode::Tiered,
        _ => lux::StorageMode::Memory,
    };
    let storage_dir = std::env::var("LUX_STORAGE_DIR")
        .unwrap_or_else(|_| format!("{}/storage", data_dir.trim_end_matches('/')));
    let save_interval_secs = std::env::var("LUX_SAVE_INTERVAL")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);

    let eviction_max_memory = std::env::var("LUX_MAXMEMORY")
        .ok()
        .as_deref()
        .and_then(lux::parse_memory_size)
        .unwrap_or(0);
    let eviction_policy = std::env::var("LUX_MAXMEMORY_POLICY")
        .ok()
        .map(|s| lux::parse_eviction_policy(&s))
        .unwrap_or(lux::EvictionPolicy::NoEviction);
    let eviction_sample_size = std::env::var("LUX_MAXMEMORY_SAMPLES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5usize);
    let auth_enabled = std::env::var("LUX_AUTH_ENABLED").is_ok_and(|v| {
        let v = v.to_ascii_lowercase();
        v == "1" || v == "true"
    });
    let auth_access_token_ttl = std::env::var("LUX_AUTH_ACCESS_TOKEN_TTL")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3600);
    let auth_refresh_token_ttl = std::env::var("LUX_AUTH_REFRESH_TOKEN_TTL")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30 * 24 * 60 * 60);

    let config = lux::ServerConfig {
        bind_host: std::env::var("LUX_BIND_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
        port: std::env::var("LUX_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(6379),
        http_port: std::env::var("LUX_HTTP_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        max_rows: std::env::var("LUX_MAX_ROWS")
            .ok()
            .and_then(|s| s.parse().ok()),
        max_body: std::env::var("LUX_MAX_BODY_SIZE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(64 * 1024 * 1024),
        max_resp_request: std::env::var("LUX_MAX_RESP_REQUEST_SIZE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(64 * 1024 * 1024),
        password,
        require_auth,
        allow_insecure_no_auth: std::env::var("LUX_ALLOW_INSECURE_NO_AUTH").is_ok_and(|v| {
            let v = v.to_ascii_lowercase();
            v == "1" || v == "true"
        }),
        restricted,
        enable_resp: std::env::var("LUX_ENABLE_RESP").map_or(true, |v| {
            let v = v.to_ascii_lowercase();
            !(v == "0" || v == "false")
        }),
        shards,
        data_dir,
        save_interval: std::time::Duration::from_secs(save_interval_secs),
        storage: lux::StorageConfig {
            mode: storage_mode,
            dir: storage_dir,
        },
        eviction: lux::EvictionConfig {
            max_memory: eviction_max_memory,
            policy: eviction_policy,
            sample_size: eviction_sample_size,
        },
        auth: lux::AuthConfig {
            enabled: auth_enabled,
            issuer: std::env::var("LUX_AUTH_ISSUER")
                .unwrap_or_else(|_| "http://localhost:7379/auth/v1".to_string()),
            access_token_ttl: std::time::Duration::from_secs(auth_access_token_ttl),
            refresh_token_ttl: std::time::Duration::from_secs(auth_refresh_token_ttl),
            email_password_enabled: std::env::var("LUX_AUTH_EMAIL_PASSWORD").map_or(true, |v| {
                let v = v.to_ascii_lowercase();
                !(v == "0" || v == "false")
            }),
            email_confirmation_required: std::env::var("LUX_AUTH_EMAIL_CONFIRMATION_REQUIRED")
                .is_ok_and(|v| {
                    let v = v.to_ascii_lowercase();
                    v == "1" || v == "true"
                }),
            anonymous_enabled: std::env::var("LUX_AUTH_ANONYMOUS").map_or(true, |v| {
                let v = v.to_ascii_lowercase();
                !(v == "0" || v == "false")
            }),
            flow_token_ttl: std::time::Duration::from_secs(
                std::env::var("LUX_AUTH_FLOW_TOKEN_TTL_SECONDS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(24 * 60 * 60),
            ),
            site_url: std::env::var("LUX_AUTH_SITE_URL")
                .unwrap_or_else(|_| "http://localhost:7379".to_string()),
            initial_publishable_key: std::env::var("LUX_AUTH_PUBLISHABLE_KEY").ok(),
            initial_secret_key: std::env::var("LUX_AUTH_SECRET_KEY").ok(),
        },
        // The library is quiet by default; the binary maps severity-specific
        // callbacks back to the previous stdout/stderr behavior.
        on_info: Some(std::sync::Arc::new(print_info_event)),
        on_warn: Some(std::sync::Arc::new(print_warn_event)),
        on_error: Some(std::sync::Arc::new(print_error_event)),
    };

    let handle = lux::run_with_config(config).await?;
    if let Some(addr) = handle.local_addr() {
        println!("lux v{} ready on {}", env!("CARGO_PKG_VERSION"), addr);
    } else {
        println!("lux v{} ready", env!("CARGO_PKG_VERSION"));
    }
    handle.wait().await
}

fn print_info_event(event: lux::ServerInfoEvent) {
    match event {
        lux::ServerInfoEvent::TieredStorageEnabled { dir } => {
            println!("storage: tiered mode (dir: {dir})");
        }
        lux::ServerInfoEvent::NoSnapshotFound => {
            println!("no snapshot found");
        }
        lux::ServerInfoEvent::SnapshotLoaded { keys } => {
            println!("loaded {keys} keys from snapshot");
        }
        lux::ServerInfoEvent::SnapshotSaved { keys } => {
            println!("snapshot: saved {keys} keys");
        }
        lux::ServerInfoEvent::WalReplayed { commands } => {
            println!("wal: replayed {commands} commands");
        }
        lux::ServerInfoEvent::HttpReady { addr } => {
            println!("lux http api ready on {addr}");
        }
    }
}

fn print_warn_event(event: lux::ServerWarnEvent) {
    match event {
        lux::ServerWarnEvent::WalCorruptedFrameSkipped {
            stored_crc,
            computed_crc,
            ..
        } => {
            eprintln!(
                "WAL: corrupted frame detected (crc mismatch: stored={stored_crc:#010x} computed={computed_crc:#010x}), skipping"
            );
        }
        lux::ServerWarnEvent::WalCorruptedFramesSkipped { frames, .. } => {
            eprintln!("WAL: skipped {frames} corrupted frame(s) during replay");
        }
        lux::ServerWarnEvent::DiskCorruptedEntrySkipped { offset, .. } => {
            eprintln!("disk: corrupted entry at offset {offset} (crc mismatch), skipping");
        }
        lux::ServerWarnEvent::DiskEntryParseFailed { offset, error, .. } => {
            eprintln!("disk: failed to parse entry at offset {offset}: {error}");
        }
        lux::ServerWarnEvent::DiskCorruptedEntriesSkipped { entries, .. } => {
            eprintln!("disk: skipped {entries} corrupted entry/entries during index rebuild");
        }
        lux::ServerWarnEvent::ConnectionFailed { peer, error } => {
            eprintln!("connection error {peer}: {error}");
        }
    }
}

fn print_error_event(event: lux::ServerErrorEvent) {
    match event {
        lux::ServerErrorEvent::SnapshotLoadFailed { error } => {
            eprintln!("snapshot load error: {error}");
        }
        lux::ServerErrorEvent::SnapshotSaveFailed { error, path } => {
            eprintln!("snapshot error: {error} (path: {path})");
        }
        lux::ServerErrorEvent::WalReplayFailed { shard, error } => {
            eprintln!("WAL replay error (shard {shard}): {error}");
        }
        lux::ServerErrorEvent::WalTruncateFailed { error } => {
            eprintln!("WAL truncate error: {error}");
        }
        lux::ServerErrorEvent::DiskEvictionWriteFailed { key, error } => {
            eprintln!(
                "CRITICAL: disk eviction write failed for key '{}', keeping in memory. \
                 Data will be LOST on restart if not re-evicted successfully: {error}",
                key
            );
        }
        lux::ServerErrorEvent::InlineCompactionFailed { error } => {
            eprintln!("inline compaction error: {error}");
        }
        lux::ServerErrorEvent::DiskCompactionFailed { shard, error } => {
            eprintln!("compaction error (shard {shard}): {error}");
        }
        lux::ServerErrorEvent::WalAppendFailed { error } => {
            eprintln!(
                "CRITICAL: WAL append failed, in-memory mutation will not survive crash: {error}"
            );
        }
        lux::ServerErrorEvent::SnapshotDiskDumpFailed { error } => {
            eprintln!(
                "CRITICAL: failed to dump disk shard during snapshot, cold data may be lost: {error}"
            );
        }
        lux::ServerErrorEvent::WalFsyncFailed { error } => {
            eprintln!("CRITICAL: WAL fsync failed, up to 1s of writes may not be durable: {error}");
        }
        lux::ServerErrorEvent::HttpServerFailed { error } => {
            eprintln!("http server error: {error}");
        }
    }
}
