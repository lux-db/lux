#[tokio::main]
async fn main() -> std::io::Result<()> {
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
        "tiered" => lux::disk::StorageMode::Tiered,
        _ => lux::disk::StorageMode::Memory,
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
        .and_then(lux::eviction::parse_memory_size)
        .unwrap_or(0);
    let eviction_policy = std::env::var("LUX_MAXMEMORY_POLICY")
        .ok()
        .map(|s| lux::eviction::parse_eviction_policy(&s))
        .unwrap_or(lux::eviction::EvictionPolicy::NoEviction);
    let eviction_sample_size = std::env::var("LUX_MAXMEMORY_SAMPLES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5usize);

    let config = lux::ServerConfig {
        bind_host: std::env::var("LUX_BIND_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
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
        password,
        require_auth,
        restricted,
        shards,
        data_dir,
        save_interval: std::time::Duration::from_secs(save_interval_secs),
        storage: lux::disk::StorageConfig {
            mode: storage_mode,
            dir: storage_dir,
        },
        eviction: lux::eviction::EvictionConfig {
            max_memory: eviction_max_memory,
            policy: eviction_policy,
            sample_size: eviction_sample_size,
        },
    };

    let handle = lux::run_with_config(config).await?;
    println!(
        "lux v{} ready on {}",
        env!("CARGO_PKG_VERSION"),
        handle.local_addr()
    );
    handle.wait().await
}
