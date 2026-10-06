#[path = "bin_support/logging.rs"]
mod logging;

fn main() -> std::process::ExitCode {
    let log_config = (|| {
        let level = optional_env("LUX_LOG_LEVEL")?;
        let format = optional_env("LUX_LOG_FORMAT")?;
        logging::Logger::parse(level.as_deref(), format.as_deref()).map_err(invalid_config)
    })();
    match log_config {
        Ok(logger) => logging::init(logger),
        Err(error) => {
            eprintln!("lux: {error}");
            return std::process::ExitCode::from(1);
        }
    }
    let mut runtime = tokio::runtime::Builder::new_multi_thread();
    runtime.enable_all();
    match runtime_threads_from_env() {
        Ok(Some(worker_threads)) => {
            runtime.worker_threads(worker_threads);
        }
        Ok(None) => {}
        Err(error) => {
            logging::failure("runtime_configuration_failed", &error);
            return std::process::ExitCode::from(1);
        }
    }
    let result = match runtime.build() {
        Ok(runtime) => runtime.block_on(async_main()),
        Err(error) => {
            logging::failure("runtime_initialization_failed", &error);
            return std::process::ExitCode::from(1);
        }
    };
    match result {
        Ok(lux::ShutdownOutcome::Clean) => {
            logging::emit(
                logging::Level::Info,
                "shutdown_completed",
                serde_json::json!({}),
            );
            std::process::ExitCode::SUCCESS
        }
        Ok(lux::ShutdownOutcome::Forced) => {
            logging::emit(
                logging::Level::Error,
                "shutdown_timeout",
                serde_json::json!({"remaining_work_cancelled": true}),
            );
            std::process::ExitCode::from(2)
        }
        Err(lux::ShutdownError::Persistence(error)) => {
            logging::failure("shutdown_persistence_failed", &error);
            std::process::ExitCode::from(3)
        }
        Err(lux::ShutdownError::Runtime(error)) => {
            logging::failure("server_failed", &error);
            std::process::ExitCode::from(1)
        }
    }
}

fn runtime_threads_from_env() -> std::io::Result<Option<usize>> {
    optional_env("LUX_RUNTIME_THREADS")?
        .map(|raw| parse_number("LUX_RUNTIME_THREADS", &raw, 1usize))
        .transpose()
}

fn optional_env(name: &str) -> std::io::Result<Option<String>> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(invalid_config(format!("{name} must be UTF-8")))
        }
    }
}

fn parse_number<T: std::str::FromStr + PartialOrd + std::fmt::Display>(
    name: &str,
    raw: &str,
    minimum: T,
) -> std::io::Result<T> {
    raw.parse::<T>()
        .ok()
        .filter(|value| *value >= minimum)
        .ok_or_else(|| {
            invalid_config(format!(
                "{name} must be an integer >= {minimum} within the supported range"
            ))
        })
}

fn number_env<T: std::str::FromStr + PartialOrd + std::fmt::Display>(
    name: &str,
    default: T,
    minimum: T,
) -> std::io::Result<T> {
    match optional_env(name)? {
        Some(raw) => parse_number(name, &raw, minimum),
        None => Ok(default),
    }
}

fn parse_bool(name: &str, raw: &str) -> std::io::Result<bool> {
    match raw.to_ascii_lowercase().as_str() {
        "1" | "true" => Ok(true),
        "0" | "false" => Ok(false),
        _ => Err(invalid_config(format!(
            "{name} must be true, false, 1, or 0"
        ))),
    }
}

fn bool_env(name: &str, default: bool) -> std::io::Result<bool> {
    optional_env(name)?.map_or(Ok(default), |raw| parse_bool(name, &raw))
}

fn invalid_config(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message.into())
}

fn positive_usize_env(name: &str, default: usize) -> std::io::Result<usize> {
    match std::env::var(name) {
        Ok(raw) => raw
            .parse::<usize>()
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| invalid_config(format!("{name} must be a positive integer"))),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(invalid_config(format!("{name} must be UTF-8")))
        }
    }
}

fn positive_duration_ms_env(
    name: &str,
    default: std::time::Duration,
) -> std::io::Result<std::time::Duration> {
    let default_ms = usize::try_from(default.as_millis())
        .map_err(|_| invalid_config(format!("default value for {name} is too large")))?;
    let millis = positive_usize_env(name, default_ms)?;
    let millis =
        u64::try_from(millis).map_err(|_| invalid_config(format!("{name} is too large")))?;
    Ok(std::time::Duration::from_millis(millis))
}

fn optional_limit_env(name: &str, default: usize) -> std::io::Result<Option<usize>> {
    match std::env::var(name) {
        Ok(raw) => raw
            .parse::<usize>()
            .map(|value| (value != 0).then_some(value))
            .map_err(|_| invalid_config(format!("{name} must be a non-negative integer"))),
        Err(std::env::VarError::NotPresent) => Ok(Some(default)),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(invalid_config(format!("{name} must be UTF-8")))
        }
    }
}

fn parse_storage_mode(raw: Option<String>) -> std::io::Result<lux::StorageMode> {
    match raw.as_deref().map(str::trim) {
        None => Ok(lux::StorageMode::Memory),
        Some(value) if value.eq_ignore_ascii_case("memory") => Ok(lux::StorageMode::Memory),
        Some(value) if value.eq_ignore_ascii_case("tiered") => Ok(lux::StorageMode::Tiered),
        Some(_) => Err(invalid_config(
            "LUX_STORAGE_MODE must be one of: memory, tiered",
        )),
    }
}

fn parse_durability(
    raw_policy: Option<String>,
    raw_sync_interval_ms: Option<String>,
) -> std::io::Result<lux::DurabilityConfig> {
    let policy = match raw_policy.as_deref().map(str::trim) {
        None => lux::DurabilityPolicy::AlwaysSync,
        Some(value) if value.eq_ignore_ascii_case("ephemeral") => lux::DurabilityPolicy::Ephemeral,
        Some(value) if value.eq_ignore_ascii_case("every_second") => {
            lux::DurabilityPolicy::EverySecond
        }
        Some(value) if value.eq_ignore_ascii_case("always_sync") => {
            lux::DurabilityPolicy::AlwaysSync
        }
        Some(_) => {
            return Err(invalid_config(
                "LUX_DURABILITY must be one of: ephemeral, every_second, always_sync",
            ));
        }
    };

    let sync_interval = match raw_sync_interval_ms {
        Some(_) if policy != lux::DurabilityPolicy::EverySecond => {
            return Err(invalid_config(
                "LUX_DURABILITY_SYNC_INTERVAL_MS is valid only with every_second",
            ));
        }
        Some(raw) => {
            let millis = raw.parse::<u64>().map_err(|_| {
                invalid_config("LUX_DURABILITY_SYNC_INTERVAL_MS must be an integer from 1 to 1000")
            })?;
            if !(1..=1_000).contains(&millis) {
                return Err(invalid_config(
                    "LUX_DURABILITY_SYNC_INTERVAL_MS must be from 1 to 1000",
                ));
            }
            std::time::Duration::from_millis(millis)
        }
        None => std::time::Duration::from_secs(1),
    };

    Ok(lux::DurabilityConfig {
        policy,
        sync_interval,
    })
}

async fn async_main() -> Result<lux::ShutdownOutcome, lux::ShutdownError> {
    let password = optional_env("LUX_PASSWORD")?.unwrap_or_default();
    let restricted = bool_env("LUX_RESTRICTED", false)?;
    let require_auth = !password.is_empty();

    let shards = number_env("LUX_SHARDS", lux::default_shard_count(), 1usize)?;

    let data_dir = optional_env("LUX_DATA_DIR")?.unwrap_or_else(|| ".".to_string());
    let storage_mode = parse_storage_mode(optional_env("LUX_STORAGE_MODE")?)?;
    let storage_dir_env = optional_env("LUX_STORAGE_DIR")?;
    if storage_mode == lux::StorageMode::Memory && storage_dir_env.is_some() {
        return Err(
            invalid_config("LUX_STORAGE_DIR is valid only when LUX_STORAGE_MODE=tiered").into(),
        );
    }
    let storage_dir =
        storage_dir_env.unwrap_or_else(|| format!("{}/storage", data_dir.trim_end_matches('/')));
    let durability = parse_durability(
        optional_env("LUX_DURABILITY")?,
        optional_env("LUX_DURABILITY_SYNC_INTERVAL_MS")?,
    )?;
    let save_interval_secs = number_env("LUX_SAVE_INTERVAL", 60u64, 0)?;

    let eviction_max_memory = optional_env("LUX_MAXMEMORY")?.map_or(Ok(0), |raw| {
        lux::parse_memory_size(&raw).ok_or_else(|| invalid_config("LUX_MAXMEMORY must be a byte count or a supported memory size within the supported range"))
    })?;
    let eviction_policy = optional_env("LUX_MAXMEMORY_POLICY")?.map_or(Ok(lux::EvictionPolicy::NoEviction), |raw| {
        match raw.to_ascii_lowercase().as_str() {
            "noeviction" | "allkeys-lru" | "volatile-lru" | "allkeys-random" | "volatile-random" => Ok(lux::parse_eviction_policy(&raw)),
            _ => Err(invalid_config("LUX_MAXMEMORY_POLICY must be noeviction, allkeys-lru, volatile-lru, allkeys-random, or volatile-random")),
        }
    })?;
    let eviction_sample_size = number_env("LUX_MAXMEMORY_SAMPLES", 5usize, 1)?;
    let auth_enabled = bool_env("LUX_AUTH_ENABLED", false)?;
    let auth_access_token_ttl = number_env("LUX_AUTH_ACCESS_TOKEN_TTL", 3600u64, 1)?;
    let auth_refresh_token_ttl = number_env("LUX_AUTH_REFRESH_TOKEN_TTL", 30u64 * 24 * 60 * 60, 1)?;
    let managed_email = managed_auth_email_from_env()?;

    let encryption = encryption_config_from_env()?;
    let default_limits = lux::ServerLimits::default();

    // `site_url` and `issuer` default to the address this engine actually serves
    // HTTP on. They used to hardcode port 7379, which is not the RESP port, the
    // HTTP port, or the Studio port -- a default that looked derived and was not.
    let http_port = number_env("LUX_HTTP_PORT", 0u16, 0)?;
    let auth_http_port = if http_port == 0 { 5890 } else { http_port };
    let auth_base_url = format!("http://localhost:{auth_http_port}");
    let studio_session_ttl = match std::env::var("LUX_STUDIO_SESSION_TTL_SECONDS") {
        Ok(value) => std::time::Duration::from_secs(value.parse::<u64>().map_err(|_| {
            invalid_config("LUX_STUDIO_SESSION_TTL_SECONDS must be an integer from 1 to 86400")
        })?),
        Err(std::env::VarError::NotPresent) => std::time::Duration::from_secs(12 * 60 * 60),
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(invalid_config("LUX_STUDIO_SESSION_TTL_SECONDS must be UTF-8").into());
        }
    };

    let config = lux::ServerConfig {
        bind_host: optional_env("LUX_BIND_HOST")?.unwrap_or_else(|| "127.0.0.1".to_string()),
        port: number_env("LUX_PORT", 6379u16, 0)?,
        http_port,
        max_rows: optional_limit_env("LUX_MAX_ROWS", 10_000)?,
        max_body: positive_usize_env("LUX_MAX_BODY_SIZE", 64 * 1024 * 1024)?,
        http_browser: lux::HttpBrowserConfig {
            allowed_hosts: optional_env("LUX_HTTP_ALLOWED_HOSTS")?
                .map(|value| {
                    value
                        .split(',')
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default(),
            allowed_origins: optional_env("LUX_HTTP_ALLOWED_ORIGINS")?
                .map(|value| {
                    value
                        .split(',')
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default(),
            studio_session_ttl,
        },
        max_resp_request: positive_usize_env("LUX_MAX_RESP_REQUEST_SIZE", 64 * 1024 * 1024)?,
        limits: lux::ServerLimits {
            max_resp_connections: positive_usize_env(
                "LUX_MAX_RESP_CONNECTIONS",
                default_limits.max_resp_connections,
            )?,
            max_http_connections: positive_usize_env(
                "LUX_MAX_HTTP_CONNECTIONS",
                default_limits.max_http_connections,
            )?,
            max_blocked_clients: positive_usize_env(
                "LUX_MAX_BLOCKED_CLIENTS",
                default_limits.max_blocked_clients,
            )?,
            max_resp_pipeline_commands: positive_usize_env(
                "LUX_MAX_RESP_PIPELINE_COMMANDS",
                default_limits.max_resp_pipeline_commands,
            )?,
            max_resp_command_args: positive_usize_env(
                "LUX_MAX_RESP_COMMAND_ARGS",
                default_limits.max_resp_command_args,
            )?,
            max_resp_subscriptions: positive_usize_env(
                "LUX_MAX_RESP_SUBSCRIPTIONS",
                default_limits.max_resp_subscriptions,
            )?,
            max_subscription_name_bytes: positive_usize_env(
                "LUX_MAX_SUBSCRIPTION_NAME_SIZE",
                default_limits.max_subscription_name_bytes,
            )?,
            max_live_subscriptions: positive_usize_env(
                "LUX_MAX_LIVE_SUBSCRIPTIONS",
                default_limits.max_live_subscriptions,
            )?,
            max_subscriptions: positive_usize_env(
                "LUX_MAX_SUBSCRIPTIONS",
                default_limits.max_subscriptions,
            )?,
            max_query_candidates: positive_usize_env(
                "LUX_MAX_QUERY_CANDIDATES",
                default_limits.max_query_candidates,
            )?,
            max_blocking_keys: positive_usize_env(
                "LUX_MAX_BLOCKING_KEYS",
                default_limits.max_blocking_keys,
            )?,
            max_resp_response: positive_usize_env(
                "LUX_MAX_RESP_RESPONSE_SIZE",
                default_limits.max_resp_response,
            )?,
            max_request_buffer_bytes: positive_usize_env(
                "LUX_MAX_REQUEST_BUFFER_SIZE",
                default_limits.max_request_buffer_bytes,
            )?,
            max_response_buffer_bytes: positive_usize_env(
                "LUX_MAX_RESPONSE_BUFFER_SIZE",
                default_limits.max_response_buffer_bytes,
            )?,
            max_auth_workers: positive_usize_env(
                "LUX_MAX_AUTH_WORKERS",
                default_limits.max_auth_workers,
            )?,
            max_script_memory: positive_usize_env(
                "LUX_MAX_SCRIPT_MEMORY_SIZE",
                default_limits.max_script_memory,
            )?,
            resp_idle_timeout: positive_duration_ms_env(
                "LUX_RESP_IDLE_TIMEOUT_MS",
                default_limits.resp_idle_timeout,
            )?,
            resp_request_timeout: positive_duration_ms_env(
                "LUX_RESP_REQUEST_TIMEOUT_MS",
                default_limits.resp_request_timeout,
            )?,
            http_header_timeout: positive_duration_ms_env(
                "LUX_HTTP_HEADER_TIMEOUT_MS",
                default_limits.http_header_timeout,
            )?,
            http_body_timeout: positive_duration_ms_env(
                "LUX_HTTP_BODY_TIMEOUT_MS",
                default_limits.http_body_timeout,
            )?,
            http_keep_alive_timeout: positive_duration_ms_env(
                "LUX_HTTP_KEEP_ALIVE_TIMEOUT_MS",
                default_limits.http_keep_alive_timeout,
            )?,
            live_idle_timeout: positive_duration_ms_env(
                "LUX_LIVE_IDLE_TIMEOUT_MS",
                default_limits.live_idle_timeout,
            )?,
            write_timeout: positive_duration_ms_env(
                "LUX_WRITE_TIMEOUT_MS",
                default_limits.write_timeout,
            )?,
        },
        password,
        require_auth,
        allow_insecure_no_auth: bool_env("LUX_ALLOW_INSECURE_NO_AUTH", false)?,
        restricted,
        enable_resp: bool_env("LUX_ENABLE_RESP", true)?,
        shards,
        data_dir,
        save_interval: std::time::Duration::from_secs(save_interval_secs),
        storage: lux::StorageConfig {
            mode: storage_mode,
            dir: storage_dir,
        },
        durability,
        eviction: lux::EvictionConfig {
            max_memory: eviction_max_memory,
            policy: eviction_policy,
            sample_size: eviction_sample_size,
        },
        auth: lux::AuthConfig {
            enabled: auth_enabled,
            issuer: optional_env("LUX_AUTH_ISSUER")?
                .unwrap_or_else(|| format!("{auth_base_url}/auth/v1")),
            access_token_ttl: std::time::Duration::from_secs(auth_access_token_ttl),
            refresh_token_ttl: std::time::Duration::from_secs(auth_refresh_token_ttl),
            email_password_enabled: bool_env("LUX_AUTH_EMAIL_PASSWORD", true)?,
            email_confirmation_required: bool_env("LUX_AUTH_EMAIL_CONFIRMATION_REQUIRED", false)?,
            anonymous_enabled: bool_env("LUX_AUTH_ANONYMOUS", true)?,
            flow_token_ttl: std::time::Duration::from_secs(number_env(
                "LUX_AUTH_FLOW_TOKEN_TTL_SECONDS",
                24u64 * 60 * 60,
                1,
            )?),
            site_url: optional_env("LUX_AUTH_SITE_URL")?.unwrap_or_else(|| auth_base_url.clone()),
            initial_publishable_key: optional_env("LUX_AUTH_PUBLISHABLE_KEY")?,
            initial_secret_key: optional_env("LUX_AUTH_SECRET_KEY")?,
            managed_email,
        },
        encryption,
        // Embedded callers remain quiet unless they install callbacks.
        on_info: Some(std::sync::Arc::new(logging::info)),
        on_warn: Some(std::sync::Arc::new(logging::warn)),
        on_error: Some(std::sync::Arc::new(logging::error)),
    };

    let shutdown_timeout = shutdown_timeout_from_env()?;
    // Register signal handlers before recovery starts so a signal received
    // during slow startup is retained and honored at the first safe lifecycle
    // boundary. Registration failure is fatal rather than silently falling
    // back to an ungraceful process termination.
    let signal = shutdown_signal()?;
    let signal_task = tokio::spawn(signal);
    logging::emit(
        logging::Level::Debug,
        "effective_configuration",
        serde_json::json!({
            "resp_enabled": config.enable_resp,
            "resp_port": config.port,
            "http_port": config.http_port,
            "shards": config.shards,
            "storage_layout": config.storage.mode.as_str(),
            "durability": config.durability.policy.as_str(),
            "auth_enabled": config.auth.enabled,
            "operator_auth_configured": config.require_auth,
            "restricted": config.restricted,
            "max_memory": config.eviction.max_memory,
            "max_resp_connections": config.limits.max_resp_connections,
            "max_http_connections": config.limits.max_http_connections,
            "max_body_size": config.max_body,
            "max_rows": config.max_rows,
            "shutdown_timeout_ms": shutdown_timeout.as_millis(),
        }),
    );
    logging::emit(
        logging::Level::Info,
        "startup_started",
        serde_json::json!({"version": env!("CARGO_PKG_VERSION")}),
    );
    let handle = lux::run_with_config(config).await?;
    logging::emit(
        logging::Level::Info,
        "server_ready",
        serde_json::json!({"address": handle.local_addr().map(|addr| addr.to_string())}),
    );
    handle
        .wait_or_shutdown(
            async move {
                let _ = signal_task.await;
                logging::emit(
                    logging::Level::Info,
                    "shutdown_started",
                    serde_json::json!({}),
                );
            },
            shutdown_timeout,
        )
        .await
}

fn shutdown_timeout_from_env() -> std::io::Result<std::time::Duration> {
    parse_shutdown_timeout(optional_env("LUX_SHUTDOWN_TIMEOUT_MS")?.as_deref())
}

fn parse_shutdown_timeout(raw: Option<&str>) -> std::io::Result<std::time::Duration> {
    let Some(raw) = raw else {
        return Ok(lux::DEFAULT_SHUTDOWN_TIMEOUT);
    };
    let millis = raw.parse::<u64>().map_err(|_| {
        invalid_config("LUX_SHUTDOWN_TIMEOUT_MS must be an integer from 1 to 300000")
    })?;
    if !(1..=300_000).contains(&millis) {
        return Err(invalid_config(
            "LUX_SHUTDOWN_TIMEOUT_MS must be from 1 to 300000",
        ));
    }
    Ok(std::time::Duration::from_millis(millis))
}

#[cfg(unix)]
fn shutdown_signal() -> std::io::Result<impl std::future::Future<Output = ()>> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    Ok(async move {
        tokio::select! {
            _ = interrupt.recv() => {}
            _ = terminate.recv() => {}
        }
    })
}

#[cfg(not(unix))]
fn shutdown_signal() -> std::io::Result<impl std::future::Future<Output = ()>> {
    Ok(async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            logging::failure("interrupt_wait_failed", &error);
        }
    })
}

fn encryption_config_from_env() -> std::io::Result<lux::EncryptionConfig> {
    let state_path = optional_env("LUX_ENC_STATE_PATH")?;
    let seal_path = optional_env("LUX_ENC_SEAL_PATH")?;
    let auto_init = bool_env("LUX_ENC_AUTO_INIT", false)?;
    let seal_secret = parse_seal_env("LUX_ENC_SEAL_KEY")
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
    let previous_seal_secrets = parse_seal_list_env("LUX_ENC_SEAL_KEY_PREVIOUS")
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;

    // Warn once at boot when encryption is in use but the seal lives on the data
    // volume: a stolen disk/snapshot then carries both the sealed keyring and its
    // key. Env-sourced seals (LUX_ENC_SEAL_KEY) avoid this.
    let encryption_in_use = auto_init
        || std::env::var("LUX_ENCRYPTION_KEYS").is_ok()
        || std::env::var("LUX_ENCRYPTION_KEY").is_ok();
    if seal_secret.is_none() && encryption_in_use {
        logging::emit(
            logging::Level::Warn,
            "encryption_seal_on_data_volume",
            serde_json::json!({"action": "set LUX_ENC_SEAL_KEY from your secret store so backups do not carry the seal key"}),
        );
    }

    let keys_json = optional_env("LUX_ENCRYPTION_KEYS")?;
    let single_key = optional_env("LUX_ENCRYPTION_KEY")?;
    if keys_json.is_some() && single_key.is_some() {
        return Err(invalid_config(
            "configure only one of LUX_ENCRYPTION_KEYS and LUX_ENCRYPTION_KEY",
        ));
    }
    if let Some(raw) = keys_json {
        let mut config = parse_encryption_keys_json(&raw, optional_env("LUX_ENCRYPTION_KEY_ID")?)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error));
        if let Ok(config) = &mut config {
            config.state_path = state_path;
            config.seal_path = seal_path;
            config.auto_init = auto_init;
            config.seal_secret = seal_secret;
            config.previous_seal_secrets = previous_seal_secrets;
        }
        return config;
    }

    let Some(secret) = single_key else {
        return Ok(lux::EncryptionConfig {
            state_path,
            seal_path,
            auto_init,
            seal_secret,
            previous_seal_secrets,
            ..Default::default()
        });
    };
    let id = optional_env("LUX_ENCRYPTION_KEY_ID")?.unwrap_or_else(|| "local".to_string());
    Ok(lux::EncryptionConfig {
        active_key_id: Some(id.clone()),
        keys: vec![lux::EncryptionKeyConfig {
            id,
            secret: secret.into_bytes(),
            decrypt_only: false,
        }],
        state_path,
        seal_path,
        auto_init,
        seal_secret,
        previous_seal_secrets,
    })
}

/// Decode a single base64 seal env var into 32 bytes. Absent -> None; present but
/// malformed / wrong length -> hard error (fail closed rather than silently
/// falling back to a disk seal).
fn parse_seal_env(name: &str) -> Result<Option<[u8; 32]>, String> {
    match optional_env(name).map_err(|error| error.to_string())? {
        Some(raw) => Ok(Some(decode_seal_value(name, raw.trim())?)),
        None => Ok(None),
    }
}

/// Decode a comma-separated list of base64 seals (previous/rotated-out keys).
fn parse_seal_list_env(name: &str) -> Result<Vec<[u8; 32]>, String> {
    let Some(raw) = optional_env(name).map_err(|error| error.to_string())? else {
        return Ok(Vec::new());
    };
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| decode_seal_value(name, s))
        .collect()
}

fn decode_seal_value(name: &str, value: &str) -> Result<[u8; 32], String> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| format!("{name} must be base64"))?;
    bytes
        .try_into()
        .map_err(|_| format!("{name} must decode to exactly 32 bytes"))
}

fn parse_encryption_keys_json(
    raw: &str,
    active_key_id: Option<String>,
) -> Result<lux::EncryptionConfig, String> {
    let value = serde_json::from_str::<serde_json::Value>(raw)
        .map_err(|error| format!("invalid LUX_ENCRYPTION_KEYS JSON: {error}"))?;
    let items = value
        .as_array()
        .ok_or_else(|| "LUX_ENCRYPTION_KEYS must be a JSON array".to_string())?;
    let mut keys = Vec::with_capacity(items.len());
    for (idx, item) in items.iter().enumerate() {
        let object = item
            .as_object()
            .ok_or_else(|| format!("LUX_ENCRYPTION_KEYS[{idx}] must be an object"))?;
        if object.keys().any(|name| {
            !matches!(
                name.as_str(),
                "id" | "secret" | "decryptOnly" | "decrypt_only"
            )
        }) {
            return Err(format!(
                "LUX_ENCRYPTION_KEYS[{idx}] contains an unknown field"
            ));
        }
        let mut decrypt_only = None;
        for name in ["decryptOnly", "decrypt_only"] {
            if let Some(value) = item.get(name) {
                let value = value.as_bool().ok_or_else(|| {
                    format!("LUX_ENCRYPTION_KEYS[{idx}].{name} must be a boolean")
                })?;
                if decrypt_only.is_some_and(|previous| previous != value) {
                    return Err(format!(
                        "LUX_ENCRYPTION_KEYS[{idx}] contains contradictory decrypt-only settings"
                    ));
                }
                decrypt_only = Some(value);
            }
        }
        let id = item
            .get("id")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| format!("LUX_ENCRYPTION_KEYS[{idx}].id must be a non-empty string"))?;
        let secret = item
            .get("secret")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                format!("LUX_ENCRYPTION_KEYS[{idx}].secret must be a non-empty string")
            })?;
        keys.push(lux::EncryptionKeyConfig {
            id: id.to_string(),
            secret: secret.as_bytes().to_vec(),
            decrypt_only: decrypt_only.unwrap_or(false),
        });
    }
    let active_key_id = active_key_id.or_else(|| {
        keys.iter()
            .rev()
            .find(|k| !k.decrypt_only)
            .map(|k| k.id.clone())
    });
    if active_key_id.is_none() {
        return Err("LUX_ENCRYPTION_KEYS must include at least one writable key".to_string());
    }
    let config = lux::EncryptionConfig {
        active_key_id,
        keys,
        state_path: std::env::var("LUX_ENC_STATE_PATH").ok(),
        seal_path: std::env::var("LUX_ENC_SEAL_PATH").ok(),
        auto_init: bool_env("LUX_ENC_AUTO_INIT", false).map_err(|error| error.to_string())?,
        // Filled in by the caller from LUX_ENC_SEAL_KEY / _PREVIOUS.
        seal_secret: None,
        previous_seal_secrets: Vec::new(),
    };
    Ok(config)
}

fn managed_auth_email_from_env() -> std::io::Result<Option<lux::AuthManagedEmailConfig>> {
    let token = optional_env("LUX_AUTH_MANAGED_POSTMARK_SERVER_TOKEN")?;
    let provider = optional_env("LUX_AUTH_MANAGED_EMAIL_PROVIDER")?
        .or_else(|| token.as_ref().map(|_| "postmark".to_string()));
    let from = optional_env("LUX_AUTH_MANAGED_EMAIL_FROM")?;
    let reply_to = optional_env("LUX_AUTH_MANAGED_EMAIL_REPLY_TO")?;
    let postmark_message_stream = optional_env("LUX_AUTH_MANAGED_POSTMARK_MESSAGE_STREAM")?;
    if provider.is_none()
        && from.is_none()
        && reply_to.is_none()
        && postmark_message_stream.is_none()
    {
        return Ok(None);
    }
    let provider = provider.ok_or_else(|| {
        invalid_config("LUX_AUTH_MANAGED_EMAIL_PROVIDER is required for managed email")
    })?;
    if provider != "postmark" {
        return Err(invalid_config(
            "LUX_AUTH_MANAGED_EMAIL_PROVIDER must be postmark",
        ));
    }
    let from = from
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            invalid_config("LUX_AUTH_MANAGED_EMAIL_FROM is required for managed email")
        })?;
    if token.as_ref().is_none_or(|value| value.trim().is_empty()) {
        return Err(invalid_config(
            "LUX_AUTH_MANAGED_POSTMARK_SERVER_TOKEN is required for managed email",
        ));
    }
    Ok(Some(lux::AuthManagedEmailConfig {
        provider,
        from,
        reply_to,
        postmark_server_token: token,
        postmark_message_stream,
    }))
}

#[cfg(test)]
mod tests {
    use super::{
        decode_seal_value, parse_durability, parse_encryption_keys_json, parse_shutdown_timeout,
        parse_storage_mode,
    };

    #[test]
    fn numeric_configuration_rejects_malformed_and_out_of_range_values() {
        for raw in ["", "no", "-1", "1.5", "65536", "18446744073709551616"] {
            assert!(super::parse_number("port", raw, 0u16).is_err());
        }
        assert_eq!(super::parse_number("port", "0", 0u16).unwrap(), 0);
        assert_eq!(super::parse_number("port", "65535", 0u16).unwrap(), 65535);
        assert!(super::parse_number("threads", "0", 1usize).is_err());
        assert_eq!(super::parse_number("threads", "2", 1usize).unwrap(), 2);
    }

    #[test]
    fn boolean_configuration_is_explicit_and_does_not_echo_values() {
        for raw in ["true", "TRUE", "1"] {
            assert!(super::parse_bool("setting", raw).unwrap());
        }
        for raw in ["false", "FALSE", "0"] {
            assert!(!super::parse_bool("setting", raw).unwrap());
        }
        for raw in ["", "yes", "tru", "private-value"] {
            let error = super::parse_bool("setting", raw).unwrap_err().to_string();
            assert_eq!(error, "setting must be true, false, 1, or 0");
        }
    }

    #[test]
    fn decode_seal_value_requires_base64_of_32_bytes() {
        use base64::Engine as _;
        let good = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        assert_eq!(decode_seal_value("X", &good).unwrap(), [7u8; 32]);

        // Not base64.
        assert!(decode_seal_value("X", "not base64!!").is_err());
        // Base64 but wrong length (16 bytes).
        let short = base64::engine::general_purpose::STANDARD.encode([1u8; 16]);
        let err = decode_seal_value("X", &short).unwrap_err();
        assert!(err.contains("32 bytes"), "{err}");
    }

    #[test]
    fn encryption_keys_json_parses_rotation_network() {
        let config = parse_encryption_keys_json(
            r#"[
                {"id":"k1","secret":"old","decryptOnly":true},
                {"id":"k2","secret":"new"}
            ]"#,
            None,
        )
        .unwrap();

        assert_eq!(config.active_key_id.as_deref(), Some("k2"));
        assert_eq!(config.keys.len(), 2);
        assert!(config.keys[0].decrypt_only);
        assert!(!config.keys[1].decrypt_only);
    }

    #[test]
    fn encryption_keys_json_fails_closed_on_bad_config() {
        let err = parse_encryption_keys_json("not-json", None).unwrap_err();
        assert!(err.contains("invalid LUX_ENCRYPTION_KEYS JSON"), "{err}");

        let err = parse_encryption_keys_json(r#"{"id":"k1"}"#, None).unwrap_err();
        assert!(err.contains("must be a JSON array"), "{err}");

        let err = parse_encryption_keys_json(r#"[{"id":"k1"}]"#, None).unwrap_err();
        assert!(err.contains("secret must be a non-empty string"), "{err}");

        let err =
            parse_encryption_keys_json(r#"[{"id":"k1","secret":"old","decryptOnly":true}]"#, None)
                .unwrap_err();
        assert!(err.contains("at least one writable key"), "{err}");
    }

    #[test]
    fn durability_defaults_safe_and_parses_explicit_policies() {
        let default = parse_durability(None, None).unwrap();
        assert_eq!(default.policy, lux::DurabilityPolicy::AlwaysSync);
        assert_eq!(default.sync_interval, std::time::Duration::from_secs(1));

        let ephemeral = parse_durability(Some("ephemeral".to_string()), None).unwrap();
        assert_eq!(ephemeral.policy, lux::DurabilityPolicy::Ephemeral);

        let always = parse_durability(Some("always_sync".to_string()), None).unwrap();
        assert_eq!(always.policy, lux::DurabilityPolicy::AlwaysSync);
    }

    #[test]
    fn encryption_bootstrap_rejects_unknown_and_contradictory_fields() {
        for raw in [
            r#"[{"id":"key","secret":"value","decrypt_onyl":true}]"#,
            r#"[{"id":"key","secret":"value","decrypt_only":"true"}]"#,
            r#"[{"id":"key","secret":"value","decrypt_only":false,"decryptOnly":true}]"#,
        ] {
            assert!(parse_encryption_keys_json(raw, None).is_err());
        }
        assert!(parse_encryption_keys_json(
            r#"[{"id":"key","secret":"value","decrypt_only":false,"decryptOnly":false}]"#,
            None
        )
        .is_ok());
    }

    #[test]
    fn persistence_environment_values_fail_closed() {
        assert!(parse_durability(Some("sometimes".to_string()), None).is_err());
        assert!(parse_durability(Some("every_second".to_string()), Some("0".to_string())).is_err());
        assert!(
            parse_durability(Some("every_second".to_string()), Some("1001".to_string())).is_err()
        );
        assert!(
            parse_durability(Some("always_sync".to_string()), Some("1000".to_string())).is_err()
        );
        assert!(parse_storage_mode(Some("unknown".to_string())).is_err());
    }

    #[test]
    fn shutdown_timeout_is_bounded_and_fails_closed() {
        assert_eq!(
            parse_shutdown_timeout(None).unwrap(),
            lux::DEFAULT_SHUTDOWN_TIMEOUT
        );
        assert_eq!(
            parse_shutdown_timeout(Some("2500")).unwrap(),
            std::time::Duration::from_millis(2_500)
        );
        assert!(parse_shutdown_timeout(Some("0")).is_err());
        assert!(parse_shutdown_timeout(Some("300001")).is_err());
        assert!(parse_shutdown_timeout(Some("one second")).is_err());
    }
}
