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
    let managed_email = managed_auth_email_from_env();

    let encryption = encryption_config_from_env()?;

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
            managed_email,
        },
        encryption,
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

fn encryption_config_from_env() -> std::io::Result<lux::EncryptionConfig> {
    let state_path = std::env::var("LUX_ENC_STATE_PATH").ok();
    let seal_path = std::env::var("LUX_ENC_SEAL_PATH").ok();
    let auto_init = std::env::var("LUX_ENC_AUTO_INIT").is_ok_and(|value| {
        let value = value.to_ascii_lowercase();
        value == "1" || value == "true"
    });
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
        eprintln!(
            "lux: warning: encryption seal key is stored on the data volume; \
             a stolen disk or backup carries the key. Set LUX_ENC_SEAL_KEY \
             (base64 of 32 bytes) from your secret store."
        );
    }

    if let Ok(raw) = std::env::var("LUX_ENCRYPTION_KEYS") {
        let mut config =
            parse_encryption_keys_json(&raw, std::env::var("LUX_ENCRYPTION_KEY_ID").ok())
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

    let Some(secret) = std::env::var("LUX_ENCRYPTION_KEY").ok() else {
        return Ok(lux::EncryptionConfig {
            state_path,
            seal_path,
            auto_init,
            seal_secret,
            previous_seal_secrets,
            ..Default::default()
        });
    };
    let id = std::env::var("LUX_ENCRYPTION_KEY_ID").unwrap_or_else(|_| "local".to_string());
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
    match std::env::var(name) {
        Ok(raw) if !raw.trim().is_empty() => Ok(Some(decode_seal_value(name, raw.trim())?)),
        _ => Ok(None),
    }
}

/// Decode a comma-separated list of base64 seals (previous/rotated-out keys).
fn parse_seal_list_env(name: &str) -> Result<Vec<[u8; 32]>, String> {
    let Ok(raw) = std::env::var(name) else {
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
            decrypt_only: item
                .get("decryptOnly")
                .or_else(|| item.get("decrypt_only"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
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
        auto_init: std::env::var("LUX_ENC_AUTO_INIT").is_ok_and(|value| {
            let value = value.to_ascii_lowercase();
            value == "1" || value == "true"
        }),
        // Filled in by the caller from LUX_ENC_SEAL_KEY / _PREVIOUS.
        seal_secret: None,
        previous_seal_secrets: Vec::new(),
    };
    Ok(config)
}

fn managed_auth_email_from_env() -> Option<lux::AuthManagedEmailConfig> {
    let token = std::env::var("LUX_AUTH_MANAGED_POSTMARK_SERVER_TOKEN").ok();
    let provider = std::env::var("LUX_AUTH_MANAGED_EMAIL_PROVIDER")
        .ok()
        .or_else(|| token.as_ref().map(|_| "postmark".to_string()))?;
    let from = std::env::var("LUX_AUTH_MANAGED_EMAIL_FROM").ok()?;
    Some(lux::AuthManagedEmailConfig {
        provider,
        from,
        reply_to: std::env::var("LUX_AUTH_MANAGED_EMAIL_REPLY_TO").ok(),
        postmark_server_token: token,
        postmark_message_stream: std::env::var("LUX_AUTH_MANAGED_POSTMARK_MESSAGE_STREAM").ok(),
    })
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

#[cfg(test)]
mod tests {
    use super::{decode_seal_value, parse_encryption_keys_json};

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
}
