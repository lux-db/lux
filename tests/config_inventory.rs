use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stability {
    Stable,
    Excluded,
}

#[derive(Clone, Copy, Debug)]
struct RuntimeConfig {
    name: &'static str,
    stability: Stability,
}

const RUNTIME_CONFIG: &[RuntimeConfig] = &[
    stable("LUX_ALLOW_INSECURE_NO_AUTH"),
    stable("LUX_AUTH_ACCESS_TOKEN_TTL"),
    stable("LUX_AUTH_ANONYMOUS"),
    stable("LUX_AUTH_EMAIL_CONFIRMATION_REQUIRED"),
    stable("LUX_AUTH_EMAIL_PASSWORD"),
    stable("LUX_AUTH_ENABLED"),
    stable("LUX_AUTH_FLOW_TOKEN_TTL_SECONDS"),
    stable("LUX_AUTH_ISSUER"),
    stable("LUX_AUTH_MANAGED_EMAIL_FROM"),
    stable("LUX_AUTH_MANAGED_EMAIL_PROVIDER"),
    stable("LUX_AUTH_MANAGED_EMAIL_REPLY_TO"),
    stable("LUX_AUTH_MANAGED_POSTMARK_MESSAGE_STREAM"),
    stable("LUX_AUTH_MANAGED_POSTMARK_SERVER_TOKEN"),
    stable("LUX_AUTH_PUBLISHABLE_KEY"),
    stable("LUX_AUTH_REFRESH_TOKEN_TTL"),
    stable("LUX_AUTH_SECRET_KEY"),
    stable("LUX_AUTH_SITE_URL"),
    stable("LUX_BIND_HOST"),
    stable("LUX_DATA_DIR"),
    stable("LUX_DURABILITY"),
    stable("LUX_DURABILITY_SYNC_INTERVAL_MS"),
    stable("LUX_ENABLE_RESP"),
    stable("LUX_ENCRYPTION_KEY"),
    stable("LUX_ENCRYPTION_KEYS"),
    stable("LUX_ENCRYPTION_KEY_ID"),
    stable("LUX_ENC_AUTO_INIT"),
    stable("LUX_ENC_SEAL_KEY"),
    stable("LUX_ENC_SEAL_KEY_PREVIOUS"),
    stable("LUX_ENC_SEAL_PATH"),
    stable("LUX_ENC_STATE_PATH"),
    stable("LUX_HTTP_PORT"),
    stable("LUX_MAXMEMORY"),
    stable("LUX_MAXMEMORY_POLICY"),
    stable("LUX_MAXMEMORY_SAMPLES"),
    stable("LUX_MAX_BODY_SIZE"),
    stable("LUX_MAX_RESP_REQUEST_SIZE"),
    stable("LUX_MAX_ROWS"),
    stable("LUX_PASSWORD"),
    stable("LUX_PORT"),
    excluded("LUX_PUSH_ALLOW_PRIVATE_ENDPOINTS"),
    stable("LUX_RESTRICTED"),
    stable("LUX_RUNTIME_THREADS"),
    stable("LUX_SAVE_INTERVAL"),
    stable("LUX_SHARDS"),
    stable("LUX_SHUTDOWN_TIMEOUT_MS"),
    stable("LUX_STORAGE_DIR"),
    stable("LUX_STORAGE_MODE"),
];

const fn stable(name: &'static str) -> RuntimeConfig {
    RuntimeConfig {
        name,
        stability: Stability::Stable,
    }
}

const fn excluded(name: &'static str) -> RuntimeConfig {
    RuntimeConfig {
        name,
        stability: Stability::Excluded,
    }
}

fn quoted_env_names(source: &str) -> BTreeSet<&str> {
    source
        .split('"')
        .filter(|value| {
            value.starts_with("LUX_") && value.bytes().all(|b| b == b'_' || b.is_ascii_uppercase())
        })
        .collect()
}

#[test]
fn every_engine_runtime_variable_is_classified() {
    let source_names = quoted_env_names(concat!(
        include_str!("../src/main.rs"),
        include_str!("../src/push/webpush.rs")
    ));
    let inventory_names: BTreeSet<_> = RUNTIME_CONFIG.iter().map(|entry| entry.name).collect();

    assert_eq!(source_names, inventory_names);
}

#[test]
fn every_engine_runtime_variable_is_in_the_public_contract() {
    let docs = concat!(
        include_str!("../README.md"),
        include_str!("../COMPATIBILITY.md")
    );
    for entry in RUNTIME_CONFIG {
        assert!(
            docs.contains(&format!("`{}`", entry.name)),
            "{} ({:?}) is missing from the public configuration contract",
            entry.name,
            entry.stability
        );
    }
}
