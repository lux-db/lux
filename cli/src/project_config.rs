use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

use crate::file_security::read_optional_secret_file;

#[derive(Serialize, Deserialize, Default)]
pub(super) struct LocalConfig {
    pub(super) project_id: Option<String>,
    pub(super) project_name: Option<String>,
    /// Optional host port overrides for `lux start` (engine listens on 6379/5890
    /// inside the container; these map to the host).
    pub(super) local_http_port: Option<u16>,
    pub(super) local_resp_port: Option<u16>,
    /// Pin the local engine to a specific version (e.g. "0.23.0") instead of
    /// tracking `:latest`. Maps to the corresponding published Engine image.
    pub(super) engine_version: Option<String>,
    /// Normalized Engine overrides parsed from the public TOML sections. This
    /// is derived state; the writer preserves source sections with toml_edit.
    #[serde(skip)]
    pub(super) engine_env: HashMap<String, String>,
}

#[derive(Clone, Copy)]
enum ValueKind {
    PositiveInteger,
    OptionalLimit,
    Bytes,
    Duration,
}

#[derive(Clone, Copy)]
struct Setting {
    section: &'static str,
    key: &'static str,
    env: &'static str,
    value: ValueKind,
}

const fn setting(
    section: &'static str,
    key: &'static str,
    env: &'static str,
    value: ValueKind,
) -> Setting {
    Setting {
        section,
        key,
        env,
        value,
    }
}

const SETTINGS: &[Setting] = &[
    setting("limits", "rows", "LUX_MAX_ROWS", ValueKind::OptionalLimit),
    setting(
        "limits",
        "http_body_bytes",
        "LUX_MAX_BODY_SIZE",
        ValueKind::Bytes,
    ),
    setting(
        "limits",
        "resp_request_bytes",
        "LUX_MAX_RESP_REQUEST_SIZE",
        ValueKind::Bytes,
    ),
    setting(
        "limits",
        "resp_connections",
        "LUX_MAX_RESP_CONNECTIONS",
        ValueKind::PositiveInteger,
    ),
    setting(
        "limits",
        "http_connections",
        "LUX_MAX_HTTP_CONNECTIONS",
        ValueKind::PositiveInteger,
    ),
    setting(
        "limits",
        "blocked_clients",
        "LUX_MAX_BLOCKED_CLIENTS",
        ValueKind::PositiveInteger,
    ),
    setting(
        "limits",
        "resp_pipeline_commands",
        "LUX_MAX_RESP_PIPELINE_COMMANDS",
        ValueKind::PositiveInteger,
    ),
    setting(
        "limits",
        "resp_command_args",
        "LUX_MAX_RESP_COMMAND_ARGS",
        ValueKind::PositiveInteger,
    ),
    setting(
        "limits",
        "resp_subscriptions",
        "LUX_MAX_RESP_SUBSCRIPTIONS",
        ValueKind::PositiveInteger,
    ),
    setting(
        "limits",
        "subscription_name_bytes",
        "LUX_MAX_SUBSCRIPTION_NAME_SIZE",
        ValueKind::Bytes,
    ),
    setting(
        "limits",
        "live_subscriptions",
        "LUX_MAX_LIVE_SUBSCRIPTIONS",
        ValueKind::PositiveInteger,
    ),
    setting(
        "limits",
        "process_subscriptions",
        "LUX_MAX_SUBSCRIPTIONS",
        ValueKind::PositiveInteger,
    ),
    setting(
        "limits",
        "query_candidates",
        "LUX_MAX_QUERY_CANDIDATES",
        ValueKind::PositiveInteger,
    ),
    setting(
        "limits",
        "blocking_keys",
        "LUX_MAX_BLOCKING_KEYS",
        ValueKind::PositiveInteger,
    ),
    setting(
        "limits",
        "resp_response_bytes",
        "LUX_MAX_RESP_RESPONSE_SIZE",
        ValueKind::Bytes,
    ),
    setting(
        "limits",
        "request_buffer_bytes",
        "LUX_MAX_REQUEST_BUFFER_SIZE",
        ValueKind::Bytes,
    ),
    setting(
        "limits",
        "response_buffer_bytes",
        "LUX_MAX_RESPONSE_BUFFER_SIZE",
        ValueKind::Bytes,
    ),
    setting(
        "limits",
        "auth_workers",
        "LUX_MAX_AUTH_WORKERS",
        ValueKind::PositiveInteger,
    ),
    setting(
        "limits",
        "script_memory_bytes",
        "LUX_MAX_SCRIPT_MEMORY_SIZE",
        ValueKind::Bytes,
    ),
    setting(
        "timeouts",
        "resp_idle",
        "LUX_RESP_IDLE_TIMEOUT_MS",
        ValueKind::Duration,
    ),
    setting(
        "timeouts",
        "resp_request",
        "LUX_RESP_REQUEST_TIMEOUT_MS",
        ValueKind::Duration,
    ),
    setting(
        "timeouts",
        "http_header",
        "LUX_HTTP_HEADER_TIMEOUT_MS",
        ValueKind::Duration,
    ),
    setting(
        "timeouts",
        "http_body",
        "LUX_HTTP_BODY_TIMEOUT_MS",
        ValueKind::Duration,
    ),
    setting(
        "timeouts",
        "http_keep_alive",
        "LUX_HTTP_KEEP_ALIVE_TIMEOUT_MS",
        ValueKind::Duration,
    ),
    setting(
        "timeouts",
        "live_idle",
        "LUX_LIVE_IDLE_TIMEOUT_MS",
        ValueKind::Duration,
    ),
    setting(
        "timeouts",
        "write",
        "LUX_WRITE_TIMEOUT_MS",
        ValueKind::Duration,
    ),
];

pub(super) const INITIAL_CONFIG: &str = r#"# Project metadata is managed by `lux link`.
project_id = ""
project_name = ""

# Optional local Engine overrides. Omitted settings use Engine defaults.
# [engine.limits]
# resp_connections = 1024
# query_candidates = 1_000_000
# request_buffer_bytes = "256mb"
#
# [engine.timeouts]
# resp_idle = "5m"
# write = "30s"
"#;

fn normalized_positive_integer(value: i64, name: &str) -> Result<String, String> {
    if value <= 0 {
        return Err(format!("{name} must be greater than zero"));
    }
    usize::try_from(value)
        .map(|value| value.to_string())
        .map_err(|_| format!("{name} is too large for this platform"))
}

fn normalized_optional_limit(value: i64, name: &str) -> Result<String, String> {
    if value < 0 {
        return Err(format!("{name} must be zero or greater"));
    }
    usize::try_from(value)
        .map(|value| value.to_string())
        .map_err(|_| format!("{name} is too large for this platform"))
}

fn parse_quantity(value: &str, units: &[(&str, u64)], name: &str) -> Result<u64, String> {
    let value = value.trim().to_ascii_lowercase();
    let split = value
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(value.len());
    let (amount, unit) = value.split_at(split);
    if amount.is_empty() || unit.is_empty() {
        return Err(format!("{name} must include a number and unit"));
    }
    let amount = amount
        .parse::<u64>()
        .map_err(|_| format!("{name} has an invalid number"))?;
    if amount == 0 {
        return Err(format!("{name} must be greater than zero"));
    }
    let multiplier = units
        .iter()
        .find_map(|(candidate, multiplier)| (*candidate == unit).then_some(*multiplier))
        .ok_or_else(|| format!("{name} has unsupported unit '{unit}'"))?;
    amount
        .checked_mul(multiplier)
        .ok_or_else(|| format!("{name} is too large"))
}

fn normalized_bytes(item: &toml_edit::Item, name: &str) -> Result<String, String> {
    let bytes = if let Some(value) = item.as_integer() {
        return normalized_positive_integer(value, name);
    } else if let Some(value) = item.as_str() {
        parse_quantity(
            value,
            &[
                ("b", 1),
                ("kb", 1024),
                ("kib", 1024),
                ("mb", 1024 * 1024),
                ("mib", 1024 * 1024),
                ("gb", 1024 * 1024 * 1024),
                ("gib", 1024 * 1024 * 1024),
            ],
            name,
        )?
    } else {
        return Err(format!(
            "{name} must be an integer byte count or size string"
        ));
    };
    usize::try_from(bytes)
        .map(|value| value.to_string())
        .map_err(|_| format!("{name} is too large for this platform"))
}

fn normalized_duration(item: &toml_edit::Item, name: &str) -> Result<String, String> {
    let milliseconds = if let Some(value) = item.as_integer() {
        return normalized_positive_integer(value, name);
    } else if let Some(value) = item.as_str() {
        parse_quantity(
            value,
            &[("ms", 1), ("s", 1_000), ("m", 60_000), ("h", 3_600_000)],
            name,
        )?
    } else {
        return Err(format!("{name} must be milliseconds or a duration string"));
    };
    usize::try_from(milliseconds)
        .map(|value| value.to_string())
        .map_err(|_| format!("{name} is too large for this platform"))
}

fn normalized_toml_value(setting: Setting, item: &toml_edit::Item) -> Result<String, String> {
    let name = format!("engine.{}.{}", setting.section, setting.key);
    match setting.value {
        ValueKind::PositiveInteger => item
            .as_integer()
            .ok_or_else(|| format!("{name} must be an integer"))
            .and_then(|value| normalized_positive_integer(value, &name)),
        ValueKind::OptionalLimit => item
            .as_integer()
            .ok_or_else(|| format!("{name} must be an integer"))
            .and_then(|value| normalized_optional_limit(value, &name)),
        ValueKind::Bytes => normalized_bytes(item, &name),
        ValueKind::Duration => normalized_duration(item, &name),
    }
}

fn parse_engine_env(
    doc: &toml_edit::DocumentMut,
    path: &Path,
) -> Result<HashMap<String, String>, String> {
    let Some(engine) = doc.get("engine") else {
        return Ok(HashMap::new());
    };
    let engine = engine
        .as_table_like()
        .ok_or_else(|| format!("engine must be a table in {}", path.display()))?;
    for (key, _) in engine.iter() {
        if key != "limits" && key != "timeouts" {
            return Err(format!(
                "unknown engine section 'engine.{key}' in {}",
                path.display()
            ));
        }
    }

    let mut values = HashMap::new();
    for section in ["limits", "timeouts"] {
        let Some(item) = engine.get(section) else {
            continue;
        };
        let table = item
            .as_table_like()
            .ok_or_else(|| format!("engine.{section} must be a table in {}", path.display()))?;
        for (key, item) in table.iter() {
            let setting = SETTINGS
                .iter()
                .copied()
                .find(|setting| setting.section == section && setting.key == key)
                .ok_or_else(|| {
                    format!(
                        "unknown Engine setting 'engine.{section}.{key}' in {}",
                        path.display()
                    )
                })?;
            values.insert(
                setting.env.to_string(),
                normalized_toml_value(setting, item)?,
            );
        }
    }
    Ok(values)
}

fn normalize_environment_value(setting: Setting, value: &str) -> Result<String, String> {
    let value = value
        .trim()
        .parse::<i64>()
        .map_err(|_| format!("{} must be an integer", setting.env))?;
    match setting.value {
        ValueKind::OptionalLimit => normalized_optional_limit(value, setting.env),
        _ => normalized_positive_integer(value, setting.env),
    }
}

pub(super) fn resolved_engine_env_with<F>(
    config: &LocalConfig,
    mut environment: F,
) -> Result<Vec<String>, String>
where
    F: FnMut(&str) -> Result<Option<String>, String>,
{
    let mut resolved = HashMap::new();
    for setting in SETTINGS {
        let value = match environment(setting.env)? {
            Some(value) => Some(normalize_environment_value(*setting, &value)?),
            None => config.engine_env.get(setting.env).cloned(),
        };
        if let Some(value) = value {
            resolved.insert(setting.env.to_string(), value);
        }
    }
    validate_relationships(&resolved)?;
    Ok(SETTINGS
        .iter()
        .filter_map(|setting| {
            resolved
                .get(setting.env)
                .map(|value| format!("{}={value}", setting.env))
        })
        .collect())
}

pub(super) fn resolved_engine_env(config: &LocalConfig) -> Result<Vec<String>, String> {
    resolved_engine_env_with(config, |name| match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(format!("{name} must be UTF-8")),
    })
}

fn validate_relationships(values: &HashMap<String, String>) -> Result<(), String> {
    // These are the Engine's public defaults. Mirroring them here lets the CLI
    // reject an invalid partial override before it changes a running container.
    const DEFAULT_REQUEST_BYTES: usize = 64 * 1024 * 1024;
    const DEFAULT_BUFFER_BYTES: usize = 256 * 1024 * 1024;
    const DEFAULT_QUERY_CANDIDATES: usize = 1_000_000;

    let value = |name: &str, default: usize| -> usize {
        values
            .get(name)
            .and_then(|value| value.parse().ok())
            .unwrap_or(default)
    };
    let max_body = value("LUX_MAX_BODY_SIZE", DEFAULT_REQUEST_BYTES);
    let max_resp_request = value("LUX_MAX_RESP_REQUEST_SIZE", DEFAULT_REQUEST_BYTES);
    let request_budget = value("LUX_MAX_REQUEST_BUFFER_SIZE", DEFAULT_BUFFER_BYTES);
    if request_budget < max_body.max(max_resp_request) {
        return Err(
            "engine.limits.request_buffer_bytes must be at least the larger HTTP body or RESP request limit"
                .to_string(),
        );
    }
    let max_resp_response = value("LUX_MAX_RESP_RESPONSE_SIZE", DEFAULT_REQUEST_BYTES);
    if max_resp_response < b"-ERR RESP response exceeds maximum\r\n".len() {
        return Err(
            "engine.limits.resp_response_bytes is too small for an error response".to_string(),
        );
    }
    let response_budget = value("LUX_MAX_RESPONSE_BUFFER_SIZE", DEFAULT_BUFFER_BYTES);
    if response_budget < max_resp_response {
        return Err(
            "engine.limits.response_buffer_bytes must be at least resp_response_bytes".to_string(),
        );
    }
    if value("LUX_MAX_QUERY_CANDIDATES", DEFAULT_QUERY_CANDIDATES) == usize::MAX {
        return Err("engine.limits.query_candidates is too large".to_string());
    }
    Ok(())
}

pub(super) fn managed_configuration_matches(
    actual: &HashMap<String, String>,
    expected: &[String],
) -> bool {
    let expected: HashMap<&str, &str> = expected
        .iter()
        .filter_map(|entry| entry.split_once('='))
        .collect();
    if expected
        .iter()
        .any(|(key, value)| actual.get(*key).map(String::as_str) != Some(*value))
    {
        return false;
    }
    SETTINGS
        .iter()
        .all(|setting| expected.contains_key(setting.env) || !actual.contains_key(setting.env))
}

pub(super) fn load(path: &Path) -> Result<Option<LocalConfig>, String> {
    let Some(data) = read_optional_secret_file(path)? else {
        return Ok(None);
    };
    let doc = data
        .parse::<toml_edit::DocumentMut>()
        .map_err(|error| format!("parse {}: {error}", path.display()))?;
    let string = |key: &str| -> Result<Option<String>, String> {
        let Some(item) = doc.get(key) else {
            return Ok(None);
        };
        let value = item
            .as_str()
            .ok_or_else(|| format!("{key} must be a string in {}", path.display()))?;
        Ok((!value.trim().is_empty()).then(|| value.to_string()))
    };
    let port = |key: &str| -> Result<Option<u16>, String> {
        let Some(item) = doc.get(key) else {
            return Ok(None);
        };
        let value = item
            .as_integer()
            .ok_or_else(|| format!("{key} must be an integer in {}", path.display()))?;
        u16::try_from(value)
            .map(Some)
            .map_err(|_| format!("{key} must be between 0 and 65535 in {}", path.display()))
    };
    Ok(Some(LocalConfig {
        project_id: string("project_id")?,
        project_name: string("project_name")?,
        local_http_port: port("local_http_port")?,
        local_resp_port: port("local_resp_port")?,
        engine_version: string("engine_version")?,
        engine_env: parse_engine_env(&doc, path)?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn public_setting_names_and_engine_variables_are_unique_and_documented() {
        let mut names = HashSet::new();
        let mut variables = HashSet::new();
        let docs = include_str!("../README.md");
        for setting in SETTINGS {
            assert!(
                names.insert((setting.section, setting.key)),
                "duplicate TOML setting {}.{}",
                setting.section,
                setting.key
            );
            assert!(variables.insert(setting.env), "duplicate {}", setting.env);
            assert!(
                docs.contains(&format!("`{}`", setting.key)),
                "{} is missing from the CLI configuration reference",
                setting.key
            );
        }
    }
}
