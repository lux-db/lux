use std::collections::HashMap;
use std::future::Future;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use base64::Engine;
use jsonwebtoken::jwk::{Jwk, JwkSet, KeyAlgorithm, PublicKeyUse};
use jsonwebtoken::{
    decode, decode_header, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use p256::pkcs8::{EncodePrivateKey, LineEnding};
use p256::SecretKey;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::runtime::RuntimeFlavor;
use tokio::task::block_in_place;

use crate::store::Store;
use crate::tables::{self, CmpOp, SelectPlan, SelectResult, SharedSchemaCache, WhereClause};
use crate::{AuthConfig, AuthManagedEmailConfig};

mod apple;
use apple::{
    admin_upsert_apple_provider, exchange_apple_code, issue_apple_native_nonce,
    migrate_provider_apple_columns, mint_apple_client_secret, parse_apple_callback_name,
    signin_apple,
};
#[cfg(test)]
use apple::{
    seal_apple_private_key, seed_apple_jwks_for_test, sha256_hex, verify_apple_id_token,
    APPLE_ISSUER,
};
mod refresh;
mod secrets;

pub(crate) const USERS_TABLE: &str = "auth.users";
pub(crate) const IDENTITIES_TABLE: &str = "auth.identities";
pub(crate) const SESSIONS_TABLE: &str = "auth.sessions";
pub(crate) const KEYS_TABLE: &str = "auth.keys";
pub(crate) const SIGNING_KEYS_TABLE: &str = "auth.signing_keys";
pub(crate) const GRANTS_TABLE: &str = "auth.grants";
pub(crate) const PROVIDERS_TABLE: &str = "auth.providers";
pub(crate) const FLOW_TOKENS_TABLE: &str = "auth.flow_tokens";
pub(crate) const SETTINGS_TABLE: &str = "auth.settings";

const AUTH_SCHEMA_VERSION_KEY: &[u8] = b"_auth:schema_version";
const AUTH_SCHEMA_VERSION: &[u8] = b"4";
const OAUTH_STATE_TTL: Duration = Duration::from_secs(10 * 60);
const OAUTH_CALLBACK_BODY_LIMIT: usize = 64 * 1024;
const POSTMARK_EMAIL_TIMEOUT: Duration = Duration::from_secs(10);
const ACCESS_REVOKED_AFTER_PREFIX: &[u8] = b"_auth:access_revoked_after:";
static FLOW_TOKEN_CONSUME_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ApiKeyKind {
    Publishable,
    Secret,
}

#[derive(Clone)]
struct SigningKey {
    kid: String,
    algorithm: String,
    public_jwk: String,
    private_key: String,
}

#[derive(Clone)]
struct AuthSettings {
    email_confirmation_required: bool,
    flow_token_ttl: Duration,
    site_url: String,
    redirect_allow_list: Vec<String>,
    email_provider: String,
    email_from: Option<String>,
    email_reply_to: Option<String>,
    email_postmark_server_token: Option<String>,
    email_postmark_message_stream: String,
    email_app_name: String,
    email_from_name: Option<String>,
}

struct FlowTokenInsert<'a> {
    settings: &'a AuthSettings,
    kind: &'a str,
    user_id: &'a str,
    email: &'a str,
    redirect_to: &'a str,
    metadata: Value,
}

#[derive(Clone)]
struct EffectiveEmailDelivery {
    provider: String,
    from: Option<String>,
    reply_to: Option<String>,
    postmark_server_token: Option<String>,
    postmark_message_stream: String,
    app_name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AuthEmailMessage {
    from: String,
    to: String,
    reply_to: Option<String>,
    subject: String,
    text_body: String,
    html_body: String,
    message_stream: String,
}

#[derive(Clone, Debug, Serialize)]
struct PostmarkEmailPayload {
    #[serde(rename = "From")]
    from: String,
    #[serde(rename = "To")]
    to: String,
    #[serde(rename = "Subject")]
    subject: String,
    #[serde(rename = "TextBody")]
    text_body: String,
    #[serde(rename = "HtmlBody")]
    html_body: String,
    #[serde(rename = "MessageStream")]
    message_stream: String,
    #[serde(rename = "ReplyTo", skip_serializing_if = "Option::is_none")]
    reply_to: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PasswordVerification {
    Invalid,
    Valid,
    ValidNeedsRehash,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AccessClaims {
    iss: String,
    sub: String,
    email: String,
    session_id: String,
    role: String,
    iat: usize,
    exp: usize,
    // Anonymous (signInAnonymously) sessions. Gates decryption of ENCRYPTED
    // columns: anonymous callers get NULL, real users get plaintext. Defaulted
    // so tokens minted before this field decode (missing -> not anonymous).
    #[serde(default)]
    is_anonymous: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct AuthHttpResponse {
    pub status: u16,
    pub status_text: &'static str,
    pub body: String,
    pub content_type: &'static str,
    pub headers: Vec<(String, String)>,
}

impl AuthHttpResponse {
    fn json(status: u16, status_text: &'static str, body: String) -> Self {
        Self {
            status,
            status_text,
            body,
            content_type: "application/json",
            headers: Vec::new(),
        }
    }

    fn redirect(location: String) -> Self {
        Self {
            status: 302,
            status_text: "Found",
            body: String::new(),
            content_type: "text/plain",
            headers: vec![("Location".to_string(), location)],
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuthPrincipal {
    pub user_id: String,
    pub email: String,
    pub session_id: String,
    pub role: String,
    /// Anonymous (signInAnonymously) session. Encrypted columns are NULLed for
    /// these principals; real users and the operator get plaintext.
    pub is_anonymous: bool,
}

/// An access token authenticated during credential resolution. The claims are
/// retained only for bounded state revalidation by long-lived connections.
#[derive(Clone, Debug)]
pub(crate) struct UserCredential {
    pub principal: AuthPrincipal,
    claims: AccessClaims,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthSecretStorageStatus {
    Disabled,
    Ready,
    Degraded,
    Locked,
}

impl AuthSecretStorageStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Ready => "ready",
            Self::Degraded => "degraded",
            Self::Locked => "locked",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AuthSecretStorageHealth {
    pub status: AuthSecretStorageStatus,
    pub mode: &'static str,
    pub persistent: bool,
    pub snapshots_allowed: bool,
    pub message: Option<&'static str>,
}

#[derive(Debug)]
pub(crate) struct AuthRuntimeBootstrap {
    pub(crate) secret_history_checkpoint_required: bool,
}

pub(crate) fn secret_storage_health(store: &Store) -> AuthSecretStorageHealth {
    secrets::health(store)
}

pub(crate) fn health_json(store: &Store) -> Value {
    let health = secret_storage_health(store);
    json!({
        "enabled": store.config().auth.enabled,
        "secret_storage": {
            "status": health.status.as_str(),
            "mode": health.mode,
            "persistent": health.persistent,
            "snapshots_allowed": health.snapshots_allowed,
            "message": health.message,
        }
    })
}

pub(crate) fn is_reserved_auth_table(table: &str) -> bool {
    table.starts_with("auth.")
}

/// Reserved system scopes managed by the engine (auth + push). Client `T*`/raw-KV
/// access is blocked and sensitive columns are redacted on operator reads.
pub(crate) fn is_reserved_system_table(table: &str) -> bool {
    table.starts_with("auth.") || table.starts_with("push.")
}

/// Auth credentials use their own location-bound envelope and must never be
/// copied into value-bearing table-index keys. These internal tables are read
/// by primary key or non-secret identity fields instead.
pub(crate) fn is_auth_secret_storage_field(table: &str, field: &str) -> bool {
    matches!(
        (table, field),
        (SIGNING_KEYS_TABLE, "private_key_encrypted")
            | (PROVIDERS_TABLE, "client_secret")
            | (PROVIDERS_TABLE, "apple_private_key")
            | (SETTINGS_TABLE, "value")
    )
}

pub(crate) fn reserved_table_mutation_error(args: &[&[u8]], store: &Store) -> Option<String> {
    if store
        .wal_suppress
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return None;
    }
    if args.is_empty() {
        return None;
    }
    let cmd = std::str::from_utf8(args[0])
        .unwrap_or("")
        .to_ascii_uppercase();
    let table = match cmd.as_str() {
        "TCREATE" | "TINSERT" | "TUPDATE" | "TDROP" | "TALTER" | "TSET" => args.get(1),
        "TDELETE" => args.get(2),
        _ => None,
    }
    .and_then(|raw| std::str::from_utf8(raw).ok())?;

    if is_reserved_system_table(table) {
        Some(reserved_table_error(table))
    } else {
        None
    }
}

pub(crate) fn reserved_table_access_error(table: &str) -> Option<String> {
    if is_reserved_system_table(table) {
        Some(reserved_table_error(table))
    } else {
        None
    }
}

/// Defense-in-depth: forbid raw KV mutation (HSET/HDEL/DEL/SET/...) of Lux Auth
/// internal keys (`_t:auth.*`). The table-command guard above only covers
/// `T*` commands, so without this an operator could tamper with / delete auth
/// internals (users, sessions, keys, grants) via raw KV, bypassing the auth API.
/// Internal engine writes use the store layer directly (not this command path),
/// and WAL replay sets `wal_suppress`, so neither is affected.
pub(crate) fn reserved_key_mutation_error(args: &[&[u8]], store: &Store) -> Option<String> {
    if store
        .wal_suppress
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return None;
    }
    if args.is_empty() {
        return None;
    }
    let cmd = std::str::from_utf8(args[0])
        .unwrap_or("")
        .to_ascii_uppercase();
    // `T*` table commands are handled by `reserved_table_mutation_error`.
    if matches!(
        cmd.as_str(),
        "TINSERT" | "TUPSERT" | "TUPDATE" | "TDELETE" | "TCREATE" | "TDROP" | "TALTER" | "TSET"
    ) {
        return None;
    }
    for raw in &args[1..] {
        if let Ok(k) = std::str::from_utf8(raw) {
            if k.starts_with("_t:auth.") || k.starts_with("_t:push.") {
                return Some("ERR access to Lux internal keys is not permitted".to_string());
            }
        }
    }
    None
}

/// Reject a read whose base table or any joined table is Lux Auth managed.
/// The base-table guard alone leaves a bypass: `TSELECT ... FROM posts JOIN
/// auth.users ...` could project `encrypted_password` through the join.
pub(crate) fn reserved_plan_access_error(plan: &SelectPlan) -> Option<String> {
    if let Some(err) = reserved_table_access_error(&plan.table) {
        return Some(err);
    }
    for join in &plan.joins {
        if let Some(err) = reserved_table_access_error(&join.table) {
            return Some(err);
        }
    }
    None
}

pub(crate) fn redact_auth_table_row(table: &str, row: &mut [(String, String)]) {
    if !is_reserved_system_table(table) {
        return;
    }
    if table == SETTINGS_TABLE {
        let key = row
            .iter()
            .find(|(field, _)| bare_auth_field(field) == "key")
            .map(|(_, value)| value.as_str())
            .unwrap_or("");
        if key == "email_postmark_server_token" {
            redact_row_field(row, "value");
        }
        return;
    }
    for field in sensitive_auth_fields(table) {
        redact_row_field(row, field);
    }
}

pub(crate) fn redact_auth_select_row(plan: &SelectPlan, row: &mut [(String, String)]) {
    redact_auth_table_row(&plan.table, row);
    for join in &plan.joins {
        redact_auth_table_row(&join.table, row);
    }
}

fn redact_row_field(row: &mut [(String, String)], field: &str) {
    for (name, value) in row {
        if bare_auth_field(name) == field && !value.is_empty() {
            *value = "<redacted>".to_string();
        }
    }
}

fn bare_auth_field(field: &str) -> &str {
    field.rsplit('.').next().unwrap_or(field)
}

fn sensitive_auth_fields(table: &str) -> &'static [&'static str] {
    match table {
        USERS_TABLE => &["encrypted_password"],
        SESSIONS_TABLE => &["refresh_token_hash", "legacy_refresh_token_hash"],
        KEYS_TABLE => &["key_hash"],
        SIGNING_KEYS_TABLE => &["private_key_encrypted"],
        PROVIDERS_TABLE => &["client_secret", "apple_private_key"],
        FLOW_TOKENS_TABLE => &["token_hash"],
        "push.devices" => &["token"],
        "push.credentials" => &[
            "apns_p8_pem",
            "apns_p8_pem_encrypted",
            "vapid_private",
            "vapid_private_encrypted",
        ],
        "push.outbox" => &["target_token"],
        _ => &[],
    }
}

fn reserved_table_error(table: &str) -> String {
    let scope = if table.starts_with("push.") {
        "Lux Push"
    } else {
        "Lux Auth"
    };
    format!("ERR table '{table}' is managed by {scope}; use its API")
}

pub(crate) fn bootstrap(
    store: &Store,
    cache: &SharedSchemaCache,
    _config: &AuthConfig,
) -> Result<(), String> {
    let now = Instant::now();
    create_table_if_missing(
        store,
        cache,
        USERS_TABLE,
        &[
            "id UUID PRIMARY KEY,",
            "email STR UNIQUE,",
            "phone STR UNIQUE,",
            "encrypted_password STR,",
            "email_confirmed_at INT,",
            "phone_confirmed_at INT,",
            "raw_user_meta_data STR,",
            "raw_app_meta_data STR,",
            "created_at INT,",
            "updated_at INT,",
            "last_sign_in_at INT,",
            "banned_until INT,",
            "deleted_at INT",
        ],
        now,
    )?;
    create_table_if_missing(
        store,
        cache,
        IDENTITIES_TABLE,
        &[
            "id STR PRIMARY KEY,",
            "user_id UUID,",
            "provider STR,",
            "provider_id STR UNIQUE,",
            "identity_data STR,",
            "created_at INT,",
            "updated_at INT",
        ],
        now,
    )?;
    create_table_if_missing(
        store,
        cache,
        SESSIONS_TABLE,
        &[
            "id STR PRIMARY KEY,",
            "user_id UUID,",
            "refresh_token_hash STR UNIQUE,",
            "refresh_token_family STR,",
            "refresh_generation INT,",
            "legacy_refresh_token_hash STR,",
            "user_agent STR,",
            "ip STR,",
            "expires_at INT,",
            "revoked_at INT,",
            "access_revoked_at INT,",
            "refresh_rotated_at INT,",
            "refresh_reuse_detected_at INT,",
            "created_at INT,",
            "updated_at INT",
        ],
        now,
    )?;
    refresh::migrate_columns(store, cache, now)?;
    create_table_if_missing(
        store,
        cache,
        KEYS_TABLE,
        &[
            "id STR PRIMARY KEY,",
            "name STR,",
            "kind STR,",
            "prefix STR UNIQUE,",
            "key_hash STR UNIQUE,",
            "scopes STR,",
            "created_at INT,",
            "revoked_at INT,",
            "last_used_at INT",
        ],
        now,
    )?;
    create_table_if_missing(
        store,
        cache,
        SIGNING_KEYS_TABLE,
        &[
            "id STR PRIMARY KEY,",
            "kid STR UNIQUE,",
            "algorithm STR,",
            "public_jwk STR,",
            "private_key_encrypted STR,",
            "active BOOL,",
            "created_at INT,",
            "rotated_at INT",
        ],
        now,
    )?;
    create_table_if_missing(
        store,
        cache,
        GRANTS_TABLE,
        &[
            "id STR PRIMARY KEY,",
            "tbl STR,",
            "scope STR,",
            "predicate STR,",
            "created_at INT",
        ],
        now,
    )?;
    create_table_if_missing(
        store,
        cache,
        PROVIDERS_TABLE,
        &[
            "provider STR PRIMARY KEY,",
            "enabled BOOL,",
            "client_id STR,",
            "client_secret STR,",
            "redirect_uri STR,",
            "scopes STR,",
            "created_at INT,",
            "updated_at INT,",
            // Apple Sign In key material. `apple_private_key` holds the .p8 in
            // the shared, location-bound auth-secret envelope.
            "apple_team_id STR,",
            "apple_key_id STR,",
            "apple_services_id STR,",
            "apple_bundle_ids STR,",
            "apple_private_key STR",
        ],
        now,
    )?;
    migrate_provider_apple_columns(store, cache, now)?;
    create_table_if_missing(
        store,
        cache,
        FLOW_TOKENS_TABLE,
        &[
            "id STR PRIMARY KEY,",
            "type STR,",
            "token_hash STR UNIQUE,",
            "user_id UUID,",
            "email STR,",
            "redirect_to STR,",
            "metadata STR,",
            "expires_at INT,",
            "consumed_at INT,",
            "created_at INT",
        ],
        now,
    )?;
    create_table_if_missing(
        store,
        cache,
        SETTINGS_TABLE,
        &["key STR PRIMARY KEY,", "value STR,", "updated_at INT"],
        now,
    )?;
    if store.get_checked(AUTH_SCHEMA_VERSION_KEY, now)?.as_deref() != Some(AUTH_SCHEMA_VERSION) {
        let command: [&[u8]; 3] = [b"SET", AUTH_SCHEMA_VERSION_KEY, AUTH_SCHEMA_VERSION];
        store
            .commit_journaled(&command, || {
                store.set(AUTH_SCHEMA_VERSION_KEY, AUTH_SCHEMA_VERSION, None, now)
            })
            .map_err(|error| format!("ERR WAL append failed: {error}"))?;
    }
    Ok(())
}

pub(crate) async fn route_http_response(
    method: &str,
    path: &str,
    body: &str,
    params: &[(String, String)],
    headers: &[(String, String)],
    store: &Store,
    cache: &SharedSchemaCache,
) -> AuthHttpResponse {
    if !store.config().auth.enabled {
        let (status, status_text, body) = error(404, "Not Found", "auth is not enabled");
        return AuthHttpResponse::json(status, status_text, body);
    }

    let path = path.trim_start_matches('/');
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let base = match segments.as_slice() {
        ["auth", "v1", rest @ ..] => rest,
        _ => {
            let (status, status_text, body) = error(404, "Not Found", "not found");
            return AuthHttpResponse::json(status, status_text, body);
        }
    };

    match (method, base) {
        ("GET", ["authorize"]) => oauth_authorize(params, headers, store, cache),
        ("GET", ["callback", provider]) => {
            oauth_callback(provider, params, headers, store, cache).await
        }
        // Apple uses response_mode=form_post, so its callback arrives as a POST
        // with form-encoded code/state in the body rather than the query string.
        ("POST", ["callback", "apple"]) => {
            if body.len() > OAUTH_CALLBACK_BODY_LIMIT {
                let (status, status_text, body) =
                    error(413, "Payload Too Large", "oauth callback body is too large");
                return AuthHttpResponse::json(status, status_text, body);
            }
            if !header_value(headers, "content-type")
                .map(|value| value.starts_with("application/x-www-form-urlencoded"))
                .unwrap_or(false)
            {
                let (status, status_text, body) = error(
                    415,
                    "Unsupported Media Type",
                    "apple callback must be form encoded",
                );
                return AuthHttpResponse::json(status, status_text, body);
            }
            let mut form = parse_form_urlencoded(body);
            form.extend_from_slice(params);
            oauth_callback("apple", &form, headers, store, cache).await
        }
        ("POST", ["callback", _]) => {
            let (status, status_text, body) =
                error(405, "Method Not Allowed", "provider callback must use GET");
            AuthHttpResponse::json(status, status_text, body)
        }
        ("POST", ["signin", "apple", "nonce"]) => {
            if let Err((status, status_text, body)) =
                require_publishable_or_secret(headers, store, cache)
            {
                return AuthHttpResponse::json(status, status_text, body);
            }
            issue_apple_native_nonce(store)
        }
        ("POST", ["signin", "apple"]) => {
            if let Err((status, status_text, body)) =
                require_publishable_or_secret(headers, store, cache)
            {
                return AuthHttpResponse::json(status, status_text, body);
            }
            signin_apple(body, headers, store, cache).await
        }
        _ => {
            let (status, status_text, body) = route_http(
                method,
                &format!("/{}", path),
                body,
                params,
                headers,
                store,
                cache,
            );
            AuthHttpResponse::json(status, status_text, body)
        }
    }
}

pub(crate) fn bootstrap_runtime(
    store: &Store,
    cache: &SharedSchemaCache,
    config: &AuthConfig,
) -> Result<AuthRuntimeBootstrap, String> {
    let now = Instant::now();
    let migration = secrets::migrate_storage(store, cache, now)?;
    ensure_signing_key(store, cache, now)?;
    ensure_auth_setting(
        store,
        cache,
        "email_confirmation_required",
        if config.email_confirmation_required {
            "true"
        } else {
            "false"
        },
        now,
    )?;
    ensure_auth_setting(
        store,
        cache,
        "flow_token_ttl_seconds",
        &config.flow_token_ttl.as_secs().to_string(),
        now,
    )?;
    ensure_auth_setting(store, cache, "site_url", &config.site_url, now)?;
    ensure_auth_setting(store, cache, "redirect_allow_list", "", now)?;
    ensure_auth_setting(store, cache, "email_provider", "console", now)?;
    ensure_auth_setting(
        store,
        cache,
        "email_postmark_message_stream",
        "outbound",
        now,
    )?;
    ensure_auth_setting(store, cache, "email_app_name", "Lux", now)?;
    if let Some(key) = config.initial_publishable_key.as_deref() {
        ensure_api_key(
            store,
            cache,
            key,
            ApiKeyKind::Publishable,
            "initial_publishable",
            now,
        )?;
    }
    if let Some(key) = config.initial_secret_key.as_deref() {
        ensure_api_key(store, cache, key, ApiKeyKind::Secret, "initial_secret", now)?;
    }
    store.set_auth_secret_storage_degraded(
        !store.config().durability.policy.is_persistent() && !store.encryption().has_active_key(),
    );
    if !migration.checkpoint_required && store.encryption().has_active_key() {
        secrets::mark_storage_current(store, cache, now)?;
    }
    Ok(AuthRuntimeBootstrap {
        secret_history_checkpoint_required: migration.checkpoint_required,
    })
}

pub(crate) fn mark_secret_storage_checkpoint_complete(
    store: &Store,
    cache: &SharedSchemaCache,
) -> Result<(), String> {
    secrets::mark_storage_current(store, cache, Instant::now())
}

pub(crate) fn route_http(
    method: &str,
    path: &str,
    body: &str,
    params: &[(String, String)],
    headers: &[(String, String)],
    store: &Store,
    cache: &SharedSchemaCache,
) -> (u16, &'static str, String) {
    if !store.config().auth.enabled {
        return error(404, "Not Found", "auth is not enabled");
    }

    let path = path.trim_start_matches('/');
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let base = match segments.as_slice() {
        ["auth", "v1", rest @ ..] => rest,
        _ => return error(404, "Not Found", "not found"),
    };

    match (method, base) {
        ("GET", ["health"]) => {
            let health = secret_storage_health(store);
            let result = if health.status == AuthSecretStorageStatus::Ready {
                "ok"
            } else {
                health.status.as_str()
            };
            let body = json!({
                "result": result,
                "secret_storage": {
                    "status": health.status.as_str(),
                    "mode": health.mode,
                    "persistent": health.persistent,
                    "snapshots_allowed": health.snapshots_allowed,
                    "message": health.message,
                }
            })
            .to_string();
            if health.status == AuthSecretStorageStatus::Locked {
                (503, "Service Unavailable", body)
            } else {
                (200, "OK", body)
            }
        }
        ("GET", [".well-known", "jwks.json"]) => jwks(store, cache),
        ("POST", ["signup"]) => {
            if let Err(response) = require_publishable_or_secret(headers, store, cache) {
                return response;
            }
            signup(body, headers, store, cache)
        }
        ("POST", ["signin", "anonymous"]) => {
            if let Err(response) = require_publishable_or_secret(headers, store, cache) {
                return response;
            }
            signin_anonymous(headers, store, cache)
        }
        ("POST", ["token"]) => {
            if let Err(response) = require_publishable_or_secret(headers, store, cache) {
                return response;
            }
            let grant_type = get_param(params, "grant_type").unwrap_or("");
            token(body, grant_type, headers, store, cache)
        }
        ("POST", ["recover"]) => {
            if let Err(response) = require_publishable_or_secret(headers, store, cache) {
                return response;
            }
            recover(body, store, cache)
        }
        ("POST", ["verify"]) => {
            if let Err(response) = require_publishable_or_secret(headers, store, cache) {
                return response;
            }
            verify_otp(body, headers, store, cache)
        }
        ("GET", ["user"]) => user_from_bearer(headers, store, cache),
        ("PUT", ["user"]) | ("PATCH", ["user"]) => update_user(body, headers, store, cache),
        ("POST", ["logout"]) => logout(body, headers, store, cache),
        ("GET", ["admin", "users"]) => {
            if let Err(response) = require_secret(headers, store, cache) {
                return response;
            }
            admin_list_users(store, cache)
        }
        ("GET", ["admin", "users", user_id]) => {
            if let Err(response) = require_secret(headers, store, cache) {
                return response;
            }
            admin_get_user(user_id, store, cache)
        }
        ("POST", ["admin", "users"]) => {
            if let Err(response) = require_secret(headers, store, cache) {
                return response;
            }
            admin_create_user(body, store, cache)
        }
        ("PATCH", ["admin", "users", user_id]) => {
            if let Err(response) = require_secret(headers, store, cache) {
                return response;
            }
            admin_update_user(user_id, body, store, cache)
        }
        ("DELETE", ["admin", "users", user_id]) => {
            if let Err(response) = require_secret(headers, store, cache) {
                return response;
            }
            admin_delete_user(user_id, store, cache)
        }
        ("GET", ["admin", "keys"]) => {
            if let Err(response) = require_secret(headers, store, cache) {
                return response;
            }
            admin_list_keys(store, cache)
        }
        ("POST", ["admin", "keys"]) => {
            if let Err(response) = require_secret(headers, store, cache) {
                return response;
            }
            admin_create_key(body, store, cache)
        }
        ("DELETE", ["admin", "keys", key_id]) => {
            if let Err(response) = require_secret(headers, store, cache) {
                return response;
            }
            admin_revoke_key(key_id, store, cache)
        }
        ("GET", ["admin", "providers"]) => {
            if let Err(response) = require_secret(headers, store, cache) {
                return response;
            }
            admin_list_providers(store, cache)
        }
        ("GET", ["admin", "settings"]) => {
            if let Err(response) = require_secret(headers, store, cache) {
                return response;
            }
            admin_get_settings(store, cache)
        }
        ("PATCH", ["admin", "settings"]) => {
            if let Err(response) = require_secret(headers, store, cache) {
                return response;
            }
            admin_update_settings(body, store, cache)
        }
        ("POST", ["admin", "providers", provider]) | ("PUT", ["admin", "providers", provider]) => {
            if let Err(response) = require_secret(headers, store, cache) {
                return response;
            }
            admin_upsert_provider(provider, body, store, cache)
        }
        _ => error(404, "Not Found", "not found"),
    }
}

fn signup(
    body: &str,
    headers: &[(String, String)],
    store: &Store,
    cache: &SharedSchemaCache,
) -> (u16, &'static str, String) {
    if !store.config().auth.email_password_enabled {
        return error(400, "Bad Request", "email/password auth is disabled");
    }
    let parsed = match parse_json(body) {
        Ok(parsed) => parsed,
        Err(response) => return response,
    };
    let email = match required_string(&parsed, "email") {
        Ok(email) => normalize_email(email),
        Err(response) => return response,
    };
    let password = match required_string(&parsed, "password") {
        Ok(password) => password.to_string(),
        Err(response) => return response,
    };
    if password.len() < 8 {
        return error(400, "Bad Request", "password must be at least 8 characters");
    }

    let now = Instant::now();
    if find_row_by_field(store, cache, USERS_TABLE, "email", &email, now)
        .ok()
        .flatten()
        .is_some()
    {
        return error(409, "Conflict", "user already exists");
    }

    let now_sec = unix_seconds();
    let user_id = tables::generate_uuid_v7();
    let password_hash = match hash_password(&password) {
        Ok(hash) => hash,
        Err(e) => return error(500, "Internal Server Error", &e),
    };
    let user_meta = parsed
        .get("data")
        .or_else(|| {
            parsed
                .get("options")
                .and_then(|options| options.get("data"))
        })
        .or_else(|| parsed.get("user_metadata"))
        .cloned()
        .unwrap_or_else(|| json!({}))
        .to_string();
    let app_meta = json!({"provider":"email","providers":["email"]}).to_string();
    let settings = match auth_settings(store, cache, now) {
        Ok(settings) => settings,
        Err(e) => return error(400, "Bad Request", &e),
    };
    let signup_redirect_to = if settings.email_confirmation_required {
        match auth_redirect_to_with_default(&parsed, &settings) {
            Ok(redirect_to) => Some(redirect_to),
            Err(e) => return error(400, "Bad Request", &e),
        }
    } else {
        None
    };
    let now_sec_str = now_sec.to_string();
    let mut fields = vec![
        ("id", user_id.as_str()),
        ("email", email.as_str()),
        ("encrypted_password", password_hash.as_str()),
        ("raw_user_meta_data", user_meta.as_str()),
        ("raw_app_meta_data", app_meta.as_str()),
        ("created_at", now_sec_str.as_str()),
        ("updated_at", now_sec_str.as_str()),
    ];
    if !settings.email_confirmation_required {
        fields.push(("email_confirmed_at", now_sec_str.as_str()));
    }

    if let Err(e) = durable_table_insert(store, cache, USERS_TABLE, &fields, now) {
        return error(400, "Bad Request", &e);
    }
    if let Err(e) = durable_table_insert(
        store,
        cache,
        IDENTITIES_TABLE,
        &[
            ("id", random_id("idn").as_str()),
            ("user_id", user_id.as_str()),
            ("provider", "email"),
            ("provider_id", email.as_str()),
            ("identity_data", json!({"email":email}).to_string().as_str()),
            ("created_at", now_sec_str.as_str()),
            ("updated_at", now_sec_str.as_str()),
        ],
        now,
    ) {
        let _ = durable_table_delete_where(store, cache, USERS_TABLE, &["id", "=", &user_id], now);
        return error(400, "Bad Request", &e);
    }

    if settings.email_confirmation_required {
        let redirect_to = signup_redirect_to.as_deref().unwrap_or("/");
        if let Err(response) =
            create_email_flow_token(store, cache, "signup", &user_id, &email, redirect_to, now)
        {
            let _ = durable_table_delete_where(
                store,
                cache,
                IDENTITIES_TABLE,
                &["user_id", "=", &user_id],
                now,
            );
            let _ =
                durable_table_delete_where(store, cache, USERS_TABLE, &["id", "=", &user_id], now);
            return response;
        }
        return ok(json!({
            "access_token": Value::Null,
            "token_type": "bearer",
            "expires_in": 0,
            "refresh_token": Value::Null,
            "session": Value::Null,
            "user": user_json(store, cache, &user_id, now).unwrap_or_else(|| json!({"id":user_id,"email":email}))
        }));
    }

    match issue_session_response(store, cache, headers, &user_id, &email, now) {
        response @ (200, _, _) => response,
        response => {
            let _ = durable_table_delete_where(
                store,
                cache,
                IDENTITIES_TABLE,
                &["user_id", "=", &user_id],
                now,
            );
            let _ =
                durable_table_delete_where(store, cache, USERS_TABLE, &["id", "=", &user_id], now);
            response
        }
    }
}

// Accountless sign-in: mints a fresh user with no email/password and issues a
// session, so a browser can hold a real principal (`auth.uid()`) for RLS-gated
// reads and `.live()` without collecting credentials. The user is flagged via
// `raw_app_meta_data.provider = "anonymous"` (no schema column, so existing
// instances need no migration).
fn signin_anonymous(
    headers: &[(String, String)],
    store: &Store,
    cache: &SharedSchemaCache,
) -> (u16, &'static str, String) {
    if !store.config().auth.anonymous_enabled {
        return error(400, "Bad Request", "anonymous sign-in is disabled");
    }

    let now = Instant::now();
    let now_sec = unix_seconds();
    let user_id = tables::generate_uuid_v7();
    let app_meta = json!({"provider":"anonymous","providers":["anonymous"]}).to_string();

    if let Err(e) = durable_table_insert(
        store,
        cache,
        USERS_TABLE,
        &[
            ("id", user_id.as_str()),
            ("raw_user_meta_data", "{}"),
            ("raw_app_meta_data", app_meta.as_str()),
            ("created_at", &now_sec.to_string()),
            ("updated_at", &now_sec.to_string()),
        ],
        now,
    ) {
        return error(400, "Bad Request", &e);
    }

    match issue_session_response(store, cache, headers, &user_id, "", now) {
        response @ (200, _, _) => response,
        response => {
            let _ =
                durable_table_delete_where(store, cache, USERS_TABLE, &["id", "=", &user_id], now);
            response
        }
    }
}

fn token(
    body: &str,
    grant_type_param: &str,
    headers: &[(String, String)],
    store: &Store,
    cache: &SharedSchemaCache,
) -> (u16, &'static str, String) {
    let parsed = match parse_json(body) {
        Ok(parsed) => parsed,
        Err(response) => return response,
    };
    let grant_type = parsed
        .get("grant_type")
        .and_then(Value::as_str)
        .unwrap_or(grant_type_param);

    match grant_type {
        "password" => password_grant(&parsed, headers, store, cache),
        "refresh_token" => refresh::grant(&parsed, headers, store, cache),
        "authorization_code" | "pkce" => authorization_code_grant(&parsed, headers, store, cache),
        _ => error(400, "Bad Request", "unsupported grant_type"),
    }
}

fn password_grant(
    parsed: &Value,
    headers: &[(String, String)],
    store: &Store,
    cache: &SharedSchemaCache,
) -> (u16, &'static str, String) {
    if !store.config().auth.email_password_enabled {
        return error(400, "Bad Request", "email/password auth is disabled");
    }
    let email = match required_string(parsed, "email") {
        Ok(email) => normalize_email(email),
        Err(response) => return response,
    };
    let password = match required_string(parsed, "password") {
        Ok(password) => password,
        Err(response) => return response,
    };
    let now = Instant::now();
    let Some(user) = find_row_by_field(store, cache, USERS_TABLE, "email", &email, now)
        .ok()
        .flatten()
    else {
        return error(400, "Bad Request", "invalid login credentials");
    };
    let Some(password_hash) = user.get("encrypted_password") else {
        return error(400, "Bad Request", "invalid login credentials");
    };
    if let Err(response) = validate_user_active(&user, unix_seconds()) {
        return response;
    }
    let settings = match auth_settings(store, cache, now) {
        Ok(settings) => settings,
        Err(e) => return error(400, "Bad Request", &e),
    };
    if settings.email_confirmation_required
        && user
            .get("email_confirmed_at")
            .map(|value| value.trim().is_empty() || value == "0")
            .unwrap_or(true)
    {
        return error(401, "Unauthorized", "email not confirmed");
    }
    match verify_password_state(password, password_hash) {
        Ok(PasswordVerification::Valid) => {}
        Ok(PasswordVerification::ValidNeedsRehash) => {
            if let Some(user_id) = user.get("id") {
                match hash_password(password) {
                    Ok(hash) => {
                        let now_sec = unix_seconds().to_string();
                        let _ = durable_table_update_where(
                            store,
                            cache,
                            USERS_TABLE,
                            &[
                                ("encrypted_password", hash.as_str()),
                                ("updated_at", now_sec.as_str()),
                            ],
                            &["id", "=", user_id],
                            now,
                        );
                    }
                    Err(e) => return error(500, "Internal Server Error", &e),
                }
            }
        }
        Ok(PasswordVerification::Invalid) => {
            return error(400, "Bad Request", "invalid login credentials")
        }
        Err(e) => return error(500, "Internal Server Error", &e),
    }
    let Some(user_id) = user.get("id") else {
        return error(500, "Internal Server Error", "auth user row is missing id");
    };
    issue_session_response(store, cache, headers, user_id, &email, now)
}

fn authorization_code_grant(
    parsed: &Value,
    headers: &[(String, String)],
    store: &Store,
    cache: &SharedSchemaCache,
) -> (u16, &'static str, String) {
    let code = match required_string(parsed, "code") {
        Ok(code) => code,
        Err(response) => return response,
    };
    let now = Instant::now();
    let token = match consume_flow_token(store, cache, "oauth_code", code, now, |flow| {
        verify_oauth_pkce(flow, parsed)
    }) {
        Ok(token) => token,
        Err(response) => return response,
    };
    let Some(user_id) = token.get("user_id") else {
        return error(400, "Bad Request", "authorization code is missing user");
    };
    let Some(user) = find_row_by_field(store, cache, USERS_TABLE, "id", user_id, now)
        .ok()
        .flatten()
    else {
        return error(401, "Unauthorized", "user not found");
    };
    if let Err(response) = validate_user_active(&user, unix_seconds()) {
        return response;
    }
    let email = user.get("email").cloned().unwrap_or_default();
    issue_session_response(store, cache, headers, user_id, &email, now)
}

fn recover(body: &str, store: &Store, cache: &SharedSchemaCache) -> (u16, &'static str, String) {
    if !store.config().auth.email_password_enabled {
        return error(400, "Bad Request", "email/password auth is disabled");
    }
    let parsed = match parse_json(body) {
        Ok(parsed) => parsed,
        Err(response) => return response,
    };
    let email = match required_string(&parsed, "email") {
        Ok(email) => normalize_email(email),
        Err(response) => return response,
    };
    let now = Instant::now();
    let settings = match auth_settings(store, cache, now) {
        Ok(settings) => settings,
        Err(e) => return error(400, "Bad Request", &e),
    };
    let redirect_to = match auth_redirect_to_with_default(&parsed, &settings) {
        Ok(redirect_to) => redirect_to,
        Err(e) => return error(400, "Bad Request", &e),
    };
    if let Some(user) = find_row_by_field(store, cache, USERS_TABLE, "email", &email, now)
        .ok()
        .flatten()
    {
        if validate_user_active(&user, unix_seconds()).is_ok() {
            if let Some(user_id) = user.get("id") {
                if let Err(response) = create_email_flow_token(
                    store,
                    cache,
                    "recovery",
                    user_id,
                    &email,
                    &redirect_to,
                    now,
                ) {
                    return response;
                }
            }
        }
    }
    ok(json!({}))
}

fn verify_otp(
    body: &str,
    headers: &[(String, String)],
    store: &Store,
    cache: &SharedSchemaCache,
) -> (u16, &'static str, String) {
    let parsed = match parse_json(body) {
        Ok(parsed) => parsed,
        Err(response) => return response,
    };
    let token = match required_string(&parsed, "token_hash") {
        Ok(token) => token,
        Err(response) => return response,
    };
    let kind = match required_string(&parsed, "type") {
        Ok(kind) => kind,
        Err(response) => return response,
    };
    let expected_kind = match kind {
        "signup" | "email" | "email_change" => "signup",
        "recovery" => "recovery",
        _ => return error(400, "Bad Request", "unsupported verification type"),
    };
    let now = Instant::now();
    let flow = match consume_flow_token(store, cache, expected_kind, token, now, |_| Ok(())) {
        Ok(flow) => flow,
        Err(response) => return response,
    };
    let Some(user_id) = flow.get("user_id") else {
        return error(400, "Bad Request", "verification token is missing user");
    };
    let Some(user) = find_row_by_field(store, cache, USERS_TABLE, "id", user_id, now)
        .ok()
        .flatten()
    else {
        return error(401, "Unauthorized", "user not found");
    };
    if let Err(response) = validate_user_active(&user, unix_seconds()) {
        return response;
    }
    if expected_kind == "signup" {
        let now_sec = unix_seconds().to_string();
        if let Err(e) = durable_table_update_where(
            store,
            cache,
            USERS_TABLE,
            &[
                ("email_confirmed_at", now_sec.as_str()),
                ("updated_at", now_sec.as_str()),
            ],
            &["id", "=", user_id],
            now,
        ) {
            return error(400, "Bad Request", &e);
        }
    }
    let email = user.get("email").cloned().unwrap_or_default();
    issue_session_response(store, cache, headers, user_id, &email, now)
}

fn issue_session_response(
    store: &Store,
    cache: &SharedSchemaCache,
    headers: &[(String, String)],
    user_id: &str,
    email: &str,
    now: Instant,
) -> (u16, &'static str, String) {
    let now_sec = unix_seconds();
    let session_id = random_id("ses");
    let refresh_token_family = session_id.as_str();
    let refresh_generation = 1u64;
    let refresh_token = match refresh::sign(
        store,
        cache,
        user_id,
        &session_id,
        refresh_token_family,
        refresh_generation,
        now_sec,
    ) {
        Ok(token) => token,
        Err(e) => return error(500, "Internal Server Error", &e),
    };
    let refresh_hash = hash_secret(&refresh_token);
    let access_token = match sign_access_token(store, cache, user_id, email, &session_id) {
        Ok(token) => token,
        Err(e) => return error(500, "Internal Server Error", &e),
    };
    let expires_at = now_sec + store.config().auth.refresh_token_ttl.as_secs();
    let user_agent = header_value(headers, "user-agent")
        .unwrap_or("")
        .to_string();

    if let Err(e) = durable_table_insert(
        store,
        cache,
        SESSIONS_TABLE,
        &[
            ("id", session_id.as_str()),
            ("user_id", user_id),
            ("refresh_token_hash", refresh_hash.as_str()),
            ("refresh_token_family", refresh_token_family),
            ("refresh_generation", &refresh_generation.to_string()),
            ("user_agent", user_agent.as_str()),
            ("ip", ""),
            ("expires_at", &expires_at.to_string()),
            ("created_at", &now_sec.to_string()),
            ("updated_at", &now_sec.to_string()),
        ],
        now,
    ) {
        return error(400, "Bad Request", &e);
    }
    let _ = durable_table_update_where(
        store,
        cache,
        USERS_TABLE,
        &[("last_sign_in_at", now_sec.to_string().as_str())],
        &["id", "=", user_id],
        now,
    );

    ok(json!({
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": store.config().auth.access_token_ttl.as_secs(),
        "refresh_token": refresh_token,
        "user": user_json(store, cache, user_id, now).unwrap_or_else(|| json!({"id":user_id,"email":email}))
    }))
}

fn user_from_bearer(
    headers: &[(String, String)],
    store: &Store,
    cache: &SharedSchemaCache,
) -> (u16, &'static str, String) {
    let claims = match claims_from_bearer(headers, store, cache) {
        Ok(claims) => claims,
        Err(response) => return response,
    };
    let now = Instant::now();
    match user_json(store, cache, &claims.sub, now) {
        Some(user) => ok(json!({"user": user})),
        None => error(404, "Not Found", "user not found"),
    }
}

fn update_user(
    body: &str,
    headers: &[(String, String)],
    store: &Store,
    cache: &SharedSchemaCache,
) -> (u16, &'static str, String) {
    let claims = match claims_from_bearer(headers, store, cache) {
        Ok(claims) => claims,
        Err(response) => return response,
    };
    let parsed = match parse_json(body) {
        Ok(parsed) => parsed,
        Err(response) => return response,
    };
    let now = Instant::now();
    let now_sec = unix_seconds().to_string();
    let mut updates: Vec<(String, String)> = Vec::new();

    if let Some(password) = parsed.get("password").and_then(Value::as_str) {
        if password.len() < 8 {
            return error(400, "Bad Request", "password must be at least 8 characters");
        }
        match hash_password(password) {
            Ok(hash) => updates.push(("encrypted_password".to_string(), hash)),
            Err(e) => return error(500, "Internal Server Error", &e),
        }
    }
    if let Some(email) = parsed.get("email").and_then(Value::as_str) {
        let email = normalize_email(email);
        if email.is_empty() {
            return error(400, "Bad Request", "email cannot be empty");
        }
        if let Some(row) = find_row_by_field(store, cache, USERS_TABLE, "email", &email, now)
            .ok()
            .flatten()
        {
            if row.get("id").map(String::as_str) != Some(claims.sub.as_str()) {
                return error(409, "Conflict", "email already exists");
            }
        }
        updates.push(("email".to_string(), email));
    }
    if let Some(metadata) = parsed
        .get("data")
        .or_else(|| parsed.get("user_metadata"))
        .cloned()
    {
        updates.push(("raw_user_meta_data".to_string(), metadata.to_string()));
    }

    if updates.is_empty() {
        return error(400, "Bad Request", "no user attributes to update");
    }
    updates.push(("updated_at".to_string(), now_sec));
    let update_refs: Vec<(&str, &str)> = updates
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    if let Err(e) = durable_table_update_where(
        store,
        cache,
        USERS_TABLE,
        &update_refs,
        &["id", "=", &claims.sub],
        now,
    ) {
        return error(400, "Bad Request", &e);
    }
    match user_json(store, cache, &claims.sub, now) {
        Some(user) => ok(json!({"user": user})),
        None => error(404, "Not Found", "user not found"),
    }
}

fn logout(
    body: &str,
    headers: &[(String, String)],
    store: &Store,
    cache: &SharedSchemaCache,
) -> (u16, &'static str, String) {
    let now = Instant::now();
    let now_sec = unix_seconds().to_string();
    if let Ok(claims) = claims_from_bearer(headers, store, cache) {
        return match refresh::revoke_family(store, cache, &claims.session_id, &now_sec, now, false)
        {
            Ok(()) => ok(json!({"result":"OK"})),
            Err(e) => error(500, "Internal Server Error", &e),
        };
    }

    if let Ok(parsed) = serde_json::from_str::<Value>(body) {
        if let Some(refresh_token) = parsed.get("refresh_token").and_then(Value::as_str) {
            match refresh::session_id_for_token(refresh_token, store, cache, now) {
                Ok(Some(session_id)) => {
                    if let Err(e) =
                        refresh::revoke_family(store, cache, &session_id, &now_sec, now, false)
                    {
                        return error(500, "Internal Server Error", &e);
                    }
                }
                Ok(None) => {}
                Err(e) => return error(500, "Internal Server Error", &e),
            }
            return ok(json!({"result":"OK"}));
        }
    }
    error(401, "Unauthorized", "missing bearer token or refresh_token")
}

fn jwks(store: &Store, cache: &SharedSchemaCache) -> (u16, &'static str, String) {
    let plan = SelectPlan {
        table: SIGNING_KEYS_TABLE.to_string(),
        alias: None,
        projections: Vec::new(),
        aggregates: Vec::new(),
        joins: Vec::new(),
        conditions: Vec::new(),
        group_by: Vec::new(),
        having: Vec::new(),
        near: None,
        order_by: None,
        limit: Some(100),
        offset: None,
        decrypt_authorized: true,
    };
    match tables::table_select(store, cache, &plan, Instant::now()) {
        Ok(SelectResult::Rows(rows)) => {
            let keys = rows
                .into_iter()
                .map(|row| row.into_iter().collect::<HashMap<_, _>>())
                .filter(|row| {
                    parse_bool(row.get("active"))
                        && row.get("algorithm").map(String::as_str) != Some("HS256")
                })
                .filter_map(|row| {
                    row.get("public_jwk")
                        .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
                })
                .collect::<Vec<_>>();
            ok(json!({"keys": keys}))
        }
        Ok(SelectResult::Aggregate(_)) => ok(json!({"keys": []})),
        Err(e) => error(400, "Bad Request", &e),
    }
}

fn admin_list_users(store: &Store, cache: &SharedSchemaCache) -> (u16, &'static str, String) {
    let plan = SelectPlan {
        table: USERS_TABLE.to_string(),
        alias: None,
        projections: Vec::new(),
        aggregates: Vec::new(),
        joins: Vec::new(),
        conditions: Vec::new(),
        group_by: Vec::new(),
        having: Vec::new(),
        near: None,
        order_by: None,
        limit: Some(1000),
        offset: None,
        decrypt_authorized: true,
    };
    match tables::table_select(store, cache, &plan, Instant::now()) {
        Ok(SelectResult::Rows(rows)) => {
            let users: Vec<Value> = rows.into_iter().map(user_row_json).collect();
            ok(json!({"users": users}))
        }
        Ok(SelectResult::Aggregate(_)) => ok(json!({"users": []})),
        Err(e) => error(400, "Bad Request", &e),
    }
}

fn admin_create_user(
    body: &str,
    store: &Store,
    cache: &SharedSchemaCache,
) -> (u16, &'static str, String) {
    let parsed = match parse_json(body) {
        Ok(parsed) => parsed,
        Err(response) => return response,
    };
    let email = match required_string(&parsed, "email") {
        Ok(email) => normalize_email(email),
        Err(response) => return response,
    };
    let now = Instant::now();
    if find_row_by_field(store, cache, USERS_TABLE, "email", &email, now)
        .ok()
        .flatten()
        .is_some()
    {
        return error(409, "Conflict", "user already exists");
    }

    let user_id = parsed
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.trim().is_empty())
        .map(str::to_string)
        .unwrap_or_else(tables::generate_uuid_v7);
    let password_hash = match admin_password_hash(&parsed) {
        Ok(hash) => hash,
        Err(response) => return response,
    };
    let now_sec = unix_seconds();
    let now_sec_str = now_sec.to_string();
    let email_confirmed_at = admin_confirmed_at(&parsed, "email_confirmed_at", "email_confirmed")
        .unwrap_or_else(|| now_sec.to_string());
    let phone = optional_json_string(&parsed, "phone");
    let phone_confirmed_at =
        admin_confirmed_at(&parsed, "phone_confirmed_at", "phone_confirmed").unwrap_or_default();
    let user_meta = parsed
        .get("user_metadata")
        .or_else(|| parsed.get("data"))
        .cloned()
        .unwrap_or_else(|| json!({}))
        .to_string();
    let app_meta = parsed
        .get("app_metadata")
        .cloned()
        .unwrap_or_else(|| json!({"provider":"email","providers":["email"]}))
        .to_string();
    let banned_until = optional_json_string(&parsed, "banned_until");

    let mut fields = vec![
        ("id", user_id.as_str()),
        ("email", email.as_str()),
        ("raw_user_meta_data", user_meta.as_str()),
        ("raw_app_meta_data", app_meta.as_str()),
        ("created_at", now_sec_str.as_str()),
        ("updated_at", now_sec_str.as_str()),
    ];
    if !email_confirmed_at.is_empty() {
        fields.push(("email_confirmed_at", email_confirmed_at.as_str()));
    }
    if let Some(password_hash) = password_hash.as_deref() {
        fields.push(("encrypted_password", password_hash));
    }
    if let Some(phone) = phone.as_deref() {
        fields.push(("phone", phone));
    }
    if !phone_confirmed_at.is_empty() {
        fields.push(("phone_confirmed_at", phone_confirmed_at.as_str()));
    }
    if let Some(banned_until) = banned_until.as_deref() {
        fields.push(("banned_until", banned_until));
    }

    if let Err(e) = durable_table_insert(store, cache, USERS_TABLE, &fields, now) {
        return error(400, "Bad Request", &e);
    }
    if let Err(e) = durable_table_insert(
        store,
        cache,
        IDENTITIES_TABLE,
        &[
            ("id", random_id("idn").as_str()),
            ("user_id", user_id.as_str()),
            ("provider", "email"),
            ("provider_id", email.as_str()),
            ("identity_data", json!({"email":email}).to_string().as_str()),
            ("created_at", now_sec_str.as_str()),
            ("updated_at", now_sec_str.as_str()),
        ],
        now,
    ) {
        let _ = durable_table_delete_where(store, cache, USERS_TABLE, &["id", "=", &user_id], now);
        return error(400, "Bad Request", &e);
    }

    ok(
        json!({"user": user_json(store, cache, &user_id, now).unwrap_or_else(|| json!({"id":user_id,"email":email}))}),
    )
}

fn admin_get_user(
    user_id: &str,
    store: &Store,
    cache: &SharedSchemaCache,
) -> (u16, &'static str, String) {
    match user_json(store, cache, user_id, Instant::now()) {
        Some(user) => ok(json!({"user": user})),
        None => error(404, "Not Found", "user not found"),
    }
}

fn admin_update_user(
    user_id: &str,
    body: &str,
    store: &Store,
    cache: &SharedSchemaCache,
) -> (u16, &'static str, String) {
    let parsed = match parse_json(body) {
        Ok(parsed) => parsed,
        Err(response) => return response,
    };
    let now = Instant::now();
    let Some(existing) = find_row_by_field(store, cache, USERS_TABLE, "id", user_id, now)
        .ok()
        .flatten()
    else {
        return error(404, "Not Found", "user not found");
    };

    let mut updates: Vec<(String, String)> = Vec::new();
    let mut new_email = None;
    if let Some(email) = parsed.get("email").and_then(Value::as_str) {
        let email = normalize_email(email);
        if email.is_empty() {
            return error(400, "Bad Request", "email cannot be empty");
        }
        if existing.get("email").map(String::as_str) != Some(email.as_str()) {
            if let Some(row) = find_row_by_field(store, cache, USERS_TABLE, "email", &email, now)
                .ok()
                .flatten()
            {
                if row.get("id").map(String::as_str) != Some(user_id) {
                    return error(409, "Conflict", "user already exists");
                }
            }
        }
        updates.push(("email".to_string(), email.clone()));
        new_email = Some(email);
    }
    if let Some(phone) = optional_json_string(&parsed, "phone") {
        updates.push(("phone".to_string(), phone));
    }
    match admin_password_hash(&parsed) {
        Ok(Some(hash)) => updates.push(("encrypted_password".to_string(), hash)),
        Ok(None) => {}
        Err(response) => return response,
    }
    if let Some(value) = parsed.get("user_metadata").or_else(|| parsed.get("data")) {
        updates.push(("raw_user_meta_data".to_string(), value.clone().to_string()));
    }
    if let Some(value) = parsed.get("app_metadata") {
        updates.push(("raw_app_meta_data".to_string(), value.clone().to_string()));
    }
    if let Some(value) = admin_confirmed_at(&parsed, "email_confirmed_at", "email_confirmed") {
        updates.push(("email_confirmed_at".to_string(), value));
    }
    if let Some(value) = admin_confirmed_at(&parsed, "phone_confirmed_at", "phone_confirmed") {
        updates.push(("phone_confirmed_at".to_string(), value));
    }
    if let Some(value) = optional_json_string(&parsed, "banned_until") {
        updates.push(("banned_until".to_string(), value));
    }
    if let Some(value) = optional_json_string(&parsed, "deleted_at") {
        updates.push(("deleted_at".to_string(), value));
    }
    let now_sec = unix_seconds().to_string();
    updates.push(("updated_at".to_string(), now_sec.clone()));

    let refs: Vec<(&str, &str)> = updates
        .iter()
        .map(|(field, value)| (field.as_str(), value.as_str()))
        .collect();
    if let Err(e) =
        durable_table_update_where(store, cache, USERS_TABLE, &refs, &["id", "=", user_id], now)
    {
        return error(400, "Bad Request", &e);
    }
    if let Some(email) = new_email {
        let identity_data = json!({"email":email}).to_string();
        let _ = durable_table_update_where(
            store,
            cache,
            IDENTITIES_TABLE,
            &[
                ("provider_id", email.as_str()),
                ("identity_data", identity_data.as_str()),
                ("updated_at", now_sec.as_str()),
            ],
            &["user_id", "=", user_id],
            now,
        );
    }

    match user_json(store, cache, user_id, now) {
        Some(user) => ok(json!({"user": user})),
        None => error(404, "Not Found", "user not found"),
    }
}

fn admin_delete_user(
    user_id: &str,
    store: &Store,
    cache: &SharedSchemaCache,
) -> (u16, &'static str, String) {
    let now = Instant::now();
    let Some(user) = user_json(store, cache, user_id, now) else {
        return error(404, "Not Found", "user not found");
    };
    if let Err(e) = durable_table_delete_where(
        store,
        cache,
        IDENTITIES_TABLE,
        &["user_id", "=", user_id],
        now,
    ) {
        return error(400, "Bad Request", &e);
    }
    if let Err(e) = durable_table_delete_where(
        store,
        cache,
        SESSIONS_TABLE,
        &["user_id", "=", user_id],
        now,
    ) {
        return error(400, "Bad Request", &e);
    }
    match durable_table_delete_where(store, cache, USERS_TABLE, &["id", "=", user_id], now) {
        Ok(0) => error(404, "Not Found", "user not found"),
        Ok(_) => ok(json!({"user": user})),
        Err(e) => error(400, "Bad Request", &e),
    }
}

fn admin_password_hash(parsed: &Value) -> Result<Option<String>, (u16, &'static str, String)> {
    if let Some(hash) = parsed
        .get("encrypted_password")
        .and_then(Value::as_str)
        .filter(|hash| !hash.is_empty())
    {
        return Ok(Some(hash.to_string()));
    }
    if let Some(password) = parsed
        .get("password")
        .and_then(Value::as_str)
        .filter(|password| !password.is_empty())
    {
        if password.len() < 8 {
            return Err(error(
                400,
                "Bad Request",
                "password must be at least 8 characters",
            ));
        }
        return hash_password(password)
            .map(Some)
            .map_err(|e| error(500, "Internal Server Error", &e));
    }
    Ok(None)
}

fn admin_confirmed_at(parsed: &Value, timestamp_field: &str, bool_field: &str) -> Option<String> {
    if let Some(value) = parsed.get(timestamp_field) {
        return json_scalar_to_string(value);
    }
    parsed
        .get(bool_field)
        .and_then(Value::as_bool)
        .map(|confirmed| {
            if confirmed {
                unix_seconds().to_string()
            } else {
                String::new()
            }
        })
}

fn optional_json_string(parsed: &Value, field: &str) -> Option<String> {
    parsed.get(field).and_then(json_scalar_to_string)
}

fn json_scalar_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Null => Some(String::new()),
        _ => None,
    }
}

fn admin_list_providers(store: &Store, cache: &SharedSchemaCache) -> (u16, &'static str, String) {
    let plan = SelectPlan {
        table: PROVIDERS_TABLE.to_string(),
        alias: None,
        projections: Vec::new(),
        aggregates: Vec::new(),
        joins: Vec::new(),
        conditions: Vec::new(),
        group_by: Vec::new(),
        having: Vec::new(),
        near: None,
        order_by: None,
        limit: Some(100),
        offset: None,
        decrypt_authorized: true,
    };
    match tables::table_select(store, cache, &plan, Instant::now()) {
        Ok(SelectResult::Rows(rows)) => {
            let providers: Vec<Value> = rows.into_iter().map(provider_row_json).collect();
            ok(json!({
                "providers": providers,
                "capabilities": {"apple_native": true, "apple_web": true},
            }))
        }
        Ok(SelectResult::Aggregate(_)) => ok(json!({
            "providers": [],
            "capabilities": {"apple_native": true, "apple_web": true},
        })),
        Err(e) => error(400, "Bad Request", &e),
    }
}

fn admin_get_settings(store: &Store, cache: &SharedSchemaCache) -> (u16, &'static str, String) {
    match auth_settings(store, cache, Instant::now()) {
        Ok(settings) => ok(
            json!({"settings": auth_settings_json(&settings, store.config().auth.managed_email.as_ref())}),
        ),
        Err(e) => error(400, "Bad Request", &e),
    }
}

fn admin_update_settings(
    body: &str,
    store: &Store,
    cache: &SharedSchemaCache,
) -> (u16, &'static str, String) {
    let parsed = match parse_json(body) {
        Ok(parsed) => parsed,
        Err(response) => return response,
    };
    let Some(object) = parsed.as_object() else {
        return error(400, "Bad Request", "settings payload must be an object");
    };
    let now = Instant::now();
    let managed_email = store.config().auth.managed_email.as_ref();
    if managed_email.is_some()
        && [
            "email_provider",
            "email_from",
            "email_reply_to",
            "email_postmark_server_token",
            "email_postmark_message_stream",
        ]
        .iter()
        .any(|field| object.contains_key(*field))
    {
        return error(
            400,
            "Bad Request",
            "managed email delivery settings cannot be changed on this project",
        );
    }

    if let Some(value) = object.get("email_confirmation_required") {
        let Some(enabled) = value.as_bool() else {
            return error(
                400,
                "Bad Request",
                "email_confirmation_required must be a boolean",
            );
        };
        if let Err(e) = set_auth_setting(
            store,
            cache,
            "email_confirmation_required",
            if enabled { "true" } else { "false" },
            now,
        ) {
            return error(400, "Bad Request", &e);
        }
    }

    if let Some(value) = object.get("flow_token_ttl_seconds") {
        let Some(ttl) = value.as_u64() else {
            return error(
                400,
                "Bad Request",
                "flow_token_ttl_seconds must be a positive integer",
            );
        };
        if ttl == 0 {
            return error(
                400,
                "Bad Request",
                "flow_token_ttl_seconds must be greater than zero",
            );
        }
        if let Err(e) = set_auth_setting(
            store,
            cache,
            "flow_token_ttl_seconds",
            &ttl.to_string(),
            now,
        ) {
            return error(400, "Bad Request", &e);
        }
    }

    if let Some(value) = object.get("site_url") {
        let Some(site_url) = value.as_str().map(str::trim).filter(|url| !url.is_empty()) else {
            return error(400, "Bad Request", "site_url must be a non-empty string");
        };
        if let Err(e) = set_auth_setting(store, cache, "site_url", site_url, now) {
            return error(400, "Bad Request", &e);
        }
    }

    if let Some(value) = object.get("redirect_allow_list") {
        let allow_list = match optional_string_list_setting(value) {
            Some(values) => values,
            None => {
                return error(
                    400,
                    "Bad Request",
                    "redirect_allow_list must be an array, string, or null",
                )
            }
        };
        if let Err(e) = set_auth_setting(
            store,
            cache,
            "redirect_allow_list",
            &allow_list.join("\n"),
            now,
        ) {
            return error(400, "Bad Request", &e);
        }
    }

    if let Some(value) = object.get("email_provider") {
        let Some(provider) = value.as_str().map(str::trim).filter(|v| !v.is_empty()) else {
            return error(
                400,
                "Bad Request",
                "email_provider must be a non-empty string",
            );
        };
        let provider = provider.to_ascii_lowercase();
        if !matches!(provider.as_str(), "console" | "log" | "postmark") {
            return error(400, "Bad Request", "unsupported email_provider");
        }
        let provider = if provider == "log" {
            "console".to_string()
        } else {
            provider
        };
        if let Err(e) = set_auth_setting(store, cache, "email_provider", &provider, now) {
            return error(400, "Bad Request", &e);
        }
    }

    for field in [
        "email_from",
        "email_reply_to",
        "email_postmark_server_token",
        "email_postmark_message_stream",
        "email_app_name",
        "email_from_name",
    ] {
        if let Some(value) = object.get(field) {
            let Some(value) = optional_setting_string(value) else {
                return error(
                    400,
                    "Bad Request",
                    &format!("{field} must be a string or null"),
                );
            };
            if let Err(e) = set_auth_setting(store, cache, field, &value, now) {
                return error(400, "Bad Request", &e);
            }
        }
    }

    admin_get_settings(store, cache)
}

fn admin_upsert_provider(
    provider: &str,
    body: &str,
    store: &Store,
    cache: &SharedSchemaCache,
) -> (u16, &'static str, String) {
    let provider = match normalize_oauth_provider(provider) {
        Ok(provider) => provider,
        Err(response) => return response,
    };
    let parsed = match parse_json(body) {
        Ok(parsed) => parsed,
        Err(response) => return response,
    };
    if provider == "apple" {
        return admin_upsert_apple_provider(&parsed, store, cache);
    }
    let client_id = match required_string(&parsed, "client_id") {
        Ok(client_id) => client_id.trim(),
        Err(response) => return response,
    };
    let client_secret = parsed
        .get("client_secret")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    let redirect_uri = match required_string(&parsed, "redirect_uri") {
        Ok(redirect_uri) => redirect_uri.trim(),
        Err(response) => return response,
    };
    let enabled = parsed
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(true)
        .to_string();
    let scopes = parsed
        .get("scopes")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|scopes| !scopes.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| default_oauth_scopes(&provider).to_string());

    let now = Instant::now();
    let now_sec = unix_seconds().to_string();
    match find_row_by_field(store, cache, PROVIDERS_TABLE, "provider", &provider, now) {
        Ok(Some(existing)) => {
            let secret = if client_secret.is_empty() {
                existing
                    .get("client_secret")
                    .map(String::as_str)
                    .unwrap_or("")
                    .to_string()
            } else {
                match secrets::seal(
                    store,
                    PROVIDERS_TABLE,
                    "client_secret",
                    &provider,
                    client_secret,
                ) {
                    Ok(secret) => secret,
                    Err(message) => return error(400, "Bad Request", &message),
                }
            };
            match durable_table_update_where(
                store,
                cache,
                PROVIDERS_TABLE,
                &[
                    ("enabled", enabled.as_str()),
                    ("client_id", client_id),
                    ("client_secret", secret.as_str()),
                    ("redirect_uri", redirect_uri),
                    ("scopes", scopes.as_str()),
                    ("updated_at", now_sec.as_str()),
                ],
                &["provider", "=", &provider],
                now,
            ) {
                Ok(_) => match oauth_provider_config(store, cache, &provider, now) {
                    Ok(Some(config)) => ok(json!({"provider": provider_config_json(&config)})),
                    Ok(None) => error(404, "Not Found", "provider not found"),
                    Err(e) => error(400, "Bad Request", &e),
                },
                Err(e) => error(400, "Bad Request", &e),
            }
        }
        Ok(None) => {
            if client_secret.is_empty() {
                return error(400, "Bad Request", "missing client_secret");
            }
            let client_secret = match secrets::seal(
                store,
                PROVIDERS_TABLE,
                "client_secret",
                &provider,
                client_secret,
            ) {
                Ok(secret) => secret,
                Err(message) => return error(400, "Bad Request", &message),
            };
            match durable_table_insert(
                store,
                cache,
                PROVIDERS_TABLE,
                &[
                    ("provider", provider.as_str()),
                    ("enabled", enabled.as_str()),
                    ("client_id", client_id),
                    ("client_secret", client_secret.as_str()),
                    ("redirect_uri", redirect_uri),
                    ("scopes", scopes.as_str()),
                    ("created_at", now_sec.as_str()),
                    ("updated_at", now_sec.as_str()),
                ],
                now,
            ) {
                Ok(_) => match oauth_provider_config(store, cache, &provider, now) {
                    Ok(Some(config)) => ok(json!({"provider": provider_config_json(&config)})),
                    Ok(None) => error(404, "Not Found", "provider not found"),
                    Err(e) => error(400, "Bad Request", &e),
                },
                Err(e) => error(400, "Bad Request", &e),
            }
        }
        Err(e) => error(400, "Bad Request", &e),
    }
}

fn oauth_authorize(
    params: &[(String, String)],
    headers: &[(String, String)],
    store: &Store,
    cache: &SharedSchemaCache,
) -> AuthHttpResponse {
    let provider = match get_param(params, "provider") {
        Some(provider) => match normalize_oauth_provider(provider) {
            Ok(provider) => provider,
            Err((status, status_text, body)) => {
                return AuthHttpResponse::json(status, status_text, body)
            }
        },
        None => {
            let (status, status_text, body) = error(400, "Bad Request", "missing provider");
            return AuthHttpResponse::json(status, status_text, body);
        }
    };
    let redirect_to = get_param(params, "redirect_to")
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("/");
    let settings = match auth_settings(store, cache, Instant::now()) {
        Ok(settings) => settings,
        Err(e) => {
            let (status, status_text, body) = error(400, "Bad Request", &e);
            return AuthHttpResponse::json(status, status_text, body);
        }
    };
    let redirect_to = match validate_auth_redirect(redirect_to, &settings) {
        Ok(redirect_to) => redirect_to,
        Err(e) => {
            let (status, status_text, body) = error(400, "Bad Request", &e);
            return AuthHttpResponse::json(status, status_text, body);
        }
    };
    let flow = get_param(params, "flow").unwrap_or("code");
    if !matches!(flow, "code" | "implicit") {
        let (status, status_text, body) = error(400, "Bad Request", "unsupported oauth flow");
        return AuthHttpResponse::json(status, status_text, body);
    }
    let code_challenge = match oauth_pkce_challenge(params) {
        Ok(challenge) => challenge,
        Err(response) => {
            let (status, status_text, body) = response;
            return AuthHttpResponse::json(status, status_text, body);
        }
    };
    let is_custom_scheme = !redirect_to.starts_with('/') && url_origin(&redirect_to).is_none();
    if flow == "code" && is_custom_scheme && code_challenge.is_none() {
        let (status, status_text, body) = error(
            400,
            "Bad Request",
            "custom-scheme oauth code flows require PKCE",
        );
        return AuthHttpResponse::json(status, status_text, body);
    }
    let config = match oauth_provider_config(store, cache, &provider, Instant::now()) {
        Ok(Some(config)) if config.enabled => config,
        Ok(Some(_)) => {
            let (status, status_text, body) = error(400, "Bad Request", "provider is disabled");
            return AuthHttpResponse::json(status, status_text, body);
        }
        Ok(None) => {
            let (status, status_text, body) = error(404, "Not Found", "provider not configured");
            return AuthHttpResponse::json(status, status_text, body);
        }
        Err(e) => {
            let (status, status_text, body) = error(400, "Bad Request", &e);
            return AuthHttpResponse::json(status, status_text, body);
        }
    };
    if provider == "apple" && mint_apple_client_secret(&config).is_err() {
        let (status, status_text, body) =
            error(400, "Bad Request", "apple web sign-in is not configured");
        return AuthHttpResponse::json(status, status_text, body);
    }
    let state = random_token(32);
    let oidc_nonce = random_token(32);
    let state_key = oauth_state_key(&state);
    let payload = json!({
        "provider": provider,
        "redirect_to": redirect_to,
        "flow": flow,
        "code_challenge": code_challenge,
        "oidc_nonce": oidc_nonce,
        "created_at": unix_seconds(),
    });
    let payload = payload.to_string();
    if let Err(e) = persist_oauth_state(store, state_key.as_bytes(), payload.as_bytes()) {
        let (status, status_text, body) = error(500, "Internal Server Error", &e);
        return AuthHttpResponse::json(status, status_text, body);
    }

    let callback = if config.redirect_uri.is_empty() {
        default_callback_url(headers, &provider)
    } else {
        config.redirect_uri.clone()
    };
    let url = oauth_authorization_url(&config, &callback, &state, &oidc_nonce);
    AuthHttpResponse::redirect(url)
}

async fn oauth_callback(
    provider: &str,
    params: &[(String, String)],
    headers: &[(String, String)],
    store: &Store,
    cache: &SharedSchemaCache,
) -> AuthHttpResponse {
    let provider = match normalize_oauth_provider(provider) {
        Ok(provider) => provider,
        Err((status, status_text, body)) => {
            return AuthHttpResponse::json(status, status_text, body)
        }
    };
    let state = match get_param(params, "state") {
        Some(state) if !state.is_empty() => state,
        _ => {
            let (status, status_text, body) = error(400, "Bad Request", "missing state");
            return AuthHttpResponse::json(status, status_text, body);
        }
    };
    let state_key = oauth_state_key(state);
    let raw_state = match take_oauth_state(store, state_key.as_bytes(), Instant::now()) {
        Ok(Some(raw_state)) => raw_state,
        Ok(None) => {
            let (status, status_text, body) = error(400, "Bad Request", "invalid oauth state");
            return AuthHttpResponse::json(status, status_text, body);
        }
        Err(e) => {
            let (status, status_text, body) = error(500, "Internal Server Error", &e);
            return AuthHttpResponse::json(status, status_text, body);
        }
    };
    let state_value: Value = serde_json::from_slice(&raw_state).unwrap_or_else(|_| json!({}));
    if state_value.get("provider").and_then(Value::as_str) != Some(provider.as_str()) {
        let (status, status_text, body) =
            error(400, "Bad Request", "oauth state provider mismatch");
        return AuthHttpResponse::json(status, status_text, body);
    }
    let redirect_to = state_value
        .get("redirect_to")
        .and_then(Value::as_str)
        .unwrap_or("/");
    let redirect_to = sanitize_header_value(redirect_to);
    if let Some(oauth_error) = get_param(params, "error") {
        return AuthHttpResponse::redirect(oauth_error_url(&redirect_to, oauth_error));
    }
    let code = match get_param(params, "code") {
        Some(code) if !code.is_empty() => code,
        _ => {
            let (status, status_text, body) = error(400, "Bad Request", "missing code");
            return AuthHttpResponse::json(status, status_text, body);
        }
    };
    let config = match oauth_provider_config(store, cache, &provider, Instant::now()) {
        Ok(Some(config)) if config.enabled => config,
        Ok(Some(_)) => {
            return AuthHttpResponse::redirect(oauth_error_url(&redirect_to, "provider_disabled"))
        }
        Ok(None) => {
            return AuthHttpResponse::redirect(oauth_error_url(
                &redirect_to,
                "provider_not_configured",
            ))
        }
        Err(_) => {
            return AuthHttpResponse::redirect(oauth_error_url(
                &redirect_to,
                "provider_config_error",
            ))
        }
    };
    let callback = if config.redirect_uri.is_empty() {
        default_callback_url(headers, &provider)
    } else {
        config.redirect_uri.clone()
    };
    let oidc_nonce = state_value
        .get("oidc_nonce")
        .and_then(Value::as_str)
        .unwrap_or("");
    let apple_name = if provider == "apple" {
        get_param(params, "user").and_then(parse_apple_callback_name)
    } else {
        None
    };
    let oauth_user = match exchange_oauth_code(
        &config,
        code,
        &callback,
        (!oidc_nonce.is_empty()).then_some(oidc_nonce),
        apple_name,
    )
    .await
    {
        Ok(user) => user,
        Err(e) => return AuthHttpResponse::redirect(oauth_error_url(&redirect_to, &e)),
    };
    let flow = state_value
        .get("flow")
        .and_then(Value::as_str)
        .unwrap_or("code");
    match oauth_resolve_user(&oauth_user, store, cache) {
        Ok(subject) if flow == "implicit" => {
            match issue_session_response(
                store,
                cache,
                headers,
                &subject.user_id,
                &subject.email,
                Instant::now(),
            ) {
                (200, _, body) => match serde_json::from_str::<Value>(&body) {
                    Ok(session) => {
                        AuthHttpResponse::redirect(oauth_success_url(&redirect_to, &session))
                    }
                    Err(_) => {
                        AuthHttpResponse::redirect(oauth_error_url(&redirect_to, "invalid_session"))
                    }
                },
                (_, _, body) => AuthHttpResponse::redirect(oauth_error_url(
                    &redirect_to,
                    &json_error_message(&body)
                        .unwrap_or_else(|| "oauth_sign_in_failed".to_string()),
                )),
            }
        }
        Ok(subject) => {
            let now = Instant::now();
            let settings = match auth_settings(store, cache, now) {
                Ok(settings) => settings,
                Err(_) => {
                    return AuthHttpResponse::redirect(oauth_error_url(
                        &redirect_to,
                        "invalid_session",
                    ))
                }
            };
            match create_flow_token(
                store,
                cache,
                FlowTokenInsert {
                    settings: &settings,
                    kind: "oauth_code",
                    user_id: &subject.user_id,
                    email: &subject.email,
                    redirect_to: &redirect_to,
                    metadata: json!({
                        "code_challenge": state_value
                            .get("code_challenge")
                            .cloned()
                            .unwrap_or(Value::Null),
                    }),
                },
                now,
            ) {
                Ok(code) => AuthHttpResponse::redirect(oauth_code_url(&redirect_to, &code)),
                Err(_) => {
                    AuthHttpResponse::redirect(oauth_error_url(&redirect_to, "invalid_session"))
                }
            }
        }
        Err((_, _, body)) => AuthHttpResponse::redirect(oauth_error_url(
            &redirect_to,
            &json_error_message(&body).unwrap_or_else(|| "oauth_sign_in_failed".to_string()),
        )),
    }
}

#[derive(Clone, Debug)]
struct AuthSessionSubject {
    user_id: String,
    email: String,
}

#[cfg(test)]
fn oauth_sign_in(
    oauth_user: &OAuthUser,
    headers: &[(String, String)],
    store: &Store,
    cache: &SharedSchemaCache,
) -> (u16, &'static str, String) {
    match oauth_resolve_user(oauth_user, store, cache) {
        Ok(subject) => issue_session_response(
            store,
            cache,
            headers,
            &subject.user_id,
            &subject.email,
            Instant::now(),
        ),
        Err(response) => response,
    }
}

fn oauth_resolve_user(
    oauth_user: &OAuthUser,
    store: &Store,
    cache: &SharedSchemaCache,
) -> Result<AuthSessionSubject, (u16, &'static str, String)> {
    let provider = oauth_user.provider.as_str();
    let provider_user_id = oauth_user.provider_id.as_str();
    let email = normalize_email(&oauth_user.email);
    let email_confirmed = oauth_user.email_verified;
    let user_meta = oauth_user.user_metadata.clone();
    let identity_data = oauth_user.identity_data.clone();
    let stored_provider_id = oauth_provider_id(provider, provider_user_id);

    let now = Instant::now();
    if let Some(identity) = match find_row_by_field(
        store,
        cache,
        IDENTITIES_TABLE,
        "provider_id",
        &stored_provider_id,
        now,
    ) {
        Ok(identity) => identity,
        Err(e) => return Err(error(400, "Bad Request", &e)),
    } {
        let Some(user_id) = identity.get("user_id") else {
            return Err(error(
                500,
                "Internal Server Error",
                "identity row is missing user_id",
            ));
        };
        let Some(user) = (match find_row_by_field(store, cache, USERS_TABLE, "id", user_id, now) {
            Ok(user) => user,
            Err(e) => return Err(error(400, "Bad Request", &e)),
        }) else {
            return Err(error(401, "Unauthorized", "user not found"));
        };
        validate_user_active(&user, unix_seconds())?;
        let user_email = user.get("email").cloned().unwrap_or_else(|| email.clone());
        let now_sec = unix_seconds().to_string();
        let merged_app_meta =
            app_metadata_with_provider(user.get("raw_app_meta_data").map(String::as_str), provider);
        let _ = durable_table_update_where(
            store,
            cache,
            USERS_TABLE,
            &[
                ("raw_app_meta_data", merged_app_meta.as_str()),
                ("updated_at", now_sec.as_str()),
            ],
            &["id", "=", user_id],
            now,
        );
        let identity_payload =
            oauth_identity_data(provider, provider_user_id, &email, identity_data);
        let _ = durable_table_update_where(
            store,
            cache,
            IDENTITIES_TABLE,
            &[
                ("identity_data", identity_payload.as_str()),
                ("updated_at", now_sec.as_str()),
            ],
            &[
                "id",
                "=",
                identity.get("id").map(String::as_str).unwrap_or(""),
            ],
            now,
        );
        return Ok(AuthSessionSubject {
            user_id: user_id.to_string(),
            email: user_email,
        });
    }

    if email.is_empty() {
        return Err(error(
            400,
            "Bad Request",
            "verified email is required for a new oauth identity",
        ));
    }
    if !email_confirmed {
        return Err(error(
            400,
            "Bad Request",
            "verified email is required for oauth account linking",
        ));
    }

    let now_sec = unix_seconds();
    let existing_user = match find_row_by_field(store, cache, USERS_TABLE, "email", &email, now) {
        Ok(user) => user,
        Err(e) => return Err(error(400, "Bad Request", &e)),
    };
    let (user_id, created_user) = if let Some(user) = existing_user {
        let Some(user_id) = user.get("id").cloned() else {
            return Err(error(
                500,
                "Internal Server Error",
                "auth user row is missing id",
            ));
        };
        let merged_app_meta =
            app_metadata_with_provider(user.get("raw_app_meta_data").map(String::as_str), provider);
        if let Err(e) = durable_table_update_where(
            store,
            cache,
            USERS_TABLE,
            &[
                ("raw_app_meta_data", merged_app_meta.as_str()),
                ("updated_at", &now_sec.to_string()),
            ],
            &["id", "=", &user_id],
            now,
        ) {
            return Err(error(400, "Bad Request", &e));
        }
        (user_id, false)
    } else {
        let user_id = tables::generate_uuid_v7();
        let user_meta = user_meta.to_string();
        let app_meta = app_metadata_with_provider(None, provider);
        let now_sec_str = now_sec.to_string();
        let mut fields = vec![
            ("id", user_id.as_str()),
            ("email", email.as_str()),
            ("raw_user_meta_data", user_meta.as_str()),
            ("raw_app_meta_data", app_meta.as_str()),
            ("created_at", now_sec_str.as_str()),
            ("updated_at", now_sec_str.as_str()),
        ];
        if email_confirmed {
            fields.push(("email_confirmed_at", now_sec_str.as_str()));
        }
        if let Err(e) = durable_table_insert(store, cache, USERS_TABLE, &fields, now) {
            return Err(error(400, "Bad Request", &e));
        }
        (user_id, true)
    };

    let identity_payload = oauth_identity_data(provider, provider_user_id, &email, identity_data);
    if let Err(e) = durable_table_insert(
        store,
        cache,
        IDENTITIES_TABLE,
        &[
            ("id", random_id("idn").as_str()),
            ("user_id", user_id.as_str()),
            ("provider", provider),
            ("provider_id", stored_provider_id.as_str()),
            ("identity_data", identity_payload.as_str()),
            ("created_at", &now_sec.to_string()),
            ("updated_at", &now_sec.to_string()),
        ],
        now,
    ) {
        if created_user {
            let _ =
                durable_table_delete_where(store, cache, USERS_TABLE, &["id", "=", &user_id], now);
        }
        return Err(error(400, "Bad Request", &e));
    }

    Ok(AuthSessionSubject { user_id, email })
}

fn admin_list_keys(store: &Store, cache: &SharedSchemaCache) -> (u16, &'static str, String) {
    let plan = SelectPlan {
        table: KEYS_TABLE.to_string(),
        alias: None,
        projections: Vec::new(),
        aggregates: Vec::new(),
        joins: Vec::new(),
        conditions: Vec::new(),
        group_by: Vec::new(),
        having: Vec::new(),
        near: None,
        order_by: None,
        limit: Some(1000),
        offset: None,
        decrypt_authorized: true,
    };
    match tables::table_select(store, cache, &plan, Instant::now()) {
        Ok(SelectResult::Rows(rows)) => {
            let keys: Vec<Value> = rows.into_iter().map(key_row_json).collect();
            ok(json!({"keys": keys}))
        }
        Ok(SelectResult::Aggregate(_)) => ok(json!({"keys": []})),
        Err(e) => error(400, "Bad Request", &e),
    }
}

fn admin_create_key(
    body: &str,
    store: &Store,
    cache: &SharedSchemaCache,
) -> (u16, &'static str, String) {
    let parsed = match parse_json(body) {
        Ok(parsed) => parsed,
        Err(response) => return response,
    };
    let kind = match required_string(&parsed, "kind") {
        Ok("publishable") => ApiKeyKind::Publishable,
        Ok("secret") => ApiKeyKind::Secret,
        Ok(_) => return error(400, "Bad Request", "kind must be publishable or secret"),
        Err(response) => return response,
    };
    let name = parsed
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.trim().is_empty())
        .unwrap_or(match kind {
            ApiKeyKind::Publishable => "publishable",
            ApiKeyKind::Secret => "secret",
        });
    let raw_key = match kind {
        ApiKeyKind::Publishable => format!("lux_pub_{}", random_token(24)),
        ApiKeyKind::Secret => format!("lux_sec_{}", random_token(32)),
    };
    match insert_api_key(store, cache, &raw_key, kind, name, Instant::now()) {
        Ok(key) => ok(json!({"key": key, "plain_key": raw_key})),
        Err(e) => error(400, "Bad Request", &e),
    }
}

fn admin_revoke_key(
    key_id: &str,
    store: &Store,
    cache: &SharedSchemaCache,
) -> (u16, &'static str, String) {
    let now = Instant::now();
    let now_sec = unix_seconds().to_string();
    match durable_table_update_where(
        store,
        cache,
        KEYS_TABLE,
        &[
            ("revoked_at", now_sec.as_str()),
            ("last_used_at", now_sec.as_str()),
        ],
        &["id", "=", key_id],
        now,
    ) {
        Ok(0) => error(404, "Not Found", "key not found"),
        Ok(_) => {
            // Revocation must take effect now, not when the cache entry ages out.
            invalidate_api_key_cache(store);
            ok(json!({"result":"OK"}))
        }
        Err(e) => error(400, "Bad Request", &e),
    }
}

pub(crate) fn create_table_if_missing(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    columns: &[&str],
    now: Instant,
) -> Result<(), String> {
    match tables::table_schema(store, cache, table, now) {
        Ok(_) => Ok(()),
        Err(error) if error == format!("ERR table '{table}' does not exist") => {
            tables::table_create(store, cache, table, columns, now)
        }
        Err(error) => Err(format!("ERR could not inspect table '{table}': {error}")),
    }
}

/// Add a column to an existing internal table if it isn't there already. The
/// companion to `create_table_if_missing` for schema that arrives after a table
/// has already shipped: new projects pick the column up from the CREATE, and
/// projects created before it get it from here.
///
/// `table_add_column` owns the journal-before-apply boundary so this path and
/// the public command path share one authoritative recovery record.
pub(crate) fn add_column_if_missing(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    field_spec: &str,
    now: Instant,
) -> Result<(), String> {
    let mut tokens = field_spec.split_whitespace();
    let Some(column) = tokens.next() else {
        return Err("ERR empty column spec".to_string());
    };
    let schema = tables::table_schema(store, cache, table, now)?;
    if schema
        .iter()
        .any(|field| field.split_whitespace().next() == Some(column))
    {
        return Ok(());
    }

    tables::table_add_column(store, cache, table, field_spec, now)
}

pub(crate) fn durable_table_insert(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    field_values: &[(&str, &str)],
    now: Instant,
) -> Result<i64, String> {
    tables::table_insert(store, cache, table, field_values, now)
}

pub(crate) fn durable_table_update_where(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    field_values: &[(&str, &str)],
    where_args: &[&str],
    now: Instant,
) -> Result<i64, String> {
    tables::table_update_where(store, cache, table, field_values, where_args, now)
}

pub(crate) fn durable_table_delete_where(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    where_args: &[&str],
    now: Instant,
) -> Result<i64, String> {
    tables::table_delete_where(store, cache, table, where_args, now)
}

fn ensure_signing_key(
    store: &Store,
    cache: &SharedSchemaCache,
    now: Instant,
) -> Result<(), String> {
    if active_signing_key(store, cache, now)?.is_some() {
        return Ok(());
    }
    let key = generate_es256_signing_key()?;
    let id = random_id("sgn");
    let private_key = secrets::seal(
        store,
        SIGNING_KEYS_TABLE,
        "private_key_encrypted",
        &id,
        &key.private_key,
    )?;
    let now_sec = unix_seconds().to_string();
    durable_table_insert(
        store,
        cache,
        SIGNING_KEYS_TABLE,
        &[
            ("id", id.as_str()),
            ("kid", key.kid.as_str()),
            ("algorithm", key.algorithm.as_str()),
            ("public_jwk", key.public_jwk.as_str()),
            ("private_key_encrypted", private_key.as_str()),
            ("active", "true"),
            ("created_at", now_sec.as_str()),
        ],
        now,
    )?;
    Ok(())
}

fn generate_es256_signing_key() -> Result<SigningKey, String> {
    let kid = random_id("kid");
    let secret = SecretKey::random(&mut OsRng);
    let private_pem = secret
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| e.to_string())?
        .to_string();
    let encoding_key =
        EncodingKey::from_ec_pem(private_pem.as_bytes()).map_err(|e| e.to_string())?;
    let mut jwk =
        Jwk::from_encoding_key(&encoding_key, Algorithm::ES256).map_err(|e| e.to_string())?;
    jwk.common.key_id = Some(kid.clone());
    jwk.common.public_key_use = Some(PublicKeyUse::Signature);
    jwk.common.key_algorithm = Some(KeyAlgorithm::ES256);
    let public_jwk = serde_json::to_string(&jwk).map_err(|e| e.to_string())?;
    Ok(SigningKey {
        kid,
        algorithm: "ES256".to_string(),
        public_jwk,
        private_key: private_pem,
    })
}

fn ensure_api_key(
    store: &Store,
    cache: &SharedSchemaCache,
    key: &str,
    kind: ApiKeyKind,
    name: &str,
    now: Instant,
) -> Result<(), String> {
    insert_api_key(store, cache, key, kind, name, now).map(|_| ())
}

fn insert_api_key(
    store: &Store,
    cache: &SharedSchemaCache,
    key: &str,
    kind: ApiKeyKind,
    name: &str,
    now: Instant,
) -> Result<Value, String> {
    let hash = hash_secret(key);
    if let Some(row) = find_row_by_field(store, cache, KEYS_TABLE, "key_hash", &hash, now)? {
        return Ok(key_map_json(&row));
    }
    let now_sec = unix_seconds().to_string();
    let kind_str = match kind {
        ApiKeyKind::Publishable => "publishable",
        ApiKeyKind::Secret => "secret",
    };
    let key_id = random_id("key");
    let prefix = key_prefix(key);
    durable_table_insert(
        store,
        cache,
        KEYS_TABLE,
        &[
            ("id", key_id.as_str()),
            ("name", name),
            ("kind", kind_str),
            ("prefix", prefix.as_str()),
            ("key_hash", hash.as_str()),
            ("scopes", "auth"),
            ("created_at", now_sec.as_str()),
        ],
        now,
    )?;
    // A negative result for this key may already be cached (something tried it
    // before it existed); drop it so the new key works immediately.
    invalidate_api_key_cache(store);
    Ok(json!({
        "id": key_id,
        "name": name,
        "kind": kind_str,
        "prefix": prefix,
        "scopes": ["auth"],
        "created_at": now_sec.parse::<u64>().unwrap_or_default(),
        "revoked_at": Value::Null,
        "last_used_at": Value::Null,
    }))
}

/// Which surface a credential is being presented to. The resolver enforces the
/// surface rule itself so no call site has to remember it: a publishable key is
/// browser-embedded and must never reach the raw command protocol, where lua,
/// FLUSHALL and raw KV live and no grant can contain the blast radius.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Surface {
    /// RESP command protocol. Secret keys and the operator password only.
    Resp,
    /// HTTP data routes and the `/live` websocket handshake.
    Http,
    /// `/auth/v1/*`, which publishable keys legitimately reach.
    AuthApi,
}

/// What a presented credential turned out to be.
///
/// This is the *identity* of the caller, not their permissions: `Publishable`
/// and `User` still answer to grants for every row they touch. Only `Secret` and
/// `Operator` carry blanket project access.
#[derive(Clone, Debug)]
pub(crate) enum Credential {
    /// No credential presented.
    Anonymous,
    /// Browser-safe project key. Reaches auth; reaches data only when an
    /// end-user token rides along and supplies a principal.
    Publishable,
    /// Server-side project key: full project access.
    Secret,
    /// End-user access token: subject to grants.
    User(Box<UserCredential>),
    /// `LUX_PASSWORD`. Break-glass and control-plane operations.
    Operator,
}

/// Turn a presented credential into an identity, for any surface.
///
/// Every entry point (RESP `AUTH`, HTTP, `/live`, `/auth/v1/*`) funnels through
/// here. The `_t:` namespace bug was two dispatch paths that had to agree and
/// silently didn't; one resolver is what keeps that from recurring for auth.
///
/// `presented` is the api key or bearer token. `user_token` is a separate
/// end-user access token when one accompanies a project key (the browser case:
/// `apikey=lux_pub_...` plus `Authorization: Bearer <jwt>`).
pub(crate) fn resolve_credential(
    presented: &str,
    user_token: &str,
    surface: Surface,
    store: &Store,
    cache: &SharedSchemaCache,
) -> Result<Credential, String> {
    let password = &store.config().password;

    // Operator first: the password is the break-glass path and must keep working
    // even if auth.keys is unreadable.
    if !password.is_empty()
        && !presented.is_empty()
        && constant_time_eq(presented.as_bytes(), password.as_bytes())
    {
        return Ok(Credential::Operator);
    }

    if !presented.is_empty() {
        if let Some(kind) = lookup_api_key(presented, store, cache)? {
            return match (kind, surface) {
                (ApiKeyKind::Publishable, Surface::Resp) => Err(
                    "publishable keys cannot use the RESP protocol; use a secret key".to_string(),
                ),
                (ApiKeyKind::Publishable, _) => {
                    // A publishable key alone is an identity of the project, not
                    // of a person. Data access needs a principal on top.
                    match resolve_user(user_token, store, cache)? {
                        Some(credential) => Ok(Credential::User(Box::new(credential))),
                        None => Ok(Credential::Publishable),
                    }
                }
                (ApiKeyKind::Secret, _) => Ok(Credential::Secret),
            };
        }
    }

    // No project key matched. An end-user token can still stand on its own.
    if let Some(credential) = resolve_user(user_token, store, cache)? {
        return Ok(Credential::User(Box::new(credential)));
    }
    if let Some(credential) = resolve_user(presented, store, cache)? {
        return Ok(Credential::User(Box::new(credential)));
    }

    Ok(Credential::Anonymous)
}

/// Validate an end-user access token, if one was supplied and auth is on.
fn resolve_user(
    token: &str,
    store: &Store,
    cache: &SharedSchemaCache,
) -> Result<Option<UserCredential>, String> {
    if token.is_empty() || !store.config().auth.enabled {
        return Ok(None);
    }
    // A project key in this slot is not a user token; don't report it as a bad
    // JWT.
    if token.starts_with("lux_pub_") || token.starts_with("lux_sec_") {
        return Ok(None);
    }
    match authenticate_user_credential(token, store, cache) {
        Ok(credential) => Ok(Some(credential)),
        Err(e) => Err(e),
    }
}

/// The project credential presented on an `/auth/v1/*` request.
fn presented_key(headers: &[(String, String)]) -> &str {
    header_value(headers, "apikey")
        .or_else(|| bearer_token(headers))
        .unwrap_or("")
}

fn require_publishable_or_secret(
    headers: &[(String, String)],
    store: &Store,
    cache: &SharedSchemaCache,
) -> Result<(), (u16, &'static str, String)> {
    match resolve_credential(presented_key(headers), "", Surface::AuthApi, store, cache) {
        Ok(Credential::Publishable | Credential::Secret | Credential::Operator) => Ok(()),
        // An engine with no keys configured yet is still open, as before.
        Ok(_) if no_project_keys_configured(store, cache) => Ok(()),
        Ok(_) => Err(error(
            401,
            "Unauthorized",
            "missing or invalid auth api key",
        )),
        Err(e) => Err(error(401, "Unauthorized", &e)),
    }
}

fn require_secret(
    headers: &[(String, String)],
    store: &Store,
    cache: &SharedSchemaCache,
) -> Result<(), (u16, &'static str, String)> {
    match resolve_credential(presented_key(headers), "", Surface::AuthApi, store, cache) {
        Ok(Credential::Secret | Credential::Operator) => Ok(()),
        _ => Err(error(401, "Unauthorized", "secret key required")),
    }
}

/// Resolve a raw key string to its kind, or `None` if unknown or revoked. The
/// single place `auth.keys` is consulted, shared by [`resolve_credential`] and
/// the `/auth/v1/*` guards.
fn lookup_api_key(
    key: &str,
    store: &Store,
    cache: &SharedSchemaCache,
) -> Result<Option<ApiKeyKind>, String> {
    if key.is_empty() {
        return Ok(None);
    }
    let hash = hash_secret(key);

    // HTTP authenticates per request, so an uncached lookup puts a hash plus a
    // table read on the hot path (measured at roughly +5us/req against the
    // password memcmp). Cache the resolution briefly. Misses are cached too, so
    // a client looping with a bad key cannot turn into a read storm.
    if let Some(kind) = cached_api_key(store, &hash) {
        return Ok(kind);
    }

    let resolved =
        match find_row_by_field(store, cache, KEYS_TABLE, "key_hash", &hash, Instant::now())? {
            Some(row)
                if row
                    .get("revoked_at")
                    .map(|v| !v.is_empty() && v != "0")
                    .unwrap_or(false) =>
            {
                None
            }
            Some(row) => match row.get("kind").map(String::as_str) {
                Some("publishable") => Some(ApiKeyKind::Publishable),
                Some("secret") => Some(ApiKeyKind::Secret),
                _ => None,
            },
            None => None,
        };
    store_cached_api_key(store, hash, resolved);
    Ok(resolved)
}

/// How long a resolved key stays cached. The ceiling on revocation latency for
/// anything that does not go through [`invalidate_api_key_cache`], not the
/// normal path: minting and revoking both clear the cache outright.
const API_KEY_CACHE_TTL: Duration = Duration::from_secs(5);

pub(crate) type ApiKeyCache = parking_lot::RwLock<HashMap<String, (Option<ApiKeyKind>, Instant)>>;

/// `Some(kind)` on a live cache hit, `None` when the caller must do the lookup.
fn cached_api_key(store: &Store, hash: &str) -> Option<Option<ApiKeyKind>> {
    let cache = store.api_key_cache.read();
    let (kind, stored_at) = cache.get(hash)?;
    if stored_at.elapsed() >= API_KEY_CACHE_TTL {
        return None;
    }
    Some(*kind)
}

fn store_cached_api_key(store: &Store, hash: String, kind: Option<ApiKeyKind>) {
    let mut cache = store.api_key_cache.write();
    // Bounded so an attacker spraying distinct keys cannot grow it without
    // limit; the working set is a handful of real keys.
    if cache.len() > 1024 {
        cache.retain(|_, (_, stored_at)| stored_at.elapsed() < API_KEY_CACHE_TTL);
        if cache.len() > 1024 {
            cache.clear();
        }
    }
    cache.insert(hash, (kind, Instant::now()));
}

/// Drop every cached resolution. Called whenever a key is minted or revoked so
/// the TTL is a backstop rather than the mechanism.
pub(crate) fn invalidate_api_key_cache(store: &Store) {
    store.api_key_cache.write().clear();
}

/// Whether this engine has project keys, i.e. whether key-based auth is in play.
pub(crate) fn project_keys_configured(store: &Store, cache: &SharedSchemaCache) -> bool {
    !no_project_keys_configured(store, cache)
}

fn no_project_keys_configured(store: &Store, cache: &SharedSchemaCache) -> bool {
    if store.config().auth.initial_publishable_key.is_some()
        || store.config().auth.initial_secret_key.is_some()
    {
        return false;
    }
    tables::table_count(store, cache, KEYS_TABLE, Instant::now()).unwrap_or(0) == 0
}

fn sign_access_token(
    store: &Store,
    cache: &SharedSchemaCache,
    user_id: &str,
    email: &str,
    session_id: &str,
) -> Result<String, String> {
    let now = unix_seconds();
    let exp = now + store.config().auth.access_token_ttl.as_secs();
    // Derive is_anonymous from the user's stored app metadata so every mint path
    // (signin, anonymous, refresh) stamps it consistently without threading a flag.
    let is_anonymous = find_row_by_field(store, cache, USERS_TABLE, "id", user_id, Instant::now())
        .ok()
        .flatten()
        .as_ref()
        .map(row_is_anonymous)
        .unwrap_or(false);
    let claims = AccessClaims {
        iss: store.config().auth.issuer.clone(),
        sub: user_id.to_string(),
        email: email.to_string(),
        session_id: session_id.to_string(),
        role: "authenticated".to_string(),
        iat: now as usize,
        exp: exp as usize,
        is_anonymous,
    };
    encode_auth_claims(store, cache, &claims)
}

fn encode_auth_claims<T: Serialize>(
    store: &Store,
    cache: &SharedSchemaCache,
    claims: &T,
) -> Result<String, String> {
    let signing_key = active_signing_key(store, cache, Instant::now())?
        .ok_or_else(|| "missing active auth signing key".to_string())?;
    match signing_key.algorithm.as_str() {
        "ES256" => {
            let mut header = Header::new(Algorithm::ES256);
            header.kid = Some(signing_key.kid);
            let key = EncodingKey::from_ec_pem(signing_key.private_key.as_bytes())
                .map_err(|e| e.to_string())?;
            encode(&header, claims, &key).map_err(|e| e.to_string())
        }
        _ => {
            let mut header = Header::new(Algorithm::HS256);
            if !signing_key.kid.is_empty() {
                header.kid = Some(signing_key.kid);
            }
            encode(
                &header,
                claims,
                &EncodingKey::from_secret(signing_key.private_key.as_bytes()),
            )
            .map_err(|e| e.to_string())
        }
    }
}

fn claims_from_bearer(
    headers: &[(String, String)],
    store: &Store,
    cache: &SharedSchemaCache,
) -> Result<AccessClaims, (u16, &'static str, String)> {
    let Some(token) = bearer_token(headers) else {
        return Err(error(401, "Unauthorized", "missing bearer token"));
    };
    claims_from_access_token(token, store, cache)
}

fn authenticate_user_credential(
    token: &str,
    store: &Store,
    cache: &SharedSchemaCache,
) -> Result<UserCredential, String> {
    let claims = claims_from_access_token(token, store, cache)
        .map_err(|(_, _, body)| json_error_message(&body).unwrap_or_else(|| body.clone()))?;
    Ok(UserCredential {
        principal: AuthPrincipal {
            user_id: claims.sub.clone(),
            email: claims.email.clone(),
            session_id: claims.session_id.clone(),
            role: claims.role.clone(),
            is_anonymous: claims.is_anonymous,
        },
        claims,
    })
}

/// Recheck a token that was cryptographically verified at connection setup.
/// This deliberately performs only the mutable session/user checks, not JWT
/// cryptography, so long-lived realtime sockets do not do that work per tick.
pub(crate) fn revalidate_user_credential(
    credential: &UserCredential,
    store: &Store,
    cache: &SharedSchemaCache,
) -> Result<(), String> {
    validate_access_claims(credential.claims.clone(), store, cache)
        .map(|_| ())
        .map_err(|(_, _, body)| json_error_message(&body).unwrap_or(body))
}

fn claims_from_access_token(
    token: &str,
    store: &Store,
    cache: &SharedSchemaCache,
) -> Result<AccessClaims, (u16, &'static str, String)> {
    let header =
        decode_header(token).map_err(|_| error(401, "Unauthorized", "invalid bearer token"))?;
    let signing_key = match header.alg {
        Algorithm::ES256 => {
            let kid = header
                .kid
                .as_deref()
                .ok_or_else(|| error(401, "Unauthorized", "invalid bearer token"))?;
            signing_key_by_kid(store, cache, kid, Instant::now())
                .map_err(|e| error(500, "Internal Server Error", &e))?
        }
        Algorithm::HS256 => active_signing_key(store, cache, Instant::now())
            .map_err(|e| error(500, "Internal Server Error", &e))?,
        _ => None,
    }
    .ok_or_else(|| error(401, "Unauthorized", "invalid bearer token"))?;

    let (algorithm, decoding_key) = match signing_key.algorithm.as_str() {
        "ES256" => {
            let jwk = serde_json::from_str::<Jwk>(&signing_key.public_jwk)
                .map_err(|_| error(500, "Internal Server Error", "invalid auth signing key"))?;
            let key = DecodingKey::from_jwk(&jwk)
                .map_err(|_| error(500, "Internal Server Error", "invalid auth signing key"))?;
            (Algorithm::ES256, key)
        }
        _ => (
            Algorithm::HS256,
            DecodingKey::from_secret(signing_key.private_key.as_bytes()),
        ),
    };
    let mut validation = Validation::new(algorithm);
    validation.set_issuer(&[store.config().auth.issuer.as_str()]);
    decode::<AccessClaims>(token, &decoding_key, &validation)
        .map(|token| token.claims)
        .map_err(|_| error(401, "Unauthorized", "invalid bearer token"))
        .and_then(|claims| validate_access_claims(claims, store, cache))
}

fn validate_access_claims(
    claims: AccessClaims,
    store: &Store,
    cache: &SharedSchemaCache,
) -> Result<AccessClaims, (u16, &'static str, String)> {
    let now = Instant::now();
    let now_sec = unix_seconds();
    if claims.exp as u64 <= now_sec {
        return Err(error(401, "Unauthorized", "access token expired"));
    }
    let session = find_row_by_field(store, cache, SESSIONS_TABLE, "id", &claims.session_id, now)
        .map_err(|e| error(500, "Internal Server Error", &e))?
        .ok_or_else(|| error(401, "Unauthorized", "session not found"))?;

    if session.get("user_id").map(String::as_str) != Some(claims.sub.as_str()) {
        return Err(error(401, "Unauthorized", "session user mismatch"));
    }
    let persisted_revocation = session
        .get("access_revoked_at")
        .and_then(|value| value.parse::<u64>().ok());
    let legacy_revocation = access_revoked_after(store, &claims.session_id, now)
        .map_err(|e| error(500, "Internal Server Error", &e))?;
    if persisted_revocation
        .into_iter()
        .chain(legacy_revocation)
        .max()
        .map(|revoked_after| claims.iat as u64 <= revoked_after)
        .unwrap_or(false)
    {
        return Err(error(401, "Unauthorized", "session revoked"));
    }
    let expires_at = session
        .get("expires_at")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    if expires_at <= now_sec {
        return Err(error(401, "Unauthorized", "session expired"));
    }

    let user = find_row_by_field(store, cache, USERS_TABLE, "id", &claims.sub, now)
        .map_err(|e| error(500, "Internal Server Error", &e))?
        .ok_or_else(|| error(401, "Unauthorized", "user not found"))?;
    validate_user_active(&user, now_sec)?;

    Ok(claims)
}

fn access_revoked_after(
    store: &Store,
    session_id: &str,
    now: Instant,
) -> Result<Option<u64>, String> {
    let key = access_revoked_after_key(session_id);
    store
        .get_checked(&key, now)
        .map(|value| value.and_then(|value| std::str::from_utf8(&value).ok()?.parse::<u64>().ok()))
}

#[cfg(test)]
fn persist_access_revocation(
    store: &Store,
    session_id: &str,
    revoked_after: &str,
    now: Instant,
) -> Result<(), String> {
    let key = access_revoked_after_key(session_id);
    let ttl = store.config().auth.access_token_ttl;
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0);
    let deadline = now_ms
        .saturating_add(u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX))
        .to_string();
    let command: [&[u8]; 5] = [
        b"SET",
        &key,
        revoked_after.as_bytes(),
        b"PXAT",
        deadline.as_bytes(),
    ];
    store
        .commit_journaled(&command, || {
            store.set(&key, revoked_after.as_bytes(), Some(ttl), now)
        })
        .map_err(|error| format!("ERR WAL append failed: {error}"))?;
    Ok(())
}

fn access_revoked_after_key(session_id: &str) -> Vec<u8> {
    let mut key = ACCESS_REVOKED_AFTER_PREFIX.to_vec();
    key.extend_from_slice(session_id.as_bytes());
    key
}

fn validate_user_active(
    user: &HashMap<String, String>,
    now_sec: u64,
) -> Result<(), (u16, &'static str, String)> {
    if row_field_is_set(user, "deleted_at") {
        return Err(error(401, "Unauthorized", "user deleted"));
    }
    let banned_until = user
        .get("banned_until")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    if banned_until > now_sec {
        return Err(error(401, "Unauthorized", "user banned"));
    }
    Ok(())
}

fn json_error_message(body: &str) -> Option<String> {
    serde_json::from_str::<Value>(body).ok().and_then(|value| {
        value
            .get("error")
            .and_then(Value::as_str)
            .map(str::to_string)
    })
}

fn row_field_is_set(row: &HashMap<String, String>, field: &str) -> bool {
    row.get(field)
        .map(|value| !value.is_empty() && value != "0")
        .unwrap_or(false)
}

fn active_signing_key(
    store: &Store,
    cache: &SharedSchemaCache,
    now: Instant,
) -> Result<Option<SigningKey>, String> {
    let row = find_row_by_field(store, cache, SIGNING_KEYS_TABLE, "active", "true", now)?;
    row.map(|row| signing_key_from_row(store, row)).transpose()
}

fn signing_key_by_kid(
    store: &Store,
    cache: &SharedSchemaCache,
    kid: &str,
    now: Instant,
) -> Result<Option<SigningKey>, String> {
    let row = find_row_by_field(store, cache, SIGNING_KEYS_TABLE, "kid", kid, now)?;
    row.map(|row| signing_key_from_row(store, row)).transpose()
}

fn signing_key_from_row(store: &Store, row: HashMap<String, String>) -> Result<SigningKey, String> {
    let id = row.get("id").map(String::as_str).unwrap_or("");
    let stored = row
        .get("private_key_encrypted")
        .map(String::as_str)
        .unwrap_or("");
    Ok(SigningKey {
        kid: row.get("kid").cloned().unwrap_or_default(),
        algorithm: row
            .get("algorithm")
            .cloned()
            .filter(|algorithm| !algorithm.is_empty())
            .unwrap_or_else(|| "HS256".to_string()),
        public_jwk: row.get("public_jwk").cloned().unwrap_or_default(),
        private_key: secrets::open(
            store,
            SIGNING_KEYS_TABLE,
            "private_key_encrypted",
            id,
            stored,
        )?,
    })
}

fn user_json(
    store: &Store,
    cache: &SharedSchemaCache,
    user_id: &str,
    now: Instant,
) -> Option<Value> {
    find_row_by_field(store, cache, USERS_TABLE, "id", user_id, now)
        .ok()
        .flatten()
        .map(|row| user_map_json(&row))
}

fn user_row_json(row: Vec<(String, String)>) -> Value {
    let map: HashMap<String, String> = row.into_iter().collect();
    user_map_json(&map)
}

fn key_row_json(row: Vec<(String, String)>) -> Value {
    let map: HashMap<String, String> = row.into_iter().collect();
    key_map_json(&map)
}

fn provider_row_json(row: Vec<(String, String)>) -> Value {
    let map: HashMap<String, String> = row.into_iter().collect();
    provider_map_json(&map)
}

fn key_map_json(row: &HashMap<String, String>) -> Value {
    let scopes = row
        .get("scopes")
        .map(|scopes| {
            scopes
                .split(',')
                .filter(|scope| !scope.trim().is_empty())
                .map(|scope| Value::String(scope.trim().to_string()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    json!({
        "id": row.get("id").cloned().unwrap_or_default(),
        "name": row.get("name").cloned().unwrap_or_default(),
        "kind": row.get("kind").cloned().unwrap_or_default(),
        "prefix": row.get("prefix").cloned().unwrap_or_default(),
        "scopes": scopes,
        "created_at": parse_optional_int(row.get("created_at")),
        "revoked_at": parse_optional_int(row.get("revoked_at")),
        "last_used_at": parse_optional_int(row.get("last_used_at")),
    })
}

#[derive(Clone)]
struct OAuthProviderConfig {
    provider: String,
    enabled: bool,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    scopes: String,
    // Apple Sign In: services_id is the web OAuth client_id (aud), bundle_ids is a
    // comma-separated list of native audiences, apple_private_key is the unsealed
    // .p8 PEM (empty unless configured). team_id/key_id identify the .p8 to Apple.
    apple_team_id: String,
    apple_key_id: String,
    apple_services_id: String,
    apple_bundle_ids: String,
    apple_private_key: String,
    created_at: Value,
    updated_at: Value,
}

#[derive(Clone, Debug)]
struct OAuthUser {
    provider: String,
    provider_id: String,
    email: String,
    email_verified: bool,
    user_metadata: Value,
    identity_data: Value,
}

fn provider_map_json(row: &HashMap<String, String>) -> Value {
    json!({
        "provider": row.get("provider").cloned().unwrap_or_default(),
        "enabled": parse_bool(row.get("enabled")),
        "client_id": row.get("client_id").cloned().unwrap_or_default(),
        "redirect_uri": row.get("redirect_uri").cloned().unwrap_or_default(),
        "scopes": row.get("scopes").cloned().unwrap_or_default(),
        "has_client_secret": row.get("client_secret").map(|s| !s.is_empty()).unwrap_or(false),
        "apple_team_id": row.get("apple_team_id").cloned().unwrap_or_default(),
        "apple_key_id": row.get("apple_key_id").cloned().unwrap_or_default(),
        "apple_services_id": row.get("apple_services_id").cloned().unwrap_or_default(),
        "apple_bundle_ids": row.get("apple_bundle_ids").cloned().unwrap_or_default(),
        "has_apple_private_key": row.get("apple_private_key").map(|s| !s.is_empty()).unwrap_or(false),
        "created_at": parse_optional_int(row.get("created_at")),
        "updated_at": parse_optional_int(row.get("updated_at")),
    })
}

fn provider_config_json(config: &OAuthProviderConfig) -> Value {
    json!({
        "provider": config.provider,
        "enabled": config.enabled,
        "client_id": config.client_id,
        "redirect_uri": config.redirect_uri,
        "scopes": config.scopes,
        "has_client_secret": !config.client_secret.is_empty(),
        "apple_team_id": config.apple_team_id,
        "apple_key_id": config.apple_key_id,
        "apple_services_id": config.apple_services_id,
        "apple_bundle_ids": config.apple_bundle_ids,
        "has_apple_private_key": !config.apple_private_key.is_empty(),
        "created_at": config.created_at,
        "updated_at": config.updated_at,
    })
}

fn oauth_provider_config(
    store: &Store,
    cache: &SharedSchemaCache,
    provider: &str,
    now: Instant,
) -> Result<Option<OAuthProviderConfig>, String> {
    let Some(row) = find_row_by_field(store, cache, PROVIDERS_TABLE, "provider", provider, now)?
    else {
        return Ok(None);
    };
    let apple_private_key = match row.get("apple_private_key") {
        Some(stored) if !stored.is_empty() => secrets::open(
            store,
            PROVIDERS_TABLE,
            "apple_private_key",
            provider,
            stored,
        )?,
        _ => String::new(),
    };
    let client_secret = match row.get("client_secret") {
        Some(stored) if !stored.is_empty() => {
            secrets::open(store, PROVIDERS_TABLE, "client_secret", provider, stored)?
        }
        _ => String::new(),
    };
    Ok(Some(OAuthProviderConfig {
        provider: row.get("provider").cloned().unwrap_or_default(),
        enabled: parse_bool(row.get("enabled")),
        client_id: row.get("client_id").cloned().unwrap_or_default(),
        client_secret,
        redirect_uri: row.get("redirect_uri").cloned().unwrap_or_default(),
        scopes: row
            .get("scopes")
            .cloned()
            .unwrap_or_else(|| default_oauth_scopes(provider).to_string()),
        apple_team_id: row.get("apple_team_id").cloned().unwrap_or_default(),
        apple_key_id: row.get("apple_key_id").cloned().unwrap_or_default(),
        apple_services_id: row.get("apple_services_id").cloned().unwrap_or_default(),
        apple_bundle_ids: row.get("apple_bundle_ids").cloned().unwrap_or_default(),
        apple_private_key,
        created_at: parse_optional_int(row.get("created_at")),
        updated_at: parse_optional_int(row.get("updated_at")),
    }))
}

fn normalize_oauth_provider(provider: &str) -> Result<String, (u16, &'static str, String)> {
    let provider = provider.trim().to_ascii_lowercase();
    match provider.as_str() {
        "google" | "github" | "apple" => Ok(provider),
        _ => Err(error(400, "Bad Request", "unsupported provider")),
    }
}

fn default_oauth_scopes(provider: &str) -> &'static str {
    match provider {
        "google" => "openid email profile",
        "github" => "read:user user:email",
        "apple" => "name email",
        _ => "",
    }
}

fn oauth_state_key(state: &str) -> String {
    format!("_auth:oauth_state:{state}")
}

fn persist_oauth_state(store: &Store, key: &[u8], payload: &[u8]) -> Result<(), String> {
    let now = Instant::now();
    let ttl_ms = i64::try_from(OAUTH_STATE_TTL.as_millis()).unwrap_or(i64::MAX);
    let deadline = crate::store::epoch_ms().saturating_add(ttl_ms).to_string();
    let command: [&[u8]; 5] = [b"SET", key, payload, b"PXAT", deadline.as_bytes()];
    store
        .commit_journaled(&command, || {
            store.set(key, payload, Some(OAUTH_STATE_TTL), now)
        })
        .map_err(|error| format!("ERR WAL append failed: {error}"))?;
    Ok(())
}

fn take_oauth_state(
    store: &Store,
    key: &[u8],
    now: Instant,
) -> Result<Option<bytes::Bytes>, String> {
    let command: [&[u8]; 2] = [b"DEL", key];
    let prepare = store
        .prepare_journaled(&command)
        .map_err(|error| format!("ERR WAL append failed: {error}"))?;
    let Some(payload) = store.get_checked(key, now)? else {
        return Ok(None);
    };
    let commit = prepare
        .commit(&command)
        .map_err(|error| format!("ERR WAL append failed: {error}"))?;
    let removed = store.del(&[key]);
    debug_assert_eq!(removed, 1);
    commit
        .complete()
        .map_err(|error| format!("ERR journal apply failed: {error}"))?;
    Ok(Some(payload))
}

fn default_callback_url(headers: &[(String, String)], provider: &str) -> String {
    let host = header_value(headers, "host").unwrap_or("localhost");
    format!("http://{host}/auth/v1/callback/{provider}")
}

fn oauth_authorization_url(
    config: &OAuthProviderConfig,
    redirect_uri: &str,
    state: &str,
    oidc_nonce: &str,
) -> String {
    match config.provider.as_str() {
        "google" => format!(
            "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}&access_type=offline&prompt=consent",
            url_encode(&config.client_id),
            url_encode(redirect_uri),
            url_encode(&config.scopes),
            url_encode(state),
        ),
        "github" => format!(
            "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}",
            url_encode(&config.client_id),
            url_encode(redirect_uri),
            url_encode(&config.scopes),
            url_encode(state),
        ),
        // Apple uses the Services ID as client_id and requires form_post response
        // mode when name/email scopes are requested (Apple then POSTs the callback).
        "apple" => format!(
            "https://appleid.apple.com/auth/authorize?client_id={}&redirect_uri={}&response_type=code&response_mode=form_post&scope={}&state={}&nonce={}",
            url_encode(&config.apple_services_id),
            url_encode(redirect_uri),
            url_encode(&config.scopes),
            url_encode(state),
            url_encode(oidc_nonce),
        ),
        _ => String::new(),
    }
}

// ---- Sign in with Apple ----------------------------------------------------

async fn exchange_oauth_code(
    config: &OAuthProviderConfig,
    code: &str,
    redirect_uri: &str,
    expected_nonce: Option<&str>,
    apple_name: Option<String>,
) -> Result<OAuthUser, String> {
    match config.provider.as_str() {
        "google" => exchange_google_code(config, code, redirect_uri).await,
        "github" => exchange_github_code(config, code, redirect_uri).await,
        "apple" => {
            exchange_apple_code(config, code, redirect_uri, expected_nonce, apple_name).await
        }
        _ => Err("unsupported_provider".to_string()),
    }
}

/// Mint Apple's OAuth "client secret" on demand: an ES256 JWT signed with the
/// stored .p8. Minted per exchange with a short expiry, so unlike a manually
/// pasted secret it never goes stale and never needs rotation.
async fn exchange_google_code(
    config: &OAuthProviderConfig,
    code: &str,
    redirect_uri: &str,
) -> Result<OAuthUser, String> {
    let client = reqwest::Client::new();
    let body = form_body(&[
        ("client_id", config.client_id.as_str()),
        ("client_secret", config.client_secret.as_str()),
        ("code", code),
        ("grant_type", "authorization_code"),
        ("redirect_uri", redirect_uri),
    ]);
    let token: Value = client
        .post("https://oauth2.googleapis.com/token")
        .header("Accept", "application/json")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .map_err(|_| "token_exchange_failed".to_string())?
        .json()
        .await
        .map_err(|_| "token_response_invalid".to_string())?;
    let access_token = token
        .get("access_token")
        .and_then(Value::as_str)
        .ok_or_else(|| "token_exchange_failed".to_string())?;
    let profile: Value = client
        .get("https://openidconnect.googleapis.com/v1/userinfo")
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|_| "userinfo_failed".to_string())?
        .json()
        .await
        .map_err(|_| "userinfo_invalid".to_string())?;
    oauth_user_from_google(profile)
}

async fn exchange_github_code(
    config: &OAuthProviderConfig,
    code: &str,
    redirect_uri: &str,
) -> Result<OAuthUser, String> {
    let client = reqwest::Client::new();
    let body = form_body(&[
        ("client_id", config.client_id.as_str()),
        ("client_secret", config.client_secret.as_str()),
        ("code", code),
        ("redirect_uri", redirect_uri),
    ]);
    let token: Value = client
        .post("https://github.com/login/oauth/access_token")
        .header("Accept", "application/json")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .map_err(|_| "token_exchange_failed".to_string())?
        .json()
        .await
        .map_err(|_| "token_response_invalid".to_string())?;
    let access_token = token
        .get("access_token")
        .and_then(Value::as_str)
        .ok_or_else(|| "token_exchange_failed".to_string())?;
    let profile: Value = client
        .get("https://api.github.com/user")
        .header("User-Agent", "Lux Auth")
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|_| "userinfo_failed".to_string())?
        .json()
        .await
        .map_err(|_| "userinfo_invalid".to_string())?;
    let emails: Value = client
        .get("https://api.github.com/user/emails")
        .header("User-Agent", "Lux Auth")
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|_| "userinfo_failed".to_string())?
        .json()
        .await
        .map_err(|_| "userinfo_invalid".to_string())?;
    oauth_user_from_github(profile, emails)
}

fn oauth_user_from_google(profile: Value) -> Result<OAuthUser, String> {
    let provider_id = profile
        .get("sub")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing_provider_user_id".to_string())?;
    let email = profile
        .get("email")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing_email".to_string())?;
    Ok(OAuthUser {
        provider: "google".to_string(),
        provider_id: provider_id.to_string(),
        email: email.to_string(),
        email_verified: profile
            .get("email_verified")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        user_metadata: json!({
            "name": profile.get("name").cloned().unwrap_or(Value::Null),
            "avatar_url": profile.get("picture").cloned().unwrap_or(Value::Null),
        }),
        identity_data: profile,
    })
}

fn oauth_user_from_github(profile: Value, emails: Value) -> Result<OAuthUser, String> {
    let provider_id = profile
        .get("id")
        .map(|value| match value {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            _ => String::new(),
        })
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "missing_provider_user_id".to_string())?;
    let primary_email = emails.as_array().and_then(|items| {
        items
            .iter()
            .find(|item| {
                item.get("primary")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
            })
            .and_then(|item| item.get("email").and_then(Value::as_str))
    });
    let email = profile
        .get("email")
        .and_then(Value::as_str)
        .filter(|email| !email.is_empty())
        .or(primary_email)
        .ok_or_else(|| "missing_email".to_string())?;
    let email_verified = emails
        .as_array()
        .and_then(|items| {
            items
                .iter()
                .find(|item| item.get("email").and_then(Value::as_str) == Some(email))
        })
        .and_then(|item| item.get("verified").and_then(Value::as_bool))
        .unwrap_or(true);
    Ok(OAuthUser {
        provider: "github".to_string(),
        provider_id,
        email: email.to_string(),
        email_verified,
        user_metadata: json!({
            "name": profile.get("name").cloned().unwrap_or(Value::Null),
            "user_name": profile.get("login").cloned().unwrap_or(Value::Null),
            "avatar_url": profile.get("avatar_url").cloned().unwrap_or(Value::Null),
        }),
        identity_data: json!({
            "profile": profile,
            "emails": emails,
        }),
    })
}

fn oauth_success_url(redirect_to: &str, session: &Value) -> String {
    let mut fragment = Vec::new();
    for key in ["access_token", "refresh_token", "token_type", "expires_in"] {
        if let Some(value) = session.get(key) {
            let value = value
                .as_str()
                .map(str::to_string)
                .unwrap_or_else(|| value.to_string());
            fragment.push(format!("{}={}", url_encode(key), url_encode(&value)));
        }
    }
    append_fragment(redirect_to, &fragment.join("&"))
}

fn oauth_code_url(redirect_to: &str, code: &str) -> String {
    append_query(redirect_to, &[("code", code)])
}

fn oauth_error_url(redirect_to: &str, message: &str) -> String {
    append_query(redirect_to, &[("error", message)])
}

fn append_fragment(url: &str, fragment: &str) -> String {
    let separator = if url.contains('#') { "&" } else { "#" };
    format!("{url}{separator}{fragment}")
}

fn append_query(url: &str, params: &[(&str, &str)]) -> String {
    let separator = if url.contains('?') { "&" } else { "?" };
    let query = params
        .iter()
        .map(|(key, value)| format!("{}={}", url_encode(key), url_encode(value)))
        .collect::<Vec<_>>()
        .join("&");
    format!("{url}{separator}{query}")
}

fn auth_action_link(redirect_to: &str, token: &str, kind: &str) -> String {
    append_query(redirect_to, &[("token_hash", token), ("type", kind)])
}

fn auth_redirect_to_with_default(
    parsed: &Value,
    settings: &AuthSettings,
) -> Result<String, String> {
    let redirect = parsed
        .get("redirect_to")
        .or_else(|| parsed.get("email_redirect_to"))
        .and_then(Value::as_str)
        .or_else(|| {
            parsed
                .get("options")
                .and_then(|options| {
                    options
                        .get("emailRedirectTo")
                        .or_else(|| options.get("redirectTo"))
                })
                .and_then(Value::as_str)
        })
        .filter(|value| !value.trim().is_empty())
        .map(sanitize_header_value)
        .unwrap_or_else(|| settings.site_url.clone());
    validate_auth_redirect(&redirect, settings)
}

fn validate_auth_redirect(redirect: &str, settings: &AuthSettings) -> Result<String, String> {
    let redirect = sanitize_header_value(redirect).trim().to_string();
    if redirect.is_empty() {
        return Err("redirect URL cannot be empty".to_string());
    }
    if is_relative_redirect(&redirect) {
        return Ok(redirect);
    }
    let Some(target_origin) = url_origin(&redirect) else {
        // A custom scheme (`myapp://auth/callback`) has no http(s) origin, so it
        // can only ever match an allow-list entry exactly. Native OAuth needs
        // one of these or a universal link, and the allow list is the security
        // boundary: an unlisted scheme is still refused. Without this the allow
        // list accepted a value that `authorize` then rejected at sign-in time.
        if settings
            .redirect_allow_list
            .iter()
            .any(|allowed| allowed.trim() == redirect)
        {
            return Ok(redirect);
        }
        return Err(
            "redirect URL must be relative, http(s), or a custom scheme on the redirect allow list"
                .to_string(),
        );
    };
    if url_origin(&settings.site_url).as_deref() == Some(target_origin.as_str()) {
        return Ok(redirect);
    }
    if settings
        .redirect_allow_list
        .iter()
        .any(|allowed| redirect_matches_allowed(&redirect, &target_origin, allowed))
    {
        return Ok(redirect);
    }
    Err("redirect URL is not allowed".to_string())
}

fn is_relative_redirect(value: &str) -> bool {
    value.starts_with('/') && !value.starts_with("//") && !value.contains('\\')
}

fn redirect_matches_allowed(redirect: &str, target_origin: &str, allowed: &str) -> bool {
    let allowed = allowed.trim();
    if allowed.is_empty() {
        return false;
    }
    if let Some(allowed_origin) = url_origin(allowed) {
        if allowed_origin != target_origin {
            return false;
        }
        if let Some(path_start) = url_path_start(allowed) {
            let allowed_path = &allowed[path_start..];
            if allowed_path == "/" {
                return true;
            }
            return redirect
                .get(path_start..)
                .is_some_and(|path| path.starts_with(allowed_path));
        }
        return true;
    }
    redirect == allowed
}

fn url_origin(value: &str) -> Option<String> {
    let scheme_end = value.find("://")?;
    let scheme = &value[..scheme_end].to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let rest = &value[scheme_end + 3..];
    if rest.is_empty() || rest.starts_with('/') {
        return None;
    }
    let host_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    if host_end == 0 {
        return None;
    }
    Some(format!(
        "{}://{}",
        scheme,
        rest[..host_end].to_ascii_lowercase()
    ))
}

fn url_path_start(value: &str) -> Option<usize> {
    let scheme_end = value.find("://")?;
    let rest_start = scheme_end + 3;
    let rest = &value[rest_start..];
    rest.find('/').map(|idx| rest_start + idx)
}

fn create_email_flow_token(
    store: &Store,
    cache: &SharedSchemaCache,
    kind: &str,
    user_id: &str,
    email: &str,
    redirect_to: &str,
    now: Instant,
) -> Result<String, (u16, &'static str, String)> {
    let settings = auth_settings(store, cache, now).map_err(|e| error(400, "Bad Request", &e))?;
    let metadata = json!({
        "action_link": auth_action_link(redirect_to, "", kind),
    });
    let token = create_flow_token(
        store,
        cache,
        FlowTokenInsert {
            settings: &settings,
            kind,
            user_id,
            email,
            redirect_to,
            metadata,
        },
        now,
    )?;
    let action_link = auth_action_link(redirect_to, &token, kind);
    let metadata = json!({ "action_link": action_link }).to_string();
    durable_table_update_where(
        store,
        cache,
        FLOW_TOKENS_TABLE,
        &[("metadata", metadata.as_str())],
        &["token_hash", "=", &hash_secret(&token)],
        now,
    )
    .map_err(|e| error(400, "Bad Request", &e))?;
    if let Err(e) = send_auth_email(store, &settings, kind, email, &action_link) {
        let _ = durable_table_delete_where(
            store,
            cache,
            FLOW_TOKENS_TABLE,
            &["token_hash", "=", &hash_secret(&token)],
            now,
        );
        return Err(error(502, "Bad Gateway", &e));
    }
    Ok(token)
}

fn send_auth_email(
    store: &Store,
    settings: &AuthSettings,
    kind: &str,
    email: &str,
    action_link: &str,
) -> Result<(), String> {
    validate_auth_email_settings(settings, store.config().auth.managed_email.as_ref())?;
    let delivery = effective_email_delivery(settings, store.config().auth.managed_email.as_ref())?;
    match delivery.provider.as_str() {
        "console" | "log" => {
            eprintln!("Lux Auth {kind} link for {email}: {action_link}");
            Ok(())
        }
        "postmark" => {
            let token = delivery
                .postmark_server_token
                .clone()
                .ok_or_else(|| "postmark email delivery requires a server token".to_string())?;
            let message = auth_email_message(kind, email, action_link, &delivery)?;
            run_async_work(send_postmark_email(token, message))
        }
        _ => Err("unsupported email_provider".to_string()),
    }
}

fn effective_email_delivery(
    settings: &AuthSettings,
    managed_email: Option<&AuthManagedEmailConfig>,
) -> Result<EffectiveEmailDelivery, String> {
    if let Some(managed) = managed_email {
        let provider = managed.provider.trim().to_ascii_lowercase();
        let from = apply_email_from_name(&managed.from, settings.email_from_name.as_deref());
        return Ok(EffectiveEmailDelivery {
            provider,
            from: Some(from),
            reply_to: managed.reply_to.clone(),
            postmark_server_token: managed.postmark_server_token.clone(),
            postmark_message_stream: managed
                .postmark_message_stream
                .clone()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "outbound".to_string()),
            app_name: settings.email_app_name.clone(),
        });
    }
    Ok(EffectiveEmailDelivery {
        provider: settings.email_provider.clone(),
        from: settings.email_from.clone(),
        reply_to: settings.email_reply_to.clone(),
        postmark_server_token: settings.email_postmark_server_token.clone(),
        postmark_message_stream: settings.email_postmark_message_stream.clone(),
        app_name: settings.email_app_name.clone(),
    })
}

fn auth_email_message(
    kind: &str,
    email: &str,
    action_link: &str,
    delivery: &EffectiveEmailDelivery,
) -> Result<AuthEmailMessage, String> {
    let from = delivery
        .from
        .clone()
        .ok_or_else(|| "email delivery requires a from address".to_string())?;
    let app_name = delivery.app_name.trim();
    let app_name = if app_name.is_empty() { "Lux" } else { app_name };
    let (subject, text_intro, html_heading) = match kind {
        "signup" => (
            format!("Confirm your email for {app_name}"),
            format!("Confirm your email for {app_name} by opening this link:"),
            "Confirm your email",
        ),
        "recovery" => (
            format!("Reset your password for {app_name}"),
            format!("Reset your password for {app_name} by opening this link:"),
            "Reset your password",
        ),
        _ => (
            format!("Continue signing in to {app_name}"),
            format!("Continue signing in to {app_name} by opening this link:"),
            "Continue signing in",
        ),
    };
    let escaped_link = html_escape(action_link);
    let escaped_heading = html_escape(html_heading);
    let escaped_app = html_escape(app_name);
    Ok(AuthEmailMessage {
        from,
        to: email.to_string(),
        reply_to: delivery.reply_to.clone(),
        subject,
        text_body: format!("{text_intro}\n\n{action_link}\n\nIf you did not request this, you can ignore this email."),
        html_body: format!(
            "<h2>{escaped_heading}</h2><p>Use this link to continue with {escaped_app}:</p><p><a href=\"{escaped_link}\">{escaped_link}</a></p><p>If you did not request this, you can ignore this email.</p>"
        ),
        message_stream: delivery.postmark_message_stream.clone(),
    })
}

fn postmark_payload(message: &AuthEmailMessage) -> PostmarkEmailPayload {
    PostmarkEmailPayload {
        from: message.from.clone(),
        to: message.to.clone(),
        subject: message.subject.clone(),
        text_body: message.text_body.clone(),
        html_body: message.html_body.clone(),
        message_stream: message.message_stream.clone(),
        reply_to: message.reply_to.clone(),
    }
}

async fn send_postmark_email(
    server_token: String,
    message: AuthEmailMessage,
) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(POSTMARK_EMAIL_TIMEOUT)
        .build()
        .map_err(|_| "postmark email client setup failed".to_string())?;
    let response = client
        .post("https://api.postmarkapp.com/email")
        .header("Accept", "application/json")
        .header("X-Postmark-Server-Token", server_token)
        .json(&postmark_payload(&message))
        .send()
        .await
        .map_err(|_| "postmark email request failed".to_string())?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(format!(
            "postmark email request failed with status {}",
            response.status().as_u16()
        ))
    }
}

fn apply_email_from_name(from: &str, from_name: Option<&str>) -> String {
    let Some(name) = from_name.map(str::trim).filter(|value| !value.is_empty()) else {
        return sanitize_header_value(from);
    };
    let safe_name = sanitize_header_value(name)
        .replace(['<', '>'], "")
        .trim()
        .to_string();
    if safe_name.is_empty() {
        return sanitize_header_value(from);
    }
    let safe_from = sanitize_header_value(from);
    if let Some((_, rest)) = safe_from.split_once('<') {
        if let Some((address, _)) = rest.split_once('>') {
            return format!("{safe_name} <{}>", address.trim());
        }
    }
    format!("{safe_name} <{}>", safe_from.trim())
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn create_flow_token(
    store: &Store,
    cache: &SharedSchemaCache,
    insert: FlowTokenInsert<'_>,
    now: Instant,
) -> Result<String, (u16, &'static str, String)> {
    let token = random_token(32);
    let token_hash = hash_secret(&token);
    let now_sec = unix_seconds();
    let expires_at = now_sec + insert.settings.flow_token_ttl.as_secs();
    durable_table_insert(
        store,
        cache,
        FLOW_TOKENS_TABLE,
        &[
            ("id", random_id("flt").as_str()),
            ("type", insert.kind),
            ("token_hash", token_hash.as_str()),
            ("user_id", insert.user_id),
            ("email", insert.email),
            ("redirect_to", insert.redirect_to),
            ("metadata", insert.metadata.to_string().as_str()),
            ("expires_at", &expires_at.to_string()),
            ("created_at", &now_sec.to_string()),
        ],
        now,
    )
    .map_err(|e| error(400, "Bad Request", &e))?;
    Ok(token)
}

fn auth_settings_json(
    settings: &AuthSettings,
    managed_email: Option<&AuthManagedEmailConfig>,
) -> Value {
    let managed = managed_email.is_some();
    json!({
        "email_confirmation_required": settings.email_confirmation_required,
        "flow_token_ttl_seconds": settings.flow_token_ttl.as_secs(),
        "site_url": settings.site_url,
        "redirect_allow_list": settings.redirect_allow_list.clone(),
        "email_provider": if managed { "managed" } else { settings.email_provider.as_str() },
        "email_delivery_managed": managed,
        "email_delivery_configured": managed || matches!(settings.email_provider.as_str(), "console" | "log") || settings.email_postmark_server_token.is_some(),
        "email_from": if managed { Value::Null } else { optional_string_json(settings.email_from.as_deref()) },
        "email_reply_to": if managed { Value::Null } else { optional_string_json(settings.email_reply_to.as_deref()) },
        "email_postmark_message_stream": if managed {
            Value::Null
        } else {
            Value::String(settings.email_postmark_message_stream.clone())
        },
        "has_email_postmark_server_token": !managed && settings.email_postmark_server_token.is_some(),
        "email_app_name": settings.email_app_name,
        "email_from_name": optional_string_json(settings.email_from_name.as_deref()),
    })
}

fn optional_string_json(value: Option<&str>) -> Value {
    value
        .filter(|value| !value.trim().is_empty())
        .map(|value| Value::String(value.to_string()))
        .unwrap_or(Value::Null)
}

fn ensure_auth_setting(
    store: &Store,
    cache: &SharedSchemaCache,
    key: &str,
    value: &str,
    now: Instant,
) -> Result<(), String> {
    if find_row_by_field(store, cache, SETTINGS_TABLE, "key", key, now)?.is_some() {
        return Ok(());
    }
    let stored_value = if key == secrets::EMAIL_POSTMARK_TOKEN_KEY {
        secrets::seal(store, SETTINGS_TABLE, "value", key, value)?
    } else {
        value.to_string()
    };
    let now_sec = unix_seconds().to_string();
    durable_table_insert(
        store,
        cache,
        SETTINGS_TABLE,
        &[
            ("key", key),
            ("value", stored_value.as_str()),
            ("updated_at", now_sec.as_str()),
        ],
        now,
    )
    .map(|_| ())
}

fn set_auth_setting(
    store: &Store,
    cache: &SharedSchemaCache,
    key: &str,
    value: &str,
    now: Instant,
) -> Result<(), String> {
    if find_row_by_field(store, cache, SETTINGS_TABLE, "key", key, now)?.is_some() {
        let stored_value = if key == secrets::EMAIL_POSTMARK_TOKEN_KEY {
            secrets::seal(store, SETTINGS_TABLE, "value", key, value)?
        } else {
            value.to_string()
        };
        let now_sec = unix_seconds().to_string();
        durable_table_update_where(
            store,
            cache,
            SETTINGS_TABLE,
            &[
                ("value", stored_value.as_str()),
                ("updated_at", now_sec.as_str()),
            ],
            &["key", "=", key],
            now,
        )?;
    } else {
        ensure_auth_setting(store, cache, key, value, now)?;
    }
    Ok(())
}

fn auth_settings(
    store: &Store,
    cache: &SharedSchemaCache,
    now: Instant,
) -> Result<AuthSettings, String> {
    Ok(AuthSettings {
        email_confirmation_required: auth_setting_value(
            store,
            cache,
            "email_confirmation_required",
            now,
        )?
        .map(|value| parse_setting_bool(&value))
        .unwrap_or(store.config().auth.email_confirmation_required),
        flow_token_ttl: Duration::from_secs(
            auth_setting_value(store, cache, "flow_token_ttl_seconds", now)?
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or_else(|| store.config().auth.flow_token_ttl.as_secs()),
        ),
        site_url: auth_setting_value(store, cache, "site_url", now)?
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| store.config().auth.site_url.clone()),
        redirect_allow_list: auth_setting_value(store, cache, "redirect_allow_list", now)?
            .map(|value| parse_redirect_allow_list(&value))
            .unwrap_or_default(),
        email_provider: auth_setting_value(store, cache, "email_provider", now)?
            .filter(|value| !value.trim().is_empty())
            .map(|value| value.to_ascii_lowercase())
            .map(|value| {
                if value == "log" {
                    "console".to_string()
                } else {
                    value
                }
            })
            .unwrap_or_else(|| "console".to_string()),
        email_from: auth_setting_value(store, cache, "email_from", now)?
            .filter(|value| !value.trim().is_empty()),
        email_reply_to: auth_setting_value(store, cache, "email_reply_to", now)?
            .filter(|value| !value.trim().is_empty()),
        email_postmark_server_token: auth_setting_value(
            store,
            cache,
            "email_postmark_server_token",
            now,
        )?
        .filter(|value| !value.trim().is_empty()),
        email_postmark_message_stream: auth_setting_value(
            store,
            cache,
            "email_postmark_message_stream",
            now,
        )?
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "outbound".to_string()),
        email_app_name: auth_setting_value(store, cache, "email_app_name", now)?
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "Lux".to_string()),
        email_from_name: auth_setting_value(store, cache, "email_from_name", now)?
            .filter(|value| !value.trim().is_empty()),
    })
}

fn auth_setting_value(
    store: &Store,
    cache: &SharedSchemaCache,
    key: &str,
    now: Instant,
) -> Result<Option<String>, String> {
    let value = find_row_by_field(store, cache, SETTINGS_TABLE, "key", key, now)?
        .and_then(|row| row.get("value").cloned());
    if key == secrets::EMAIL_POSTMARK_TOKEN_KEY {
        value
            .map(|stored| secrets::open(store, SETTINGS_TABLE, "value", key, &stored))
            .transpose()
    } else {
        Ok(value)
    }
}

fn parse_setting_bool(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn optional_setting_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.trim().to_string()),
        Value::Null => Some(String::new()),
        _ => None,
    }
}

fn optional_string_list_setting(value: &Value) -> Option<Vec<String>> {
    match value {
        Value::Null => Some(Vec::new()),
        Value::String(value) => Some(parse_redirect_allow_list(value)),
        Value::Array(values) => values
            .iter()
            .map(|value| value.as_str().map(|s| s.trim().to_string()))
            .collect::<Option<Vec<_>>>()
            .map(|values| {
                values
                    .into_iter()
                    .filter(|value| !value.is_empty())
                    .collect()
            }),
        _ => None,
    }
}

fn parse_redirect_allow_list(value: &str) -> Vec<String> {
    value
        .split([',', '\n'])
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
}

fn validate_auth_email_settings(
    settings: &AuthSettings,
    managed_email: Option<&AuthManagedEmailConfig>,
) -> Result<(), String> {
    if let Some(managed) = managed_email {
        if managed.provider.trim().eq_ignore_ascii_case("postmark")
            && managed
                .postmark_server_token
                .as_deref()
                .unwrap_or("")
                .is_empty()
        {
            return Err("managed postmark email delivery requires a server token".to_string());
        }
        return Ok(());
    }
    match settings.email_provider.as_str() {
        "console" | "log" => Ok(()),
        "postmark" => {
            if settings.email_from.as_deref().unwrap_or("").is_empty() {
                return Err("postmark email delivery requires email_from".to_string());
            }
            if settings
                .email_postmark_server_token
                .as_deref()
                .unwrap_or("")
                .is_empty()
            {
                return Err(
                    "postmark email delivery requires email_postmark_server_token".to_string(),
                );
            }
            Ok(())
        }
        _ => Err("unsupported email_provider".to_string()),
    }
}

fn consume_flow_token<F>(
    store: &Store,
    cache: &SharedSchemaCache,
    kind: &str,
    token: &str,
    now: Instant,
    validate: F,
) -> Result<HashMap<String, String>, (u16, &'static str, String)>
where
    F: FnOnce(&HashMap<String, String>) -> Result<(), (u16, &'static str, String)>,
{
    let _guard = FLOW_TOKEN_CONSUME_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| {
            error(
                500,
                "Internal Server Error",
                "auth flow token lock poisoned",
            )
        })?;
    let token_hash = hash_secret(token);
    let Some(existing) = find_row_by_field(
        store,
        cache,
        FLOW_TOKENS_TABLE,
        "token_hash",
        &token_hash,
        now,
    )
    .map_err(|e| error(400, "Bad Request", &e))?
    else {
        return Err(error(400, "Bad Request", "invalid or expired token"));
    };
    if existing.get("type").map(String::as_str) != Some(kind) {
        return Err(error(400, "Bad Request", "invalid token type"));
    }
    if existing
        .get("consumed_at")
        .map(|value| !value.is_empty() && value != "0")
        .unwrap_or(false)
    {
        return Err(error(400, "Bad Request", "token already consumed"));
    }
    let expires_at = existing
        .get("expires_at")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    let now_sec = unix_seconds();
    if expires_at <= now_sec {
        return Err(error(400, "Bad Request", "invalid or expired token"));
    }
    validate(&existing)?;
    let consumed_at = now_sec.to_string();
    let expires_at_s = expires_at.to_string();
    let rows = tables::table_update_where_returning_ttl(
        store,
        cache,
        FLOW_TOKENS_TABLE,
        &[("consumed_at", consumed_at.as_str())],
        &[
            "token_hash",
            "=",
            &token_hash,
            "AND",
            "type",
            "=",
            kind,
            "AND",
            "expires_at",
            "=",
            &expires_at_s,
            "AND",
            "consumed_at",
            "IS",
            "NULL",
        ],
        None,
        now,
    )
    .map_err(|e| error(400, "Bad Request", &e))?;
    if rows.len() != 1 {
        return Err(error(400, "Bad Request", "token already consumed"));
    }
    Ok(rows
        .into_iter()
        .next()
        .unwrap_or_default()
        .into_iter()
        .collect())
}

fn form_body(items: &[(&str, &str)]) -> String {
    items
        .iter()
        .map(|(k, v)| format!("{}={}", url_encode(k), url_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn parse_form_urlencoded(body: &str) -> Vec<(String, String)> {
    body.split('&')
        .filter(|pair| !pair.is_empty())
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            let key = parts.next()?;
            let value = parts.next().unwrap_or("");
            Some((url_decode(key), url_decode(value)))
        })
        .collect()
}

fn url_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => match u8::from_str_radix(&value[i + 1..i + 3], 16) {
                Ok(byte) => {
                    out.push(byte);
                    i += 3;
                }
                Err(_) => {
                    out.push(b'%');
                    i += 1;
                }
            },
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn sanitize_header_value(value: &str) -> String {
    value.replace(['\r', '\n'], "")
}

/// A user is anonymous when their app metadata records the anonymous provider
/// (set by `signin_anonymous`). Single source of truth for the flag.
fn row_is_anonymous(row: &HashMap<String, String>) -> bool {
    parse_json_string(row.get("raw_app_meta_data"))
        .get("provider")
        .and_then(Value::as_str)
        == Some("anonymous")
}

fn user_map_json(row: &HashMap<String, String>) -> Value {
    let app_metadata = parse_json_string(row.get("raw_app_meta_data"));
    let is_anonymous = row_is_anonymous(row);
    json!({
        "id": row.get("id").cloned().unwrap_or_default(),
        "email": row.get("email").cloned().unwrap_or_default(),
        "phone": row.get("phone").cloned().unwrap_or_default(),
        "email_confirmed_at": parse_optional_int(row.get("email_confirmed_at")),
        "phone_confirmed_at": parse_optional_int(row.get("phone_confirmed_at")),
        "last_sign_in_at": parse_optional_int(row.get("last_sign_in_at")),
        "created_at": parse_optional_int(row.get("created_at")),
        "updated_at": parse_optional_int(row.get("updated_at")),
        "user_metadata": parse_json_string(row.get("raw_user_meta_data")),
        "app_metadata": app_metadata,
        "is_anonymous": is_anonymous,
    })
}

fn oauth_provider_id(provider: &str, provider_user_id: &str) -> String {
    format!("{provider}:{provider_user_id}")
}

fn oauth_identity_data(
    provider: &str,
    provider_user_id: &str,
    email: &str,
    identity_data: Value,
) -> String {
    let mut payload = match identity_data {
        Value::Object(map) => Value::Object(map),
        _ => json!({}),
    };
    if let Value::Object(map) = &mut payload {
        map.insert("provider".to_string(), Value::String(provider.to_string()));
        map.insert(
            "provider_id".to_string(),
            Value::String(provider_user_id.to_string()),
        );
        map.insert("email".to_string(), Value::String(email.to_string()));
    }
    payload.to_string()
}

fn app_metadata_with_provider(existing: Option<&str>, provider: &str) -> String {
    let mut value = existing
        .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
        .unwrap_or_else(|| json!({}));
    let Some(map) = value.as_object_mut() else {
        return json!({"provider":provider,"providers":[provider]}).to_string();
    };

    map.insert("provider".to_string(), Value::String(provider.to_string()));
    let mut providers = map
        .get("providers")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|value| value.as_str().map(str::to_string))
        .collect::<Vec<_>>();
    if !providers.iter().any(|item| item == provider) {
        providers.push(provider.to_string());
    }
    map.insert(
        "providers".to_string(),
        Value::Array(providers.into_iter().map(Value::String).collect()),
    );
    value.to_string()
}

pub(crate) fn find_row_by_field(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    field: &str,
    value: &str,
    now: Instant,
) -> Result<Option<HashMap<String, String>>, String> {
    let plan = SelectPlan {
        table: table.to_string(),
        alias: None,
        projections: Vec::new(),
        aggregates: Vec::new(),
        joins: Vec::new(),
        conditions: vec![WhereClause::single(
            field.to_string(),
            CmpOp::Eq,
            value.to_string(),
        )],
        group_by: Vec::new(),
        having: Vec::new(),
        near: None,
        order_by: None,
        limit: Some(1),
        offset: None,
        decrypt_authorized: true,
    };
    match tables::table_select(store, cache, &plan, now)? {
        SelectResult::Rows(rows) => Ok(rows
            .into_iter()
            .next()
            .map(|row| row.into_iter().collect::<HashMap<_, _>>())),
        SelectResult::Aggregate(_) => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// Grant storage + enforcement (the GRANT language)
// ---------------------------------------------------------------------------

/// Store a grant (one row per scope) in `auth.grants`, replacing any existing.
fn ensure_grants_table(
    store: &Store,
    cache: &SharedSchemaCache,
    now: Instant,
) -> Result<(), String> {
    create_table_if_missing(
        store,
        cache,
        GRANTS_TABLE,
        &[
            "id STR PRIMARY KEY,",
            "tbl STR,",
            "scope STR,",
            "predicate STR,",
            "created_at INT",
        ],
        now,
    )
}

pub(crate) fn put_grant(
    store: &Store,
    cache: &SharedSchemaCache,
    grant: &crate::grants::Grant,
    now: Instant,
) -> Result<(), String> {
    ensure_grants_table(store, cache, now)?;
    let created = unix_seconds().to_string();
    for scope in &grant.scopes {
        let id = format!("{}:{}", grant.table, scope.as_str());
        let predicate = match load_grant_predicate(store, cache, &grant.table, *scope, now)? {
            Some(mut predicate) => {
                predicate.append_alternatives(&grant.predicate);
                predicate
            }
            None => grant.predicate.clone(),
        };
        validate_grant_predicate_for_schema(store, cache, &grant.table, &predicate, now)?;
        let predicate = crate::grants::predicate_to_string(&predicate);
        let _ =
            tables::table_delete_where(store, cache, GRANTS_TABLE, &["id", "=", id.as_str()], now);
        tables::table_insert(
            store,
            cache,
            GRANTS_TABLE,
            &[
                ("id", id.as_str()),
                ("tbl", grant.table.as_str()),
                ("scope", scope.as_str()),
                ("predicate", predicate.as_str()),
                ("created_at", created.as_str()),
            ],
            now,
        )?;
    }
    Ok(())
}

fn validate_grant_predicate_for_schema(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    predicate: &crate::grants::Predicate,
    now: Instant,
) -> Result<(), String> {
    let Ok(schema) = tables::load_schema(store, cache, table, now) else {
        return Ok(());
    };
    validate_grant_predicate_columns(store, cache, table, &schema, predicate, now)
}

fn validate_grant_predicate_columns(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    schema: &[tables::FieldDef],
    predicate: &crate::grants::Predicate,
    now: Instant,
) -> Result<(), String> {
    for clause in predicate.clauses() {
        for condition in clause {
            validate_grant_condition_columns(store, cache, table, schema, condition, now)?;
        }
    }
    Ok(())
}

fn validate_grant_condition_columns(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    schema: &[tables::FieldDef],
    condition: &crate::grants::Condition,
    now: Instant,
) -> Result<(), String> {
    match condition {
        crate::grants::Condition::Cmp { column, op, .. } => {
            validate_grant_column_filter(table, schema, column, op)
        }
        crate::grants::Condition::InSubquery {
            column,
            negated,
            subquery,
        } => {
            validate_grant_column_filter(
                table,
                schema,
                column,
                if *negated { "NOT IN" } else { "IN" },
            )?;
            if let Ok(inner_schema) = tables::load_schema(store, cache, &subquery.table, now) {
                validate_grant_predicate_columns(
                    store,
                    cache,
                    &subquery.table,
                    &inner_schema,
                    &subquery.inner,
                    now,
                )?;
            }
            Ok(())
        }
    }
}

fn validate_grant_column_filter(
    table: &str,
    schema: &[tables::FieldDef],
    column: &str,
    op: &str,
) -> Result<(), String> {
    if let Some((root, rest)) = column.split_once('.') {
        if !rest.is_empty() && schema.iter().any(|f| f.name == root && f.encrypted) {
            return Err(format!(
                "ERR encrypted column '{}' in grant on '{}' does not support JSON path filters",
                root, table
            ));
        }
    }
    let bare = column.split('.').next().unwrap_or(column);
    let Some(field) = schema.iter().find(|f| f.name == bare) else {
        return Ok(());
    };
    if !field.encrypted {
        return Ok(());
    }
    if op == "=" && field.searchable {
        return Ok(());
    }
    if op == "=" {
        return Err(format!(
            "ERR encrypted column '{}' in grant on '{}' must be SEARCHABLE for equality filters",
            field.name, table
        ));
    }
    Err(format!(
        "ERR encrypted column '{}' in grant on '{}' only supports equality filters when SEARCHABLE",
        field.name, table
    ))
}

/// Remove a grant for (table, scope). Returns true if one existed.
pub(crate) fn delete_grant(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    scope: crate::grants::Scope,
    now: Instant,
) -> Result<bool, String> {
    let id = format!("{}:{}", table, scope.as_str());
    let n = tables::table_delete_where(store, cache, GRANTS_TABLE, &["id", "=", id.as_str()], now)?;
    Ok(n > 0)
}

fn load_grant_predicate(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    scope: crate::grants::Scope,
    now: Instant,
) -> Result<Option<crate::grants::Predicate>, String> {
    let id = format!("{}:{}", table, scope.as_str());
    // A missing grants table means no grants exist yet -> deny-by-default.
    let row = match find_row_by_field(store, cache, GRANTS_TABLE, "id", &id, now) {
        Ok(r) => r,
        Err(e) if e.contains("does not exist") => return Ok(None),
        Err(e) => return Err(e),
    };
    match row {
        Some(row) => {
            let pred_str = row.get("predicate").cloned().unwrap_or_default();
            let toks: Vec<&str> = pred_str.split_whitespace().collect();
            Ok(Some(crate::grants::parse_predicate(&toks)?))
        }
        None => Ok(None),
    }
}

fn resolve_for_principal(
    pred: &crate::grants::Predicate,
    principal: &AuthPrincipal,
) -> Result<Vec<Vec<crate::grants::ResolvedCondition>>, String> {
    crate::grants::resolve_clauses(pred, &principal.user_id, |claim| match claim {
        "role" => Some(principal.role.clone()),
        "email" => Some(principal.email.clone()),
        "sub" | "uid" => Some(principal.user_id.clone()),
        _ => None,
    })
}

/// Convert a subquery's enforced inner conditions into query `WhereClause`s.
fn inner_conds_to_where(
    conds: &[crate::grants::EnforcedCondition],
) -> Result<Vec<WhereClause>, String> {
    use crate::grants::EnforcedCondition;
    let mut out = Vec::new();
    for cond in conds {
        match cond {
            EnforcedCondition::Cmp(rc) => {
                out.push(WhereClause::single(
                    rc.column.clone(),
                    tables::parse_cmp_op(&rc.op)?,
                    rc.value.clone(),
                ));
            }
            EnforcedCondition::InSet {
                column,
                negated,
                values,
            } => {
                if values.is_empty() {
                    if !negated {
                        out.push(WhereClause::single(
                            column.clone(),
                            tables::CmpOp::IsNull,
                            String::new(),
                        ));
                        out.push(WhereClause::single(
                            column.clone(),
                            tables::CmpOp::IsNotNull,
                            String::new(),
                        ));
                    }
                } else {
                    out.push(WhereClause::in_list(
                        column.clone(),
                        if *negated {
                            tables::CmpOp::NotIn
                        } else {
                            tables::CmpOp::In
                        },
                        values.clone(),
                    ));
                }
            }
        }
    }
    Ok(out)
}

/// Execute any subquery conditions (once) against the store, turning resolved
/// conditions into fully-enforced ones (subqueries become membership sets).
fn execute_resolved(
    store: &Store,
    cache: &SharedSchemaCache,
    conds: Vec<crate::grants::ResolvedCondition>,
    now: Instant,
) -> Result<Vec<crate::grants::EnforcedCondition>, String> {
    use crate::grants::{EnforcedCondition, ResolvedCondition};
    let mut out = Vec::with_capacity(conds.len());
    for c in conds {
        match c {
            ResolvedCondition::Cmp(rc) => out.push(EnforcedCondition::Cmp(rc)),
            ResolvedCondition::InSubqueryResolved {
                column,
                negated,
                inner_table,
                inner_projected,
                inner_conds,
            } => {
                // Defense in depth: a grant subquery may never read auth tables.
                if let Some(err) = reserved_table_access_error(&inner_table) {
                    return Err(err);
                }
                let inner_enforced = execute_resolved(store, cache, inner_conds, now)?;
                let where_clauses = inner_conds_to_where(&inner_enforced)?;
                let values = tables::scan_projected_column(
                    store,
                    cache,
                    &inner_table,
                    &where_clauses,
                    &inner_projected,
                    now,
                )?;
                out.push(EnforcedCondition::InSet {
                    column,
                    negated,
                    values,
                });
            }
        }
    }
    Ok(out)
}

fn execute_resolved_clauses(
    store: &Store,
    cache: &SharedSchemaCache,
    clauses: Vec<Vec<crate::grants::ResolvedCondition>>,
    now: Instant,
) -> Result<Vec<Vec<crate::grants::EnforcedCondition>>, String> {
    clauses
        .into_iter()
        .map(|conds| execute_resolved(store, cache, conds, now))
        .collect()
}

fn collect_resolved_subquery_tables(
    clauses: &[Vec<crate::grants::ResolvedCondition>],
    tables: &mut Vec<String>,
) {
    for conds in clauses {
        for condition in conds {
            if let crate::grants::ResolvedCondition::InSubqueryResolved {
                inner_table,
                inner_conds,
                ..
            } = condition
            {
                if !tables.iter().any(|table| table == inner_table) {
                    tables.push(inner_table.clone());
                }
                collect_resolved_subquery_tables(std::slice::from_ref(inner_conds), tables);
            }
        }
    }
}

/// Render enforced conditions into a WHERE fragment that the query path ANDs
/// onto the caller's own WHERE (RLS `USING`). `IN`/`NOT IN` sets render as
/// `col IN ( a b c )` - the engine's WHERE parser already handles these.
///
/// Empty-set handling, both expressed *within* the rendered string so the read
/// and write paths need no special casing:
/// - empty positive set (`IN ( )` is invalid, and the caller may see no rows):
///   render an always-false, type-agnostic contradiction `col IS NULL AND col
///   IS NOT NULL` so the query matches nothing.
/// - empty negated set (`NOT IN ( )` matches everything): omit it.
fn render_enforced_clause(conds: &[crate::grants::EnforcedCondition]) -> String {
    use crate::grants::EnforcedCondition;
    let mut parts: Vec<String> = Vec::new();
    for c in conds {
        match c {
            EnforcedCondition::Cmp(rc) => {
                parts.push(format!("{} {} {}", rc.column, rc.op, rc.value))
            }
            EnforcedCondition::InSet {
                column,
                negated,
                values,
            } => {
                if values.is_empty() {
                    if !negated {
                        parts.push(format!("{column} IS NULL AND {column} IS NOT NULL"));
                    }
                    // empty NOT IN matches all rows -> nothing to add
                } else {
                    let kw = if *negated { "NOT IN" } else { "IN" };
                    parts.push(format!("{column} {kw} ( {} )", values.join(" ")));
                }
            }
        }
    }
    parts.join(" AND ")
}

fn render_enforced_or_clauses(
    clauses: &[Vec<crate::grants::EnforcedCondition>],
) -> Result<String, String> {
    use crate::grants::EnforcedCondition;
    if let Some(cond) = collapse_same_column_or_clauses(clauses) {
        return Ok(render_enforced_clause(&[cond]));
    }
    let mut branches = Vec::new();
    for clause in clauses {
        if clause.is_empty() {
            return Ok(String::new());
        }
        let mut parts = Vec::new();
        let mut branch_is_false = false;
        for condition in clause {
            match condition {
                EnforcedCondition::Cmp(rc) => {
                    parts.push(format!("{} {} {}", rc.column, rc.op, rc.value));
                }
                EnforcedCondition::InSet {
                    column,
                    negated,
                    values,
                } => {
                    if values.is_empty() {
                        if *negated {
                            continue;
                        }
                        branch_is_false = true;
                        break;
                    }
                    let kw = if *negated { "NOT IN" } else { "IN" };
                    parts.push(format!("{column} {kw} ( {} )", values.join(" ")));
                }
            }
        }
        if branch_is_false {
            continue;
        }
        if parts.is_empty() {
            return Ok(String::new());
        }
        if parts.len() != 1 {
            return Err(
                "OR grants with multi-condition branches are not supported yet".to_string(),
            );
        }
        branches.push(parts.remove(0));
    }
    if branches.is_empty() {
        let Some(first_column) = clauses
            .iter()
            .flat_map(|clause| clause.iter())
            .map(|condition| match condition {
                EnforcedCondition::Cmp(rc) => rc.column.as_str(),
                EnforcedCondition::InSet { column, .. } => column.as_str(),
            })
            .next()
        else {
            return Ok(String::new());
        };
        return Ok(format!(
            "{first_column} IS NULL AND {first_column} IS NOT NULL"
        ));
    }
    Ok(branches.join(" OR "))
}

fn collapse_same_column_or_clauses(
    clauses: &[Vec<crate::grants::EnforcedCondition>],
) -> Option<crate::grants::EnforcedCondition> {
    use crate::grants::EnforcedCondition;
    let mut column: Option<String> = None;
    let mut values: Vec<String> = Vec::new();
    for clause in clauses {
        if clause.len() != 1 {
            return None;
        }
        match &clause[0] {
            EnforcedCondition::Cmp(rc) if rc.op == "=" => {
                if column.as_deref().is_some_and(|c| c != rc.column) {
                    return None;
                }
                column.get_or_insert_with(|| rc.column.clone());
                if !values.iter().any(|value| value == &rc.value) {
                    values.push(rc.value.clone());
                }
            }
            EnforcedCondition::InSet {
                column: c,
                negated: false,
                values: set,
            } => {
                if column.as_deref().is_some_and(|column| column != c) {
                    return None;
                }
                column.get_or_insert_with(|| c.clone());
                for value in set {
                    if !values.iter().any(|existing| existing == value) {
                        values.push(value.clone());
                    }
                }
            }
            _ => return None,
        }
    }
    Some(EnforcedCondition::InSet {
        column: column?,
        negated: false,
        values,
    })
}

fn render_enforced_clauses(
    clauses: &[Vec<crate::grants::EnforcedCondition>],
) -> Result<String, String> {
    if clauses.len() == 1 {
        return Ok(render_enforced_clause(&clauses[0]));
    }
    render_enforced_or_clauses(clauses)
}

/// Resolve + execute the grant for `(table, scope)` into enforced conditions.
/// `Ok(None)` means no grant exists (deny-by-default).
fn enforced_conds(
    store: &Store,
    cache: &SharedSchemaCache,
    principal: &AuthPrincipal,
    table: &str,
    scope: crate::grants::Scope,
    now: Instant,
) -> Result<Option<Vec<Vec<crate::grants::EnforcedCondition>>>, String> {
    let Some(pred) = load_grant_predicate(store, cache, table, scope, now)? else {
        return Ok(None);
    };
    let resolved = resolve_for_principal(&pred, principal)?;
    Ok(Some(execute_resolved_clauses(store, cache, resolved, now)?))
}

/// Resolve the READ grant for `principal` into a WHERE filter fragment that
/// scopes a query to the rows the grant allows (RLS `USING` semantics). The
/// caller ANDs this onto the query's own WHERE, so a token user only ever sees
/// their permitted rows. `Err` when no read grant exists (deny-by-default); an
/// unconditional grant yields an empty string (no extra filter).
pub(crate) fn read_filter(
    store: &Store,
    cache: &SharedSchemaCache,
    principal: &AuthPrincipal,
    table: &str,
    now: Instant,
) -> Result<String, String> {
    let Some(conds) = enforced_conds(
        store,
        cache,
        principal,
        table,
        crate::grants::Scope::Read,
        now,
    )?
    else {
        return Err(format!("no read access to '{table}'"));
    };
    render_enforced_clauses(&conds)
}

/// Like `read_filter`, but returns the resolved conditions as structured tuples
/// (column, op, value) instead of a rendered string. Used by the `.live()` path,
/// which merges them into the subscription's own `where_conditions` so both the
/// initial snapshot and streamed events are scoped to the grant.
#[cfg(test)]
pub(crate) fn read_filter_conds(
    store: &Store,
    cache: &SharedSchemaCache,
    principal: &AuthPrincipal,
    table: &str,
    now: Instant,
) -> Result<Vec<crate::grants::EnforcedCondition>, String> {
    let Some(conds) = enforced_conds(
        store,
        cache,
        principal,
        table,
        crate::grants::Scope::Read,
        now,
    )?
    else {
        return Err(format!("no read access to '{table}'"));
    };
    if conds.len() != 1 {
        return Err(
            "read grant has OR alternatives; use read_filter for expression rendering".to_string(),
        );
    }
    Ok(conds.into_iter().next().unwrap_or_default())
}

/// Return tables consulted by READ-grant membership subqueries. Live queries
/// subscribe to these tables as authorization dependencies so gaining or losing
/// membership wakes the query even when its base table did not change.
pub(crate) fn read_filter_dependencies(
    store: &Store,
    cache: &SharedSchemaCache,
    principal: &AuthPrincipal,
    table: &str,
    now: Instant,
) -> Result<Vec<String>, String> {
    let Some(pred) = load_grant_predicate(store, cache, table, crate::grants::Scope::Read, now)?
    else {
        return Err(format!("no read access to '{table}'"));
    };
    let resolved = resolve_for_principal(&pred, principal)?;
    let mut tables = Vec::new();
    collect_resolved_subquery_tables(&resolved, &mut tables);
    Ok(tables)
}

/// Enforce a WRITE grant on a new/updated row (WITH CHECK).
pub(crate) fn check_write_row(
    store: &Store,
    cache: &SharedSchemaCache,
    principal: &AuthPrincipal,
    table: &str,
    row_value: impl Fn(&str) -> Option<String>,
    now: Instant,
) -> Result<(), String> {
    let Some(conds) = enforced_conds(
        store,
        cache,
        principal,
        table,
        crate::grants::Scope::Write,
        now,
    )?
    else {
        return Err(format!("no write access to '{table}'"));
    };
    if conds
        .iter()
        .any(|clause| crate::grants::enforced_row_satisfies(clause, &row_value))
    {
        Ok(())
    } else {
        Err(format!("row not permitted by write grant on '{table}'"))
    }
}

/// WITH CHECK on UPDATE: the values an UPDATE *sets* must not move a row out of
/// the write grant (e.g. you can't change a row you own to set `owner` to
/// someone else). The USING filter already guarantees the existing row is in
/// scope, so only grant conditions on columns being set can be violated -
/// conditions on untouched columns are unchanged and remain valid. `Err` when a
/// set value breaks the grant, or when no write grant exists.
pub(crate) fn check_update_set(
    store: &Store,
    cache: &SharedSchemaCache,
    principal: &AuthPrincipal,
    table: &str,
    set_fields: &[(&str, &str)],
    now: Instant,
) -> Result<(), String> {
    let Some(conds) = enforced_conds(
        store,
        cache,
        principal,
        table,
        crate::grants::Scope::Write,
        now,
    )?
    else {
        return Err(format!("no write access to '{table}'"));
    };
    if conds
        .iter()
        .any(|clause| crate::grants::enforced_set_satisfies(clause, set_fields))
    {
        Ok(())
    } else {
        Err(format!(
            "update would move a row outside the write grant on '{table}'"
        ))
    }
}

/// Resolve the WRITE grant for `principal` into a WHERE filter fragment that
/// scopes an UPDATE/DELETE to the rows the grant allows (RLS `USING`). The
/// caller ANDs this onto the statement's WHERE so only in-scope rows are
/// touched. `Err` when no write grant exists (deny-by-default). (INSERT/UPSERT
/// use `check_write_row` for WITH CHECK on the new row.)
pub(crate) fn write_filter(
    store: &Store,
    cache: &SharedSchemaCache,
    principal: &AuthPrincipal,
    table: &str,
    now: Instant,
) -> Result<String, String> {
    let Some(conds) = enforced_conds(
        store,
        cache,
        principal,
        table,
        crate::grants::Scope::Write,
        now,
    )?
    else {
        return Err(format!("no write access to '{table}'"));
    };
    render_enforced_clauses(&conds)
}

fn find_rows_by_field(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    field: &str,
    value: &str,
    now: Instant,
) -> Result<Vec<HashMap<String, String>>, String> {
    let plan = SelectPlan {
        table: table.to_string(),
        alias: None,
        projections: Vec::new(),
        aggregates: Vec::new(),
        joins: Vec::new(),
        conditions: vec![WhereClause::single(
            field.to_string(),
            CmpOp::Eq,
            value.to_string(),
        )],
        group_by: Vec::new(),
        having: Vec::new(),
        near: None,
        order_by: None,
        limit: Some(1000),
        offset: None,
        decrypt_authorized: true,
    };
    match tables::table_select(store, cache, &plan, now)? {
        SelectResult::Rows(rows) => Ok(rows
            .into_iter()
            .map(|row| row.into_iter().collect::<HashMap<_, _>>())
            .collect()),
        SelectResult::Aggregate(_) => Ok(Vec::new()),
    }
}

fn hash_password(password: &str) -> Result<String, String> {
    let password = password.to_string();
    run_password_work(move || {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|e| e.to_string())
    })
}

#[cfg(test)]
fn verify_password(password: &str, hash: &str) -> Result<bool, String> {
    verify_password_state(password, hash).map(|state| state != PasswordVerification::Invalid)
}

fn verify_password_state(password: &str, hash: &str) -> Result<PasswordVerification, String> {
    let password = password.to_string();
    let hash = hash.to_string();
    run_password_work(move || {
        if is_bcrypt_hash(&hash) {
            return bcrypt::verify(&password, &hash)
                .map(|valid| {
                    if valid {
                        PasswordVerification::ValidNeedsRehash
                    } else {
                        PasswordVerification::Invalid
                    }
                })
                .map_err(|e| e.to_string());
        }
        let parsed = PasswordHash::new(&hash).map_err(|e| e.to_string())?;
        let valid = Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok();
        Ok(if valid {
            PasswordVerification::Valid
        } else {
            PasswordVerification::Invalid
        })
    })
}

fn is_bcrypt_hash(hash: &str) -> bool {
    hash.starts_with("$2a$") || hash.starts_with("$2b$") || hash.starts_with("$2y$")
}

fn run_password_work<T, F>(work: F) -> T
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == RuntimeFlavor::MultiThread => block_in_place(work),
        _ => work(),
    }
}

fn run_async_work<T, F>(future: F) -> T
where
    T: Send + 'static,
    F: Future<Output = T> + Send + 'static,
{
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == RuntimeFlavor::MultiThread => {
            block_in_place(|| handle.block_on(future))
        }
        Ok(_) => std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("failed to build auth email runtime")
                .block_on(future)
        })
        .join()
        .expect("auth email runtime thread panicked"),
        Err(_) => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build auth email runtime")
            .block_on(future),
    }
}

fn hash_secret(secret: &str) -> String {
    let digest = Sha256::digest(secret.as_bytes());
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn oauth_pkce_challenge(
    params: &[(String, String)],
) -> Result<Option<String>, (u16, &'static str, String)> {
    let Some(challenge) = get_param(params, "code_challenge") else {
        return Ok(None);
    };
    if challenge.len() != 43
        || !challenge
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(error(400, "Bad Request", "invalid PKCE code_challenge"));
    }
    if get_param(params, "code_challenge_method") != Some("S256") {
        return Err(error(
            400,
            "Bad Request",
            "PKCE code_challenge_method must be S256",
        ));
    }
    Ok(Some(challenge.to_string()))
}

fn verify_oauth_pkce(
    flow: &HashMap<String, String>,
    request: &Value,
) -> Result<(), (u16, &'static str, String)> {
    let metadata = flow
        .get("metadata")
        .and_then(|value| serde_json::from_str::<Value>(value).ok())
        .unwrap_or_else(|| json!({}));
    let Some(challenge) = metadata.get("code_challenge").and_then(Value::as_str) else {
        return Ok(());
    };
    let verifier = required_string(request, "code_verifier")?;
    if !(43..=128).contains(&verifier.len())
        || !verifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
    {
        return Err(error(400, "Bad Request", "invalid PKCE code_verifier"));
    }
    let digest = Sha256::digest(verifier.as_bytes());
    let calculated = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
    if !constant_time_eq(calculated.as_bytes(), challenge.as_bytes()) {
        return Err(error(400, "Bad Request", "PKCE verification failed"));
    }
    Ok(())
}

fn random_token(bytes: usize) -> String {
    let mut raw = vec![0u8; bytes];
    OsRng.fill_bytes(&mut raw);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
}

pub(crate) fn random_id(prefix: &str) -> String {
    format!("{prefix}_{}", random_token(18))
}

fn key_prefix(key: &str) -> String {
    key.chars().take(12).collect()
}

pub(crate) fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn parse_json(body: &str) -> Result<Value, (u16, &'static str, String)> {
    serde_json::from_str(body).map_err(|_| error(400, "Bad Request", "invalid json"))
}

fn required_string<'a>(
    value: &'a Value,
    field: &str,
) -> Result<&'a str, (u16, &'static str, String)> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| error(400, "Bad Request", &format!("missing {field}")))
}

fn normalize_email(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

fn parse_optional_int(value: Option<&String>) -> Value {
    value
        .and_then(|value| {
            if value.is_empty() || value == "0" {
                None
            } else {
                value.parse::<i64>().ok()
            }
        })
        .map(Value::from)
        .unwrap_or(Value::Null)
}

fn parse_bool(value: Option<&String>) -> bool {
    matches!(
        value.map(|value| value.as_str()),
        Some("true") | Some("1") | Some("TRUE") | Some("True")
    )
}

fn parse_json_string(value: Option<&String>) -> Value {
    value
        .and_then(|value| serde_json::from_str(value).ok())
        .unwrap_or_else(|| json!({}))
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn bearer_token(headers: &[(String, String)]) -> Option<&str> {
    header_value(headers, "authorization").and_then(|auth| auth.strip_prefix("Bearer "))
}

fn get_param<'a>(params: &'a [(String, String)], key: &str) -> Option<&'a str> {
    params
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

fn url_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => {
                use std::fmt::Write as _;
                let _ = write!(out, "%{byte:02X}");
            }
        }
    }
    out
}

fn ok(value: Value) -> (u16, &'static str, String) {
    (200, "OK", value.to_string())
}

fn error(status: u16, status_text: &'static str, message: &str) -> (u16, &'static str, String) {
    (status, status_text, json!({"error": message}).to_string())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        let mut _acc = 0u8;
        for &byte in a {
            _acc |= byte;
        }
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
#[path = "auth/tests.rs"]
mod tests;

#[cfg(test)]
mod redirect_validation_tests {
    use super::*;

    fn settings(site_url: &str, allow: &[&str]) -> AuthSettings {
        AuthSettings {
            email_confirmation_required: false,
            flow_token_ttl: Duration::from_secs(3600),
            site_url: site_url.to_string(),
            redirect_allow_list: allow.iter().map(|s| s.to_string()).collect(),
            email_provider: "console".to_string(),
            email_from: None,
            email_reply_to: None,
            email_postmark_server_token: None,
            email_postmark_message_stream: "outbound".to_string(),
            email_app_name: "Lux".to_string(),
            email_from_name: None,
        }
    }

    /// The allow list used to accept a custom scheme that `authorize` then
    /// refused, so the setting looked configured and failed at sign-in on a
    /// phone. Native OAuth needs custom schemes, and the allow list is the
    /// security boundary, so an explicitly listed one is honored.
    #[test]
    fn allow_listed_custom_scheme_is_accepted() {
        let s = settings("http://localhost:5990", &["vigil://auth/callback"]);
        assert_eq!(
            validate_auth_redirect("vigil://auth/callback", &s).unwrap(),
            "vigil://auth/callback"
        );
    }

    #[test]
    fn unlisted_custom_scheme_is_still_refused() {
        let s = settings("http://localhost:5990", &["vigil://auth/callback"]);
        let err = validate_auth_redirect("evil://auth/callback", &s).unwrap_err();
        assert!(err.contains("allow list"), "unexpected error: {err}");

        // And with no allow list at all.
        let s = settings("http://localhost:5990", &[]);
        assert!(validate_auth_redirect("vigil://auth/callback", &s).is_err());
    }

    /// A custom scheme matches only exactly: it has no origin to compare, so
    /// prefix games must not get through.
    #[test]
    fn custom_scheme_matches_exactly_not_by_prefix() {
        let s = settings("http://localhost:5990", &["vigil://auth/callback"]);
        for attempt in [
            "vigil://auth/callback/../elsewhere",
            "vigil://auth/callbackevil",
            "vigil://evil",
            "vigil://auth",
        ] {
            assert!(
                validate_auth_redirect(attempt, &s).is_err(),
                "{attempt} must not match the allow-listed scheme"
            );
        }
    }

    #[test]
    fn http_and_relative_redirects_still_behave() {
        let s = settings("http://localhost:5990", &["http://localhost:3000/cb"]);
        assert!(validate_auth_redirect("/dashboard", &s).is_ok());
        assert!(validate_auth_redirect("http://localhost:5990/anything", &s).is_ok());
        assert!(validate_auth_redirect("http://localhost:3000/cb", &s).is_ok());
        assert!(validate_auth_redirect("http://evil.example/cb", &s).is_err());
    }
}
