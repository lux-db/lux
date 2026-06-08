use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use base64::Engine;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::runtime::RuntimeFlavor;
use tokio::task::block_in_place;

use crate::store::Store;
use crate::tables::{self, CmpOp, SelectPlan, SelectResult, SharedSchemaCache, WhereClause};
use crate::AuthConfig;

pub(crate) const USERS_TABLE: &str = "auth.users";
pub(crate) const IDENTITIES_TABLE: &str = "auth.identities";
pub(crate) const SESSIONS_TABLE: &str = "auth.sessions";
pub(crate) const KEYS_TABLE: &str = "auth.keys";
pub(crate) const SIGNING_KEYS_TABLE: &str = "auth.signing_keys";
pub(crate) const GRANTS_TABLE: &str = "auth.grants";
pub(crate) const PROVIDERS_TABLE: &str = "auth.providers";

const AUTH_SCHEMA_VERSION_KEY: &[u8] = b"_auth:schema_version";
const AUTH_SCHEMA_VERSION: &[u8] = b"1";
const OAUTH_STATE_TTL: Duration = Duration::from_secs(10 * 60);
const ACCESS_REVOKED_AFTER_PREFIX: &[u8] = b"_auth:access_revoked_after:";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ApiKeyKind {
    Publishable,
    Secret,
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
}

pub(crate) fn is_reserved_auth_table(table: &str) -> bool {
    table.starts_with("auth.")
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
        "TCREATE" | "TINSERT" | "TUPDATE" | "TDROP" | "TALTER" => args.get(1),
        "TDELETE" => args.get(2),
        _ => None,
    }
    .and_then(|raw| std::str::from_utf8(raw).ok())?;

    if is_reserved_auth_table(table) {
        Some(reserved_table_error(table))
    } else {
        None
    }
}

pub(crate) fn reserved_table_access_error(_table: &str) -> Option<String> {
    None
}

fn reserved_table_error(table: &str) -> String {
    format!(
        "ERR table '{}' is managed by Lux Auth; use /auth/v1 APIs",
        table
    )
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
            "id STR PRIMARY KEY,",
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
            "user_id STR,",
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
            "user_id STR,",
            "refresh_token_hash STR UNIQUE,",
            "refresh_token_family STR,",
            "user_agent STR,",
            "ip STR,",
            "expires_at INT,",
            "revoked_at INT,",
            "created_at INT,",
            "updated_at INT",
        ],
        now,
    )?;
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
            "user_id STR,",
            "capability STR,",
            "created_at INT,",
            "revoked_at INT",
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
            "updated_at INT",
        ],
        now,
    )?;
    store.set(AUTH_SCHEMA_VERSION_KEY, AUTH_SCHEMA_VERSION, None, now);
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
) -> Result<(), String> {
    let now = Instant::now();
    ensure_signing_key(store, cache, now)?;
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
    Ok(())
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
        ("GET", ["health"]) => ok(json!({"result":"ok"})),
        ("POST", ["signup"]) => {
            if let Err(response) = require_publishable_or_secret(headers, store, cache) {
                return response;
            }
            signup(body, headers, store, cache)
        }
        ("POST", ["token"]) => {
            if let Err(response) = require_publishable_or_secret(headers, store, cache) {
                return response;
            }
            let grant_type = get_param(params, "grant_type").unwrap_or("");
            token(body, grant_type, headers, store, cache)
        }
        ("GET", ["user"]) => user_from_bearer(headers, store, cache),
        ("POST", ["logout"]) => logout(body, headers, store, cache),
        ("GET", ["admin", "users"]) => {
            if let Err(response) = require_secret(headers, store, cache) {
                return response;
            }
            admin_list_users(store, cache)
        }
        ("POST", ["admin", "users"]) => {
            if let Err(response) = require_secret(headers, store, cache) {
                return response;
            }
            admin_create_user(body, store, cache)
        }
        ("POST", ["admin", "grants"]) => {
            if let Err(response) = require_secret(headers, store, cache) {
                return response;
            }
            admin_create_grant(body, store, cache)
        }
        ("DELETE", ["admin", "grants", grant_id]) => {
            if let Err(response) = require_secret(headers, store, cache) {
                return response;
            }
            admin_revoke_grant(grant_id, store, cache)
        }
        ("GET", ["admin", "users", user_id, "grants"]) => {
            if let Err(response) = require_secret(headers, store, cache) {
                return response;
            }
            admin_list_user_grants(user_id, store, cache)
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
    let user_id = random_id("usr");
    let password_hash = match hash_password(&password) {
        Ok(hash) => hash,
        Err(e) => return error(500, "Internal Server Error", &e),
    };
    let user_meta = parsed
        .get("data")
        .or_else(|| parsed.get("user_metadata"))
        .cloned()
        .unwrap_or_else(|| json!({}))
        .to_string();
    let app_meta = json!({"provider":"email","providers":["email"]}).to_string();

    if let Err(e) = durable_table_insert(
        store,
        cache,
        USERS_TABLE,
        &[
            ("id", user_id.as_str()),
            ("email", email.as_str()),
            ("encrypted_password", password_hash.as_str()),
            ("email_confirmed_at", &now_sec.to_string()),
            ("raw_user_meta_data", user_meta.as_str()),
            ("raw_app_meta_data", app_meta.as_str()),
            ("created_at", &now_sec.to_string()),
            ("updated_at", &now_sec.to_string()),
        ],
        now,
    ) {
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
            ("created_at", &now_sec.to_string()),
            ("updated_at", &now_sec.to_string()),
        ],
        now,
    ) {
        let _ = durable_table_delete_where(store, cache, USERS_TABLE, &["id", "=", &user_id], now);
        return error(400, "Bad Request", &e);
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
        "refresh_token" => refresh_token_grant(&parsed, headers, store, cache),
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
    match verify_password(password, password_hash) {
        Ok(true) => {}
        Ok(false) => return error(400, "Bad Request", "invalid login credentials"),
        Err(e) => return error(500, "Internal Server Error", &e),
    }
    let Some(user_id) = user.get("id") else {
        return error(500, "Internal Server Error", "auth user row is missing id");
    };
    issue_session_response(store, cache, headers, user_id, &email, now)
}

fn refresh_token_grant(
    parsed: &Value,
    headers: &[(String, String)],
    store: &Store,
    cache: &SharedSchemaCache,
) -> (u16, &'static str, String) {
    let refresh_token = match required_string(parsed, "refresh_token") {
        Ok(refresh_token) => refresh_token,
        Err(response) => return response,
    };
    let now = Instant::now();
    let token_hash = hash_secret(refresh_token);
    let Some(session) = find_row_by_field(
        store,
        cache,
        SESSIONS_TABLE,
        "refresh_token_hash",
        &token_hash,
        now,
    )
    .ok()
    .flatten() else {
        return error(401, "Unauthorized", "invalid refresh token");
    };
    if session
        .get("revoked_at")
        .map(|v| !v.is_empty() && v != "0")
        .unwrap_or(false)
    {
        return error(401, "Unauthorized", "refresh token revoked");
    }
    let expires_at = session
        .get("expires_at")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    if expires_at <= unix_seconds() {
        return error(401, "Unauthorized", "refresh token expired");
    }
    let Some(user_id) = session.get("user_id") else {
        return error(
            500,
            "Internal Server Error",
            "session row is missing user_id",
        );
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
    let now_sec = unix_seconds().to_string();
    if let Err(e) = durable_table_update_where(
        store,
        cache,
        SESSIONS_TABLE,
        &[
            ("revoked_at", now_sec.as_str()),
            ("updated_at", now_sec.as_str()),
        ],
        &[
            "id",
            "=",
            session.get("id").map(String::as_str).unwrap_or(""),
        ],
        now,
    ) {
        return error(400, "Bad Request", &e);
    }
    issue_session_response_with_family(
        store,
        cache,
        headers,
        user_id,
        &email,
        session
            .get("refresh_token_family")
            .map(String::as_str)
            .unwrap_or_else(|| session.get("id").map(String::as_str).unwrap_or("")),
        now,
    )
}

fn issue_session_response(
    store: &Store,
    cache: &SharedSchemaCache,
    headers: &[(String, String)],
    user_id: &str,
    email: &str,
    now: Instant,
) -> (u16, &'static str, String) {
    issue_session_response_with_family(store, cache, headers, user_id, email, "", now)
}

fn issue_session_response_with_family(
    store: &Store,
    cache: &SharedSchemaCache,
    headers: &[(String, String)],
    user_id: &str,
    email: &str,
    refresh_token_family: &str,
    now: Instant,
) -> (u16, &'static str, String) {
    let now_sec = unix_seconds();
    let refresh_token = random_token(32);
    let refresh_hash = hash_secret(&refresh_token);
    let session_id = random_id("ses");
    let refresh_token_family = if refresh_token_family.is_empty() {
        session_id.as_str()
    } else {
        refresh_token_family
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

    let access_token = match sign_access_token(store, cache, user_id, email, &session_id) {
        Ok(token) => token,
        Err(e) => return error(500, "Internal Server Error", &e),
    };

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

fn logout(
    body: &str,
    headers: &[(String, String)],
    store: &Store,
    cache: &SharedSchemaCache,
) -> (u16, &'static str, String) {
    let now = Instant::now();
    let now_sec = unix_seconds().to_string();
    if let Ok(claims) = claims_from_bearer(headers, store, cache) {
        let _ = revoke_session_family_access(store, cache, &claims.session_id, &now_sec, now);
        return ok(json!({"result":"OK"}));
    }

    if let Ok(parsed) = serde_json::from_str::<Value>(body) {
        if let Some(refresh_token) = parsed.get("refresh_token").and_then(Value::as_str) {
            let token_hash = hash_secret(refresh_token);
            if let Ok(Some(session)) = find_row_by_field(
                store,
                cache,
                SESSIONS_TABLE,
                "refresh_token_hash",
                &token_hash,
                now,
            ) {
                if let Some(session_id) = session.get("id") {
                    let _ = revoke_session_family_access(store, cache, session_id, &now_sec, now);
                }
            }
            return ok(json!({"result":"OK"}));
        }
    }
    error(401, "Unauthorized", "missing bearer token or refresh_token")
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
    signup(body, &[], store, cache)
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
    };
    match tables::table_select(store, cache, &plan, Instant::now()) {
        Ok(SelectResult::Rows(rows)) => {
            let providers: Vec<Value> = rows.into_iter().map(provider_row_json).collect();
            ok(json!({"providers": providers}))
        }
        Ok(SelectResult::Aggregate(_)) => ok(json!({"providers": []})),
        Err(e) => error(400, "Bad Request", &e),
    }
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
                client_secret.to_string()
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
            match durable_table_insert(
                store,
                cache,
                PROVIDERS_TABLE,
                &[
                    ("provider", provider.as_str()),
                    ("enabled", enabled.as_str()),
                    ("client_id", client_id),
                    ("client_secret", client_secret),
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
    let redirect_to = sanitize_header_value(redirect_to);
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
    let state = random_token(32);
    let state_key = oauth_state_key(&state);
    let payload = json!({
        "provider": provider,
        "redirect_to": redirect_to,
        "created_at": unix_seconds(),
    });
    store.set(
        state_key.as_bytes(),
        payload.to_string().as_bytes(),
        Some(OAUTH_STATE_TTL),
        Instant::now(),
    );

    let callback = if config.redirect_uri.is_empty() {
        default_callback_url(headers, &provider)
    } else {
        config.redirect_uri.clone()
    };
    let url = oauth_authorization_url(&config, &callback, &state);
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
    if let Some(oauth_error) = get_param(params, "error") {
        return redirect_oauth_error(params, oauth_error);
    }
    let code = match get_param(params, "code") {
        Some(code) if !code.is_empty() => code,
        _ => {
            let (status, status_text, body) = error(400, "Bad Request", "missing code");
            return AuthHttpResponse::json(status, status_text, body);
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
    let Some(raw_state) = store.get(state_key.as_bytes(), Instant::now()) else {
        let (status, status_text, body) = error(400, "Bad Request", "invalid oauth state");
        return AuthHttpResponse::json(status, status_text, body);
    };
    let _ = store.del(&[state_key.as_bytes()]);
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
    let oauth_user = match exchange_oauth_code(&config, code, &callback).await {
        Ok(user) => user,
        Err(e) => return AuthHttpResponse::redirect(oauth_error_url(&redirect_to, &e)),
    };
    match oauth_sign_in(&oauth_user, headers, store, cache) {
        (200, _, body) => match serde_json::from_str::<Value>(&body) {
            Ok(session) => AuthHttpResponse::redirect(oauth_success_url(&redirect_to, &session)),
            Err(_) => AuthHttpResponse::redirect(oauth_error_url(&redirect_to, "invalid_session")),
        },
        (_, _, body) => AuthHttpResponse::redirect(oauth_error_url(
            &redirect_to,
            &json_error_message(&body).unwrap_or_else(|| "oauth_sign_in_failed".to_string()),
        )),
    }
}

fn oauth_sign_in(
    oauth_user: &OAuthUser,
    headers: &[(String, String)],
    store: &Store,
    cache: &SharedSchemaCache,
) -> (u16, &'static str, String) {
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
        Err(e) => return error(400, "Bad Request", &e),
    } {
        let Some(user_id) = identity.get("user_id") else {
            return error(
                500,
                "Internal Server Error",
                "identity row is missing user_id",
            );
        };
        let Some(user) = (match find_row_by_field(store, cache, USERS_TABLE, "id", user_id, now) {
            Ok(user) => user,
            Err(e) => return error(400, "Bad Request", &e),
        }) else {
            return error(401, "Unauthorized", "user not found");
        };
        if let Err(response) = validate_user_active(&user, unix_seconds()) {
            return response;
        }
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
        return issue_session_response(store, cache, headers, user_id, &user_email, now);
    }

    let now_sec = unix_seconds();
    let existing_user = match find_row_by_field(store, cache, USERS_TABLE, "email", &email, now) {
        Ok(user) => user,
        Err(e) => return error(400, "Bad Request", &e),
    };
    let (user_id, created_user) = if let Some(user) = existing_user {
        let Some(user_id) = user.get("id").cloned() else {
            return error(500, "Internal Server Error", "auth user row is missing id");
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
            return error(400, "Bad Request", &e);
        }
        (user_id, false)
    } else {
        let user_id = random_id("usr");
        let user_meta = user_meta.to_string();
        let app_meta = app_metadata_with_provider(None, provider);
        let email_confirmed_at = if email_confirmed {
            now_sec.to_string()
        } else {
            String::new()
        };
        if let Err(e) = durable_table_insert(
            store,
            cache,
            USERS_TABLE,
            &[
                ("id", user_id.as_str()),
                ("email", email.as_str()),
                ("email_confirmed_at", email_confirmed_at.as_str()),
                ("raw_user_meta_data", user_meta.as_str()),
                ("raw_app_meta_data", app_meta.as_str()),
                ("created_at", &now_sec.to_string()),
                ("updated_at", &now_sec.to_string()),
            ],
            now,
        ) {
            return error(400, "Bad Request", &e);
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
        return error(400, "Bad Request", &e);
    }

    issue_session_response(store, cache, headers, &user_id, &email, now)
}

fn admin_create_grant(
    body: &str,
    store: &Store,
    cache: &SharedSchemaCache,
) -> (u16, &'static str, String) {
    let parsed = match parse_json(body) {
        Ok(parsed) => parsed,
        Err(response) => return response,
    };
    let user_id = match required_string(&parsed, "user_id") {
        Ok(user_id) => user_id,
        Err(response) => return response,
    };
    let capability = match required_string(&parsed, "capability") {
        Ok(capability) => capability,
        Err(response) => return response,
    };
    if capability.trim().is_empty() {
        return error(400, "Bad Request", "capability must not be empty");
    }
    let now = Instant::now();
    if find_row_by_field(store, cache, USERS_TABLE, "id", user_id, now)
        .ok()
        .flatten()
        .is_none()
    {
        return error(404, "Not Found", "user not found");
    }

    let grant_id = random_id("grnt");
    let now_sec = unix_seconds().to_string();
    if let Err(e) = durable_table_insert(
        store,
        cache,
        GRANTS_TABLE,
        &[
            ("id", grant_id.as_str()),
            ("user_id", user_id),
            ("capability", capability),
            ("created_at", now_sec.as_str()),
        ],
        now,
    ) {
        return error(400, "Bad Request", &e);
    }
    ok(
        json!({"grant":{"id":grant_id,"user_id":user_id,"capability":capability,"created_at":now_sec}}),
    )
}

fn admin_revoke_grant(
    grant_id: &str,
    store: &Store,
    cache: &SharedSchemaCache,
) -> (u16, &'static str, String) {
    let now = Instant::now();
    let now_sec = unix_seconds().to_string();
    match durable_table_update_where(
        store,
        cache,
        GRANTS_TABLE,
        &[("revoked_at", now_sec.as_str())],
        &["id", "=", grant_id],
        now,
    ) {
        Ok(0) => error(404, "Not Found", "grant not found"),
        Ok(_) => ok(json!({"result":"OK"})),
        Err(e) => error(400, "Bad Request", &e),
    }
}

fn admin_list_user_grants(
    user_id: &str,
    store: &Store,
    cache: &SharedSchemaCache,
) -> (u16, &'static str, String) {
    match active_grants_for_user(store, cache, user_id, Instant::now()) {
        Ok(grants) => ok(json!({"grants": grants})),
        Err(e) => error(400, "Bad Request", &e),
    }
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
        Ok(_) => ok(json!({"result":"OK"})),
        Err(e) => error(400, "Bad Request", &e),
    }
}

fn create_table_if_missing(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    columns: &[&str],
    now: Instant,
) -> Result<(), String> {
    match tables::table_schema(store, cache, table, now) {
        Ok(_) => Ok(()),
        Err(_) => tables::table_create(store, cache, table, columns, now),
    }
}

fn durable_table_insert(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    field_values: &[(&str, &str)],
    now: Instant,
) -> Result<i64, String> {
    let mut args: Vec<Vec<u8>> = vec![b"TINSERT".to_vec(), table.as_bytes().to_vec()];
    for (field, value) in field_values {
        args.push(field.as_bytes().to_vec());
        args.push(value.as_bytes().to_vec());
    }
    log_command(store, &args)?;
    tables::table_insert(store, cache, table, field_values, now)
}

fn durable_table_update_where(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    field_values: &[(&str, &str)],
    where_args: &[&str],
    now: Instant,
) -> Result<i64, String> {
    let mut args: Vec<Vec<u8>> = vec![
        b"TUPDATE".to_vec(),
        table.as_bytes().to_vec(),
        b"SET".to_vec(),
    ];
    for (field, value) in field_values {
        args.push(field.as_bytes().to_vec());
        args.push(value.as_bytes().to_vec());
    }
    args.push(b"WHERE".to_vec());
    for arg in where_args {
        args.push(arg.as_bytes().to_vec());
    }
    log_command(store, &args)?;
    tables::table_update_where(store, cache, table, field_values, where_args, now)
}

fn durable_table_delete_where(
    store: &Store,
    cache: &SharedSchemaCache,
    table: &str,
    where_args: &[&str],
    now: Instant,
) -> Result<i64, String> {
    let mut args: Vec<Vec<u8>> = vec![
        b"TDELETE".to_vec(),
        b"FROM".to_vec(),
        table.as_bytes().to_vec(),
    ];
    args.push(b"WHERE".to_vec());
    for arg in where_args {
        args.push(arg.as_bytes().to_vec());
    }
    log_command(store, &args)?;
    tables::table_delete_where(store, cache, table, where_args, now)
}

fn log_command(store: &Store, args: &[Vec<u8>]) -> Result<(), String> {
    let refs: Vec<&[u8]> = args.iter().map(Vec::as_slice).collect();
    store
        .wal_log_command(&refs)
        .map_err(|e| format!("ERR WAL append failed: {e}"))
}

fn ensure_signing_key(
    store: &Store,
    cache: &SharedSchemaCache,
    now: Instant,
) -> Result<(), String> {
    if active_signing_secret(store, cache, now)?.is_some() {
        return Ok(());
    }
    let now_sec = unix_seconds().to_string();
    durable_table_insert(
        store,
        cache,
        SIGNING_KEYS_TABLE,
        &[
            ("id", random_id("sgn").as_str()),
            ("kid", random_id("kid").as_str()),
            ("algorithm", "HS256"),
            ("public_jwk", ""),
            ("private_key_encrypted", random_token(48).as_str()),
            ("active", "true"),
            ("created_at", now_sec.as_str()),
        ],
        now,
    )?;
    Ok(())
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

fn require_publishable_or_secret(
    headers: &[(String, String)],
    store: &Store,
    cache: &SharedSchemaCache,
) -> Result<(), (u16, &'static str, String)> {
    match api_key_kind(headers, store, cache) {
        Ok(Some(ApiKeyKind::Publishable | ApiKeyKind::Secret)) => Ok(()),
        Ok(None) if no_project_keys_configured(store, cache) => Ok(()),
        Ok(None) => Err(error(
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
    if let Some(password) = bearer_token(headers) {
        if !store.config().password.is_empty()
            && constant_time_eq(password.as_bytes(), store.config().password.as_bytes())
        {
            return Ok(());
        }
    }
    match api_key_kind(headers, store, cache) {
        Ok(Some(ApiKeyKind::Secret)) => Ok(()),
        _ => Err(error(401, "Unauthorized", "secret key required")),
    }
}

fn api_key_kind(
    headers: &[(String, String)],
    store: &Store,
    cache: &SharedSchemaCache,
) -> Result<Option<ApiKeyKind>, String> {
    let Some(key) = header_value(headers, "apikey").or_else(|| bearer_token(headers)) else {
        return Ok(None);
    };

    let hash = hash_secret(key);
    let Some(row) = find_row_by_field(store, cache, KEYS_TABLE, "key_hash", &hash, Instant::now())?
    else {
        return Ok(None);
    };
    if row
        .get("revoked_at")
        .map(|v| !v.is_empty() && v != "0")
        .unwrap_or(false)
    {
        return Ok(None);
    }
    Ok(match row.get("kind").map(String::as_str) {
        Some("publishable") => Some(ApiKeyKind::Publishable),
        Some("secret") => Some(ApiKeyKind::Secret),
        _ => None,
    })
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
    let claims = AccessClaims {
        iss: store.config().auth.issuer.clone(),
        sub: user_id.to_string(),
        email: email.to_string(),
        session_id: session_id.to_string(),
        role: "authenticated".to_string(),
        iat: now as usize,
        exp: exp as usize,
    };
    let secret = active_signing_secret(store, cache, Instant::now())?
        .ok_or_else(|| "missing active auth signing key".to_string())?;
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| e.to_string())
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

pub(crate) fn authenticate_access_token(
    token: &str,
    store: &Store,
    cache: &SharedSchemaCache,
) -> Result<AuthPrincipal, String> {
    let claims = claims_from_access_token(token, store, cache)
        .map_err(|(_, _, body)| json_error_message(&body).unwrap_or_else(|| body.clone()))?;
    Ok(AuthPrincipal {
        user_id: claims.sub,
        email: claims.email,
        session_id: claims.session_id,
        role: claims.role,
    })
}

pub(crate) fn principal_has_capability(
    store: &Store,
    cache: &SharedSchemaCache,
    principal: &AuthPrincipal,
    capability: &str,
) -> Result<bool, String> {
    let grants = active_grants_for_user(store, cache, &principal.user_id, Instant::now())?;
    Ok(grants
        .iter()
        .any(|grant| grant_matches_capability(grant, capability)))
}

fn claims_from_access_token(
    token: &str,
    store: &Store,
    cache: &SharedSchemaCache,
) -> Result<AccessClaims, (u16, &'static str, String)> {
    let secret = active_signing_secret(store, cache, Instant::now())
        .map_err(|e| error(500, "Internal Server Error", &e))?
        .ok_or_else(|| {
            error(
                500,
                "Internal Server Error",
                "missing active auth signing key",
            )
        })?;
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_issuer(&[store.config().auth.issuer.as_str()]);
    decode::<AccessClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
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
    let session = find_row_by_field(store, cache, SESSIONS_TABLE, "id", &claims.session_id, now)
        .map_err(|e| error(500, "Internal Server Error", &e))?
        .ok_or_else(|| error(401, "Unauthorized", "session not found"))?;

    if session.get("user_id").map(String::as_str) != Some(claims.sub.as_str()) {
        return Err(error(401, "Unauthorized", "session user mismatch"));
    }
    if access_revoked_after(store, &claims.session_id, now)
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

fn revoke_session_family_access(
    store: &Store,
    cache: &SharedSchemaCache,
    session_id: &str,
    now_sec: &str,
    now: Instant,
) -> Result<(), String> {
    let Some(session) = find_row_by_field(store, cache, SESSIONS_TABLE, "id", session_id, now)?
    else {
        return Ok(());
    };
    let family = session
        .get("refresh_token_family")
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .unwrap_or(session_id);
    let sessions = find_rows_by_field(
        store,
        cache,
        SESSIONS_TABLE,
        "refresh_token_family",
        family,
        now,
    )?;

    for session in sessions {
        if let Some(id) = session.get("id") {
            persist_access_revocation(store, id, now_sec, now)?;
        }
    }

    durable_table_update_where(
        store,
        cache,
        SESSIONS_TABLE,
        &[("revoked_at", now_sec), ("updated_at", now_sec)],
        &["refresh_token_family", "=", family],
        now,
    )?;
    Ok(())
}

fn persist_access_revocation(
    store: &Store,
    session_id: &str,
    revoked_after: &str,
    now: Instant,
) -> Result<(), String> {
    let key = access_revoked_after_key(session_id);
    let args = vec![
        b"SET".to_vec(),
        key.clone(),
        revoked_after.as_bytes().to_vec(),
    ];
    log_command(store, &args)?;
    store.set(
        &key,
        revoked_after.as_bytes(),
        Some(store.config().auth.access_token_ttl),
        now,
    );
    Ok(())
}

fn access_revoked_after(store: &Store, session_id: &str, now: Instant) -> Option<u64> {
    let key = access_revoked_after_key(session_id);
    store
        .get(&key, now)
        .and_then(|value| std::str::from_utf8(&value).ok()?.parse::<u64>().ok())
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

fn active_signing_secret(
    store: &Store,
    cache: &SharedSchemaCache,
    now: Instant,
) -> Result<Option<String>, String> {
    let row = find_row_by_field(store, cache, SIGNING_KEYS_TABLE, "active", "true", now)?;
    Ok(row.and_then(|row| row.get("private_key_encrypted").cloned()))
}

fn active_grants_for_user(
    store: &Store,
    cache: &SharedSchemaCache,
    user_id: &str,
    now: Instant,
) -> Result<Vec<String>, String> {
    let plan = SelectPlan {
        table: GRANTS_TABLE.to_string(),
        alias: None,
        projections: Vec::new(),
        aggregates: Vec::new(),
        joins: Vec::new(),
        conditions: vec![WhereClause {
            field: "user_id".to_string(),
            op: CmpOp::Eq,
            value: user_id.to_string(),
        }],
        group_by: Vec::new(),
        having: Vec::new(),
        near: None,
        order_by: None,
        limit: None,
        offset: None,
    };
    match tables::table_select(store, cache, &plan, now)? {
        SelectResult::Rows(rows) => Ok(rows
            .into_iter()
            .filter_map(|row| {
                let row: HashMap<String, String> = row.into_iter().collect();
                if row
                    .get("revoked_at")
                    .map(|v| !v.is_empty() && v != "0")
                    .unwrap_or(false)
                {
                    None
                } else {
                    row.get("capability").cloned()
                }
            })
            .collect()),
        SelectResult::Aggregate(_) => Ok(Vec::new()),
    }
}

fn grant_matches_capability(grant: &str, capability: &str) -> bool {
    if grant == "*" || grant == capability {
        return true;
    }
    if let Some(prefix) = grant.strip_suffix('*') {
        return capability.starts_with(prefix);
    }
    false
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

#[derive(Clone, Debug)]
struct OAuthProviderConfig {
    provider: String,
    enabled: bool,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    scopes: String,
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
    Ok(Some(OAuthProviderConfig {
        provider: row.get("provider").cloned().unwrap_or_default(),
        enabled: parse_bool(row.get("enabled")),
        client_id: row.get("client_id").cloned().unwrap_or_default(),
        client_secret: row.get("client_secret").cloned().unwrap_or_default(),
        redirect_uri: row.get("redirect_uri").cloned().unwrap_or_default(),
        scopes: row
            .get("scopes")
            .cloned()
            .unwrap_or_else(|| default_oauth_scopes(provider).to_string()),
        created_at: parse_optional_int(row.get("created_at")),
        updated_at: parse_optional_int(row.get("updated_at")),
    }))
}

fn normalize_oauth_provider(provider: &str) -> Result<String, (u16, &'static str, String)> {
    let provider = provider.trim().to_ascii_lowercase();
    match provider.as_str() {
        "google" | "github" => Ok(provider),
        _ => Err(error(400, "Bad Request", "unsupported provider")),
    }
}

fn default_oauth_scopes(provider: &str) -> &'static str {
    match provider {
        "google" => "openid email profile",
        "github" => "read:user user:email",
        _ => "",
    }
}

fn oauth_state_key(state: &str) -> String {
    format!("_auth:oauth_state:{state}")
}

fn default_callback_url(headers: &[(String, String)], provider: &str) -> String {
    let host = header_value(headers, "host").unwrap_or("localhost");
    format!("http://{host}/auth/v1/callback/{provider}")
}

fn oauth_authorization_url(
    config: &OAuthProviderConfig,
    redirect_uri: &str,
    state: &str,
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
        _ => String::new(),
    }
}

async fn exchange_oauth_code(
    config: &OAuthProviderConfig,
    code: &str,
    redirect_uri: &str,
) -> Result<OAuthUser, String> {
    match config.provider.as_str() {
        "google" => exchange_google_code(config, code, redirect_uri).await,
        "github" => exchange_github_code(config, code, redirect_uri).await,
        _ => Err("unsupported_provider".to_string()),
    }
}

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

fn oauth_error_url(redirect_to: &str, message: &str) -> String {
    append_fragment(redirect_to, &format!("error={}", url_encode(message)))
}

fn redirect_oauth_error(params: &[(String, String)], message: &str) -> AuthHttpResponse {
    let redirect_to = get_param(params, "redirect_to").unwrap_or("/");
    AuthHttpResponse::redirect(oauth_error_url(
        &sanitize_header_value(redirect_to),
        message,
    ))
}

fn append_fragment(url: &str, fragment: &str) -> String {
    let separator = if url.contains('#') { "&" } else { "#" };
    format!("{url}{separator}{fragment}")
}

fn form_body(items: &[(&str, &str)]) -> String {
    items
        .iter()
        .map(|(k, v)| format!("{}={}", url_encode(k), url_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn sanitize_header_value(value: &str) -> String {
    value.replace(['\r', '\n'], "")
}

fn user_map_json(row: &HashMap<String, String>) -> Value {
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
        "app_metadata": parse_json_string(row.get("raw_app_meta_data")),
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

fn find_row_by_field(
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
        conditions: vec![WhereClause {
            field: field.to_string(),
            op: CmpOp::Eq,
            value: value.to_string(),
        }],
        group_by: Vec::new(),
        having: Vec::new(),
        near: None,
        order_by: None,
        limit: Some(1),
        offset: None,
    };
    match tables::table_select(store, cache, &plan, now)? {
        SelectResult::Rows(rows) => Ok(rows
            .into_iter()
            .next()
            .map(|row| row.into_iter().collect::<HashMap<_, _>>())),
        SelectResult::Aggregate(_) => Ok(None),
    }
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
        conditions: vec![WhereClause {
            field: field.to_string(),
            op: CmpOp::Eq,
            value: value.to_string(),
        }],
        group_by: Vec::new(),
        having: Vec::new(),
        near: None,
        order_by: None,
        limit: Some(1000),
        offset: None,
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

fn verify_password(password: &str, hash: &str) -> Result<bool, String> {
    let password = password.to_string();
    let hash = hash.to_string();
    run_password_work(move || {
        let parsed = PasswordHash::new(&hash).map_err(|e| e.to_string())?;
        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok())
    })
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

fn hash_secret(secret: &str) -> String {
    let digest = Sha256::digest(secret.as_bytes());
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn random_token(bytes: usize) -> String {
    let mut raw = vec![0u8; bytes];
    OsRng.fill_bytes(&mut raw);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
}

fn random_id(prefix: &str) -> String {
    format!("{prefix}_{}", random_token(18))
}

fn key_prefix(key: &str) -> String {
    key.chars().take(12).collect()
}

fn unix_seconds() -> u64 {
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
mod tests {
    use std::sync::Arc;

    use parking_lot::RwLock;

    use super::*;
    use crate::tables::SchemaCache;

    #[test]
    fn bootstrap_creates_auth_tables_idempotently() {
        let store = Store::new();
        let cache = Arc::new(RwLock::new(SchemaCache::new()));

        bootstrap(&store, &cache, &AuthConfig::default()).unwrap();
        bootstrap(&store, &cache, &AuthConfig::default()).unwrap();

        let now = Instant::now();
        assert!(tables::table_schema(&store, &cache, USERS_TABLE, now).is_ok());
        assert!(tables::table_schema(&store, &cache, SESSIONS_TABLE, now).is_ok());
        assert_eq!(
            store.get(AUTH_SCHEMA_VERSION_KEY, now).unwrap(),
            AUTH_SCHEMA_VERSION
        );
    }

    #[test]
    fn auth_tables_are_reserved() {
        assert!(is_reserved_auth_table("auth.users"));
        assert!(!is_reserved_auth_table("users"));
    }

    #[test]
    fn auth_config_debug_redacts_initial_keys() {
        let config = AuthConfig {
            enabled: true,
            initial_publishable_key: Some("lux_pub_secret".to_string()),
            initial_secret_key: Some("lux_sec_secret".to_string()),
            ..AuthConfig::default()
        };
        let debug = format!("{config:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("lux_pub_secret"));
        assert!(!debug.contains("lux_sec_secret"));
    }

    #[test]
    fn password_hashes_verify_without_storing_plaintext() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert_ne!(hash, "correct horse battery staple");
        assert!(verify_password("correct horse battery staple", &hash).unwrap());
        assert!(!verify_password("wrong password", &hash).unwrap());
    }

    #[test]
    fn reserved_table_mutations_are_blocked_for_client_commands() {
        let store = Store::new();
        let err = reserved_table_mutation_error(&[b"TINSERT", b"auth.users"], &store).unwrap();
        assert!(err.contains("managed by Lux Auth"));

        store
            .wal_suppress
            .store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(reserved_table_mutation_error(&[b"TINSERT", b"auth.users"], &store).is_none());
    }

    #[test]
    fn reserved_auth_tables_are_readable_from_generic_table_reads() {
        let store = Store::new();
        let cache = Arc::new(RwLock::new(SchemaCache::new()));
        bootstrap(&store, &cache, &AuthConfig::default()).unwrap();

        let mut out = bytes::BytesMut::new();
        crate::cmd::execute(
            &store,
            &cache,
            &crate::pubsub::Broker::new(),
            &[b"TSCHEMA", b"auth.users"],
            &mut out,
            Instant::now(),
        );
        let response = std::str::from_utf8(&out).unwrap();
        assert!(response.starts_with('*'), "{response}");
        assert!(response.contains("email"), "{response}");
    }

    #[test]
    fn grant_matching_supports_exact_and_suffix_wildcard() {
        assert!(grant_matches_capability(
            "live.channel.room:1",
            "live.channel.room:1"
        ));
        assert!(grant_matches_capability(
            "live.channel.room:*",
            "live.channel.room:1"
        ));
        assert!(grant_matches_capability("*", "table.messages.read"));
        assert!(!grant_matches_capability(
            "live.channel.room:1",
            "live.channel.room:2"
        ));
        assert!(!grant_matches_capability(
            "table.messages.read",
            "table.messages.write"
        ));
    }

    #[test]
    fn signup_and_password_grant_issue_tokens() {
        let config = Arc::new(crate::ServerConfig {
            auth: AuthConfig {
                enabled: true,
                ..AuthConfig::default()
            },
            ..crate::ServerConfig::default()
        });
        let store = Store::new_with_config(config);
        let cache = Arc::new(RwLock::new(SchemaCache::new()));
        bootstrap(&store, &cache, &store.config().auth).unwrap();
        bootstrap_runtime(&store, &cache, &store.config().auth).unwrap();

        let (_, _, signup_body) = route_http(
            "POST",
            "/auth/v1/signup",
            r#"{"email":"Test@Example.com","password":"password123"}"#,
            &[],
            &[],
            &store,
            &cache,
        );
        let signup_json: Value = serde_json::from_str(&signup_body).unwrap();
        assert!(signup_json.get("access_token").is_some(), "{signup_body}");
        assert_eq!(signup_json["user"]["email"], "test@example.com");

        let (_, _, token_body) = route_http(
            "POST",
            "/auth/v1/token",
            r#"{"grant_type":"password","email":"test@example.com","password":"password123"}"#,
            &[],
            &[],
            &store,
            &cache,
        );
        let token_json: Value = serde_json::from_str(&token_body).unwrap();
        assert!(token_json.get("access_token").is_some(), "{token_body}");
        assert!(token_json.get("refresh_token").is_some(), "{token_body}");
    }

    #[tokio::test]
    async fn oauth_provider_config_and_authorize_redirect_are_core_owned() {
        let config = Arc::new(crate::ServerConfig {
            auth: AuthConfig {
                enabled: true,
                initial_secret_key: Some("lux_sec_test".to_string()),
                ..AuthConfig::default()
            },
            ..crate::ServerConfig::default()
        });
        let store = Store::new_with_config(config);
        let cache = Arc::new(RwLock::new(SchemaCache::new()));
        bootstrap(&store, &cache, &store.config().auth).unwrap();
        bootstrap_runtime(&store, &cache, &store.config().auth).unwrap();

        let (status, _, body) = route_http(
            "PUT",
            "/auth/v1/admin/providers/google",
            r#"{"client_id":"google-client","client_secret":"google-secret","redirect_uri":"http://app.test/auth/callback","enabled":true}"#,
            &[],
            &[("apikey".to_string(), "lux_sec_test".to_string())],
            &store,
            &cache,
        );
        assert_eq!(status, 200, "{body}");
        let provider: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(provider["provider"]["provider"], "google");
        assert_eq!(provider["provider"]["has_client_secret"], true);
        assert!(
            !body.contains("google-secret"),
            "admin provider response must not expose client secret: {body}"
        );

        let response = route_http_response(
            "GET",
            "/auth/v1/authorize",
            "",
            &[
                ("provider".to_string(), "google".to_string()),
                (
                    "redirect_to".to_string(),
                    "http://app.test/welcome".to_string(),
                ),
            ],
            &[("host".to_string(), "localhost:17777".to_string())],
            &store,
            &cache,
        )
        .await;
        assert_eq!(response.status, 302);
        let location = response
            .headers
            .iter()
            .find(|(key, _)| key == "Location")
            .map(|(_, value)| value.as_str())
            .unwrap_or("");
        assert!(location.starts_with("https://accounts.google.com/o/oauth2/v2/auth?"));
        assert!(location.contains("client_id=google-client"), "{location}");
        assert!(
            location.contains("redirect_uri=http%3A%2F%2Fapp.test%2Fauth%2Fcallback"),
            "{location}"
        );
        assert!(
            location.contains("scope=openid%20email%20profile"),
            "{location}"
        );
    }

    #[test]
    fn oauth_sign_in_links_identity_and_issues_session() {
        let config = Arc::new(crate::ServerConfig {
            auth: AuthConfig {
                enabled: true,
                ..AuthConfig::default()
            },
            ..crate::ServerConfig::default()
        });
        let store = Store::new_with_config(config);
        let cache = Arc::new(RwLock::new(SchemaCache::new()));
        bootstrap(&store, &cache, &store.config().auth).unwrap();
        bootstrap_runtime(&store, &cache, &store.config().auth).unwrap();

        let oauth_user = OAuthUser {
            provider: "github".to_string(),
            provider_id: "42".to_string(),
            email: "octo@example.com".to_string(),
            email_verified: true,
            user_metadata: json!({"name":"Octo"}),
            identity_data: json!({"login":"octo"}),
        };
        let (status, _, body) = oauth_sign_in(&oauth_user, &[], &store, &cache);
        assert_eq!(status, 200, "{body}");
        let session: Value = serde_json::from_str(&body).unwrap();
        assert!(session["access_token"].is_string(), "{body}");
        assert_eq!(session["user"]["email"], "octo@example.com");

        let identity = find_row_by_field(
            &store,
            &cache,
            IDENTITIES_TABLE,
            "provider_id",
            "github:42",
            Instant::now(),
        )
        .unwrap()
        .expect("oauth identity should be stored");
        assert_eq!(identity.get("provider").map(String::as_str), Some("github"));
    }

    #[test]
    fn deleted_users_cannot_use_or_refresh_tokens() {
        let config = Arc::new(crate::ServerConfig {
            auth: AuthConfig {
                enabled: true,
                ..AuthConfig::default()
            },
            ..crate::ServerConfig::default()
        });
        let store = Store::new_with_config(config);
        let cache = Arc::new(RwLock::new(SchemaCache::new()));
        bootstrap(&store, &cache, &store.config().auth).unwrap();
        bootstrap_runtime(&store, &cache, &store.config().auth).unwrap();

        let (_, _, signup_body) = route_http(
            "POST",
            "/auth/v1/signup",
            r#"{"email":"deleted@example.com","password":"password123"}"#,
            &[],
            &[],
            &store,
            &cache,
        );
        let signup_json: Value = serde_json::from_str(&signup_body).unwrap();
        let user_id = signup_json["user"]["id"].as_str().unwrap();
        let access_token = signup_json["access_token"].as_str().unwrap();
        let refresh_token = signup_json["refresh_token"].as_str().unwrap();

        let deleted_at = unix_seconds().to_string();
        durable_table_update_where(
            &store,
            &cache,
            USERS_TABLE,
            &[("deleted_at", deleted_at.as_str())],
            &["id", "=", user_id],
            Instant::now(),
        )
        .unwrap();

        let (status, _, body) = route_http(
            "GET",
            "/auth/v1/user",
            "",
            &[],
            &[(
                "Authorization".to_string(),
                format!("Bearer {access_token}"),
            )],
            &store,
            &cache,
        );
        assert_eq!(status, 401, "{body}");
        assert!(body.contains("user deleted"), "{body}");

        let (status, _, body) = route_http(
            "POST",
            "/auth/v1/token",
            &format!(
                r#"{{"grant_type":"refresh_token","refresh_token":"{}"}}"#,
                refresh_token
            ),
            &[],
            &[],
            &store,
            &cache,
        );
        assert_eq!(status, 401, "{body}");

        let (status, _, body) = route_http(
            "POST",
            "/auth/v1/token",
            r#"{"grant_type":"password","email":"deleted@example.com","password":"password123"}"#,
            &[],
            &[],
            &store,
            &cache,
        );
        assert_eq!(status, 401, "{body}");
    }

    #[test]
    fn auth_users_survive_wal_replay() {
        let temp = tempfile::tempdir().unwrap();
        let config = Arc::new(crate::ServerConfig {
            auth: AuthConfig {
                enabled: true,
                ..AuthConfig::default()
            },
            storage: crate::StorageConfig {
                mode: crate::StorageMode::Tiered,
                dir: temp.path().to_string_lossy().to_string(),
            },
            ..crate::ServerConfig::default()
        });

        let store = Store::new_with_config(config.clone());
        let cache = Arc::new(RwLock::new(SchemaCache::new()));
        bootstrap(&store, &cache, &store.config().auth).unwrap();
        bootstrap_runtime(&store, &cache, &store.config().auth).unwrap();

        let (_, _, signup_body) = route_http(
            "POST",
            "/auth/v1/signup",
            r#"{"email":"wal@example.com","password":"password123"}"#,
            &[],
            &[],
            &store,
            &cache,
        );
        assert!(
            serde_json::from_str::<Value>(&signup_body).unwrap()["access_token"].is_string(),
            "{signup_body}"
        );

        let restored = Store::new_with_config(config);
        let restored_cache = Arc::new(RwLock::new(SchemaCache::new()));
        bootstrap(&restored, &restored_cache, &restored.config().auth).unwrap();
        restored.replay_wal(&crate::pubsub::Broker::new());
        bootstrap_runtime(&restored, &restored_cache, &restored.config().auth).unwrap();

        let user = find_row_by_field(
            &restored,
            &restored_cache,
            USERS_TABLE,
            "email",
            "wal@example.com",
            Instant::now(),
        )
        .unwrap()
        .expect("auth user should replay from WAL");
        assert_eq!(
            user.get("email").map(String::as_str),
            Some("wal@example.com")
        );
    }
}
