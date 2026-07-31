use super::*;

const APPLE_PRIVATE_KEY_MAX_BYTES: usize = 16 * 1024;
const APPLE_NATIVE_NONCE_PREFIX: &str = "_auth:apple_native_nonce:";
static APPLE_NATIVE_NONCE_CONSUME_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

pub(super) fn admin_upsert_apple_provider(
    parsed: &Value,
    store: &Store,
    cache: &SharedSchemaCache,
) -> (u16, &'static str, String) {
    let now = Instant::now();
    let now_sec = unix_seconds().to_string();
    let existing = match find_row_by_field(store, cache, PROVIDERS_TABLE, "provider", "apple", now)
    {
        Ok(existing) => existing,
        Err(e) => return error(400, "Bad Request", &e),
    };
    if parsed.get("enabled").and_then(Value::as_bool) == Some(false) {
        let result = if existing.is_some() {
            durable_table_update_where(
                store,
                cache,
                PROVIDERS_TABLE,
                &[("enabled", "false"), ("updated_at", now_sec.as_str())],
                &["provider", "=", "apple"],
                now,
            )
        } else {
            durable_table_insert(
                store,
                cache,
                PROVIDERS_TABLE,
                &[
                    ("provider", "apple"),
                    ("enabled", "false"),
                    ("created_at", now_sec.as_str()),
                    ("updated_at", now_sec.as_str()),
                ],
                now,
            )
        };
        return match result {
            Ok(_) => {
                match find_row_by_field(store, cache, PROVIDERS_TABLE, "provider", "apple", now) {
                    Ok(Some(row)) => ok(json!({
                        "provider": provider_row_json(row.into_iter().collect())
                    })),
                    Ok(None) => error(500, "Internal Server Error", "provider update failed"),
                    Err(e) => error(400, "Bad Request", &e),
                }
            }
            Err(e) => error(400, "Bad Request", &e),
        };
    }

    let string_value = |key: &str| -> String {
        if parsed.get(key).is_some() {
            return parsed
                .get(key)
                .and_then(Value::as_str)
                .map(str::trim)
                .unwrap_or("")
                .to_string();
        }
        existing
            .as_ref()
            .and_then(|row| row.get(key))
            .cloned()
            .unwrap_or_default()
    };
    let enabled = parsed
        .get("enabled")
        .and_then(Value::as_bool)
        .or_else(|| {
            existing
                .as_ref()
                .and_then(|row| row.get("enabled"))
                .map(|value| parse_bool(Some(value)))
        })
        .unwrap_or(true)
        .to_string();
    let services_id = string_value("apple_services_id");
    let team_id = string_value("apple_team_id");
    let key_id = string_value("apple_key_id");
    let bundle_ids = match normalize_apple_bundle_ids(&string_value("apple_bundle_ids")) {
        Ok(bundle_ids) => bundle_ids,
        Err(message) => return error(400, "Bad Request", &message),
    };
    let redirect_uri = string_value("redirect_uri");
    let scopes = {
        let value = string_value("scopes");
        if value.is_empty() {
            default_oauth_scopes("apple").to_string()
        } else {
            value
        }
    };
    let private_key_input = parsed
        .get("apple_private_key")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    if private_key_input.len() > APPLE_PRIVATE_KEY_MAX_BYTES {
        return error(400, "Bad Request", "Apple .p8 key must be 16 KB or smaller");
    }
    if !team_id.is_empty() && !valid_apple_account_id(&team_id) {
        return error(400, "Bad Request", "invalid Apple Team ID");
    }
    if !key_id.is_empty() && !valid_apple_account_id(&key_id) {
        return error(400, "Bad Request", "invalid Apple Key ID");
    }
    if !services_id.is_empty() && !valid_apple_client_id(&services_id) {
        return error(400, "Bad Request", "invalid Apple Services ID");
    }
    let sealed_key = if private_key_input.is_empty() {
        existing
            .as_ref()
            .and_then(|row| row.get("apple_private_key"))
            .cloned()
            .unwrap_or_default()
    } else {
        // Fail fast on a bad or wrong-file .p8 with a clear message, instead of a
        // cryptic mint failure at first web sign-in. Same parse the client-secret
        // minter (mint_apple_client_secret) does per exchange.
        if EncodingKey::from_ec_pem(private_key_input.as_bytes()).is_err() {
            return error(
                400,
                "Bad Request",
                "invalid Apple .p8 auth key: expected a PKCS#8 EC private key (the AuthKey_*.p8 Apple issued, starting with -----BEGIN PRIVATE KEY-----)",
            );
        }
        match seal_apple_private_key(store, private_key_input) {
            Ok(sealed) => sealed,
            Err(e) => return error(400, "Bad Request", &e),
        }
    };

    // Require at least one usable flow: native (bundle IDs to check `aud`) or web
    // (services ID + team/key IDs + the .p8 to mint the client secret).
    let native_ok = !bundle_ids.is_empty();
    let web_ok = !services_id.is_empty()
        && !team_id.is_empty()
        && !key_id.is_empty()
        && !sealed_key.is_empty();
    if web_ok && !valid_apple_web_redirect_uri(&redirect_uri) {
        return error(
            400,
            "Bad Request",
            "Apple web sign-in requires an HTTPS redirect_uri with a public domain and no fragment",
        );
    }
    if !native_ok && !web_ok {
        return error(
            400,
            "Bad Request",
            "apple provider requires apple_bundle_ids (native) or apple_services_id + apple_team_id + apple_key_id + apple_private_key (web)",
        );
    }

    let result = if existing.is_some() {
        durable_table_update_where(
            store,
            cache,
            PROVIDERS_TABLE,
            &[
                ("enabled", enabled.as_str()),
                ("redirect_uri", redirect_uri.as_str()),
                ("scopes", scopes.as_str()),
                ("apple_team_id", team_id.as_str()),
                ("apple_key_id", key_id.as_str()),
                ("apple_services_id", services_id.as_str()),
                ("apple_bundle_ids", bundle_ids.as_str()),
                ("apple_private_key", sealed_key.as_str()),
                ("updated_at", now_sec.as_str()),
            ],
            &["provider", "=", "apple"],
            now,
        )
        .map(|_| ())
    } else {
        durable_table_insert(
            store,
            cache,
            PROVIDERS_TABLE,
            &[
                ("provider", "apple"),
                ("enabled", enabled.as_str()),
                ("redirect_uri", redirect_uri.as_str()),
                ("scopes", scopes.as_str()),
                ("apple_team_id", team_id.as_str()),
                ("apple_key_id", key_id.as_str()),
                ("apple_services_id", services_id.as_str()),
                ("apple_bundle_ids", bundle_ids.as_str()),
                ("apple_private_key", sealed_key.as_str()),
                ("created_at", now_sec.as_str()),
                ("updated_at", now_sec.as_str()),
            ],
            now,
        )
        .map(|_| ())
    };

    match result {
        Ok(()) => match oauth_provider_config(store, cache, "apple", now) {
            Ok(Some(config)) => ok(json!({"provider": provider_config_json(&config)})),
            Ok(None) => error(404, "Not Found", "provider not found"),
            Err(e) => error(400, "Bad Request", &e),
        },
        Err(e) => error(400, "Bad Request", &e),
    }
}

fn valid_apple_account_id(value: &str) -> bool {
    value.len() == 10 && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

fn valid_apple_client_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
}

fn normalize_apple_bundle_ids(value: &str) -> Result<String, String> {
    if value.len() > 4096 {
        return Err("Apple Bundle IDs must be 4096 characters or fewer".to_string());
    }
    let mut normalized = Vec::new();
    for bundle_id in value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if !valid_apple_client_id(bundle_id) {
            return Err(format!("invalid Apple Bundle ID: {bundle_id}"));
        }
        if !normalized.contains(&bundle_id) {
            normalized.push(bundle_id);
        }
    }
    Ok(normalized.join(","))
}

// Apple Sign In columns added to auth.providers after the original two-provider
// (google/github) schema shipped. Adds them to instances whose auth.providers
// predates Apple support; idempotent, so it also no-ops on fresh instances that
// already have them from the bootstrap CREATE above.
const APPLE_PROVIDER_COLUMNS: &[&str] = &[
    "apple_team_id STR",
    "apple_key_id STR",
    "apple_services_id STR",
    "apple_bundle_ids STR",
    "apple_private_key STR",
];

pub(super) fn migrate_provider_apple_columns(
    store: &Store,
    cache: &SharedSchemaCache,
    now: Instant,
) -> Result<(), String> {
    for spec in APPLE_PROVIDER_COLUMNS {
        add_column_if_missing(store, cache, PROVIDERS_TABLE, spec, now)?;
    }
    Ok(())
}

pub(super) fn migrate_apple_private_key_storage(
    store: &Store,
    cache: &SharedSchemaCache,
    now: Instant,
) -> Result<(), String> {
    let Some(row) = find_row_by_field(store, cache, PROVIDERS_TABLE, "provider", "apple", now)?
    else {
        return Ok(());
    };
    let Some(stored) = row.get("apple_private_key").filter(|value| {
        !value.is_empty()
            && !crate::encryption::EncryptionKeyring::is_encrypted_value(value.as_bytes())
    }) else {
        return Ok(());
    };
    if !store.encryption().has_active_key() {
        return Err(
            "ERR legacy Apple private key requires an active Lux encryption key for migration"
                .to_string(),
        );
    }
    let replacement = seal_apple_private_key(store, stored)?;
    durable_table_update_where(
        store,
        cache,
        PROVIDERS_TABLE,
        &[("apple_private_key", replacement.as_str())],
        &["provider", "=", "apple"],
        now,
    )?;
    Ok(())
}

// Apple's .p8 is stored in the plain `apple_private_key` STR column only after
// envelope encryption. Native-only Apple auth does not need a keyring, but web
// Apple auth fails closed rather than persisting signing material in plaintext.
const APPLE_KEY_AAD_PK: &str = "apple";

pub(super) fn seal_apple_private_key(store: &Store, p8: &str) -> Result<String, String> {
    if p8.is_empty() {
        return Ok(String::new());
    }
    if !store.encryption().has_active_key() {
        return Err("ERR Apple web sign-in requires an active Lux encryption key".to_string());
    }
    let sealed = store.encryption().seal(
        PROVIDERS_TABLE,
        "apple_private_key",
        APPLE_KEY_AAD_PK,
        p8.as_bytes(),
    )?;
    String::from_utf8(sealed).map_err(|e| format!("ERR apple private key seal failed: {e}"))
}

pub(super) fn unseal_apple_private_key(store: &Store, stored: &str) -> Result<String, String> {
    if !crate::encryption::EncryptionKeyring::is_encrypted_value(stored.as_bytes()) {
        return Err("ERR refusing to load an unencrypted Apple private key".to_string());
    }
    let plain = store.encryption().unseal(
        PROVIDERS_TABLE,
        "apple_private_key",
        APPLE_KEY_AAD_PK,
        stored.as_bytes(),
    )?;
    String::from_utf8(plain).map_err(|e| format!("ERR apple private key not utf-8: {e}"))
}

fn valid_apple_web_redirect_uri(value: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(value) else {
        return false;
    };
    if url.scheme() != "https"
        || url.username() != ""
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return false;
    }
    let Some(host) = url.host_str() else {
        return false;
    };
    host != "localhost" && host.parse::<std::net::IpAddr>().is_err()
}

pub(super) const APPLE_ISSUER: &str = "https://appleid.apple.com";
const APPLE_JWKS_URL: &str = "https://appleid.apple.com/auth/keys";
const APPLE_JWKS_TTL: Duration = Duration::from_secs(6 * 3600);
const APPLE_JWKS_FORCE_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

static APPLE_JWKS_CACHE: OnceLock<Mutex<Option<(Instant, JwkSet)>>> = OnceLock::new();
static APPLE_JWKS_FORCE_REFRESHED_AT: OnceLock<Mutex<Option<Instant>>> = OnceLock::new();
static APPLE_JWKS_FETCH_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
static APPLE_HTTP_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

#[derive(Debug, Deserialize)]
pub(super) struct AppleIdTokenClaims {
    pub(super) sub: String,
    #[serde(default)]
    pub(super) email: Option<String>,
    #[serde(default)]
    pub(super) email_verified: Option<Value>,
    #[serde(default)]
    pub(super) nonce: Option<String>,
}

fn apple_jwks_cache() -> &'static Mutex<Option<(Instant, JwkSet)>> {
    APPLE_JWKS_CACHE.get_or_init(|| Mutex::new(None))
}

fn apple_http_client() -> &'static reqwest::Client {
    APPLE_HTTP_CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(10))
            .build()
            .expect("valid Apple HTTP client")
    })
}

/// Seed the Apple JWKS cache so verification runs without a network fetch.
#[cfg(test)]
pub(super) fn seed_apple_jwks_for_test(set: JwkSet) {
    *apple_jwks_cache().lock().unwrap() = Some((Instant::now(), set));
}

/// Apple's public signing keys, cached with a TTL. In tests the cache is seeded
/// directly (see test_support) so no network call is made.
async fn apple_jwks(force_refresh: bool) -> Result<JwkSet, String> {
    if !force_refresh {
        if let Some((fetched, set)) = apple_jwks_cache().lock().unwrap().as_ref() {
            if fetched.elapsed() < APPLE_JWKS_TTL {
                return Ok(set.clone());
            }
        }
    }

    let _fetch_guard = APPLE_JWKS_FETCH_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    let stale = apple_jwks_cache()
        .lock()
        .unwrap()
        .as_ref()
        .map(|(_, set)| set.clone());
    if !force_refresh {
        if let Some((fetched, set)) = apple_jwks_cache().lock().unwrap().as_ref() {
            if fetched.elapsed() < APPLE_JWKS_TTL {
                return Ok(set.clone());
            }
        }
    } else {
        let mut refreshed_at = APPLE_JWKS_FORCE_REFRESHED_AT
            .get_or_init(|| Mutex::new(None))
            .lock()
            .unwrap();
        if refreshed_at
            .as_ref()
            .map(|last| last.elapsed() < APPLE_JWKS_FORCE_REFRESH_INTERVAL)
            .unwrap_or(false)
        {
            return stale.ok_or_else(|| "apple_jwks_fetch_throttled".to_string());
        }
        *refreshed_at = Some(Instant::now());
    }
    let response = match apple_http_client().get(APPLE_JWKS_URL).send().await {
        Ok(response) => response,
        Err(_) => return stale.ok_or_else(|| "apple_jwks_fetch_failed".to_string()),
    };
    let response = match response.error_for_status() {
        Ok(response) => response,
        Err(_) => return stale.ok_or_else(|| "apple_jwks_fetch_failed".to_string()),
    };
    let set: JwkSet = match response.json().await {
        Ok(set) => set,
        Err(_) => {
            return stale.ok_or_else(|| "apple_jwks_parse_failed".to_string());
        }
    };
    *apple_jwks_cache().lock().unwrap() = Some((Instant::now(), set.clone()));
    Ok(set)
}

pub(super) fn sha256_hex(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn apple_native_nonce_key(nonce: &str) -> String {
    format!("{APPLE_NATIVE_NONCE_PREFIX}{}", sha256_hex(nonce))
}

pub(super) fn issue_apple_native_nonce(store: &Store) -> AuthHttpResponse {
    let nonce = random_token(32);
    let key = apple_native_nonce_key(&nonce);
    store.set(key.as_bytes(), b"1", Some(OAUTH_STATE_TTL), Instant::now());
    let (status, status_text, body) = ok(json!({"nonce": nonce}));
    AuthHttpResponse::json(status, status_text, body)
}

fn consume_apple_native_nonce(store: &Store, nonce: &str) -> bool {
    let _guard = APPLE_NATIVE_NONCE_CONSUME_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap();
    let key = apple_native_nonce_key(nonce);
    if store.get(key.as_bytes(), Instant::now()).is_none() {
        return false;
    }
    store.del(&[key.as_bytes()]) > 0
}

/// Verify an Apple identity token against Apple's JWKS. Checks RS256 signature,
/// issuer, that `aud` is one of `allowed_auds`, expiry, and (when provided) that
/// the token's `nonce` equals `expected_nonce_claim`.
pub(super) fn verify_apple_id_token(
    jwks: &JwkSet,
    id_token: &str,
    allowed_auds: &[String],
    expected_nonce_claim: Option<&str>,
) -> Result<AppleIdTokenClaims, String> {
    let header = decode_header(id_token).map_err(|_| "apple_id_token_invalid".to_string())?;
    let kid = header
        .kid
        .ok_or_else(|| "apple_id_token_missing_kid".to_string())?;
    let jwk = jwks
        .find(&kid)
        .ok_or_else(|| "apple_signing_key_not_found".to_string())?;
    let decoding_key = DecodingKey::from_jwk(jwk).map_err(|_| "apple_jwk_invalid".to_string())?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[APPLE_ISSUER]);
    validation.set_audience(allowed_auds);
    let claims = decode::<AppleIdTokenClaims>(id_token, &decoding_key, &validation)
        .map_err(|_| "apple_id_token_verification_failed".to_string())?
        .claims;
    if let Some(expected) = expected_nonce_claim {
        match claims.nonce.as_deref() {
            Some(nonce) if nonce == expected => {}
            _ => return Err("apple_id_token_nonce_mismatch".to_string()),
        }
    }
    Ok(claims)
}

fn apple_email_verified(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Bool(value)) => *value,
        Some(Value::String(value)) => value.eq_ignore_ascii_case("true"),
        _ => false,
    }
}

fn oauth_user_from_apple(claims: AppleIdTokenClaims, name: Option<String>) -> OAuthUser {
    let email = claims.email.clone().unwrap_or_default();
    let email_verified = apple_email_verified(claims.email_verified.as_ref());
    let mut user_metadata = json!({});
    if let Some(name) = name.filter(|n| !n.trim().is_empty()) {
        user_metadata["name"] = json!(name);
    }
    OAuthUser {
        provider: "apple".to_string(),
        provider_id: claims.sub.clone(),
        email,
        email_verified,
        user_metadata,
        identity_data: json!({ "sub": claims.sub }),
    }
}

pub(super) async fn signin_apple(
    body: &str,
    headers: &[(String, String)],
    store: &Store,
    cache: &SharedSchemaCache,
) -> AuthHttpResponse {
    let parsed = match parse_json(body) {
        Ok(parsed) => parsed,
        Err((status, status_text, body)) => {
            return AuthHttpResponse::json(status, status_text, body)
        }
    };
    let id_token = match required_string(&parsed, "id_token") {
        Ok(id_token) => id_token.trim().to_string(),
        Err((status, status_text, body)) => {
            return AuthHttpResponse::json(status, status_text, body)
        }
    };
    let nonce = match required_string(&parsed, "nonce") {
        Ok(nonce) if !nonce.trim().is_empty() => nonce.trim().to_string(),
        _ => {
            let (status, status_text, body) = error(400, "Bad Request", "missing nonce");
            return AuthHttpResponse::json(status, status_text, body);
        }
    };
    let nonce_claim = sha256_hex(&nonce);
    if !consume_apple_native_nonce(store, &nonce) {
        let (status, status_text, body) = error(
            401,
            "Unauthorized",
            "invalid or expired Apple sign-in nonce",
        );
        return AuthHttpResponse::json(status, status_text, body);
    }
    let name = parsed
        .get("user")
        .and_then(|user| user.get("name"))
        .and_then(Value::as_str)
        .map(str::to_string);

    let now = Instant::now();
    let config = match oauth_provider_config(store, cache, "apple", now) {
        Ok(Some(config)) if config.enabled => config,
        Ok(Some(_)) => {
            let (s, st, b) = error(400, "Bad Request", "apple provider is disabled");
            return AuthHttpResponse::json(s, st, b);
        }
        Ok(None) => {
            let (s, st, b) = error(400, "Bad Request", "apple provider is not configured");
            return AuthHttpResponse::json(s, st, b);
        }
        Err(e) => {
            let (s, st, b) = error(400, "Bad Request", &e);
            return AuthHttpResponse::json(s, st, b);
        }
    };

    // Native tokens carry the app's bundle ID as `aud`; also accept the web
    // services ID so a single provider config serves both surfaces.
    let mut allowed_auds: Vec<String> = config
        .apple_bundle_ids
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if !config.apple_services_id.is_empty() {
        allowed_auds.push(config.apple_services_id.clone());
    }
    if allowed_auds.is_empty() {
        let (s, st, b) = error(
            400,
            "Bad Request",
            "apple provider has no configured audiences",
        );
        return AuthHttpResponse::json(s, st, b);
    }

    let jwks = match apple_jwks(false).await {
        Ok(jwks) => jwks,
        Err(e) => {
            let (s, st, b) = error(502, "Bad Gateway", &e);
            return AuthHttpResponse::json(s, st, b);
        }
    };
    // A rotated Apple key can miss the cache; refetch once before failing.
    let claims = match verify_apple_id_token(&jwks, &id_token, &allowed_auds, Some(&nonce_claim)) {
        Ok(claims) => claims,
        Err(first) if first == "apple_signing_key_not_found" => match apple_jwks(true).await {
            Ok(fresh) => {
                match verify_apple_id_token(&fresh, &id_token, &allowed_auds, Some(&nonce_claim)) {
                    Ok(claims) => claims,
                    Err(e) => {
                        let (s, st, b) = error(401, "Unauthorized", &e);
                        return AuthHttpResponse::json(s, st, b);
                    }
                }
            }
            Err(e) => {
                let (s, st, b) = error(502, "Bad Gateway", &e);
                return AuthHttpResponse::json(s, st, b);
            }
        },
        Err(e) => {
            let (s, st, b) = error(401, "Unauthorized", &e);
            return AuthHttpResponse::json(s, st, b);
        }
    };

    let oauth_user = oauth_user_from_apple(claims, name);
    let subject = match oauth_resolve_user(&oauth_user, store, cache) {
        Ok(subject) => subject,
        Err((status, status_text, body)) => {
            return AuthHttpResponse::json(status, status_text, body)
        }
    };
    let (status, status_text, body) =
        issue_session_response(store, cache, headers, &subject.user_id, &subject.email, now);
    AuthHttpResponse::json(status, status_text, body)
}

pub(super) fn mint_apple_client_secret(config: &OAuthProviderConfig) -> Result<String, String> {
    if config.apple_team_id.is_empty()
        || config.apple_key_id.is_empty()
        || config.apple_services_id.is_empty()
        || config.apple_private_key.is_empty()
    {
        return Err("apple_web_not_configured".to_string());
    }
    let now = unix_seconds() as i64;
    let claims = json!({
        "iss": config.apple_team_id,
        "iat": now,
        "exp": now + 300,
        "aud": APPLE_ISSUER,
        "sub": config.apple_services_id,
    });
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(config.apple_key_id.clone());
    let key = EncodingKey::from_ec_pem(config.apple_private_key.as_bytes())
        .map_err(|_| "apple_private_key_invalid".to_string())?;
    encode(&header, &claims, &key).map_err(|_| "apple_client_secret_mint_failed".to_string())
}

pub(super) async fn exchange_apple_code(
    config: &OAuthProviderConfig,
    code: &str,
    redirect_uri: &str,
    expected_nonce: Option<&str>,
    name: Option<String>,
) -> Result<OAuthUser, String> {
    let client_secret = mint_apple_client_secret(config)?;
    let body = form_body(&[
        ("client_id", config.apple_services_id.as_str()),
        ("client_secret", client_secret.as_str()),
        ("code", code),
        ("grant_type", "authorization_code"),
        ("redirect_uri", redirect_uri),
    ]);
    let token: Value = apple_http_client()
        .post("https://appleid.apple.com/auth/token")
        .header("Accept", "application/json")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .map_err(|_| "token_exchange_failed".to_string())?
        .error_for_status()
        .map_err(|_| "token_exchange_failed".to_string())?
        .json()
        .await
        .map_err(|_| "token_response_invalid".to_string())?;
    let id_token = token
        .get("id_token")
        .and_then(Value::as_str)
        .ok_or_else(|| "token_exchange_failed".to_string())?;
    let allowed = [config.apple_services_id.clone()];
    let jwks = apple_jwks(false).await?;
    let expected_nonce = expected_nonce.ok_or_else(|| "apple_nonce_missing".to_string())?;
    let claims = match verify_apple_id_token(&jwks, id_token, &allowed, Some(expected_nonce)) {
        Ok(claims) => claims,
        Err(e) if e == "apple_signing_key_not_found" => {
            let fresh = apple_jwks(true).await?;
            verify_apple_id_token(&fresh, id_token, &allowed, Some(expected_nonce))?
        }
        Err(e) => return Err(e),
    };
    Ok(oauth_user_from_apple(claims, name))
}

pub(super) fn parse_apple_callback_name(raw: &str) -> Option<String> {
    let value: Value = serde_json::from_str(raw).ok()?;
    if let Some(name) = value.get("name").and_then(Value::as_str) {
        let name = name.trim();
        return (!name.is_empty()).then(|| name.to_string());
    }
    let name = value.get("name")?.as_object()?;
    let parts = ["firstName", "middleName", "lastName"]
        .iter()
        .filter_map(|key| name.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    (!parts.is_empty()).then(|| parts.join(" "))
}
