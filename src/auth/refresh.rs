use std::collections::HashMap;
use std::time::Instant;

use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::store::Store;
use crate::tables::SharedSchemaCache;

use super::{
    active_signing_key, add_column_if_missing, durable_table_update_where, encode_auth_claims,
    error, find_row_by_field, find_rows_by_field, hash_secret, header_value, json_error_message,
    random_id, required_string, row_field_is_set, sign_access_token, signing_key_by_kid,
    unix_seconds, user_map_json, validate_user_active, SESSIONS_TABLE, USERS_TABLE,
};

const REFRESH_TOKEN_AUDIENCE: &str = "lux-auth-refresh";
const REFRESH_TOKEN_TYPE: &str = "refresh";
const MAX_REFRESH_TOKEN_BYTES: usize = 8 * 1024;

type AuthResponse = (u16, &'static str, String);

#[derive(Clone, Copy, Eq, PartialEq)]
enum Presentation {
    Current,
    Reuse,
    Revoked,
    Invalid,
}

#[derive(Serialize, Deserialize)]
pub(super) struct RefreshClaims {
    iss: String,
    sub: String,
    aud: String,
    session_id: String,
    refresh_token_family: String,
    refresh_generation: u64,
    token_type: String,
    jti: String,
    iat: usize,
    exp: usize,
}

pub(super) fn migrate_columns(
    store: &Store,
    cache: &SharedSchemaCache,
    now: Instant,
) -> Result<(), String> {
    for field_spec in [
        "refresh_generation INT",
        "legacy_refresh_token_hash STR",
        "access_revoked_at INT",
        "refresh_rotated_at INT",
        "refresh_reuse_detected_at INT",
    ] {
        add_column_if_missing(store, cache, SESSIONS_TABLE, field_spec, now)?;
    }
    Ok(())
}

pub(super) fn grant(
    parsed: &Value,
    headers: &[(String, String)],
    store: &Store,
    cache: &SharedSchemaCache,
) -> AuthResponse {
    let refresh_token = match required_string(parsed, "refresh_token") {
        Ok(token) if token.len() <= MAX_REFRESH_TOKEN_BYTES => token,
        Ok(_) => return error(401, "Unauthorized", "invalid refresh token"),
        Err(response) => return response,
    };
    let token_hash = hash_secret(refresh_token);
    let parsed_claims = match claims(refresh_token, store, cache, true) {
        Ok(claims) => claims,
        Err(response) => return response,
    };
    let now = Instant::now();
    let now_sec = unix_seconds();
    let session = match session_for_token(&token_hash, parsed_claims.as_ref(), store, cache, now) {
        Ok(Some(session)) => session,
        Ok(None) => return error(401, "Unauthorized", "invalid refresh token"),
        Err(e) => return error(500, "Internal Server Error", &e),
    };

    match classify(&session, parsed_claims.as_ref(), &token_hash) {
        Presentation::Current => {}
        Presentation::Reuse => return reuse_detected(&session, store, cache, now, now_sec),
        Presentation::Revoked => {
            if parsed_claims.is_none() {
                match revoked_opaque_was_consumed(&session, store, cache, now) {
                    Ok(true) => return reuse_detected(&session, store, cache, now, now_sec),
                    Ok(false) => {}
                    Err(e) => return error(500, "Internal Server Error", &e),
                }
            }
            return error(401, "Unauthorized", "refresh token revoked");
        }
        Presentation::Invalid => return error(401, "Unauthorized", "invalid refresh token"),
    }

    let expires_at = session
        .get("expires_at")
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    if expires_at <= now_sec {
        return error(401, "Unauthorized", "refresh token expired");
    }
    let Some(user_id) = session.get("user_id") else {
        return error(
            500,
            "Internal Server Error",
            "session row is missing user_id",
        );
    };
    let user = match find_row_by_field(store, cache, USERS_TABLE, "id", user_id, now) {
        Ok(Some(user)) => user,
        Ok(None) => return error(401, "Unauthorized", "user not found"),
        Err(e) => return error(500, "Internal Server Error", &e),
    };
    if let Err(response) = validate_user_active(&user, now_sec) {
        return response;
    }
    let Some(session_id) = session.get("id") else {
        return error(500, "Internal Server Error", "session row is missing id");
    };
    let email = user.get("email").cloned().unwrap_or_default();
    let family = session_family(&session).to_string();
    let generation = session_generation(&session).saturating_add(1).max(1);
    let next_refresh_token = match sign(
        store, cache, user_id, session_id, &family, generation, now_sec,
    ) {
        Ok(token) => token,
        Err(e) => return error(500, "Internal Server Error", &e),
    };
    let next_refresh_hash = hash_secret(&next_refresh_token);
    let access_token = match sign_access_token(store, cache, user_id, &email, session_id) {
        Ok(token) => token,
        Err(e) => return error(500, "Internal Server Error", &e),
    };
    let next_expires_at = now_sec.saturating_add(store.config().auth.refresh_token_ttl.as_secs());
    let now_text = now_sec.to_string();
    let generation_text = generation.to_string();
    let expires_text = next_expires_at.to_string();
    let user_agent = header_value(headers, "user-agent").unwrap_or("");
    let mut updates = vec![
        ("refresh_token_hash", next_refresh_hash.as_str()),
        ("refresh_generation", generation_text.as_str()),
        ("expires_at", expires_text.as_str()),
        ("refresh_rotated_at", now_text.as_str()),
        ("updated_at", now_text.as_str()),
        ("user_agent", user_agent),
    ];
    if parsed_claims.is_none() {
        updates.push(("legacy_refresh_token_hash", token_hash.as_str()));
    }

    // The table mutation gate stays held while this predicate is resolved and
    // published. Matching both the session and current hash makes this the
    // durable single-winner boundary for concurrent refreshes.
    let rotated = durable_table_update_where(
        store,
        cache,
        SESSIONS_TABLE,
        &updates,
        &[
            "id",
            "=",
            session_id,
            "AND",
            "refresh_token_hash",
            "=",
            token_hash.as_str(),
            "AND",
            "expires_at",
            ">",
            now_text.as_str(),
            "AND",
            "revoked_at",
            "IS",
            "NULL",
            "OR",
            "revoked_at",
            "=",
            "0",
        ],
        now,
    );
    match rotated {
        Ok(1) => {
            let _ = durable_table_update_where(
                store,
                cache,
                USERS_TABLE,
                &[("last_sign_in_at", now_text.as_str())],
                &["id", "=", user_id],
                now,
            );
            super::ok(json!({
                "access_token": access_token,
                "token_type": "bearer",
                "expires_in": store.config().auth.access_token_ttl.as_secs(),
                "refresh_token": next_refresh_token,
                "user": user_map_json(&user),
            }))
        }
        Ok(0) => rotation_lost(
            session_id,
            parsed_claims.as_ref(),
            &token_hash,
            store,
            cache,
            now,
        ),
        Ok(_) => error(
            500,
            "Internal Server Error",
            "refresh rotation matched more than one session",
        ),
        Err(e) => error(500, "Internal Server Error", &e),
    }
}

pub(super) fn sign(
    store: &Store,
    cache: &SharedSchemaCache,
    user_id: &str,
    session_id: &str,
    refresh_token_family: &str,
    refresh_generation: u64,
    now: u64,
) -> Result<String, String> {
    let claims = RefreshClaims {
        iss: store.config().auth.issuer.clone(),
        sub: user_id.to_string(),
        aud: REFRESH_TOKEN_AUDIENCE.to_string(),
        session_id: session_id.to_string(),
        refresh_token_family: refresh_token_family.to_string(),
        refresh_generation,
        token_type: REFRESH_TOKEN_TYPE.to_string(),
        jti: random_id("rft"),
        iat: now as usize,
        exp: now.saturating_add(store.config().auth.refresh_token_ttl.as_secs()) as usize,
    };
    encode_auth_claims(store, cache, &claims)
}

fn claims(
    token: &str,
    store: &Store,
    cache: &SharedSchemaCache,
    validate_expiration: bool,
) -> Result<Option<RefreshClaims>, AuthResponse> {
    if token.bytes().filter(|byte| *byte == b'.').count() != 2 {
        return Ok(None);
    }
    let invalid = || error(401, "Unauthorized", "invalid refresh token");
    let header = decode_header(token).map_err(|_| invalid())?;
    let signing_key = match header.alg {
        Algorithm::ES256 => {
            let kid = header.kid.as_deref().ok_or_else(invalid)?;
            signing_key_by_kid(store, cache, kid, Instant::now())
                .map_err(|e| error(500, "Internal Server Error", &e))?
        }
        Algorithm::HS256 => match header.kid.as_deref() {
            Some(kid) => signing_key_by_kid(store, cache, kid, Instant::now())
                .map_err(|e| error(500, "Internal Server Error", &e))?,
            None => active_signing_key(store, cache, Instant::now())
                .map_err(|e| error(500, "Internal Server Error", &e))?,
        },
        _ => None,
    }
    .ok_or_else(invalid)?;
    let (algorithm, decoding_key) = match signing_key.algorithm.as_str() {
        "ES256" if header.alg == Algorithm::ES256 => {
            let jwk = serde_json::from_str::<Jwk>(&signing_key.public_jwk)
                .map_err(|_| error(500, "Internal Server Error", "invalid auth signing key"))?;
            let key = DecodingKey::from_jwk(&jwk)
                .map_err(|_| error(500, "Internal Server Error", "invalid auth signing key"))?;
            (Algorithm::ES256, key)
        }
        "HS256" if header.alg == Algorithm::HS256 => (
            Algorithm::HS256,
            DecodingKey::from_secret(signing_key.private_key.as_bytes()),
        ),
        _ => return Err(invalid()),
    };
    let mut validation = Validation::new(algorithm);
    validation.set_issuer(&[store.config().auth.issuer.as_str()]);
    validation.set_audience(&[REFRESH_TOKEN_AUDIENCE]);
    validation.validate_exp = validate_expiration;
    let claims = decode::<RefreshClaims>(token, &decoding_key, &validation)
        .map_err(|_| invalid())?
        .claims;
    if claims.token_type != REFRESH_TOKEN_TYPE {
        return Err(invalid());
    }
    Ok(Some(claims))
}

pub(super) fn session_id_for_token(
    token: &str,
    store: &Store,
    cache: &SharedSchemaCache,
    now: Instant,
) -> Result<Option<String>, String> {
    if token.len() > MAX_REFRESH_TOKEN_BYTES {
        return Ok(None);
    }
    match claims(token, store, cache, false) {
        Ok(Some(claims)) => Ok(Some(claims.session_id)),
        Ok(None) => {
            let token_hash = hash_secret(token);
            let session = find_row_by_field(
                store,
                cache,
                SESSIONS_TABLE,
                "refresh_token_hash",
                &token_hash,
                now,
            )?;
            let session = match session {
                Some(session) => Some(session),
                None => find_row_by_field(
                    store,
                    cache,
                    SESSIONS_TABLE,
                    "legacy_refresh_token_hash",
                    &token_hash,
                    now,
                )?,
            };
            Ok(session.and_then(|session| session.get("id").cloned()))
        }
        Err((status, _, body)) if status >= 500 => Err(json_error_message(&body).unwrap_or(body)),
        Err(_) => Ok(None),
    }
}

fn session_for_token(
    token_hash: &str,
    claims: Option<&RefreshClaims>,
    store: &Store,
    cache: &SharedSchemaCache,
    now: Instant,
) -> Result<Option<HashMap<String, String>>, String> {
    if let Some(claims) = claims {
        return find_row_by_field(store, cache, SESSIONS_TABLE, "id", &claims.session_id, now);
    }
    let session = find_row_by_field(
        store,
        cache,
        SESSIONS_TABLE,
        "refresh_token_hash",
        token_hash,
        now,
    )?;
    match session {
        Some(session) => Ok(Some(session)),
        None => find_row_by_field(
            store,
            cache,
            SESSIONS_TABLE,
            "legacy_refresh_token_hash",
            token_hash,
            now,
        ),
    }
}

fn classify(
    session: &HashMap<String, String>,
    claims: Option<&RefreshClaims>,
    token_hash: &str,
) -> Presentation {
    let revoked = row_field_is_set(session, "revoked_at");
    if let Some(claims) = claims {
        let identity_matches = session.get("id") == Some(&claims.session_id)
            && session.get("user_id") == Some(&claims.sub)
            && session_family(session) == claims.refresh_token_family;
        if !identity_matches {
            return Presentation::Invalid;
        }
        let current_generation = session_generation(session);
        if claims.refresh_generation > current_generation {
            return Presentation::Invalid;
        }
        if claims.refresh_generation < current_generation
            || session.get("refresh_token_hash").map(String::as_str) != Some(token_hash)
        {
            return Presentation::Reuse;
        }
        return if revoked {
            Presentation::Revoked
        } else {
            Presentation::Current
        };
    }
    if session.get("legacy_refresh_token_hash").map(String::as_str) == Some(token_hash) {
        return Presentation::Reuse;
    }
    if session.get("refresh_token_hash").map(String::as_str) == Some(token_hash) {
        return if revoked {
            Presentation::Revoked
        } else {
            Presentation::Current
        };
    }
    Presentation::Invalid
}

fn rotation_lost(
    session_id: &str,
    claims: Option<&RefreshClaims>,
    token_hash: &str,
    store: &Store,
    cache: &SharedSchemaCache,
    now: Instant,
) -> AuthResponse {
    let latest = match find_row_by_field(store, cache, SESSIONS_TABLE, "id", session_id, now) {
        Ok(Some(session)) => session,
        Ok(None) => return error(401, "Unauthorized", "invalid refresh token"),
        Err(e) => return error(500, "Internal Server Error", &e),
    };
    match classify(&latest, claims, token_hash) {
        Presentation::Reuse => reuse_detected(&latest, store, cache, now, unix_seconds()),
        Presentation::Revoked => error(401, "Unauthorized", "refresh token revoked"),
        Presentation::Current | Presentation::Invalid => {
            error(401, "Unauthorized", "invalid refresh token")
        }
    }
}

fn reuse_detected(
    session: &HashMap<String, String>,
    store: &Store,
    cache: &SharedSchemaCache,
    now: Instant,
    now_sec: u64,
) -> AuthResponse {
    let Some(session_id) = session.get("id") else {
        return error(500, "Internal Server Error", "session row is missing id");
    };
    match revoke_family(store, cache, session_id, &now_sec.to_string(), now, true) {
        Ok(()) => error(
            401,
            "Unauthorized",
            "refresh token reuse detected; session revoked",
        ),
        Err(e) => error(500, "Internal Server Error", &e),
    }
}

pub(super) fn revoke_family(
    store: &Store,
    cache: &SharedSchemaCache,
    session_id: &str,
    now_sec: &str,
    now: Instant,
    reuse_detected: bool,
) -> Result<(), String> {
    let Some(session) = find_row_by_field(store, cache, SESSIONS_TABLE, "id", session_id, now)?
    else {
        return Ok(());
    };
    let mut updates = vec![
        ("revoked_at", now_sec),
        ("access_revoked_at", now_sec),
        ("updated_at", now_sec),
    ];
    if reuse_detected {
        updates.push(("refresh_reuse_detected_at", now_sec));
    }
    let family = session
        .get("refresh_token_family")
        .map(String::as_str)
        .filter(|value| !value.is_empty());
    match family {
        Some(family) => durable_table_update_where(
            store,
            cache,
            SESSIONS_TABLE,
            &updates,
            &["refresh_token_family", "=", family],
            now,
        )?,
        None => durable_table_update_where(
            store,
            cache,
            SESSIONS_TABLE,
            &updates,
            &["id", "=", session_id],
            now,
        )?,
    };
    Ok(())
}

fn revoked_opaque_was_consumed(
    session: &HashMap<String, String>,
    store: &Store,
    cache: &SharedSchemaCache,
    now: Instant,
) -> Result<bool, String> {
    let family = session_family(session);
    let id = session.get("id").map(String::as_str).unwrap_or("");
    if family.is_empty() {
        return Ok(false);
    }
    Ok(find_rows_by_field(
        store,
        cache,
        SESSIONS_TABLE,
        "refresh_token_family",
        family,
        now,
    )?
    .iter()
    .any(|candidate| {
        candidate.get("id").map(String::as_str) != Some(id)
            && !row_field_is_set(candidate, "revoked_at")
    }))
}

fn session_family(session: &HashMap<String, String>) -> &str {
    session
        .get("refresh_token_family")
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .or_else(|| session.get("id").map(String::as_str))
        .unwrap_or("")
}

fn session_generation(session: &HashMap<String, String>) -> u64 {
    session
        .get("refresh_generation")
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}
