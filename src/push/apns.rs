//! APNs delivery sink and the generic `Sink` abstraction the delivery worker
//! drives. `ApnsSink` speaks the native APNs HTTP/2 protocol directly (no
//! OneSignal/Firebase in the path): an ES256 provider JWT minted from the app's
//! `.p8` key, cached and refreshed, and a `POST /3/device/<token>`.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::Serialize;
use serde_json::json;

/// A single delivery target: the platform token plus whatever routing metadata
/// the sink needs (APNs topic, etc.).
#[derive(Clone, Debug)]
pub(crate) struct DeliveryTarget {
    pub token: String,
    pub topic: String,
}

/// Outcome of a failed delivery. `Retryable` is re-attempted with backoff;
/// `Terminal` means the token is dead (prune the device) or the request is
/// permanently malformed.
#[derive(Debug)]
pub(crate) enum DeliveryError {
    Retryable(String),
    Terminal(String),
}

impl DeliveryError {
    pub fn message(&self) -> &str {
        match self {
            DeliveryError::Retryable(m) | DeliveryError::Terminal(m) => m,
        }
    }
    pub fn is_terminal(&self) -> bool {
        matches!(self, DeliveryError::Terminal(_))
    }
}

/// A delivery transport for one platform. Implementors turn a `(target,
/// payload)` into an at-most-one network attempt and classify the result.
pub(crate) trait Sink: Send + Sync {
    fn deliver(
        &self,
        target: &DeliveryTarget,
        payload: &[u8],
    ) -> impl std::future::Future<Output = Result<(), DeliveryError>> + Send;
}

/// Provider-token claims: APNs wants `{iss: team_id, iat}` signed ES256 with the
/// `.p8` key id in the JWT header `kid`.
#[derive(Serialize)]
struct ApnsClaims {
    iss: String,
    iat: u64,
}

struct CachedToken {
    jwt: String,
    minted: Instant,
}

/// Apple rotates provider tokens on a 20-60 min window; refresh at 50 min.
const APNS_TOKEN_TTL: Duration = Duration::from_secs(50 * 60);
const APNS_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// The credential material for one app's APNs connection.
#[derive(Clone)]
pub(crate) struct ApnsCredentials {
    pub team_id: String,
    pub key_id: String,
    pub p8_pem: String,
}

pub(crate) struct ApnsSink {
    client: reqwest::Client,
    base_url: String,
    creds: ApnsCredentials,
    token_cache: Mutex<Option<CachedToken>>,
}

impl ApnsSink {
    /// `base_url` is `https://api.push.apple.com` (production) or
    /// `https://api.sandbox.push.apple.com` (sandbox); tests inject a localhost
    /// mock. A single reused HTTP/2 client (ALPN negotiates h2 over TLS).
    pub fn new(base_url: impl Into<String>, creds: ApnsCredentials) -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .timeout(APNS_REQUEST_TIMEOUT)
            .build()
            .map_err(|e| format!("apns client setup failed: {e}"))?;
        Ok(Self {
            client,
            base_url: base_url.into(),
            creds,
            token_cache: Mutex::new(None),
        })
    }

    /// Resolve the APNs base URL from the stored `environment`. `production`/
    /// `prod` and anything else map to the two Apple hosts; a literal
    /// `http(s)://` value is used verbatim (operator escape hatch for a relay,
    /// and the seam tests point at a local mock).
    pub fn resolve_base_url(environment: &str) -> String {
        if environment.starts_with("http://") || environment.starts_with("https://") {
            environment.trim_end_matches('/').to_string()
        } else if environment == "production" || environment == "prod" {
            "https://api.push.apple.com".to_string()
        } else {
            "https://api.sandbox.push.apple.com".to_string()
        }
    }

    /// Mint (or reuse a cached) ES256 provider JWT. Mirrors the auth-layer
    /// signing at `src/auth.rs` (`EncodingKey::from_ec_pem` + `Header.kid`); a
    /// `.p8` file is a PKCS8 EC PEM, so it feeds `from_ec_pem` directly.
    fn provider_token(&self, now_secs: u64) -> Result<String, DeliveryError> {
        let mut cache = self.token_cache.lock().unwrap();
        if let Some(cached) = cache.as_ref() {
            if cached.minted.elapsed() < APNS_TOKEN_TTL {
                return Ok(cached.jwt.clone());
            }
        }
        let jwt = self.mint_token(now_secs).map_err(DeliveryError::Terminal)?;
        *cache = Some(CachedToken {
            jwt: jwt.clone(),
            minted: Instant::now(),
        });
        Ok(jwt)
    }

    fn mint_token(&self, now_secs: u64) -> Result<String, String> {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.creds.key_id.clone());
        let key = EncodingKey::from_ec_pem(self.creds.p8_pem.as_bytes())
            .map_err(|e| format!("invalid APNs .p8 key: {e}"))?;
        let claims = ApnsClaims {
            iss: self.creds.team_id.clone(),
            iat: now_secs,
        };
        encode(&header, &claims, &key).map_err(|e| format!("APNs JWT sign failed: {e}"))
    }

    /// Map an APNs HTTP status + `reason` body into a delivery outcome. 410
    /// (`Unregistered`) and 400/`BadDeviceToken` are terminal (dead token);
    /// 429 and 5xx are retryable.
    fn classify_status(status: u16, reason: &str) -> Result<(), DeliveryError> {
        match status {
            200 => Ok(()),
            410 => Err(DeliveryError::Terminal(format!("unregistered: {reason}"))),
            400 if reason.contains("BadDeviceToken")
                || reason.contains("DeviceTokenNotForTopic") =>
            {
                Err(DeliveryError::Terminal(format!("bad token: {reason}")))
            }
            400 | 403 | 404 => Err(DeliveryError::Terminal(format!(
                "rejected ({status}): {reason}"
            ))),
            429 => Err(DeliveryError::Retryable(format!("throttled: {reason}"))),
            500..=599 => Err(DeliveryError::Retryable(format!(
                "apns server error ({status}): {reason}"
            ))),
            other => Err(DeliveryError::Retryable(format!(
                "unexpected apns status {other}: {reason}"
            ))),
        }
    }
}

/// Build the APNs request body from a caller notification payload. The payload
/// is `{title, body, data?}` JSON; we wrap it into the APNs `aps` envelope.
pub(crate) fn apns_body_from_payload(payload: &[u8]) -> Vec<u8> {
    let parsed: serde_json::Value = serde_json::from_slice(payload).unwrap_or(json!({}));
    let s = |k: &str| {
        parsed
            .get(k)
            .and_then(|v| v.as_str())
            .filter(|v| !v.is_empty())
    };

    // aps.alert (title / body / subtitle)
    let mut alert = serde_json::Map::new();
    if let Some(v) = s("title") {
        alert.insert("title".into(), json!(v));
    }
    if let Some(v) = s("body") {
        alert.insert("body".into(), json!(v));
    }
    if let Some(v) = s("subtitle") {
        alert.insert("subtitle".into(), json!(v));
    }

    let mut aps = serde_json::Map::new();
    if !alert.is_empty() {
        aps.insert("alert".into(), serde_json::Value::Object(alert));
    }
    if let Some(v) = s("thread_id") {
        aps.insert("thread-id".into(), json!(v));
    }
    if let Some(v) = s("category") {
        aps.insert("category".into(), json!(v));
    }
    if let Some(v) = s("sound") {
        aps.insert("sound".into(), json!(v));
    }
    if let Some(v) = parsed.get("badge").and_then(|v| v.as_i64()) {
        aps.insert("badge".into(), json!(v));
    }
    let has_image = s("image").is_some();
    let mutable = parsed
        .get("mutable_content")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    // Flip mutable-content when an image is attached so the iOS NSE runs and
    // downloads the thumbnail (mirrors FCM `fcmOptions.imageUrl`).
    if mutable || has_image {
        aps.insert("mutable-content".into(), json!(1));
    }
    if parsed
        .get("content_available")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        aps.insert("content-available".into(), json!(1));
    }

    let mut envelope = serde_json::Map::new();
    envelope.insert("aps".into(), serde_json::Value::Object(aps));
    if let Some(v) = s("image") {
        envelope.insert("image_url".into(), json!(v));
    }
    // Arbitrary custom data merged at top level (arrives in the client userInfo).
    if let Some(data) = parsed.get("data").and_then(|v| v.as_object()) {
        for (k, v) in data {
            envelope.insert(k.clone(), v.clone());
        }
    }
    serde_json::to_vec(&serde_json::Value::Object(envelope)).unwrap_or_else(|_| b"{}".to_vec())
}

/// `(apns-push-type, apns-priority)` for a payload. A `content_available` push
/// with no visible alert is a background push (type `background`, priority 5);
/// everything else is a normal alert (type `alert`, priority 10).
pub(crate) fn apns_delivery_headers(payload: &[u8]) -> (&'static str, &'static str) {
    let parsed: serde_json::Value = serde_json::from_slice(payload).unwrap_or(json!({}));
    let s = |k: &str| {
        parsed
            .get(k)
            .and_then(|v| v.as_str())
            .filter(|v| !v.is_empty())
    };
    let has_alert = s("title").is_some() || s("body").is_some();
    let content_available = parsed
        .get("content_available")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if content_available && !has_alert {
        ("background", "5")
    } else {
        ("alert", "10")
    }
}

impl Sink for ApnsSink {
    async fn deliver(&self, target: &DeliveryTarget, payload: &[u8]) -> Result<(), DeliveryError> {
        let now_secs = crate::auth::unix_seconds();
        let jwt = self.provider_token(now_secs)?;
        let url = format!("{}/3/device/{}", self.base_url, target.token);
        let body = apns_body_from_payload(payload);
        let (push_type, priority) = apns_delivery_headers(payload);
        let resp = self
            .client
            .post(&url)
            .header("authorization", format!("bearer {jwt}"))
            .header("apns-topic", &target.topic)
            .header("apns-push-type", push_type)
            .header("apns-priority", priority)
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() || e.is_connect() {
                    DeliveryError::Retryable(format!("apns transport: {e}"))
                } else {
                    DeliveryError::Retryable(format!("apns request failed: {e}"))
                }
            })?;
        let status = resp.status().as_u16();
        let reason = resp.text().await.unwrap_or_default();
        ApnsSink::classify_status(status, &reason)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{decode_header, Algorithm};
    use p256::pkcs8::{EncodePrivateKey, LineEnding};
    use p256::SecretKey;
    use rand_core::OsRng;

    fn test_p8() -> String {
        SecretKey::random(&mut OsRng)
            .to_pkcs8_pem(LineEnding::LF)
            .unwrap()
            .to_string()
    }

    fn sink_with(p8: String) -> ApnsSink {
        ApnsSink::new(
            "https://api.sandbox.push.apple.com",
            ApnsCredentials {
                team_id: "TEAM123456".to_string(),
                key_id: "KEY7890AB".to_string(),
                p8_pem: p8,
            },
        )
        .unwrap()
    }

    #[test]
    fn mints_es256_jwt_with_kid_and_iss() {
        let sink = sink_with(test_p8());
        let jwt = sink.mint_token(1_700_000_000).unwrap();
        let header = decode_header(&jwt).unwrap();
        assert_eq!(header.alg, Algorithm::ES256);
        assert_eq!(header.kid.as_deref(), Some("KEY7890AB"));
        // Middle segment decodes to claims carrying the team id as issuer.
        let claims_b64 = jwt.split('.').nth(1).unwrap();
        let claims_json = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            claims_b64,
        )
        .unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&claims_json).unwrap();
        assert_eq!(claims["iss"], "TEAM123456");
        assert_eq!(claims["iat"], 1_700_000_000);
    }

    #[test]
    fn provider_token_is_cached() {
        let sink = sink_with(test_p8());
        let a = sink.provider_token(1_700_000_000).unwrap();
        let b = sink.provider_token(1_700_000_030).unwrap();
        assert_eq!(a, b, "token within TTL should be reused");
    }

    #[test]
    fn invalid_p8_is_terminal() {
        let sink = sink_with(
            "-----BEGIN PRIVATE KEY-----\nnonsense\n-----END PRIVATE KEY-----".to_string(),
        );
        let err = sink.provider_token(1_700_000_000).unwrap_err();
        assert!(err.is_terminal(), "bad key must be terminal, got {err:?}");
    }

    #[test]
    fn status_classification() {
        assert!(ApnsSink::classify_status(200, "").is_ok());
        assert!(ApnsSink::classify_status(410, "Unregistered")
            .unwrap_err()
            .is_terminal());
        assert!(ApnsSink::classify_status(400, "BadDeviceToken")
            .unwrap_err()
            .is_terminal());
        assert!(!ApnsSink::classify_status(429, "TooManyRequests")
            .unwrap_err()
            .is_terminal());
        assert!(!ApnsSink::classify_status(503, "ServiceUnavailable")
            .unwrap_err()
            .is_terminal());
    }

    #[test]
    fn body_wraps_alert_and_merges_data() {
        let payload = br#"{"title":"Hi","body":"There","data":{"k":"v"}}"#;
        let out = apns_body_from_payload(payload);
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["aps"]["alert"]["title"], "Hi");
        assert_eq!(v["aps"]["alert"]["body"], "There");
        assert_eq!(v["k"], "v");
    }

    #[test]
    fn body_maps_rich_fields() {
        let payload = br#"{
            "title":"T","body":"B","subtitle":"S","thread_id":"th1",
            "category":"MSG","sound":"ping.caf","badge":3,"image":"https://x/i.png",
            "data":{"route":"/w/1"}
        }"#;
        let v: serde_json::Value =
            serde_json::from_slice(&apns_body_from_payload(payload)).unwrap();
        assert_eq!(v["aps"]["alert"]["subtitle"], "S");
        assert_eq!(v["aps"]["thread-id"], "th1");
        assert_eq!(v["aps"]["category"], "MSG");
        assert_eq!(v["aps"]["sound"], "ping.caf");
        assert_eq!(v["aps"]["badge"], 3);
        assert_eq!(v["aps"]["mutable-content"], 1); // image → NSE
        assert_eq!(v["image_url"], "https://x/i.png");
        assert_eq!(v["route"], "/w/1");
    }

    #[test]
    fn content_available_is_a_background_push() {
        assert_eq!(
            apns_delivery_headers(br#"{"content_available":true}"#),
            ("background", "5")
        );
        assert_eq!(
            apns_delivery_headers(br#"{"title":"hi","content_available":true}"#),
            ("alert", "10")
        );
        assert_eq!(apns_delivery_headers(br#"{"title":"hi"}"#), ("alert", "10"));
    }
}
