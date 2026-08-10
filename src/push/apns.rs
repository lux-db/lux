//! APNs delivery sink and the generic `Sink` abstraction the delivery worker
//! drives. `ApnsSink` speaks the native APNs HTTP/2 protocol directly (no
//! OneSignal/Firebase in the path): an ES256 provider JWT minted from the app's
//! `.p8` key, cached and refreshed, and a `POST /3/device/<token>`.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// A single delivery target: the platform token plus whatever routing metadata
/// the sink needs (APNs topic, etc.).
#[derive(Clone, Debug)]
pub(crate) struct DeliveryTarget {
    pub token: String,
    pub topic: String,
    /// Stable per-outbox-row APNs request UUID, reused across retries.
    pub request_id: String,
}

/// Outcome of a failed delivery. `Retryable` is re-attempted with backoff,
/// `Permanent` dead-letters the request without touching the device, and
/// `InvalidTarget` prunes a token or subscription that cannot receive again.
#[derive(Debug)]
pub(crate) enum DeliveryError {
    Retryable(String),
    Permanent(String),
    InvalidTarget(String),
}

impl DeliveryError {
    pub fn message(&self) -> &str {
        match self {
            DeliveryError::Retryable(m)
            | DeliveryError::Permanent(m)
            | DeliveryError::InvalidTarget(m) => m,
        }
    }
    pub fn is_permanent(&self) -> bool {
        matches!(self, DeliveryError::Permanent(_))
    }
    pub fn invalidates_target(&self) -> bool {
        matches!(self, DeliveryError::InvalidTarget(_))
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
        let jwt = self
            .mint_token(now_secs)
            .map_err(DeliveryError::Permanent)?;
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
            410 => Err(DeliveryError::InvalidTarget(format!(
                "unregistered: {reason}"
            ))),
            400 if reason.contains("BadDeviceToken")
                || reason.contains("DeviceTokenNotForTopic") =>
            {
                Err(DeliveryError::InvalidTarget(format!("bad token: {reason}")))
            }
            400 | 403 | 404 | 405 | 413 => Err(DeliveryError::Permanent(format!(
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

    // aps.alert (literal text, bundle localization, and launch image)
    let mut alert = serde_json::Map::new();
    for (source, target) in [
        ("title", "title"),
        ("body", "body"),
        ("subtitle", "subtitle"),
        ("title_loc_key", "title-loc-key"),
        ("subtitle_loc_key", "subtitle-loc-key"),
        ("body_loc_key", "loc-key"),
        ("launch_image", "launch-image"),
    ] {
        if let Some(value) = s(source) {
            alert.insert(target.into(), json!(value));
        }
    }
    for (source, target) in [
        ("title_loc_args", "title-loc-args"),
        ("subtitle_loc_args", "subtitle-loc-args"),
        ("body_loc_args", "loc-args"),
    ] {
        if let Some(values) = parsed.get(source).and_then(Value::as_array) {
            if values.iter().all(Value::is_string) {
                alert.insert(target.into(), Value::Array(values.clone()));
            }
        }
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
    if let Some(sound) = parsed.get("sound") {
        match sound {
            Value::String(value) if !value.is_empty() => {
                aps.insert("sound".into(), json!(value));
            }
            Value::Object(sound)
                if sound.get("critical").and_then(Value::as_bool) == Some(true)
                    && sound
                        .get("name")
                        .and_then(Value::as_str)
                        .is_some_and(|name| !name.is_empty()) =>
            {
                let mut critical = serde_json::Map::new();
                critical.insert("critical".into(), json!(1));
                critical.insert("name".into(), sound["name"].clone());
                if let Some(volume) = sound
                    .get("volume")
                    .and_then(Value::as_f64)
                    .filter(|volume| (0.0..=1.0).contains(volume))
                {
                    critical.insert("volume".into(), json!(volume));
                }
                aps.insert("sound".into(), Value::Object(critical));
            }
            _ => {}
        }
    }
    if let Some(v) = s("interruption_level").filter(|v| super::is_valid_interruption_level(v)) {
        aps.insert("interruption-level".into(), json!(v));
    }
    if let Some(v) = s("target_content_id") {
        aps.insert("target-content-id".into(), json!(v));
    }
    if let Some(v) = parsed
        .get("relevance_score")
        .and_then(Value::as_f64)
        .filter(|value| (0.0..=1.0).contains(value))
    {
        aps.insert("relevance-score".into(), json!(v));
    }
    if let Some(v) = s("filter_criteria") {
        aps.insert("filter-criteria".into(), json!(v));
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
    // Arbitrary custom data merged at top level (arrives in the client userInfo).
    if let Some(data) = parsed.get("data").and_then(|v| v.as_object()) {
        for (k, v) in data {
            if k != "aps" {
                envelope.insert(k.clone(), v.clone());
            }
        }
    }
    // This is the contract with Lux's iOS notification-service extension.
    // Insert it after custom data so callers cannot accidentally replace it.
    if let Some(v) = s("image") {
        envelope.insert("image_url".into(), json!(v));
    }
    serde_json::to_vec(&serde_json::Value::Object(envelope)).unwrap_or_else(|_| b"{}".to_vec())
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ApnsDeliveryHeaders {
    push_type: &'static str,
    priority: &'static str,
    expiration: Option<String>,
    collapse_id: Option<String>,
}

/// APNs request headers for a payload. Lux derives the push type so callers
/// cannot accidentally mismatch the payload and header; the remaining optional
/// transport controls are validated before enqueue.
pub(crate) fn apns_delivery_headers(payload: &[u8]) -> ApnsDeliveryHeaders {
    let parsed: serde_json::Value = serde_json::from_slice(payload).unwrap_or(json!({}));
    let background = super::notification_is_background(&parsed);
    let apns = parsed.get("apns").and_then(Value::as_object);
    let configured_priority = apns
        .and_then(|options| options.get("priority"))
        .and_then(Value::as_u64);
    let priority = if background {
        "5"
    } else {
        match configured_priority {
            Some(1) => "1",
            Some(5) => "5",
            Some(10) => "10",
            _ => "10",
        }
    };
    ApnsDeliveryHeaders {
        push_type: if background { "background" } else { "alert" },
        priority,
        expiration: apns
            .and_then(|options| options.get("expiration"))
            .and_then(Value::as_u64)
            .map(|value| value.to_string()),
        collapse_id: apns
            .and_then(|options| options.get("collapse_id"))
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= 64)
            .map(str::to_string),
    }
}

/// Derive a stable canonical request UUID from the durable outbox id. APNs
/// echoes this value in error responses, and retries of one delivery keep the
/// same id while fan-out rows get distinct ids.
pub(crate) fn apns_request_id(outbox_id: &str) -> String {
    let digest = Sha256::digest(outbox_id.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    // RFC 9562 UUIDv8: application-defined bytes plus the RFC variant bits.
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let id = format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    );
    debug_assert!(super::is_canonical_uuid(&id));
    id
}

fn with_optional_header(
    request: reqwest::RequestBuilder,
    name: &'static str,
    value: &Option<String>,
) -> reqwest::RequestBuilder {
    if let Some(value) = value {
        request.header(name, value)
    } else {
        request
    }
}

impl Sink for ApnsSink {
    async fn deliver(&self, target: &DeliveryTarget, payload: &[u8]) -> Result<(), DeliveryError> {
        let now_secs = crate::auth::unix_seconds();
        let jwt = self.provider_token(now_secs)?;
        let url = format!("{}/3/device/{}", self.base_url, target.token);
        let body = apns_body_from_payload(payload);
        if body.len() > super::APNS_PAYLOAD_LIMIT_BYTES {
            return Err(DeliveryError::Permanent(format!(
                "APNs payload exceeds {} bytes",
                super::APNS_PAYLOAD_LIMIT_BYTES
            )));
        }
        let headers = apns_delivery_headers(payload);
        let request = self
            .client
            .post(&url)
            .header("authorization", format!("bearer {jwt}"))
            .header("apns-topic", &target.topic)
            .header("apns-id", &target.request_id)
            .header("apns-push-type", headers.push_type)
            .header("apns-priority", headers.priority)
            .header("content-type", "application/json")
            .body(body);
        let request = with_optional_header(request, "apns-expiration", &headers.expiration);
        let request = with_optional_header(request, "apns-collapse-id", &headers.collapse_id);
        let resp = request.send().await.map_err(|e| {
            if e.is_timeout() || e.is_connect() {
                DeliveryError::Retryable(format!("apns transport: {e}"))
            } else {
                DeliveryError::Retryable(format!("apns request failed: {e}"))
            }
        })?;
        let status = resp.status().as_u16();
        let response_body = resp.text().await.unwrap_or_default();
        let reason = if target.request_id.is_empty() {
            response_body
        } else {
            format!("apns-id {}: {response_body}", target.request_id)
        };
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

    // The two hosts are the whole reason a device carries an environment: one
    // `.p8` signs for both, and a token minted for one is rejected by the other.
    #[test]
    fn base_url_splits_sandbox_from_production() {
        assert_eq!(
            ApnsSink::resolve_base_url("production"),
            "https://api.push.apple.com"
        );
        assert_eq!(
            ApnsSink::resolve_base_url("prod"),
            "https://api.push.apple.com"
        );
        assert_eq!(
            ApnsSink::resolve_base_url("sandbox"),
            "https://api.sandbox.push.apple.com"
        );
        // Unknown values are sandbox, so a misconfiguration cannot silently
        // deliver to real users.
        assert_eq!(
            ApnsSink::resolve_base_url(""),
            "https://api.sandbox.push.apple.com"
        );
        // An explicit base survives verbatim; the tests point it at a mock.
        assert_eq!(
            ApnsSink::resolve_base_url("http://127.0.0.1:9000/"),
            "http://127.0.0.1:9000"
        );
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
    fn request_id_is_stable_canonical_and_unique_per_outbox_row() {
        let first = apns_request_id("out_first");
        assert_eq!(first, apns_request_id("out_first"));
        assert_ne!(first, apns_request_id("out_second"));
        assert!(super::super::is_canonical_uuid(&first));
        assert_eq!(&first[14..15], "8");
    }

    #[test]
    fn invalid_p8_is_permanent_without_invalidating_device() {
        let sink = sink_with(
            "-----BEGIN PRIVATE KEY-----\nnonsense\n-----END PRIVATE KEY-----".to_string(),
        );
        let err = sink.provider_token(1_700_000_000).unwrap_err();
        assert!(err.is_permanent(), "bad key must be permanent, got {err:?}");
        assert!(!err.invalidates_target());
    }

    #[test]
    fn status_classification() {
        assert!(ApnsSink::classify_status(200, "").is_ok());
        assert!(ApnsSink::classify_status(410, "Unregistered")
            .unwrap_err()
            .invalidates_target());
        assert!(ApnsSink::classify_status(400, "BadDeviceToken")
            .unwrap_err()
            .invalidates_target());
        let bad_payload = ApnsSink::classify_status(400, "BadCollapseId").unwrap_err();
        assert!(bad_payload.is_permanent());
        assert!(!bad_payload.invalidates_target());
        let throttled = ApnsSink::classify_status(429, "TooManyRequests").unwrap_err();
        assert!(!throttled.is_permanent());
        assert!(!throttled.invalidates_target());
        let unavailable = ApnsSink::classify_status(503, "ServiceUnavailable").unwrap_err();
        assert!(!unavailable.is_permanent());
        assert!(!unavailable.invalidates_target());
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
            "interruption_level":"time-sensitive","target_content_id":"message-window",
            "relevance_score":0.75,"filter_criteria":"work",
            "data":{"route":"/w/1","nested":{"count":2}}
        }"#;
        let v: serde_json::Value =
            serde_json::from_slice(&apns_body_from_payload(payload)).unwrap();
        assert_eq!(v["aps"]["alert"]["subtitle"], "S");
        assert_eq!(v["aps"]["thread-id"], "th1");
        assert_eq!(v["aps"]["category"], "MSG");
        assert_eq!(v["aps"]["sound"], "ping.caf");
        assert_eq!(v["aps"]["interruption-level"], "time-sensitive");
        assert_eq!(v["aps"]["target-content-id"], "message-window");
        assert_eq!(v["aps"]["relevance-score"], 0.75);
        assert_eq!(v["aps"]["filter-criteria"], "work");
        assert_eq!(v["aps"]["badge"], 3);
        assert_eq!(v["aps"]["mutable-content"], 1); // image → NSE
        assert_eq!(v["image_url"], "https://x/i.png");
        assert_eq!(v["route"], "/w/1");
        assert_eq!(v["nested"]["count"], 2);
    }

    #[test]
    fn body_maps_localization_launch_image_and_critical_sound() {
        let payload = br#"{
            "title_loc_key":"QUESTION_TITLE","title_loc_args":["Codex"],
            "subtitle_loc_key":"PROJECT_NAME","subtitle_loc_args":["Vigil"],
            "body_loc_key":"QUESTION_BODY","body_loc_args":["Deploy"],
            "launch_image":"LaunchQuestion",
            "sound":{"critical":true,"name":"alarm.caf","volume":0.4}
        }"#;
        let v: Value = serde_json::from_slice(&apns_body_from_payload(payload)).unwrap();
        let alert = &v["aps"]["alert"];
        assert_eq!(alert["title-loc-key"], "QUESTION_TITLE");
        assert_eq!(alert["title-loc-args"], json!(["Codex"]));
        assert_eq!(alert["subtitle-loc-key"], "PROJECT_NAME");
        assert_eq!(alert["subtitle-loc-args"], json!(["Vigil"]));
        assert_eq!(alert["loc-key"], "QUESTION_BODY");
        assert_eq!(alert["loc-args"], json!(["Deploy"]));
        assert_eq!(alert["launch-image"], "LaunchQuestion");
        assert_eq!(v["aps"]["sound"]["critical"], 1);
        assert_eq!(v["aps"]["sound"]["name"], "alarm.caf");
        assert_eq!(v["aps"]["sound"]["volume"], 0.4);
    }

    #[test]
    fn custom_data_cannot_replace_aps_envelope() {
        let payload = br#"{
            "title":"Safe",
            "image":"https://example.com/safe.png",
            "data":{
                "aps":{"alert":"overridden"},
                "image_url":"https://example.com/overridden.png"
            }
        }"#;
        let v: Value = serde_json::from_slice(&apns_body_from_payload(payload)).unwrap();
        assert_eq!(v["aps"]["alert"]["title"], "Safe");
        assert_eq!(v["image_url"], "https://example.com/safe.png");
    }

    #[test]
    fn body_omits_invalid_interruption_level() {
        let payload = br#"{"title":"Hi","interruption_level":"urgent"}"#;
        let v: serde_json::Value =
            serde_json::from_slice(&apns_body_from_payload(payload)).unwrap();
        assert!(v["aps"].get("interruption-level").is_none());
    }

    #[test]
    fn content_available_is_a_background_push() {
        assert_eq!(
            apns_delivery_headers(br#"{"content_available":true}"#),
            ApnsDeliveryHeaders {
                push_type: "background",
                priority: "5",
                expiration: None,
                collapse_id: None,
            }
        );
        assert_eq!(
            apns_delivery_headers(br#"{"title":"hi","content_available":true}"#),
            ApnsDeliveryHeaders {
                push_type: "alert",
                priority: "10",
                expiration: None,
                collapse_id: None,
            }
        );
        assert_eq!(
            apns_delivery_headers(br#"{"badge":1,"content_available":true}"#).push_type,
            "alert"
        );
        assert_eq!(
            apns_delivery_headers(br#"{"title_loc_key":"TITLE","content_available":true}"#)
                .push_type,
            "alert"
        );
    }

    #[test]
    fn delivery_headers_map_transport_controls() {
        let headers = apns_delivery_headers(
            br#"{
                "title":"Hi",
                "apns":{
                    "priority":5,
                    "expiration":1700000000,
                    "collapse_id":"thread-1"
                }
            }"#,
        );
        assert_eq!(
            headers,
            ApnsDeliveryHeaders {
                push_type: "alert",
                priority: "5",
                expiration: Some("1700000000".to_string()),
                collapse_id: Some("thread-1".to_string()),
            }
        );
    }
}
