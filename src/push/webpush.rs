//! Web Push message encryption (RFC 8291) with the `aes128gcm` content coding
//! (RFC 8188). This is the wire format browsers' push services require:
//! ephemeral P-256 ECDH against the subscription key, HKDF-SHA256 to a
//! content-encryption key + nonce, then a single AES-128-GCM record.
//!
//! Validated against the RFC 8291 Appendix A test vector (see tests).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use p256::{PublicKey, SecretKey};
use rand_core::{OsRng, RngCore};
use ring::{aead, hmac};
use serde::{Deserialize, Serialize};

use super::apns::{DeliveryError, DeliveryTarget, Sink};

const AUTH_INFO: &[u8] = b"WebPush: info\0";
const CEK_INFO: &[u8] = b"Content-Encoding: aes128gcm\0";
const NONCE_INFO: &[u8] = b"Content-Encoding: nonce\0";
/// Advertised record size in the aes128gcm header. Our payloads are a single
/// small record; any value larger than the plaintext + 17 works.
const RECORD_SIZE: u32 = 4096;
const ALLOW_PRIVATE_ENDPOINTS_ENV: &str = "LUX_PUSH_ALLOW_PRIVATE_ENDPOINTS";
const MAX_ENDPOINT_BYTES: usize = 2 * 1024;

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Generate an RFC 8292 VAPID key pair. The public key is the browser-facing
/// base64url uncompressed P-256 point; the private key is PKCS#8 PEM for ES256
/// signing and must only be stored in an engine ENCRYPTED column.
pub(crate) fn generate_vapid_keypair() -> Result<(String, String), String> {
    let secret = SecretKey::random(&mut OsRng);
    let public = B64.encode(secret.public_key().to_encoded_point(false).as_bytes());
    let private = secret
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|error| format!("could not encode VAPID private key: {error}"))?
        .to_string();
    Ok((public, private))
}

pub(super) fn validate_vapid_keypair(public_key: &str, private_pem: &str) -> Result<(), String> {
    let declared = b64url_decode(public_key).map_err(|_| "invalid VAPID public key".to_string())?;
    if declared.len() != 65 || PublicKey::from_sec1_bytes(&declared).is_err() {
        return Err("invalid VAPID public key".to_string());
    }
    let private = SecretKey::from_pkcs8_pem(private_pem)
        .map_err(|_| "invalid VAPID private key".to_string())?;
    if private.public_key().to_encoded_point(false).as_bytes() != declared {
        return Err("VAPID public and private keys do not match".to_string());
    }
    Ok(())
}

/// Decode a base64url (no-pad) subscription field.
pub(crate) fn b64url_decode(s: &str) -> Result<Vec<u8>, String> {
    B64.decode(s.trim())
        .map_err(|e| format!("invalid base64url: {e}"))
}

fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, salt), ikm);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

/// Single-block HKDF-Expand (valid for `len <= 32`, which covers all our uses).
fn hkdf_expand(prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, prk);
    let mut ctx = hmac::Context::with_key(&key);
    ctx.update(info);
    ctx.update(&[0x01u8]);
    ctx.sign().as_ref()[..len].to_vec()
}

/// Derive the AES-128-GCM content-encryption key + nonce for one message
/// (RFC 8291 §3.4 combined with RFC 8188 key derivation).
fn derive_content_keys(
    ua_public: &[u8],
    as_public: &[u8],
    auth_secret: &[u8],
    salt: &[u8],
    ecdh_secret: &[u8],
) -> ([u8; 16], [u8; 12]) {
    // Combine the shared secret with the auth secret, bound to both public keys.
    let prk_key = hkdf_extract(auth_secret, ecdh_secret);
    let mut key_info = Vec::with_capacity(AUTH_INFO.len() + ua_public.len() + as_public.len());
    key_info.extend_from_slice(AUTH_INFO);
    key_info.extend_from_slice(ua_public);
    key_info.extend_from_slice(as_public);
    let ikm = hkdf_expand(&prk_key, &key_info, 32);

    // Content-encryption key + nonce, salted by the per-message salt.
    let prk = hkdf_extract(salt, &ikm);
    let cek: [u8; 16] = hkdf_expand(&prk, CEK_INFO, 16).try_into().unwrap();
    let nonce: [u8; 12] = hkdf_expand(&prk, NONCE_INFO, 12).try_into().unwrap();
    (cek, nonce)
}

/// Encrypt `plaintext` for a subscription with a fixed salt + sender key. The
/// returned bytes are the full `aes128gcm` message body (header + record), ready
/// to POST with `Content-Encoding: aes128gcm`. Deterministic — used by the
/// vector test; production callers use [`seal`].
fn encrypt_with(
    plaintext: &[u8],
    ua_public: &[u8],
    auth_secret: &[u8],
    salt: &[u8; 16],
    as_secret: &SecretKey,
) -> Result<Vec<u8>, String> {
    let ua_pk = PublicKey::from_sec1_bytes(ua_public)
        .map_err(|e| format!("invalid subscription p256dh key: {e}"))?;
    let as_public_pt = as_secret.public_key().to_encoded_point(false);
    let as_public = as_public_pt.as_bytes(); // 65-byte uncompressed point

    let shared = diffie_hellman(as_secret.to_nonzero_scalar(), ua_pk.as_affine());
    let (cek, nonce) = derive_content_keys(
        ua_public,
        as_public,
        auth_secret,
        salt,
        shared.raw_secret_bytes(),
    );

    // Single record: plaintext || 0x02 (last-record delimiter), then AEAD-sealed.
    let mut record = Vec::with_capacity(plaintext.len() + 1 + 16);
    record.extend_from_slice(plaintext);
    record.push(0x02);
    let unbound = aead::UnboundKey::new(&aead::AES_128_GCM, &cek)
        .map_err(|_| "aead key init failed".to_string())?;
    let key = aead::LessSafeKey::new(unbound);
    key.seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key(nonce),
        aead::Aad::empty(),
        &mut record,
    )
    .map_err(|_| "aead seal failed".to_string())?;

    // Header: salt(16) || record_size(4, BE) || idlen(1) || keyid(=as_public).
    let mut body = Vec::with_capacity(16 + 4 + 1 + as_public.len() + record.len());
    body.extend_from_slice(salt);
    body.extend_from_slice(&RECORD_SIZE.to_be_bytes());
    body.push(as_public.len() as u8);
    body.extend_from_slice(as_public);
    body.extend_from_slice(&record);
    Ok(body)
}

/// Encrypt `plaintext` for a subscription, generating a fresh salt + ephemeral
/// sender key. Returns the `aes128gcm` message body.
pub(crate) fn seal(
    plaintext: &[u8],
    ua_public: &[u8],
    auth_secret: &[u8],
) -> Result<Vec<u8>, String> {
    let as_secret = SecretKey::random(&mut OsRng);
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    encrypt_with(plaintext, ua_public, auth_secret, &salt, &as_secret)
}

// ---------------------------------------------------------------------------
// WebPushSink — deliver an encrypted message to a browser push service with a
// VAPID-authenticated POST.
// ---------------------------------------------------------------------------

/// A browser `PushSubscription`, the "token" for a web device.
#[derive(Deserialize)]
struct Subscription {
    endpoint: String,
    keys: SubscriptionKeys,
}

#[derive(Deserialize)]
struct SubscriptionKeys {
    /// base64url uncompressed P-256 public key.
    p256dh: String,
    /// base64url 16-byte auth secret.
    auth: String,
}

fn loopback_mock_allowed() -> bool {
    std::env::var(ALLOW_PRIVATE_ENDPOINTS_ENV).as_deref() == Ok("1")
}

/// Validate the network destination carried inside a serialized browser
/// `PushSubscription`. This runs both when the device is registered and again
/// immediately before delivery so legacy/WAL-restored rows cannot bypass it.
pub(super) fn validate_subscription_token(token: &str) -> Result<(), String> {
    parse_subscription(token, loopback_mock_allowed()).map(|_| ())
}

fn parse_subscription(token: &str, allow_loopback_mock: bool) -> Result<Subscription, String> {
    if token.is_empty() || token.len() > super::MAX_WEB_SUBSCRIPTION_BYTES {
        return Err(format!(
            "web push subscription must contain 1 to {} bytes",
            super::MAX_WEB_SUBSCRIPTION_BYTES
        ));
    }
    let subscription: Subscription =
        serde_json::from_str(token).map_err(|e| format!("invalid web push subscription: {e}"))?;
    validate_endpoint(&subscription.endpoint, allow_loopback_mock)?;
    let public_key = b64url_decode(&subscription.keys.p256dh)
        .map_err(|_| "invalid web push p256dh key".to_string())?;
    if public_key.len() != 65 || PublicKey::from_sec1_bytes(&public_key).is_err() {
        return Err("invalid web push p256dh key".to_string());
    }
    let auth = b64url_decode(&subscription.keys.auth)
        .map_err(|_| "invalid web push auth secret".to_string())?;
    if auth.len() != 16 {
        return Err("invalid web push auth secret".to_string());
    }
    Ok(subscription)
}

fn validate_endpoint(endpoint: &str, allow_loopback_mock: bool) -> Result<reqwest::Url, String> {
    if endpoint.is_empty() || endpoint.len() > MAX_ENDPOINT_BYTES {
        return Err(format!(
            "bad push endpoint: must contain 1 to {MAX_ENDPOINT_BYTES} bytes"
        ));
    }
    let url = reqwest::Url::parse(endpoint).map_err(|e| format!("bad push endpoint: {e}"))?;
    if url.username() != "" || url.password().is_some() {
        return Err("bad push endpoint: credentials are not allowed".to_string());
    }
    if url.fragment().is_some() {
        return Err("bad push endpoint: fragments are not allowed".to_string());
    }
    let host = url
        .host_str()
        .ok_or_else(|| "bad push endpoint: host is required".to_string())?;
    let normalized = host.trim_end_matches('.').to_ascii_lowercase();
    let localhost_name = normalized == "localhost";
    let reserved_localhost_name = localhost_name || normalized.ends_with(".localhost");
    let ip_literal = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    let literal_ip = ip_literal.parse::<IpAddr>().ok();
    let loopback = localhost_name || literal_ip.is_some_and(|address| address.is_loopback());
    match url.scheme() {
        "https" => {}
        "http" if allow_loopback_mock && loopback => {}
        _ => return Err("bad push endpoint: HTTPS is required".to_string()),
    }
    if reserved_localhost_name && !(allow_loopback_mock && localhost_name) {
        return Err("bad push endpoint: private hosts are not allowed".to_string());
    }
    if let Some(ip) = literal_ip {
        if !is_public_ip(ip) && !(allow_loopback_mock && ip.is_loopback()) {
            return Err("bad push endpoint: private addresses are not allowed".to_string());
        }
    }
    Ok(url)
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_ipv4(ip),
        IpAddr::V6(ip) => is_public_ipv6(ip),
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_multicast()
        || a == 0
        || (a == 100 && (64..=127).contains(&b))
        || (a == 192 && b == 0)
        || (a == 198 && (b == 18 || b == 19))
        || a >= 240)
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    // Globally routed unicast space is 2000::/3. Keep the policy deliberately
    // conservative, and exclude documentation space inside that range.
    (segments[0] & 0xe000) == 0x2000 && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
}

fn resolved_address_allowed(host: &str, ip: IpAddr, allow_loopback_mock: bool) -> bool {
    is_public_ip(ip)
        || (allow_loopback_mock
            && host.trim_end_matches('.').eq_ignore_ascii_case("localhost")
            && ip.is_loopback())
}

#[derive(Debug)]
struct PublicDnsResolver {
    allow_loopback_mock: bool,
}

impl reqwest::dns::Resolve for PublicDnsResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        let allow_loopback_mock = self.allow_loopback_mock;
        Box::pin(async move {
            let resolved = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map_err(|error| {
                    Box::new(error) as Box<dyn std::error::Error + Send + Sync + 'static>
                })?;
            let addresses: Vec<SocketAddr> = resolved
                .filter(|address| {
                    resolved_address_allowed(&host, address.ip(), allow_loopback_mock)
                })
                .collect();
            if addresses.is_empty() {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "push endpoint resolved only to private addresses",
                ))
                    as Box<dyn std::error::Error + Send + Sync + 'static>);
            }
            Ok(Box::new(addresses.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

#[derive(Serialize)]
struct VapidClaims {
    aud: String,
    exp: u64,
    sub: String,
}

pub(crate) struct WebPushSink {
    client: reqwest::Client,
    /// base64url public key, sent as the `k=` VAPID parameter.
    public_key: String,
    private_pem: String,
    subject: String,
}

impl WebPushSink {
    pub fn new(creds: super::ResolvedVapidCreds) -> Result<Self, String> {
        let allow_loopback_mock = loopback_mock_allowed();
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            // A configured forward proxy would perform its own DNS resolution
            // and bypass the address filter below.
            .no_proxy()
            // Never follow a push-service redirect to a destination that was
            // not validated or used as the VAPID audience.
            .redirect(reqwest::redirect::Policy::none())
            // Validate resolved addresses at connect time as well as literal IP
            // hosts above, closing the DNS-rebinding/private-DNS gap. The test
            // override admits only the exact localhost hostname.
            .dns_resolver(Arc::new(PublicDnsResolver {
                allow_loopback_mock,
            }));
        let client = client
            .build()
            .map_err(|e| format!("web push client setup failed: {e}"))?;
        let subject = if creds.subject.trim().is_empty() {
            "mailto:push@luxdb.dev".to_string()
        } else {
            creds.subject
        };
        Ok(Self {
            client,
            public_key: creds.public_key,
            private_pem: creds.private_pem,
            subject,
        })
    }

    /// Sign a VAPID JWT (RFC 8292) scoped to the push service origin.
    fn vapid_jwt(&self, endpoint: &str) -> Result<String, DeliveryError> {
        let endpoint = validate_endpoint(endpoint, loopback_mock_allowed())
            .map_err(DeliveryError::InvalidTarget)?;
        let aud = endpoint.origin().ascii_serialization();
        let claims = VapidClaims {
            aud,
            exp: crate::auth::unix_seconds() + 12 * 3600,
            sub: self.subject.clone(),
        };
        let key = EncodingKey::from_ec_pem(self.private_pem.as_bytes())
            .map_err(|e| DeliveryError::Permanent(format!("invalid VAPID key: {e}")))?;
        encode(&Header::new(Algorithm::ES256), &claims, &key)
            .map_err(|e| DeliveryError::Permanent(format!("VAPID JWT sign failed: {e}")))
    }
}

impl Sink for WebPushSink {
    async fn deliver(&self, target: &DeliveryTarget, payload: &[u8]) -> Result<(), DeliveryError> {
        // The web "token" is the serialized browser PushSubscription.
        let sub = parse_subscription(&target.token, loopback_mock_allowed())
            .map_err(DeliveryError::InvalidTarget)?;
        let p256dh = b64url_decode(&sub.keys.p256dh).map_err(DeliveryError::InvalidTarget)?;
        let auth = b64url_decode(&sub.keys.auth).map_err(DeliveryError::InvalidTarget)?;
        let body = seal(payload, &p256dh, &auth).map_err(DeliveryError::InvalidTarget)?;
        let jwt = self.vapid_jwt(&sub.endpoint)?;

        let resp = self
            .client
            .post(&sub.endpoint)
            .header("Content-Encoding", "aes128gcm")
            .header("Content-Type", "application/octet-stream")
            .header("TTL", "86400")
            .header(
                "Authorization",
                format!("vapid t={jwt}, k={}", self.public_key),
            )
            .body(body)
            .send()
            .await
            .map_err(|error| {
                let message = if error.is_timeout() {
                    "web push request timed out"
                } else if error.is_connect() {
                    "web push connection failed"
                } else {
                    "web push transport failed"
                };
                DeliveryError::Retryable(message.to_string())
            })?;
        classify_web_push(resp.status().as_u16())
    }
}

/// Push-service response classification. 404/410 mean the subscription is gone
/// (prune it); 429/5xx are retryable.
fn classify_web_push(status: u16) -> Result<(), DeliveryError> {
    match status {
        200..=202 => Ok(()),
        404 | 410 => Err(DeliveryError::InvalidTarget(format!(
            "subscription gone ({status})"
        ))),
        300..=399 => Err(DeliveryError::Permanent(format!(
            "push service redirect refused ({status})"
        ))),
        400..=499 if status != 429 => Err(DeliveryError::Permanent(format!("rejected ({status})"))),
        429 => Err(DeliveryError::Retryable("throttled".to_string())),
        500..=599 => Err(DeliveryError::Retryable(format!(
            "push service error ({status})"
        ))),
        other => Err(DeliveryError::Retryable(format!(
            "unexpected push status {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8291 Appendix A.
    const PLAINTEXT: &str = "V2hlbiBJIGdyb3cgdXAsIEkgd2FudCB0byBiZSBhIHdhdGVybWVsb24";
    const SALT: &str = "DGv6ra1nlYgDCS1FRnbzlw";
    const AUTH: &str = "BTBZMqHH6r4Tts7J_aSIgg";
    const UA_PUBLIC: &str =
        "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4";
    const AS_PRIVATE: &str = "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw";
    const SHARED: &str = "kyrL1jIIOHEzg3sM2ZWRHDRB62YACZhhSlknJ672kSs";
    const CEK: &str = "oIhVW04MRdy2XN9CiKLxTg";
    const NONCE: &str = "4h_95klXJ5E_qnoN";
    const CIPHERTEXT: &str =
        "8pfeW0KbunFT06SuDKoJH9Ql87S1QUrdirN6GcG7sFz1y1sqLgVi1VhjVkHsUoEsbI_0LpXMuGvnzQ";

    fn enc(b: &[u8]) -> String {
        B64.encode(b)
    }

    #[test]
    fn rfc8291_appendix_a_vector() {
        let plaintext = b64url_decode(PLAINTEXT).unwrap();
        let salt: [u8; 16] = b64url_decode(SALT).unwrap().try_into().unwrap();
        let auth = b64url_decode(AUTH).unwrap();
        let ua_public = b64url_decode(UA_PUBLIC).unwrap();
        let as_secret = SecretKey::from_slice(&b64url_decode(AS_PRIVATE).unwrap()).unwrap();

        // ECDH shared secret matches the RFC.
        let ua_pk = PublicKey::from_sec1_bytes(&ua_public).unwrap();
        let shared = diffie_hellman(as_secret.to_nonzero_scalar(), ua_pk.as_affine());
        assert_eq!(enc(shared.raw_secret_bytes()), SHARED, "ecdh secret");

        // Derived CEK + nonce match the RFC.
        let as_public_pt = as_secret.public_key().to_encoded_point(false);
        let (cek, nonce) = derive_content_keys(
            &ua_public,
            as_public_pt.as_bytes(),
            &auth,
            &salt,
            shared.raw_secret_bytes(),
        );
        assert_eq!(enc(&cek), CEK, "content encryption key");
        assert_eq!(enc(&nonce), NONCE, "nonce");

        // Full ciphertext (record after the header) matches the RFC.
        let body = encrypt_with(&plaintext, &ua_public, &auth, &salt, &as_secret).unwrap();
        let header_len = 16 + 4 + 1 + as_public_pt.as_bytes().len();
        assert_eq!(enc(&body[header_len..]), CIPHERTEXT, "aes128gcm ciphertext");
    }

    #[test]
    fn seal_produces_a_wellformed_body() {
        let ua_public = b64url_decode(UA_PUBLIC).unwrap();
        let auth = b64url_decode(AUTH).unwrap();
        let body = seal(b"hello", &ua_public, &auth).unwrap();
        // header = salt(16) + rs(4) + idlen(1) + keyid(65); record = 5 + 1 + 16 tag.
        assert_eq!(body.len(), 16 + 4 + 1 + 65 + (5 + 1 + 16));
        assert_eq!(body[16 + 4], 65, "keyid length byte");
    }

    #[test]
    fn endpoint_policy_rejects_ssrf_destinations() {
        for endpoint in [
            "http://push.example.test/device",
            "https://localhost/device",
            "https://api.localhost/device",
            "https://127.0.0.1/device",
            "https://10.1.2.3/device",
            "https://169.254.169.254/latest/meta-data",
            "https://[::1]/device",
            "https://[fd00::1]/device",
            "https://user:password@push.example.test/device",
            "https://push.example.test/device#fragment",
        ] {
            assert!(
                validate_endpoint(endpoint, false).is_err(),
                "unsafe endpoint was accepted: {endpoint}"
            );
        }
    }

    #[test]
    fn endpoint_policy_accepts_public_https_and_explicit_test_override() {
        assert!(validate_endpoint(
            "https://updates.push.services.mozilla.com/wpush/v2/id",
            false
        )
        .is_ok());
        assert!(validate_endpoint("http://127.0.0.1:9000/mock", true).is_ok());
        assert!(validate_endpoint("http://localhost:9000/mock", true).is_ok());
        assert!(validate_endpoint("http://10.1.2.3/mock", true).is_err());
        assert!(validate_endpoint("http://push.example.test/mock", true).is_err());
        assert!(validate_endpoint("https://10.1.2.3/mock", true).is_err());
    }

    #[test]
    fn dns_address_policy_keeps_only_public_or_explicit_loopback_addresses() {
        for address in [
            "127.0.0.1",
            "10.1.2.3",
            "169.254.169.254",
            "100.64.0.1",
            "::1",
            "fd00::1",
            "2001:db8::1",
        ] {
            assert!(!is_public_ip(address.parse().unwrap()), "{address}");
        }
        for address in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(is_public_ip(address.parse().unwrap()), "{address}");
        }
    }

    #[test]
    fn dns_rebinding_to_private_space_is_rejected_at_connect_time() {
        let private: IpAddr = "169.254.169.254".parse().unwrap();
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        let public: IpAddr = "1.1.1.1".parse().unwrap();
        assert!(!resolved_address_allowed("push.example", private, false));
        assert!(!resolved_address_allowed("push.example", loopback, false));
        assert!(!resolved_address_allowed("push.example", loopback, true));
        assert!(resolved_address_allowed("push.example", public, false));
        assert!(resolved_address_allowed("localhost", loopback, true));
    }

    #[test]
    fn malformed_subscription_keys_are_rejected_before_delivery() {
        let bad_curve = serde_json::json!({
            "endpoint": "https://push.example.test/device",
            "keys": { "p256dh": enc(&[4_u8; 65]), "auth": enc(&[7_u8; 16]) }
        });
        assert!(parse_subscription(&bad_curve.to_string(), false).is_err());

        let secret = SecretKey::random(&mut OsRng);
        let valid_public = enc(secret.public_key().to_encoded_point(false).as_bytes());
        let short_auth = serde_json::json!({
            "endpoint": "https://push.example.test/device",
            "keys": { "p256dh": valid_public, "auth": enc(&[7_u8; 15]) }
        });
        assert!(parse_subscription(&short_auth.to_string(), false).is_err());
    }

    #[test]
    fn response_classification_only_prunes_gone_subscriptions() {
        assert!(classify_web_push(201).is_ok());
        assert!(classify_web_push(410).unwrap_err().invalidates_target());

        let bad_request = classify_web_push(400).unwrap_err();
        assert!(bad_request.is_permanent());
        assert!(!bad_request.invalidates_target());

        let unavailable = classify_web_push(503).unwrap_err();
        assert!(!unavailable.is_permanent());
        assert!(!unavailable.invalidates_target());

        let redirect = classify_web_push(302).unwrap_err();
        assert!(redirect.is_permanent());
        assert!(!redirect.invalidates_target());
    }
}
