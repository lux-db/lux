//! Web Push message encryption (RFC 8291) with the `aes128gcm` content coding
//! (RFC 8188). This is the wire format browsers' push services require:
//! ephemeral P-256 ECDH against the subscription key, HKDF-SHA256 to a
//! content-encryption key + nonce, then a single AES-128-GCM record.
//!
//! Validated against the RFC 8291 Appendix A test vector (see tests).

use std::time::Duration;

use base64::Engine as _;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::sec1::ToEncodedPoint;
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

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

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
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
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
        let aud = origin_of(endpoint)
            .ok_or_else(|| DeliveryError::Terminal(format!("bad push endpoint: {endpoint}")))?;
        let claims = VapidClaims {
            aud,
            exp: crate::auth::unix_seconds() + 12 * 3600,
            sub: self.subject.clone(),
        };
        let key = EncodingKey::from_ec_pem(self.private_pem.as_bytes())
            .map_err(|e| DeliveryError::Terminal(format!("invalid VAPID key: {e}")))?;
        encode(&Header::new(Algorithm::ES256), &claims, &key)
            .map_err(|e| DeliveryError::Terminal(format!("VAPID JWT sign failed: {e}")))
    }
}

impl Sink for WebPushSink {
    async fn deliver(&self, target: &DeliveryTarget, payload: &[u8]) -> Result<(), DeliveryError> {
        // The web "token" is the serialized browser PushSubscription.
        let sub: Subscription = serde_json::from_str(&target.token)
            .map_err(|e| DeliveryError::Terminal(format!("invalid web push subscription: {e}")))?;
        let p256dh = b64url_decode(&sub.keys.p256dh).map_err(DeliveryError::Terminal)?;
        let auth = b64url_decode(&sub.keys.auth).map_err(DeliveryError::Terminal)?;
        let body = seal(payload, &p256dh, &auth).map_err(DeliveryError::Terminal)?;
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
            .map_err(|e| DeliveryError::Retryable(format!("web push transport: {e}")))?;
        classify_web_push(resp.status().as_u16())
    }
}

/// Push-service response classification. 404/410 mean the subscription is gone
/// (prune it); 429/5xx are retryable.
fn classify_web_push(status: u16) -> Result<(), DeliveryError> {
    match status {
        200..=202 => Ok(()),
        404 | 410 => Err(DeliveryError::Terminal(format!(
            "subscription gone ({status})"
        ))),
        400 | 401 | 403 => Err(DeliveryError::Terminal(format!("rejected ({status})"))),
        429 => Err(DeliveryError::Retryable("throttled".to_string())),
        500..=599 => Err(DeliveryError::Retryable(format!(
            "push service error ({status})"
        ))),
        other => Err(DeliveryError::Retryable(format!(
            "unexpected push status {other}"
        ))),
    }
}

/// `scheme://host[:port]` of a URL (the VAPID audience).
fn origin_of(url: &str) -> Option<String> {
    let scheme_end = url.find("://")?;
    let rest = &url[scheme_end + 3..];
    let host_len = rest.find('/').unwrap_or(rest.len());
    Some(format!("{}://{}", &url[..scheme_end], &rest[..host_len]))
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
}
