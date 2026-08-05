use super::ClusterError;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

const MAX_ENCODED_CONTROLLER_KEY_BYTES: usize = 128;
const MAX_ENCODED_SIGNATURE_BYTES: usize = 128;

#[must_use]
pub fn encode_controller_public_key(verifying_key: &VerifyingKey) -> String {
    URL_SAFE_NO_PAD.encode(verifying_key.to_encoded_point(false).as_bytes())
}

pub(super) fn sign_payload(payload: &[u8], signing_key: &SigningKey) -> String {
    let signature: Signature = signing_key.sign(payload);
    let signature = signature.normalize_s().unwrap_or(signature);
    URL_SAFE_NO_PAD.encode(signature.to_bytes())
}

pub(super) fn verify_payload(
    payload: &[u8],
    encoded_signature: &str,
    encoded_public_key: &str,
) -> Result<(), ClusterError> {
    if encoded_public_key.len() > MAX_ENCODED_CONTROLLER_KEY_BYTES {
        return Err(ClusterError::Signature(
            "encoded controller public key is too large".to_owned(),
        ));
    }
    if encoded_signature.len() > MAX_ENCODED_SIGNATURE_BYTES {
        return Err(ClusterError::Signature(
            "encoded cluster signature is too large".to_owned(),
        ));
    }
    let key_bytes = URL_SAFE_NO_PAD
        .decode(encoded_public_key)
        .map_err(|error| {
            ClusterError::Signature(format!("public key is not base64url: {error}"))
        })?;
    let verifying_key = VerifyingKey::from_sec1_bytes(&key_bytes).map_err(|error| {
        ClusterError::Signature(format!("public key is not P-256 SEC1: {error}"))
    })?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(encoded_signature)
        .map_err(|error| ClusterError::Signature(format!("signature is not base64url: {error}")))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|error| ClusterError::Signature(format!("signature is not P-256: {error}")))?;
    if signature.normalize_s().is_some() {
        return Err(ClusterError::Signature(
            "signature is not in canonical low-S form".to_owned(),
        ));
    }
    verifying_key
        .verify(payload, &signature)
        .map_err(|_| ClusterError::Signature("signed payload did not verify".to_owned()))
}
