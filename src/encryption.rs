use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine;
use parking_lot::RwLock;
use rand_core::{OsRng, RngCore};
use ring::{aead, hmac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const ENVELOPE_MAGIC: &[u8] = b"LUXENC2";
const STATE_MAGIC: &[u8] = b"LUXENCSTATE1";
const NONCE_LEN: usize = 12;
const DATA_KEY_LEN: usize = 32;
const WRAPPED_DATA_KEY_LEN: usize = DATA_KEY_LEN + 16;

#[derive(Clone, Default)]
pub struct EncryptionConfig {
    /// Legacy/bootstrap active key id. Native deployments should use ENC INIT /
    /// ENC ROTATE and persisted encryption state instead.
    pub active_key_id: Option<String>,
    /// Legacy/bootstrap key list. Used when no persisted ENC state exists.
    pub keys: Vec<EncryptionKeyConfig>,
    /// Optional sealed ENC state path. Defaults to `<data_dir>/lux.enc`.
    pub state_path: Option<String>,
    /// Optional local seal secret path. Defaults to `<data_dir>/lux.enc.seal`.
    pub seal_path: Option<String>,
    /// Generate persisted ENC state automatically when no state exists.
    pub auto_init: bool,
    /// Seal key sourced from outside the data volume (e.g. an injected env var).
    /// When set, the keyring is sealed/unsealed with this instead of the on-disk
    /// seal file, so a stolen data volume does not also carry the key.
    pub seal_secret: Option<[u8; 32]>,
    /// Prior seal keys accepted for *unsealing* only (seal rotation). On open the
    /// keyring is re-sealed under `seal_secret`; these let a rotated deployment
    /// still read state sealed by the previous key.
    pub previous_seal_secrets: Vec<[u8; 32]>,
}

impl std::fmt::Debug for EncryptionConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptionConfig")
            .field("active_key_id", &self.active_key_id)
            .field("keys", &self.keys.iter().map(|k| &k.id).collect::<Vec<_>>())
            .field("state_path", &self.state_path)
            .field("seal_path", &self.seal_path)
            .field("auto_init", &self.auto_init)
            .field("seal_secret", &self.seal_secret.map(|_| "<redacted>"))
            .field("previous_seal_secrets", &self.previous_seal_secrets.len())
            .finish()
    }
}

#[derive(Clone)]
pub struct EncryptionKeyConfig {
    pub id: String,
    pub secret: Vec<u8>,
    pub decrypt_only: bool,
}

impl std::fmt::Debug for EncryptionKeyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptionKeyConfig")
            .field("id", &self.id)
            .field("secret", &"<redacted>")
            .field("decrypt_only", &self.decrypt_only)
            .finish()
    }
}

pub(crate) struct EncryptionKeyring {
    inner: RwLock<EncryptionState>,
    state_path: Option<PathBuf>,
    seal_path: Option<PathBuf>,
    /// Env-sourced seal used to seal/unseal persisted state. When `None`, the
    /// on-disk `seal_path` file is the seal source (local-dev behavior). Previous
    /// seals (rotation / file-to-env migration) are only needed while unsealing at
    /// `open`, so they are not retained on the keyring.
    seal_secret: Option<[u8; 32]>,
}

struct EncryptionState {
    active_key_id: Option<String>,
    keys: HashMap<String, NetworkKey>,
}

struct NetworkKey {
    secret: Vec<u8>,
    wrap_key: aead::LessSafeKey,
    search_key: hmac::Key,
    decrypt_only: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct EncryptionStatus {
    pub initialized: bool,
    pub active_key_id: Option<String>,
    pub key_count: usize,
    pub persisted: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct EncryptionKeyInfo {
    pub id: String,
    pub status: &'static str,
}

#[derive(Debug, Serialize, Deserialize)]
struct PlainState {
    version: u8,
    active_key_id: Option<String>,
    keys: Vec<PlainKey>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PlainKey {
    id: String,
    secret: String,
    decrypt_only: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct SealedState {
    version: u8,
    nonce: String,
    ciphertext: String,
}

impl EncryptionKeyring {
    pub(crate) fn open(config: &EncryptionConfig, data_dir: &str) -> Result<Self, String> {
        let state_path = resolve_path(config.state_path.as_deref(), data_dir, "lux.enc");
        let seal_path = resolve_path(config.seal_path.as_deref(), data_dir, "lux.enc.seal");
        let seal_secret = config.seal_secret;
        let previous_seal_secrets = config.previous_seal_secrets.clone();

        // Unseal existing state by trying every candidate seal (current env seal,
        // rotated-out previous seals, then the on-disk file seal). Track whether
        // the seal that actually opened it matches the current sealing seal; if
        // not, we re-seal below so the state converges onto the current seal.
        let mut needs_reseal = false;
        let state = if state_path.as_ref().is_some_and(|p| p.exists()) {
            let candidates =
                collect_candidate_seals(seal_secret, &previous_seal_secrets, seal_path.as_deref())?;
            let (state, used_seal) = Self::load_state(
                state_path.as_ref().expect("state path checked").as_path(),
                &candidates,
            )?;
            let current = current_seal(seal_secret, seal_path.as_deref())?;
            needs_reseal = used_seal != current;
            state
        } else {
            Self::state_from_config(config)?
        };

        let keyring = Self {
            inner: RwLock::new(state),
            state_path,
            seal_path,
            seal_secret,
        };
        keyring.validate()?;

        // Migration / rotation: re-seal persisted state under the current seal
        // when it was opened with a previous or on-disk seal.
        if needs_reseal {
            let inner = keyring.inner.read();
            keyring.persist_state(&inner)?;
        }

        if config.auto_init && !keyring.has_active_key() {
            keyring.init(None)?;
        }

        // When the seal is sourced from the env, the on-disk seal file is now
        // obsolete (state is sealed under the env seal). Remove it so a stolen
        // data volume no longer carries the key that opens it.
        if keyring.seal_secret.is_some() {
            if let Some(path) = &keyring.seal_path {
                if path.exists() {
                    let _ = fs::remove_file(path);
                }
            }
        }

        Ok(keyring)
    }

    fn state_from_config(config: &EncryptionConfig) -> Result<EncryptionState, String> {
        let keys = build_network_keys(&config.keys)?;
        validate_active_key(config.active_key_id.as_deref(), &keys)?;
        Ok(EncryptionState {
            active_key_id: config.active_key_id.clone(),
            keys,
        })
    }

    fn validate(&self) -> Result<(), String> {
        let inner = self.inner.read();
        validate_active_key(inner.active_key_id.as_deref(), &inner.keys)
    }

    pub(crate) fn status(&self) -> EncryptionStatus {
        let inner = self.inner.read();
        EncryptionStatus {
            initialized: inner.active_key_id.is_some(),
            active_key_id: inner.active_key_id.clone(),
            key_count: inner.keys.len(),
            persisted: self.state_path.as_ref().is_some_and(|p| p.exists()),
        }
    }

    pub(crate) fn list(&self) -> Vec<EncryptionKeyInfo> {
        let inner = self.inner.read();
        let mut keys: Vec<EncryptionKeyInfo> = inner
            .keys
            .iter()
            .map(|(id, key)| EncryptionKeyInfo {
                id: id.clone(),
                status: if inner.active_key_id.as_deref() == Some(id.as_str()) {
                    "active"
                } else if key.decrypt_only {
                    "decrypt-only"
                } else {
                    "available"
                },
            })
            .collect();
        keys.sort_by(|a, b| a.id.cmp(&b.id));
        keys
    }

    pub(crate) fn init(&self, requested_id: Option<&str>) -> Result<String, String> {
        let mut inner = self.inner.write();
        if let Some(active) = inner.active_key_id.clone() {
            return Ok(active);
        }
        let id = requested_id
            .map(str::to_string)
            .unwrap_or_else(generate_key_id);
        validate_key_id(&id)?;
        let key = EncryptionKeyConfig {
            id: id.clone(),
            secret: generate_secret(),
            decrypt_only: false,
        };
        inner.keys = build_network_keys(&[key])?;
        inner.active_key_id = Some(id.clone());
        self.persist_state(&inner)?;
        Ok(id)
    }

    pub(crate) fn rotate(&self, requested_id: Option<&str>) -> Result<String, String> {
        let mut inner = self.inner.write();
        if inner.keys.is_empty() {
            drop(inner);
            return self.init(requested_id);
        }
        let id = requested_id
            .map(str::to_string)
            .unwrap_or_else(generate_key_id);
        validate_key_id(&id)?;
        if inner.keys.contains_key(&id) {
            return Err(format!("ERR ENC key '{}' already exists", id));
        }
        for key in inner.keys.values_mut() {
            key.decrypt_only = true;
        }
        let config = EncryptionKeyConfig {
            id: id.clone(),
            secret: generate_secret(),
            decrypt_only: false,
        };
        let mut new_keys = build_network_keys(&[config])?;
        inner
            .keys
            .insert(id.clone(), new_keys.remove(&id).expect("new key exists"));
        inner.active_key_id = Some(id.clone());
        self.persist_state(&inner)?;
        Ok(id)
    }

    pub(crate) fn retire(&self, key_id: &str) -> Result<(), String> {
        let mut inner = self.inner.write();
        if inner.active_key_id.as_deref() == Some(key_id) {
            return Err("ERR ENC cannot retire the active key".to_string());
        }
        if inner.keys.remove(key_id).is_none() {
            return Err(format!("ERR ENC key '{}' does not exist", key_id));
        }
        self.persist_state(&inner)
    }

    pub(crate) fn remaining_key_ids_without(&self, key_id: &str) -> HashSet<String> {
        self.inner
            .read()
            .keys
            .keys()
            .filter(|id| id.as_str() != key_id)
            .cloned()
            .collect()
    }

    pub(crate) fn is_encrypted_value(raw: &[u8]) -> bool {
        raw.starts_with(ENVELOPE_MAGIC)
    }

    pub(crate) fn envelope_decryptable_by_any(envelope: &[u8], key_ids: &HashSet<String>) -> bool {
        parse_envelope(envelope).is_ok_and(|parsed| {
            parsed
                .wraps
                .iter()
                .any(|wrap| key_ids.contains(wrap.key_id))
        })
    }

    pub(crate) fn reencrypt(
        &self,
        table: &str,
        field: &str,
        pk: &str,
        envelope: &[u8],
    ) -> Result<Vec<u8>, String> {
        let plaintext = self.decrypt(table, field, pk, envelope)?;
        self.encrypt(table, field, pk, &plaintext)
    }

    pub(crate) fn has_active_key(&self) -> bool {
        self.inner.read().active_key_id.is_some()
    }

    pub(crate) fn encrypt(
        &self,
        table: &str,
        field: &str,
        pk: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, String> {
        let inner = self.inner.read();
        let active_key_id = inner
            .active_key_id
            .as_deref()
            .ok_or_else(|| "ERR encrypted values require an active encryption key".to_string())?;
        if inner.keys.is_empty() {
            return Err("ERR encrypted values require at least one encryption key".to_string());
        }

        let mut data_key = [0u8; DATA_KEY_LEN];
        OsRng.fill_bytes(&mut data_key);

        let value_key = data_value_key(&data_key)?;
        let mut value_nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut value_nonce);
        let aad = value_aad(table, field, pk, active_key_id);
        let mut ciphertext = plaintext.to_vec();
        value_key
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(value_nonce),
                aead::Aad::from(aad.as_slice()),
                &mut ciphertext,
            )
            .map_err(|_| "ERR encryption failed".to_string())?;

        let mut key_ids: Vec<&String> = inner.keys.keys().collect();
        key_ids.sort();
        let wrap_aad = wrap_aad(table, field, pk, active_key_id);
        let mut wraps = Vec::with_capacity(key_ids.len());
        for key_id in key_ids {
            let Some(key) = inner.keys.get(key_id) else {
                continue;
            };
            let mut wrap_nonce = [0u8; NONCE_LEN];
            OsRng.fill_bytes(&mut wrap_nonce);
            let mut wrapped = data_key.to_vec();
            key.wrap_key
                .seal_in_place_append_tag(
                    aead::Nonce::assume_unique_for_key(wrap_nonce),
                    aead::Aad::from(wrap_aad.as_slice()),
                    &mut wrapped,
                )
                .map_err(|_| "ERR encryption key wrap failed".to_string())?;
            wraps.push((key_id.as_str(), wrap_nonce, wrapped));
        }
        if wraps.len() > u8::MAX as usize {
            return Err("ERR too many encryption keys for one encrypted value".to_string());
        }

        let mut envelope = Vec::new();
        envelope.extend_from_slice(ENVELOPE_MAGIC);
        envelope.push(active_key_id.len() as u8);
        envelope.extend_from_slice(active_key_id.as_bytes());
        envelope.push(wraps.len() as u8);
        for (key_id, nonce, wrapped) in wraps {
            envelope.push(key_id.len() as u8);
            envelope.extend_from_slice(key_id.as_bytes());
            envelope.extend_from_slice(&nonce);
            envelope.extend_from_slice(&wrapped);
        }
        envelope.extend_from_slice(&value_nonce);
        envelope.extend_from_slice(&ciphertext);
        Ok(envelope)
    }

    pub(crate) fn decrypt(
        &self,
        table: &str,
        field: &str,
        pk: &str,
        envelope: &[u8],
    ) -> Result<Vec<u8>, String> {
        let inner = self.inner.read();
        let parsed = parse_envelope(envelope)?;
        let wrap_aad = wrap_aad(table, field, pk, parsed.writer_key_id);
        let mut data_key = None;
        for wrap in parsed.wraps {
            let Some(key) = inner.keys.get(wrap.key_id) else {
                continue;
            };
            let mut in_out = wrap.wrapped_data_key.to_vec();
            if let Ok(opened) = key.wrap_key.open_in_place(
                aead::Nonce::assume_unique_for_key(*wrap.nonce),
                aead::Aad::from(wrap_aad.as_slice()),
                &mut in_out,
            ) {
                if opened.len() == DATA_KEY_LEN {
                    let mut key_bytes = [0u8; DATA_KEY_LEN];
                    key_bytes.copy_from_slice(opened);
                    data_key = Some(key_bytes);
                    break;
                }
            }
        }
        let data_key = data_key.ok_or_else(|| {
            "ERR encrypted value cannot be decrypted by configured keys".to_string()
        })?;
        let value_key = data_value_key(&data_key)?;
        let aad = value_aad(table, field, pk, parsed.writer_key_id);
        let mut in_out = parsed.ciphertext.to_vec();
        let plaintext = value_key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(*parsed.value_nonce),
                aead::Aad::from(aad.as_slice()),
                &mut in_out,
            )
            .map_err(|_| "ERR encrypted value could not be decrypted".to_string())?;
        Ok(plaintext.to_vec())
    }

    pub(crate) fn blind_indexes(
        &self,
        table: &str,
        field: &str,
        encoded_value: &[u8],
    ) -> Result<Vec<String>, String> {
        let inner = self.inner.read();
        if inner.keys.is_empty() {
            return Err(
                "ERR searchable encrypted columns require configured encryption keys".to_string(),
            );
        }
        let mut key_ids: Vec<&String> = inner.keys.keys().collect();
        key_ids.sort();
        let mut indexes = Vec::with_capacity(key_ids.len());
        for key_id in key_ids {
            let key = inner.keys.get(key_id).unwrap();
            let mut msg = Vec::with_capacity(table.len() + field.len() + encoded_value.len() + 2);
            msg.extend_from_slice(table.as_bytes());
            msg.push(0);
            msg.extend_from_slice(field.as_bytes());
            msg.push(0);
            msg.extend_from_slice(encoded_value);
            let tag = hmac::sign(&key.search_key, &msg);
            indexes.push(hex(tag.as_ref()));
        }
        Ok(indexes)
    }

    /// Unseal persisted state by trying each candidate seal in order. Returns the
    /// decoded state together with the seal that successfully opened it, so the
    /// caller can decide whether to re-seal under a newer key.
    fn load_state(
        state_path: &Path,
        candidates: &[[u8; 32]],
    ) -> Result<(EncryptionState, [u8; 32]), String> {
        let raw = fs::read(state_path).map_err(|e| format!("ERR ENC state read failed: {e}"))?;
        let sealed: SealedState =
            serde_json::from_slice(&raw).map_err(|e| format!("ERR ENC state is invalid: {e}"))?;
        if sealed.version != 1 {
            return Err("ERR ENC state version is unsupported".to_string());
        }
        let nonce = base64::engine::general_purpose::STANDARD
            .decode(sealed.nonce)
            .map_err(|_| "ERR ENC state nonce is invalid".to_string())?;
        let nonce: [u8; NONCE_LEN] = nonce
            .try_into()
            .map_err(|_| "ERR ENC state nonce is invalid".to_string())?;
        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(sealed.ciphertext)
            .map_err(|_| "ERR ENC state ciphertext is invalid".to_string())?;

        for seal in candidates {
            let key = seal_state_key(seal)?;
            let mut buf = ciphertext.clone();
            let Ok(plain) = key.open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(STATE_MAGIC),
                &mut buf,
            ) else {
                continue;
            };
            let plain: PlainState = serde_json::from_slice(plain)
                .map_err(|e| format!("ERR ENC state is invalid: {e}"))?;
            if plain.version != 1 {
                return Err("ERR ENC state version is unsupported".to_string());
            }
            let configs = plain
                .keys
                .into_iter()
                .map(|key| {
                    let secret = base64::engine::general_purpose::STANDARD
                        .decode(key.secret)
                        .map_err(|_| "ERR ENC state key secret is invalid".to_string())?;
                    Ok(EncryptionKeyConfig {
                        id: key.id,
                        secret,
                        decrypt_only: key.decrypt_only,
                    })
                })
                .collect::<Result<Vec<_>, String>>()?;
            let keys = build_network_keys(&configs)?;
            validate_active_key(plain.active_key_id.as_deref(), &keys)?;
            return Ok((
                EncryptionState {
                    active_key_id: plain.active_key_id,
                    keys,
                },
                *seal,
            ));
        }
        Err("ERR ENC state could not be unsealed".to_string())
    }

    fn persist_state(&self, inner: &EncryptionState) -> Result<(), String> {
        let state_path = self
            .state_path
            .as_ref()
            .ok_or_else(|| "ERR ENC state path is not configured".to_string())?;
        let seal = current_seal(self.seal_secret, self.seal_path.as_deref())?;
        let mut key_ids: Vec<&String> = inner.keys.keys().collect();
        key_ids.sort();
        let plain = PlainState {
            version: 1,
            active_key_id: inner.active_key_id.clone(),
            keys: key_ids
                .into_iter()
                .map(|id| {
                    let key = inner.keys.get(id).expect("key id from map");
                    PlainKey {
                        id: id.clone(),
                        secret: base64::engine::general_purpose::STANDARD.encode(&key.secret),
                        decrypt_only: key.decrypt_only,
                    }
                })
                .collect(),
        };
        let mut plaintext = serde_json::to_vec(&plain)
            .map_err(|e| format!("ERR ENC state serialize failed: {e}"))?;
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let key = seal_state_key(&seal)?;
        key.seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(STATE_MAGIC),
            &mut plaintext,
        )
        .map_err(|_| "ERR ENC state seal failed".to_string())?;
        let sealed = SealedState {
            version: 1,
            nonce: base64::engine::general_purpose::STANDARD.encode(nonce),
            ciphertext: base64::engine::general_purpose::STANDARD.encode(plaintext),
        };
        let raw = serde_json::to_vec_pretty(&sealed)
            .map_err(|e| format!("ERR ENC state serialize failed: {e}"))?;
        if let Some(parent) = state_path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("ERR ENC state mkdir failed: {e}"))?;
        }
        let tmp = state_path.with_extension("enc.tmp");
        {
            use std::io::Write;
            let mut file =
                fs::File::create(&tmp).map_err(|e| format!("ERR ENC state write failed: {e}"))?;
            file.write_all(&raw)
                .map_err(|e| format!("ERR ENC state write failed: {e}"))?;
            file.sync_all()
                .map_err(|e| format!("ERR ENC state sync failed: {e}"))?;
        }
        fs::rename(&tmp, state_path).map_err(|e| format!("ERR ENC state replace failed: {e}"))?;
        // fsync the directory so the rename itself is durable across a crash.
        if let Some(parent) = state_path.parent() {
            if let Ok(dir) = fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    }
}

/// The seal used to *seal* state: the env-sourced secret when present, otherwise
/// the on-disk seal file (created on first use, matching local-dev behavior).
fn current_seal(
    seal_secret: Option<[u8; 32]>,
    seal_path: Option<&Path>,
) -> Result<[u8; 32], String> {
    if let Some(secret) = seal_secret {
        return Ok(secret);
    }
    let path = seal_path.ok_or_else(|| "ERR ENC seal key is not configured".to_string())?;
    read_seal_key(path, true)
}

/// Seals accepted for *unsealing*, in priority order: the current env seal, then
/// rotated-out previous env seals, then the on-disk seal file if it exists.
/// Errors only when no source is configured at all.
fn collect_candidate_seals(
    seal_secret: Option<[u8; 32]>,
    previous: &[[u8; 32]],
    seal_path: Option<&Path>,
) -> Result<Vec<[u8; 32]>, String> {
    let mut out: Vec<[u8; 32]> = Vec::new();
    if let Some(secret) = seal_secret {
        out.push(secret);
    }
    for seal in previous {
        if !out.contains(seal) {
            out.push(*seal);
        }
    }
    if let Some(path) = seal_path {
        if path.exists() {
            let file_seal = read_seal_key(path, false)?;
            if !out.contains(&file_seal) {
                out.push(file_seal);
            }
        }
    }
    if out.is_empty() {
        return Err("ERR ENC no seal key configured".to_string());
    }
    Ok(out)
}

struct ParsedEnvelope<'a> {
    writer_key_id: &'a str,
    wraps: Vec<KeyWrap<'a>>,
    value_nonce: &'a [u8; NONCE_LEN],
    ciphertext: &'a [u8],
}

struct KeyWrap<'a> {
    key_id: &'a str,
    nonce: &'a [u8; NONCE_LEN],
    wrapped_data_key: &'a [u8],
}

fn parse_envelope(envelope: &[u8]) -> Result<ParsedEnvelope<'_>, String> {
    if !envelope.starts_with(ENVELOPE_MAGIC) {
        return Err("ERR stored value is not encrypted".to_string());
    }
    let mut pos = ENVELOPE_MAGIC.len();
    let writer_len = *envelope
        .get(pos)
        .ok_or_else(|| "ERR encrypted value is truncated".to_string())?
        as usize;
    pos += 1;
    let writer_end = pos + writer_len;
    if envelope.len() < writer_end + 1 {
        return Err("ERR encrypted value is truncated".to_string());
    }
    let writer_key_id = std::str::from_utf8(&envelope[pos..writer_end])
        .map_err(|_| "ERR encrypted value has invalid writer key id".to_string())?;
    pos = writer_end;
    let wrap_count = envelope[pos] as usize;
    pos += 1;
    let mut wraps = Vec::with_capacity(wrap_count);
    for _ in 0..wrap_count {
        let id_len = *envelope
            .get(pos)
            .ok_or_else(|| "ERR encrypted value is truncated".to_string())?
            as usize;
        pos += 1;
        let id_end = pos + id_len;
        let wrap_end = id_end + NONCE_LEN + WRAPPED_DATA_KEY_LEN;
        if envelope.len() < wrap_end {
            return Err("ERR encrypted value is truncated".to_string());
        }
        let key_id = std::str::from_utf8(&envelope[pos..id_end])
            .map_err(|_| "ERR encrypted value has invalid key id".to_string())?;
        pos = id_end;
        let nonce: &[u8; NONCE_LEN] = envelope[pos..pos + NONCE_LEN]
            .try_into()
            .map_err(|_| "ERR encrypted value has invalid key nonce".to_string())?;
        pos += NONCE_LEN;
        let wrapped_data_key = &envelope[pos..pos + WRAPPED_DATA_KEY_LEN];
        pos += WRAPPED_DATA_KEY_LEN;
        wraps.push(KeyWrap {
            key_id,
            nonce,
            wrapped_data_key,
        });
    }
    if envelope.len() < pos + NONCE_LEN {
        return Err("ERR encrypted value is truncated".to_string());
    }
    let value_nonce: &[u8; NONCE_LEN] = envelope[pos..pos + NONCE_LEN]
        .try_into()
        .map_err(|_| "ERR encrypted value has invalid value nonce".to_string())?;
    pos += NONCE_LEN;
    Ok(ParsedEnvelope {
        writer_key_id,
        wraps,
        value_nonce,
        ciphertext: &envelope[pos..],
    })
}

fn build_network_keys(
    configs: &[EncryptionKeyConfig],
) -> Result<HashMap<String, NetworkKey>, String> {
    let mut keys = HashMap::new();
    for key in configs {
        validate_key_id(&key.id)?;
        if keys.contains_key(&key.id) {
            return Err(format!("ERR duplicate ENC key '{}'", key.id));
        }
        let wrap_key = derive_key(&key.secret, b"lux-dek-wrap-v1");
        let search_key = derive_key(&key.secret, b"lux-table-search-v1");
        let unbound = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &wrap_key)
            .map_err(|_| "ERR invalid encryption key".to_string())?;
        keys.insert(
            key.id.clone(),
            NetworkKey {
                secret: key.secret.clone(),
                wrap_key: aead::LessSafeKey::new(unbound),
                search_key: hmac::Key::new(hmac::HMAC_SHA256, &search_key),
                decrypt_only: key.decrypt_only,
            },
        );
    }
    Ok(keys)
}

fn validate_key_id(id: &str) -> Result<(), String> {
    if id.is_empty() {
        return Err("ERR encryption key id cannot be empty".to_string());
    }
    if id.len() > u8::MAX as usize {
        return Err("ERR encryption key id is too long".to_string());
    }
    if !id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(
            "ERR encryption key id must contain only letters, numbers, '_' or '-'".to_string(),
        );
    }
    Ok(())
}

fn validate_active_key(
    active_key_id: Option<&str>,
    keys: &HashMap<String, NetworkKey>,
) -> Result<(), String> {
    if let Some(active) = active_key_id {
        let key = keys
            .get(active)
            .ok_or_else(|| format!("ERR active encryption key '{}' is not configured", active))?;
        if key.decrypt_only {
            return Err(format!(
                "ERR active encryption key '{}' is marked decrypt-only",
                active
            ));
        }
    }
    Ok(())
}

fn resolve_path(configured: Option<&str>, data_dir: &str, default_name: &str) -> Option<PathBuf> {
    if configured == Some("") {
        return None;
    }
    Some(
        configured
            .map(PathBuf::from)
            .unwrap_or_else(|| Path::new(data_dir).join(default_name)),
    )
}

fn generate_key_id() -> String {
    let mut bytes = [0u8; 8];
    OsRng.fill_bytes(&mut bytes);
    format!("k{}", hex(&bytes))
}

fn generate_secret() -> Vec<u8> {
    let mut secret = vec![0u8; 32];
    OsRng.fill_bytes(&mut secret);
    secret
}

fn read_seal_key(path: &Path, create: bool) -> Result<[u8; 32], String> {
    match fs::read(path) {
        Ok(raw) => {
            let text = String::from_utf8(raw)
                .map_err(|_| "ERR ENC seal file is not valid UTF-8".to_string())?;
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(text.trim())
                .map_err(|_| "ERR ENC seal file is invalid".to_string())?;
            decoded
                .try_into()
                .map_err(|_| "ERR ENC seal file has invalid length".to_string())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && create => {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| format!("ERR ENC seal mkdir failed: {e}"))?;
            }
            let mut seal = [0u8; 32];
            OsRng.fill_bytes(&mut seal);
            let encoded = base64::engine::general_purpose::STANDARD.encode(seal);
            write_new_seal_file(path, encoded.as_bytes())?;
            Ok(seal)
        }
        Err(e) => Err(format!("ERR ENC seal read failed: {e}")),
    }
}

fn write_new_seal_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("ERR ENC seal create failed: {e}"))?;
        file.write_all(bytes)
            .map_err(|e| format!("ERR ENC seal write failed: {e}"))?;
        file.write_all(b"\n")
            .map_err(|e| format!("ERR ENC seal write failed: {e}"))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        fs::write(path, [bytes, b"\n"].concat())
            .map_err(|e| format!("ERR ENC seal write failed: {e}"))
    }
}

fn seal_state_key(secret: &[u8; 32]) -> Result<aead::LessSafeKey, String> {
    let key = derive_key(secret, b"lux-enc-state-seal-v1");
    let unbound = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key)
        .map_err(|_| "ERR invalid ENC seal key".to_string())?;
    Ok(aead::LessSafeKey::new(unbound))
}

fn data_value_key(data_key: &[u8; DATA_KEY_LEN]) -> Result<aead::LessSafeKey, String> {
    let unbound = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, data_key)
        .map_err(|_| "ERR invalid data encryption key".to_string())?;
    Ok(aead::LessSafeKey::new(unbound))
}

fn derive_key(secret: &[u8], label: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(label);
    hasher.update([0]);
    hasher.update(secret);
    hasher.finalize().into()
}

fn wrap_aad(table: &str, field: &str, pk: &str, writer_key_id: &str) -> Vec<u8> {
    aad_with_writer(b"lux-dek-wrap-aad-v1", table, field, pk, writer_key_id)
}

fn value_aad(table: &str, field: &str, pk: &str, writer_key_id: &str) -> Vec<u8> {
    aad_with_writer(b"lux-value-aad-v1", table, field, pk, writer_key_id)
}

fn aad_with_writer(
    label: &[u8],
    table: &str,
    field: &str,
    pk: &str,
    writer_key_id: &str,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        label.len() + table.len() + field.len() + pk.len() + writer_key_id.len() + 4,
    );
    aad.extend_from_slice(label);
    aad.push(0);
    aad.extend_from_slice(table.as_bytes());
    aad.push(0);
    aad.extend_from_slice(field.as_bytes());
    aad.push(0);
    aad.extend_from_slice(pk.as_bytes());
    aad.push(0);
    aad.extend_from_slice(writer_key_id.as_bytes());
    aad
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod adversarial_tests {
    //! Adversarial unit tests for the core crypto envelope. These try to *break*
    //! the construction: reuse ciphertext across (table, field, pk), tamper the
    //! AEAD, forge the writer key id, and abuse the keyring lifecycle.
    use super::*;

    fn mem_ring(keys: &[(&str, &[u8], bool)], active: Option<&str>) -> EncryptionKeyring {
        let config = EncryptionConfig {
            active_key_id: active.map(str::to_string),
            keys: keys
                .iter()
                .map(|(id, secret, decrypt_only)| EncryptionKeyConfig {
                    id: id.to_string(),
                    secret: secret.to_vec(),
                    decrypt_only: *decrypt_only,
                })
                .collect(),
            // Empty string disables persistence (resolve_path -> None), keeping
            // these tests purely in-memory.
            state_path: Some(String::new()),
            seal_path: Some(String::new()),
            auto_init: false,
            ..Default::default()
        };
        EncryptionKeyring::open(&config, ".").expect("keyring opens")
    }

    fn one_key_ring() -> EncryptionKeyring {
        mem_ring(
            &[("k1", b"a-32-byte-ish-secret-for-tests!!", false)],
            Some("k1"),
        )
    }

    #[test]
    fn round_trips_and_marks_envelope() {
        let ring = one_key_ring();
        let ct = ring.encrypt("users", "ssn", "42", b"123-45-6789").unwrap();
        assert!(EncryptionKeyring::is_encrypted_value(&ct));
        // Ciphertext must not contain the plaintext.
        assert!(!ct.windows(11).any(|w| w == b"123-45-6789"));
        let pt = ring.decrypt("users", "ssn", "42", &ct).unwrap();
        assert_eq!(pt, b"123-45-6789");
    }

    #[test]
    fn same_plaintext_encrypts_differently() {
        let ring = one_key_ring();
        let a = ring.encrypt("t", "f", "1", b"same").unwrap();
        let b = ring.encrypt("t", "f", "1", b"same").unwrap();
        assert_ne!(
            a, b,
            "random DEK/nonce must make ciphertext non-deterministic"
        );
    }

    #[test]
    fn ciphertext_is_bound_to_field_row_and_table() {
        let ring = one_key_ring();
        let ct = ring.encrypt("users", "ssn", "42", b"secret").unwrap();
        // Same key, wrong field / row / table must all fail (AAD binding).
        assert!(
            ring.decrypt("users", "email", "42", &ct).is_err(),
            "cross-field"
        );
        assert!(
            ring.decrypt("users", "ssn", "43", &ct).is_err(),
            "cross-row"
        );
        assert!(
            ring.decrypt("orders", "ssn", "42", &ct).is_err(),
            "cross-table"
        );
        // Correct coordinates still work.
        assert!(ring.decrypt("users", "ssn", "42", &ct).is_ok());
    }

    #[test]
    fn tampering_ciphertext_or_wrap_is_rejected() {
        let ring = one_key_ring();
        let base = ring.encrypt("t", "f", "1", b"the-plaintext").unwrap();
        // Flip the final byte (inside the value ciphertext/tag).
        let mut last = base.clone();
        *last.last_mut().unwrap() ^= 0x01;
        assert!(ring.decrypt("t", "f", "1", &last).is_err(), "value tag");
        // Flip a byte in the middle (inside the wrapped-key region).
        let mut mid = base.clone();
        let i = ENVELOPE_MAGIC.len() + 8;
        mid[i] ^= 0x01;
        assert!(ring.decrypt("t", "f", "1", &mid).is_err(), "wrap region");
    }

    #[test]
    fn forging_writer_key_id_bytes_is_rejected() {
        let ring = one_key_ring();
        let mut ct = ring.encrypt("t", "f", "1", b"payload").unwrap();
        // writer_key_id is a length-prefixed field right after the magic; the id
        // is "k1", so flip a byte of it while keeping the length. AAD binds the
        // writer id, so unwrap should fail.
        let id_pos = ENVELOPE_MAGIC.len() + 1;
        ct[id_pos] ^= 0x01;
        assert!(ring.decrypt("t", "f", "1", &ct).is_err());
    }

    #[test]
    fn truncated_envelopes_error_without_panic() {
        let ring = one_key_ring();
        let ct = ring.encrypt("t", "f", "1", b"payload").unwrap();
        for len in 0..ct.len() {
            // Must never panic; every prefix is either an error or (only at full
            // length) a success.
            let _ = ring.decrypt("t", "f", "1", &ct[..len]);
        }
        assert!(ring.decrypt("t", "f", "1", &ct).is_ok());
    }

    #[test]
    fn blind_index_is_deterministic_per_field_and_value() {
        let ring = one_key_ring();
        let a1 = ring
            .blind_indexes("users", "email", b"alice@x.com")
            .unwrap();
        let a2 = ring
            .blind_indexes("users", "email", b"alice@x.com")
            .unwrap();
        let b = ring.blind_indexes("users", "email", b"bob@x.com").unwrap();
        let other_field = ring
            .blind_indexes("users", "recovery", b"alice@x.com")
            .unwrap();
        assert_eq!(a1, a2, "same (field,value) -> same index");
        assert_ne!(a1, b, "different value -> different index");
        assert_ne!(a1, other_field, "different field -> different index");
    }

    #[test]
    fn blind_index_has_one_entry_per_key() {
        let ring = mem_ring(
            &[
                ("k1", b"secret-number-one-secret-number1", false),
                ("k2", b"secret-number-two-secret-number2", false),
            ],
            Some("k2"),
        );
        let idx = ring.blind_indexes("t", "f", b"v").unwrap();
        assert_eq!(idx.len(), 2);
        assert_ne!(idx[0], idx[1], "each key derives a distinct blind index");
    }

    #[test]
    fn active_key_cannot_be_decrypt_only() {
        let config = EncryptionConfig {
            active_key_id: Some("k1".into()),
            keys: vec![EncryptionKeyConfig {
                id: "k1".into(),
                secret: b"decrypt-only-secret-decrypt-only".to_vec(),
                decrypt_only: true,
            }],
            state_path: Some(String::new()),
            seal_path: Some(String::new()),
            auto_init: false,
            ..Default::default()
        };
        assert!(EncryptionKeyring::open(&config, ".").is_err());
    }

    #[test]
    fn value_decryptable_by_any_ring_holding_a_wrapped_key() {
        // Written while both keys are in the ring -> DEK wrapped under both.
        let writer = mem_ring(
            &[
                ("old", b"old-secret-old-secret-old-secre1", false),
                ("new", b"new-secret-new-secret-new-secre2", false),
            ],
            Some("new"),
        );
        let ct = writer.encrypt("t", "f", "1", b"shared").unwrap();
        // A reader that only has "old" must still decrypt (wrap present).
        let reader_old = mem_ring(
            &[("old", b"old-secret-old-secret-old-secre1", false)],
            Some("old"),
        );
        assert_eq!(reader_old.decrypt("t", "f", "1", &ct).unwrap(), b"shared");
        // A reader with an unrelated key cannot.
        let stranger = mem_ring(
            &[("x", b"stranger-secret-stranger-secret1", false)],
            Some("x"),
        );
        assert!(stranger.decrypt("t", "f", "1", &ct).is_err());
    }

    #[test]
    fn persisted_state_survives_reopen_and_wrong_seal_fails() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_string_lossy().to_string();
        let config = EncryptionConfig {
            state_path: None,
            seal_path: None,
            auto_init: false,
            ..Default::default()
        };
        // Init + encrypt.
        let ring = EncryptionKeyring::open(&config, &data_dir).unwrap();
        let kid = ring.init(Some("k1")).unwrap();
        assert_eq!(kid, "k1");
        let ct = ring.encrypt("t", "f", "1", b"persisted").unwrap();
        drop(ring);

        // Reopen from the same dir: state unseals, data decrypts.
        let reopened = EncryptionKeyring::open(&config, &data_dir).unwrap();
        assert!(reopened.has_active_key());
        assert_eq!(reopened.decrypt("t", "f", "1", &ct).unwrap(), b"persisted");
        drop(reopened);

        // Corrupt the seal file: reopen must fail closed, not silently reset.
        let seal_path = std::path::Path::new(&data_dir).join("lux.enc.seal");
        let mut bad = [0u8; 32];
        bad[0] = 0xAB;
        let encoded = base64::engine::general_purpose::STANDARD.encode(bad);
        std::fs::write(&seal_path, encoded).unwrap();
        assert!(
            EncryptionKeyring::open(&config, &data_dir).is_err(),
            "wrong seal must not unseal the keyring"
        );
    }

    #[test]
    fn retire_rules_hold_at_keyring_level() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_string_lossy().to_string();
        let config = EncryptionConfig::default();
        let ring = EncryptionKeyring::open(&config, &data_dir).unwrap();
        ring.init(Some("k1")).unwrap();
        ring.rotate(Some("k2")).unwrap();
        // Cannot retire the active key; cannot retire a nonexistent key.
        assert!(ring.retire("k2").is_err(), "active key");
        assert!(ring.retire("does-not-exist").is_err());
        // Retiring the old (now decrypt-only) key is allowed at this layer.
        assert!(ring.retire("k1").is_ok());
    }

    // ---- seal sourcing: env seal, file->env migration, rotation ----

    fn seal_bytes(tag: u8) -> [u8; 32] {
        [tag; 32]
    }

    fn env_seal_config(seal: [u8; 32], previous: Vec<[u8; 32]>) -> EncryptionConfig {
        EncryptionConfig {
            seal_secret: Some(seal),
            previous_seal_secrets: previous,
            auto_init: false,
            ..Default::default()
        }
    }

    #[test]
    fn env_seal_round_trips_without_writing_a_seal_file() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_string_lossy().to_string();
        let config = env_seal_config(seal_bytes(1), Vec::new());

        let ring = EncryptionKeyring::open(&config, &data_dir).unwrap();
        ring.init(Some("k1")).unwrap();
        let ct = ring.encrypt("t", "f", "1", b"envsealed").unwrap();
        drop(ring);

        // No on-disk seal file is created when the seal comes from the env.
        assert!(!dir.path().join("lux.enc.seal").exists());
        assert!(dir.path().join("lux.enc").exists());

        let reopened = EncryptionKeyring::open(&config, &data_dir).unwrap();
        assert_eq!(reopened.decrypt("t", "f", "1", &ct).unwrap(), b"envsealed");
    }

    #[test]
    fn migrates_file_seal_to_env_seal_and_deletes_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_string_lossy().to_string();

        // Bootstrap with a file seal (no env seal), like today's local/native mode.
        let file_config = EncryptionConfig {
            auto_init: false,
            ..Default::default()
        };
        let ring = EncryptionKeyring::open(&file_config, &data_dir).unwrap();
        ring.init(Some("k1")).unwrap();
        let ct = ring.encrypt("t", "f", "1", b"legacy").unwrap();
        drop(ring);
        assert!(dir.path().join("lux.enc.seal").exists());

        // Reopen with a fresh env seal while the old file is still present: the
        // engine unseals via the file, re-seals under the env seal, deletes file.
        let env_config = env_seal_config(seal_bytes(7), Vec::new());
        let migrated = EncryptionKeyring::open(&env_config, &data_dir).unwrap();
        assert_eq!(migrated.decrypt("t", "f", "1", &ct).unwrap(), b"legacy");
        drop(migrated);
        assert!(
            !dir.path().join("lux.enc.seal").exists(),
            "seal file must be removed after migration"
        );

        // A second reopen with only the env seal (no file) still works.
        let reopened = EncryptionKeyring::open(&env_config, &data_dir).unwrap();
        assert_eq!(reopened.decrypt("t", "f", "1", &ct).unwrap(), b"legacy");
    }

    #[test]
    fn rotates_seal_via_previous_and_old_seal_stops_working() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_string_lossy().to_string();
        let old = seal_bytes(3);
        let new = seal_bytes(9);

        // Seal under the old env seal.
        let old_config = env_seal_config(old, Vec::new());
        let ring = EncryptionKeyring::open(&old_config, &data_dir).unwrap();
        ring.init(Some("k1")).unwrap();
        let ct = ring.encrypt("t", "f", "1", b"rotate-me").unwrap();
        drop(ring);

        // Boot with new current + old as previous: unseals and re-seals under new.
        let rotate_config = env_seal_config(new, vec![old]);
        let rotated = EncryptionKeyring::open(&rotate_config, &data_dir).unwrap();
        assert_eq!(rotated.decrypt("t", "f", "1", &ct).unwrap(), b"rotate-me");
        drop(rotated);

        // The new seal alone now opens it.
        let new_only = env_seal_config(new, Vec::new());
        assert!(EncryptionKeyring::open(&new_only, &data_dir).is_ok());

        // The old seal alone no longer opens the re-sealed state.
        let old_only = env_seal_config(old, Vec::new());
        assert!(
            EncryptionKeyring::open(&old_only, &data_dir).is_err(),
            "old seal must not open state re-sealed under the new seal"
        );
    }

    #[test]
    fn wrong_env_seal_with_no_previous_or_file_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_string_lossy().to_string();

        let good = env_seal_config(seal_bytes(4), Vec::new());
        let ring = EncryptionKeyring::open(&good, &data_dir).unwrap();
        ring.init(Some("k1")).unwrap();
        ring.encrypt("t", "f", "1", b"x").unwrap();
        drop(ring);

        let wrong = env_seal_config(seal_bytes(5), Vec::new());
        assert!(
            EncryptionKeyring::open(&wrong, &data_dir).is_err(),
            "a wrong env seal with no fallback must fail closed"
        );
    }
}
