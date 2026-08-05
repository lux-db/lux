use super::execution_wire::{
    canonical_manifest_bytes, decode_digest, execution_content_eq, manifest_digest,
    validate_manifest, validate_manifest_bounds,
};
use super::signature::{sign_payload, verify_payload};
use super::ClusterError;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::DecodingKey;
use p256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub const CLUSTER_EXECUTION_SCHEMA_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionApiKeyKind {
    Publishable,
    Secret,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionGrantScope {
    Read,
    Write,
}

impl ExecutionGrantScope {
    const fn index(self) -> usize {
        match self {
            Self::Read => 0,
            Self::Write => 1,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutionField {
    pub name: String,
    /// Exact durable field definition emitted by the table schema encoder.
    pub definition: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutionPathIndex {
    pub path: String,
    /// Canonical persisted index type token.
    pub field_type: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutionTable {
    pub name: String,
    /// Declared primary-key field, or `None` for the Engine's implicit `id`.
    pub primary_key: Option<String>,
    pub fields: Vec<ExecutionField>,
    pub path_indexes: Vec<ExecutionPathIndex>,
    pub default_ttl_seconds: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutionGrant {
    pub table: String,
    pub scope: ExecutionGrantScope,
    /// Canonical predicate text produced by the grant serializer.
    pub predicate: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutionApiKey {
    /// Lowercase SHA-256 of the presented key. Raw key material is forbidden.
    pub digest: String,
    pub kind: ExecutionApiKeyKind,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutionJwtKey {
    pub kid: String,
    /// Canonical public ES256 JWK. Private `d` material is rejected.
    pub public_jwk: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutionSessionRevocation {
    pub session_id: String,
    pub revoked_after: u64,
    /// Entry can be dropped after every affected access token has expired.
    pub retain_until: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionPrincipalBlockKind {
    Banned,
    Deleted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutionPrincipalBlock {
    pub user_id: String,
    pub kind: ExecutionPrincipalBlockKind,
    /// Instant at which the principal became banned or deleted.
    pub blocked_at: u64,
    /// Required for a temporary ban and absent for a deletion.
    pub blocked_until: Option<u64>,
    /// Entry can be dropped after every affected access token has expired.
    pub retain_until: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutionAuth {
    pub enabled: bool,
    pub issuer: String,
    /// Maximum lifetime of an access token issued by this project.
    pub access_token_ttl_seconds: u64,
    pub api_keys: Vec<ExecutionApiKey>,
    pub jwt_keys: Vec<ExecutionJwtKey>,
    pub grants: Vec<ExecutionGrant>,
    pub session_revocations: Vec<ExecutionSessionRevocation>,
    pub principal_blocks: Vec<ExecutionPrincipalBlock>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutionManifest {
    pub schema_version: u16,
    pub protocol_version: u16,
    pub cluster_id: String,
    pub version: u64,
    /// SHA-256 of the previous canonical manifest, forming a no-rollback chain.
    pub previous_digest: Option<String>,
    /// Digest of locally supplied encryption key IDs/material. Secrets stay out
    /// of the signed bundle; owners compare this before accepting encrypted schemas.
    pub encryption_keyring_digest: Option<String>,
    pub tables: Vec<ExecutionTable>,
    pub auth: ExecutionAuth,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignedExecution {
    pub manifest: ExecutionManifest,
    pub signature: String,
}

impl SignedExecution {
    pub fn sign(
        manifest: ExecutionManifest,
        signing_key: &SigningKey,
    ) -> Result<Self, ClusterError> {
        validate_manifest(&manifest)?;
        let payload = canonical_manifest_bytes(&manifest)?;
        Ok(Self {
            manifest,
            signature: sign_payload(&payload, signing_key),
        })
    }

    pub fn verify(&self, controller_public_key: &str) -> Result<CompiledExecution, ClusterError> {
        validate_manifest_bounds(&self.manifest)?;
        let payload = canonical_manifest_bytes(&self.manifest)?;
        verify_payload(&payload, &self.signature, controller_public_key)?;
        CompiledExecution::compile(self.clone())
    }
}

impl ExecutionManifest {
    pub fn signing_payload(&self) -> Result<Vec<u8>, ClusterError> {
        validate_manifest(self)?;
        canonical_manifest_bytes(self)
    }
}

pub struct CompiledExecution {
    signed: SignedExecution,
    digest: String,
    table_indexes: HashMap<String, usize>,
    grant_indexes: HashMap<String, [Option<usize>; 2]>,
    api_key_kinds: HashMap<[u8; 32], ExecutionApiKeyKind>,
    jwt_keys: HashMap<String, DecodingKey>,
    session_revocations: HashMap<String, ExecutionSessionRevocation>,
    principal_blocks: HashMap<String, ExecutionPrincipalBlock>,
}

impl std::fmt::Debug for CompiledExecution {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CompiledExecution")
            .field("cluster_id", &self.signed.manifest.cluster_id)
            .field("version", &self.signed.manifest.version)
            .field("digest", &self.digest)
            .field("tables", &self.table_indexes.len())
            .field("grants", &self.grant_indexes.len())
            .field("api_keys", &self.api_key_kinds.len())
            .field("jwt_keys", &self.jwt_keys.len())
            .field("session_revocations", &self.session_revocations.len())
            .field("principal_blocks", &self.principal_blocks.len())
            .finish()
    }
}

impl CompiledExecution {
    fn compile(signed: SignedExecution) -> Result<Self, ClusterError> {
        validate_manifest(&signed.manifest)?;
        let digest = manifest_digest(&signed.manifest)?;
        let table_indexes = signed
            .manifest
            .tables
            .iter()
            .enumerate()
            .map(|(index, table)| (table.name.clone(), index))
            .collect();
        let mut grant_indexes = HashMap::<String, [Option<usize>; 2]>::new();
        for (index, grant) in signed.manifest.auth.grants.iter().enumerate() {
            grant_indexes.entry(grant.table.clone()).or_default()[grant.scope.index()] =
                Some(index);
        }
        let api_key_kinds = signed
            .manifest
            .auth
            .api_keys
            .iter()
            .map(|key| {
                let digest = decode_digest(&key.digest).ok_or_else(|| {
                    ClusterError::InvalidExecution(
                        "validated API key digest could not be decoded".to_owned(),
                    )
                })?;
                Ok((digest, key.kind))
            })
            .collect::<Result<HashMap<_, _>, ClusterError>>()?;
        let jwt_keys = signed
            .manifest
            .auth
            .jwt_keys
            .iter()
            .map(|key| {
                let jwk = serde_json::from_str::<Jwk>(&key.public_jwk).map_err(|error| {
                    ClusterError::InvalidExecution(format!(
                        "validated JWT key {} could not be decoded: {error}",
                        key.kid
                    ))
                })?;
                let decoding_key = DecodingKey::from_jwk(&jwk).map_err(|error| {
                    ClusterError::InvalidExecution(format!(
                        "validated JWT key {} could not be compiled: {error}",
                        key.kid
                    ))
                })?;
                Ok((key.kid.clone(), decoding_key))
            })
            .collect::<Result<HashMap<_, _>, ClusterError>>()?;
        let session_revocations = signed
            .manifest
            .auth
            .session_revocations
            .iter()
            .map(|entry| (entry.session_id.clone(), entry.clone()))
            .collect();
        let principal_blocks = signed
            .manifest
            .auth
            .principal_blocks
            .iter()
            .map(|entry| (entry.user_id.clone(), entry.clone()))
            .collect();
        Ok(Self {
            signed,
            digest,
            table_indexes,
            grant_indexes,
            api_key_kinds,
            jwt_keys,
            session_revocations,
            principal_blocks,
        })
    }

    #[must_use]
    pub fn manifest(&self) -> &ExecutionManifest {
        &self.signed.manifest
    }

    #[must_use]
    pub fn signed(&self) -> &SignedExecution {
        &self.signed
    }

    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    #[must_use]
    pub fn table(&self, name: &str) -> Option<&ExecutionTable> {
        self.table_indexes
            .get(name)
            .and_then(|index| self.signed.manifest.tables.get(*index))
    }

    #[must_use]
    pub fn primary_key(&self, table: &str) -> Option<&str> {
        self.table(table)
            .map(|table| table.primary_key.as_deref().unwrap_or("id"))
    }

    #[must_use]
    pub fn grant(&self, table: &str, scope: ExecutionGrantScope) -> Option<&ExecutionGrant> {
        self.grant_indexes
            .get(table)
            .and_then(|indexes| indexes[scope.index()])
            .and_then(|index| self.signed.manifest.auth.grants.get(index))
    }

    #[must_use]
    pub fn api_key_kind(&self, presented: &str) -> Option<ExecutionApiKeyKind> {
        let digest: [u8; 32] = Sha256::digest(presented.as_bytes()).into();
        self.api_key_kinds.get(&digest).copied()
    }

    #[must_use]
    pub fn has_jwt_key(&self, kid: &str) -> bool {
        self.jwt_keys.contains_key(kid)
    }

    #[must_use]
    pub fn session_is_revoked(&self, session_id: &str, issued_at: u64, now: u64) -> bool {
        self.session_revocations
            .get(session_id)
            .is_some_and(|entry| now <= entry.retain_until && issued_at <= entry.revoked_after)
    }

    #[must_use]
    pub fn principal_is_blocked(&self, user_id: &str, now: u64) -> bool {
        self.principal_blocks.get(user_id).is_some_and(|entry| {
            if now > entry.retain_until {
                return false;
            }
            match entry.kind {
                ExecutionPrincipalBlockKind::Deleted => true,
                ExecutionPrincipalBlockKind::Banned => entry
                    .blocked_until
                    .is_some_and(|blocked_until| now < blocked_until),
            }
        })
    }

    pub fn transition_to(&self, candidate: &CompiledExecution) -> Result<(), ClusterError> {
        let current = self.manifest();
        let next = candidate.manifest();
        if current.cluster_id != next.cluster_id {
            return invalid("prepared execution metadata belongs to another cluster");
        }
        let expected_version = current.version.checked_add(1).ok_or_else(|| {
            ClusterError::InvalidExecution("committed execution version is exhausted".to_owned())
        })?;
        if next.version != expected_version {
            return invalid(format!(
                "prepared execution version {} must immediately follow committed version {}",
                next.version, current.version
            ));
        }
        if next.previous_digest.as_deref() != Some(self.digest()) {
            return invalid("prepared execution metadata does not extend the committed digest");
        }
        if execution_content_eq(current, next) {
            return invalid("prepared execution metadata has no semantic change");
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) fn api_key_digest(secret: &str) -> String {
    let digest = Sha256::digest(secret.as_bytes());
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn invalid<T>(message: impl Into<String>) -> Result<T, ClusterError> {
    Err(ClusterError::InvalidExecution(message.into()))
}

#[cfg(test)]
#[path = "execution_tests.rs"]
mod tests;
