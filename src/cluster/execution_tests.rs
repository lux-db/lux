use super::*;
use crate::cluster::{encode_controller_public_key, ExecutionState, CLUSTER_PROTOCOL_VERSION};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::SigningKey;
use rand_core::OsRng;

fn public_jwk(key: &SigningKey, kid: &str) -> String {
    let point = key.verifying_key().to_encoded_point(false);
    serde_json::to_string(&serde_json::json!({
        "alg": "ES256",
        "crv": "P-256",
        "kid": kid,
        "kty": "EC",
        "use": "sig",
        "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
        "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
    }))
    .unwrap()
}

fn manifest(version: u64, jwt_signing_key: &SigningKey) -> ExecutionManifest {
    let kid = "jwt-1";
    ExecutionManifest {
        schema_version: CLUSTER_EXECUTION_SCHEMA_VERSION,
        protocol_version: CLUSTER_PROTOCOL_VERSION,
        cluster_id: "project-cluster-1".to_owned(),
        version,
        previous_digest: None,
        encryption_keyring_digest: None,
        tables: vec![ExecutionTable {
            name: "accounts".to_owned(),
            primary_key: Some("id".to_owned()),
            fields: vec![
                ExecutionField {
                    name: "id".to_owned(),
                    definition: "uuid|pk|unique|notnull".to_owned(),
                },
                ExecutionField {
                    name: "owner_id".to_owned(),
                    definition: "uuid".to_owned(),
                },
            ],
            path_indexes: Vec::new(),
            default_ttl_seconds: None,
        }],
        auth: ExecutionAuth {
            enabled: true,
            issuer: "http://localhost:5890/auth/v1".to_owned(),
            access_token_ttl_seconds: 100,
            api_keys: vec![ExecutionApiKey {
                digest: api_key_digest("lux_sec_test"),
                kind: ExecutionApiKeyKind::Secret,
            }],
            jwt_keys: vec![ExecutionJwtKey {
                kid: kid.to_owned(),
                public_jwk: public_jwk(jwt_signing_key, kid),
            }],
            grants: vec![ExecutionGrant {
                table: "accounts".to_owned(),
                scope: ExecutionGrantScope::Read,
                predicate: "owner_id = auth.uid()".to_owned(),
            }],
            session_revocations: vec![ExecutionSessionRevocation {
                session_id: "session-1".to_owned(),
                revoked_after: 100,
                retain_until: 200,
            }],
            principal_blocks: vec![ExecutionPrincipalBlock {
                user_id: "user-1".to_owned(),
                kind: ExecutionPrincipalBlockKind::Banned,
                blocked_at: 100,
                blocked_until: Some(150),
                retain_until: 200,
            }],
        },
    }
}

fn signed(
    version: u64,
    controller_key: &SigningKey,
    jwt_signing_key: &SigningKey,
) -> SignedExecution {
    SignedExecution::sign(manifest(version, jwt_signing_key), controller_key).unwrap()
}

#[test]
fn signed_execution_compiles_owner_local_lookup_indexes() {
    let controller_key = SigningKey::random(&mut OsRng);
    let jwt_signing_key = SigningKey::random(&mut OsRng);
    let execution = signed(1, &controller_key, &jwt_signing_key)
        .verify(&encode_controller_public_key(
            controller_key.verifying_key(),
        ))
        .unwrap();
    assert_eq!(execution.primary_key("accounts"), Some("id"));
    assert_eq!(
        execution
            .grant("accounts", ExecutionGrantScope::Read)
            .unwrap()
            .predicate,
        "owner_id = auth.uid()"
    );
    assert_eq!(
        execution.api_key_kind("lux_sec_test"),
        Some(ExecutionApiKeyKind::Secret)
    );
    assert_eq!(execution.api_key_kind("lux_sec_wrong"), None);
    assert!(execution.has_jwt_key("jwt-1"));
    assert!(execution.session_is_revoked("session-1", 100, 150));
    assert!(!execution.session_is_revoked("session-1", 101, 150));
    assert!(!execution.session_is_revoked("session-1", 100, 201));
    assert!(execution.principal_is_blocked("user-1", 149));
    assert!(!execution.principal_is_blocked("user-1", 150));
}

#[test]
fn signed_payload_never_contains_api_key_or_private_jwk_material() {
    let controller_key = SigningKey::random(&mut OsRng);
    let jwt_signing_key = SigningKey::random(&mut OsRng);
    let mut candidate = manifest(1, &jwt_signing_key);
    let payload = candidate.signing_payload().unwrap();
    assert!(!payload
        .windows(b"lux_sec_test".len())
        .any(|window| window == b"lux_sec_test"));

    let mut jwk =
        serde_json::from_str::<serde_json::Value>(&candidate.auth.jwt_keys[0].public_jwk).unwrap();
    jwk.as_object_mut().unwrap().insert(
        "d".to_owned(),
        serde_json::Value::String("private".to_owned()),
    );
    candidate.auth.jwt_keys[0].public_jwk = serde_json::to_string(&jwk).unwrap();
    assert!(matches!(
        SignedExecution::sign(candidate, &controller_key),
        Err(ClusterError::InvalidExecution(_))
    ));

    let mut candidate = manifest(1, &jwt_signing_key);
    let mut jwk =
        serde_json::from_str::<serde_json::Value>(&candidate.auth.jwt_keys[0].public_jwk).unwrap();
    jwk.as_object_mut().unwrap().insert(
        "client_secret".to_owned(),
        serde_json::Value::String("must-not-travel".to_owned()),
    );
    candidate.auth.jwt_keys[0].public_jwk = serde_json::to_string(&jwk).unwrap();
    assert!(matches!(
        SignedExecution::sign(candidate, &controller_key),
        Err(ClusterError::InvalidExecution(_))
    ));
}

#[test]
fn untrusted_execution_payload_is_bounded_before_signature_work() {
    let controller_key = SigningKey::random(&mut OsRng);
    let jwt_signing_key = SigningKey::random(&mut OsRng);
    let public_key = encode_controller_public_key(controller_key.verifying_key());
    let mut candidate = signed(1, &controller_key, &jwt_signing_key);
    candidate.manifest.auth.jwt_keys[0].public_jwk = "x".repeat(16 * 1024 + 1);
    assert!(matches!(
        candidate.verify(&public_key),
        Err(ClusterError::InvalidExecution(_))
    ));
}

#[test]
fn signature_covers_every_execution_projection() {
    let controller_key = SigningKey::random(&mut OsRng);
    let jwt_signing_key = SigningKey::random(&mut OsRng);
    let public_key = encode_controller_public_key(controller_key.verifying_key());
    let mut candidate = signed(1, &controller_key, &jwt_signing_key);
    candidate.manifest.auth.grants[0].predicate = "owner_id = attacker".to_owned();
    assert!(matches!(
        candidate.verify(&public_key),
        Err(ClusterError::Signature(_))
    ));

    let mut candidate = signed(1, &controller_key, &jwt_signing_key);
    candidate.manifest.tables[0].primary_key = Some("owner_id".to_owned());
    assert!(matches!(
        candidate.verify(&public_key),
        Err(ClusterError::Signature(_))
    ));
}

#[test]
fn transition_is_linear_hash_chained_and_semantic() {
    let controller_key = SigningKey::random(&mut OsRng);
    let jwt_signing_key = SigningKey::random(&mut OsRng);
    let public_key = encode_controller_public_key(controller_key.verifying_key());
    let current = signed(1, &controller_key, &jwt_signing_key)
        .verify(&public_key)
        .unwrap();
    let mut next = current.manifest().clone();
    next.version = 2;
    next.previous_digest = Some(current.digest().to_owned());
    next.auth.session_revocations[0].retain_until = 250;
    let next = SignedExecution::sign(next, &controller_key)
        .unwrap()
        .verify(&public_key)
        .unwrap();
    current.transition_to(&next).unwrap();

    let mut wrong_parent = next.manifest().clone();
    wrong_parent.version = 3;
    wrong_parent.previous_digest = Some("0".repeat(64));
    wrong_parent.auth.session_revocations[0].retain_until = 300;
    let wrong_parent = SignedExecution::sign(wrong_parent, &controller_key)
        .unwrap()
        .verify(&public_key)
        .unwrap();
    assert!(matches!(
        next.transition_to(&wrong_parent),
        Err(ClusterError::InvalidExecution(_))
    ));

    let mut no_change = next.manifest().clone();
    no_change.version = 3;
    no_change.previous_digest = Some(next.digest().to_owned());
    let no_change = SignedExecution::sign(no_change, &controller_key)
        .unwrap()
        .verify(&public_key)
        .unwrap();
    assert!(matches!(
        next.transition_to(&no_change),
        Err(ClusterError::InvalidExecution(_))
    ));
}

#[test]
fn rcu_execution_state_keeps_prepared_metadata_off_the_dataplane() {
    let controller_key = SigningKey::random(&mut OsRng);
    let jwt_signing_key = SigningKey::random(&mut OsRng);
    let public_key = encode_controller_public_key(controller_key.verifying_key());
    let current = signed(1, &controller_key, &jwt_signing_key)
        .verify(&public_key)
        .unwrap();
    let state = ExecutionState::in_memory(current, public_key);
    let before = state.current();
    let mut next = before.manifest().clone();
    next.version = 2;
    next.previous_digest = Some(before.digest().to_owned());
    next.auth.session_revocations[0].retain_until = 250;
    state
        .prepare(SignedExecution::sign(next, &controller_key).unwrap())
        .unwrap();

    let prepared = state.snapshot();
    assert_eq!(prepared.current().manifest().version, 1);
    assert_eq!(prepared.pending().unwrap().manifest().version, 2);
    assert_eq!(before.manifest().version, 1);

    state.commit(2).unwrap();
    assert_eq!(state.current().manifest().version, 2);
    assert_eq!(prepared.current().manifest().version, 1);
    assert_eq!(prepared.pending().unwrap().manifest().version, 2);
}

#[test]
fn durable_execution_prepare_survives_restart_without_cutover() {
    let controller_key = SigningKey::random(&mut OsRng);
    let jwt_signing_key = SigningKey::random(&mut OsRng);
    let public_key = encode_controller_public_key(controller_key.verifying_key());
    let current = signed(1, &controller_key, &jwt_signing_key)
        .verify(&public_key)
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let state_path = directory.path().join("execution-state.json");
    let state = ExecutionState::open(current, public_key.clone(), &state_path).unwrap();
    let current = state.current();
    let mut next = current.manifest().clone();
    next.version = 2;
    next.previous_digest = Some(current.digest().to_owned());
    next.auth.session_revocations[0].retain_until = 250;
    state
        .prepare(SignedExecution::sign(next, &controller_key).unwrap())
        .unwrap();
    drop(state);

    let supplied = signed(1, &controller_key, &jwt_signing_key)
        .verify(&public_key)
        .unwrap();
    let reopened = ExecutionState::open(supplied, public_key, &state_path).unwrap();
    assert_eq!(reopened.current().manifest().version, 1);
    assert_eq!(reopened.pending().unwrap().manifest().version, 2);
    reopened.commit(2).unwrap();
    assert_eq!(reopened.current().manifest().version, 2);
}

#[test]
fn durable_execution_rejects_same_version_with_different_contents() {
    let controller_key = SigningKey::random(&mut OsRng);
    let jwt_signing_key = SigningKey::random(&mut OsRng);
    let public_key = encode_controller_public_key(controller_key.verifying_key());
    let current = signed(1, &controller_key, &jwt_signing_key)
        .verify(&public_key)
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let state_path = directory.path().join("execution-state.json");
    let state = ExecutionState::open(current, public_key.clone(), &state_path).unwrap();
    drop(state);

    let mut conflicting = manifest(1, &jwt_signing_key);
    conflicting.tables[0].default_ttl_seconds = Some(60);
    let conflicting = SignedExecution::sign(conflicting, &controller_key)
        .unwrap()
        .verify(&public_key)
        .unwrap();
    assert!(matches!(
        ExecutionState::open(conflicting, public_key, &state_path),
        Err(ClusterError::InvalidExecution(_))
    ));
}

#[test]
fn canonical_order_and_encryption_digest_are_enforced() {
    let controller_key = SigningKey::random(&mut OsRng);
    let jwt_signing_key = SigningKey::random(&mut OsRng);
    let mut candidate = manifest(1, &jwt_signing_key);
    candidate.tables[0].fields.reverse();
    assert!(matches!(
        SignedExecution::sign(candidate, &controller_key),
        Err(ClusterError::InvalidExecution(_))
    ));

    let mut candidate = manifest(1, &jwt_signing_key);
    candidate.tables[0].fields[0]
        .definition
        .push_str("|encrypted");
    assert!(matches!(
        SignedExecution::sign(candidate.clone(), &controller_key),
        Err(ClusterError::InvalidExecution(_))
    ));
    candidate.encryption_keyring_digest = Some("a".repeat(64));
    SignedExecution::sign(candidate, &controller_key).unwrap();

    let mut candidate = manifest(1, &jwt_signing_key);
    candidate.tables[0].fields[0].definition = "uuid|pk".to_owned();
    assert!(matches!(
        SignedExecution::sign(candidate, &controller_key),
        Err(ClusterError::InvalidExecution(_))
    ));
}

#[test]
fn table_names_match_the_engine_namespace_contract() {
    let controller_key = SigningKey::random(&mut OsRng);
    let jwt_signing_key = SigningKey::random(&mut OsRng);
    let mut candidate = manifest(1, &jwt_signing_key);
    candidate.tables[0].name = "not-an-engine-table".to_owned();
    candidate.auth.grants[0].table = candidate.tables[0].name.clone();
    assert!(matches!(
        SignedExecution::sign(candidate, &controller_key),
        Err(ClusterError::InvalidExecution(_))
    ));
}

#[test]
fn implicit_primary_keys_are_projected_as_engine_id() {
    let controller_key = SigningKey::random(&mut OsRng);
    let jwt_signing_key = SigningKey::random(&mut OsRng);
    let public_key = encode_controller_public_key(controller_key.verifying_key());
    let mut candidate = manifest(1, &jwt_signing_key);
    candidate.tables[0].primary_key = None;
    candidate.tables[0].fields[0].definition = "uuid".to_owned();
    let compiled = SignedExecution::sign(candidate, &controller_key)
        .unwrap()
        .verify(&public_key)
        .unwrap();
    assert_eq!(compiled.primary_key("accounts"), Some("id"));
}

#[test]
fn disabled_auth_cannot_smuggle_user_execution_state() {
    let controller_key = SigningKey::random(&mut OsRng);
    let jwt_signing_key = SigningKey::random(&mut OsRng);
    let mut candidate = manifest(1, &jwt_signing_key);
    candidate.auth.enabled = false;
    assert!(matches!(
        SignedExecution::sign(candidate, &controller_key),
        Err(ClusterError::InvalidExecution(_))
    ));
}

#[test]
fn revocation_entries_cover_the_full_token_lifetime() {
    let controller_key = SigningKey::random(&mut OsRng);
    let jwt_signing_key = SigningKey::random(&mut OsRng);

    let mut candidate = manifest(1, &jwt_signing_key);
    candidate.auth.session_revocations[0].retain_until = 199;
    assert!(matches!(
        SignedExecution::sign(candidate, &controller_key),
        Err(ClusterError::InvalidExecution(_))
    ));

    let mut candidate = manifest(1, &jwt_signing_key);
    candidate.auth.principal_blocks[0].blocked_until = Some(250);
    assert!(matches!(
        SignedExecution::sign(candidate, &controller_key),
        Err(ClusterError::InvalidExecution(_))
    ));

    let mut candidate = manifest(1, &jwt_signing_key);
    candidate.auth.access_token_ttl_seconds = 0;
    assert!(matches!(
        SignedExecution::sign(candidate, &controller_key),
        Err(ClusterError::InvalidExecution(_))
    ));
}

#[test]
fn grant_subqueries_require_metadata_for_every_dependency() {
    let controller_key = SigningKey::random(&mut OsRng);
    let jwt_signing_key = SigningKey::random(&mut OsRng);
    let mut candidate = manifest(1, &jwt_signing_key);
    candidate.auth.grants[0].predicate =
        "owner_id IN ( SELECT id FROM missing_accounts )".to_owned();
    assert!(matches!(
        SignedExecution::sign(candidate, &controller_key),
        Err(ClusterError::InvalidExecution(_))
    ));
}

#[test]
fn wire_enums_are_snake_case() {
    assert_eq!(
        serde_json::to_string(&ExecutionApiKeyKind::Publishable).unwrap(),
        "\"publishable\""
    );
    assert_eq!(
        serde_json::to_string(&ExecutionGrantScope::Write).unwrap(),
        "\"write\""
    );
    assert_eq!(
        serde_json::to_string(&ExecutionPrincipalBlockKind::Deleted).unwrap(),
        "\"deleted\""
    );
}
