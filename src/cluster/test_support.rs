use super::{
    encode_controller_public_key, CompiledExecution, ExecutionAuth, ExecutionField,
    ExecutionManifest, ExecutionPathIndex, ExecutionTable, SignedExecution,
    CLUSTER_EXECUTION_SCHEMA_VERSION, CLUSTER_PROTOCOL_VERSION,
};
use p256::ecdsa::SigningKey;
use rand_core::OsRng;

pub(crate) fn compiled_execution(
    cluster_id: &str,
    tables: Vec<ExecutionTable>,
) -> CompiledExecution {
    let controller_key = SigningKey::random(&mut OsRng);
    SignedExecution::sign(
        ExecutionManifest {
            schema_version: CLUSTER_EXECUTION_SCHEMA_VERSION,
            protocol_version: CLUSTER_PROTOCOL_VERSION,
            cluster_id: cluster_id.to_owned(),
            version: 1,
            previous_digest: None,
            encryption_keyring_digest: None,
            tables,
            auth: ExecutionAuth {
                enabled: false,
                issuer: String::new(),
                access_token_ttl_seconds: 0,
                api_keys: Vec::new(),
                jwt_keys: Vec::new(),
                grants: Vec::new(),
                session_revocations: Vec::new(),
                principal_blocks: Vec::new(),
            },
        },
        &controller_key,
    )
    .expect("test execution metadata must be valid")
    .verify(&encode_controller_public_key(
        controller_key.verifying_key(),
    ))
    .expect("test execution signature must verify")
}

pub(crate) fn execution_table(
    name: &str,
    primary_key: Option<&str>,
    fields: &[(&str, &str)],
    path_indexes: &[(&str, &str)],
) -> ExecutionTable {
    let mut fields = fields
        .iter()
        .map(|(name, definition)| ExecutionField {
            name: (*name).to_owned(),
            definition: (*definition).to_owned(),
        })
        .collect::<Vec<_>>();
    fields.sort_unstable_by(|left, right| left.name.cmp(&right.name));
    let mut path_indexes = path_indexes
        .iter()
        .map(|(path, field_type)| ExecutionPathIndex {
            path: (*path).to_owned(),
            field_type: (*field_type).to_owned(),
        })
        .collect::<Vec<_>>();
    path_indexes.sort_unstable_by(|left, right| left.path.cmp(&right.path));
    ExecutionTable {
        name: name.to_owned(),
        primary_key: primary_key.map(str::to_owned),
        fields,
        path_indexes,
        default_ttl_seconds: None,
    }
}
