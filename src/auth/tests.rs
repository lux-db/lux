use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::Arc;

use p256::pkcs8::EncodePublicKey;
use parking_lot::RwLock;
use rsa::pkcs8::EncodePrivateKey as EncodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;

use super::*;
use crate::tables::SchemaCache;
use crate::{DurabilityConfig, DurabilityPolicy, ServerConfig};

fn principal(uid: &str) -> AuthPrincipal {
    AuthPrincipal {
        user_id: uid.into(),
        email: "u@x.dev".into(),
        session_id: "sess".into(),
        role: "authenticated".into(),
        is_anonymous: false,
    }
}

#[test]
fn api_key_cache_is_isolated_per_store() {
    let store_a = Store::new();
    let store_b = Store::new();
    let cache_a = Arc::new(RwLock::new(SchemaCache::new()));
    let cache_b = Arc::new(RwLock::new(SchemaCache::new()));
    bootstrap(&store_a, &cache_a, &store_a.config().auth).unwrap();
    bootstrap(&store_b, &cache_b, &store_b.config().auth).unwrap();

    let raw_key = "lux_sec_store_a_only";
    insert_api_key(
        &store_a,
        &cache_a,
        raw_key,
        ApiKeyKind::Secret,
        "store-a",
        Instant::now(),
    )
    .unwrap();

    assert_eq!(
        lookup_api_key(raw_key, &store_a, &cache_a)
            .unwrap()
            .map(|resolved| resolved.kind),
        Some(ApiKeyKind::Secret)
    );
    assert_eq!(
        lookup_api_key(raw_key, &store_b, &cache_b)
            .unwrap()
            .map(|resolved| resolved.kind),
        None,
        "a cache hit from store A must not authenticate against store B"
    );
}

#[test]
fn project_key_storage_errors_never_look_like_open_local() {
    let mut config = ServerConfig::default();
    config.auth.enabled = true;
    let store = Store::new_with_config(Arc::new(config));
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    bootstrap(&store, &cache, &store.config().auth).unwrap();
    assert!(!project_keys_configured(&store, &cache).unwrap());

    store.del(&[b"_t:auth.keys:schema"]);
    let cold_cache = Arc::new(RwLock::new(SchemaCache::new()));
    assert!(
        project_keys_configured(&store, &cold_cache).is_err(),
        "an unreadable auth.keys table must fail closed"
    );
}

#[test]
fn auth_routes_are_private_until_explicitly_classified() {
    assert_eq!(
        auth_route_access("POST", &["signup"]),
        Some(AuthRouteAccess::Project)
    );
    assert_eq!(
        auth_route_access("GET", &["admin", "users"]),
        Some(AuthRouteAccess::Secret)
    );
    assert_eq!(auth_route_access("GET", &["future-route"]), None);
}

#[test]
fn grant_definitions_cannot_target_reserved_tables() {
    let store = Store::new();
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    let now = Instant::now();
    let outer = crate::grants::parse_grant(&["read", "ON", "auth.users"]).unwrap();
    assert!(put_grant(&store, &cache, &outer, now)
        .unwrap_err()
        .contains("managed"));

    let nested = crate::grants::Grant {
        table: "messages".to_string(),
        scopes: vec![crate::grants::Scope::Read],
        predicate: crate::grants::Predicate {
            conditions: vec![crate::grants::Condition::InSubquery {
                column: "owner_id".to_string(),
                negated: false,
                subquery: crate::grants::Subquery {
                    projected: "subject_id".to_string(),
                    table: "push.devices".to_string(),
                    inner: crate::grants::Predicate::default(),
                },
            }],
            alternatives: Vec::new(),
        },
    };
    assert!(put_grant(&store, &cache, &nested, now)
        .unwrap_err()
        .contains("managed"));
}

#[test]
fn row_is_anonymous_detects_provider() {
    let anon = HashMap::from([(
        "raw_app_meta_data".to_string(),
        r#"{"provider":"anonymous"}"#.to_string(),
    )]);
    assert!(row_is_anonymous(&anon));
    let real = HashMap::from([(
        "raw_app_meta_data".to_string(),
        r#"{"provider":"email","providers":["email"]}"#.to_string(),
    )]);
    assert!(!row_is_anonymous(&real));
    assert!(!row_is_anonymous(&HashMap::new())); // missing metadata -> not anonymous
}

fn cond(c: &str, o: &str, v: &str) -> crate::grants::ResolvedCond {
    crate::grants::ResolvedCond {
        column: c.into(),
        op: o.into(),
        value: v.into(),
    }
}

#[test]
fn add_column_if_missing_is_idempotent_and_leaves_existing_schema_alone() {
    let store = Store::new();
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    let now = Instant::now();

    create_table_if_missing(
        &store,
        &cache,
        "widgets",
        &["id STR PRIMARY KEY,", "name STR"],
        now,
    )
    .unwrap();
    crate::tables::table_insert(
        &store,
        &cache,
        "widgets",
        &[("id", "w1"), ("name", "bolt")],
        now,
    )
    .unwrap();

    add_column_if_missing(&store, &cache, "widgets", "environment STR", now).unwrap();
    let schema = crate::tables::table_schema(&store, &cache, "widgets", now).unwrap();
    assert!(
        schema.iter().any(|f| f.starts_with("environment ")),
        "column not added: {schema:?}"
    );

    // Called on every `ensure_tables`, so a second call must be a no-op
    // rather than the "field already exists" error `table_add_column` raises.
    add_column_if_missing(&store, &cache, "widgets", "environment STR", now).unwrap();
    let after = crate::tables::table_schema(&store, &cache, "widgets", now).unwrap();
    assert_eq!(schema, after);

    // The existing row survives the backfill.
    let row = find_row_by_field(&store, &cache, "widgets", "id", "w1", now)
        .unwrap()
        .expect("row should survive the column add");
    assert_eq!(row.get("name").map(String::as_str), Some("bolt"));
}

// Internal schema upgrades never reach `execute_with_wal`, so the table layer
// must own their journal boundary just as it does for command-driven upgrades.
#[test]
fn add_column_if_missing_survives_wal_replay() {
    let dir = tempfile::tempdir().unwrap();
    let config = Arc::new(crate::ServerConfig {
        storage: crate::StorageConfig {
            mode: crate::StorageMode::Tiered,
            dir: dir.path().to_string_lossy().to_string(),
        },
        ..crate::ServerConfig::default()
    });
    let store = Arc::new(Store::new_with_config(config.clone()));
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    let now = Instant::now();

    create_table_if_missing(
        &store,
        &cache,
        "widgets",
        &["id STR PRIMARY KEY,", "name STR"],
        now,
    )
    .unwrap();
    add_column_if_missing(&store, &cache, "widgets", "environment STR", now).unwrap();
    store.fsync_wal();

    let restored = Arc::new(Store::new_with_config(config));
    restored.replay_wal(&crate::pubsub::Broker::new()).unwrap();
    let restored_cache = Arc::new(RwLock::new(SchemaCache::new()));
    let schema = crate::tables::table_schema(&restored, &restored_cache, "widgets", now).unwrap();
    assert!(
        schema.iter().any(|f| f.starts_with("environment ")),
        "column lost on replay: {schema:?}"
    );
}

#[test]
fn read_grant_enforced_end_to_end() {
    let store = Store::new();
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    let now = Instant::now();

    // GRANT read ON messages WHERE user_id = auth.uid()
    let grant = crate::grants::parse_grant(&[
        "read",
        "ON",
        "messages",
        "WHERE",
        "user_id",
        "=",
        "auth.uid()",
    ])
    .unwrap();
    put_grant(&store, &cache, &grant, now).unwrap();

    let p = principal("123abc");
    // Read grant resolves to a filter scoping the query to the caller's
    // own rows (RLS USING) -- the caller's uid is substituted for auth.uid().
    let filter = read_filter(&store, &cache, &p, "messages", now).unwrap();
    assert_eq!(filter, "user_id = '123abc'");
    // A different principal gets a filter scoped to *their* uid, never others'.
    let other = principal("999zzz");
    let other_filter = read_filter(&store, &cache, &other, "messages", now).unwrap();
    assert_eq!(other_filter, "user_id = '999zzz'");
    // No grant on another table -> deny-by-default (Err, not an open filter).
    assert!(read_filter(&store, &cache, &p, "secrets", now).is_err());
}

#[test]
fn write_grant_with_check_end_to_end() {
    let store = Store::new();
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    let now = Instant::now();

    let grant = crate::grants::parse_grant(&[
        "write",
        "ON",
        "messages",
        "WHERE",
        "user_id",
        "=",
        "auth.uid()",
    ])
    .unwrap();
    put_grant(&store, &cache, &grant, now).unwrap();
    let p = principal("123abc");

    // Inserting a row owned by self -> allowed.
    let own = |c: &str| match c {
        "user_id" => Some("123abc".to_string()),
        _ => None,
    };
    assert!(check_write_row(&store, &cache, &p, "messages", own, now).is_ok());
    // Inserting a row for someone else -> denied (WITH CHECK).
    let other = |c: &str| match c {
        "user_id" => Some("evil".to_string()),
        _ => None,
    };
    assert!(check_write_row(&store, &cache, &p, "messages", other, now).is_err());
    // UPDATE/DELETE: the write grant resolves to a filter that scopes the
    // statement to the caller's own rows (RLS USING).
    let filter = write_filter(&store, &cache, &p, "messages", now).unwrap();
    assert_eq!(filter, "user_id = '123abc'");
    // No write grant on another table -> deny-by-default (Err).
    assert!(write_filter(&store, &cache, &p, "other", now).is_err());
}

#[test]
fn update_with_check_single_condition() {
    let store = Store::new();
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    let now = Instant::now();
    grant(
        &store,
        &cache,
        &["write", "ON", "t", "WHERE", "owner", "=", "auth.uid()"],
        now,
    );
    let p = principal("u1");
    // moving ownership away -> rejected
    assert!(check_update_set(&store, &cache, &p, "t", &[("owner", "u2")], now).is_err());
    // setting owner to self -> ok
    assert!(check_update_set(&store, &cache, &p, "t", &[("owner", "u1")], now).is_ok());
    // a non-grant column -> ok (grant column untouched)
    assert!(check_update_set(&store, &cache, &p, "t", &[("body", "hi")], now).is_ok());
    // empty set -> ok
    assert!(check_update_set(&store, &cache, &p, "t", &[], now).is_ok());
    // no write grant on another table -> deny-by-default
    assert!(check_update_set(&store, &cache, &p, "other", &[("x", "y")], now).is_err());
}

#[test]
fn update_with_check_multi_condition_enforces_each() {
    let store = Store::new();
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    let now = Instant::now();
    grant(
        &store,
        &cache,
        &[
            "write",
            "ON",
            "t",
            "WHERE",
            "owner",
            "=",
            "auth.uid()",
            "AND",
            "status",
            "=",
            "active",
        ],
        now,
    );
    let p = principal("u1");
    // changing a *second* grant column to an invalid value is caught even
    // though owner is untouched (every condition is enforced, not just the first)
    assert!(check_update_set(&store, &cache, &p, "t", &[("status", "archived")], now).is_err());
    assert!(check_update_set(&store, &cache, &p, "t", &[("status", "active")], now).is_ok());
    assert!(check_update_set(&store, &cache, &p, "t", &[("owner", "u2")], now).is_err());
    // both set validly -> ok; one of them invalid -> rejected
    assert!(check_update_set(
        &store,
        &cache,
        &p,
        "t",
        &[("owner", "u1"), ("status", "active")],
        now
    )
    .is_ok());
    assert!(check_update_set(
        &store,
        &cache,
        &p,
        "t",
        &[("owner", "u1"), ("status", "x")],
        now
    )
    .is_err());
    // touching neither grant column -> ok
    assert!(check_update_set(&store, &cache, &p, "t", &[("body", "z")], now).is_ok());
}

#[test]
fn update_with_check_comparison_operator() {
    let store = Store::new();
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    let now = Instant::now();
    grant(
        &store,
        &cache,
        &["write", "ON", "t", "WHERE", "priority", ">=", "5"],
        now,
    );
    let p = principal("u1");
    // the >= operator is applied to the set value, numerically
    assert!(check_update_set(&store, &cache, &p, "t", &[("priority", "3")], now).is_err());
    assert!(check_update_set(&store, &cache, &p, "t", &[("priority", "5")], now).is_ok());
    assert!(check_update_set(&store, &cache, &p, "t", &[("priority", "9")], now).is_ok());
}

#[test]
fn revoke_removes_grant() {
    let store = Store::new();
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    let now = Instant::now();
    let grant = crate::grants::parse_grant(&[
        "read",
        "ON",
        "messages",
        "WHERE",
        "user_id",
        "=",
        "auth.uid()",
    ])
    .unwrap();
    put_grant(&store, &cache, &grant, now).unwrap();
    let p = principal("123abc");
    assert!(read_filter(&store, &cache, &p, "messages", now).is_ok());
    delete_grant(&store, &cache, "messages", crate::grants::Scope::Read, now).unwrap();
    // After revoke -> deny-by-default.
    assert!(read_filter(&store, &cache, &p, "messages", now).is_err());
}

#[test]
fn nested_membership_subquery_read_filter_resolves() {
    let store = Store::new();
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    let now = Instant::now();
    crate::tables::table_create(
        &store,
        &cache,
        "profiles",
        &["id", "STR", "PRIMARY", "KEY,", "name", "STR"],
        now,
    )
    .unwrap();
    crate::tables::table_create(
        &store,
        &cache,
        "members",
        &[
            "id", "STR", "PRIMARY", "KEY,", "user_id", "STR,", "team_id", "STR",
        ],
        now,
    )
    .unwrap();
    for (id, name) in [("alice", "Alice"), ("bob", "Bob"), ("cyd", "Cyd")] {
        crate::tables::table_insert(
            &store,
            &cache,
            "profiles",
            &[("id", id), ("name", name)],
            now,
        )
        .unwrap();
    }
    for (id, uid, team) in [
        ("1", "alice", "team-a"),
        ("2", "bob", "team-a"),
        ("3", "cyd", "team-b"),
    ] {
        crate::tables::table_insert(
            &store,
            &cache,
            "members",
            &[("id", id), ("user_id", uid), ("team_id", team)],
            now,
        )
        .unwrap();
    }
    grant(
        &store,
        &cache,
        &[
            "read",
            "ON",
            "profiles",
            "WHERE",
            "id",
            "IN",
            "(",
            "SELECT",
            "user_id",
            "FROM",
            "members",
            "WHERE",
            "team_id",
            "IN",
            "(",
            "SELECT",
            "team_id",
            "FROM",
            "members",
            "WHERE",
            "user_id",
            "=",
            "auth.uid()",
            ")",
            ")",
        ],
        now,
    );
    let filter = read_filter(&store, &cache, &principal("alice"), "profiles", now).unwrap();
    assert!(filter.starts_with("id IN ( "), "got: {filter}");
    assert!(filter.contains("alice"), "got: {filter}");
    assert!(filter.contains("bob"), "got: {filter}");
    assert!(!filter.contains("cyd"), "got: {filter}");

    let deps =
        read_filter_dependencies(&store, &cache, &principal("alice"), "profiles", now).unwrap();
    assert_eq!(deps, vec!["members".to_string()]);
}

#[test]
fn repeated_profile_read_grants_accumulate_as_alternatives() {
    let store = Store::new();
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    let now = Instant::now();
    crate::tables::table_create(
        &store,
        &cache,
        "profiles",
        &["id", "STR", "PRIMARY", "KEY,", "name", "STR"],
        now,
    )
    .unwrap();
    crate::tables::table_create(
        &store,
        &cache,
        "members",
        &[
            "id", "STR", "PRIMARY", "KEY,", "user_id", "STR,", "team_id", "STR",
        ],
        now,
    )
    .unwrap();

    grant(
        &store,
        &cache,
        &[
            "read,",
            "write",
            "ON",
            "profiles",
            "WHERE",
            "id",
            "=",
            "auth.uid()",
        ],
        now,
    );
    grant(
        &store,
        &cache,
        &[
            "read",
            "ON",
            "profiles",
            "WHERE",
            "id",
            "IN",
            "(",
            "SELECT",
            "user_id",
            "FROM",
            "members",
            "WHERE",
            "team_id",
            "IN",
            "(",
            "SELECT",
            "team_id",
            "FROM",
            "members",
            "WHERE",
            "user_id",
            "=",
            "auth.uid()",
            ")",
            ")",
        ],
        now,
    );

    let alice_filter = read_filter(&store, &cache, &principal("alice"), "profiles", now).unwrap();
    assert_eq!(alice_filter, "id IN ( 'alice' )");
    assert_eq!(
        write_filter(&store, &cache, &principal("alice"), "profiles", now).unwrap(),
        "id = 'alice'"
    );

    crate::tables::table_insert(
        &store,
        &cache,
        "members",
        &[("id", "1"), ("user_id", "alice"), ("team_id", "team-a")],
        now,
    )
    .unwrap();
    crate::tables::table_insert(
        &store,
        &cache,
        "members",
        &[("id", "2"), ("user_id", "bob"), ("team_id", "team-a")],
        now,
    )
    .unwrap();

    let teamed_filter = read_filter(&store, &cache, &principal("alice"), "profiles", now).unwrap();
    assert!(
        teamed_filter.starts_with("id IN ( "),
        "got: {teamed_filter}"
    );
    assert!(teamed_filter.contains("alice"), "got: {teamed_filter}");
    assert!(teamed_filter.contains("bob"), "got: {teamed_filter}");
}

#[test]
fn repeated_read_grants_on_different_columns_render_or_alternatives() {
    let store = Store::new();
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    let now = Instant::now();
    crate::tables::table_create(
        &store,
        &cache,
        "invites",
        &[
            "id", "STR", "PRIMARY", "KEY,", "team_id", "STR,", "email", "STR",
        ],
        now,
    )
    .unwrap();
    crate::tables::table_create(
        &store,
        &cache,
        "members",
        &[
            "id", "STR", "PRIMARY", "KEY,", "user_id", "STR,", "team_id", "STR",
        ],
        now,
    )
    .unwrap();
    crate::tables::table_insert(
        &store,
        &cache,
        "members",
        &[("id", "1"), ("user_id", "alice"), ("team_id", "team-a")],
        now,
    )
    .unwrap();

    grant(
        &store,
        &cache,
        &[
            "read",
            "ON",
            "invites",
            "WHERE",
            "team_id",
            "IN",
            "(",
            "SELECT",
            "team_id",
            "FROM",
            "members",
            "WHERE",
            "user_id",
            "=",
            "auth.uid()",
            ")",
        ],
        now,
    );
    grant(
        &store,
        &cache,
        &["read", "ON", "invites", "WHERE", "email", "=", "auth.email"],
        now,
    );

    let filter = read_filter(&store, &cache, &principal("alice"), "invites", now).unwrap();
    assert_eq!(filter, "team_id IN ( 'team-a' ) OR email = 'u@x.dev'");
}

// ── RLS auto-filter (USING) coverage ──

fn grant(store: &Store, cache: &SharedSchemaCache, args: &[&str], now: Instant) {
    let g = crate::grants::parse_grant(args).unwrap();
    put_grant(store, cache, &g, now).unwrap();
}

#[test]
fn read_filter_conds_returns_structured_conditions() {
    let store = Store::new();
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    let now = Instant::now();
    grant(
        &store,
        &cache,
        &[
            "read",
            "ON",
            "messages",
            "WHERE",
            "user_id",
            "=",
            "auth.uid()",
        ],
        now,
    );
    let p = principal("abc123");
    let conds = read_filter_conds(&store, &cache, &p, "messages", now).unwrap();
    assert_eq!(
        conds,
        vec![crate::grants::EnforcedCondition::Cmp(cond(
            "user_id", "=", "abc123"
        ))]
    );
}

#[test]
fn unconditional_grant_yields_empty_filter() {
    // GRANT read ON public_posts (no WHERE) -> everyone with the grant reads
    // all rows; the filter is empty (no narrowing), but access is NOT denied.
    let store = Store::new();
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    let now = Instant::now();
    grant(&store, &cache, &["read", "ON", "public_posts"], now);
    let p = principal("anyone");
    let filter = read_filter(&store, &cache, &p, "public_posts", now).unwrap();
    assert_eq!(filter, "");
    assert!(read_filter_conds(&store, &cache, &p, "public_posts", now)
        .unwrap()
        .is_empty());
}

#[test]
fn multi_condition_grant_renders_and_chain() {
    let store = Store::new();
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    let now = Instant::now();
    grant(
        &store,
        &cache,
        &[
            "read",
            "ON",
            "messages",
            "WHERE",
            "user_id",
            "=",
            "auth.uid()",
            "AND",
            "room",
            "=",
            "general",
        ],
        now,
    );
    let p = principal("u1");
    let filter = read_filter(&store, &cache, &p, "messages", now).unwrap();
    assert_eq!(filter, "user_id = 'u1' AND room = 'general'");
}

#[test]
fn grant_resolves_non_uid_claims() {
    // auth.role / auth.email operands resolve from the principal's claims.
    let store = Store::new();
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    let now = Instant::now();
    grant(
        &store,
        &cache,
        &["read", "ON", "audit", "WHERE", "owner", "=", "auth.email"],
        now,
    );
    let p = principal("u1");
    let filter = read_filter(&store, &cache, &p, "audit", now).unwrap();
    assert_eq!(filter, "owner = 'u@x.dev'");
}

fn encrypted_test_store() -> Store {
    Store::new_with_config(Arc::new(crate::ServerConfig {
        encryption: crate::EncryptionConfig {
            active_key_id: Some("k1".to_string()),
            keys: vec![crate::EncryptionKeyConfig {
                id: "k1".to_string(),
                secret: b"grant-encryption-secret".to_vec(),
                decrypt_only: false,
            }],
            ..Default::default()
        },
        ..crate::ServerConfig::default()
    }))
}

fn assert_auth_secret_is_sealed(stored: &str, plaintext: &str) {
    assert!(stored.starts_with("luxsealed:"), "not sealed: {stored}");
    assert!(
        !stored.contains(plaintext),
        "auth secret envelope leaked plaintext"
    );
}

#[test]
fn auth_secret_storage_health_distinguishes_every_operating_state() {
    let disabled = Store::new();
    let disabled_health = secret_storage_health(&disabled);
    assert_eq!(disabled_health.status, AuthSecretStorageStatus::Disabled);

    let degraded = Store::new_with_config(Arc::new(ServerConfig {
        auth: AuthConfig {
            enabled: true,
            ..AuthConfig::default()
        },
        ..ServerConfig::default()
    }));
    let degraded_health = secret_storage_health(&degraded);
    assert_eq!(degraded_health.status, AuthSecretStorageStatus::Degraded);
    assert_eq!(degraded_health.mode, "ephemeral_plaintext");
    assert!(!degraded_health.persistent);
    assert!(!degraded_health.snapshots_allowed);

    let ready = Store::new_with_config(Arc::new(ServerConfig {
        auth: AuthConfig {
            enabled: true,
            ..AuthConfig::default()
        },
        encryption: crate::EncryptionConfig {
            active_key_id: Some("health-key".to_string()),
            keys: vec![crate::EncryptionKeyConfig {
                id: "health-key".to_string(),
                secret: b"health-encryption-key".to_vec(),
                decrypt_only: false,
            }],
            ..Default::default()
        },
        ..ServerConfig::default()
    }));
    let ready_health = secret_storage_health(&ready);
    assert_eq!(ready_health.status, AuthSecretStorageStatus::Ready);
    assert_eq!(ready_health.mode, "encrypted");
    assert!(ready_health.snapshots_allowed);
    let ready_json = health_json(&ready).to_string();
    assert!(!ready_json.contains("health-key"), "{ready_json}");

    let root = tempfile::tempdir().unwrap();
    let locked = Store::new_with_config(Arc::new(ServerConfig {
        data_dir: root.path().to_string_lossy().to_string(),
        durability: DurabilityConfig {
            policy: DurabilityPolicy::EverySecond,
            ..DurabilityConfig::default()
        },
        auth: AuthConfig {
            enabled: true,
            ..AuthConfig::default()
        },
        ..ServerConfig::default()
    }));
    let locked_health = secret_storage_health(&locked);
    assert_eq!(locked_health.status, AuthSecretStorageStatus::Locked);
    assert_eq!(locked_health.mode, "unavailable");
    assert!(locked_health.persistent);
    assert!(!locked_health.snapshots_allowed);
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    let (status, _, body) = route_http("GET", "/auth/v1/health", "", &[], &[], &locked, &cache);
    assert_eq!(status, 503, "{body}");
    let health: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(health["result"], "locked");
    assert_eq!(health["secret_storage"]["status"], "locked");
}

#[test]
fn auth_health_marks_ephemeral_plaintext_as_degraded() {
    let store = Store::new_with_config(Arc::new(ServerConfig {
        auth: AuthConfig {
            enabled: true,
            ..AuthConfig::default()
        },
        ..ServerConfig::default()
    }));
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    bootstrap(&store, &cache, &store.config().auth).unwrap();
    bootstrap_runtime(&store, &cache, &store.config().auth).unwrap();

    let (status, _, body) = route_http("GET", "/auth/v1/health", "", &[], &[], &store, &cache);
    assert_eq!(status, 200, "{body}");
    let health: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(health["result"], "degraded");
    assert_eq!(health["secret_storage"]["status"], "degraded");
    assert_eq!(health["secret_storage"]["mode"], "ephemeral_plaintext");
    assert_eq!(health["secret_storage"]["snapshots_allowed"], false);
}

#[test]
fn signing_oauth_and_email_secrets_share_one_envelope_boundary() {
    let store = encrypted_test_store();
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    bootstrap(&store, &cache, &store.config().auth).unwrap();
    bootstrap_runtime(&store, &cache, &store.config().auth).unwrap();
    let now = Instant::now();

    let signing = find_row_by_field(&store, &cache, SIGNING_KEYS_TABLE, "active", "true", now)
        .unwrap()
        .unwrap();
    let stored_signing_key = signing.get("private_key_encrypted").unwrap();
    assert_auth_secret_is_sealed(stored_signing_key, "BEGIN PRIVATE KEY");
    assert!(store
        .keys(b"_t:auth.signing_keys:idx:private_key_encrypted:*", now)
        .is_empty());
    assert!(active_signing_key(&store, &cache, now)
        .unwrap()
        .unwrap()
        .private_key
        .contains("BEGIN PRIVATE KEY"));

    let (status, _, body) = admin_upsert_provider(
        "google",
        r#"{"client_id":"google-client","client_secret":"google-secret","redirect_uri":"https://app.example/auth/callback","enabled":true}"#,
        &store,
        &cache,
    );
    assert_eq!(status, 200, "{body}");
    assert!(!body.contains("google-secret"), "{body}");
    let google = find_row_by_field(&store, &cache, PROVIDERS_TABLE, "provider", "google", now)
        .unwrap()
        .unwrap();
    let stored_google_secret = google.get("client_secret").unwrap().clone();
    assert_auth_secret_is_sealed(&stored_google_secret, "google-secret");
    assert!(store
        .keys(b"_t:auth.providers:idx:client_secret:*", now)
        .is_empty());
    assert_eq!(
        oauth_provider_config(&store, &cache, "google", now)
            .unwrap()
            .unwrap()
            .client_secret,
        "google-secret"
    );
    let (status, _, body) = admin_upsert_provider(
        "google",
        r#"{"client_id":"google-client","redirect_uri":"https://app.example/auth/callback","enabled":true,"scopes":["openid","email"]}"#,
        &store,
        &cache,
    );
    assert_eq!(status, 200, "{body}");
    let google = find_row_by_field(&store, &cache, PROVIDERS_TABLE, "provider", "google", now)
        .unwrap()
        .unwrap();
    assert_eq!(
        google.get("client_secret"),
        Some(&stored_google_secret),
        "omitting a provider secret must preserve its existing envelope"
    );
    assert_eq!(
        oauth_provider_config(&store, &cache, "google", now)
            .unwrap()
            .unwrap()
            .client_secret,
        "google-secret"
    );

    let (status, _, body) = admin_update_settings(
        r#"{"email_provider":"postmark","email_from":"auth@app.example","email_postmark_server_token":"postmark-secret"}"#,
        &store,
        &cache,
    );
    assert_eq!(status, 200, "{body}");
    assert!(!body.contains("postmark-secret"), "{body}");
    let email = find_row_by_field(
        &store,
        &cache,
        SETTINGS_TABLE,
        "key",
        secrets::EMAIL_POSTMARK_TOKEN_KEY,
        now,
    )
    .unwrap()
    .unwrap();
    let stored_email_secret = email.get("value").unwrap().clone();
    assert_auth_secret_is_sealed(&stored_email_secret, "postmark-secret");
    assert!(store.keys(b"_t:auth.settings:idx:value:*", now).is_empty());
    assert_eq!(
        auth_settings(&store, &cache, now)
            .unwrap()
            .email_postmark_server_token
            .as_deref(),
        Some("postmark-secret")
    );
    let (status, _, body) =
        admin_update_settings(r#"{"email_from":"new-auth@app.example"}"#, &store, &cache);
    assert_eq!(status, 200, "{body}");
    let email = find_row_by_field(
        &store,
        &cache,
        SETTINGS_TABLE,
        "key",
        secrets::EMAIL_POSTMARK_TOKEN_KEY,
        now,
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        email.get("value"),
        Some(&stored_email_secret),
        "omitting an email token must preserve its existing envelope"
    );
    assert_eq!(
        auth_settings(&store, &cache, now)
            .unwrap()
            .email_postmark_server_token
            .as_deref(),
        Some("postmark-secret")
    );

    assert!(secrets::open(
        &store,
        PROVIDERS_TABLE,
        "client_secret",
        "github",
        &stored_google_secret,
    )
    .is_err());
}

#[test]
fn plaintext_auth_secret_migration_is_complete_and_idempotent() {
    let store = encrypted_test_store();
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    bootstrap(&store, &cache, &store.config().auth).unwrap();
    let now = Instant::now();

    durable_table_insert(
        &store,
        &cache,
        SIGNING_KEYS_TABLE,
        &[
            ("id", "legacy-signing"),
            ("kid", "legacy-kid"),
            ("algorithm", "ES256"),
            ("private_key_encrypted", "legacy-signing-secret"),
            ("active", "true"),
        ],
        now,
    )
    .unwrap();
    durable_table_insert(
        &store,
        &cache,
        PROVIDERS_TABLE,
        &[
            ("provider", "github"),
            ("enabled", "true"),
            ("client_secret", "legacy-oauth-secret"),
        ],
        now,
    )
    .unwrap();
    durable_table_insert(
        &store,
        &cache,
        SETTINGS_TABLE,
        &[
            ("key", secrets::EMAIL_POSTMARK_TOKEN_KEY),
            ("value", "legacy-email-secret"),
        ],
        now,
    )
    .unwrap();

    secrets::migrate_storage(&store, &cache, now).unwrap();
    secrets::migrate_storage(&store, &cache, now).unwrap();

    let signing = find_row_by_field(
        &store,
        &cache,
        SIGNING_KEYS_TABLE,
        "id",
        "legacy-signing",
        now,
    )
    .unwrap()
    .unwrap();
    assert_auth_secret_is_sealed(
        signing.get("private_key_encrypted").unwrap(),
        "legacy-signing-secret",
    );
    let provider = find_row_by_field(&store, &cache, PROVIDERS_TABLE, "provider", "github", now)
        .unwrap()
        .unwrap();
    assert_auth_secret_is_sealed(
        provider.get("client_secret").unwrap(),
        "legacy-oauth-secret",
    );
    let email = find_row_by_field(
        &store,
        &cache,
        SETTINGS_TABLE,
        "key",
        secrets::EMAIL_POSTMARK_TOKEN_KEY,
        now,
    )
    .unwrap()
    .unwrap();
    assert_auth_secret_is_sealed(email.get("value").unwrap(), "legacy-email-secret");
}

#[test]
fn persistent_auth_refuses_to_create_signing_material_without_encryption() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new_with_config(Arc::new(ServerConfig {
        data_dir: dir.path().to_string_lossy().to_string(),
        durability: DurabilityConfig {
            policy: DurabilityPolicy::EverySecond,
            ..DurabilityConfig::default()
        },
        auth: AuthConfig {
            enabled: true,
            ..AuthConfig::default()
        },
        ..ServerConfig::default()
    }));
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    bootstrap(&store, &cache, &store.config().auth).unwrap();
    let error = bootstrap_runtime(&store, &cache, &store.config().auth).unwrap_err();
    assert!(error.contains("persistent auth secrets require"), "{error}");
    assert!(
        active_signing_key(&store, &cache, Instant::now())
            .unwrap()
            .is_none(),
        "a failed seal must not persist plaintext signing material"
    );
}

#[test]
fn corrupt_auth_secret_envelope_is_not_rewrapped_as_plaintext() {
    let store = encrypted_test_store();
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    bootstrap(&store, &cache, &store.config().auth).unwrap();
    let now = Instant::now();
    durable_table_insert(
        &store,
        &cache,
        PROVIDERS_TABLE,
        &[
            ("provider", "google"),
            ("enabled", "true"),
            ("client_secret", "luxsealed:not-valid-base64"),
        ],
        now,
    )
    .unwrap();

    let error = secrets::migrate_storage(&store, &cache, now).unwrap_err();
    assert!(error.contains("sealed value"), "{error}");
    let row = find_row_by_field(&store, &cache, PROVIDERS_TABLE, "provider", "google", now)
        .unwrap()
        .unwrap();
    assert_eq!(
        row.get("client_secret").map(String::as_str),
        Some("luxsealed:not-valid-base64")
    );
}

fn persisted_files_contain(path: &std::path::Path, needle: &[u8]) -> bool {
    let Ok(entries) = std::fs::read_dir(path) else {
        return false;
    };
    entries.flatten().any(|entry| {
        let path = entry.path();
        if path.is_dir() {
            persisted_files_contain(&path, needle)
        } else {
            std::fs::read(path)
                .ok()
                .is_some_and(|bytes| bytes.windows(needle.len()).any(|window| window == needle))
        }
    })
}

#[test]
fn new_auth_secrets_never_reach_persistent_files_as_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new_with_config(Arc::new(ServerConfig {
        data_dir: dir.path().to_string_lossy().to_string(),
        durability: DurabilityConfig {
            policy: DurabilityPolicy::EverySecond,
            ..DurabilityConfig::default()
        },
        auth: AuthConfig {
            enabled: true,
            ..AuthConfig::default()
        },
        encryption: crate::EncryptionConfig {
            active_key_id: Some("auth-persist".to_string()),
            keys: vec![crate::EncryptionKeyConfig {
                id: "auth-persist".to_string(),
                secret: b"auth-persistence-encryption-key".to_vec(),
                decrypt_only: false,
            }],
            ..Default::default()
        },
        ..ServerConfig::default()
    }));
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    bootstrap(&store, &cache, &store.config().auth).unwrap();
    bootstrap_runtime(&store, &cache, &store.config().auth).unwrap();
    let (status, _, body) = admin_upsert_provider(
        "github",
        r#"{"client_id":"github-client","client_secret":"persisted-oauth-secret","redirect_uri":"https://app.example/auth/callback"}"#,
        &store,
        &cache,
    );
    assert_eq!(status, 200, "{body}");
    let (status, _, body) = admin_update_settings(
        r#"{"email_provider":"postmark","email_from":"auth@app.example","email_postmark_server_token":"persisted-email-secret"}"#,
        &store,
        &cache,
    );
    assert_eq!(status, 200, "{body}");
    store.fsync_wal();
    crate::snapshot::save_and_truncate_wal_consistent(&store).unwrap();

    for secret in [
        b"persisted-oauth-secret".as_slice(),
        b"persisted-email-secret".as_slice(),
        b"BEGIN PRIVATE KEY".as_slice(),
    ] {
        assert!(
            !persisted_files_contain(dir.path(), secret),
            "plaintext auth secret reached persistent storage"
        );
    }
}

#[test]
fn plaintext_auth_secret_migration_survives_repeated_wal_replay() {
    let dir = tempfile::tempdir().unwrap();
    let config = Arc::new(ServerConfig {
        data_dir: dir.path().to_string_lossy().to_string(),
        durability: DurabilityConfig {
            policy: DurabilityPolicy::EverySecond,
            ..DurabilityConfig::default()
        },
        auth: AuthConfig {
            enabled: true,
            ..AuthConfig::default()
        },
        encryption: crate::EncryptionConfig {
            active_key_id: Some("auth-migration".to_string()),
            keys: vec![crate::EncryptionKeyConfig {
                id: "auth-migration".to_string(),
                secret: b"auth-migration-encryption-key".to_vec(),
                decrypt_only: false,
            }],
            ..Default::default()
        },
        ..ServerConfig::default()
    });
    let legacy_signing = generate_es256_signing_key().unwrap();

    {
        let store = Store::new_with_config(config.clone());
        let cache = Arc::new(RwLock::new(SchemaCache::new()));
        bootstrap(&store, &cache, &store.config().auth).unwrap();
        let now = Instant::now();
        durable_table_insert(
            &store,
            &cache,
            SIGNING_KEYS_TABLE,
            &[
                ("id", "legacy-signing"),
                ("kid", legacy_signing.kid.as_str()),
                ("algorithm", legacy_signing.algorithm.as_str()),
                ("public_jwk", legacy_signing.public_jwk.as_str()),
                ("private_key_encrypted", legacy_signing.private_key.as_str()),
                ("active", "true"),
            ],
            now,
        )
        .unwrap();
        durable_table_insert(
            &store,
            &cache,
            PROVIDERS_TABLE,
            &[
                ("provider", "google"),
                ("enabled", "true"),
                ("client_secret", "legacy-replay-oauth-secret"),
            ],
            now,
        )
        .unwrap();
        store.fsync_wal();
    }

    {
        let store = Store::new_with_config(config.clone());
        let cache = Arc::new(RwLock::new(SchemaCache::new()));
        bootstrap(&store, &cache, &store.config().auth).unwrap();
        store.replay_wal(&crate::pubsub::Broker::new()).unwrap();
        let migration = bootstrap_runtime(&store, &cache, &store.config().auth).unwrap();
        assert!(migration.secret_history_checkpoint_required);
        store.fsync_wal();
    }

    let store = Store::new_with_config(config);
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    bootstrap(&store, &cache, &store.config().auth).unwrap();
    store.replay_wal(&crate::pubsub::Broker::new()).unwrap();
    let migration = bootstrap_runtime(&store, &cache, &store.config().auth).unwrap();
    assert!(
        migration.secret_history_checkpoint_required,
        "a crash after row migration must preserve the pending checkpoint requirement"
    );
    let now = Instant::now();
    let signing = find_row_by_field(
        &store,
        &cache,
        SIGNING_KEYS_TABLE,
        "id",
        "legacy-signing",
        now,
    )
    .unwrap()
    .unwrap();
    assert_auth_secret_is_sealed(
        signing.get("private_key_encrypted").unwrap(),
        "BEGIN PRIVATE KEY",
    );
    assert_eq!(
        active_signing_key(&store, &cache, now)
            .unwrap()
            .unwrap()
            .private_key,
        legacy_signing.private_key
    );
    let provider = find_row_by_field(&store, &cache, PROVIDERS_TABLE, "provider", "google", now)
        .unwrap()
        .unwrap();
    assert_auth_secret_is_sealed(
        provider.get("client_secret").unwrap(),
        "legacy-replay-oauth-secret",
    );
    assert_eq!(
        oauth_provider_config(&store, &cache, "google", now)
            .unwrap()
            .unwrap()
            .client_secret,
        "legacy-replay-oauth-secret"
    );
}

#[tokio::test]
async fn runtime_migration_removes_plaintext_history_before_readiness() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let config = ServerConfig {
        data_dir: root.to_string_lossy().to_string(),
        enable_resp: false,
        durability: DurabilityConfig {
            policy: DurabilityPolicy::AlwaysSync,
            ..DurabilityConfig::default()
        },
        auth: AuthConfig {
            enabled: true,
            ..AuthConfig::default()
        },
        encryption: crate::EncryptionConfig {
            active_key_id: Some("auth-upgrade".to_string()),
            keys: vec![crate::EncryptionKeyConfig {
                id: "auth-upgrade".to_string(),
                secret: b"auth-upgrade-encryption-key".to_vec(),
                decrypt_only: false,
            }],
            ..Default::default()
        },
        ..ServerConfig::default()
    };

    {
        let store = Store::new_with_config(Arc::new(config.clone()));
        let cache = Arc::new(RwLock::new(SchemaCache::new()));
        bootstrap(&store, &cache, &store.config().auth).unwrap();
        durable_table_insert(
            &store,
            &cache,
            PROVIDERS_TABLE,
            &[
                ("provider", "google"),
                ("enabled", "true"),
                ("client_secret", "legacy-live-history-secret"),
            ],
            Instant::now(),
        )
        .unwrap();
        store.fsync_wal();
    }
    assert!(persisted_files_contain(
        &root,
        b"legacy-live-history-secret"
    ));

    let handle = crate::run_with_config(config.clone()).await.unwrap();
    assert!(
        !persisted_files_contain(&root, b"legacy-live-history-secret"),
        "the Engine reached readiness while its live persistence files still contained a migrated plaintext secret"
    );
    assert_eq!(
        oauth_provider_config(
            &handle.runtime.store,
            &handle.runtime.schema_cache,
            "google",
            Instant::now(),
        )
        .unwrap()
        .unwrap()
        .client_secret,
        "legacy-live-history-secret"
    );
    handle.shutdown_and_wait().await.unwrap();

    let restarted = crate::run_with_config(config).await.unwrap();
    assert_eq!(
        oauth_provider_config(
            &restarted.runtime.store,
            &restarted.runtime.schema_cache,
            "google",
            Instant::now(),
        )
        .unwrap()
        .unwrap()
        .client_secret,
        "legacy-live-history-secret"
    );
    assert!(!persisted_files_contain(
        &root,
        b"legacy-live-history-secret"
    ));
    restarted.shutdown_and_wait().await.unwrap();
}

#[test]
fn auth_secrets_survive_rewrap_and_prior_key_retirement() {
    let dir = tempfile::tempdir().unwrap();
    let config = Arc::new(ServerConfig {
        data_dir: dir.path().to_string_lossy().to_string(),
        durability: DurabilityConfig {
            policy: DurabilityPolicy::AlwaysSync,
            ..DurabilityConfig::default()
        },
        auth: AuthConfig {
            enabled: true,
            ..AuthConfig::default()
        },
        encryption: crate::EncryptionConfig {
            active_key_id: Some("auth-k1".to_string()),
            keys: vec![crate::EncryptionKeyConfig {
                id: "auth-k1".to_string(),
                secret: b"auth-rotation-initial-key".to_vec(),
                decrypt_only: false,
            }],
            ..Default::default()
        },
        ..ServerConfig::default()
    });

    {
        let store = Store::new_with_config(config.clone());
        let cache = Arc::new(RwLock::new(SchemaCache::new()));
        bootstrap(&store, &cache, &store.config().auth).unwrap();
        bootstrap_runtime(&store, &cache, &store.config().auth).unwrap();
        let (status, _, body) = admin_upsert_provider(
            "google",
            r#"{"client_id":"rotation-client","client_secret":"rotation-oauth-secret","redirect_uri":"https://app.example/auth/callback","enabled":true}"#,
            &store,
            &cache,
        );
        assert_eq!(status, 200, "{body}");
        let (status, _, body) = admin_update_settings(
            r#"{"email_provider":"postmark","email_from":"auth@app.example","email_postmark_server_token":"rotation-email-secret"}"#,
            &store,
            &cache,
        );
        assert_eq!(status, 200, "{body}");

        store.encryption().rotate(Some("auth-k2")).unwrap();
        assert!(store.enc_rewrap_all().unwrap() >= 3);
        store.enc_retire_key("auth-k1").unwrap();
        assert!(active_signing_key(&store, &cache, Instant::now())
            .unwrap()
            .is_some());
        assert_eq!(
            oauth_provider_config(&store, &cache, "google", Instant::now())
                .unwrap()
                .unwrap()
                .client_secret,
            "rotation-oauth-secret"
        );
    }

    let restored = Store::new_with_config(config);
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    bootstrap(&restored, &cache, &restored.config().auth).unwrap();
    crate::snapshot::load(&restored).unwrap();
    restored.replay_wal(&crate::pubsub::Broker::new()).unwrap();
    bootstrap_runtime(&restored, &cache, &restored.config().auth).unwrap();
    assert!(active_signing_key(&restored, &cache, Instant::now())
        .unwrap()
        .is_some());
    assert_eq!(
        oauth_provider_config(&restored, &cache, "google", Instant::now())
            .unwrap()
            .unwrap()
            .client_secret,
        "rotation-oauth-secret"
    );
    assert_eq!(
        auth_settings(&restored, &cache, Instant::now())
            .unwrap()
            .email_postmark_server_token
            .as_deref(),
        Some("rotation-email-secret")
    );
}

fn selected_rows(result: crate::tables::SelectResult) -> Vec<Vec<(String, String)>> {
    match result {
        crate::tables::SelectResult::Rows(rows) => rows,
        crate::tables::SelectResult::Aggregate(_) => panic!("expected row result"),
    }
}

#[test]
fn read_grant_on_encrypted_searchable_column_filters_through_blind_index() {
    let store = encrypted_test_store();
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    let now = Instant::now();
    crate::tables::table_create(
        &store,
        &cache,
        "messages",
        &[
            "id",
            "STR",
            "PRIMARY",
            "KEY,",
            "owner_email",
            "STR",
            "ENCRYPTED",
            "SEARCHABLE,",
            "body",
            "STR",
        ],
        now,
    )
    .unwrap();
    crate::tables::table_insert(
        &store,
        &cache,
        "messages",
        &[
            ("id", "m1"),
            ("owner_email", "u@x.dev"),
            ("body", "allowed"),
        ],
        now,
    )
    .unwrap();
    crate::tables::table_insert(
        &store,
        &cache,
        "messages",
        &[
            ("id", "m2"),
            ("owner_email", "other@x.dev"),
            ("body", "blocked"),
        ],
        now,
    )
    .unwrap();
    grant(
        &store,
        &cache,
        &[
            "read",
            "ON",
            "messages",
            "WHERE",
            "owner_email",
            "=",
            "auth.email",
        ],
        now,
    );

    let p = principal("u1");
    let filter = read_filter(&store, &cache, &p, "messages", now).unwrap();
    assert_eq!(filter, "owner_email = 'u@x.dev'");
    let mut tokens = vec!["*", "FROM", "messages", "WHERE"];
    let filter_tokens = crate::tables::tokenize_where(&filter).unwrap();
    tokens.extend(filter_tokens.iter().map(String::as_str));
    let plan = crate::tables::parse_select(&tokens).unwrap();
    let rows = selected_rows(crate::tables::table_select(&store, &cache, &plan, now).unwrap());
    assert_eq!(rows.len(), 1);
    assert!(rows[0].iter().any(|(k, v)| k == "body" && v == "allowed"));
    assert!(rows[0]
        .iter()
        .any(|(k, v)| k == "owner_email" && v == "u@x.dev"));
}

#[test]
fn grant_on_encrypted_non_searchable_column_is_rejected() {
    let store = encrypted_test_store();
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    let now = Instant::now();
    crate::tables::table_create(
        &store,
        &cache,
        "messages",
        &[
            "id",
            "UUID",
            "PRIMARY",
            "KEY,",
            "secret",
            "STR",
            "ENCRYPTED",
        ],
        now,
    )
    .unwrap();
    let grant = crate::grants::parse_grant(&[
        "read",
        "ON",
        "messages",
        "WHERE",
        "secret",
        "=",
        "auth.email",
    ])
    .unwrap();

    let err = put_grant(&store, &cache, &grant, now).unwrap_err();
    assert!(err.contains("must be SEARCHABLE"), "{err}");
}

#[test]
fn read_and_write_grants_are_independent_scopes() {
    // A read grant does not imply a write filter and vice versa: each scope
    // is loaded separately, so a read-only table denies write_filter.
    let store = Store::new();
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    let now = Instant::now();
    grant(
        &store,
        &cache,
        &["read", "ON", "feed", "WHERE", "user_id", "=", "auth.uid()"],
        now,
    );
    let p = principal("u1");
    assert_eq!(
        read_filter(&store, &cache, &p, "feed", now).unwrap(),
        "user_id = 'u1'"
    );
    // No write grant -> writes denied even though reads are allowed.
    assert!(write_filter(&store, &cache, &p, "feed", now).is_err());
    assert!(check_write_row(&store, &cache, &p, "feed", |_| None, now).is_err());
}

#[test]
fn comparison_operators_round_trip_into_filter() {
    // Non-equality operators (>, >=, etc.) survive into the rendered filter
    // so range grants (e.g. "created_at > X") scope correctly.
    let store = Store::new();
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    let now = Instant::now();
    grant(
        &store,
        &cache,
        &["read", "ON", "events", "WHERE", "priority", ">=", "5"],
        now,
    );
    let p = principal("u1");
    assert_eq!(
        read_filter(&store, &cache, &p, "events", now).unwrap(),
        "priority >= '5'"
    );
}

#[test]
fn literal_grant_values_round_trip_as_data() {
    let store = Store::new();
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    let now = Instant::now();
    grant(
        &store,
        &cache,
        &[
            "read",
            "ON",
            "events",
            "WHERE",
            "label",
            "=",
            "attacker's OR id != victim",
        ],
        now,
    );
    assert_eq!(
        read_filter(&store, &cache, &principal("u1"), "events", now).unwrap(),
        "label = 'attacker\\'s OR id != victim'"
    );
}

#[test]
fn bootstrap_creates_auth_tables_idempotently() {
    let store = Store::new();
    let cache = Arc::new(RwLock::new(SchemaCache::new()));

    bootstrap(&store, &cache, &AuthConfig::default()).unwrap();
    bootstrap(&store, &cache, &AuthConfig::default()).unwrap();

    let now = Instant::now();
    assert!(tables::table_schema(&store, &cache, USERS_TABLE, now).is_ok());
    assert!(tables::table_schema(&store, &cache, SESSIONS_TABLE, now).is_ok());
    assert_eq!(
        store.get(AUTH_SCHEMA_VERSION_KEY, now).unwrap(),
        AUTH_SCHEMA_VERSION
    );
}

#[test]
fn oauth_state_crosses_the_journal_boundary_on_create_and_consume() {
    let dir = tempfile::tempdir().unwrap();
    let config = Arc::new(ServerConfig {
        data_dir: dir.path().to_string_lossy().to_string(),
        durability: DurabilityConfig {
            policy: DurabilityPolicy::AlwaysSync,
            ..DurabilityConfig::default()
        },
        ..ServerConfig::default()
    });
    let key = b"_auth:oauth_state:test";
    let payload = br#"{"provider":"google"}"#;
    let store = Store::new_with_config(config.clone());

    store.inject_journal_failures(1);
    let error = persist_oauth_state(&store, key, payload).unwrap_err();
    assert!(error.contains("WAL append failed"), "{error}");
    assert!(store.get(key, Instant::now()).is_none());

    persist_oauth_state(&store, key, payload).unwrap();
    store.inject_journal_failures(1);
    let error = take_oauth_state(&store, key, Instant::now()).unwrap_err();
    assert!(error.contains("WAL append failed"), "{error}");
    assert_eq!(store.get(key, Instant::now()).unwrap(), payload.as_slice());

    assert_eq!(
        take_oauth_state(&store, key, Instant::now()).unwrap(),
        Some(bytes::Bytes::from_static(payload))
    );
    assert!(take_oauth_state(&store, key, Instant::now())
        .unwrap()
        .is_none());
    drop(store);

    let restored = Store::new_with_config(config);
    restored.replay_wal(&crate::pubsub::Broker::new()).unwrap();
    assert!(restored.get(key, Instant::now()).is_none());
}

#[test]
fn corrupt_cold_access_revocation_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_string_lossy().to_string();
    let config = Arc::new(ServerConfig {
        data_dir: path.clone(),
        storage: crate::StorageConfig {
            mode: crate::StorageMode::Tiered,
            dir: path,
        },
        durability: DurabilityConfig {
            policy: DurabilityPolicy::AlwaysSync,
            ..DurabilityConfig::default()
        },
        ..ServerConfig::default()
    });
    let store = Store::new_with_config(config);
    let now = Instant::now();
    let session_id = "session-with-revocation";
    persist_access_revocation(&store, session_id, "123", now).unwrap();
    let key = access_revoked_after_key(session_id);
    assert!(store.evict_key(store.shard_for_key(&key), &key));

    let cold_path = std::fs::read_dir(&store.config().storage.dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path().join("data.lux"))
        .find(|path| std::fs::metadata(path).is_ok_and(|metadata| metadata.len() > 8))
        .expect("the evicted revocation marker must have a cold data file");
    let mut cold_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(cold_path)
        .unwrap();
    cold_file.seek(SeekFrom::Start(8)).unwrap();
    let mut byte = [0u8; 1];
    cold_file.read_exact(&mut byte).unwrap();
    cold_file.seek(SeekFrom::Start(8)).unwrap();
    cold_file.write_all(&[byte[0] ^ 0xff]).unwrap();
    cold_file.sync_all().unwrap();

    let error = access_revoked_after(&store, session_id, now).unwrap_err();
    assert!(error.contains("cold storage read failed"), "{error}");
    assert!(!store.wal_enabled());
}

#[test]
fn auth_tables_are_reserved() {
    assert!(is_reserved_auth_table("auth.users"));
    assert!(!is_reserved_auth_table("users"));
}

#[test]
fn auth_config_debug_redacts_initial_keys() {
    let config = AuthConfig {
        enabled: true,
        initial_publishable_key: Some("lux_pub_secret".to_string()),
        initial_secret_key: Some("lux_sec_secret".to_string()),
        managed_email: Some(crate::AuthManagedEmailConfig {
            provider: "postmark".to_string(),
            from: "auth@app.test".to_string(),
            reply_to: None,
            postmark_server_token: Some("pm_secret".to_string()),
            postmark_message_stream: None,
        }),
        ..AuthConfig::default()
    };
    let debug = format!("{config:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("lux_pub_secret"));
    assert!(!debug.contains("lux_sec_secret"));
    assert!(!debug.contains("pm_secret"));
}

#[test]
fn password_hashes_verify_without_storing_plaintext() {
    let hash = hash_password("correct horse battery staple").unwrap();
    assert_ne!(hash, "correct horse battery staple");
    assert!(verify_password("correct horse battery staple", &hash).unwrap());
    assert!(!verify_password("wrong password", &hash).unwrap());
}

#[test]
fn bcrypt_password_hashes_verify_and_request_rehash() {
    let hash = bcrypt::hash("correct horse battery staple", 4).unwrap();
    assert_eq!(
        verify_password_state("correct horse battery staple", &hash).unwrap(),
        PasswordVerification::ValidNeedsRehash
    );
    assert_eq!(
        verify_password_state("wrong password", &hash).unwrap(),
        PasswordVerification::Invalid
    );
}

#[test]
fn reserved_table_mutations_are_blocked_for_client_commands() {
    let store = Store::new();
    let err = reserved_table_mutation_error(&[b"TINSERT", b"auth.users"], &store).unwrap();
    assert!(err.contains("managed by Lux Auth"));

    store
        .wal_suppress
        .store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(reserved_table_mutation_error(&[b"TINSERT", b"auth.users"], &store).is_none());
}

#[test]
fn reserved_auth_tables_are_readable_through_direct_table_commands() {
    let store = Store::new();
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    bootstrap(&store, &cache, &AuthConfig::default()).unwrap();

    let broker = crate::pubsub::Broker::new();
    // Direct operator command surfaces (CLI/cloud command prompt/RESP) can
    // inspect auth internals. Public REST/table/live paths still carry their
    // own reserved-table guards, and mutations remain blocked.
    for cmd in [
        &[b"TSCHEMA".as_ref(), b"auth.users".as_ref()][..],
        &[
            b"TSELECT".as_ref(),
            b"*".as_ref(),
            b"FROM".as_ref(),
            b"auth.users".as_ref(),
        ][..],
    ] {
        let mut out = bytes::BytesMut::new();
        crate::cmd::execute(&store, &cache, &broker, cmd, &mut out, Instant::now());
        let response = std::str::from_utf8(&out).unwrap();
        assert!(
            !response.starts_with("-ERR"),
            "direct auth table read should be allowed: {response}"
        );
    }
}

#[test]
fn direct_auth_table_reads_redact_sensitive_values() {
    let config = Arc::new(crate::ServerConfig {
        auth: AuthConfig {
            enabled: true,
            ..AuthConfig::default()
        },
        ..crate::ServerConfig::default()
    });
    let store = Store::new_with_config(config);
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    bootstrap(&store, &cache, &store.config().auth).unwrap();
    bootstrap_runtime(&store, &cache, &store.config().auth).unwrap();
    set_auth_setting(
        &store,
        &cache,
        "email_postmark_server_token",
        "server-token",
        Instant::now(),
    )
    .unwrap();
    let (status, _, body) = route_http(
        "POST",
        "/auth/v1/signup",
        r#"{"email":"redact@example.com","password":"password123"}"#,
        &[],
        &[],
        &store,
        &cache,
    );
    assert_eq!(status, 200, "signup: {body}");
    let signup_json: Value = serde_json::from_str(&body).unwrap();
    let user_id = signup_json["user"]["id"].as_str().unwrap();
    tables::table_create(
        &store,
        &cache,
        "redaction_posts",
        &["id STR PRIMARY KEY,", "user_id UUID"],
        Instant::now(),
    )
    .unwrap();
    durable_table_insert(
        &store,
        &cache,
        "redaction_posts",
        &[("id", "post_1"), ("user_id", user_id)],
        Instant::now(),
    )
    .unwrap();

    let broker = crate::pubsub::Broker::new();
    let mut users = bytes::BytesMut::new();
    crate::cmd::execute(
        &store,
        &cache,
        &broker,
        &[
            b"TSELECT",
            b"*",
            b"FROM",
            b"auth.users",
            b"WHERE",
            b"email",
            b"=",
            b"redact@example.com",
        ],
        &mut users,
        Instant::now(),
    );
    let users = std::str::from_utf8(&users).unwrap();
    assert!(
        users.contains("<redacted>"),
        "password hash should be redacted: {users}"
    );
    assert!(!users.contains("$argon2"), "password hash leaked: {users}");

    let mut joined_users = bytes::BytesMut::new();
    crate::cmd::execute(
        &store,
        &cache,
        &broker,
        &[
            b"TSELECT",
            b"*",
            b"FROM",
            b"redaction_posts",
            b"p",
            b"JOIN",
            b"auth.users",
            b"u",
            b"ON",
            b"p.user_id",
            b"=",
            b"u.id",
        ],
        &mut joined_users,
        Instant::now(),
    );
    let joined_users = std::str::from_utf8(&joined_users).unwrap();
    assert!(
        joined_users.contains("<redacted>"),
        "joined password hash should be redacted: {joined_users}"
    );
    assert!(
        !joined_users.contains("$argon2"),
        "joined password hash leaked: {joined_users}"
    );
    let mut aliased_join = bytes::BytesMut::new();
    crate::cmd::execute(
        &store,
        &cache,
        &broker,
        &[
            b"TSELECT",
            b"u.encrypted_password",
            b"AS",
            b"leaked",
            b"FROM",
            b"redaction_posts",
            b"p",
            b"JOIN",
            b"auth.users",
            b"u",
            b"ON",
            b"p.user_id",
            b"=",
            b"u.id",
        ],
        &mut aliased_join,
        Instant::now(),
    );
    let aliased_join = std::str::from_utf8(&aliased_join).unwrap();
    assert!(aliased_join.contains("<redacted>"), "{aliased_join}");
    assert!(!aliased_join.contains("$argon2"), "{aliased_join}");

    let mut unqualified_join = bytes::BytesMut::new();
    crate::cmd::execute(
        &store,
        &cache,
        &broker,
        &[
            b"TSELECT",
            b"encrypted_password",
            b"AS",
            b"leaked",
            b"FROM",
            b"redaction_posts",
            b"p",
            b"JOIN",
            b"auth.users",
            b"u",
            b"ON",
            b"p.user_id",
            b"=",
            b"u.id",
        ],
        &mut unqualified_join,
        Instant::now(),
    );
    let unqualified_join = std::str::from_utf8(&unqualified_join).unwrap();
    assert!(
        unqualified_join.contains("<redacted>"),
        "{unqualified_join}"
    );
    assert!(!unqualified_join.contains("$argon2"), "{unqualified_join}");

    let session = find_row_by_field(
        &store,
        &cache,
        SESSIONS_TABLE,
        "user_id",
        user_id,
        Instant::now(),
    )
    .unwrap()
    .unwrap();
    durable_table_update_where(
        &store,
        &cache,
        SESSIONS_TABLE,
        &[("legacy_refresh_token_hash", "legacy-refresh-hash")],
        &["id", "=", &session["id"]],
        Instant::now(),
    )
    .unwrap();
    let mut sessions = bytes::BytesMut::new();
    crate::cmd::execute(
        &store,
        &cache,
        &broker,
        &[b"TSELECT", b"*", b"FROM", b"auth.sessions"],
        &mut sessions,
        Instant::now(),
    );
    let sessions = std::str::from_utf8(&sessions).unwrap();
    assert!(sessions.matches("<redacted>").count() >= 2, "{sessions}");
    assert!(!sessions.contains("legacy-refresh-hash"), "{sessions}");

    let mut signing_keys = bytes::BytesMut::new();
    crate::cmd::execute(
        &store,
        &cache,
        &broker,
        &[b"TSELECT", b"*", b"FROM", b"auth.signing_keys"],
        &mut signing_keys,
        Instant::now(),
    );
    let signing_keys = std::str::from_utf8(&signing_keys).unwrap();
    assert!(
        signing_keys.contains("<redacted>"),
        "private signing key should be redacted: {signing_keys}"
    );
    assert!(
        !signing_keys.contains("BEGIN PRIVATE KEY"),
        "private signing key leaked: {signing_keys}"
    );

    let mut settings = bytes::BytesMut::new();
    crate::cmd::execute(
        &store,
        &cache,
        &broker,
        &[
            b"TSELECT",
            b"*",
            b"FROM",
            b"auth.settings",
            b"WHERE",
            b"key",
            b"=",
            b"email_postmark_server_token",
        ],
        &mut settings,
        Instant::now(),
    );
    let settings = std::str::from_utf8(&settings).unwrap();
    assert!(
        settings.contains("<redacted>"),
        "postmark token should be redacted: {settings}"
    );
    assert!(
        !settings.contains("server-token"),
        "postmark token leaked: {settings}"
    );
    for command in [
        &[
            b"TSELECT".as_ref(),
            b"value".as_ref(),
            b"AS".as_ref(),
            b"leaked".as_ref(),
            b"FROM".as_ref(),
            b"auth.settings".as_ref(),
            b"WHERE".as_ref(),
            b"key".as_ref(),
            b"=".as_ref(),
            b"email_postmark_server_token".as_ref(),
        ][..],
        &[
            b"TSELECT".as_ref(),
            b"MAX(value)".as_ref(),
            b"AS".as_ref(),
            b"leaked".as_ref(),
            b"FROM".as_ref(),
            b"auth.settings".as_ref(),
            b"WHERE".as_ref(),
            b"key".as_ref(),
            b"=".as_ref(),
            b"email_postmark_server_token".as_ref(),
        ][..],
    ] {
        let mut aliased = bytes::BytesMut::new();
        crate::cmd::execute(
            &store,
            &cache,
            &broker,
            command,
            &mut aliased,
            Instant::now(),
        );
        let aliased = std::str::from_utf8(&aliased).unwrap();
        assert!(aliased.contains("<redacted>"), "aliased setting: {aliased}");
        assert!(
            !aliased.contains("server-token"),
            "aliased postmark token leaked: {aliased}"
        );
    }
}

#[test]
fn direct_push_credential_reads_redact_legacy_and_encrypted_secrets() {
    let store = Store::new();
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    tables::table_create(
        &store,
        &cache,
        "push.credentials",
        &[
            "app_id STR PRIMARY KEY,",
            "apns_p8_pem STR,",
            "apns_p8_pem_encrypted STR,",
            "vapid_private STR,",
            "vapid_private_encrypted STR",
        ],
        Instant::now(),
    )
    .unwrap();
    durable_table_insert(
        &store,
        &cache,
        "push.credentials",
        &[
            ("app_id", "redaction-test"),
            ("apns_p8_pem", "legacy-apns-sentinel"),
            ("apns_p8_pem_encrypted", "encrypted-apns-sentinel"),
            ("vapid_private", "legacy-vapid-sentinel"),
            ("vapid_private_encrypted", "encrypted-vapid-sentinel"),
        ],
        Instant::now(),
    )
    .unwrap();

    let broker = crate::pubsub::Broker::new();
    let mut out = bytes::BytesMut::new();
    crate::cmd::execute(
        &store,
        &cache,
        &broker,
        &[b"TSELECT", b"*", b"FROM", b"push.credentials"],
        &mut out,
        Instant::now(),
    );
    let response = std::str::from_utf8(&out).unwrap();
    assert!(response.contains("<redacted>"), "{response}");
    for secret in [
        "legacy-apns-sentinel",
        "encrypted-apns-sentinel",
        "legacy-vapid-sentinel",
        "encrypted-vapid-sentinel",
    ] {
        assert!(!response.contains(secret), "push secret leaked: {response}");
    }

    for command in [
        &[
            b"TSELECT".as_ref(),
            b"apns_p8_pem_encrypted".as_ref(),
            b"AS".as_ref(),
            b"leaked".as_ref(),
            b"FROM".as_ref(),
            b"push.credentials".as_ref(),
        ][..],
        &[
            b"TSELECT".as_ref(),
            b"MAX(apns_p8_pem_encrypted)".as_ref(),
            b"AS".as_ref(),
            b"leaked".as_ref(),
            b"FROM".as_ref(),
            b"push.credentials".as_ref(),
        ][..],
    ] {
        let mut aliased = bytes::BytesMut::new();
        crate::cmd::execute(
            &store,
            &cache,
            &broker,
            command,
            &mut aliased,
            Instant::now(),
        );
        let aliased = std::str::from_utf8(&aliased).unwrap();
        assert!(aliased.contains("<redacted>"), "aliased secret: {aliased}");
        assert!(
            !aliased.contains("encrypted-apns-sentinel"),
            "aliased push provider secret leaked: {aliased}"
        );
    }
}

#[test]
fn signup_and_password_grant_issue_tokens() {
    let config = Arc::new(crate::ServerConfig {
        auth: AuthConfig {
            enabled: true,
            ..AuthConfig::default()
        },
        ..crate::ServerConfig::default()
    });
    let store = Store::new_with_config(config);
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    bootstrap(&store, &cache, &store.config().auth).unwrap();
    bootstrap_runtime(&store, &cache, &store.config().auth).unwrap();

    let (_, _, signup_body) = route_http(
        "POST",
        "/auth/v1/signup",
        r#"{"email":"Test@Example.com","password":"password123"}"#,
        &[],
        &[],
        &store,
        &cache,
    );
    let signup_json: Value = serde_json::from_str(&signup_body).unwrap();
    assert!(signup_json.get("access_token").is_some(), "{signup_body}");
    assert_eq!(signup_json["user"]["email"], "test@example.com");

    let (_, _, token_body) = route_http(
        "POST",
        "/auth/v1/token",
        r#"{"grant_type":"password","email":"test@example.com","password":"password123"}"#,
        &[],
        &[],
        &store,
        &cache,
    );
    let token_json: Value = serde_json::from_str(&token_body).unwrap();
    assert!(token_json.get("access_token").is_some(), "{token_body}");
    assert!(token_json.get("refresh_token").is_some(), "{token_body}");
}

fn refresh_rotation_test_store() -> (Arc<Store>, SharedSchemaCache) {
    let config = Arc::new(crate::ServerConfig {
        auth: AuthConfig {
            enabled: true,
            ..AuthConfig::default()
        },
        ..crate::ServerConfig::default()
    });
    let store = Arc::new(Store::new_with_config(config));
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    bootstrap(&store, &cache, &store.config().auth).unwrap();
    bootstrap_runtime(&store, &cache, &store.config().auth).unwrap();
    (store, cache)
}

fn signup_refresh_token(store: &Store, cache: &SharedSchemaCache, email: &str) -> Value {
    let (status, _, body) = route_http(
        "POST",
        "/auth/v1/signup",
        &json!({"email":email,"password":"password123"}).to_string(),
        &[],
        &[],
        store,
        cache,
    );
    assert_eq!(status, 200, "signup failed: {body}");
    serde_json::from_str(&body).unwrap()
}

fn rotate_refresh_token(
    store: &Store,
    cache: &SharedSchemaCache,
    refresh_token: &str,
    user_agent: &str,
) -> (u16, Value) {
    let (status, _, body) = route_http(
        "POST",
        "/auth/v1/token",
        &json!({"grant_type":"refresh_token","refresh_token":refresh_token}).to_string(),
        &[],
        &[("user-agent".to_string(), user_agent.to_string())],
        store,
        cache,
    );
    let parsed = serde_json::from_str(&body).unwrap_or_else(|_| json!({"body": body}));
    (status, parsed)
}

#[test]
fn refresh_rotation_updates_one_session_and_reuse_revokes_access() {
    let (store, cache) = refresh_rotation_test_store();
    let signup = signup_refresh_token(&store, &cache, "rotate@example.com");
    let first_refresh = signup["refresh_token"].as_str().unwrap();
    assert_eq!(first_refresh.matches('.').count(), 2);
    let first_hash = hash_secret(first_refresh);
    let initial = find_row_by_field(
        &store,
        &cache,
        SESSIONS_TABLE,
        "refresh_token_hash",
        &first_hash,
        Instant::now(),
    )
    .unwrap()
    .unwrap();
    let family = initial["refresh_token_family"].clone();
    assert_eq!(
        initial.get("refresh_generation").map(String::as_str),
        Some("1")
    );

    let (status, rotated) = rotate_refresh_token(&store, &cache, first_refresh, "second-client");
    assert_eq!(status, 200, "{rotated}");
    let next_refresh = rotated["refresh_token"].as_str().unwrap();
    let rotated_access = rotated["access_token"].as_str().unwrap();
    let family_rows = find_rows_by_field(
        &store,
        &cache,
        SESSIONS_TABLE,
        "refresh_token_family",
        &family,
        Instant::now(),
    )
    .unwrap();
    assert_eq!(
        family_rows.len(),
        1,
        "new rotations must not grow a session chain"
    );
    assert_eq!(
        family_rows[0].get("refresh_generation").map(String::as_str),
        Some("2")
    );
    assert_eq!(
        family_rows[0].get("user_agent").map(String::as_str),
        Some("second-client")
    );

    let (status, replay) = rotate_refresh_token(&store, &cache, first_refresh, "replay");
    assert_eq!(status, 401, "{replay}");
    assert!(replay.to_string().contains("reuse detected"), "{replay}");
    assert!(claims_from_access_token(rotated_access, &store, &cache).is_err());
    let (status, body) = rotate_refresh_token(&store, &cache, next_refresh, "winner");
    assert_eq!(status, 401, "{body}");
}

#[test]
fn invalid_structured_refresh_tokens_cannot_revoke_a_session() {
    let (store, cache) = refresh_rotation_test_store();
    let signup = signup_refresh_token(&store, &cache, "forged@example.com");
    let refresh = signup["refresh_token"].as_str().unwrap();
    let access = signup["access_token"].as_str().unwrap();

    let (status, _) = rotate_refresh_token(&store, &cache, access, "wrong-token-type");
    assert_eq!(status, 401);
    let mut forged = refresh.as_bytes().to_vec();
    let last = forged.len() - 1;
    forged[last] = if forged[last] == b'a' { b'b' } else { b'a' };
    let forged = String::from_utf8(forged).unwrap();
    let (status, _) = rotate_refresh_token(&store, &cache, &forged, "attacker");
    assert_eq!(status, 401);

    let (status, body) = rotate_refresh_token(&store, &cache, refresh, "real-client");
    assert_eq!(status, 200, "{body}");
}

#[test]
fn expired_signed_refresh_token_can_still_log_out_its_family() {
    let (store, cache) = refresh_rotation_test_store();
    let signup = signup_refresh_token(&store, &cache, "expired-logout@example.com");
    let issued = signup["refresh_token"].as_str().unwrap();
    let session = find_row_by_field(
        &store,
        &cache,
        SESSIONS_TABLE,
        "refresh_token_hash",
        &hash_secret(issued),
        Instant::now(),
    )
    .unwrap()
    .unwrap();
    let expired = super::refresh::sign(
        &store,
        &cache,
        &session["user_id"],
        &session["id"],
        &session["refresh_token_family"],
        1,
        1,
    )
    .unwrap();
    durable_table_update_where(
        &store,
        &cache,
        SESSIONS_TABLE,
        &[
            ("refresh_token_hash", &hash_secret(&expired)),
            ("expires_at", "1"),
        ],
        &["id", "=", &session["id"]],
        Instant::now(),
    )
    .unwrap();

    let (status, _, body) = route_http(
        "POST",
        "/auth/v1/logout",
        &json!({"refresh_token":expired}).to_string(),
        &[],
        &[],
        &store,
        &cache,
    );
    assert_eq!(status, 200, "{body}");
    assert!(
        claims_from_access_token(signup["access_token"].as_str().unwrap(), &store, &cache).is_err()
    );
}

#[test]
fn legacy_opaque_refresh_token_migrates_once_and_detects_reuse() {
    let (store, cache) = refresh_rotation_test_store();
    let signup = signup_refresh_token(&store, &cache, "legacy@example.com");
    let issued = signup["refresh_token"].as_str().unwrap();
    let issued_hash = hash_secret(issued);
    let session = find_row_by_field(
        &store,
        &cache,
        SESSIONS_TABLE,
        "refresh_token_hash",
        &issued_hash,
        Instant::now(),
    )
    .unwrap()
    .unwrap();
    let session_id = session["id"].clone();
    let legacy = random_token(32);
    let legacy_hash = hash_secret(&legacy);
    durable_table_update_where(
        &store,
        &cache,
        SESSIONS_TABLE,
        &[
            ("refresh_token_hash", &legacy_hash),
            ("refresh_generation", "0"),
            ("revoked_at", "0"),
        ],
        &["id", "=", &session_id],
        Instant::now(),
    )
    .unwrap();

    let (status, rotated) = rotate_refresh_token(&store, &cache, &legacy, "legacy-client");
    assert_eq!(status, 200, "{rotated}");
    let next = rotated["refresh_token"].as_str().unwrap();
    let migrated = find_row_by_field(
        &store,
        &cache,
        SESSIONS_TABLE,
        "id",
        &session_id,
        Instant::now(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        migrated.get("legacy_refresh_token_hash"),
        Some(&legacy_hash)
    );
    assert_eq!(
        migrated.get("refresh_generation").map(String::as_str),
        Some("1")
    );

    let (status, body) = rotate_refresh_token(&store, &cache, &legacy, "legacy-replay");
    assert_eq!(status, 401, "{body}");
    assert!(body.to_string().contains("reuse detected"), "{body}");
    let (status, body) = rotate_refresh_token(&store, &cache, next, "legacy-client");
    assert_eq!(status, 401, "{body}");
}

#[test]
fn consumed_legacy_session_row_revokes_its_active_family_successor() {
    let (store, cache) = refresh_rotation_test_store();
    let signup = signup_refresh_token(&store, &cache, "legacy-chain@example.com");
    let current_refresh = signup["refresh_token"].as_str().unwrap();
    let current_hash = hash_secret(current_refresh);
    let current = find_row_by_field(
        &store,
        &cache,
        SESSIONS_TABLE,
        "refresh_token_hash",
        &current_hash,
        Instant::now(),
    )
    .unwrap()
    .unwrap();
    let old_token = random_token(32);
    let old_hash = hash_secret(&old_token);
    let now = unix_seconds().to_string();
    let expires = unix_seconds().saturating_add(3600).to_string();
    let old_session_id = "legacy-consumed-session";
    durable_table_insert(
        &store,
        &cache,
        SESSIONS_TABLE,
        &[
            ("id", old_session_id),
            ("user_id", &current["user_id"]),
            ("refresh_token_hash", &old_hash),
            ("refresh_token_family", &current["refresh_token_family"]),
            ("expires_at", &expires),
            ("revoked_at", &now),
            ("created_at", &now),
            ("updated_at", &now),
        ],
        Instant::now(),
    )
    .unwrap();
    let old_access = sign_access_token(
        &store,
        &cache,
        &current["user_id"],
        "legacy-chain@example.com",
        old_session_id,
    )
    .unwrap();

    let (status, body) = rotate_refresh_token(&store, &cache, &old_token, "legacy-replay");
    assert_eq!(status, 401, "{body}");
    assert!(body.to_string().contains("reuse detected"), "{body}");
    assert!(claims_from_access_token(&old_access, &store, &cache).is_err());
    assert!(
        claims_from_access_token(signup["access_token"].as_str().unwrap(), &store, &cache).is_err()
    );
    let (status, body) = rotate_refresh_token(&store, &cache, current_refresh, "current-client");
    assert_eq!(status, 401, "{body}");
}

#[test]
fn expired_refresh_token_cannot_rotate_or_mark_reuse() {
    let (store, cache) = refresh_rotation_test_store();
    let signup = signup_refresh_token(&store, &cache, "expired@example.com");
    let refresh = signup["refresh_token"].as_str().unwrap();
    let hash = hash_secret(refresh);
    let session = find_row_by_field(
        &store,
        &cache,
        SESSIONS_TABLE,
        "refresh_token_hash",
        &hash,
        Instant::now(),
    )
    .unwrap()
    .unwrap();
    durable_table_update_where(
        &store,
        &cache,
        SESSIONS_TABLE,
        &[("expires_at", "1")],
        &["id", "=", &session["id"]],
        Instant::now(),
    )
    .unwrap();

    let (status, body) = rotate_refresh_token(&store, &cache, refresh, "expired-client");
    assert_eq!(status, 401, "{body}");
    assert!(body.to_string().contains("expired"), "{body}");
    let session = find_row_by_field(
        &store,
        &cache,
        SESSIONS_TABLE,
        "id",
        &session["id"],
        Instant::now(),
    )
    .unwrap()
    .unwrap();
    assert!(!row_field_is_set(&session, "refresh_reuse_detected_at"));
}

#[test]
fn concurrent_refresh_has_one_winner_and_revokes_the_winner_on_reuse() {
    let (store, cache) = refresh_rotation_test_store();
    let signup = signup_refresh_token(&store, &cache, "race@example.com");
    let refresh = Arc::new(signup["refresh_token"].as_str().unwrap().to_string());
    let barrier = Arc::new(std::sync::Barrier::new(8));
    let mut threads = Vec::new();
    for client in 0..8 {
        let store = store.clone();
        let cache = cache.clone();
        let refresh = refresh.clone();
        let barrier = barrier.clone();
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            rotate_refresh_token(&store, &cache, &refresh, &format!("race-{client}"))
        }));
    }
    let responses = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        responses
            .iter()
            .filter(|(status, _)| *status == 200)
            .count(),
        1,
        "exactly one rotation may commit: {responses:?}"
    );
    assert!(responses
        .iter()
        .filter(|(status, _)| *status == 401)
        .all(|(_, body)| body.to_string().contains("reuse detected")));
    let winner = responses.iter().find(|(status, _)| *status == 200).unwrap();
    let access = winner.1["access_token"].as_str().unwrap();
    assert!(claims_from_access_token(access, &store, &cache).is_err());
}

#[test]
fn refresh_rotation_does_not_advance_when_wal_append_or_fsync_fails() {
    let dir = tempfile::tempdir().unwrap();
    let config = Arc::new(ServerConfig {
        data_dir: dir.path().to_string_lossy().to_string(),
        durability: DurabilityConfig {
            policy: DurabilityPolicy::AlwaysSync,
            ..DurabilityConfig::default()
        },
        auth: AuthConfig {
            enabled: true,
            ..AuthConfig::default()
        },
        encryption: crate::EncryptionConfig {
            active_key_id: Some("refresh-test".to_string()),
            keys: vec![crate::EncryptionKeyConfig {
                id: "refresh-test".to_string(),
                secret: b"refresh-rotation-test-key".to_vec(),
                decrypt_only: false,
            }],
            ..Default::default()
        },
        ..ServerConfig::default()
    });
    let store = Store::new_with_config(config);
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    bootstrap(&store, &cache, &store.config().auth).unwrap();
    bootstrap_runtime(&store, &cache, &store.config().auth).unwrap();
    let signup = signup_refresh_token(&store, &cache, "wal-refresh@example.com");
    let first = signup["refresh_token"].as_str().unwrap();

    store.inject_journal_failures(1);
    let (status, body) = rotate_refresh_token(&store, &cache, first, "append-failure");
    assert_eq!(status, 500, "{body}");
    let (status, recovered) = rotate_refresh_token(&store, &cache, first, "append-retry");
    assert_eq!(status, 200, "{recovered}");
    let second = recovered["refresh_token"].as_str().unwrap();

    store.inject_journal_fsync_failures(1);
    let (status, body) = rotate_refresh_token(&store, &cache, second, "fsync-failure");
    assert_eq!(status, 500, "{body}");
    let (status, recovered) = rotate_refresh_token(&store, &cache, second, "fsync-retry");
    assert_eq!(status, 200, "{recovered}");
}

#[test]
fn interrupted_refresh_rotation_replays_fail_closed_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let config = Arc::new(ServerConfig {
        data_dir: dir.path().to_string_lossy().to_string(),
        durability: DurabilityConfig {
            policy: DurabilityPolicy::AlwaysSync,
            ..DurabilityConfig::default()
        },
        auth: AuthConfig {
            enabled: true,
            ..AuthConfig::default()
        },
        encryption: crate::EncryptionConfig {
            active_key_id: Some("refresh-crash".to_string()),
            keys: vec![crate::EncryptionKeyConfig {
                id: "refresh-crash".to_string(),
                secret: b"refresh-crash-test-key".to_vec(),
                decrypt_only: false,
            }],
            ..Default::default()
        },
        ..ServerConfig::default()
    });
    let (refresh, access) = {
        let store = Store::new_with_config(config.clone());
        let cache = Arc::new(RwLock::new(SchemaCache::new()));
        bootstrap(&store, &cache, &store.config().auth).unwrap();
        bootstrap_runtime(&store, &cache, &store.config().auth).unwrap();
        let signup = signup_refresh_token(&store, &cache, "crash-refresh@example.com");
        let refresh = signup["refresh_token"].as_str().unwrap().to_string();
        let access = signup["access_token"].as_str().unwrap().to_string();
        crate::tables::fail_next_table_mutation_after_journal();
        let (status, body) = rotate_refresh_token(&store, &cache, &refresh, "crash-window");
        assert_eq!(status, 500, "{body}");
        (refresh, access)
    };

    let restored = Store::new_with_config(config);
    restored.replay_wal(&crate::pubsub::Broker::new()).unwrap();
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    bootstrap(&restored, &cache, &restored.config().auth).unwrap();
    bootstrap_runtime(&restored, &cache, &restored.config().auth).unwrap();
    let (status, body) = rotate_refresh_token(&restored, &cache, &refresh, "after-restart");
    assert_eq!(status, 401, "{body}");
    assert!(body.to_string().contains("reuse detected"), "{body}");
    assert!(claims_from_access_token(&access, &restored, &cache).is_err());
}

#[test]
fn refresh_schema_upgrade_is_idempotent() {
    let store = Store::new();
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    create_table_if_missing(
        &store,
        &cache,
        SESSIONS_TABLE,
        &[
            "id STR PRIMARY KEY,",
            "user_id UUID,",
            "refresh_token_hash STR UNIQUE,",
            "refresh_token_family STR,",
            "expires_at INT,",
            "revoked_at INT",
        ],
        Instant::now(),
    )
    .unwrap();
    bootstrap(&store, &cache, &AuthConfig::default()).unwrap();
    bootstrap(&store, &cache, &AuthConfig::default()).unwrap();
    let schema = tables::table_schema(&store, &cache, SESSIONS_TABLE, Instant::now()).unwrap();
    for field in [
        "refresh_generation",
        "legacy_refresh_token_hash",
        "access_revoked_at",
        "refresh_rotated_at",
        "refresh_reuse_detected_at",
    ] {
        assert_eq!(
            schema
                .iter()
                .filter(|definition| definition.split_whitespace().next() == Some(field))
                .count(),
            1,
            "{field} must be added exactly once"
        );
    }
}

fn flow_token_for_email(
    store: &Store,
    cache: &SharedSchemaCache,
    email: &str,
    kind: &str,
) -> String {
    let rows = find_rows_by_field(
        store,
        cache,
        FLOW_TOKENS_TABLE,
        "email",
        email,
        Instant::now(),
    )
    .unwrap();
    let row = rows
        .iter()
        .find(|row| row.get("type").map(String::as_str) == Some(kind))
        .expect("flow token should exist");
    let metadata: Value =
        serde_json::from_str(row.get("metadata").map(String::as_str).unwrap_or("{}")).unwrap();
    metadata["action_link"]
        .as_str()
        .and_then(|link| link.split("token_hash=").nth(1))
        .map(|rest| rest.split('&').next().unwrap_or(rest).to_string())
        .expect("action link should carry token_hash")
}

#[test]
fn signup_rejects_untrusted_redirect_before_creating_user() {
    let config = Arc::new(crate::ServerConfig {
        auth: AuthConfig {
            enabled: true,
            email_confirmation_required: true,
            site_url: "http://app.test/auth".to_string(),
            ..AuthConfig::default()
        },
        ..crate::ServerConfig::default()
    });
    let store = Store::new_with_config(config);
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    bootstrap(&store, &cache, &store.config().auth).unwrap();
    bootstrap_runtime(&store, &cache, &store.config().auth).unwrap();

    let (status, _, body) = route_http(
        "POST",
        "/auth/v1/signup",
        r#"{"email":"evil-redirect@example.com","password":"password123","email_redirect_to":"https://evil.test/steal"}"#,
        &[],
        &[],
        &store,
        &cache,
    );
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("redirect URL is not allowed"), "{body}");
    assert!(
        find_row_by_field(
            &store,
            &cache,
            USERS_TABLE,
            "email",
            "evil-redirect@example.com",
            Instant::now(),
        )
        .unwrap()
        .is_none(),
        "bad redirect signup should not leave a user row"
    );
}

#[test]
fn recover_rejects_untrusted_redirect() {
    let config = Arc::new(crate::ServerConfig {
        auth: AuthConfig {
            enabled: true,
            site_url: "http://app.test/auth".to_string(),
            ..AuthConfig::default()
        },
        ..crate::ServerConfig::default()
    });
    let store = Store::new_with_config(config);
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    bootstrap(&store, &cache, &store.config().auth).unwrap();
    bootstrap_runtime(&store, &cache, &store.config().auth).unwrap();

    let (status, _, body) = route_http(
        "POST",
        "/auth/v1/signup",
        r#"{"email":"recover-redirect@example.com","password":"password123"}"#,
        &[],
        &[],
        &store,
        &cache,
    );
    assert_eq!(status, 200, "signup: {body}");

    let (status, _, body) = route_http(
        "POST",
        "/auth/v1/recover",
        r#"{"email":"recover-redirect@example.com","redirect_to":"https://evil.test/update"}"#,
        &[],
        &[],
        &store,
        &cache,
    );
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("redirect URL is not allowed"), "{body}");
}

#[test]
fn signup_confirmation_flow_confirms_email_and_issues_session() {
    let config = Arc::new(crate::ServerConfig {
        auth: AuthConfig {
            enabled: true,
            email_confirmation_required: true,
            site_url: "http://app.test/auth".to_string(),
            ..AuthConfig::default()
        },
        ..crate::ServerConfig::default()
    });
    let store = Store::new_with_config(config);
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    bootstrap(&store, &cache, &store.config().auth).unwrap();
    bootstrap_runtime(&store, &cache, &store.config().auth).unwrap();

    let (status, _, signup_body) = route_http(
        "POST",
        "/auth/v1/signup",
        r#"{"email":"confirm@example.com","password":"password123","email_redirect_to":"http://app.test/confirm"}"#,
        &[],
        &[],
        &store,
        &cache,
    );
    assert_eq!(status, 200, "{signup_body}");
    let signup_json: Value = serde_json::from_str(&signup_body).unwrap();
    assert!(signup_json["access_token"].is_null(), "{signup_body}");

    let (status, _, body) = route_http(
        "POST",
        "/auth/v1/token",
        r#"{"grant_type":"password","email":"confirm@example.com","password":"password123"}"#,
        &[],
        &[],
        &store,
        &cache,
    );
    assert_eq!(status, 401, "unconfirmed login should fail: {body}");

    let token = flow_token_for_email(&store, &cache, "confirm@example.com", "signup");
    let (status, _, verify_body) = route_http(
        "POST",
        "/auth/v1/verify",
        &format!(r#"{{"type":"signup","token_hash":"{token}"}}"#),
        &[],
        &[],
        &store,
        &cache,
    );
    assert_eq!(status, 200, "verify: {verify_body}");
    let verified: Value = serde_json::from_str(&verify_body).unwrap();
    assert!(verified["access_token"].is_string(), "{verify_body}");

    let (status, _, body) = route_http(
        "POST",
        "/auth/v1/token",
        r#"{"grant_type":"password","email":"confirm@example.com","password":"password123"}"#,
        &[],
        &[],
        &store,
        &cache,
    );
    assert_eq!(status, 200, "confirmed login should succeed: {body}");
}

#[test]
fn admin_settings_update_auth_flows_without_restart() {
    let config = Arc::new(crate::ServerConfig {
        auth: AuthConfig {
            enabled: true,
            initial_secret_key: Some("lux_sec_test".to_string()),
            email_confirmation_required: false,
            site_url: "http://initial.test/auth".to_string(),
            ..AuthConfig::default()
        },
        ..crate::ServerConfig::default()
    });
    let store = Store::new_with_config(config);
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    bootstrap(&store, &cache, &store.config().auth).unwrap();
    bootstrap_runtime(&store, &cache, &store.config().auth).unwrap();

    let (status, _, body) = route_http(
        "PATCH",
        "/auth/v1/admin/settings",
        r#"{"email_confirmation_required":true,"flow_token_ttl_seconds":120,"site_url":"http://updated.test/auth"}"#,
        &[],
        &[("apikey".to_string(), "lux_sec_test".to_string())],
        &store,
        &cache,
    );
    assert_eq!(status, 200, "settings update: {body}");
    let settings: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(settings["settings"]["email_confirmation_required"], true);
    assert_eq!(settings["settings"]["flow_token_ttl_seconds"], 120);
    assert_eq!(settings["settings"]["site_url"], "http://updated.test/auth");

    let (status, _, signup_body) = route_http(
        "POST",
        "/auth/v1/signup",
        r#"{"email":"dynamic@example.com","password":"password123"}"#,
        &[],
        &[("apikey".to_string(), "lux_sec_test".to_string())],
        &store,
        &cache,
    );
    assert_eq!(status, 200, "signup: {signup_body}");
    let signup: Value = serde_json::from_str(&signup_body).unwrap();
    assert!(signup["session"].is_null(), "{signup_body}");

    let token_row = find_rows_by_field(
        &store,
        &cache,
        FLOW_TOKENS_TABLE,
        "email",
        "dynamic@example.com",
        Instant::now(),
    )
    .unwrap()
    .pop()
    .expect("signup flow token should exist after dynamic settings update");
    let metadata: Value =
        serde_json::from_str(token_row.get("metadata").map(String::as_str).unwrap()).unwrap();
    assert!(
        metadata["action_link"]
            .as_str()
            .unwrap()
            .starts_with("http://updated.test/auth?token_hash="),
        "{metadata}"
    );
}

#[test]
fn postmark_payload_renders_builtin_signup_and_recovery_emails() {
    let delivery = EffectiveEmailDelivery {
        provider: "postmark".to_string(),
        from: Some("Auth <auth@app.test>".to_string()),
        reply_to: Some("support@app.test".to_string()),
        postmark_server_token: Some("server-token".to_string()),
        postmark_message_stream: "outbound".to_string(),
        app_name: "Pompeii".to_string(),
    };

    let signup = auth_email_message(
        "signup",
        "user@app.test",
        "http://app.test/confirm",
        &delivery,
    )
    .unwrap();
    let signup_payload = postmark_payload(&signup);
    assert_eq!(signup_payload.from, "Auth <auth@app.test>");
    assert_eq!(signup_payload.to, "user@app.test");
    assert_eq!(signup_payload.reply_to.as_deref(), Some("support@app.test"));
    assert_eq!(signup_payload.subject, "Confirm your email for Pompeii");
    assert!(signup_payload.text_body.contains("http://app.test/confirm"));
    assert!(signup_payload.html_body.contains("Confirm your email"));

    let recovery = auth_email_message(
        "recovery",
        "user@app.test",
        "http://app.test/reset",
        &delivery,
    )
    .unwrap();
    let recovery_payload = postmark_payload(&recovery);
    assert_eq!(recovery_payload.subject, "Reset your password for Pompeii");
    assert!(recovery_payload.text_body.contains("http://app.test/reset"));
    assert!(recovery_payload.html_body.contains("Reset your password"));
}

#[test]
fn admin_settings_redacts_and_preserves_postmark_token() {
    let config = Arc::new(crate::ServerConfig {
        auth: AuthConfig {
            enabled: true,
            initial_secret_key: Some("lux_sec_test".to_string()),
            ..AuthConfig::default()
        },
        ..crate::ServerConfig::default()
    });
    let store = Store::new_with_config(config);
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    bootstrap(&store, &cache, &store.config().auth).unwrap();
    bootstrap_runtime(&store, &cache, &store.config().auth).unwrap();

    let (status, _, body) = route_http(
        "PATCH",
        "/auth/v1/admin/settings",
        r#"{"email_provider":"postmark","email_from":"Auth <auth@app.test>","email_postmark_server_token":"server-token","email_postmark_message_stream":"outbound","email_app_name":"Pompeii"}"#,
        &[],
        &[("apikey".to_string(), "lux_sec_test".to_string())],
        &store,
        &cache,
    );
    assert_eq!(status, 200, "settings update: {body}");
    assert!(!body.contains("server-token"), "{body}");
    let settings: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(settings["settings"]["email_provider"], "postmark");
    assert_eq!(
        settings["settings"]["has_email_postmark_server_token"],
        true
    );

    let (status, _, body) = route_http(
        "PATCH",
        "/auth/v1/admin/settings",
        r#"{"email_app_name":"Pompeii AI"}"#,
        &[],
        &[("apikey".to_string(), "lux_sec_test".to_string())],
        &store,
        &cache,
    );
    assert_eq!(status, 200, "settings update without token: {body}");
    let settings: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        settings["settings"]["has_email_postmark_server_token"],
        true
    );
    assert_eq!(settings["settings"]["email_app_name"], "Pompeii AI");
    assert!(!body.contains("server-token"), "{body}");
}

#[test]
fn signup_delivery_failure_invalidates_flow_token() {
    let config = Arc::new(crate::ServerConfig {
        auth: AuthConfig {
            enabled: true,
            initial_secret_key: Some("lux_sec_test".to_string()),
            email_confirmation_required: true,
            ..AuthConfig::default()
        },
        ..crate::ServerConfig::default()
    });
    let store = Store::new_with_config(config);
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    bootstrap(&store, &cache, &store.config().auth).unwrap();
    bootstrap_runtime(&store, &cache, &store.config().auth).unwrap();

    let (status, _, body) = route_http(
        "PATCH",
        "/auth/v1/admin/settings",
        r#"{"email_provider":"postmark","email_from":"Auth <auth@app.test>"}"#,
        &[],
        &[("apikey".to_string(), "lux_sec_test".to_string())],
        &store,
        &cache,
    );
    assert_eq!(status, 200, "settings update: {body}");

    let (status, _, body) = route_http(
        "POST",
        "/auth/v1/signup",
        r#"{"email":"sendfail@example.com","password":"password123"}"#,
        &[],
        &[("apikey".to_string(), "lux_sec_test".to_string())],
        &store,
        &cache,
    );
    assert_eq!(
        status, 502,
        "signup should fail when delivery fails: {body}"
    );
    assert!(
        find_rows_by_field(
            &store,
            &cache,
            FLOW_TOKENS_TABLE,
            "email",
            "sendfail@example.com",
            Instant::now(),
        )
        .unwrap()
        .is_empty(),
        "unsent flow token should be removed"
    );
}

#[test]
fn managed_email_delivery_overrides_project_provider_settings() {
    let config = Arc::new(crate::ServerConfig {
        auth: AuthConfig {
            enabled: true,
            initial_secret_key: Some("lux_sec_test".to_string()),
            managed_email: Some(crate::AuthManagedEmailConfig {
                provider: "postmark".to_string(),
                from: "managed@app.test".to_string(),
                reply_to: None,
                postmark_server_token: Some("managed-token".to_string()),
                postmark_message_stream: Some("broadcast".to_string()),
            }),
            ..AuthConfig::default()
        },
        ..crate::ServerConfig::default()
    });
    let store = Store::new_with_config(config);
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    bootstrap(&store, &cache, &store.config().auth).unwrap();
    bootstrap_runtime(&store, &cache, &store.config().auth).unwrap();

    let (status, _, body) = route_http(
        "PATCH",
        "/auth/v1/admin/settings",
        r#"{"email_provider":"postmark"}"#,
        &[],
        &[("apikey".to_string(), "lux_sec_test".to_string())],
        &store,
        &cache,
    );
    assert_eq!(status, 400, "managed provider should be immutable: {body}");

    let (status, _, body) = route_http(
        "PATCH",
        "/auth/v1/admin/settings",
        r#"{"email_from_name":"Pompeii","email_app_name":"Pompeii"}"#,
        &[],
        &[("apikey".to_string(), "lux_sec_test".to_string())],
        &store,
        &cache,
    );
    assert_eq!(status, 200, "safe branding update: {body}");
    let settings_json: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(settings_json["settings"]["email_provider"], "managed");
    assert_eq!(settings_json["settings"]["email_delivery_managed"], true);
    assert_eq!(
        settings_json["settings"]["has_email_postmark_server_token"],
        false
    );
    assert!(!body.contains("managed-token"), "{body}");

    let settings = auth_settings(&store, &cache, Instant::now()).unwrap();
    let delivery =
        effective_email_delivery(&settings, store.config().auth.managed_email.as_ref()).unwrap();
    assert_eq!(delivery.provider, "postmark");
    assert_eq!(delivery.from.as_deref(), Some("Pompeii <managed@app.test>"));
    assert_eq!(
        delivery.postmark_server_token.as_deref(),
        Some("managed-token")
    );
    assert_eq!(delivery.postmark_message_stream, "broadcast");
}

#[test]
fn recovery_flow_issues_session_and_allows_password_update() {
    let config = Arc::new(crate::ServerConfig {
        auth: AuthConfig {
            enabled: true,
            site_url: "http://app.test/auth".to_string(),
            ..AuthConfig::default()
        },
        ..crate::ServerConfig::default()
    });
    let store = Store::new_with_config(config);
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    bootstrap(&store, &cache, &store.config().auth).unwrap();
    bootstrap_runtime(&store, &cache, &store.config().auth).unwrap();

    let (status, _, body) = route_http(
        "POST",
        "/auth/v1/signup",
        r#"{"email":"recover@example.com","password":"password123"}"#,
        &[],
        &[],
        &store,
        &cache,
    );
    assert_eq!(status, 200, "signup: {body}");

    let (status, _, body) = route_http(
        "POST",
        "/auth/v1/recover",
        r#"{"email":"recover@example.com","redirect_to":"http://app.test/update-password"}"#,
        &[],
        &[],
        &store,
        &cache,
    );
    assert_eq!(status, 200, "recover: {body}");
    let token = flow_token_for_email(&store, &cache, "recover@example.com", "recovery");

    let (status, _, verify_body) = route_http(
        "POST",
        "/auth/v1/verify",
        &format!(r#"{{"type":"recovery","token_hash":"{token}"}}"#),
        &[],
        &[],
        &store,
        &cache,
    );
    assert_eq!(status, 200, "verify recovery: {verify_body}");
    let session: Value = serde_json::from_str(&verify_body).unwrap();
    let access = session["access_token"].as_str().unwrap();

    let (status, _, update_body) = route_http(
        "PUT",
        "/auth/v1/user",
        r#"{"password":"newpassword123"}"#,
        &[],
        &[("authorization".to_string(), format!("Bearer {access}"))],
        &store,
        &cache,
    );
    assert_eq!(status, 200, "update password: {update_body}");

    let (status, _, old_body) = route_http(
        "POST",
        "/auth/v1/token",
        r#"{"grant_type":"password","email":"recover@example.com","password":"password123"}"#,
        &[],
        &[],
        &store,
        &cache,
    );
    assert_eq!(status, 400, "old password should fail: {old_body}");

    let (status, _, new_body) = route_http(
        "POST",
        "/auth/v1/token",
        r#"{"grant_type":"password","email":"recover@example.com","password":"newpassword123"}"#,
        &[],
        &[],
        &store,
        &cache,
    );
    assert_eq!(status, 200, "new password should login: {new_body}");
}

#[test]
fn authorization_code_flow_is_one_time_use() {
    let config = Arc::new(crate::ServerConfig {
        auth: AuthConfig {
            enabled: true,
            ..AuthConfig::default()
        },
        ..crate::ServerConfig::default()
    });
    let store = Store::new_with_config(config);
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    bootstrap(&store, &cache, &store.config().auth).unwrap();
    bootstrap_runtime(&store, &cache, &store.config().auth).unwrap();

    let (_, _, signup_body) = route_http(
        "POST",
        "/auth/v1/signup",
        r#"{"email":"code@example.com","password":"password123"}"#,
        &[],
        &[],
        &store,
        &cache,
    );
    let signup: Value = serde_json::from_str(&signup_body).unwrap();
    let user_id = signup["user"]["id"].as_str().unwrap();
    let settings = auth_settings(&store, &cache, Instant::now()).unwrap();
    let code = create_flow_token(
        &store,
        &cache,
        FlowTokenInsert {
            settings: &settings,
            kind: "oauth_code",
            user_id,
            email: "code@example.com",
            redirect_to: "http://app.test/callback",
            metadata: json!({}),
        },
        Instant::now(),
    )
    .unwrap();

    let (status, _, body) = route_http(
        "POST",
        "/auth/v1/token",
        &format!(r#"{{"grant_type":"authorization_code","code":"{code}"}}"#),
        &[],
        &[],
        &store,
        &cache,
    );
    assert_eq!(status, 200, "code exchange: {body}");

    let (status, _, body) = route_http(
        "POST",
        "/auth/v1/token",
        &format!(r#"{{"grant_type":"authorization_code","code":"{code}"}}"#),
        &[],
        &[],
        &store,
        &cache,
    );
    assert_eq!(status, 400, "code should be single-use: {body}");
}

#[test]
fn authorization_code_pkce_is_bound_and_failed_attempt_does_not_consume() {
    let config = Arc::new(crate::ServerConfig {
        auth: AuthConfig {
            enabled: true,
            ..AuthConfig::default()
        },
        ..crate::ServerConfig::default()
    });
    let store = Store::new_with_config(config);
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    bootstrap(&store, &cache, &store.config().auth).unwrap();
    bootstrap_runtime(&store, &cache, &store.config().auth).unwrap();

    let (_, _, signup_body) = route_http(
        "POST",
        "/auth/v1/signup",
        r#"{"email":"pkce@example.com","password":"password123"}"#,
        &[],
        &[],
        &store,
        &cache,
    );
    let signup: Value = serde_json::from_str(&signup_body).unwrap();
    let user_id = signup["user"]["id"].as_str().unwrap();
    let settings = auth_settings(&store, &cache, Instant::now()).unwrap();
    // RFC 7636 Appendix B's verifier/challenge pair.
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    let code = create_flow_token(
        &store,
        &cache,
        FlowTokenInsert {
            settings: &settings,
            kind: "oauth_code",
            user_id,
            email: "pkce@example.com",
            redirect_to: "vigil://auth/callback",
            metadata: json!({"code_challenge": challenge}),
        },
        Instant::now(),
    )
    .unwrap();

    for body in [
        format!(r#"{{"grant_type":"authorization_code","code":"{code}"}}"#),
        format!(
            r#"{{"grant_type":"authorization_code","code":"{code}","code_verifier":"{}"}}"#,
            "x".repeat(43)
        ),
    ] {
        let (status, _, _) = route_http("POST", "/auth/v1/token", &body, &[], &[], &store, &cache);
        assert_eq!(status, 400);
    }

    let (status, _, body) = route_http(
        "POST",
        "/auth/v1/token",
        &format!(
            r#"{{"grant_type":"authorization_code","code":"{code}","code_verifier":"{verifier}"}}"#
        ),
        &[],
        &[],
        &store,
        &cache,
    );
    assert_eq!(status, 200, "correct verifier should redeem code: {body}");

    let (status, _, _) = route_http(
        "POST",
        "/auth/v1/token",
        &format!(
            r#"{{"grant_type":"authorization_code","code":"{code}","code_verifier":"{verifier}"}}"#
        ),
        &[],
        &[],
        &store,
        &cache,
    );
    assert_eq!(status, 400, "successful redemption remains one-time");
}

#[test]
fn flow_token_consume_has_single_winner_under_concurrency() {
    let config = Arc::new(crate::ServerConfig {
        auth: AuthConfig {
            enabled: true,
            ..AuthConfig::default()
        },
        ..crate::ServerConfig::default()
    });
    let store = Arc::new(Store::new_with_config(config));
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    bootstrap(&store, &cache, &store.config().auth).unwrap();
    bootstrap_runtime(&store, &cache, &store.config().auth).unwrap();

    let settings = auth_settings(&store, &cache, Instant::now()).unwrap();
    let user_id = tables::generate_uuid_v7();
    let token = create_flow_token(
        &store,
        &cache,
        FlowTokenInsert {
            settings: &settings,
            kind: "recovery",
            user_id: &user_id,
            email: "race@example.com",
            redirect_to: "/",
            metadata: json!({}),
        },
        Instant::now(),
    )
    .unwrap();

    let workers = 8;
    let barrier = Arc::new(std::sync::Barrier::new(workers));
    let successes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut handles = Vec::new();
    for _ in 0..workers {
        let store = Arc::clone(&store);
        let cache = Arc::clone(&cache);
        let barrier = Arc::clone(&barrier);
        let successes = Arc::clone(&successes);
        let token = token.clone();
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            if consume_flow_token(&store, &cache, "recovery", &token, Instant::now(), |_| {
                Ok(())
            })
            .is_ok()
            {
                successes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }));
    }
    for handle in handles {
        handle.join().unwrap();
    }

    assert_eq!(
        successes.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "only one concurrent consumer may redeem a flow token"
    );
}

#[tokio::test]
async fn oauth_provider_config_and_authorize_redirect_are_core_owned() {
    let config = Arc::new(crate::ServerConfig {
        auth: AuthConfig {
            enabled: true,
            initial_secret_key: Some("lux_sec_test".to_string()),
            site_url: "http://app.test/auth".to_string(),
            ..AuthConfig::default()
        },
        ..crate::ServerConfig::default()
    });
    let store = Store::new_with_config(config);
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    bootstrap(&store, &cache, &store.config().auth).unwrap();
    bootstrap_runtime(&store, &cache, &store.config().auth).unwrap();

    let (status, _, body) = route_http(
        "PUT",
        "/auth/v1/admin/providers/google",
        r#"{"client_id":"google-client","client_secret":"google-secret","redirect_uri":"http://app.test/auth/callback","enabled":true}"#,
        &[],
        &[("apikey".to_string(), "lux_sec_test".to_string())],
        &store,
        &cache,
    );
    assert_eq!(status, 200, "{body}");
    let provider: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(provider["provider"]["provider"], "google");
    assert_eq!(provider["provider"]["has_client_secret"], true);
    assert!(
        !body.contains("google-secret"),
        "admin provider response must not expose client secret: {body}"
    );
    let (status, _, body) = route_http(
        "GET",
        "/auth/v1/admin/providers",
        "",
        &[],
        &[("apikey".to_string(), "lux_sec_test".to_string())],
        &store,
        &cache,
    );
    assert_eq!(status, 200, "{body}");
    let listed: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(listed["capabilities"]["apple_native"], true);
    assert_eq!(listed["capabilities"]["apple_web"], true);

    let response = route_http_response(
        "GET",
        "/auth/v1/authorize",
        "",
        &[
            ("provider".to_string(), "google".to_string()),
            (
                "redirect_to".to_string(),
                "http://app.test/welcome".to_string(),
            ),
        ],
        &[
            ("host".to_string(), "localhost:17777".to_string()),
            ("apikey".to_string(), "lux_sec_test".to_string()),
        ],
        &store,
        &cache,
    )
    .await;
    assert_eq!(response.status, 302);
    let location = response
        .headers
        .iter()
        .find(|(key, _)| key == "Location")
        .map(|(_, value)| value.as_str())
        .unwrap_or("");
    assert!(location.starts_with("https://accounts.google.com/o/oauth2/v2/auth?"));
    assert!(location.contains("client_id=google-client"), "{location}");
    assert!(
        location.contains("redirect_uri=http%3A%2F%2Fapp.test%2Fauth%2Fcallback"),
        "{location}"
    );
    assert!(
        location.contains("scope=openid%20email%20profile"),
        "{location}"
    );

    let (status, _, body) = route_http(
        "PATCH",
        "/auth/v1/admin/settings",
        r#"{"redirect_allow_list":["vigil://auth/callback"]}"#,
        &[],
        &[("apikey".to_string(), "lux_sec_test".to_string())],
        &store,
        &cache,
    );
    assert_eq!(status, 200, "allow custom redirect: {body}");

    let response = route_http_response(
        "GET",
        "/auth/v1/authorize",
        "",
        &[
            ("provider".to_string(), "google".to_string()),
            (
                "redirect_to".to_string(),
                "vigil://auth/callback".to_string(),
            ),
            ("flow".to_string(), "code".to_string()),
        ],
        &[
            ("host".to_string(), "localhost:17777".to_string()),
            ("apikey".to_string(), "lux_sec_test".to_string()),
        ],
        &store,
        &cache,
    )
    .await;
    assert_eq!(response.status, 400, "custom schemes must require PKCE");

    let response = route_http_response(
        "GET",
        "/auth/v1/authorize",
        "",
        &[
            ("provider".to_string(), "google".to_string()),
            (
                "redirect_to".to_string(),
                "vigil://auth/callback".to_string(),
            ),
            ("flow".to_string(), "code".to_string()),
            (
                "code_challenge".to_string(),
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_string(),
            ),
            ("code_challenge_method".to_string(), "S256".to_string()),
        ],
        &[
            ("host".to_string(), "localhost:17777".to_string()),
            ("apikey".to_string(), "lux_sec_test".to_string()),
        ],
        &store,
        &cache,
    )
    .await;
    assert_eq!(response.status, 302, "valid S256 PKCE should authorize");
}

#[test]
fn oauth_sign_in_links_identity_and_issues_session() {
    let config = Arc::new(crate::ServerConfig {
        auth: AuthConfig {
            enabled: true,
            ..AuthConfig::default()
        },
        ..crate::ServerConfig::default()
    });
    let store = Store::new_with_config(config);
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    bootstrap(&store, &cache, &store.config().auth).unwrap();
    bootstrap_runtime(&store, &cache, &store.config().auth).unwrap();

    let oauth_user = OAuthUser {
        provider: "github".to_string(),
        provider_id: "42".to_string(),
        email: "octo@example.com".to_string(),
        email_verified: true,
        user_metadata: json!({"name":"Octo"}),
        identity_data: json!({"login":"octo"}),
    };
    let (status, _, body) = oauth_sign_in(&oauth_user, &[], &store, &cache);
    assert_eq!(status, 200, "{body}");
    let session: Value = serde_json::from_str(&body).unwrap();
    assert!(session["access_token"].is_string(), "{body}");
    assert_eq!(session["user"]["email"], "octo@example.com");

    let identity = find_row_by_field(
        &store,
        &cache,
        IDENTITIES_TABLE,
        "provider_id",
        "github:42",
        Instant::now(),
    )
    .unwrap()
    .expect("oauth identity should be stored");
    assert_eq!(identity.get("provider").map(String::as_str), Some("github"));
}

#[test]
fn deleted_users_cannot_use_or_refresh_tokens() {
    let config = Arc::new(crate::ServerConfig {
        auth: AuthConfig {
            enabled: true,
            ..AuthConfig::default()
        },
        ..crate::ServerConfig::default()
    });
    let store = Store::new_with_config(config);
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    bootstrap(&store, &cache, &store.config().auth).unwrap();
    bootstrap_runtime(&store, &cache, &store.config().auth).unwrap();

    let (_, _, signup_body) = route_http(
        "POST",
        "/auth/v1/signup",
        r#"{"email":"deleted@example.com","password":"password123"}"#,
        &[],
        &[],
        &store,
        &cache,
    );
    let signup_json: Value = serde_json::from_str(&signup_body).unwrap();
    let user_id = signup_json["user"]["id"].as_str().unwrap();
    let access_token = signup_json["access_token"].as_str().unwrap();
    let refresh_token = signup_json["refresh_token"].as_str().unwrap();

    let deleted_at = unix_seconds().to_string();
    durable_table_update_where(
        &store,
        &cache,
        USERS_TABLE,
        &[("deleted_at", deleted_at.as_str())],
        &["id", "=", user_id],
        Instant::now(),
    )
    .unwrap();

    let (status, _, body) = route_http(
        "GET",
        "/auth/v1/user",
        "",
        &[],
        &[(
            "Authorization".to_string(),
            format!("Bearer {access_token}"),
        )],
        &store,
        &cache,
    );
    assert_eq!(status, 401, "{body}");
    assert!(body.contains("user deleted"), "{body}");

    let (status, _, body) = route_http(
        "POST",
        "/auth/v1/token",
        &format!(
            r#"{{"grant_type":"refresh_token","refresh_token":"{}"}}"#,
            refresh_token
        ),
        &[],
        &[],
        &store,
        &cache,
    );
    assert_eq!(status, 401, "{body}");

    let (status, _, body) = route_http(
        "POST",
        "/auth/v1/token",
        r#"{"grant_type":"password","email":"deleted@example.com","password":"password123"}"#,
        &[],
        &[],
        &store,
        &cache,
    );
    assert_eq!(status, 401, "{body}");
}

#[test]
fn auth_users_survive_wal_replay() {
    let temp = tempfile::tempdir().unwrap();
    let config = Arc::new(crate::ServerConfig {
        auth: AuthConfig {
            enabled: true,
            ..AuthConfig::default()
        },
        storage: crate::StorageConfig {
            mode: crate::StorageMode::Tiered,
            dir: temp.path().to_string_lossy().to_string(),
        },
        durability: crate::DurabilityConfig {
            policy: crate::DurabilityPolicy::EverySecond,
            ..Default::default()
        },
        encryption: crate::EncryptionConfig {
            active_key_id: Some("auth-wal".to_string()),
            keys: vec![crate::EncryptionKeyConfig {
                id: "auth-wal".to_string(),
                secret: b"auth-wal-secret".to_vec(),
                decrypt_only: false,
            }],
            ..Default::default()
        },
        ..crate::ServerConfig::default()
    });

    let store = Store::new_with_config(config.clone());
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    bootstrap(&store, &cache, &store.config().auth).unwrap();
    bootstrap_runtime(&store, &cache, &store.config().auth).unwrap();

    let (_, _, signup_body) = route_http(
        "POST",
        "/auth/v1/signup",
        r#"{"email":"wal@example.com","password":"password123"}"#,
        &[],
        &[],
        &store,
        &cache,
    );
    assert!(
        serde_json::from_str::<Value>(&signup_body).unwrap()["access_token"].is_string(),
        "{signup_body}"
    );

    let restored = Store::new_with_config(config);
    let restored_cache = Arc::new(RwLock::new(SchemaCache::new()));
    bootstrap(&restored, &restored_cache, &restored.config().auth).unwrap();
    restored.replay_wal(&crate::pubsub::Broker::new()).unwrap();
    bootstrap_runtime(&restored, &restored_cache, &restored.config().auth).unwrap();

    let user = find_row_by_field(
        &restored,
        &restored_cache,
        USERS_TABLE,
        "email",
        "wal@example.com",
        Instant::now(),
    )
    .unwrap()
    .expect("auth user should replay from WAL");
    assert_eq!(
        user.get("email").map(String::as_str),
        Some("wal@example.com")
    );
}

// ---- Sign in with Apple ------------------------------------------------

const APPLE_TEST_KID: &str = "apple-test-kid";

struct AppleTestRsaKey {
    private_pem: String,
    jwks: JwkSet,
}

fn apple_test_rsa_key() -> &'static AppleTestRsaKey {
    static KEY: OnceLock<AppleTestRsaKey> = OnceLock::new();
    KEY.get_or_init(|| {
        let private = RsaPrivateKey::new(&mut OsRng, 2048).expect("generate test RSA key");
        let private_pem = private
            .to_pkcs8_pem(LineEnding::LF)
            .expect("encode test RSA key")
            .to_string();
        let n = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(private.n().to_bytes_be());
        let e = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(private.e().to_bytes_be());
        let jwks = serde_json::from_value(json!({
            "keys": [{
                "kty": "RSA",
                "kid": APPLE_TEST_KID,
                "use": "sig",
                "alg": "RS256",
                "n": n,
                "e": e,
            }],
        }))
        .expect("build test Apple JWKS");
        AppleTestRsaKey { private_pem, jwks }
    })
}

fn apple_test_jwks() -> JwkSet {
    apple_test_rsa_key().jwks.clone()
}

fn apple_encrypted_store(key_id: &str) -> Store {
    Store::new_with_config(Arc::new(crate::ServerConfig {
        encryption: crate::EncryptionConfig {
            active_key_id: Some(key_id.to_string()),
            keys: vec![crate::EncryptionKeyConfig {
                id: key_id.to_string(),
                secret: format!("{key_id}-secret").into_bytes(),
                decrypt_only: false,
            }],
            ..Default::default()
        },
        ..crate::ServerConfig::default()
    }))
}

fn mint_apple_id_token(
    aud: &str,
    sub: &str,
    email: Option<&str>,
    nonce_claim: Option<&str>,
    exp_offset_secs: i64,
) -> String {
    let now = unix_seconds() as i64;
    let mut claims = json!({
        "iss": APPLE_ISSUER,
        "aud": aud,
        "sub": sub,
        "iat": now,
        "exp": now + exp_offset_secs,
    });
    if let Some(email) = email {
        claims["email"] = json!(email);
        claims["email_verified"] = json!(true);
    }
    if let Some(nonce) = nonce_claim {
        claims["nonce"] = json!(nonce);
    }
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(APPLE_TEST_KID.to_string());
    encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(apple_test_rsa_key().private_pem.as_bytes()).unwrap(),
    )
    .unwrap()
}

#[test]
fn verify_apple_id_token_accepts_valid_token() {
    let jwks = apple_test_jwks();
    let nonce_claim = sha256_hex("raw-nonce-123");
    let token = mint_apple_id_token(
        "com.pompeii.app",
        "apple-sub-001",
        Some("user@privaterelay.appleid.com"),
        Some(&nonce_claim),
        3600,
    );
    let claims = verify_apple_id_token(
        &jwks,
        &token,
        &["com.pompeii.app".to_string()],
        Some(&nonce_claim),
    )
    .expect("valid token should verify");
    assert_eq!(claims.sub, "apple-sub-001");
    assert_eq!(
        claims.email.as_deref(),
        Some("user@privaterelay.appleid.com")
    );
}

#[test]
fn verify_apple_id_token_rejects_wrong_audience() {
    let jwks = apple_test_jwks();
    let token = mint_apple_id_token("com.pompeii.app", "s", None, None, 3600);
    assert!(verify_apple_id_token(&jwks, &token, &["com.someone.else".to_string()], None).is_err());
}

#[test]
fn verify_apple_id_token_rejects_expired() {
    let jwks = apple_test_jwks();
    let token = mint_apple_id_token("com.pompeii.app", "s", None, None, -3600);
    assert!(verify_apple_id_token(&jwks, &token, &["com.pompeii.app".to_string()], None).is_err());
}

#[test]
fn verify_apple_id_token_rejects_nonce_mismatch() {
    let jwks = apple_test_jwks();
    let token = mint_apple_id_token(
        "com.pompeii.app",
        "s",
        None,
        Some(&sha256_hex("expected")),
        3600,
    );
    assert!(verify_apple_id_token(
        &jwks,
        &token,
        &["com.pompeii.app".to_string()],
        Some("attacker-supplied")
    )
    .is_err());
}

#[test]
fn apple_private_key_seals_and_unseals_with_active_key() {
    let store = apple_encrypted_store("k1");
    let p8 = "-----BEGIN PRIVATE KEY-----\nMOCKAPPLEP8\n-----END PRIVATE KEY-----\n";
    let sealed = seal_apple_private_key(&store, p8).unwrap();
    assert!(sealed.starts_with("luxsealed:"), "{sealed}");
    assert!(
        !sealed.contains("MOCKAPPLEP8"),
        "sealed key leaked plaintext"
    );
    assert_eq!(
        secrets::open(
            &store,
            PROVIDERS_TABLE,
            "apple_private_key",
            "apple",
            &sealed,
        )
        .unwrap(),
        p8
    );
}

#[test]
fn apple_private_key_plaintext_exception_is_ephemeral_only() {
    let store = Store::new();
    let p8 = "-----BEGIN PRIVATE KEY-----\nNOKEY\n-----END PRIVATE KEY-----\n";
    assert!(!store.config().durability.policy.is_persistent());
    let stored = seal_apple_private_key(&store, p8).unwrap();
    assert_eq!(stored, p8);
    assert_eq!(
        secrets::open(
            &store,
            PROVIDERS_TABLE,
            "apple_private_key",
            "apple",
            &stored,
        )
        .unwrap(),
        p8
    );
}

#[test]
fn legacy_plaintext_apple_private_key_is_migrated() {
    let store = apple_encrypted_store("apple-migration-key");
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    bootstrap(&store, &cache, &store.config().auth).unwrap();
    durable_table_insert(
        &store,
        &cache,
        PROVIDERS_TABLE,
        &[
            ("provider", "apple"),
            ("enabled", "true"),
            ("apple_bundle_ids", "com.example.app"),
            (
                "apple_private_key",
                apple_test_ec_key().private_pem.as_str(),
            ),
        ],
        Instant::now(),
    )
    .unwrap();

    secrets::migrate_storage(&store, &cache, Instant::now()).unwrap();
    let row = find_row_by_field(
        &store,
        &cache,
        PROVIDERS_TABLE,
        "provider",
        "apple",
        Instant::now(),
    )
    .unwrap()
    .unwrap();
    let stored = row.get("apple_private_key").unwrap();
    assert!(stored.starts_with("luxsealed:"));
    assert!(!stored.contains("BEGIN PRIVATE KEY"));
    assert_eq!(
        secrets::open(
            &store,
            PROVIDERS_TABLE,
            "apple_private_key",
            "apple",
            stored,
        )
        .unwrap(),
        apple_test_ec_key().private_pem
    );
}

#[test]
fn legacy_plaintext_apple_private_key_remains_in_ephemeral_memory_without_keyring() {
    let store = Store::new();
    if store.encryption().has_active_key() {
        return;
    }
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    bootstrap(&store, &cache, &store.config().auth).unwrap();
    durable_table_insert(
        &store,
        &cache,
        PROVIDERS_TABLE,
        &[
            ("provider", "apple"),
            ("enabled", "true"),
            (
                "apple_private_key",
                apple_test_ec_key().private_pem.as_str(),
            ),
        ],
        Instant::now(),
    )
    .unwrap();
    secrets::migrate_storage(&store, &cache, Instant::now()).unwrap();
    let row = find_row_by_field(
        &store,
        &cache,
        PROVIDERS_TABLE,
        "provider",
        "apple",
        Instant::now(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        row.get("apple_private_key").unwrap(),
        &apple_test_ec_key().private_pem
    );
}

#[tokio::test]
async fn signin_apple_native_creates_and_relinks_user() {
    let config = Arc::new(crate::ServerConfig {
        auth: AuthConfig {
            enabled: true,
            initial_secret_key: Some("lux_sec_test".to_string()),
            ..AuthConfig::default()
        },
        ..crate::ServerConfig::default()
    });
    let store = Store::new_with_config(config);
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    bootstrap(&store, &cache, &store.config().auth).unwrap();
    bootstrap_runtime(&store, &cache, &store.config().auth).unwrap();

    let (status, _, body) = route_http(
        "PUT",
        "/auth/v1/admin/providers/apple",
        r#"{"enabled":true,"apple_bundle_ids":"com.pompeii.app"}"#,
        &[],
        &[("apikey".to_string(), "lux_sec_test".to_string())],
        &store,
        &cache,
    );
    assert_eq!(status, 200, "provider upsert: {body}");

    seed_apple_jwks_for_test(apple_test_jwks());
    let missing_key_nonce = route_http_response(
        "POST",
        "/auth/v1/signin/apple/nonce",
        "",
        &[],
        &[],
        &store,
        &cache,
    )
    .await;
    assert_eq!(missing_key_nonce.status, 401);
    let nonce_response = route_http_response(
        "POST",
        "/auth/v1/signin/apple/nonce",
        "",
        &[],
        &[("apikey".to_string(), "lux_sec_test".to_string())],
        &store,
        &cache,
    )
    .await;
    assert_eq!(nonce_response.status, 200, "{}", nonce_response.body);
    let nonce_json: Value = serde_json::from_str(&nonce_response.body).unwrap();
    let raw_nonce = nonce_json["nonce"].as_str().unwrap();
    let token = mint_apple_id_token(
        "com.pompeii.app",
        "apple-sub-777",
        Some("ada@privaterelay.appleid.com"),
        Some(&sha256_hex(raw_nonce)),
        3600,
    );
    let no_key = route_http_response(
        "POST",
        "/auth/v1/signin/apple",
        &json!({"id_token": token.clone(), "nonce": raw_nonce}).to_string(),
        &[],
        &[("host".to_string(), "localhost".to_string())],
        &store,
        &cache,
    )
    .await;
    assert_eq!(no_key.status, 401, "{}", no_key.body);
    let no_nonce = route_http_response(
        "POST",
        "/auth/v1/signin/apple",
        &json!({"id_token": token.clone()}).to_string(),
        &[],
        &[("apikey".to_string(), "lux_sec_test".to_string())],
        &store,
        &cache,
    )
    .await;
    assert_eq!(no_nonce.status, 400, "{}", no_nonce.body);
    let signin_body =
        json!({"id_token": token, "nonce": raw_nonce, "user": {"name": "Ada Lovelace"}})
            .to_string();
    let response = route_http_response(
        "POST",
        "/auth/v1/signin/apple",
        &signin_body,
        &[],
        &[
            ("host".to_string(), "localhost".to_string()),
            ("apikey".to_string(), "lux_sec_test".to_string()),
        ],
        &store,
        &cache,
    )
    .await;
    assert_eq!(response.status, 200, "signin: {}", response.body);
    let session: Value = serde_json::from_str(&response.body).unwrap();
    assert!(
        session
            .get("access_token")
            .and_then(Value::as_str)
            .is_some(),
        "expected a session: {}",
        response.body
    );
    let first_user_id = session["user"]["id"].as_str().unwrap().to_string();
    let replay = route_http_response(
        "POST",
        "/auth/v1/signin/apple",
        &signin_body,
        &[],
        &[("apikey".to_string(), "lux_sec_test".to_string())],
        &store,
        &cache,
    )
    .await;
    assert_eq!(replay.status, 401, "{}", replay.body);

    // The captured first-login name is persisted on the user.
    let user = find_row_by_field(
        &store,
        &cache,
        USERS_TABLE,
        "id",
        &first_user_id,
        Instant::now(),
    )
    .unwrap()
    .expect("user row exists");
    assert!(
        user.get("raw_user_meta_data")
            .map(|m| m.contains("Ada Lovelace"))
            .unwrap_or(false),
        "name not stored: {user:?}"
    );

    // A second sign-in for the same Apple sub reuses the same user (relink),
    // not a duplicate.
    let nonce_response2 = route_http_response(
        "POST",
        "/auth/v1/signin/apple/nonce",
        "",
        &[],
        &[("apikey".to_string(), "lux_sec_test".to_string())],
        &store,
        &cache,
    )
    .await;
    let nonce_json2: Value = serde_json::from_str(&nonce_response2.body).unwrap();
    let raw_nonce2 = nonce_json2["nonce"].as_str().unwrap();
    let token2 = mint_apple_id_token(
        "com.pompeii.app",
        "apple-sub-777",
        None,
        Some(&sha256_hex(raw_nonce2)),
        3600,
    );
    let signin_body2 = json!({"id_token": token2, "nonce": raw_nonce2}).to_string();
    let response2 = route_http_response(
        "POST",
        "/auth/v1/signin/apple",
        &signin_body2,
        &[],
        &[
            ("host".to_string(), "localhost".to_string()),
            ("apikey".to_string(), "lux_sec_test".to_string()),
        ],
        &store,
        &cache,
    )
    .await;
    assert_eq!(response2.status, 200, "second signin: {}", response2.body);
    let session2: Value = serde_json::from_str(&response2.body).unwrap();
    assert_eq!(session2["user"]["id"].as_str().unwrap(), first_user_id);
}

struct AppleTestEcKey {
    private_pem: String,
    public_pem: String,
}

fn apple_test_ec_key() -> &'static AppleTestEcKey {
    static KEY: OnceLock<AppleTestEcKey> = OnceLock::new();
    KEY.get_or_init(|| {
        let private = SecretKey::random(&mut OsRng);
        let private_pem = private
            .to_pkcs8_pem(LineEnding::LF)
            .expect("encode test Apple .p8")
            .to_string();
        let public_pem = private
            .public_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("encode test Apple public key");
        AppleTestEcKey {
            private_pem,
            public_pem,
        }
    })
}

fn apple_web_config() -> OAuthProviderConfig {
    OAuthProviderConfig {
        provider: "apple".to_string(),
        enabled: true,
        client_id: String::new(),
        client_secret: String::new(),
        redirect_uri: "https://app.test/auth/callback/apple".to_string(),
        scopes: "name email".to_string(),
        apple_team_id: "TEAM123456".to_string(),
        apple_key_id: "KEY7890ABC".to_string(),
        apple_services_id: "com.pompeii.web".to_string(),
        apple_bundle_ids: "com.pompeii.app".to_string(),
        apple_private_key: apple_test_ec_key().private_pem.clone(),
        created_at: Value::Null,
        updated_at: Value::Null,
    }
}

#[test]
fn mint_apple_client_secret_produces_verifiable_es256() {
    let secret = mint_apple_client_secret(&apple_web_config()).expect("mint");
    let header = decode_header(&secret).unwrap();
    assert_eq!(header.alg, Algorithm::ES256);
    assert_eq!(header.kid.as_deref(), Some("KEY7890ABC"));

    let mut validation = Validation::new(Algorithm::ES256);
    validation.validate_aud = false;
    let claims = decode::<Value>(
        &secret,
        &DecodingKey::from_ec_pem(apple_test_ec_key().public_pem.as_bytes()).unwrap(),
        &validation,
    )
    .expect("client secret verifies against the .p8 public key")
    .claims;
    assert_eq!(claims["iss"], "TEAM123456");
    assert_eq!(claims["sub"], "com.pompeii.web");
    assert_eq!(claims["aud"], APPLE_ISSUER);
}

#[test]
fn mint_apple_client_secret_requires_web_config() {
    let mut config = apple_web_config();
    config.apple_private_key = String::new();
    assert!(mint_apple_client_secret(&config).is_err());
}

#[test]
fn parse_form_urlencoded_decodes_apple_callback() {
    let parsed = parse_form_urlencoded("code=abc123&state=xyz&user=%7B%22name%22%3A%22Ada%22%7D");
    assert_eq!(get_param(&parsed, "code"), Some("abc123"));
    assert_eq!(get_param(&parsed, "state"), Some("xyz"));
    assert_eq!(get_param(&parsed, "user"), Some(r#"{"name":"Ada"}"#));
    assert_eq!(
        parse_apple_callback_name(r#"{"name":{"firstName":"Ada","lastName":"Lovelace"}}"#),
        Some("Ada Lovelace".to_string())
    );
}

#[test]
fn new_oauth_identity_requires_a_verified_email() {
    let store = Store::new();
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    bootstrap(&store, &cache, &store.config().auth).unwrap();
    bootstrap_runtime(&store, &cache, &store.config().auth).unwrap();

    for oauth_user in [
        OAuthUser {
            provider: "apple".to_string(),
            provider_id: "missing-email".to_string(),
            email: String::new(),
            email_verified: false,
            user_metadata: json!({}),
            identity_data: json!({}),
        },
        OAuthUser {
            provider: "apple".to_string(),
            provider_id: "unverified-email".to_string(),
            email: "person@example.com".to_string(),
            email_verified: false,
            user_metadata: json!({}),
            identity_data: json!({}),
        },
    ] {
        let (status, _, body) = oauth_sign_in(&oauth_user, &[], &store, &cache);
        assert_eq!(status, 400, "{body}");
    }
}

#[tokio::test]
async fn oauth_error_callback_requires_and_consumes_stored_state() {
    let store = Store::new();
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    let state = "valid-state";
    let state_key = oauth_state_key(state);
    store.set(
        state_key.as_bytes(),
        json!({
            "provider": "apple",
            "redirect_to": "https://app.example.com/callback",
            "oidc_nonce": "nonce",
        })
        .to_string()
        .as_bytes(),
        Some(OAUTH_STATE_TTL),
        Instant::now(),
    );

    let response = oauth_callback(
        "apple",
        &[
            ("state".to_string(), state.to_string()),
            ("error".to_string(), "access_denied".to_string()),
            (
                "redirect_to".to_string(),
                "https://attacker.example.com".to_string(),
            ),
        ],
        &[],
        &store,
        &cache,
    )
    .await;
    assert_eq!(response.status, 302);
    let location = response
        .headers
        .iter()
        .find(|(key, _)| key == "Location")
        .map(|(_, value)| value.as_str())
        .unwrap_or("");
    assert!(location.starts_with("https://app.example.com/callback?"));
    assert!(!location.contains("attacker.example.com"));
    assert!(store.get(state_key.as_bytes(), Instant::now()).is_none());

    let replay = oauth_callback(
        "apple",
        &[
            ("state".to_string(), state.to_string()),
            ("error".to_string(), "access_denied".to_string()),
        ],
        &[],
        &store,
        &cache,
    )
    .await;
    assert_eq!(replay.status, 400);
}

#[tokio::test]
async fn signin_apple_rejects_unconfigured_provider() {
    let config = Arc::new(crate::ServerConfig {
        auth: AuthConfig {
            enabled: true,
            initial_publishable_key: Some("lux_pub_test".to_string()),
            ..AuthConfig::default()
        },
        ..crate::ServerConfig::default()
    });
    let store = Store::new_with_config(config);
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    bootstrap(&store, &cache, &store.config().auth).unwrap();
    bootstrap_runtime(&store, &cache, &store.config().auth).unwrap();

    seed_apple_jwks_for_test(apple_test_jwks());
    let nonce_response = route_http_response(
        "POST",
        "/auth/v1/signin/apple/nonce",
        "",
        &[],
        &[("apikey".to_string(), "lux_pub_test".to_string())],
        &store,
        &cache,
    )
    .await;
    let nonce_json: Value = serde_json::from_str(&nonce_response.body).unwrap();
    let nonce = nonce_json["nonce"].as_str().unwrap();
    let token = mint_apple_id_token("com.pompeii.app", "s", None, Some(&sha256_hex(nonce)), 3600);
    let signin_body = json!({"id_token": token, "nonce": nonce}).to_string();
    let response = route_http_response(
        "POST",
        "/auth/v1/signin/apple",
        &signin_body,
        &[],
        &[
            ("host".to_string(), "localhost".to_string()),
            ("apikey".to_string(), "lux_pub_test".to_string()),
        ],
        &store,
        &cache,
    )
    .await;
    assert_eq!(response.status, 400, "{}", response.body);
}

#[test]
fn admin_upsert_apple_provider_rejects_invalid_p8() {
    let store = apple_encrypted_store("apple-test-key");
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    bootstrap(&store, &cache, &store.config().auth).unwrap();
    bootstrap_runtime(&store, &cache, &store.config().auth).unwrap();

    // A web config with a bad .p8 is rejected up front with a clear message.
    let bad = json!({
        "apple_services_id": "com.pompeii.web",
        "apple_team_id": "TEAM123456",
        "apple_key_id": "KEY7890ABC",
        "apple_private_key": "-----BEGIN PRIVATE KEY-----\nNOTAKEY\n-----END PRIVATE KEY-----\n",
    });
    let (status, _, body) = admin_upsert_apple_provider(&bad, &store, &cache);
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("invalid Apple .p8"), "{body}");

    // The same config with a real EC .p8 passes the key check.
    let good = json!({
        "apple_services_id": "com.pompeii.web",
        "apple_team_id": "TEAM123456",
        "apple_key_id": "KEY7890ABC",
        "apple_private_key": apple_test_ec_key().private_pem,
        "redirect_uri": "https://app.example.com/auth/callback/apple",
    });
    let (status, _, body) = admin_upsert_apple_provider(&good, &store, &cache);
    assert_eq!(status, 200, "{body}");
    assert!(
        !body.contains("invalid Apple .p8"),
        "valid key wrongly rejected: {body}"
    );

    let invalid_redirect = json!({
        "apple_services_id": "com.pompeii.web",
        "apple_team_id": "TEAM123456",
        "apple_key_id": "KEY7890ABC",
        "apple_private_key": apple_test_ec_key().private_pem,
        "redirect_uri": "http://localhost:5890/auth/v1/callback/apple",
    });
    let (status, _, body) = admin_upsert_apple_provider(&invalid_redirect, &store, &cache);
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("HTTPS redirect_uri"), "{body}");

    let fragment_redirect = json!({
        "apple_services_id": "com.pompeii.web",
        "apple_team_id": "TEAM123456",
        "apple_key_id": "KEY7890ABC",
        "apple_private_key": apple_test_ec_key().private_pem,
        "redirect_uri": "https://app.example.com/auth/callback/apple#fragment",
    });
    let (status, _, body) = admin_upsert_apple_provider(&fragment_redirect, &store, &cache);
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("no fragment"), "{body}");
}

#[test]
fn admin_upsert_apple_provider_preserves_omitted_fields() {
    let store = apple_encrypted_store("apple-update-key");
    let cache = Arc::new(RwLock::new(SchemaCache::new()));
    bootstrap(&store, &cache, &store.config().auth).unwrap();
    bootstrap_runtime(&store, &cache, &store.config().auth).unwrap();
    let initial = json!({
        "enabled": true,
        "apple_services_id": "com.pompeii.web",
        "apple_team_id": "TEAM123456",
        "apple_key_id": "KEY7890ABC",
        "apple_bundle_ids": "com.pompeii.app",
        "apple_private_key": apple_test_ec_key().private_pem,
        "redirect_uri": "https://app.example.com/auth/callback/apple",
    });
    let (status, _, body) = admin_upsert_apple_provider(&initial, &store, &cache);
    assert_eq!(status, 200, "{body}");

    let (status, _, body) = admin_upsert_apple_provider(&json!({"enabled": false}), &store, &cache);
    assert_eq!(status, 200, "{body}");
    let provider = oauth_provider_config(&store, &cache, "apple", Instant::now())
        .unwrap()
        .unwrap();
    assert!(!provider.enabled);
    assert_eq!(provider.apple_services_id, "com.pompeii.web");
    assert_eq!(provider.apple_team_id, "TEAM123456");
    assert_eq!(provider.apple_key_id, "KEY7890ABC");
    assert_eq!(provider.apple_bundle_ids, "com.pompeii.app");
    assert_eq!(
        provider.apple_private_key,
        apple_test_ec_key().private_pem.trim()
    );
}
