# Table Feature Interaction Matrix

This is the regression map for table features that share derived state. A table
change is not done when the leaf feature works in isolation; it also has to keep
these interactions correct across snapshots, WAL replay, tiered storage, indexes,
constraints, and query planning.

## How to Use This Matrix

- Add a row when a table feature introduces stored or derived state.
- Mark the invariant that must survive insert, update, delete, upsert, snapshot,
  and WAL replay.
- Add at least one regression test for every high-risk `Required` interaction.
- If an interaction is intentionally unsupported, test the rejection path.
- Prefer adversarial tests that compose features. Single-feature happy-path tests
  do not catch index/WAL/TTL/order regressions.
- Every row with `Status = Gap` is either unsupported behavior that needs an
  explicit rejection test, or supported behavior that needs a regression test.

## Derived State Surfaces

Most table bugs come from writing one surface and forgetting another. Any feature
that touches a user-visible value needs an answer for each surface below.

| Surface | What can go stale or leak | Required check |
| --- | --- | --- |
| Row hash | canonical stored field bytes, hidden TTL field | insert/update/upsert/delete replace the right fields and do not leave hidden state behind |
| Primary ordering set | default scan order for INT and non-INT primary keys | WAL replay and updates preserve original order unless the user asked for another order |
| Scalar indexes | string/numeric/bool/timestamp lookup sets and sorted sets | update/delete/upsert remove old entries before adding new entries |
| Unique indexes | value-to-primary-key holder map | stale holders are purged, expired rows do not block reuse, updates rekey correctly |
| Path indexes | JSON/ARRAY extracted scalar values | values match full-scan semantics and never expose encrypted roots |
| Vector indexes | vector bytes plus distance candidate planning | updates/deletes/replay keep `NEAR` candidates in sync with row hashes |
| TTL index | global expiry sorted set plus per-row hidden deadline | TTL clear removes both surfaces; replay does not resurrect old deadlines |
| WAL | command log for crash recovery | replay reproduces rows, derived indexes, order, TTL, and constraints without plaintext leaks |
| Snapshots | compact persisted image | snapshot/load preserves encrypted bytes, derived state, expiry, and schema flags |
| Query planner | index candidate selection, fallback scan, OR planning, joins | indexed and non-indexed paths return the same rows and reject unsupported encrypted access |
| Live/change events | emitted row payloads and delete/update signals | events expose allowed plaintext only after normal table read rules |

## Encryption Interactions

| Feature | Interaction | Required invariant | Status | Coverage |
| --- | --- | --- | --- | --- |
| `ENCRYPTED` scalar | row storage | row hash, snapshots, tiered storage, and WAL never contain plaintext | Covered | `encrypted_field_stores_ciphertext_and_returns_plaintext`, `encrypted_snapshot_does_not_store_plaintext_and_loads`, `encrypted_wal_does_not_store_plaintext_and_replays_latest_update` |
| `ENCRYPTED SEARCHABLE` | equality filter | `WHERE col = value` uses blind indexes and returns plaintext rows | Covered | `encrypted_field_stores_ciphertext_and_returns_plaintext` |
| `ENCRYPTED` non-searchable | equality / range filters | equality requires `SEARCHABLE`; range and other operators reject | Covered | `encrypted_query_guards_reject_unsupported_filters_and_ordering` |
| `ENCRYPTED` mutation predicates | update/delete `WHERE` filters | mutation scans use the same encrypted predicate rules as reads | Covered | `encrypted_mutation_guards_reject_unsupported_predicates_and_conflicts` |
| `ENCRYPTED` | `ORDER BY` | encrypted columns cannot be ordered, including `json.path` ordering on encrypted roots | Covered | `encrypted_query_guards_reject_unsupported_filters_and_ordering` |
| `ENCRYPTED UNIQUE SEARCHABLE` | insert/update unique index | uniqueness is enforced on plaintext semantics and stale blind-index entries are removed on update | Covered | `encrypted_searchable_unique_uses_plaintext_semantics`, `encrypted_searchable_unique_rekeys_on_update` |
| `ENCRYPTED UNIQUE SEARCHABLE` | delete unique/index cleanup | deleting a row removes blind unique holders and searchable index members so values can be reused | Covered | `encrypted_searchable_unique_delete_cleans_blind_indexes_and_allows_reuse` |
| `ENCRYPTED UNIQUE SEARCHABLE` | upsert conflict target | `TUPSERT ... ON CONFLICT encrypted_unique_col` finds and updates the matching row | Covered | `encrypted_upsert_on_searchable_unique_replays_with_ttl_clear` |
| `ENCRYPTED` non-searchable | upsert conflict target | non-searchable encrypted columns cannot be used as conflict targets via full-table decrypting scans | Covered | `encrypted_mutation_guards_reject_unsupported_predicates_and_conflicts` |
| `ENCRYPTED` | `RETURNING` | insert/update/delete returning paths emit plaintext rows while committed storage remains ciphertext | Covered | `encrypted_returning_paths_emit_plaintext_and_store_ciphertext` |
| `ENCRYPTED` defaults | schema/WAL literals | encrypted columns reject `DEFAULT` so schema metadata and raw `TALTER` WAL never persist default plaintext | Covered | `encrypted_field_rejects_invalid_combinations`, `encrypted_add_column_rejects_default_and_keeps_existing_rows_readable` |
| `ENCRYPTED` add column | nullable backfill | adding a nullable encrypted column leaves existing rows readable without storing undecryptable empty bytes | Covered | `encrypted_add_column_rejects_default_and_keeps_existing_rows_readable` |
| `ENCRYPTED` | HTTP table routes | JSON table create/insert/query paths honor encrypted schema flags, return plaintext rows, and store ciphertext | Covered | `http_table_routes_round_trip_encrypted_columns_without_raw_plaintext`, `http_table_create_rejects_encrypted_default` |
| `ENCRYPTED` + WAL | nonnumeric primary key ordering | replayed updates preserve original default scan order | Covered | `encrypted_wal_replay_preserves_uuid_row_order_after_update` |
| `ENCRYPTED` + WAL | TTL clear | replay of `TTL 0` removes both TTL index and hidden row deadline | Covered | `encrypted_wal_replay_clears_hidden_ttl_field` |
| `ENCRYPTED` + upsert + WAL | conflict update with TTL clear | replay preserves upserted row identity, updated plaintext, unique blind index, and cleared TTL state | Covered | `encrypted_upsert_on_searchable_unique_replays_with_ttl_clear` |
| `ENCRYPTED JSON` | `TINDEX json.path` | path indexes are rejected so scalar path values are not stored in plaintext index keys | Covered | `tindex_rejects_encrypted_json_column` |
| `ENCRYPTED JSON` | JSON path filters | dot-path filters on encrypted roots reject instead of decrypting every row or leaking planner behavior | Covered | `encrypted_query_guards_reject_unsupported_filters_and_ordering` |
| `ENCRYPTED JSON/ARRAY` | searchable equality | `SEARCHABLE` is rejected for JSON/ARRAY until whole-document canonical search semantics are deliberately designed | Covered | `encrypted_json_and_array_cannot_be_searchable_and_paths_reject` |
| `ENCRYPTED` | joins | join keys cannot be encrypted; reject instead of doing decrypted hash joins | Covered | `encrypted_join_keys_are_rejected` |
| `ENCRYPTED` | live/change events | table streams emit normal plaintext row payloads; raw key subscriptions emit only key metadata and not encrypted values | Covered | `live_encrypted_table_streams_plaintext_rows_without_key_event_value_leak` |
| `ENCRYPTED SEARCHABLE` | RLS grants | row-scoped grants over encrypted searchable columns resolve through blind indexes; non-searchable encrypted grant predicates reject | Covered | `read_grant_on_encrypted_searchable_column_filters_through_blind_index`, `grant_on_encrypted_non_searchable_column_is_rejected` |
| encryption key rotation | mixed-key rows | old keys decrypt; only active key writes; snapshots and WAL replay preserve key ids across update and search | Covered | `encrypted_key_rotation_survives_wal_replay_update_and_search`, `encrypted_snapshot_does_not_store_plaintext_and_loads` |

## Core Table Interaction Backlog

These are the next high-value compatibility rows outside encryption. They should
be filled in as regressions when touching the corresponding subsystem.

| Feature | Interaction | Required invariant | Status |
| --- | --- | --- | --- |
| `SEQUENCE PARTITION BY` | concurrent insert/upsert | generated values are unique and monotonic within partition | Gap |
| `SEQUENCE PARTITION BY` | WAL replay/snapshot | counters resume at or above the highest committed value per partition | Gap |
| `SEQUENCE PARTITION BY` | delete/reinsert | deleted rows do not allow duplicate sequence reuse | Gap |
| Foreign keys | non-INT references | FK checks use encoded logical value semantics for all supported key types | Gap |
| Foreign keys | TTL expiry | expired parent rows cannot satisfy new child inserts; expiry cleanup removes dependent state according to declared behavior | Gap |
| Foreign keys | delete/cascade | row hash, indexes, unique holders, TTL entries, and live events agree after cascade | Gap |
| Vector fields | `NEAR` with `WHERE` | vector candidate planning and scalar filters produce the same rows as full filtering | Gap |
| Vector fields | update/delete/replay | vector index entries are replaced or removed with no stale candidates | Gap |
| JSON/ARRAY paths | index vs full scan | `TINDEX` results exactly match non-indexed dot-path filters for missing/null/type mismatch cases | Gap |
| JSON/ARRAY paths | update/delete/replay | path index entries are removed on update/delete and rebuilt on WAL replay | Gap |
| Row TTL | unique reuse | expired rows do not block unique values, and purging removes all index forms | Gap |
| Row TTL | snapshot downtime | expired rows are not resurrected after load; future deadlines keep their remaining absolute deadline | Gap |
| Row TTL | live events | automatic expiry emits the intended delete/update signal exactly once | Gap |
| RLS grants | joins/subqueries | policy evaluation cannot be bypassed through joined predicates or aliased columns | Gap |
| RLS grants | OR predicates | every branch is checked under the same access rules as simple predicates | Gap |
| RLS grants | writes | update/delete policies and `WITH CHECK` observe generated/default/encrypted values consistently | Gap |
| `RETURNING` | generated/default values | returned rows match committed rows after defaults, serials, UUIDs, TTL, and encryption transforms | Gap |
| `RETURNING` | multi-row mutations | partial failures do not emit rows for uncommitted mutations | Gap |
