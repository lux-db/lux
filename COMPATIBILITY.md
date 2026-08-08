# Lux Compatibility

This document defines the Redis-compatible, Lux-native, divergent, and
unsupported surfaces exposed by Lux.

Lux is Redis-compatible where documented, but Lux is not a Redis clone. Lux adds
tables, auth, vectors, time series, HTTP APIs, live subscriptions, tiered
storage, and embedded APIs. A Lux-native surface is public only where it is
documented here or in the README.

## Compatibility Classes

Lux behavior falls into five classes:

- **Compatible**: expected to match Redis/Valkey command behavior for ordinary
  clients.
- **Compatible with documented differences**: supported, but semantics differ in
  known ways.
- **Lux-native**: public Lux API with no Redis compatibility claim.
- **Experimental**: available, but not yet stable for 1.x compatibility.
- **Unsupported**: not implemented or intentionally outside Lux's scope.

These compatibility classes describe behavior. The 1.0 support lifecycle is
separate:

- **Stable**: part of the Lux 1.x compatibility contract. Patch and minor
  releases preserve it, subject to documented bug and security fixes.
- **Preview**: shipped for evaluation, but may change in a minor release. Preview
  behavior is never required to adopt Lux 1.0.
- **Excluded**: not part of the Lux 1.0 contract, even if a compatibility alias
  or Cloud-only client helper exists.

## Lux 1.0 Support Matrix

| Surface | 1.0 status | Contract | Executable owner |
|---|---|---|---|
| Engine RESP | Stable | RESP2 plus every `Supported` and `LuxNative` command in the command inventory. `Partial` commands are stable only for the exact behavior listed below. | `tests/redis_parity_inventory.rs` and command-family integration tests |
| Engine HTTP `/v1` | Stable | Version discovery, migrations, exec, KV, tables, time series, vectors, push, snapshot, and restore route families listed below. | `tests/http.rs`, `tests/auth.rs`, `tests/push.rs`, `tests/live_ws.rs`, and migration tests |
| Engine app auth `/auth/v1` | Stable | Email/password, anonymous auth, refresh and PKCE flows, user/session lifecycle, Google/GitHub/Apple OAuth, project keys, admin users/providers/settings, and JWKS. | `tests/auth.rs` and auth unit tests |
| Engine live WebSocket `/live` | Stable | Authenticated key and grant-scoped table subscriptions using the documented message shapes. | `tests/live_ws.rs` |
| CLI local/self-hosted workflow | Stable | `init`, `start`, `stop`, `studio`, local `status`, `exec`, `connect`, `doctor`, `version`, `update engine`, `update studio`, migrations, auth providers, push, seed, encryption, types, and local env profiles. | CLI unit tests and `cli/tests/e2e-local.sh` |
| CLI Cloud control-plane workflow | Excluded | Login, linking, project/key lifecycle, Cloud env profiles, logs, snapshots, restarts/updates, billing-aware create/destroy, and Cloud targets are maintained with Lux Cloud, not gated by OSS Engine 1.0. | Cloud integration tests |
| TypeScript SDK | Stable | Direct RESP client plus HTTP project/browser/SSR clients for auth, tables, vectors, time series, realtime, and push. | `sdk/tests/*.test.ts` plus SDK typecheck/build |
| TypeScript SDK storage client | Excluded | Object storage is Cloud-only; the OSS engine has no local object-storage service. | `sdk/tests/storage.test.ts` against its Cloud contract |
| Swift SDK | Stable | Authentication/session handling and APNs device registration for Apple platforms. | `lux-swift/Tests/LuxTests` |
| Swift data, realtime, storage, and push sending | Excluded | The 1.0 Swift contract is auth plus device registration, not a general database client. | Explicitly outside the Swift package surface |
| Local Studio | Stable | The local project UI, capability negotiation, command editor, migrations, tables, vectors, queues, time series, realtime, snapshots, auth, and push. | Studio contract/navigation tests plus CLI local-stack E2E |
| Local Studio storage, logs, and domains | Excluded | These require Cloud services and remain visibly Cloud-only in local Studio. | Studio navigation contract tests |
| Embedded Rust API | Stable | Documented `ServerConfig`, `run_with_config`, `ServerHandle`, and `EmbeddedClient` behavior. | `tests/public_api.rs` |
| Undocumented Rust exports | Excluded | Public Rust symbols not documented in the README or rustdoc examples carry no 1.x compatibility promise. | Explicit exclusion |
| Workbenches | Stable | The six bundled `core`, `auth`, `migrations`, `realtime`, `push`, and `durability` Workbenches. | `tests/workbench_inventory.rs` |
| First-party Python and Go SDKs | Excluded | Python and Go applications use standard RESP2 clients for 1.0; dedicated first-party SDKs are not GA blockers. | RESP compatibility suite |
| Multi-node clustering/replication | Excluded | Single-node Lux only. | Explicit exclusion |

The stable HTTP paths are:

- `GET /v1` and `GET /v1/version` for the authenticated engine capability
  manifest.
- `GET /v1/migrations` and `POST /v1/migrations/{plan,apply,repair}`.
- `POST /v1/exec`.
- `/v1/kv/*`, `/v1/keys`, `/v1/dbsize`, and `/v1/ping`.
- `/v1/tables` and `/v1/tables/{table}` including schema, count, point reads,
  inserts, updates, and deletes.
- `/v1/ts/*` and `/v1/vectors/*`.
- `/v1/push/*` for user device lifecycle, service-key sending, APNs/VAPID
  configuration, and admin inspection.
- `GET /v1/snapshot` and `POST /v1/restore`.
- `/auth/v1/*` and `/live` as described above.

Except for the stable `/auth/v1/*` and `/live` surfaces, every unversioned alias
of a `/v1` route is **Preview**. The legacy flat shapes (`/get/*`, `/set/*`,
`/del/*`, `/incr/*`, `/decr/*`, `/hgetall/*`, and `/keys/*`) are also Preview
with or without the `/v1` prefix. New integrations must use the stable route
families listed above; compatibility aliases do not carry a 1.x path-stability
guarantee.

## RESP Protocol

Current protocol:

- RESP2 command protocol.
- Binary-safe bulk strings.
- Pipelined requests with per-client response order preserved.
- Existing Redis clients can connect with `redis://`.

Not supported:

- RESP3.
- Redis Cluster protocol.
- Redis module API.

## Compatible Redis Surface

The README lists common commands. This document defines their compatibility
class, and `tests/redis_parity_inventory.rs` keeps the command registry
classified. The following areas are intended to be Redis-compatible for normal
client use unless a partial behavior or difference is documented below:

- Strings and bit operations.
- Keys, TTL, expiry, rename, scan, and type inspection.
- Lists, blocking list pops, and list movement.
- Hashes.
- Sets.
- Sorted sets and blocking sorted-set pops.
- Geo commands.
- Streams and consumer groups.
- HyperLogLog.
- Pub/Sub and pattern Pub/Sub.
- Lua basics: `EVAL`, `EVALSHA`, `SCRIPT LOAD`, `SCRIPT EXISTS`,
  `SCRIPT FLUSH`, `redis.call`, `redis.pcall`, `KEYS`, `ARGV`, `cjson`, and
  `cmsgpack`.
- Server basics: `PING`, `ECHO`, `QUIT`, `HELLO`, `INFO`, `TIME`, `AUTH`,
  `SELECT`, `COMMAND`, `OBJECT`, and `MEMORY`.

Compatibility must be backed by integration tests and, where practical,
Redis/Valkey differential tests.

## Redis OSS/Core Inventory

The pinned Redis OSS/core command inventory lives in
`tests/redis_parity_inventory.rs`. It derives Lux's implemented RESP surface by
parsing the in-repo command registry in `src/cmd/mod.rs`, then classifies each
known command as one of:

- **Supported**: registered by Lux and expected to behave like Redis for normal
  client use.
- **Partial**: registered by Lux, but currently a compatibility shim, partial
  implementation, or documented semantic difference.
- **Missing**: Redis OSS/core command not currently registered by Lux and
  tracked for this parity project.
- **Excluded**: Redis OSS command intentionally outside this project.
- **Lux-native**: public Lux command with no Redis compatibility claim.

For local compatibility exploration, run selected Valkey Tcl suites against a
running Lux RESP listener:

```sh
# Terminal 1
cargo build
LUX_PORT=6379 ./target/debug/lux

# Terminal 2
VALKEY_DIR="$PWD/../valkey" LUX_PORT=6379 just valkey-compat
```

The recipe is intentionally local/manual. It runs Redis OSS/core-oriented suites
for strings, keyspace, lists, hashes, sets, sorted sets, streams, scripting, and
transactions in durable mode so one missing command does not stop the whole
report, with `VALKEY_TIMEOUT` defaulting to 60 seconds to keep blocking-command
failures bounded. It does not run Redis Stack/module suites, cluster suites,
replication suites, or CI gates. It ignores Valkey internal encoding checks and
skips individual tests whose assertions are about replication, command
propagation, or Valkey's exact expiry scheduling; those are separate
compatibility targets from single-node command semantics.

Current partial/stub surfaces:

- `BGSAVE` -- performs a consistent save synchronously rather than scheduling a
  background save.
- `CLIENT` -- network connections maintain `SETNAME`/`GETNAME` state.
  `SETINFO LIB-NAME` and `SETINFO LIB-VER` are accepted as explicit metadata
  no-ops for modern clients; other subcommands return an unsupported error.
- `COMMAND` -- `COMMAND COUNT` is supported. Metadata forms return an explicit
  unsupported error.
- `CONFIG` -- only the zset listpack/ziplist entry threshold is read and
  changed; other settings are not implemented.
- `INFO` -- reports Lux's server, client, storage, persistence, keyspace, and
  push fields rather than the complete Redis field set.
- `LATENCY` -- Lux does not retain Redis latency-monitor samples; reporting
  forms return an empty array and `LATENCY RESET` returns `0`.
- `MEMORY USAGE` and `OBJECT ENCODING` -- available for supported Lux values;
  other subcommands return an explicit unsupported error.
- `DEBUG` and `RESET` -- registered for compatibility but return explicit
  unsupported errors.
- `DUMP`/`RESTORE` -- implemented with a Lux-internal value format (not RDB;
  round-trips within Lux). `TOUCH` returns the key count without an
  access-recency effect.
- `HELLO` -- identifies Lux as RESP2 and supports `HELLO 2 AUTH`. RESP3 and
  `HELLO SETNAME` return explicit errors; use `CLIENT SETNAME` separately.
- `LASTSAVE` -- returns the timestamp of the last successfully installed
  snapshot, or `0` before the first save.
- `FUNCTION LIST` -- returns an empty library list; other Redis Functions
  subcommands return an explicit unsupported error.
- `SELECT` -- only database `0` is accepted. `SWAPDB` returns an explicit
  unsupported error because Lux exposes one logical database.
- `WAIT` -- returns `0` because Lux has no replicas.

Current missing Redis OSS/core command groups:

- Streams: `XSETID` (top-level command). Consumer-group lifecycle
  (`XGROUP CREATE`/`SETID`/`DESTROY`/`CREATECONSUMER`/`DELCONSUMER`/`HELP`)
  and `XINFO STREAM`/`GROUPS`/`CONSUMERS` are implemented.
- Scripting/functions: `EVAL_RO`, `EVALSHA_RO`, `FCALL`, `FCALL_RO`.
- Admin/diagnostics and key migration: `ACL`, `BGREWRITEAOF`, `LOLWUT`,
  `MONITOR`, `MOVE`, `ROLE`, `SLOWLOG`.

Explicitly excluded from this parity project:

- Redis Cluster commands and cluster routing behavior.
- Redis multi-node replication/failover commands and Sentinel behavior.
- Redis module APIs and Redis Stack/module command families.
- Exact Redis AOF/RDB persistence semantics.
- Process lifecycle commands such as `SHUTDOWN`.

## Documented Redis Differences

Known differences:

- **Persistence**: Lux uses snapshots plus WAL instead of Redis AOF/RDB
  semantics. See `DURABILITY.md`.
- **Hash field TTLs**: `HEXPIRE`/`HTTL`/`HGETEX`/`HGETDEL` and the full
  family are supported. Expired fields are hidden from reads immediately;
  a hash whose last field expires is reclaimed on the next write that
  touches it (or an active cycle), not necessarily at the instant of
  expiry, so `EXISTS` may briefly report an all-expired hash.
- **Serialization / migration**: `DUMP`/`RESTORE` use a Lux-internal value
  format that round-trips within Lux; the payload is not Redis RDB-compatible.
  `MIGRATE` (inter-node key movement) and `WAITAOF` (AOF fsync wait) return
  explicit unsupported errors; use `DUMP`/`RESTORE` to move a key between Lux
  instances.
- **RESP version**: RESP2 only.
- **Cluster**: no Redis Cluster mode.
- **Sharded Pub/Sub**: `SPUBLISH`/`SSUBSCRIBE`/`SUNSUBSCRIBE` return explicit
  unsupported errors (they exist for Redis Cluster, which Lux does not run). Use
  `PUBLISH`/`SUBSCRIBE`. `PUBSUB CHANNELS`/`NUMSUB`/`NUMPAT` are supported.
- **Transactions**: `MULTI`/`EXEC` is supported with WATCH-based optimistic
  concurrency. Lux commands in an EXEC execute sequentially and may be observed
  between steps by other clients. Each mutating command also crosses its own
  durability boundary, so a process crash during EXEC can recover a completed
  prefix of an EXEC whose response was never acknowledged. Redis avoids both
  differences through its single-threaded execution and transaction-aware AOF
  framing.
- **Concurrency**: Lux is sharded and concurrent. Commands touching different
  shards can execute in parallel.
- **Restricted mode**: Lux may reject scan-heavy or administrative commands
  where configured.
- **Lua sandbox**: Lux intentionally removes filesystem, process, module
  loading, debug, and garbage-collector globals. Lua cannot execute blocking,
  transaction-control, subscription, `SAVE`, or `BGSAVE` commands.
- **Resource limits**: Lux caps RESP request size, HTTP body size, sparse string
  growth, snapshot field sizes, Lua VM instructions, and MessagePack container
  sizes. Redis may differ on exact limits.

## Lux-Native Public Surface

The following Lux-native surfaces are public:

- Tables: `TCREATE`, `TINSERT`, `TUPSERT`, `TSELECT`, `TUPDATE`, `TDELETE`,
  `TGET`, `TSET`, `TDROP`, `TCOUNT`, `TSCHEMA`, `TLIST`, `TALTER`, `TINDEX`,
  `TDROPINDEX`.
- Auth grants: `GRANT`, `REVOKE`, app-auth tables, app-auth HTTP endpoints, and
  row-level grants.
- Vectors: `VSET`, `VGET`, `VSEARCH`, `VCARD`, and vector table columns.
- Time series: `TSADD`, `TSMADD`, `TSGET`, `TSRANGE`, `TSMRANGE`, `TSINFO`.
- Key subscriptions: `KSUB`, `KUNSUB`.
- Atomic conditional deletion: `DELIFEQ`.
- Engine management: `LUX VERSION`, `LUX MIGRATE`, and `LUX PUSH`.
- Encryption administration: `ENC`.
- HTTP REST API.
- Live WebSocket API.
- Embedded Rust API.
- Lux TypeScript SDK.
- Lux CLI.

## Configuration Contract

Every standalone-engine runtime variable is inventoried by
`tests/config_inventory.rs` and documented in the README. Those variables are
**Stable** for 1.x, including the legacy `LUX_ENCRYPTION_KEY`,
`LUX_ENCRYPTION_KEY_ID`, and `LUX_ENCRYPTION_KEYS` bootstrap forms. New
deployments should use persisted `ENC` state and an externally supplied
`LUX_ENC_SEAL_KEY`; the legacy forms remain readable for compatibility.

`LUX_PUSH_ALLOW_PRIVATE_ENDPOINTS` set to `1` is **Excluded** from the
production contract. It disables the Web Push private-network endpoint guard
for local integration tests and must not be set in a production deployment.

The CLI's stable local configuration file is `lux/config.toml`. Its supported
keys are `project_id`, `project_name`, `local_http_port`, `local_resp_port`, and
`engine_version`; unknown TOML keys and comments are preserved. Files under
`lux/migrations/*.lux` and `lux/seed.lux` are stable UTF-8 Lux command files.
The private `lux/.env-profiles` representation and `~/.lux/config.json` login
cache are implementation details, not interchange formats.

CLI environment variables have the following 1.0 status:

| Variables | Status | Purpose |
|---|---|---|
| `LUX_ENGINE_URL`, `LUX_ENGINE_PASSWORD` | Stable | Select and authenticate a local or self-hosted engine. |
| `LUX_URL` | Stable | Override the browser-reachable engine URL used when Studio starts. |
| `LUX_OPENROUTER_KEY`, `OPENROUTER_API_KEY` | Preview | Optional localhost Studio AI assistance. |
| `LUX_API_URL`, `LUX_TOKEN` | Excluded | Lux Cloud control-plane configuration. |
| `LUX_PROJECT_ID`, `LUX_DIRECT_URL`, `LUX_PUBLISHABLE_KEY`, `LUX_SECRET_KEY` | Stable outputs | Values written by `lux env`; applications consume them, while the CLI does not treat them as command inputs. |
| `LUX_AUTH_URL`, `LUX_HTTP_URL` | Excluded | Obsolete generated aliases removed when a modern profile is activated. |

`LUX_BUILD_SHA` is an internal build-time metadata value, not a runtime
configuration interface.

## File Compatibility

| File or payload | 1.0 status | Compatibility promise | Executable owner |
|---|---|---|---|
| `lux.dat` snapshot | Stable | Lux writes snapshot version 3 and reads versions 1, 2, and 3. Every Lux 1.x release must continue reading all three. | snapshot unit tests, `tests/http.rs`, and crash-recovery tests |
| `DUMP`/`RESTORE` payload | Stable within Lux | Lux 1.x preserves read compatibility for its own payloads. They are not Redis RDB payloads. | `tests/server.rs` |
| `lux/migrations/*.lux` | Stable | UTF-8 command files with SHA-256 ledger identity; filename/content mismatches fail until explicitly repaired. | migration unit/integration tests and CLI E2E |
| `lux/config.toml` | Stable | The five documented keys above retain their meaning throughout 1.x; unknown keys/comments survive CLI edits. | CLI config unit tests |
| WAL (`LXW1`) and tiered data (`LXD1`) | Excluded as interchange formats | They are private restart/recovery files. Durability is guaranteed as documented, but external tools must not parse or copy them independently of the complete data directory. | disk, tiered, reliability, and crash-recovery tests |
| Encryption envelope/state (`LUXENC2`, `LUXENCSTATE1`) | Excluded as interchange formats | Private authenticated-encryption formats; access them only through Lux commands and complete snapshots. | encryption and corruption tests |

## Unsupported

The following are outside the documented public surface:

- Redis Cluster.
- Redis modules.
- RESP3.
- Built-in TLS termination.
- Multi-node replication.
- Distributed transactions.
- Full SQL grammar or PostgreSQL compatibility.
- Redis-identical transaction isolation.
- Undocumented internal keys and on-disk implementation details beyond the
  durability promises in `DURABILITY.md`.

## Versioning Rules

Starting with 1.0:

- Patch releases fix bugs without public API breakage.
- Minor releases add backward-compatible public functionality.
- Major releases are required for backward-incompatible changes to documented
  public behavior.
- Deprecations are documented in at least one minor release before removal in a
  major release.
