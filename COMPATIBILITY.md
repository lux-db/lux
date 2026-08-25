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
- `CLIENT` -- compatibility shim that returns `OK`; Redis client state and
  metadata are not maintained.
- `COMMAND` -- metadata parity incomplete.
- `CONFIG` -- only the zset listpack/ziplist entry threshold is read and
  changed; other settings are not implemented.
- `INFO` -- reports Lux's server, client, storage, persistence, keyspace, and
  push fields rather than the complete Redis field set.
- `LATENCY` -- Lux does not retain Redis latency-monitor samples; reporting
  forms return an empty array and `LATENCY RESET` returns `0`.
- `MEMORY USAGE` and `OBJECT ENCODING` -- available for supported Lux values;
  other Redis subcommands and metadata are not implemented.
- `DEBUG` -- registered as a no-op compatibility shim.
- `RESET` -- returns Redis's `+RESET` status, but connection-state parity is
  incomplete.
- `DUMP`/`RESTORE` -- implemented with a Lux-internal value format (not RDB;
  round-trips within Lux). `TOUCH` returns the key count without an
  access-recency effect.
- `HELLO` -- identifies Lux as RESP2. RESP3 negotiation and RESP3 command
  protocol are unsupported.
- `LASTSAVE` -- currently returns the server's current Unix time rather than
  the timestamp of the last successful snapshot.
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
  between steps by other clients. Redis avoids this through single-threaded
  execution.
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

- Tables: `TCREATE`, `TINSERT`, `TSELECT`, `TUPDATE`, `TDELETE`, `TDROP`,
  `TCOUNT`, `TSCHEMA`, `TLIST`, `TALTER`, `TINDEX`, `TDROPINDEX`.
- Auth grants: `GRANT`, `REVOKE`, app-auth tables, app-auth HTTP endpoints, and
  row-level grants.
- Vectors: `VSET`, `VGET`, `VSEARCH`, `VCARD`, and vector table columns.
- Time series: `TSADD`, `TSMADD`, `TSGET`, `TSRANGE`, `TSMRANGE`, `TSINFO`.
- Key subscriptions: `KSUB`, `KUNSUB`.
- HTTP REST API.
- Live WebSocket API.
- Embedded Rust API.
- Lux TypeScript SDK.
- Lux CLI.

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
