# Lux Compatibility Contract

This document defines what compatibility means for Lux 1.0.

Lux is Redis-compatible where documented, but Lux is not a Redis clone. Lux adds
tables, auth, vectors, time series, HTTP APIs, live subscriptions, tiered
storage, and embedded APIs. Those Lux-native surfaces are part of the 1.0 public
contract only where they are documented here or in the README.

## Compatibility Classes

Lux behavior falls into five classes:

- **Compatible**: expected to match Redis/Valkey command behavior for ordinary
  clients.
- **Compatible with documented differences**: supported, but semantics differ in
  known ways.
- **Lux-native**: public Lux API with no Redis compatibility claim.
- **Experimental**: available, but not yet stable for 1.x compatibility.
- **Unsupported**: not part of 1.0.

## RESP Protocol

1.0 target:

- RESP2 command protocol.
- Binary-safe bulk strings.
- Pipelined requests with per-client response order preserved.
- Existing Redis clients can connect with `redis://`.

Not 1.0:

- RESP3.
- Redis Cluster protocol.
- Redis module API.

## Compatible Redis Surface

The command list in README is the source of truth for supported commands. The
following areas are intended to be Redis-compatible for normal client use:

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

## Documented Redis Differences

Known 1.0 differences:

- **Persistence**: Lux uses snapshots plus WAL instead of Redis AOF/RDB
  semantics. See `DURABILITY.md`.
- **RESP version**: RESP2 only.
- **Cluster**: no Redis Cluster mode.
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

The following Lux-native surfaces are part of the 1.0 target:

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

Each Lux-native surface should have examples, tests, and stable error shape
expectations before 1.0.

## Unsupported in 1.0

The following are not part of the 1.0 contract:

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

After 1.0:

- Patch releases fix bugs without public API breakage.
- Minor releases add backward-compatible public functionality.
- Major releases are required for backward-incompatible changes to documented
  public behavior.
- Deprecations should be documented in at least one minor release before
  removal in a major release.

## Release Evidence

A release is compatible enough for 1.0 only if:

- Full test suite passes.
- SDK tests pass.
- Differential tests pass for the documented Redis-compatible subset.
- Known divergences are listed here.
- Release notes call out any newly discovered compatibility gap.
