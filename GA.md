# Lux 1.0 GA Criteria

Lux 1.0.0 is ready when Lux can be treated as a stable single-node application
database runtime: users can understand its public contract, trust bounded failure
modes, operate it from documented runbooks, and upgrade within 1.x without
surprise breaking changes.

This document is the release gate for 1.0. It is intentionally stricter than a
feature checklist. New features are not GA blockers unless they are part of the
public contract below.

## Definition

Lux 1.0 promises:

- A stable public surface for RESP, HTTP, SDK, CLI, embedded Rust APIs, config
  variables, snapshot/WAL files, and Lux-native commands.
- Production-ready single-node operation.
- Redis compatibility for the documented command subset, with documented
  differences where Lux intentionally diverges.
- Bounded persistence behavior for snapshots, WAL replay, tiered storage, and
  restore.
- Secure-by-default local development and explicit production deployment
  requirements.
- Patch and minor releases that follow semantic versioning.

Lux 1.0 does not promise:

- Redis Cluster, Redis modules, or RESP3.
- Multi-node replication or distributed consensus.
- Full SQL compatibility.
- Built-in TLS termination.
- Redis-identical MULTI/EXEC isolation.
- Compatibility for undocumented internal files, private Rust modules, or
  experimental commands.

## Public Contract Gate

Required before 1.0:

- `COMPATIBILITY.md` defines supported, divergent, Lux-native, experimental, and
  unsupported behavior.
- `DURABILITY.md` defines snapshot, WAL, restore, crash recovery, fsync, and
  data-loss expectations.
- `SECURITY.md` defines supported versions, disclosure process, deployment
  threat model, and dangerous command posture.
- README links to the contract docs.
- Every public config variable is documented with default, valid range, and
  operational impact.
- Every public SDK entrypoint has stable naming and error semantics.

## Data Safety Gate

Required before 1.0:

- Full Rust test suite passes.
- SDK test suite passes.
- Crash recovery tests cover every persisted data type.
- Hard-kill tests cover writes before and after snapshots.
- Corrupt WAL, snapshot, and tiered data files fail closed: no panic, no OOM, no
  silent acceptance of invalid records.
- Restore tests prove stale WAL and cold shard data cannot overwrite restored
  snapshots.
- Lua writes through both `EVAL` and `EVALSHA` survive crash replay.
- `SAVE` and `BGSAVE` are safe from script contexts and restricted mode.

Recommended before 1.0:

- Simulated I/O error tests for snapshot write, WAL append, WAL truncate,
  tiered write, and startup recovery.
- Disk-full behavior documented and tested.
- Compound failure tests: crash during recovery, I/O error during restore, and
  partial snapshot plus WAL replay.

## Fuzzing Gate

Required before 1.0:

- Fuzz targets exist for RESP parsing, command parsing/lowering, WAL replay,
  snapshot loading, disk entry loading, table query parsing, HTTP where parsing,
  and Lua MessagePack unpacking.
- Fuzz targets are runnable locally with documented commands.
- A minimal checked-in corpus covers previously fixed malformed inputs.

Recommended before 1.0:

- Nightly or scheduled fuzz job for parser and persistence targets.
- OSS-Fuzz or equivalent continuous fuzzing for externally reachable decoders.

## Compatibility Gate

Required before 1.0:

- Redis/Valkey differential tests run for overlapping commands in strings,
  lists, hashes, sets, sorted sets, streams, bitops, geo, Lua basics, TTL, and
  transactions where Lux claims compatibility.
- Known divergences are written down in `COMPATIBILITY.md`.
- BullMQ-compatible flows have an integration smoke test.
- Client compatibility smoke tests cover at least `redis-cli`, Node/ioredis,
  redis-py, go-redis, and the Lux SDK.

## Security Gate

Required before 1.0:

- Non-loopback unauthenticated RESP listeners are rejected by default or require
  an explicit unsafe opt-in.
- HTTP snapshot, restore, admin auth, and mutation surfaces require operator or
  service-level credentials as documented.
- App auth is deny-by-default for end-user tokens unless grants exist.
- Auth-owned tables cannot be read or mutated through generic table, HTTP, or
  key-value routes.
- Lua has no filesystem, process, module loading, or debug access.
- Lua cannot run blocking, transaction-control, subscription, `SAVE`, or
  `BGSAVE` commands.
- Resource limits exist for HTTP body, RESP request bulk length, sparse string
  growth, snapshot field sizes, Lua instruction count, and MessagePack
  container sizes.
- `SECURITY.md` explains the deployment model and vulnerability reporting path.

## Operations Gate

Required before 1.0:

- Backup and restore runbook.
- Upgrade and rollback notes for patch/minor releases.
- Config reference.
- Health endpoint documented.
- Docker image and binary release process documented.
- Release artifacts include checksums.
- Logs are sufficient to diagnose startup, recovery, bind, restore, and
  persistence failures.
- Metrics or `INFO` fields expose enough persistence and runtime state for
  production monitoring.

## Performance Gate

Required before 1.0:

- Benchmark commands and hardware are documented.
- Current benchmarks are reproducible from the repo.
- Benchmarks distinguish single-key, multi-key, pipelined, table, vector,
  time-series, and tiered-storage workloads.
- Release notes avoid claiming broad performance wins outside measured cases.

## Release Process

The 1.0 process should be:

1. Merge all blocker fixes and docs.
2. Cut `1.0.0-rc.1`.
3. Freeze public API except blocker fixes.
4. Run full Rust tests, SDK tests, compatibility tests, fuzz corpus, and release
   benchmarks.
5. Run an overnight stress/soak profile with memory mode, tiered mode, auth
   enabled, Lua scripts, snapshots, WAL replay, and HTTP live subscriptions.
6. Publish release candidate notes with known limitations.
7. Repeat release candidates until no GA blockers remain.
8. Tag `v1.0.0` and publish immutable artifacts.

## References

- Semantic Versioning: https://semver.org/spec/v2.0.0.html
- SQLite testing model: https://www.sqlite.org/testing.html
- Redis security model: https://redis.io/docs/latest/operate/oss_and_stack/management/security/
- Valkey security model: https://valkey.io/topics/security/
