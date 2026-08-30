# Lux Durability Contract

This document defines Lux persistence and recovery behavior.

Lux uses snapshots plus a write-ahead log (WAL). It does not use Redis AOF. The
durability contract is intentionally explicit so users understand the data-loss
envelope and operators can test recovery procedures.

## Storage Model

Lux persists state through:

- `lux.dat`: point-in-time snapshot of the in-memory database.
- One ordered mutation journal: committed effects replayed after the snapshot.
- Tiered storage files: cold entries evicted from memory when tiered mode is
  enabled.

Storage layout and durability are independent:

- `memory` keeps live values in memory. Persistent policies place its WAL under
  `{data_dir}/journal`.
- `tiered` adds disk-backed cold storage. Its WAL remains in the tiered storage
  directory so existing deployments keep their current recovery files.

A persistent runtime holds an exclusive advisory lock on each configured state
root for its lifetime. Starting a second Lux runtime against the same data or
tiered-storage directory fails before recovery, preventing concurrent writers
from corrupting snapshots, journals, or tiered files. The backing filesystem
must preserve POSIX advisory-lock semantics; use Docker named volumes rather
than macOS host bind mounts when relying on cross-container exclusion.

Persistent startup loads the snapshot, replays valid legacy per-shard WAL files
from pre-1.0 versions, then replays the ordered journal and rebuilds tiered
indexes as needed. New writes use only the ordered journal. Lux refuses to start
when a layout change would hide known journal or tiered shard state.

## Durability Policies

- `ephemeral` performs no automatic snapshot load/save and creates no WAL. It
  must be chosen explicitly.
- `every_second` appends before mutation and synchronizes the WAL every 1,000 ms
  by default. The interval can be lowered to 1 ms.
- `always_sync` appends and synchronizes before applying each mutation.

`always_sync` is the default for both the standalone binary and
`ServerConfig`. `LUX_STORAGE_MODE` never changes the durability policy.
`INFO`, `GET /v1`, and `GET /v1/version` report the effective layout, policy,
sync interval, and whether the journal is enabled.

## Acknowledgement Guarantee

By default, Lux appends and synchronizes each journal frame before applying the
mutation or acknowledging success. Once a client receives a successful reply,
that mutation must recover after a process crash, operating-system crash, or
power loss, subject to the persistence guarantees provided by the filesystem
and storage hardware.

`every_second` is an explicit performance tradeoff comparable to Redis
`appendfsync everysec`. Under that policy:

- Successfully fsynced WAL frames must recover.
- Writes acknowledged after the last fsync may be lost on sudden power failure.
- The maximum expected power-loss window is approximately the configured sync
  interval (1,000 ms unless changed).
- A failed periodic fsync emits a critical runtime error, increments the
  `persistence_err_wal_fsync` counter, and fences subsequent mutations until
  restart. The configured loss bound cannot be promised for writes accepted
  since the last successful sync when the storage device fails.
- `ServerHandle::shutdown_and_wait` stops new work, drains accepted requests,
  and performs a checked final WAL sync before returning.

## Graceful Shutdown

The standalone server handles SIGINT and SIGTERM. It closes its listeners,
allows accepted requests to finish within the configured grace period, fences
later mutations, and then synchronizes the authoritative journal. Embedded
hosts get the same lifecycle through `ServerHandle::shutdown_and_wait`; use
`shutdown_and_wait_detailed` to choose a grace period and distinguish a clean
drain from forced cancellation.

`LUX_SHUTDOWN_TIMEOUT_MS` controls the standalone grace period and defaults to
30,000 ms. The accepted range is 1 through 300,000 ms. A timeout bounds the
request-drain phase, not unsafe cancellation cleanup: Lux still waits until
cancelled mutation tasks can no longer race the final persistence barrier.

Standalone exit status distinguishes the result:

- `0`: clean drain and successful final sync.
- `2`: the drain deadline elapsed, remaining work was cancelled, and the final
  sync succeeded.
- `3`: the final persistence sync failed.
- `1`: configuration or another runtime failure.

Docker Compose and `lux stop` give the engine 35 seconds to honor the default
30-second shutdown contract before container removal. Operators that override
`LUX_SHUTDOWN_TIMEOUT_MS` must set their orchestrator termination grace period
to a longer value. SIGKILL and sudden process, operating-system, or power loss
remain crash recovery events and do not run the final sync.

Process crash behavior:

- Valid WAL frames before the crash must replay.
- Partial WAL frames at the end of a file must be ignored safely.
- A single logical mutation whose resolved recovery form contains multiple
  commands is stored in one checksummed frame, so a torn frame replays every
  effect or none of them. This applies to commands such as cross-key moves and
  replacements; it does not make a `MULTI`/`EXEC` queue one crash-atomic
  mutation.
- Any complete WAL frame with a corrupt boundary marker, length guard,
  checksum, argument encoding, or batch encoding rejects startup. Lux never
  skips a complete damaged mutation and continues with a partial history.
- Only an incomplete final LXW3 frame is treated as an uncommitted append and
  ignored. Truncation inside a legacy WAL is rejected because the older formats
  cannot prove that the suffix was never acknowledged.

## Snapshots

Snapshots are complete point-in-time images of the logical database.

Snapshot behavior:

- Manual `SAVE` writes a consistent snapshot and rotates WAL generations only
  after the snapshot succeeds.
- `BGSAVE` currently uses the same synchronous save path as `SAVE`; it does not
  yet provide Redis-compatible background execution.
- Snapshot files use a binary format with explicit type tags and length fields.
- Snapshot loading must reject invalid lengths and container counts before large
  allocation.
- Snapshot loading must never turn malformed input into a process panic or OOM.
- Key TTLs are stored as absolute deadlines so remaining time is honored across
  restarts rather than rebased to load time.
- Each snapshot records the generation and exact included offset of every WAL
  stream, plus the one successor generation authorized for the following
  rotation. Recovery skips the included prefix if the old generation survived
  a crash, or replays the complete authorized successor after rotation.
- A missing, empty, or unrelated journal recorded by a snapshot rejects startup
  without creating or rewriting recovery files. Pre-global snapshots may create
  the global journal only when they never recorded one. This prevents journal
  deletion or substitution from looking like a successful rotation while
  preserving the one-way upgrade from legacy per-shard journals.

## WAL Replay

Lux logs the *resolved effects* of every write, not raw client intent. A command
that generates a server-side value (an auto-generated primary key, a `now()`
column default, a relative TTL) is logged with that value already materialized,
so replay is deterministic and reproduces exactly the state clients observed.

Replay behavior:

- All write commands that mutate durable state are WAL logged.
- New writes share one journal order across shards and command surfaces.
- Logged commands carry resolved values, so replaying them never regenerates a
  different primary key, timestamp, or default.
- Table writes log their own resolved command from the table layer (so HTTP
  table writes, which bypass the RESP command path, are still durable).
- `MULTI`/`EXEC` commands cross individual durability boundaries in queue order.
  A complete `EXEC` response means every successful queued mutation is durable;
  a crash before that response may recover a completed prefix.
- Commands denied by restricted mode or the script sandbox never execute, so
  they create no replay gaps.

## Lua Durability

Lua script writes are durable through **effects replication**: every write a
script performs via `redis.call` / `redis.pcall` is logged to the WAL as an
individual resolved command, exactly as if a client had issued it directly. The
script body itself is not logged and is never re-run during replay.

This is deliberate. Re-running a script on replay would regenerate any
server-side value it produced (a generated primary key, a `now()` default), so
the recovered state could diverge from what clients and live subscribers already
observed. Logging effects keeps replay deterministic regardless of script
content.

- Writes performed inside `EVAL` and `EVALSHA` survive crash replay.
- Replay reapplies the logged effects without needing a populated script cache.
- `SAVE`, `BGSAVE`, blocking commands, transaction-control commands, and
  subscription commands are denied inside scripts to avoid mid-script
  persistence or event-loop hazards.

Known limitation: a script's effects are logged per write, not as one atomic
batch. A crash before the script response can recover a completed prefix. Once
the client receives a successful script response, every effect is durable. The
effects that recover are individually correct; the script is not all-or-nothing
across a crash boundary.

## Restore

Restore behavior:

- Restore fully validates Lux snapshots in the current and older binary formats
  before committing them for installation.
- Restore writes a new `lux.dat` snapshot atomically.
- A durable restore marker makes startup finish snapshot installation and stale
  persistence cleanup before opening any WAL or tiered shard after a crash.
- Startup installs a clean journal bound to the restored snapshot before it
  removes that marker, so restored state enters the normal strict recovery path.
- Restore purges only Lux-owned legacy `shard_*` and current `global` journal or
  tiered-storage directories, never the storage parent or unrelated files.
- After restore, stale WAL or cold tiered data must not overwrite restored
  state on restart.
- Once a restore is accepted, writes and snapshots are rejected until the
  process restarts into the restored state.
- Operators should restart the process after restore so startup rebuilds state
  from the restored snapshot.

## Tiered Storage

Tiered mode expectations:

- Cold entries must be included in snapshots.
- Cold entries must survive restart.
- Mutations to cold entries must be WAL logged.
- Tiered files are a live placement cache, not an independent durability
  authority. Persistent startup discards this derived cache before the verified
  snapshot plus WAL reconstruct the logical database, preventing cached values
  from being applied twice or carrying process-relative TTLs across restart.
  Corruption encountered by a running command is an explicit error and fences
  later mutations until restart.
- Rebuilt tiered indexes must describe only valid entries.

## Failure Modes That Must Be Bounded

Lux treats these as part of the durability failure surface:

- Process kill during ordinary writes.
- Process kill after snapshot before WAL truncation.
- Process kill during or after `FLUSHDB` and deletes.
- Corrupted WAL frames.
- Partial WAL frames.
- Corrupted snapshot length fields.
- Corrupted tiered data records.
- Restore with invalid payload.
- Restore with stale pre-restore WAL and tiered files.

## Operator Runbook

Backup:

1. Prefer the authenticated operator snapshot endpoint or manual `SAVE`.
2. Copy the produced `lux.dat` plus any required release metadata.
3. Record Lux version, config, and storage mode.
4. Periodically test restore into a fresh instance.

Restore:

1. Stop writes.
2. POST the snapshot to the operator restore endpoint or place `lux.dat`
   according to deployment tooling.
3. Restart Lux.
4. Verify startup logs, `INFO`, and application-level invariants.

Upgrade:

1. Back up before upgrading.
2. Read release notes for durability or file-format changes.
3. Roll forward through documented upgrade paths.
4. Do not downgrade across file-format changes unless release notes explicitly
   say it is safe.
