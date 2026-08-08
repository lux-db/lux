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

`every_second` is the default for both the standalone binary and
`ServerConfig`. `LUX_STORAGE_MODE` never changes the durability policy.
`INFO`, `GET /v1`, and `GET /v1/version` report the effective layout, policy,
sync interval, and whether the journal is enabled.

## Default Data-Loss Envelope

By default, Lux fsyncs WAL data on an interval comparable to Redis
`appendfsync everysec`.

Expected power-loss behavior:

- Successfully fsynced WAL frames must recover.
- Writes acknowledged after the last fsync may be lost on sudden power failure.
- The default maximum expected power-loss window is approximately one second of
  writes.
- A failed periodic fsync emits a critical runtime error and increments the
  `persistence_err_wal_fsync` counter. The one-second bound does not apply while
  the storage device cannot complete synchronization.
- `ServerHandle::shutdown_and_wait` flushes pending WAL data before returning.

Process crash behavior:

- Valid WAL frames before the crash must replay.
- Partial WAL frames at the end of a file must be ignored safely.
- A single logical mutation whose resolved recovery form contains multiple
  commands is stored in one checksummed frame, so a torn frame replays every
  effect or none of them. This applies to commands such as cross-key moves and
  replacements; it does not make a `MULTI`/`EXEC` queue one crash-atomic
  mutation.
- Corrupt WAL frames must be skipped or rejected without panicking.

## Snapshots

Snapshots are complete point-in-time images of the logical database.

Snapshot behavior:

- Manual `SAVE` writes a consistent snapshot and truncates WAL only after the
  snapshot succeeds.
- `BGSAVE` currently uses the same synchronous save path as `SAVE`; it does not
  yet provide Redis-compatible background execution.
- Snapshot files use a binary format with explicit type tags and length fields.
- Snapshot loading must reject invalid lengths and container counts before large
  allocation.
- Snapshot loading must never turn malformed input into a process panic or OOM.
- Key TTLs are stored as absolute deadlines so remaining time is honored across
  restarts rather than rebased to load time.

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
- Transaction replay preserves the committed command sequence.
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
batch. A crash in the middle of a multi-write script can leave the earlier
writes durable and the later ones lost. The effects that survive are always
individually correct; the script is not all-or-nothing across a crash boundary.

## Restore

Restore behavior:

- Restore accepts any valid Lux snapshot header (current and older versions).
- Restore writes a new `lux.dat` snapshot atomically.
- Restore purges only Lux-owned legacy `shard_*` and current `global` journal or
  tiered-storage directories, never the storage parent or unrelated files.
- After restore, stale WAL or cold tiered data must not overwrite restored
  state on restart.
- Operators should restart the process after restore so startup rebuilds state
  from the restored snapshot.

## Tiered Storage

Tiered mode expectations:

- Cold entries must be included in snapshots.
- Cold entries must survive restart.
- Mutations to cold entries must be WAL logged.
- Tiered data corruption must not crash startup.
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
