# Lux Durability Contract

This document defines Lux persistence and recovery expectations for 1.0.

Lux uses snapshots plus a write-ahead log (WAL). It does not use Redis AOF. The
durability contract is intentionally explicit so users understand the data-loss
envelope and operators can test recovery procedures.

## Storage Model

Lux persists state through:

- `lux.dat`: point-in-time snapshot of the in-memory database.
- Per-shard WAL files: command log replayed after the snapshot.
- Tiered storage files: cold entries evicted from memory when tiered mode is
  enabled.

On startup Lux loads the snapshot, replays valid WAL frames, and rebuilds tiered
indexes as needed. The WAL exists only in tiered storage mode; memory mode is
snapshot-only.

## Default Data-Loss Envelope

By default, Lux fsyncs WAL data on an interval comparable to Redis
`appendfsync everysec`.

Expected power-loss behavior:

- Successfully fsynced WAL frames must recover.
- Writes acknowledged after the last fsync may be lost on sudden power failure.
- The default maximum expected power-loss window is approximately one second of
  writes.
- Graceful shutdown should flush pending persistence state before exit.

Process crash behavior:

- Valid WAL frames before the crash must replay.
- Partial WAL frames at the end of a file must be ignored safely.
- Corrupt WAL frames must be skipped or rejected without panicking.

## Snapshots

Snapshots are complete point-in-time images of the logical database.

Required behavior:

- Manual `SAVE` writes a consistent snapshot and truncates WAL only after the
  snapshot succeeds.
- `BGSAVE` uses the same consistency model from a background task.
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

Required behavior:

- All write commands that mutate durable state are WAL logged.
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
- Restore purges only Lux-owned `shard_*` storage directories, never the whole
  storage parent or unrelated files.
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

1.0 requires explicit tests or documented behavior for:

- Process kill during ordinary writes.
- Process kill after snapshot before WAL truncation.
- Process kill during or after `FLUSHDB` and deletes.
- Corrupted WAL frames.
- Partial WAL frames.
- Corrupted snapshot length fields.
- Corrupted tiered data records.
- Restore with invalid payload.
- Restore with stale pre-restore WAL and tiered files.

Recommended before 1.0:

- I/O error during snapshot write.
- I/O error during WAL append.
- I/O error during WAL truncation.
- I/O error during tiered write.
- Crash during recovery from a previous crash.
- Disk full during restore.

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

## Release Evidence

Every 1.0 release candidate should record:

- Full test command and result.
- Crash-recovery test result.
- Persistence fuzz or corpus result.
- Backup/restore smoke test result.
- Any known durability limitation.
