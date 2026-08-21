---
name: recovery-testing
description: Use when planning or performing Lux backups, restore drills, persistence or TTL configuration, secure deployment, storage-mode decisions, or upgrades.
---

# Lux Backup And Recovery

Start with the requested operation's minimum safe runbook. Use only public `README.md`, `DURABILITY.md`, `SECURITY.md`, `cli/README.md`, and installed public CLI help. Do not read, cite, or derive consumer guidance from source, tests, engine internals, or undocumented settings unless the user explicitly asks to contribute to Lux. If public docs conflict, name it and prefer `DURABILITY.md` for durability decisions.

Record the Lux version, storage mode, configuration, and backup time. Create an authenticated snapshot or run `SAVE`, then protect the produced snapshot and metadata with the same access controls as application data.

Practice recovery in a fresh instance: stop writes, restore the snapshot, restart Lux, and verify `INFO` plus application-level invariants. Treat tiered-mode WAL recovery as bounded by the documented fsync window; memory mode is snapshot-only. Do not assume a multi-write Lua script is crash-atomic.

Before an upgrade, create and verify a backup, read relevant release notes, and use explicit `lux update` commands. Do not downgrade across a storage-format change without documented support. Keep RESP/HTTP and snapshot/restore endpoints private or authenticated; use `--bind` only for a deliberate trusted-network deployment.
