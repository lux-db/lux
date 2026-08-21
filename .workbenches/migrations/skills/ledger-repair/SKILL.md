---
name: ledger-repair
description: Use when authoring, planning, applying, pulling, rolling out, or repairing Lux application migrations.
---

# Lux Migration Rollout

Lead with the minimal command sequence for the requested migration. Verify commands in `cli/README.md` or installed public `lux migrate --help` before emitting them; do not infer syntax from memory. Create an additive, reviewable `.lux` migration with `lux migrate new <name>`. Keep the file under version control and use JSON argv arrays for values that are difficult to quote safely. Include grants with the schema change that requires them.

Before rollout, run `lux migrate plan` against the intended target and inspect `lux migrate status`. Omitted target means local; name the Cloud project or direct target explicitly. Apply with `lux migrate run`, then run `lux types` if TypeScript application types changed.

For a blocked record, inspect status first. Select exactly one reviewed repair: resume from a command index, mark applied, or abandon. Never edit `__migrations`, change a previously applied file to force a retry, or script automatic repair.
