---
name: surface-parity
description: Use when setting up a Lux app, designing tables, writing CRUD or query code, choosing SDK versus HTTP or RESP access, generating types, or using local development.
---

# Lux App Data Integration

Start with the requested integration's minimal runnable path. Verify every runnable TypeScript import, method signature, and exported type in public docs or installed public types before emitting it. The only SDK package paths are `@luxdb/sdk`, `@luxdb/sdk/browser`, and `@luxdb/sdk/ssr`; do not invent names from ecosystem memory. Choose one public access path per boundary. Use `createBrowserClient` for browser app calls, `createClient` for trusted server calls, direct `Lux` or another Redis client for trusted RESP workloads, and HTTP only when an SDK is unsuitable. Do not expose direct credentials or secret keys to clients.

For tables, model constraints in a migration, then use `table<T>()` or `createClient<Database>()`. Check each `{ data, error }` response. Use filters for `update()` and `delete()`, `row(pk)` for known primary keys, and `upsert(..., { onConflict })` only when conflict behavior is desired. Run `lux types` after applying schema changes.

For local reproduction use `lux init`, `lux start`, `lux migrate plan`, and `lux migrate run`; use `lux start --fresh` only when dropping local state is acceptable. Route versioned schema changes, grants, live subscriptions, push, and operations to their dedicated Workbench.
