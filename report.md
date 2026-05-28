# Enterprise Production Readiness Review

Scope: `src/*`

## Remediation status

All findings below have been remediated in this change set with targeted fixes:

- RESP and HTTP now default to loopback binding and reject unauthenticated non-loopback listeners unless explicitly allowed.
- HTTP now binds to the configured `bind_host`.
- WAL append failures now propagate before write mutation instead of being logged as successful writes.
- Background snapshots now hold a write barrier through snapshot generation and WAL truncation.
- RESP parsing now enforces a configured pending request/bulk limit and closes on parser errors.
- `maxmemory` is enforced for `noeviction`, embedded fast paths, and optimized pipeline paths.
- Invalid UTF-8 command identities are rejected before dispatch instead of being silently coerced.
- Common RESP shard-batch writes now route through `Store::*_on_shard` primitives for consistent accounting and semantics.

## Findings

### 1. Severity: Critical
Location: `src/lib.rs` `ServerConfig::default`, `src/main.rs` `main`

Problem: Default runtime binds RESP to `0.0.0.0:6379` with `require_auth = false` unless `LUX_PASSWORD` is set.

Why it matters: A default production deployment exposes unauthenticated Redis-compatible command execution on every interface. That includes destructive commands unless separately restricted.

Recommended fix: Default to `127.0.0.1`, require explicit opt-in for unauthenticated non-loopback binds, and fail startup if binding non-loopback with auth disabled unless an explicit insecure flag is set.

Confidence: High

### 2. Severity: Critical
Location: `src/http.rs` `start_http_server`, `src/lib.rs` `Runtime::start_http_if_enabled`

Problem: HTTP always binds `0.0.0.0:{http_port}` and does not use `ServerConfig::bind_host`.

Why it matters: A user can set `LUX_BIND_HOST=127.0.0.1` and still expose the HTTP API remotely when `LUX_HTTP_PORT` is enabled. HTTP auth is also skipped when `password` is empty.

Recommended fix: Add `bind_host` to `HttpServerConfig`, bind HTTP to the configured host, and apply the same non-loopback/auth startup guard as RESP.

Confidence: High

### 3. Severity: Critical
Location: `src/store.rs` `Store::wal_log_command`, `src/cmd/mod.rs` `execute_with_wal`, `src/store.rs` `Store::fsync_wal`

Problem: WAL append/fsync failures are recorded and emitted as events, but writes continue and return success.

Why it matters: In tiered/durable mode, a disk-full or permissions failure can acknowledge writes that are not recoverable after a crash. This is fail-open durability.

Recommended fix: Make WAL append return `Result`; for configured durable modes, reject the write before mutation when WAL append fails. Treat repeated fsync failure as an unhealthy/read-only state or expose an explicit durability mode that documents accepted data-loss behavior.

Confidence: High

### 4. Severity: Critical
Location: `src/snapshot.rs` `save`, `src/snapshot.rs` `background_save_loop`, `src/store.rs` `Store::dump_all`, `src/store.rs` `Store::truncate_wal`

Problem: Background snapshot dumps shards without a global write barrier, then truncates the entire WAL after save.

Why it matters: Writes that happen after a shard has been dumped but before `truncate_wal()` can be absent from the snapshot and then removed from the WAL. That is a real crash-recovery data-loss race.

Recommended fix: Rotate WAL at snapshot start and truncate only frames covered by the snapshot checkpoint, or take a global write barrier for the snapshot plus WAL truncation. The checkpoint/rotation approach is preferable for availability.

Confidence: High

### 5. Severity: Important
Location: `src/resp.rs` `Parser::parse_multibulk`, `src/resp.rs` `Parser::parse_bulk_string`, `src/lib.rs` `handle_connection`

Problem: RESP pending input can grow without a configured max bulk/request size, and parser errors are ignored by `while let Ok(Some(args))`.

Why it matters: A client can send a huge declared bulk string or malformed frame and force unbounded memory growth or ambiguous connection behavior. This is a network DoS risk.

Recommended fix: Add max RESP bulk length and max pending-buffer size, emit a protocol error, and close the connection on parser `Err`. Reuse `max_body`-style configuration or add `max_resp_request`.

Confidence: High

### 6. Severity: Important
Location: `src/eviction.rs` `eviction_enabled`, `src/cmd/mod.rs` `execute`, `src/lib.rs` `EmbeddedClient::execute_command_fast_path`, `src/lib.rs` `CommandExecutor::execute_pipeline`

Problem: `maxmemory` with `NoEviction` disables enforcement entirely, and embedded/native fast paths do not consistently call the eviction gate before writes.

Why it matters: Enterprise operators expect `maxmemory noeviction` to reject writes once memory is over limit. Current behavior can exceed configured memory limits, especially through embedded and optimized pipeline paths.

Recommended fix: Change enforcement to trigger whenever `max_memory > 0`; for `NoEviction`, return OOM instead of disabling enforcement. Centralize a write-admission gate used by RESP, HTTP, embedded, fast path, and pipeline writes.

Confidence: High

### 7. Severity: Important
Location: `src/cmd/mod.rs` `arg_str`, `src/store.rs` `key_str`, `src/store.rs` `key_string`, `src/lib.rs` `arg_str`

Problem: Invalid UTF-8 keys/fields are silently converted to `""` or lossy replacement strings depending on code path.

Why it matters: Redis keys are binary-safe. Current behavior can make keys inaccessible, mismatch reads and writes, or corrupt persisted names for non-UTF-8 inputs.

Recommended fix: Either store keys/fields as byte strings consistently, or explicitly reject invalid UTF-8 at the command boundary with a deterministic error. Do not use `unwrap_or("")` for key identity.

Confidence: High

### 8. Severity: Important
Location: `src/cmd/mod.rs` `execute_on_shard`, shard write helpers

Problem: Optimized RESP shard-batch helpers duplicate store mutation logic and do not consistently update memory accounting or match store-level semantics.

Why it matters: Metrics, eviction decisions, and behavior can diverge depending on whether a command uses the generic path or pipeline fast path.

Recommended fix: Route shard-batch execution through the existing `Store::*_on_shard` primitives wherever possible. Keep only dispatch and response encoding in `cmd::execute_on_shard`.

Confidence: High

## Highest leverage fixes

1. Harden network defaults and HTTP binding.
Why it is high leverage: Removes the most obvious remote-exposure risk.
Findings addressed: 1, 2

2. Make WAL durability fail closed and fix snapshot/WAL checkpointing.
Why it is high leverage: Prevents acknowledged-write loss after crashes.
Findings addressed: 3, 4

3. Centralize write admission and memory accounting.
Why it is high leverage: Keeps RESP, HTTP, embedded, and pipeline paths consistent.
Findings addressed: 6, 8

4. Add RESP request/bulk limits and close on parser errors.
Why it is high leverage: Reduces unauthenticated network DoS exposure.
Findings addressed: 5

5. Decide binary-key policy and enforce it everywhere.
Why it is high leverage: Prevents hard-to-debug correctness and persistence corruption.
Findings addressed: 7

## Original production readiness summary

Not ready for production.

Main reason: there are critical security and durability issues: unauthenticated remote exposure by default, HTTP binding bypassing configured host, WAL fail-open behavior, and a snapshot/WAL truncation race that can lose acknowledged writes.

## Post-remediation summary

Ready after targeted operational validation.

Main reason: the identified code-level blockers have been fixed and focused checks pass, but the full non-fuzz suite exceeded the 60s harness timeout and should be run in an unrestricted local/CI environment before release.
