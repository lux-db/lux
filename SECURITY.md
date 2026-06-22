# Security Policy

## Security Model

Lux is a database process. Treat the RESP port, HTTP port, snapshot endpoint,
restore endpoint, and operator credentials as sensitive infrastructure.

The default production model is:

- Run Lux on a trusted host or private network.
- Expose the RESP port only to trusted application servers or through an
  authenticated gateway.
- Expose the HTTP API only behind operator/app authentication and normal network
  controls.
- Use long random operator credentials when `LUX_PASSWORD` is enabled.
- Run Lux as an unprivileged OS user with access only to its data and storage
  directories.
- Back up snapshots and WAL-related data to storage with access controls.

Lux refuses to bind a non-loopback listener without authentication configured,
so an unauthenticated instance is reachable only from localhost. Do not expose
unauthenticated Lux ports directly to the public internet.

## Sensitive Surfaces

These surfaces are security-sensitive and treated as release-blocking when
regressions are found:

- Operator authentication and `LUX_PASSWORD`.
- App auth, sessions, refresh tokens, OAuth provider configuration, project
  keys, and row-level grants.
- Reserved auth tables (`_t:auth.*`) and the raw-KV guard that protects them.
- HTTP `/v1/snapshot`, `/v1/restore`, table routes, `/auth/v1/*`, and live
  WebSocket routes.
- RESP commands that can delete, rewrite, persist, inspect, or execute code:
  `FLUSHALL`, `FLUSHDB`, `SAVE`, `BGSAVE`, `EVAL`, `EVALSHA`, `SCRIPT`,
  `DEBUG`, `CONFIG`, `COMMAND`, and administrative routes.
- Lua sandbox globals and `redis.call` / `redis.pcall` behavior.
- Snapshot, WAL, tiered-storage, RESP, HTTP, and MessagePack decoders.

## Resource Exhaustion

Lux rejects maliciously large or malformed inputs before unbounded CPU, memory,
disk, or task growth. Reports here are security-relevant when they can crash the
process, wedge the runtime, or create large sparse allocations from small
requests. Examples:

- Malformed length-prefixed data that drives a large allocation (snapshot, WAL,
  RESP, or MessagePack length prefixes).
- Sparse `SETRANGE` / `SETBIT` / repeated `APPEND` that bypass the configured
  value-size limit.
- Lua scripts that bypass filesystem/process sandboxing or msgpack bounds.
- Snapshot, WAL, or tiered files that cause panic, OOM, or infinite loop on
  startup.

## Reporting a Vulnerability

If you discover a security vulnerability in Lux, please report it privately so we can fix it before it's exploited. **Please do not open a public GitHub issue** for security vulnerabilities, as this exposes the issue to everyone before a fix is available.

Email **[hello@pompeiilabs.com](mailto:hello@pompeiilabs.com)** with:

- A description of the vulnerability
- Steps to reproduce
- Affected versions (if known)
- Any potential impact assessment

## Response Timeline

We aim to acknowledge reports within a few business days and prioritize fixes based on severity. Lux is maintained by a small team, so timelines vary, but we treat security issues as our highest priority when they come in.

## What Qualifies

- Authentication or authorization bypasses
- Data loss or corruption vulnerabilities
- Denial of service attacks against the server process
- Memory safety issues
- Information disclosure (credentials, customer data)
- Injection attacks (command injection, Lua sandbox escapes)

## What Does Not Qualify

- Vulnerabilities in dependencies that don't affect Lux in practice
- Issues that require physical access to the host machine
- Social engineering attacks
- Denial of service via expected behavior (e.g., KEYS on large datasets)
- Non-security bugs (crashes, incorrect results) -- please open a regular GitHub issue for these

## Disclosure

We will coordinate disclosure with the reporter. Once a fix is available, we will:

1. Release a patched version
2. Publish a GitHub Security Advisory
3. Credit the reporter (unless they prefer to remain anonymous)

We ask that you give us reasonable time to address the issue before public disclosure.

## Scope

This policy covers:

- The Lux database engine ([github.com/lux-db/lux](https://github.com/lux-db/lux))
- Lux Cloud ([luxdb.dev](https://luxdb.dev))
- The Lux CLI
- The @luxdb/sdk npm package

## Contact

Pompeii Labs, Inc.
hello@pompeiilabs.com
