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
- Configure exact `LUX_HTTP_ALLOWED_HOSTS` and `LUX_HTTP_ALLOWED_ORIGINS` values
  for every browser-facing HTTP listener. A non-loopback bind that enables any
  browser origin fails closed without an explicit Host allowlist.
- Use long random operator credentials when `LUX_PASSWORD` is enabled.
- Run Lux as an unprivileged OS user with access only to its data and storage
  directories.
- Back up snapshots and WAL-related data to storage with access controls.

Official Lux binaries target Unix platforms. Persisted engine files and CLI
credential files are opened without following final-component symbolic links
and are restricted to the owning user. Dedicated engine state directories are
restricted to the owning user as well. Lux refuses unsafe file types,
directories writable by other users, ownership mismatches, and a persistent
directory already locked by another Lux process.

Lux refuses to bind a non-loopback listener without authentication configured,
so an unauthenticated instance is reachable only from localhost. Do not expose
unauthenticated Lux ports directly to the public internet.

## Sensitive Surfaces

These surfaces are security-sensitive and treated as release-blocking when
regressions are found:

- Credential resolution (`resolve_credential`): the single path every surface
  uses to turn a presented secret key, publishable key, end-user token or
  `LUX_PASSWORD` into an identity.
- App auth, sessions, refresh tokens, OAuth provider configuration, project
  keys, and row-level grants.
- Reserved auth tables (`_t:auth.*`) and the raw-KV guard that protects them.
- HTTP `/v1/snapshot`, `/v1/restore`, table routes, `/auth/v1/*`, and live
  WebSocket routes.
- Local Studio sessions minted by `POST /v1/studio/sessions`. They are
  short-lived, bound to one exact Origin, stored only as hashes in process
  memory, and never accepted by RESP. Minting another session for an Origin
  revokes the prior one.
- RESP commands that can delete, rewrite, persist, inspect, or execute code:
  `FLUSHALL`, `FLUSHDB`, `SAVE`, `BGSAVE`, `EVAL`, `EVALSHA`, `SCRIPT`,
  `DEBUG`, `CONFIG`, `COMMAND`, and administrative routes.
- Lua sandbox globals and `redis.call` / `redis.pcall` behavior.
- Snapshot, WAL, tiered-storage, RESP, HTTP, and MessagePack decoders.

## Resource Exhaustion

Resource-exhaustion reports are security-relevant when a small or unauthenticated
input can cause disproportionate CPU, memory, disk, network, or task growth;
crash the process; or wedge the runtime. Examples include:

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
- The Lux CLI
- The @luxdb/sdk npm package
- The Workbenches distributed in this repository

Lux Cloud and the Swift SDK are maintained in separate repositories and follow
their own reporting and release processes.

## Contact

Pompeii Labs, Inc.
hello@pompeiilabs.com
