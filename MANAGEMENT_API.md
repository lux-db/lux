# Engine management API

Lux owns migration parsing, checksums, execution progress, and repair state in
the engine. CLI, Cloud, and Studio must use this contract rather than writing
`__migrations` directly.

## Discovery

`GET /v1/version` and `LUX VERSION` return the fields below. On a
credential-gated engine, the HTTP route requires an operator or secret
credential and RESP requires normal connection authentication.

- `version`: engine semantic version
- `build_sha`: source revision (`unknown` for builds that do not provide one)
- `api_version`: management API version
- `capabilities`: feature identifiers callers must check before using a feature

## Health

Container orchestrators may call `GET /health/live` and `GET /health/ready`
without database credentials. Liveness means the recovered engine's HTTP
listener is serving requests. Readiness also requires the engine to be
accepting normal traffic, with no restore, shutdown, or poisoned mutation
journal in progress. The endpoints return only the health state and never
project data.

## Migrations

Operator-authenticated HTTP routes:

- `GET /v1/migrations?limit=100&offset=0`
- `POST /v1/migrations/plan`
- `POST /v1/migrations/apply`
- `POST /v1/migrations/repair`

Plan and apply accept:

```json
{
  "filename": "001_create_messages.lux",
  "body": "TCREATE messages id UUID PRIMARY KEY, body STR;"
}
```

Studio may send `name` instead of `filename`; the engine generates a safe,
timestamped `.lux` basename. Bodies are checksummed as exact UTF-8 bytes with
SHA-256.

The engine records `applying` before the first command and persists
`completed_commands` after each success. `applying` and `failed` records block
later migration writes. They never auto-resume. Repair requires one explicit
action:

```json
{"filename":"001_create_messages.lux","action":"resume","from_command":1}
{"filename":"001_create_messages.lux","action":"mark_applied"}
{"filename":"001_create_messages.lux","action":"abandon"}
```

`from_command` is a reviewed, zero-based command index. Existing DJB2 and Studio
FNV-1a ledger checksums remain readable and idempotent; all new records use
SHA-256.

RESP parity is available under `LUX MIGRATE LIST|PLAN|APPLY|REPAIR`.

## Snapshot and restore

Full-instance backup and restore use the strongest configured management
credential. An engine with a password requires the operator password. A
project-key-only engine requires a secret key. A bare loopback engine with no
configured credential remains accessible to its local operator.

`GET /v1/snapshot` creates a consistent current-format snapshot and streams it
as `application/octet-stream`. The response includes:

- `X-Lux-Snapshot-SHA256`: SHA-256 of the exact streamed bytes
- `X-Lux-Snapshot-Format`: binary snapshot format version

`POST /v1/restore` accepts a Lux snapshot as `application/octet-stream` and an
optional `X-Lux-Snapshot-SHA256` header. It validates and stages the complete
snapshot without changing the running database. Success is `202 Accepted`:

```json
{
  "staged": true,
  "restart_required": true,
  "restore_id": "...",
  "source_bytes": 1234,
  "staged_bytes": 1250,
  "entries": 42,
  "source_format": 5,
  "format": 6,
  "source_sha256": "...",
  "sha256": "..."
}
```

`GET /v1/restore` reports whether a validated restore is pending and returns
the restore id, source and staged checksums, byte lengths, and format versions.
Clients must compare `source_sha256` before treating a lost `POST` response or
`409 Conflict` as an idempotent retry.

The host must then gracefully restart Lux. Startup revalidates the staged
artifact, preserves the complete current state as a rollback, atomically
installs the replacement, and creates only the successor journal authorized by
that snapshot. The request handler never exits the process. A second staging
request returns `409 Conflict` while one is pending; malformed, truncated, or
checksum-mismatched payloads return `400 Bad Request`; insufficient staging
space returns `507 Insufficient Storage`.

## Push configuration

The operator-only configuration surface never returns provider secrets:

- `GET /v1/push/config?app_id=default`
- `PUT /v1/push/config/apns`
- `DELETE /v1/push/config/apns?app_id=default`
- `POST /v1/push/config/vapid` with `action: "enable"` or `"rotate"`
- `DELETE /v1/push/config/vapid?app_id=default`

APNs updates preserve the existing private key when `p8_pem` is omitted.
VAPID enable is idempotent; rotate intentionally changes the public key.
Provider private keys are written only to `ENCRYPTED` columns. Legacy plaintext
keys remain readable until encryption is available, are reported as unhealthy,
and are migrated in-engine as soon as an active encryption key exists.

The CLI exposes the same contract for an implicit local engine or a positional
Cloud project:

```text
lux push status [project] [--check] [--output json]
lux push apns set [project] --team-id ... --key-id ... --topic ... [--p8-file ...]
lux push apns clear [project] --yes
lux push vapid enable [project] [--subject ...]
lux push vapid rotate [project] [--subject ...] --yes
lux push vapid disable [project] --yes
```

Cloud's authenticated `/push/:project/config` routes are pass-throughs to these
engine endpoints. The CLI reads APNs key material only from the requested file,
never persists it, and never includes provider private keys in status output.
