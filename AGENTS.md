# Lux

Lux is an application database written in Rust. One engine provides
Redis-compatible commands, typed tables, vectors, time series, streams,
realtime subscriptions, app authentication, row-level grants, and push
notifications. It exposes RESP for trusted infrastructure and versioned HTTP,
auth, and WebSocket APIs for applications.

Use this file as the short product map. The authoritative public contracts are
[README.md](README.md), [COMPATIBILITY.md](COMPATIBILITY.md),
[DURABILITY.md](DURABILITY.md), [SECURITY.md](SECURITY.md), and
[MANAGEMENT_API.md](MANAGEMENT_API.md).

## Start a local project

Docker is required for the local stack.

```bash
curl -fsSL https://luxdb.dev/install.sh | sh
lux init
lux start
```

`lux start` launches a real Lux engine and Lux Studio on loopback, applies
pending migrations, seeds a fresh data volume, and creates a private `local`
environment profile. On first setup it safely merges the Lux variables into
`.env.local`; unrelated variables and comments are preserved.

```bash
lux status             # local runtime and connection details
lux studio             # open the local Studio
lux doctor             # runtime, env, API, and migration checks
lux target             # local, linked-Cloud, and active app-env targets
lux stop               # keep local data
lux stop --clear       # delete the local data volume
lux start --fresh      # recreate the volume, then migrate and seed it
```

Local ports bind to `127.0.0.1` by default. Use `lux start --bind <IP>` only
when a trusted device or development environment must connect over the network.
Use `lux start --no-studio` when only the engine is needed.

## Connections and credentials

| Variable | Use |
|---|---|
| `LUX_URL` | HTTP base URL used by browser, server, and Swift project clients |
| `LUX_DIRECT_URL` | RESP connection URL for trusted servers, CLI commands, and Redis-compatible clients |
| `LUX_PUBLISHABLE_KEY` | Browser/mobile-safe project key; data access still requires a signed-in user and matching grants |
| `LUX_SECRET_KEY` | Trusted-server key with full project access; never ship it to a browser or mobile app |

Use `lux://` or `luxs://` URLs with Lux's CLI and direct TypeScript client.
Third-party Redis clients do not know those schemes, so use `redis://` or
`rediss://` with the same host and credential. Never expose a direct database
password to client code.

Use an HTTP project client for application tables, auth, grants, vectors, time
series, live queries, and push. Use RESP from trusted infrastructure for cache
and key/value workloads, collections, streams and queues, Pub/Sub, and direct
Lux commands. Both surfaces address the same engine; they are not separate
services.

An omitted CLI target means the local engine for migrations, seeds, types,
auth-provider configuration, and push configuration. A linked Cloud project is
used only when it is named or a comparison command such as `--all` asks for it.
`lux link` does not silently change local commands into production commands.

## Schema and migrations

Lux migrations are ordered UTF-8 command files under `lux/migrations/`.
Schema, indexes, grants, and stable seed-independent data belong in migrations.

```bash
lux migrate new create_messages
lux migrate plan
lux migrate run
lux migrate status --check
lux types
```

The engine owns parsing, SHA-256 identity, the migration ledger, command
progress, and repair state. Do not write `__migrations` directly. A failed or
interrupted migration blocks later migration writes and never resumes itself:
inspect `lux migrate status`, then use an explicit `lux migrate repair` action
only after reviewing the recorded command cursor.

`lux/seed.lux` uses the same command format but is not ledgered. Run it with
`lux seed run`; use stable identifiers when repeated seed execution must be
predictable.

## Lux Studio

Local Studio is part of the supported local stack, not a mock dashboard. It
talks directly to the engine and exposes engine-native Overview, command
editor, Migrations, Tables, Vectors, Queues, Time Series, Realtime, Backups,
Auth, Push, and Settings surfaces. It negotiates capabilities through `GET /v1`
instead of guessing from an image tag.

If Studio reports a compatibility problem, run `lux version`, `lux doctor`,
and the explicit update it recommends (`lux update engine` or
`lux update studio`). `lux start` never changes a running component's version
implicitly. Object storage, logs, domains, billing, and provisioning depend on
Cloud services and are not local Studio features.

## TypeScript applications

Install the stable first-party SDK:

```bash
bun add @luxdb/sdk
```

Use a publishable key in browser code and a secret key only on a trusted
server. Project clients return `{ data, error }`.

```ts
import { createBrowserClient } from "@luxdb/sdk/browser";

const lux = createBrowserClient(LUX_URL, LUX_PUBLISHABLE_KEY);

const { error: signInError } = await lux.auth.signInAnonymously();
if (signInError) throw signInError;

const { data: messages, error } = await lux
  .table("messages")
  .select()
  .eq("channel_id", "general")
  .order("created_at", { ascending: false })
  .limit(50);
if (error) throw error;
```

Generate the `Database` type from the live schema with `lux types`, pass it to
`createClient<Database>()`, and regenerate it after schema migrations. Use the
direct `Lux` client only for trusted RESP workloads; use project clients for
tables, auth, grants, live queries, and push.

## Auth and grants

Lux Auth supports email/password, anonymous users, refresh sessions, PKCE,
Google, GitHub, and Apple. Configure providers in Studio, or configure a local
or HTTPS self-hosted engine with `lux auth provider ...`. Managed Cloud
providers are normally configured in the Cloud dashboard.

With auth enabled, end users are denied data access by default. Publishable keys
can reach authentication, but a signed-in user's reads, writes, and `.live()`
subscriptions require a matching table grant. Secret-key and operator callers
bypass end-user grants.

```text
GRANT read, write ON messages WHERE user_id = auth.uid()
GRANT read ON messages WHERE workspace_id IN ( SELECT workspace_id FROM members WHERE user_id = auth.uid() )
```

Grants automatically narrow reads, updates, deletes, and live subscriptions.
Inserts and upserts check the resulting row. Keep grants in migrations so the
same access model reaches local, self-hosted, and Cloud environments.

## Realtime

Lux has two realtime surfaces:

- `SUBSCRIBE`/`PSUBSCRIBE` and Lux-native `KSUB` for RESP channel or key events.
- Table `.live()` over WebSocket for a query snapshot followed by `insert`,
  `update`, and `delete` events.

```ts
const { live, error } = await lux
  .table("messages")
  .eq("channel_id", "general")
  .live();
if (error) throw error;

for await (const event of live) {
  console.log(event.type, event);
}
```

Table live subscriptions enforce the same read grant as the query. Client-side
filtering may shape the UI, but it is not an authorization boundary.

## Push

Lux supports APNs and W3C Web Push. Configure credentials locally through
Studio or the CLI; the corresponding commands accept an explicit Cloud project
when needed.

```bash
lux push apns set --team-id TEAM_ID --key-id KEY_ID \
  --topic com.example.app --environment sandbox \
  --p8-file AuthKey_KEY_ID.p8
lux push vapid enable --subject mailto:push@example.com
lux push status --check
```

The CLI never persists or prints APNs key material; provider keys belong to
engine-managed encrypted fields. A signed-in client may register only its own
device. Sending to an explicit subject, or registering on another subject's
behalf, requires a secret-key server client.

```ts
import { createClient } from "@luxdb/sdk";

const server = createClient(LUX_URL, LUX_SECRET_KEY);
await server.push.send(userId, {
  title: "New message",
  body: "A teammate replied.",
  data: { conversation_id: conversationId },
});
```

## SDK and protocol choices

- **TypeScript:** `@luxdb/sdk` is stable for HTTP project/browser/SSR clients
  and direct RESP access, including tables, auth, realtime, vectors, time
  series, and push. Its object-storage namespace is Cloud-only.
- **Swift:** `lux-db/lux-swift` is stable for authentication, durable sessions,
  and authenticated APNs device registration. Swift data access, realtime,
  storage, notification sending, and secret-key administration are outside its
  current contract.
- **Python, Go, and other languages:** use a supported RESP2 client. Lux does
  not promise first-party Python or Go SDKs for 1.0.
- **Rust:** the documented embedded API can run Lux in-process without opening
  network listeners.

## Self-hosting

Run the published engine container or binary on trusted infrastructure. Persist
the complete `LUX_DATA_DIR`, authenticate every non-loopback listener, keep
RESP private, and set `LUX_HTTP_PORT` when project clients need the HTTP API.
Read [SECURITY.md](SECURITY.md) before exposing any listener and
[DURABILITY.md](DURABILITY.md) before choosing a persistence policy.

Storage placement and write durability are independent:

- `LUX_STORAGE_MODE=memory` or `tiered` controls where live data is placed.
- `LUX_DURABILITY=ephemeral`, `every_second`, or `always_sync` controls what a
  successful write acknowledges.

Memory placement is not automatically ephemeral. `always_sync` is the default;
`every_second` explicitly accepts loss of writes acknowledged since the most
recent sync after a sudden power failure, while `ephemeral` provides no recovery
guarantee. For production, preserve the entire data directory, use an
intentional durability policy, allow graceful shutdown to finish, and back up
complete snapshots rather than individual private WAL or tiered-storage files.

## Move from local to Lux Cloud

The engine and application APIs stay the same. Create and link a project, apply
the same ledgered migrations to that explicit target, then activate the Cloud
environment profile:

```bash
lux login
lux create my-app --accept-charges
lux link my-app
lux migrate plan my-app
lux migrate run my-app
lux env pull my-app
lux env use my-app
```

Return the application to the local profile with `lux env use local`. Use
`lux status --all`, `lux doctor --all`, and `lux version --all` to compare the
local engine with the linked Cloud project without changing either one.

## 1.0 contract boundaries

The exact support matrix lives in [COMPATIBILITY.md](COMPATIBILITY.md). In
short, the documented RESP2 commands, versioned Engine HTTP API, app auth,
live WebSocket API, local/self-hosted CLI workflow, TypeScript SDK, limited
Swift SDK, Local Studio, and documented embedded Rust API are stable surfaces.

Unversioned HTTP aliases are preview unless the compatibility document says
otherwise. Object storage is Cloud-only. Multi-node clustering and replication,
RESP3, Redis modules, built-in TLS termination, first-party Python/Go SDKs, and
the broader Swift database surface are not part of Lux 1.0. Cloud control-plane
commands are available in the CLI but are maintained and gated with Lux Cloud,
not by the open-source Engine 1.0 suite.
