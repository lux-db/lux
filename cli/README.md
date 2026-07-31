# lux

CLI for [Lux](https://luxdb.dev). Manage Lux Cloud projects, run migrations and seeds, execute commands, stream logs, and connect to Lux instances from the terminal.

## Install

One-line install:
```bash
curl -fsSL https://luxdb.dev/install.sh | sh
```

From source (requires Rust):
```bash
git clone https://github.com/lux-db/lux && cargo install --path lux/cli
```

From GitHub Releases (manual download):
```bash
# macOS (Apple Silicon)
curl -fsSL https://github.com/lux-db/lux/releases/latest/download/lux-cli-macos-arm64.tar.gz | tar xz
mv lux-cli-macos-arm64 /usr/local/bin/lux

# macOS (Intel)
curl -fsSL https://github.com/lux-db/lux/releases/latest/download/lux-cli-macos-x86_64.tar.gz | tar xz
mv lux-cli-macos-x86_64 /usr/local/bin/lux

# Linux (x86_64)
curl -fsSL https://github.com/lux-db/lux/releases/latest/download/lux-cli-linux-x86_64.tar.gz | tar xz
mv lux-cli-linux-x86_64 /usr/local/bin/lux

# Linux (ARM64)
curl -fsSL https://github.com/lux-db/lux/releases/latest/download/lux-cli-linux-arm64.tar.gz | tar xz
mv lux-cli-linux-arm64 /usr/local/bin/lux
```

## Auth

Create a token at [luxdb.dev/dashboard/tokens](https://luxdb.dev/dashboard/tokens), then:

```bash
lux login
```

Token and API URL are stored in `~/.lux/config.json`.

## Commands

```bash
lux init                                      # scaffold lux/config.toml and lux/migrations
lux start                                     # run a local engine + Studio in Docker
lux studio                                    # open Lux Studio (local web UI)
lux stop                                      # stop the local engine + Studio
lux login                                     # authenticate
lux logout                                    # clear credentials
lux link my-app                               # associate this repo with a cloud project
lux unlink                                    # remove the cloud association
lux target                                    # show local, linked-cloud, and app-env targets
lux projects                                  # list all projects
lux create my-app --accept-charges            # create a Standard project
lux status                                    # show local engine status
lux status my-app                             # show explicit cloud project status
lux status --all                              # show local + linked cloud together
lux doctor --all                              # diagnose local + linked cloud
lux version                                   # CLI, local engine, and Studio versions
lux version my-app                            # cloud engine version/update status
lux update engine                             # explicitly update local engine in place
lux update engine my-app                      # snapshot-gated cloud engine update
lux update studio                             # explicitly update local Studio
lux exec my-app SET hello world               # execute a command
lux exec my-app KEYS '*'                      # wildcards need quotes
lux logs my-app                               # fetch explicit cloud project logs
lux logs my-app -l 500                        # fetch 500 lines
lux restart my-app                            # restart explicit cloud project
lux destroy my-app --accept-consequences      # permanently delete
lux connect my-app                            # interactive REPL via Lux Cloud
lux keys list                                 # list project API keys
lux keys create --kind secret --name server   # create an additional project API key
lux keys revoke <key-id>                      # revoke a project API key
lux env pull my-app                           # save a private cloud env profile
lux env use my-app                            # safely merge its Lux keys into .env.local
lux env use local                             # switch the app back to local
lux migrate new create_users                  # create a migration file
lux migrate status                            # check status (local instance)
lux migrate plan                              # preview without applying
lux migrate run                               # run pending migrations (local instance)
lux migrate run my-app                        # run against a cloud project
lux push status                               # local push config and health
lux push status my-app                        # cloud push config and health
lux seed run                                  # run lux/seed.lux against local
lux seed run my-app                           # run against explicit cloud
lux types                                     # generate TypeScript types from your schema
```

## Local development

Run a full local stack in Docker, Supabase-style. `lux start` boots a local
engine, applies your migrations (and seeds on a fresh volume), then launches
**Lux Studio** — a local web UI to browse/edit tables, run console commands, and
manage auth — pointed at that engine.

```bash
lux start                  # engine + Studio; prints connection info + the Studio URL
lux start --no-studio      # engine only
lux start --fresh          # recreate from a clean data volume (drops local data)
lux start --bind 0.0.0.0   # explicitly expose both services on every interface
lux studio                 # open Lux Studio in your browser (starts it if needed)
lux status                 # show local engine status
lux env export local       # print the local profile when explicitly needed
lux stop                   # stop the engine + Studio
lux stop --clear           # also delete the local data volume
```

`lux start` refreshes a private `local` env profile containing `LUX_URL`,
`LUX_PUBLISHABLE_KEY`, `LUX_SECRET_KEY`, and `LUX_DIRECT_URL`. On first setup it
safely merges those Lux-managed keys into `.env.local`; later starts preserve
whichever profile you selected with `lux env use`. Unrelated application
variables and comments in `.env.local` are never replaced.
The local secret key equals the engine password, so a secret-key client gets
operator access while a publishable-key client must sign in (JWT → grant-enforced
user), mirroring production. Studio runs as a container
(`ghcr.io/lux-db/studio`) and talks to the engine
directly from your browser. With the default loopback binding, credentials
never leave your machine.

Engine and Studio ports bind to `127.0.0.1` by default. Use `--bind <IP>` only
when another device or development environment must reach them. Non-loopback
bindings expose an operator credential through Studio, so they are intended for
trusted networks and explicit port-forwarding setups.

Existing engine and Studio containers never change versions implicitly during
`lux start`. Start reports available image updates; `lux update engine` and
`lux update studio` perform them explicitly. Local engine updates preserve the
data volume and restart a running engine. Cloud updates first create a completed
snapshot and automatically roll back to the prior immutable image if the new
engine fails its management health check.

## Local Connections

Connect directly to any Lux or Redis instance without going through the cloud API:

```bash
lux connect lux://localhost:6379
lux connect lux://:password@localhost:6379
lux connect -H localhost -p 6379 -a mypassword
```

## Migrations

Manage schema changes with versioned `.lux` files:

```bash
# Create a new migration
lux migrate new create_users
# Creates lux/migrations/{timestamp}_create_users.lux

# Use a custom migration directory
lux migrate new create_users --dir db/migrations
lux migrate status --dir db/migrations
lux migrate run --dir db/migrations

# Check migration status (an omitted project always means local)
lux migrate status
lux migrate status my-app              # cloud project
lux migrate status --host 10.0.0.5     # specific host

# Preview exact engine decisions without executing anything
lux migrate plan
lux migrate plan my-app

# Run all pending migrations
lux migrate run                               # local instance
lux migrate run my-app                        # cloud project
lux migrate run lux://:pass@myhost:6379       # connection string
lux migrate run --host 10.0.0.5 --port 6379   # specific host

# Pull migrations recorded on the target into the local directory
# (e.g. ones authored in the Lux Cloud dashboard)
lux migrate pull my-app                       # cloud project
lux migrate pull --host 10.0.0.5 --port 6379  # specific host

# Explicitly resolve an interrupted or failed migration after reviewing status
lux migrate repair 202607280001_create_users.lux resume 1
lux migrate repair 202607280001_create_users.lux mark-applied
lux migrate repair 202607280001_create_users.lux abandon
```

`lux link` records the cloud project associated with the repository for
comparison commands such as `lux status --all`. It never changes the target of
an omitted command: `lux migrate run` is local and `lux migrate run my-app` is
cloud.

Migration files contain Lux commands (one per line). Lines starting with `#` or `--` are comments. Commands can be written as shell-like strings:

```text
TCREATE users id STR PRIMARY KEY, email STR UNIQUE
TINSERT users id user_1 email user@example.com
```

Access grants are authored the same way, so row-level security versions and
travels with your schema:

```text
GRANT read, write ON messages WHERE user_id = auth.uid()
GRANT read ON messages WHERE workspace_id IN ( SELECT workspace_id FROM members WHERE user_id = auth.uid() )
```

For commands with complex quoted values, use JSON argv arrays:

```json
["TINSERT", "posts", "id", "post_1", "body", "hello world"]
```

The engine owns parsing, SHA-256 checksums, execution, and the `__migrations`
ledger. It records progress before executing commands. A failed or interrupted
migration blocks later writes and is never replayed or resumed automatically;
use `lux migrate status` to review its command cursor, then choose an explicit
repair action. `pull` understands legacy checksums and never overwrites a local
file that differs from the recorded version.

## Doctor, versions, and updates

```bash
lux doctor                         # local runtime, env, engine API, migrations
lux doctor my-app                  # explicit cloud project
lux doctor --all                   # local + linked cloud
lux doctor --fix                   # safe filesystem hygiene only
lux doctor --output json

lux version                        # CLI + local engine + Studio
lux version my-app                 # cloud engine
lux version --all                  # include linked cloud
lux update --check                 # legacy alias: check CLI
lux update cli                     # update CLI
lux update engine                  # local engine
lux update engine my-app           # cloud engine
lux update studio                  # local Studio
```

`doctor --fix` is intentionally constrained: it may create
`lux/migrations`, add Lux secret paths to `.gitignore`, and rebuild a missing
local env profile from existing local state. It never starts, stops, updates,
migrates, repairs, rotates credentials, or changes the active app target.
For Cloud projects, `doctor` checks version and capability support over the
authenticated direct connection while migration state uses Cloud's dedicated
management endpoints; it never sends generic `LUX` commands through the
restricted Cloud console.

Self-hosted tooling can discover the engine's Studio contract without
credentials from `GET /v1` (or the richer `GET /v1/version`). Both responses
advertise `studio_api` and a capability list, allowing a Studio client to hide
or label unavailable features instead of inferring support from a version
number.

## Auth providers

Lux Auth supports Google, GitHub, and Apple. Provider commands target the local
`lux start` engine by default. For a remote self-hosted engine, pass `--url` and
`--password`, or set `LUX_ENGINE_URL` and `LUX_ENGINE_PASSWORD`. Remote URLs must
use HTTPS; HTTP is accepted only for localhost. Managed Cloud providers are
normally configured on the project's **Auth** page.

```bash
# Google and GitHub (callback defaults to the target engine's auth callback)
lux auth provider google \
  --client-id GOOGLE_CLIENT_ID \
  --client-secret GOOGLE_CLIENT_SECRET
lux auth provider github \
  --client-id GITHUB_CLIENT_ID \
  --client-secret GITHUB_CLIENT_SECRET

# Native Sign in with Apple on the local engine
lux auth provider apple --bundle-id com.example.app

# Apple web sign-in on a publicly reachable HTTPS engine
lux auth provider apple \
  --url https://db.example.com \
  --password "$LUX_ENGINE_PASSWORD" \
  --services-id com.example.web \
  --team-id TEAM_ID \
  --key-id KEY_ID \
  --p8 AuthKey_KEY_ID.p8

# Secrets are redacted from this output
lux auth provider list
```

Use `--redirect-uri` with Google or GitHub when their registered callback differs
from the engine default. Re-running a command with an omitted client secret or
Apple key retains the encrypted value already stored by the engine. The `.p8`
file and provider secrets are sent directly to encrypted provider storage; they
are never written to CLI configuration or printed.

## Push configuration

Push configuration has the same target rule as migrations: omitted means local;
a positional project means cloud. Status is secret-free. APNs keys are read from
a file and sent directly to the engine-owned encrypted configuration—the CLI
never writes them to its config or prints them.

```bash
lux push status
lux push status my-app --check
lux push status --output json

lux push apns set \
  --team-id TEAM_ID \
  --key-id KEY_ID \
  --topic com.example.app \
  --environment sandbox \
  --p8-file AuthKey_KEY_ID.p8

# Metadata-only updates preserve the existing encrypted .p8 key
lux push apns set my-app \
  --team-id TEAM_ID \
  --key-id KEY_ID \
  --topic com.example.app \
  --environment production

lux push vapid enable --subject mailto:push@example.com
lux push vapid rotate --subject mailto:push@example.com --yes
lux push vapid disable --yes
lux push apns clear --yes
```

VAPID enable is idempotent. Rotation deliberately changes the browser-facing
public key and therefore requires `--yes`, because existing subscriptions must
resubscribe. Clearing either provider also requires `--yes`.

## Seeds

Use `lux/seed.lux` for stable local/demo data:

```bash
lux seed run
lux seed run my-app
lux seed run --file lux/demo.seed.lux
```

Seed files use the same command format as migrations, including JSON argv arrays. Seeds are not recorded in `__migrations`; write stable IDs if you want predictable demo data.

## Types

Generate TypeScript types from your project's table schema and feed them to the
SDK for end-to-end inference:

```bash
lux types                       # writes lux/types/database.ts (local instance)
lux types my-app                # generate from a cloud project
lux types --out src/db.ts       # custom output path
lux types --stdout              # print to stdout instead of writing a file
lux types --host 10.0.0.5       # specific host
```

The generated file exports a `Row` type per table plus a `Database` map. Pass it
to the SDK's `createClient<Database>()` so `lux.table(name)` infers row types and
autocompletes table names. System tables (`auth.*`, internal `_t:`/`__`) are
skipped. Re-run after a migration to keep types in sync.

## Project linking and env

Initialize a repo, link it to a Cloud project, and pull connection variables:

```bash
lux init
lux link my-app
lux env pull
```

`lux env pull` writes `.env.local` with app-first project settings:

```env
LUX_PROJECT_ID=
LUX_URL=
LUX_PUBLISHABLE_KEY=
LUX_SECRET_KEY=
LUX_DIRECT_URL=
```

Use `LUX_URL` with the SDK. `LUX_DIRECT_URL` is the optional RESP/database connection string for direct Redis-compatible access.

The database password is only needed for direct RESP access. Browser and server apps should normally use `LUX_URL` with a publishable or secret project key.

## Project keys

Manage Cloud gateway keys for browser and server access. Every auth-enabled Cloud project is created with default publishable and secret keys; create additional keys when you need rotation or a separate server/client boundary.

```bash
lux keys list
lux keys create --kind publishable --name browser
lux keys create --kind secret --name server
lux keys revoke <key-id>
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `LUX_API_URL` | Override the API URL (default: https://api.luxdb.dev) |

For local development:
```bash
export LUX_API_URL=http://localhost:3000
```
