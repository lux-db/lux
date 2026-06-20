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
lux link my-app                               # save a default project for this repo
lux projects                                  # list all projects
lux create my-app --accept-charges            # create a Standard project
lux status                                    # show linked project status and live metrics
lux exec my-app SET hello world               # execute a command
lux exec my-app KEYS '*'                      # wildcards need quotes
lux logs                                      # fetch linked project logs
lux logs my-app -l 500                        # fetch 500 lines
lux restart                                   # restart linked project
lux destroy my-app --accept-consequences      # permanently delete
lux connect my-app                            # interactive REPL via Lux Cloud
lux keys list                                 # list project API keys
lux keys create --kind secret --name server   # create an additional project API key
lux keys revoke <key-id>                      # revoke a project API key
lux env pull                                  # write linked project env to .env.local
lux migrate new create_users                  # create a migration file
lux migrate status                            # check status (local instance)
lux migrate run                               # run pending migrations (local instance)
lux migrate run my-app                        # run against a cloud project
lux seed run                                  # run lux/seed.lux against the linked project
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
lux studio                 # open Lux Studio in your browser (starts it if needed)
lux status                 # show local engine status
lux status -o env          # print LUX_* env lines for `eval`
lux stop                   # stop the engine + Studio
lux stop --clear           # also delete the local data volume
```

`lux start` writes `.env.local` with `LUX_URL`, `LUX_PUBLISHABLE_KEY`,
`LUX_SECRET_KEY`, and `LUX_DIRECT_URL` so the SDK connects with no extra config.
The local secret key equals the engine password, so a secret-key client gets
operator access while a publishable-key client must sign in (JWT → grant-enforced
user), mirroring production. Studio runs as a container
(`ghcr.io/lux-db/studio`), pulled on each `lux start`, and talks to the engine
directly from your browser; credentials never leave your machine.

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

# Check migration status (defaults to localhost:6379)
lux migrate status
lux migrate status my-app              # cloud project
lux migrate status --host 10.0.0.5     # specific host

# Run all pending migrations
lux migrate run                               # local instance
lux migrate run my-app                        # cloud project
lux migrate run lux://:pass@myhost:6379       # connection string
lux migrate run --host 10.0.0.5 --port 6379   # specific host

# Pull migrations recorded on the target into the local directory
# (e.g. ones authored in the Lux Cloud dashboard)
lux migrate pull my-app                       # cloud project
lux migrate pull --host 10.0.0.5 --port 6379  # specific host
```

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

Applied migrations are tracked in a `__migrations` table on your project, which
also stores each migration's source so `lux migrate pull` can recreate the files
on another machine. Pull never overwrites a local file that differs from the
recorded version; it warns and keeps your copy.

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
LUX_AUTH_URL=
LUX_HTTP_URL=
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
