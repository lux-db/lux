<p align="center">
  <img src="logo.png" alt="Lux" width="120" height="120" />
</p>

<h1 align="center">Lux</h1>

<p align="center">
  <strong>A database that works the way your app does.</strong>
</p>

<p align="center">
  The Application Database: one engine for tables, cache, vectors, realtime, queues, time series,<br/>
  and auth, instead of six services glued together. Written in Rust. MIT licensed forever.
</p>

<p align="center">
  <a href="https://github.com/lux-db/lux/actions/workflows/test.yml"><img src="https://github.com/lux-db/lux/actions/workflows/test.yml/badge.svg" alt="Tests" /></a>
  <a href="https://github.com/lux-db/lux/releases/latest"><img src="https://img.shields.io/github/v/release/lux-db/lux" alt="Release" /></a>
  <a href="https://github.com/lux-db/lux/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT License" /></a>
</p>

<p align="center">
  <a href="https://luxdb.dev">Lux Cloud</a> &middot;
  <a href="https://luxdb.dev/architecture">Architecture</a>
</p>

---

## What is Lux?

Lux is a database engine for modern application state. A real app is not just rows in a primary database: it is users and sessions, cache, live UI state, semantic search, jobs, metrics, queues, durable records, and low-latency commands. Lux puts those primitives in one runtime so they can share the same operational model, connection surface, durability layer, and SDK.

The engine speaks RESP, so supported Redis clients can connect directly. That compatibility is intentional: Lux should be easy to adopt for cache, queues, BullMQ, pub/sub, and command-oriented workloads. But Lux is not only a cache. It also includes typed relational tables, native vector search, time series, realtime key subscriptions, streams, snapshots, WAL recovery, tiered storage, and optional app auth.

Use Lux when you want one database process to cover the hot path of your application backend instead of stitching together Redis, Postgres, Pinecone, Kafka-style realtime plumbing, BullMQ, and a metrics store for every new product.

## Why Lux?

Every app has a second data layer beyond its primary rows: cache, sessions, live UI state, semantic search, jobs, metrics, queues, leaderboards. Today you assemble it from Redis + Postgres + Pinecone + Kafka-style plumbing + BullMQ + a metrics store, each its own connection string, SDK, dashboard, bill, and thing that breaks at 3am.

Lux collapses that into one engine. Tables, cache, vectors, realtime, queues, time series, and auth share one runtime, one connection surface, one durability layer, and one SDK. You add primitives as the app needs them instead of standing up another service for each one.

It speaks RESP, so supported Redis clients and tools can connect directly. That
compatibility is the on-ramp, not the ceiling; reach for the Lux SDK and CLI
when you want tables, migrations, gateway auth, and app-first workflows. The
documented command surface is listed in
[COMPATIBILITY.md](COMPATIBILITY.md).

## Architecture

Lux maps keys across independent in-process shards and executes network work on
Tokio. Commands that touch one shard can proceed independently of commands on
other shards. Multi-key commands, transactions, persistence, and Lux-native data
types have their own synchronization requirements; see
[COMPATIBILITY.md](COMPATIBILITY.md) and [DURABILITY.md](DURABILITY.md) for the
documented behavior.

Lux does not publish comparative performance claims from this repository
without pinned versions, configurations, hardware, raw results, and
reproducible commands.

## Lux Cloud

Don't want to manage infrastructure? **[Lux Cloud](https://luxdb.dev)** is the managed product built on the open-source Lux engine. It gives you projects, dashboard, browser/server SDK access, project keys, app auth, OAuth providers, snapshots, logs, metrics, MCP, and direct Redis-compatible access when you need it.

Lux Cloud is the managed option for building an app backend around Lux without
operating the runtime yourself. Self-hosting stays available because the engine
is MIT licensed and runs as a normal binary or container.

## Features

- **One command surface** -- strings, lists, hashes, sets, sorted sets, streams, vectors, geo, time series, tables, HyperLogLog, bitops, pub/sub, and transactions
- **Relational tables** -- TCREATE, TINSERT, TSELECT, TUPDATE (WHERE), TDELETE (WHERE), TALTER with typed fields (str, int, float, bool, timestamp, uuid, vector, json, array), unique constraints, foreign keys, encrypted columns, joins, GROUP BY/HAVING, WHERE/ORDER BY/LIMIT, `IN`/`NOT IN`, JSON dot-path queries with `IS VALID`, array `CONTAINS`, declared JSON-path indexes, and vector-aware NEAR queries. Structured data without standing up a separate primary database
- **Realtime key subscriptions** -- KSUB/KUNSUB: subscribe to key patterns and receive events when matching keys are mutated
- **Native time series** -- TSADD, TSGET, TSRANGE, TSMRANGE with aggregation (avg, sum, min, max, count, std), retention policies, and label-based filtering
- **Native vector search** -- VSET, VGET, VSEARCH with cosine similarity and metadata filtering, plus `VECTOR(n)` table columns that compose with table filters and live queries. No extensions, no sidecars
- **GEO commands** -- GEOADD, GEOSEARCH, GEODIST, GEOPOS, GEOHASH, GEORADIUS
- **LRU eviction** -- maxmemory with allkeys-lru, volatile-lru, allkeys-random, volatile-random policies
- **BullMQ-oriented primitives** -- blocking commands, streams, Lua scripting
  with cmsgpack/cjson, and an in-repo compatibility regression suite
- **Lua scripting** -- EVAL, EVALSHA, SCRIPT with redis.call/pcall, cmsgpack, and cjson
- **Redis Streams** -- XADD, XREAD, XREADGROUP, XACK, consumer groups, blocking reads
- **Blocking commands** -- BLPOP, BRPOP, BLMOVE, BZPOPMIN, BZPOPMAX
- **HTTP REST API** -- built-in JSON API on a separate port for browser, edge, serverless, and MCP-style access
- **RESP2 protocol** -- supported Redis clients can connect over RESP2; command
  compatibility is documented in [COMPATIBILITY.md](COMPATIBILITY.md)
- **Multi-threaded** -- auto-tuned shards, parking_lot RwLocks, tokio async runtime
- **Borrowed RESP parser** -- RESP arguments are parsed as byte slices from the
  read buffer; larger command argument lists may allocate
- **Pipeline batching** -- consecutive same-shard commands batched under a single lock
- **Persistence** -- automatic and asynchronous on-demand snapshots, write-ahead log (WAL) with CRC32 checksums, tiered hot/cold storage with automatic eviction to disk
- **Auth** -- project secret/publishable keys or the `LUX_PASSWORD` operator credential, plus optional app auth with users, identities, sessions, OAuth providers, JWTs, auth-owned system tables, and per-table row-level grants (`GRANT read, write ON t WHERE user_id = auth.uid()`) that gate reads, writes, and `.live()`
- **Pub/Sub** -- SUBSCRIBE, PSUBSCRIBE, PUBLISH, plus KSUB/KUNSUB for realtime key change events
- **TTL support** -- EX, PX, EXPIRE, PEXPIRE, PERSIST, TTL, PTTL
- **MIT licensed**

## Quick Start

```bash
curl -fsSL https://luxdb.dev/install.sh | sh
lux init
lux start
```

`lux start` launches the Engine and Lux Studio on loopback, applies migrations,
seeds a fresh volume, and prints the HTTP, RESP, publishable-key, and secret-key
connection values. Open Studio with `lux studio` or connect to the printed RESP
port with a supported Redis client.

> **Protocol note:** `lux://` is the primary protocol for the Lux SDK and CLI. When using third-party Redis clients (ioredis, redis-py, go-redis) directly, use `redis://` since they don't recognize `lux://`. Both connect to the same server.

```bash
lux exec local --host 127.0.0.1 --port 6379 --password <local-secret-key> SET hello world
```

### Workbenches

Lux publishes six [Workbench](https://github.com/pompeii-labs/workbenches) experts for building applications with Lux: `core`, `auth`, `migrations`, `realtime`, `push`, and `durability`.

Discover the available Workbenches, save the expert you need, and run it in your application repository:

```bash
wb list lux-db/lux
wb add lux-db/lux#core
wb run lux-core "Add a typed tasks table and wire up CRUD"
```

Choose the narrowest expert for the feature you are building. The Workbenches are consumer-focused: they help application developers use Lux correctly rather than modify the Lux engine itself.

### Embedded Rust API

Lux can run inside a Rust process without opening a RESP socket or going through
HTTP routing. The embedded client shares the same store, WAL, snapshots, Lua
engine, pub/sub broker, and command execution path as the server.

```rust
use std::time::Duration;

let cfg = lux::ServerConfig {
    enable_resp: false,
    data_dir: "./lux-data".to_string(),
    ..Default::default()
};
let handle = lux::run_with_config(cfg).await?;
let client = handle.client();

client.set("hello", "world").await?;
let value = client.get("hello").await?;
assert_eq!(value, Some(bytes::Bytes::from_static(b"world")));

let mut sub = client.subscribe("events");
client.publish("events", "ready").await?;
let message = sub.recv().await?;
assert_eq!(&message.payload[..], b"ready");

let blocked = handle.client();
let producer = handle.client();
let waiter = tokio::spawn(async move {
    blocked.blpop(&["jobs"], Duration::from_secs(5)).await
});
producer.rpush("jobs", &["job-1"]).await?;
assert_eq!(&waiter.await??.unwrap().1[..], b"job-1");

handle.shutdown_and_wait().await?;
```

`shutdown_and_wait` stops new work, drains accepted requests for up to 30
seconds, and performs a checked final journal sync. Hosts that need explicit
clean-versus-forced reporting can use `shutdown_and_wait_detailed` with their
own timeout.

Native methods like `get`, `set`, `hget`, `zadd`, `publish`, and `blpop` avoid
RESP encoding/parsing on the hot path. `EmbeddedPipeline` provides the same
native path for batched common commands. Use
`execute_embedded_pipeline_discard` for write-heavy batches that do not need
per-command replies. `execute`, `execute_bytes`, and `pipeline` remain
available as raw RESP-byte escape hatches. Embedded clients start authenticated
because they already run inside the trusted process boundary.

### Docker

```bash
LUX_PASSWORD="$(openssl rand -hex 32)"
docker run -d --stop-timeout 35 --read-only --cap-drop ALL \
  --security-opt no-new-privileges -p 6379:6379 -p 5890:5890 \
  -v lux-data:/data \
  -e LUX_PASSWORD="$LUX_PASSWORD" ghcr.io/lux-db/lux:latest
```

The image runs as numeric user `10001:10001`; `/data` is its only writable
path. Named volumes are initialized with the correct ownership. Give that user
write access before using a host bind mount. The image includes a small
`lux-healthcheck` executable: `live` checks process/listener liveness and
`ready` additionally requires the engine to be available for normal traffic.
The unauthenticated `/health/live` and `/health/ready` endpoints expose only
those states. They are intended for orchestrator probes, not database access.

### Docker Compose

```bash
export LUX_PASSWORD="$(openssl rand -hex 32)"
docker compose up -d        # start
docker compose up -d --build  # rebuild & start
docker compose down         # stop
```

### Vector Search

Lux has native vector storage and cosine similarity search. No extensions, no sidecars, no separate services.

```bash
# Store vectors with optional metadata
redis-cli VSET doc:1 3 0.1 0.2 0.3 META '{"title":"hello world"}'
redis-cli VSET doc:2 3 0.9 0.1 0.0 META '{"title":"another doc"}'

# Find the 5 nearest neighbors
redis-cli VSEARCH 3 0.1 0.2 0.3 K 5

# Search with metadata filtering
redis-cli VSEARCH 3 0.1 0.2 0.3 K 5 FILTER title "hello world" META

# Count vectors
redis-cli VCARD
```

Sub-millisecond search at 10,000 vectors with HNSW indexing. Built for AI agent memory, RAG, and semantic search.

### Time Series

Built-in time series with retention policies, label-based filtering, and aggregation. No modules required.

```bash
# Add samples with labels
redis-cli TSADD cpu:host1 '*' 72.5 RETENTION 86400000 LABELS host server1 metric cpu
redis-cli TSADD cpu:host1 '*' 75.0
redis-cli TSADD cpu:host1 '*' 68.2

# Get latest sample
redis-cli TSGET cpu:host1

# Query range with aggregation (1-hour average)
redis-cli TSRANGE cpu:host1 - + AGGREGATION avg 3600000

# Query across all series matching labels
redis-cli TSMRANGE - + FILTER host=server1

# Batch insert across multiple series
redis-cli TSMADD cpu:host1 '*' 72.5 mem:host1 '*' 45.0 disk:host1 '*' 82.1
```

Supported aggregation functions are avg, sum, min, max, count, first, last,
range, std.p, std.s, var.p, and var.s.

### Realtime Key Subscriptions (KSUB)

Subscribe to key mutation events by pattern. When any client writes to a matching key, subscribers receive a realtime notification with the key name and operation. No polling, no keyspace notification config, no separate service.

```bash
# Client A: subscribe to all user key mutations
redis-cli
> KSUB user:*

# Client B: write some data
redis-cli
> SET user:1 alice
> HSET user:2 name bob
> DEL user:1

# Client A receives:
# ["kmessage", "user:*", "user:1", "set"]
# ["kmessage", "user:*", "user:2", "hset"]
# ["kmessage", "user:*", "user:1", "del"]
```

Events are `["kmessage", pattern, key, operation]`. Operations are lowercase command names: `set`, `del`, `lpush`, `hset`, `zadd`, `tsadd`, etc.

**How it differs from Redis keyspace notifications:**

- KSUB does not require Redis's global `notify-keyspace-events` setting.
- Mutations check whether a key subscriber exists before constructing an event.
- With active subscribers, mutations enqueue events onto a bounded channel for
  asynchronous pattern matching and delivery. Saturated events are coalesced by
  key until the worker drains them.

Built for reactive applications, cache invalidation, live dashboards, and any use case where you need to react to data changes without polling.

### Tables

Built-in relational tables with typed fields, indexes, unique constraints, foreign keys, joins, grouped aggregates, and native vector fields.

```bash
# Create a table with typed fields
redis-cli TCREATE users id INT PRIMARY KEY, name STR, email STR UNIQUE, age INT, active BOOL

# Insert rows (* auto-generates timestamp)
redis-cli TINSERT users name Alice email alice@example.com age 28 active true created_at *
redis-cli TINSERT users name Bob email bob@example.com age 35 active false created_at *

# Query with WHERE, ORDER BY, LIMIT
redis-cli TSELECT '*' FROM users WHERE age '>' 25 ORDER BY age DESC LIMIT 10

# Foreign keys and joins
redis-cli TCREATE posts id INT PRIMARY KEY, title STR, author_id INT REFERENCES users(id)
redis-cli TINSERT posts id 1 title "Hello World" author_id 1
redis-cli TSELECT '*' FROM posts p JOIN users u ON p.author_id = u.id

# Grouped aggregates and left joins
redis-cli TSELECT author_id, COUNT(*) AS post_count FROM posts GROUP BY author_id HAVING post_count '>' 1
redis-cli TSELECT '*' FROM posts p LEFT JOIN users u ON p.author_id = u.id

# Vector fields compose with table filters
redis-cli TCREATE messages id INT PRIMARY KEY, channel STR, body STR, embedding VECTOR(3)
redis-cli TINSERT messages id 1 channel general body hello embedding "[0.1,0.2,0.3]"
redis-cli TSELECT id, body, _similarity FROM messages WHERE channel = general NEAR embedding "[0.1,0.2,0.3]" K 10 THRESHOLD 0.8

# Update and delete by predicates
redis-cli TUPDATE users SET active true WHERE id = 1
redis-cli TDELETE FROM users WHERE id = 2

# IN / NOT IN
redis-cli TSELECT '*' FROM users WHERE id IN '(' 1 2 3 ')'

# JSON and ARRAY columns, queried by dot-path like a JS object
redis-cli TCREATE events id INT PRIMARY KEY, metadata JSON, tags ARRAY
redis-cli TINSERT events id 1 metadata '{"plan":{"tier":"pro"},"count":0}' tags '["a","b"]'
redis-cli TSELECT '*' FROM events WHERE metadata.plan.tier = pro      # non-resolving path = non-match, never an error
redis-cli TSELECT '*' FROM events WHERE metadata.count IS VALID       # existence (0/false/"" are valid), not truthiness
redis-cli TSELECT '*' FROM events WHERE tags CONTAINS a               # array membership; tags.0 indexes an element
redis-cli TINDEX events metadata.plan.tier STR                        # declare a JSON-path index

# Encrypted columns keep values encrypted in WAL/snapshots/tiered storage.
# Add SEARCHABLE when you need exact equality filters or UNIQUE. ENCRYPTED
# columns do not support DEFAULT because defaults are stored in schema metadata.
redis-cli TCREATE secrets id UUID PRIMARY KEY, token STR ENCRYPTED, email STR UNIQUE ENCRYPTED SEARCHABLE
redis-cli TSELECT '*' FROM secrets WHERE email = alice@example.com

# Alter tables
redis-cli TALTER users ADD role STR
redis-cli TALTER users DROP role
```

Field types: `STR`, `INT`, `FLOAT`, `BOOL`, `TIMESTAMP`, `UUID`, `VECTOR(n)`, `JSON`, `ARRAY`.
WHERE operators: `= != < > <= >=`, `IN`/`NOT IN`, JSON `IS VALID`/`IS NOT VALID`, and `CONTAINS`.
Use SQL-style constraints like `UNIQUE`, `PRIMARY KEY`, and `REFERENCES table(field)`. Encrypted columns and encrypted provider secrets use native `ENC` state (`ENC INIT`, `ENC ROTATE`, `ENC LIST`); `lux start` and Lux Cloud auto-initialize their managed keyrings.

### CLI

```bash
curl -fsSL https://luxdb.dev/install.sh | sh
```

```bash
lux init                               # scaffold local Lux project files
lux start                              # run a local engine + Studio (web UI) in Docker
lux start --bind 0.0.0.0               # explicitly expose local ports on the network
lux studio                             # open Lux Studio against the local engine
lux stop                               # stop the local engine + Studio
lux restore ./lux.dat                  # transactionally restore the local engine
lux login                              # authenticate with a lux_ token
lux link my-app                        # associate this repo with a cloud project
lux target                             # show local, linked-cloud, and app-env targets
lux projects                           # list projects
lux create my-app --accept-charges     # create a new project
lux status                             # show local engine status
lux status my-app                      # show explicit cloud status and metrics
lux exec my-app SET hello world        # run a command
lux logs my-app                        # fetch explicit cloud project logs
lux restart my-app                     # restart explicit cloud project
lux connect my-app                     # interactive REPL via cloud
lux connect lux://localhost:6379       # connect to local instance
lux keys list                          # list project API keys
lux env pull my-app                    # save a private cloud env profile
lux env use my-app                     # safely activate its Lux variables
lux destroy my-app --accept-consequences  # delete project
```

See [cli/README.md](cli/README.md) for full installation and usage docs.

### SDK

```bash
bun i @luxdb/sdk
```

```typescript
import { Lux, createBrowserClient, type LuxAggregateRow, type LuxNearRow } from "@luxdb/sdk"

interface User {
  id: number
  email: string
  age: number
}

interface Message {
  id: string
  channel_id: string
  body: string
  embedding: number[]
}

interface Member {
  id: number
  team_id: number
  age: number
}

// App/project client over HTTP. Use a publishable key in browser clients
// and a secret key on trusted servers.
const lux = createBrowserClient(
  "https://api.luxdb.dev/v1/my-project",
  "lux_pub_..."
)

const { data: session, error: signInError } = await lux.auth.signInWithPassword({
  email: "user@example.com",
  password: "correct horse battery staple",
})

const { data: users, error } = await lux
  .table<User[]>("users")
  .select()
  .gt("age", 25)
  .order("age", { ascending: false })
  .limit(10)

if (error) throw error

const { data: user } = await lux
  .table<User>("users")
  .select()
  .eq("id", 1)
  .single()

type TeamStats = { team_id: number } & LuxAggregateRow<"count">

const { data: teamCounts } = await lux
  .table<Member>("members")
  .select<TeamStats>("team_id,COUNT(*) AS count")
  .leftJoin("teams", "t", "team_id", "id")
  .group("team_id")
  .having("count", "gt", 1)

await lux
  .table("messages")
  .update({ body: "edited" })
  .eq("id", 42)

await lux
  .table("messages")
  .delete()
  .eq("id", 42)

const sub = lux
  .table<Message>("messages")
  .select<LuxNearRow<Message>>("id,channel_id,body,_similarity")
  .eq("channel_id", "general")
  .near("embedding", queryEmbedding, { k: 20, threshold: 0.8 })
  .live()
  .on("insert", (event) => {
    console.log(event.new)
  })

// Direct RESP client for server-side Redis-compatible access.
const db = new Lux("lux://localhost:6379")

await db.vset("doc:1", embedding, { metadata: { title: "my doc" } })
const results = await db.vsearch(queryEmbedding, { k: 5, meta: true })

await db.tsadd("cpu:host1", '*', 72.5, { labels: { host: "server1" } })
const latest = await db.tsget("cpu:host1")
const range = await db.tsrange("cpu:host1", '-', '+', {
  aggregation: { type: 'avg', bucketSize: 3600000 }
})

const sub = db.ksub(["user:*"], (event) => {
  console.log(`${event.key} was ${event.operation}`)
})
```

The direct client extends ioredis with typed methods for vectors, time series,
and realtime key subscriptions. Redis commands documented as supported in
[COMPATIBILITY.md](COMPATIBILITY.md) remain available through ioredis.
Project clients use the Cloud/self-hosted HTTP gateway and return `{ data, error }` results for app code.

### HTTP REST API

Lux has a built-in HTTP/JSON API. Set `LUX_HTTP_PORT` to enable it alongside the
RESP protocol. It exposes engine discovery and management, command execution,
keys, tables, time series, vectors, push, and app-auth routes.

```bash
LUX_HTTP_PORT=5890 ./target/release/lux
```

**Key-Value:**
```bash
curl http://localhost:5890/v1/kv/mykey                    # GET
curl -X PUT http://localhost:5890/v1/kv/mykey \
  -d '{"value":"hello","ex":3600}'                        # SET (with optional TTL)
curl -X DELETE http://localhost:5890/v1/kv/mykey           # DEL
curl -X POST http://localhost:5890/v1/kv/counter/incr      # INCR
curl http://localhost:5890/v1/kv/myhash/hash               # HGETALL
curl http://localhost:5890/v1/kv/mylist/list                # LRANGE
curl http://localhost:5890/v1/kv/myset/set                 # SMEMBERS
curl http://localhost:5890/v1/kv/myzset/zset               # ZRANGEBYSCORE
```

**Tables:**
```bash
curl -X POST http://localhost:5890/v1/tables \
  -d '{"name":"users","columns":["id INT PRIMARY KEY","name STR","age INT"]}'   # TCREATE
curl http://localhost:5890/v1/tables                        # TLIST
curl -X POST http://localhost:5890/v1/tables/users \
  -d '{"name":"Alice","age":"28"}'                          # TINSERT
curl 'http://localhost:5890/v1/tables/users?where=age>25&order=name&limit=10'  # TSELECT
curl http://localhost:5890/v1/tables/users/1                # row lookup endpoint
curl -X PATCH http://localhost:5890/v1/tables/users/1 \
  -d '{"name":"Alicia"}'                                    # TUPDATE ... WHERE id = 1
curl -X DELETE 'http://localhost:5890/v1/tables/users?where=id=1'  # TDELETE ... WHERE id = 1
```

**Time Series:**
```bash
curl -X POST http://localhost:5890/v1/ts/cpu:host1 \
  -d '{"value":72.5,"labels":{"host":"server1"}}'          # TSADD
curl http://localhost:5890/v1/ts/cpu:host1/latest           # TSGET
curl 'http://localhost:5890/v1/ts/cpu:host1?from=-&to=+&agg=avg&bucket=3600000'  # TSRANGE
curl http://localhost:5890/v1/ts/cpu:host1/info             # TSINFO
```

**Vectors:**
```bash
curl -X POST http://localhost:5890/v1/vectors/doc:1 \
  -d '{"vector":[0.1,0.2,0.3],"metadata":{"title":"hello"}}'  # VSET
curl http://localhost:5890/v1/vectors/doc:1                     # VGET
curl -X POST http://localhost:5890/v1/vectors/search \
  -d '{"vector":[0.1,0.2,0.3],"k":5}'                         # VSEARCH
curl http://localhost:5890/v1/vectors                            # VCARD
```

**Exec (any command):**
```bash
curl -X POST http://localhost:5890/v1/exec \
  -d '{"command":["HSET","user:1","name","alice"]}'
```

Authenticate with `Authorization: Bearer <credential>`, where the credential is
a project secret key (`lux_sec_*`) or the operator password. CORS is enabled by
default.

### App Auth

Lux can also expose a Supabase-style app auth surface. Project keys are engine
credentials in their own right, so one secret key covers auth, data, native
commands, vectors, pubsub, lua and `.live()`:

- `LUX_PASSWORD` is the operator/break-glass credential; it still works everywhere.
- `LUX_AUTH_ENABLED=true` creates and serves app auth endpoints.
- `LUX_AUTH_PUBLISHABLE_KEY` is safe for browser/client auth calls.
- `LUX_AUTH_SECRET_KEY` is the server-side credential: full project access on
  every surface, including RESP.

An engine is credential-gated once it has a password *or* project keys.
Publishable keys never reach RESP and, on HTTP, reach only `/auth/v1/*` until a
signed-in user's JWT accompanies them; grants then decide which rows.

```bash
LUX_HTTP_PORT=5890 \
LUX_AUTH_ENABLED=true \
LUX_AUTH_PUBLISHABLE_KEY=lux_pub_local \
LUX_AUTH_SECRET_KEY=lux_sec_local \
./target/release/lux
```

Auth creates reserved tables under the `auth` namespace:

| Table | Purpose |
|-------|---------|
| `auth.users` | App users |
| `auth.identities` | Email/password and OAuth identities linked to users |
| `auth.sessions` | Refresh-token sessions |
| `auth.keys` | Project publishable/secret keys |
| `auth.grants` | Per-table access grants (row-level) |
| `auth.providers` | OAuth provider configuration |

Core auth routes:

```bash
POST /auth/v1/signup
POST /auth/v1/token
GET  /auth/v1/user
POST /auth/v1/logout
GET  /auth/v1/authorize?provider=google&redirect_to=http://localhost:5173/callback
POST /auth/v1/signin/apple
```

OAuth authorization-code clients can send an RFC 7636
`code_challenge` with `code_challenge_method=S256`, then include the matching
`code_verifier` in the token exchange. Lux binds and verifies the pair before
consuming the one-time code. PKCE is required for custom-scheme callback URLs;
browser HTTP(S) flows remain backward compatible.

Lux supports Google, GitHub, and Apple OAuth. Configure a local or remote
self-hosted engine with the CLI; managed Cloud projects use the **Auth** page in
the Lux dashboard.

```bash
# Google
lux auth provider google \
  --client-id GOOGLE_CLIENT_ID \
  --client-secret GOOGLE_CLIENT_SECRET

# GitHub
lux auth provider github \
  --client-id GITHUB_CLIENT_ID \
  --client-secret GITHUB_CLIENT_SECRET

# Native iOS/macOS
lux auth provider apple --bundle-id com.example.app

# Apple web (the engine must be reachable at a public HTTPS URL)
lux auth provider apple \
  --url https://db.example.com \
  --password "$LUX_ENGINE_PASSWORD" \
  --services-id com.example.web \
  --team-id YOUR_TEAM_ID \
  --key-id YOUR_KEY_ID \
  --p8 /path/to/AuthKey.p8
```

`lux start` initializes encrypted provider storage automatically. Other
self-hosted deployments must initialize the keyring before uploading an Apple
`.p8`; Lux refuses to persist that key in plaintext. Remote provider
configuration requires HTTPS, while plain HTTP is accepted only for localhost.
Local Studio exposes the same Google, GitHub, and Apple provider settings from
its **Auth -> Providers** tab.

OAuth providers are configured through admin routes with a secret key:

```bash
curl -X PUT http://localhost:5890/auth/v1/admin/providers/google \
  -H "Authorization: Bearer lux_sec_local" \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "client_id": "GOOGLE_CLIENT_ID",
    "client_secret": "GOOGLE_CLIENT_SECRET",
    "redirect_uri": "http://localhost:5890/auth/v1/callback/google",
    "scopes": "openid email profile"
  }'
```

Use `createBrowserClient(url, publishableKey)` in browsers and `createClient(url, secretKey)` on trusted servers. Browser live subscriptions use the publishable key plus the signed-in user's JWT. Direct RESP access takes the secret key (`AUTH lux_sec_...`) or the operator password.

#### Grants (row-level access)

With auth enabled, token (end-user) principals are **denied by default**; operator (`LUX_PASSWORD`) and service-key callers bypass. Access is granted per table with a row-scoped predicate:

```bash
redis-cli GRANT read, write ON messages WHERE user_id = auth.uid()
redis-cli REVOKE read ON messages

# membership through a junction table: see messages in workspaces you belong to
redis-cli GRANT read, write ON messages WHERE workspace_id IN ( SELECT workspace_id FROM members WHERE user_id = auth.uid() )
```

- Two scopes: `read` (covers SELECT and `.live()`), `write` (INSERT/UPDATE/DELETE; INSERT is checked against the new row, UPDATE/DELETE against the WHERE).
- **Auto-filter (USING).** A grant's `WHERE` is applied automatically as an implicit row filter that *narrows* access; it never widens it. A bare SELECT (or `.live()`) returns only the rows the grant allows, and UPDATE/DELETE are scoped the same way; the caller does not restate the predicate. INSERT/UPSERT get a WITH CHECK: the new row must fall inside the grant.
- Predicate values: `auth.uid()` (the caller's id), `auth.<claim>` (e.g. `auth.role`, `auth.email`), or a literal. Operators `= != < > <= >=`. Combine conditions with `AND`.
- **Membership subqueries** express relationship access (the canonical multi-tenant pattern `users <-> members <-> workspaces`): `col [NOT] IN ( SELECT col FROM t WHERE <predicate> )`. The subquery is *uncorrelated* (its WHERE references `auth.*`, literals, and its own columns, not the outer row), runs once per request, and is auto-applied as a filter. A user in no workspaces sees nothing; gate child tables (`messages.workspace_id IN (...)`) and create the parent via ownership or a service key (inserting a brand-new workspace whose id isn't yet a membership is correctly denied).
- Grants are authored as migrations, so they version and travel with schema (`lux migrate run` / `lux migrate pull`).

### Environment Variables

#### Server and storage

| Variable | Default | Description |
|----------|---------|-------------|
| `LUX_RUNTIME_THREADS` | Tokio default | Positive number of async runtime worker threads |
| `LUX_BIND_HOST` | `127.0.0.1` | Interface for RESP and HTTP listeners |
| `LUX_PORT` | `6379` | RESP (Redis-compatible) TCP port |
| `LUX_HTTP_PORT` | (disabled) | HTTP API port (set to enable; `lux start` defaults it to `5890`) |
| `LUX_PASSWORD` | (none) | Operator/break-glass AUTH (RESP and HTTP). Project keys also gate the engine |
| `LUX_ALLOW_INSECURE_NO_AUTH` | `false` | Explicitly allow an unauthenticated non-loopback bind; development only |
| `LUX_ENABLE_RESP` | `true` | Set to `0` or `false` to disable the RESP listener |
| `LUX_RESTRICTED` | `false` | Disable `KEYS`, `FLUSHALL`, `FLUSHDB`, and `DEBUG` |
| `LUX_DATA_DIR` | image: `/data`; binary: `.` | Snapshot and journal root; persistent relative paths are resolved at startup |
| `LUX_DURABILITY` | `always_sync` | Acknowledgement policy: `ephemeral`, `every_second`, or `always_sync` |
| `LUX_DURABILITY_SYNC_INTERVAL_MS` | `1000` | WAL sync interval for `every_second` (1–1000 ms); invalid for other policies |
| `LUX_SHUTDOWN_TIMEOUT_MS` | `30000` | Grace period for accepted work during SIGINT/SIGTERM shutdown (1–300000 ms) |
| `LUX_SAVE_INTERVAL` | `60` | Snapshot interval in seconds (0 to disable) |
| `LUX_SHARDS` | auto | Next power of two at or above logical CPUs × 16, clamped to 16–1024 |
| `LUX_MAX_ROWS` | (unlimited) | Optional maximum row count returned by an HTTP table query |
| `LUX_MAX_BODY_SIZE` | `67108864` | Maximum HTTP request body in bytes |
| `LUX_MAX_RESP_REQUEST_SIZE` | `67108864` | Maximum buffered RESP request in bytes |
| `LUX_MAXMEMORY` | `0` (unlimited) | Memory limit (e.g. `100mb`, `1gb`) |
| `LUX_MAXMEMORY_POLICY` | `noeviction` | Eviction policy: `allkeys-lru`, `volatile-lru`, `allkeys-random`, `volatile-random` |
| `LUX_MAXMEMORY_SAMPLES` | `5` | Keys sampled per eviction round |
| `LUX_STORAGE_MODE` | `memory` | Data-placement layout: `memory` or `tiered`; independent of durability |
| `LUX_STORAGE_DIR` | `{LUX_DATA_DIR}/storage` | Tiered data and WAL directory; valid only in `tiered` mode |

#### App auth

| Variable | Default | Description |
|----------|---------|-------------|
| `LUX_AUTH_ENABLED` | `false` | Enable app auth tables and `/auth/v1` routes |
| `LUX_AUTH_ACCESS_TOKEN_TTL` | `3600` | Access-token lifetime in seconds |
| `LUX_AUTH_REFRESH_TOKEN_TTL` | `2592000` | Refresh-token lifetime in seconds |
| `LUX_AUTH_ISSUER` | `http://localhost:{HTTP port}/auth/v1` | JWT issuer; the default HTTP port is `5890` |
| `LUX_AUTH_SITE_URL` | local HTTP address | Application base URL used by auth flows |
| `LUX_AUTH_EMAIL_PASSWORD` | `true` | Enable email/password sign-up and sign-in |
| `LUX_AUTH_EMAIL_CONFIRMATION_REQUIRED` | `false` | Require email confirmation before normal sign-in |
| `LUX_AUTH_ANONYMOUS` | `true` | Enable anonymous sign-in |
| `LUX_AUTH_FLOW_TOKEN_TTL_SECONDS` | `86400` | Email confirmation/recovery flow-token lifetime |
| `LUX_AUTH_PUBLISHABLE_KEY` | (none) | Initial browser-safe project key; `lux start` generates one |
| `LUX_AUTH_SECRET_KEY` | (none) | Initial server/admin project key; `lux start` generates one |

Managed email delivery is optional. Without it, auth uses the engine's console
delivery behavior. The supported managed provider is Postmark.

| Variable | Default | Description |
|----------|---------|-------------|
| `LUX_AUTH_MANAGED_EMAIL_PROVIDER` | `postmark` when a token is set | Managed delivery provider; currently `postmark` |
| `LUX_AUTH_MANAGED_EMAIL_FROM` | (none) | Required managed sender address, optionally `Name <address>` |
| `LUX_AUTH_MANAGED_EMAIL_REPLY_TO` | (none) | Optional Reply-To address |
| `LUX_AUTH_MANAGED_POSTMARK_SERVER_TOKEN` | (none) | Postmark server token |
| `LUX_AUTH_MANAGED_POSTMARK_MESSAGE_STREAM` | `outbound` | Postmark message stream |

#### Encryption at rest

`ENC INIT`/`ENC ROTATE` with persisted state is the preferred configuration.
For production, inject the seal key from a secret store so the data volume does
not contain both encrypted state and the key that seals it.

| Variable | Default | Description |
|----------|---------|-------------|
| `LUX_ENC_AUTO_INIT` | `false` | Initialize a persisted encryption keyring when none exists |
| `LUX_ENC_STATE_PATH` | `{LUX_DATA_DIR}/lux.enc` | Sealed encryption state path |
| `LUX_ENC_SEAL_PATH` | `{LUX_DATA_DIR}/lux.enc.seal` | Local seal-key path for development |
| `LUX_ENC_SEAL_KEY` | (none) | Base64-encoded 32-byte seal key supplied outside the data volume |
| `LUX_ENC_SEAL_KEY_PREVIOUS` | (none) | Comma-separated prior seal keys accepted during rotation |
| `LUX_ENCRYPTION_KEYS` | (none) | Legacy JSON bootstrap key list (`id`, `secret`, optional `decrypt_only`) |
| `LUX_ENCRYPTION_KEY` | (none) | Legacy single bootstrap key |
| `LUX_ENCRYPTION_KEY_ID` | `local` | Active/bootstrap key ID for legacy configuration |

`LUX_PUSH_ALLOW_PRIVATE_ENDPOINTS` set to `1` is an unsafe local
integration-test escape hatch for Web Push. It is not supported in production. See
[COMPATIBILITY.md](COMPATIBILITY.md#configuration-contract) for lifecycle and
file-format guarantees.

### Node.js

```bash
bun i @luxdb/sdk   # or: bun i ioredis
```

```typescript
import { Lux } from "@luxdb/sdk"

const db = new Lux("lux://localhost:6379")
await db.set("hello", "world")
await db.vset("doc:1", [0.1, 0.2, 0.3], { metadata: { title: "hello" } })
const results = await db.vsearch([0.1, 0.2, 0.3], { k: 5, meta: true })
```

### Python (redis-py)

```bash
pip install redis
```

```python
import redis

r = redis.Redis(host="localhost", port=6379)
r.set("hello", "world")
print(r.get("hello"))  # b"world"
```

### Go (go-redis)

```go
import "github.com/redis/go-redis/v9"

rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
rdb.Set(ctx, "hello", "world", 0)
```

## Testing

Lux uses unit, integration, property-based, compatibility, and crash-recovery
tests. The suite count is intentionally not hard-coded here because tests are
added and removed with the code they verify.

```bash
cargo test
```

### CI

The Tests workflow runs on every pull request and every push to `main`:

- `cargo fmt -- --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test --all-targets`
- CLI end-to-end tests against a locally built engine
- TypeScript SDK tests and build

Tag-triggered release, CLI-release, and Docker workflows run their own required
test jobs before publishing artifacts.

## Public contracts

- [COMPATIBILITY.md](COMPATIBILITY.md) -- Redis-compatible, Lux-native, divergent, and unsupported behavior
- [DURABILITY.md](DURABILITY.md) -- snapshot, WAL, restore, crash recovery, and data-loss expectations
- [MANAGEMENT_API.md](MANAGEMENT_API.md) -- version discovery, engine-owned migrations, repair, and push configuration
- [SECURITY.md](SECURITY.md) -- disclosure, deployment model, sensitive surfaces, and supported versions

## Common RESP Commands

This is a practical overview, not a claim that every Redis subcommand or edge
case is implemented. See [COMPATIBILITY.md](COMPATIBILITY.md) for compatible,
partial, divergent, and unsupported behavior.

**Strings:** `SET` `GET` `SETNX` `SETEX` `PSETEX` `GETSET` `GETDEL` `GETEX` `GETRANGE` `SETRANGE` `MGET` `MSET` `MSETNX` `STRLEN` `APPEND` `INCR` `DECR` `INCRBY` `DECRBY` `INCRBYFLOAT` `SETBIT` `GETBIT` `BITCOUNT` `BITPOS` `BITOP`

**Keys:** `DEL` `UNLINK` `EXISTS` `KEYS` `SCAN` `TYPE` `RENAME` `RENAMENX` `RANDOMKEY` `COPY` `TTL` `PTTL` `EXPIRE` `PEXPIRE` `EXPIREAT` `PEXPIREAT` `EXPIRETIME` `PEXPIRETIME` `PERSIST` `DBSIZE` `FLUSHDB` `FLUSHALL`

**Lists:** `LPUSH` `RPUSH` `LPUSHX` `RPUSHX` `LPOP` `RPOP` `BLPOP` `BRPOP` `BLMOVE` `LLEN` `LRANGE` `LINDEX` `LSET` `LINSERT` `LREM` `LTRIM` `LPOS` `LMOVE` `RPOPLPUSH`

**Hashes:** `HSET` `HSETNX` `HMSET` `HGET` `HMGET` `HDEL` `HGETALL` `HKEYS` `HVALS` `HLEN` `HEXISTS` `HINCRBY` `HINCRBYFLOAT` `HSTRLEN` `HRANDFIELD` `HSCAN`

**Sets:** `SADD` `SREM` `SMEMBERS` `SISMEMBER` `SMISMEMBER` `SCARD` `SPOP` `SRANDMEMBER` `SMOVE` `SUNION` `SINTER` `SDIFF` `SUNIONSTORE` `SINTERSTORE` `SDIFFSTORE` `SINTERCARD` `SSCAN`

**Sorted Sets:** `ZADD` `ZSCORE` `ZMSCORE` `ZRANK` `ZREVRANK` `ZREM` `ZCARD` `ZCOUNT` `ZLEXCOUNT` `ZINCRBY` `ZRANGE` `ZREVRANGE` `ZRANGEBYSCORE` `ZREVRANGEBYSCORE` `ZRANGEBYLEX` `ZREVRANGEBYLEX` `ZPOPMIN` `ZPOPMAX` `BZPOPMIN` `BZPOPMAX` `ZUNIONSTORE` `ZINTERSTORE` `ZDIFFSTORE` `ZREMRANGEBYRANK` `ZREMRANGEBYSCORE` `ZREMRANGEBYLEX` `ZSCAN`

**Geo:** `GEOADD` `GEODIST` `GEOPOS` `GEOHASH` `GEOSEARCH` `GEOSEARCHSTORE` `GEORADIUS` `GEORADIUSBYMEMBER` `GEORADIUS_RO` `GEORADIUSBYMEMBER_RO`

**Streams:** `XADD` `XLEN` `XRANGE` `XREVRANGE` `XREAD` `XREADGROUP` `XGROUP CREATE` `XGROUP DESTROY` `XACK` `XPENDING` `XCLAIM` `XAUTOCLAIM` `XDEL` `XTRIM` `XINFO STREAM` `XINFO GROUPS`

**HyperLogLog:** `PFADD` `PFCOUNT` `PFMERGE`

**Time Series:** `TSADD` `TSMADD` `TSGET` `TSRANGE` `TSMRANGE` `TSINFO`

**Pub/Sub:** `PUBLISH` `SUBSCRIBE` `PSUBSCRIBE` `UNSUBSCRIBE` `PUNSUBSCRIBE` `KSUB` `KUNSUB`

**Transactions:** `MULTI` `EXEC` `DISCARD` `WATCH` `UNWATCH`

**Vectors:** `VSET` `VGET` `VSEARCH` `VCARD`

**Tables:** `TCREATE` `TINSERT` `TSELECT` `TUPDATE` `TDELETE` `TDROP` `TCOUNT` `TSCHEMA` `TLIST` `TALTER` `TINDEX` `TDROPINDEX`

**Auth grants:** `GRANT` `REVOKE`

**Scripting:** `EVAL` `EVALSHA` `SCRIPT LOAD` `SCRIPT EXISTS` `SCRIPT FLUSH`

**Sorting:** `SORT` `SORT_RO`

**Server:** `PING` `ECHO` `QUIT` `HELLO` `INFO` `TIME` `SAVE` `BGSAVE` `LASTSAVE` `AUTH` `CONFIG` `CLIENT` `SELECT` `COMMAND` `OBJECT` `MEMORY`

## Known Differences from Redis

Lux is Redis-compatible but not identical. Key differences:

- **No AOF persistence** -- Lux uses snapshots plus a checksummed write-ahead
  log (WAL) instead of Redis AOF. The default `always_sync` policy fsyncs each
  mutation before acknowledging it. The opt-in `every_second` policy trades
  that guarantee for throughput and can lose acknowledged writes since its last
  successful fsync. See [DURABILITY.md](DURABILITY.md).
- **No RESP3 protocol** -- RESP2 only
- **No cluster mode** -- single-node only (use Lux Cloud for managed hosting)
- **MULTI/EXEC** -- supported with WATCH-based optimistic locking. Commands in a transaction execute sequentially, each acquiring its own shard and durability boundary, so another client can observe intermediate state and a process crash during an unacknowledged EXEC can recover a completed prefix. Redis avoids this via single-threading and transaction-aware AOF framing. Standard client libraries (Redlock, BullMQ, Sidekiq) rely on WATCH for correctness, not EXEC isolation. Full transaction isolation and crash-atomic framing may be added in a future release if there is demand
- **Pipeline ordering** -- per-client command order is preserved. Consecutive same-shard commands are batched for performance

## Architecture

```
Client connections (tokio tasks)
        |
   Borrowed RESP Parser
        |
   Command Dispatch
        |
   Sharded In-Memory Store
        |
   Snapshots + WAL (persistent durability)
```

Read the full deep dive at [luxdb.dev/architecture](https://luxdb.dev/architecture).

## License

MIT
