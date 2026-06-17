<p align="center">
  <img src="logo.png" alt="Lux" width="120" height="120" />
</p>

<h1 align="center">Lux</h1>

<p align="center">
  <strong>An open-source application database engine.</strong><br/>
  Tables, cache, vectors, realtime, queues, time series, auth, and Redis-compatible commands in one Rust runtime. MIT licensed forever.
</p>

<p align="center">
  <a href="https://github.com/lux-db/lux/actions/workflows/test.yml"><img src="https://github.com/lux-db/lux/actions/workflows/test.yml/badge.svg" alt="Tests" /></a>
  <a href="https://github.com/lux-db/lux/releases/latest"><img src="https://img.shields.io/github/v/release/lux-db/lux" alt="Release" /></a>
  <a href="https://github.com/lux-db/lux/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT License" /></a>
</p>

<p align="center">
  <a href="https://luxdb.dev">Lux Cloud</a> &middot;
  <a href="https://luxdb.dev/vs/redis">Benchmarks</a> &middot;
  <a href="https://luxdb.dev/architecture">Architecture</a>
</p>

---

## What is Lux?

Lux is a database engine for modern application state. A real app is not just rows in a primary database: it is users and sessions, cache, live UI state, semantic search, jobs, metrics, queues, durable records, and low-latency commands. Lux puts those primitives in one runtime so they can share the same operational model, connection surface, durability layer, and SDK.

The engine speaks RESP, so existing Redis clients still work. That compatibility is intentional: Lux should be easy to adopt for cache, queues, BullMQ, pub/sub, and command-oriented workloads. But Lux is not only a faster cache. It also includes typed relational tables, native vector search, time series, realtime key subscriptions, streams, snapshots, WAL recovery, tiered storage, and optional app auth.

Use Lux when you want one database process to cover the hot path of your application backend instead of stitching together Redis, Postgres, Pinecone, Kafka-style realtime plumbing, BullMQ, and a metrics store for every new product.

## Why Lux?

Redis is single-threaded by design. That simplicity is part of why it became foundational infrastructure. But it also creates a ceiling: once one core is saturated, the usual answer is to shard at the client or cluster level and accept the operational complexity.

Lux uses a **sharded concurrent architecture** that safely uses all your cores in a single process. Each key maps to one of N shards, each protected by a `parking_lot` RwLock. Reads never block reads. Writes only block the shard they touch. Tokio handles thousands of connections across cores. The result is single-digit microsecond latency at low concurrency and throughput that keeps scaling with cores and pipeline depth.

The concurrency model is deliberately conservative. Commands acquire a shard lock, do their work, and release it. There are no cross-shard locks in normal command execution and no lock-ordering games. MULTI/EXEC uses WATCH-based optimistic concurrency with shard versioning, matching what Redis clients rely on.

**Compatibility:** ioredis, redis-py, go-redis, Jedis, redis-rb, BullMQ, redis-cli, and other RESP clients can connect directly. Use the Lux SDK and CLI when you want higher-level tables, migrations, Cloud gateway auth, and app-first workflows.

### Benchmarks

`redis-benchmark`, 50 clients, 1M requests, pipeline=64. Sequential runs (one server at a time) on a 32-core Intel i9-14900K, 128GB RAM, Ubuntu 24.04.

| Command | Lux | Redis 8.6.1 | Lux/Redis |
|---------|-----|-------------|-----------|
| SET | 11.2M | 3.3M | **3.4x** |
| GET | 12.0M | 4.7M | **2.6x** |
| INCR | 6.3M | 4.0M | **1.6x** |
| LPUSH | 6.5M | 3.3M | **2.0x** |
| RPUSH | 6.4M | 3.7M | **1.7x** |
| LPOP | 11.6M | 3.0M | **3.9x** |
| RPOP | 11.1M | 3.3M | **3.4x** |
| SADD | 7.2M | 4.1M | **1.8x** |
| HSET | 6.8M | 3.3M | **2.0x** |
| SPOP | 12.2M | 4.5M | **2.7x** |
| ZADD | 7.0M | 3.1M | **2.3x** |
| ZPOPMIN | 11.5M | 5.3M | **2.2x** |
| GEOPOS | 5.26M | 2.60M | **2.0x** |
| GEODIST | 6.67M | 2.53M | **2.6x** |
| GEOSEARCH (500km) | 4.44M | 559K | **8.0x** |
| GEOSEARCH (5000km) | 200K | 20K | **10.0x** |

Lux beats Redis on the measured single-key command set at pipeline=64. At pipeline=1, both are network-bound and roughly equal. The gap grows with pipeline depth because Lux batches same-shard commands under a single lock while Redis processes sequentially on one core. Multi-key commands have different tradeoffs and should be benchmarked against your workload.

Full results including SET scaling by pipeline depth are in [BENCHMARKS.md](BENCHMARKS.md). Reproduce with `./bench.sh`.

## Lux Cloud

Don't want to manage infrastructure? **[Lux Cloud](https://luxdb.dev)** is the managed product built on the open-source Lux engine. It gives you projects, dashboard, browser/server SDK access, project keys, app auth, OAuth providers, snapshots, logs, metrics, MCP, and direct Redis-compatible access when you need it.

Lux Cloud is the fastest path when you want to build an app backend around Lux without operating the runtime yourself. Self-hosting stays available because the engine is MIT licensed and runs as a normal binary or container.

## Features

- **200+ commands** -- strings, lists, hashes, sets, sorted sets, streams, vectors, geo, time series, tables, HyperLogLog, bitops, pub/sub, transactions
- **Relational tables** -- TCREATE, TINSERT, TSELECT, TUPDATE (WHERE), TDELETE (WHERE), TALTER with typed fields (str, int, float, bool, timestamp, uuid, vector, json, array), unique constraints, foreign keys, joins, GROUP BY/HAVING, WHERE/ORDER BY/LIMIT, `IN`/`NOT IN`, JSON dot-path queries with `IS VALID`, array `CONTAINS`, declared JSON-path indexes, and vector-aware NEAR queries. Structured data without standing up a separate primary database
- **Realtime key subscriptions** -- KSUB/KUNSUB: subscribe to key patterns, receive events when matching keys are mutated. Zero overhead when unused. No global config flags, no separate services. Unlike Redis keyspace notifications which tax every write globally, KSUB is surgical and async
- **Native time series** -- TSADD, TSGET, TSRANGE, TSMRANGE with aggregation (avg, sum, min, max, count, std), retention policies, and label-based filtering. No modules, no sidecars. TSGET 4x faster than Redis GET
- **Native vector search** -- VSET, VGET, VSEARCH with cosine similarity and metadata filtering, plus `VECTOR(n)` table columns that compose with table filters and live queries. No extensions, no sidecars
- **GEO commands** -- GEOADD, GEOSEARCH, GEODIST, GEOPOS, GEOHASH, GEORADIUS with up to 10x faster spatial queries
- **LRU eviction** -- maxmemory with allkeys-lru, volatile-lru, allkeys-random, volatile-random policies
- **BullMQ compatible** -- blocking commands, streams, Lua scripting with cmsgpack/cjson
- **Lua scripting** -- EVAL, EVALSHA, SCRIPT with redis.call/pcall, cmsgpack, and cjson
- **Redis Streams** -- XADD, XREAD, XREADGROUP, XACK, consumer groups, blocking reads
- **Blocking commands** -- BLPOP, BRPOP, BLMOVE, BZPOPMIN, BZPOPMAX
- **HTTP REST API** -- built-in JSON API on a separate port for browser, edge, serverless, and MCP-style access
- **RESP2 protocol** -- compatible with every Redis client
- **Multi-threaded** -- auto-tuned shards, parking_lot RwLocks, tokio async runtime
- **Zero-copy parser** -- RESP arguments are byte slices into the read buffer
- **Pipeline batching** -- consecutive same-shard commands batched under a single lock
- **Persistence** -- automatic snapshots, write-ahead log (WAL) with CRC32 checksums, tiered hot/cold storage with automatic eviction to disk
- **Auth** -- password authentication via `LUX_PASSWORD`, plus optional app auth with users, identities, sessions, OAuth providers, JWTs, auth-owned system tables, and per-table row-level grants (`GRANT read, write ON t WHERE user_id = auth.uid()`) that gate reads, writes, and `.live()`
- **Pub/Sub** -- SUBSCRIBE, PSUBSCRIBE, PUBLISH, plus KSUB/KUNSUB for realtime key change events
- **TTL support** -- EX, PX, EXPIRE, PEXPIRE, PERSIST, TTL, PTTL
- **MIT licensed** -- no license rug-pulls, unlike Redis (RSALv2/SSPL)

## Quick Start

```bash
cargo build --release
./target/release/lux
```

Lux starts on `0.0.0.0:6379` by default. Connect with any Redis client using `lux://` or `redis://`:

> **Protocol note:** `lux://` is the primary protocol for the Lux SDK and CLI. When using third-party Redis clients (ioredis, redis-py, go-redis) directly, use `redis://` since they don't recognize `lux://`. Both connect to the same server.

```bash
redis-cli
> SET hello world
OK
> GET hello
"world"
```

### Embedded Rust API

Lux can run inside a Rust process without opening a RESP socket or going through
HTTP routing. The embedded client shares the same store, WAL, snapshots, Lua
engine, pub/sub broker, and command execution path as the server.

```rust
use std::time::Duration;

let cfg = lux::ServerConfig {
    enable_resp: false,
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

Native methods like `get`, `set`, `hget`, `zadd`, `publish`, and `blpop` avoid
RESP encoding/parsing on the hot path. `EmbeddedPipeline` provides the same
native path for batched common commands. Use
`execute_embedded_pipeline_discard` for write-heavy batches that do not need
per-command replies. `execute`, `execute_bytes`, and `pipeline` remain
available as raw RESP-byte escape hatches. Embedded clients start authenticated
because they already run inside the trusted process boundary.

### Docker

```bash
docker run -d -p 6379:6379 ghcr.io/lux-db/lux:latest
```

### Docker Compose

```bash
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

TSGET runs at 18M ops/sec at high pipeline. Supports avg, sum, min, max, count, first, last, range, std.p, std.s, var.p, var.s aggregation functions.

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
- Redis requires a global `notify-keyspace-events` config flag that adds overhead to every write, even if nobody is listening
- KSUB has zero overhead when no subscribers exist (single atomic check)
- When subscribers exist, event dispatch is fully async -- writes enqueue to a lock-free channel and a background task handles matching and delivery. The write path never blocks on subscriber fanout

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

# Alter tables
redis-cli TALTER users ADD role STR
redis-cli TALTER users DROP role
```

Field types: `STR`, `INT`, `FLOAT`, `BOOL`, `TIMESTAMP`, `UUID`, `VECTOR(n)`, `JSON`, `ARRAY`.
WHERE operators: `= != < > <= >=`, `IN`/`NOT IN`, JSON `IS VALID`/`IS NOT VALID`, and `CONTAINS`.
Use SQL-style constraints like `UNIQUE`, `PRIMARY KEY`, and `REFERENCES table(field)`.

### CLI

```bash
curl -fsSL https://luxdb.dev/install.sh | sh
```

```bash
lux init                               # scaffold local Lux project files
lux login                              # authenticate with a lux_ token
lux link my-app                        # save a default project for this repo
lux projects                           # list projects
lux create my-app --accept-charges     # create a new project
lux status                             # show linked project status and metrics
lux exec my-app SET hello world        # run a command
lux logs                               # fetch linked project logs
lux restart                            # restart linked project
lux connect my-app                     # interactive REPL via cloud
lux connect lux://localhost:6379       # connect to local instance
lux keys list                          # list project API keys
lux env pull                           # write .env.local for the linked project
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

Extends ioredis with typed methods for vectors, time series, and realtime key subscriptions. All standard Redis commands work as usual.
Project clients use the Cloud/self-hosted HTTP gateway and return `{ data, error }` results for app code.

### HTTP REST API

Lux has a built-in HTTP/JSON API. Set `LUX_HTTP_PORT` to enable it alongside the RESP protocol. Every data primitive gets its own RESTful routes.

```bash
LUX_HTTP_PORT=8080 ./target/release/lux
```

**Key-Value:**
```bash
curl http://localhost:8080/v1/kv/mykey                    # GET
curl -X PUT http://localhost:8080/v1/kv/mykey \
  -d '{"value":"hello","ex":3600}'                        # SET (with optional TTL)
curl -X DELETE http://localhost:8080/v1/kv/mykey           # DEL
curl -X POST http://localhost:8080/v1/kv/counter/incr      # INCR
curl http://localhost:8080/v1/kv/myhash/hash               # HGETALL
curl http://localhost:8080/v1/kv/mylist/list                # LRANGE
curl http://localhost:8080/v1/kv/myset/set                 # SMEMBERS
curl http://localhost:8080/v1/kv/myzset/zset               # ZRANGEBYSCORE
```

**Tables:**
```bash
curl -X POST http://localhost:8080/v1/tables \
  -d '{"name":"users","columns":["id INT PRIMARY KEY","name STR","age INT"]}'   # TCREATE
curl http://localhost:8080/v1/tables                        # TLIST
curl -X POST http://localhost:8080/v1/tables/users \
  -d '{"name":"Alice","age":"28"}'                          # TINSERT
curl 'http://localhost:8080/v1/tables/users?where=age>25&order=name&limit=10'  # TSELECT
curl http://localhost:8080/v1/tables/users/1                # row lookup endpoint
curl -X PUT http://localhost:8080/v1/tables/users/1 \
  -d '{"name":"Alicia"}'                                    # TUPDATE ... WHERE id = 1
curl -X DELETE http://localhost:8080/v1/tables/users/1      # TDELETE FROM ... WHERE id = 1
```

**Time Series:**
```bash
curl -X POST http://localhost:8080/v1/ts/cpu:host1 \
  -d '{"value":72.5,"labels":{"host":"server1"}}'          # TSADD
curl http://localhost:8080/v1/ts/cpu:host1/latest           # TSGET
curl 'http://localhost:8080/v1/ts/cpu:host1?from=-&to=+&agg=avg&bucket=3600000'  # TSRANGE
curl http://localhost:8080/v1/ts/cpu:host1/info             # TSINFO
```

**Vectors:**
```bash
curl -X POST http://localhost:8080/v1/vectors/doc:1 \
  -d '{"vector":[0.1,0.2,0.3],"metadata":{"title":"hello"}}'  # VSET
curl http://localhost:8080/v1/vectors/doc:1                     # VGET
curl -X POST http://localhost:8080/v1/vectors/search \
  -d '{"vector":[0.1,0.2,0.3],"k":5}'                         # VSEARCH
curl http://localhost:8080/v1/vectors                            # VCARD
```

**Exec (any command):**
```bash
curl -X POST http://localhost:8080/v1/exec \
  -d '{"command":["HSET","user:1","name","alice"]}'
```

Auth via `Authorization: Bearer <password>` when `LUX_PASSWORD` is set. CORS enabled by default. 174K ops/sec at 256 concurrent connections with keep-alive.

### App Auth

Lux can also expose a Supabase-style app auth surface. This is optional and is separate from the database password:

- `LUX_PASSWORD` protects direct RESP/admin HTTP access.
- `LUX_AUTH_ENABLED=true` creates and serves app auth endpoints.
- `LUX_AUTH_PUBLISHABLE_KEY` is safe for browser/client auth calls.
- `LUX_AUTH_SECRET_KEY` is for trusted servers and admin auth operations.

```bash
LUX_HTTP_PORT=8080 \
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
```

OAuth providers are configured through admin routes with a secret key:

```bash
curl -X PUT http://localhost:8080/auth/v1/admin/providers/google \
  -H "Authorization: Bearer lux_sec_local" \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "client_id": "GOOGLE_CLIENT_ID",
    "client_secret": "GOOGLE_CLIENT_SECRET",
    "redirect_uri": "http://localhost:8080/auth/v1/callback/google",
    "scopes": "openid email profile"
  }'
```

Use `createBrowserClient(url, publishableKey)` in browsers and `createClient(url, secretKey)` on trusted servers. Browser live subscriptions use the publishable key plus the signed-in user's JWT; direct RESP access still uses the database password.

#### Grants (row-level access)

With auth enabled, token (end-user) principals are **denied by default**; operator (`LUX_PASSWORD`) and service-key callers bypass. Access is granted per table with a row-scoped predicate:

```bash
redis-cli GRANT read, write ON messages WHERE user_id = auth.uid()
redis-cli REVOKE read ON messages
```

- Two scopes: `read` (covers SELECT and `.live()`), `write` (INSERT/UPDATE/DELETE; INSERT is checked against the new row, UPDATE/DELETE against the WHERE).
- A grant is a contract the query is checked **against**, not a filter silently applied. A query (or `.live()` subscription) must itself satisfy the predicate, or it is rejected. An unscoped `.live()` under a row-scoped grant is refused at subscribe time.
- Predicate values: `auth.uid()` (the caller's id), `auth.<claim>` (e.g. `auth.role`, `auth.email`), or a literal. Operators `= != < > <= >=`.
- Grants are authored as migrations, so they version and travel with schema (`lux migrate run` / `lux migrate pull`).

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LUX_PORT` | `6379` | TCP port |
| `LUX_HTTP_PORT` | (disabled) | HTTP API port (set to enable) |
| `LUX_PASSWORD` | (none) | Enable AUTH (applies to both RESP and HTTP) |
| `LUX_DATA_DIR` | `.` | Snapshot directory |
| `LUX_SAVE_INTERVAL` | `60` | Snapshot interval in seconds (0 to disable) |
| `LUX_SHARDS` | auto | Shard count (default: num_cpus * 16) |
| `LUX_MAXMEMORY` | `0` (unlimited) | Memory limit (e.g. `100mb`, `1gb`) |
| `LUX_MAXMEMORY_POLICY` | `noeviction` | Eviction policy: `allkeys-lru`, `volatile-lru`, `allkeys-random`, `volatile-random` |
| `LUX_MAXMEMORY_SAMPLES` | `5` | Keys sampled per eviction round |
| `LUX_STORAGE_MODE` | `memory` | Set to `tiered` for hot/cold storage with disk-backed eviction |
| `LUX_STORAGE_DIR` | `{LUX_DATA_DIR}/storage` | Directory for tiered storage data files |
| `LUX_RESTRICTED` | (none) | Set to `1` to disable KEYS, FLUSHALL, FLUSHDB |
| `LUX_AUTH_ENABLED` | `false` | Enable app auth tables and `/auth/v1` routes |
| `LUX_AUTH_PUBLISHABLE_KEY` | (generated) | Browser-safe app auth key when auth is enabled |
| `LUX_AUTH_SECRET_KEY` | (generated) | Server/admin app auth key when auth is enabled |

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

Lux has 617 tests across unit, integration, property-based, and crash recovery suites.

```bash
cargo test
```

| Suite | Tests | What it covers |
|-------|------:|----------------|
| **Unit: cmd** | 65 | Every command handler, arg validation, error paths |
| **Unit: store** | 79 | All data structures, TTL, shard versioning, expiry, vector index lifecycle |
| **Unit: resp** | 18 | RESP parser, serializers, edge cases |
| **Unit: snapshot** | 16 | Roundtrip all data types including streams, TTL preservation, binary safety |
| **Unit: pubsub** | 6 | Broker subscribe/publish/isolation |
| **Unit: disk** | 19 | CRC32 checksums, corruption detection, WAL/disk round-trips, partial write recovery, compaction, atomic writes |
| **Fuzz: persistence** | 7 | proptest-driven: random bytes into parsers (no panics), round-trip equivalence for all 9 data types, WAL replay fidelity, DiskShard reopen consistency |
| **Integration: transactions** | 29 | MULTI/EXEC, WATCH/UNWATCH, EXECABORT, DISCARD |
| **Integration: auth** | 9 | Password gating, per-connection state, error paths, HELLO auth |
| **Integration: pubsub** | 11 | Cross-connection message delivery, unsubscribe, sub mode, binary payloads |
| **Integration: persistence** | 3 | Snapshot save/restart/restore, FLUSHDB+SAVE |
| **Integration: crash recovery** | 10 | Hard kill + WAL replay for all data types, snapshot+WAL interaction, MULTI/EXEC crash, repeated crash cycles, hot+cold data, DEL/FLUSHDB durability, rapid pipeline crash, corrupted WAL startup |
| **Integration: tiered** | 18 | Cold storage reads/writes, eviction to disk, WAL crash recovery, snapshot with cold data, compaction |
| **Integration: pipelines** | 4 | Ordering under contention, fast-path batching |
| **Integration: embedded API** | 36 | Public library API, embedded/direct parity, native pipelines, embedded pub/sub and KSUB, persistence |
| **Integration: reliability** | 6 | Malformed protocol isolation, tiered restart safety, manual snapshot/WAL truncation |
| **Integration: stress** | 3 | Deterministic model stress in memory and tiered mode, optional Redis differential subset |
| **Integration: blocking** | 6 | BLPOP/BRPOP immediate, timeout, woken-by-push, BLMOVE |
| **Integration: streams** | 10 | XADD, XREAD, XREADGROUP, XACK, XREAD BLOCK, consumer groups |
| **Integration: lua** | 10 | EVAL, EVALSHA, redis.call, KEYS/ARGV, SCRIPT LOAD/EXISTS/FLUSH |
| **Integration: vectors** | 11 | VSET, VGET, VSEARCH, VCARD, metadata filtering, TTL, dimension validation |
| **Integration: geo** | 14 | GEOADD, GEODIST, GEOPOS, GEOHASH, GEOSEARCH, GEOSEARCHSTORE, GEORADIUS, edge cases |
| **Integration: hll** | 9 | PFADD, PFCOUNT, PFMERGE, cardinality accuracy, multi-key count, merge, WRONGTYPE |
| **Integration: timeseries** | 18 | TSADD, TSGET, TSRANGE, TSMRANGE, TSMADD, TSINFO, aggregation, retention, labels, filtering |
| **Integration: ksub** | 6 | KSUB event delivery, pattern filtering, multiple patterns, KUNSUB, HSET/DEL events |
| **Integration: http** | 21 | HTTP REST API: health, auth, auth grants/admin keys, KV CRUD, tables REST, time series REST, vectors REST, data types, exec, CORS |
| **Integration: live websocket** | 6 | `/live` auth, key/pubsub events, table subscriptions, vector-near subscriptions, unsubscribe |
| **Integration: tables** | 26 | TCREATE, TINSERT, TSELECT, TUPDATE, TDELETE, TDROP, TCOUNT, TLIST, TSCHEMA, joins, grouped aggregates, NEAR, foreign keys, unique constraints |
| **Valkey compat** | 10+ | Valkey multi.tcl test suite run against Lux |

Run the benchmark against Redis:

```bash
./bench.sh
```

### CI

Every push and pull request runs:

- `cargo fmt -- --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test --all-targets`
- Integration tests against the Valkey test harness

Release and Docker builds only proceed after tests pass.

## Supported Commands

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

- **No AOF persistence** -- Lux uses snapshots + a write-ahead log (WAL) with CRC32 checksums instead of Redis AOF. The WAL is fsync'd every 1 second (matching Redis `appendfsync everysec`). Maximum data loss on power failure is 1 second of writes
- **No RESP3 protocol** -- RESP2 only
- **No cluster mode** -- single-node only (use Lux Cloud for managed hosting)
- **MULTI/EXEC** -- supported with WATCH-based optimistic locking. Commands in a transaction execute sequentially, each acquiring its own shard lock, so another client could observe intermediate state mid-EXEC. Redis avoids this via single-threading. Standard client libraries (Redlock, BullMQ, Sidekiq) rely on WATCH for correctness, not EXEC isolation. Full shard-locking isolation may be added in a future release if there's demand
- **Pipeline ordering** -- per-client command order is preserved. Consecutive same-shard commands are batched for performance

## Architecture

```
Client connections (tokio tasks)
        |
   Zero-Copy RESP Parser (byte slices, no allocations)
        |
   Pipeline Batching (consecutive same-shard commands batched)
        |
   Command Dispatch (byte-level matching, no string conversion)
        |
   Sharded Store (auto-tuned RwLock shards, hashbrown raw_entry)
        |
   FNV Hash -> Shard Selection (pre-computed, reused for HashMap lookup)
```

Read the full deep dive at [luxdb.dev/architecture](https://luxdb.dev/architecture).

## License

MIT
