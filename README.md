<p align="center">
  <img src="logo.png" alt="Lux" width="120" height="120" />
</p>

<h1 align="center">Lux</h1>

<p align="center">
  <strong>A Redis-compatible key-value store. Up to 10x faster.</strong><br/>
  Multi-threaded. Built-in vector search, time series, realtime key subscriptions, and GEO. BullMQ-compatible. Written in Rust. MIT licensed forever.
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

## Why Lux?

Redis is single-threaded by design. Antirez made that choice in 2009 because it eliminates all locking, race conditions, and concurrency bugs. For most workloads, the bottleneck is network I/O, not CPU, so a single-threaded event loop is fast enough. It was a brilliant simplification.

But it has a ceiling. Once you saturate one core, that's it. Redis can't use the other 15 cores on your machine. The official answer is to run multiple Redis instances and shard at the client level (Redis Cluster), which adds significant operational complexity.

Lux takes the opposite approach: a **sharded concurrent architecture** that safely uses all your cores in a single process. Each key maps to one of N shards, each protected by a `parking_lot` RwLock. Reads never block reads. Writes only block the single shard they touch. Tokio's async runtime handles thousands of connections across all cores. The result: single-digit microsecond latency at low concurrency (matching Redis), and linear throughput scaling as you add cores and pipeline depth (where Redis flatlines).

"Doesn't multi-threading introduce the bugs Redis avoided?" No. Lux's concurrency is at the shard level, not the command level. Each command acquires a single shard lock, does its work, and releases. There are no cross-shard locks, no lock ordering issues, no deadlocks. The only shared mutable state is inside shards, and the RwLock makes that safe. MULTI/EXEC transactions use WATCH-based optimistic concurrency (shard versioning) rather than global locks, matching what Redis clients actually rely on.

Point your existing Redis client at Lux. Most workloads just work.

**Works with every Redis client** -- ioredis, redis-py, go-redis, Jedis, redis-rb, BullMQ. Zero code changes.

### Benchmarks

`redis-benchmark`, 50 clients, 1M requests, pipeline=64. Sequential runs (one server at a time) on a 32-core Intel i9-14900K, 128GB RAM, Ubuntu 24.04.

| Command | Lux | Redis 8.4.2 | Lux/Redis |
|---------|-----|-------------|-----------|
| SET | 10.2M | 3.4M | **3.0x** |
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

Lux beats Redis on every supported command. At pipeline=1, both are network-bound and roughly equal. The gap grows with pipeline depth because Lux batches same-shard commands under a single lock while Redis processes sequentially on one core. GEO commands see the biggest gains because GEOSEARCH parallelizes across shards while Redis scans single-threaded.

Full results including SET scaling by pipeline depth (up to **5.8x** at pipeline=512) in [BENCHMARKS.md](BENCHMARKS.md). Reproduce with `./bench.sh`.

## Lux Cloud

Don't want to manage infrastructure? **[Lux Cloud](https://luxdb.dev)** is managed Lux hosting. Deploy in seconds, connect with any Redis client. Includes BullMQ queue dashboard, agent memory MCP server, persistence, monitoring, and web console.

## Features

- **200+ commands** -- strings, lists, hashes, sets, sorted sets, streams, vectors, geo, time series, tables, HyperLogLog, bitops, pub/sub, transactions
- **Relational tables** -- TCREATE, TINSERT, TSELECT, TUPDATE (WHERE), TDELETE (WHERE), TALTER with typed fields (str, int, float, bool, timestamp, uuid), unique constraints, foreign keys, joins, WHERE/ORDER BY/LIMIT. Structured data without standing up Postgres
- **Realtime key subscriptions** -- KSUB/KUNSUB: subscribe to key patterns, receive events when matching keys are mutated. Zero overhead when unused. No global config flags, no separate services. Unlike Redis keyspace notifications which tax every write globally, KSUB is surgical and async
- **Native time series** -- TSADD, TSGET, TSRANGE, TSMRANGE with aggregation (avg, sum, min, max, count, std), retention policies, and label-based filtering. No modules, no sidecars. TSGET 4x faster than Redis GET
- **Native vector search** -- VSET, VGET, VSEARCH with cosine similarity and metadata filtering. No extensions, no sidecars
- **GEO commands** -- GEOADD, GEOSEARCH, GEODIST, GEOPOS, GEOHASH, GEORADIUS with up to 10x faster spatial queries
- **LRU eviction** -- maxmemory with allkeys-lru, volatile-lru, allkeys-random, volatile-random policies
- **BullMQ compatible** -- blocking commands, streams, Lua scripting with cmsgpack/cjson
- **Lua scripting** -- EVAL, EVALSHA, SCRIPT with redis.call/pcall, cmsgpack, and cjson
- **Redis Streams** -- XADD, XREAD, XREADGROUP, XACK, consumer groups, blocking reads
- **Blocking commands** -- BLPOP, BRPOP, BLMOVE, BZPOPMIN, BZPOPMAX
- **HTTP REST API** -- built-in JSON API on a separate port, 174K ops/sec, Bearer auth, CORS
- **RESP2 protocol** -- compatible with every Redis client
- **Multi-threaded** -- auto-tuned shards, parking_lot RwLocks, tokio async runtime
- **Zero-copy parser** -- RESP arguments are byte slices into the read buffer
- **Pipeline batching** -- consecutive same-shard commands batched under a single lock
- **Persistence** -- automatic snapshots, write-ahead log (WAL) with CRC32 checksums, tiered hot/cold storage with automatic eviction to disk
- **Auth** -- password authentication via `LUX_PASSWORD`
- **Pub/Sub** -- SUBSCRIBE, PSUBSCRIBE, PUBLISH, plus KSUB/KUNSUB for realtime key change events
- **TTL support** -- EX, PX, EXPIRE, PEXPIRE, PERSIST, TTL, PTTL
- **MIT licensed** -- no license rug-pulls, unlike Redis (RSALv2/SSPL)

## Quick Start

```bash
cargo build --release
./target/release/lux
```

Lux starts on `0.0.0.0:6379` by default. Connect with any Redis client using `lux://` or `redis://`:

> **Protocol note:** `lux://` is the primary protocol for the Lux SDK and luxctl CLI. When using third-party Redis clients (ioredis, redis-py, go-redis) directly, use `redis://` since they don't recognize `lux://`. Both connect to the same server.

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

Built-in relational tables with typed fields, indexes, unique constraints, foreign keys, and joins.

```bash
# Create a table with typed fields
redis-cli TCREATE users "id INT PRIMARY KEY," "name STR," "email STR UNIQUE," "age INT," "active BOOL"

# Insert rows (* auto-generates timestamp)
redis-cli TINSERT users name Alice email alice@example.com age 28 active true created_at *
redis-cli TINSERT users name Bob email bob@example.com age 35 active false created_at *

# Query with WHERE, ORDER BY, LIMIT
redis-cli TSELECT '*' FROM users WHERE age '>' 25 ORDER BY age DESC LIMIT 10

# Foreign keys and joins
redis-cli TCREATE posts "id INT PRIMARY KEY," "title STR," "author_id INT REFERENCES users(id)"
redis-cli TINSERT posts id 1 title "Hello World" author_id 1
redis-cli TSELECT '*' FROM posts p JOIN users u ON p.author_id = u.id

# Update and delete by predicates
redis-cli TUPDATE users SET active true WHERE id = 1
redis-cli TDELETE FROM users WHERE id = 2

# Alter tables
redis-cli TALTER users ADD role STR
redis-cli TALTER users DROP role
```

Field types: `STR`, `INT`, `FLOAT`, `BOOL`, `TIMESTAMP`, `UUID`.
Use SQL-style constraints like `UNIQUE`, `PRIMARY KEY`, and `REFERENCES table(field)`.

### CLI

```bash
curl -fsSL https://raw.githubusercontent.com/lux-db/lux/main/cli/install.sh | sh
```

```bash
luxctl login                              # authenticate with a lux_ token
luxctl projects                           # list projects
luxctl create my-app --accept-charges     # create a new project
luxctl status my-app                      # show status and metrics
luxctl exec my-app SET hello world        # run a command
luxctl logs my-app                        # fetch logs
luxctl restart my-app                     # restart instance
luxctl connect my-app                     # interactive REPL via cloud
luxctl connect lux://localhost:6379       # connect to local instance
luxctl destroy my-app --accept-consequences  # delete project
```

See [cli/README.md](cli/README.md) for full installation and usage docs.

### SDK

```bash
bun i @luxdb/sdk
```

```typescript
import { Lux } from "@luxdb/sdk"

const db = new Lux("lux://localhost:6379")

await db.set("hello", "world")

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

Lux has 409 tests across unit, integration, property-based, and crash recovery suites.

```bash
cargo test
```

| Suite | Tests | What it covers |
|-------|------:|----------------|
| **Unit: cmd** | 62 | Every command handler, arg validation, error paths |
| **Unit: store** | 66 | All data structures, TTL, shard versioning, expiry |
| **Unit: resp** | 19 | RESP parser, serializers, edge cases |
| **Unit: snapshot** | 7 | Roundtrip all data types including streams, TTL preservation |
| **Unit: pubsub** | 5 | Broker subscribe/publish/isolation |
| **Unit: disk** | 18 | CRC32 checksums, corruption detection, WAL/disk round-trips, partial write recovery, compaction, atomic writes |
| **Fuzz: persistence** | 7 | proptest-driven: random bytes into parsers (no panics), round-trip equivalence for all 9 data types, WAL replay fidelity, DiskShard reopen consistency |
| **Integration: transactions** | 29 | MULTI/EXEC, WATCH/UNWATCH, EXECABORT, DISCARD |
| **Integration: auth** | 6 | Password gating, per-connection state, error paths |
| **Integration: pubsub** | 10 | Cross-connection message delivery, unsubscribe, sub mode |
| **Integration: persistence** | 3 | Snapshot save/restart/restore, FLUSHDB+SAVE |
| **Integration: crash recovery** | 10 | Hard kill + WAL replay for all data types, snapshot+WAL interaction, MULTI/EXEC crash, repeated crash cycles, hot+cold data, DEL/FLUSHDB durability, rapid pipeline crash, corrupted WAL startup |
| **Integration: tiered** | 18 | Cold storage reads/writes, eviction to disk, WAL crash recovery, snapshot with cold data, compaction |
| **Integration: pipelines** | 3 | Ordering under contention, fast-path batching |
| **Integration: blocking** | 6 | BLPOP/BRPOP immediate, timeout, woken-by-push, BLMOVE |
| **Integration: streams** | 10 | XADD, XREAD, XREADGROUP, XACK, XREAD BLOCK, consumer groups |
| **Integration: lua** | 10 | EVAL, EVALSHA, redis.call, KEYS/ARGV, SCRIPT LOAD/EXISTS/FLUSH |
| **Integration: vectors** | 10 | VSET, VGET, VSEARCH, VCARD, metadata filtering, TTL, dimension validation |
| **Integration: geo** | 14 | GEOADD, GEODIST, GEOPOS, GEOHASH, GEOSEARCH, GEOSEARCHSTORE, GEORADIUS, edge cases |
| **Integration: hll** | 9 | PFADD, PFCOUNT, PFMERGE, cardinality accuracy, multi-key count, merge, WRONGTYPE |
| **Integration: timeseries** | 18 | TSADD, TSGET, TSRANGE, TSMRANGE, TSMADD, TSINFO, aggregation, retention, labels, filtering |
| **Integration: ksub** | 6 | KSUB event delivery, pattern filtering, multiple patterns, KUNSUB, HSET/DEL events |
| **Integration: http** | 14 | HTTP REST API: health, auth, KV CRUD, tables REST, time series REST, vectors REST, data types, exec, CORS, 404 |
| **Integration: tables** | 14 | TCREATE, TINSERT, TSELECT, TUPDATE, TDELETE, TDROP, TCOUNT, TLIST, TSCHEMA, joins, foreign keys, unique constraints |
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

**Tables:** `TCREATE` `TINSERT` `TSELECT` `TUPDATE` `TDELETE` `TDROP` `TCOUNT` `TSCHEMA` `TLIST` `TALTER`

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