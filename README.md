<p align="center">
  <img src="logo.png" alt="Lux" width="120" height="120" />
</p>

<h1 align="center">Lux</h1>

<p align="center">
  <strong>A drop-in Redis replacement. 3-5x faster.</strong><br/>
  Multi-threaded. Written in Rust. MIT licensed forever.
</p>

<p align="center">
  <a href="https://luxdb.dev">Lux Cloud</a> &middot;
  <a href="https://luxdb.dev/vs/redis">Benchmarks</a> &middot;
  <a href="https://luxdb.dev/architecture">Architecture</a>
</p>

---

## Why Lux?

Redis is single-threaded by design. Every command runs on one core. Lux takes the opposite approach: a **sharded concurrent architecture** built in Rust that safely uses all your cores. Change your connection string. Everything else stays the same.

**Works with every Redis client** -- ioredis, redis-py, go-redis, Jedis, redis-rb. Zero code changes.

### Benchmarks

`redis-benchmark`, 50 clients, 1M requests per test. All competitors on the same machine.

| Pipeline | Lux | Redis 7 | Valkey 9 | KeyDB | Lux vs Redis |
|----------|-----|---------|----------|-------|-------------|
| 1 | 106K | 110K | 108K | 68K | 0.97x |
| 16 | 1.49M | 902K | 745K | 930K | **1.65x** |
| 64 | **4.65M** | 1.50M | 1.16M | 1.41M | **3.10x** |
| 128 | **7.19M** | 1.73M | 1.30M | 1.46M | **4.16x** |
| 256 | **10.5M** | 1.88M | 1.41M | 1.35M | **5.59x** |

At pipeline depth 256, Lux hits **10.5 million SET ops/sec**. That's 5.6x faster than Redis. The gap grows with core count and pipeline depth because Lux's shard batching and multi-threading scale with concurrency while Redis hits a single-core ceiling.

## Lux Cloud

Don't want to manage infrastructure? **[Lux Cloud](https://luxdb.dev)** is managed Lux hosting.

- **$5/mo** per instance, 1GB memory
- 4x more memory than Redis Cloud at the same price
- Deploy in seconds, connect with any Redis client
- Persistence, monitoring, and web console included

## Features

- **80+ Redis commands** -- strings, lists, hashes, sets, pub/sub
- **RESP protocol** -- drop-in compatible with every Redis client
- **Multi-threaded** -- auto-tuned shards, parking_lot RwLocks, tokio async runtime
- **Zero-copy parser** -- RESP arguments are byte slices into the read buffer
- **Pipeline batching** -- commands grouped by shard, one lock acquisition per batch
- **Persistence** -- automatic snapshots, configurable interval
- **Auth** -- password authentication via `LUX_PASSWORD`
- **Pub/Sub** -- SUBSCRIBE, UNSUBSCRIBE, PUBLISH
- **TTL support** -- EX, PX, EXPIRE, PEXPIRE, PERSIST, TTL, PTTL
- **856KB Docker image** -- the entire database fits in under 1MB. Redis is 30MB. Dragonfly is 180MB.
- **MIT licensed** -- no license rug-pulls, unlike Redis (RSALv2/SSPL)

## Quick Start

```bash
cargo build --release
./target/release/lux
```

Lux starts on `0.0.0.0:6379` by default. Connect with any Redis client:

```bash
redis-cli
> SET hello world
OK
> GET hello
"world"
```

### Docker

```bash
docker run -d -p 6379:6379 ghcr.io/lux-db/lux:latest
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LUX_PORT` | `6379` | TCP port |
| `LUX_PASSWORD` | (none) | Enable AUTH |
| `LUX_DATA_DIR` | `.` | Snapshot directory |
| `LUX_SAVE_INTERVAL` | `60` | Snapshot interval in seconds (0 to disable) |
| `LUX_SHARDS` | auto | Shard count (default: num_cpus * 16) |
| `LUX_RESTRICTED` | (none) | Set to `1` to disable KEYS, FLUSHALL, FLUSHDB |

### Node.js SDK

```bash
npm install @luxdb/sdk
```

```typescript
import { Lux } from "@luxdb/sdk"

const db = new Lux({ host: "localhost", port: 6379 })
await db.connect()
await db.set("hello", "world")
console.log(await db.get("hello")) // "world"
```

## Supported Commands

**Strings:** `SET` `GET` `SETNX` `SETEX` `PSETEX` `GETSET` `MGET` `MSET` `STRLEN` `APPEND` `INCR` `DECR` `INCRBY` `DECRBY`

**Keys:** `DEL` `EXISTS` `KEYS` `SCAN` `TYPE` `RENAME` `TTL` `PTTL` `EXPIRE` `PEXPIRE` `PERSIST` `DBSIZE` `FLUSHDB` `FLUSHALL`

**Lists:** `LPUSH` `RPUSH` `LPOP` `RPOP` `LLEN` `LRANGE` `LINDEX`

**Hashes:** `HSET` `HMSET` `HGET` `HMGET` `HDEL` `HGETALL` `HKEYS` `HVALS` `HLEN` `HEXISTS` `HINCRBY`

**Sets:** `SADD` `SREM` `SMEMBERS` `SISMEMBER` `SCARD` `SUNION` `SINTER` `SDIFF`

**Pub/Sub:** `PUBLISH` `SUBSCRIBE` `UNSUBSCRIBE`

**Server:** `PING` `ECHO` `INFO` `SAVE` `BGSAVE` `LASTSAVE` `AUTH` `CONFIG` `CLIENT` `SELECT` `COMMAND` `DUMP` `RESTORE`

## Architecture

```
Client connections (tokio tasks)
        |
   Zero-Copy RESP Parser (byte slices, no allocations)
        |
   Pipeline Batching (group by shard, sort, batch execute)
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
