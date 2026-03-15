<p align="center">
  <img src="logo.png" alt="Lux" width="120" height="120" />
</p>

<h1 align="center">Lux</h1>

<p align="center">
  <strong>The fastest Redis-compatible key-value store.</strong><br/>
  Multi-threaded. Written in Rust. 2-4x faster than Redis.
</p>

<p align="center">
  <a href="https://luxdb.dev">LuxDB Cloud</a> &middot;
  <a href="https://luxdb.dev/vs/redis">Benchmarks</a> &middot;
  <a href="https://luxdb.dev/architecture">Architecture</a>
</p>

---

## Why Lux?

Redis is single-threaded. Lux is not.

Lux uses a **sharded concurrent architecture** with per-shard reader-writer locks, zero-copy RESP parsing, and pipeline batching by shard. Every core works in parallel. The shard count auto-tunes based on your CPU count.

### Benchmarks (12-core, redis-benchmark, 50 clients)

| Benchmark | Lux | Redis 7 | Ratio |
|-----------|-----|---------|-------|
| SET | 104,493 rps | 45,455 rps | **2.30x** |
| GET | 104,822 rps | 46,168 rps | **2.27x** |
| SET (pipeline 16) | 1,488,095 rps | 541,126 rps | **2.75x** |
| GET (pipeline 16) | 1,488,095 rps | 704,225 rps | **2.11x** |
| SET (pipeline 64) | **4,640,372 rps** | 1,992,032 rps | **2.33x** |
| GET (pipeline 64) | **4,629,630 rps** | 1,879,699 rps | **2.46x** |
| SET (pipeline 256) | **10,178,117 rps** | 2,301,496 rps | **4.42x** |
| GET (pipeline 256) | **10,282,776 rps** | 3,427,592 rps | **3.00x** |

The advantage grows with core count. On a 4-core Raspberry Pi 5, Lux matches Redis at parity. On 12+ cores, it pulls ahead on every benchmark. At high pipeline depths it reaches **10M+ ops/sec**.

## LuxDB Cloud

Don't want to manage infrastructure? **[LuxDB Cloud](https://luxdb.dev)** is managed Lux hosting.

- **$5/mo** per instance, 1GB memory
- 4x more memory than Redis Cloud at the same price
- Deploy in seconds, connect with any Redis client
- Persistence, monitoring, and auth included

```bash
redis-cli -h your-instance.luxdb.dev -p 30115 -a your-password
```

## Features

- **80+ Redis commands** -- strings, lists, hashes, sets, pub/sub
- **RESP protocol** -- works with redis-cli, ioredis, redis-py, any Redis client
- **Multi-threaded** -- auto-tuned shards with parking_lot RwLocks, tokio async runtime
- **Zero-copy parser** -- RESP arguments are byte slices into the read buffer, zero heap allocations
- **Pipeline batching** -- commands grouped by shard, one lock acquisition per shard per batch
- **Persistence** -- automatic snapshots, configurable interval via `LUX_SAVE_INTERVAL`
- **Auth** -- `LUX_PASSWORD` env var enables AUTH command
- **Pub/Sub** -- SUBSCRIBE, UNSUBSCRIBE, PUBLISH with broadcast channels
- **TTL support** -- EX, PX, EXPIRE, PEXPIRE, PERSIST, TTL, PTTL
- **Sub-2MB binary** -- starts instantly, zero runtime dependencies

## Quick Start

```bash
cargo build --release
./target/release/lux
```

Lux starts on `0.0.0.0:6379` by default. Connect with any Redis client:

```bash
redis-cli -p 6379
> SET hello world
OK
> GET hello
"world"
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LUX_PORT` | `6379` | TCP port to listen on |
| `LUX_PASSWORD` | (none) | Enable AUTH, require this password |
| `LUX_DATA_DIR` | `.` | Directory for snapshot files |
| `LUX_SAVE_INTERVAL` | `60` | Snapshot interval in seconds (0 to disable) |
| `LUX_SHARDS` | auto | Number of shards (default: num_cpus * 16, rounded to power of 2) |
| `LUX_RESTRICTED` | (none) | Set to `1` to disable KEYS, FLUSHALL, FLUSHDB |

### Docker

```bash
docker run -d -p 6379:6379 \
  -e LUX_PASSWORD=mysecretpassword \
  ghcr.io/mattyhogan/lux:latest
```

### Node.js SDK

```bash
npm install @luxdb/sdk
```

```typescript
import { Lux } from "@luxdb/sdk"

const db = new Lux({
  host: "localhost",
  port: 6379,
  password: "mysecretpassword"
})

await db.connect()
await db.set("hello", "world")
console.log(await db.get("hello")) // "world"
```

## Supported Commands

### Strings
`SET` `GET` `SETNX` `SETEX` `PSETEX` `GETSET` `MGET` `MSET` `STRLEN` `APPEND` `INCR` `DECR` `INCRBY` `DECRBY`

### Keys
`DEL` `EXISTS` `KEYS` `SCAN` `TYPE` `RENAME` `TTL` `PTTL` `EXPIRE` `PEXPIRE` `PERSIST` `DBSIZE` `FLUSHDB` `FLUSHALL`

### Lists
`LPUSH` `RPUSH` `LPOP` `RPOP` `LLEN` `LRANGE` `LINDEX`

### Hashes
`HSET` `HMSET` `HGET` `HMGET` `HDEL` `HGETALL` `HKEYS` `HVALS` `HLEN` `HEXISTS` `HINCRBY`

### Sets
`SADD` `SREM` `SMEMBERS` `SISMEMBER` `SCARD` `SUNION` `SINTER` `SDIFF`

### Pub/Sub
`PUBLISH` `SUBSCRIBE` `UNSUBSCRIBE`

### Server
`PING` `ECHO` `INFO` `SAVE` `AUTH` `CONFIG` `CLIENT` `SELECT` `COMMAND`

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

Each shard is cache-line aligned (`#[repr(align(128))]`) to prevent false sharing. Values stored as `bytes::Bytes`. Common responses pre-serialized as static byte slices. Expiration checks use a cached `Instant::now()` captured once per pipeline batch. Background sweep task evicts expired keys every 100ms.

Read the full architecture deep dive at [luxdb.dev/architecture](https://luxdb.dev/architecture).

## License

MIT
