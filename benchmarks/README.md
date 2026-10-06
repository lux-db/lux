# Lux benchmarks

This directory contains the public benchmark harness for Lux. It runs with Bun,
uses no package dependencies, and records the inputs needed to reproduce a
result. Comparative workloads use the same pinned `redis-benchmark` client and
the same client settings against Lux and Redis.

Benchmark results are evidence for one exact artifact on one recorded machine;
they are not universal performance guarantees. Compatibility workloads are
reported separately from Lux-native tables, vectors, time series, realtime,
tiered storage, and recovery.

The suite answers three different questions:

1. **Compatibility scaling:** how Lux and a pinned Redis release behave under
   identical strings, collections, GEO, mixed read/write, payload, connection,
   and pipeline workloads.
2. **Application workloads:** how Lux's own table, HTTP, vector, time-series,
   realtime, and tiered-storage paths behave on declared datasets, with results
   checked as part of measurement.
3. **Lifecycle behavior:** how snapshotting affects reads and how long exact
   recovery takes after an immediate stop, including writes acknowledged after
   the snapshot in both memory-backed and tiered Lux storage.

## Requirements

- Bun (release evidence currently records Bun 1.3.11)
- Docker

The Redis server and benchmark client use the digest-pinned image declared in
[`config.ts`](config.ts). The harness records both requested references and
resolved image IDs. The same file pins the Lux Docker build recipe and Rust
toolchain expected by release evidence.

## Run

Validate the harness without starting containers:

```bash
bun test benchmarks
bun benchmarks/run.ts --validate
```

Run every benchmark against the current checkout:

```bash
bun benchmarks/run.ts
```

The runner builds a temporary Lux image, prints the report to the terminal, and
removes its containers, volumes, network, and image when finished. Redirect the
report normally when you want to keep it:

```bash
bun benchmarks/run.ts > results.md
```

Run a shorter pass, select features, or use an existing release candidate:

```bash
bun benchmarks/run.ts --quick
bun benchmarks/run.ts --feature tables
bun benchmarks/run.ts --feature vectors,realtime
bun benchmarks/run.ts --image ghcr.io/lux-db/lux:<candidate>
```

The available features are `compatibility`, `tables`, `vectors`, `timeseries`,
`realtime`, `tiered`, and `recovery`. Use `--json` when raw repetitions and the
complete machine-readable configuration are needed:

```bash
bun benchmarks/run.ts --image ghcr.io/lux-db/lux:<candidate> --json > results.json
```

Request counts, repetitions, concurrency, keyspace, pipeline depth, CPU, and
memory can be overridden with flags shown by `--help`. Without overrides, the
runner uses the complete five-repetition settings. `--quick` is the one-pass
developer check.

## Method

Both database containers receive the same CPU and memory limits. Authentication
is enabled for both. Compatibility measurements use in-memory, non-persistent
configuration for both databases; recovery measurements use one-second
durability for both. Lux-specific configuration and Redis server arguments are
written into `results.json`.

Each workload is warmed before measurement. The default run uses five
repetitions with alternating subject order and reports the median, range, and
coefficient of variation rather than selecting the best run. Latency includes
the client, protocol, and Docker network path. Pipelined workloads are labeled
separately from single-request latency. Tiered cold-read passes use disjoint
keys that were seeded before the hot working set and report placement before
and after measurement; a promoted value is never reused as a "cold" sample.

Official release numbers must come from the checked release artifact on a quiet,
dedicated machine. Save the JSON output with the release. Do not compare results
produced with different settings or materially different hardware.

The methodology follows the same broad principles used by established database
projects: Redis's guidance on equivalent configuration and disclosed client
shape, PostgreSQL's warmup/client/duration and per-command reporting model,
Dragonfly's repeated trials and raw-result retention, and DuckDB's separation
of microbenchmarks from representative application suites:

- [Redis benchmark guidance](https://redis.io/docs/latest/operate/oss_and_stack/management/optimization/benchmarks/)
- [PostgreSQL `pgbench`](https://www.postgresql.org/docs/current/pgbench.html)
- [Dragonfly benchmarking](https://github.com/dragonflydb/benchmarking)
- [DuckDB benchmarks](https://github.com/duckdb/duckdb/tree/main/benchmark)
