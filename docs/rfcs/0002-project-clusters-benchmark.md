# RFC 0002: Project Clusters benchmark and release contract

- Status: Accepted
- Date: 2026-08-04
- Owners: Lux Engine and Lux Cloud
- Depends on: [RFC 0001: Project Clusters architecture](0001-project-clusters-architecture.md)

## Decision

Project Clusters are accepted by measurements from outside the engine, on
isolated engine processes or machines, under fixed and reproducible resource
allocations. The benchmark must prove useful throughput, latency, routing,
correctness, recovery, and cost efficiency. A green unit test or an in-process
microbenchmark cannot make the feature shippable.

The native and compatibility paths are different products from a performance
perspective and are never averaged together.

This RFC is normative. If implementation and benchmark disagree, the feature
is not ready; the gate is not weakened to fit the implementation.

## Required release results

Every primary KV and point-table workload must pass all applicable gates.

| Gate | Required result |
| --- | --- |
| cluster tax | one-node cluster owner-local throughput is at least 97% of the same node's standalone throughput |
| per-owner capacity | at equal per-node concurrency, every owner contributes at least 97% of its host-matched standalone baseline |
| 2-node aggregate | at least 1.90x the normalized standalone baseline |
| 4-node aggregate | at least 3.70x the normalized standalone baseline |
| 8-node aggregate | at least 7.20x the normalized standalone baseline |
| one-node p99 | no more than 5% above host-matched standalone at equal offered load |
| 2/4/8-node p99 | no more than 10% above host-matched standalone at equal per-node offered load |
| stable native routing | 100% of correctly routed point operations execute owner-local; zero point-operation peer frames |
| resize throughput | minimum one-second successful throughput during resize is at least 90% of pre-resize steady throughput |
| resize correctness | zero missing and zero duplicate committed logical operations |
| cost efficiency | useful throughput per core and per dollar is at least 90% of standalone after including incremental cluster infrastructure |
| compatibility | correctness passes; throughput, p50/p95/p99, forward ratio, hop cost, and CPU amplification are reported separately |

Both per-owner and aggregate gates apply. A high aggregate cannot hide one slow
owner, and healthy individual owners cannot hide a shared cluster bottleneck.

The lower bound of the reported 95% confidence interval must clear a throughput
gate. The upper bound must clear a latency-regression gate. A rounded point
estimate at the threshold is not a pass.

## Why the experimental test is rejected

The experimental `tests/cluster_performance.rs` cannot answer the release
question:

- all engines share one process, one eight-thread Tokio runtime, one host, and
  one load-generator process;
- it deliberately forces one storage shard per node;
- total concurrency is fixed while node count grows instead of holding
  concurrency and offered load constant per node;
- the client is embedded, so it bypasses real sockets, TLS, DNS, load balancing,
  connection pools, and client routing;
- it measures only generated-key `SET` operations;
- a sample can be only 30,000 operations and only three samples are taken;
- it records throughput but no p50, p95, p99, error rate, routing, CPU, network,
  disk, or correctness history;
- its one-node gate allows a 20% regression;
- its two-node gate calls 1.25x success;
- it does not test 4 or 8 nodes, tables, auth/grants, transitions, recovery,
  backup/restore, Cloud routes, or compatibility isolation.

That test must be deleted or demoted to a non-gating developer smoke test. It
must never be cited as horizontal-scaling evidence.

## Benchmark components

The harness is its own workspace under `bench/cluster/` and produces versioned
artifacts. It has four binaries or equivalent isolated roles:

1. **orchestrator** provisions hosts/processes, identities, topology, datasets,
   and run order;
2. **load generator** speaks public RESP and HTTP/SDK protocols from a machine
   that runs no engine;
3. **observer** collects host, process, engine, route, peer, and network metrics
   without sharing the load-generator event loop;
4. **verifier** validates topology, histories, final data, transition receipts,
   backup bundles, and statistical gates after the run.

The engine is the ordinary release binary. Benchmark-only shortcuts in command
execution are prohibited. Optional observability endpoints may expose counters
and immutable run IDs, but cannot execute or route data operations.

### Providers

The orchestrator supports:

- `local_process`: separate OS processes with explicit CPU sets, directories,
  ports, and network namespaces; useful for development, not 8-node release
  certification;
- `ssh`: one engine host per node plus separate load-generator and observer
  hosts;
- `kubernetes`: one engine pod per dedicated Kubernetes worker with required
  anti-affinity and Guaranteed QoS, plus load generator on a separate worker.

Only `ssh` or a Kubernetes run satisfying the isolation preflight can certify
2/4/8-node release results.

## Testbed requirements

### Isolation

- one Lux engine process per allocated node machine or dedicated worker;
- identical CPU model, core count, memory, storage class, kernel, and network
  class across engine nodes;
- exclusive physical cores or a documented dedicated VM allocation;
- no engine shares a core with the load generator, observer, Kubernetes system
  daemons, or another database;
- one durable volume per node with identical performance class;
- load-generator CPU and network capacity of at least 2x the projected 8-node
  result;
- observer overhead below 1% CPU on every engine host;
- no unrelated autoscaling, backups, image pulls, compaction experiments, or
  scheduled jobs during stable runs.

For Kubernetes, pods use integer CPU and memory requests equal to limits,
topology spread, required pod anti-affinity, and static CPU-manager allocation.
Node placement and CPU IDs are recorded in the artifact.

### Host configuration

The preflight records and validates:

- CPU model, sockets, cores, SMT state, NUMA layout, and assigned CPU set;
- CPU governor/frequency policy and thermal-throttling counters;
- total/free memory, huge-page policy, and swap state;
- kernel, libc, container runtime, and relevant sysctls;
- NIC model, negotiated speed, MTU, offload settings, queue count, and errors;
- disk model/class, filesystem, mount options, capacity, and an independent
  sequential/random I/O sanity result;
- round-trip latency and achievable bandwidth between every load-generator/node
  and node/node pair;
- clock synchronization offset;
- engine binary SHA-256, build profile, features, allocator, and image digest;
- full redacted runtime configuration.

A run is invalid if any engine throttles, swaps, hits an OOM condition, loses
CPU exclusivity, exceeds 80% NIC bandwidth, exceeds 80% load-generator CPU, or
has observer loss above 0.1%.

### Resource parity

Standalone and clustered nodes receive identical per-node resources and engine
settings:

- same release binary and allocator;
- same storage mode, shard count, persistence, fsync, eviction, and save policy;
- same CPU/memory limit and volume class;
- same TLS and auth cost for the compared public path;
- same dataset per owner and value/row size;
- same connection and pipeline count per owner;
- same logging and metrics level.

Disabling durability, TLS, auth, grants, or limits only for one side invalidates
the comparison.

## Baseline design

Every engine host is measured in standalone mode immediately before and after
its clustered runs. This prevents a fast machine or time drift from inflating
cluster scale.

For workload `w` and host `i`:

```text
baseline_i,w = geometric_mean(before_i,w, after_i,w)
normalized_baseline_N,w = sum(baseline_i,w for every cluster owner i)
owner_ratio_i,w = owner_throughput_i,w / baseline_i,w
aggregate_ratio_N,w = cluster_throughput_N,w /
                      mean(baseline_i,w for every owner i)
```

`aggregate_ratio_N,w` is the familiar 1x/2x/4x/8x scale number. The sum baseline
is retained for efficiency calculations.

Run order is randomized in blocks, for example:

```text
standalone before -> cluster 1 -> cluster 4 -> cluster 2 -> cluster 8 ->
standalone after
```

At least five valid blocks run. A failed/invalid block is explained and rerun;
it is never silently removed from the result set.

## Capacity calibration

A fixed total client count is not a scaling test. Client connections,
concurrency, target rate, and dataset grow with the number of nodes.

For each workload, the harness first sweeps standalone concurrency on every
host. The calibrated per-node concurrency is the smallest value that reaches at
least 95% of that host's observed maximum sustainable throughput without a
runaway latency knee or errors.

The chosen concurrency is frozen per node:

```text
clients_N = clients_per_node * N
concurrency_N = concurrency_per_node * N
operations_N = operations_per_node * N
dataset_N = dataset_per_node * N
```

Cluster runs cannot tune each node to a more favorable workload after seeing
the result.

Two complementary tests are required:

### Saturated useful throughput

Closed-loop clients use the calibrated per-node concurrency. The result is
successful logical operations divided by the measurement interval. Redirects,
retries, duplicate attempts, and internal peer operations do not count as
useful operations.

### Equal-load latency

An open-loop generator offers 70% of each host's standalone sustainable rate to
each owner. It uses a coordinated-omission-correcting histogram and records
scheduled-to-complete latency. The generator does not slow its schedule to make
a saturated cluster's p99 look healthy.

One-node cluster p99 may regress by at most 5%. At 2/4/8 nodes, every owner's
p99 and the aggregate p99 may regress by at most 10% from its host-matched
standalone result.

## Run duration and statistics

Each sample has:

- at least 60 seconds of dataset/cache warmup;
- at least 30 seconds of connection and topology stabilization;
- at least 300 seconds of measured steady state;
- at least 30 seconds of post-run metric drain;
- at least five valid samples per mode/workload;
- randomized mode ordering;
- raw one-second time series retained.

The report includes median, minimum, maximum, standard deviation, coefficient
of variation, and bootstrap 95% confidence interval. A workload is unstable and
invalid when within-mode throughput coefficient of variation exceeds 3% or
when a trend test shows sustained thermal/resource drift.

No result is rounded before gate evaluation.

## Datasets

Data is preloaded outside the measurement interval and verified before every
mode.

- keys/rows distribute uniformly across all 4,096 slots unless the workload is
  explicitly a skew diagnostic;
- every owner receives the same number of keys/rows and approximately the same
  bytes;
- the active dataset is at least four times aggregate last-level CPU cache and
  fits within the configured memory/storage contract;
- reads have a declared hit ratio, normally 99% for the primary point-read
  gate;
- writes replace or update a bounded working set unless the workload explicitly
  measures insert growth;
- values and rows are generated deterministically from the run seed;
- table primary keys use the public canonical routing algorithm;
- no owner is favored by sequential key generation or hash tags.

The artifact includes per-owner slot, object, and byte histograms. An owner
imbalance above 1% invalidates a uniform run.

## Primary workload matrix

Every row is run at 1, 2, 4, and 8 nodes in native mode and against host-matched
standalone engines.

| ID | Surface | Mix | Payload | Required authorization |
| --- | --- | --- | --- | --- |
| `kv_get_256` | RESP | 100% hit `GET` | 256-byte value | secret project key |
| `kv_set_256` | RESP | 100% replacing `SET` | 256-byte value | secret project key |
| `kv_mixed_256` | RESP | 80% `GET`, 20% replacing `SET` | 256-byte value | secret project key |
| `table_get_1k` | native Lux HTTP/SDK | 100% primary-key read | approximately 1 KiB typed row | user JWT plus publishable key and grants |
| `table_upsert_1k` | native Lux HTTP/SDK | 100% primary-key upsert | approximately 1 KiB typed row | user JWT plus publishable key and grants |
| `table_mixed_1k` | native Lux HTTP/SDK | 80% primary-key read, 20% upsert | approximately 1 KiB typed row | user JWT plus publishable key and grants |

RESP throughput gates run at pipeline depths 1 and 16. Pipeline 1 is the
latency-sensitive contract; pipeline 16 proves batching does not reintroduce a
shared coordinator. HTTP uses persistent connections and the SDK's production
pool/multiplexing behavior.

The table schema includes representative types, a primary key, one ordinary
index, defaults, one encrypted field, read/write grants using `auth.uid()`, and
no unsupported global constraint. Owners must enforce schema, encryption, JWT
session state, and grants locally.

All six workloads pass the same cluster-tax, per-owner, aggregate, and p99
gates. It is not sufficient for KV to scale while tables centralize, or vice
versa.

## Required diagnostic workloads

These do not redefine the primary linear-scaling claim but must be published:

- 64-byte, 1 KiB, and 16 KiB KV values;
- 256-byte, 4 KiB, and 32 KiB table rows;
- 50/50 and 95/5 read/write mixes;
- cache-cold reads and persistence-heavy writes;
- pipeline depths 1, 4, 16, and 64;
- publishable-key-only auth endpoint operations;
- secret-key, user-JWT, and operator authorization costs;
- Zipfian slot distribution and one deliberately hot slot;
- same-slot multi-key commands;
- explicit cross-slot rejection;
- global scans, counts, broad table filters, and project-wide realtime fan-in;
- topology refresh storms and reconnects;
- node count 16 as a non-gating headroom diagnostic when infrastructure allows.

Hot-key and global-query results are labeled non-linear workloads. The report
must explain the limiting owner/fan-in rather than imply that adding idle nodes
can accelerate one serialized key.

## Native zero-hop proof

Throughput alone does not prove architecture. For every stable primary native
run, the verifier checks:

- each logical operation's client-selected node owns the computed slot at the
  active topology epoch;
- engine `route_mode=owner_local` count equals successful point operations;
- native `compat_forward` point count equals zero;
- point-command peer request count equals zero;
- peer data-plane bytes attributable to point operations equal zero;
- only bounded health/control traffic appears on peer links;
- `MOVED`/`ASK` occur only during the declared topology convergence window;
- no stable endpoint appears in the measured request path after bootstrap;
- connections are reused and no connection or TLS handshake occurs per
  operation.

Packet capture may be used as an audit cross-check, but authenticated engine and
SDK counters with matching run IDs are the primary machine-verifiable evidence.

## Resize benchmark

Resize runs use native KV and point-table mixed workloads concurrently at 70%
of the smaller cluster's measured sustainable capacity.

Required transitions are:

- 1 -> 2;
- 2 -> 4;
- 4 -> 8;
- 8 -> 4;
- 4 -> 2;
- 2 -> 1, including return to ordinary standalone mode.

Before the transition, the workload must be steady for at least two minutes.
It continues throughout copy, WAL catch-up, fence, handoff, commit, cleanup,
and two minutes after convergence.

### Resize performance gates

- every one-second bucket contains at least 90% of pre-transition steady useful
  throughput;
- automatic redirection/retry may not create a client-visible failed logical
  operation;
- no complete service stall occurs;
- foreground p99 remains within 25% of pre-transition p99;
- background transfer respects configured CPU, disk, and network budgets;
- source-to-target transfer does not consume more than 10% of the limiting
  foreground resource unless spare capacity is proven;
- cleanup cannot begin until the post-commit observation window passes.

The 90% floor is measured, not inferred from a rate limiter configuration.

### Resize correctness history

Every mutation carries a globally unique logical operation ID. The workload
contains:

- unique-key writes for missing-operation detection;
- append/list entries containing operation IDs for duplicate detection;
- per-worker monotonic counters for lost or repeated mutation detection;
- point-table inserts and upserts with deterministic primary keys and versions;
- reads that record observed per-key versions before and after ownership moves.

The load generator records invocation, routing epoch, redirects, response, and
ambiguity. After quiescence, the verifier reads every affected slot from its
committed owner and checks:

- every acknowledged mutation exists;
- every committed logical operation ID appears exactly once where semantics
  require exactly one effect;
- no unacknowledged transfer replay manufactured a visible mutation;
- per-key versions never move backward;
- source and target do not retain divergent live copies;
- table indexes match row images;
- WAL and transition receipts form contiguous sequences;
- slot counts and checksums before/after reconcile with intended writes.

Any missing or duplicate committed logical operation fails the entire feature,
even when aggregate counts happen to match.

## Transition crash matrix

Every transition phase is exercised with process termination and restart:

| Injection | Source | Target | Controller | Required proof |
| --- | --- | --- | --- | --- |
| before prepare receipts | optional | optional | kill | no ownership change; safe resume/discard |
| mid-snapshot chunk | alive | kill/restart | alive | idempotent resume from durable chunk receipt |
| mid-WAL catch-up | alive | kill/restart | alive | contiguous resume; source remains owner |
| immediately before source fence | kill/restart | alive | alive | old committed topology remains authoritative |
| immediately after durable source fence | kill/restart | alive | kill/restart | no second ordinary writer; signed recovery completes or safely reopens source |
| target ready before commit | alive | kill/restart | kill/restart | `ASK` state resumes; no duplicate ordinary ownership |
| immediately after topology commit | kill/restart | alive | kill/restart | target remains owner; source fence survives rollback/restart |
| during cleanup | kill/restart | alive | kill/restart | committed owner/data intact; cleanup idempotent |

Network tests also delay, duplicate, reorder, and replay control and transfer
frames within protocol limits. Timeouts alone may never grant ownership.

Correctness is checked against signed topology, durable node receipts, final
data, and request history—not only the Cloud operation state.

## Stable failure tests

RF1 deliberately makes affected slots unavailable when an owner's process and
volume are unavailable. Required behavior is still strict:

- unaffected owners continue serving at least 95% of their prior throughput;
- the stable compatibility endpoint does not turn one node failure into total
  project failure;
- requests for unavailable slots fail quickly with a stable error, not a long
  timeout or partial result;
- restarting the node with its volume restores exactly its committed data and
  ownership epoch;
- restarting with an empty/wrong volume fails closed and does not join;
- a stale node cannot accept writes after its slots moved;
- losing the control node pauses control mutations but not already authorized
  native operations on other owners;
- a partitioned minority cannot invent a topology or ownership change.

These tests do not convert RF1 into an HA claim. They prevent avoidable blast
radius.

## Execution-metadata tests

The benchmark/test suite proves all owners execute from local metadata:

- schema create/alter/drop prepare, commit, rollback, restart, and version-gap
  behavior;
- grant add/revoke with identical authorization result on every owner;
- project key issue/revoke, including zero successful requests after revocation
  acknowledgement;
- user session issue/refresh/revoke/global sign-out with exact session checks on
  every owner;
- node removal from readiness while structural or authorization metadata lags;
- rejection of a bundle with invalid signature, signer, cluster ID, topology
  epoch, previous digest, version, catalog, grant, or capability;
- crash at every await between control persistence, prepare receipts, commit,
  and caller acknowledgement;
- snapshot/delta compaction and restart without an unbounded replay;
- no private signing/provider/project-key secret in owner status, topology,
  metadata artifacts, metrics, logs, or backups.

The native workload asserts zero control-node lookups during point
authentication and authorization.

## Backup and restore gates

Required scenarios at 1, 2, 4, and 8 nodes include:

- backup under mixed foreground writes while meeting its documented
  foreground-interference budget;
- controller restart during barrier collection and part upload;
- one failed/retried part upload;
- exact manifest/part/topology/metadata/WAL digest validation;
- rejection of missing, duplicate, swapped, truncated, oversized, or modified
  parts;
- restore into isolated fresh volumes;
- restore failure before activation leaves the prior runtime usable;
- successful activation exposes the complete expected dataset and auth state;
- scale-down refuses destructive cleanup without the required recoverable
  checkpoint.

Restored data is verified per slot and per table/index, not just by process
readiness.

## Security gates

Automated adversarial tests include:

- unsigned, rollback, same-epoch-conflicting, incomplete, and overlapping
  topologies;
- a valid node certificate from another cluster or retired epoch;
- DNS resolving to a node whose certificate pin does not match;
- peer source/target spoofing and request-envelope tampering;
- expired deadlines, replayed request IDs, and mutation attempts over 0-RTT;
- invalid transition tokens and `ASKING` on unrelated slots;
- transfer chunk reordering, duplication, corruption, decompression bombs, and
  frame-size limits;
- stale structural/authorization metadata;
- reserved `auth.*` and `push.*` tables routed as ordinary user data;
- user-controlled endpoints entering peer, backup, push, or OAuth network
  destinations;
- tenant/project credential use against another cluster's direct endpoint;
- publishable keys reaching secret/operator surfaces;
- secret material search across topology, status, logs, traces, metrics, core
  dumps configured for tests, and backup artifacts.

Fuzz targets cover canonical topology encoding, signed metadata encoding, peer
frames, transition receipts, backup manifests, routing classification, and
redirection parsing.

## Compatibility benchmark

The compatibility benchmark uses the stable project endpoint and a client that
does not cache topology. It runs the same six primary workload shapes but its
numbers are in a separate table and chart.

Required reported fields are:

- useful throughput and scaling ratio;
- p50, p95, p99, and maximum latency;
- local-ingress versus forwarded operation counts;
- mean and p99 added hop latency;
- ingress CPU plus owner CPU per useful operation;
- peer bytes per useful operation;
- connection-pool/queue saturation and backpressure errors;
- fairness across owners;
- behavior when one ingress/owner is unavailable.

Compatibility must be correct, bounded, and free of a distinguished ingress
bottleneck. It is not required to meet native 97%/1.90x/3.70x/7.20x gates, and
its results can never be used to claim native scaling.

A mixed-mode isolation test drives native traffic at 70% sustainable capacity
while compatibility traffic ramps. Native p99 and throughput budgets must
remain protected by separate peer queues and resource controls.

## Cost-efficiency calculation

The report records actual or normalized hourly cost of:

- engine CPU and memory;
- per-node durable volumes and provisioned IOPS/bandwidth;
- incremental load balancer/routes attributable to cluster mode;
- incremental network transfer, including compatibility and resize;
- any new runtime component required only by cluster mode.

Existing shared Cloud API replicas are not charged again unless the feature
requires scaling them. Hidden new pods are included.

For workload `w`:

```text
standalone_efficiency = standalone_useful_ops / standalone_hourly_cost
cluster_efficiency_N = cluster_useful_ops_N / cluster_incremental_hourly_cost_N
efficiency_ratio_N = cluster_efficiency_N / standalone_efficiency
```

`efficiency_ratio_N` must be at least 0.90 at 2, 4, and 8 nodes. Useful ops per
allocated physical core must also be at least 0.90 of standalone. Memory bytes,
disk I/O, and network bytes per useful operation are published so a throughput
pass cannot conceal disproportionate resource amplification.

Native stable point workloads should have only amortized bounded control peer
bytes. Compatibility and resizing network costs are separate line items.

## Cloud certification

Engine certification is necessary but not sufficient. The Cloud run uses the
production image, ingress, TLS, direct per-node DNS, credentials, lifecycle
controller, metrics, volumes, and network policy in an isolated environment.

It proves:

- direct node endpoints advertised in signed topology are reachable and map to
  the intended node;
- stable bootstrap plus native SDK convergence;
- no Cloud API request is on the native point path;
- fixed scale and autoscale operations resume after either API replica dies;
- two API replicas do not execute one transition concurrently;
- route creation precedes topology advertisement and safe route retention
  follows topology removal;
- project state is accurate and real-time enough to explain transitions;
- one project resize cannot materially degrade another project;
- node accounting matches observed node minutes;
- no new global pod role is required;
- rollback to standalone preserves endpoint/SDK compatibility.

The full 8-node Cloud run may use production-equivalent dedicated workers. A
single Kubernetes worker with eight pods is not horizontal certification.

## Artifacts and schema

Every run emits one immutable directory or object prefix:

```text
run.json
environment.json
topology.json
execution_metadata.json
workloads/<id>/samples/*.json
workloads/<id>/histograms/*.hdr
metrics/engine/*.parquet
metrics/host/*.parquet
metrics/network/*.parquet
transitions/*.json
histories/*.jsonl.zst
verification.json
report.md
```

`run.json` includes git SHA, image/binary digest, dirty-state flag, harness SHA,
seed, exact command, UTC timestamps, provider, node allocation, workload
versions, and artifact checksums.

`verification.json` is machine-readable and lists every gate with numerator,
denominator, confidence bounds, pass/fail, and source artifact. The report is a
projection of this file; humans cannot hand-edit a failed measurement into a
pass.

Artifacts are uploaded even on failure. Secrets are redacted before upload,
and the redaction verifier itself is a gate.

## CI and release policy

### Pull requests

Engine PRs run:

- unit, property, fuzz-smoke, and protocol test vectors;
- separate-process 1- and 2-node correctness tests;
- a short non-certifying performance regression smoke test;
- static checks that native point handlers cannot call peer forwarding APIs;
- static/metric checks for forbidden hot-path locks and allocations where
  practical.

PR CI labels performance smoke results as diagnostic. It cannot say the feature
is shippable.

### Nightly

Nightly dedicated infrastructure runs the full stable 1/2/4-node primary
matrix, transition subset, crash rotation, and compatibility report. Results
are trended by commit with alerts on regression.

### Release candidate

An Engine/Cloud release candidate runs all 1/2/4/8 primary workloads, every
required resize direction, complete crash/security/backup gates, cost report,
and Cloud certification on one immutable candidate digest.

Any code change to routing, storage, auth, grants, topology, transition, peer
transport, networking, allocator, persistence, container base, or Cloud runtime
after certification invalidates the affected results and requires rerun.

No tag, image promotion, autoscaling enablement, or customer rollout occurs
until `verification.json` passes every required gate.

## Anti-gaming rules

The following invalidate a result:

- embedded clients or engines for certification;
- fixed total clients/concurrency/operations while node count increases;
- comparing a durable/authenticated cluster to a non-durable/open standalone;
- co-locating multiple owners on one constrained runtime and calling it scale;
- counting redirects, retries, peer forwards, or internal subqueries as useful
  operations;
- excluding slow owners from aggregate latency;
- reporting average latency without p99;
- reporting only the best run;
- changing values, row shapes, hit ratios, pipeline depth, or dataset size
  between modes;
- using different binaries or resource limits;
- measuring only the compatibility path and labeling it native;
- accepting a topology based only on process readiness;
- lowering a threshold because a completed implementation misses it;
- treating an ignored test or an unexecuted workload as green;
- using a manually edited report without matching raw artifacts and verifier
  output.

## Completion checklist

Project Clusters are not complete until evidence proves every item:

- architecture RFC approved;
- benchmark RFC approved;
- experimental stacks remain unmerged and replacement stacks start from
  current `main`;
- signed topology/membership security gates pass;
- native RESP and Lux SDK discovery/redirection pass;
- execution metadata and exact authorization gates pass;
- no control/system node participates in native point KV/table operations;
- immutable routing and transition admission have no hot reader lock;
- stable native point operations generate zero peer data frames;
- all six primary workloads pass 1/2/4/8 throughput and p99 gates;
- every resize direction passes the 90% floor and exact correctness verifier;
- crash matrix passes;
- backup/restore gates pass;
- compatibility report exists separately;
- cost efficiency passes;
- Cloud production-equivalent certification passes;
- canary rollout and rollback procedure are exercised;
- all required artifacts correspond to the exact release digest.

Anything missing or indirectly inferred keeps the feature experimental.

## Accepted decisions

This RFC was approved on 2026-08-04 with agreement that:

- these thresholds are hard release gates;
- the testbed must use isolated processes/machines and an external load
  generator;
- load, clients, operations, and data scale per node;
- KV and point-table paths both pass every native scaling gate;
- p99, routing evidence, correctness, and cost count as much as aggregate ops/s;
- resize throughput is checked in one-second buckets;
- compatibility results are separate;
- no existing in-process benchmark can substitute for certification;
- a missed gate changes the design or implementation, not the contract.
