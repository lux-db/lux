# RFC 0001: Project Clusters architecture

- Status: Accepted
- Date: 2026-08-04
- Owners: Lux Engine and Lux Cloud
- Companion: [RFC 0002: Project Clusters benchmark and release contract](0002-project-clusters-benchmark.md)

## Decision

Project Clusters will be a client-routed, shared-nothing data plane. After
bootstrap, a cluster-aware client sends a point operation directly to the node
that owns its slot. An owner executes that operation through the same local
storage path as a standalone Lux engine. A normal point operation does not pass
through a coordinator, another engine, or a peer RPC.

The stable project endpoint remains the bootstrap and compatibility endpoint.
It is not the native steady-state data path. Standard Redis Cluster clients use
`CLUSTER SHARDS`/`CLUSTER SLOTS` plus `MOVED`/`ASK`. Lux SDKs use a signed Lux
topology descriptor and equivalent structured HTTP redirections.

The current experimental Engine and Cloud stacks are not the implementation of
this RFC and must not merge. Their security, lifecycle, transition, and backup
work is reference material to port selectively. Their coordinator-routed hot
path, per-operation metadata attachment, topology locks, transition locks, and
performance test are rejected.

No implementation is shippable until RFC 0002 passes on isolated processes or
machines.

## Why this architecture

The scaling target is physical, not cosmetic: adding an equal node must add
nearly an equal amount of useful capacity without increasing normal point
latency. Any shared request coordinator, remote-owner hop, global lock, or
per-operation consensus creates a serial or coherency term that eventually
dominates throughput.

The Universal Scalability Law models that limit as contention and coherency
penalties in the denominator of capacity. The design response is to remove
those penalties from the common path rather than make them faster.

This follows proven properties of high-throughput distributed stores:

- Redis Cluster has clients cache ownership and contact owners directly. It
  explicitly avoids proxies in the normal path and expects approximately
  single-node performance multiplied by the number of owners.
- ScyllaDB's token- and shard-aware drivers route to the exact node and CPU to
  remove coordinator-node and cross-core traffic.
- Seastar's shared-nothing model avoids locks and shared cache-line traffic by
  keeping ownership on one executor per core.
- Read-copy-update publishes immutable read-mostly state without blocking
  readers while rare writers construct a replacement.
- FaRM demonstrates the value of lock-free reads, locality, and function
  shipping for common-case distributed performance. Lux does not require RDMA
  for this release, but it adopts the same locality rule: move the request to
  the data once, from the client, and execute locally.
- Tail-at-scale research makes p99 a first-class scaling result. Aggregate
  throughput is not a pass if a larger cluster becomes visibly slower.

References are listed at the end of this RFC.

## Non-negotiable invariants

1. **Zero owner hops.** A correctly routed native point operation uses one
   client-to-owner network hop and zero node-to-node data RPCs.
2. **No point coordinator.** No distinguished node participates in ordinary KV
   or point-table reads and writes.
3. **Standalone-equivalent owner path.** Once ownership is confirmed, execution
   falls into the ordinary local command and storage path. Cluster mode may not
   wrap the operation in serialization, allocation, a Tokio mutex, or a
   reader-writer lock.
4. **Immutable routing reads.** Stable routing and execution metadata are read
   from immutable snapshots published with RCU-style replacement. Rare updates
   never take a lock needed by point readers.
5. **Single writer per slot.** At every durable transition state, at most one
   node accepts ordinary writes for a slot.
6. **No invisible fallback.** A native request sent to the wrong node receives
   a redirection. It is never silently proxied.
7. **Local authorization.** Every owner can authenticate and authorize a data
   request from local, versioned execution metadata. It does not call an auth
   node.
8. **Control traffic is off-path.** Peer transport carries topology,
   execution-metadata, transfer, backup, recovery, health, and explicit
   compatibility traffic. It carries no correctly routed native point
   operation.
9. **RF1 is honest.** The first release has one durable owner per slot. Loss of
   that node makes those slots unavailable until its durable volume returns.
   Project Clusters scale capacity; they do not claim high availability.
10. **Single-node remains ordinary Lux.** Projects that do not enable a cluster
    do not initialize cluster routing, peer transport, or metadata replication.

## Terminology and naming

- **cluster**: the optional multi-node runtime for one Lux project;
- **node**: one Lux engine process with its own compute and durable volume;
- **slot**: one of 4,096 virtual ownership partitions;
- **owner**: the one node allowed to execute ordinary operations for a slot;
- **control node**: the node that serializes rare engine-owned metadata changes;
- **controller**: the trusted OSS CLI or Lux Cloud component that signs
  membership and topology;
- **native client**: a Redis Cluster client or Lux SDK that routes to owners;
- **compatibility request**: a request sent through the stable endpoint by a
  client that does not route to owners;
- **execution metadata**: the versioned material required to execute and
  authorize an operation locally;
- **transition**: a crash-safe ownership move from one node to another.

Public JSON, signed payload fields, HTTP contracts, database tables, and
database columns use `snake_case`. Rust identifiers follow Rust conventions.
TypeScript domain objects follow the Cloud style guide and convert to/from
`snake_case` at their owning boundary. Production table names remain concise:
`clusters`, `cluster_nodes`, and `node_minutes`, never redundant project-prefixed
names.

## Product shape

Project Clusters are configured in project settings and by the CLI. This is a
capacity setting, not a separate product universe.

- Autoscaling is off by default.
- A user can select a fixed node count.
- Autoscaling exposes `min_nodes` and `max_nodes` when enabled.
- Scaling back to one node consolidates all slots and can return the project to
  the ordinary standalone runtime.
- Local Lux supports the same fixed scaling, transition, consolidation,
  discovery, and verification behavior using local processes and ports.
- Lux Cloud and local Lux differ in infrastructure adapters, not data-plane
  semantics.

The first release supports at most 16 owners and 4,096 virtual slots. Those are
protocol constants, not performance assumptions.

## System shape

```text
                           rare control operations
                 +--------------------------------------+
                 |                                      v
  OSS CLI or Cloud controller                    control node
        | signs membership/topology              metadata authority
        |                                               |
        |                 signed immutable snapshots    |
        +----------------------+------------------------+
                               |
             +-----------------+-----------------+
             v                 v                 v
          owner 1           owner 2           owner N
       slots 0..x       slots x+1..y      slots ...4095
             ^                 ^                 ^
             |                 |                 |
             +------ native client routing -----+
                    one client-to-owner hop

  stable project endpoint
      |-- bootstrap/discovery for native clients
      `-- compatibility ingress for legacy clients
```

There are three planes:

### Native data plane

Point KV and point-table operations travel directly from client to owner.
Owners execute locally. Global queries are decomposed by a cluster-aware client
or an explicit compatibility coordinator and are reported separately.

### Engine control plane

The control node serializes schemas, grants, project-key records, token
verification material, auth-session authorization records, and other rare
engine metadata. It publishes durable, versioned execution metadata to all
owners before acknowledging a change.

The control node is not in the native point path. If it is unavailable, already
authorized point operations continue on owners; metadata mutations and auth
session issuance may pause.

### Infrastructure control plane

The OSS CLI or Lux Cloud creates identities and nodes, signs topology,
orchestrates transitions, exposes endpoints, meters nodes, and coordinates
backup/restore. Lux Cloud continues to run durable controllers inside its
existing API replicas. This RFC does not add global worker or supervisor pod
roles. Enabling a cluster adds only the requested per-project engine nodes and
their volumes.

## Signed topology and membership

The existing experimental security model is retained in principle:

- the controller owns a P-256 topology signing key;
- every node has a unique client/server mTLS identity for peer traffic;
- the signed topology binds `cluster_id`, protocol version, topology epoch,
  node identity, public endpoints, peer endpoint, server name, certificate, and
  certificate digest;
- every node rejects unsigned state, rollback, conflicting content at one
  epoch, incomplete slot coverage, duplicate slots, unknown members, and
  identity changes outside a signed topology;
- mutations are forbidden over 0-RTT peer transport;
- peer envelopes bind source, target, cluster, topology epoch, request ID, and
  deadline to the mutually authenticated connection.

The new manifest separates routing from execution-metadata versions:

```json
{
  "schema_version": 1,
  "protocol_version": 1,
  "cluster_id": "...",
  "topology_epoch": 42,
  "control_node_id": "node_1",
  "slot_count": 4096,
  "nodes": [
    {
      "node_id": "node_1",
      "peer_addr": "...",
      "resp_addr": "...",
      "http_url": "...",
      "server_name": "...",
      "certificate_der": "...",
      "certificate_sha256": "..."
    }
  ],
  "assignments": [
    { "start": 0, "end": 2047, "node_id": "node_1" }
  ],
  "transitions": []
}
```

Execution metadata has its own monotonic version and hash chain. A schema or
grant change does not require changing slot ownership, and an ownership change
does not manufacture a new schema version.

The canonical signature encoding remains length-prefixed and deterministic;
JSON is only its storage and API envelope. The exact byte encoding is a public
test vector in the implementation.

## Discovery and endpoint protocol

### Bootstrap trust

The stable project endpoint is reached over ordinary trusted TLS. It returns:

- the controller public key;
- the current signed topology;
- the active execution-metadata version and digest;
- cache lifetime and refresh hints;
- the minimum client protocol version.

The client pins the controller key for that project while it caches topology.
A direct node cannot substitute its own topology signing key. Local clients
receive the same trust root from the CLI-created project configuration.

### RESP clients

Any node supports the Redis Cluster discovery and redirection surface:

- `CLUSTER SHARDS` is canonical;
- `CLUSTER SLOTS` remains available for older drivers;
- the 4,096 internal assignments are projected deterministically across the
  Redis 16,384-slot client space;
- a stale or misrouted request receives `MOVED <slot> <owner>`;
- a request crossing an active cutover may receive `ASK <slot> <target>` and
  must use `ASKING` on the target;
- nodes never proxy native Redis Cluster operations.

Clients keep persistent connection pools to owners. Discovery does not create
a new connection per operation.

### Lux HTTP and SDK clients

Lux SDKs fetch `GET /.well-known/lux/cluster` from the stable endpoint. Every
node exposes the same descriptor and its digest.

A stale or misrouted HTTP point operation returns a structured response:

```json
{
  "code": "slot_moved",
  "slot": 917,
  "topology_epoch": 42,
  "owner_url": "https://node-2.project.example",
  "topology_digest": "..."
}
```

The SDK refreshes the signed topology and retries only when retrying is safe.
Writes carry a request ID so a response lost around a retry can be resolved
without duplicating a committed mutation. During cutover, `slot_ask` is the HTTP
equivalent of Redis `ASK`.

Cloud exposes an HTTPS and RESP address per node. CORS, auth headers, request
limits, and project-domain policy are identical on stable and direct endpoints.

### Routing algorithms

KV routing retains Redis CRC16 and hash-tag semantics. Multi-key operations are
allowed only when all keys map to one slot.

Point-table routing is:

```text
slot = fnv1a64(table_name || 0x00 || canonical_primary_key) mod 4096
```

The algorithm, canonical primary-key encoding, and test vectors are versioned
public protocol. Lux SDKs implement it. Table inserts in native cluster mode
materialize UUIDv7 primary keys client-side. Generic commands that omit a
required routing key fail clearly or use the explicitly slower compatibility
path; they never acquire a hidden point coordinator.

## Owner-local hot path

The common path is deliberately short:

1. parse the command/request;
2. authenticate from a connection/session cache backed by the active immutable
   execution snapshot;
3. derive the routing slot while parsing the routing key;
4. read the connection's current immutable routing snapshot;
5. index the fixed owner array;
6. if local and open, enqueue/execute on the local storage shard;
7. otherwise return `MOVED`, `ASK`, or a fenced-transition error.

The owner-local branch is prohibited from:

- acquiring a topology or transition reader-writer lock;
- cloning command arguments;
- serializing a peer frame;
- opening a peer stream;
- consulting the control node;
- attaching a table catalog to the request;
- mirroring events at an ingress node;
- consulting a global database;
- allocating solely because cluster mode is enabled.

### Immutable routing snapshots

Topology compilation produces one immutable `RoutingSnapshot` containing:

- topology epoch and digest;
- a dense 4,096-entry owner array;
- compact per-slot stable/transition state;
- immutable node endpoints;
- control-node identity;
- active execution-metadata version.

Rare writers validate and compile a complete replacement, persist it, then
publish it with an RCU-style atomic pointer swap. Readers never observe partial
state.

Connections cache a snapshot and the published epoch. The stable fast path is
an atomic epoch comparison followed by an array lookup. It does not increment a
shared reference counter on every command if the snapshot has not changed.
Reclamation waits until old connection/batch guards are gone.

The implementation may use `arc-swap`, epoch-based reclamation, or an
equivalent proven primitive, but the behavior is the contract: readers do not
block writers or one another, and no unsafe reclamation is possible.

### Shard-local execution and transition fences

Lux will move toward one logical executor per storage shard. A slot is mapped
to exactly one local executor. Point operations and transition barriers for
that slot enter the same ordered queue.

Fencing is therefore not a lock around every operation:

1. the transition controller enqueues `fence(slot, epoch)` on the owning shard;
2. the shard finishes all operations already ahead of the fence;
3. it persists the fence and last accepted WAL sequence;
4. later operations for that slot are rejected or redirected;
5. the controller receives the durable fence receipt.

This ordering provides a precise drain boundary without a per-operation
transition guard. Until the executor conversion is complete, an implementation
may use an atomic admission state plus an in-flight counter, but it cannot ship
unless the same 97% owner-local gate passes. A reader-writer lock held through
the operation is not an acceptable interim design.

## Versioned execution metadata

Every owner must independently execute the same request with the same schema,
authorization, and project settings. Per-request metadata forwarding is
forbidden.

Execution metadata is split into two durable streams.

### Structural snapshot

The structural snapshot is immutable, hash-chained, and changes rarely. It
contains only material required on a data owner:

- canonical table schemas, primary keys, defaults, constraints, index plans,
  encryption flags, and schema versions;
- compiled grants and their source versions;
- project-key digests, key kind, and revocation state, never raw project keys;
- JWT verification public keys and allowed algorithms, never active private
  signing keys;
- issuer and authorization settings needed to validate requests;
- routing-algorithm and command-capability versions.

Provider credentials, email provider secrets, OAuth client secrets, APNs
private keys, and active JWT signing private keys remain on the control side.
Cluster enablement requires asymmetric JWT signing. A bounded migration from a
legacy symmetric key must complete or explicitly invalidate the old access
tokens before owners can serve direct user-token traffic.

### Authorization ledger

Token verification currently includes session existence and revocation, so a
self-contained JWT alone is insufficient. Every owner keeps a minimal exact
authorization ledger containing active session ID, user ID, expiry, anonymous
status, and revocation boundary. It does not replicate user profiles, password
hashes, refresh tokens, identities, or provider secrets.

Session issue, refresh, revoke, and global sign-out are control operations:

1. persist the control-side mutation;
2. append a monotonic authorization record;
3. apply and durably acknowledge it on every serving owner;
4. publish it into each owner's immutable/sharded authorization view;
5. only then return the new token or successful revocation.

A node behind the required authorization version is removed from readiness and
fails closed. This retains exact revocation semantics without a per-request
remote lookup. The ledger must be compacted into signed snapshots plus a delta
tail so restarts do not replay unbounded history.

### Metadata commit protocol

Structural changes use prepare/commit:

1. the control node serializes the mutation and assigns `metadata_version`;
2. it creates a canonical bundle with `previous_digest` and signs it using an
   identity authorized by the current topology;
3. owners validate cluster, signer, topology epoch, previous digest, version,
   schema, grants, and capability compatibility;
4. every serving owner persists and compiles the prepared bundle;
5. the control node durably records all receipts and commits the version;
6. owners atomically publish the compiled snapshot;
7. the initiating DDL/grant/key operation is acknowledged.

On crash, the control node resumes from the durable prepared record and owner
receipts. An owner may be at committed version `V` with `V+1` prepared, never at
an unidentifiable mixture. A topology transition cannot commit while its owners
disagree on the required structural or authorization versions.

## Table behavior

### Point operations

`TGET`, `TSET`, exact-primary-key `TINSERT`, `TUPSERT`, `TUPDATE`, and `TDELETE`
route directly to the row owner. The owner already has the compiled catalog and
grants. The control node is not involved.

Generated UUID primary keys are materialized once by a native SDK or supplied
by the caller. Integer sequences and globally unique secondary constraints
require an explicit distributed design and are rejected in native cluster mode
until one meets the performance and correctness contract.

### DDL and grants

DDL, grant changes, provider configuration, project-key management, and auth
session issuance are control operations. They may be redirected to the control
node or reached through the stable management endpoint. Their latency does not
affect point data throughput, but their crash safety and security are release
gates.

### Broad queries

Scans, broad predicates, global counts, cross-slot secondary indexes, and
distributed joins are not point operations. They use an explicit distributed
query path:

- a native Lux SDK may issue owner-local partial queries concurrently and merge
  them client-side;
- Studio and legacy callers may use the compatibility path;
- node-to-node scatter is allowed only as a labeled compatibility/query
  operation, never as an accidental fallback;
- latency, amplification, limits, cancellation, and partial failure are
  reported separately from point scaling.

The first release may reject unsupported distributed query shapes. Returning a
clear unsupported error is preferable to silently producing partial data.

## Realtime behavior

Realtime subscriptions follow ownership too:

- a key- or slot-scoped native subscription connects to its owner;
- a project-wide native subscription opens owner streams and merges events in
  the SDK;
- the stable compatibility endpoint may fan in streams explicitly;
- moving a slot carries its durable event sequence and produces a resume token
  so an SDK can reconnect without a silent gap or duplicate delivery beyond the
  documented at-least-once boundary.

Realtime is not allowed to reintroduce ingress event mirroring on every point
write.

## Online ownership transitions

Resizing uses copy plus WAL catch-up, not synchronous dual-writing in the
request path.

### Transition phases

1. **Plan.** The trusted controller signs a pending topology and explicit slot
   transfer plan. Source remains the sole ordinary owner.
2. **Prepare.** Source and target persist the plan and verify identical
   execution-metadata versions.
3. **Copy.** Source captures a slot snapshot at WAL sequence `S`, sends
   checksummed idempotent chunks over persistent QUIC streams, and continues
   serving ordinary traffic. Transfer I/O is rate-limited below the latency and
   throughput interference budget.
4. **Catch up.** Target applies slot WAL records after `S` in sequence. Duplicate
   transfer frames are harmless; gaps fail closed.
5. **Fence.** A shard-local fence drains operations already accepted by source,
   persists final sequence `F`, and prevents later ordinary writes.
6. **Tail.** Source sends through `F`; target verifies snapshot, record count,
   sequence continuity, and digest, then persists a ready receipt.
7. **Handoff.** Target accepts only transition-authorized `ASKING` requests.
   Source returns `ASK`. This preserves availability while nodes and clients
   converge without two ordinary owners.
8. **Commit.** The controller commits the new signed topology. Target becomes
   ordinary owner; source returns `MOVED` and retains a durable moved-slot fence.
9. **Clean up.** Source deletes old slot data only after a retention period,
   committed receipts, and a recoverable checkpoint.

Slots move in bounded batches. Copy and compaction run through a scheduler that
protects foreground p99 and throughput. A resize pauses rather than violating
the 90% foreground-throughput floor.

### Failure behavior

| Failure point | Required recovery |
| --- | --- |
| before prepared state | discard the unsigned/unpersisted plan |
| during snapshot copy | resume idempotent chunks from durable receipts |
| during WAL catch-up | resume at the last contiguous durable sequence |
| after source fence, before target ready | source stays fenced; recover source/target and finish or execute a signed rollback that reopens source only after proving target never accepted ordinary writes |
| target ready, before topology commit | source returns `ASK`; target accepts only transition-authorized requests; resume commit |
| after topology commit | target owns; source's durable fence prevents rollback writes |
| controller restart | reconstruct from signed plan and durable node receipts |

No timeout alone changes ownership. Only signed epochs and durable receipts do.

## Peer transport

Peer QUIC remains valuable but is removed from normal point execution.

Allowed peer message families are:

- topology prepare/commit/status;
- execution-metadata prepare/commit/status;
- authorization-ledger records and snapshots;
- ownership snapshot chunks, WAL tail, receipts, and recovery;
- backup barriers, parts, restore staging, and receipts;
- health/capability probes;
- explicitly labeled compatibility forwarding and distributed-query partials.

Connections are persistent and multiplexed. Request code does not take a global
async mutex to find a connection and does not open a new bidirectional stream
for each data operation. Bounded per-peer queues provide backpressure; control,
transfer, and compatibility traffic have separate budgets so a legacy request
storm cannot starve topology or recovery.

Stable native benchmark runs assert that peer point-operation frames equal
zero.

## Compatibility path

Existing non-cluster-aware clients retain the stable project URL. A request can
land on any owner. If it is misrouted, that ingress owner may forward it over
the explicitly labeled compatibility channel.

This does not require new global Cloud pod roles. The project engine nodes form
a horizontally distributed compatibility ingress behind the existing stable
route. Persistent peer connections avoid connection setup per request.

Compatibility has weaker performance expectations because a fraction of
operations require an extra hop and consume CPU on two nodes. It must:

- preserve correctness and security;
- avoid a distinguished ingress node;
- remain bounded and backpressured;
- expose forwarded/local counters and hop latency;
- be benchmarked and published separately;
- never be used by a client that advertised native cluster support.

SDK releases should prefer native routing while keeping the stable endpoint as
bootstrap. This permits an additive rollout rather than breaking existing
applications.

## Distributed backup and restore

The experimental distributed bundle model is retained and tightened.

A cluster backup contains:

- project and cluster identity;
- committed topology epoch and digest;
- committed structural and authorization versions/digests;
- one checksummed part per node and volume;
- per-slot ownership and WAL boundaries;
- a signed bundle manifest;
- no plaintext controller, peer, provider, signing, or project-key secrets.

The controller establishes a short logical barrier through shard executors,
records each part boundary, and releases foreground work. Parts upload in
parallel after the barrier. Because RF1 does not support cross-slot atomic
transactions, the documented consistency boundary is the ordered set of shard
barrier positions; the manifest makes it reproducible and auditable.

Restore is staged into stopped or isolated replacement volumes. Every part,
digest, cluster ID, topology, metadata version, and slot range is validated
before any restored node is exposed. Activation is all-or-nothing at the
project lifecycle layer. A failed restore leaves the previous runtime and
volumes recoverable.

Scale-down and consolidation cannot delete a source volume until a post-move
backup or equivalent recoverable checkpoint exists.

## Cloud runtime

Lux Cloud retains the useful experimental groundwork:

- concise `clusters`, `cluster_nodes`, and `node_minutes` persistence;
- encrypted stable node identities;
- signed desired and observed topology;
- one StatefulSet member/service/volume per requested project node;
- direct node SNI routes for RESP, extended to direct HTTPS;
- durable, retryable lifecycle operations;
- node-minute accounting;
- autoscaling hysteresis, bounds, and cooldowns;
- distributed backup bundle orchestration.

The Cloud controller must never infer ownership from Kubernetes pod order or
readiness alone. Signed topology plus engine receipts are authoritative.

All API replicas run the same in-process control-plane runtime under durable
database leases. There is no new deployment split into API, worker, and
supervisor pods. A replica can die at any await and another can resume from
durable intent, operations, leases, and receipts.

Direct node routes are created before a topology advertising them can commit,
and removed only after no committed topology or retained recovery state names
them.

## Local runtime and CLI

The CLI creates the same artifacts under the project directory:

- controller trust root;
- stable node IDs and mTLS identities;
- one data directory and fixed port set per node;
- current and prepared signed topologies;
- transition and backup receipts;
- deterministic direct RESP and HTTP endpoints.

`lux start` launches separate engine processes. Local certification benchmarks
do not use multiple embedded engines on one Tokio runtime. `lux cluster status`
shows desired/observed nodes, epochs, metadata versions, slot balance, transfer
progress, direct endpoints, and any readiness/fencing reason.

`lux cluster scale --nodes N` and consolidation to one node use the same engine
protocol as Cloud. Killing the CLI does not corrupt or implicitly roll back a
transition; rerunning the command resumes it.

## Security model

### Trust boundaries

- The topology controller can add/remove identities and change ownership.
- The control node can propose engine execution metadata but only while its
  identity is authorized by current signed topology.
- Data owners hold project data, local data-encryption material, project-key
  digests, public token-verification keys, and the minimal authorization ledger.
- Native clients trust the Cloud TLS endpoint or local project configuration to
  bootstrap the controller public key, then verify topology.
- Compatibility ingress nodes are not trusted to choose ownership; receiving
  owners re-derive and validate the slot.

### Required defenses

- canonical signed bytes and cross-language test vectors;
- anti-rollback persistence on every node;
- mTLS identity pinning independent of DNS;
- cluster/source/target/epoch/deadline/request-ID binding on every peer frame;
- maximum frame/chunk sizes and decompression limits;
- no mutation over 0-RTT;
- idempotent transfer and control request IDs;
- strict metadata schema and previous-digest validation;
- no user-controlled network destination in any control or delivery record;
- secret redaction in topology, status, backup, logs, and errors;
- readiness removal and fail-closed behavior for stale metadata;
- explicit rate and resource budgets for transfer and compatibility queues;
- tenant confinement at Cloud routes and per-project certificate boundaries.

Security tests must include malicious nodes presenting valid certificates from
another epoch, replayed signed manifests, source-ID spoofing, modified transfer
chunks, stale authorization snapshots, oversized frames, and attempts to route
reserved auth/push tables as ordinary data.

## Observability

Every node exports low-cardinality metrics for:

- native owner-local operations and latency;
- `MOVED`, `ASK`, stale-metadata, and fenced responses;
- compatibility local and forwarded operations;
- peer bytes and frames by allowed message family;
- topology and metadata epoch/version/digest;
- transition snapshot/WAL bytes, lag, throttle time, and cutover duration;
- per-slot or bucketed load/skew without unbounded labels;
- executor queue depth and scheduling delay;
- foreground throughput and p99 during resize;
- backup/restore barrier and part progress.

Tracing marks `route_mode=owner_local|redirect|compat_forward|distributed_query`
and `served_by`. The benchmark uses these fields to prove native zero-hop
behavior rather than inferring it from throughput.

## Performance and cost contract

RFC 0002 is normative. In summary:

- owner-local per-node throughput is at least 97% of standalone;
- aggregate throughput reaches at least 1.90x, 3.70x, and 7.20x at 2, 4, and 8
  nodes;
- equal-load p99 remains within 5% for one-node cluster mode and within 10% at
  2/4/8 nodes;
- resize foreground throughput remains at least 90% of steady state;
- KV and point-table paths both pass;
- no committed operation is missing or duplicated through resize;
- native and compatibility results are never blended;
- throughput per core and throughput per dollar cannot hide a scaling win
  produced only by disproportionate resources.

## Deliberate non-goals for the first release

- replication factor greater than one and automatic failover;
- cross-slot ACID transactions;
- globally coordinated integer sequences;
- globally unique secondary constraints without a proven partitioned design;
- a claim that skewed hot-key workloads scale linearly;
- transparent native scaling for a client that refuses discovery/redirection;
- RDMA or kernel-bypass networking;
- silently partial global queries.

These are future designs, not loopholes in the point-operation release gates.

## Experimental-stack disposition

The existing branches are a quarry, not a merge base for the final stack.

| Experimental area | Disposition |
| --- | --- |
| canonical P-256 signed topology and anti-rollback validation | port after security review |
| per-node certificate generation, pinning, and QUIC mTLS | port after protocol review |
| signed public per-node RESP endpoints and Cloud SNI routes | port and extend to HTTP |
| durable transition plan, receipts, chunk digests, resume state | port concepts; replace request fencing and copy protocol as required by this RFC |
| distributed backup bundle, checksums, staging, restore rollback | port after failure-injection review |
| Cloud `clusters`, `cluster_nodes`, accounting, settings, autoscaling | port selectively; preserve concise schema and in-process control runtime |
| local multi-process identity/lifecycle groundwork | port selectively |
| system-node entry for point table operations | delete |
| per-request table catalog attachment/install | delete |
| remote point-command forwarding as the normal data path | delete |
| ingress event mirroring for remote writes | delete |
| `RwLock` topology reads on every operation | replace with immutable RCU snapshot |
| transition read guard held through local execution | replace with shard-ordered fence or qualifying atomic design |
| global async connection-map lock and stream-per-request peer RPC | replace with persistent multiplexed control channels; absent from native point path |
| in-process fixed-total-concurrency performance test | delete and replace with RFC 0002 harness |

New implementation branches start from current `main`. Validated pieces are
ported in reviewable commits; the 15,000-line additive experimental stack is not
blindly rebased or merged.

## Proposed implementation stack after RFC approval

The exact PR numbers are assigned later. Each Engine PR is independently
reviewable, contains no hidden Cloud mutation, and remains behind an
off-by-default capability until certification.

1. **Benchmark harness and red baselines.** External load generator,
   isolated-process runner, artifact schema, topology verifier, and intentionally
   failing scaling gates.
2. **Signed topology and membership foundation.** Port only canonical signing,
   identities, validation, persistence, and protocol tests.
3. **Immutable routing and redirection.** RCU snapshot, RESP/HTTP discovery,
   `MOVED`/`ASK`, direct endpoints, no forwarding in native mode.
4. **Execution metadata.** Structural snapshot, authorization ledger,
   prepare/commit/recovery, local auth and grant enforcement.
5. **Native KV data plane.** Owner-local fast path, persistent client pools,
   zero peer frames, 1/2/4/8 KV gates.
6. **Native point-table data plane.** Public routing algorithm, SDK routing,
   owner-local catalogs/grants, table gates.
7. **Online transitions.** Snapshot plus WAL catch-up, shard fences, throttling,
   crash matrix, scale up/down/consolidation gates.
8. **Distributed query/realtime compatibility.** Explicit scatter/fan-in,
   cancellation, limits, resume behavior, separately measured.
9. **Backup, restore, and recovery.** Distributed barrier/bundle/staging with
   failure injection.
10. **OSS CLI lifecycle.** Multi-process local runtime, scale, consolidate,
    status, doctor, and recovery.

The Cloud stack begins only when the corresponding Engine contracts are stable:

1. concise persistence and contracts;
2. node identities and direct RESP/HTTP routes;
3. durable lifecycle and topology controller inside existing API replicas;
4. execution-metadata and transition orchestration;
5. backup/restore and accounting;
6. settings UI, fixed scaling, autoscaling, and consolidation;
7. isolated Cloud certification and canary rollout.

No PR in either stack describes the feature as production-ready before the
final certification artifacts pass.

## Accepted decisions

This RFC was approved on 2026-08-04 with agreement that:

- native clients own steady-state routing;
- the stable endpoint is bootstrap plus compatibility, not a native point
  coordinator;
- the control node exists only for rare metadata/auth/control mutations;
- user-token verification uses replicated minimal authorization state and
  asymmetric verification material;
- broad distributed queries are explicit and separately measured;
- resize uses background copy plus WAL catch-up and shard-ordered cutover;
- RF1 provides capacity scaling, not failover;
- the experimental PRs will be replaced with new stacks from `main`;
- RFC 0002 gates are release requirements, not aspirational dashboards.

## References

- [Redis Cluster specification](https://redis.io/docs/latest/operate/oss_and_stack/reference/cluster-spec/)
- [ScyllaDB CQL drivers and shard-aware routing](https://docs.scylladb.com/stable/drivers/cql-drivers)
- [ScyllaDB driver load balancing and shard awareness](https://cpp-rs-driver.docs.scylladb.com/stable/topics/configuration/load-balancing)
- [Seastar asynchronous and shared-nothing design tutorial](https://docs.seastar.io/master/tutorial.html)
- [Linux kernel RCU concepts](https://docs.kernel.org/RCU/rcu.html)
- [ArcSwap performance characteristics](https://docs.rs/arc-swap/latest/arc_swap/docs/performance/index.html)
- [A General Theory of Computational Scalability Based on Rational Functions](https://arxiv.org/abs/0808.1431)
- [The Tail at Scale](https://research.google/pubs/the-tail-at-scale/)
- [FaRM: Fast Remote Memory](https://www.microsoft.com/en-us/research/publication/farm-fast-remote-memory/)
- [Dynamo: Amazon's Highly Available Key-value Store](https://www.amazon.science/publications/dynamo-amazons-highly-available-key-value-store)
- [SILK: Preventing Latency Spikes in Log-Structured Merge Key-Value Stores](https://www.usenix.org/conference/atc19/presentation/balmau)
- [Replicating Persistent Memory Key-Value Stores](https://www.usenix.org/system/files/osdi23-wang-qing.pdf)
