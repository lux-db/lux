# Cluster v2

Cluster is Lux's optional capacity-scaling layer. It maps a fixed 4,096-slot
space onto otherwise normal Lux engines. It is deliberately not Raft, does not
replicate writes, and does not change the ordinary single-node path unless a
server is started with `LUX_CLUSTER_CONFIG`.

The first release is RF1: adding nodes increases aggregate capacity for data
that distributes across slots, but the loss of a node makes its slots
unavailable until that node and its volume return. Replication and automatic
failover are a separate future design.

## Trust and topology

The Cloud controller or OSS CLI is the only topology authority. It signs every
manifest with P-256 ECDSA. A node receives the controller's SEC1 public key in
its local config, persists committed and prepared epochs on its own volume, and
rejects rollback, conflicting contents at the same epoch, unknown nodes,
certificate changes outside a signed manifest, and incomplete slot maps.

The signature payload is a deterministic binary encoding:

1. ASCII `LUX-CLUSTER-TOPOLOGY` followed by a zero byte.
2. Fixed-width unsigned integers in network byte order.
3. Every string or vector prefixed with its unsigned 32-bit length.
4. Manifest fields, nodes, and assignments in their declared order.

`TopologyManifest::signing_payload` is the executable reference for other
implementations. The JSON representation is only the storage envelope and is
not itself signed.

Each node has a unique self-signed TLS certificate. The signed manifest carries
the public certificate and SHA-256 pin. Peer traffic uses mutual TLS over QUIC
with ALPN `lux-cluster/1`; requests bind the authenticated certificate to their
claimed source node and carry cluster, epoch, target, deadline, slot, catalog,
and request identity. Mutations never use 0-RTT.

## Client discovery

The signed descriptor for each node also carries its externally reachable RESP
address. `CLUSTER SLOTS` projects Lux's 4,096 internal owners across Redis's
16,384 client slots, and key ownership uses Redis CRC16 plus hash tags. Standard
Redis Cluster clients can therefore discover every owner and send keyed traffic
directly without Lux-specific routing code.

The stable RESP endpoint remains a compatibility ingress and forwards keyed
commands to their signed owner. HTTP clients also remain on the stable endpoint.
Commands that have no safe distributed semantics fail explicitly instead of
silently executing on one node. See `README.md` for the currently supported
Redis Cluster compatibility surface.

## Node config

`LUX_CLUSTER_CONFIG` names one JSON file. Paths are relative to that file:

```json
{
  "local_node_id": "node-1",
  "peer_bind_addr": "0.0.0.0:7946",
  "certificate_chain_path": "secrets/node-1.pem",
  "private_key_path": "secrets/node-1.key",
  "topology_path": "topology.json",
  "topology_state_path": "data/topology-state.json",
  "controller_public_key": "base64url-sec1-public-key",
  "max_frame_bytes": 16777216
}
```

Peer and client addresses in the manifest may be IP or DNS names plus ports. DNS is
resolved for each new connection, allowing a Kubernetes Service to move without
changing ownership. Certificate identity remains pinned independently of DNS.

Cluster remains completely disabled unless `LUX_CLUSTER_CONFIG` is present.
When enabled, the management capability contract advertises topology,
transfers, distributed scans and tables, backup barriers and parts, and staged
restore. The OSS CLI and Lux Cloud require that complete contract before they
allow a project to use multiple nodes.
