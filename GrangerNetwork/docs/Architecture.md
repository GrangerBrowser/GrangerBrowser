# Architecture

## Scope

Granger Network v0.3 is a transport-independent experimental private namespace
and privacy-overlay prototype. This iteration adds distributed discovery,
service introduction points, signed peer identities, and a local multi-hop
transport simulation. It changes only `GrangerNetwork`; Qt WebEngine, browser
routing, Tor, I2P, installers, and public packages are unchanged.

The existing single-rendezvous implementation remains as a compatibility path
for the browser adapter and earlier tests. The new experimental path is:

```text
client
  |
entry node
  |
client middle
  |
introduction / rendezvous
  |
host middle
  |
service relay
  |
service host -> numeric-loopback application
```

The client and host construct their sides independently. No route contains a
direct client-to-host edge, and the service address never contains an IP
address. This source implementation is an in-process protocol simulation over
socket pairs, not a deployed WAN, production DHT, or anonymity claim.

## Layers

The implementation keeps these responsibilities separate:

1. Ed25519 service and node identities;
2. canonical `.granger` address derivation;
3. signed service, peer, alias, and introduction records;
4. bounded XOR-nearest record replication and lookup;
5. route planning from independently advertised capabilities;
6. telescoped, independently authenticated wire 3 sessions;
7. an end-to-end service-authenticated wire 3 channel;
8. the bounded HTTP application bridge;
9. the unchanged browser compatibility adapter.

Discovery cannot resolve through DNS. Route construction cannot ask the
compatibility resolver for a single rendezvous and cannot create a direct host
connection after an overlay failure.

## Service identity and names

`ServiceIdentity` owns an Ed25519 private key. The canonical service identifier
is a domain-separated SHA-256 digest of its public key, encoded as 52 lower-case
Base32 characters. The canonical name is therefore self-authenticating:

```text
<service-id>.granger
```

A human alias such as `forum.granger` is a signed mapping to the same service
identity, but a self-signature alone cannot establish global ownership of a
human-readable label. `DistributedResolver` therefore also requires a local
alias-to-service identity pin. A valid signature cannot override that pin.

## Service descriptor compatibility

The distributed prototype reuses the exact signed v2 remote
`ServiceDescriptor` and wire 3 identity contract. It adds no service endpoint.
The legacy `rendezvousId` and `transports` fields remain in that descriptor for
schema and browser compatibility, but `DistributedResolver` does not consume
them and deliberately rejects `resolve_rendezvous()`. A matching signed
`IntroductionDescriptor` is authoritative for overlay reachability.

An explicit distributed transport field will require a reviewed descriptor
revision before a real network deployment. Treating legacy rendezvous bootstrap
as an overlay fallback is forbidden.

## Peer model

Each `GrangerNode` has an independent Ed25519 identity. Its signed, short-lived
`NodeDescriptor` contains:

- a public-key-derived node ID;
- a numeric node endpoint used only as a routing hint;
- sorted capabilities: discovery, entry, middle, introduction, or service relay;
- an explicit relay opt-in flag;
- maximum concurrent circuits, bytes per circuit, and aggregate KiB/s;
- issue and expiry times.

Advertising any forwarding role requires explicit opt-in. The runtime enforces
the circuit, byte, and one-second bandwidth quotas under a lock. Exhaustion
fails the affected circuit. Merely running Granger Browser does not enable relay
participation, and this iteration does not connect the peer model to browser
settings.

## Distributed discovery

`DistributedDiscoveryNetwork` is a bounded DHT-like record layer for local
experiments. It computes a domain-separated SHA-256 routing key and stores each
record at the nearest signed discovery node IDs by XOR distance. The default
policy writes three replicas and requires at least two valid peers.

Only these records are accepted:

- signed node descriptors and numeric node routing hints;
- signed service identity descriptors with no service endpoint;
- signed short-lived introduction descriptors;
- signed alias records.

Records are limited to 64 KiB and peer stores to 4,096 entries. Strict schemas,
signatures, expiry, identity binding, storage keys, sequence high-water marks,
and same-sequence equivocation are checked at publication and lookup. A corrupt
replica is ignored; it cannot forge another identity's valid record.

This is not a complete Kademlia implementation. Peer RPC, iterative lookup,
bucket maintenance, churn, persistence, authenticated bootstrap, Sybil
resistance, diversity constraints, and WAN replication are not implemented.
Consequently the prototype demonstrates record semantics and trust boundaries,
not distributed availability on the Internet.

## Introduction points

The host publishes a signed `IntroductionDescriptor` bound to the exact service
descriptor digest. It contains one or more introduction node IDs, random
32-byte authorization tokens, a monotonic sequence, and a maximum 30-minute
lifetime. It contains no service endpoint or host IP.

An introduction node accepts a request only when the service identity,
introduction node ID, token, descriptor binding, and fresh 16-byte request nonce
match installed state. Replayed request nonces, stale sequences, same-sequence
equivocation, mismatched service identities, and expired records fail closed.

The token is currently present in the discoverable signed record. It limits
accidental or stale introductions but is not client authorization and does not
prevent a reader from attempting denial of service. Private introduction
credentials and rate-limited admission remain future work.

## Multi-hop transport

`OverlayRoutePlanner` selects five distinct, currently valid node identities:

- client entry;
- client middle;
- service-authorized introduction;
- host middle;
- service relay.

Each role must be advertised in a verified node descriptor. Missing roles,
duplicate node identities, invalid introduction state, or unavailable runtimes
terminate route construction without trying another transport.

`MultiHopCircuit` models telescoping. Physical adjacent links first establish
wire 3 sessions. Inner wire 3 handshakes are then carried through those secure
streams to the next node. The client and host sides meet at the introduction
node, where a final service-authenticated wire 3 session is established end to
end. The current topology creates eleven unique channel bindings: ten hop or
telescoping sessions plus one end-to-end service session.

Every session has a fresh session ID, X25519 and ML-KEM-768 exchange, transcript,
nonces, directional keys, counters, ratchets, and lifetime. No key, exporter,
nonce space, or ratchet is copied between hops. Relays forward the ciphertext
of deeper layers and never receive the application channel keys.

This implementation validates the composition over local socket pairs. It does
not yet define relay cells, congestion control, stream multiplexing, network
listeners, NAT traversal, peer RPC, or production path selection.

## Wire 3 secure channel

Wire 3 itself is unchanged. It authenticates a transcript containing the exact
protocol and suite selection, session ID, freshness timestamp, ephemeral
X25519 and ML-KEM-768 material, service or node Ed25519 identity, random nonces,
frame limit, rekey interval, and session lifetime.

Hybrid shared secrets feed transcript-bound HKDF-SHA256. HMAC-SHA256 Finished
messages confirm key possession. ChaCha20-Poly1305 protects independently
derived control and data keys in each direction. Sequence, kind, epoch, size,
direction, suite, session, and channel binding are authenticated. Traffic keys
ratchet and the session expires after its negotiated lifetime.

## Visibility by role

- The client knows the service identity, signed records, selected entry, its
  request and response, and local timing. It has no host endpoint.
- The host knows the service identity, selected service relay, application
  plaintext, and local timing. It has no client endpoint.
- The entry sees the client network address and the next relay. Deeper route and
  application bytes are encrypted.
- A middle sees only its adjacent overlay nodes and encrypted bytes.
- The service relay sees the host network address and host middle, not the
  client.
- The introduction sees the two adjacent middle nodes, introduction token use,
  end-to-end service handshake metadata, sizes, and timing. It does not see
  either endpoint address in the modeled topology.
- Discovery replicas see signed public records and lookup timing. They do not
  receive a service or client IP from those records.

A single modeled relay does not see both endpoint addresses and relay captures
do not contain test application markers. Colluding relays, an ISP observing
both ends, or a global passive observer may still correlate timing and sizes.

## Metadata protection and performance

No padding, uniform frame sizing, batching, cover traffic, traffic shaping, or
artificial delay is enabled. These features can consume substantial bandwidth,
increase latency, create recognizable schedules, and amplify denial of service.

The local benchmark performs eleven hybrid wire 3 sessions per route. On the
recorded Windows development environment, 20 route setups averaged about
25.7 ms and a 1 MiB, 64-frame transfer reached about 25.5 MiB/s. This is an
in-process best case, not a WAN estimate. The result supports keeping metadata
defenses disabled until packet distributions, route latency, CPU, memory, and
bandwidth overhead are measured on independent nodes.

## Browser compatibility

The existing Qt WebEngine adapter still uses `LocalResolver` and the established
rendezvous transport. It is intentionally not wired to the distributed
prototype. Browser acceptance therefore checks that HTML, CSS, JavaScript,
resources, origin isolation, and cross-network blocking did not regress; it
does not claim that the browser is already using the distributed route.

## Failure behavior

Malformed names, missing identity pins, invalid or expired records, insufficient
replicas, descriptor rollback or equivocation, unavailable or repeated route
nodes, failed introduction authorization, resource exhaustion, failed hop
handshakes, mismatched identities, failed Finished confirmation, invalid frames,
and closed relay streams terminate the request and release node quotas.

There is no DNS, direct client-host, clearnet HTTP, single-rendezvous, lower-wire
version, or alternate-transport fallback from the distributed overlay.

## Architectural references

The design uses concepts, not source code, from:

- [Tor Onion Service protocol overview](https://spec.torproject.org/rend-spec/protocol-overview.html):
  separate introduction and rendezvous roles and independently built paths;
- [I2P network database](https://i2p.net/en/docs/overview/network-database/):
  signed, expiring descriptors replicated near cryptographic keys;
- [Kademlia paper](https://pdos.csail.mit.edu/~petar/papers/maymounkov-kademlia.pdf):
  XOR-distance record placement.
