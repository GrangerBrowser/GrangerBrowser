# Granger Network Protocol v0.4

## Status

This document describes the protocol implemented in `src/granger_network`.
Granger Network is experimental and has not received an independent security
review. The protocol is not TLS, Tor, I2P, or a replacement for their published
security analyses.

The implementation uses real TCP sockets and separate processes in local
acceptance tests. Physical cross-network operation is still **UNVERIFIED**.

## Protocol layers

```text
bounded application messages
        |
multiplexed fixed relay cells
        |
end-to-end wire 3 service channel
        |
paired client and service circuits
        |
authenticated peer RPC over per-hop wire 3 channels
        |
numeric TCP endpoints
```

Ordinary clients and service hosts initiate outbound connections. Only
explicitly configured infrastructure nodes listen for inbound TCP. The
protocol contains no DNS, STUN, ICE, UPnP, NAT-PMP, direct client-to-service, or
alternate clearnet path.

## Identities and records

Service and node identities are Ed25519 key pairs. Canonical service names are
the full lower-case Base32 encoding of the domain-separated SHA-256 digest of
the service public key. See [AddressFormat.md](AddressFormat.md).

The distributed store carries four bounded signed record types:

| Record | Key | Endpoint contents |
| --- | --- | --- |
| Node descriptor | node ID | Public numeric endpoint of an opt-in reachable node |
| Service descriptor | service ID | None |
| Introduction descriptor | service ID | Introduction node identities and opaque tokens only |
| Alias record | alias | Service ID only; clients also require a local identity pin |

Records include a version and expiry. Sequence-bearing records reject rollback
and same-sequence equivocation. A service or introduction record containing a
service endpoint is rejected.

## Wire 3 secure channel

Every adjacent peer channel and the final client-to-service channel use wire
version 3 from `protocol.py`:

- ephemeral X25519 and ML-KEM-768 key exchange;
- HKDF-SHA256 key derivation with domain separation;
- Ed25519 server authentication;
- transcript-bound Finished confirmation;
- ChaCha20-Poly1305 authenticated frames;
- independent transmit and receive sequence numbers;
- control/data frame separation;
- key epochs and bounded session lifetime;
- 4 MiB maximum plaintext frame size.

The peer identity proof below additionally binds both peer HELLO messages to
the wire-3 channel binding. A lower wire version is not accepted for WAN peer
RPC. Long-term identity keys authenticate sessions but are not mixed into the
ephemeral shared secret.

## Peer authentication

An endpoint connects to the numeric address in a previously verified node
descriptor. The connection performs:

1. Wire-3 client/server handshake pinned to the expected node Ed25519 key.
2. `HELLO` exchange containing role, public key, random nonce, and, for
   infrastructure peers, the signed node descriptor.
3. Validation that the returned descriptor exactly matches the pinned node.
4. `AUTH` exchange: both sides sign the domain-separated channel binding and
   both encoded HELLO messages.
5. Strict transition to ordinary peer RPC only after both proofs pass.

Client and service endpoint roles do not send relay descriptors. Relay and
bootstrap roles must send one. Invalid roles, substituted identities, malformed
descriptors, missing proofs, or unexpected state transitions close the channel.

## Peer RPC framing

RPC version 1 runs inside authenticated wire-3 control frames. The fixed
36-byte network-order header is:

```text
magic[4] = "GNRP"
version[1]
message_type[1]
flags[1]
reserved[1] = 0
request_id[16]
sequence[8]
payload_length[4]
payload[payload_length]
```

Payloads are limited to 256 KiB. Each direction starts at sequence zero and
increments exactly once per frame. Unknown types, unknown flags, oversized or
inconsistent lengths, sequence gaps, and mismatched response IDs are terminal.
An authenticated peer connection is closed after 1024 ordinary RPC requests;
circuit, introduction, rendezvous, and reverse-adjacency transfers leave this
request loop earlier and retain their existing bounded data-plane lifetime.

Implemented message types are:

```text
HELLO AUTH CAPABILITIES PING PONG
PEER_SAMPLE FIND_NODE FIND_RECORD STORE_RECORD
OPEN_CIRCUIT EXTEND_CIRCUIT CIRCUIT_CREATED CIRCUIT_FAILED CLOSE_CIRCUIT
INTRO_REGISTER INTRO_REQUEST INTRO_DELIVER
RENDEZVOUS_REGISTER RENDEZVOUS_JOIN
STREAM_OPEN STREAM_DATA STREAM_CLOSE STREAM_RESET WINDOW_UPDATE
ERROR REVERSE_REGISTER
RESEED_QUERY RESEED_CHUNK OBSERVED_ADDRESS REACHABILITY_PROBE
```

Not every named stream message is used directly by the current cell
multiplexer; fixed cells carry the data-plane stream state. Unsupported or
out-of-state messages fail closed.

### Reverse adjacency

`REVERSE_REGISTER` has an empty payload and is valid only on a directly
authenticated relay connection. The initiating relay HELLO must carry a signed
node descriptor version 4 with:

- `reachability = "adjacent"`;
- the sole capability `middle`;
- `viaNodeId` equal to the authenticated receiving anchor;
- endpoint metadata equal to that anchor's signed endpoint;
- an enabled bounded relay policy and normal network/protocol binding.

The anchor stores a bounded one-shot authenticated session. A circuit extension
to that descriptor consumes the session instead of dialing the descriptor
endpoint. Direct socket connection APIs reject every non-`reachable`
descriptor. Expired, rolled-back, equivocated, misbound, over-capacity, or
nested registrations are rejected.

## Distributed lookup

Bootstrap peers provide an initial authenticated route to the discovery mesh.
Direct first contact is allowed only to an identity-pinned node from a verified
signed reseed/bootstrap set. It requests a bounded `PEER_SAMPLE`; responses
contain signed node descriptors, never an unsigned endpoint list. After join,
the client reaches discovery peers through access/guard/middle circuits, asks
for descriptors nearest to a domain-separated XOR key, and sends `FIND_RECORD`
or `STORE_RECORD` to the nearest eligible discovery nodes.

Default publication replication is three and default read quorum is two.
Responses are independently parsed and signature-verified. A lookup succeeds
only when a non-stale sequence has an unambiguous replica quorum. A peer cache
stores bounded valid signed descriptors plus non-sensitive reliability metadata
and may provide startup after all bootstrap peers become unreachable. Cache and
bootstrap descriptors are bound to the same network ID and wire protocol. A
fresh profile with no reachable bootstrap/reseed peer and no valid cache returns
network unavailable.

## Circuit construction

A client circuit has three relays before rendezvous:

```text
client -> access -> stable guard -> middle -> rendezvous
```

A service circuit has three relays before its terminal infrastructure role:

```text
service -> access -> stable service guard -> middle -> introduction-or-rendezvous
```

The circuit builder connects only to the access node. It then sends one
`EXTEND_CIRCUIT` request at a time. The request gives the current relay only its
own role, an independent incoming/outgoing circuit ID, the next role, and the
next signed descriptor. A new authenticated wire-3 channel with a per-hop
ephemeral identity is established through each resulting stream before the
following extension. No relay receives the complete route list or persistent
endpoint identity.

Node identities may not repeat within a route. Selection prefers distinct IPv4
/16 or IPv6 /32 network groups and reports when that diversity preference had
to be relaxed. This is a heuristic, not operator, AS, jurisdiction, or family
diversity.

An adjacent middle must immediately follow its signed `viaNodeId` anchor and
must carry the same public endpoint metadata. The first circuit hop must always
have a directly reachable version-3 descriptor. Adjacent descriptors are
returned by peer discovery only while the anchor owns an unused authenticated
slot. Direct `PEER_SAMPLE` and `FIND_NODE` requests never receive adjacent
descriptors. They become eligible only when discovery arrives through an
already established private circuit, so an arbitrary direct client cannot
enumerate the restricted-browser topology.

## Fixed relay cells

The data plane uses 1024-byte cells. The 38-byte network-order header is:

```text
magic[4] = "GNC1"
version[1]
type[1]
flags[1]
reserved[1] = 0
circuit_id[16]
stream_id[4]
sequence[8]
payload_length[2]
payload[0..986]
random_padding[to 1024 bytes]
```

Cell types are `OPEN`, `DATA`, `CLOSE`, `RESET`, and `WINDOW_UPDATE`. Cells are
authenticated by their enclosing wire-3 channel. Each stream enforces ordered
cell sequences, a bounded receive window, explicit window updates, bounded
queues, and a maximum stream count. Sending batches contain at most 64 cells.

Fixed cells reduce direct application-size disclosure on each cell. They do not
hide cell count, direction, timing, connection lifetime, or total volume.
Authenticated empty `COVER` cells may be sent under a bounded profile; real
cells have priority and cover generation has strict quiet-window and
per-minute limits. No artificial delay is applied to real scroll or request
traffic.

## Introduction and rendezvous

The host maintains at least two outbound introduction circuits and a separate
rendezvous circuit. It publishes a signed introduction descriptor containing
the introduction node IDs and opaque tokens.

The client:

1. Resolves and verifies the service and introduction records.
2. Builds a client access/guard/middle prefix.
3. Sends a fresh 16-byte introduction nonce and the selected opaque token.
4. Receives a short-lived service-signed rendezvous grant.
5. Verifies that the grant is bound to the request nonce, service identity,
   rendezvous descriptor, 32-byte cookie, and expiry.
6. Extends its circuit to the rendezvous and submits the cookie.

The host receives the request over an existing introduction circuit, creates
the signed grant, and registers its rendezvous circuit with the same cookie.
The rendezvous pairs the two opaque circuit streams. It does not receive the
end-to-end service keys.

Introduction nonces and rendezvous cookies are single-use within their bounded
lifetimes. Replay state is expiry-aware and bounded; live entries are never
evicted to make room, and unknown cookie tags do not consume replay capacity.
Replay, wrong service identity, wrong signature, expiry, duplicate registration,
and unexpected order are rejected.

## End-to-end service session

After pairing, the client performs another wire-3 handshake over the complete
paired circuit and pins the service public key from the verified service
descriptor. Relay nodes therefore forward fixed cells and encrypted service
frames but do not receive application plaintext.

The end-to-end channel carries a second cell multiplexer. Each application
request gets a distinct stream. Version-1 application messages support `GET`,
`HEAD`, and `POST`, up to 32 bounded headers, percent-encoded ASCII paths, and a
2 MiB body limit. Responses are also bounded to 2 MiB. The service bridge may
connect only to a numeric loopback HTTP target.

## Failure semantics

The following failures terminate the current operation or circuit:

- missing, invalid, expired, or ambiguous records;
- unreachable or unverified bootstrap/relay nodes;
- peer identity, channel binding, or signature mismatch;
- malformed, oversized, replayed, or out-of-order RPC/cell/application data;
- missing role capability or repeated route identity;
- introduction or rendezvous expiry/replay;
- resource, timeout, flow-control, or local-upstream failure.

Route retries select other verified relay candidates. They never dial a service
endpoint, invoke DNS, use a compatibility rendezvous, switch to Tor/I2P, or
continue over clearnet. Exhaustion returns a private-route error.

An authenticated `SERVICE_OFFLINE` reply to `INTRO_REQUEST` suppresses other
paths to that introduction endpoint for the current request only. It does not
establish that the service does not exist. The client tries the other signed
points and checks once for a newer quorum-verified introduction before failing
closed. A newer sequence permits new attempts within the original shared
budget; rollback and equivocation are still rejected. Intermediate circuit
errors and temporary endpoint failures do not trigger this suppression.
An introduction node already present in the current authority-signed bootstrap
set uses that still-valid signed descriptor directly. Unknown or expired nodes
retain the normal DHT quorum lookup. Independent fallback lookups run at most
two at a time, retaining each lookup's full quorum and verification; all
workers are joined. Every circuit still authenticates the selected node key.
Canonical service and introduction record lookups also overlap, with at most
two workers. The introduction must bind to the quorum-verified service before
either result is returned to the connection path.

During a DHT request, failure of a nested circuit hop excludes that directed
role-specific segment only from the remaining attempts of the same request
or its enclosing single-record transaction.
It is not evidence that either router is unreachable in every role. A lost
end-to-end transport similarly cannot identify the failing router. Only an
observed first-hop connection failure retains the local peer cooldown. Retries
remain bounded, use distinct eligible paths, and authenticate every hop; no
cooldown change makes an invalid identity or record acceptable.
Previously attempted paths are removed before applying the candidate-list
limit. Pending distinct alternatives retain their order; refilling a depleted
list cannot reset the attempt budget. With equal network diversity, locally
authenticated ingress peers precede uncontacted hints; this is not a reason
to skip hop authentication or change role separation.

Hosts issue the existing 120-second default rendezvous grant, capped by the
remaining registration lifetime. They do not mint grants at the receiver's
absolute 300-second limit: even a one-second leading host clock would make
such a grant invalid on receipt. Receiver expiry, nonce binding, signatures,
and the maximum validity window are unchanged. Clocks still need to be
reasonably synchronized; no expired grant is accepted.
Registration issuance similarly leaves five seconds below the receiver's
600-second maximum, including when its circuit has already been built. This
shortens the issued registration; it does not grant receiver-side clock grace.

The hosting startup worker builds its independent introduction and rendezvous
chains concurrently, with at most three temporary workers. It joins every
build before registration and readiness, and closes all successful partial
builds if another build fails or startup is stopped. The initial rendezvous
chain is transferred to the existing session lifecycle, not retained as an
extra pooled circuit. Each chain still uses the existing fresh per-hop keys.

A DHT record transaction may reuse at most four authenticated circuits between
its node search and its read or write of the same record. The scope authorizes
only those exact payloads. Reuse ends with the transaction, expires after at
most 30 seconds idle, and rechecks the peer pin, signed descriptor validity,
and transport state. No circuit is shared between records, services, or later
requests. The discovery peer already receives the deterministic routing key
and record key in this transaction; this does not add cross-record linkage.
The quorum, route roles, encrypted cells, and record validation are unchanged.
Record storage/lookup uses responders from that transaction's node search,
not nodes whose private search failed or which were only advertised as hints.
The bounded failed-path budget is shared between its search and record RPCs,
then discarded. It is neither a persistent negative service cache nor proof
that an unavailable peer is globally offline.

Consecutive node searches also retain a bounded in-memory backoff for a failed
terminal `middle -> discovery` edge or an intermediate circuit extension.
It is keyed by both signed descriptor identities, issuance versions, ordered
direction and roles; it expires
after 60-300 seconds using the existing connection-failure backoff scale.
At most 2048 entries are retained. New descriptor versions and other roles
remain eligible; a successfully authenticated edge clears its entry. This
prevents hosting startup from spending a new full route-retry budget on the
same unavailable edge at each selection/publication stage. An intermediate
authentication failure remains request-scoped; it is not promoted to an
extension reachability claim. This state does
not establish a negative service record or change the required replica quorum.
If a `FIND_NODE` exhausts its twelve-attempt budget or all currently eligible
routes, and every attempted route failed at the terminal role, the next search
for the same descriptor version is deferred for 60 seconds from completion.
Small topologies must not immediately restart an exhausted search merely
because fewer than twelve eligible terminal edges existed.
This bounded, process-local search backoff does not disable other roles or
record RPCs and is never treated as a signed absence result. Changed descriptor
versions remain eligible. Other circuit failures do not trigger this backoff.

Each validated node-list response is ingested as one bounded peer-cache batch,
using the existing source, signature, endpoint ownership and network-group
checks. Route diversity scoring precomputes invariant identity pairs but keeps
the same greedy ordering and tie-breaking rules.

Gateway diagnostics distinguish unavailable record quorum, unavailable
network, unavailable introduction points, and exhausted routes. None of these
is reported as proof that a remote service does not exist.

Production nodes retain connection source addresses and per-circuit topology
only when an explicit diagnostic capture path is configured. Default runtime
state keeps aggregate counters, while persisted diagnostics store bounded error
categories rather than raw exception text. Peer caches, live node views, DHT
records, discovery outcome history, rollback state, introduction state,
rendezvous replay state, RPC requests per connection, and browser service
sessions all have explicit bounds. Expired DHT and replay entries release their
capacity without requiring a restart.

## Versioning

Record, bootstrap, RPC, cell, application, and wire versions are validated at
their parsing boundary. There is no negotiated downgrade in the WAN path.
Adding a version requires a new specification, explicit parser support, and
cross-version tests; unknown versions are rejected.

The reverse-adjacency extension does not change wire version 3 or RPC framing
version 1. Existing version-3 reachable node descriptors remain valid. New
implementations additionally parse adjacency descriptor version 4 and message
type 26. An older node rejects the version-4 descriptor during authentication,
or rejects the unknown RPC type if it reaches dispatch, and cannot act as an
adjacency anchor. The browser records the failure and tries another verified
candidate. There is no downgrade to direct dialing or a less protected transport.

The current implementation also adds RPC types 27 (`RESEED_QUERY`),
28 (`RESEED_CHUNK`), 29 (`OBSERVED_ADDRESS`), and 30 (`REACHABILITY_PROBE`).
Wire 3 and RPC framing version 1 are unchanged. Older peers may reject these
messages; they are not treated as a new trust root or a reason to bypass
authentication. Reseed responses contain only existing signed public bundles,
not private authority material. See `Bootstrap.md` for size, overlap, and
high-water checks.

Public relay proof is restricted to the authenticated caller's signed node
descriptor and actual numeric source address. A random PING callback must
authenticate that same node identity; the caller cannot supply an unrelated
callback target. At most eight callbacks run concurrently per verifier. The
browser publishes reachable status only after its configured callback quorum.
