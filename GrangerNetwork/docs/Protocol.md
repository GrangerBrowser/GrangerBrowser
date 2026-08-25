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

Implemented message types are:

```text
HELLO AUTH CAPABILITIES PING PONG
FIND_NODE FIND_RECORD STORE_RECORD
OPEN_CIRCUIT EXTEND_CIRCUIT CIRCUIT_CREATED CIRCUIT_FAILED CLOSE_CIRCUIT
INTRO_REGISTER INTRO_REQUEST INTRO_DELIVER
RENDEZVOUS_REGISTER RENDEZVOUS_JOIN
STREAM_OPEN STREAM_DATA STREAM_CLOSE STREAM_RESET WINDOW_UPDATE
ERROR
```

Not every named stream message is used directly by the current cell
multiplexer; fixed cells carry the data-plane stream state. Unsupported or
out-of-state messages fail closed.

## Distributed lookup

Bootstrap peers provide an initial authenticated route to the discovery mesh.
The client asks peers for node descriptors nearest to a domain-separated XOR
key and then sends `FIND_RECORD` or `STORE_RECORD` to the nearest eligible
discovery nodes.

Default publication replication is three and default read quorum is two.
Responses are independently parsed and signature-verified. A lookup succeeds
only when a non-stale sequence has an unambiguous replica quorum. A peer cache
stores only bounded, valid, signed node descriptors and may provide startup
after all bootstrap peers become unreachable. A fresh profile with no reachable
bootstrap and no valid cache returns network unavailable.

## Circuit construction

A client circuit has two relays before rendezvous:

```text
client -> entry -> middle -> rendezvous
```

A service circuit has three infrastructure roles:

```text
service -> service-entry -> middle -> introduction-or-rendezvous
```

The circuit builder connects only to the first node. It then sends one
`EXTEND_CIRCUIT` request at a time. The request gives the current relay only its
own role, an independent incoming/outgoing circuit ID, the next role, and the
next signed descriptor. A new authenticated wire-3 channel is established
through each resulting stream before the following extension. No relay receives
the complete route list.

Node identities may not repeat within a route. Selection prefers distinct IPv4
/16 or IPv6 /32 network groups and reports when that diversity preference had
to be relaxed. This is a heuristic, not operator, AS, jurisdiction, or family
diversity.

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
hide cell count, direction, timing, connection lifetime, or total volume. There
is no default cover traffic or artificial delay.

## Introduction and rendezvous

The host maintains at least two outbound introduction circuits and a separate
rendezvous circuit. It publishes a signed introduction descriptor containing
the introduction node IDs and opaque tokens.

The client:

1. Resolves and verifies the service and introduction records.
2. Builds a client entry/middle prefix.
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
lifetimes. Replay, wrong service identity, wrong signature, expiry, duplicate
registration, and unexpected order are rejected.

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

## Versioning

Record, bootstrap, RPC, cell, application, and wire versions are validated at
their parsing boundary. There is no negotiated downgrade in the WAN path.
Adding a version requires a new specification, explicit parser support, and
cross-version tests; unknown versions are rejected.
