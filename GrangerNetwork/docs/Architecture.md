# Architecture

## Scope

Granger Network v0.2 is a standalone prototype. It does not depend on or modify
Granger Browser, Qt WebEngine, Tor, I2P, browser routing, or browser fail-closed
behavior.

The remote-capable path is:

```text
numeric-loopback HTTP application
              |
      granger-host (service identity)
              |
       outbound TCP connection
              |
        rendezvous relay
              |
       outbound TCP connection
              |
        granger-client
```

The relay forwards a Granger protocol stream. The service handshake and all
application messages are end-to-end authenticated and encrypted between host
and client. The relay does not terminate that secure channel.

## Identity and address

`ServiceIdentity` owns an Ed25519 private key. The canonical service identifier
is a domain-separated SHA-256 digest of the raw public key, encoded as lower-case
Base32. IP addresses are not service identities.

A local alias such as `test.granger` maps to a canonical identity address. It is
a convenience label, not a globally registered domain.

## Descriptor v2

A v2 `ServiceDescriptor` contains:

- descriptor and Granger protocol versions;
- canonical service ID and Ed25519 public key;
- supported transport identifiers;
- a logical rendezvous ID;
- issue and expiry times;
- bounded display metadata (`title` and `contentType`);
- an Ed25519 signature over the canonical document.

It deliberately contains no host address, host port, relay address, HTTP URL,
or operator metadata. Descriptor verification checks key/address binding,
signature, exact schema, supported versions and transports, clock bounds,
expiry, lifetime, and metadata limits.

The v1 descriptor remains readable only for the existing numeric-loopback
compatibility profile.

## Discovery layer

`DiscoveryProvider` has two independent responsibilities:

1. resolve a `.granger` name to a signed descriptor;
2. resolve a descriptor's logical rendezvous ID to transport bootstrap data.

`LocalResolver` is the v0.2 experimental implementation. It stores descriptors,
local aliases, and rendezvous bootstrap entries in separate files. It accepts
only `.granger` names, never invokes DNS, and has no alternate network lookup.

Separating the interfaces allows a future distributed discovery mechanism to
replace the local files without changing identity verification or encrypted
protocol code. v0.2 does not implement that distributed mechanism.

## Transport layer

`GrangerTransport.connect(destination_id)` accepts only a canonical
cryptographic service ID. It returns a `TransportSession` with a 128-bit session
ID and `send`, `receive`, and `close` operations.

`RendezvousClientTransport` connects only to a separately configured numeric
relay endpoint. `RendezvousHostTransport` also creates an outbound relay
connection. No remote descriptor carries a service endpoint, and no client code
has a destination from which it could construct a direct host connection.

Numeric relay bootstrap avoids accidental hostname resolution. A relay endpoint
may be remote; loopback is used by the automated test network.

## Rendezvous layer

The service host registers its service ID, public key, fresh nonce, and timestamp
with an Ed25519 signature. The relay verifies that the public key derives the
claimed service ID and verifies the signature before making the host available.

The client sends a canonical destination ID and a random session ID. The relay
rejects reused registration nonces and session IDs, selects a waiting host, and
sends the same session ID to both peers. It then forwards bytes in both
directions without parsing the end-to-end protocol.

The host remains behind an outbound connection. The client never receives the
host peer address, and the host never receives the client peer address. Both do,
however, expose their network address to the relay.

## End-to-end protocol

Protocol v2 binds the relay session ID and a fresh client timestamp into the
ClientHello. The service signs the complete handshake transcript with Ed25519.
The client verifies the expected descriptor identity before sending a request.

Ephemeral X25519 and HKDF-SHA256 derive independent directional keys.
ChaCha20-Poly1305 frames bind the session ID, direction, size, and sequence
number as authenticated data. Sequence numbers start at zero and must be exact;
a repeated, skipped, reordered, modified, or cross-session frame is rejected.

## Service bridge

The service host is the only process that can reach the local application. Its
`LoopbackHttpBridge` permits only numeric-loopback HTTP, GET/HEAD, safe
origin-form paths, bounded bodies, and selected headers. It never opens a public
HTTP listener.

## Data visibility

The client knows the signed descriptor, service identity, configured relay
endpoint, request, and response. It sees the relay as its network peer, not the
service host.

The host knows its identity, relay endpoint, decrypted request, and local
application response. It sees the relay as its network peer, not the client.

The relay knows both peers' source network addresses, service ID, host public
key, registration nonce, session ID, timestamps, connection timing, duration,
directional sizes, and end-to-end handshake bytes. It cannot authenticate as the
service or decrypt application frames without the service private key.

The local discovery store knows descriptors, aliases, and relay bootstrap data
installed by that user. It performs no network query.

## Failure behavior

Malformed names, unknown descriptors, invalid signatures, expired descriptors,
missing relay bootstrap, unsupported transports, failed relay pairing,
mismatched identities, stale handshakes, and invalid or replayed frames terminate
the request. There is no DNS, direct-host, clearnet HTTP, or alternate transport
fallback.
