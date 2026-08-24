# Architecture

## Scope

Granger Network is a transport-independent experimental private namespace and
overlay module. The current source tree also contains a local Granger Browser
adapter. This cryptographic update changes only Granger Network. It does not
modify Qt WebEngine, Tor, I2P, browser routing, or their fail-closed behavior.

The current remote path is:

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

The relay forwards an end-to-end Granger wire stream. It does not terminate the
authenticated secure channel between the client and service host.

## Layers

The implementation keeps six responsibilities separate:

1. identity and canonical address derivation;
2. signed service descriptors and local alias resolution;
3. rendezvous bootstrap and pairing;
4. transport sessions that expose an opaque byte stream;
5. authenticated wire handshakes and encrypted frames;
6. the bounded application bridge and browser adapter.

Cryptographic channels do not discover destinations, resolve DNS names, choose
alternate transports, or create direct client-to-host connections.

## Identity and address

`ServiceIdentity` owns an Ed25519 private key. The canonical service identifier
is a domain-separated SHA-256 digest of the raw public key, encoded as lower-case
Base32. IP addresses are not service identities.

A local alias such as `test.granger` maps to a canonical identity address. It is
a convenience label, not a globally registered or self-authenticating name.

## Descriptor v2

A v2 `ServiceDescriptor` contains:

- descriptor and exact Granger wire versions;
- canonical service ID and Ed25519 public key;
- supported transport identifiers;
- a logical rendezvous ID;
- issue and expiry times;
- bounded display metadata;
- an Ed25519 signature over the canonical document.

It deliberately contains no host address, host port, relay address, HTTP URL,
or operator metadata. Verification checks key/address binding, signature, exact
schema, supported versions and transports, clock bounds, expiry, lifetime, and
metadata limits.

New remote descriptors select wire 3. Signed wire 2 descriptors remain readable
for explicit compatibility; there is no automatic version fallback. Descriptor
version 1 remains restricted to the numeric-loopback compatibility profile.

## Discovery layer

`DiscoveryProvider` has two independent responsibilities:

1. resolve a `.granger` name to a signed descriptor;
2. resolve a descriptor's logical rendezvous ID to transport bootstrap data.

`LocalResolver` stores descriptors, local aliases, and rendezvous bootstrap
entries in separate files. It accepts only `.granger` names, never invokes DNS,
and has no alternate network lookup.

Separating discovery interfaces permits a future discovery mechanism without
changing identity verification or the encrypted protocol. No distributed
discovery system is implemented now.

## Transport and rendezvous

`GrangerTransport.connect(destination_id)` accepts only a canonical
cryptographic service ID. It returns a `TransportSession` with a 128-bit session
ID and `send`, `receive`, and `close` operations.

`RendezvousClientTransport` connects only to a separately configured numeric
relay endpoint. `RendezvousHostTransport` also creates an outbound relay
connection. No remote descriptor carries a service endpoint, and no client code
has a destination from which it could construct a direct host connection.

The service registers its identity with a fresh signed nonce. The client sends
the canonical destination and a fresh session ID. The relay verifies
registration identity and replay state, pairs waiting connections, then forwards
bytes without parsing the end-to-end protocol. Both peers expose their network
addresses to the relay but not to one another.

## Wire 3 secure channel

Wire 3 authenticates a full transcript containing:

- protocol version and suite offer;
- rendezvous session ID and freshness timestamp;
- ephemeral X25519 and ML-KEM-768 material;
- service Ed25519 identity;
- client and server random nonces;
- selected frame limit, rekey interval, and session lifetime.

The service signs the transcript with the descriptor identity. Hybrid
ML-KEM-768 and X25519 shared secrets feed a transcript-bound HKDF-SHA256 key
schedule. Client and server HMAC Finished messages confirm that both sides
derived the same secrets before application data is sent.

The schedule derives independent secrets for:

- client-to-service data;
- service-to-client data;
- client-to-service control;
- service-to-client control;
- client and server Finished confirmation;
- a reserved exporter.

ChaCha20-Poly1305 frames authenticate the suite, session, channel binding,
direction, kind, flags, key epoch, ciphertext size, and exact sequence number.
Control and data use separate ratchets while sharing one strict sequence space
per direction.

## Key lifecycle

Every wire 3 connection generates fresh X25519 and ML-KEM material and fresh
nonces. Long-term Ed25519 identity keys authenticate but do not enter the shared
secret. Compromise of an identity key alone therefore does not reconstruct old
session keys.

Traffic keys rotate after the negotiated number of frames, `2^20` by default.
Each purpose and direction has a one-way HKDF ratchet. The implementation drops
the previous ratchet state on a best-effort basis. Sessions expire after 15
minutes by default and at most one hour, forcing a new authenticated handshake.

This lifecycle provides forward-secret session establishment and backward
protection for ratchet epochs subject to endpoint memory handling. It does not
provide post-compromise security: compromise of live endpoint state can expose
the current epoch and allow derivation of later epochs until a new handshake.

## Multi-hop readiness

The channel abstraction can be instantiated independently for adjacent peers in
a future route:

```text
client <=> relay A <=> relay B <=> host
```

Each arrow must have a unique session ID, fresh hybrid handshake, independent
identity decision, counters, nonces, keys, ratchets, and lifetime. A single
end-to-end or hop key must never be copied along the chain. The reserved
exporter is not a substitute for independent hop handshakes.

This is structural readiness only. Multi-hop route construction, onion
encryption, relay identities, path selection, and route failure handling are
not implemented.

## Service bridge

The service host is the only process that can reach the local application. Its
`LoopbackHttpBridge` permits only numeric-loopback HTTP, GET/HEAD, safe
origin-form paths, bounded bodies, and selected headers. It never opens a public
HTTP listener.

Wire 3 sends response metadata in a control frame and the exact response body
in a data frame. This avoids Base64 expansion and enforces the control/data key
boundary.

## Data visibility

The client knows the signed descriptor, service identity, configured relay,
request, response, and its own timing. It sees the relay as its network peer,
not the service host.

The host knows its identity, relay, decrypted request, and local application
response. It sees the relay as its network peer, not the client.

The relay knows both peers' source network addresses, service ID, host public
key, registration nonce, session ID, timestamps, connection timing and
duration, handshake version, frame kinds, frame sizes, sequence and epoch
values, direction, and failure patterns. It cannot decrypt valid application
frames or authenticate as the service under the current assumptions.

The local discovery store knows descriptors, aliases, and relay bootstrap data
installed by that user. It performs no network query.

No padding, uniform frame sizing, timing normalization, cover traffic, or
artificial delay is enabled. Those are future traffic-analysis work, not
properties of the current cryptographic channel.

## Browser adapter

Qt WebEngine receives each service as a host-based custom URL origin. A
browser-owned child process connects the C++ scheme handler to `LocalResolver`
and `GrangerClient` over anonymous stdin/stdout pipes. It opens no IPC listener,
accepts no arbitrary URL or host, and is terminated with the browser. See
`BrowserIntegration.md` for URL, origin, and cross-network policy details.

## Failure behavior

Malformed names, unknown descriptors, invalid signatures, expired descriptors,
missing relay bootstrap, unsupported transports or suites, failed pairing,
mismatched identities, stale or modified handshakes, failed key confirmation,
expired sessions, and invalid or replayed frames terminate the request and
poison the affected secure channel. There is no DNS, direct-host, clearnet HTTP,
lower-version retry, or alternate transport fallback.
