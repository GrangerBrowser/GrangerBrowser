# Protocol

## Status

This document describes experimental service descriptor version 2,
rendezvous control version 1, and Granger wire protocol version 3. These are
not stable public standards and have not received an independent security
review. Implementations reject unknown versions, extra descriptor fields,
duplicate JSON keys, invalid encodings, unsupported suites, and invalid
negotiated parameters.

All multi-byte wire integers are unsigned and use network byte order. JSON
signatures cover canonical UTF-8 JSON with sorted keys and no insignificant
whitespace. Binary JSON values use unpadded canonical Base64url.

## Service descriptor v2

New remote descriptors select wire protocol 3:

```json
{
  "expiresAt": 1700086400,
  "identityKey": "base64url Ed25519 public key",
  "issuedAt": 1700000000,
  "metadata": {
    "contentType": "text/html",
    "title": "Example service"
  },
  "protocolVersion": 3,
  "rendezvousId": "example-relay",
  "serviceId": "52-character lower-case Base32 identifier",
  "signature": "base64url Ed25519 signature",
  "transports": ["rendezvous-v1"],
  "version": 2
}
```

The signature covers the document without `signature`, prefixed by:

```text
granger-network-v0.2/descriptor NUL
```

The maximum descriptor lifetime is seven days. A descriptor is rejected if it
is expired, issued more than 120 seconds in the future, contains an unsupported
field, or does not bind `serviceId` to `identityKey`. Only bounded `title` and
`contentType` display metadata is accepted. No service or relay IP address is
part of the descriptor.

`protocolVersion` is signed and determines the exact wire protocol. There is no
in-band fallback from wire 3 to wire 2. A modified version invalidates the
descriptor signature. Wire 2 descriptors remain readable only for explicit
compatibility with descriptors created by the previous prototype.

Descriptor version 1 remains available for the numeric-loopback compatibility
transport and uses its original signature domain and schema.

## Rendezvous control

Each control object is prefixed by a 32-bit length and is limited to 16 KiB.
Control version 1 supports registration and connect requests.

### Host registration

```json
{
  "identityKey": "base64url Ed25519 public key",
  "nonce": "base64url 16 random bytes",
  "serviceId": "canonical service identifier",
  "signature": "base64url Ed25519 signature",
  "timestamp": 1700000000,
  "type": "register",
  "version": 1
}
```

The signature covers the object without `signature`, prefixed by:

```text
granger-network-v0.2/rendezvous-registration NUL
```

The relay verifies timestamp freshness, nonce uniqueness, signature, and the
public-key-derived service ID. A valid registration receives:

```json
{"type":"registered","version":1}
```

### Client connect

```json
{
  "serviceId": "canonical service identifier",
  "sessionId": "base64url 16 random bytes",
  "timestamp": 1700000000,
  "type": "connect",
  "version": 1
}
```

The relay checks timestamp freshness and session-ID uniqueness. When a verified
host is waiting, both peers receive the same pairing object:

```json
{"sessionId":"base64url 16 bytes","type":"paired","version":1}
```

The connection becomes an opaque bidirectional byte stream immediately after
that object. If no host is waiting, the relay returns `NO_HOST`; clients may
retry only the same configured relay with a new random session ID. There is no
direct-host or DNS fallback.

Relay freshness windows are 120 seconds. Used nonces and session IDs remain in
the replay cache for longer than two full freshness windows.

## Wire protocol 3

### Cryptographic suite

Wire 3 currently defines one suite:

| ID | Key exchange | Service authentication | KDF | Frames |
| --- | --- | --- | --- | --- |
| 1 | ephemeral X25519 + ephemeral ML-KEM-768 | Ed25519 | HKDF-SHA256 | ChaCha20-Poly1305 |

Suite IDs are public algorithm-agility identifiers, not a random or secret
cipher choice. The client offers a 32-bit suite mask and the server selects one
offered, locally allowed suite. The offer and selection are authenticated by
the service signature and included in the key schedule. An empty intersection
terminates the handshake.

The implementation uses the ML-KEM-768 primitive supplied by Python
`cryptography` 47 or newer. It does not implement ML-KEM, X25519, Ed25519,
HKDF, or ChaCha20-Poly1305 itself.

### ClientHello

`ClientHello` is exactly 1,293 bytes:

```text
magic                         4 bytes   "GRN3"
version                       1 byte    0x03
supported suite mask          4 bytes
session ID                   16 bytes
Unix timestamp                8 bytes
maximum plaintext frame       4 bytes
rekey interval in frames      4 bytes
maximum session age           4 bytes
X25519 public key            32 bytes
ML-KEM-768 public key      1,184 bytes
client nonce                 32 bytes
```

The session ID must be the 128-bit value assigned by the rendezvous. The
timestamp must be within the server's 120-second freshness window. The default
offers are a 4 MiB maximum plaintext frame, a `2^20` frame rekey interval, and
a 900-second session lifetime.

### ServerHello

The signed body is 1,219 bytes and is followed by a 64-byte Ed25519 signature,
for a total of 1,283 bytes:

```text
magic                         4 bytes   "GRN3"
version                       1 byte    0x03
selected suite                2 bytes
session ID                   16 bytes
selected maximum frame        4 bytes
selected rekey interval       4 bytes
selected session age          4 bytes
X25519 public key            32 bytes
ML-KEM-768 ciphertext     1,088 bytes
Ed25519 identity key         32 bytes
server nonce                 32 bytes
Ed25519 signature            64 bytes
```

The server selects the minimum of each valid local and client limit. A client
rejects values larger than its authenticated offer. The selected identity key
must exactly equal the key in the already verified descriptor.

The service signature covers every ClientHello field and every unsigned
ServerHello field:

```text
"granger-network-v0.3/server-auth\0"
|| ClientHello
|| ServerHelloBody
```

Consequently, changing the version, session ID, timestamp, suite offer,
selected suite, ephemeral keys, nonces, identity, or session parameters causes
signature verification or key confirmation to fail.

### Hybrid shared secret

The client generates an ephemeral ML-KEM-768 key pair and an ephemeral X25519
key pair. The service encapsulates to the ML-KEM public key and generates its
own ephemeral X25519 key pair. Both sides construct:

```text
hybrid_secret = mlkem_shared_secret || x25519_shared_secret
```

An all-zero X25519 result and invalid ML-KEM material are rejected. The two
32-byte shared secrets are not used directly as traffic keys.

This ordering follows the X25519MLKEM768 shared-secret convention, but Granger
wire 3 is not TLS and does not claim the security analysis of the TLS hybrid
group. The intended benefit is resistance to passive store-now/decrypt-later
collection if at least one component and the combiner remain secure. Ed25519
authentication is not post-quantum, so wire 3 is not a fully post-quantum
authenticated protocol.

### Transcript and key schedule

The transcript is the complete `ClientHello || ServerHello`, including the
service signature. HKDF-SHA256 first derives a transcript-bound root from:

- the 64-byte hybrid shared secret;
- the session ID and both random nonces;
- SHA-256 of the transcript;
- the selected suite, frame limit, rekey interval, and session lifetime;
- domain-separated salt and info strings.

Separate HKDF-Expand labels derive seven 32-byte values:

```text
client-data
server-data
client-control
server-control
client-finished
server-finished
exporter
```

Direction and purpose therefore never share an AEAD key. `exporter` is reserved
for a future explicitly specified extension and is not exposed as a hop key or
application API.

### Key confirmation

After deriving secrets, the client sends a 32-byte HMAC-SHA256 Finished value
over the transcript hash. The service verifies it and replies with its own
32-byte Finished value, additionally binding the client's Finished value. No
application frame is accepted until both sides prove possession of the same
hybrid secret and authenticated parameters.

## Encrypted frames

Wire 3 frame headers are 22 bytes:

```text
kind                  1 byte    1 = control, 2 = data
flags                 1 byte    must be zero
key epoch             8 bytes
ciphertext length     4 bytes
sequence number       8 bytes
ciphertext + tag      variable
```

The 96-bit AEAD nonce is a four-byte direction tag (`C2S3` or `S2C3`) followed
by the 64-bit sequence number. Associated data contains the wire 3 frame domain,
suite ID, rendezvous session ID, channel binding, direction, and complete frame
header.

One sequence space is shared by control and data frames in each direction.
Sequence numbers start at zero and must arrive exactly in order. Reuse,
skipping, reordering, an incorrect epoch, an unknown kind or flag, a modified
header, a modified ciphertext, replay into another session, and frames larger
than the negotiated limit terminate the channel. Sequence exhaustion also
terminates the channel before nonce reuse.

Control and data frames use independent traffic-key ratchets. The epoch is:

```text
epoch = sequence_number / negotiated_rekey_interval
```

At an epoch boundary, HKDF-Expand derives the next one-way ratchet secret and
then a new purpose- and direction-bound AEAD key. The implementation overwrites
the previous Python-managed ratchet secret on a best-effort basis and does not
retain an API for old epochs. Strict frame ordering means a receiver never needs
an old key. Python and the cryptographic backend may still retain internal
copies outside application control.

A session also expires against a monotonic local clock after the negotiated
lifetime, 15 minutes by default and at most one hour. Rekeying limits traffic
under one AEAD key; it does not replace a fresh authenticated handshake and
does not recover security after an active endpoint compromise.

## Application messages

Requests remain bounded JSON control frames. Wire 3 responses separate bounded
JSON metadata from the response body:

1. a control frame carries status, reason, headers, and exact `bodyLength`;
2. a data frame carries exactly that many body bytes.

This avoids Base64 expansion and keeps control and application data on separate
keys. One GET or HEAD request is supported per session. The service bridge
filters request and response headers and limits a response body to 2 MiB.

## Legacy compatibility and downgrade rules

Wire 1 remains restricted to the numeric-loopback compatibility transport.
Wire 2 remains implemented so an explicitly signed old remote descriptor can
be read. Wire 2 is classical X25519 only and has no suite negotiation, Finished
messages, control/data key separation, traffic-key ratchet, or session-age
limit.

The implementation never negotiates a wire version on an unauthenticated
connection and never silently retries a lower version. A descriptor selects one
exact version. Replaying a still-valid historical descriptor is not prevented
by a global transparency log or monotonic version store; short descriptor
lifetimes and service-side version agreement limit, but do not eliminate, that
rollback class.

## Multi-hop compatibility

Wire 3 provides a session abstraction suitable for one authenticated channel
per future hop. A future multi-hop route must run an independent handshake for
every adjacent peer with a unique session ID, fresh X25519 and ML-KEM material,
separate transcript, and separate traffic keys. Keys, nonces, counters, ratchet
state, Finished values, and exporter material must never be copied across hops.

No multi-hop routing, onion encryption, relay identity system, or route
construction protocol is implemented by this change.

## Metadata and security limits

Encryption does not hide:

- transport endpoints and connection timing;
- the fixed, recognizable wire 3 handshake sizes;
- service and rendezvous identifiers exposed by rendezvous control;
- frame kind, ciphertext length, sequence, epoch, direction, count, and timing;
- total session duration and failure patterns.

Wire 3 deliberately does not enable padding, uniform frame sizes, timing
normalization, cover traffic, or artificial latency. Those mechanisms require
separate traffic-analysis design and performance testing. The protocol does not
authenticate clients or relays, hide the service identity from the relay,
support resumption or multiplexing, or provide a formal security proof.

## Standards references

- [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final),
  Module-Lattice-Based Key-Encapsulation Mechanism Standard.
- [RFC 7748](https://datatracker.ietf.org/doc/html/rfc7748), Elliptic Curves for
  Security.
- [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869), HMAC-based
  Extract-and-Expand Key Derivation Function.
- [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439), ChaCha20 and
  Poly1305 for IETF Protocols.
- [RFC 10024](https://datatracker.ietf.org/doc/html/rfc10024), X25519MLKEM768
  key agreement for TLS 1.3.
- [Python cryptography ML-KEM API](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/mlkem/).
