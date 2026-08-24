# Protocol

## Status

This document describes experimental descriptor version 2, rendezvous control
version 1, and Granger wire protocol version 2. They are not stable public
standards. Implementations reject unknown versions, extra fields, duplicate JSON
keys, invalid encodings, and unsupported transports.

All multi-byte wire integers are unsigned and use network byte order. JSON
signatures cover canonical UTF-8 JSON with sorted keys and no insignificant
whitespace. Binary JSON values use unpadded canonical Base64url.

## Service descriptor v2

```json
{
  "expiresAt": 1700086400,
  "identityKey": "base64url Ed25519 public key",
  "issuedAt": 1700000000,
  "metadata": {
    "contentType": "text/html",
    "title": "Example service"
  },
  "protocolVersion": 2,
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
is expired, issued more than 120 seconds in the future, has an unsupported
field, or does not bind `serviceId` to `identityKey`. Only bounded `title` and
`contentType` display metadata is accepted. No service or relay IP address is
part of the descriptor.

Descriptor v1 remains available for the local compatibility transport and uses
its original signature domain and schema.

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

## Granger handshake v2

### ClientHello (93 bytes)

```text
magic                4 bytes   "GRN2"
version              1 byte    0x02
session ID          16 bytes
Unix timestamp       8 bytes
X25519 public key   32 bytes
client nonce        32 bytes
```

### ServerHello (149 bytes)

```text
magic                   4 bytes   "GRN2"
version                 1 byte    0x02
session ID             16 bytes
X25519 public key      32 bytes
Ed25519 public key     32 bytes
Ed25519 signature      64 bytes
```

The service rejects a session ID different from the relay pairing and a client
timestamp outside 120 seconds. It signs:

```text
"granger-network-v0.2/server-auth\0" || ClientHello || ServerHelloBody
```

The client verifies the returned session ID, transcript signature, and exact
equality of the service public key with the already verified descriptor.

Both peers derive an ephemeral X25519 shared secret. HKDF-SHA256 produces 64
bytes split into client-to-service and service-to-client ChaCha20-Poly1305 keys.
The HKDF salt and info bind the session ID, client nonce, protocol domain, and
SHA-256 handshake transcript.

## Encrypted frames

```text
ciphertext length   uint32
sequence number     uint64
ciphertext + tag    variable
```

The 96-bit AEAD nonce is a four-byte direction tag (`C2S2` or `S2C2`) followed
by the 64-bit sequence number. Associated data contains the v0.2 frame domain,
session ID, direction, and complete frame header.

Sequence numbers start at zero and must arrive exactly in order. Reuse,
skipping, reordering, a modified header, a modified ciphertext, or replay into a
different session fails. Plaintext is limited to 4 MiB per frame.

## Application messages

Application objects retain the v0.1 request/response schema and remain inside
encrypted frames. One GET or HEAD request is supported per session. The service
bridge filters request and response headers and limits a response body to 2 MiB.

## Security limits

The protocol authenticates the service and protects application content across
the relay. It does not authenticate clients or relays, hide the service identity
from the relay, pad messages, multiplex streams, support resumption, or provide
a formal cryptographic proof. A malicious relay can observe metadata, deny or
delay service, and correlate both TCP peers.
