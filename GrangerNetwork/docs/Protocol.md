# Protocol

## Status

This document describes experimental protocol version 1. It is not a stable
wire standard. Implementations must reject unknown versions and malformed data.

All multi-byte integers are unsigned and encoded in network byte order.

## Service descriptor

The JSON descriptor contains exactly these fields:

```json
{
  "identityKey": "base64url Ed25519 public key",
  "serviceId": "52-character lower-case Base32 identifier",
  "signature": "base64url Ed25519 signature",
  "transport": {
    "host": "127.0.0.1",
    "port": 7777,
    "type": "loopback-tcp"
  },
  "version": 1
}
```

The signature covers the canonical JSON representation without `signature`,
prefixed by:

```text
granger-network-v0.1/descriptor NUL
```

Base64url fields are unpadded and canonical. Extra fields are rejected.

## Handshake

### ClientHello (69 bytes)

```text
magic              4 bytes   "GRN1"
version            1 byte    0x01
X25519 public key 32 bytes
client nonce      32 bytes
```

### ServerHello (133 bytes)

```text
magic                 4 bytes   "GRN1"
version               1 byte    0x01
X25519 public key    32 bytes
Ed25519 public key   32 bytes
Ed25519 signature    64 bytes
```

The service signs:

```text
"granger-network-v0.1/server-auth\0" || ClientHello || ServerHelloBody
```

Before sending application data, the client verifies both the signature and
the exact equality of the service identity with the identity in the resolved
descriptor. A valid signature from a different service is rejected.

Both peers derive the X25519 shared secret. HKDF-SHA256 produces 64 bytes split
into independent client-to-service and service-to-client ChaCha20-Poly1305 keys.
The HKDF salt and info bind the client nonce and SHA-256 transcript hash to the
domain-separated protocol context.

## Encrypted frames

Each frame is:

```text
ciphertext length   uint32
sequence number     uint64
ciphertext + tag    variable
```

The 96-bit AEAD nonce is a four-byte direction tag (`C2S1` or `S2C1`) followed
by the 64-bit sequence number. Associated data contains a protocol domain,
direction tag, and complete frame header.

Sequence numbers start at zero and must arrive in order. Reuse, skipping,
reordering, a modified header, or a modified ciphertext causes authentication
failure. The plaintext size limit is 4 MiB per frame.

## Application messages

Messages are UTF-8 JSON objects inside encrypted frames. Version 0.1 supports a
single request per connection.

Request:

```json
{
  "headers": {"accept": "text/html"},
  "method": "GET",
  "path": "/",
  "type": "request"
}
```

Response:

```json
{
  "body": "base64 response bytes",
  "headers": {"content-type": "text/html"},
  "reason": "OK",
  "status": 200,
  "type": "response"
}
```

Duplicate JSON fields and unexpected top-level fields are rejected. The bridge
permits only GET and HEAD, a safe origin-form path, selected headers, and a 2 MiB
response body.

## Cryptographic properties and limits

The handshake authenticates the service and gives the channel forward secrecy
from ephemeral X25519 keys. ChaCha20-Poly1305 provides payload confidentiality
and integrity. There is no client authentication, identity hiding, padding,
resumption, multiplexing, formal protocol proof, or denial-of-service defense
in v0.1.
