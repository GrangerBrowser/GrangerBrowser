# Architecture

## Scope

Granger Network v0.1 is a standalone prototype. It has no dependency on the
Granger Browser executable and does not modify Qt WebEngine, Tor, I2P, browser
routing, or the browser's fail-closed policy.

The prototype demonstrates four boundaries:

```text
Local application page
        |
Loopback HTTP bridge (service side only)
        |
Authenticated Granger protocol
        |
ClientTransport abstraction
        |
Numeric loopback TCP in v0.1
```

## Modules

### Identity and address

`ServiceIdentity` owns an Ed25519 private key. The canonical service identifier
is a domain-separated SHA-256 digest of the raw Ed25519 public key, encoded as
lower-case Base32. A client can therefore verify that a descriptor's public key
belongs to its canonical address.

### Signed descriptor

A `ServiceDescriptor` contains the service identifier, Ed25519 public key,
transport type, numeric loopback endpoint, and version. The service identity
signs the canonical descriptor document. A modified endpoint or identity makes
verification fail.

Descriptors are exchanged explicitly in v0.1. There is no discovery network,
global naming authority, or central domain table.

### Resolver

`LocalResolver` is a file-backed local trust store. It resolves either:

- a canonical identity address; or
- a user-installed local alias such as `test.granger`.

The resolver accepts only the `.granger` namespace. Unknown and non-Granger
names fail before transport connection. It never invokes DNS and never delegates
to an operating-system resolver.

Aliases are local labels, not globally unique identities. The resolver maps an
alias to a canonical address and then verifies the signed descriptor.

### Protocol

The client and service perform an ephemeral X25519 handshake. The service signs
the transcript with its Ed25519 identity. The client compares that identity with
the already-verified descriptor before sending an application request.

HKDF-SHA256 derives independent client-to-service and service-to-client keys.
Application frames use ChaCha20-Poly1305 with monotonic sequence numbers and
authenticated frame headers.

### Transport

`ClientTransport` and `ServerTransport` separate protocol code from connection
establishment. The v0.1 implementations are `LoopbackTcpTransport` and
`LoopbackTcpServerTransport`. Both client endpoints and service listeners
require numeric loopback IP addresses. The implementation constructs AF_INET or
AF_INET6 sockets directly and does not call hostname resolution APIs.

A future transport must preserve the same fail-closed contract. Adding a remote
transport is not equivalent to changing the endpoint validation in the current
loopback class.

### Service bridge

`LoopbackHttpBridge` translates an authenticated encrypted request into one
HTTP/1.1 GET or HEAD request to a numeric loopback application. It rejects
hostnames, non-loopback addresses, redirects as client behavior, unsafe paths,
unsupported methods, oversized bodies, and unapproved headers.

The bridge leg is plaintext HTTP on the same host. The Granger protocol leg
between client and service host is encrypted.

## Data visibility

The client knows the local descriptor, service public identity, loopback
transport endpoint, response status, selected headers, and page body.

The service host sees a loopback peer, request path, selected request headers,
and the local application's response. The current request does not transmit the
alias used by the client.

A local observer can see loopback connection timing, sizes, protocol version,
ephemeral keys, nonce, and service public identity. Application payloads are
encrypted, but v0.1 has no padding or traffic-shape protection.

## Failure behavior

Malformed names, missing descriptors, invalid signatures, mismatched identities,
unsupported transports, non-loopback endpoints, failed handshakes, and invalid
frames all terminate the operation. There is no DNS, clearnet, or alternate
transport fallback.
