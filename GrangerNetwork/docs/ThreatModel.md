# Threat Model

## Security goals for v0.2

- Bind a canonical `.granger` address to an Ed25519 service identity.
- Detect modified, expired, substituted, or incorrectly signed descriptors.
- Keep service network locations out of addresses and descriptors.
- Prevent a direct client-to-host connection path in the remote transport.
- Authenticate the host before sending an application request.
- Encrypt and authenticate application messages end to end across the relay.
- Reject stale handshakes, replayed rendezvous tokens, and replayed frames.
- Resolve `.granger` locally without DNS or clearnet fallback.
- Keep the host's application upstream on numeric loopback.

These are identity, confidentiality, integrity, and routing-architecture goals.
They are not an anonymity claim.

## Trust boundaries

### Client

The client trusts its local descriptor and relay-bootstrap files, the
cryptographic implementation, and its host operating system. It learns the
service identity, safe descriptor metadata, relay endpoint, decrypted response,
and traffic timing from its own connection. It does not learn the host peer IP
from the protocol.

### Service host

The host trusts its private key storage, local application, cryptographic
implementation, and operating system. It learns the relay endpoint, decrypted
request, selected request headers, and local response. It does not learn the
client peer IP from the protocol.

### Rendezvous relay

The relay is not trusted with application content or service authentication. It
does learn:

- source network addresses of both TCP peers;
- service ID and host public key;
- registration nonce, session ID, and timestamps;
- handshake bytes;
- connection start, duration, direction, sizes, and failure patterns.

The relay can therefore correlate a client with a host for a session. v0.2 does
not hide this metadata.

### Discovery store

The local discovery implementation sees only descriptors, aliases, and relay
bootstrap entries installed by the user. It makes no network query. A future
distributed discovery system would introduce new observers and requires a new
threat analysis.

## Considered attackers

### Malicious or compromised relay

A relay can drop, delay, reorder, truncate, or replay traffic; report that no
host exists; pair a client with the wrong connection; and analyze metadata. It
cannot make a wrong service pass the client's Ed25519 handshake check or decrypt
authenticated frames without the service private key.

A captured valid host registration can be raced, but a duplicate nonce is
rejected and the attacker still cannot complete the service handshake. This
remains an availability risk.

### Host identity substitution

A registration whose public key does not derive the claimed service ID or whose
signature is wrong is rejected by the relay. Even if relay validation is
bypassed, the client independently compares the handshake identity with the
signed descriptor before sending its request.

### Descriptor or alias modification

Changing any signed v2 field invalidates the signature. Expired descriptors are
rejected. A local alias is not self-authenticating: filesystem compromise can
map `test.granger` to another valid canonical identity. Users needing stable
identity semantics must compare the canonical address through a trusted channel.

### Replay attacker

Relay registration nonces and client session IDs are single-use within a cache
window. Client timestamps and descriptor expiry constrain stale material.
End-to-end frame sequence numbers and session-bound AEAD associated data reject
repeated, skipped, reordered, modified, and cross-session frames.

### Malicious service

A correctly identified service controls its content. Identity authentication
does not make HTML safe. The standalone client writes bytes; v0.2 provides no
browser sandbox, origin model, or content sanitizer.

### Network observer

A local or path observer sees TCP endpoints, relay use, packet timing, sizes,
and encrypted protocol bytes. A global observer can correlate host and client
connections at the relay. There is no onion routing, padding, cover traffic, or
multi-relay path in v0.2.

## Leak and fallback analysis

The resolver parses `.granger` names locally. Relay bootstrap accepts only
numeric IP addresses and constructs AF_INET or AF_INET6 sockets directly. A v2
descriptor contains no service endpoint. The client transport has only one
connection target: its configured relay. The host also connects outward to that
relay, while its HTTP bridge accepts only a numeric loopback upstream.

Any missing descriptor, missing bootstrap entry, invalid signature, unavailable
relay, missing host, identity mismatch, stale handshake, or invalid frame ends
the request. There is no system DNS, ordinary HTTP URL, direct service IP, or
alternate transport fallback.

Automated tests replace common Python hostname-resolution APIs with failing
stubs and record every client `connect()` destination. A relay capture is
checked for known HTML and HTTP plaintext markers. These tests are regression
coverage, not packet-capture proof for every operating system or network stack.

## Remaining attacks and limitations

- Client/host correlation by the relay or a global observer.
- Relay enumeration of registered service identities and availability patterns.
- Traffic fingerprinting from sizes, direction, timing, and duration.
- Denial of service, registration flooding, connection exhaustion, and relay
  censorship.
- Relay bootstrap substitution and downgrade denial; relays are not yet
  authenticated as infrastructure identities.
- No client authentication, authorization, revocation, key rotation, recovery,
  relay federation, route selection, persistence, padding, or cover traffic.
- No protection after local administrator, process, registry, or private-key
  compromise.
- No independent protocol review, formal proof, or production hardening.

## Fail-closed rule

Every discovery, descriptor, transport, pairing, identity, freshness, replay,
frame, and upstream-policy failure terminates the request. Future transports
must preserve the absence of DNS, clearnet HTTP, direct-host, and alternate-route
fallbacks.
