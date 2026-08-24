# Threat Model

## Security goals

- Bind a canonical `.granger` address to an Ed25519 service identity.
- Detect modified, expired, substituted, or incorrectly signed descriptors.
- Keep service network locations out of addresses and descriptors.
- Prevent direct client-to-host, DNS, clearnet, and alternate-route fallback.
- Authenticate the host and handshake parameters before application traffic.
- Encrypt and authenticate control and data independently across the relay.
- Combine ephemeral X25519 and ML-KEM-768 for wire 3 session establishment.
- Reject downgrade attempts, stale handshakes, replayed rendezvous tokens,
  replayed frames, malformed frames, nonce exhaustion, and expired sessions.
- Rotate traffic keys without retaining usable old-epoch state.

These are identity, confidentiality, integrity, and routing-architecture goals.
They are not anonymity or unlinkability claims.

## Assumptions

The design relies on the security and correct use of Ed25519, X25519,
ML-KEM-768, HKDF-SHA256, HMAC-SHA256, ChaCha20-Poly1305, the operating system
random source, and the Python `cryptography` implementation. It also assumes
the client obtains the intended signed descriptor through an authenticated
local or out-of-band process.

The protocol has not received an independent cryptographic audit or formal
proof. The hybrid composition is domain-separated and transcript-bound, but is
not claimed to inherit the complete proof of a different protocol such as TLS.

## Trust boundaries

### Client

The client trusts its local descriptor and relay-bootstrap files, cryptographic
implementation, browser adapter, and operating system. It learns the service
identity, descriptor metadata, relay endpoint, decrypted response, and traffic
timing. It does not learn the host peer address from Granger Network.

### Service host

The host trusts private-key storage, its local application, cryptographic
implementation, and operating system. It learns the relay endpoint, decrypted
request, selected headers, and local response. It does not learn the client peer
address from Granger Network.

### Rendezvous relay

The relay is not trusted with application content or service authentication. It
does learn:

- source network addresses of both TCP peers;
- service ID and host public key;
- registration nonce, session ID, and timestamps;
- recognizable handshake size and protocol version;
- frame kind, size, sequence, epoch, direction, count, and timing;
- connection start, duration, and failure patterns.

The relay can correlate the client and host for a session. The current protocol
does not hide that metadata.

### Discovery store

The local discovery implementation sees descriptors, aliases, and relay
bootstrap entries installed by the user. It makes no network query. A future
distributed discovery system would introduce new observers and needs a separate
threat analysis.

## Considered attackers

### Malicious or compromised relay

A relay can drop, delay, reorder, truncate, replay, or selectively forward
traffic; claim no host exists; pair the client with the wrong connection; and
analyze metadata. It cannot make a different service identity pass descriptor
and handshake verification or construct valid encrypted frames without the
negotiated keys.

A captured host registration can be raced, but duplicate nonces are rejected
and the attacker still cannot complete the service handshake. Availability
attacks remain possible.

### Host identity substitution

A registration whose public key does not derive the claimed service ID or whose
signature is wrong is rejected by the relay. Even if relay validation is
bypassed, the client independently requires exact equality between the signed
descriptor identity and the signed handshake identity before key confirmation.

### Descriptor, alias, and version modification

Changing any signed descriptor field, including `protocolVersion`, invalidates
the signature. Wire 3 authenticates both the suite offer and selected suite, so
an active relay cannot remove the hybrid suite or select an unoffered suite.
There is no automatic fallback to wire 2 after any wire 3 failure.

A local alias is not self-authenticating: filesystem compromise can map
`test.granger` to another valid identity. A previously signed wire 2 descriptor
can also be replayed while it remains valid because the prototype has no global
transparency log or monotonic descriptor-version store. Service-side exact
version selection prevents that descriptor from silently downgrading a host
currently serving wire 3, but descriptor rollback remains a documented
compatibility limitation.

### Handshake modification

The Ed25519 signature covers the complete client hello and unsigned server
hello. The HKDF schedule also binds the transcript and selected parameters.
Client and server Finished values prove possession of the derived hybrid keys.
Modification of a version, identity, session, timestamp, suite, key, nonce, or
limit therefore terminates the handshake before application traffic.

### Replay and malformed-frame attacker

Rendezvous registration nonces and session IDs are single-use within a cache
window. Handshake timestamps and descriptor expiry constrain stale material.
End-to-end frame sequence numbers must be exact and are bound, with the key
epoch and full header, into AEAD associated data.

Duplicate, skipped, reordered, old-session, wrong-kind, unknown-flag,
wrong-epoch, modified, unauthenticated, and oversized frames terminate and
poison the channel. Sequence exhaustion fails before a nonce can be reused.

### Network observer

A local or path observer sees TCP endpoints, relay use, packet timing, sizes,
and encrypted protocol bytes. A global observer can correlate host and client
connections at the relay. Fixed ML-KEM handshake sizes make wire 3 recognizable.
There is no padding, cover traffic, onion routing, or multi-relay path.

### Malicious service

A correctly identified service controls its content. Identity authentication
does not make HTML safe. In the development browser integration, Qt WebEngine
renders content in its Chromium renderer sandbox and assigns one origin per
`.granger` host. A request interceptor blocks embedded cross-service and
cross-network requests. This does not remove browser-engine vulnerabilities.

## Post-quantum scope

Wire 3 combines ephemeral ML-KEM-768 and ephemeral X25519 before HKDF. Its
intended benefit is protection of recorded session traffic against a future
passive attacker if either key-exchange component and the combiner remain
secure. This improves post-quantum migration readiness and store-now/decrypt-
later resistance relative to classical-only wire 2.

Service authentication remains Ed25519 and is not post-quantum. A future
cryptographically relevant quantum computer able to forge Ed25519 could
actively impersonate a service during a new handshake. Wire 3 must therefore
not be described as fully post-quantum secure. Migrating identity signatures
requires a separately reviewed descriptor and address-transition design.

## Key compromise and forward secrecy

Every wire 3 session uses fresh X25519 and ML-KEM material. The long-term
Ed25519 key signs the transcript but is not input to the shared secret.
Compromise of only that identity key after a completed session does not reveal
the recorded session keys.

Traffic-key ratchets erase prior Python-managed secrets on a best-effort basis.
Compromise of a current ratchet state should not reveal earlier epochs, but it
does reveal the current state and permits derivation of future epochs until a
fresh handshake. This is forward secrecy and backward epoch protection, not
post-compromise security.

Python object copies, allocator behavior, process dumps, swap, and native
cryptographic objects are outside reliable application-level zeroization.
Administrator, kernel, debugger, or live process compromise can expose
plaintext and current keys.

## Multi-hop assumptions

The secure-channel API can support independent sessions between future adjacent
hops. Each hop must authenticate independently and use fresh ephemeral keys,
session IDs, nonces, counters, ratchets, and lifetimes. Reusing an end-to-end
key, exporter, nonce space, or ratchet across relays is forbidden.

No multi-hop routing or onion encryption exists today. Adding it changes which
nodes see identities, plaintext, and metadata and requires a new threat model.

## Leak and fallback analysis

The resolver parses `.granger` names locally. Relay bootstrap accepts only
numeric IP addresses and constructs AF_INET or AF_INET6 sockets directly. A
remote descriptor contains no service endpoint. The client and host each have
only one connection target: the configured relay. The service HTTP bridge
accepts only a numeric-loopback upstream.

Any missing descriptor, bootstrap entry, signature, suite, host, identity,
freshness proof, key confirmation, or valid frame ends the request. There is no
system DNS, ordinary HTTP URL, direct service IP, lower-version retry, or
alternate transport fallback.

Automated tests replace common Python hostname-resolution APIs with failing
stubs and record client `connect()` destinations. Relay captures are checked
for known HTTP and HTML plaintext markers. These tests are regression evidence,
not packet-capture proof for every operating system and network stack.

## Metadata protection

The current release intentionally does not add padding, uniform frame sizes,
timing normalization, traffic shaping, or cover traffic. Adding those mechanisms
without a traffic model could increase distinguishability, latency, bandwidth,
or denial-of-service exposure.

Future work should measure actual packet and frame distributions before choosing
padding buckets, maximum overhead, delay bounds, or cover schedules. Real scroll
or request input must not be delayed merely to make an unvalidated privacy
claim.

## Remaining attacks and limitations

- Client/host correlation by the relay or a global observer.
- Relay enumeration of registered service identities and availability.
- Traffic fingerprinting from handshake, frame headers, sizes, timing, and
  duration.
- Denial of service, registration flooding, connection exhaustion, and relay
  censorship.
- Unauthenticated relay infrastructure and bootstrap substitution.
- No client authentication, authorization, identity revocation, recovery,
  relay federation, path selection, persistence, resumption, or multiplexing.
- No full post-quantum service authentication.
- No protection after administrator, kernel, browser, or live endpoint
  compromise.
- No independent review, formal proof, production hardening, padding, or cover
  traffic.

## Fail-closed rule

Every discovery, descriptor, transport, pairing, identity, suite, transcript,
freshness, Finished, sequence, epoch, frame, session-lifetime, and upstream-
policy failure terminates the request. Future transports and cryptographic
suites must preserve the absence of DNS, clearnet HTTP, direct-host, version,
and alternate-route fallback.
