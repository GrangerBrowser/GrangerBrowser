# Threat Model

## Scope

This model covers the Granger Network v0.3 distributed-discovery and multi-hop
source prototype, plus the unchanged wire 3 secure channel. The multi-hop
implementation runs over local socket pairs and synthetic documentation
addresses. Its tests establish software invariants; they do not prove anonymity
on a real WAN or resistance to a global passive adversary.

## Security goals

- Bind canonical `.granger` addresses to Ed25519 service identities.
- Bind node IDs, capabilities, endpoints, expiry, and limits to signed Ed25519
  node identities.
- Keep the service host IP out of service, alias, and introduction records.
- Require a local identity pin before accepting a human-readable alias.
- Detect modified, expired, substituted, replayed, rolled-back, or equivocal
  signed records.
- Prevent one modeled relay from seeing both client and host endpoint addresses.
- Prevent relays from reading authenticated application plaintext.
- Give every hop and telescoped layer independent wire 3 session material.
- Prevent DNS, direct client-host, clearnet, legacy-rendezvous, alternate-route,
  and lower-version fallback after a distributed-route failure.
- Enforce voluntary relay participation and bounded circuit, byte, and
  bandwidth use.

These are identity, confidentiality, integrity, endpoint-separation, and
fail-closed goals. They are not anonymity, unlinkability, availability, or
traffic-correlation guarantees.

## Cryptographic assumptions

The design relies on the security and correct use of Ed25519, X25519,
ML-KEM-768, HKDF-SHA256, HMAC-SHA256, ChaCha20-Poly1305, the operating-system
random source, and Python `cryptography`. Wire 3 has not changed in this
iteration.

The protocol has no independent audit or formal proof. The hybrid composition
is domain-separated and transcript-bound but is not claimed to inherit the
complete proof of TLS, Tor, or I2P.

## Endpoint assumptions

The model assumes uncompromised client and host operating systems, private-key
storage, and local application boundaries. Administrator, kernel, debugger,
browser renderer, process dump, or live endpoint compromise can expose
plaintext, addresses, keys, and route state.

Node endpoints are public routing hints in signed node descriptors. Service and
client endpoints are not published. The prototype has no authenticated WAN
bootstrap, routing-table maintenance, autonomous peer RPC, or network listener.

## Visibility by role

### Client

The client learns signed service and introduction records, public node
descriptors, its selected entry, its request and response, and local timing. It
has no service-host address or direct-host dialing API.

### Service host

The host learns its selected service relay, its own service and introduction
state, decrypted requests, local application responses, and local timing. It
has no client address or direct-client dialing API.

### Entry node

The entry sees the client network address, its next middle node, physical-link
timing and sizes, and ciphertext. It does not receive the host address or
application keys.

### Middle node

A middle sees only adjacent overlay nodes, timing, sizes, session failures, and
ciphertext at its forwarding layer. It does not receive an endpoint address.

### Service relay

The service relay sees the host network address, its next middle node, timing,
sizes, and ciphertext. It does not receive the client address.

### Introduction node

The introduction sees both middle nodes, service ID and handshake metadata,
authorization-token use, timing, size, duration, and failure patterns. It does
not see either endpoint address in the modeled topology and does not receive
the end-to-end application keys.

### Discovery participant

A discovery participant sees signed node, service, alias, and introduction
records stored near its node ID, plus lookup and publication timing when a real
RPC layer exists. Service records contain no service IP. Node descriptors do
contain public node routing endpoints.

## Considered attackers

### Client-side or host-side ISP

A client-side ISP can observe a connection to the entry. A host-side ISP can
observe a connection to the service relay. Either can measure packet timing,
sizes, duration, and recognizable protocol behavior. A party observing both
sides may correlate them because padding, batching, and cover traffic are not
enabled.

### One malicious relay

One relay can drop, delay, reorder, truncate, replay, selectively forward, or
exhaust a circuit. It can analyze its adjacent metadata. Wire 3 authentication
and AEAD prevent it from modifying a deeper handshake or application frame
without detection.

In the modeled route, no single relay observation contains both synthetic
endpoint addresses. Relay-captured bytes do not contain known application
markers. These tests do not prevent a relay from inferring content from timing
or sizes.

### Multiple malicious relays

Colluding entry and service-relay positions can combine endpoint knowledge.
Colluding adjacent relays can reconstruct larger route segments. A discovery
observer combined with a route observer may correlate lookup and connection
timing. The route planner currently enforces distinct identities but not
operator, subnet, jurisdiction, autonomous-system, or family diversity.

### Malicious discovery peers

A peer can omit, delay, replay, corrupt, or selectively return records. Record
signatures and identity bindings prevent it from forging another service or
node. Highest-sequence selection, local high-water marks, and equivocation
checks detect tested rollback classes.

A single malicious replica cannot replace a valid signed service record when
another valid replica responds. It can still censor its copy. Sybil creation,
eclipse attacks, malicious bootstrap, route-key grinding, churn, and a majority
of malicious nearest replicas are unsolved.

### Service identity substitution

Changing a service descriptor, alias record, introduction descriptor, node
descriptor, service descriptor digest, capability, token, sequence, or expiry
invalidates the relevant signature. The final end-to-end wire 3 handshake must
authenticate the exact service public key from the verified descriptor.

A human-readable alias remains meaningful only with a trusted local identity
pin. A valid attacker-signed alias cannot replace the pinned service ID.

### Replay attacker

Signed records expire. Alias and introduction records have monotonic sequences;
discovery peers and clients reject observed rollback and same-sequence
equivocation. Introduction request nonces are single-use under installed state.

Wire 3 timestamps, Finished confirmation, exact session IDs, strict frame
sequences, epochs, and AEAD associated data reject stale handshakes and replayed
or reordered frames. Availability attacks remain possible.

### Malicious service

A correctly authenticated service controls its returned content. Identity
authentication does not make HTML trustworthy. The unchanged development
browser adapter relies on Chromium sandboxing, one origin per `.granger` host,
and request interception to block cross-service and cross-network escapes.

### Malicious client

A client can consume introduction attempts, handshakes, bandwidth, and service
work. Introduction nonces, bounded records, relay quotas, frame limits, and
session lifetimes constrain some resource use but are not a complete admission,
reputation, proof-of-work, or denial-of-service design.

### Global observer

A global observer can observe both endpoint-to-overlay connections and many or
all relay links. Without padding or timing defenses, it can correlate flows by
start time, burst pattern, sizes, direction, and duration. Multi-hop routing
does not by itself defeat this attacker.

## Metadata leakage

Encryption does not hide:

- public node endpoints and capabilities;
- discovery lookup and publication timing in a future network;
- fixed and recognizable wire 3 handshake sizes;
- adjacent transport endpoints;
- encrypted-frame and packet sizes, direction, count, and timing;
- route setup, lifetime, failure, and retry patterns;
- service identity at the introduction and end-to-end handshake;
- total transferred bytes.

The introduction token is distributed with the signed introduction record. It
prevents stale or accidental introduction use but is not confidential client
authorization and can be used in denial-of-service attempts.

## Metadata defenses and performance

Padding, uniform frames, batching, traffic shaping, timing normalization, cover
traffic, and artificial delay remain disabled. Unmeasured activation could
increase bandwidth and CPU, amplify denial of service, delay interactive page
loads, or create a more distinctive traffic pattern.

The local benchmark established eleven hybrid wire 3 sessions per circuit. On
the recorded Windows development environment, 20 setups averaged 25.7 ms and a
1 MiB transfer over 64 frames reached 25.5 MiB/s. This is an in-process best
case with no network latency, packet loss, congestion, or competing routes. It
is insufficient to choose padding buckets or cover schedules. Those mechanisms
require packet-level measurements on independent nodes and explicit overhead
budgets before implementation.

## Post-quantum scope

Each wire 3 session combines ephemeral ML-KEM-768 and X25519 before
transcript-bound HKDF. The intended benefit is resistance to passive
store-now/decrypt-later collection if either exchange and the combiner remain
secure.

Service and node authentication remain Ed25519 and are not post-quantum. A
cryptographically relevant quantum attacker able to forge Ed25519 could
actively impersonate new sessions. Wire 3 must not be described as fully
post-quantum secure.

## Key compromise

Each of the eleven modeled bindings uses fresh exchange material. Long-term
Ed25519 keys authenticate but do not enter the shared secret. Later compromise
of only an identity key does not reconstruct recorded completed-session keys.

Compromise of live channel state exposes that channel's current epoch and may
permit later epoch derivation until a fresh handshake. Best-effort Python object
destruction is not guaranteed memory zeroization. Compromise of entry state
does not reveal host-side channel keys, but endpoint or multiple-relay
compromise changes that analysis.

## Leak and fallback evidence

Automated tests replace common Python DNS APIs with failing stubs and assert
zero calls. They also replace `socket.create_connection` and
`socket.socket.connect` during multi-hop construction and assert zero calls;
the prototype uses only local socket pairs. The route graph is checked for zero
direct client-host edges.

Relay observations are sampled and checked for known request and response
plaintext markers. Distinct node identities, eleven unique channel bindings,
resource release, tamper, identity spoofing, record rollback, introduction
nonce replay, missing-hop failure, and a corrupt discovery replica are covered.

This is application-level regression evidence. It is not packet-capture proof,
an independent-machine test, or validation of every operating-system network
stack.

## Remaining limitations

- The distributed layer is in-memory and has no network peer RPC or persistence.
- No authenticated bootstrap, Sybil resistance, routing diversity, reputation,
  revocation, recovery, churn handling, or distributed availability proof.
- No production path selection, circuit rotation, relay cells, multiplexing,
  congestion control, NAT traversal, or relay listener.
- No padding, cover traffic, batching, traffic-shaping, or global-observer
  resistance.
- Introduction tokens are public to record readers and do not authorize users.
- No client authentication or service access-control protocol.
- No full post-quantum identity authentication.
- No protection after administrator, kernel, browser, or live endpoint
  compromise.
- No independent security review, formal proof, or production hardening.
- The existing browser adapter still exercises the compatibility rendezvous,
  not this distributed transport.

## Fail-closed rule

Every name, pin, discovery, signature, expiry, sequence, descriptor binding,
replica, capability, introduction, quota, route, hop, identity, suite,
transcript, Finished, sequence, epoch, frame, session-lifetime, and upstream
policy failure terminates the request and releases acquired resources.

The distributed overlay has no DNS, direct TCP to a service, clearnet HTTP,
legacy rendezvous, lower-version, or alternate-transport fallback.
