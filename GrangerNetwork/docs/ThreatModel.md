# Threat Model

## Scope and evidence boundary

This model covers Granger Network v0.4: signed WAN discovery, authenticated
peer RPC, telescoped TCP relay circuits, introduction/rendezvous, end-to-end
service encryption, the loopback application bridge, and Qt WebEngine
integration.

Local unit, parser, real-socket, multi-process, and browser tests establish
software invariants on one Windows development machine. They do not prove
anonymity, resistance to a global observer, or physical cross-network
portability. A Windows-to-Debian or cross-ISP run remains **UNVERIFIED**.

## Security goals

- Bind canonical `.granger` names to Ed25519 service identities.
- Authenticate every infrastructure peer against a signed node descriptor.
- Keep service and client endpoints out of service discovery and opposite
  endpoint APIs.
- Require outbound-only client and service connectivity through separate relay
  paths.
- Ensure no ordinary relay receives both endpoint addresses or application
  plaintext.
- Authenticate application traffic end to end between client and service.
- Reject replay, downgrade, malformed input, rollback, equivocation, and
  descriptor substitution within the implemented bounds.
- Never resolve `.granger` through DNS or use a direct/clearnet fallback.

These are confidentiality, integrity, endpoint separation, and fail-closed
goals. They are not guarantees of availability, anonymity, unlinkability, or
traffic-correlation resistance.

## Trust assumptions

The design depends on the correct implementation and security of Ed25519,
X25519, ML-KEM-768, HKDF-SHA256, ChaCha20-Poly1305, the operating-system random
source, Python `cryptography`, TCP, Qt WebEngine, and the local operating system.
There is no formal proof or independent protocol audit.

The client must obtain an authentic bootstrap-authority key pin and, when using
a human-readable alias, an authentic alias-to-service identity pin. Reachable
relay operators must publish correct numeric endpoints. Clients and service
hosts are assumed not to be compromised at the administrator, kernel, browser,
or live-process level.

## Implemented route

```text
CLIENT
  -> CLIENT ENTRY -> CLIENT MIDDLE -> RENDEZVOUS
                                         ^
                                         |
HOST -> SERVICE ENTRY -> SERVICE MIDDLE --+
```

The service also keeps independent outbound circuits to at least two
introduction nodes. Client and host never dial each other. The rendezvous pairs
opaque streams; a separate wire-3 session protects application data end to end.

## Visibility by role

| Role | What it sees | What it does not receive |
| --- | --- | --- |
| Client | Own address, entry endpoint, public relay descriptors, service identity, own requests/responses, local timing | Host endpoint or local backend address |
| Service host | Own address, service-entry endpoint, own records, decrypted requests, loopback backend | Client endpoint |
| Client entry | Client transport endpoint, next relay, encrypted cells, timing and volume | Host endpoint, service plaintext, full route |
| Client middle | Adjacent relays, encrypted cells, timing and volume | Either endpoint, plaintext, full route |
| Service entry | Host transport endpoint, next relay, encrypted cells, timing and volume | Client endpoint, plaintext, full route |
| Service middle | Adjacent relays, encrypted cells, timing and volume | Either endpoint, plaintext, full route |
| Introduction | Adjacent service relay, client-side introduction request, service ID/token, timing | Client or host endpoint from protocol data, application plaintext |
| Rendezvous | Its two adjacent relay connections, cookie, circuit IDs, timing and volume | Client/host endpoint from protocol data, end-to-end keys, application plaintext |
| Discovery peer | Public node descriptors, signed service/intro/alias records, lookup timing | Service backend endpoint or client endpoint |
| Bootstrap authority | Signed seed set contents and issue schedule | Service request traffic unless separately operating relays |

Transport peers naturally see the network endpoint directly connected to them.
A single machine operating multiple roles can combine those observations; role
separation in the protocol does not create organizational separation.

## Attacker classes

### Malicious client

It can generate lookups, introductions, circuits, streams, and application
requests; consume relay/service resources; replay old input; and serve malicious
browser-visible state to itself. Bounds on frames, records, connections,
circuits, streams, queues, bodies, nonces, windows, and timeouts constrain but
do not eliminate denial of service. There is no reputation, proof-of-work, or
complete admission-control system.

It cannot derive the host endpoint from valid service/introduction records or
ask the runtime to dial a service directly. A compromised client OS can of
course reveal everything visible at that endpoint.

### Malicious service

It controls returned content and may fingerprint or attack the browser within
the Chromium security boundary. Service identity authentication does not make
HTML trustworthy. The custom scheme isolates origins and blocks cross-service,
clearnet, Onion, I2P, file, WebSocket, and external subresource escapes from a
`.granger` document.

The service receives application content and timing, but the protocol does not
provide the client endpoint. Active content can still collect application-level
identifiers supplied by the user or browser.

A malicious static source can contain active HTML/JavaScript and is treated as
untrusted web content. Hosting validation prevents filesystem escape and
executable-file publication; it does not make page script trustworthy. A
malicious local application receives request content and an opaque per-session
identifier, but forwarding/client/relay IP headers are removed.

### Malicious hosted source

Static request paths are decoded once and resolved under a canonical source
root. Traversal, absolute paths, network paths, unsupported extensions,
oversized files, and symlink escapes fail closed. The selected source directory
remains trusted local input: a compromised local process able to modify allowed
files can change the published site. Content is not snapshotted or signed as an
authoring-time file manifest.

### Malicious relay

A relay can drop, delay, reorder, duplicate, truncate, selectively forward, or
rate-limit cells. It can inspect adjacent endpoints, connection lifetime, cell
count, direction, and timing. Wire-3 authentication, RPC/cell sequences, and
AEAD detect tested modification and replay, but availability is not guaranteed.

A single role observation does not contain both endpoint addresses. A relay
cannot decrypt the end-to-end service session. Fixed cells hide the exact
payload length within one cell but not total volume or burst structure.

### Colluding relays

Client entry plus service entry can combine endpoint knowledge. Adjacent or
strategically placed relays can reconstruct more route metadata. Selection
avoids repeated identities and prefers different network prefixes, but it does
not yet enforce operator, family, autonomous-system, jurisdiction, or ownership
diversity.

### Malicious bootstrap

A seed can omit peers, refuse service, return stale data, or try to bias the
initial view. The bootstrap set is signed by a locally pinned authority,
requires multiple distinct reachable peers, expires, and is bounded. Peer RPC
authenticates each selected node independently. A malicious or compromised
pinned authority can still distribute an attacker-controlled initial set and
facilitate eclipse attacks.

### Malicious DHT peers

Peers can omit, delay, corrupt, flood, replay, or selectively return records.
Signatures and identity-derived keys prevent forging another service/node.
Expiry, highest-sequence tracking, equivocation detection, bounded storage, and
replica quorum cover tested failures. Sybil resistance, economic admission,
majority-malicious nearest replicas, key grinding, and robust anti-eclipse
protection remain unsolved.

### Client or host ISP and local observer

The client-side observer sees a connection to the client entry. The host-side
observer sees outbound connections to service relays/introduction points. Each
can inspect timing, sizes, duration, and recognizable protocol behavior. They
do not see end-to-end application plaintext from encryption alone.

### Global passive observer

An observer able to see both sides can correlate start times, fixed-cell bursts,
direction, total bytes, duration, route rebuilds, and application behavior.
There is no default cover traffic, constant-rate padding, or timing
normalization. Multi-hop routing does not defeat this attacker.

### Compromised endpoint

Administrator, kernel, debugger, browser renderer, process injection, memory
dump, or private-key compromise can expose plaintext, identities, keys, route
state, and local addresses. This is outside the overlay's protection boundary.

## Identity, replay, and downgrade attacks

- Node IDs and canonical service IDs are recomputed from public keys.
- Signed descriptors bind identity, version, capabilities, endpoint where
  appropriate, sequence, and expiry.
- Peer AUTH binds both HELLO messages to the wire-3 channel binding.
- Introduction requests use fresh nonces; grants bind the nonce, service,
  rendezvous descriptor, cookie, and expiry.
- Rendezvous registrations are service-signed and short-lived.
- Wire-3 frames and relay cells enforce exact directional sequences.
- WAN peer RPC requires wire 3; unknown versions and messages are rejected.
- Alias records require a separate local identity pin.

These checks do not provide revocation after a key compromise. Operators must
replace and redistribute pins/descriptors through an authenticated channel.

## DNS and direct-connection policy

`.granger` resolution accepts only the internal canonical/alias grammar. WAN
configuration and node descriptors require numeric endpoints. The browser
intercepts `.granger` before ordinary URL resolution. Python acceptance installs
DNS and socket audit guards; process reports assert zero DNS and UDP calls and
zero client-to-host or host-to-client socket edges.

When bootstrap, quorum, routing, introduction, rendezvous, identity, transport,
or service setup fails, the operation ends with a private network error. It does
not try DNS, system proxy, clearnet, Tor, I2P, a compatibility rendezvous, or a
direct endpoint.

This is application and local process evidence. Packet capture on two physical
networks is still required to independently validate operating-system traffic.

## Metadata and logging

Public node descriptors intentionally disclose reachable infrastructure IPs and
ports. Service descriptors do not disclose a host endpoint. Runtime diagnostics
may contain process IDs, node IDs, capabilities, counters, error categories,
timing, and public relay endpoints. They must not log private keys, service
backend addresses to clients, client addresses to services, handshake secrets,
cookies, full application bodies, or raw plaintext captures.

Capture files and diagnostics are security-sensitive operational artifacts.
They should be access-controlled and removed after analysis.

## Post-quantum scope

Wire 3 combines ephemeral ML-KEM-768 and X25519 before transcript-bound HKDF.
The intended benefit is resistance to passive store-now/decrypt-later attacks
if at least one exchange and the combiner remain secure. Authentication remains
Ed25519 and is not post-quantum. Granger Network must not be described as fully
post-quantum secure.

## Remaining risks

- Physical WAN behavior and packet-level leak checks are unverified.
- No public, independently operated seed/relay fleet exists in this local stage.
- No operator/family/AS diversity, Sybil resistance, reputation, or revocation.
- Timing, volume, session duration, and first/last relay relationships leak.
- No cover traffic or periodic circuit rotation.
- TCP head-of-line blocking and network-level denial of service remain.
- Application responses are bounded and buffered; large streaming and
  WebSocket traffic are not implemented.
- Hosting availability depends on its local source/backend and a valid shared
  WAN configuration; there is no public relay fleet in this stage.
- Python process memory is not guaranteed to be zeroized.
- No formal verification, independent review, or production security audit.

## Fail-closed invariant

Any invalid name, pin, bootstrap set, record, signature, expiry, sequence,
quorum, capability, route, handshake, channel binding, RPC frame, cell,
introduction, rendezvous grant, flow-control state, application message, or
loopback target terminates the affected operation. There is no direct
client-to-host fallback.
