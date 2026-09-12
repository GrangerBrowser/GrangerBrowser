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

The client must obtain authentic bootstrap/reseed authority pins and, when
using a human-readable alias, an authentic alias-to-service identity pin.
Reachable relay operators must publish correct numeric endpoints. Clients and
service hosts are assumed not to be compromised at the administrator, kernel,
browser, or live-process level.

## Implemented route

```text
CLIENT
  -> CLIENT ACCESS -> STABLE CLIENT GUARD -> CLIENT MIDDLE -> RENDEZVOUS
                                                               ^
                                                               |
HOST -> SERVICE ACCESS -> STABLE SERVICE GUARD -> SERVICE MIDDLE
```

The service also keeps independent outbound circuits to at least two
introduction nodes. Client and host never dial each other. The rendezvous pairs
opaque streams; a separate wire-3 session protects application data end to end.

## Visibility by role

| Role | What it sees | What it does not receive |
| --- | --- | --- |
| Client | Own address, access endpoint, public relay descriptors, service identity, own requests/responses, local timing | Host endpoint or local backend address |
| Service host | Own address, service-access endpoint, own records, decrypted requests, loopback backend | Client endpoint |
| Client access | Client transport endpoint, next guard, encrypted cells, timing and volume | Service identity, host endpoint, service plaintext, full route |
| Client guard | Access-relay endpoint, next relay, encrypted cells, timing and volume | Client transport endpoint, host endpoint, service plaintext, full route |
| Client middle | Adjacent relays, encrypted cells, timing and volume | Either endpoint, plaintext, full route |
| Service access | Host transport endpoint, next guard, encrypted cells, timing and volume | Service destination, client endpoint, plaintext, full route |
| Service guard | Access-relay endpoint, next relay, encrypted cells, timing and volume | Host transport endpoint, client endpoint, plaintext, full route |
| Service middle | Adjacent relays, encrypted cells, timing and volume | Either endpoint, plaintext, full route |
| Introduction | Adjacent service relay, client-side introduction request, service ID/token, timing | Client or host endpoint from protocol data, application plaintext |
| Rendezvous | Its two adjacent relay connections, cookie, circuit IDs, timing and volume | Client/host endpoint from protocol data, end-to-end keys, application plaintext |
| Discovery peer | Public node descriptors, signed service/intro/alias records, lookup timing; a signed seed also sees a fresh endpoint during first contact | Service backend endpoint; post-join endpoint address |
| Bootstrap authority | Signed seed set contents and issue schedule | Service request traffic unless separately operating relays |

Transport peers naturally see the network endpoint directly connected to them.
A single machine operating multiple roles can combine those observations; role
separation in the protocol does not create organizational separation.

## Observer matrix

| Observer | Directly visible metadata | Stable or linkable values | Inference boundary |
| --- | --- | --- | --- |
| Local OS | Browser/helper memory, files, keys, plaintext, routes, sockets and timing | All local identities and history | Full endpoint compromise is outside overlay protection |
| Client ISP | Client or VPN destination, packet sizes, timing and duration | Subscriber address and repeated flows | Can correlate with another vantage; transport encryption hides plaintext only |
| VPN provider | Client address, contacted relay endpoints, timing and volume | VPN account/session and repeated flows | Becomes the client-side observer; Granger does not control the VPN |
| Bootstrap node | Source endpoint, first-contact time, fresh ephemeral auth key and bounded request | Source IP and retries on that connection | Does not receive the persistent discovery seed or later service destination |
| Reseed provider | Requested public generation/digest and adjacent transport peer | First-contact source or post-join previous relay | Authenticated overlay RPC carries pinned signed bundles; no reseed HTTP request |
| Reachable anchor | Restricted peer endpoint, persistent relay ID, descriptor lifetime, slots and relayed circuits | Browser relay across reconnects and anchor sessions | Registration has no destination, but the anchor is a concentration point |
| Access peer | Endpoint IP, ephemeral hop key, next guard, cells, timing and volume | TCP lifetime and activity bursts | Does not receive service ID, opposite endpoint, plaintext or full path |
| Middle relay | Previous/next relay, role transition, cells, timing and volume | Circuit-local IDs and flow | No endpoint IP or plaintext unless another position is controlled/correlated |
| Service relay/guard | Service-access relay, next middle, cells, timing and volume | Circuit-local auth and flow | Does not receive host IP, client IP, service ID or plaintext |
| Introduction peer | Persistent service ID, record/token, client request and adjacent relays | Service across introduction-circuit lifetime | No endpoint IP from protocol data; request timing remains visible |
| Rendezvous peer | Two adjacent middle links, cookie tag, circuit IDs, timing and volume | One rendezvous session | No service ID, endpoint IP, end-to-end key or plaintext |
| DHT peer | Raw record kind/key, including service ID, query/store timing and previous middle | Repeated lookup of the same public record | Post-join source IP is hidden by a private circuit; query target is not hidden |
| `.granger` host | Decrypted HTTP data, response timing and per-session opaque ID | Application cookies/content and one service session | Protocol does not provide client IP; active content can add identifiers |
| Malicious client | Public service identity/records and returned content | Its own sessions and browser state | Cannot derive or directly dial a host endpoint from valid records |
| Malicious host | Host view plus attacker-controlled page behavior | User-supplied/application identifiers | Application fingerprinting remains possible; protocol withholds client IP |
| Malicious relay | Adjacent endpoints, role, cells, timing, count and direction | Flows traversing that relay | Can delay/drop/tag timing; cannot decrypt end-to-end application traffic |
| Colluding relays | Union of their positions and clocks | Shared timing/volume fingerprints | Ingress-adjacent plus egress-adjacent observation can correlate endpoints |
| A/B/C/D operator | Roles and public endpoints operated by that party | Cross-role node IDs, logs, timing and traffic | Multiple selected roles remove organizational separation |
| Passive network observer | TCP endpoints, lengths, timing and duration at its vantage | Repeated endpoint flows | One-sided view lacks the other endpoint; broad/two-sided view can correlate |
| Ingress-and-egress observer | Client-side and host-side timing, direction, cells and volume | Request/response fingerprints | Bounded cover is not constant rate and does not defeat this observer |
| Hostile DHT sampler | Signed reachable nodes and service/intro/alias records | Public service and reachable topology over time | Adjacent descriptors are not stored and direct sampling excludes them |
| Hostile bootstrap authority | Signed seed view and generation schedule | Initial client source when also operating a seed | A pinned malicious authority can bias/eclipse first contact, not forge services |
| Compromised browser peer | Relay links plus its local browser process data | Relay ID, local activity, circuits and live keys | Endpoint compromise defeats local isolation; other endpoints stay encrypted |

An outbound-only browser relay is a middle with a reverse adjacency to one
reachable anchor. The anchor sees that browser's transport endpoint, persistent
node identity, descriptor lifetime, and session timing. The next hop dialed by
the browser sees it as its immediate transport peer. The signed adjacency
descriptor publishes the anchor endpoint, not a private or self-asserted browser
endpoint, and is neither cached as a reachable peer nor stored as a DHT record.
Rotating anchors can reduce one anchor's availability control but does not hide
the browser from its current adjacent transport peers.

The browser relay identity is intentionally separate from the persistent local
discovery/guard-selection seed. Each client/service circuit hop otherwise uses
a fresh authentication identity, except that the service uses its persistent
service identity at its introduction endpoint. An anchor that learns the relay
identity therefore cannot derive the client's deterministic guard order from
that public key.

## Identity scope

| Identifier | Lifetime | Visible to | Linkability purpose or boundary |
| --- | --- | --- | --- |
| Reachable node ID | Persistent | Peers and signed bootstrap/DHT consumers | Authenticates infrastructure; linkable to its public endpoint |
| Discovery client seed | Persistent local file | Local process/OS only | Stable guard preference; never sent as circuit authentication |
| Browser relay ID | Persistent separate local file | Anchors and circuits using that relay | Relay continuity; linkable to restricted peer IP at its anchor |
| Per-hop circuit auth key | Fresh per hop and circuit | One authenticated hop | Prevents protocol-level linking across ordinary browsing circuits |
| Service ID | Persistent per service | Clients, DHT and introduction peers | Address/identity binding; not sent to rendezvous by protocol |
| Circuit ID | Random per adjacent segment | The two peers on that segment | Not a global route identifier |
| Introduction nonce/token | Fresh and short-lived | Client, service and selected introduction peer | Request authorization and replay rejection |
| Rendezvous cookie/tag | Fresh and short-lived | Client, service and rendezvous peer | Pairs one session without carrying service ID |
| Application session identity | Fresh per service session | Client and local host bridge | Same-session state only; not an IP address |

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
high-confidence secret publication; it does not make page script trustworthy. A
malicious local application receives request content and an opaque per-session
identifier, but forwarding/client/relay IP headers are removed.

### Malicious hosted source

Static request paths are decoded once and resolved under a canonical publication
snapshot root. Traversal, absolute paths, network paths, oversized files,
symlinks, junctions, reparse points, and manifest mismatches fail closed. There
is no extension whitelist. A bounded text preflight detects private-key markers
and local-user paths but cannot prove that arbitrary content contains no secret.
The service copies approved files to an atomic snapshot with a relative-path
manifest and deterministic SHA-256. Later source edits do not alter the active
snapshot; an explicit update creates a new snapshot while preserving identity.
A compromised local process that can modify service state or race authoring files
remains outside this protection boundary; copy-time hash mismatches abort.

### Malicious relay

A relay can drop, delay, reorder, duplicate, truncate, selectively forward, or
rate-limit cells. It can inspect adjacent endpoints, connection lifetime, cell
count, direction, and timing. Wire-3 authentication, RPC/cell sequences, and
AEAD detect tested modification and replay, but availability is not guaranteed.

A single role observation does not contain both endpoint addresses. A relay
cannot decrypt the end-to-end service session. Fixed cells hide the exact
payload length within one cell but not total volume or burst structure.

A malicious reverse-adjacency anchor can consume, withhold, expire, or refuse a
browser's one-shot relay sessions and can bias which clients learn that browser
descriptor. It cannot change the descriptor identity, ingress binding, relay
limits, or validity interval without invalidating the signature. Reverse
registration accepts no destination or proxy payload, and circuit extension can
use the session only for the signed middle role. Per-anchor, per-identity, and
per-browser connection/circuit/stream/byte/bandwidth limits bound this path but
do not eliminate denial of service or timing correlation.

### Colluding relays

Client access plus service access can combine endpoint addresses, but neither
alone receives the service destination. Correlation with guards, middles,
introduction/rendezvous roles, or a broad network observer can reconstruct more
route metadata. Selection avoids repeated identities, keeps a stable guard, and
prefers different network prefixes, but it does not yet prove operator, family,
autonomous-system, jurisdiction, or ownership diversity.

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

The client-side observer sees a connection to the client access relay. The
host-side observer sees outbound connections to service access relays. Each
can inspect timing, sizes, duration, and recognizable protocol behavior. They
do not see end-to-end application plaintext from encryption alone.

### Global passive observer

An observer able to see both sides can correlate start times, fixed-cell bursts,
direction, total bytes, duration, route rebuilds, and application behavior.
The default bounded cover profile perturbs quiet-link cadence but is not
constant-rate padding or complete timing normalization. Multi-hop routing and
bounded cover do not defeat this attacker.

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

Normal node operation does not retain source endpoint lists or per-circuit path
objects. Those structures are populated only when an explicit diagnostic
capture path is configured. Error persistence is bounded and records categories
instead of raw exception strings. Service-host failure lists follow the same
category-only rule while retaining route role and stage attribution. This
reduces accidental retention; it does not hide live socket metadata from the
node OS or operator.

## Post-quantum scope

Wire 3 combines ephemeral ML-KEM-768 and X25519 before transcript-bound HKDF.
The intended benefit is resistance to passive store-now/decrypt-later attacks
if at least one exchange and the combiner remain secure. Authentication remains
Ed25519 and is not post-quantum. Granger Network must not be described as fully
post-quantum secure.

## Remaining risks

- Physical WAN behavior and packet-level leak checks are unverified.
- Local tests do not establish independence or health of a physical relay fleet.
- Per-source and endpoint-prefix cache limits do not identify a common
  operator. There is no complete Sybil resistance, reputation, ASN diversity,
  or global revocation.
- Timing, volume, session duration, and first/last relay relationships leak.
- A controlled measurement produced one cell for a 97-byte payload and four
  cells for a `3 * CELL_PAYLOAD_SIZE + 97` payload. A 30 ms application burst
  gap remained visible at the sender channel. Fixed cells therefore do not
  provide total-size or timing-fingerprint resistance.
- Bounded cover cells and request/age-based circuit rotation do not provide
  constant-rate traffic shaping or defeat a global timing observer. Dedicated
  cover circuits and deliberate timing normalization are not implemented.
- TCP head-of-line blocking and network-level denial of service remain.
- Application responses are bounded and buffered; large streaming and
  WebSocket traffic are not implemented.
- Hosting availability depends on its local source/backend, sufficient reachable
  authenticated relays, and a valid signed WAN configuration.
- Python process memory is not guaranteed to be zeroized.
- No formal verification, independent review, or production security audit.

## Fail-closed invariant

Any invalid name, pin, bootstrap set, record, signature, expiry, sequence,
quorum, capability, route, handshake, channel binding, RPC frame, cell,
introduction, rendezvous grant, flow-control state, application message, or
loopback target terminates the affected operation. There is no direct
client-to-host fallback.

## Bootstrap generation expiry and recovery

Cold discovery startup requires a valid authority-pinned generation. The
runtime can fetch a newer signed bundle through still-valid cached discovery
peers after installed bundles expire. Peers supply bytes, not authorization:
pins, network, protocol, signatures, monotonic generation, member expiry, and
advertised metadata are checked before atomic acceptance. Up to two valid
generations overlap, but expiry of the high-water generation cannot reactivate
an older one. No authority is generated or replaced during recovery.

Recovery still fails closed if every carrier is unreachable or expired, the
next signed generation was never issued, or persistent high-water state is
lost/corrupt. The independent signed browser WAN configuration is not renewed
by reseed transport. The candidate's separate [config recovery channel](WanConfigRecovery.md)
permits only signed control snapshots through historical authenticated contacts,
not expired routing instructions. Reseed tests alone do not prove browser
startup after long offline periods. Existing authority issuance and fresh
carrier descriptors remain availability requirements, not optional checks.

Public browser relay mode exposes a persistent relay identity and numeric
endpoint by explicit listener opt-in. At least two distinct authenticated
observers must agree and authenticate callbacks; the browser is excluded from
its own quorum. Distinct keys do not establish distinct operators. Malicious
observers can withhold proof or coordinate false observations, resulting in
failure to become public, not permission for a client-to-host fallback.
