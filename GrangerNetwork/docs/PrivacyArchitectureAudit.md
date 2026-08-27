# Granger Network privacy architecture audit

## Evidence boundary

This document records the implementation at commit
`00b866bd7b2336a1157642d8a4964aa627acf982` before the endpoint-privacy work.
The evidence is source inspection and local Windows tests. Physical Linux,
cross-ISP, public-WAN, independent-operator, and global-observer claims are not
established by this audit.

## Current architecture

```text
CLIENT PROCESS
  | direct authenticated TCP
  v
CLIENT ENTRY -> MIDDLE -> INTRODUCTION
       |          |
       +----------+-----> RENDEZVOUS <----- MIDDLE <- SERVICE ENTRY
                                                   ^
                                                   | direct authenticated TCP
                                               HOST PROCESS

CLIENT/HOST -> direct authenticated DISCOVERY RPC -> DHT peers
FRESH CLIENT -> direct authenticated PEER_SAMPLE -> bootstrap/discovery peers
```

Each circuit is telescoped one hop at a time over wire v3. The endpoint sends a
next-hop descriptor only to the current hop. Every nested link has independent
X25519 + ML-KEM-768 derived keys, ChaCha20-Poly1305 protection, transcript
authentication, sequence checking, and key rotation. Client and service create
a separate end-to-end wire-v3 channel through the rendezvous.

## Current knowledge model

| Component | Current knowledge |
| --- | --- |
| Bootstrap/discovery peer | Immediate endpoint IP, persistent endpoint peer-auth key, requested capability/record key, and public signed records |
| Client entry | Client IP, persistent client peer-auth key, guard role, next middle descriptor, timing and volume |
| Service entry | Host IP, persistent service identity key, next middle descriptor, timing and volume |
| Middle | Previous/next router, the same persistent endpoint peer-auth key, local circuit IDs, timing and volume |
| Introduction | Service identity and descriptor, introduction tokens, client service request and timing |
| Rendezvous | Service identity, service ID, cookie, both adjacent circuit halves, timing and volume |
| Client | Service identity, introduction nodes and rendezvous router; no host endpoint |
| Host | Local backend and service identity; no client endpoint |
| Local backend | Request data and synthetic `X-Granger-Session`; no forwarded client address headers |

## Current IP visibility

- Client entry is the immediate TCP peer and therefore sees the client IP.
- Service entry is the immediate TCP peer and therefore sees the host IP.
- Discovery peers directly contacted by a client or host see that endpoint IP.
- Middle, introduction, and rendezvous nodes receive relay source addresses,
  not an opposite endpoint address, from the socket layer.
- Remote service and introduction descriptors contain no host IP, host port,
  LAN address, hostname, or backend endpoint.
- The client and host have no protocol field or direct dial path containing the
  opposite endpoint address.

## Current metadata leaks

1. There is no access relay before either entry. The guard and endpoint-facing
   relay are the same node, so the guard sees the real endpoint IP.
2. `CircuitBuilder` authenticates every relay hop with the same long-lived
   endpoint identity. Service-side transit relays can derive the service
   identity even though service descriptors do not expose an endpoint.
3. DHT lookup/publication uses direct peer RPC. A discovery node can associate
   an immediate endpoint IP with a service record key or publication.
4. Rendezvous registration and join contain the service ID; registration also
   carries the service identity key. The rendezvous halves are not opaque with
   respect to service identity.
5. Fixed cells pad each 1024-byte cell, but batch size, direction, cadence,
   total volume, session lifetime, and request boundaries remain observable.
6. There is no cover-cell type, background cover policy, or measured timing
   jitter.
7. Browser WAN sessions are cached until failure. There is no age/byte/request
   circuit rotation policy.
8. Route selection avoids repeated identities and prefers different network
   prefixes, but has no stable guard set or operator/ASN knowledge.

## Current bootstrap dependencies

- A fresh profile requires an authentic signed bootstrap/reseed set with at
  least two distinct reachable descriptors.
- Cached, valid, reachable discovery peers are tried before signed seeds.
- Once joined, peer exchange and DHT can continue after initial seed loss.
- A fresh profile with no valid cache or reachable signed seed fails closed.
- The browser does not fetch arbitrary reseed URLs and does not use DNS,
  clearnet, Tor, or I2P to recover `.granger`.
- No independently operated public Granger router fleet is deployed or proven.

## Current centralization risks

- The protocol and reseed store support multiple authorities and multiple
  nodes, but a packaged browser configuration currently activates one signed
  configuration authority and one bootstrap bundle at a time.
- Public availability would depend on the actual diversity of deployed
  operators, not merely on distinct cryptographic node identities.
- Self-declared identity and endpoint-prefix diversity cannot prove operator,
  ASN, jurisdiction, or ownership independence.

## Current OPSEC risks

- The tracked Debian operator example contains a development/home public and
  LAN endpoint. Packaging copies that configuration and documentation.
- There is no build gate that accepts an external private-marker denylist and
  scans source, embedded Python, generated configuration, Windows release, and
  extracted AppImage content.
- Runtime diagnostics are bounded but operator diagnostics can contain public
  relay endpoints. They are not suitable for automatic publication.
- Private node, service, bootstrap-authority, and configuration-authority keys
  are generated in state roots and are not intentionally packaged, but this is
  not yet enforced by one release-wide scanner.

## Current traffic-analysis risks

- Adjacent peers and ISPs see TCP endpoints, timing, direction, volume, and
  duration.
- Fixed cell padding hides payload length inside one cell but not total cells
  or protected batch length.
- Entry/service-entry collusion links both endpoints. A global observer can
  correlate both circuit halves.
- Active delay/drop/tag attempts remain observable in timing even when byte
  mutation and replay are rejected cryptographically.

## Current failure paths

Routing, DHT, introduction, rendezvous, handshake, and service failures either
try another verified overlay route or terminate. There is no service endpoint
in a public record and no direct client-host, DNS, clearnet, Tor, I2P, or local
compatibility fallback in WAN mode. Host/client route replacement is bounded,
but active-session draining and privacy-triggered rotation are incomplete.

## Current public artifact surface

The Windows package and Linux AppImage can contain the app-local Python source,
signed public trust material when explicitly supplied, runtime manifests,
documentation, and executable strings. Private state is not a required package
member. The operator package contains source, offline dependency wheels, an
example configuration, and empty `state`, `private`, and `public` directories.

## Target architecture

```text
CLIENT
  -> ACCESS -> STABLE CLIENT GUARD -> MIDDLE -> RENDEZVOUS
                                                   ^
                                                   |
HOST
  -> ACCESS -> STABLE SERVICE GUARD -> MIDDLE ------+

HOST -> ACCESS -> GUARD -> MIDDLE -> INTRODUCTION (at least two)
ENDPOINT -> ACCESS -> GUARD -> MIDDLE -> DISCOVERY for post-join DHT data
FRESH ENDPOINT -> signed seed/discovery first contact only
```

Target properties:

- access sees the immediate endpoint but not service identity or full route;
- guard sees access, not the endpoint IP;
- transit hop authentication uses per-hop unlinkable identities;
- service identity is revealed only where protocol authorization requires it
  and in the end-to-end service handshake;
- post-join service lookup and publication use private discovery circuits;
- rendezvous pairing uses an opaque random handle, not a service ID;
- cover is authenticated fixed-cell protocol traffic, never a fake peer,
  service, user, request, or backend visit;
- cover yields immediately to real traffic and is bounded by an explicit
  profile;
- circuits rotate by age, bytes, requests, degradation, and failure by building
  a replacement before draining the old route;
- stable, bounded guard selection reduces exposure to many first-hop relays;
- release promotion fails when an externally supplied private marker or private
  key artifact appears in public output.

## Gap analysis

| Gap | Required implementation |
| --- | --- |
| Guard sees endpoint IP | Add mandatory access role on client and service paths; no one-hop fallback |
| Persistent key at every hop | Use fresh hop-auth identities; reveal service identity only to introduction and end-to-end service peer |
| Direct DHT metadata association | Prime private routes during first contact, then route DHT RPC through access/guard/middle |
| Rendezvous sees service identity | Replace service-ID rendezvous key with signed-grant-bound opaque cookie handling |
| No cover traffic | Add replay-protected `COVER` cells, bounded profiles, opportunistic scheduling, counters, and backend-isolation tests |
| No rotation | Add measurable age/byte/request policy and replacement/drain lifecycle for browser sessions |
| Weak guard policy | Add deterministic bounded guard ranking from a local secret and preserve path exclusions/diversity |
| Private endpoint in source/package | Replace with documentation-only address space and require local operator override |
| No release scanner | Add external-marker, private-key, absolute-path, source/runtime/release scanner and negative tests |
| No public independent fleet | Keep production bundle absent and report infrastructure as NOT DEPLOYED; do not embed a home endpoint |

## Implemented architecture

The endpoint-privacy stage changes the effective route grammar to:

```text
client -> access -> stable entry guard -> middle -> introduction/rendezvous
host   -> access -> stable service guard -> middle -> introduction/rendezvous
joined endpoint -> access -> entry guard -> middle -> discovery
```

There is no shorter-path fallback. First contact to a verified signed seed is
direct only while a private discovery circuit cannot yet exist. That contact
uses a one-time authentication identity and may only prime verified router
descriptors. Service records, introduction records, lookup keys, and
publication are sent through private discovery circuits after join.

| Component | Information available after this stage |
| --- | --- |
| Access | Immediate endpoint address, ephemeral hop key, selected guard, local timing and volume; no service identity or final path |
| Entry/service guard | Access relay address and ephemeral hop key, selected middle, local timing and volume; no endpoint socket address |
| Middle | Adjacent authenticated routers, ephemeral hop key, local timing and volume; no endpoint socket address |
| Introduction | Client service request; service identity only for authenticated service registration |
| Rendezvous | Opaque cookie tag, one-time nonce, adjacent circuit halves, timing and volume; no service ID, raw cookie, service key, client IP, or host IP in rendezvous control messages |
| Service | End-to-end authenticated client session and application request; no client network address |
| Client | Authenticated service identity and response; no host network address |

Every transit hop uses a freshly generated authentication identity. The
persistent service identity is used at the service's final introduction hop
and in the end-to-end service handshake, where authorization requires it. It
is not reused at access, guard, middle, discovery, or rendezvous hops.

## Cover traffic

`COVER` is a valid 1024-byte relay cell carried inside the authenticated and
encrypted wire-v3 channel. It uses stream ID zero, has no application payload,
participates in the same monotonic sequence space as real cells, and is
discarded before stream dispatch. It cannot reach HTTP, a hosted backend, DHT
records, or browser request handling.

Cover is generated independently on real authenticated circuit links. It does
not create peer identities, RouterInfo, service descriptors, users, browser
requests, or fake application visits. A non-blocking send lock makes cover
yield to waiting control/application traffic. Recent real traffic suppresses
cover, and a rolling per-minute cap bounds bandwidth. The scheduler sleeps on
an event and has no polling loop while idle.

Profiles can be selected with `GRANGER_COVER_PROFILE=off|light|standard|high-privacy`:

| Profile | Random interval | Quiet period after real traffic | Maximum cells/minute/link/direction |
| --- | --- | --- | --- |
| OFF | none | none | 0 |
| LIGHT | 7.5-15 s | 2.0 s | 6 |
| STANDARD | 3.5-8 s | 1.5 s | 14 |
| HIGH PRIVACY | 1.5-4 s | 0.75 s | 32 |

One wire-v3 cover frame is 1,062 bytes before TCP/IP overhead: 1,024 fixed-cell
bytes, a 22-byte wire-v3 header, and a 16-byte AEAD tag. STANDARD therefore has
a hard protocol-layer ceiling of 14,868 bytes per minute per active link and
direction; adaptive suppression normally sends less. This changes the visible
cadence but does not provide traffic-analysis immunity. A dedicated pool of
cover-only circuits is not enabled: doing so without deployment measurements
would consume relay capacity and could worsen availability. Cover-only circuit
status is therefore PARTIAL, while cover cells on real circuits are active.

## Circuit rotation

The browser gateway rotates a service circuit before a new request when any
of these limits is reached: ten minutes, 128 completed requests, 64 MiB of
accounted request/response data, channel degradation, or relay failure. It
builds and authenticates a replacement first, atomically selects it for new
requests, drains in-flight requests on the old circuit, and closes the old
circuit only after its active-request count reaches zero. A failed replacement
does not use the expired route and never falls back to DNS, clearnet, Tor, I2P,
or a direct service connection.

Service rendezvous circuits are per-client session. Two independent
introduction circuits are maintained and their generation is refreshed before
descriptor expiry. Active application frames are not deliberately migrated
between service processes; this remains a documented limit for very long
sessions during introduction-generation replacement.

## Guard, Sybil, and eclipse status

Guard ordering is deterministic from a persistent local network identity and
does not select a new guard per request. Access selection is independent of
guard ordering. Route construction rejects repeated identities and prefers
different IPv4 /16 or IPv6 /32 groups, recording when diversity has to be
relaxed.

Peer admission verifies every signed descriptor, rejects duplicate endpoint
ownership, accepts at most 64 peers from one source, accepts at most 32 peers
from one IPv4 /24 or IPv6 /48 group, limits cache size and source history, and
persists success/failure scores. Multiple signed bootstrap authorities and
peer-assisted cache recovery are supported. These measures are partial Sybil
and eclipse hardening. They do not prove distinct operators, ASNs,
jurisdictions, or resistance to a sufficiently large hostile population.

## Release privacy gate

Canonical Windows promotion and Linux AppDir packaging invoke
`scripts/test-release-privacy.py`. The scanner reads exact private markers from
`GRANGER_PRIVATE_MARKER_FILE` or ignored local
`output/private-markers.txt`; markers are never committed. It scans UTF-8,
UTF-16, source, resources, and binary chunks; rejects actual PEM key blocks,
serialized private keys, private state filenames, PKCS#12 files, and exact
build-machine markers. Generic user-home paths are reported as advisories
because official Qt/Chromium binaries and intentional security fixtures can
contain upstream/example paths. Exact local markers remain blocking in every
file, including third-party binaries. The scanner can extract and scan an
AppImage with `--appimage` on a Linux build host.

Any blocking finding stops canonical promotion. The report contains rule and
relative artifact path, but never echoes the private marker value.

## Non-goals and honest limits

This work does not solve Sybil attacks, prove operator independence, hide an
endpoint from its ISP or immediate access relay, defeat colluding path nodes,
or defeat a global timing/volume observer. No fake nodes or users will be
created. Physical Linux and public-WAN behavior remain unverified until run on
the actual systems.
