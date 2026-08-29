# Architecture

## Scope

Granger Network v0.4 is an experimental distributed private overlay for the
`.granger` namespace. It has real authenticated TCP peer connections,
multi-process nodes, replicated discovery, telescoped circuits, introduction
points, rendezvous and a browser bridge. It is not a deployed public network
and does not claim anonymity against colluding relays or a global observer.

## Current architecture

```text
Granger Browser
  |
  | granger-network:// canonical custom scheme
  v
Qt scheme handler
  |
  | bounded stdio protocol v2
  v
Browser gateway process
  |
  | signed bootstrap set + peer cache
  v
Distributed discovery over authenticated peer RPC
  |
  +--> signed service descriptor
  +--> signed introduction descriptor
  +--> signed node descriptors
  |
  v
Client circuit: CLIENT -> ACCESS -> STABLE GUARD -> MIDDLE -> INTRO/RENDEZVOUS
                                                                    ^
                                                                    |
Service circuit: HOST -> ACCESS -> STABLE SERVICE GUARD -> MIDDLE
  |
  v
End-to-end wire-3 service channel
  |
  v
Loopback-only HTTP backend
```

For browser-managed publication, `GrangerHostingManager` starts a separate
app-local `granger_network.hosting` process per enabled service. Static folders
are filtered into an integrity-checked publication snapshot before terminating
in a GET/HEAD file bridge; dynamic services terminate only at a numeric loopback
HTTP target. Both use the existing service publication,
introduction, rendezvous, and wire-3 path shown above.

No component resolves a `.granger` name through system DNS. The browser does
not reinterpret an unavailable `.granger` address as search text or HTTP. The
WAN gateway has no compatibility or local-demo fallback unless that mode was
explicitly selected for a test.

## Layers

1. **Address and identity**: Ed25519 service identities produce canonical
   52-character base32 names. Local aliases require an explicit service-ID pin.
2. **Discovery**: signed records are stored at XOR-nearest discovery peers with
   bounded replication and quorum requirements.
3. **Bootstrap and reseed**: one or more explicitly pinned Ed25519 authorities
   sign generation-numbered sets containing multiple reachable bootstrap
   descriptors. Learned descriptors and reliability metadata are retained in
   an atomic, bounded, network-scoped peer cache.
4. **Link security**: every adjacent peer connection uses wire protocol 3 and
   authenticated peer RPC.
5. **Circuit transport**: routes are built one hop at a time. A relay receives
   its previous connection, next signed descriptor, local circuit identifiers
   and the role for that extension, not a complete route list.
6. **Cells and streams**: fixed 1024-byte padded cells multiplex bounded streams
   with explicit receive windows and `WINDOW_UPDATE` credit.
7. **Service session**: introduction returns a service-signed, nonce-bound
   rendezvous grant. Client and host then perform a separate wire-3 handshake
   through the rendezvous.
8. **Application bridge**: GET, HEAD and POST messages carry bounded paths,
   selected headers and at most 2 MiB bodies to a numeric loopback HTTP target.
   Static hosting uses a GET/HEAD snapshot bridge with canonical root
   containment, a relative-path integrity manifest, deterministic content hash,
   standard MIME fallback, and configurable per-file bounds.

## Process model

Infrastructure roles run as independent `granger_network.node` processes:

- bootstrap/discovery;
- access;
- client guard (`entry` capability);
- middle;
- service guard (`service-relay` capability);
- introduction;
- rendezvous.

Relay participation is opt-in through a signed `RelayPolicy`. The policy bounds
connections, circuits, streams, bandwidth, burst, bytes per circuit, memory
budget, connection timeout and idle timeout. Ordinary clients and service hosts
do not listen for inbound WAN connections.

The browser gateway is a separate child process. It has a maximum of 16 request
workers and 64 accepted pending jobs. Cached service sessions permit HTML,
CSS, JavaScript and API requests to share one rendezvous session and multiple
streams. Closing the gateway waits for active workers, then closes every session.

## Discovery model

Records are canonical, signed and bounded to 64 KiB. Current record kinds are:

- node descriptor;
- service descriptor;
- introduction descriptor;
- local-pinned alias record.

Publication selects XOR-nearest valid discovery peers and requires a configured
minimum number of successful replicas. Lookup rejects malformed payloads,
expired signatures, rollback and same-sequence equivocation. Discovery storage
is bounded to 4096 records per participant. Peer cache storage is bounded to 512
descriptors.

Bootstrap is used for cold start, not as a mandatory traffic proxy. The runtime
tries valid cached peers before current signed seeds, with at most four
concurrent discovery dials. Authenticated `PEER_SAMPLE` responses feed bounded
parallel `FIND_NODE` expansion. If every initial seed later stops, a valid
cache and reachable learned peers still provide discovery. A fresh profile
with neither a reachable seed nor a valid cache fails with
`NETWORK_UNAVAILABLE`.

Cache ingestion is capped globally, per authenticated source, and per IPv4
`/24` or IPv6 `/48`; duplicate endpoints and invalid, expired, or wrong-network
descriptors are rejected. Signed reseed generations are stored atomically and
protected against rollback and same-generation equivocation. This is
meaningful eclipse hardening, not complete Sybil resistance.

## Service publication

The host performs only outbound operations:

1. Load or create the long-term service identity.
2. Discover eligible access, service-guard, middle, introduction and rendezvous nodes.
3. Build at least two independent introduction circuits.
4. Build a separate rendezvous circuit.
5. Register opaque introduction tokens.
6. Publish signed service and introduction records to a discovery quorum.
7. Refresh descriptors before their expiry.
8. Accept service sessions through rendezvous and forward requests only to the
   configured numeric loopback backend.

No service record contains the backend host, backend port, LAN address, public
address or ISP information.

Browser-created services persist identity and configuration below the local
browser data root. Only explicitly enabled services are restored on startup.
Missing WAN configuration creates no route and no hosting process.

## Connection establishment

```text
CLIENT                         SERVICE
  |                              |
  | FIND service + intro         | outbound intro registration
  |                              |
  | circuit to intro             |
  | INTRO_REQUEST(nonce, token)  |
  |----------------------------->| via introduction circuits
  |                              |
  | signed rendezvous grant      |
  |<-----------------------------|
  |                              |
  | circuit to rendezvous        | outbound circuit to rendezvous
  | RENDEZVOUS_JOIN(cookie)      | RENDEZVOUS_REGISTER(cookie)
  |------------------------------X-------------------------------|
  |              opaque paired cell streams                      |
  |<================ wire-3 service handshake ==================>|
  |<================ multiplexed application ===================>|
```

The rendezvous sees opaque circuit identifiers, cookies and timing. It does not
receive a service backend endpoint and cannot decrypt the end-to-end service
channel.

## Endpoint visibility

| Role | Knows | Does not receive |
|---|---|---|
| Client | service key/name, public relay descriptors, own access endpoint | host IP, host port, backend endpoint |
| Host | service identity, local backend, own access endpoint | client IP, client port, client LAN endpoint |
| Client access | client socket address, next guard | service identity, full route, host endpoint and application plaintext |
| Client guard | access-relay socket address, next relay | client endpoint, host endpoint and application plaintext |
| Client middle | adjacent relays | client endpoint, host endpoint, application plaintext |
| Service access | host socket address, next guard | service destination, client endpoint and application plaintext |
| Service guard | access-relay socket address, next relay | host endpoint, client endpoint and application plaintext |
| Service middle | adjacent relays | client endpoint, host backend, application plaintext |
| Introduction | upstream relay, service ID/token, request timing | client/host endpoint pair and application plaintext |
| Rendezvous | paired circuit timing and opaque cell streams | end-to-end plaintext and backend endpoint |
| Discovery | signed public records and requester socket to that node | service backend and opposite endpoint |

An access relay necessarily sees the endpoint connecting to it. The stable guard
sees the access relay as its immediate peer. Endpoint privacy is knowledge
separation, not invisibility from the endpoint's ISP or first access relay.

## Failure behavior

Every routing stage returns a typed failure. Route attempts may choose another
eligible access, guard, middle, introduction point or bootstrap peer, but cannot change
the destination transport. There is no path from `.granger` failure to:

- direct TCP or UDP;
- system DNS;
- clearnet HTTP/HTTPS;
- Tor;
- I2P;
- local compatibility transport.

The host going offline invalidates the live introduction/rendezvous path. A
restarted host republishes fresh signed state under the same service identity.

## Performance architecture

Fixed cells reduce payload-size leakage but add padding overhead. Up to 64 cells
are encrypted and written as one protected batch to reduce syscall and framing
cost. One service session multiplexes independent request streams and applies a
256 KiB default flow-control window.

Discovery routing values are computed once for immutable verified descriptors.
Each operation still checks issue/expiry time, but avoids repeated Ed25519
verification and base32 decoding. This changed the local 1000-peer controlled
benchmark from 2.56 to 140.34 operations per second.

## Trust and deployment boundary

Bootstrap authorities are cold-start trust anchors, not account services or
traffic relays. Operators must distribute public pins out of band and protect
private signing identities. The reseed store can retain signed generations
from several explicitly pinned authorities, while the current packaged browser
configuration supplies its bundled authority. A network still needs multiple
independently operated, publicly reachable infrastructure nodes. A package
without a valid signed bootstrap/reseed set intentionally has no working
`.granger` WAN route.

## Remaining architecture work

- physical cross-network acceptance;
- public independent seed/relay deployment and authenticated bundle delivery;
- operational automatic node-descriptor rotation;
- broader Sybil/eclipse resistance;
- physical-WAN measurement of cover profiles and rotation overhead;
- dedicated cover circuits and stronger timing-correlation defenses;
- streaming responses and long-lived browser APIs;
- independent security review and protocol interoperability tests.
