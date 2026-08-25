# WAN Architecture Audit

## Scope and baseline

This audit records the implementation state at Granger Network v0.3 before
the WAN overlay work. The baseline source revision is
`37600d605af7542daada99ad5e90617ccc755824`. All 51 source tests passed on
Windows 11 with Python 3.14.5 and `cryptography` 49.0.0.

The audit distinguishes runtime behavior from modeled behavior. A signed data
structure or an in-process socket-pair test is not counted as a WAN feature.

## Current runtime architecture

```text
Granger Browser
    |
    | private stdio JSON, GET/HEAD only
    v
browser_gateway Python worker
    |
    | LocalResolver: local JSON descriptor and rendezvous map
    v
GrangerClient
    |
    | outbound TCP, wire v3 end-to-end service channel
    v
single RendezvousServer
    ^
    | outbound TCP, wire v3 end-to-end service channel
    |
RendezvousServiceHost
    |
    | numeric loopback HTTP, GET/HEAD only
    v
local application
```

The compatibility rendezvous forwards encrypted service bytes, so it cannot
read HTTP plaintext. It does, however, accept the client and service sockets in
one process and therefore observes both network endpoints. It is unsuitable as
the WAN privacy path.

The following v0.3 components are separate from that runtime path:

```text
DistributedDiscoveryNetwork  -> in-memory method calls
OverlayRoutePlanner          -> verified modeled route selection
MultiHopCircuit              -> socket.socketpair() links in one process
IntroductionRegistry         -> in-memory authorization state
GrangerNode                  -> in-memory quota accounting only
```

The browser does not invoke these components. No v0.3 node listens for peer
RPC, no DHT record crosses a network socket, and no modeled relay is a separate
operating-system process.

## Properties worth preserving

- Canonical service names are derived from Ed25519 public identities.
- Service descriptor v2 contains no service endpoint.
- Node, service, introduction, and alias records are strictly parsed, signed,
  bounded, expiring, and protected against rollback and equivocation.
- Wire v3 provides X25519 plus ML-KEM-768 key exchange, HKDF-SHA256,
  ChaCha20-Poly1305 framing, Ed25519 server authentication, transcript-bound
  Finished messages, replay protection, key epochs, and session lifetime.
- `.granger` browser requests use a private Qt URL scheme and never enter the
  system DNS resolver.
- Local application forwarding accepts numeric loopback endpoints only.
- Existing Tor, I2P, and browser fail-closed routing are outside this module
  and require regression testing, not redesign.

## Direct-connection and metadata audit

| Surface | Current behavior | Risk or limitation |
| --- | --- | --- |
| Browser gateway | Replaces Python hostname resolver APIs with a rejecting guard | Good boundary, but it uses only the local compatibility resolver |
| Local resolver | Reads local JSON and numeric relay endpoints | No DNS fallback; no cold-start network discovery |
| Compatibility client | Connects only to one configured numeric rendezvous | The rendezvous sees the client endpoint |
| Compatibility host | Connects outbound to that same rendezvous | The rendezvous sees the host endpoint too |
| Service descriptor | Carries service identity and rendezvous ID, not an IP | Good identity privacy, but rendezvous selection is centralized |
| Node descriptor | Carries a public relay endpoint | Appropriate for opt-in reachable infrastructure only |
| DHT prototype | Direct Python calls to in-memory peers | No WAN availability, bootstrap, persistence, or authenticated RPC |
| Introduction prototype | Signed record plus in-memory registry | No live host circuit or request delivery |
| Multi-hop prototype | Nested wire v3 over local socket pairs | Cryptographic composition only; no process or network isolation |
| HTTP bridge | Numeric loopback, GET/HEAD, 2 MiB response limit | Safe endpoint policy; insufficient for dynamic POST applications |
| Logging | CLI status and exception class/name output | No key material, but WAN runtime needs explicit metadata-safe events |
| Recovery | Compatibility client retries the same rendezvous | No path diversity, relay replacement, or peer-cache recovery |

No source path intentionally resolves a `.granger` name through DNS. Numeric
relay endpoints are permitted because reachable relay infrastructure must have
connectable addresses. A service endpoint must never be inserted into a public
record, route response, browser API, or client memory.

## Target runtime architecture

```text
CLIENT PROCESS
    |
    | outbound authenticated hop channel
    v
ENTRY A
    |
    | fixed, bounded encrypted relay cells
    v
MIDDLE B
    |
    | fixed, bounded encrypted relay cells
    v
RENDEZVOUS C
    ^
    | fixed, bounded encrypted relay cells
    |
MIDDLE D
    ^
    | fixed, bounded encrypted relay cells
    |
SERVICE ENTRY E
    ^
    | outbound authenticated hop channel
    |
HOST PROCESS -> numeric-loopback application
```

The client and host build their halves independently. Introduction delivery
authorizes a short-lived rendezvous cookie. Rendezvous C pairs opaque circuit
streams, after which the client and service perform a separate wire v3
end-to-end handshake. Relays have independent hop keys and cannot decrypt the
service channel.

Cold start and record lookup use several independently pinned bootstrap peers,
a persistent peer cache, and authenticated DHT RPC:

```text
bootstrap set + peer cache
          |
          v
authenticated peer RPC mesh
          |
          +-- signed node records
          +-- signed service records
          +-- signed introduction records
          +-- signed aliases with local identity pins
```

Bootstrap peers help a new node enter the mesh. They are not on every service
request and are not permitted to return a service host endpoint.

## Gap analysis

| Required capability | v0.3 status | Required implementation |
| --- | --- | --- |
| Real peer transport | Missing | Numeric TCP listeners with bounded timeouts and no hostname resolution |
| Mutual peer authentication | Missing | Wire v3 server authentication plus channel-bound Ed25519 peer proof |
| Versioned peer RPC | Missing | Strict authenticated binary envelope and state machine |
| Multiple bootstrap peers | Missing | Signed descriptor set, rotation, retry, and manual import |
| Persistent peer cache | Missing | Bounded atomic store with expiry and identity verification |
| WAN DHT | Modeled | Authenticated FIND_NODE, FIND_RECORD, STORE_RECORD and iterative quorum lookup |
| Relay cells | Missing | Uniform bounded cells, padding, fragmentation, reassembly, sequence checks |
| Multiplexing | Missing | Circuit and stream IDs with per-stream lifecycle |
| Flow control | Missing | Bounded queues, explicit receive windows, TCP backpressure |
| Real telescoping | Modeled | Incremental EXTEND where each relay learns only its next hop |
| Introduction delivery | Modeled | Long-lived outbound host introduction circuit and live request delivery |
| Rendezvous | Central compatibility relay | Opaque pairing of independently built multi-hop circuit halves |
| End-to-end service crypto | Implemented | Reuse wire v3 across the paired circuit stream |
| Dynamic application bridge | Partial | Bounded POST body support and safe content headers |
| Resource controls | Partial | Connections, streams, queues, memory, idle and handshake timeouts |
| Failure recovery | Missing | Alternate eligible peers, circuit teardown/rebuild, cache bootstrap |
| Process topology tests | Compatibility only | Separate bootstrap, relay, host, client, and backend processes |
| Packet/WAN evidence | Missing | Local process socket audit plus scripts for two physical networks |
| Browser distributed path | Missing | Select WAN resolver/client without weakening custom-scheme isolation |

## Implementation decisions

1. Keep wire v3 unchanged for hop handshakes and end-to-end service sessions.
2. Use TCP because it is available on Windows and Linux, works through outbound
   NAT/CGNAT policy, and adds no external runtime dependency.
3. Carry peer RPC in an authenticated binary envelope over wire v3 control
   frames. Canonical signed records remain their existing JSON representation.
4. Carry tunneled bytes in fixed-size cells over wire v3 data frames. Random
   padding is enabled; continuous cover traffic remains disabled.
5. Build paths incrementally. A relay receives only the descriptor of its next
   hop and never a route list.
6. Keep ordinary client and service nodes non-listening. Only explicitly
   enabled, reachable infrastructure nodes accept inbound peer connections.
7. Preserve the compatibility path for existing tests and local demo until the
   browser WAN path passes its own acceptance. It is not a fallback from a
   failed WAN route.
8. Treat a physical cross-ISP test as `UNVERIFIED` until it is actually run.

## Acceptance boundary

Local multi-process tests can prove socket topology, protocol behavior,
plaintext absence in captured relay payloads, DNS API non-use, fail-closed
errors, and process cleanup. They cannot prove resistance to a global passive
observer or establish physical WAN portability. Those residual claims remain
explicitly outside local PASS results.
