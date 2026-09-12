# Routing

## Route shape

The implemented service path is composed from two independently established
halves:

```text
client -> access -> stable guard -> middle -> rendezvous
                                              ^
                                              |
service -> access -> stable service guard -> middle
```

The host also maintains at least two access/service-guard/middle/introduction
circuits. Ordinary clients and services make outbound connections only. The
access relay is the only overlay role that directly accepts the endpoint TCP
connection; the next guard sees the access relay, not the endpoint address.

## Selection

Candidate nodes come from authenticated distributed `FIND_NODE` queries. Every
descriptor is signature-, identity-, expiry-, capability-, reachability-, and
endpoint-validated before use.

Selection uses a domain-separated random target and XOR distance. A persistent
endpoint identity deterministically prefers a stable guard, while bounded
retries distribute attempts across other eligible access relays and guards. A
route:

- never repeats a node identity;
- requires the exact advertised role for each hop;
- prefers a different IPv4 /16 or IPv6 /32 network group for subsequent hops;
- reports `diversityRelaxed` when the prefix preference cannot be met;
- never treats an ordinary client or service as a relay automatically.

An ordinary browser gateway explicitly opts in to the `middle` role with a
signed short-lived adjacency descriptor. Such a descriptor is eligible only
when it immediately follows its named reachable anchor. It cannot be selected
as the first hop or for access, guard, discovery, introduction, rendezvous, or
service-relay roles.

Network-prefix diversity is a limited heuristic. It does not establish
different operators, families, AS numbers, hosting providers, jurisdictions, or
failure domains.

## Telescoping

The endpoint connects only to the access relay. Circuit extension is incremental:

1. Authenticate the first relay using its signed descriptor and wire 3.
2. Ask it to extend to one next verified descriptor.
3. Create a fixed-cell stream through that hop.
4. Authenticate the next relay over that stream.
5. Repeat until the final introduction or rendezvous role is reached.

For a directly reachable next hop, the current relay opens a new TCP connection
as before. For an adjacency descriptor, the named anchor consumes a previously
authenticated outbound session registered by that peer. The restricted peer
then accepts `OPEN_CIRCUIT` over this channel and dials the following verified
hop outbound. No unsolicited inbound connection to the restricted peer is
required.

Each extension authenticates with a per-hop ephemeral identity. Each relay
receives only its previous transport peer, its next node descriptor, its local
incoming/outgoing circuit IDs, and its current/next roles. It does not receive
the route list, persistent endpoint identity, service destination, or opposite
endpoint address.

## Recovery

Client connection attempts iterate bounded access/guard/middle candidates and
exclude failed identities. The service host rebuilds introduction and
rendezvous paths after route failure and refreshes descriptors before expiry.
Direct first contact is restricted to signed reseed/bootstrap candidates. Once
joined, peer exchange and DHT operations use verified private overlay routes;
valid cached peers permit startup after the original seeds disappear.

Recovery is always another verified overlay route. There is no service endpoint
in discovery, no direct dial API, and no DNS, clearnet, Tor, I2P, LAN, or
compatibility-rendezvous fallback.

Private discovery retries at most 12 routes. Queued candidates are rechecked
against failures learned by concurrent requests before each new attempt.
Intermediate extension failures enter a bounded, descriptor-versioned cooldown
for the directed role edge, not a global exclusion of either peer. An exhausted
FIND_NODE search retains a 60-second retry window, including searches exhausted
before the terminal hop. Record RPCs and other roles remain eligible. Expired live-view
descriptors are excluded even if they remain in memory. Each role's search
set is capped at 32 candidates, sampled across advertised network groups when
larger, bounding enumeration to 32 cubed combinations. Four distinct node
identities and adjacent-middle binding remain mandatory. These are local
selection heuristics, not operator-independence or Sybil guarantees.

## Resource limits

Node descriptors publish bounded relay policy. Runtime enforcement covers
connections, circuits, streams, bytes, token-bucket rate/burst, timeouts, and
bounded captures/diagnostics. Fixed cells use explicit stream receive windows
and TCP backpressure. Resource exhaustion resets the affected stream/circuit or
rejects the connection; it does not widen routing policy.

Receive payload budgets are shared across a node's multiplexers. Each source
has at most 32 simultaneous connections and 4096 RPCs per minute across
reconnects, in addition to global policy and per-connection RPC limits. Source
accounting retains only transient keyed hashes, not persistent raw addresses.
Several users behind one NAT share this source limit. It is not protection
against distributed bandwidth exhaustion or attackers with many source IPs.

Reverse adjacencies are bounded globally and per identity, are one-shot, expire
with their descriptor, and are advertised only while a live slot is available.
They are not persisted in the peer cache or treated as DHT storage nodes.
Direct discovery does not return adjacency descriptors; a requester must first
use a private access/guard/middle discovery route.

The browser isolates cached application circuits by normalized service name.
A circuit rotates after 10 minutes, 128 requests, 64 MiB, or transport failure;
at most 16 service circuits are retained. Repeated assets for one origin may
therefore remain linkable by timing on that circuit, while unrelated services
do not share the same end-to-end service session.

## Known metadata

Access relays see their directly connected endpoint. Client and service guards
see an access relay as their previous socket peer. All relays see adjacent
links, timing, direction, cell count, volume, and session lifetime. Fixed cells,
random in-cell padding and bounded cover cells do not hide all flow timing or
total traffic. Browser circuits rotate by age, request count, byte count and
degradation; existing streams drain on the old circuit. Dedicated cover
circuits are not implemented.
