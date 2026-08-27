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

## Resource limits

Node descriptors publish bounded relay policy. Runtime enforcement covers
connections, circuits, streams, bytes, token-bucket rate/burst, timeouts, and
bounded captures/diagnostics. Fixed cells use explicit stream receive windows
and TCP backpressure. Resource exhaustion resets the affected stream/circuit or
rejects the connection; it does not widen routing policy.

## Known metadata

Access relays see their directly connected endpoint. Client and service guards
see an access relay as their previous socket peer. All relays see adjacent
links, timing, direction, cell count, volume, and session lifetime. Fixed cells,
random in-cell padding and bounded cover cells do not hide all flow timing or
total traffic. Browser circuits rotate by age, request count, byte count and
degradation; existing streams drain on the old circuit. Dedicated cover
circuits are not implemented.
