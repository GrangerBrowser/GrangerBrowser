# Routing

## Route shape

The implemented service path is composed from two independently established
halves:

```text
client -> entry -> middle -> rendezvous
                                    ^
                                    |
service -> service-entry -> middle -+
```

The host also maintains at least two service-entry/middle/introduction
circuits. Ordinary clients and services make outbound connections only.

## Selection

Candidate nodes come from authenticated distributed `FIND_NODE` queries. Every
descriptor is signature-, identity-, expiry-, capability-, reachability-, and
endpoint-validated before use.

Selection uses a domain-separated random target and XOR distance. A route:

- never repeats a node identity;
- requires the exact advertised role for each hop;
- prefers a different IPv4 /16 or IPv6 /32 network group for subsequent hops;
- reports `diversityRelaxed` when the prefix preference cannot be met;
- never treats an ordinary client or service as a relay automatically.

Network-prefix diversity is a limited heuristic. It does not establish
different operators, families, AS numbers, hosting providers, jurisdictions, or
failure domains.

## Telescoping

The endpoint connects only to the first relay. Circuit extension is incremental:

1. Authenticate the first relay using its signed descriptor and wire 3.
2. Ask it to extend to one next verified descriptor.
3. Create a fixed-cell stream through that hop.
4. Authenticate the next relay over that stream.
5. Repeat until the final introduction or rendezvous role is reached.

Each relay receives only its previous transport peer, its next node descriptor,
its local incoming/outgoing circuit IDs, and its current/next roles. It does not
receive the route list or opposite endpoint address.

## Recovery

Client connection attempts iterate bounded entry/middle candidates and exclude
failed identities. The service host rebuilds introduction and rendezvous paths
after route failure and refreshes descriptors before expiry. Discovery retries
multiple bootstrap peers and then valid cached peers.

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

Entry relays see their endpoint client. Service-entry relays see their endpoint
host. All relays see adjacent links, timing, direction, cell count, volume, and
session lifetime. Fixed cells and random in-cell padding do not hide flow timing
or total traffic. Cover traffic and periodic circuit rotation are not enabled.
