# Bootstrap and reseed

## Purpose

Bootstrap is a first-contact mechanism. It is not a service directory, traffic
proxy, DNS replacement, or mandatory participant in later `.granger` requests.
After a node has authenticated other discovery peers, its DHT operations use
those peers and its persistent cache even if every initial seed goes offline.

A completely fresh node cannot discover an overlay without at least one known
reachable peer or an authentic reseed bundle. If every candidate is
unreachable, the runtime returns `NETWORK_UNAVAILABLE`; it never tries DNS,
clearnet, Tor, I2P, multicast, or a direct service connection.

## Signed formats

`BootstrapSet` version 2 binds all of the following to an Ed25519 authority
signature:

- network ID and protocol version;
- monotonic generation;
- issue and expiry times;
- between 2 and 64 signed node descriptors.

Node descriptor version 3 binds the node identity, numeric TCP endpoint,
capabilities, reachability, resource policy, network ID, protocol version, and
expiry to the node's Ed25519 signature. Production and development network
descriptors cannot be mixed. Legacy bootstrap sets are rejected unless a
caller explicitly enables migration mode; normal browser runtime does not.

The endpoint is never trusted merely because it appeared in JSON. The root
signature, node signature, identity-derived node ID, schema, lifetime,
capabilities, network, protocol, endpoint, and duplicate constraints are all
checked before dialing.

## First-contact order

The runtime performs two bounded phases:

1. Try up to eight valid cached discovery peers.
2. If quorum is not reached, try up to eight current signed seed descriptors.
3. Dial at most four candidates concurrently.
4. Request a bounded authenticated `PEER_SAMPLE`.
5. Accept only valid signed descriptors for the active network and protocol.
6. Expand the routing view through bounded parallel `FIND_NODE` requests.

Stale cache entries cannot prevent the signed seed phase. Failure of seed A is
not a network failure while another authenticated candidate remains available.

## Persistent peer cache

The cache is an atomic schema-versioned JSON file containing public node data
only:

- signed descriptor and descriptor expiry;
- last seen and last successful connection;
- bounded success/failure counters;
- up to four authenticated source labels.

It does not contain private keys, service names, browsing history, request
content, or plaintext traffic. The cache is capped at 512 peers, 64 accepted
descriptors per source, and 32 entries per IPv4 `/24` or IPv6 `/48`. Duplicate
endpoints, invalid signatures, expired descriptors, wrong networks, and
malformed entries are dropped. A corrupt outer cache is ignored and reported;
it never enables a fallback transport.

These limits reduce trivial cache poisoning and eclipse concentration. They do
not solve Sybil attacks, identify common operators, or prove ASN/geographic
diversity.

## Reseed store

`ReseedStore` supports up to eight explicitly pinned authorities. Bundles are
verified before installation, written atomically, and tracked by generation
and canonical digest. Rollback and same-generation equivocation are rejected
per authority. Up to four recent files per authority are retained.

The current runtime supports bundled and manually imported signed bundles. It
does not fetch remote URLs itself, so there is no hidden DNS or clearnet path.
Future download transports may provide bytes from independent sources, but the
bytes remain untrusted until the pinned Ed25519 signature verifies.

Manual import and inspection:

```powershell
python tools\reseed_tool.py `
  --store C:\granger\client\reseed `
  --authority-pin C:\granger\trust\operator-a.pin `
  --authority-pin C:\granger\trust\operator-b.pin `
  import --bundle C:\granger\incoming\bootstrap-set.json

python tools\reseed_tool.py `
  --store C:\granger\client\reseed `
  --authority-pin C:\granger\trust\operator-a.pin `
  --authority-pin C:\granger\trust\operator-b.pin `
  list
```

Export active signed public bundles for another operator or test client:

```powershell
python tools\reseed_tool.py `
  --store C:\granger\client\reseed `
  --authority-pin C:\granger\trust\operator-a.pin `
  export --destination C:\granger\export
```

Raw IP imports are not supported. Adding a new authority pin is an explicit
trust decision and must use an authenticated channel.

## Provisioning and rotation

Create independently reachable bootstrap node descriptors, then sign a set on
a controlled authority machine:

```powershell
tools\wan-test\provision-bootstrap.ps1 `
  -AuthorityState C:\granger\authority\identity.json `
  -Descriptor C:\granger\seed-a.json,C:\granger\seed-b.json,C:\granger\seed-c.json `
  -Bundle C:\granger\distribution\bootstrap-set.json `
  -AuthorityPin C:\granger\distribution\bootstrap-authority.pin `
  -Generation 7 `
  -Lifetime 21600
```

Before expiry, issue fresh node descriptors and a strictly newer bundle
generation. Never distribute the authority private identity, node private
identities, or service identities with a client package. A browser package may
contain public authority pins and a signed bundle only.

## Evidence boundary

The automated local topology proves multiple seed handling, authenticated peer
exchange, DHT join, warm-cache operation after all initial seeds stop, and
fresh-profile fail-closed behavior. It does not prove public reachability,
operator independence, or cross-ISP portability. No public Granger seed/relay
fleet exists in this local stage.
