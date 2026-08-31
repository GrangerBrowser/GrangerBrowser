# Operations

## Deployment roles

Reachable infrastructure may opt into one or more roles: `bootstrap`,
`discovery`, `access`, `entry`, `middle`, `service-relay`, `introduction`, and
`rendezvous`. Ordinary clients and service hosts are not listeners or relays by
default.

A useful test network needs at least two bootstrap/discovery nodes and enough
distinct access, guard, middle, introduction, and rendezvous identities to
create client and service paths after one failure. One machine can run multiple
test processes, but that does not provide operator or network independence.

## Node state

Each node state directory contains a private identity, signed descriptor, and
relay policy. Generate state with `granger_network.node init` or the wrappers in
`tools/wan-test`. Do not share identity files. Public descriptor files may be
distributed to bootstrap provisioners and peer operators.

Descriptors expire. Current scripts default physical-test descriptors to 24
hours and bootstrap bundles to 6 hours. Rotation is an operator task; the
runtime fails closed after expiry.

Bootstrap sets carry a monotonic generation. Clients reject a lower generation
after accepting a newer one and reject different content at the same generation.
Use `tools/reseed_tool.py` for explicit signed bundle import, inspection, and
export. The tool never accepts a raw endpoint as a trust substitute.

## Starting nodes

For a persistent physical bootstrap/relay, use `granger_network.operator` or
the generated `output/granger-node-linux` package. The operator keeps the
local listener outside the signed descriptor, so a node behind NAT can bind
`0.0.0.0:62441` while advertising a forwarded public endpoint such as
`203.0.113.20:62441`. It reuses the current peer RPC, wire-v3, DHT, relay,
reseed, descriptor, and identity implementations.

The first start creates the private Ed25519 node identity in the operator state
directory and exports only its signed public descriptor. A valid public
`BootstrapSet` still requires at least two independent reachable seed
descriptors. Do not weaken this requirement or duplicate one operator merely
to satisfy the seed count.

Windows:

```powershell
tools\wan-test\run-relay.ps1 `
  -StateDir C:\granger\middle-a `
  -ListenHost 203.0.113.30 -ListenPort 18441 `
  -Capability middle,discovery `
  -PeerDescriptor C:\granger\peers\seed-a.json
```

Linux:

```bash
tools/wan-test/run-relay.sh \
  --state-dir /srv/granger/middle-a \
  --listen-host 203.0.113.30 --listen-port 18441 \
  --capability middle --capability discovery \
  --peer-descriptor /srv/granger/peers/seed-a.json
```

Replace documentation addresses with actual numeric reachable addresses.
Configure host firewalls explicitly. The tools do not open ports with UPnP or
NAT-PMP.

## Limits

Set `max-connections` and `max-circuits` according to available memory and
bandwidth. Signed relay policy also bounds streams, byte accounting, rate,
burst, idle timeout, and connection timeout. Rejections should be monitored by
category, not worked around by enabling direct transport.

The Linux systemd unit uses `MemoryHigh=128M` and `MemoryMax=160M`.
The soft threshold must leave room for the warm interpreter, cryptographic
backend, peer cache, and active circuits. A threshold below the working set
can stall authenticated handshakes even when TCP connect succeeds and the
process remains active. Raising the soft threshold does not remove the hard
memory limit or the signed connection, circuit, and stream limits.

For a slow node, inspect the unit's `MemoryCurrent`, `MemoryHigh`, and
`MemoryMax`, then its cgroup `memory.events` and `memory.pressure`. Increasing
`high` events and sustained full memory pressure distinguish reclaim stalls
from a merely reachable TCP listener. Compare authentication from the node
itself with authentication from the remote client before attributing a
failure to an ISP or VPN. See the
[kernel cgroup memory documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html#memory-interface-files).

## Diagnostics and captures

`granger_network.node run` supports:

- `--ready-file`: bounded JSON process/endpoint readiness;
- `--diagnostics`: bounded JSONL event categories and counters;
- `--capture`: up to 8 MiB of forwarded relay payload bytes for plaintext tests.

The OS packet wrappers use PktMon on elevated Windows and tcpdump on Linux.
Diagnostics and captures may expose public relay endpoints, timing, volume, and
operational topology. Restrict access and remove them after analysis.

## Health checks

Operators should monitor:

- process readiness and clean shutdown;
- descriptor and bootstrap expiry;
- listener reachability from an independent network;
- authentication, quorum, route, circuit, and resource-limit errors;
- connection/circuit counts and sustained byte rates;
- unexpected DNS, UDP, or direct endpoint traffic in packet capture;
- stale or orphan processes after restart.

Client diagnostics expose only bounded network health metadata:
`OFFLINE`, `BOOTSTRAPPING`, `JOINING`, `CONNECTED`, `DEGRADED`, or
`RESEEDING`, plus aggregate peer/DHT counters and a short failure category.

`WanDiscoveryClient.first_contact_diagnostics()` returns at most 32 local
records for the current join attempt. Records contain an operation ID,
monotonic timing, public node ID, stage, attempt count, configured timeout,
and a fixed reason code. TCP, authentication, and peer-sample failures remain
distinct; unavailable private ingress and missing seed sources retain their
own health reasons. These diagnostics do not change retry or trust policy.

Do not log private identities, channel keys, introduction cookies, application
bodies, or endpoint addresses across the client/service boundary.

## Incident response

On suspected relay compromise, remove its descriptor from new bootstrap sets
and peer distributions, rotate any colocated identities, and rebuild circuits.
On service identity compromise, create a new service identity and redistribute
the canonical name through an authenticated channel. There is no implemented
global revocation service.

On bootstrap-authority compromise, create a new authority and distribute its
pin through a trusted out-of-band channel. Merely publishing a new pin beside an
untrusted bundle does not restore trust.

## Release status

No public seed fleet or v0.4 public release is created by this development
stage. Physical cross-network operation must be accepted using
[WAN-Test.md](WAN-Test.md) before production claims.
