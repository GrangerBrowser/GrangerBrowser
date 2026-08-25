# Granger Network v0.4

Granger Network is an experimental private overlay and `.granger` namespace.
Services are identified by Ed25519 keys, discovered through signed replicated
records, and reached through separate client and service relay circuits. A
service may expose a loopback HTTP application without publishing its backend
address to clients.

This repository does not claim anonymity. Local multi-process tests verify the
implemented routing and fail-closed invariants. A physical Windows-to-Linux,
cross-network test has not yet been completed and is explicitly **UNVERIFIED**.

## Implemented path

```text
CLIENT
  -> client entry -> client middle -> rendezvous
                                      ^
                                      |
HOST -> service entry -> service middle
```

The host also maintains at least two independent outbound introduction
circuits. The client learns signed introduction identities and opaque tokens,
not the host endpoint. The host receives a signed rendezvous grant, not the
client endpoint. Client and host establish a separate wire-3 encrypted session
through the rendezvous before application data is exchanged.

## Components

- `granger_network.node`: authenticated bootstrap, discovery and opt-in relay
  runtime over real TCP sockets.
- `granger_network.peer_rpc`: bounded, versioned and sequenced peer RPC over a
  wire-3 secure channel.
- `granger_network.wan_discovery`: signed DHT record publication and lookup,
  replication quorum, persistent peer cache and multiple bootstrap seeds.
- `granger_network.circuit`: telescoping multi-hop circuit construction.
- `granger_network.cells`: fixed 1024-byte padded cells, multiplexed streams,
  flow control and batches of at most 64 cells.
- `granger_network.wan_service`: introduction, rendezvous and end-to-end
  service sessions.
- `granger_network.wan_host`: service publication, multiple introduction
  circuits and descriptor refresh.
- `granger_network.browser_gateway`: bounded stdio bridge used by Qt WebEngine.
- `granger/network/GrangerNetworkRuntime.cpp`: browser custom-scheme handler
  for `granger-network://<name>.granger/`.

## Requirements

- Python 3.11 or later
- `cryptography>=47`
- Numeric relay/bootstrap endpoints; the resolver never calls DNS
- At least two signed bootstrap seeds
- Reachable infrastructure nodes for bootstrap and relay roles

Ordinary clients and service hosts use outbound connections only. They do not
need public inbound ports. Infrastructure operators must provide genuinely
reachable TCP endpoints; the protocol does not use UPnP, NAT-PMP, STUN, ICE,
multicast or mDNS.

## Development setup

From `GrangerNetwork`:

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -e .
.venv\Scripts\python -m unittest discover -s tests -v
```

On Debian:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/python -m unittest discover -s tests -v
```

## Real-socket acceptance

The acceptance harness creates separate identities, state roots, ports and OS
processes for three bootstrap nodes, discovery nodes, client entries, five
middle relays, two service entries, two introduction points, a rendezvous,
host, clients, a loopback forum and optionally Granger Browser:

```powershell
$env:PYTHONPATH = "$PWD\src"
python tools\wan_process_acceptance.py `
  --work-dir ..\output\granger-network\wan-acceptance `
  --report ..\output\granger-network\wan-acceptance.json
```

With the locally built Qt browser:

```powershell
python tools\wan_process_acceptance.py `
  --work-dir ..\output\granger-network\wan-browser `
  --report ..\output\granger-network\wan-browser.json `
  --browser ..\build\desktop\Release\GrangerBrowser.exe `
  --qt-bin C:\path\to\Qt\6.11.2\msvc2022_64\bin
```

The test checks HTML, CSS, JavaScript, POST/readback, multiple clients, host
offline/restart, middle and entry replacement, bootstrap loss, cached-peer
startup, no fresh-profile fallback, DNS/UDP calls, endpoint socket sets,
plaintext relay captures and orphan processes.

## Benchmarks

Real local socket path:

```powershell
$env:PYTHONPATH = "$PWD\src"
python benchmarks\wan_benchmark.py --iterations 7 --output wan-benchmark.json
```

Logical discovery and circuit-state scale:

```powershell
python benchmarks\wan_scale_benchmark.py --operations 32 --output wan-scale.json
```

The scale benchmark exercises 100, 500 and 1000 signed discovery peers plus
100, 500, 1000, 5000 and 10000 real `GrangerNode` circuit-accounting states.
It is not a claim that 1000 independent WAN processes were run.

## Physical WAN preparation

Cross-platform scripts are in `tools/wan-test`:

- `run-bootstrap.ps1` / `run-bootstrap.sh`
- `run-relay.ps1` / `run-relay.sh`
- `run-test-host.ps1` / `run-test-host.sh`
- `run-test-client.ps1` / `run-test-client.sh`
- `capture-network.ps1` / `capture-network.sh`
- `provision-bootstrap.ps1` / `provision-bootstrap.sh`

See [WAN-Test.md](docs/WAN-Test.md) for the exact Windows and Debian plan.

## Browser configuration

Normal browser WAN mode requires an explicit signed configuration. Missing or
invalid configuration leaves `.granger` unavailable; it does not select the
local compatibility transport and never falls back to clearnet, Tor or I2P.

```json
{
  "aliasPins": {},
  "authorityPin": "bootstrap-authority.pin",
  "bootstrap": "bootstrap-set.json",
  "minimumReplicas": 2,
  "replicationFactor": 3,
  "routeAttempts": 6,
  "timeoutSeconds": 8,
  "version": 1
}
```

Paths are relative to the configuration directory and may not escape it.
Canonical cryptographic names do not require aliases. Human-readable aliases
are local identity pins, not global DNS.

## Security boundary

- `.granger` is intercepted before system DNS.
- No route means `NETWORK_UNAVAILABLE`; there is no direct client-to-host path.
- The local backend accepts only numeric loopback addresses.
- Only GET, HEAD and same-origin POST are carried by the browser bridge.
- Cross-service requests and `.granger` requests from clearnet origins are
  blocked.
- Relay payload captures must not contain known HTML, HTTP or test-message
  markers.
- Endpoint IPs remain visible to their first relays and to local/ISP observers.
- Colluding first relays or a global observer can perform traffic correlation.

## Documents

- [Architecture](docs/Architecture.md)
- [Protocol](docs/Protocol.md)
- [Threat model](docs/ThreatModel.md)
- [Browser integration](docs/BrowserIntegration.md)
- [Bootstrap operations](docs/Bootstrap.md)
- [Routing](docs/Routing.md)
- [Service publishing](docs/Services.md)
- [Operations](docs/Operations.md)
- [Physical WAN test](docs/WAN-Test.md)
- [Pre-v0.4 WAN audit](docs/WANAudit.md)

## Current limitations

- Physical cross-ISP and Windows-to-Debian behavior is **UNVERIFIED**.
- No public bootstrap/relay fleet is shipped in this local development stage.
- Bootstrap bundles and node descriptors require operator rotation before
  expiry; automatic authority distribution is not implemented.
- Traffic timing, volume and session duration remain observable.
- Cover traffic and periodic circuit rotation are not enabled.
- Responses are buffered up to bounded limits; streaming large files and
  WebSocket integration are not implemented.
- Qt custom schemes expose successful fetches as status 200. The original
  backend status is available as `X-Granger-Status`.
