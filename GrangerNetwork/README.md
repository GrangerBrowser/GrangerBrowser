# Granger Network v0.3

Granger Network is a standalone experimental private namespace and privacy-
overlay prototype. A canonical `.granger` address is derived from an Ed25519
service identity. v0.3 adds signed peer identities, replicated DHT-like record
discovery, service introduction points, and a local multi-hop transport
simulation. The earlier rendezvous path remains for browser compatibility.

The current source tree includes a local development integration with Granger
Browser. It is not included in a public installer or release, is not a public
network, and does not provide anonymity. The distributed path is not yet wired
to the browser. Its source tests establish endpoint-separation and fail-closed
invariants over local socket pairs, not WAN anonymity.

## Components

- `granger-host`: creates a service identity and exposes a numeric-loopback HTTP
  application through either the legacy local transport or a rendezvous.
- `granger-client`: verifies a signed descriptor and fetches a `.granger` page.
- `granger-rendezvous`: pairs an outbound host connection with an outbound
  client connection and forwards opaque bytes.
- `DiscoveryProvider`: separates identity discovery from transport bootstrap.
- `GrangerTransport`: connects by cryptographic destination ID; a returned
  session provides `send`, `receive`, and `close` operations.
- `LocalResolver`: a file-backed experimental discovery provider that never
  delegates `.granger` names to DNS.
- `GrangerNode`: an explicitly enabled, signed, resource-limited peer runtime.
- `DistributedDiscoveryNetwork`: a bounded replicated signed-record store
  using XOR-distance placement.
- `DistributedResolver`: resolves canonical identities, pinned aliases, node
  descriptors, and service introduction points without DNS.
- `OverlayRoutePlanner` and `MultiHopCircuit`: build distinct entry, middle,
  introduction, host-middle, and service-relay paths from independent wire 3
  sessions.
- `granger-browser-gateway`: a browser-owned stdio adapter that accepts only
  bounded `.granger` GET/HEAD requests and invokes the existing resolver and
  client. It has no listening socket or general-purpose proxy interface.

Wire 3 uses Ed25519 service authentication, hybrid ephemeral X25519 plus
ML-KEM-768 key exchange, HKDF-SHA256, HMAC-SHA256 key confirmation, and
ChaCha20-Poly1305 from the Python `cryptography` package. The implementation
does not implement cryptographic primitives itself. Ed25519 is not
post-quantum, so this hybrid key exchange must not be described as complete
post-quantum authentication.

## Setup

Python 3.11 or newer is required.

```powershell
cd C:\path\to\GrangerBrowser\GrangerNetwork
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
```

On Linux or macOS, activate the environment with `source .venv/bin/activate`.

## Rendezvous compatibility prototype

The following local three-terminal example uses separate processes. The relay
address is transport bootstrap data, not a service address. `test.granger` is a
local alias for the generated identity-bound canonical address.

Start the relay:

```powershell
granger-rendezvous --listen-host 127.0.0.1 --listen-port 7788
```

Create a remote descriptor and install it in the test client registry:

```powershell
granger-host init-remote `
  --state-dir demo-state/service `
  --rendezvous-id demo-relay `
  --rendezvous-host 127.0.0.1 `
  --rendezvous-port 7788 `
  --registry demo-state/client `
  --alias test.granger `
  --title "Example service"
```

Start the local application and service host:

```powershell
python -m http.server 8080 --bind 127.0.0.1 --directory examples/site
granger-host serve `
  --state-dir demo-state/service `
  --upstream http://127.0.0.1:8080
```

Fetch through the rendezvous from the client terminal:

```powershell
granger-client fetch test.granger `
  --registry demo-state/client `
  --output fetched.html
```

For experiments on separate machines, configure the same numeric rendezvous
endpoint on host and client and transfer the signed descriptor through an
authenticated out-of-band channel. The service host still exposes no HTTP
listener and requires no direct client route or port forwarding. This CLI path
does not exercise the v0.3 distributed transport.

## Local compatibility demo

The v0.1 numeric-loopback profile remains available for regression testing:

```powershell
python examples/run_demo.py
```

## Tests

Without installing the package, run:

```powershell
$env:PYTHONPATH=(Resolve-Path src)
py -3 -m unittest discover -s tests -v
```

The suite includes a real three-process host/relay/client compatibility case,
distributed signed-record replication, pinned aliases, introduction points,
multi-hop construction, relay resource limits, descriptor
tampering and expiry checks, authenticated-suite downgrade attempts, handshake
tampering, identity substitution, key separation and rekeying, stale-session,
replay, out-of-order, oversized, modified-frame, and nonce-exhaustion checks,
DNS API blocking, recorded socket destinations, and a relay-wire plaintext
marker check.

These checks are useful regression evidence, not a packet-level proof on every
operating system.

Build the browser development target and run the real Qt WebEngine integration
acceptance with:

```powershell
$env:PYTHONPATH=(Resolve-Path GrangerNetwork/src)
python GrangerNetwork/tests/browser_acceptance_harness.py `
  --browser build/desktop/Release/GrangerBrowser.exe `
  --qt-bin C:/Qt/6.11.2/msvc2022_64/bin `
  --output output/granger-network-browser-acceptance.json
```

The harness creates two identity-bound services behind a rendezvous and opens
them through the real browser. It does not represent an independent WAN test.
It verifies compatibility only; the distributed transport is not integrated
with Qt WebEngine in v0.3.

## Cryptographic benchmark

Run the same-process comparison between compatibility wire 2 and hybrid wire 3
with:

```powershell
$env:PYTHONPATH=(Resolve-Path src)
python benchmarks/crypto_benchmark.py
```

The benchmark reports handshake latency, Python allocation peak, and encrypted
frame throughput. It is a local engineering comparison, not a cross-platform
performance guarantee. See [Cryptographic benchmark](docs/CryptographicBenchmark.md)
for the recorded environment, method, and interpretation.

## Distributed overlay benchmark

Run the local multi-hop setup and throughput baseline with:

```powershell
$env:PYTHONPATH=(Resolve-Path src)
python benchmarks/overlay_benchmark.py
```

The benchmark reports eleven independent wire 3 bindings, circuit setup
latency, payload throughput, and the relay plaintext-marker check. It also
records that padding, uniform frames, batching, and cover traffic are disabled.
See [Distributed overlay benchmark](docs/DistributedOverlayBenchmark.md).

## Documents

- [Architecture](docs/Architecture.md)
- [Protocol](docs/Protocol.md)
- [Threat model](docs/ThreatModel.md)
- [Address format](docs/AddressFormat.md)
- [Browser integration](docs/BrowserIntegration.md)
- [Cryptographic benchmark](docs/CryptographicBenchmark.md)
- [Distributed overlay benchmark](docs/DistributedOverlayBenchmark.md)

## Prototype limits

- Distributed discovery and multi-hop routing are in-process simulations with
  no WAN peer RPC, persistence, authenticated bootstrap, or listener.
- Distinct relay identities are enforced, but operator and network diversity,
  Sybil resistance, churn, revocation, and availability are unsolved.
- A single modeled relay does not see both endpoint addresses or application
  plaintext. Colluding relays and global observers can correlate timing and
  sizes.
- There is no padding, cover traffic, batching, congestion control,
  multiplexing, or traffic-correlation resistance.
- Relay authentication, client authentication, authorization, long-term
  identity rotation, and denial-of-service controls are incomplete.
- Browser integration is source-only development functionality and has not been
  added to a public installer, AppImage, or release archive.
- Qt WebEngine 6.11.2 exposes separate localStorage and IndexedDB origins and
  supports service workers for the registered scheme. Its cookie and Cache APIs
  are unavailable for this custom scheme in the tested Windows build.
- Distributed aliases require a local identity pin; canonical addresses remain
  self-authenticating.
