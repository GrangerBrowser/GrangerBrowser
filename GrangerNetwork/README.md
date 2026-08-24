# Granger Network v0.2

Granger Network is a standalone experimental private namespace and overlay
protocol prototype. A canonical `.granger` address is derived from an Ed25519
service identity. The client and service host each connect out to a rendezvous
and never connect to one another directly. New remote descriptors use wire 3,
which hardens the authenticated handshake, key lifecycle, and encrypted frame
format without changing discovery or routing behavior.

The current source tree includes a local development integration with Granger
Browser. It is not included in a public installer or release, is not a public
network, and does not provide anonymity. A rendezvous can observe both peers'
network addresses and traffic metadata even though it cannot read authenticated
application messages.

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

## Remote prototype

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
authenticated out-of-band channel. v0.2 has no distributed discovery service.
The service host still exposes no HTTP listener and requires no direct client
route or port forwarding.

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

The suite includes a real three-process host/relay/client case, descriptor
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

## Documents

- [Architecture](docs/Architecture.md)
- [Protocol](docs/Protocol.md)
- [Threat model](docs/ThreatModel.md)
- [Address format](docs/AddressFormat.md)
- [Browser integration](docs/BrowserIntegration.md)
- [Cryptographic benchmark](docs/CryptographicBenchmark.md)

## Prototype limits

- The discovery registry and rendezvous bootstrap are configured locally.
- The relay learns client and host network addresses, service and session IDs,
  connection timing, duration, and byte counts.
- There is one relay hop, no onion routing, relay federation, path selection,
  padding, cover traffic, or traffic-correlation resistance.
- Traffic keys rotate within wire 3 sessions, but relay authentication, client
  authentication, authorization, long-term identity rotation and revocation,
  persistence, multiplexing, and denial-of-service controls are not complete.
- Browser integration is source-only development functionality and has not been
  added to a public installer, AppImage, or release archive.
- Qt WebEngine 6.11.2 exposes separate localStorage and IndexedDB origins and
  supports service workers for the registered scheme. Its cookie and Cache APIs
  are unavailable for this custom scheme in the tested Windows build.
- Local aliases rely on local registry integrity; canonical addresses remain
  self-authenticating.
