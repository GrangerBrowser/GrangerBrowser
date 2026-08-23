# Granger Network v0.1

Granger Network is an experimental private namespace and protocol prototype. It
maps cryptographic service identities to `.granger` names, authenticates a
service with Ed25519, and carries application messages over an encrypted
X25519/ChaCha20-Poly1305 channel.

Version 0.1 is deliberately local. Its only transport is numeric loopback TCP,
and its service bridge can reach only numeric loopback HTTP endpoints. It is not
integrated into Granger Browser, does not provide anonymity, and is not a public
network or a replacement for DNS.

## Components

- `granger-host`: creates a service identity and exposes a local HTTP service.
- `granger-client`: imports signed descriptors and fetches a `.granger` page.
- `LocalResolver`: resolves canonical identity addresses and local aliases
  without DNS or a network fallback.
- `ClientTransport`: the transport boundary used by the loopback prototype and
  intended for future private transport adapters.

The implementation uses the Python `cryptography` package. It does not
implement cryptographic primitives itself.

## Setup

Python 3.11 or newer is required for this standalone prototype.

```powershell
cd C:\path\to\GrangerBrowser\GrangerNetwork
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
```

On Linux or macOS, activate the environment with `source .venv/bin/activate`.

## One-command demo

The demo starts an HTTP page on `127.0.0.1:8080`, creates `test.granger`, starts
the encrypted service host, fetches the page, and shuts everything down:

```powershell
python examples/run_demo.py
```

## Manual example

Start the sample website:

```powershell
python -m http.server 8080 --bind 127.0.0.1 --directory examples/site
```

Create an identity-bound service and install the local `test.granger` alias:

```powershell
granger-host init `
  --state-dir demo-state/service `
  --listen-port 7777 `
  --registry demo-state/client `
  --alias test.granger
```

Start the service host:

```powershell
granger-host serve `
  --state-dir demo-state/service `
  --upstream http://127.0.0.1:8080
```

Fetch through Granger Network from another terminal:

```powershell
granger-client fetch test.granger `
  --registry demo-state/client `
  --output fetched.html
```

The `init` command prints the canonical identity address. `test.granger` is a
local convenience alias; the canonical 52-character address is derived from
the Ed25519 public key.

## Tests

Without installing the package, run:

```powershell
$env:PYTHONPATH=(Resolve-Path src)
py -3 -m unittest discover -s tests -v
```

The suite checks descriptor signatures, identity mismatch rejection, encrypted
wire frames, fail-closed resolution, loopback-only policy, and an end-to-end
`test.granger` fetch while system hostname-resolution APIs are blocked.

## Documents

- [Architecture](docs/Architecture.md)
- [Protocol](docs/Protocol.md)
- [Threat model](docs/ThreatModel.md)
- [Address format](docs/AddressFormat.md)

## Prototype limits

- Localhost transport only; no peer discovery or remote overlay routing.
- No browser integration, HTML security model, or navigation interception.
- No client authentication, authorization policy, persistence service, or key
  rotation protocol.
- No traffic-analysis resistance, padding, cover traffic, or availability
  protection.
- Local aliases depend on the integrity of the user's local registry.
- Tests block common DNS APIs and record socket destinations; they are not a
  packet-capture proof for every operating system.
