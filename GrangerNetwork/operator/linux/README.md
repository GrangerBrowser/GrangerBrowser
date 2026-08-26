# Granger Network Debian operator package

This directory runs the current Granger Network wire-v3 node implementation as
an opt-in bootstrap, discovery, and bounded relay. It is not a mock node and it
does not implement a second protocol.

## Target

- Debian Linux x86_64 with glibc 2.28 or newer;
- CPython 3.11 through 3.14;
- `python3-venv` for the first local setup;
- inbound TCP port 62441 forwarded to the node.

The package contains an offline wheelhouse. Setup does not download Python
packages. Linux execution and public reachability remain unverified until the
operator runs the commands on the physical Debian machine.

## Router

Forward public TCP port 62441 to `192.168.110.166:62441`. Do not forward UDP.
The signed node descriptor advertises `95.182.105.239:62441`; the process binds
locally to `0.0.0.0:62441`.

## First start

Transfer this complete directory to Debian, enter it, and run:

```bash
chmod +x granger-node *.sh
./start-granger-node.sh
```

The first start creates `state/node-identity.json` with mode 0600. Back up that
file securely. Losing it changes the node identity; disclosing it lets another
party impersonate the node. The public signed descriptor is exported to
`public/node-descriptor.json` and never contains the private key.

Check process and listener state:

```bash
./status-granger-node.sh
sudo ss -lntp | grep 62441
```

Stop cleanly:

```bash
./stop-granger-node.sh
```

State, peer cache, DHT records, and identities survive restart. Starting the
node renews a descriptor that is expired, near expiry, or inconsistent with the
current operator config while retaining the same Ed25519 identity. A changed
descriptor must be included in the next signed bootstrap generation.

## First-node boundary

One node can listen as a first bootstrap and relay, but a valid Granger
`BootstrapSet` intentionally requires at least two independent reachable seed
descriptors. The first node alone does not prove a healthy DHT or public WAN.
Do not replace the second descriptor with another process under the same
operator merely to satisfy the count.

After a second independent operator supplies its public descriptor, create the
signed public bundle:

```bash
./create-public-bootstrap.sh \
  --generation 1 \
  --peer-descriptor /trusted/path/second-node-descriptor.json
./verify-public-bootstrap.sh
```

Public outputs are:

- `public/node-descriptor.json`;
- `public/bootstrap-set.json`;
- `public/bootstrap-authority.pin`;
- `public/browser-wan.json`;
- `public/config-authority.pin`;
- `public/bootstrap-manifest.json`.

Private bootstrap and browser-config authority identities stay under
`private/authorities/`. Never distribute that directory. Verify authority pins
through an authenticated out-of-band channel before a Windows client trusts
the bundle.

## Windows provisioning

Copy the complete `public` directory to the Windows machine. After independently
verifying `config-authority.pin`, run from PowerShell:

```powershell
.\windows\install-granger-bootstrap.ps1 `
  -BrowserExe 'C:\path\to\GrangerBrowser.exe' `
  -PublicBundle 'C:\path\to\verified\public' `
  -ExpectedConfigAuthorityPin '<OUT-OF-BAND-VERIFIED-PIN>'
```

The browser validates the signed browser config, bootstrap signature, each node
descriptor, network ID, protocol version, generation, and expiry. Failure is
closed; there is no DNS, clearnet, Tor, I2P, or direct-service fallback for a
`.granger` request.

## Resource policy

`config/granger-node.json` signs and enforces bounded connection, circuit,
stream, bandwidth, burst, per-circuit byte, timeout, and memory-budget values.
Relay participation is explicit in the capability list. Edit limits before the
first start or restart to issue a fresh descriptor with the same identity.
