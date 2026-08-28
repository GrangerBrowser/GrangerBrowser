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

## Distributed public router

For a fleet with one persistent router identity per physical VPS, install the
same package independently on every host. Generate each identity on its own
host and use the same TCP port on distinct public addresses:

```bash
sudo ./install-public-router.sh \
  --node-name node-b \
  --public-ip 198.51.100.20 \
  --port 62441
```

The first pass intentionally starts without reseed material and exports only
`/var/lib/granger-node/public/node-b/node-descriptor.json`. Collect those public
descriptors through authenticated SSH, create one signed bootstrap generation
with the existing authority, then install the verified public bundle on every
router:

```bash
sudo /opt/granger-node/install-public-router.sh \
  --node-name node-b \
  --public-ip 198.51.100.20 \
  --port 62441 \
  --public-bootstrap /root/verified-public-bootstrap
```

The installer validates the signatures before activation, keeps the identity
under `/var/lib/granger-node`, and preserves the previous public bundle as a
rollback copy. It never creates or distributes bootstrap authority keys.

## Public single-host smoke topology

For a controlled public deployment, the package includes a systemd template
and an installer for four isolated logical routers on one Debian host. This is
the minimum functional topology for the current client and service route shape,
but it provides no physical-host, operator, network-prefix, or ASN diversity.
It must be described as a **SINGLE-PHYSICAL-HOST TEST TOPOLOGY**, not as an
anonymous or production deployment.

Run as root with an explicitly verified public IPv4 address:

```bash
./install-public-test-topology.sh \
  --public-ip 203.0.113.20 \
  --base-port 62441 \
  --nodes 4
```

The installer creates the non-login `granger` user, installs the offline
runtime under `/opt/granger-node`, writes root-controlled configuration under
`/etc/granger-node`, and keeps node and authority private keys under
`/var/lib/granger-node`. Each router has a separate identity, state directory,
TCP listener, and `granger-node@.service` instance. The public browser bundle
is written to `/var/lib/granger-node/public-bundle`; only that directory may be
copied to clients.

Check or stop the topology with:

```bash
./status-public-test-topology.sh
sudo ./stop-public-test-topology.sh
```

`install-granger-firewall.sh` installs a live nftables allowlist for SSH and
the selected Granger TCP range. Open a second SSH connection after applying it
and before configuring persistent nftables loading. Provider-side firewall
rules remain a separate operator responsibility.

## Router

Before first start, replace the RFC 5737 example address `203.0.113.20` in
`config/granger-node.json` with the router's independently verified public
address. Forward TCP port 62441 to the operator-selected LAN host and do not
forward UDP. Keep private LAN addresses and unpublished operator endpoints in a
local configuration outside source control. The process binds locally to
`0.0.0.0:62441`.

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
`BootstrapSet` intentionally requires at least two reachable seed descriptors.
Independent physical operators remain required for real path diversity. The
four-process deployment above is permitted only as a controlled functional
smoke topology and does not prove decentralization, anonymity, or resilience
against the host operator.

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
The `access` capability is the endpoint-facing first hop; `entry` and
`service-relay` guards are reached through it.
