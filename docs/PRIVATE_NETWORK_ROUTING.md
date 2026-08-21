# Private Network Routing

Granger Browser uses a process-wide local SOCKS gateway between Qt WebEngine
and its managed privacy-network backends. Chromium is configured to use only
that loopback gateway. Host resolution is delegated through the proxy and QUIC
is disabled, so removing or changing a backend does not expose a direct
WebEngine route.

## Backends

- Tor is the default preferred network and supports `.onion` plus clearnet.
- I2P uses bundled PurpleI2P i2pd 2.61.0 and supports `.i2p` destinations.
- The bundled I2P configuration has no verified clearnet outproxy. Clearnet is
  therefore blocked while I2P is the only active route.
- There is no Direct, No Proxy, or system-proxy user mode.

The Windows package uses Tor 0.4.9.11 from the official Tor Expert Bundle
15.0.20. The pinned archive SHA-256 is
`D59BFF934E3AD876E1623E24AE60C19AEEA56F50178093B9F86FBA230639F949`.
The build verifies its detached signature against Tor Browser Developers key
fingerprint `EF6E286DDA85EA2A4BA7DE684E2C6E8793298290`, then records hashes for
Tor, lyrebird 0.8.1, Conjure, `pt_config.json`, `geoip`, and `geoip6` in
`deployment-metadata.json`. The package retains the upstream Tor, lyrebird,
Conjure, libevent, OpenSSL, and zlib notices.

The native Linux x86_64 local RC uses Tor 0.4.9.11 and lyrebird 0.8.1 from the
signed Tor Expert Bundle 15.0.20. Its pinned archive SHA-256 is
`3B39A2A7FBF43EF28B9AE0A6AFCA02A12935232F81769E4FEF7472D6B5676EAF`.
The build validates the detached signature against the same Tor Browser
Developers primary fingerprint and records hashes for the Linux Tor,
lyrebird, Conjure, GeoIP, and transport configuration files.

The i2pd archive is the official Windows x64 MinGW release with SHA-256
`A0A8FB199A6BC5B487DF71567791DE6997050B921D65622EF9E936FFA88BC83F`.
It is licensed under BSD-3-Clause. Binaries and certificates are read from the
package; mutable router state is stored under the Granger user-data root.

The Linux local RC uses PurpleI2P's official Ubuntu Jammy amd64 package with
SHA-256
`09348999D4561C46037E3CC2AA2B9D76EC7AC3007DB2C1D4A9F92B20B9CA8687`.
The staged i2pd binary SHA-256 is
`252823E8F3DDE6232D2A178027D2A249AFA81B7A4595273BCDBE4CD3500852B1`.
Linux Tor and I2P mutable state follows the Granger XDG data root; neither
backend writes into the read-only AppImage mount or falls back to a system
installation.

### I2P naming and startup

Both `.b32.i2p` destinations and human-readable `.i2p` names are resolved by
i2pd. Granger never sends an I2P hostname to Windows or Linux system DNS, Tor
DNS, or a clearnet resolver. An unknown name therefore fails inside the I2P
backend.

On a new profile, Granger copies a compiled address-book bootstrap to the
writable I2P data directory before starting i2pd. The snapshot was retrieved
through I2P from the i2pd 2.61.0 default subscription at
`http://shx5vqsw7usdaunyzr2qmes2fq37oumybpudrd4jjj4e4vk4uusa.b32.i2p/hosts.txt`.
Its source-file SHA-256 is
`4EA21E8A9C631A60382DAF23BD90D0BAE0CAB742B93B21BBF3BD885F05F78000`.
It is used only when neither a persisted address book nor an existing
`hosts.txt` is present. i2pd then persists and updates the address book through
its normal `http://reg.i2p/hosts.txt` subscription. Installation files remain
read-only; address-book, NetDB, keys, tunnels, and logs remain in the Granger
user-data directory.

The startup states distinguish process launch, proxy availability, tunnel
construction, route verification, and address-book readiness. A router may
report `Firewalled` and still be usable for client browsing; that label alone
does not fail verification.

The official i2pd Windows archive includes a tray application. Granger starts
that unmodified binary on a dedicated, non-visible Windows desktop and
requests a normal window-message shutdown there. This keeps the bundled
backend visible in Task Manager while preventing its window, tray icon, and
startup notification from appearing on the user's desktop. The diagnostic web
console listens only on `127.0.0.1:19770` and is not opened automatically.

## Verification and failover

Opening a local proxy port is not sufficient to mark a backend connected. Tor
must pass its browser route check. I2P must carry a randomized self-hosted HTTP
probe through an actual `.b32.i2p` tunnel. Only then does the state machine mark
that route verified.

At process startup, WebEngine is assigned either the canonical loopback gateway
or a deliberately blocked loopback test gateway. Environment and command-line
Chromium proxy/resolver overrides are removed or rejected before QApplication
and WebEngine initialization. Offline tests therefore cannot create a direct
network path merely by disabling managed Tor.

When the active route is lost, the gateway first rejects new requests and
closes all current proxy sessions. The manager then checks the secondary
backend and only installs a new route policy after verification. If neither
backend is verified, the state is `NoPrivateRoute` and browsing stays blocked.
A recovery cooldown prevents immediate switching back and forth.

I2P health reports separate process exit, proxy loss, missing tunnels, probe
timeout, invalid probe response, destination unreachability, and recovery
verification. A single transient response does not revoke the last verified
route. Three consecutive probe failures close the route gate; a confirmed
proxy loss restarts i2pd immediately, while persistent tunnel/probe failures
must continue before a managed restart. Probe work from an older process
generation is discarded, so a late asynchronous result cannot overwrite the
state of a restarted backend.

Destination rules are independent of preference:

```text
.onion   -> verified Tor only
.i2p     -> verified I2P only
clearnet -> verified Tor only
otherwise blocked
```

The preferred network setting persists, with Tor used for existing profiles
that have no stored selection. Spaces keep their existing persistent storage
and privacy policy; route transitions invalidate network connections rather
than deleting user data.

## Scope

Tor and I2P have different threat models. This design reduces accidental direct
network exposure and standardizes the browser's routing boundary. It does not
promise anonymity, prevent host compromise, or eliminate traffic correlation.
