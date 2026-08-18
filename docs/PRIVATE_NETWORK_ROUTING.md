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

The i2pd archive is the official Windows x64 MinGW release with SHA-256
`A0A8FB199A6BC5B487DF71567791DE6997050B921D65622EF9E936FFA88BC83F`.
It is licensed under BSD-3-Clause. Binaries and certificates are read from the
package; mutable router state is stored under the Granger user-data root.

## Verification and failover

Opening a local proxy port is not sufficient to mark a backend connected. Tor
must pass its browser route check. I2P must carry a randomized self-hosted HTTP
probe through an actual `.b32.i2p` tunnel. Only then does the state machine mark
that route verified.

When the active route is lost, the gateway first rejects new requests and
closes all current proxy sessions. The manager then checks the secondary
backend and only installs a new route policy after verification. If neither
backend is verified, the state is `NoPrivateRoute` and browsing stays blocked.
A recovery cooldown prevents immediate switching back and forth.

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
