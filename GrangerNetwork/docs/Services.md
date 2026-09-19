# Service Publishing

## Model

A service has a persistent Ed25519 identity and canonical cryptographic
`.granger` name. It publishes signed service and introduction records, creates
outbound relay circuits, and forwards decrypted application requests only to a
numeric loopback HTTP target.

Neither the service descriptor nor introduction descriptor contains the
backend, LAN, NAT, ISP, or public host endpoint.

The browser-managed workflow, static-file policy, and on-disk lifecycle are
documented in [Hosting.md](Hosting.md).

## Create from Granger Browser

Open `Settings -> Granger Network -> Sites & Hosting`, choose `Static website`
or `Local application`, validate the source, then select `Publish service`.
The displayed canonical address is an identity-derived service name, not a DNS
registration. `Open` navigates to the service's normal `.granger` HTTP origin,
which Chromium maps only to the authenticated browser-owned loopback gateway;
it never opens the source folder or backend localhost address.

## Initialize a service

```powershell
$env:PYTHONPATH = "$PWD\src"
python -m granger_network.wan_host init `
  --state-dir C:\granger\forum `
  --title "Private forum"
```

The command prints the canonical name and creates private identity state plus a
signed service descriptor. Protect `service-identity.json`; its compromise
permits service impersonation.

## Serve a loopback application

Start the application on numeric loopback, for example `127.0.0.1:8080`, then:

```powershell
python -m granger_network.wan_host serve `
  --state-dir C:\granger\forum `
  --bootstrap C:\granger\config\bootstrap-set.json `
  --authority-pin C:\granger\config\bootstrap-authority.pin `
  --upstream 127.0.0.1:8080 `
  --introduction-points 2 `
  --minimum-introduction-points 2
```

The host selects introduction and rendezvous infrastructure, publishes records
to a verified quorum, establishes its outbound circuits, and refreshes service
and introduction state before expiry. Startup fails if the minimum independent
introduction paths or a distinct rendezvous cannot be built.

The loopback bridge accepts only numeric loopback targets. Hostnames, wildcard,
LAN, public, Unix-domain, and non-loopback targets are rejected.

## Open from a client

Canonical names need no alias:

```powershell
python -m granger_network.wan_client fetch `
  abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst.granger `
  --state-dir C:\granger\client `
  --bootstrap C:\granger\config\bootstrap-set.json `
  --authority-pin C:\granger\config\bootstrap-authority.pin `
  --path /
```

A human-readable alias requires a local pin:

```text
--alias-pin forum.granger=<52-character-service-id>
```

The client verifies the signed alias record and the independent local pin. It
never sends the alias to DNS.

## Application behavior

The current application protocol supports bounded `GET`, `HEAD`, `POST`, `PUT`,
`PATCH`, `DELETE`, and `OPTIONS` requests, response status/headers/body,
multiple sequential requests, and concurrent streams. JSON, form, multipart,
text, binary, cookie headers, and application security headers are
preserved within the approved header policy. Requests and responses are
buffered with a 2 MiB limit; streaming downloads, WebSocket, SSE, CONNECT,
arbitrary TCP forwarding, and UDP are not implemented.

The browser-owned HTTP gateway preserves native status, redirects, response
headers, and Chromium cookie/credentials semantics. It does not implement a
manual cookie store. See
[ApplicationHostingBoundary.md](ApplicationHostingBoundary.md).

The browser-managed loopback bridge strips client/network forwarding headers.
It supplies the canonical `.granger` name as `Host` and does not supply client,
relay, node, circuit, DHT, or Granger session identity headers. Applications
use cookies or application accounts for session state. A backend may store
SQLite, uploads, or other mutable state in its own data directory; that state
is never placed in the browser release directory or service descriptor.

## Lifecycle

- Stopping the host tears down its circuits; client requests fail closed.
- Restarting with the same state preserves the service identity and canonical
  name, publishes refreshed descriptors, and creates new circuits.
- Expired service/introduction records are not accepted.
- Deleting the service identity creates a different service on re-init; it is
  not a recovery operation.
