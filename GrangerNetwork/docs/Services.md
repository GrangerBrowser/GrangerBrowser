# Service Publishing

## Model

A service has a persistent Ed25519 identity and canonical cryptographic
`.granger` name. It publishes signed service and introduction records, creates
outbound relay circuits, and forwards decrypted application requests only to a
numeric loopback HTTP target.

Neither the service descriptor nor introduction descriptor contains the
backend, LAN, NAT, ISP, or public host endpoint.

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

The current application protocol supports bounded `GET`, `HEAD`, and `POST`
requests, response status/headers/body, multiple sequential requests, and
concurrent streams. The test forum exercises HTML, CSS, JavaScript, POST, and
readback. Responses are buffered with a 2 MiB limit; streaming downloads,
WebSocket, CONNECT, arbitrary TCP forwarding, and UDP are not implemented.

## Lifecycle

- Stopping the host tears down its circuits; client requests fail closed.
- Restarting with the same state preserves the service identity and canonical
  name, publishes refreshed descriptors, and creates new circuits.
- Expired service/introduction records are not accepted.
- Deleting the service identity creates a different service on re-init; it is
  not a recovery operation.
