# Threat Model

## Security goals for v0.1

- Bind a canonical `.granger` address to an Ed25519 service identity.
- Detect modified service descriptors and endpoint substitution.
- Authenticate the service before application requests are transmitted.
- Encrypt and authenticate application messages on the Granger protocol leg.
- Keep every v0.1 socket destination on numeric loopback.
- Reject non-`.granger`, unknown, malformed, or unsupported destinations without
  DNS or clearnet fallback.
- Limit the service's HTTP upstream to numeric loopback.

## Considered attackers

### Transport interceptor

An attacker who can observe or modify the local transport can see handshake
metadata, timing, and sizes. Transcript signatures prevent impersonation of the
expected identity, and AEAD detects application-frame modification. The attacker
can still block, delay, replay entire connection attempts, or perform traffic
analysis.

### Modified descriptor

Changing the identity, service identifier, host, port, or version invalidates
the descriptor signature. A canonical address also requires the public-key hash
to match its label.

### Malicious service

A correctly identified service controls its page content and can return hostile
HTML. The prototype is a transport and identity layer, not a browser sandbox or
content sanitizer. Clients must not treat identity authentication as content
safety.

### Malicious local alias mapping

A user-installed alias is not self-authenticating. An attacker able to modify
the local registry can repoint `test.granger` to another valid canonical service.
Canonical addresses avoid this alias ambiguity, but local filesystem integrity
remains required.

## Leak and fallback analysis

The resolver parses `.granger` names locally and does not call DNS APIs. The
loopback transport receives a validated numeric IP and creates an AF_INET or
AF_INET6 socket directly. The HTTP bridge applies the same numeric-loopback
rule. There is no code path from resolution failure to system DNS, an HTTP
library URL fetch, or a direct public socket.

Tests replace common Python hostname-resolution APIs with failing stubs and
record every client and bridge `connect()` destination during the end-to-end
case. This is useful regression coverage, not a universal packet-level proof.

## Metadata

No public IP address is placed in an address or protocol message in v0.1. Since
both endpoints are local processes, the observed socket peer is loopback. This
does not yet solve IP-metadata exposure for a future remote overlay; that design
must be evaluated independently before such a transport is enabled.

The service public key is visible in the handshake. Packet lengths, timing, and
connection attempts are also visible. There is no service-identity hiding,
padding, cover traffic, or correlation resistance.

## Out of scope

- Anonymity, onion routing, or resistance to a global observer.
- Remote peer discovery, routing, relays, NAT traversal, and availability.
- A global human-readable naming or ownership system.
- Protection after local administrator, process, registry, or private-key
  compromise.
- Browser integration, same-origin policy, script isolation, and phishing UI.
- Client authentication and authorization.
- Key rotation, revocation, backup, and recovery.
- Side-channel and denial-of-service resistance.

## Fail-closed rule

Any validation, identity, handshake, transport, or upstream-policy failure ends
the request. Adding a future transport must not turn an unsupported or failed
route into DNS, clearnet HTTP, or a direct IP connection.
