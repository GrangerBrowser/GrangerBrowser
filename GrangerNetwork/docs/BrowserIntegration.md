# Browser Integration

## Scope

Granger Browser integrates the Granger Network v0.4 WAN runtime through the
private `granger-network` Qt WebEngine scheme. This path owns only `.granger`.
It does not replace or modify ordinary, Tor, Onion, or I2P routing.

The browser requires an explicit valid WAN configuration for normal `.granger`
use. Missing or invalid configuration leaves the namespace unavailable. It does
not select the old local compatibility path or any direct network fallback.

## URL handling

Accepted address-bar forms are:

```text
forum.granger
<52-character-base32-service-id>.granger
http://forum.granger/path
https://forum.granger/path
```

The HTTP/HTTPS spellings are input compatibility only. They are intercepted
before WebEngine performs ordinary resolution and rewritten internally to:

```text
granger-network://forum.granger/path
```

The private scheme is registered before `QApplication` with host syntax and a
secure origin model. It is separate from the `granger:` internal-action scheme.
Ports, credentials, multiple labels, Unicode names, malformed paths, and
unsupported methods are rejected.

## Runtime process

The Qt scheme handler starts `granger_network.browser_gateway` as a child
`QProcess` on first use. Communication is bounded newline-delimited JSON over
anonymous stdin/stdout pipes. The helper receives no service endpoint and
exposes no loopback listener or generic proxy port.

Normal WAN startup passes one explicit config path. The config references a
signed bootstrap set, an authority-key pin, optional local alias pins, route
attempt count, quorum policy, and timeout. Relative paths are resolved inside
the config directory and may not escape it.

The child runtime persists a network-scoped peer cache and signed reseed
generations next to its identity. Diagnostics expose aggregate network health
(`OFFLINE`, `BOOTSTRAPPING`, `JOINING`, `CONNECTED`, `DEGRADED`, or
`RESEEDING`) without service browsing details. Retry reuses the same identity
and valid cache; it never switches transports.

The packaged browser uses its app-local Python and `cryptography` runtime.
Source-tree runtime discovery and explicit test arguments are development-only
paths. Browser shutdown closes the pipe, waits for active requests, closes
cached WAN sessions, and terminates the helper. Acceptance checks for orphan
gateway processes.

## Request bridge

The request envelope contains:

- validated `.granger` destination;
- bounded ASCII origin-form path/query;
- `GET`, `HEAD`, or `POST`;
- bounded selected headers;
- a body of at most 2 MiB;
- a random request identifier.

The gateway resolves signed WAN records, builds a private route, and reuses a
bounded service session where valid. It uses a bounded worker executor; no idle
polling or direct HTTP client exists. The service-side bridge can connect only
to a numeric loopback HTTP target.

Responses are bounded to 2 MiB. Qt custom-scheme replies are surfaced with
WebEngine status 200; the original backend status is preserved in
`X-Granger-Status`. The browser acceptance uses this header to verify a real
POST returning 201 and subsequent readback.

## Navigation and origin policy

| Source | Destination | Result |
| --- | --- | --- |
| Address bar/top-level | Valid `.granger` | Allow through Granger Network |
| `.granger` document | Same-origin GET/HEAD/POST | Allow |
| `.granger` document | Another `.granger` subresource/fetch/form | Block |
| `.granger` document | Clearnet, Onion, I2P, WebSocket, file, internal URL | Block |
| Non-`.granger` document | Embedded `.granger` resource/frame | Block |
| `.granger` document | Non-network `data:`, `blob:`, safe `about:` use | Allow under WebEngine policy |

Top-level navigation between `.granger` services is an explicit origin change.
Same-origin forms may use GET or POST. External and cross-service POST are
blocked before their body can leave the origin. CSP limits connections and form
actions to the current origin.

Every normal, private, Tor, Onion, Space, isolated, and internal WebEngine
profile receives the same `.granger` request interceptor and scheme handler.
WebEngine profile boundaries add the existing Space/isolated-tab separation.

## Failures

The handler returns a same-origin error document with a bounded category such
as service not found, identity verification failed, network unavailable,
connection expired, or replay rejected. It does not include private keys,
cookies, raw descriptors, local paths, session IDs, endpoints, or exception
details.

A failed `.granger` operation is terminal. It never retries through DNS, Direct,
system proxy, Tor DNS, I2P naming, clearnet HTTP, or the compatibility
rendezvous.

## Verified behavior

The local Qt WebEngine acceptance covers:

- alias and canonical address-bar input;
- HTTP/HTTPS interception before ordinary resolution;
- HTML, CSS, JavaScript, image, fetch, link, history, reload and same-origin
  form behavior;
- POST body delivery, backend status propagation, and readback;
- origin storage behavior supported by the current custom scheme;
- cross-service and cross-network blocking;
- invalid/missing WAN config failure;
- DNS/UDP counters and endpoint socket topology;
- relay-capture plaintext markers;
- gateway shutdown and zero orphan processes.

The physically independent WAN and packet-capture acceptance is **UNVERIFIED**.
No anonymity claim follows from local browser tests.
