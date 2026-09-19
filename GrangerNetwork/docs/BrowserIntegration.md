# Browser Integration

## Scope

Granger Browser integrates the Granger Network v0.4 WAN runtime as normal
Chromium `http://<service>.granger/` origins routed through a browser-owned
numeric-loopback gateway. This path owns only `.granger`. It does not replace
or modify ordinary, Tor, Onion, or I2P routing.

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

Every accepted form is canonicalized before ordinary navigation to:

```text
http://forum.granger/path
```

`https://` and the legacy `granger-network://` form are compatibility inputs;
they do not enable HTTPS or a Secure Context. Ports, credentials, multiple
labels, Unicode names, malformed paths, and unsupported methods are rejected.

Chromium's resolver maps only `*.granger` to the browser's OS-assigned
`127.0.0.1` gateway port and maps every unmatched resolver request to failure.
The operating-system resolver is never used for this namespace. A failed
internal route has no DNS or direct fallback.

## Runtime process

When a valid production WAN configuration is installed, the Qt profile handler
starts `granger_network.browser_gateway` as a child `QProcess` immediately.
Compatibility and local-demo modes retain request-driven startup. Communication
is bounded newline-delimited JSON over anonymous stdin/stdout pipes. The Python
helper receives no service endpoint and exposes no listener. The separate C++
HTTP gateway listens only on `127.0.0.1`, requires a 32-byte ephemeral browser
capability, accepts only `.granger` Host values, and is not a generic proxy.

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

## Browser peer contribution

The WAN gateway also starts `BrowserPeerRuntime` with a separate persistent
relay identity stored under `browser-peer/relay-identity.json`. The discovery
client seed in `client-identity.json` is used only for local guard preference
and is not reused as the public browser-relay identity. Its default role is a
bounded outbound-only middle relay. It does not open a public listener,
discover a public address, invoke DNS, or request router configuration.

The runtime maintains two authenticated one-shot sessions to a verified
reachable entry/discovery node. Each session carries a signed adjacency descriptor and a
`REVERSE_REGISTER` request. The entry may use that already-established channel
to extend one circuit through the browser peer. The browser then uses the normal
wire-3 node and fixed-cell forwarding implementation to connect to the next
verified hop. A consumed or failed slot is replenished with bounded exponential
backoff. Node identity persists across reconnect and anchor changes; adjacency
descriptors are short-lived.

Default browser relay limits are four circuits, four connections, 32 streams,
16 MiB per circuit, and 256 KiB/s. A shared 16 MiB budget bounds queued cell
receive payloads across the node's multiplexers. This is not an RSS limit:
Python objects, crypto frames, socket buffers, and other runtime allocations
remain outside that payload budget. Diagnostics report aggregate adjacency, circuit, byte, reconnect,
and failure counters. No payload, private key, or private local endpoint is
added to diagnostics.

An operator may explicitly enable a high TCP listener port with
`GRANGER_BROWSER_RELAY_PORT`. Public mode requires matching numeric source
observations and successful authenticated callbacks from at least two distinct
verified discovery peers. The browser cannot vote for itself. The candidate
descriptor must already be served during its renewal callback; publication
follows proof. Failed proofs fall back to restricted relay participation,
not direct browsing. Active restricted adjacencies do not suppress the public
retry deadline. Public identity and endpoint are intentionally discoverable in
this opt-in mode; two peer identities do not prove independent operators.

Public reprobes default to five minutes, retries to one minute. Restricted
reconnects use bounded exponential backoff with deterministic per-identity
jitter. Stop clears readiness and prevents a second supervisor from starting
while the preceding supervisor or adjacency workers are still stopping.

## Request bridge

The request envelope contains:

- validated `.granger` destination;
- bounded ASCII origin-form path/query;
- `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, or `OPTIONS`;
- bounded selected headers;
- a body of at most 2 MiB;
- a random request identifier.

The gateway resolves signed WAN records, builds a private route, and reuses a
bounded service session where valid. Sessions rotate after 10 minutes, 128
requests, 64 MiB, or transport failure. At most 16 service circuits remain in
the cache; the oldest inactive entry is closed first, and a full cache of
active entries fails closed. It uses a bounded worker executor; no idle polling
or direct HTTP client exists. The service-side bridge can connect only to a
numeric loopback HTTP target.

Responses are bounded to 2 MiB. Approved application headers, including
repeated fields, are transported. The loopback gateway returns the backend
status, headers, and body as HTTP/1.1, so Chromium owns native status,
redirects, cookies, credentials modes, CORS, cache, and origin storage. No
manual browser cookie jar exists. The browser's CSP, no-referrer, nosniff, and
denied-device policies remain a minimum restriction; an application's CSP may
add restrictions.

## Navigation and origin policy

| Source | Destination | Result |
| --- | --- | --- |
| Address bar/top-level | Valid `.granger` | Allow through Granger Network |
| `.granger` document | Same-origin GET/HEAD/POST/PUT/PATCH/DELETE/OPTIONS | Allow |
| `.granger` document | Another `.granger` subresource/fetch/form | Block |
| `.granger` document | Clearnet, Onion, I2P, WebSocket, file, internal URL | Block |
| Non-`.granger` document | Embedded `.granger` resource/frame | Block |
| `.granger` document | Non-network `data:`, `blob:`, safe `about:` use | Allow under WebEngine policy |

Top-level navigation between `.granger` services is an explicit origin change.
Same-origin forms may use GET or POST and same-origin fetch may use every
supported method. External and cross-service requests are blocked before their
body can leave the origin. CSP limits connections and form actions to the
current origin.

Every normal, private, Tor, Onion, Space, isolated, and internal WebEngine
profile receives the same `.granger` request interceptor. WebEngine profile
boundaries retain the existing Space/isolated-tab cookie and storage
separation.

## Failures

The gateway returns a same-origin error document with a bounded category such
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
- JSON, form, multipart, text and binary body delivery;
- GET/HEAD/POST/PUT/PATCH/DELETE/OPTIONS and native backend statuses;
- 302/303/307/308 redirect method behavior;
- Chromium-managed repeated Set-Cookie, HttpOnly, Path, expiry, deletion,
  SameSite, Secure rejection, and all Fetch credentials modes;
- XHR status, response headers, CSP, CORS, binary upload/download;
- database-backed thread/reply persistence through the local application;
- cookie, localStorage, IndexedDB, network-cache, container, and isolated-tab
  boundaries;
- cross-service and cross-network blocking;
- unauthenticated loopback denial, gateway failure/recovery, fixed-port
  collision failure, and browser-restart persistence;
- invalid/missing WAN config failure;
- DNS/UDP counters and endpoint socket topology;
- relay-capture plaintext markers;
- gateway shutdown and zero orphan processes.

The physically independent WAN and packet-capture acceptance is **UNVERIFIED**.
No anonymity claim follows from local browser tests.
