# Application Hosting Boundary

Granger Hosting has two persisted service modes:

- `static` serves an immutable, inspected publication snapshot;
- `local-application` forwards bounded HTTP requests to one trusted numeric
  loopback target.

The browser path is:

```text
Qt WebEngine: http://service.granger/
  -> Chromium-internal *.granger resolver rule
  -> authenticated 127.0.0.1 Granger HTTP gateway
  -> GrangerNetworkRuntime worker
  -> authenticated Granger application circuit
  -> WanApplicationServer
  -> LoopbackHttpBridge
  -> 127.0.0.1:<owner-configured application port>
```

The custom `granger-network://` URL remains a compatibility input and is
canonicalized to the HTTP origin before navigation. It is not used to claim
native application semantics. Qt's custom-scheme request-job API cannot expose
arbitrary native HTTP status or Chromium-managed HTTP cookies.

## Browser-owned gateway

The gateway binds only numeric IPv4 loopback on an OS-assigned port. Chromium
maps only `*.granger` to that port; a catch-all resolver failure rule prevents
system DNS fallback. The normal private SOCKS route remains in force for every
other hostname.

At startup the browser creates a 32-byte random capability. The request
interceptor adds it only to valid `.granger` HTTP requests. The gateway rejects
requests without the capability and strips it before application transport.
The value is absent from URLs, DOM, JavaScript, cookies, application headers,
logs, and diagnostics. The gateway is not a generic HTTP or SOCKS proxy.

The gateway keeps its assigned port across an in-process restart because the
Chromium resolver rule is fixed at process startup. If the port is occupied,
restart fails closed instead of selecting another interface or port.

## Application semantics

Chromium receives a normal HTTP/1.1 response and therefore owns:

- native response status;
- redirects and method conversion;
- cookies and Fetch credentials modes;
- same-origin policy, CORS, cache, localStorage, and IndexedDB;
- profile, container, and isolated-tab storage boundaries.

The transport preserves repeated response fields, including multiple
`Set-Cookie` lines. Granger does not implement an application cookie jar and
does not add Cookie headers outside Chromium's normal policy.

The HTTP origin is intentionally not treated as a Secure Context. Secure
cookies and `SameSite=None` cookies lacking Secure are rejected by Chromium;
Service Worker is unsupported. HTTPS certificate checks are not bypassed and
no private CA is silently installed.

## Bounds and failure policy

Requests support GET, HEAD, POST, PUT, PATCH, DELETE, and OPTIONS. Request and
response bodies are bounded to 2 MiB. Header count/value size, connections,
pending requests, concurrent application streams, and stage timeouts are
bounded. WebSocket, SSE streaming, HTTP/2, and HTTP/3 are not added here.

Only local owner configuration may select the upstream. It must be numeric
loopback; hostnames, LAN, VPN, wildcard, and public targets are rejected without
DNS. Client, relay, circuit, node, forwarding, gateway-capability, and backend
path metadata are not forwarded.

Unknown services, gateway failure, backend refusal, timeout, malformed
responses, and resource-limit failures terminate locally. They do not select
DNS, direct Internet, Tor, I2P, LAN, or static fallbacks.

## Acceptance

Run:

```text
python GrangerNetwork/tests/browser_acceptance_harness.py \
  --browser <GrangerBrowser executable> \
  --qt-bin <Qt bin directory> \
  --output <report.json> \
  --require-application-semantics
```

The gate executes inside the real Qt WebEngine process and checks native
statuses, methods, bodies, response fields, redirects, XHR, Chromium cookies,
credentials omission, origin/cache/profile isolation, gateway authorization,
gateway restart/port collision, browser restart persistence, DNS/direct escape
probes, encrypted relay capture, and orphan cleanup.
