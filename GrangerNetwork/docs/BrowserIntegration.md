# Browser integration

## Status and scope

The current repository integrates Granger Network v0.2 into the browser and the
canonical local Windows build. It is not present in a public installer,
AppImage, release ZIP, tag, or GitHub release.

This layer does not route ordinary, `.onion`, or `.i2p` browsing. It only owns
the `.granger` namespace and fails closed when its runtime, registry,
descriptor, rendezvous, service identity, handshake, or encrypted channel is
unavailable.

## URL semantics

Users enter an alias or canonical identity address directly:

```text
test.granger
<52-character-base32-service-id>.granger
```

`http://` and `https://` spellings are accepted only as input compatibility.
They are intercepted before standard resolution and do not mean HTTP or HTTPS
transport. The browser converts them to this non-user-facing URL:

```text
granger-network://test.granger/path?query
```

The scheme is registered before `QApplication` with host syntax, secure-context,
Fetch API, and service-worker flags. It is deliberately separate from the
existing `granger:` internal-action scheme. Ports, credentials, multiple host
labels, malformed names, and methods other than GET/HEAD are rejected.

## WebEngine bridge

Every normal, private, Tor, Onion, Space, isolated, and internal WebEngine
profile receives the same scheme-handler implementation. A request carries only:

- a validated single-label `.granger` destination;
- a bounded ASCII origin-form path and query;
- GET or HEAD;
- bounded `Accept`, `Accept-Language`, and `User-Agent` values;
- a random request identifier.

The handler starts `granger_network.browser_gateway` as a child `QProcess` on
first use. Communication uses the process's anonymous stdin/stdout pipes. There
is no loopback port, LAN listener, capability exposed in a process argument, or
general proxy API. The helper removes proxy environment variables, disables
Python hostname-resolution APIs, and uses the existing numeric-endpoint Granger
transport. Browser shutdown closes the pipe and terminates the helper; the
acceptance harness also checks its PID after browser exit.

The canonical local package carries the required Python and `cryptography`
runtime under `runtime/python`. The browser prefers that signed app-local
runtime, starts it with isolated path handling, and removes Python environment
overrides. Source-tree discovery and explicit runtime arguments remain available
only for development and tests when the app-local runtime is absent.

For double-click verification, the app-local runtime exposes `test.granger` as
an ephemeral demonstration service only when no explicit registry was supplied.
It runs through the existing identity descriptor, encrypted handshake, and
numeric-loopback service transport. The alias never enters DNS and its generated
identity is intentionally not stable across helper restarts. Explicit registries
used by real services and acceptance tests are never replaced by the demo.

## Origin and storage model

Host syntax preserves separate Chromium origins:

```text
granger-network://forum.granger
granger-network://docs.granger
```

The Windows Qt 6.11.2 acceptance verifies isolation for localStorage and
IndexedDB, same-origin fetches, relative resources, and service workers. The
tested Qt build does not expose cookies or the Cache API for this custom scheme;
those capabilities are reported as unsupported instead of being simulated on a
shared localhost origin. WebEngine profile boundaries still provide the normal
additional isolation for Spaces and isolated tabs.

## Request policy

| Source | Destination | Policy |
| --- | --- | --- |
| Address bar or top-level navigation | valid `.granger` | Allow through Granger Network only |
| Same `.granger` origin | relative/same-origin `.granger` resource | Allow |
| One `.granger` origin | another `.granger` embedded resource, fetch, XHR, or frame | Block |
| `.granger` document | clearnet, `.onion`, `.i2p`, WebSocket, file, or internal URL | Block |
| Non-`.granger` document | embedded `.granger` resource or frame | Block |
| `.granger` document | `data:`, `blob:`, or `about:` non-network content | Allow |

Top-level navigation between two `.granger` services is allowed as a visible
origin change. GET forms remain inside the same service. POST forms fail closed
because v0.2 carries no request body. CSP additionally limits connections and
form actions to the current origin. No failed request falls back to DNS, Tor
DNS, I2P naming, the system resolver, Direct, or clearnet.

## Failures

The browser shows a same-origin internal response with one safe category:

- Service not found;
- Identity verification failed;
- Network unavailable;
- Connection expired;
- Connection replay rejected.

Descriptor content, private keys, relay credentials, local paths, session IDs,
and raw exception messages are never included in the page.

## Verified local behavior

The real Qt WebEngine acceptance covers alias and canonical address-bar input,
`http://`/`https://` interception, HTML, CSS, JavaScript, image and fetch
resources, links, GET forms, history, back/forward, reload, two-origin storage,
service workers, cross-network blocking, error rendering, zero helper DNS calls,
zero escape-probe connections, relay-wire plaintext markers, and zero orphan
gateway processes.

This is local regression evidence. A physically independent WAN endpoint and a
packet capture on a second machine remain unverified. The rendezvous still sees
both peers' IP addresses, timing, sizes, and service/session metadata; browser
integration does not provide anonymity.
