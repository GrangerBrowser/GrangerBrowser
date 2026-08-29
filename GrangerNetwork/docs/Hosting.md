# Sites and Hosting

## Browser workflow

Granger Browser exposes hosting controls at:

```text
Settings -> Granger Network -> Sites & Hosting
```

A user can publish either a static directory or a numeric-loopback HTTP
application. Creation generates a persistent Ed25519 service identity and its
canonical identity-derived `.granger` name. The service host then publishes
signed service and introduction descriptors through the configured discovery
quorum and builds outbound service circuits.

The feature requires a valid signed WAN configuration shared by participating
clients and hosts. Without one, the UI reports `Network unavailable` and stays
fail-closed. It does not try DNS, clearnet, Tor, I2P, UPnP, NAT-PMP, or a direct
client-to-host connection.

## Static websites

The native Qt folder picker passes an absolute path only to the local hosting
runtime and local service configuration. Privacy Preflight resolves and scans
that path without following symlinks, junctions, or reparse points, checks
canonical containment and readability, and enforces file-count and per-file
limits. UNC roots and path escapes fail closed. A root `index.html` is selected
automatically. If it is absent and more than one HTML file exists, the user must
choose an entry page before publication; that choice is persisted with the
service identity.

Preflight builds a filtered, atomic publication snapshot. It recursively omits
version-control metadata, common IDE/cache directories, project documentation,
debug output, logs, temporary files, and editor backups. High-confidence secret
filenames, private-key markers, and local-user path disclosures block
publication instead of being silently omitted. The UI separates exclusions from
blocking findings and has no "publish anyway" path. The authoring directory is
never modified.

There is no extension whitelist. WASM, binary resources, and unknown legitimate
asset types are retained unless a specific privacy or filesystem rule blocks
them. Request paths are percent-decoded once, interpreted as POSIX origin paths,
resolved to canonical snapshot targets, and checked against the snapshot root.
Traversal and directory listing are not implemented.

The static bridge implements GET and HEAD. POST returns `405`. Known web MIME
types use a fixed table; other types use Python's standard MIME database and
fall back to `application/octet-stream`.

## Local applications

Dynamic hosting accepts only `http://127.0.0.1:<port>` or numeric IPv6
loopback. The target must be reachable when the service is created or edited.
Hostnames, LAN addresses, wildcard binds, and public endpoints are rejected
without DNS lookup.

The bridge carries bounded GET, HEAD, and POST requests. Its allowlist excludes
`Forwarded`, `X-Forwarded-For`, `X-Real-IP`, relay metadata, and arbitrary
client headers. For each end-to-end rendezvous session, the application server
generates an opaque `X-Granger-Session` value and overwrites any client input
before the loopback request. This is not a network address or stable user ID.

## Storage and lifecycle

Per-service state is stored below the browser data root:

```text
granger-network/services/<random-id>/
  config.json
  identity/
    service-identity.json
    network-identity.json
  metadata/
    service-descriptor.json
    introduction-descriptor.json
    introduction-sequence.txt
    peer-cache.json
    reseed/
    status.json
  publication/
    current/
      content/
      manifest.json
```

Configuration, identities, status, and sequence updates use same-directory
temporary files followed by atomic replacement. The publication manifest stores
only relative paths, counts, byte totals, exclusions, blocked findings, entry
point, and a deterministic snapshot SHA-256. Runtime startup revalidates that
manifest against the physical snapshot. The absolute authoring path remains only
in local `config.json`; it is never added to descriptors, DHT records, RPC,
published content, or snapshot metadata. Private keys are never placed in status
output or browser diagnostics. `Stop hosting` disables startup and
tears down the child process. `Restart` preserves the service identity and
canonical address while publishing fresh state. Deleting a service deletes its
identity and cannot be undone.

At browser startup, only services with `autoStart` enabled are restored. The
manager has no idle polling loop. A bounded timer observes only an actively
starting process and stops after online, a PID-bound terminal failure, or a
four-minute outer watchdog. Runtime status distinguishes network bootstrap,
signed-record publication, and private-route construction. Retry preserves the
service identity and does not accept stale status from a previous process.

## Platform packaging

Windows uses the existing app-local CPython runtime in `runtime/python`. Linux
AppImage packaging creates the equivalent app-local layout from the native
x86-64 build host's CPython 3.11+ and verified `cryptography`, `cffi`, and
`pycparser` installations. Both packages contain the same `granger_network`
source. Browser and hosting processes clear Python and proxy environment
overrides before launch.

The Linux packaging step must run on native Linux x86-64. A shell syntax check
on Windows is not AppImage portability acceptance.

## Evidence boundary

Unit and local multi-process tests cover static assets, loopback POST, ten
independent identities, lifecycle, descriptor publication, browser navigation,
zero resolver calls, and no direct client-host edge. They do not prove
anonymity or physical cross-network portability. A real Windows-to-Linux or
cross-ISP run remains required before those results can be marked verified.
