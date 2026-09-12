# Hosting Dashboard

Settings / Sites & Hosting lists every locally managed service, including
offline services. It exposes start/stop/restart/delete, open/copy, details,
visibility, uptime and aggregate session payload counters. Counters record no
request paths, visitor addresses or client identities. They are local runtime
counters, not durable access logs, and reset with the hosting worker.

## Public and Unlisted

Unlisted is the default, including legacy configurations with no visibility
field. Exact cryptographic addresses remain resolvable through the existing
signed service/introduction DHT records. Unlisted is not access control and
must not be described as a private or authenticated-members-only website.

Public discovery is an explicit service-owner choice. A signed service
descriptor carries `metadata.visibility = "public"`. Updated discovery nodes
answer `PUBLIC_SERVICE_SAMPLE` (RPC 33) only through a private circuit and only
with public, valid, unexpired service records. Each response is bounded to 16
records. Exact record lookup is unchanged. Missing visibility means unlisted.
The browser's local management list is never filtered by this network setting.

The client treats public samples as hints and performs the existing signed
quorum lookup before displaying a sampled service. This rejects stale public
hints after a newer unlisted descriptor has reached quorum. Visibility changes
restart that service, republish a monotonic descriptor, and retain its identity
and address. Other services are unaffected. ONLINE is still contingent on the
normal introduction/rendezvous/DHT health checks, not on the requested setting.

This is not erasure: previously shared addresses and cached public information
cannot be recalled. Storage nodes already see records they store. Unlisted
does not prevent exact lookup or deliberate redistribution by a party that
knows the address. Sampling is bounded, not a complete global directory.

Public sampling/metadata requires updated nodes. Unlisted descriptors omit the
new metadata field and retain compatibility with existing wire-v3 record
validators. This local development stage does not deploy changes to the fleet.

## Local Regression Commands

```text
python -m unittest test_hosting_dashboard
python -m unittest test_wan_discovery.WanDiscoveryTests.test_public_hidden_public_uses_signed_network_discovery
GrangerBrowser.exe --smoke-granger-hosting-dashboard --smoke-output=<isolated-output.json> --granger-hosting-source=<fixture>
```

Python tests require `GrangerNetwork/src` and `GrangerNetwork/tests` on
PYTHONPATH. The browser smoke requires isolated data/settings/cache/download
roots. It can use an isolated signed fixture network or the packaged production
bundle for a WAN check. Do not run it against a production user profile.

`GRANGER_SMOKE_DASHBOARD_PHASE` selects a diagnostic scope:

- `all` (default): the combined dashboard scenario.
- `visibility`: one service, Public/Unlisted/Public exact-address GETs, and
  persistence of Unlisted through a worker stop/start.
- `multi-service`: three online services, GETs to all three, dashboard geometry,
  then deletion of A with unchanged B/C worker PIDs and successful B/C GETs.

Each run retains its 285-second operation budget and must be supervised by a
300-second process deadline. Separate scope results do not turn a failed
combined run into a pass. The visibility smoke tests exact-address access and
worker restart persistence; public sampling propagation and a full browser
restart need their own network acceptance evidence.
