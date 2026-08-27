# Physical WAN Acceptance

## Status

The scripts in `tools/wan-test` are ready for a Windows and Debian physical
test without source changes. Until this procedure is completed on independent
networks with packet captures, the status is:

```text
PHYSICAL WAN: UNVERIFIED
```

Local multi-process acceptance is useful evidence but is not a substitute.

## Required topology

Use independently reachable infrastructure with enough identities for failure
tests:

```text
Bootstrap/discovery A, B (C recommended)
Access relay A, B, C
Client guard A, B
Middle A, B, C
Service guard A, B
Introduction A, B
Rendezvous A, B
Windows client on network 1
Debian service host on network 2
```

Roles may share physical infrastructure for initial connectivity testing, but
privacy acceptance must record every colocation. At minimum, neither endpoint
machine may operate the opposite endpoint's first relay or the rendezvous.

## Preconditions

- Python 3.11+ and project dependencies installed from the checked-out source.
- Clocks synchronized sufficiently for the 120-second protocol skew bound.
- Numeric public relay addresses and explicit firewall rules.
- No inbound requirement for the ordinary client or service host.
- An authenticated channel for descriptor, bootstrap bundle, authority pin, and
  canonical service-name exchange.
- Elevated PowerShell for PktMon on Windows and root/sudo tcpdump on Debian.

Record the source commit, Python/cryptography versions, OS builds, public test
endpoint addresses, NAT/CGNAT status, and SHA-256 of every distributed config.

## Provision infrastructure

1. Run each bootstrap/relay wrapper with `--init-only` or `-InitOnly`.
2. Exchange only the public `node-descriptor.json` files.
3. Give nodes the public descriptors needed for their discovery view.
4. Start nodes and wait for their ready files.
5. On a controlled authority machine, create a signed bundle from at least two
   bootstrap descriptors using `provision-bootstrap`.
6. Verify the printed bundle hash and distribute the bundle plus authority pin
   out of band.

Node descriptors used by the physical scripts default to a 24-hour lifetime.
The provisioner refuses to create a bundle that outlives its shortest member.

## Start packet capture

Windows, from elevated PowerShell:

```powershell
tools\wan-test\capture-network.ps1 `
  -OutputBase C:\granger\capture\client -DurationSeconds 600
```

Debian:

```bash
tools/wan-test/capture-network.sh \
  --output-base /tmp/granger-host --duration 600 --interface any
```

Capture on the endpoint machines and, where possible, the first relays. Keep
the generated hashes with the report.

## Start service host

On the Debian endpoint:

```bash
tools/wan-test/run-test-host.sh \
  --state-dir /tmp/granger-service \
  --bootstrap /tmp/granger-config/bootstrap-set.json \
  --authority-pin /tmp/granger-config/bootstrap-authority.pin \
  --ready-file /tmp/granger-service/host-ready.json
```

The wrapper starts a numeric-loopback forum fixture, initializes a persistent
service identity if needed, publishes descriptors, and creates at least two
introduction circuits. Transfer only the canonical `.granger` name to the
client; do not transfer the ready file or any host endpoint.

## Run client

On Windows network 1:

```powershell
tools\wan-test\run-test-client.ps1 `
  -Name <canonical-name>.granger `
  -StateDir C:\granger\client `
  -Bootstrap C:\granger\config\bootstrap-set.json `
  -AuthorityPin C:\granger\config\bootstrap-authority.pin `
  -Report C:\granger\reports\client.json
```

PASS requires successful page, CSS, JavaScript, POST, and message readback over
the overlay. Repeat with Granger Browser using an equivalent browser WAN config
to verify real Qt WebEngine rendering.

## Failure matrix

While captures continue:

1. Stop the service host. A client request must fail closed with no DNS or
   direct attempt. Restart it and verify refreshed access.
2. Stop the active client middle. The old circuit must fail; a different valid
   route may recover.
3. Stop the active client access relay, then the active guard. Recovery may use
   another verified access/guard path only.
4. Stop the rendezvous. New requests may recover through another verified
   rendezvous after descriptor/route refresh.
5. Stop bootstrap A, then all bootstrap nodes while retaining a valid peer
   cache. Cached startup and an existing published service should continue
   through discovered relays without contacting an initial seed.
6. Use a fresh client state with every bootstrap unreachable. It must report
   network unavailable and make no other connection.
7. Test malformed, expired, replayed, substituted, and wrong-authority data.

Every recovery route must remain client-access/guard/middle/rendezvous plus the
independent service access/guard/middle half. Direct client-to-host and
host-to-client connections must remain zero.

## Packet analysis

Use known `CLIENT_IP` and `HOST_IP` values. Inspect all endpoint captures and
process socket logs.

Required assertions:

```text
client process tree -> HOST_IP TCP connections: 0
client process tree -> HOST_IP UDP datagrams: 0
host process tree -> CLIENT_IP TCP connections: 0
host process tree -> CLIENT_IP UDP datagrams: 0
.granger DNS queries on every captured interface: 0
unexpected DNS queries caused by Granger runtime: 0
application plaintext markers in relay payload captures: 0
direct fallback after each induced failure: 0
orphan Granger child processes after shutdown: 0
```

Expected traffic includes endpoint-to-access TCP and relay-to-adjacent-relay
TCP. The access relay inevitably sees its immediate endpoint IP, while the next
guard must see only the access relay. Public relay IPs in descriptors are not
leaks. Any endpoint-to-opposite-endpoint packet, `.granger` DNS query, UDP
fallback, or plaintext application marker is a test failure requiring
root-cause analysis.

## Acceptance record

Archive:

- source commit and clean/dirty status;
- topology and role/operator mapping;
- all public descriptor and config hashes;
- client/host reports and node diagnostics;
- PktMon/tcpdump captures and hashes;
- exact failure timestamps and replacement routes;
- process list before/after;
- browser screenshot and WebEngine result;
- limitations such as node colocation or missing capture points.

Only after this evidence exists may `PHYSICAL WAN` be marked PASS. One-machine
loopback, documentation addresses, socket mocks, or modeled topology are never
sufficient.

For browser static-hosting acceptance, use the selected source and entry point
without modifying the source directory:

```powershell
python tools\wan_process_acceptance.py `
  --work-dir C:\granger\acceptance `
  --report C:\granger\acceptance.json `
  --browser C:\path\to\GrangerBrowser.exe `
  --hosting-source C:\path\to\granger-test-site `
  --hosting-entry-page nova_demo_site.html
```

The report must include source hashes before and after, HTML/second-page/CSS/
JavaScript/JSON/SVG checks, service restart under the same identity, host
offline fail-closed behavior, and warm-cache access after all seeds stop.
