# Signed WAN Configuration Recovery

This is experimental local-candidate functionality, not a production fleet
rollout. Existing configuration and bootstrap authorities remain unchanged.

## Trust and Transport

Wire v3 retains its existing authenticated encryption and peer authentication.
RPC 31 (`WAN_CONFIG_QUERY`) and 32 (`WAN_CONFIG_CHUNK`) transport a public
configuration snapshot. A carrier does not become an authority.

Recovery uses peer role 5 (`CONFIG_RECOVERY`). The server permits only the two
configuration messages for this role, at most 65 requests and ten seconds per
authenticated session. It denies circuit, DHT, introduction, rendezvous, and
application operations. Ordinary client/relay authentication still rejects
expired descriptors.

An expired, correctly signed configuration can provide historical numeric
contacts. This does not make that configuration valid for routing. The client
authenticates the contacted key and requires a fresh descriptor bound to the
same endpoint, network, and protocol with no `issuedAt` rollback.
An ephemeral first-contact identity avoids exposing the persistent client seed
to these carriers. No resolver, hostname, HTTP mirror, Tor, or I2P is involved.

When a running gateway has private ingress, config propagation uses a protected
circuit to an ordinary discovery peer. Failure does not retry that carrier
directly. On expiry, the old gateway is retired before cold control recovery.
Reachable BrowserPeers can relay validated snapshots, as can operator nodes;
there are no special developer node IDs in this selection.

## Snapshot Validation

The transport envelope contains only `version`, base64url `config`, and two
base64url `members`: `bootstrap-set.json` and `bootstrap-authority.pin`.
It is not an archive extractor or arbitrary-file download facility. Configuration
bytes retain their exact original encoding because existing high-water state
uses the file digest. The envelope reuses the bounded reseed advertisement and
chunk codecs, with separate RPC message types.

Before activation the client checks:

- Existing external config authority pin and Ed25519 signature/domain.
- Supported schema, network and wire version; bounded signed policy.
- Current validity, including the existing 120-second not-before tolerance.
- Config generation and exact-digest rollback/equivocation high-water state.
- Signed member hashes, bootstrap signature, current bootstrap/peer validity.
- Existing bootstrap authority, which recovery cannot rotate.
- Advertised generation, envelope hash, byte count and effective expiry.

No unverified advertisement advances high-water state. Unavailable sources,
invalid signatures and expired replacements leave routing fail-closed. Clock
accuracy remains an external prerequisite; expiry is not ignored on clock skew.

## Persistence

The existing WAN installation root owns immutable generation directories,
`active.json`, and the separately configured rollback state file. Candidate
activation holds an OS-backed lock released on process death; wall-clock jumps
cannot steal a live provisioning lease. The persistent lock file is not deleted.
Candidate files are verified before activation; file data is flushed before replacement.
The high-water state is persisted before the active pointer. A process crash
between those writes is recovered from the exact matching immutable snapshot,
not the preceding generation. The preceding directory is retained for in-flight
readers, but is not eligible as a rollback fallback. POSIX directory fsync is
used; Windows abrupt-power-loss durability is not yet physically verified.

Startup prefers a verified newer installed configuration over an obsolete
application bundle. This is not an import of the obsolete bundle. A damaged
active snapshot is not silently declared valid.

## Lifecycle and Bounds

The browser gateway owns one managed config lifecycle and swaps data gateways
only at an idle point. Expired policy blocks new data requests and retires the
old gateway. Hosting retains its service and network identities while replacing
network state at a host restart boundary. Status distinguishes config recovery
from an authenticated, DHT-ready network.

| Resource | Limit |
| --- | --- |
| Config document | 64 KiB |
| Public snapshot envelope | 4 MiB |
| Transfer chunk | 64 KiB |
| Carrier candidates per refresh | 8 |
| Snapshots fetched per carrier | 1 |
| Cold recovery loop deadline | 24 seconds, checked between operations |
| Cold handshake deadline | 3 seconds per attempt |
| Transfer session deadline | 3 seconds per carrier |
| Retry backoff | 30 seconds to 15 minutes, jittered +/-20% |
| Proactive window | Randomized 12-15 minutes before expiry |
| Qt worker automatic restarts | 3 per 5 minutes, delays 1/2/4 seconds |

Private circuit construction additionally uses the existing bounded per-hop
timeouts. The loop deadline is not a claim of an absolute wall-time bound on
every private multi-hop operation. Timers exist only during active transfers or
scheduled recovery; there is no continuous traffic generation.

## Operator Publication

Existing operator entrypoint accepts two optional, paired arguments:

```text
--wan-config-publication /operator/public/browser-wan.json
--wan-config-trust-anchor /operator/trust/config-authority.pin
```

The directory must already contain a valid signed config and its public
bootstrap/pin files. The operator reloads a changed public config through the
same verification path and does not serve an expired snapshot. No private
authority is loaded or generated by this facility. Production signing and
distribution of the next generation remain confined to the trusted operator.

## Operator Renewal Coordinator

`tools/operator_renewal.py --config /protected/operator.json --watch` runs on
the existing trusted authority workstation, not on public relay nodes. Without
`--watch` it performs one due operation and exits. An OS scheduler may invoke
this command; it must run as the existing operator account and must not store a
password in the configuration. No scheduled task is installed automatically.

On the existing Windows authority workstation, explicitly register the task:

```powershell
./scripts/Register-GrangerRenewalTask.ps1 -ConfigPath <protected-operator-root>/renewal-config.json -PythonExecutable <python.exe>
```

The registration requires operator-owned restricted ACLs and stores no password.
It invokes Python in isolated mode, at operator logon and every five minutes,
without overlapping instances. Each invocation obeys the coordinator's persisted
due time/backoff; the scheduler does not cause signing every five minutes.
An invocation is bounded to ten minutes, with the existing journal/OS lease
providing crash recovery. The task runs only while that operator is logged in.
Sleep, shutdown, logout or an unavailable network can prevent timely renewal;
finite expiry and fail-closed behavior remain in force. A continuously available
trusted signing host is an operational requirement, not a promise of this task.
Inspect with `Get-ScheduledTask -TaskName 'Granger Network Renewal'` and
`Get-ScheduledTaskInfo -TaskName 'Granger Network Renewal'`. Disable explicitly
with `Disable-ScheduledTask -TaskName 'Granger Network Renewal'`.

The local configuration contains `operatorRoot`, `initialGeneration`,
`sshExecutable`, `sshIdentity` (a path consumed only by OpenSSH), and four
`nodes`, each with `name` (`node-a` etc.), numeric `host`, and the existing
`nodeId`. Keep it outside source, package and diagnostics directories.
`operatorRoot` owns the existing `private`, `public-trust`, and
`public-bundles/generationN` directories. Initialization verifies the initial
generation against the external pins. It never generates a missing authority.

Renewal starts one third of the generation lifetime before expiry, bounded to
10 minutes through 6 hours, with up to 5 minutes of persisted early jitter.
All four signed fresh descriptors must match the existing identities. Issuance
retains the signed network, protocol and routing policy, cannot outlive a
descriptor, and refuses less than 6 hours of new validity. Failures back off
from 30 seconds to 30 minutes, with bounded jitter. Expiry still fails closed if
the trusted workstation is offline or fresh descriptors are unavailable.

The same-inode OS lease prevents duplicate local signing. Immutable signed
successors are reused after a crash; a persisted digest conflict stops the
operation. `renewal-state.json` journals signed generation, exact digest,
expiry, next renewal/retry, and per-node deployment/verification state. A
partially deployed generation is not reported successful. The next execution
resumes identical bytes and re-verifies all four peers. Do not operate a second
independent coordinator against another journal with the same authority keys.

Public-only SSH control validates pins, node identity, signed config, hashes,
expiry and policy before a Linux `renameat2(RENAME_EXCHANGE)` directory swap.
It refuses a non-atomic fallback. It does not restart services, replace runtime,
edit firewall/systemd, or access node private identities. The existing operator
reloads the new publication. Health must then show fresh RUNNING/CONNECTED,
AUTH 4 and DHT ready, followed by the browser's real authenticated wire-v3
config download/verification. Only after every peer passes is renewal complete.

Protect the entire operator root with owner-only ACLs and use verified SSH
host keys. The coordinator needs authority read access, local journal/bundle
write access, and restricted fleet publication privileges. Current fleet
deployment uses its existing administrative OpenSSH access. Local tests model
failure and atomic-swap behavior; they do not establish Linux power-loss or
physical unattended-renewal acceptance. No production scheduler is enabled by
adding these tools.

## Verification Scope

`test_wan_config_recovery.py` covers genuine loopback wire-v3 transfer, cold
expiry, malicious replacements, authority preservation, rollback, equivocation,
clock bounds, failed writes, crash activation recovery and bounded retries.
`wan_process_acceptance.py --expired-wan-config` supplies an expired bundle to
the actual browser and hosting smoke while nodes distribute a newer signed
snapshot. Physical WAN, clock correction, power-loss durability, and long soak
require separate evidence.

Design review reference: [TUF specification, client workflow and attack model](https://theupdateframework.github.io/specification/latest/).
No TUF code is incorporated and this protocol is not claimed to be TUF-compatible.
