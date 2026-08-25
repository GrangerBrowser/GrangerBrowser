# Bootstrap

## Purpose

Bootstrap solves cold start only. A signed bootstrap set gives a new node
several independently addressable discovery peers. It is not a central service
directory and is not placed on every application request.

The WAN runtime requires:

- at least two valid bootstrap node descriptors;
- one Ed25519 bootstrap-authority signature over the complete set;
- a locally distributed authority public-key pin;
- numeric, reachable TCP endpoints;
- a validity window no longer than the shortest included node descriptor.

If every seed is unreachable, the runtime may use valid signed peers from its
bounded local cache. A fresh profile with no reachable seed and no valid cache
fails with network unavailable.

## Trust distribution

The authority pin is a trust anchor. Distribute it through an authenticated
channel separate from the untrusted network path. Do not fetch and trust a pin
from the same unauthenticated location as the bundle.

The authority can bias or eclipse a new node by signing a hostile seed set.
Multiple peers remove a single availability dependency but do not create Sybil
resistance or organizational independence by themselves.

## Provisioning on Windows

Initialize at least two bootstrap nodes first:

```powershell
tools\wan-test\run-bootstrap.ps1 `
  -StateDir C:\granger\seed-a `
  -ListenHost 203.0.113.10 -ListenPort 18440 -InitOnly

tools\wan-test\run-bootstrap.ps1 `
  -StateDir C:\granger\seed-b `
  -ListenHost 198.51.100.20 -ListenPort 18440 -InitOnly
```

The example documentation addresses must be replaced with the real numeric
addresses of reachable test nodes. Copy the resulting public
`node-descriptor.json` files to the offline or controlled authority machine,
then create the bundle:

```powershell
tools\wan-test\provision-bootstrap.ps1 `
  -AuthorityState C:\granger\authority\identity.json `
  -Descriptor C:\granger\seed-a.json,C:\granger\seed-b.json `
  -Bundle C:\granger\distribution\bootstrap-set.json `
  -AuthorityPin C:\granger\distribution\bootstrap-authority.pin `
  -Lifetime 21600
```

The provisioner prints the peer IDs, expiry, and SHA-256 of the bundle. The
authority private identity must not be copied to clients or public nodes.

## Provisioning on Linux

The Bash wrappers accept the equivalent long options:

```bash
tools/wan-test/run-bootstrap.sh \
  --state-dir /srv/granger/seed-a \
  --listen-host 203.0.113.10 --listen-port 18440 --init-only

tools/wan-test/provision-bootstrap.sh \
  --authority-state /secure/granger/authority.json \
  --descriptor /srv/granger/seed-a/node-descriptor.json \
  --descriptor /srv/granger/seed-b/node-descriptor.json \
  --bundle /srv/granger/public/bootstrap-set.json \
  --authority-pin /srv/granger/public/bootstrap-authority.pin \
  --lifetime 21600
```

## Rotation

Node descriptors and bootstrap sets expire. Before expiry:

1. Create fresh signed descriptors for the same or replacement nodes.
2. Verify identities, capabilities, numeric endpoints, and reachability.
3. Sign a new set whose expiry does not exceed any member descriptor.
4. Publish the new bundle atomically.
5. Preserve the same authority pin unless a separately authenticated authority
   rotation is intended.

The current tools do not automatically renew descriptors or distribute a new
authority pin. Expired data is rejected rather than silently extended.

## Browser WAN configuration

The browser consumes a separate version-1 JSON config whose paths are relative
to its own directory:

```json
{
  "aliasPins": {},
  "authorityPin": "bootstrap-authority.pin",
  "bootstrap": "bootstrap-set.json",
  "minimumReplicas": 2,
  "replicationFactor": 3,
  "routeAttempts": 6,
  "timeoutSeconds": 8,
  "version": 1
}
```

The path may be supplied with `--granger-network-wan-config=<file>` or
`GRANGER_NETWORK_WAN_CONFIG`. Invalid schema, absolute member paths, path
escape, missing files, pin mismatch, or expired bundle fails closed.
