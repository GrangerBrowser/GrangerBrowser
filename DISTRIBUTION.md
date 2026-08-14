# Distribution Readiness

This document records release prerequisites. It is not a license and does not
grant permission to copy, modify, or distribute Granger Browser.

## Current Status

Public source and binary distribution are not approved by the current repository
state. Complete the items below before changing repository visibility or
publishing a release.

## Source Publication

1. Select a project-wide license, add its complete text as `LICENSE`, and update
   the README and package notices consistently.
2. Confirm that the repository owner has the right to publish every
   project-authored source and asset.
3. Confirm redistribution and trademark terms for every item listed in
   `docs/UI_ASSET_SOURCES.md`, or replace items whose provenance is insufficient.
4. Retain all third-party license and attribution files under `third_party/`.

## Binary Publication

1. Complete the source-publication requirements above.
2. Determine the applicable Qt licensing path for the exact modules and runtime
   being shipped, then include the required license texts, notices, source or
   relinking materials, and other obligations.
3. Stage a verified official Tor Expert Bundle as described in `BUILDING.md` and
   retain its bundled license documents.
4. Run `scripts/build-release.ps1` from a clean tree. Publish only the canonical
   package accepted by that script, together with its SHA-256 checksum.
5. Review the generated package manifest and confirm that it contains no user
   profile, credentials, bridge data, logs, crash dumps, or machine-specific
   paths.
6. Keep security claims bounded: Granger Browser provides privacy controls and
   fingerprinting resistance, but does not promise anonymity.

## Release Record

For each public release, record the Git commit and tag, MSVC and Qt versions,
Qt WebEngine and Chromium versions, Tor bundle filename and checksum, Tor and
pluggable-transport versions, package checksum, and acceptance result.
