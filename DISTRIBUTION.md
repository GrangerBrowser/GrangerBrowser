# Distribution Readiness

This document records release prerequisites. It is not a license and does not
grant permission to copy, modify, or distribute Granger Browser.

## Current Status

The repository and its GitHub Release assets are public. No project-wide source
license has been selected, so public access must not be interpreted as a grant
to copy, modify, or redistribute project-authored code. The repository owner
remains responsible for the source, asset, Qt, Tor, I2P, and other third-party
distribution obligations listed below.

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
4. Use the pinned official PurpleI2P i2pd archive described in `BUILDING.md`,
   verify its checksum, and retain the BSD-3-Clause notice.
5. Run `scripts/build-release.ps1` from a clean tree. Publish only the canonical
   `Granger-Browser-<version>-windows-x64.zip` asset accepted by that script,
   together with its `.sha256` checksum. GitHub-generated source archives are
   not portable packages and may contain Git LFS pointer files.
6. Review the generated package manifest and confirm that it contains no user
   profile, credentials, bridge data, logs, crash dumps, or machine-specific
   paths.
7. Keep security claims bounded: Granger Browser provides privacy controls and
   fingerprinting resistance, but does not promise anonymity.

## Release Record

For each public release, record the Git commit and tag, MSVC and Qt versions,
Qt WebEngine and Chromium versions, Tor bundle filename and checksum, Tor and
pluggable-transport versions, i2pd version and checksum, package checksum, and
acceptance result.
