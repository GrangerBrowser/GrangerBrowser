# GitHub import security audit

Date: 2026-08-08

This audit defines the source boundary used for the first Granger Browser Git
baseline. It records categories and decisions without recording secret values.

## Excluded from source control

- CMake/MSVC output and Qt deployment directories;
- portable Release and distribution directories;
- test reports, screenshots, generated manifests, logs, dumps and caches;
- browser profiles, cookies, history, sessions, LocalStorage, IndexedDB,
  service workers and Space profile data;
- Tor runtime data, generated torrc files, control cookies and process locks;
- `.env`, credential files, private keys and signing material;
- IDE-local state;
- the separate local Pamp repository, including its own Git metadata and
  runtime case/report data.

## Secret-pattern review

The intended tracked tree was searched for private-key headers, common hosted
token formats, API keys, authorization values, passwords, credentials and
user-specific absolute paths. Generic source identifiers such as
`passwordField`, `token`, `credentialTarget` and filter-list text were reviewed
as code or third-party data rather than treated as secrets automatically.

No private key, API token, account password, proxy credential, Tor control
credential or signing secret was found in the intended tracked source tree.

Gitleaks 8.30.1 reported three `sourcegraph-access-token` candidates in comment
metadata of the bundled EasyList snapshot. Each candidate was verified as an
EasyList comment, not an application credential. `.gitleaksignore` suppresses
only those three path/rule/line fingerprints; the rule remains active for all
other files and future lines.

## Bridge fixtures

Client bridge descriptors previously embedded in smoke/QR fixtures were
treated as sensitive operational endpoints even though they contain public
client material rather than private keys. The repository baseline uses only
RFC 5737 IPv4 and RFC 3849 IPv6 documentation ranges with deterministic
synthetic fingerprints and certificates. Bridge parser, exact-line, torrc and
QR workflow coverage remains active without publishing operational bridges.

## Absolute paths

Runtime paths are derived through `AppPaths` and test environment overrides.
Historical reports containing machine-specific evidence are retained locally
outside the tracked tree. Current documentation uses repository-relative or
environment-variable paths.
