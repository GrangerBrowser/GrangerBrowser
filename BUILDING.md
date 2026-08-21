# Building Granger Browser

Granger Browser is a native C++20/Qt 6 application. The release target is a GUI-subsystem executable named `GrangerBrowser.exe`; it does not open a console and does not invoke Python.

## Requirements

- CMake 3.24+
- Visual Studio 2022 with the MSVC x64 toolchain
- Qt 6.11.2 with Widgets, Svg, Network, WebEngineWidgets, WebChannel, and Positioning
- GnuPG for build-time Tor archive signature verification (Git for Windows includes it)
- Network access to the pinned official Tor and PurpleI2P assets when their verified archives are not already under `output/third-party`

Install the pinned stable Qt toolchain from Qt's official repositories when it
is not already present:

```powershell
.\scripts\install-qt-6.11.2.ps1
```

## Tor Packaging Input

`scripts/fetch-tor-runtime.ps1` stages the official Windows x86-64 Tor Expert
Bundle 15.0.20 under ignored `output/` storage. It accepts only the pinned Tor
Project archive with SHA-256
`D59BFF934E3AD876E1623E24AE60C19AEEA56F50178093B9F86FBA230639F949`.
It also verifies the detached OpenPGP signature against the Tor Browser
Developers key fingerprint
`EF6E286DDA85EA2A4BA7DE684E2C6E8793298290`, validates safe archive paths, and
checks the exact hashes and embedded versions of all runtime files used by the
package. The bundle contains Tor 0.4.9.11, lyrebird 0.8.1, Conjure, GeoIP data,
and their upstream notices. End users do not need GnuPG; signature verification
is a build-time gate.

## I2P Packaging Input

`scripts/fetch-i2p-runtime.ps1` stages the official PurpleI2P i2pd 2.61.0
Windows x64 MinGW release under ignored `output/` storage. The script accepts
only the pinned upstream asset and verifies SHA-256
`A0A8FB199A6BC5B487DF71567791DE6997050B921D65622EF9E936FFA88BC83F`
before extracting `i2pd.exe` and its certificate bundle. End users do not need
Java or a separate I2P installation. Source metadata and BSD-3-Clause terms are
tracked under `third_party/i2pd/`.

## Canonical Release

```powershell
.\scripts\build-release.ps1 `
  -QtRoot "$env:USERPROFILE\Qt\6.11.2\msvc2022_64" `
  -BuildDirectory build\desktop
```

This one command removes the previous temporary compiler output, builds Release, packages all dependencies into staging, runs the complete copied-package acceptance suite with Python absent from `PATH`, and atomically replaces the canonical release only after validation succeeds.

Canonical output:

```text
release\Granger Browser\GrangerBrowser.exe
```

For compile-only development work:

```powershell
.\scripts\compile-release.ps1 `
  -QtRoot "$env:USERPROFILE\Qt\6.11.2\msvc2022_64" `
  -BuildDirectory build\desktop
```

Internally, the release orchestrator calls `package-release.ps1`. It runs
`windeployqt` for the Release target while excluding QML debugger plugins, adds
the app-local VC143 runtime, pins Qt paths with package-local `qt.conf`, packages
Qt WebEngine resources/locales and the redistributable D3D compiler/DXC runtime, bundles
the pinned signed Tor bundle, geoip data, `lyrebird`, `conjure-client`,
`pt_config.json`, i2pd and its
certificate bundle, notices,
assets, and shortcut creation, validates required files, and writes
`deployment-metadata.json` plus `release-manifest.json` with SHA-256 hashes.

`package-release.ps1` is staging-only and rejects the canonical
`release\Granger Browser` path. It accepts only `release\.staging`, used by the
orchestrator, or `release\.ui-stage`, used for focused visual checks. Only
`build-release.ps1` may promote an accepted package to the canonical release;
it removes stale staging directories after confirming that no process is
running from them.

The optional NMEA positioning plugin is removed because it requires Qt SerialPort, which Granger Browser does not ship or use. The WinRT and polling positioning plugins remain.

The orchestrator also runs `test-windows-portability.ps1`. This build-time gate
parses every packaged EXE and DLL without relying on `dumpbin`, requires x64
PE32+ files, resolves direct and delay-load imports, verifies the package
manifest and Authenticode signatures of applicable upstream runtime files,
invokes the Windows Loader on critical Qt/WebEngine DLLs, rejects Git LFS
pointers and machine-specific user paths, validates pinned Tor/i2pd source
metadata, runtime hashes, Tor signature status, the i2pd certificate bundle,
and confirms that QML debugger tooling is absent.

## Release Layout

```text
release\Granger Browser\
  GrangerBrowser.exe
  Qt6*.dll
  QtWebEngineProcess.exe
  qt.conf
  d3dcompiler_47.dll
  dxcompiler.dll
  dxil.dll
  platforms\qwindows.dll
  resources\
  translations\qtwebengine_locales\
  runtime\tor\tor.exe
  runtime\tor\data\geoip
  runtime\tor\data\geoip6
  runtime\tor\pluggable_transports\lyrebird.exe
  runtime\tor\pluggable_transports\conjure-client.exe
  runtime\tor\pluggable_transports\pt_config.json
  runtime\i2p\i2pd.exe
  runtime\i2p\certificates\
  runtime\i2p\LICENSE.txt
  licenses\
  Create-Shortcuts.ps1
  deployment-metadata.json
  release-manifest.json
```

## Acceptance

```powershell
.\scripts\test-release.ps1 -PackageDirectory "release\Granger Browser"
```

The harness copies the release to a path containing spaces, launches it from an
unrelated current directory, removes Python and the Qt SDK from `PATH`, poisons
external `QTWEBENGINE_*` paths to prove that the package-local helper wins, and
checks the persistent WebEngine profile and User-Agent. It runs
new-tab/internal-route, product, navigation, bridge, QR, privacy, persistence,
renderer-fixture, private-route, network-bootstrap, I2P lifecycle, Tor strategy,
download, and shutdown tests. Offline smoke modes remain pinned to a blocked
loopback gateway; tests that need an external destination must first obtain a
verified private route.

The acceptance gate establishes technical behavior; it does not grant a project
license or resolve third-party redistribution rights. Review
[DISTRIBUTION.md](DISTRIBUTION.md) before publishing source or binaries.

After acceptance, `create-portable-archive.ps1` writes
`output\distribution\Granger-Browser-v<version>-windows-x64.zip` and its
`.sha256` checksum. It reopens the archive and verifies that the archived EXE is
the complete PE file from the canonical package. Publish that ZIP as a GitHub
Release asset; GitHub's generated source archives are not portable application
packages.

## Mutable Data

Runtime state uses `QStandardPaths::AppLocalDataLocation` and `CacheLocation`. The package directory is treated as read-only. Test-only overrides:

```text
GRANGER_DATA_ROOT
GRANGER_SETTINGS_ROOT
GRANGER_DOWNLOAD_ROOT
```

## Proxy Limitation

Qt WebEngine proxy configuration is process-wide. Granger Browser starts a
loopback fail-closed gateway and applies canonical Chromium proxy and resolver
flags before WebEngine initialization. External Chromium proxy/resolver
overrides are rejected. A selected Tor strategy is not shown as Connected until
Tor bootstrap and browser-route verification both succeed.
