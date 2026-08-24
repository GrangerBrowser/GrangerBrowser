# Building Granger Browser

Granger Browser is a native C++20/Qt 6 application. Windows is the public
release target. A native Linux x86_64 AppImage target is available as a local
RC build and does not use Wine. Public Windows and Linux packages do not invoke
Python at runtime. The canonical local Windows build additionally carries an
isolated app-local Python runtime for the experimental Granger Network browser
integration; no system Python or developer environment is used at runtime.

## Windows requirements

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

## Canonical local release

Browser changes are complete only after this workflow succeeds:

```powershell
.\scripts\build-local-release.ps1 `
  -QtRoot "$env:USERPROFILE\Qt\6.11.2\msvc2022_64" `
  -BuildDirectory build\desktop
```

The orchestrator requires a clean tracked HEAD, compiles Release, deploys the
base browser into `release\.local-staging`, adds the signed x64 Python runtime
and the licensed `cryptography`, `cffi`, and `pycparser` modules used by Granger
Network, validates the complete manifest,
runs copied-package and `.granger` acceptance, and atomically promotes only a
passing directory. The previous canonical directory remains untouched if
staging fails. User data is outside the package and is not moved or removed.

Canonical local executable:

```text
release\Granger Browser\GrangerBrowser.exe
```

The generated `local-runtime-metadata.json` records the source HEAD, browser
hash, Python and `cryptography` versions, licenses, and critical runtime hashes.
The embedded `python314._pth` and `-I` launch mode prevent `PYTHONPATH`, user
site-packages, and the system Python installation from influencing the helper.

## Public Windows release

```powershell
.\scripts\build-release.ps1 `
  -QtRoot "$env:USERPROFILE\Qt\6.11.2\msvc2022_64" `
  -BuildDirectory build\desktop
```

This explicit public packaging command removes the previous temporary compiler
output, builds Release, packages reviewed public dependencies, runs the complete
copied-package acceptance suite with Python absent from `PATH`, atomically
replaces the canonical release, and creates the public portable ZIP. Do not use
it as the routine local development completion step.

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
`release\Granger Browser` path. It accepts `release\.staging` for public
packaging, `release\.ui-stage` for focused visual checks, and
`release\.local-staging` for the local orchestrator. Only an orchestrator may
promote an accepted package to the canonical release; each removes its own
staging directories after confirming that no process is running from them.

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
  runtime\python\                 # canonical local build only
  local-runtime-metadata.json     # canonical local build only
  licenses\
  Create-Shortcuts.ps1
  deployment-metadata.json
  release-manifest.json
```

## Acceptance

```powershell
.\scripts\test-release.ps1 -PackageDirectory "release\Granger Browser"
```

The public harness copies the release to a path containing spaces, launches it from an
unrelated current directory, removes Python and the Qt SDK from `PATH`, poisons
external `QTWEBENGINE_*` paths to prove that the package-local helper wins, and
checks the persistent WebEngine profile and User-Agent. It runs
new-tab/internal-route, product, navigation, bridge, QR, privacy, persistence,
renderer-fixture, private-route, network-bootstrap, I2P lifecycle, Tor strategy,
download, and shutdown tests. Offline smoke modes remain pinned to a blocked
loopback gateway; tests that need an external destination must first obtain a
verified private route.

`build-local-release.ps1` enables the narrowly scoped local-runtime acceptance
mode and additionally runs the real Qt WebEngine `.granger` harness without
passing `--granger-network-python`, `--granger-network-source`, Qt SDK paths, or
`PYTHONPATH` to the browser. It verifies alias and canonical navigation, zero
helper DNS calls, zero direct escape-probe connections, encrypted relay traffic,
and zero orphan helper processes before and after promotion.

When the app-local runtime is present and no explicit test/development registry
is supplied, `test.granger` is an ephemeral local demonstration service. It uses
the existing identity-bound encrypted Granger transport on numeric loopback and
does not register with DNS or expose a clearnet listener. Its identity is new for
each helper process; it is a local runtime check, not a stable published service.

The acceptance gate establishes technical behavior; it does not grant a project
license or resolve third-party redistribution rights. Review
[DISTRIBUTION.md](DISTRIBUTION.md) before publishing source or binaries.

After acceptance, `create-portable-archive.ps1` writes
`output\distribution\Granger-Browser-v<version>-windows-x64.zip` and its
`.sha256` checksum. It reopens the archive and verifies that the archived EXE is
the complete PE file from the canonical package. Publish that ZIP as a GitHub
Release asset; GitHub's generated source archives are not portable application
packages.

## Linux local RC

The native Linux build requires CMake 3.24+, Ninja, a C++20 GCC or Clang
toolchain, GnuPG, standard ELF/AppImage tooling, and the official Qt 6.11.2
`linux_gcc_64` SDK with WebEngine, WebChannel, Positioning, and SerialPort.
SerialPort is packaged because Qt's NMEA positioning plugin depends on it.

```bash
export QT_ROOT="$HOME/Qt/6.11.2/gcc_64"
scripts/build-linux-appimage.sh
scripts/test-linux-appimage.sh
```

`scripts/fetch-linux-runtimes.sh` downloads only pinned official Tor and
PurpleI2P artifacts, verifies their hashes, validates the Tor detached OpenPGP
signature, checks embedded versions, and stages native Linux executables under
ignored `output/` storage. The resulting AppImage contains package-local Qt,
Qt WebEngine, Tor, lyrebird, Conjure, and i2pd runtimes. It does not fall back
to system Tor or i2pd.

The manual `Build Linux local RC` workflow builds and tests the native package
but never creates a tag or GitHub Release. See [docs/LINUX.md](docs/LINUX.md)
for prerequisites, runtime inventory, XDG paths, sandbox checks, packet tests,
and current portability limitations.

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
