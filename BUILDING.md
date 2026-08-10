# Building Granger Browser

Granger Browser 0.4.0 is a native C++20/Qt 6 application. The release target is a GUI-subsystem executable named `GrangerBrowser.exe`; it does not open a console and does not invoke Python.

## Requirements

- CMake 3.24+
- Visual Studio 2022 with the MSVC x64 toolchain
- Qt 6.11.1 with Widgets, Svg, Network, WebEngineWidgets, WebChannel, and Positioning
- A downloaded Tor Expert Bundle staged under `output/tor-expert` for packaging

Install the pinned stable Qt toolchain from Qt's official repositories when it
is not already present:

```powershell
.\scripts\install-qt-6.11.1.ps1
```

## Canonical Release

```powershell
.\scripts\build-release.ps1 `
  -QtRoot "$env:USERPROFILE\Qt\6.11.1\msvc2022_64" `
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
  -QtRoot "$env:USERPROFILE\Qt\6.11.1\msvc2022_64" `
  -BuildDirectory build\desktop
```

Internally, the release orchestrator calls `package-release.ps1`. It runs `windeployqt`, adds the app-local VC143 runtime, packages Qt WebEngine resources/locales, bundles Tor, geoip data, `lyrebird`, `pt_config.json`, notices, assets, and shortcut creation, validates required files, and writes `release-manifest.json` with SHA-256 hashes.

`package-release.ps1` is staging-only and rejects the canonical
`release\Granger Browser` path. It accepts only `release\.staging`, used by the
orchestrator, or `release\.ui-stage`, used for focused visual checks. Only
`build-release.ps1` may promote an accepted package to the canonical release;
it removes stale staging directories after confirming that no process is
running from them.

The optional NMEA positioning plugin is removed because it requires Qt SerialPort, which Granger Browser does not ship or use. The WinRT and polling positioning plugins remain.

## Release Layout

```text
release\Granger Browser\
  GrangerBrowser.exe
  Qt6*.dll
  QtWebEngineProcess.exe
  platforms\qwindows.dll
  resources\
  translations\qtwebengine_locales\
  runtime\tor\tor.exe
  runtime\tor\data\geoip
  runtime\tor\data\geoip6
  runtime\tor\pluggable_transports\lyrebird.exe
  runtime\tor\pluggable_transports\pt_config.json
  licenses\
  Create-Shortcuts.ps1
  release-manifest.json
```

## Acceptance

```powershell
.\scripts\test-release.ps1 -PackageDirectory "release\Granger Browser"
```

The harness copies the release to a path containing spaces, launches it from an unrelated current directory, removes Python and the Qt SDK from `PATH`, checks the persistent WebEngine profile and User-Agent, runs new-tab/internal-route, product, navigation, bridge, QR, privacy, and persistence tests, loads a real HTTPS page, verifies all connection-strategy torrc files with bundled Tor, launches a real obfs4 pluggable transport to `conn_pt`, verifies real toolbar download progress while closing the source tab, checks all search-provider navigations, closes a normal browser window, and verifies no managed processes remain.

External provider challenges are recorded honestly. A Google `sorry` page is not counted as a loaded search-results page.

## Mutable Data

Runtime state uses `QStandardPaths::AppLocalDataLocation` and `CacheLocation`. The package directory is treated as read-only. Test-only overrides:

```text
GRANGER_DATA_ROOT
GRANGER_SETTINGS_ROOT
GRANGER_DOWNLOAD_ROOT
```

## Proxy Limitation

Qt WebEngine proxy configuration is process-wide. Granger Browser applies Chromium proxy startup flags before WebEngine initialization. A selected Tor strategy is not shown as Connected until Tor bootstrap and browser-route verification both succeed.
