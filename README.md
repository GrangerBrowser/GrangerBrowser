# Granger Browser

Granger Browser is a native Windows privacy browser built with C++20, Qt Widgets, and Qt WebEngine. Qt WebEngine is Chromium-based. Python is not required to launch the packaged browser.

Granger Browser does not promise anonymity. Tor status is reported separately for configuration, bootstrap, and browser-route verification.

> **Development status:** this repository contains an actively developed,
> pre-release browser. Use a dedicated test profile when evaluating source
> builds and review the security limitations before relying on it.

## Run The Packaged Browser

Launch:

```text
release\Granger Browser\GrangerBrowser.exe
```

No terminal, Python installation, Qt SDK, or source checkout is required. To create Start menu and desktop shortcuts:

```powershell
powershell -ExecutionPolicy Bypass -File ".\release\Granger Browser\Create-Shortcuts.ps1"
```

## Desktop Features

- Compact browser toolbar with Back, Forward, Reload/Stop, site information, address/search field, downloads, settings, and new tab.
- Vertical tabs with collapsed, hover-expanded, and pinned states.
- Persistent profile, cookies, cache, session, bookmarks, history, and download history.
- Search providers: DuckDuckGo, Google, Bing, Brave Search, Startpage, Mojeek, and Onion Search through Ahmia.
- Search suggestions are disabled by default and clearly disclose provider requests when enabled.
- Chromium default, Firefox-compatible, Chrome-compatible, and custom User-Agent profiles. Compatibility profiles do not change the browser engine.
- Managed Tor strategies: Direct, obfs4, WebTunnel, Snowflake, meek_lite, vanilla bridges, external Tor SOCKS, upstream SOCKS, and upstream HTTP CONNECT.

## Tor Bridge Behavior

Bridge input is parsed into transport, endpoint, optional fingerprint, and key/value options while preserving the complete Bridge payload used in torrc. Supported current transports include `obfs4`, `webtunnel`, `snowflake`, and vanilla bridges; the parser retains generic transport syntax for future extensions.

Save persists bridge profiles. Apply resolves the bundled Tor Expert Bundle and `lyrebird`, writes a dedicated torrc under the user data directory, runs `tor.exe --verify-config -f <torrc>`, starts the managed Tor process, captures real bootstrap output, and verifies browser traffic through the Tor Project check endpoint.

`Connected` is only shown after browser route verification. A valid but unreachable bridge remains saved and reports the actual Tor connection failure.

## Data Locations

Mutable data is stored outside the package under:

```text
%LOCALAPPDATA%\Granger\Granger Browser\
```

The profile, cache, state, logs, Tor data, and generated torrc use subdirectories there. Test harnesses can override roots with `GRANGER_DATA_ROOT` and `GRANGER_SETTINGS_ROOT`.

## Build And Package

Requirements:

- Visual Studio 2022, MSVC x64
- CMake 3.24+
- Qt 6.11.1 with Widgets, Svg, Network, WebEngineWidgets, WebChannel, and Positioning

Build, package, test, and atomically replace the canonical release:

```powershell
.\scripts\build-release.ps1 -QtRoot "$env:USERPROFILE\Qt\6.11.1\msvc2022_64"
```

The pinned Qt runtime can be installed from Qt's official repositories with
`.\scripts\install-qt-6.11.1.ps1`; every downloaded archive is checked against
its published SHA-1 before extraction.

Temporary compiler output stays under `build\desktop`. Packaging uses `release\.staging` only while validation runs, then replaces `release\Granger Browser` and removes staging. The script never creates candidate or final-sanity directories.

See [BUILDING.md](BUILDING.md) for the package layout and acceptance details. The verified release record is in [docs/GRANGER_BROWSER_RELEASE_REPORT.md](docs/GRANGER_BROWSER_RELEASE_REPORT.md).

Development work is performed on focused branches and merged through review.
See [docs/GIT_WORKFLOW.md](docs/GIT_WORKFLOW.md) for the repository workflow.

## License Status

No project-wide license has been selected or added. Third-party components keep
their own licenses and attribution as documented in [NOTICE.txt](NOTICE.txt)
and `third_party/`. Do not infer an MIT, GPL, MPL, or other grant for the
Granger Browser source until the repository owner selects one explicitly.

## Security Notes

- User-Agent spoofing is compatibility-only. TLS, Client Hints, WebGL, codecs, rendering, and other Chromium identity surfaces remain Chromium-specific.
- Search providers may present CAPTCHAs or anti-automation challenges based on the current network.
- The release binary is not digitally signed. Windows may display an unknown-publisher warning.
- Use only in lawful and ethical contexts.
