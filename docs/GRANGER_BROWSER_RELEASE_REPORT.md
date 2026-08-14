# Granger Browser 0.4.1 release record

Updated: 2026-08-14

This document records the release boundary and the reproducible acceptance
procedure for Granger Browser. It is intentionally short. Detailed privacy,
content-filter, cross-device, and third-party attribution records remain in
their dedicated documents.

## Canonical artifact

The only supported packaged executable is:

```text
release\Granger Browser\GrangerBrowser.exe
```

`scripts/build-release.ps1` performs a clean Release build, packages into a
temporary staging directory, runs acceptance against the copied package, and
replaces the canonical package only after every required check succeeds.
`release-manifest.json` contains SHA-256 hashes for packaged files. The build
orchestrator writes its machine-readable result to `release/build-report.json`.

## Runtime

| Component | Release value |
| --- | --- |
| Product | Granger Browser 0.4.1 |
| Language | C++20 |
| UI | Qt Widgets 6.11.1 |
| Browser engine | Qt WebEngine 6.11.1 / Chromium 140.0.7339.225 |
| Chromium security patch API | 148.0.7778.96 |
| Tor | Bundled Tor Expert Bundle |
| Pluggable transports | Bundled lyrebird and transport configuration |
| Platform | Windows x64, MSVC 2022 |

The Qt installer script downloads official Qt archives and verifies their
published hashes before extraction. The packaged browser does not require a
Python runtime or a Qt SDK.

The Windows package uses `windeployqt` and `qtpaths` from the same Qt 6.11.1
`msvc2022_64` distribution used by the build. Package-local `qt.conf` and
startup runtime selection bind Qt WebEngine to the adjacent helper, resources,
and locales even when the parent environment contains stale `QTWEBENGINE_*`
variables. The package also contains the signed Qt D3D compiler support file,
Windows SDK DXC/DXIL redistributables, and app-local VC143 runtime. Exact source
versions and hashes are recorded in `deployment-metadata.json`.

## Architecture boundary

The release uses the existing Qt Widgets shell, one tab model, one Settings
implementation, and one `AnimationPolicy`. It does not include a parallel UI
shell, a second network stack, or a remote UI runtime.

User data is stored outside the package. Automated acceptance uses isolated
`GRANGER_DATA_ROOT`, `GRANGER_SETTINGS_ROOT`, and, where required,
`GRANGER_DOWNLOAD_ROOT` directories. Release validation must not mutate the
normal user profile.

Space removal follows the persisted lifecycle:

```text
Active -> Closing -> ProfileRelease -> CleanupPending -> Cleaned
                                                \-> Failed
```

Profile references and active downloads are released before storage cleanup.
Cleanup paths are validated beneath owned roots, serialized across processes,
and retried after Windows file locks instead of reporting false success.

## Privacy boundary

Granger Browser does not promise anonymity. UI status distinguishes configured,
bootstrapping, route-verified, and failed states.

The release keeps these existing guarantees and their regression coverage:

- Tor/SOCKS routing is fail-closed; no direct fallback is presented as Tor.
- DNS and WebRTC policies remain tied to the active privacy profile.
- Tor, Onion, Space, and isolated-tab profiles retain their storage boundaries.
- HTTPS-First, request interception, content filtering, permissions, URL
  cleaning, and fingerprint protections remain enabled by policy.
- Canvas, WebGL, WebAudio, font, screen, viewport, User-Agent, and Client Hints
  behavior remains owned by the existing privacy pipeline.
- Bridge lines are parsed and validated without rewriting the saved Tor payload.
  obfs4, WebTunnel, Snowflake, vanilla, and generic future transports remain
  covered by the bridge and strategy suites.
- `Connected` is shown only after Tor bootstrap and browser-route verification.

Qt WebEngine proxy configuration is process-wide. The process applies its proxy
startup flags before WebEngine initialization.

## Letterboxing

Physical Tor-style letterboxing remains enabled. It is described as viewport
standardization and fingerprinting resistance, not anonymity.

`FingerprintViewportPolicy::standardizedSize()` selects a host-derived logical
viewport on a 200 by 100 pixel policy grid. `LetterboxedWebView` reports that
preferred size to the existing layout while keeping a zero minimum size. The
view is centered in hidden, compact, and expanded Sidebar modes. The page
scrollbar therefore remains at the right edge of the protected WebEngine view,
not at the right edge of the outer content host.

Rapid Sidebar reversal, early tiny restored viewports, and host-size changes are
covered by regression tests. The policy is not a single hard-coded 800 by 700
viewport.

## UI acceptance

Settings uses one shared layout grammar for page width, navigation width,
content width, card inset, section and column gaps, row height, control column,
footer padding, and responsive stacking. The Reports page uses the same grammar
for its two-column controls, category checkboxes, clear-on-start/exit row, and
Save footer.

Native and internal surfaces share local design tokens. Popup animations are
short-lived and reused or stopped during rapid reversal. Settings category
content uses a 150 ms opacity/2 px transition. Existing reduced-motion policy
removes decorative motion without changing final geometry or functionality.
There are no idle animation timers for these transitions.

Focused UI acceptance measures:

- aligned card and control edges across every Settings category;
- equal Reports columns, control heights, checkbox rows, and footer insets;
- responsive layouts from wide desktop to the supported narrow window;
- DPI 100, 125, 150, 175, and 200 percent;
- Russian, English, and Kazakh localization;
- rapid popup, Sidebar, tab, focus, and Settings interactions;
- fullscreen, maximized, collapsed, expanded, and hidden Sidebar states;
- reduced motion, viewport bounds, clipping, and horizontal overflow.

Reference captures for Sidebar and letterboxing are stored in
`docs/screenshots/sidebar-layout-stability/`.

## Release gate

Run the canonical gate from the repository root:

```powershell
.\scripts\build-release.ps1 `
  -QtRoot "$env:USERPROFILE\Qt\6.11.1\msvc2022_64" `
  -BuildDirectory build\desktop
```

The gate includes PE architecture/import parsing, Windows Loader checks for
critical Qt DLLs, product, new-tab/internal-route, navigation, feature, UI,
privacy, privacy-diagnostics, bridge, QR, connection-strategy, branding,
migration, DevTools, persistence, download, visual, stability, DPI, performance,
and copied-package checks. Tor validates generated strategy configurations, and
managed transport tests use the bundled executables rather than simulated
success states.

External search providers can return CAPTCHA, anti-abuse, or exit-specific
responses. Such a response is recorded as external behavior and is not relabeled
as a successful results page.

## Windows portable 0.4.1

The published release is [Granger Browser 0.4.1](https://github.com/zakhar-git/Granger-Browser/releases/tag/v0.4.1).

| Artifact | Size | SHA-256 |
| --- | ---: | --- |
| `GrangerBrowser.exe` | 15,368,704 bytes | `9E7FAE520DE9185384F2A9C1B6AE0BB809BADFA78E36A4A078A0D4A27BEAC4CA` |
| `Granger-Browser-v0.4.1-windows-x64.zip` | 189,721,477 bytes | `F0B7CAC54F68EAE4597AF3D0B3C06B0F0C32780AD70D32BDF996BFF4FF976008` |

The package contains 191 files, including 48 x64 PE32+ executables and DLLs.
The portability audit found zero unresolved imports, verified nine upstream
runtime signatures, and loaded six critical Qt DLLs through the Windows Loader,
including `Qt6WebEngineCore.dll` and `Qt6WebEngineWidgets.dll`.

The complete local acceptance suite passed on Windows 11 development host
build 26200 with the development `PATH` removed and isolated user-data roots.
The ZIP downloaded back from GitHub passed the same helper/renderer portability
smoke on fresh GitHub-hosted Windows Server 2022 (`10.0.20348`) and Windows
Server 2025 (`10.0.26100`) x64 virtual machines. Both runners loaded
`https://example.com` through Qt WebEngine after external `QTWEBENGINE_*` paths
were deliberately pointed at an incomplete helper directory.

These hosted results are not represented as physical Windows 10 or Windows 11
tests. No physical Windows 10 machine was available during this release cycle,
and the separately reported Windows 11 computer was not remotely accessible for
a post-fix rerun.

## Known limitations

- Qt WebEngine retains a process-wide proxy model.
- Pixel captures are specific to the tested Windows, GPU, driver, and DPI stack.
- External sites and Tor exits can change independently of the application.
- The executable is not digitally signed and may show an unknown-publisher
  warning.

See `BUILDING.md`, `SECURITY.md`, `NOTICE.txt`,
`docs/CROSS_DEVICE_PRIVACY_TESTING.md`, and
`docs/FULL_PAMP_INTEGRATION_AUDIT.md` for the supporting procedures and
limitations.
