# Granger Browser UI/UX architecture audit

Audit date: 2026-08-09

## Runtime ownership

Granger Browser is a Qt 6 Widgets and Qt WebEngine Widgets application. The UI
modernization stays inside the existing owners:

- `granger/ui/DesignTokens.h`: shared color, spacing, radius, typography, size,
  shadow, and motion tokens.
- `granger/ui/ThemeManager.cpp`: native Qt palette and QSS for browser chrome,
  dialogs, menus, forms, downloads, Sidebar, and scrollbars.
- `granger/ui/AnimationPolicy.*`: duration, easing, reduced-motion, and global
  animation enablement.
- `granger/browser/InternalPages.cpp`: local HTML/CSS/JavaScript for Settings,
  History, Downloads, Spaces, and other `about:` pages.
- `granger/ui/DownloadUi.*`: views over existing immutable download snapshots.
- `granger/tabs/TabManager.*`: existing Sidebar and tab model projection.
- `granger/ui/NavigationBar.*` and `granger/ui/MainWindow.*`: browser toolbar,
  popup positioning, and actions.

No QML, WebUI framework, second tab model, second downloader, remote UI runtime,
or network-backed asset loader is required.

## Findings

- The product already has a strong token and animation foundation, but some
  colors are repeated in `QPalette`, QSS, and internal-page overrides.
- Internal pages contain legacy base CSS followed by newer scoped overrides.
  Migration should be incremental and route-scoped to avoid a risky rewrite.
- Settings already has an accessible custom select implementation with viewport
  collision handling, typeahead, keyboard navigation, and focus restoration.
- Download UI already reflects real `QWebEngineDownloadRequest` state through
  snapshots and actions. The modernization is presentation-only.
- Sidebar dimensions and physical viewport letterboxing are covered by focused
  stability tests. Styling must not alter their geometry or privacy semantics.
- Native and internal scrollbars are locally styled but visually heavier than
  the requested minimal treatment and have no shared interaction policy yet.

## Frozen privacy boundary

This work does not change Tor, SOCKS, DNS routing, bridges, pluggable transports,
route verification, profile isolation, container storage, request interception,
content blocking, HTTPS-First, WebRTC protection, fingerprint defenses, user-agent
semantics, download security, or privacy defaults.

`BrowserTab::updateLetterbox()` and the physical Tor-style viewport
standardization remain enabled and unchanged. Margins around the protected
viewport are expected fingerprint-resistance behavior, not unused UI space.

## Asset and reference policy

All runtime UI resources remain compiled local resources. There are no CDN,
remote font, remote icon, analytics, or telemetry requests. Public UI libraries
are used only as interaction and accessibility references; source-transfer and
license details remain recorded in `docs/UI_DESIGN_REFERENCES.md`.
