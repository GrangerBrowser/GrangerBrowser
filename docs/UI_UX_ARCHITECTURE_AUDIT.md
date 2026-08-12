# Granger Browser UI/UX architecture audit

Audit date: 2026-08-12

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

- The product uses one token and animation foundation across native and local
  HTML surfaces. Route-scoped internal-page rules remain incremental so a
  presentation change cannot silently replace page behavior.
- Settings owns one layout grammar for page width, navigation, content width,
  card inset, section and column gaps, row height, control column, footer, and
  responsive stacking. Individual categories do not own competing page grids.
- Settings already has an accessible custom select implementation with viewport
  collision handling, typeahead, keyboard navigation, and focus restoration.
- Download UI already reflects real `QWebEngineDownloadRequest` state through
  snapshots and actions. The modernization is presentation-only.
- Sidebar dimensions and physical viewport letterboxing are covered by focused
  stability tests. Styling must not alter their geometry or privacy semantics.
- Native and internal scrollbars use the same local active and idle policy.

## Settings geometry

`InternalPages::settings()` applies the canonical Settings layout once. Repeated
cards, forms, rows, controls, and footers consume the same CSS custom properties.
At desktop width the page uses an 1180 px maximum, a 224 px navigation column,
a 38 px shell gap, and an 860 px content maximum. Cards use an 18 px inset, a
20 px two-column gap, and a 66 px minimum row height. The layout stacks before a
control would become impractically narrow.

Reports has explicit body and footer elements. Its four controls, six category
checkboxes, two cleanup checkboxes, divider, and Save action use the shared grid
instead of relying on last-child margin overrides. UI regression tests compare
actual bounding rectangles for equal widths, aligned row origins, shared column
starts, card containment, and absence of horizontal overflow across every
Settings category.

## Motion lifecycle

`AnimationPolicy` remains the only native duration and reduced-motion owner.
Settings content uses a 150 ms opacity and 2 px entrance transition. Popup
animations are reused, stopped on reversal, and restored to their final opacity
when hidden. They do not own layout geometry and do not run while the interface
is idle. Both the operating-system reduced-motion preference and the existing
application policy produce the same final state without decorative movement.

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
