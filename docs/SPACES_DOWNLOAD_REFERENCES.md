# Granger Browser Spaces and Download UI Reference Audit

Audit date: 2026-08-08

## Scope and architecture result

Granger Browser is a Qt 6 Widgets application using Qt WebEngine Widgets. It does not
contain a Chromium source tree, Chromium Views/Aura browser shell, CEF, WinUI,
or a WebUI implementation of the browser chrome. The packaged Qt WebEngine
6.11.1 runtime reports Chromium 140.0.7339.225 and security patch level
148.0.7778.96 through Qt's runtime APIs.

The implementation therefore remains in Granger Browser-owned Qt classes:

- `granger/containers/ContainerManager.*`: persistent Space metadata and
  one persistent `QWebEngineProfile` per user Space/container.
- `granger/tabs/TabManager.*`: global stable-ID tab model, per-Space
  projection, vertical tab UI, keyboard navigation, and drag/drop.
- `granger/ui/DownloadUi.*`: native shelf and panel views over immutable
  download snapshots.
- `granger/ui/MainWindow.*`: adapters to the existing
  `QWebEngineDownloadRequest` objects and safe cross-Space navigation.
- `granger/ui/AnimationPolicy.*`: shared duration, easing, and reduced
  motion policy.

No second tab model, downloader, network client, profile store, or GUI
framework was added.

## Exact references

### Qt 6.11.1

- Documentation:
  - https://doc.qt.io/qt-6.11/qwebenginedownloadrequest.html
  - https://doc.qt.io/qt-6.11/qwebengineprofile.html#downloadRequested
- Studied: ownership and lifetime of `QWebEngineDownloadRequest`, the
  profile-level `downloadRequested` signal, real state/byte notifier signals,
  and the supported accept, cancel, pause, and resume operations.
- Transfer: no Qt documentation text or example source was copied.
- License: Qt documentation terms published by The Qt Company; the packaged Qt
  runtime remains covered by the project's existing Qt notices and deployment
  terms.

### Chromium 140.0.7339.225

- Repository: https://chromium.googlesource.com/chromium/src
- Tag: `140.0.7339.225`
- Commit: `aa324b3754009b927f7db643b2e837d6a5383b04`
- Studied files:
  - `chrome/browser/ui/views/tabs/tab_drag_controller.cc`
  - `chrome/browser/ui/views/tabs/tab_container_impl.cc`
  - `chrome/browser/ui/views/download/bubble/download_bubble_row_view.cc`
  - `ui/views/animation/bounds_animator.cc`
- Studied concepts: stable model identity during drag, one model commit on
  drop, cancellation, pinned boundaries, view/model separation, download-row
  state decomposition, and animation lifecycle ownership.
- Transfer: no Chromium source code, patch, icon, string, or layout value was
  copied. Granger Browser uses Qt APIs and independently written code.
- License: Chromium BSD-style license.

### Mozilla Gecko

- Repository: https://github.com/mozilla/gecko-dev
- Commit: `5836a062726f715fda621338a17b51aff30d0a8c`
- Studied files:
  - `browser/components/downloads/DownloadsCommon.sys.mjs`
  - `browser/components/downloads/content/downloads.js`
  - `browser/components/downloads/content/downloadsPanel.inc.xhtml`
  - `browser/components/downloads/content/downloads.css`
- Studied concepts: active/recent grouping, row action visibility, persistent
  history entry presentation, and truthful interrupted states.
- Transfer: no Gecko source, markup, CSS, icon, or string was copied.
- License: Mozilla Public License 2.0.

### Zen Browser

- Repository: https://github.com/zen-browser/desktop
- Development commit inspected: `ccbd934482ab0f454a066fcb0698407a9a42967e`
- Release reference: tag `1.19.6b`, commit
  `db3eea65b70826d16f044db58f058598d3745601`
- Studied material: repository structure and the 1.19.6b release notes about
  non-blocking Space switching, reduced motion, and low-FPS behavior.
- Studied concepts: Spaces as a visible level above tabs, compact collapsed
  navigation, and non-blocking transitions.
- Transfer: no Zen source code, branding, artwork, CSS, strings, or dimensions
  were copied. Granger Browser retains its own layout and isolation semantics.
- License: Mozilla Public License 2.0.

### Brave Core

- Repository: https://github.com/brave/brave-core
- Commit: `a77ce3e794795c41da5a13e20f030784dbdd5646`
- Studied paths: root `README.md`, `chromium_src/`, and `patches/` structure.
- Studied concept: keeping product-owned classes and overlays separate from
  the upstream Chromium tree to reduce future update conflicts.
- Transfer: no Brave source, patch, asset, or string was copied.
- License: Mozilla Public License 2.0.

## Attribution and transfer statement

This file records conceptual and API research. All Granger Browser implementation
in this change was written for Granger Browser against its existing Qt architecture.
No third-party source fragment was transferred, so no source-level derivative
notice was introduced. This audit file is packaged as
`licenses/SPACES_DOWNLOAD_REFERENCES.md` so the reviewed projects, revisions,
paths, and licenses remain visible in the portable Release.
