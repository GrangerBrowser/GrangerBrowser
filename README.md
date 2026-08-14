<div align="center">

# Granger Browser

### Privacy-focused Chromium browser with built-in Tor routing.

Native Windows browser written in C++20 and Qt 6, combining
Chromium compatibility, configurable privacy protection and managed Tor
inside a standalone desktop application.

[Download for Windows](../../releases/latest) ·
[Build from Source](BUILDING.md) ·
[Security](SECURITY.md) ·
[Documentation](docs/)

</div>

---

## Overview

Granger Browser is a native privacy-oriented browser for Windows built
with C++20, Qt Widgets and Qt WebEngine.

It combines a Chromium-based browsing engine with privacy controls,
isolated browsing environments, content blocking and integrated Tor
routing without requiring Python, a separate Tor Browser installation
or a development environment.

> **Beta software**
>
> Granger is under active development. Some functionality may change
> between releases and platform-specific issues may still occur.

## Highlights

- **Integrated Tor** — Direct Tor, bridges, obfs4, WebTunnel, Snowflake
  and external/upstream proxy configurations.
- **Privacy profiles** — configurable fingerprinting, WebRTC, Canvas,
  WebGL, cookies, scripts and storage policies.
- **Content blocking** — EasyList/EasyPrivacy-based network and cosmetic
  filtering with local rule processing.
- **Spaces** — isolated browsing environments with separate identities.
- **Site controls** — per-origin JavaScript, WebAssembly, WebGL,
  cookies, WebRTC, autoplay and permission policies.
- **HTTPS-First** — secure navigation with configurable HTTP exceptions.
- **Native desktop UI** — vertical tabs, downloads, history, bookmarks,
  settings and session restoration.
- **Portable Windows build** — extract and run without Qt, Python or
  Visual Studio installed.

## Screenshots

<!-- Replace these with actual Granger screenshots -->

| Browser | Privacy |
| --- | --- |
| ![Granger Browser](docs/images/browser.png) | ![Privacy Settings](docs/images/privacy.png) |

| Tor | Settings |
| --- | --- |
| ![Tor](docs/images/tor.png) | ![Settings](docs/images/settings.png) |

## Download

### Windows x64

Download the newest portable build from:

**[Latest Granger Browser Release](../../releases/latest)**

Then:

1. Download `Granger-Browser-*-windows-x64.zip`
2. Verify the provided SHA-256 checksum
3. Extract the complete archive
4. Run `GrangerBrowser.exe`

No Python, Qt SDK or Visual Studio installation is required.

> Do not download GitHub's automatically generated **Source code**
> archives if you only want to run Granger. Use the Windows portable
> asset attached to the release.

---

## Privacy

Granger exposes privacy controls directly instead of presenting a
single opaque "private mode".

Protection includes:

- Canvas and graphical API protection
- WebRTC restrictions
- third-party cookie blocking
- Referer reduction
- Global Privacy Control
- tracking parameter removal
- redirect tracking protection
- script and iframe controls
- WebAssembly controls
- persistent-storage policies
- per-site privacy rules

Granger does **not** claim that enabling these options automatically
makes a user anonymous.

## Tor

Tor support is integrated into the browser and its connection state is
tracked separately across:

**Configuration → Bootstrap → Browser Route Verification**

Supported strategies include:

- Direct Tor
- obfs4
- WebTunnel
- Snowflake
- meek_lite
- vanilla bridges
- external Tor SOCKS
- upstream SOCKS
- upstream HTTP CONNECT

Granger does not report **Connected** merely because the Tor process is
running. Browser traffic must pass route verification first.

## Content Blocking

Granger includes local network and cosmetic filtering with support for:

- EasyList
- EasyPrivacy
- tracking protection
- known browser mining domains
- social widgets
- regional filtering
- URL tracking-parameter removal
- user-defined blocked domains

Filtering is performed locally without sending visited URLs to an
external filtering service.

---

## Build from Source

### Requirements

- Windows 10/11 x64
- Visual Studio 2022
- MSVC x64
- CMake 3.24+
- Qt 6.11.1

Required Qt modules:

`Widgets`, `Svg`, `Network`, `WebEngineWidgets`, `WebChannel`,
`Positioning`

Build:

```powershell
.\scripts\build-release.ps1 `
    -QtRoot "$env:USERPROFILE\Qt\6.11.1\msvc2022_64"
