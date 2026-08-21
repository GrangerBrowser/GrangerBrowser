# Native Linux build

## Status

The Linux target is a native x86_64 C++20/Qt build. It does not use Wine or
wrap the Windows executable. Linux packaging is currently a local release
candidate workflow; there is no public Linux download, release tag, or GitHub
Release asset.

The reference build environment is the GitHub-hosted Ubuntu 22.04 image. The
manual `Build Linux local RC` workflow builds with GCC, CMake 3.24 or newer,
Ninja, and the official Qt 6.11.2 `linux_gcc_64` SDK. Required Qt modules are
Widgets, Svg, Network, Concurrent, WebEngineWidgets, WebChannel, Positioning,
and SerialPort. SerialPort is a transitive runtime dependency of Qt's NMEA
positioning plugin.

## Build

Install the native build and AppImage tools listed in
`.github/workflows/linux-local-rc.yml`, then install the official Qt 6.11.2
Linux SDK. The workflow uses `aqtinstall` 3.3.0 only as build tooling:

```bash
aqt install-qt -O "$HOME/Qt" linux desktop 6.11.2 linux_gcc_64 \
  -m qtwebengine qtwebchannel qtpositioning qtserialport
```

Build the local AppImage from the repository root:

```bash
export QT_ROOT="$HOME/Qt/6.11.2/gcc_64"
scripts/build-linux-appimage.sh
```

Generated files remain below ignored `output/` storage:

```text
output/linux/GrangerBrowser-0.4.4-x86_64.AppImage
output/linux/SHA256SUMS-linux.txt
output/linux/linux-build-report.json
output/linux/acceptance/
```

The packaging script performs a Release build, installs into an AppDir,
deploys Qt and Qt WebEngine with pinned linuxdeploy tools, adds the validated
privacy runtimes and notices, rejects glibc/loader bundling and unresolved
libraries, and then creates the AppImage. The AppImage, AppDir, downloaded SDK,
runtime archives, profiles, logs, and acceptance captures must not be committed.

Pinned AppImage packaging tools:

- linuxdeploy `1-alpha-20251107-1`, SHA-256
  `C20CD71E3A4E3B80C3483CEF793CDA3F4E990ACA14014D23C544CA3CE1270B4D`
- linuxdeploy Qt plugin `1-alpha-20250213-1`, SHA-256
  `15106BE885C1C48A021198E7E1E9A48CE9D02A86DD0A1848F00BDBF3C1C92724`

Both tools are fetched from their official GitHub release repositories and
validated before execution. Their MIT license texts and source records are
stored under `third_party/linuxdeploy/` and copied into the AppImage.

## Privacy runtimes

`scripts/fetch-linux-runtimes.sh` accepts only pinned official x86_64 inputs.

Tor runtime:

- Tor Expert Bundle 15.0.20 for Linux x86_64
- Tor 0.4.9.11 and lyrebird 0.8.1
- Archive SHA-256: `3B39A2A7FBF43EF28B9AE0A6AFCA02A12935232F81769E4FEF7472D6B5676EAF`
- Tor binary SHA-256: `3D3D7C6BDCAF0F55D55A7C28F2EA6C52CB3D2785A6BD9E466BDFB29E841F2780`
- lyrebird SHA-256: `63F1FD917851E406CFE8AE5750C6A9CA1C48CA59DD3195F207AC15AF2EFA1522`
- Conjure SHA-256: `10CF795F21F136A38C1989DC93B6B687A9D30A91775873F006524B08634732C0`
- Tor Browser Developers primary fingerprint: `EF6E286DDA85EA2A4BA7DE684E2C6E8793298290`

The detached signature is validated in a temporary GnuPG home. A signature by
the current signing subkey is accepted only when GnuPG reports the pinned
primary fingerprint as its issuer. The archive and every packaged Tor runtime
file are checked before staging.

I2P runtime:

- PurpleI2P i2pd 2.61.0 Ubuntu Jammy amd64 package
- Package SHA-256: `09348999D4561C46037E3CC2AA2B9D76EC7AC3007DB2C1D4A9F92B20B9CA8687`
- i2pd binary SHA-256: `252823E8F3DDE6232D2A178027D2A249AFA81B7A4595273BCDBE4CD3500852B1`
- License: BSD-3-Clause

The package metadata must report `amd64` and version `2.61.0-1jammy1`. At
least 20 upstream certificates are required. Granger never falls back to a
system `/usr/bin/tor` or `/usr/bin/i2pd` when a bundled runtime is missing.

## Runtime paths

The AppImage mount is read-only. Executables, Qt plugins, WebEngine resources,
Tor, and i2pd are read from the AppImage. Mutable state follows Qt/XDG user
locations:

```text
settings: $XDG_CONFIG_HOME/Granger/Granger Browser.conf
data:     $XDG_DATA_HOME/Granger/Granger Browser/
cache:    $XDG_CACHE_HOME/Granger/Granger Browser/
runtime:  $XDG_RUNTIME_DIR/ (Qt/AppImage transient state)
```

When an XDG variable is unset, Qt uses the corresponding directory below
`~/.config`, `~/.local/share`, or `~/.cache`. Browser profiles, Tor data,
i2pd NetDB/keys/address book, logs, and generated configuration are never
written into the AppImage mount or source tree.

## Network contract

Linux uses the same stable loopback gateway and destination policy as Windows:

```text
Qt WebEngine -> Granger loopback gateway -> verified Tor or I2P backend
```

No verified private route means no browsing. There is no system proxy, system
DNS, or direct-network fallback. `.onion` requires Tor, `.i2p` requires I2P,
and clearnet requires Tor. I2P has no enabled clearnet outproxy.

External Chromium proxy, resolver, and sandbox overrides are removed or
rejected before WebEngine initialization. QUIC is disabled and host resolution
is constrained by the packaged Chromium policy. Test-only offline modes use a
real loopback gateway that remains closed.

## Sandbox and acceptance

The package does not set `--no-sandbox` or `QTWEBENGINE_DISABLE_SANDBOX`.
`scripts/test-linux-appimage.sh` launches the copied AppImage from a detached
path with poisoned Qt variables, verifies package-local Qt/WebEngine paths,
runs the privacy and deterministic route suites, audits ELF dependencies, and
requires a renderer with seccomp filter mode 2 and no `--no-sandbox` flag.

Run the acceptance scripts on native Linux:

```bash
scripts/test-linux-appimage.sh
sudo scripts/test-linux-network-fail-closed.sh
GRANGER_LINUX_FULL_LIVE_ACCEPTANCE=1 scripts/test-linux-private-routes.sh
```

The namespace test uses a disposable network namespace, veth pair, packet
capture, and controlled non-loopback listener. It must report zero direct
browser TCP/UDP/DNS traffic. Exit status 77 means the host could not provide
the required namespace/capture capabilities and the packet result remains
`UNVERIFIED`; it is not a pass.

## Known limitations

- A second independent Linux laptop has not yet completed first-run acceptance.
- X11 is exercised through Xvfb in the reference workflow. Wayland, XWayland,
  FUSE behavior, and Intel/AMD/NVIDIA hardware coverage require physical-host
  testing.
- Chromium sandbox startup depends on normal unprivileged namespace support in
  the host kernel. Granger does not disable the sandbox when that support is
  unavailable.
- Linux uses a coherent Linux UA, `navigator.platform`, and Client Hints
  identity. Engine, fonts, graphics drivers, kernel, desktop stack, and other
  platform surfaces can still distinguish Linux and are not an anonymity
  guarantee.
- The AppImage is a local RC artifact only. Public redistribution also requires
  completion of the project and third-party obligations in `DISTRIBUTION.md`.
