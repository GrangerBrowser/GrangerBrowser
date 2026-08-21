# Windows Bootstrap Installer

`GrangerSetup.exe` is the native Windows bootstrap installer for Granger Browser. It is a separate Win32 C++20 target and does not link to Qt, WebEngine, Python, or the browser executable.

## Runtime source

The installer downloads `granger-installer-manifest.json` from the latest stable GitHub Release. The manifest identifies one complete Windows x64 portable ZIP, including its exact byte size and SHA-256 digest.

The installer never downloads individual Qt, ICU, Visual C++, Tor, I2P, or transport files. The portable ZIP and installed browser use the same canonical packaged runtime. Bundled Tor and i2pd are validated as part of that one package and are never fetched separately by Setup.

## Installation flow

1. Resolve the latest release manifest over HTTPS using WinHTTP.
2. Download the complete portable ZIP to a per-user staging directory.
3. Verify the expected size and SHA-256 digest with Windows CNG.
4. Reject unsafe ZIP paths and extract the verified package with the Windows archive tool.
5. Validate critical files, Tor signature/source metadata, runtime versions, and `release-manifest.json`.
6. Promote the staged runtime to `%LOCALAPPDATA%\Programs\Granger Browser` with rollback to the previous installation if promotion fails.
7. Create shortcuts and register per-user uninstall metadata.

The browser profile and mutable Tor/I2P state remain outside the installation directory under `%LOCALAPPDATA%\Granger\Granger Browser`. Repair, update, and normal uninstall operations preserve that data.

## Updates and uninstall

Running Setup again compares the installed version with the current stable manifest. An older installation is updated in place. The same version offers Launch, Repair, and Uninstall actions. Setup refuses to replace runtime files while `GrangerBrowser.exe` is running.

Uninstall removes program files, shortcuts, and the current-user Apps registration. Browsing data is retained unless the user explicitly selects its deletion.

## Integrity and transport

Production downloads are restricted to HTTPS and the official `zakhar-git/Granger-Browser` GitHub Release path. A package is not extracted unless its byte size and SHA-256 digest match the release manifest. The manifest and checksums are published as release assets.

## Embedded branding

`Banner_Installer/Emma.gif` is a local build-time asset. The build embeds it in `GrangerSetup.exe` as a PE `RCDATA` resource. GDI+ reads it from an in-memory stream; Setup does not create an `Emma.gif` file on the user's disk.

This is resource embedding, not cryptographic encryption. The source GIF is intentionally excluded from Git and is not shipped beside Setup or inside the installed browser directory.

## Rebuilding

Build the canonical portable package first, then run:

```powershell
.\scripts\build-installer.ps1 `
  -PackageArchive "output\distribution\Granger-Browser-v0.4.4-windows-x64.zip" `
  -Clean
```

The script verifies the GIF, configures the native x64 installer target, uses the static MSVC runtime (`/MT`), rejects Qt or dynamic MSVC imports, runs the embedded-resource self-test, and writes these ignored distribution artifacts:

- `output/distribution/GrangerSetup.exe`
- `output/distribution/granger-installer-manifest.json`
- `output/distribution/SHA256SUMS.txt`

Compiled binaries and release payloads are published through GitHub Releases, not committed to `main` and not stored with Git LFS.
