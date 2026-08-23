# Windows Installer

`GrangerSetup.exe` is the native Windows installer for Granger Browser. It is a separate Win32 C++20 target and does not link to Qt, WebEngine, Python, or the browser executable.

## Runtime source

The canonical distribution build embeds `granger-installer-manifest.json` and one complete Windows x64 portable ZIP. The manifest records the archive's exact byte size and SHA-256 digest, so the installer remains self-contained when the release host is unavailable.

The installer never resolves individual Qt, ICU, Visual C++, Tor, I2P, or transport files. The portable ZIP and installed browser use the same canonical packaged runtime. Bundled Tor and i2pd are validated as part of that one package and are never fetched separately by Setup. CMake rejects installer builds that do not provide both embedded release resources.

## Installation flow

1. Read the embedded release manifest and portable ZIP.
2. Copy the bundled ZIP to a per-user staging directory.
3. Verify the expected size and SHA-256 digest with Windows CNG.
4. Reject unsafe ZIP paths and extract the verified package with the Windows archive tool.
5. Validate critical files, Tor signature/source metadata, runtime versions, and `release-manifest.json`.
6. Promote the staged runtime to `%LOCALAPPDATA%\Programs\Granger Browser` with rollback to the previous installation if promotion fails.
7. Create shortcuts and register per-user uninstall metadata.

The browser profile and mutable Tor/I2P state remain outside the installation directory under `%LOCALAPPDATA%\Granger\Granger Browser`. Repair, update, and normal uninstall operations preserve that data.

## Updates and uninstall

Running Setup again compares the installed version with the bundled manifest. An older installation is updated in place. The same version offers Launch, Repair, and Uninstall actions. Setup refuses to replace runtime files while `GrangerBrowser.exe` is running.

Uninstall removes program files, shortcuts, and the current-user Apps registration. Browsing data is retained unless the user explicitly selects its deletion.

## Integrity and offline operation

The package is not extracted unless its byte size and SHA-256 digest match the embedded release manifest. Setup has no production download path, remote manifest URL, or install-time server dependency. The build audit rejects Windows networking imports and remote URL strings in `GrangerSetup.exe`.

The offline acceptance harness launches Setup in a Windows AppContainer with zero network capabilities. It first verifies that a control DNS/HTTPS request is blocked, then installs and validates the embedded runtime. The installed browser is launched separately with its normal Chromium sandbox against a local renderer fixture:

```powershell
.\scripts\test-installer-offline.ps1
```

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

The script embeds the portable ZIP and manifest, verifies the GIF, configures the native x64 installer target, uses the static MSVC runtime (`/MT`), rejects Qt, dynamic MSVC, or Windows networking imports, scans for remote URL strings, and runs isolated embedded install/uninstall acceptance before writing these ignored distribution artifacts:

- `output/distribution/GrangerSetup.exe`
- `output/distribution/granger-installer-manifest.json`
- `output/distribution/SHA256SUMS.txt`

Compiled binaries and release payloads are distributed separately from `main`; they are not committed to the source branch and are not stored with Git LFS.
