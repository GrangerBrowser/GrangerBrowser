# Windows Portability

The supported packaged target is 64-bit Windows 10 (1809 or newer) or Windows 11 on an x64
processor. The portable folder is self-contained for the application, Qt 6,
Qt WebEngine, the app-local VC143 runtime, Tor, and bundled pluggable
transports. It does not require a Qt SDK, Visual Studio, CMake, Ninja, or a
developer `PATH` on the destination computer.

## Download

Use the `Granger-Browser-v<version>-windows-x64.zip` asset from the GitHub
Releases page. Extract the entire `Granger Browser` directory before starting
`GrangerBrowser.exe`.

Do not treat GitHub's automatically generated `Source code (zip)` or `Source
code (tar.gz)` downloads as portable application packages. The repository is
source-oriented; packaged binaries are distributed only as GitHub Release
assets and are not stored in `main` or Git LFS.

The matching `.sha256` release asset records the SHA-256 of the portable ZIP.
The extracted package also contains `release-manifest.json`, which records the
size and SHA-256 of each packaged file.

## Packaging Gates

`scripts/build-release.ps1` performs a clean x64 Release build, runs
`windeployqt`, deploys the app-local VC143 runtime, adds the Tor runtime, and
then runs the copied-package acceptance suite. Package-local `qt.conf` and
`QTWEBENGINE_*` runtime selection keep the helper, resources, and locales next
to the application. The D3D compiler from the selected Qt distribution and the
DXC/DXIL redistributables from the selected Windows SDK are included. QML
debugger plugins are not shipped.

`scripts/test-windows-portability.ps1` rejects:

- malformed PE files;
- x86 or ARM64 executables and DLLs;
- unresolved imports on the build host;
- Git LFS pointer files inside the package;
- missing Qt WebEngine, platform, VC runtime, Tor, or transport files;
- non-local `qt.conf` paths or mismatched deployment metadata;
- invalid upstream signatures for Qt, VC, or D3D runtime files;
- a Windows Loader failure for critical Qt/WebEngine DLLs;
- QML debugger tooling;
- release-manifest size or hash mismatches;
- machine-specific user paths in packaged text files.

`scripts/create-portable-archive.ps1` creates the portable ZIP only after those
checks pass. It reopens the ZIP and verifies that the archived executable is a
full `MZ`/PE file with the same size and SHA-256 as the canonical package.

## Clean-Environment Test

The release acceptance harness copies the package to a path containing spaces,
starts it from an unrelated working directory, limits `PATH` to Windows system
directories, removes Qt and Visual Studio development variables from the child
environment, and uses isolated data, settings, and download roots. This test is
not a substitute for a clean Windows virtual machine; release records must say
explicitly which physical or virtual Windows versions were tested.

`scripts/verify-release-asset.ps1` downloads the published ZIP and checksum
back from GitHub, verifies SHA-256, extracts it into a fresh directory, repeats
the PE/Loader audit, runs the WebEngine helper with poisoned external runtime
paths, and loads a real HTTPS page. The release workflow runs this check on a
clean GitHub-hosted Windows Server runner; that result is useful remote evidence
but is not reported as a physical Windows 10 or Windows 11 test.
