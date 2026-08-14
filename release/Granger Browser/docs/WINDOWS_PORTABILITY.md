# Windows Portability

The supported packaged target is 64-bit Windows 10 or Windows 11 on an x64
processor. The portable folder is self-contained for the application, Qt 6,
Qt WebEngine, the app-local VC143 runtime, Tor, and bundled pluggable
transports. It does not require a Qt SDK, Visual Studio, CMake, Ninja, or a
developer `PATH` on the destination computer.

## Download

Use the `Granger-Browser-<version>-windows-x64.zip` asset from the GitHub
Releases page. Extract the entire `Granger Browser` directory before starting
`GrangerBrowser.exe`.

Do not treat GitHub's automatically generated `Source code (zip)` or `Source
code (tar.gz)` downloads as portable application packages. Release binaries
stored with Git LFS may be represented by small text pointer files in source
archives. Such a pointer is not a Windows executable and Windows rejects it
before application startup.

The matching `.sha256` release asset records the SHA-256 of the portable ZIP.
The extracted package also contains `release-manifest.json`, which records the
size and SHA-256 of each packaged file.

## Packaging Gates

`scripts/build-release.ps1` performs a clean x64 Release build, runs
`windeployqt`, deploys the app-local VC143 runtime, adds the Tor runtime, and
then runs the copied-package acceptance suite. QML debugger plugins are not
shipped.

`scripts/test-windows-portability.ps1` rejects:

- malformed PE files;
- x86 or ARM64 executables and DLLs;
- unresolved imports on the build host;
- Git LFS pointer files inside the package;
- missing Qt WebEngine, platform, VC runtime, Tor, or transport files;
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
