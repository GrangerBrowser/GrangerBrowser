[CmdletBinding()]
param(
    [string]$Version = '0.4.4',
    [string]$Installer = 'output/distribution/GrangerSetup.exe',
    [string]$AppImage,
    [string]$OutputDirectory = 'output/distribution'
)

$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot)).TrimEnd('\')

function Resolve-ProjectPath([string]$Path) {
    $resolved = if ([IO.Path]::IsPathRooted($Path)) {
        [IO.Path]::GetFullPath($Path)
    } else {
        [IO.Path]::GetFullPath((Join-Path $projectRoot $Path))
    }
    if (-not $resolved.StartsWith($projectRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Combined release path escaped the project: $resolved"
    }
    return $resolved
}

if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw "Invalid release version: $Version" }
if ([string]::IsNullOrWhiteSpace($AppImage)) {
    $AppImage = "output/linux/GrangerBrowser-$Version-x86_64.AppImage"
}
$installerPath = Resolve-ProjectPath $Installer
$appImagePath = Resolve-ProjectPath $AppImage
$outputRoot = Resolve-ProjectPath $OutputDirectory
foreach ($artifact in @($installerPath, $appImagePath)) {
    if (-not (Test-Path -LiteralPath $artifact -PathType Leaf)) {
        throw "Release artifact not found: $artifact"
    }
}

$trackedChanges = & git -C $projectRoot status --porcelain --untracked-files=no
if ($LASTEXITCODE -ne 0 -or $trackedChanges) {
    throw 'Commit tracked source changes before creating the combined release.'
}
$head = (& git -C $projectRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $head -notmatch '^[0-9a-f]{40}$') {
    throw 'Unable to resolve the source revision.'
}

$rootName = "GrangerBrowser-v$Version"
$stagingRoot = Resolve-ProjectPath ("output/combined-release-v$Version-staging")
if (-not $stagingRoot.StartsWith((Join-Path $projectRoot 'output') + '\',
        [StringComparison]::OrdinalIgnoreCase)) {
    throw "Unsafe combined release staging path: $stagingRoot"
}
if (Test-Path -LiteralPath $stagingRoot) {
    Remove-Item -LiteralPath $stagingRoot -Recurse -Force
}
$packageRoot = Join-Path $stagingRoot $rootName
$windowsRoot = Join-Path $packageRoot 'Windows'
$linuxRoot = Join-Path $packageRoot 'Linux'
$sourceRoot = Join-Path $packageRoot 'Source'
New-Item -ItemType Directory -Path $windowsRoot,$linuxRoot,$sourceRoot -Force | Out-Null
Copy-Item -LiteralPath $installerPath -Destination (Join-Path $windowsRoot 'GrangerSetup.exe')
Copy-Item -LiteralPath $appImagePath -Destination (Join-Path $linuxRoot 'GrangerBrowser-x86_64.AppImage')

$sourceArchive = Join-Path $stagingRoot 'source.zip'
& git -C $projectRoot archive --format=zip --output=$sourceArchive HEAD
if ($LASTEXITCODE -ne 0) { throw 'Unable to create the tracked source snapshot.' }
Expand-Archive -LiteralPath $sourceArchive -DestinationPath $sourceRoot
Remove-Item -LiteralPath $sourceArchive -Force

$installerHash = (Get-FileHash -LiteralPath (Join-Path $windowsRoot 'GrangerSetup.exe') -Algorithm SHA256).Hash
$appImageHash = (Get-FileHash -LiteralPath (Join-Path $linuxRoot 'GrangerBrowser-x86_64.AppImage') -Algorithm SHA256).Hash
@(
    "$installerHash  Windows/GrangerSetup.exe"
    "$appImageHash  Linux/GrangerBrowser-x86_64.AppImage"
) | Set-Content -LiteralPath (Join-Path $packageRoot 'SHA256SUMS.txt') -Encoding ASCII

$readme = @"
# Granger Browser $Version

Granger Browser is a privacy-oriented desktop browser based on Qt WebEngine. It supports private routing through bundled Tor and I2P components and includes fingerprint-resistance measures. These protections reduce exposure; they are not a guarantee of anonymity.

## Supported packages

- Windows 10/11 x64
- Linux x86_64 with glibc 2.34 or newer

## Windows

Run ``Windows/GrangerSetup.exe`` and follow the installer prompts. Setup is self-contained: the verified Windows runtime is embedded and installation does not require GitHub, another server, Qt, Visual Studio, or a separate runtime download.

## Linux

Make the AppImage executable and launch it:

``````bash
chmod +x Linux/GrangerBrowser-x86_64.AppImage
./Linux/GrangerBrowser-x86_64.AppImage
``````

If FUSE is unavailable:

``````bash
APPIMAGE_EXTRACT_AND_RUN=1 ./Linux/GrangerBrowser-x86_64.AppImage
``````

## Source code

The complete tracked source snapshot for commit ``$head`` is in ``Source/``. Build instructions are in ``Source/BUILDING.md`` and ``Source/docs/LINUX.md``.

## Checksums

``SHA256SUMS.txt`` contains checksums for the Windows installer and Linux AppImage. The checksum for the outer ZIP is distributed as the adjacent ``$rootName.zip.sha256`` file because an archive cannot contain a stable checksum of itself.
"@
$readme | Set-Content -LiteralPath (Join-Path $packageRoot 'README.md') -Encoding UTF8

$releaseDate = Get-Date -Format 'yyyy-MM-dd'
$changelog = @"
# Changelog

## $Version - $releaseDate

- Replaced the broken network bootstrap installer with a self-contained Windows x64 installer.
- Removed GitHub and other install-time payload dependencies.
- Embedded and integrity-checked the complete accepted Windows runtime.
- Preserved the accepted Linux x86_64 AppImage without modification.
- Included the tracked source snapshot and SHA-256 checksums.

No browser, Tor, I2P, routing, or privacy behavior was changed by this installer fix.
"@
$changelog | Set-Content -LiteralPath (Join-Path $packageRoot 'CHANGELOG.md') -Encoding UTF8

New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null
$archivePath = Join-Path $outputRoot "$rootName.zip"
if (Test-Path -LiteralPath $archivePath) { Remove-Item -LiteralPath $archivePath -Force }
$tar = Join-Path $env:SystemRoot 'System32/tar.exe'
if (-not (Test-Path -LiteralPath $tar -PathType Leaf)) { throw 'Windows tar.exe is unavailable.' }
Push-Location $stagingRoot
try {
    & $tar -a -cf $archivePath $rootName
    if ($LASTEXITCODE -ne 0) { throw 'Unable to create the combined release ZIP.' }
} finally {
    Pop-Location
}

$archiveHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash
$archiveChecksum = Join-Path $outputRoot "$rootName.zip.sha256"
"$archiveHash  $rootName.zip" | Set-Content -LiteralPath $archiveChecksum -Encoding ASCII
$combinedChecksums = Join-Path $outputRoot "$rootName-SHA256SUMS.txt"
@(
    "$installerHash  $rootName/Windows/GrangerSetup.exe"
    "$appImageHash  $rootName/Linux/GrangerBrowser-x86_64.AppImage"
    "$archiveHash  $rootName.zip"
) | Set-Content -LiteralPath $combinedChecksums -Encoding ASCII

$listing = @(& $tar -tf $archivePath)
if ($LASTEXITCODE -ne 0 `
    -or "$rootName/Windows/GrangerSetup.exe" -notin $listing `
    -or "$rootName/Linux/GrangerBrowser-x86_64.AppImage" -notin $listing `
    -or "$rootName/Source/installer/src/main.cpp" -notin $listing `
    -or @($listing | Where-Object { $_ -match '(^|/)(\.git|build|output)/' }).Count -ne 0) {
    throw 'Combined release ZIP structure validation failed.'
}

[pscustomobject]@{
    OK = $true
    Version = $Version
    SourceCommit = $head
    Archive = $archivePath
    ArchiveSize = (Get-Item -LiteralPath $archivePath).Length
    ArchiveSHA256 = $archiveHash
    InstallerSize = (Get-Item -LiteralPath $installerPath).Length
    InstallerSHA256 = $installerHash
    AppImageSize = (Get-Item -LiteralPath $appImagePath).Length
    AppImageSHA256 = $appImageHash
    Checksums = $combinedChecksums
}
