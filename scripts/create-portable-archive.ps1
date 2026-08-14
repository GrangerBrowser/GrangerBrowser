[CmdletBinding()]
param(
    [string]$PackageDirectory = "release/Granger Browser",
    [string]$OutputDirectory = "output/distribution",
    [string]$ArchiveName
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$workspaceRoot = [IO.Path]::GetFullPath($projectRoot).TrimEnd('\')
$packageRoot = [IO.Path]::GetFullPath((Join-Path $projectRoot $PackageDirectory)).TrimEnd('\')
$outputRoot = [IO.Path]::GetFullPath((Join-Path $projectRoot $OutputDirectory)).TrimEnd('\')
foreach ($path in @($packageRoot, $outputRoot)) {
    if (-not $path.StartsWith($workspaceRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Portable archive paths must remain inside the project workspace: $path"
    }
}
if (-not (Test-Path -LiteralPath (Join-Path $packageRoot "GrangerBrowser.exe") -PathType Leaf)) {
    throw "Canonical packaged executable not found under $packageRoot"
}

$portability = & (Join-Path $PSScriptRoot "test-windows-portability.ps1") `
    -PackageDirectory $packageRoot.Substring($workspaceRoot.Length + 1)
if (-not $portability.OK) { throw "Windows portability validation failed." }

$version = (Get-Item -LiteralPath (Join-Path $packageRoot "GrangerBrowser.exe")).VersionInfo.ProductVersion
if ([string]::IsNullOrWhiteSpace($version)) { throw "Packaged executable has no product version." }
if ([string]::IsNullOrWhiteSpace($ArchiveName)) {
    $normalizedVersion = $version.Trim()
    if (-not $normalizedVersion.StartsWith("v", [StringComparison]::OrdinalIgnoreCase)) {
        $normalizedVersion = "v$normalizedVersion"
    }
    $ArchiveName = "Granger-Browser-$normalizedVersion-windows-x64.zip"
}
if (-not $ArchiveName.EndsWith(".zip", [StringComparison]::OrdinalIgnoreCase) -or
    [IO.Path]::GetFileName($ArchiveName) -ne $ArchiveName) {
    throw "ArchiveName must be a plain .zip file name."
}

New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null
$archivePath = Join-Path $outputRoot $ArchiveName
$checksumPath = $archivePath + ".sha256"
if (Test-Path -LiteralPath $archivePath) { Remove-Item -LiteralPath $archivePath -Force }
if (Test-Path -LiteralPath $checksumPath) { Remove-Item -LiteralPath $checksumPath -Force }

Add-Type -AssemblyName System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::CreateFromDirectory(
    $packageRoot,
    $archivePath,
    [IO.Compression.CompressionLevel]::Optimal,
    $true
)

$zip = [IO.Compression.ZipFile]::OpenRead($archivePath)
try {
    $entryName = ([IO.Path]::GetFileName($packageRoot) + "/GrangerBrowser.exe")
    $entry = $zip.Entries | Where-Object {
        $_.FullName.Replace('\', '/').Equals($entryName, [StringComparison]::OrdinalIgnoreCase)
    } | Select-Object -First 1
    if (-not $entry) { throw "Portable archive does not contain $entryName" }

    $expectedExecutable = Join-Path $packageRoot "GrangerBrowser.exe"
    if ($entry.Length -ne (Get-Item -LiteralPath $expectedExecutable).Length) {
        throw "Archived executable size does not match the canonical package."
    }
    $entryStream = $entry.Open()
    try {
        $first = $entryStream.ReadByte()
        $second = $entryStream.ReadByte()
        if ($first -ne 0x4d -or $second -ne 0x5a) {
            throw "Archived executable is not a PE file."
        }
    } finally {
        $entryStream.Dispose()
    }

    $entryStream = $entry.Open()
    try {
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $archivedExecutableHash = ([BitConverter]::ToString($sha.ComputeHash($entryStream))).Replace('-', '') }
        finally { $sha.Dispose() }
    } finally {
        $entryStream.Dispose()
    }
    if (-not $archivedExecutableHash.Equals($portability.ExecutableSHA256, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Archived executable hash does not match the canonical package."
    }
} finally {
    $zip.Dispose()
}

$archiveHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash
"$archiveHash  $ArchiveName" | Set-Content -LiteralPath $checksumPath -Encoding ASCII

[pscustomobject]@{
    OK = $true
    Archive = $archivePath
    ArchiveSize = (Get-Item -LiteralPath $archivePath).Length
    ArchiveSHA256 = $archiveHash
    ChecksumFile = $checksumPath
    ExecutableSize = $portability.ExecutableSize
    ExecutableSHA256 = $portability.ExecutableSHA256
    Machine = $portability.Machine
}
