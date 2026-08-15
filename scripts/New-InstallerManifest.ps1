[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PackageArchive,
    [string]$OutputDirectory = "output/distribution",
    [string]$Repository = "zakhar-git/Granger-Browser",
    [string]$MinimumWindowsVersion = "10.0.17763"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$workspaceRoot = [IO.Path]::GetFullPath($projectRoot).TrimEnd('\')
$archivePath = if ([IO.Path]::IsPathRooted($PackageArchive)) {
    [IO.Path]::GetFullPath($PackageArchive)
} else {
    [IO.Path]::GetFullPath((Join-Path $projectRoot $PackageArchive))
}
$outputRoot = [IO.Path]::GetFullPath((Join-Path $projectRoot $OutputDirectory))
foreach ($path in @($archivePath, $outputRoot)) {
    if (-not $path.StartsWith($workspaceRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Installer manifest paths must remain inside the project workspace: $path"
    }
}
if (-not (Test-Path -LiteralPath $archivePath -PathType Leaf)) {
    throw "Portable archive not found: $archivePath"
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead($archivePath)
try {
    $metadataEntry = $zip.Entries | Where-Object {
        $_.FullName.Replace('\', '/').EndsWith('/deployment-metadata.json', [StringComparison]::OrdinalIgnoreCase)
    } | Select-Object -First 1
    if (-not $metadataEntry) { throw "Portable archive has no deployment-metadata.json" }
    $reader = [IO.StreamReader]::new($metadataEntry.Open(), [Text.Encoding]::UTF8, $true)
    try { $metadata = $reader.ReadToEnd() | ConvertFrom-Json }
    finally { $reader.Dispose() }
} finally {
    $zip.Dispose()
}

$version = ([string]$metadata.ProductVersion).Trim()
if ($version -notmatch '^\d+\.\d+\.\d+$' -or [string]$metadata.Architecture -ne 'x64') {
    throw "Portable deployment metadata has an unsupported version or architecture."
}
$expectedArchiveName = "Granger-Browser-v$version-windows-x64.zip"
if ([IO.Path]::GetFileName($archivePath) -ne $expectedArchiveName) {
    throw "Portable archive name must be $expectedArchiveName"
}

New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null
$manifestPath = Join-Path $outputRoot 'granger-installer-manifest.json'
$archiveHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
[ordered]@{
    schemaVersion = 1
    version = $version
    architecture = 'x64'
    minimumWindowsVersion = $MinimumWindowsVersion
    packageUrl = "https://github.com/$Repository/releases/download/v$version/$expectedArchiveName"
    packageSize = (Get-Item -LiteralPath $archivePath).Length
    sha256 = $archiveHash
} | ConvertTo-Json | Set-Content -LiteralPath $manifestPath -Encoding UTF8

[pscustomobject]@{
    OK = $true
    Version = $version
    Manifest = $manifestPath
    Package = $archivePath
    PackageSize = (Get-Item -LiteralPath $archivePath).Length
    PackageSHA256 = $archiveHash.ToUpperInvariant()
    PackageUrl = "https://github.com/$Repository/releases/download/v$version/$expectedArchiveName"
}
