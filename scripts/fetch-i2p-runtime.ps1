[CmdletBinding()]
param(
    [string]$ArchivePath = "output/third-party/i2pd-download/i2pd_2.61.0_win64_mingw.zip",
    [string]$Destination = "output/i2p-runtime"
)

$ErrorActionPreference = "Stop"
$projectRoot = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot)).TrimEnd('\')
$version = "2.61.0"
$assetName = "i2pd_2.61.0_win64_mingw.zip"
$assetUrl = "https://github.com/PurpleI2P/i2pd/releases/download/2.61.0/$assetName"
$expectedSha256 = "A0A8FB199A6BC5B487DF71567791DE6997050B921D65622EF9E936FFA88BC83F"

function Resolve-WorkspaceOutputPath {
    param([Parameter(Mandatory)][string]$Path)
    $resolved = if ([IO.Path]::IsPathRooted($Path)) {
        [IO.Path]::GetFullPath($Path)
    } else {
        [IO.Path]::GetFullPath((Join-Path $projectRoot $Path))
    }
    $outputRoot = [IO.Path]::GetFullPath((Join-Path $projectRoot "output")).TrimEnd('\')
    if (-not $resolved.StartsWith($outputRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "I2P build inputs must remain under the ignored output directory: $resolved"
    }
    return $resolved
}

$archive = Resolve-WorkspaceOutputPath $ArchivePath
$runtimeRoot = Resolve-WorkspaceOutputPath $Destination
$archiveDirectory = Split-Path -Parent $archive
New-Item -ItemType Directory -Path $archiveDirectory -Force | Out-Null

if (-not (Test-Path -LiteralPath $archive -PathType Leaf)) {
    $partial = "$archive.part"
    if (Test-Path -LiteralPath $partial) { Remove-Item -LiteralPath $partial -Force }
    Invoke-WebRequest -Uri $assetUrl -OutFile $partial -UseBasicParsing
    Move-Item -LiteralPath $partial -Destination $archive
}

$actualSha256 = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
if (-not $actualSha256.Equals($expectedSha256, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Pinned i2pd archive hash mismatch. Expected $expectedSha256, got $actualSha256"
}

$extractRoot = Resolve-WorkspaceOutputPath "output/third-party/i2pd-extract-2.61.0"
if (Test-Path -LiteralPath $extractRoot) { Remove-Item -LiteralPath $extractRoot -Recurse -Force }
New-Item -ItemType Directory -Path $extractRoot -Force | Out-Null
Expand-Archive -LiteralPath $archive -DestinationPath $extractRoot -Force

$executable = Get-ChildItem -LiteralPath $extractRoot -Recurse -File -Filter "i2pd.exe" |
    Select-Object -First 1
$certificates = Get-ChildItem -LiteralPath $extractRoot -Recurse -Directory -Filter "certificates" |
    Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName "reseed") -PathType Container } |
    Select-Object -First 1
if (-not $executable -or -not $certificates) {
    throw "Official i2pd archive does not contain i2pd.exe and the reseed certificate bundle."
}

$versionOutput = (& $executable.FullName --version 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $versionOutput -notmatch '(?m)^i2pd version 2\.61\.0') {
    throw "Unexpected i2pd runtime version: $versionOutput"
}

if (Test-Path -LiteralPath $runtimeRoot) { Remove-Item -LiteralPath $runtimeRoot -Recurse -Force }
New-Item -ItemType Directory -Path $runtimeRoot -Force | Out-Null
Copy-Item -LiteralPath $executable.FullName -Destination (Join-Path $runtimeRoot "i2pd.exe")
Copy-Item -LiteralPath $certificates.FullName -Destination $runtimeRoot -Recurse
$upstreamReadme = Get-ChildItem -LiteralPath $extractRoot -Recurse -File -Filter "README.txt" |
    Select-Object -First 1
if ($upstreamReadme) {
    Copy-Item -LiteralPath $upstreamReadme.FullName -Destination (Join-Path $runtimeRoot "README.txt")
}
Copy-Item -LiteralPath (Join-Path $projectRoot "third_party/i2pd/LICENSE") `
    -Destination (Join-Path $runtimeRoot "LICENSE.txt")

$certificateCount = @(Get-ChildItem -LiteralPath (Join-Path $runtimeRoot "certificates") -Recurse -File).Count
if ($certificateCount -lt 1) { throw "The staged i2pd certificate bundle is empty." }

Remove-Item -LiteralPath $extractRoot -Recurse -Force

[pscustomobject]@{
    OK = $true
    Version = $version
    Source = $assetUrl
    Archive = $archive
    ArchiveSHA256 = $actualSha256
    RuntimeRoot = $runtimeRoot
    Executable = Join-Path $runtimeRoot "i2pd.exe"
    ExecutableSHA256 = (Get-FileHash -LiteralPath (Join-Path $runtimeRoot "i2pd.exe") -Algorithm SHA256).Hash
    CertificateCount = $certificateCount
    License = "BSD-3-Clause"
}
