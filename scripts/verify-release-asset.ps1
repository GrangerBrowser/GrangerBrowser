[CmdletBinding()]
param(
    [string]$Repository = "zakhar-git/Granger-Browser",
    [string]$Tag = "v0.4.1",
    [string]$AssetName,
    [switch]$LegacySmoke,
    [string]$OutputDirectory = "output/remote-release-verification"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$workspaceRoot = [IO.Path]::GetFullPath($projectRoot).TrimEnd('\')
$outputRoot = [IO.Path]::GetFullPath((Join-Path $projectRoot $OutputDirectory)).TrimEnd('\')
if (-not $outputRoot.StartsWith($workspaceRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw "OutputDirectory must remain inside the project workspace."
}
if ($Repository -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' -or $Tag -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+$') {
    throw "Repository or release tag is invalid."
}

$version = $Tag.Substring(1)
if ([string]::IsNullOrWhiteSpace($AssetName)) {
    $AssetName = "Granger-Browser-$Tag-windows-x64.zip"
}
if ([IO.Path]::GetFileName($AssetName) -ne $AssetName -or
    -not $AssetName.EndsWith('.zip', [StringComparison]::OrdinalIgnoreCase)) {
    throw "AssetName must be a plain ZIP file name."
}
$checksumName = "$assetName.sha256"
$zipPath = Join-Path $outputRoot $AssetName
$checksumPath = Join-Path $outputRoot $checksumName
$extractRoot = Join-Path $outputRoot "extracted"
$packageRoot = Join-Path $extractRoot "Granger Browser"

if (Test-Path -LiteralPath $outputRoot) {
    $resolvedOutput = [IO.Path]::GetFullPath($outputRoot)
    if (-not $resolvedOutput.StartsWith($workspaceRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to replace an output directory outside the workspace."
    }
    Remove-Item -LiteralPath $outputRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $outputRoot | Out-Null

$headers = @{
    "User-Agent" = "Granger-Browser-release-verifier"
    "Accept" = "application/vnd.github+json"
    "X-GitHub-Api-Version" = "2022-11-28"
}
if (-not [string]::IsNullOrWhiteSpace($env:GITHUB_TOKEN)) {
    $headers.Authorization = "Bearer $($env:GITHUB_TOKEN)"
}
$release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repository/releases/tags/$Tag" `
    -Headers $headers -Method Get
function Save-ReleaseAsset {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Destination
    )

    $asset = @($release.assets | Where-Object { $_.name -ceq $Name }) | Select-Object -First 1
    if (-not $asset) { throw "Release $Tag does not contain $Name." }
    $downloadHeaders = $headers.Clone()
    $downloadHeaders.Accept = "application/octet-stream"
    Invoke-WebRequest -Uri ([string]$asset.url) -Headers $downloadHeaders `
        -OutFile $Destination -UseBasicParsing
}
Save-ReleaseAsset -Name $AssetName -Destination $zipPath
Save-ReleaseAsset -Name $checksumName -Destination $checksumPath

$checksumLine = (Get-Content -LiteralPath $checksumPath -Raw -Encoding ASCII).Trim()
if ($checksumLine -notmatch '^([A-Fa-f0-9]{64})\s+\*?(.+)$' -or $Matches[2] -ne $AssetName) {
    throw "Release checksum file has an invalid format."
}
$expectedZipHash = $Matches[1].ToUpperInvariant()
$actualZipHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash
if (-not $actualZipHash.Equals($expectedZipHash, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Downloaded release ZIP does not match its published SHA-256."
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
New-Item -ItemType Directory -Path $extractRoot | Out-Null
[IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $extractRoot)
if (-not (Test-Path -LiteralPath (Join-Path $packageRoot "GrangerBrowser.exe") -PathType Leaf)) {
    throw "Downloaded ZIP does not contain Granger Browser/GrangerBrowser.exe."
}

$portability = $null
if (-not $LegacySmoke) {
    $portability = & (Join-Path $PSScriptRoot "test-windows-portability.ps1") `
        -PackageDirectory $packageRoot.Substring($workspaceRoot.Length + 1)
    if (-not $portability.OK) { throw "Downloaded release failed the Windows portability audit." }
}

$executable = Join-Path $packageRoot "GrangerBrowser.exe"
$productVersion = (Get-Item -LiteralPath $executable).VersionInfo.ProductVersion
if ($productVersion -ne $version) { throw "Downloaded product version is $productVersion; expected $version." }

$oldEnvironment = @{}
$environmentNames = @(
    "PATH", "QTDIR", "CMAKE_PREFIX_PATH", "QT_PLUGIN_PATH", "QT_QPA_PLATFORM_PLUGIN_PATH",
    "QTWEBENGINEPROCESS_PATH", "QTWEBENGINE_RESOURCES_PATH", "QTWEBENGINE_LOCALES_PATH",
    "QML_IMPORT_PATH", "QML2_IMPORT_PATH", "VSINSTALLDIR", "VCINSTALLDIR",
    "VCToolsInstallDir", "VCToolsRedistDir", "WindowsSdkDir", "INCLUDE", "LIB", "LIBPATH",
    "GRANGER_DATA_ROOT", "GRANGER_SETTINGS_ROOT", "GRANGER_DOWNLOAD_ROOT"
)
foreach ($name in $environmentNames) {
    $oldEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
}

function Invoke-ReleaseSmoke {
    param([Parameter(Mandatory)][string[]]$Arguments, [int]$TimeoutSeconds = 90)

    $processInfo = New-Object Diagnostics.ProcessStartInfo
    $processInfo.FileName = $executable
    $processInfo.WorkingDirectory = $outputRoot
    $processInfo.UseShellExecute = $false
    $processInfo.CreateNoWindow = $true
    $processInfo.Arguments = (($Arguments | ForEach-Object { '"' + $_.Replace('"', '\"') + '"' }) -join ' ')
    $process = [Diagnostics.Process]::Start($processInfo)
    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
        $process.Kill()
        $process.WaitForExit()
        throw "Downloaded release smoke timed out: $($Arguments -join ' ')"
    }
    if ($process.ExitCode -ne 0) {
        throw "Downloaded release smoke failed with exit code $($process.ExitCode): $($Arguments -join ' ')"
    }
}

try {
    $env:PATH = "$(Join-Path $env:SystemRoot 'System32');$env:SystemRoot"
    foreach ($name in $environmentNames | Where-Object { $_ -notin @("PATH", "GRANGER_DATA_ROOT", "GRANGER_SETTINGS_ROOT", "GRANGER_DOWNLOAD_ROOT") }) {
        [Environment]::SetEnvironmentVariable($name, $null, "Process")
    }
    $env:GRANGER_DATA_ROOT = Join-Path $outputRoot "data"
    $env:GRANGER_SETTINGS_ROOT = Join-Path $outputRoot "settings"
    $env:GRANGER_DOWNLOAD_ROOT = Join-Path $outputRoot "downloads"

    if (-not $LegacySmoke) {
        $poisonRoot = Join-Path $outputRoot "external WebEngine runtime"
        New-Item -ItemType Directory -Path $poisonRoot | Out-Null
        $poisonedHelper = Join-Path $poisonRoot "QtWebEngineProcess.exe"
        Copy-Item -LiteralPath (Join-Path $packageRoot "QtWebEngineProcess.exe") -Destination $poisonedHelper
        $env:QTWEBENGINEPROCESS_PATH = $poisonedHelper
        $env:QTWEBENGINE_RESOURCES_PATH = $poisonRoot
        $env:QTWEBENGINE_LOCALES_PATH = $poisonRoot
    }

    $profilePath = Join-Path $outputRoot "profile-state.json"
    Invoke-ReleaseSmoke -Arguments @("--smoke-profile-state", "--smoke-output=$profilePath")
    $profile = Get-Content -LiteralPath $profilePath -Raw -Encoding UTF8 | ConvertFrom-Json
    $helperIsLocal = $LegacySmoke -or
        ([IO.Path]::GetFullPath([string]$profile.webEngineProcessPath)).Equals(
            [IO.Path]::GetFullPath((Join-Path $packageRoot "QtWebEngineProcess.exe")),
            [StringComparison]::OrdinalIgnoreCase)
    if (-not $profile.ok -or $profile.qtVersion -ne "6.11.1" -or -not $helperIsLocal) {
        throw "Downloaded release did not use its package-local Qt WebEngine helper."
    }

    $webPath = Join-Path $outputRoot "webengine-smoke.json"
    $webFixture = Join-Path $outputRoot "renderer-fixture.html"
    Set-Content -LiteralPath $webFixture -Encoding UTF8 -Value `
        '<!doctype html><meta charset="utf-8"><title>Granger renderer fixture</title><p>renderer-ok</p>'
    $webFixtureUrl = ([Uri]::new($webFixture)).AbsoluteUri
    Invoke-ReleaseSmoke -Arguments @("--smoke-url=$webFixtureUrl", "--smoke-output=$webPath")
    $web = Get-Content -LiteralPath $webPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not $web.ok -or $web.title -ne "Granger renderer fixture") {
        throw "Downloaded release renderer did not load its local fixture."
    }
} finally {
    foreach ($name in $environmentNames) {
        [Environment]::SetEnvironmentVariable($name, $oldEnvironment[$name], "Process")
    }
}

$result = [pscustomobject]@{
    OK = $true
    Repository = $Repository
    Tag = $Tag
    Asset = $AssetName
    ArchiveSize = (Get-Item -LiteralPath $zipPath).Length
    ArchiveSHA256 = $actualZipHash
    Package = $packageRoot
    ExecutableSize = (Get-Item -LiteralPath $executable).Length
    ExecutableSHA256 = (Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash
    ProductVersion = $productVersion
    LegacySmoke = [bool]$LegacySmoke
    WindowsVersion = [Environment]::OSVersion.VersionString
    Portability = $portability
    ProfileState = $profilePath
    WebEngineSmoke = $webPath
}
$result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $outputRoot "remote-verification.json") -Encoding UTF8
$result
