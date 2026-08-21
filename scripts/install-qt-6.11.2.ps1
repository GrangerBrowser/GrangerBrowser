[CmdletBinding()]
param(
    [string]$OutputRoot = "$env:USERPROFILE\Qt",
    [string]$ArchiveCache = "$env:LOCALAPPDATA\GrangerBrowserBuild\qt-6.11.2-archives"
)

$ErrorActionPreference = "Stop"
$version = "6.11.2"
$arch = "msvc2022_64"
$target = [IO.Path]::GetFullPath((Join-Path $OutputRoot "$version\$arch"))
$resolvedRoot = [IO.Path]::GetFullPath($OutputRoot).TrimEnd('\')
$resolvedCache = [IO.Path]::GetFullPath($ArchiveCache)
if (-not $target.StartsWith($resolvedRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw "Qt installation target escaped OutputRoot."
}
if (Test-Path -LiteralPath $target) {
    throw "Qt installation already exists: $target"
}

$desktopRepository = "https://download.qt.io/online/qtsdkrepository/windows_x86/desktop/qt6_6112/qt6_6112_msvc2022_64"
$webEngineRepository = "https://download.qt.io/online/qtsdkrepository/windows_x86/extensions/qtwebengine/6112/msvc2022_64"
$desktopMetadata = [xml](Invoke-WebRequest -Uri "$desktopRepository/Updates.xml" -UseBasicParsing -TimeoutSec 60).Content
$webEngineMetadata = [xml](Invoke-WebRequest -Uri "$webEngineRepository/Updates.xml" -UseBasicParsing -TimeoutSec 60).Content

function Get-PackageNode {
    param([xml]$Metadata, [string]$Name)
    $node = @($Metadata.Updates.PackageUpdate) | Where-Object { $_.Name -eq $Name }
    if (@($node).Count -ne 1) { throw "Expected one official package named $Name." }
    return $node
}

$basePackage = Get-PackageNode $desktopMetadata "qt.qt6.6112.win64_msvc2022_64"
$packages = @(
    [pscustomobject]@{
        Repository = $desktopRepository
        Node = $basePackage
        Archives = @($basePackage.DownloadableArchives -split ',\s*' | Where-Object {
            $_ -match '^(qtbase|qtsvg|qtdeclarative|qttools|qttranslations|d3dcompiler_47|opengl32sw-)'
        })
    },
    [pscustomobject]@{
        Repository = $desktopRepository
        Node = Get-PackageNode $desktopMetadata "qt.qt6.6112.addons.qtpositioning.win64_msvc2022_64"
        Archives = @()
    },
    [pscustomobject]@{
        Repository = $desktopRepository
        Node = Get-PackageNode $desktopMetadata "qt.qt6.6112.addons.qtwebchannel.win64_msvc2022_64"
        Archives = @()
    },
    [pscustomobject]@{
        Repository = $webEngineRepository
        Node = Get-PackageNode $webEngineMetadata "extensions.qtwebengine.6112.win64_msvc2022_64"
        Archives = @()
    }
)
foreach ($package in $packages) {
    if ($package.Archives.Count -eq 0) {
        $package.Archives = @($package.Node.DownloadableArchives -split ',\s*')
    }
}

New-Item -ItemType Directory -Path $resolvedCache -Force | Out-Null
$staleStagingDirectories = @(Get-ChildItem -LiteralPath $resolvedRoot -Directory -Force -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -like '.qt-6.11.2-staging-*' -and
    $_.FullName.StartsWith($resolvedRoot + '\', [StringComparison]::OrdinalIgnoreCase)
})
foreach ($staleStaging in $staleStagingDirectories) {
    Remove-Item -LiteralPath $staleStaging.FullName -Recurse -Force
}
$staging = Join-Path $resolvedRoot (".qt-6.11.2-staging-" + [guid]::NewGuid().ToString('N'))
if (-not $staging.StartsWith($resolvedRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw "Qt staging directory escaped OutputRoot."
}
New-Item -ItemType Directory -Path $staging -Force | Out-Null
$archiveReport = @()

try {
    foreach ($package in $packages) {
        foreach ($archiveName in $package.Archives) {
            $remoteName = "$($package.Node.Version)$archiveName"
            $remoteUrl = "$($package.Repository)/$($package.Node.Name)/$remoteName"
            $shaUrl = "$remoteUrl.sha1"
            $shaResponse = Invoke-WebRequest -Uri $shaUrl -UseBasicParsing -TimeoutSec 60
            $shaText = if ($shaResponse.Content -is [byte[]]) {
                [Text.Encoding]::ASCII.GetString($shaResponse.Content)
            } else {
                [string]$shaResponse.Content
            }
            $expectedSha1 = (($shaText.Trim() -split '\s+')[0]).ToUpperInvariant()
            if ($expectedSha1 -notmatch '^[0-9A-F]{40}$') {
                throw "Invalid SHA-1 metadata for $remoteName"
            }
            $localArchive = Join-Path $resolvedCache $remoteName
            $needsDownload = -not (Test-Path -LiteralPath $localArchive)
            if (-not $needsDownload) {
                $needsDownload = (Get-FileHash -LiteralPath $localArchive -Algorithm SHA1).Hash -ne $expectedSha1
            }
            if ($needsDownload) {
                $partial = "$localArchive.partial"
                if (Test-Path -LiteralPath $partial) { Remove-Item -LiteralPath $partial -Force }
                $downloadUrl = $remoteUrl
                try {
                    $mirrorList = Invoke-WebRequest -Uri "$remoteUrl.mirrorlist" -UseBasicParsing -TimeoutSec 60
                    $mirrorUrls = @($mirrorList.Links | ForEach-Object { $_.href } | Where-Object {
                        $_ -match '^https://' -and $_.EndsWith('/' + $remoteName, [StringComparison]::Ordinal)
                    })
                    $mirrorUrl = @($mirrorUrls | Where-Object {
                        ([uri]$_).Host -eq 'ftp.fau.de'
                    } | Select-Object -First 1)
                    if ($mirrorUrl.Count -eq 0) { $mirrorUrl = @($mirrorUrls | Select-Object -First 1) }
                    $mirrorUrl = $mirrorUrl | Select-Object -First 1
                    if (-not [string]::IsNullOrWhiteSpace($mirrorUrl)) { $downloadUrl = $mirrorUrl }
                } catch {
                    Write-Verbose "Mirror list unavailable for $remoteName; using the canonical URL."
                }
                Write-Host "Downloading $remoteName from $(([uri]$downloadUrl).Host)"
                & curl.exe --fail --location --retry 5 --retry-delay 2 --silent --show-error --output $partial $downloadUrl
                if ($LASTEXITCODE -ne 0) { throw "Download failed: $downloadUrl" }
                if ((Get-FileHash -LiteralPath $partial -Algorithm SHA1).Hash -ne $expectedSha1) {
                    Remove-Item -LiteralPath $partial -Force
                    throw "SHA-1 verification failed: $remoteName"
                }
                Move-Item -LiteralPath $partial -Destination $localArchive -Force
            }
            $actualSha1 = (Get-FileHash -LiteralPath $localArchive -Algorithm SHA1).Hash
            if ($actualSha1 -ne $expectedSha1) { throw "Cached archive verification failed: $remoteName" }
            & tar.exe -xf $localArchive -C $staging
            if ($LASTEXITCODE -ne 0) { throw "Archive extraction failed: $remoteName" }
            $archiveReport += [pscustomobject]@{
                Package = $package.Node.Name
                Archive = $remoteName
                SHA1 = $actualSha1
                Size = (Get-Item -LiteralPath $localArchive).Length
            }
        }
    }

    $qtConf = Join-Path $staging "bin\qt.conf"
    @"
[Paths]
Prefix=..
"@ | Set-Content -LiteralPath $qtConf -Encoding ASCII

    $required = @(
        "bin\Qt6Core.dll",
        "bin\Qt6Widgets.dll",
        "bin\Qt6Svg.dll",
        "bin\Qt6Positioning.dll",
        "bin\Qt6WebChannel.dll",
        "bin\Qt6WebEngineCore.dll",
        "bin\Qt6WebEngineWidgets.dll",
        "bin\QtWebEngineProcess.exe",
        "bin\windeployqt.exe",
        "lib\cmake\Qt6\Qt6Config.cmake",
        "lib\cmake\Qt6WebEngineWidgets\Qt6WebEngineWidgetsConfig.cmake",
        "resources\qtwebengine_resources.pak"
    )
    foreach ($relative in $required) {
        if (-not (Test-Path -LiteralPath (Join-Path $staging $relative))) {
            throw "Installed Qt staging tree is missing $relative"
        }
    }

    $versionOutput = (& (Join-Path $staging "bin\qtpaths.exe") --qt-version).Trim()
    if ($LASTEXITCODE -ne 0 -or $versionOutput -ne $version) {
        throw "qtpaths reported '$versionOutput' instead of $version"
    }
    New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force | Out-Null
    [IO.Directory]::Move($staging, $target)

    [pscustomobject]@{
        OK = $true
        QtVersion = $versionOutput
        Architecture = $arch
        Target = $target
        DesktopRepository = $desktopRepository
        WebEngineRepository = $webEngineRepository
        ArchiveCount = $archiveReport.Count
        DownloadedBytes = ($archiveReport | Measure-Object -Property Size -Sum).Sum
        Archives = $archiveReport
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path (Split-Path -Parent $target) "install-report.json") -Encoding UTF8
} catch {
    if (Test-Path -LiteralPath $staging) {
        Remove-Item -LiteralPath $staging -Recurse -Force
    }
    throw
}

Write-Host "Installed verified Qt $version to $target"
