[CmdletBinding()]
param(
    [string]$QtRoot = $env:QTDIR,
    [string]$BuildDirectory = "build/desktop",
    [string]$Destination = "release/.staging",
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($QtRoot)) { $QtRoot = $env:CMAKE_PREFIX_PATH }
if ([string]::IsNullOrWhiteSpace($QtRoot) -or -not (Test-Path -LiteralPath $QtRoot)) {
    throw "QtRoot was not found. Pass -QtRoot or set QTDIR/CMAKE_PREFIX_PATH."
}

if (-not $SkipBuild) {
    & (Join-Path $PSScriptRoot "compile-release.ps1") -QtRoot $QtRoot -BuildDirectory $BuildDirectory
    if ($LASTEXITCODE -ne 0) { throw "Build script failed." }
}

$buildPath = Join-Path $projectRoot $BuildDirectory
$sourceExecutable = Join-Path $buildPath "Release/GrangerBrowser.exe"
$packageRoot = Join-Path $projectRoot $Destination
$resolvedProject = [IO.Path]::GetFullPath($projectRoot).TrimEnd('\')
$resolvedPackage = [IO.Path]::GetFullPath($packageRoot)
if (-not $resolvedPackage.StartsWith($resolvedProject + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw "Destination must remain inside the project workspace."
}
$allowedStagingDirectories = @(
    [IO.Path]::GetFullPath((Join-Path $projectRoot "release/.staging")),
    [IO.Path]::GetFullPath((Join-Path $projectRoot "release/.ui-stage"))
)
$isAllowedStagingDirectory = @($allowedStagingDirectories | Where-Object {
    $_.Equals($resolvedPackage, [StringComparison]::OrdinalIgnoreCase)
}).Count -ne 0
if (-not $isAllowedStagingDirectory) {
    throw "Destination must be release/.staging or release/.ui-stage. Use build-release.ps1 to promote the canonical release."
}
if (Test-Path -LiteralPath $resolvedPackage) {
    Remove-Item -LiteralPath $resolvedPackage -Recurse -Force
}
New-Item -ItemType Directory -Path $resolvedPackage | Out-Null
Copy-Item -LiteralPath $sourceExecutable -Destination (Join-Path $resolvedPackage "GrangerBrowser.exe")

$windeployqt = Join-Path $QtRoot "bin/windeployqt.exe"
if (-not (Test-Path -LiteralPath $windeployqt)) { throw "windeployqt.exe was not found under $QtRoot" }
& $windeployqt --release --compiler-runtime --no-system-d3d-compiler --dir $resolvedPackage (Join-Path $resolvedPackage "GrangerBrowser.exe")
if ($LASTEXITCODE -ne 0) { throw "windeployqt failed." }
$nmeaPlugin = Join-Path $resolvedPackage "position/qtposition_nmea.dll"
if (Test-Path -LiteralPath $nmeaPlugin) {
    Remove-Item -LiteralPath $nmeaPlugin -Force
}

$vcRoots = Get-ChildItem -Path (Join-Path $env:ProgramFiles "Microsoft Visual Studio/2022") -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    Get-ChildItem -Path (Join-Path $_.FullName "VC/Redist/MSVC") -Directory -ErrorAction SilentlyContinue
} | Sort-Object Name -Descending
$vcCrt = $vcRoots | ForEach-Object {
    $candidate = Join-Path $_.FullName "x64/Microsoft.VC143.CRT"
    if (Test-Path -LiteralPath $candidate) { $candidate }
} | Select-Object -First 1
if ([string]::IsNullOrWhiteSpace($vcCrt)) { throw "Microsoft.VC143.CRT app-local runtime was not found." }
Copy-Item -Path (Join-Path $vcCrt "*.dll") -Destination $resolvedPackage -Force

$expertRoot = Join-Path $projectRoot "output/tor-expert"
$runtimeTor = Join-Path $resolvedPackage "runtime/tor"
$runtimePt = Join-Path $runtimeTor "pluggable_transports"
$runtimeData = Join-Path $runtimeTor "data"
New-Item -ItemType Directory -Path $runtimePt -Force | Out-Null
New-Item -ItemType Directory -Path $runtimeData -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $expertRoot "tor/tor.exe") -Destination $runtimeTor
Copy-Item -LiteralPath (Join-Path $expertRoot "data/geoip") -Destination $runtimeData
Copy-Item -LiteralPath (Join-Path $expertRoot "data/geoip6") -Destination $runtimeData
Copy-Item -LiteralPath (Join-Path $expertRoot "tor/pluggable_transports/lyrebird.exe") -Destination $runtimePt
Copy-Item -LiteralPath (Join-Path $expertRoot "tor/pluggable_transports/pt_config.json") -Destination $runtimePt
if (Test-Path -LiteralPath (Join-Path $expertRoot "tor/pluggable_transports/conjure-client.exe")) {
    Copy-Item -LiteralPath (Join-Path $expertRoot "tor/pluggable_transports/conjure-client.exe") -Destination $runtimePt
}

$licenses = Join-Path $resolvedPackage "licenses"
$releaseDocs = Join-Path $resolvedPackage "docs"
$releaseSidebarScreenshots = Join-Path $releaseDocs "screenshots/sidebar-layout-stability"
New-Item -ItemType Directory -Path $licenses -Force | Out-Null
New-Item -ItemType Directory -Path $releaseDocs -Force | Out-Null
New-Item -ItemType Directory -Path $releaseSidebarScreenshots -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $projectRoot "granger/resources/qr-fixtures/release-bridge.png") -Destination (Join-Path $resolvedPackage "bridge.png")
Copy-Item -LiteralPath (Join-Path $projectRoot "README.md") -Destination $resolvedPackage
Copy-Item -LiteralPath (Join-Path $projectRoot "BUILDING.md") -Destination $resolvedPackage
Copy-Item -LiteralPath (Join-Path $projectRoot "SECURITY.md") -Destination $resolvedPackage
Copy-Item -LiteralPath (Join-Path $projectRoot "NOTICE.txt") -Destination $resolvedPackage
Copy-Item -LiteralPath (Join-Path $projectRoot "docs/GRANGER_BROWSER_RELEASE_REPORT.md") -Destination $releaseDocs
Copy-Item -LiteralPath (Join-Path $projectRoot "docs/FULL_PAMP_INTEGRATION_AUDIT.md") -Destination $releaseDocs
Copy-Item -LiteralPath (Join-Path $projectRoot "docs/CROSS_DEVICE_PRIVACY_TESTING.md") -Destination $releaseDocs
Copy-Item -LiteralPath (Join-Path $projectRoot "docs/GIT_WORKFLOW.md") -Destination $releaseDocs
Copy-Item -Path (Join-Path $projectRoot "docs/screenshots/sidebar-layout-stability/*.png") `
    -Destination $releaseSidebarScreenshots
Copy-Item -LiteralPath (Join-Path $projectRoot "NOTICE.txt") -Destination $licenses
Copy-Item -LiteralPath (Join-Path $projectRoot "third_party/quirc/LICENSE") -Destination (Join-Path $licenses "quirc-LICENSE.txt")
Copy-Item -LiteralPath (Join-Path $projectRoot "third_party/lucide-LICENSE.txt") -Destination (Join-Path $licenses "lucide-LICENSE.txt")
Copy-Item -LiteralPath (Join-Path $projectRoot "third_party/simple-icons-LICENSE.md") -Destination (Join-Path $licenses "simple-icons-LICENSE.md")
Copy-Item -LiteralPath (Join-Path $projectRoot "third_party/easylist/CC-BY-SA-3.0.txt") -Destination (Join-Path $licenses "EasyList-CC-BY-SA-3.0.txt")
Copy-Item -LiteralPath (Join-Path $projectRoot "third_party/easylist/README.md") -Destination (Join-Path $licenses "EasyList-SOURCES.md")
Copy-Item -LiteralPath (Join-Path $projectRoot "third_party/adguard-filters/LICENSE") -Destination (Join-Path $licenses "AdGuard-Filters-GPL-3.0.txt")
Copy-Item -LiteralPath (Join-Path $projectRoot "docs/CONTENT_FILTER_SOURCES.md") -Destination (Join-Path $licenses "CONTENT_FILTER_SOURCES.md")
Copy-Item -LiteralPath (Join-Path $projectRoot "docs/UI_ASSET_SOURCES.md") -Destination (Join-Path $licenses "UI_ASSET_SOURCES.md")
Copy-Item -LiteralPath (Join-Path $projectRoot "docs/UI_DESIGN_REFERENCES.md") -Destination (Join-Path $licenses "UI_DESIGN_REFERENCES.md")
Copy-Item -LiteralPath (Join-Path $projectRoot "docs/SPACES_DOWNLOAD_REFERENCES.md") -Destination (Join-Path $licenses "SPACES_DOWNLOAD_REFERENCES.md")
Copy-Item -LiteralPath (Join-Path $projectRoot "granger/pamp_lite/ATTRIBUTION.md") -Destination (Join-Path $licenses "Pamp-Lite-ATTRIBUTION.md")
Copy-Item -Path (Join-Path $expertRoot "docs/*") -Destination $licenses -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "Create-Shortcuts.ps1") -Destination $resolvedPackage

$required = @(
    "GrangerBrowser.exe", "Qt6Core.dll", "Qt6Gui.dll", "Qt6Widgets.dll", "Qt6WebEngineCore.dll",
    "Qt6WebEngineWidgets.dll", "QtWebEngineProcess.exe", "platforms/qwindows.dll", "MSVCP140.dll",
    "VCRUNTIME140.dll", "VCRUNTIME140_1.dll",
    "resources/icudtl.dat", "resources/qtwebengine_resources.pak", "SECURITY.md", "NOTICE.txt", "docs/GRANGER_BROWSER_RELEASE_REPORT.md", "docs/FULL_PAMP_INTEGRATION_AUDIT.md", "docs/CROSS_DEVICE_PRIVACY_TESTING.md", "docs/GIT_WORKFLOW.md",
    "docs/screenshots/sidebar-layout-stability/sidebar-hidden.png", "docs/screenshots/sidebar-layout-stability/sidebar-rail.png",
    "docs/screenshots/sidebar-layout-stability/sidebar-expanded.png", "docs/screenshots/sidebar-layout-stability/sidebar-tabs-expanded.png",
    "docs/screenshots/sidebar-layout-stability/sidebar-tabs-collapsed.png", "docs/screenshots/sidebar-layout-stability/sidebar-collapsed.png",
    "docs/screenshots/sidebar-layout-stability/letterbox-hidden.png", "docs/screenshots/sidebar-layout-stability/letterbox-rail.png",
    "docs/screenshots/sidebar-layout-stability/letterbox-expanded.png", "docs/screenshots/sidebar-layout-stability/letterbox-toggle-stress.png",
    "docs/screenshots/sidebar-layout-stability/duckduckgo-rail.png", "docs/screenshots/sidebar-layout-stability/duckduckgo-expanded.png",
    "docs/screenshots/sidebar-layout-stability/duckduckgo-after-toggle-stress.png", "docs/screenshots/sidebar-layout-stability/sidebar-100.png",
    "docs/screenshots/sidebar-layout-stability/sidebar-150.png", "docs/screenshots/sidebar-layout-stability/sidebar-200.png",
    "licenses/quirc-LICENSE.txt", "licenses/lucide-LICENSE.txt", "licenses/simple-icons-LICENSE.md", "licenses/EasyList-CC-BY-SA-3.0.txt", "licenses/CONTENT_FILTER_SOURCES.md", "licenses/UI_ASSET_SOURCES.md", "licenses/UI_DESIGN_REFERENCES.md", "licenses/SPACES_DOWNLOAD_REFERENCES.md", "licenses/Pamp-Lite-ATTRIBUTION.md", "bridge.png", "runtime/tor/tor.exe",
    "runtime/tor/data/geoip", "runtime/tor/data/geoip6", "runtime/tor/pluggable_transports/lyrebird.exe"
)
foreach ($relative in $required) {
    $candidate = Join-Path $resolvedPackage $relative
    if (-not (Test-Path -LiteralPath $candidate)) { throw "Package validation failed; missing $relative" }
}

$forbiddenFullPampDirectories = @(Get-ChildItem -LiteralPath $resolvedPackage -Recurse -Directory | Where-Object {
    $_.Name -in @("pentest", "pamp")
})
if ($forbiddenFullPampDirectories.Count -ne 0) {
    throw "Package validation failed; an unreviewed full Pamp directory is present."
}
$forbiddenPythonExecutables = @(Get-ChildItem -LiteralPath $resolvedPackage -Recurse -File | Where-Object {
    $_.Name -in @("python.exe", "pythonw.exe")
})
if ($forbiddenPythonExecutables.Count -ne 0) {
    throw "Package validation failed; an app-local Python executable is not part of the reviewed browser runtime."
}
$appLocalPythonDlls = @(Get-ChildItem -LiteralPath $resolvedPackage -Recurse -File -Filter "python*.dll")
if ($appLocalPythonDlls.Count -ne 0) {
    throw "Package validation failed; app-local Python DLLs are not part of the reviewed browser runtime."
}

$versionInfo = (Get-Item -LiteralPath (Join-Path $resolvedPackage "GrangerBrowser.exe")).VersionInfo
if ($versionInfo.ProductName -ne "Granger Browser" -or
    $versionInfo.FileDescription -ne "Granger Browser privacy browser" -or
    $versionInfo.OriginalFilename -ne "GrangerBrowser.exe" -or
    $versionInfo.InternalName -ne "GrangerBrowser") {
    throw "Packaged executable VersionInfo does not match the Granger Browser identity."
}

$legacyStem = [Text.Encoding]::ASCII.GetString([byte[]](68,97,114,107,83,101,97,114,99,104))
$legacyTokens = @(
    $legacyStem,
    $legacyStem.ToLowerInvariant(),
    ($legacyStem -creplace '([a-z0-9])([A-Z])', '$1_$2').ToLowerInvariant(),
    ($legacyStem -creplace '([a-z0-9])([A-Z])', '$1 $2')
) | Select-Object -Unique
$legacyNamedEntries = @(Get-ChildItem -LiteralPath $resolvedPackage -Recurse -Force | Where-Object {
    $name = $_.Name
    @($legacyTokens | Where-Object { $name.IndexOf($_, [StringComparison]::OrdinalIgnoreCase) -ge 0 }).Count -ne 0
})
if ($legacyNamedEntries.Count -ne 0) {
    throw "Packaged paths retain a legacy product identifier: $($legacyNamedEntries.FullName -join ', ')"
}
$brandAuditFiles = @(Get-ChildItem -LiteralPath $resolvedPackage -Recurse -File | Where-Object {
    $_.Extension -in @('.md', '.txt', '.ps1', '.json')
})
$legacyTextMatches = foreach ($file in $brandAuditFiles) {
    $content = [IO.File]::ReadAllText($file.FullName)
    foreach ($token in $legacyTokens) {
        if ($content.IndexOf($token, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            $file.FullName
            break
        }
    }
}
if (@($legacyTextMatches).Count -ne 0) {
    throw "Packaged user-visible text retains a legacy product identifier: $($legacyTextMatches -join ', ')"
}

$looseUiAssetNames = @(
    "DuckDuck.png", "Google.png", "bing.png", "brave.png", "startpage.png",
    "mojeek.png", "yandex.png", "onion.png", "emma watson.png", "emma watson.jpg",
    "surface-9c42.jpg", "ai.png", "icon.jpg", "icon-source.jpg", "app-icon.png", "app-icon.svg",
    "GrangerBrowser.ico"
)
$looseUiAssets = @(Get-ChildItem -LiteralPath $resolvedPackage -Recurse -File | Where-Object {
    $looseUiAssetNames -contains $_.Name
})
$sourceAssetDirectories = @(Get-ChildItem -LiteralPath $resolvedPackage -Recurse -Directory | Where-Object {
    $_.Name -eq "poiskoviki"
})
if ($looseUiAssets.Count -ne 0 -or $sourceAssetDirectories.Count -ne 0) {
    $unexpectedUiAssets = @($looseUiAssets.FullName) + @($sourceAssetDirectories.FullName)
    throw "Loose UI source assets were packaged: $($unexpectedUiAssets -join ', ')"
}

$manifest = Get-ChildItem -LiteralPath $resolvedPackage -Recurse -File | ForEach-Object {
    [pscustomobject]@{
        Path = $_.FullName.Substring($resolvedPackage.TrimEnd('\').Length).TrimStart('\')
        Size = $_.Length
        SHA256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
    }
}
$manifest | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $resolvedPackage "release-manifest.json") -Encoding UTF8
Write-Host "Packaged $resolvedPackage"
