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
$QtRoot = [IO.Path]::GetFullPath($QtRoot).TrimEnd('\')

function Assert-ValidPublisherSignature {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$PublisherPattern
    )

    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
        -not $signature.SignerCertificate -or
        $signature.SignerCertificate.Subject -notmatch $PublisherPattern) {
        throw "Unexpected Authenticode signature for $Path ($($signature.Status))."
    }
}

function Get-DeploymentFileRecord {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$RelativePath,
        [Parameter(Mandatory)][string]$Source
    )

    $path = Join-Path $Root $RelativePath
    $item = Get-Item -LiteralPath $path
    [pscustomobject]@{
        Path = $RelativePath.Replace('\', '/')
        Source = $Source
        Version = [string]$item.VersionInfo.FileVersion
        Size = $item.Length
        SHA256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    }
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
    [IO.Path]::GetFullPath((Join-Path $projectRoot "release/.ui-stage")),
    [IO.Path]::GetFullPath((Join-Path $projectRoot "release/.local-staging"))
)
$isAllowedStagingDirectory = @($allowedStagingDirectories | Where-Object {
    $_.Equals($resolvedPackage, [StringComparison]::OrdinalIgnoreCase)
}).Count -ne 0
if (-not $isAllowedStagingDirectory) {
    throw "Destination must be an approved release staging directory. Use a release orchestrator to promote the canonical release."
}
if (Test-Path -LiteralPath $resolvedPackage) {
    Remove-Item -LiteralPath $resolvedPackage -Recurse -Force
}
New-Item -ItemType Directory -Path $resolvedPackage | Out-Null
Copy-Item -LiteralPath $sourceExecutable -Destination (Join-Path $resolvedPackage "GrangerBrowser.exe")

$windeployqt = Join-Path $QtRoot "bin/windeployqt.exe"
$qtpaths = Join-Path $QtRoot "bin/qtpaths.exe"
if (-not (Test-Path -LiteralPath $windeployqt)) { throw "windeployqt.exe was not found under $QtRoot" }
if (-not (Test-Path -LiteralPath $qtpaths)) { throw "qtpaths.exe was not found under $QtRoot" }
& $windeployqt --release --compiler-runtime --qtpaths $qtpaths `
    --skip-plugin-types qmltooling --dir $resolvedPackage (Join-Path $resolvedPackage "GrangerBrowser.exe")
if ($LASTEXITCODE -ne 0) { throw "windeployqt failed." }
$nmeaPlugin = Join-Path $resolvedPackage "position/qtposition_nmea.dll"
if (Test-Path -LiteralPath $nmeaPlugin) {
    Remove-Item -LiteralPath $nmeaPlugin -Force
}
$qmlDebuggerDirectory = Join-Path $resolvedPackage "qmltooling"
if (Test-Path -LiteralPath $qmlDebuggerDirectory) {
    throw "windeployqt deployed QML debugger tooling into the production package."
}

@"
[Paths]
Prefix=.
Binaries=.
Libraries=.
LibraryExecutables=.
Plugins=.
QmlImports=qml
ArchData=.
Data=.
Translations=translations
"@ | Set-Content -LiteralPath (Join-Path $resolvedPackage "qt.conf") -Encoding ASCII

$qtRuntimeFiles = @(
    "Qt6Core.dll",
    "Qt6Gui.dll",
    "Qt6Network.dll",
    "Qt6Widgets.dll",
    "Qt6WebEngineCore.dll",
    "Qt6WebEngineWidgets.dll",
    "QtWebEngineProcess.exe"
)
foreach ($relativePath in $qtRuntimeFiles) {
    $deployedPath = Join-Path $resolvedPackage $relativePath
    $qtSourceDirectory = Join-Path $QtRoot "bin"
    $qtSourcePath = Join-Path $qtSourceDirectory $relativePath
    if (-not (Test-Path -LiteralPath $qtSourcePath -PathType Leaf)) {
        throw "Qt runtime source was not found in the selected distribution: $relativePath"
    }
    if ((Get-FileHash -LiteralPath $deployedPath -Algorithm SHA256).Hash -ne
        (Get-FileHash -LiteralPath $qtSourcePath -Algorithm SHA256).Hash) {
        throw "windeployqt mixed Qt distributions for $relativePath"
    }
}

$qtD3dCompiler = Join-Path $QtRoot "d3dcompiler_47.dll"
if (-not (Test-Path -LiteralPath $qtD3dCompiler -PathType Leaf)) {
    throw "The selected Qt distribution does not contain d3dcompiler_47.dll."
}
Assert-ValidPublisherSignature -Path $qtD3dCompiler -PublisherPattern "Microsoft"
Copy-Item -LiteralPath $qtD3dCompiler -Destination (Join-Path $resolvedPackage "d3dcompiler_47.dll") -Force

# Qt 6.11.2's Windows 11 24H2 build links Qt6Core against the Windows ICU
# compatibility DLL. Deploy the signed Microsoft ICU pair app-local so the
# package does not depend on the target Windows image providing icuuc.dll.
$windowsSystemDirectory = [Environment]::GetFolderPath([Environment+SpecialFolder]::System)
foreach ($runtimeName in @("icu.dll", "icuuc.dll")) {
    $runtimeSource = Join-Path $windowsSystemDirectory $runtimeName
    if (-not (Test-Path -LiteralPath $runtimeSource -PathType Leaf)) {
        throw "Microsoft ICU runtime was not found: $runtimeSource"
    }
    Assert-ValidPublisherSignature -Path $runtimeSource -PublisherPattern "Microsoft Windows"
    Copy-Item -LiteralPath $runtimeSource -Destination (Join-Path $resolvedPackage $runtimeName) -Force
}

$projectFile = Join-Path $buildPath "granger_browser.vcxproj"
if (-not (Test-Path -LiteralPath $projectFile -PathType Leaf)) {
    throw "Generated Visual Studio project was not found: $projectFile"
}
$projectXml = [xml](Get-Content -LiteralPath $projectFile -Raw -Encoding UTF8)
$windowsSdkNode = $projectXml.SelectSingleNode("//*[local-name()='WindowsTargetPlatformVersion']")
$windowsSdkVersion = if ($windowsSdkNode) { $windowsSdkNode.InnerText.Trim() } else { "" }
if ([string]::IsNullOrWhiteSpace($windowsSdkVersion)) {
    throw "WindowsTargetPlatformVersion was not recorded by CMake."
}
$windowsSdkD3d = Join-Path ${env:ProgramFiles(x86)} "Windows Kits/10/Redist/D3D/x64"
foreach ($runtimeName in @("dxcompiler.dll", "dxil.dll")) {
    $runtimeSource = Join-Path $windowsSdkD3d $runtimeName
    if (-not (Test-Path -LiteralPath $runtimeSource -PathType Leaf)) {
        throw "Windows SDK D3D redistributable was not found: $runtimeSource"
    }
    Assert-ValidPublisherSignature -Path $runtimeSource -PublisherPattern "Microsoft"
    Copy-Item -LiteralPath $runtimeSource -Destination (Join-Path $resolvedPackage $runtimeName) -Force
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
$vcArchitectureRoot = Split-Path -Parent $vcCrt
$vcVersionRoot = Split-Path -Parent $vcArchitectureRoot
$vcRedistVersion = Split-Path -Leaf $vcVersionRoot
foreach ($runtimeName in @("MSVCP140.dll", "MSVCP140_ATOMIC_WAIT.dll", "VCRUNTIME140.dll", "VCRUNTIME140_1.dll")) {
    Assert-ValidPublisherSignature -Path (Join-Path $resolvedPackage $runtimeName) -PublisherPattern "Microsoft"
}

$i2pRuntimeInfo = & (Join-Path $PSScriptRoot "fetch-i2p-runtime.ps1")
if (-not $i2pRuntimeInfo.OK) { throw "Pinned i2pd runtime staging failed." }
$runtimeI2p = Join-Path $resolvedPackage "runtime/i2p"
New-Item -ItemType Directory -Path $runtimeI2p -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $i2pRuntimeInfo.RuntimeRoot "i2pd.exe") -Destination $runtimeI2p
Copy-Item -LiteralPath (Join-Path $i2pRuntimeInfo.RuntimeRoot "certificates") `
    -Destination $runtimeI2p -Recurse
Copy-Item -LiteralPath (Join-Path $i2pRuntimeInfo.RuntimeRoot "LICENSE.txt") -Destination $runtimeI2p
if (Test-Path -LiteralPath (Join-Path $i2pRuntimeInfo.RuntimeRoot "README.txt")) {
    Copy-Item -LiteralPath (Join-Path $i2pRuntimeInfo.RuntimeRoot "README.txt") -Destination $runtimeI2p
}
$packagedI2pCertificates = @(
    Get-ChildItem -LiteralPath (Join-Path $runtimeI2p "certificates") -Recurse -File
)
if ($packagedI2pCertificates.Count -lt 1) {
    throw "Packaged i2pd certificate bundle is empty."
}

$torRuntimeInfo = & (Join-Path $PSScriptRoot "fetch-tor-runtime.ps1")
if (-not $torRuntimeInfo.OK -or -not $torRuntimeInfo.SignatureVerified) {
    throw "Pinned Tor runtime staging failed."
}
$expertRoot = $torRuntimeInfo.RuntimeRoot
$runtimeTor = Join-Path $resolvedPackage "runtime/tor"
$runtimePt = Join-Path $runtimeTor "pluggable_transports"
$runtimeData = Join-Path $runtimeTor "data"
New-Item -ItemType Directory -Path $runtimePt -Force | Out-Null
New-Item -ItemType Directory -Path $runtimeData -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $expertRoot "tor/tor.exe") -Destination $runtimeTor
Copy-Item -LiteralPath (Join-Path $expertRoot "data/geoip") -Destination $runtimeData
Copy-Item -LiteralPath (Join-Path $expertRoot "data/geoip6") -Destination $runtimeData
Copy-Item -LiteralPath (Join-Path $expertRoot "tor/pluggable_transports/lyrebird.exe") -Destination $runtimePt
Copy-Item -LiteralPath (Join-Path $expertRoot "tor/pluggable_transports/conjure-client.exe") -Destination $runtimePt
Copy-Item -LiteralPath (Join-Path $expertRoot "tor/pluggable_transports/pt_config.json") -Destination $runtimePt

$qtVersion = (Get-Item -LiteralPath (Join-Path $QtRoot "bin/Qt6Core.dll")).VersionInfo.FileVersion
$deploymentRuntimeFiles = @(
    Get-DeploymentFileRecord -Root $resolvedPackage -RelativePath "Qt6Core.dll" -Source "Qt $qtVersion msvc2022_64"
    Get-DeploymentFileRecord -Root $resolvedPackage -RelativePath "Qt6WebEngineCore.dll" -Source "Qt $qtVersion msvc2022_64"
    Get-DeploymentFileRecord -Root $resolvedPackage -RelativePath "QtWebEngineProcess.exe" -Source "Qt $qtVersion msvc2022_64"
    Get-DeploymentFileRecord -Root $resolvedPackage -RelativePath "d3dcompiler_47.dll" -Source "Qt $qtVersion support runtime"
    Get-DeploymentFileRecord -Root $resolvedPackage -RelativePath "icu.dll" -Source "Microsoft Windows ICU runtime"
    Get-DeploymentFileRecord -Root $resolvedPackage -RelativePath "icuuc.dll" -Source "Microsoft Windows ICU compatibility runtime"
    Get-DeploymentFileRecord -Root $resolvedPackage -RelativePath "dxcompiler.dll" -Source "Windows SDK $windowsSdkVersion D3D redistributable"
    Get-DeploymentFileRecord -Root $resolvedPackage -RelativePath "dxil.dll" -Source "Windows SDK $windowsSdkVersion D3D redistributable"
    Get-DeploymentFileRecord -Root $resolvedPackage -RelativePath "MSVCP140.dll" -Source "Microsoft VC143 CRT $vcRedistVersion"
    Get-DeploymentFileRecord -Root $resolvedPackage -RelativePath "VCRUNTIME140.dll" -Source "Microsoft VC143 CRT $vcRedistVersion"
    Get-DeploymentFileRecord -Root $resolvedPackage -RelativePath "VCRUNTIME140_1.dll" -Source "Microsoft VC143 CRT $vcRedistVersion"
    Get-DeploymentFileRecord -Root $resolvedPackage -RelativePath "runtime/tor/tor.exe" -Source "Tor Expert Bundle $($torRuntimeInfo.BundleVersion), Tor $($torRuntimeInfo.TorVersion)"
    Get-DeploymentFileRecord -Root $resolvedPackage -RelativePath "runtime/tor/pluggable_transports/lyrebird.exe" -Source "Tor Expert Bundle $($torRuntimeInfo.BundleVersion), lyrebird $($torRuntimeInfo.LyrebirdVersion)"
    Get-DeploymentFileRecord -Root $resolvedPackage -RelativePath "runtime/tor/pluggable_transports/conjure-client.exe" -Source "Tor Expert Bundle $($torRuntimeInfo.BundleVersion), Conjure $($torRuntimeInfo.ConjureVersion)"
    Get-DeploymentFileRecord -Root $resolvedPackage -RelativePath "runtime/tor/pluggable_transports/pt_config.json" -Source "Tor Expert Bundle $($torRuntimeInfo.BundleVersion)"
    Get-DeploymentFileRecord -Root $resolvedPackage -RelativePath "runtime/tor/data/geoip" -Source "Tor Expert Bundle $($torRuntimeInfo.BundleVersion) GeoIP database"
    Get-DeploymentFileRecord -Root $resolvedPackage -RelativePath "runtime/tor/data/geoip6" -Source "Tor Expert Bundle $($torRuntimeInfo.BundleVersion) GeoIP database"
    Get-DeploymentFileRecord -Root $resolvedPackage -RelativePath "runtime/i2p/i2pd.exe" -Source "PurpleI2P i2pd $($i2pRuntimeInfo.Version) official Windows x64 MinGW release"
)
[pscustomobject]@{
    SchemaVersion = 2
    ProductVersion = (Get-Item -LiteralPath (Join-Path $resolvedPackage "GrangerBrowser.exe")).VersionInfo.ProductVersion
    Architecture = "x64"
    QtVersion = $qtVersion
    QtToolchain = "msvc2022_64"
    WinDeployQtVersion = (Get-Item -LiteralPath $windeployqt).VersionInfo.FileVersion
    WindowsSdkVersion = $windowsSdkVersion
    VcRuntimeVersion = $vcRedistVersion
    TorBundleVersion = $torRuntimeInfo.BundleVersion
    TorVersion = $torRuntimeInfo.TorVersion
    TorSource = $torRuntimeInfo.Source
    TorArchiveSHA256 = $torRuntimeInfo.ArchiveSHA256
    TorSignatureSource = $torRuntimeInfo.SignatureSource
    TorSignatureSHA256 = $torRuntimeInfo.SignatureSHA256
    TorSigningKeySource = $torRuntimeInfo.SigningKeySource
    TorSigningKeyFingerprint = $torRuntimeInfo.SigningKeyFingerprint
    TorSigningKeySHA256 = $torRuntimeInfo.SigningKeySHA256
    TorSignatureVerified = [bool]$torRuntimeInfo.SignatureVerified
    TorLicense = $torRuntimeInfo.TorLicense
    LyrebirdVersion = $torRuntimeInfo.LyrebirdVersion
    LyrebirdLicense = $torRuntimeInfo.LyrebirdLicense
    ConjureVersion = $torRuntimeInfo.ConjureVersion
    ConjureGoVersion = $torRuntimeInfo.ConjureGoVersion
    GeoIpBundleVersion = $torRuntimeInfo.BundleVersion
    I2pVersion = $i2pRuntimeInfo.Version
    I2pSource = $i2pRuntimeInfo.Source
    I2pArchiveSHA256 = $i2pRuntimeInfo.ArchiveSHA256
    I2pLicense = $i2pRuntimeInfo.License
    I2pCertificateCount = $packagedI2pCertificates.Count
    RuntimeFiles = $deploymentRuntimeFiles
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $resolvedPackage "deployment-metadata.json") -Encoding UTF8

$licenses = Join-Path $resolvedPackage "licenses"
$releaseDocs = Join-Path $resolvedPackage "docs"
$releaseSidebarScreenshots = Join-Path $releaseDocs "screenshots/sidebar-layout-stability"
New-Item -ItemType Directory -Path $licenses -Force | Out-Null
New-Item -ItemType Directory -Path $releaseDocs -Force | Out-Null
New-Item -ItemType Directory -Path $releaseSidebarScreenshots -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $projectRoot "granger/resources/qr-fixtures/release-bridge.png") -Destination (Join-Path $resolvedPackage "bridge.png")
Copy-Item -LiteralPath (Join-Path $projectRoot "README.md") -Destination $resolvedPackage
Copy-Item -LiteralPath (Join-Path $projectRoot "BUILDING.md") -Destination $resolvedPackage
Copy-Item -LiteralPath (Join-Path $projectRoot "DISTRIBUTION.md") -Destination $resolvedPackage
Copy-Item -LiteralPath (Join-Path $projectRoot "SECURITY.md") -Destination $resolvedPackage
Copy-Item -LiteralPath (Join-Path $projectRoot "NOTICE.txt") -Destination $resolvedPackage
Copy-Item -LiteralPath (Join-Path $projectRoot "docs/GRANGER_BROWSER_RELEASE_REPORT.md") -Destination $releaseDocs
Copy-Item -LiteralPath (Join-Path $projectRoot "docs/FULL_PAMP_INTEGRATION_AUDIT.md") -Destination $releaseDocs
Copy-Item -LiteralPath (Join-Path $projectRoot "docs/CROSS_DEVICE_PRIVACY_TESTING.md") -Destination $releaseDocs
Copy-Item -LiteralPath (Join-Path $projectRoot "docs/GIT_WORKFLOW.md") -Destination $releaseDocs
Copy-Item -LiteralPath (Join-Path $projectRoot "docs/WINDOWS_PORTABILITY.md") -Destination $releaseDocs
Copy-Item -LiteralPath (Join-Path $projectRoot "docs/INSTALLER.md") -Destination $releaseDocs
Copy-Item -LiteralPath (Join-Path $projectRoot "docs/PRIVATE_NETWORK_ROUTING.md") -Destination $releaseDocs
Copy-Item -Path (Join-Path $projectRoot "docs/screenshots/sidebar-layout-stability/*.png") `
    -Destination $releaseSidebarScreenshots
Copy-Item -LiteralPath (Join-Path $projectRoot "NOTICE.txt") -Destination $licenses
Copy-Item -LiteralPath (Join-Path $projectRoot "third_party/quirc/LICENSE") -Destination (Join-Path $licenses "quirc-LICENSE.txt")
Copy-Item -LiteralPath (Join-Path $projectRoot "third_party/lucide-LICENSE.txt") -Destination (Join-Path $licenses "lucide-LICENSE.txt")
Copy-Item -LiteralPath (Join-Path $projectRoot "third_party/simple-icons-LICENSE.md") -Destination (Join-Path $licenses "simple-icons-LICENSE.md")
Copy-Item -LiteralPath (Join-Path $projectRoot "third_party/easylist/CC-BY-SA-3.0.txt") -Destination (Join-Path $licenses "EasyList-CC-BY-SA-3.0.txt")
Copy-Item -LiteralPath (Join-Path $projectRoot "third_party/easylist/README.md") -Destination (Join-Path $licenses "EasyList-SOURCES.md")
Copy-Item -LiteralPath (Join-Path $projectRoot "third_party/adguard-filters/LICENSE") -Destination (Join-Path $licenses "AdGuard-Filters-GPL-3.0.txt")
Copy-Item -LiteralPath (Join-Path $projectRoot "third_party/i2pd/LICENSE") -Destination (Join-Path $licenses "i2pd-LICENSE.txt")
Copy-Item -LiteralPath (Join-Path $projectRoot "third_party/i2pd/README.md") -Destination (Join-Path $licenses "i2pd-SOURCE.md")
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
    "VCRUNTIME140.dll", "VCRUNTIME140_1.dll", "qt.conf", "deployment-metadata.json",
    "d3dcompiler_47.dll", "dxcompiler.dll", "dxil.dll",
    "resources/icudtl.dat", "resources/qtwebengine_resources.pak", "SECURITY.md", "NOTICE.txt", "DISTRIBUTION.md", "docs/GRANGER_BROWSER_RELEASE_REPORT.md", "docs/FULL_PAMP_INTEGRATION_AUDIT.md", "docs/CROSS_DEVICE_PRIVACY_TESTING.md", "docs/GIT_WORKFLOW.md", "docs/WINDOWS_PORTABILITY.md", "docs/INSTALLER.md", "docs/PRIVATE_NETWORK_ROUTING.md",
    "docs/screenshots/sidebar-layout-stability/sidebar-hidden.png", "docs/screenshots/sidebar-layout-stability/sidebar-rail.png",
    "docs/screenshots/sidebar-layout-stability/sidebar-expanded.png", "docs/screenshots/sidebar-layout-stability/sidebar-tabs-expanded.png",
    "docs/screenshots/sidebar-layout-stability/sidebar-tabs-collapsed.png", "docs/screenshots/sidebar-layout-stability/sidebar-collapsed.png",
    "docs/screenshots/sidebar-layout-stability/letterbox-hidden.png", "docs/screenshots/sidebar-layout-stability/letterbox-rail.png",
    "docs/screenshots/sidebar-layout-stability/letterbox-expanded.png", "docs/screenshots/sidebar-layout-stability/letterbox-toggle-stress.png",
    "docs/screenshots/sidebar-layout-stability/duckduckgo-rail.png", "docs/screenshots/sidebar-layout-stability/duckduckgo-expanded.png",
    "docs/screenshots/sidebar-layout-stability/duckduckgo-after-toggle-stress.png", "docs/screenshots/sidebar-layout-stability/sidebar-100.png",
    "docs/screenshots/sidebar-layout-stability/sidebar-150.png", "docs/screenshots/sidebar-layout-stability/sidebar-200.png",
    "licenses/quirc-LICENSE.txt", "licenses/lucide-LICENSE.txt", "licenses/simple-icons-LICENSE.md", "licenses/EasyList-CC-BY-SA-3.0.txt", "licenses/CONTENT_FILTER_SOURCES.md", "licenses/UI_ASSET_SOURCES.md", "licenses/UI_DESIGN_REFERENCES.md", "licenses/SPACES_DOWNLOAD_REFERENCES.md", "licenses/Pamp-Lite-ATTRIBUTION.md", "licenses/tor.txt", "licenses/lyrebird.txt", "licenses/conjure.txt", "licenses/i2pd-LICENSE.txt", "licenses/i2pd-SOURCE.md", "bridge.png", "runtime/tor/tor.exe",
    "runtime/tor/data/geoip", "runtime/tor/data/geoip6", "runtime/tor/pluggable_transports/lyrebird.exe",
    "runtime/tor/pluggable_transports/conjure-client.exe", "runtime/tor/pluggable_transports/pt_config.json",
    "runtime/i2p/i2pd.exe", "runtime/i2p/LICENSE.txt", "runtime/i2p/certificates"
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
$forbiddenPythonPayloads = @(Get-ChildItem -LiteralPath $resolvedPackage -Recurse -File | Where-Object {
    $_.Extension.ToLowerInvariant() -in @(".py", ".pyc", ".pyz", ".pyd", ".whl")
})
if ($forbiddenPythonPayloads.Count -ne 0) {
    throw "Package validation failed; Python source or module payloads are not part of the reviewed browser runtime."
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
    "surface-9c42.jpg", "ai.png", "icons8-chatbot-64.png", "icon.jpg", "icon-source.jpg", "app-icon.png", "app-icon.svg",
    "GrangerBrowser.ico", "bitcoin.png", "Gram.png", "Ethereum Eth-1.png", "trc20.png", "Solana Sol.png",
    "CryptoBot_QR.jpg", "EmmaWatson.gif", "ton.png", "ethereum.png", "tron.png", "solana.png",
    "cryptobot-qr.jpg", "banner.gif", "banner-static.png"
)
$looseUiAssets = @(Get-ChildItem -LiteralPath $resolvedPackage -Recurse -File | Where-Object {
    $looseUiAssetNames -contains $_.Name
})
$sourceAssetDirectories = @(Get-ChildItem -LiteralPath $resolvedPackage -Recurse -Directory | Where-Object {
    $_.Name -in @("poiskoviki", "Support-block", "Chat-bot")
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
