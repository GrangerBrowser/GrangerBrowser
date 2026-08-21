[CmdletBinding()]
param([string]$PackageDirectory = "release/Granger Browser")

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$sourcePackage = [IO.Path]::GetFullPath((Join-Path $projectRoot $PackageDirectory))
if (-not (Test-Path -LiteralPath (Join-Path $sourcePackage "GrangerBrowser.exe"))) {
    throw "Packaged executable not found under $sourcePackage"
}
$portability = & (Join-Path $PSScriptRoot "test-windows-portability.ps1") `
    -PackageDirectory $sourcePackage.Substring([IO.Path]::GetFullPath($projectRoot).TrimEnd('\').Length + 1)
if (-not $portability.OK) { throw "Windows portability validation failed before acceptance." }

$testRoot = Join-Path $projectRoot "output/release acceptance/path with spaces"
$copiedPackage = Join-Path $testRoot "copied release/Granger Browser"
$dataRoot = Join-Path $testRoot "local data"
$settingsRoot = Join-Path $testRoot "settings"
$unrelatedCwd = Join-Path $testRoot "unrelated cwd"
$resolvedTest = [IO.Path]::GetFullPath($testRoot)
if (-not $resolvedTest.StartsWith([IO.Path]::GetFullPath($projectRoot), [StringComparison]::OrdinalIgnoreCase)) {
    throw "Acceptance directory escaped the workspace."
}
if (Test-Path -LiteralPath $resolvedTest) { Remove-Item -LiteralPath $resolvedTest -Recurse -Force }
New-Item -ItemType Directory -Path $copiedPackage,$dataRoot,$settingsRoot,$unrelatedCwd -Force | Out-Null
Copy-Item -Path (Join-Path $sourcePackage "*") -Destination $copiedPackage -Recurse -Force
$executable = Join-Path $copiedPackage "GrangerBrowser.exe"
$rendererFixture = Join-Path $testRoot "renderer-fixture.html"
Set-Content -LiteralPath $rendererFixture -Encoding UTF8 -Value `
    '<!doctype html><meta charset="utf-8"><title>Granger renderer fixture</title><p>renderer-ok</p>'
$rendererFixtureUrl = ([Uri]::new($rendererFixture)).AbsoluteUri

$versionInfo = (Get-Item -LiteralPath $executable).VersionInfo
$brandingMetadata = [ordered]@{
    ProductName = $versionInfo.ProductName
    FileDescription = $versionInfo.FileDescription
    OriginalFilename = $versionInfo.OriginalFilename
    InternalName = $versionInfo.InternalName
}
if ($brandingMetadata.ProductName -ne "Granger Browser" -or
    $brandingMetadata.FileDescription -ne "Granger Browser privacy browser" -or
    $brandingMetadata.OriginalFilename -ne "GrangerBrowser.exe" -or
    $brandingMetadata.InternalName -ne "GrangerBrowser") {
    throw "Copied release executable has incorrect Granger Browser VersionInfo."
}
$legacyStem = [Text.Encoding]::ASCII.GetString([byte[]](68,97,114,107,83,101,97,114,99,104))
$legacyTokens = @(
    $legacyStem,
    $legacyStem.ToLowerInvariant(),
    ($legacyStem -creplace '([a-z0-9])([A-Z])', '$1_$2').ToLowerInvariant(),
    ($legacyStem -creplace '([a-z0-9])([A-Z])', '$1 $2')
) | Select-Object -Unique
$legacyNamedEntries = @(Get-ChildItem -LiteralPath $copiedPackage -Recurse -Force | Where-Object {
    $name = $_.Name
    @($legacyTokens | Where-Object { $name.IndexOf($_, [StringComparison]::OrdinalIgnoreCase) -ge 0 }).Count -ne 0
})
$legacyTextMatches = foreach ($file in @(Get-ChildItem -LiteralPath $copiedPackage -Recurse -File | Where-Object {
    $_.Extension -in @('.md', '.txt', '.ps1', '.json')
})) {
    $content = [IO.File]::ReadAllText($file.FullName)
    foreach ($token in $legacyTokens) {
        if ($content.IndexOf($token, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            $file.FullName
            break
        }
    }
}
if ($legacyNamedEntries.Count -ne 0 -or @($legacyTextMatches).Count -ne 0) {
    throw "Copied release contains a user-visible legacy product identifier."
}

$looseUiAssetNames = @(
    "DuckDuck.png", "Google.png", "bing.png", "brave.png", "startpage.png",
    "mojeek.png", "yandex.png", "onion.png", "emma watson.png", "emma watson.jpg",
    "surface-9c42.jpg", "ai.png", "icons8-chatbot-64.png", "icon.jpg", "icon-source.jpg", "app-icon.png", "app-icon.svg",
    "GrangerBrowser.ico", "bitcoin.png", "Gram.png", "Ethereum Eth-1.png", "trc20.png", "Solana Sol.png",
    "CryptoBot_QR.jpg", "EmmaWatson.gif", "ton.png", "ethereum.png", "tron.png", "solana.png",
    "cryptobot-qr.jpg", "banner.gif", "banner-static.png"
)
$looseUiAssets = @(Get-ChildItem -LiteralPath $copiedPackage -Recurse -File | Where-Object {
    $looseUiAssetNames -contains $_.Name
})
$sourceAssetDirectories = @(Get-ChildItem -LiteralPath $copiedPackage -Recurse -Directory | Where-Object {
    $_.Name -in @("poiskoviki", "Support-block", "Chat-bot")
})
if ($looseUiAssets.Count -ne 0 -or $sourceAssetDirectories.Count -ne 0) {
    $unexpectedUiAssets = @($looseUiAssets.FullName) + @($sourceAssetDirectories.FullName)
    throw "Acceptance package contains loose UI source assets: $($unexpectedUiAssets -join ', ')"
}

$forbiddenFullPampDirectories = @(Get-ChildItem -LiteralPath $copiedPackage -Recurse -Directory | Where-Object {
    $_.Name.ToLowerInvariant() -in @('pentest', 'pamp')
})
$pythonRuntimeArtifacts = @(Get-ChildItem -LiteralPath $copiedPackage -Recurse -File | Where-Object {
    $_.Extension.ToLowerInvariant() -in @('.py', '.pyc', '.pyz', '.pyd', '.whl') -or
    $_.Name.ToLowerInvariant() -in @('python.exe', 'pythonw.exe') -or
    $_.Name -like 'python*.dll'
})
if ($forbiddenFullPampDirectories.Count -ne 0 -or $pythonRuntimeArtifacts.Count -ne 0) {
    $unexpectedPampRuntime = @($forbiddenFullPampDirectories.FullName) + @($pythonRuntimeArtifacts.FullName)
    throw "Acceptance package contains an unreviewed full Pamp/Python runtime: $($unexpectedPampRuntime -join ', ')"
}

function Invoke-GrangerBrowser {
    param([string[]]$Arguments, [switch]$AllowNonZero, [int]$TimeoutSeconds = 0)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $executable
    $psi.WorkingDirectory = $unrelatedCwd
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $quoted = foreach ($argument in $Arguments) { '"' + $argument.Replace('"', '\"') + '"' }
    $psi.Arguments = $quoted -join ' '
    $process = [Diagnostics.Process]::Start($psi)
    if ($TimeoutSeconds -gt 0) {
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $process.Kill()
            $process.WaitForExit()
            throw "Granger Browser timed out after $TimeoutSeconds seconds: $($Arguments -join ' ')"
        }
    } else {
        $process.WaitForExit()
    }
    if ($process.ExitCode -ne 0 -and -not $AllowNonZero) { throw "Granger Browser failed with exit code $($process.ExitCode): $($Arguments -join ' ')" }
    return $process.ExitCode
}

$oldPath = $env:PATH
$oldData = $env:GRANGER_DATA_ROOT
$oldSettings = $env:GRANGER_SETTINGS_ROOT
$oldDownloads = $env:GRANGER_DOWNLOAD_ROOT
$oldFeatureFixture = $env:GRANGER_FEATURE_FIXTURE_ROOT
$developmentEnvironmentVariables = @(
    "QTDIR",
    "CMAKE_PREFIX_PATH",
    "QT_PLUGIN_PATH",
    "QT_QPA_PLATFORM_PLUGIN_PATH",
    "QTWEBENGINEPROCESS_PATH",
    "QTWEBENGINE_RESOURCES_PATH",
    "QTWEBENGINE_LOCALES_PATH",
    "QML_IMPORT_PATH",
    "QML2_IMPORT_PATH",
    "VSINSTALLDIR",
    "VCINSTALLDIR",
    "VCToolsInstallDir",
    "VCToolsRedistDir",
    "WindowsSdkDir",
    "INCLUDE",
    "LIB",
    "LIBPATH",
    "GRANGER_RUNTIME_ROOT",
    "GRANGER_TOR_PATH",
    "GRANGER_LYREBIRD_PATH",
    "GRANGER_TRANSPORT_PATH",
    "DARKSEARCH_RUNTIME_ROOT",
    "DARKSEARCH_TOR_PATH",
    "DARKSEARCH_LYREBIRD_PATH",
    "DARKSEARCH_TRANSPORT_PATH"
)
$oldDevelopmentEnvironment = @{}
foreach ($name in $developmentEnvironmentVariables) {
    $oldDevelopmentEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
}
try {
    $env:PATH = "$(Join-Path $env:SystemRoot 'System32');$env:SystemRoot"
    foreach ($name in $developmentEnvironmentVariables) {
        [Environment]::SetEnvironmentVariable($name, $null, "Process")
    }
    $env:GRANGER_DATA_ROOT = $dataRoot
    $env:GRANGER_SETTINGS_ROOT = $settingsRoot
    $env:GRANGER_DOWNLOAD_ROOT = Join-Path $testRoot "downloads"
    $pythonOnPath = [bool](Get-Command python.exe -ErrorAction SilentlyContinue)
    if ($pythonOnPath) { throw "Python unexpectedly remains available in the minimal acceptance PATH." }

    @"
[compatibility]
userAgentProfile=default
"@ | Set-Content -LiteralPath (Join-Path $settingsRoot "GrangerBrowser.ini") -Encoding UTF8

    $profileResult = Join-Path $testRoot "profile-state.json"
    Invoke-GrangerBrowser @("--smoke-profile-state", "--smoke-output=$profileResult")
    $profile = Get-Content -Raw -Encoding UTF8 -LiteralPath $profileResult | ConvertFrom-Json
    $chromiumMajor = ([string]$profile.chromiumVersion -split '\.')[0]
    if (-not $profile.ok -or $profile.qtVersion -ne "6.11.2" -or
        $profile.qtWebEngineVersion -ne "6.11.2" -or
        $profile.chromiumVersion -notmatch '^140\.0\.7339\.' -or
        $profile.javascriptUserAgent -notmatch ("Chrome/" + [regex]::Escape($chromiumMajor) + "\.") -or
        $profile.javascriptUserAgent -match "Firefox/" -or
        $profile.engine -ne "Qt WebEngine / Chromium" -or $profile.offTheRecord -or
        [string]::IsNullOrWhiteSpace($profile.cachePath)) {
        throw "Chromium-consistent User-Agent inspection failed."
    }

    $poisonedRuntime = Join-Path $testRoot "poisoned WebEngine runtime"
    $poisonedResources = Join-Path $poisonedRuntime "resources"
    $poisonedLocales = Join-Path $poisonedRuntime "locales"
    New-Item -ItemType Directory -Path $poisonedResources -Force | Out-Null
    New-Item -ItemType Directory -Path $poisonedLocales -Force | Out-Null
    $poisonedHelper = Join-Path $poisonedRuntime "QtWebEngineProcess.exe"
    Copy-Item -LiteralPath (Join-Path $copiedPackage "QtWebEngineProcess.exe") -Destination $poisonedHelper
    $env:QTWEBENGINEPROCESS_PATH = $poisonedHelper
    $env:QTWEBENGINE_RESOURCES_PATH = $poisonedResources
    $env:QTWEBENGINE_LOCALES_PATH = $poisonedLocales
    $runtimeIsolationResult = Join-Path $testRoot "webengine-runtime-isolation.json"
    Invoke-GrangerBrowser @("--smoke-profile-state", "--smoke-output=$runtimeIsolationResult") -TimeoutSeconds 90
    $runtimeIsolation = Get-Content -Raw -Encoding UTF8 -LiteralPath $runtimeIsolationResult | ConvertFrom-Json
    $expectedHelper = Join-Path $copiedPackage "QtWebEngineProcess.exe"
    $expectedResources = Join-Path $copiedPackage "resources"
    $expectedLocales = Join-Path $copiedPackage "translations/qtwebengine_locales"
    if (-not $runtimeIsolation.ok -or
        -not ([IO.Path]::GetFullPath([string]$runtimeIsolation.webEngineProcessPath)).Equals(
            [IO.Path]::GetFullPath($expectedHelper), [StringComparison]::OrdinalIgnoreCase) -or
        -not ([IO.Path]::GetFullPath([string]$runtimeIsolation.webEngineResourcesPath)).Equals(
            [IO.Path]::GetFullPath($expectedResources), [StringComparison]::OrdinalIgnoreCase) -or
        -not ([IO.Path]::GetFullPath([string]$runtimeIsolation.webEngineLocalesPath)).Equals(
            [IO.Path]::GetFullPath($expectedLocales), [StringComparison]::OrdinalIgnoreCase)) {
        throw "Packaged application did not override external Qt WebEngine runtime paths."
    }
    $env:QTWEBENGINEPROCESS_PATH = $null
    $env:QTWEBENGINE_RESOURCES_PATH = $null
    $env:QTWEBENGINE_LOCALES_PATH = $null

    $productResult = Join-Path $testRoot "product-tests.json"
    $newTabResult = Join-Path $testRoot "new-tab-tests.json"
    $browserResult = Join-Path $testRoot "browser-smoke.json"
    $strategyResult = Join-Path $testRoot "strategy-tests.json"
    $networkEnvironmentResult = Join-Path $testRoot "network-environment-smoke.json"
    $privateRouteResult = Join-Path $testRoot "private-route-smoke.json"
    $networkBootstrapResult = Join-Path $testRoot "network-bootstrap-fail-closed.json"
    $i2pRuntimeResult = Join-Path $testRoot "i2p-runtime-smoke.json"
    $downloadResult = Join-Path $testRoot "download-smoke.json"
    $navigationResult = Join-Path $testRoot "navigation-error-tests.json"
    $bridgeResult = Join-Path $testRoot "bridge-tests.json"
    $bridgePersistenceResult = Join-Path $testRoot "bridge-persistence.json"
    $qrResult = Join-Path $testRoot "qr-tests.json"
    $qrFlowResult = Join-Path $testRoot "qr-import-flow.json"
    $performanceResult = Join-Path $testRoot "performance-smoke.json"
    $containerPerformanceResult = Join-Path $testRoot "container-performance-smoke.json"
    $uiFocusResult = Join-Path $testRoot "ui-focus-smoke.json"
    $uiFocusCaptures = Join-Path $testRoot "ui-focus-captures"
    $developerToolsResult = Join-Path $testRoot "developer-tools-smoke.json"
    $privacyResult = Join-Path $testRoot "privacy-tests.json"
    $privacyDiagnosticsResult = Join-Path $testRoot "privacy-diagnostics.json"
    $contentPersistenceResult = Join-Path $testRoot "content-persistence.json"
    $contentFilterUpdateResult = Join-Path $testRoot "content-filter-update.json"
    $privacyCorruptStoreResult = Join-Path $testRoot "privacy-corrupt-store.json"
    $privacyCleanupPrepareResult = Join-Path $testRoot "privacy-cleanup-prepare.json"
    $privacyCleanupVerifyResult = Join-Path $testRoot "privacy-cleanup-verify.json"
    $privacyStabilityResult = Join-Path $testRoot "privacy-stability.json"
    $privacyVisualResult = Join-Path $testRoot "privacy-visual.json"
    $privacyVisualCaptures = Join-Path $testRoot "privacy-visual-captures"
    $mainWindowDownloadResult = Join-Path $testRoot "mainwindow-download-smoke.json"
    $unknownLengthDownloadResult = Join-Path $testRoot "unknown-length-download-smoke.json"
    $pauseResumeDownloadResult = Join-Path $testRoot "pause-resume-download-smoke.json"
    $cancelDownloadResult = Join-Path $testRoot "cancel-download-smoke.json"
    $retryFailureDownloadResult = Join-Path $testRoot "retry-failure-download-smoke.json"
    $idleEventResult = Join-Path $testRoot "idle-event-profile.json"
    $featureResult = Join-Path $testRoot "feature-tests.json"
    $featureCaptures = Join-Path $testRoot "feature-captures"
    $brandMigrationResult = Join-Path $testRoot "brand-migration-tests.json"
    $brandingResult = Join-Path $testRoot "branding-tests.json"
    $wipePreservePrepareResult = Join-Path $testRoot "wipe-preserve-prepare.json"
    $wipePreserveVerifyResult = Join-Path $testRoot "wipe-preserve-verify.json"
    $wipeDeletePrepareResult = Join-Path $testRoot "wipe-delete-prepare.json"
    $wipeDeleteVerifyResult = Join-Path $testRoot "wipe-delete-verify.json"
    $downloadActiveScreenshot = Join-Path $testRoot "download-active.png"
    $downloadCompletedScreenshot = Join-Path $testRoot "download-completed.png"
    $downloadPanelScreenshot = Join-Path $testRoot "download-completed-panel.png"
    $downloadShelfScreenshot = Join-Path $testRoot "download-completed-shelf.png"
    $retryFailureScreenshot = Join-Path $testRoot "download-retry-failed.png"
    $retryCompletedScreenshot = Join-Path $testRoot "download-retry-completed.png"
    $primaryDataRoot = $env:GRANGER_DATA_ROOT
    $primarySettingsRoot = $env:GRANGER_SETTINGS_ROOT
    $primaryDownloadsRoot = $env:GRANGER_DOWNLOAD_ROOT
    $primaryFeatureFixtureRoot = $env:GRANGER_FEATURE_FIXTURE_ROOT
    $env:GRANGER_FEATURE_FIXTURE_ROOT = Join-Path $testRoot "brand migration fixture"
    Invoke-GrangerBrowser @("--smoke-brand-migration", "--smoke-output=$brandMigrationResult")
    $env:GRANGER_FEATURE_FIXTURE_ROOT = $primaryFeatureFixtureRoot
    Invoke-GrangerBrowser @("--smoke-branding", "--smoke-output=$brandingResult")
    try {
        $env:GRANGER_DATA_ROOT = Join-Path $testRoot "privacy corrupt store data"
        $env:GRANGER_SETTINGS_ROOT = Join-Path $testRoot "privacy corrupt store settings"
        Invoke-GrangerBrowser @("--smoke-privacy-corrupt-store", "--smoke-output=$privacyCorruptStoreResult")
        $env:GRANGER_DATA_ROOT = Join-Path $testRoot "privacy cleanup data"
        $env:GRANGER_SETTINGS_ROOT = Join-Path $testRoot "privacy cleanup settings"
        Invoke-GrangerBrowser @("--smoke-privacy-cleanup-prepare", "--smoke-output=$privacyCleanupPrepareResult")
        Invoke-GrangerBrowser @("--smoke-privacy-cleanup-verify", "--smoke-output=$privacyCleanupVerifyResult")
        $env:GRANGER_DATA_ROOT = Join-Path $testRoot "privacy data"
        $env:GRANGER_SETTINGS_ROOT = Join-Path $testRoot "privacy settings"
        Invoke-GrangerBrowser @("--smoke-privacy-tests", "--smoke-output=$privacyResult")
        $env:GRANGER_DATA_ROOT = Join-Path $testRoot "privacy diagnostics data"
        $env:GRANGER_SETTINGS_ROOT = Join-Path $testRoot "privacy diagnostics settings"
        Invoke-GrangerBrowser @("--smoke-privacy-diagnostics", "--smoke-output=$privacyDiagnosticsResult")
        $env:GRANGER_DATA_ROOT = Join-Path $testRoot "privacy stability data"
        $env:GRANGER_SETTINGS_ROOT = Join-Path $testRoot "privacy stability settings"
        Invoke-GrangerBrowser @("--smoke-privacy-stability", "--smoke-output=$privacyStabilityResult")
        $env:GRANGER_DATA_ROOT = Join-Path $testRoot "privacy visual data"
        $env:GRANGER_SETTINGS_ROOT = Join-Path $testRoot "privacy visual settings"
        Invoke-GrangerBrowser @("--smoke-privacy-visual", "--smoke-output=$privacyVisualResult", "--smoke-capture-dir=$privacyVisualCaptures")
    } finally {
        $env:GRANGER_DATA_ROOT = $primaryDataRoot
        $env:GRANGER_SETTINGS_ROOT = $primarySettingsRoot
    }
    try {
        $env:GRANGER_DATA_ROOT = Join-Path $testRoot "feature data"
        $env:GRANGER_SETTINGS_ROOT = Join-Path $testRoot "feature settings"
        $env:GRANGER_DOWNLOAD_ROOT = Join-Path $testRoot "feature downloads"
        $env:GRANGER_FEATURE_FIXTURE_ROOT = Join-Path $testRoot "feature fixture"
        Invoke-GrangerBrowser @("--smoke-feature-tests", "--smoke-output=$featureResult", "--smoke-capture-dir=$featureCaptures")

        $env:GRANGER_DATA_ROOT = Join-Path $testRoot "wipe preserve data"
        $env:GRANGER_SETTINGS_ROOT = Join-Path $testRoot "wipe preserve settings"
        $env:GRANGER_DOWNLOAD_ROOT = Join-Path $testRoot "wipe preserve downloads"
        $env:GRANGER_FEATURE_FIXTURE_ROOT = Join-Path $testRoot "wipe preserve fixture"
        Invoke-GrangerBrowser @("--smoke-feature-wipe-prepare", "--smoke-output=$wipePreservePrepareResult")
        Invoke-GrangerBrowser @("--smoke-feature-wipe-verify", "--smoke-output=$wipePreserveVerifyResult")

        $env:GRANGER_DATA_ROOT = Join-Path $testRoot "wipe delete data"
        $env:GRANGER_SETTINGS_ROOT = Join-Path $testRoot "wipe delete settings"
        $env:GRANGER_DOWNLOAD_ROOT = Join-Path $testRoot "wipe delete downloads"
        $env:GRANGER_FEATURE_FIXTURE_ROOT = Join-Path $testRoot "wipe delete fixture"
        Invoke-GrangerBrowser @("--smoke-feature-wipe-prepare", "--smoke-wipe-delete-download", "--smoke-output=$wipeDeletePrepareResult")
        Invoke-GrangerBrowser @("--smoke-feature-wipe-verify", "--smoke-wipe-expect-download-deleted", "--smoke-output=$wipeDeleteVerifyResult")
    } finally {
        $env:GRANGER_DATA_ROOT = $primaryDataRoot
        $env:GRANGER_SETTINGS_ROOT = $primarySettingsRoot
        $env:GRANGER_DOWNLOAD_ROOT = $primaryDownloadsRoot
        $env:GRANGER_FEATURE_FIXTURE_ROOT = $primaryFeatureFixtureRoot
    }
    Invoke-GrangerBrowser @("--smoke-product-tests", "--smoke-output=$productResult")
    Invoke-GrangerBrowser @("--smoke-ui-focus", "--smoke-output=$uiFocusResult", "--smoke-capture-dir=$uiFocusCaptures")
    Invoke-GrangerBrowser @("--smoke-content-persistence", "--smoke-output=$contentPersistenceResult")
    try {
        $env:GRANGER_DATA_ROOT = Join-Path $testRoot "developer tools data"
        $env:GRANGER_SETTINGS_ROOT = Join-Path $testRoot "developer tools settings"
        Invoke-GrangerBrowser @("--smoke-developer-tools", "--smoke-output=$developerToolsResult")
        $env:GRANGER_DATA_ROOT = Join-Path $testRoot "content filter update data"
        $env:GRANGER_SETTINGS_ROOT = Join-Path $testRoot "content filter update settings"
        Invoke-GrangerBrowser @("--smoke-content-filter-update", "--smoke-output=$contentFilterUpdateResult")
    } finally {
        $env:GRANGER_DATA_ROOT = $primaryDataRoot
        $env:GRANGER_SETTINGS_ROOT = $primarySettingsRoot
    }
    try {
        $env:GRANGER_DATA_ROOT = Join-Path $testRoot "new tab data"
        $env:GRANGER_SETTINGS_ROOT = Join-Path $testRoot "new tab settings"
        Invoke-GrangerBrowser @("--smoke-new-tab-tests", "--smoke-output=$newTabResult")
    } finally {
        $env:GRANGER_DATA_ROOT = $primaryDataRoot
        $env:GRANGER_SETTINGS_ROOT = $primarySettingsRoot
    }
    Invoke-GrangerBrowser @("--smoke-url=$rendererFixtureUrl", "--smoke-output=$browserResult")
    Invoke-GrangerBrowser @("--smoke-navigation-errors", "--smoke-output=$navigationResult")
    Invoke-GrangerBrowser @("--smoke-bridge-tests", "--smoke-output=$bridgeResult")
    Invoke-GrangerBrowser @("--smoke-qr-tests", "--smoke-output=$qrResult")
    $releaseQrFixture = Join-Path $copiedPackage "bridge.png"
    if (-not (Test-Path -LiteralPath $releaseQrFixture)) { throw "Packaged bridge.png fixture is missing." }
    $releaseQrHash = (Get-FileHash -LiteralPath $releaseQrFixture -Algorithm SHA256).Hash
    if ($releaseQrHash -ne "31D64F7CB544FAA38F2CDDFFDE994C4498E0F33CF1C4459FBE573F85A03BEC7D") {
        throw "Packaged bridge.png fixture changed unexpectedly: $releaseQrHash"
    }
    Invoke-GrangerBrowser @("--smoke-qr-import-flow", "--smoke-output=$qrFlowResult", "--smoke-qr-image=$releaseQrFixture")
    Invoke-GrangerBrowser @("--smoke-bridge-persistence", "--smoke-output=$bridgePersistenceResult")
    Invoke-GrangerBrowser @("--smoke-strategy-tests", "--smoke-output=$strategyResult")
    Invoke-GrangerBrowser @("--smoke-network-environment", "--smoke-output=$networkEnvironmentResult")
    Invoke-GrangerBrowser @("--smoke-private-routes", "--smoke-output=$privateRouteResult")
    $relativeCopiedPackage = $copiedPackage.Substring(
        [IO.Path]::GetFullPath($projectRoot).TrimEnd('\').Length + 1)
    $relativeBootstrapResult = $networkBootstrapResult.Substring(
        [IO.Path]::GetFullPath($projectRoot).TrimEnd('\').Length + 1)
    $networkBootstrap = & (Join-Path $PSScriptRoot "test-network-bootstrap-fail-closed.ps1") `
        -PackageDirectory $relativeCopiedPackage -OutputPath $relativeBootstrapResult
    if (-not $networkBootstrap.ok) { throw "Network bootstrap fail-closed regression failed." }
    try {
        $env:GRANGER_DATA_ROOT = Join-Path $testRoot "i2p runtime data"
        $env:GRANGER_SETTINGS_ROOT = Join-Path $testRoot "i2p runtime settings"
        Invoke-GrangerBrowser @(
            "--smoke-i2p-runtime",
            "--smoke-output=$i2pRuntimeResult",
            "--smoke-timeout-ms=300000"
        ) -TimeoutSeconds 630
    } finally {
        $env:GRANGER_DATA_ROOT = $primaryDataRoot
        $env:GRANGER_SETTINGS_ROOT = $primarySettingsRoot
    }
    try {
        $env:GRANGER_DATA_ROOT = Join-Path $testRoot "performance data"
        $env:GRANGER_SETTINGS_ROOT = Join-Path $testRoot "performance settings"
        Invoke-GrangerBrowser @("--smoke-performance", "--smoke-output=$performanceResult")
        $env:GRANGER_DATA_ROOT = Join-Path $testRoot "container performance data"
        $env:GRANGER_SETTINGS_ROOT = Join-Path $testRoot "container performance settings"
        Invoke-GrangerBrowser @("--smoke-container-performance", "--smoke-output=$containerPerformanceResult")
        $env:GRANGER_DATA_ROOT = Join-Path $testRoot "idle event data"
        $env:GRANGER_SETTINGS_ROOT = Join-Path $testRoot "idle event settings"
        $previousReducedMotion = $env:GRANGER_REDUCED_MOTION
        try {
            $env:GRANGER_REDUCED_MOTION = "1"
            Invoke-GrangerBrowser @("--smoke-idle-event-profile", "--smoke-output=$idleEventResult")
        } finally {
            $env:GRANGER_REDUCED_MOTION = $previousReducedMotion
        }
    } finally {
        $env:GRANGER_DATA_ROOT = $primaryDataRoot
        $env:GRANGER_SETTINGS_ROOT = $primarySettingsRoot
    }
    $downloadPort = 18991
    $downloadServer = Start-Job -ScriptBlock {
        param([int]$Port)
        $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $Port)
        $listener.Start()
        try {
            $client = $listener.AcceptTcpClient()
            try {
                $stream = $client.GetStream()
                $request = New-Object byte[] 4096
                [void]$stream.Read($request, 0, $request.Length)
                $body = New-Object byte[] 32768
                for ($index = 0; $index -lt $body.Length; $index++) { $body[$index] = $index % 251 }
                $headers = "HTTP/1.1 200 OK`r`nContent-Type: application/octet-stream`r`nContent-Disposition: attachment; filename=granger-download.bin`r`nContent-Length: $($body.Length)`r`nConnection: close`r`n`r`n"
                $headerBytes = [Text.Encoding]::ASCII.GetBytes($headers)
                $stream.Write($headerBytes, 0, $headerBytes.Length)
                $stream.Write($body, 0, $body.Length)
                $stream.Flush()
            } finally {
                $client.Dispose()
            }
        } finally {
            $listener.Stop()
        }
    } -ArgumentList $downloadPort
    Start-Sleep -Milliseconds 500
    try {
        Invoke-GrangerBrowser @("--smoke-download-url=http://127.0.0.1:$downloadPort/download.bin", "--smoke-output=$downloadResult")
    } finally {
        Wait-Job -Job $downloadServer -Timeout 10 | Out-Null
        Remove-Job -Job $downloadServer -Force
    }

    $mainWindowDownloadPorts = @(18992, 18993)
    $mainWindowDownloadServers = @()
    foreach ($mainWindowDownloadPort in $mainWindowDownloadPorts) {
        $mainWindowDownloadServers += Start-Job -ScriptBlock {
        param([int]$Port)
        $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $Port)
        $listener.Start()
        try {
            $client = $listener.AcceptTcpClient()
            try {
                $stream = $client.GetStream()
                $request = New-Object byte[] 8192
                [void]$stream.Read($request, 0, $request.Length)
                $total = 6MB
                $encodedName = "granger-" + ("a" * 90) + "-%D1%82%D0%B5%D1%81%D1%82.zip"
                $headers = "HTTP/1.1 200 OK`r`nContent-Type: application/octet-stream`r`nContent-Disposition: attachment; filename*=UTF-8''$encodedName`r`nContent-Length: $total`r`nConnection: close`r`n`r`n"
                $headerBytes = [Text.Encoding]::ASCII.GetBytes($headers)
                $stream.Write($headerBytes, 0, $headerBytes.Length)
                $chunk = New-Object byte[] 65536
                for ($index = 0; $index -lt $chunk.Length; $index++) { $chunk[$index] = $index % 251 }
                for ($sent = 0; $sent -lt $total; $sent += $chunk.Length) {
                    $count = [Math]::Min($chunk.Length, $total - $sent)
                    $stream.Write($chunk, 0, $count)
                    $stream.Flush()
                    Start-Sleep -Milliseconds 70
                }
            } finally {
                $client.Dispose()
            }
        } finally {
            $listener.Stop()
        }
        } -ArgumentList $mainWindowDownloadPort
    }
    Start-Sleep -Milliseconds 500
    try {
        Invoke-GrangerBrowser @(
            "--smoke-mainwindow-download-url=http://127.0.0.1:$($mainWindowDownloadPorts[0])/first.zip?token=first-secret",
            "--smoke-mainwindow-download-second-url=http://127.0.0.1:$($mainWindowDownloadPorts[1])/second.zip?token=second-secret",
            "--smoke-output=$mainWindowDownloadResult",
            "--smoke-download-active-screenshot=$downloadActiveScreenshot",
            "--smoke-download-completed-screenshot=$downloadCompletedScreenshot"
        )
    } finally {
        foreach ($mainWindowDownloadServer in $mainWindowDownloadServers) {
            Wait-Job -Job $mainWindowDownloadServer -Timeout 20 | Out-Null
            Remove-Job -Job $mainWindowDownloadServer -Force
        }
    }

    $unknownLengthDownloadPort = 18994
    $unknownLengthDownloadServer = Start-Job -ScriptBlock {
        param([int]$Port)
        $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $Port)
        $listener.Start()
        try {
            $client = $listener.AcceptTcpClient()
            try {
                $stream = $client.GetStream()
                $request = New-Object byte[] 8192
                [void]$stream.Read($request, 0, $request.Length)
                $total = 4MB
                $headers = "HTTP/1.0 200 OK`r`nContent-Type: application/octet-stream`r`nContent-Disposition: attachment; filename=unknown-length.bin`r`nConnection: close`r`n`r`n"
                $headerBytes = [Text.Encoding]::ASCII.GetBytes($headers)
                $stream.Write($headerBytes, 0, $headerBytes.Length)
                $chunk = New-Object byte[] 65536
                for ($index = 0; $index -lt $chunk.Length; $index++) { $chunk[$index] = ($index * 3) % 251 }
                for ($sent = 0; $sent -lt $total; $sent += $chunk.Length) {
                    $count = [Math]::Min($chunk.Length, $total - $sent)
                    $stream.Write($chunk, 0, $count)
                    $stream.Flush()
                    Start-Sleep -Milliseconds 70
                }
            } finally {
                $client.Dispose()
            }
        } finally {
            $listener.Stop()
        }
    } -ArgumentList $unknownLengthDownloadPort
    Start-Sleep -Milliseconds 500
    try {
        Invoke-GrangerBrowser @(
            "--smoke-mainwindow-download-url=http://127.0.0.1:$unknownLengthDownloadPort/unknown-length.bin",
            "--smoke-output=$unknownLengthDownloadResult"
        )
    } finally {
        Wait-Job -Job $unknownLengthDownloadServer -Timeout 20 | Out-Null
        Remove-Job -Job $unknownLengthDownloadServer -Force
    }

    $pauseResumeDownloadPort = 18995
    $pauseResumeDownloadServer = Start-Job -ScriptBlock {
        param([int]$Port)
        $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $Port)
        $listener.Start()
        try {
            $client = $listener.AcceptTcpClient()
            try {
                $stream = $client.GetStream()
                $request = New-Object byte[] 8192
                [void]$stream.Read($request, 0, $request.Length)
                $total = 4MB
                $headers = "HTTP/1.1 200 OK`r`nContent-Type: application/octet-stream`r`nContent-Disposition: attachment; filename=pause-resume.bin`r`nContent-Length: $total`r`nConnection: close`r`n`r`n"
                $headerBytes = [Text.Encoding]::ASCII.GetBytes($headers)
                $stream.Write($headerBytes, 0, $headerBytes.Length)
                $chunk = New-Object byte[] 32768
                for ($sent = 0; $sent -lt $total; $sent += $chunk.Length) {
                    $count = [Math]::Min($chunk.Length, $total - $sent)
                    $stream.Write($chunk, 0, $count)
                    $stream.Flush()
                    Start-Sleep -Milliseconds 55
                }
            } finally {
                $client.Dispose()
            }
        } finally {
            $listener.Stop()
        }
    } -ArgumentList $pauseResumeDownloadPort
    Start-Sleep -Milliseconds 500
    try {
        Invoke-GrangerBrowser @(
            "--smoke-mainwindow-download-url=http://127.0.0.1:$pauseResumeDownloadPort/pause-resume.bin",
            "--smoke-download-control=pause-resume",
            "--smoke-output=$pauseResumeDownloadResult"
        )
    } finally {
        Wait-Job -Job $pauseResumeDownloadServer -Timeout 20 | Out-Null
        Remove-Job -Job $pauseResumeDownloadServer -Force
    }

    $cancelDownloadPort = 18996
    $cancelDownloadServer = Start-Job -ScriptBlock {
        param([int]$Port)
        $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $Port)
        $listener.Start()
        try {
            $client = $listener.AcceptTcpClient()
            try {
                $stream = $client.GetStream()
                $request = New-Object byte[] 8192
                [void]$stream.Read($request, 0, $request.Length)
                $total = 12MB
                $headers = "HTTP/1.1 200 OK`r`nContent-Type: application/octet-stream`r`nContent-Disposition: attachment; filename=cancel-test.bin`r`nContent-Length: $total`r`nConnection: close`r`n`r`n"
                $headerBytes = [Text.Encoding]::ASCII.GetBytes($headers)
                $stream.Write($headerBytes, 0, $headerBytes.Length)
                $chunk = New-Object byte[] 32768
                for ($sent = 0; $sent -lt $total; $sent += $chunk.Length) {
                    try {
                        $count = [Math]::Min($chunk.Length, $total - $sent)
                        $stream.Write($chunk, 0, $count)
                        $stream.Flush()
                    } catch {
                        break
                    }
                    Start-Sleep -Milliseconds 80
                }
            } finally {
                $client.Dispose()
            }
        } finally {
            $listener.Stop()
        }
    } -ArgumentList $cancelDownloadPort
    Start-Sleep -Milliseconds 500
    try {
        Invoke-GrangerBrowser @(
            "--smoke-mainwindow-download-url=http://127.0.0.1:$cancelDownloadPort/cancel.bin?token=cancel-secret",
            "--smoke-download-control=cancel",
            "--smoke-output=$cancelDownloadResult"
        )
    } finally {
        Wait-Job -Job $cancelDownloadServer -Timeout 20 | Out-Null
        Remove-Job -Job $cancelDownloadServer -Force
    }

    $retryFailureDownloadPort = 18997
    $retryBlockedDownloadRoot = Join-Path $testRoot "blocked download root"
    $retryRecoveredDownloadRoot = Join-Path $testRoot "recovered downloads"
    Set-Content -LiteralPath $retryBlockedDownloadRoot -Value "not a directory" -Encoding ASCII
    $retryFailureDownloadServer = Start-Job -ScriptBlock {
        param([int]$Port)
        $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $Port)
        $listener.Start()
        try {
            for ($requestIndex = 0; $requestIndex -lt 2; $requestIndex++) {
                $client = $listener.AcceptTcpClient()
                try {
                    $stream = $client.GetStream()
                    $request = New-Object byte[] 8192
                    [void]$stream.Read($request, 0, $request.Length)
                    $total = 4MB
                    $headers = "HTTP/1.1 200 OK`r`nContent-Type: application/octet-stream`r`nContent-Disposition: attachment; filename=retry-destination.bin`r`nContent-Length: $total`r`nConnection: close`r`n`r`n"
                    $headerBytes = [Text.Encoding]::ASCII.GetBytes($headers)
                    $stream.Write($headerBytes, 0, $headerBytes.Length)
                    $chunk = New-Object byte[] 65536
                    for ($index = 0; $index -lt $chunk.Length; $index++) {
                        $chunk[$index] = ($index * 7) % 251
                    }
                    for ($sent = 0; $sent -lt $total; $sent += $chunk.Length) {
                        try {
                            $count = [Math]::Min($chunk.Length, $total - $sent)
                            $stream.Write($chunk, 0, $count)
                            $stream.Flush()
                        } catch {
                            break
                        }
                        Start-Sleep -Milliseconds 25
                    }
                } finally {
                    $client.Dispose()
                }
            }
        } finally {
            $listener.Stop()
        }
    } -ArgumentList $retryFailureDownloadPort
    Start-Sleep -Milliseconds 500
    try {
        $env:GRANGER_DOWNLOAD_ROOT = $retryBlockedDownloadRoot
        Invoke-GrangerBrowser @(
            "--smoke-mainwindow-download-url=http://127.0.0.1:$retryFailureDownloadPort/retry.bin?token=retry-secret",
            "--smoke-download-control=retry-failure",
            "--smoke-download-recovery-root=$retryRecoveredDownloadRoot",
            "--smoke-output=$retryFailureDownloadResult",
            "--smoke-download-active-screenshot=$retryFailureScreenshot",
            "--smoke-download-completed-screenshot=$retryCompletedScreenshot"
        )
    } finally {
        $env:GRANGER_DOWNLOAD_ROOT = $primaryDownloadsRoot
        Wait-Job -Job $retryFailureDownloadServer -Timeout 20 | Out-Null
        Remove-Job -Job $retryFailureDownloadServer -Force
    }

    $searchResults = [ordered]@{
        Mode = "Offline URL-builder coverage"
        Evidence = $productResult
        LiveProviderNavigation = "Not attempted without a verified private route"
    }

    $product = Get-Content -Raw -Encoding UTF8 -LiteralPath $productResult | ConvertFrom-Json
    $newTab = Get-Content -Raw -Encoding UTF8 -LiteralPath $newTabResult | ConvertFrom-Json
    $browser = Get-Content -Raw -Encoding UTF8 -LiteralPath $browserResult | ConvertFrom-Json
    $strategy = Get-Content -Raw -Encoding UTF8 -LiteralPath $strategyResult | ConvertFrom-Json
    $networkEnvironment = Get-Content -Raw -Encoding UTF8 -LiteralPath $networkEnvironmentResult | ConvertFrom-Json
    $privateRoute = Get-Content -Raw -Encoding UTF8 -LiteralPath $privateRouteResult | ConvertFrom-Json
    $networkBootstrap = Get-Content -Raw -Encoding UTF8 -LiteralPath $networkBootstrapResult | ConvertFrom-Json
    $i2pRuntime = Get-Content -Raw -Encoding UTF8 -LiteralPath $i2pRuntimeResult | ConvertFrom-Json
    $download = Get-Content -Raw -Encoding UTF8 -LiteralPath $downloadResult | ConvertFrom-Json
    $navigation = Get-Content -Raw -Encoding UTF8 -LiteralPath $navigationResult | ConvertFrom-Json
    $bridge = Get-Content -Raw -Encoding UTF8 -LiteralPath $bridgeResult | ConvertFrom-Json
    $bridgePersistence = Get-Content -Raw -Encoding UTF8 -LiteralPath $bridgePersistenceResult | ConvertFrom-Json
    $qr = Get-Content -Raw -Encoding UTF8 -LiteralPath $qrResult | ConvertFrom-Json
    $qrFlow = Get-Content -Raw -Encoding UTF8 -LiteralPath $qrFlowResult | ConvertFrom-Json
    $performance = Get-Content -Raw -Encoding UTF8 -LiteralPath $performanceResult | ConvertFrom-Json
    $containerPerformance = Get-Content -Raw -Encoding UTF8 -LiteralPath $containerPerformanceResult | ConvertFrom-Json
    $uiFocus = Get-Content -Raw -Encoding UTF8 -LiteralPath $uiFocusResult | ConvertFrom-Json
    $developerTools = Get-Content -Raw -Encoding UTF8 -LiteralPath $developerToolsResult | ConvertFrom-Json
    $privacy = Get-Content -Raw -Encoding UTF8 -LiteralPath $privacyResult | ConvertFrom-Json
    $privacyDiagnostics = Get-Content -Raw -Encoding UTF8 -LiteralPath $privacyDiagnosticsResult | ConvertFrom-Json
    $contentPersistence = Get-Content -Raw -Encoding UTF8 -LiteralPath $contentPersistenceResult | ConvertFrom-Json
    $contentFilterUpdate = Get-Content -Raw -Encoding UTF8 -LiteralPath $contentFilterUpdateResult | ConvertFrom-Json
    $privacyCorruptStore = Get-Content -Raw -Encoding UTF8 -LiteralPath $privacyCorruptStoreResult | ConvertFrom-Json
    $privacyCleanupPrepare = Get-Content -Raw -Encoding UTF8 -LiteralPath $privacyCleanupPrepareResult | ConvertFrom-Json
    $privacyCleanupVerify = Get-Content -Raw -Encoding UTF8 -LiteralPath $privacyCleanupVerifyResult | ConvertFrom-Json
    $privacyStability = Get-Content -Raw -Encoding UTF8 -LiteralPath $privacyStabilityResult | ConvertFrom-Json
    $privacyVisual = Get-Content -Raw -Encoding UTF8 -LiteralPath $privacyVisualResult | ConvertFrom-Json
    $mainWindowDownload = Get-Content -Raw -Encoding UTF8 -LiteralPath $mainWindowDownloadResult | ConvertFrom-Json
    $unknownLengthDownload = Get-Content -Raw -Encoding UTF8 -LiteralPath $unknownLengthDownloadResult | ConvertFrom-Json
    $pauseResumeDownload = Get-Content -Raw -Encoding UTF8 -LiteralPath $pauseResumeDownloadResult | ConvertFrom-Json
    $cancelDownload = Get-Content -Raw -Encoding UTF8 -LiteralPath $cancelDownloadResult | ConvertFrom-Json
    $retryFailureDownload = Get-Content -Raw -Encoding UTF8 -LiteralPath $retryFailureDownloadResult | ConvertFrom-Json
    $idleEvent = Get-Content -Raw -Encoding UTF8 -LiteralPath $idleEventResult | ConvertFrom-Json
    $feature = Get-Content -Raw -Encoding UTF8 -LiteralPath $featureResult | ConvertFrom-Json
    $brandMigration = Get-Content -Raw -Encoding UTF8 -LiteralPath $brandMigrationResult | ConvertFrom-Json
    $branding = Get-Content -Raw -Encoding UTF8 -LiteralPath $brandingResult | ConvertFrom-Json
    $wipePreservePrepare = Get-Content -Raw -Encoding UTF8 -LiteralPath $wipePreservePrepareResult | ConvertFrom-Json
    $wipePreserveVerify = Get-Content -Raw -Encoding UTF8 -LiteralPath $wipePreserveVerifyResult | ConvertFrom-Json
    $wipeDeletePrepare = Get-Content -Raw -Encoding UTF8 -LiteralPath $wipeDeletePrepareResult | ConvertFrom-Json
    $wipeDeleteVerify = Get-Content -Raw -Encoding UTF8 -LiteralPath $wipeDeleteVerifyResult | ConvertFrom-Json
    if (-not $product.ok -or -not $newTab.ok -or -not $browser.ok -or -not $strategy.ok -or -not $networkEnvironment.ok -or
        -not $privateRoute.ok -or -not $networkBootstrap.ok -or -not $i2pRuntime.ok -or -not $i2pRuntime.stopped -or
        -not $download.ok -or -not $download.sourcePageClosed -or
        -not $navigation.ok -or -not $bridge.ok -or -not $bridgePersistence.ok -or -not $qr.ok -or -not $qrFlow.ok -or -not $performance.ok -or -not $containerPerformance.ok -or
        -not $uiFocus.ok -or -not $developerTools.ok -or -not $contentPersistence.ok -or -not $contentFilterUpdate.ok -or
        -not $privacy.ok -or -not $privacyDiagnostics.ok -or -not $privacyCorruptStore.ok -or
        -not $privacyCleanupPrepare.ok -or -not $privacyCleanupVerify.ok -or -not $privacyStability.ok -or -not $privacyVisual.ok -or
        -not $mainWindowDownload.ok -or $mainWindowDownload.pageUnavailableSeen -or -not $mainWindowDownload.sourceTabClosed -or
        -not $mainWindowDownload.concurrentDownloadsObserved -or -not $mainWindowDownload.sourceUrlSanitized -or
        -not $mainWindowDownload.activePanelVerified -or -not $mainWindowDownload.activePanelScreenshotSaved -or
        -not $unknownLengthDownload.ok -or -not $unknownLengthDownload.activeShelfVerified -or
        -not $pauseResumeDownload.ok -or -not $pauseResumeDownload.pauseRequested -or
        -not $pauseResumeDownload.pausedObserved -or -not $pauseResumeDownload.resumeRequested -or
        -not $cancelDownload.ok -or -not $cancelDownload.cancelRequested -or
        -not $cancelDownload.cancelledUiVerified -or -not $cancelDownload.sourceUrlSanitized -or
        -not $retryFailureDownload.ok -or -not $retryFailureDownload.failedUiVerified -or
        -not $retryFailureDownload.retryRequested -or -not $retryFailureDownload.recoveryRootApplied -or
        $retryFailureDownload.retryResumedInPlace -or -not $retryFailureDownload.sourceUrlSanitized -or
        -not $idleEvent.ok -or
        -not $feature.ok -or -not $brandMigration.ok -or -not $branding.ok -or
        -not $wipePreservePrepare.ok -or -not $wipePreserveVerify.ok -or
        -not $wipeDeletePrepare.ok -or -not $wipeDeleteVerify.ok) {
        throw "One or more packaged smoke results reported failure."
    }
    $multiDownloadItems = @($mainWindowDownload.download.items)
    if ($multiDownloadItems.Count -ne 2 -or
        $multiDownloadItems[0].filePath -eq $multiDownloadItems[1].filePath -or
        $multiDownloadItems[0].fileName.Length -lt 100 -or
        $multiDownloadItems[1].fileName -notmatch ' \(1\)\.zip$' -or
        -not $multiDownloadItems[0].fileName.Contains([char]0x0442) -or
        -not $multiDownloadItems[1].fileName.Contains([char]0x0442)) {
        throw "Concurrent duplicate/Unicode download naming was not preserved safely."
    }
    $downloadHistoryText = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $dataRoot "state/downloads.json")
    if ($downloadHistoryText.Contains("first-secret") -or
        $downloadHistoryText.Contains("second-secret") -or
        $downloadHistoryText.Contains("cancel-secret") -or
        $downloadHistoryText.Contains("retry-secret")) {
        throw "A private download query leaked into persistent download history."
    }
    $startupLogs = @(Get-ChildItem -LiteralPath $testRoot -Recurse -File -Filter "startup.log" -ErrorAction SilentlyContinue)
    $paintWarnings = @($startupLogs | ForEach-Object {
        Select-String -LiteralPath $_.FullName -Pattern "QPainter::|QAnimationGroup::"
    })
    if ($paintWarnings.Count -ne 0) {
        throw "Packaged UI emitted QPainter/QAnimationGroup warnings: $($paintWarnings.Count)"
    }

    $beforeManaged = @(Get-Process GrangerBrowser,QtWebEngineProcess,tor,lyrebird,i2pd -ErrorAction SilentlyContinue).Count
    $normal = Start-Process -FilePath $executable -WorkingDirectory $unrelatedCwd -PassThru
    Start-Sleep -Seconds 5
    $normal.Refresh()
    if ($normal.HasExited) { throw "Normal icon-style launch exited before a window could be used." }
    if (-not $normal.CloseMainWindow()) { throw "Normal browser window could not be closed through its window message." }
    if (-not $normal.WaitForExit(15000)) {
        $normal.Kill()
        throw "Normal browser did not exit within 15 seconds."
    }
    Start-Sleep -Seconds 2
    $afterManaged = @(Get-Process GrangerBrowser,QtWebEngineProcess,tor,lyrebird,i2pd -ErrorAction SilentlyContinue).Count
    if ($afterManaged -gt $beforeManaged) { throw "Managed browser/Tor/WebEngine processes remained after normal close." }

    [pscustomobject]@{
        OK = $true
        Executable = $executable
        CopiedRelease = $copiedPackage
        TestedCopyRemovedAfterReport = $true
        CurrentDirectory = $unrelatedCwd
        PythonOnPath = $pythonOnPath
        FullPampDirectoryCount = $forbiddenFullPampDirectories.Count
        PythonRuntimeArtifactCount = $pythonRuntimeArtifacts.Count
        WindowsPortability = $portability
        BrandingMetadata = $brandingMetadata
        LegacyNamedEntryCount = $legacyNamedEntries.Count
        LegacyUserVisibleTextMatchCount = @($legacyTextMatches).Count
        ProductTests = $productResult
        NewTabTests = $newTabResult
        ProfileState = $profileResult
        WebEngineRuntimeIsolation = $runtimeIsolationResult
        WebEngineSmoke = $browserResult
        StrategyTests = $strategyResult
        NetworkEnvironmentSmoke = $networkEnvironmentResult
        PrivateRouteSmoke = $privateRouteResult
        NetworkBootstrapFailClosed = $networkBootstrapResult
        I2pRuntimeSmoke = $i2pRuntimeResult
        NavigationErrorTests = $navigationResult
        BridgeTests = $bridgeResult
        BridgePersistence = $bridgePersistenceResult
        QRTests = $qrResult
        QRImportFlow = $qrFlowResult
        ExactQRFixture = $releaseQrFixture
        ExactQRFixtureSHA256 = $releaseQrHash
        PerformanceSmoke = $performanceResult
        ContainerPerformanceSmoke = $containerPerformanceResult
        UIFocusSmoke = $uiFocusResult
        UIFocusCaptures = $uiFocusCaptures
        DeveloperToolsSmoke = $developerToolsResult
        PrivacyTests = $privacyResult
        PrivacyDiagnostics = $privacyDiagnosticsResult
        ContentPersistence = $contentPersistenceResult
        ContentFilterUpdate = $contentFilterUpdateResult
        PrivacyCorruptStore = $privacyCorruptStoreResult
        PrivacyCleanupPrepare = $privacyCleanupPrepareResult
        PrivacyCleanupVerify = $privacyCleanupVerifyResult
        PrivacyStability = $privacyStabilityResult
        PrivacyVisual = $privacyVisualResult
        PrivacyVisualCaptures = $privacyVisualCaptures
        DownloadSmoke = $downloadResult
        MainWindowDownloadSmoke = $mainWindowDownloadResult
        UnknownLengthDownloadSmoke = $unknownLengthDownloadResult
        PauseResumeDownloadSmoke = $pauseResumeDownloadResult
        CancelDownloadSmoke = $cancelDownloadResult
        RetryFailureDownloadSmoke = $retryFailureDownloadResult
        IdleEventProfile = $idleEventResult
        FeatureTests = $featureResult
        BrandMigrationTests = $brandMigrationResult
        BrandingTests = $brandingResult
        WipePreservePrepare = $wipePreservePrepareResult
        WipePreserveVerify = $wipePreserveVerifyResult
        WipeDeletePrepare = $wipeDeletePrepareResult
        WipeDeleteVerify = $wipeDeleteVerifyResult
        DownloadActiveScreenshot = $downloadActiveScreenshot
        DownloadCompletedScreenshot = $downloadCompletedScreenshot
        DownloadPanelScreenshot = $downloadPanelScreenshot
        DownloadShelfScreenshot = $downloadShelfScreenshot
        RetryFailureScreenshot = $retryFailureScreenshot
        RetryCompletedScreenshot = $retryCompletedScreenshot
        PaintWarningCount = $paintWarnings.Count
        StartupLogCount = $startupLogs.Count
        SearchChecks = $searchResults
        DataRoot = $dataRoot
        OrphanProcessCountBefore = $beforeManaged
        OrphanProcessCountAfter = $afterManaged
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $testRoot "release-acceptance.json") -Encoding UTF8
    if (Test-Path -LiteralPath $copiedPackage) {
        Remove-Item -LiteralPath $copiedPackage -Recurse -Force
    }
} finally {
    $env:PATH = $oldPath
    $env:GRANGER_DATA_ROOT = $oldData
    $env:GRANGER_SETTINGS_ROOT = $oldSettings
    $env:GRANGER_DOWNLOAD_ROOT = $oldDownloads
    $env:GRANGER_FEATURE_FIXTURE_ROOT = $oldFeatureFixture
    foreach ($name in $developmentEnvironmentVariables) {
        [Environment]::SetEnvironmentVariable($name, $oldDevelopmentEnvironment[$name], "Process")
    }
}
Write-Host "Release acceptance passed in $testRoot"
