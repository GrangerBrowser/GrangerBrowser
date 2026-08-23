[CmdletBinding()]
param(
    [string]$Setup = "output/distribution/GrangerSetup.exe",
    [string]$PackageArchive = "output/distribution/Granger-Browser-v0.4.4-windows-x64.zip",
    [string]$TestRoot = "output/installer-acceptance"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$workspaceRoot = [IO.Path]::GetFullPath($projectRoot).TrimEnd('\')
function Resolve-WorkspacePath([string]$Path) {
    $resolved = if ([IO.Path]::IsPathRooted($Path)) {
        [IO.Path]::GetFullPath($Path)
    } else {
        [IO.Path]::GetFullPath((Join-Path $projectRoot $Path))
    }
    if (-not $resolved.StartsWith($workspaceRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Installer test path escaped the workspace: $resolved"
    }
    return $resolved
}

$setupPath = Resolve-WorkspacePath $Setup
$packagePath = Resolve-WorkspacePath $PackageArchive
$testPath = Resolve-WorkspacePath $TestRoot
if (-not (Test-Path -LiteralPath $setupPath -PathType Leaf)) { throw "Setup not found: $setupPath" }
if (-not (Test-Path -LiteralPath $packagePath -PathType Leaf)) { throw "Package not found: $packagePath" }
$packageName = [IO.Path]::GetFileName($packagePath)
if ($packageName -notmatch '^Granger-Browser-v(\d+\.\d+\.\d+)-windows-x64\.zip$') {
    throw "Unexpected portable package name: $packageName"
}
$packageVersion = $Matches[1]
if (Test-Path -LiteralPath $testPath) { Remove-Item -LiteralPath $testPath -Recurse -Force }
New-Item -ItemType Directory -Path $testPath -Force | Out-Null

$standalone = Join-Path $testPath 'standalone/GrangerSetup.exe'
New-Item -ItemType Directory -Path (Split-Path -Parent $standalone) -Force | Out-Null
Copy-Item -LiteralPath $setupPath -Destination $standalone
$selfTest = Join-Path $testPath 'standalone/self-test.json'

function Invoke-Setup {
    param(
        [string[]]$Arguments,
        [int]$ExpectedExitCode = 0
    )
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $standalone
    $startInfo.UseShellExecute = $false
    foreach ($argument in $Arguments) {
        [void]$startInfo.ArgumentList.Add($argument)
    }
    $process = [Diagnostics.Process]::Start($startInfo)
    $process.WaitForExit()
    if ($process.ExitCode -ne $ExpectedExitCode) {
        throw "Setup exit code $($process.ExitCode), expected $ExpectedExitCode. Args: $($Arguments -join ' ')"
    }
}

function Stop-IsolatedBrowser([string]$Root) {
    $deadline = (Get-Date).AddSeconds(8)
    do {
        $browser = @(Get-CimInstance Win32_Process | Where-Object {
            $_.Name -eq 'GrangerBrowser.exe' -and $_.ExecutablePath -and
            $_.ExecutablePath.StartsWith($Root + '\', [StringComparison]::OrdinalIgnoreCase)
        })
        foreach ($entry in $browser) {
            $process = Get-Process -Id $entry.ProcessId -ErrorAction SilentlyContinue
            if ($process -and $process.MainWindowHandle -ne 0) {
                $null = $process.CloseMainWindow()
            }
        }
        if ($browser.Count -eq 0) { return }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $deadline)

    Get-CimInstance Win32_Process | Where-Object {
        $_.ExecutablePath -and
        $_.ExecutablePath.StartsWith($Root + '\', [StringComparison]::OrdinalIgnoreCase)
    } | ForEach-Object {
        Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Milliseconds 500
}

Invoke-Setup @('--test-mode', "--self-test=$selfTest")
$self = Get-Content -LiteralPath $selfTest -Raw | ConvertFrom-Json
if (-not $self.ok -or -not $self.gifEmbedded -or $self.gifFrames -lt 2 `
    -or $self.externalGifRequired -or -not $self.releaseManifestEmbedded `
    -or -not $self.packageEmbedded -or -not $self.embeddedMetadataValid `
    -or [uint64]$self.embeddedPackageSize -ne [uint64](Get-Item -LiteralPath $packagePath).Length) {
    throw "Standalone embedded release self-test failed."
}

$uiSmoke = Join-Path $testPath 'standalone/ui-smoke.json'
Invoke-Setup @('--test-mode', "--ui-smoke=$uiSmoke")
$ui = Get-Content -LiteralPath $uiSmoke -Raw | ConvertFrom-Json
if (-not $ui.ok -or $ui.framesAdvanced -lt 1) { throw "Installer GIF animation did not advance." }

$fixtureRoot = Join-Path $testPath 'fixtures'
New-Item -ItemType Directory -Path $fixtureRoot -Force | Out-Null
$invalidZip = Join-Path $fixtureRoot 'invalid.zip'
[IO.File]::WriteAllText($invalidZip, 'not a zip archive', [Text.Encoding]::ASCII)
$packageSize = (Get-Item -LiteralPath $packagePath).Length
$packageHash = (Get-FileHash -LiteralPath $packagePath -Algorithm SHA256).Hash.ToLowerInvariant()
$manifestPath = Join-Path $fixtureRoot 'manifest.json'
[ordered]@{
    schemaVersion = 2
    version = $packageVersion
    architecture = 'x64'
    minimumWindowsVersion = '10.0.17763'
    packageSize = $packageSize
    sha256 = $packageHash
} | ConvertTo-Json | Set-Content -LiteralPath $manifestPath -Encoding UTF8

$installRoot = Join-Path $testPath 'installed/Granger Browser'
$profileRoot = Join-Path $testPath 'user profile'
$marker = Join-Path $profileRoot 'preserve-me.txt'
New-Item -ItemType Directory -Path $profileRoot -Force | Out-Null
Set-Content -LiteralPath $marker -Value 'profile marker' -Encoding ASCII
$testId = 'acceptance'
$resultInstall = Join-Path $testPath 'install.json'
$oldData = $env:GRANGER_DATA_ROOT
$oldSettings = $env:GRANGER_SETTINGS_ROOT
$oldCache = $env:GRANGER_CACHE_ROOT
$oldDownloads = $env:GRANGER_DOWNLOAD_ROOT
$env:GRANGER_DATA_ROOT = Join-Path $testPath 'launched-browser/data'
$env:GRANGER_SETTINGS_ROOT = Join-Path $testPath 'launched-browser/settings'
$env:GRANGER_CACHE_ROOT = Join-Path $testPath 'launched-browser/cache'
$env:GRANGER_DOWNLOAD_ROOT = Join-Path $testPath 'launched-browser/downloads'
$i2pOutput = Join-Path $testPath 'managed-i2p.json'

$results = [ordered]@{}
try {
    Invoke-Setup @(
        '--test-mode', '--unattended',
        "--install-root=$installRoot",
        "--profile-root=$profileRoot",
        "--test-id=$testId",
        "--result=$resultInstall"
    )
    $install = Get-Content -LiteralPath $resultInstall -Raw | ConvertFrom-Json
    if (-not $install.ok -or -not $install.manifestEmbedded -or -not $install.packageEmbedded `
        -or $install.manifestDownloaded -or $install.packageDownloaded `
        -or -not $install.shaVerified -or -not $install.extracted -or -not $install.packageValidated `
        -or -not $install.shortcutsCreated -or -not $install.uninstallRegistered -or -not $install.launched) {
        throw "Full installer flow did not report every required stage."
    }
    $results.OfflineInstall = $true
    $results.ManifestEmbedded = $true
    $results.RuntimeEmbedded = $true
    $results.RemoteManifestDownloadDisabled = $true
    $results.RemotePackageDownloadDisabled = $true
    $results.ProgressReporting = $true
    $results.ShaVerification = $true
    $results.Extraction = $true
    $results.PackageValidation = $true
    $results.Launch = $true

    Stop-IsolatedBrowser $installRoot

    $shortcutRoot = Join-Path (Split-Path -Parent $installRoot) "installer-test-shortcuts/$testId"
    $startShortcut = Join-Path $shortcutRoot 'Start Menu/Granger Browser.lnk'
    $desktopShortcut = Join-Path $shortcutRoot 'Desktop/Granger Browser.lnk'
    if (-not (Test-Path $startShortcut) -or -not (Test-Path $desktopShortcut)) {
        throw "Installer shortcuts were not created."
    }
    $results.Shortcuts = $true

    $rerunResult = Join-Path $testPath 'rerun.json'
    Invoke-Setup @(
        '--test-mode', '--unattended', '--no-launch',
        "--install-root=$installRoot",
        "--profile-root=$profileRoot", "--test-id=$testId", "--result=$rerunResult"
    )
    $rerun = Get-Content $rerunResult -Raw | ConvertFrom-Json
    if (-not $rerun.ok -or -not $rerun.alreadyInstalled) { throw "Same-version re-run was not detected." }
    $results.Rerun = $true

    $repairResult = Join-Path $testPath 'repair.json'
    Invoke-Setup @(
        '--test-mode', '--unattended', '--force', '--no-launch',
        "--install-root=$installRoot", "--profile-root=$profileRoot",
        "--test-id=$testId", "--result=$repairResult"
    )
    $repair = Get-Content $repairResult -Raw | ConvertFrom-Json
    if (-not $repair.ok -or -not $repair.manifestEmbedded -or -not $repair.packageEmbedded `
        -or -not $repair.shaVerified -or -not $repair.packageValidated -or -not (Test-Path $marker)) {
        throw "Same-version repair failed or changed the user profile."
    }
    $results.Repair = $true

    $testRegistry = "HKCU:\Software\Granger Browser\InstallerTests\$testId"
    Set-ItemProperty -LiteralPath $testRegistry -Name DisplayVersion -Value '0.4.3'
    $updateResult = Join-Path $testPath 'update.json'
    Invoke-Setup @(
        '--test-mode', '--unattended', '--no-launch',
        "--install-root=$installRoot",
        "--profile-root=$profileRoot", "--test-id=$testId", "--result=$updateResult"
    )
    $update = Get-Content $updateResult -Raw | ConvertFrom-Json
    if (-not $update.ok -or -not $update.shaVerified -or -not (Test-Path $marker)) {
        throw "Update simulation failed or changed the user profile."
    }
    $results.Update = $true
    $results.UserProfilePreserved = $true

    $runningBrowser = Start-Process -FilePath (Join-Path $installRoot 'GrangerBrowser.exe') -PassThru
    try {
        $deadline = (Get-Date).AddSeconds(10)
        do {
            $runningBrowser.Refresh()
            if (-not $runningBrowser.HasExited) { break }
            Start-Sleep -Milliseconds 200
        } while ((Get-Date) -lt $deadline)
        if ($runningBrowser.HasExited) { throw "Installed browser did not stay running for update protection test." }
        $runningResult = Join-Path $testPath 'running-browser.json'
        Invoke-Setup @(
            '--test-mode', '--unattended', '--force', '--no-launch',
            "--install-root=$installRoot",
            "--profile-root=$profileRoot", "--test-id=$testId", "--result=$runningResult"
        ) 1
        $running = Get-Content $runningResult -Raw | ConvertFrom-Json
        if ($running.ok -or $running.reason -notmatch 'Close Granger Browser') {
            throw "Running-browser protection did not reject the update."
        }
        $results.RunningBrowserProtected = $true
    } finally {
        Stop-IsolatedBrowser $installRoot
    }

    $webOutput = Join-Path $testPath 'web.json'
    $webFixture = Join-Path $testPath 'renderer-fixture.html'
    Set-Content -LiteralPath $webFixture -Encoding UTF8 -Value `
        '<!doctype html><meta charset="utf-8"><title>Granger renderer fixture</title><p>renderer-ok</p>'
    $webFixtureUrl = ([Uri]::new($webFixture)).AbsoluteUri
    $webProcess = Start-Process -FilePath (Join-Path $installRoot 'GrangerBrowser.exe') `
        -ArgumentList @("--smoke-url=$webFixtureUrl", "--smoke-output=$webOutput") -Wait -PassThru
    $web = Get-Content $webOutput -Raw | ConvertFrom-Json
    if ($webProcess.ExitCode -ne 0 -or -not $web.ok -or $web.title -ne 'Granger renderer fixture') {
        throw "Installed browser WebEngine smoke failed."
    }
    $results.Granger = $true
    $results.QtWebEngine = $true
    $results.WebPage = $true

    $torPassed = $false
    $maxTorAttempts = 3
    for ($torAttempt = 1; $torAttempt -le $maxTorAttempts; $torAttempt++) {
        $torOutput = Join-Path $testPath $(if ($torAttempt -eq 1) { 'managed-tor.json' } else { 'managed-tor-retry.json' })
        $torProcess = Start-Process -FilePath (Join-Path $installRoot 'GrangerBrowser.exe') `
            -ArgumentList @('--smoke-managed-mode=direct', "--smoke-output=$torOutput") -Wait -PassThru
        $tor = Get-Content $torOutput -Raw | ConvertFrom-Json
        $torPassed = $torProcess.ExitCode -eq 0 -and $tor.ok -and $tor.routeVerified `
            -and $tor.bootstrapProgress -eq 100
        if ($torPassed) { break }
        $retryableVerificationFailure = $torAttempt -lt $maxTorAttempts `
            -and $tor.bootstrapProgress -eq 100 -and -not $tor.routeVerified `
            -and $tor.configVerificationOutput -match 'Configuration was valid' `
            -and $tor.reason -match 'route verification|check endpoint|timed out'
        if (-not $retryableVerificationFailure) { break }
        Start-Sleep -Seconds 2
    }
    if (-not $torPassed) {
        throw "Installed browser managed Tor smoke failed after $torAttempt attempt(s)."
    }
    $results.Tor = $true
    $results.TorAttempts = $torAttempt

    $i2pPassed = $false
    $maxI2pAttempts = 2
    for ($i2pAttempt = 1; $i2pAttempt -le $maxI2pAttempts; $i2pAttempt++) {
        $i2pOutput = Join-Path $testPath $(if ($i2pAttempt -eq 1) { 'managed-i2p.json' } else { 'managed-i2p-retry.json' })
        $i2pProcess = Start-Process -FilePath (Join-Path $installRoot 'GrangerBrowser.exe') `
            -ArgumentList @('--smoke-i2p-runtime', "--smoke-output=$i2pOutput", '--smoke-timeout-ms=300000') `
            -Wait -PassThru
        $i2p = Get-Content -LiteralPath $i2pOutput -Raw | ConvertFrom-Json
        $i2pPassed = $i2pProcess.ExitCode -eq 0 -and $i2p.ok `
            -and $i2p.firstRouteVerified -and $i2p.secondRouteVerified `
            -and $i2p.firstAddressBookReady -and $i2p.bootstrapContainsExpectedNames `
            -and $i2p.humanReadableConnected -and $i2p.humanReadableHttpResponse `
            -and $i2p.externalB32Connected -and $i2p.externalB32HttpResponse `
            -and $i2p.unknownNameBlocked -and $i2p.headlessConfigured `
            -and $i2p.routeLossObserved -and $i2p.restartRequested -and $i2p.stopped `
            -and -not $i2p.outproxyConfigured -and $i2p.clearnetPolicy -eq 'blocked'
        if ($i2pPassed) { break }
        $retryableReseedFailure = $i2pAttempt -lt $maxI2pAttempts `
            -and $i2p.started -and $i2p.stopped -and $i2p.firstAddressBookReady `
            -and -not $i2p.firstRouteVerified `
            -and $i2p.finalError -match 'SOCKS is not listening|timed out|reseed'
        if (-not $retryableReseedFailure) { break }
        Start-Sleep -Seconds 2
    }
    if (-not $i2pPassed) {
        throw "Installed browser managed I2P smoke failed after $i2pAttempt attempt(s)."
    }
    $results.I2P = $true
    $results.I2PAttempts = $i2pAttempt
    $results.I2PAddressBook = $true
    $results.I2PExternalB32 = $true
    $results.I2PHeadless = $true
    $results.I2PHumanReadable = $true
    $results.I2PRecovery = $true

    $wrongManifest = Join-Path $fixtureRoot 'wrong-sha.json'
    $wrongObject = Get-Content $manifestPath -Raw | ConvertFrom-Json
    $wrongObject.sha256 = ('0' * 64)
    $wrongObject | ConvertTo-Json | Set-Content $wrongManifest -Encoding UTF8
    $wrongResult = Join-Path $testPath 'wrong-sha-result.json'
    Invoke-Setup @(
        '--test-mode', '--unattended', '--no-launch', '--force',
        "--manifest-path=$wrongManifest", "--package-path=$packagePath",
        "--install-root=$(Join-Path $testPath 'wrong-sha-install')",
        "--profile-root=$(Join-Path $testPath 'wrong-sha-profile')", '--test-id=wrong-sha',
        "--result=$wrongResult"
    ) 1
    $wrong = Get-Content $wrongResult -Raw | ConvertFrom-Json
    if ($wrong.ok -or $wrong.shaVerified -or $wrong.reason -notmatch 'integrity') {
        throw "Wrong-SHA package was not rejected."
    }
    $results.WrongShaRejected = $true

    $invalidManifest = Join-Path $fixtureRoot 'invalid-zip.json'
    $invalidSize = (Get-Item $invalidZip).Length
    [ordered]@{
        schemaVersion = 2; version = $packageVersion; architecture = 'x64'
        minimumWindowsVersion = '10.0.17763'
        packageSize = $invalidSize
        sha256 = (Get-FileHash $invalidZip -Algorithm SHA256).Hash.ToLowerInvariant()
    } | ConvertTo-Json | Set-Content $invalidManifest -Encoding UTF8
    $invalidResult = Join-Path $testPath 'invalid-zip-result.json'
    Invoke-Setup @(
        '--test-mode', '--unattended', '--no-launch', '--force',
        "--manifest-path=$invalidManifest", "--package-path=$invalidZip",
        "--install-root=$(Join-Path $testPath 'invalid-zip-install')",
        "--profile-root=$(Join-Path $testPath 'invalid-zip-profile')", '--test-id=invalid-zip',
        "--result=$invalidResult"
    ) 1
    $invalid = Get-Content $invalidResult -Raw | ConvertFrom-Json
    if ($invalid.ok -or $invalid.reason -notmatch 'valid ZIP') { throw "Invalid ZIP was not rejected." }
    $results.InvalidZipRejected = $true

    $incompleteResult = Join-Path $testPath 'incomplete-local-override-result.json'
    Invoke-Setup @(
        '--test-mode', '--unattended', '--no-launch', '--force',
        "--manifest-path=$manifestPath", "--install-root=$(Join-Path $testPath 'incomplete-install')",
        "--profile-root=$(Join-Path $testPath 'incomplete-profile')", '--test-id=incomplete',
        "--result=$incompleteResult"
    ) 1
    $incomplete = Get-Content $incompleteResult -Raw | ConvertFrom-Json
    if ($incomplete.ok -or $incomplete.reason -notmatch 'provided together') {
        throw "Incomplete local test release override was not rejected."
    }
    $results.IncompleteLocalOverrideRejected = $true

    Add-Type -AssemblyName System.IO.Compression
    $traversalZip = Join-Path $fixtureRoot 'path-traversal.zip'
    $zipStream = [IO.File]::Open($traversalZip, [IO.FileMode]::CreateNew)
    try {
        $zip = [IO.Compression.ZipArchive]::new($zipStream, [IO.Compression.ZipArchiveMode]::Create, $false)
        try {
            $entry = $zip.CreateEntry('../outside.txt')
            $writer = [IO.StreamWriter]::new($entry.Open())
            try { $writer.Write('must not escape extraction root') } finally { $writer.Dispose() }
        } finally {
            $zip.Dispose()
        }
    } finally {
        $zipStream.Dispose()
    }
    $traversalManifest = Join-Path $fixtureRoot 'path-traversal.json'
    [ordered]@{
        schemaVersion = 2; version = $packageVersion; architecture = 'x64'
        minimumWindowsVersion = '10.0.17763'
        packageSize = (Get-Item $traversalZip).Length
        sha256 = (Get-FileHash $traversalZip -Algorithm SHA256).Hash.ToLowerInvariant()
    } | ConvertTo-Json | Set-Content $traversalManifest -Encoding UTF8
    $traversalResult = Join-Path $testPath 'path-traversal-result.json'
    Invoke-Setup @(
        '--test-mode', '--unattended', '--no-launch', '--force',
        "--manifest-path=$traversalManifest", "--package-path=$traversalZip",
        "--install-root=$(Join-Path $testPath 'traversal/install')",
        "--profile-root=$(Join-Path $testPath 'traversal/profile')", '--test-id=traversal',
        "--result=$traversalResult"
    ) 1
    $traversal = Get-Content $traversalResult -Raw | ConvertFrom-Json
    $escapedFiles = @(Get-ChildItem -LiteralPath $testPath -Filter outside.txt -Recurse -File -ErrorAction SilentlyContinue)
    if ($traversal.ok -or $traversal.reason -notmatch 'unsafe archive path' -or $escapedFiles.Count -ne 0) {
        throw "Archive path traversal was not rejected safely."
    }
    $results.PathTraversalRejected = $true

    $invalidTarget = Join-Path $testPath 'invalid-install-target'
    Set-Content -LiteralPath $invalidTarget -Value 'not a directory' -Encoding ASCII
    $invalidPathResult = Join-Path $testPath 'invalid-path-result.json'
    Invoke-Setup @(
        '--test-mode', '--unattended', '--no-launch', '--force',
        "--install-root=$invalidTarget",
        "--profile-root=$(Join-Path $testPath 'invalid-path-profile')", '--test-id=invalid-path',
        "--result=$invalidPathResult"
    ) 1
    $invalidPath = Get-Content $invalidPathResult -Raw | ConvertFrom-Json
    if ($invalidPath.ok -or $invalidPath.reason -notmatch 'not a directory') {
        throw "Invalid installation target was not rejected."
    }
    $results.InvalidInstallPathRejected = $true

    $uninstallResult = Join-Path $testPath 'uninstall.json'
    Invoke-Setup @(
        '--test-mode', '--unattended', '--uninstall',
        "--install-root=$installRoot", "--profile-root=$profileRoot",
        "--test-id=$testId", "--result=$uninstallResult"
    )
    $uninstall = Get-Content $uninstallResult -Raw | ConvertFrom-Json
    if (-not $uninstall.ok -or (Test-Path $installRoot) -or -not (Test-Path $marker) `
        -or (Test-Path $startShortcut) -or (Test-Path $desktopShortcut)) {
        throw "Uninstall failed or removed preserved user data."
    }
    $results.Uninstall = $true
    $results.UserProfilePreservedAfterUninstall = $true
} finally {
    Stop-IsolatedBrowser $installRoot
    $testRegistry = "HKCU:\Software\Granger Browser\InstallerTests\$testId"
    if (Test-Path -LiteralPath $testRegistry) {
        Remove-Item -LiteralPath $testRegistry -Recurse -Force
    }
    $env:GRANGER_DATA_ROOT = $oldData
    $env:GRANGER_SETTINGS_ROOT = $oldSettings
    $env:GRANGER_CACHE_ROOT = $oldCache
    $env:GRANGER_DOWNLOAD_ROOT = $oldDownloads
}

$report = [ordered]@{
    OK = (@($results.Values | Where-Object { -not $_ }).Count -eq 0)
    Setup = $standalone
    SetupSHA256 = (Get-FileHash $standalone -Algorithm SHA256).Hash
    GifEmbedded = [bool]$self.gifEmbedded
    GifFrames = [int]$self.gifFrames
    GifAnimation = [bool]$ui.ok
    DpiChecks = $self.dpiChecks
    Package = $packagePath
    PackageSize = $packageSize
    PackageSHA256 = $packageHash.ToUpperInvariant()
    I2P = $i2pOutput
    Results = $results
}
$reportPath = Join-Path $testPath 'installer-acceptance.json'
$report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $reportPath -Encoding UTF8
$report
