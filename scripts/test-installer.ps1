[CmdletBinding()]
param(
    [string]$Setup = "output/distribution/GrangerSetup.exe",
    [string]$PackageArchive = "output/distribution/Granger-Browser-v0.4.3-windows-x64.zip",
    [string]$TestRoot = "output/installer-acceptance"
)

$ErrorActionPreference = "Stop"
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class GrangerInstallerTestNative {
    [DllImport("user32.dll")]
    public static extern bool PostMessage(IntPtr window, uint message, UIntPtr wParam, IntPtr lParam);
}
'@
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
if (-not $self.ok -or -not $self.gifEmbedded -or $self.gifFrames -lt 2 -or $self.externalGifRequired) {
    throw "Standalone embedded GIF self-test failed."
}

$uiSmoke = Join-Path $testPath 'standalone/ui-smoke.json'
Invoke-Setup @('--test-mode', "--ui-smoke=$uiSmoke")
$ui = Get-Content -LiteralPath $uiSmoke -Raw | ConvertFrom-Json
if (-not $ui.ok -or $ui.framesAdvanced -lt 1) { throw "Installer GIF animation did not advance." }

$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
$listener.Start()
$port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
$listener.Stop()
$serverRoot = Join-Path $testPath 'server'
New-Item -ItemType Directory -Path $serverRoot -Force | Out-Null
$invalidZip = Join-Path $serverRoot 'invalid.zip'
[IO.File]::WriteAllText($invalidZip, 'not a zip archive', [Text.Encoding]::ASCII)
$packageSize = (Get-Item -LiteralPath $packagePath).Length
$packageHash = (Get-FileHash -LiteralPath $packagePath -Algorithm SHA256).Hash.ToLowerInvariant()
$baseUrl = "http://127.0.0.1:$port"
$manifestPath = Join-Path $serverRoot 'manifest.json'
[ordered]@{
    schemaVersion = 1
    version = '0.4.3'
    architecture = 'x64'
    minimumWindowsVersion = '10.0.17763'
    packageUrl = "$baseUrl/package.zip"
    packageSize = $packageSize
    sha256 = $packageHash
} | ConvertTo-Json | Set-Content -LiteralPath $manifestPath -Encoding UTF8

$server = Start-Job -ArgumentList $port,$manifestPath,$packagePath,$invalidZip -ScriptBlock {
    param($Port, $Manifest, $Package, $InvalidZip)
    $listener = [Net.HttpListener]::new()
    $listener.Prefixes.Add("http://127.0.0.1:$Port/")
    $listener.Start()
    $retryManifestFailed = $false
    try {
        while ($listener.IsListening) {
            $context = $listener.GetContext()
            $requestPath = $context.Request.Url.AbsolutePath.ToLowerInvariant()
            if ($requestPath -eq '/retry-manifest.json' -and -not $retryManifestFailed) {
                $retryManifestFailed = $true
                $context.Response.Abort()
                continue
            }
            $file = switch ($requestPath) {
                '/manifest.json' { $Manifest }
                '/retry-manifest.json' { $Manifest }
                '/package.zip' { $Package }
                '/invalid.zip' { $InvalidZip }
                default { $null }
            }
            if (-not $file) {
                $context.Response.StatusCode = 404
                $context.Response.Close()
                continue
            }
            $stream = [IO.File]::OpenRead($file)
            try {
                $context.Response.StatusCode = 200
                $context.Response.ContentLength64 = $stream.Length
                $buffer = New-Object byte[] (1024 * 512)
                while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $context.Response.OutputStream.Write($buffer, 0, $read)
                }
            } finally {
                $stream.Dispose()
                $context.Response.OutputStream.Close()
            }
        }
    } finally {
        $listener.Stop()
    }
}
Start-Sleep -Milliseconds 500

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
    $retryInstallRoot = Join-Path $testPath 'network-retry/Granger Browser'
    $retryProfileRoot = Join-Path $testPath 'network-retry-profile'
    $retryResult = Join-Path $testPath 'network-retry-first.json'
    $retryStart = [Diagnostics.ProcessStartInfo]::new()
    $retryStart.FileName = $standalone
    $retryStart.UseShellExecute = $false
    foreach ($argument in @(
        '--test-mode', '--no-launch', '--no-desktop-shortcut',
        "--manifest-url=$baseUrl/retry-manifest.json", "--install-root=$retryInstallRoot",
        "--profile-root=$retryProfileRoot", '--test-id=network-retry', "--result=$retryResult"
    )) {
        [void]$retryStart.ArgumentList.Add($argument)
    }
    $retryProcess = [Diagnostics.Process]::Start($retryStart)
    try {
        $deadline = (Get-Date).AddSeconds(30)
        while (-not (Test-Path -LiteralPath $retryResult) -and (Get-Date) -lt $deadline) {
            Start-Sleep -Milliseconds 100
        }
        if (-not (Test-Path -LiteralPath $retryResult)) { throw 'Disconnected manifest did not reach the installer failure state.' }
        $firstRetryOutcome = Get-Content -LiteralPath $retryResult -Raw | ConvertFrom-Json
        if ($firstRetryOutcome.ok -or $firstRetryOutcome.reason -notmatch 'download server|reach') {
            throw 'Disconnected manifest did not produce an understandable network error.'
        }
        $retryProcess.Refresh()
        if ($retryProcess.HasExited -or $retryProcess.MainWindowHandle -eq 0) {
            throw 'Installer Retry UI was not available after the network error.'
        }
        Remove-Item -LiteralPath $retryResult -Force
        [void][GrangerInstallerTestNative]::PostMessage(
            $retryProcess.MainWindowHandle, 0x0100, [UIntPtr]0x0D, [IntPtr]::Zero)
        $deadline = (Get-Date).AddMinutes(2)
        while (-not (Test-Path -LiteralPath $retryResult) -and (Get-Date) -lt $deadline) {
            Start-Sleep -Milliseconds 100
        }
        if (-not (Test-Path -LiteralPath $retryResult)) { throw 'Installer Retry did not complete.' }
        $retryOutcome = Get-Content -LiteralPath $retryResult -Raw | ConvertFrom-Json
        if (-not $retryOutcome.ok -or -not $retryOutcome.packageDownloaded -or -not $retryOutcome.shaVerified `
            -or -not $retryOutcome.packageValidated -or -not (Test-Path (Join-Path $retryInstallRoot 'GrangerBrowser.exe'))) {
            throw 'Installer Retry did not recover from the interrupted connection.'
        }
        $results.NetworkDisconnectRetry = $true
    } finally {
        $retryProcess.Refresh()
        if (-not $retryProcess.HasExited) {
            [void][GrangerInstallerTestNative]::PostMessage(
                $retryProcess.MainWindowHandle, 0x0010, [UIntPtr]::Zero, [IntPtr]::Zero)
            if (-not $retryProcess.WaitForExit(5000)) {
                Stop-Process -Id $retryProcess.Id -Force -ErrorAction SilentlyContinue
            }
        }
    }
    $retryUninstall = Join-Path $testPath 'network-retry-uninstall.json'
    Invoke-Setup @(
        '--test-mode', '--unattended', '--uninstall', "--install-root=$retryInstallRoot",
        "--profile-root=$retryProfileRoot", '--test-id=network-retry', "--result=$retryUninstall"
    )

    Invoke-Setup @(
        '--test-mode', '--unattended',
        "--manifest-url=$baseUrl/manifest.json",
        "--install-root=$installRoot",
        "--profile-root=$profileRoot",
        "--test-id=$testId",
        "--result=$resultInstall"
    )
    $install = Get-Content -LiteralPath $resultInstall -Raw | ConvertFrom-Json
    if (-not $install.ok -or -not $install.manifestDownloaded -or -not $install.packageDownloaded `
        -or -not $install.shaVerified -or -not $install.extracted -or -not $install.packageValidated `
        -or -not $install.shortcutsCreated -or -not $install.uninstallRegistered -or -not $install.launched) {
        throw "Full installer flow did not report every required stage."
    }
    $results.Install = $true
    $results.ManifestDownload = $true
    $results.RuntimeDownload = $true
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
        "--manifest-url=$baseUrl/manifest.json", "--install-root=$installRoot",
        "--profile-root=$profileRoot", "--test-id=$testId", "--result=$rerunResult"
    )
    $rerun = Get-Content $rerunResult -Raw | ConvertFrom-Json
    if (-not $rerun.ok -or -not $rerun.alreadyInstalled) { throw "Same-version re-run was not detected." }
    $results.Rerun = $true

    $testRegistry = "HKCU:\Software\Granger Browser\InstallerTests\$testId"
    Set-ItemProperty -LiteralPath $testRegistry -Name DisplayVersion -Value '0.4.2'
    $updateResult = Join-Path $testPath 'update.json'
    Invoke-Setup @(
        '--test-mode', '--unattended', '--no-launch',
        "--manifest-url=$baseUrl/manifest.json", "--install-root=$installRoot",
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
            "--manifest-url=$baseUrl/manifest.json", "--install-root=$installRoot",
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
        $retryableTimeout = $torAttempt -lt $maxTorAttempts -and $tor.bootstrapProgress -gt 0 `
            -and $tor.configVerificationOutput -match 'Configuration was valid' `
            -and $tor.reason -match 'timed out'
        if (-not $retryableTimeout) { break }
        Start-Sleep -Seconds 2
    }
    if (-not $torPassed) {
        throw "Installed browser managed Tor smoke failed after $torAttempt attempt(s)."
    }
    $results.Tor = $true
    $results.TorAttempts = $torAttempt

    $i2pProcess = Start-Process -FilePath (Join-Path $installRoot 'GrangerBrowser.exe') `
        -ArgumentList @('--smoke-i2p-runtime', "--smoke-output=$i2pOutput", '--smoke-timeout-ms=240000') `
        -Wait -PassThru
    $i2p = Get-Content -LiteralPath $i2pOutput -Raw | ConvertFrom-Json
    if ($i2pProcess.ExitCode -ne 0 -or -not $i2p.ok `
        -or -not $i2p.firstRouteVerified -or -not $i2p.secondRouteVerified `
        -or -not $i2p.firstAddressBookReady -or -not $i2p.bootstrapContainsExpectedNames `
        -or -not $i2p.humanReadableConnected -or -not $i2p.humanReadableHttpResponse `
        -or -not $i2p.externalB32Connected -or -not $i2p.externalB32HttpResponse `
        -or -not $i2p.unknownNameBlocked -or -not $i2p.headlessConfigured) {
        throw "Installed browser managed I2P smoke failed."
    }
    $results.I2P = $true
    $results.I2PAddressBook = $true
    $results.I2PExternalB32 = $true
    $results.I2PHeadless = $true
    $results.I2PHumanReadable = $true
    $results.I2PRecovery = $true

    $wrongManifest = Join-Path $serverRoot 'wrong-sha.json'
    $wrongObject = Get-Content $manifestPath -Raw | ConvertFrom-Json
    $wrongObject.sha256 = ('0' * 64)
    $wrongObject | ConvertTo-Json | Set-Content $wrongManifest -Encoding UTF8
    $wrongResult = Join-Path $testPath 'wrong-sha-result.json'
    Invoke-Setup @(
        '--test-mode', '--unattended', '--no-launch', '--force',
        "--manifest-path=$wrongManifest", "--install-root=$(Join-Path $testPath 'wrong-sha-install')",
        "--profile-root=$(Join-Path $testPath 'wrong-sha-profile')", '--test-id=wrong-sha',
        "--result=$wrongResult"
    ) 1
    $wrong = Get-Content $wrongResult -Raw | ConvertFrom-Json
    if ($wrong.ok -or $wrong.shaVerified -or $wrong.reason -notmatch 'integrity') {
        throw "Wrong-SHA package was not rejected."
    }
    $results.WrongShaRejected = $true

    $invalidManifest = Join-Path $serverRoot 'invalid-zip.json'
    $invalidSize = (Get-Item $invalidZip).Length
    [ordered]@{
        schemaVersion = 1; version = '0.4.3'; architecture = 'x64'
        minimumWindowsVersion = '10.0.17763'; packageUrl = "$baseUrl/invalid.zip"
        packageSize = $invalidSize
        sha256 = (Get-FileHash $invalidZip -Algorithm SHA256).Hash.ToLowerInvariant()
    } | ConvertTo-Json | Set-Content $invalidManifest -Encoding UTF8
    $invalidResult = Join-Path $testPath 'invalid-zip-result.json'
    Invoke-Setup @(
        '--test-mode', '--unattended', '--no-launch', '--force',
        "--manifest-path=$invalidManifest", "--install-root=$(Join-Path $testPath 'invalid-zip-install')",
        "--profile-root=$(Join-Path $testPath 'invalid-zip-profile')", '--test-id=invalid-zip',
        "--result=$invalidResult"
    ) 1
    $invalid = Get-Content $invalidResult -Raw | ConvertFrom-Json
    if ($invalid.ok -or $invalid.reason -notmatch 'valid ZIP') { throw "Invalid ZIP was not rejected." }
    $results.InvalidZipRejected = $true

    $missingResult = Join-Path $testPath 'missing-manifest-result.json'
    Invoke-Setup @(
        '--test-mode', '--unattended', '--no-launch', '--force',
        "--manifest-url=$baseUrl/missing.json", "--install-root=$(Join-Path $testPath 'missing-install')",
        "--profile-root=$(Join-Path $testPath 'missing-profile')", '--test-id=missing',
        "--result=$missingResult"
    ) 1
    $missing = Get-Content $missingResult -Raw | ConvertFrom-Json
    if ($missing.ok -or $missing.reason -notmatch 'HTTP 404') { throw "Missing manifest was not reported." }
    $results.MissingManifestRejected = $true

    $invalidTarget = Join-Path $testPath 'invalid-install-target'
    Set-Content -LiteralPath $invalidTarget -Value 'not a directory' -Encoding ASCII
    $invalidPathResult = Join-Path $testPath 'invalid-path-result.json'
    Invoke-Setup @(
        '--test-mode', '--unattended', '--no-launch', '--force',
        "--manifest-url=$baseUrl/manifest.json", "--install-root=$invalidTarget",
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
    $retryRegistry = 'HKCU:\Software\Granger Browser\InstallerTests\network-retry'
    if (Test-Path -LiteralPath $retryRegistry) {
        Remove-Item -LiteralPath $retryRegistry -Recurse -Force
    }
    $env:GRANGER_DATA_ROOT = $oldData
    $env:GRANGER_SETTINGS_ROOT = $oldSettings
    $env:GRANGER_CACHE_ROOT = $oldCache
    $env:GRANGER_DOWNLOAD_ROOT = $oldDownloads
    Stop-Job $server -ErrorAction SilentlyContinue
    Remove-Job $server -Force -ErrorAction SilentlyContinue
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
