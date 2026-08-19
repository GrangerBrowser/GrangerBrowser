[CmdletBinding()]
param(
    [string]$PackageDirectory = "release/Granger Browser",
    [string]$OutputPath = "output/network-bootstrap-fail-closed.json"
)

$ErrorActionPreference = "Stop"
$projectRoot = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot)).TrimEnd('\')
$packageRoot = [IO.Path]::GetFullPath((Join-Path $projectRoot $PackageDirectory))
$resultPath = [IO.Path]::GetFullPath((Join-Path $projectRoot $OutputPath))
if (-not $packageRoot.StartsWith($projectRoot + '\', [StringComparison]::OrdinalIgnoreCase) -or
    -not $resultPath.StartsWith($projectRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw "Test paths must remain inside the project workspace."
}

$executable = Join-Path $packageRoot "GrangerBrowser.exe"
if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
    throw "Packaged executable was not found: $executable"
}

$testRoot = Join-Path (Split-Path -Parent $resultPath) "network-bootstrap-fixture"
New-Item -ItemType Directory -Path $testRoot -Force | Out-Null
$browserResultPath = Join-Path $testRoot "blocked-navigation.json"
$probeAddress = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
    Where-Object {
        $_.AddressState -eq "Preferred" -and
        $_.IPAddress -notlike "127.*" -and
        $_.IPAddress -ne "0.0.0.0"
    } |
    Select-Object -First 1 -ExpandProperty IPAddress
if ([string]::IsNullOrWhiteSpace($probeAddress)) {
    throw "No non-loopback IPv4 address is available for the direct-route probe."
}

$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Any, 0)
$listener.Start()
$probePort = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
$acceptTask = $listener.AcceptTcpClientAsync()

$environmentNames = @(
    "GRANGER_DATA_ROOT", "GRANGER_SETTINGS_ROOT", "GRANGER_DOWNLOAD_ROOT",
    "QTWEBENGINE_CHROMIUM_FLAGS"
)
$oldEnvironment = @{}
foreach ($name in $environmentNames) {
    $oldEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
}

try {
    $env:GRANGER_DATA_ROOT = Join-Path $testRoot "data"
    $env:GRANGER_SETTINGS_ROOT = Join-Path $testRoot "settings"
    $env:GRANGER_DOWNLOAD_ROOT = Join-Path $testRoot "downloads"
    $env:QTWEBENGINE_CHROMIUM_FLAGS = `
        '--no-proxy-server --proxy-bypass-list=* --host-resolver-rules="EXCLUDE *"'

    $target = "http://${probeAddress}:$probePort/direct-route-probe"
    $process = Start-Process -FilePath $executable -WorkingDirectory $testRoot -PassThru `
        -ArgumentList @("--smoke-url=$target", "--smoke-output=$browserResultPath")
    if (-not $process.WaitForExit(30000)) {
        $process.Kill()
        $process.WaitForExit()
        throw "Blocked navigation smoke timed out."
    }

    $directConnectionObserved = $acceptTask.Wait(1500)
    if ($directConnectionObserved) {
        $client = $acceptTask.Result
        $client.Close()
    }
    $listener.Stop()

    if (-not (Test-Path -LiteralPath $browserResultPath -PathType Leaf)) {
        throw "Blocked navigation did not produce diagnostics."
    }
    $browserResult = Get-Content -LiteralPath $browserResultPath -Raw -Encoding UTF8 |
        ConvertFrom-Json
    $flags = [string]$browserResult.chromiumFlags
    $gatewayPinned = [bool]$browserResult.blockedTestGateway -and
        ([Uri]$browserResult.startupProcessProxy).Host -eq "127.0.0.1"
    $untrustedFlagsRemoved = $flags -notmatch '(?i)--no-proxy-server' -and
        $flags -notmatch '(?i)--proxy-bypass-list=\*' -and
        $flags -notmatch '(?i)EXCLUDE \*'

    $proxyProbe = Start-Process -FilePath $executable -WorkingDirectory $testRoot -Wait -PassThru `
        -ArgumentList @(
            "--smoke-proxy=socks5://${probeAddress}:$probePort",
            "--smoke-profile-state",
            "--smoke-output=$(Join-Path $testRoot 'invalid-proxy.json')"
        )
    $externalSmokeProxyRejected = $proxyProbe.ExitCode -eq 7
    $argumentProbe = Start-Process -FilePath $executable -WorkingDirectory $testRoot -Wait -PassThru `
        -ArgumentList @('--webEngineArgs', '--no-proxy-server')
    $chromiumArgumentOverrideRejected = $argumentProbe.ExitCode -eq 8
    $mixedModeProbe = Start-Process -FilePath $executable -WorkingDirectory $testRoot -Wait -PassThru `
        -ArgumentList @(
            '--smoke-managed-mode=direct',
            "--smoke-url=$target",
            "--smoke-output=$(Join-Path $testRoot 'mixed-mode.json')"
        )
    $mixedManagedModeRejected = $mixedModeProbe.ExitCode -eq 9
    $ok = -not $directConnectionObserved -and -not [bool]$browserResult.ok -and
        $gatewayPinned -and $untrustedFlagsRemoved -and $externalSmokeProxyRejected -and
        $chromiumArgumentOverrideRejected -and $mixedManagedModeRejected

    $result = [ordered]@{
        ok = $ok
        target = $target
        directConnectionObserved = [bool]$directConnectionObserved
        browserExitCode = $process.ExitCode
        navigationLoaded = [bool]$browserResult.ok
        blockedTestGateway = [bool]$browserResult.blockedTestGateway
        startupProcessProxy = [string]$browserResult.startupProcessProxy
        untrustedChromiumFlagsRemoved = $untrustedFlagsRemoved
        externalSmokeProxyRejected = $externalSmokeProxyRejected
        chromiumArgumentOverrideRejected = $chromiumArgumentOverrideRejected
        mixedManagedModeRejected = $mixedManagedModeRejected
        chromiumFlags = $flags
    }
    New-Item -ItemType Directory -Path (Split-Path -Parent $resultPath) -Force | Out-Null
    $result | ConvertTo-Json -Depth 4 |
        Set-Content -LiteralPath $resultPath -Encoding UTF8
    if (-not $ok) { throw "Network bootstrap fail-closed regression failed." }
    [pscustomobject]$result
} finally {
    $listener.Stop()
    foreach ($name in $environmentNames) {
        [Environment]::SetEnvironmentVariable($name, $oldEnvironment[$name], "Process")
    }
}
