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

function Start-GrangerProbe {
    param([string[]]$Arguments)

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $executable
    $startInfo.WorkingDirectory = $testRoot
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $quoted = foreach ($argument in $Arguments) {
        '"' + $argument.Replace('"', '\"') + '"'
    }
    $startInfo.Arguments = $quoted -join ' '
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        $process.Dispose()
        throw "Granger probe process could not be started."
    }
    return $process
}

$testRoot = Join-Path (Split-Path -Parent $resultPath) `
    ("network-bootstrap-fixture-" + [guid]::NewGuid().ToString("N"))
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
    $process = Start-GrangerProbe @("--smoke-url=$target", "--smoke-output=$browserResultPath")
    if (-not $process.WaitForExit(45000)) {
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
        throw "Blocked navigation did not produce diagnostics (exit code $($process.ExitCode))."
    }
    $browserResult = Get-Content -LiteralPath $browserResultPath -Raw -Encoding UTF8 |
        ConvertFrom-Json
    $flags = [string]$browserResult.chromiumFlags
    $gatewayPinned = [bool]$browserResult.blockedTestGateway -and
        ([Uri]$browserResult.startupProcessProxy).Host -eq "127.0.0.1"
    $untrustedFlagsRemoved = $flags -notmatch '(?i)--no-proxy-server' -and
        $flags -notmatch '(?i)--proxy-bypass-list=\*' -and
        $flags -notmatch '(?i)EXCLUDE \*'

    $proxyProbe = Start-GrangerProbe @(
        "--smoke-proxy=socks5://${probeAddress}:$probePort",
        "--smoke-profile-state",
        "--smoke-output=$(Join-Path $testRoot 'invalid-proxy.json')"
    )
    $proxyProbe.WaitForExit()
    $externalSmokeProxyRejected = $proxyProbe.ExitCode -eq 7
    $argumentProbe = Start-GrangerProbe @('--webEngineArgs', '--no-proxy-server')
    $argumentProbe.WaitForExit()
    $chromiumArgumentOverrideRejected = $argumentProbe.ExitCode -eq 8
    $mixedModeProbe = Start-GrangerProbe @(
        '--smoke-managed-mode=direct',
        "--smoke-url=$target",
        "--smoke-output=$(Join-Path $testRoot 'mixed-mode.json')"
    )
    $mixedModeProbe.WaitForExit()
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
