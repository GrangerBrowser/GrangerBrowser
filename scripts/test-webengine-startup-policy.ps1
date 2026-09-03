[CmdletBinding()]
param(
    [string]$PackageDirectory = "release/Granger Browser",
    [string]$OutputPath = "output/webengine-startup-policy.json"
)

$ErrorActionPreference = "Stop"
$projectRoot = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot)).TrimEnd('\')
$packageRoot = [IO.Path]::GetFullPath((Join-Path $projectRoot $PackageDirectory))
$resultPath = [IO.Path]::GetFullPath((Join-Path $projectRoot $OutputPath))
foreach ($path in @($packageRoot, $resultPath)) {
    if (-not $path.StartsWith($projectRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Startup policy test paths must remain inside the workspace."
    }
}
$executable = Join-Path $packageRoot "GrangerBrowser.exe"
if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) { throw "Browser not found." }
$testRoot = Join-Path (Split-Path -Parent $resultPath) ("startup-policy-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $testRoot -Force | Out-Null
$reservation = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
$reservation.Start()
$debugPort = ([Net.IPEndPoint]$reservation.LocalEndpoint).Port
$reservation.Stop()

function Invoke-StartupProbe {
    param([string]$Name, [string[]]$Arguments, [switch]$HostileEnvironment, [switch]$ObserveListener)
    $runRoot = Join-Path $testRoot $Name
    New-Item -ItemType Directory -Path $runRoot -Force | Out-Null
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $executable
    $start.WorkingDirectory = $runRoot
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardError = $true
    $start.RedirectStandardOutput = $true
    foreach ($argument in $Arguments) { [void]$start.ArgumentList.Add($argument) }
    foreach ($kind in @("DATA", "SETTINGS", "CACHE", "DOWNLOAD")) {
        $start.Environment["GRANGER_${kind}_ROOT"] = Join-Path $runRoot $kind.ToLowerInvariant()
    }
    foreach ($name in @("QTWEBENGINE_CHROMIUM_FLAGS", "QTWEBENGINE_REMOTE_DEBUGGING", "QTWEBENGINE_DISABLE_SANDBOX")) {
        [void]$start.Environment.Remove($name)
    }
    if ($HostileEnvironment) {
        $start.Environment["QTWEBENGINE_REMOTE_DEBUGGING"] = "127.0.0.1:$debugPort"
        $start.Environment["QTWEBENGINE_DISABLE_SANDBOX"] = "1"
        $start.Environment["QTWEBENGINE_CHROMIUM_FLAGS"] = "--enable-quic --no-proxy-server --no-sandbox --remote-debugging-port=$debugPort"
    }
    $process = [Diagnostics.Process]::Start($start)
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    $observed = $false
    $watch = [Diagnostics.Stopwatch]::StartNew()
    try {
        while (-not $process.WaitForExit(100)) {
            if ($watch.Elapsed.TotalSeconds -gt 45) { throw "Startup probe $Name timed out." }
            if ($ObserveListener) {
                $client = [Net.Sockets.TcpClient]::new()
                try {
                    $connection = $client.ConnectAsync([Net.IPAddress]::Loopback, $debugPort)
                    try { [void]$connection.Wait(100) } catch { }
                    $observed = $observed -or $client.Connected
                } finally { $client.Dispose() }
            }
        }
        $out = $stdout.GetAwaiter().GetResult()
        $err = $stderr.GetAwaiter().GetResult()
        $out | Set-Content -LiteralPath (Join-Path $runRoot "stdout.log") -Encoding UTF8
        $err | Set-Content -LiteralPath (Join-Path $runRoot "stderr.log") -Encoding UTF8
        return [pscustomobject]@{
            ExitCode = $process.ExitCode
            ListenerObserved = $observed
            DebugServerLogged = $err.Contains("DevTools listening on")
        }
    } finally {
        if (-not $process.HasExited) {
            & "$env:SystemRoot/System32/taskkill.exe" /PID $process.Id /T /F | Out-Null
            [void]$process.WaitForExit(10000)
        }
        $process.Dispose()
    }
}

$idleResult = Join-Path $testRoot "idle.json"
$environment = Invoke-StartupProbe -Name "environment" -HostileEnvironment -ObserveListener `
    -Arguments @("--smoke-idle-event-profile", "--smoke-output=$idleResult")
$arguments = [ordered]@{}
foreach ($argument in @("--remote-debugging-port=$debugPort", "--remote-debugging-address=127.0.0.1", "--remote-debugging-pipe", "--remote-allow-origins=*")) {
    $name = "argument-" + $arguments.Count
    $probe = Invoke-StartupProbe -Name $name -Arguments @($argument, "--smoke-profile-state", "--smoke-output=$(Join-Path $testRoot "$name.json")")
    $arguments[$argument.Split('=')[0]] = $probe.ExitCode -eq 8
}
$ok = $environment.ExitCode -eq 0 -and -not $environment.ListenerObserved -and
    -not $environment.DebugServerLogged -and @($arguments.Values | Where-Object { -not $_ }).Count -eq 0
$result = [ordered]@{
    ok = $ok
    scope = "Packaged WebEngine, isolated roots, loopback-only hostile debugging probe"
    environment = $environment
    argumentRejections = $arguments
    evidence = $testRoot
}
$result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $resultPath -Encoding UTF8
if (-not $ok) { throw "WebEngine startup policy regression failed: $resultPath" }
[pscustomobject]$result
