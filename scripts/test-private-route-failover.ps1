param(
    [string]$PackageDirectory = "release/Granger Browser",
    [ValidateSet("tor-loss", "i2p-loss", "both-loss")]
    [string[]]$Scenario = @("tor-loss", "i2p-loss", "both-loss"),
    [int]$TimeoutMinutes = 14,
    [switch]$KillRendererDuringSwitch
)

$ErrorActionPreference = "Stop"
$projectRoot = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$packageRoot = [IO.Path]::GetFullPath((Join-Path $projectRoot $PackageDirectory))
$executable = Join-Path $packageRoot "GrangerBrowser.exe"
if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
    throw "Packaged GrangerBrowser.exe not found: $executable"
}
if (-not (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)) {
    throw "Get-NetTCPConnection is required for browser socket observation."
}
if (-not (Get-Command Get-NetUDPEndpoint -ErrorAction SilentlyContinue)) {
    throw "Get-NetUDPEndpoint is required for browser socket observation."
}

$resultsRoot = Join-Path $projectRoot "output/private-route-live-acceptance"
New-Item -ItemType Directory -Path $resultsRoot -Force | Out-Null

function Test-LoopbackAddress([string]$Address) {
    if ([string]::IsNullOrWhiteSpace($Address)) { return $false }
    try {
        $parsed = [Net.IPAddress]::Parse($Address)
        if ([Net.IPAddress]::IsLoopback($parsed)) { return $true }
        return $parsed.IsIPv4MappedToIPv6 -and [Net.IPAddress]::IsLoopback($parsed.MapToIPv4())
    } catch {
        return $false
    }
}

function Get-ObservedBrowserProcesses([int]$RootProcessId, [Collections.Generic.HashSet[int]]$KnownIds) {
    $processes = @(Get-CimInstance Win32_Process -ErrorAction Stop)
    [void]$KnownIds.Add($RootProcessId)
    $changed = $true
    while ($changed) {
        $changed = $false
        foreach ($entry in $processes) {
            if ($KnownIds.Contains([int]$entry.ParentProcessId) -and
                -not $KnownIds.Contains([int]$entry.ProcessId)) {
                [void]$KnownIds.Add([int]$entry.ProcessId)
                $changed = $true
            }
        }
    }
    return @($processes | Where-Object {
        $KnownIds.Contains([int]$_.ProcessId) -and
        $_.Name -in @("GrangerBrowser.exe", "QtWebEngineProcess.exe")
    })
}

function Read-AcceptanceReport([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    try { return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json } catch { return $null }
}

$allResults = @()
foreach ($case in $Scenario) {
    $caseRoot = [IO.Path]::GetFullPath((Join-Path $resultsRoot $case))
    if (-not $caseRoot.StartsWith($resultsRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Acceptance path escaped the workspace: $caseRoot"
    }
    if (Test-Path -LiteralPath $caseRoot) {
        Remove-Item -LiteralPath $caseRoot -Recurse -Force
    }
    $dataRoot = Join-Path $caseRoot "data"
    $settingsRoot = Join-Path $caseRoot "settings"
    $cacheRoot = Join-Path $caseRoot "cache"
    $workingDirectory = Join-Path $caseRoot "unrelated working directory"
    New-Item -ItemType Directory -Path $dataRoot,$settingsRoot,$cacheRoot,$workingDirectory -Force | Out-Null
    $applicationReport = Join-Path $caseRoot "application.json"
    $socketReport = Join-Path $caseRoot "socket-observation.json"

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $executable
    $startInfo.WorkingDirectory = $workingDirectory
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.Arguments = @(
        "--private-route-live-acceptance=$case",
        "--acceptance-output=$applicationReport",
        "--acceptance-timeout-ms=$($TimeoutMinutes * 60 * 1000)"
    ) | ForEach-Object { '"' + $_.Replace('"', '\"') + '"' } | Join-String -Separator ' '

    foreach ($name in @(
        "QTDIR", "CMAKE_PREFIX_PATH", "QT_PLUGIN_PATH", "QT_QPA_PLATFORM_PLUGIN_PATH",
        "QTWEBENGINEPROCESS_PATH", "QTWEBENGINE_RESOURCES_PATH", "QTWEBENGINE_LOCALES_PATH",
        "QML_IMPORT_PATH", "QML2_IMPORT_PATH", "VSINSTALLDIR", "VCINSTALLDIR",
        "VCToolsInstallDir", "VCToolsRedistDir", "WindowsSdkDir", "INCLUDE", "LIB", "LIBPATH",
        "GRANGER_RUNTIME_ROOT", "GRANGER_TOR_PATH", "GRANGER_LYREBIRD_PATH",
        "GRANGER_TRANSPORT_PATH", "GRANGER_I2P_PATH", "GRANGER_I2P_CERTS"
    )) {
        [void]$startInfo.Environment.Remove($name)
    }
    $startInfo.Environment["PATH"] = "$env:SystemRoot\System32;$env:SystemRoot"
    $startInfo.Environment["GRANGER_DATA_ROOT"] = $dataRoot
    $startInfo.Environment["GRANGER_SETTINGS_ROOT"] = $settingsRoot
    $startInfo.Environment["GRANGER_CACHE_ROOT"] = $cacheRoot

    $process = [Diagnostics.Process]::Start($startInfo)
    $knownIds = [Collections.Generic.HashSet[int]]::new()
    $directConnections = [Collections.Generic.List[object]]::new()
    $directUdpEndpoints = [Collections.Generic.List[object]]::new()
    $observedUdpKeys = [Collections.Generic.HashSet[string]]::new()
    $loopbackConnections = [Collections.Generic.HashSet[string]]::new()
    $sampleCount = 0
    $samplesAfterKill = 0
    $rendererKillIssued = $false
    $rendererKillAccepted = $false
    $rendererProcessId = 0
    $rendererKillPhase = ""
    $lastPhase = "starting"
    $deadline = [DateTime]::UtcNow.AddMinutes($TimeoutMinutes + 1)

    while (-not $process.HasExited -and [DateTime]::UtcNow -lt $deadline) {
        $report = Read-AcceptanceReport $applicationReport
        if ($report) {
            $lastPhase = [string]$report.phase
            if ($report.killIssued) { $samplesAfterKill++ }
        }
        $targets = @(Get-ObservedBrowserProcesses $process.Id $knownIds)
        if ($KillRendererDuringSwitch -and $report -and $report.killIssued -and
            -not $rendererKillIssued) {
            $renderer = @($targets | Where-Object {
                $_.Name -eq "QtWebEngineProcess.exe" -and
                $_.CommandLine -match '--type=renderer'
            }) | Select-Object -First 1
            if ($renderer) {
                $rendererKillIssued = $true
                $rendererProcessId = [int]$renderer.ProcessId
                $rendererKillPhase = $lastPhase
                try {
                    Stop-Process -Id $rendererProcessId -Force -ErrorAction Stop
                    $rendererKillAccepted = $true
                } catch {
                    $rendererKillAccepted = $false
                }
            }
        }
        $targetIds = @($targets | ForEach-Object { [int]$_.ProcessId })
        $namesById = @{}
        foreach ($target in $targets) { $namesById[[int]$target.ProcessId] = [string]$target.Name }
        if ($targetIds.Count -gt 0) {
            $connections = @(Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object {
                $targetIds -contains [int]$_.OwningProcess -and $_.RemotePort -gt 0
            })
            foreach ($connection in $connections) {
                $sampleCount++
                $key = "$($connection.OwningProcess)|$($connection.RemoteAddress)|$($connection.RemotePort)"
                if (Test-LoopbackAddress $connection.RemoteAddress) {
                    [void]$loopbackConnections.Add($key)
                    continue
                }
                $directConnections.Add([pscustomobject]@{
                    TimestampUtc = [DateTime]::UtcNow.ToString("o")
                    Phase = $lastPhase
                    Process = $namesById[[int]$connection.OwningProcess]
                    ProcessId = [int]$connection.OwningProcess
                    State = [string]$connection.State
                    LocalAddress = [string]$connection.LocalAddress
                    LocalPort = [int]$connection.LocalPort
                    RemoteAddress = [string]$connection.RemoteAddress
                    RemotePort = [int]$connection.RemotePort
                })
            }
            $udpEndpoints = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Where-Object {
                $targetIds -contains [int]$_.OwningProcess
            })
            foreach ($endpoint in $udpEndpoints) {
                $key = "$($endpoint.OwningProcess)|$($endpoint.LocalAddress)|$($endpoint.LocalPort)"
                if (-not $observedUdpKeys.Add($key) -or (Test-LoopbackAddress $endpoint.LocalAddress)) {
                    continue
                }
                $directUdpEndpoints.Add([pscustomobject]@{
                    TimestampUtc = [DateTime]::UtcNow.ToString("o")
                    Phase = $lastPhase
                    Process = $namesById[[int]$endpoint.OwningProcess]
                    ProcessId = [int]$endpoint.OwningProcess
                    LocalAddress = [string]$endpoint.LocalAddress
                    LocalPort = [int]$endpoint.LocalPort
                })
            }
        }
        Start-Sleep -Milliseconds ($report -and $report.killIssued ? 50 : 250)
        $process.Refresh()
    }

    if (-not $process.HasExited) {
        $process.Kill($true)
        $process.WaitForExit()
        throw "Private-route acceptance timed out for $case."
    }
    $process.WaitForExit()
    $application = Read-AcceptanceReport $applicationReport
    $liveKnownProcesses = @()
    $shutdownDeadline = [DateTime]::UtcNow.AddSeconds(5)
    do {
        $liveKnownProcesses = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
            $knownIds.Contains([int]$_.ProcessId) -and
            $_.Name -in @("GrangerBrowser.exe", "QtWebEngineProcess.exe", "tor.exe", "i2pd.exe")
        })
        if ($liveKnownProcesses.Count -eq 0 -or [DateTime]::UtcNow -ge $shutdownDeadline) {
            break
        }
        Start-Sleep -Milliseconds 100
    } while ($true)
    foreach ($orphan in $liveKnownProcesses) {
        Stop-Process -Id $orphan.ProcessId -Force -ErrorAction SilentlyContinue
    }

    $ok = $process.ExitCode -eq 0 -and $application -and $application.ok -and
        $directConnections.Count -eq 0 -and $directUdpEndpoints.Count -eq 0 -and
        $samplesAfterKill -gt 0 -and
        $liveKnownProcesses.Count -eq 0 -and
        (-not $KillRendererDuringSwitch -or $rendererKillAccepted)
    $result = [ordered]@{
        OK = [bool]$ok
        Scenario = $case
        ExitCode = $process.ExitCode
        ApplicationReport = $applicationReport
        ApplicationOK = [bool]($application -and $application.ok)
        FinalPhase = $lastPhase
        SocketSamples = $sampleCount
        SamplesAfterKill = $samplesAfterKill
        RendererKillRequested = [bool]$KillRendererDuringSwitch
        RendererKillAccepted = $rendererKillAccepted
        RendererProcessId = $rendererProcessId
        RendererKillPhase = $rendererKillPhase
        LoopbackConnectionsObserved = $loopbackConnections.Count
        DirectConnections = @($directConnections)
        DirectUdpEndpoints = @($directUdpEndpoints)
        OrphanProcesses = @($liveKnownProcesses | Select-Object Name,ProcessId,ParentProcessId)
        Observation = "Windows kernel TCP ownership and UDP endpoint tables sampled for GrangerBrowser.exe and QtWebEngineProcess.exe; Tor and i2pd runtime traffic is excluded by process identity."
    }
    $result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $socketReport -Encoding utf8
    $allResults += [pscustomobject]$result
}

if (@($allResults | Where-Object { -not $_.OK }).Count -ne 0) {
    $allResults | ConvertTo-Json -Depth 8
    throw "One or more private-route live acceptance scenarios failed."
}
$allResults
