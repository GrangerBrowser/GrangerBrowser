[CmdletBinding()]
param(
    [string]$QtRoot = $env:QTDIR,
    [string]$BuildDirectory = "build/desktop",
    [string]$PythonExecutable = ""
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($QtRoot)) { $QtRoot = $env:CMAKE_PREFIX_PATH }
if ([string]::IsNullOrWhiteSpace($QtRoot) -or -not (Test-Path -LiteralPath $QtRoot)) {
    throw "QtRoot was not found. Pass -QtRoot or set QTDIR/CMAKE_PREFIX_PATH."
}
if ([string]::IsNullOrWhiteSpace($PythonExecutable)) {
    $PythonExecutable = (Get-Command python.exe -ErrorAction SilentlyContinue).Source
}
if ([string]::IsNullOrWhiteSpace($PythonExecutable) -or
    -not (Test-Path -LiteralPath $PythonExecutable -PathType Leaf)) {
    throw "Python 3.11+ with cryptography 44+ is required only on the build machine."
}

$workspaceRoot = [IO.Path]::GetFullPath($projectRoot).TrimEnd('\')
$releaseRoot = [IO.Path]::GetFullPath((Join-Path $projectRoot "release")).TrimEnd('\')
$canonical = Join-Path $releaseRoot "Granger Browser"
$staging = Join-Path $releaseRoot ".local-staging"
$previous = Join-Path $releaseRoot ".local-previous"
foreach ($path in @($releaseRoot, $canonical, $staging, $previous)) {
    if (-not $path.StartsWith($workspaceRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Local release path escaped the project workspace: $path"
    }
}
New-Item -ItemType Directory -Path $releaseRoot -Force | Out-Null

function Get-PackageProcesses {
    param([Parameter(Mandatory)][string]$PackageDirectory)

    $prefix = [IO.Path]::GetFullPath($PackageDirectory).TrimEnd('\') + '\'
    return @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_.ExecutablePath) -and
        $_.ExecutablePath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
    })
}

function Remove-TemporaryDirectory {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return }
    if (-not ($Path.Equals($staging, [StringComparison]::OrdinalIgnoreCase) -or
              $Path.Equals($previous, [StringComparison]::OrdinalIgnoreCase))) {
        throw "Refusing to remove a non-temporary local release path: $Path"
    }
    $running = @(Get-PackageProcesses -PackageDirectory $Path)
    if ($running.Count -ne 0) {
        throw "A process is still running from temporary local release: $($running.ProcessId -join ', ')"
    }
    Remove-Item -LiteralPath $Path -Recurse -Force
}

function Assert-NoGeneratedPythonBytecode {
    param([Parameter(Mandatory)][string]$PackageDirectory)

    $runtimeRoot = Join-Path $PackageDirectory "runtime/python"
    if (-not (Test-Path -LiteralPath $runtimeRoot -PathType Container)) { return }
    $bytecode = @(Get-ChildItem -LiteralPath $runtimeRoot -Recurse -File -Filter "*.pyc")
    $cacheDirectories = @(Get-ChildItem -LiteralPath $runtimeRoot -Recurse -Directory -Filter "__pycache__")
    if ($bytecode.Count -ne 0 -or $cacheDirectories.Count -ne 0) {
        throw "App-local Granger Network runtime generated unmanifested Python bytecode."
    }
}

function Move-DirectoryAtomically {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination
    )

    if (-not (Test-Path -LiteralPath $Source -PathType Container)) {
        throw "Local release directory was not found: $Source"
    }
    if (Test-Path -LiteralPath $Destination) {
        throw "Local release destination already exists: $Destination"
    }
    [IO.Directory]::Move($Source, $Destination)
}

function Invoke-IsolatedBrowser {
    param(
        [Parameter(Mandatory)][string]$Executable,
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$RunRoot,
        [int]$TimeoutSeconds = 240
    )

    New-Item -ItemType Directory -Path $RunRoot -Force | Out-Null
    $working = Join-Path $RunRoot "working"
    $data = Join-Path $RunRoot "data"
    $settings = Join-Path $RunRoot "settings"
    $downloads = Join-Path $RunRoot "downloads"
    New-Item -ItemType Directory -Path $working,$data,$settings,$downloads -Force | Out-Null
    $startInfo = New-Object Diagnostics.ProcessStartInfo
    $startInfo.FileName = $Executable
    $startInfo.WorkingDirectory = $working
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.EnvironmentVariables["PATH"] = "$(Join-Path $env:SystemRoot 'System32');$env:SystemRoot"
    $startInfo.EnvironmentVariables["GRANGER_DATA_ROOT"] = $data
    $startInfo.EnvironmentVariables["GRANGER_SETTINGS_ROOT"] = $settings
    $startInfo.EnvironmentVariables["GRANGER_DOWNLOAD_ROOT"] = $downloads
    foreach ($name in @(
        "PYTHONHOME", "PYTHONPATH", "PYTHONUSERBASE", "QTDIR", "CMAKE_PREFIX_PATH",
        "QT_PLUGIN_PATH", "QT_QPA_PLATFORM_PLUGIN_PATH", "QTWEBENGINEPROCESS_PATH",
        "QTWEBENGINE_RESOURCES_PATH", "QTWEBENGINE_LOCALES_PATH", "VSINSTALLDIR",
        "VCINSTALLDIR", "VCToolsInstallDir", "VCToolsRedistDir", "WindowsSdkDir"
    )) {
        $startInfo.EnvironmentVariables.Remove($name)
    }
    $startInfo.Arguments = (@($Arguments) | ForEach-Object {
        '"' + $_.Replace('"', '\"') + '"'
    }) -join ' '
    $process = [Diagnostics.Process]::Start($startInfo)
    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
        & taskkill.exe /PID $process.Id /T /F | Out-Null
        throw "Canonical local browser smoke timed out: $($Arguments -join ' ')"
    }
    if ($process.ExitCode -ne 0) {
        throw "Canonical local browser smoke failed with exit code $($process.ExitCode): $($Arguments -join ' ')"
    }
}

function Invoke-GrangerNetworkAcceptance {
    param(
        [Parameter(Mandatory)][string]$Browser,
        [Parameter(Mandatory)][string]$OutputPath
    )

    $oldPythonPath = $env:PYTHONPATH
    try {
        $env:PYTHONPATH = Join-Path $projectRoot "GrangerNetwork/src"
        & $PythonExecutable (Join-Path $projectRoot "GrangerNetwork/tests/browser_acceptance_harness.py") `
            --browser $Browser --output $OutputPath --expect-packaged-runtime
        if ($LASTEXITCODE -ne 0) { throw "Packaged Granger Network browser acceptance failed." }
    } finally {
        $env:PYTHONPATH = $oldPythonPath
    }
    $result = Get-Content -LiteralPath $OutputPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not $result.ok -or -not $result.aliasNavigation -or -not $result.canonicalNavigation -or
        [int]$result.dnsRequests -ne 0 -or [int]$result.harness.escapeProbeConnections -ne 0 -or
        [int]$result.harness.orphanProcesses -ne 0 -or
        -not [bool]$result.harness.packagedRuntimeConfirmed) {
        throw "Packaged Granger Network acceptance did not satisfy fail-closed invariants."
    }
    return $result
}

function Invoke-SourceIndependentDemo {
    param(
        [Parameter(Mandatory)][string]$Browser,
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)][string]$RunRoot
    )

    $sourcePackage = Join-Path $projectRoot "GrangerNetwork/src/granger_network"
    $unavailablePackage = Join-Path $projectRoot "GrangerNetwork/src/.granger_network-source-unavailable"
    if (-not (Test-Path -LiteralPath $sourcePackage -PathType Container) -or
        (Test-Path -LiteralPath $unavailablePackage)) {
        throw "Granger Network source-independence precondition failed."
    }
    $moved = $false
    try {
        [IO.Directory]::Move($sourcePackage, $unavailablePackage)
        $moved = $true
        Invoke-IsolatedBrowser -Executable $Browser -Arguments @(
            "--smoke-granger-network-local-demo",
            "--smoke-output=$OutputPath"
        ) -RunRoot $RunRoot
    } finally {
        if ($moved -and (Test-Path -LiteralPath $unavailablePackage -PathType Container)) {
            [IO.Directory]::Move($unavailablePackage, $sourcePackage)
        }
    }
    $result = Get-Content -LiteralPath $OutputPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not $result.ok -or -not $result.aliasNavigation -or
        -not $result.canonicalNavigation -or -not $result.appLocalRuntime -or
        [int]$result.dnsRequests -ne 0) {
        throw "Packaged Granger Network depends on the source tree."
    }
    return $result
}

$trackedStatus = @(git -C $projectRoot status --porcelain --untracked-files=no)
if ($LASTEXITCODE -ne 0 -or $trackedStatus.Count -ne 0) {
    throw "Commit tracked source changes before producing the canonical local release."
}
$sourceHead = (& git -C $projectRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $sourceHead -notmatch '^[0-9a-f]{40}$') {
    throw "Could not determine the source HEAD."
}
$expectedNetworkIdentity = & (Join-Path $PSScriptRoot "Get-GrangerNetworkRuntimeIdentity.ps1") -SourceDirectory (Join-Path $projectRoot "GrangerNetwork/src/granger_network")

if ((Test-Path -LiteralPath $canonical) -and (Test-Path -LiteralPath $previous)) {
    throw "Interrupted local release swap detected. Resolve $previous before rebuilding."
}
if ((Test-Path -LiteralPath $previous) -and -not (Test-Path -LiteralPath $canonical)) {
    Move-DirectoryAtomically -Source $previous -Destination $canonical
}
Remove-TemporaryDirectory -Path $staging

$resultRoot = Join-Path $projectRoot "output/local-release-acceptance"
if (Test-Path -LiteralPath $resultRoot) { Remove-Item -LiteralPath $resultRoot -Recurse -Force }
New-Item -ItemType Directory -Path $resultRoot -Force | Out-Null
$sourcePrivacyScan = & (Join-Path $PSScriptRoot "test-release-privacy.ps1") `
    -TrackedRoot $projectRoot -RequireMarkerFile `
    -Report (Join-Path $resultRoot "tracked-source-privacy.json")
if (-not $sourcePrivacyScan.ok) { throw "Tracked source privacy gate failed." }
$promoted = $false
try {
    & (Join-Path $PSScriptRoot "compile-release.ps1") -QtRoot $QtRoot `
        -BuildDirectory $BuildDirectory -Clean
    if ($LASTEXITCODE -ne 0) { throw "Release compilation failed." }

    & (Join-Path $PSScriptRoot "package-release.ps1") -QtRoot $QtRoot `
        -BuildDirectory $BuildDirectory -Destination "release/.local-staging" -SkipBuild
    if ($LASTEXITCODE -ne 0) { throw "Base local deployment failed." }

    $runtime = & (Join-Path $PSScriptRoot "package-local-granger-runtime.ps1") `
        -PackageDirectory "release/.local-staging" -PythonExecutable $PythonExecutable
    if (-not $runtime.OK -or $runtime.SourceHead -ne $sourceHead -or
        [string]$runtime.GrangerNetworkVersion -ne [string]$expectedNetworkIdentity.Version -or
        [string]$runtime.GrangerNetworkSourceSHA256 -ne [string]$expectedNetworkIdentity.SHA256 -or
        [int]$runtime.GrangerNetworkSourceFiles -ne [int]$expectedNetworkIdentity.FileCount) {
        throw "App-local Granger Network runtime packaging failed."
    }
    Assert-NoGeneratedPythonBytecode -PackageDirectory $staging

    $portability = & (Join-Path $PSScriptRoot "test-windows-portability.ps1") `
        -PackageDirectory "release/.local-staging"
    if (-not $portability.OK) { throw "Staged Windows portability validation failed." }

    $stagingNetworkOutput = Join-Path $resultRoot "staging-granger-network.json"
    $stagingNetwork = Invoke-GrangerNetworkAcceptance `
        -Browser (Join-Path $staging "GrangerBrowser.exe") -OutputPath $stagingNetworkOutput

    $stagingDemoOutput = Join-Path $resultRoot "staging-local-demo.json"
    Invoke-IsolatedBrowser -Executable (Join-Path $staging "GrangerBrowser.exe") `
        -Arguments @("--smoke-granger-network-local-demo", "--smoke-output=$stagingDemoOutput") `
        -RunRoot (Join-Path $resultRoot "staging-local-demo")
    $stagingDemo = Get-Content -LiteralPath $stagingDemoOutput -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not $stagingDemo.ok -or -not $stagingDemo.aliasNavigation -or
        -not $stagingDemo.canonicalNavigation -or [int]$stagingDemo.dnsRequests -ne 0) {
        throw "Staged double-click test.granger demo acceptance failed."
    }

    $sourceIndependentOutput = Join-Path $resultRoot "staging-source-independent.json"
    $sourceIndependentDemo = Invoke-SourceIndependentDemo -Browser (Join-Path $staging "GrangerBrowser.exe") -OutputPath $sourceIndependentOutput -RunRoot (Join-Path $resultRoot "staging-source-independent")

    & (Join-Path $PSScriptRoot "test-release.ps1") `
        -PackageDirectory "release/.local-staging" -AllowLocalGrangerRuntime
    if ($LASTEXITCODE -ne 0) { throw "Complete staged release acceptance failed." }
    Assert-NoGeneratedPythonBytecode -PackageDirectory $staging

    $privacyScan = & (Join-Path $PSScriptRoot "test-release-privacy.ps1") `
        -Root $staging -RequireMarkerFile `
        -Report (Join-Path $resultRoot "staging-release-privacy.json")
    if (-not $privacyScan.ok) { throw "Staged release privacy gate failed." }

    $runningCanonical = @(Get-PackageProcesses -PackageDirectory $canonical)
    if ($runningCanonical.Count -ne 0) {
        throw "Canonical local release is running: $($runningCanonical.ProcessId -join ', ')"
    }
    if (Test-Path -LiteralPath $canonical) {
        Move-DirectoryAtomically -Source $canonical -Destination $previous
    }
    try {
        Move-DirectoryAtomically -Source $staging -Destination $canonical
        $promoted = $true
    } catch {
        if ((Test-Path -LiteralPath $previous) -and -not (Test-Path -LiteralPath $canonical)) {
            Move-DirectoryAtomically -Source $previous -Destination $canonical
        }
        throw
    }

    $canonicalExecutable = Join-Path $canonical "GrangerBrowser.exe"
    $canonicalMetadata = Get-Content -LiteralPath (Join-Path $canonical "local-runtime-metadata.json") `
        -Raw -Encoding UTF8 | ConvertFrom-Json
    if ([string]$canonicalMetadata.SourceHead -ne $sourceHead -or
        [string]$canonicalMetadata.GrangerNetworkVersion -ne [string]$expectedNetworkIdentity.Version -or
        [string]$canonicalMetadata.GrangerNetworkSourceSHA256 -ne [string]$expectedNetworkIdentity.SHA256 -or
        [int]$canonicalMetadata.GrangerNetworkSourceFiles -ne [int]$expectedNetworkIdentity.FileCount) {
        throw "Promoted local release does not match source HEAD $sourceHead."
    }

    $canonicalPortability = & (Join-Path $PSScriptRoot "test-windows-portability.ps1") `
        -PackageDirectory "release/Granger Browser"
    if (-not $canonicalPortability.OK) { throw "Canonical Windows portability validation failed." }

    $profileOutput = Join-Path $resultRoot "canonical-profile.json"
    Invoke-IsolatedBrowser -Executable $canonicalExecutable `
        -Arguments @("--smoke-profile-state", "--smoke-output=$profileOutput") `
        -RunRoot (Join-Path $resultRoot "canonical-profile")
    $profile = Get-Content -LiteralPath $profileOutput -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not $profile.ok -or $profile.qtVersion -ne "6.11.2" -or
        $profile.qtWebEngineVersion -ne "6.11.2") {
        throw "Canonical Qt WebEngine profile smoke failed."
    }

    $canonicalNetworkOutput = Join-Path $resultRoot "canonical-granger-network.json"
    $canonicalNetwork = Invoke-GrangerNetworkAcceptance `
        -Browser $canonicalExecutable -OutputPath $canonicalNetworkOutput

    $canonicalDemoOutput = Join-Path $resultRoot "canonical-local-demo.json"
    Invoke-IsolatedBrowser -Executable $canonicalExecutable `
        -Arguments @("--smoke-granger-network-local-demo", "--smoke-output=$canonicalDemoOutput") `
        -RunRoot (Join-Path $resultRoot "canonical-local-demo")
    $canonicalDemo = Get-Content -LiteralPath $canonicalDemoOutput -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not $canonicalDemo.ok -or -not $canonicalDemo.aliasNavigation -or
        -not $canonicalDemo.canonicalNavigation -or [int]$canonicalDemo.dnsRequests -ne 0) {
        throw "Canonical double-click test.granger demo acceptance failed."
    }

    $bootstrapOutput = Join-Path $resultRoot "canonical-network-bootstrap.json"
    $bootstrapRelative = $bootstrapOutput.Substring($workspaceRoot.Length + 1)
    $bootstrap = & (Join-Path $PSScriptRoot "test-network-bootstrap-fail-closed.ps1") `
        -PackageDirectory "release/Granger Browser" -OutputPath $bootstrapRelative
    if (-not $bootstrap.ok -or [int]$bootstrap.directBackendConnections -ne 0) {
        throw "Canonical fail-closed network bootstrap validation failed."
    }

    $torOutput = Join-Path $resultRoot "canonical-managed-tor.json"
    Invoke-IsolatedBrowser -Executable $canonicalExecutable `
        -Arguments @("--smoke-managed-mode=direct", "--smoke-output=$torOutput") `
        -RunRoot (Join-Path $resultRoot "canonical-managed-tor") -TimeoutSeconds 420
    $tor = Get-Content -LiteralPath $torOutput -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not $tor.ok -or -not $tor.routeVerified -or [int]$tor.bootstrapProgress -ne 100) {
        throw "Canonical managed Tor smoke failed."
    }

    $i2pOutput = Join-Path $resultRoot "canonical-i2p.json"
    Invoke-IsolatedBrowser -Executable $canonicalExecutable `
        -Arguments @("--smoke-i2p-runtime", "--smoke-output=$i2pOutput", "--smoke-timeout-ms=600000") `
        -RunRoot (Join-Path $resultRoot "canonical-i2p") -TimeoutSeconds 1300
    $i2p = Get-Content -LiteralPath $i2pOutput -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not $i2p.ok -or -not $i2p.firstRouteVerified -or -not $i2p.secondRouteVerified -or
        -not $i2p.stopped -or [string]$i2p.clearnetPolicy -ne "blocked" -or
        [bool]$i2p.outproxyConfigured) {
        throw "Canonical bundled I2P smoke failed."
    }
    Assert-NoGeneratedPythonBytecode -PackageDirectory $canonical

    Start-Sleep -Milliseconds 500
    $orphanProcesses = @(Get-PackageProcesses -PackageDirectory $canonical)
    if ($orphanProcesses.Count -ne 0) {
        throw "Canonical local release left orphan processes: $($orphanProcesses.ProcessId -join ', ')"
    }

    $promoted = $false
    if (Test-Path -LiteralPath $previous) { Remove-TemporaryDirectory -Path $previous }
    [ordered]@{
        OK = $true
        CanonicalLocalRelease = $canonical
        Executable = $canonicalExecutable
        SourceHead = $sourceHead
        LocalReleaseHead = [string]$canonicalMetadata.SourceHead
        ExecutableSHA256 = (Get-FileHash -LiteralPath $canonicalExecutable -Algorithm SHA256).Hash
        GrangerNetworkIncluded = $true
        GrangerNetworkRuntime = $runtime
        GrangerNetworkVersion = [string]$canonicalMetadata.GrangerNetworkVersion
        GrangerNetworkSourceSHA256 = [string]$canonicalMetadata.GrangerNetworkSourceSHA256
        GrangerNetworkSourceFiles = [int]$canonicalMetadata.GrangerNetworkSourceFiles
        WindowsPortability = $canonicalPortability
        BrowserStartup = [bool]$profile.ok
        QtWebEngine = [bool]$profile.ok
        Tor = [bool]$tor.ok
        I2P = [bool]$i2p.ok
        TestGranger = [bool]$canonicalDemo.aliasNavigation
        CanonicalGranger = [bool]$canonicalDemo.canonicalNavigation
        SourceIndependentStart = [bool]$sourceIndependentDemo.ok
        GrangerDnsRequests = [int]$canonicalDemo.dnsRequests
        DirectFallbackConnections = [int]$bootstrap.directBackendConnections
        OrphanProcesses = 0
        NormalUser = -not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)
        PublicReleaseChanged = $false
        Results = $resultRoot
    } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $releaseRoot "local-build-report.json") -Encoding UTF8
} catch {
    if ($promoted) {
        $runningPromoted = @(Get-PackageProcesses -PackageDirectory $canonical)
        foreach ($process in $runningPromoted) {
            Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
        }
        if ($runningPromoted.Count -ne 0) { Start-Sleep -Milliseconds 500 }
        if (@(Get-PackageProcesses -PackageDirectory $canonical).Count -ne 0) {
            throw "Failed local release left processes running and could not be rolled back."
        }
        Remove-Item -LiteralPath $canonical -Recurse -Force
        if (Test-Path -LiteralPath $previous) {
            Move-DirectoryAtomically -Source $previous -Destination $canonical
        }
    }
    Remove-TemporaryDirectory -Path $staging
    throw
}

Write-Host "Canonical local release ready: $canonical"
