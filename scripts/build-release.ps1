[CmdletBinding()]
param(
    [string]$QtRoot = $env:QTDIR,
    [string]$BuildDirectory = "build/desktop"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($QtRoot)) { $QtRoot = $env:CMAKE_PREFIX_PATH }
if ([string]::IsNullOrWhiteSpace($QtRoot) -or -not (Test-Path -LiteralPath $QtRoot)) {
    throw "QtRoot was not found. Pass -QtRoot or set QTDIR/CMAKE_PREFIX_PATH."
}

$releaseRoot = [IO.Path]::GetFullPath((Join-Path $projectRoot "release"))
$canonical = Join-Path $releaseRoot "Granger Browser"
$staging = Join-Path $releaseRoot ".staging"
$uiStaging = Join-Path $releaseRoot ".ui-stage"
$previous = Join-Path $releaseRoot ".previous"
$resolvedProject = [IO.Path]::GetFullPath($projectRoot).TrimEnd('\')
foreach ($path in @($releaseRoot, $canonical, $staging, $uiStaging, $previous)) {
    if (-not $path.StartsWith($resolvedProject + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Release path escaped the project workspace: $path"
    }
}
New-Item -ItemType Directory -Path $releaseRoot -Force | Out-Null

function Move-DirectoryAtomically {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination
    )

    if (-not (Test-Path -LiteralPath $Source -PathType Container)) {
        throw "Release directory not found: $Source"
    }
    if (Test-Path -LiteralPath $Destination) {
        throw "Release destination already exists: $Destination"
    }
    [IO.Directory]::Move($Source, $Destination)
}

function Get-PackageProcesses {
    param([Parameter(Mandatory)][string]$PackageDirectory)

    $prefix = [IO.Path]::GetFullPath($PackageDirectory).TrimEnd('\') + '\'
    return @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_.ExecutablePath) -and
        $_.ExecutablePath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
    })
}

function Remove-StagingDirectory {
    param([Parameter(Mandatory)][string]$PackageDirectory)

    if (-not (Test-Path -LiteralPath $PackageDirectory)) { return }
    $activeProcesses = @(Get-PackageProcesses -PackageDirectory $PackageDirectory)
    if ($activeProcesses.Count -ne 0) {
        $details = $activeProcesses | ForEach-Object { "$($_.Name) (PID $($_.ProcessId))" }
        throw "Temporary release is still running from $PackageDirectory`: $($details -join ', ')"
    }
    Remove-Item -LiteralPath $PackageDirectory -Recurse -Force
}

if ((Test-Path -LiteralPath $canonical) -and (Test-Path -LiteralPath $previous)) {
    throw "Interrupted release swap detected. Restore or remove $previous before rebuilding."
}
if ((Test-Path -LiteralPath $previous) -and -not (Test-Path -LiteralPath $canonical)) {
    Move-DirectoryAtomically -Source $previous -Destination $canonical
}
Remove-StagingDirectory -PackageDirectory $staging
Remove-StagingDirectory -PackageDirectory $uiStaging

$sourcePrivacyScan = & (Join-Path $PSScriptRoot "test-release-privacy.ps1") `
    -TrackedRoot $projectRoot -RequireMarkerFile `
    -Report (Join-Path $projectRoot "output/release-privacy-source.json")
if (-not $sourcePrivacyScan.ok) { throw "Tracked source privacy gate failed." }

try {
    & (Join-Path $PSScriptRoot "compile-release.ps1") -QtRoot $QtRoot -BuildDirectory $BuildDirectory -Clean
    if ($LASTEXITCODE -ne 0) { throw "Compile script failed." }

    & (Join-Path $PSScriptRoot "package-release.ps1") -QtRoot $QtRoot -BuildDirectory $BuildDirectory `
        -Destination "release/.staging" -SkipBuild
    if ($LASTEXITCODE -ne 0) { throw "Package script failed." }

    $portability = & (Join-Path $PSScriptRoot "test-windows-portability.ps1") `
        -PackageDirectory "release/.staging"
    if (-not $portability.OK) { throw "Windows portability validation failed." }

    $forbiddenFullPampDirectories = @(Get-ChildItem -LiteralPath $staging -Recurse -Directory | Where-Object {
        $_.Name.ToLowerInvariant() -in @('pentest', 'pamp')
    })
    if ($forbiddenFullPampDirectories.Count -ne 0) {
        throw "Full Pamp directories were packaged: $($forbiddenFullPampDirectories.FullName -join ', ')"
    }
    $pythonArtifacts = @(Get-ChildItem -LiteralPath $staging -Recurse -File | Where-Object {
        $_.Extension.ToLowerInvariant() -in @('.py', '.pyc', '.pyz', '.pyd', '.whl') -or
        $_.Name.ToLowerInvariant() -in @('python.exe', 'pythonw.exe') -or
        $_.Name -like 'python*.dll'
    })
    if ($pythonArtifacts.Count -ne 0) {
        throw "Python runtime artifacts were packaged: $($pythonArtifacts.FullName -join ', ')"
    }
    if ((Test-Path -LiteralPath (Join-Path $projectRoot "main.py")) -or
        (Test-Path -LiteralPath (Join-Path $projectRoot "requirements.txt")) -or
        @(Get-ChildItem -LiteralPath (Join-Path $projectRoot "granger") -Recurse -File |
            Where-Object { $_.Extension -in @('.py', '.pyc') }).Count -ne 0) {
        throw "The obsolete Python CLI/runtime tree is still present."
    }

    & (Join-Path $PSScriptRoot "test-release.ps1") -PackageDirectory "release/.staging"
    if ($LASTEXITCODE -ne 0) { throw "Release acceptance failed." }

    $privacyScan = & (Join-Path $PSScriptRoot "test-release-privacy.ps1") `
        -Root $staging -RequireMarkerFile `
        -Report (Join-Path $projectRoot "output/release-privacy-windows.json")
    if (-not $privacyScan.ok) { throw "Release privacy gate failed." }

    $activeReleaseProcesses = @(Get-PackageProcesses -PackageDirectory $canonical)
    if ($activeReleaseProcesses.Count -ne 0) {
        $details = $activeReleaseProcesses | ForEach-Object { "$($_.Name) (PID $($_.ProcessId))" }
        throw "Canonical release is still running: $($details -join ', ')"
    }

    if (Test-Path -LiteralPath $canonical) {
        Move-DirectoryAtomically -Source $canonical -Destination $previous
    }
    try {
        Move-DirectoryAtomically -Source $staging -Destination $canonical
    } catch {
        if ((Test-Path -LiteralPath $previous) -and -not (Test-Path -LiteralPath $canonical)) {
            Move-DirectoryAtomically -Source $previous -Destination $canonical
        }
        throw
    }
    if (Test-Path -LiteralPath $previous) { Remove-Item -LiteralPath $previous -Recurse -Force }

    $portableArchive = & (Join-Path $PSScriptRoot "create-portable-archive.ps1") `
        -PackageDirectory "release/Granger Browser"
    if (-not $portableArchive.OK) { throw "Portable archive creation failed." }

    $unexpected = @(Get-ChildItem -LiteralPath $releaseRoot -Directory -Force | Where-Object {
        $_.Name -ne 'Granger Browser'
    })
    if ($unexpected.Count -ne 0 -or -not (Test-Path -LiteralPath (Join-Path $canonical "GrangerBrowser.exe"))) {
        throw "Canonical release validation failed. Unexpected directories: $($unexpected.Name -join ', ')"
    }

    [pscustomobject]@{
        OK = $true
        CanonicalRelease = $canonical
        Executable = Join-Path $canonical "GrangerBrowser.exe"
        ExecutableSHA256 = (Get-FileHash -LiteralPath (Join-Path $canonical "GrangerBrowser.exe") -Algorithm SHA256).Hash
        PortableArchive = $portableArchive.Archive
        PortableArchiveSize = $portableArchive.ArchiveSize
        PortableArchiveSHA256 = $portableArchive.ArchiveSHA256
        WindowsPortability = $portability
        ReleasePrivacyScan = Join-Path $projectRoot "output/release-privacy-windows.json"
        Acceptance = Join-Path $projectRoot "output/release acceptance/path with spaces/release-acceptance.json"
        PythonRuntimeArtifacts = 0
        TemporaryStagingRemoved = (-not (Test-Path -LiteralPath $staging) -and
            -not (Test-Path -LiteralPath $uiStaging))
        ReleaseDirectories = @((Get-ChildItem -LiteralPath $releaseRoot -Directory -Force).Name)
    } | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $releaseRoot "build-report.json") -Encoding UTF8
} catch {
    Remove-StagingDirectory -PackageDirectory $staging
    Remove-StagingDirectory -PackageDirectory $uiStaging
    throw
}
Write-Host "Canonical release ready: $canonical"
