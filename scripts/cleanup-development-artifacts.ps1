[CmdletBinding()]
param(
    [switch]$Apply,
    [switch]$IncludeBuild,
    [string]$Report = "output/cleanup-development-artifacts.json"
)

$ErrorActionPreference = "Stop"
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$outputRoot = [IO.Path]::GetFullPath((Join-Path $projectRoot "output"))
$buildRoot = [IO.Path]::GetFullPath((Join-Path $projectRoot "build"))
$reportPath = [IO.Path]::GetFullPath((Join-Path $projectRoot $Report))

$protectedOutputNames = @(
    "distribution",
    "granger-network",
    "i2p-runtime",
    "linux",
    "linux-vm",
    "third-party",
    "tor-expert",
    "tor-runtime"
)

$generatedPatterns = @(
    "^test-roots$",
    "^remote-",
    "^superseded-",
    "^local-v0",
    "^ci-.*-download$",
    "^(tar|expand)-repro-",
    "^windeployqt-",
    "^pv-",
    "^combined-release-.*(staging|verification)$",
    "^granger-network-(dev-package|product-test.*|regression)$",
    "^network-bootstrap-fixture",
    "^wan-(selector|final|signed-autoprovision)-\d{8}-\d{6}$",
    "^ui-privacy-geometry-",
    "^hosting-selector-ui-",
    "^rebrand-(smoke|migration-smoke)$",
    "acceptance",
    "smoke",
    "retest",
    "rerun",
    "simulation"
)

function Get-PathUsage([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    if (-not $item.PSIsContainer) {
        return [pscustomobject]@{ Bytes = [int64]$item.Length; Files = 1 }
    }
    $files = Get-ChildItem -LiteralPath $Path -File -Recurse -Force -ErrorAction SilentlyContinue
    $measure = $files | Measure-Object -Property Length -Sum
    return [pscustomobject]@{ Bytes = [int64]$measure.Sum; Files = [int]$measure.Count }
}

function Assert-SafeCandidate([string]$Path) {
    $resolved = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $outputPrefix = $outputRoot.TrimEnd('\') + '\'
    $insideOutput = $resolved.StartsWith($outputPrefix, [StringComparison]::OrdinalIgnoreCase)
    $isBuild = $resolved.Equals($buildRoot.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)
    $isOldArchive = $resolved.Equals(
        [IO.Path]::GetFullPath((Join-Path $projectRoot "Granger-Browser-Windows-x64.zip")),
        [StringComparison]::OrdinalIgnoreCase)
    if (-not ($insideOutput -or $isBuild -or $isOldArchive)) {
        throw "Cleanup candidate escaped the generated roots: $resolved"
    }
    if ($resolved.Equals($outputRoot.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove the complete output root"
    }
    if ($resolved.StartsWith(
            [IO.Path]::GetFullPath((Join-Path $projectRoot "release")).TrimEnd('\') + '\',
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove the canonical release"
    }
    return $resolved
}

$candidates = @()
if (Test-Path -LiteralPath $outputRoot) {
    foreach ($item in Get-ChildItem -LiteralPath $outputRoot -Force) {
        if ($protectedOutputNames -contains $item.Name) { continue }
        $generated = $false
        foreach ($pattern in $generatedPatterns) {
            if ($item.Name -match $pattern) {
                $generated = $true
                break
            }
        }
        if (-not $generated) { continue }
        $usage = Get-PathUsage $item.FullName
        $candidates += [pscustomobject]@{
            Category = "TEST_OR_STAGING_OUTPUT"
            Path = Assert-SafeCandidate $item.FullName
            Bytes = $usage.Bytes
            Files = $usage.Files
        }
    }
}

if ($IncludeBuild -and (Test-Path -LiteralPath $buildRoot)) {
    $usage = Get-PathUsage $buildRoot
    $candidates += [pscustomobject]@{
        Category = "BUILD"
        Path = Assert-SafeCandidate $buildRoot
        Bytes = $usage.Bytes
        Files = $usage.Files
    }
}

$oldArchive = Join-Path $projectRoot "Granger-Browser-Windows-x64.zip"
if (Test-Path -LiteralPath $oldArchive) {
    $usage = Get-PathUsage $oldArchive
    $candidates += [pscustomobject]@{
        Category = "OLD_RELEASE"
        Path = Assert-SafeCandidate $oldArchive
        Bytes = $usage.Bytes
        Files = $usage.Files
    }
}

$candidates = @($candidates | Sort-Object Path -Unique)
$removed = @()
if ($Apply) {
    foreach ($candidate in $candidates) {
        $safePath = Assert-SafeCandidate $candidate.Path
        if (Test-Path -LiteralPath $safePath) {
            Remove-Item -LiteralPath $safePath -Recurse -Force
            $removed += $safePath
        }
    }
}

$reportObject = [ordered]@{
    Version = 1
    Mode = if ($Apply) { "apply" } else { "dry-run" }
    ProjectRoot = $projectRoot
    CandidateBytes = [int64](($candidates | Measure-Object -Property Bytes -Sum).Sum)
    CandidateFiles = [int](($candidates | Measure-Object -Property Files -Sum).Sum)
    CandidateCount = $candidates.Count
    ProtectedOutputNames = $protectedOutputNames
    Candidates = $candidates
    Removed = $removed
    SourceRemoved = $false
    UserIdentitiesRemoved = $false
    CanonicalReleaseRemoved = $false
}

$reportDirectory = Split-Path -Parent $reportPath
New-Item -ItemType Directory -Force -Path $reportDirectory | Out-Null
$reportObject | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $reportPath -Encoding utf8
$reportObject | ConvertTo-Json -Depth 6
