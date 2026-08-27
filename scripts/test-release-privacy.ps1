[CmdletBinding()]
param(
    [string[]]$Root = @(),
    [string[]]$TrackedRoot = @(),
    [string]$MarkerFile = $env:GRANGER_PRIVATE_MARKER_FILE,
    [string]$Report,
    [switch]$RequireMarkerFile,
    [string]$PythonExecutable = "python"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($MarkerFile)) {
    $MarkerFile = Join-Path $projectRoot "output/private-markers.txt"
}
if ([string]::IsNullOrWhiteSpace($Report)) {
    $Report = Join-Path $projectRoot "output/release-privacy-scan.json"
}

$arguments = @(
    (Join-Path $PSScriptRoot "test-release-privacy.py"),
    "--marker-file", $MarkerFile,
    "--report", $Report
)
foreach ($scanRoot in $Root) {
    $arguments += @("--root", $scanRoot)
}
foreach ($trackedScanRoot in $TrackedRoot) {
    $arguments += @("--git-tracked-root", $trackedScanRoot)
}
if ($RequireMarkerFile) { $arguments += "--require-marker-file" }

& $PythonExecutable @arguments | Out-Host
if ($LASTEXITCODE -ne 0) {
    throw "Release privacy scan failed. See $Report"
}
Get-Content -LiteralPath $Report -Raw -Encoding UTF8 | ConvertFrom-Json
