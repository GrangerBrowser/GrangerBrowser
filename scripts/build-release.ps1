[CmdletBinding()]
param(
    [string]$QtRoot = $env:QTDIR,
    [string]$BuildDirectory = 'build/desktop',
    [string]$PythonExecutable = '',
    [string]$WanBundleDirectory = $env:GRANGER_NETWORK_RELEASE_BUNDLE
)

$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent $PSScriptRoot
$sourceHead = (& git -C $projectRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $sourceHead -notmatch '^[0-9a-f]{40}$') {
    throw 'Unable to resolve the release source revision.'
}
$sourceChanges = @(& git -C $projectRoot status --porcelain=v1 --untracked-files=all)
if ($LASTEXITCODE -ne 0) {
    throw 'Unable to inspect the release source tree.'
}
if ($sourceChanges.Count -ne 0) {
    throw 'Public release builds require a clean committed source tree.'
}

# Both entrypoints build the same browser, including its mandatory network runtime.
& (Join-Path $PSScriptRoot 'build-local-release.ps1') @PSBoundParameters
