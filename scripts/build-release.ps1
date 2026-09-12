[CmdletBinding()]
param(
    [string]$QtRoot = $env:QTDIR,
    [string]$BuildDirectory = 'build/desktop',
    [string]$PythonExecutable = '',
    [string]$WanBundleDirectory = $env:GRANGER_NETWORK_RELEASE_BUNDLE
)

$ErrorActionPreference = 'Stop'
# Both entrypoints build the same browser, including its mandatory network runtime.
& (Join-Path $PSScriptRoot 'build-local-release.ps1') @PSBoundParameters
