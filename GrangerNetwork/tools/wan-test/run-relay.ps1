[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$StateDir,
    [Parameter(Mandatory)][string]$ListenHost,
    [Parameter(Mandatory)][ValidateRange(1, 65535)][int]$ListenPort,
    [Parameter(Mandatory)][ValidateSet("entry", "middle", "service-relay", "introduction", "rendezvous", "discovery")][string[]]$Capability,
    [string[]]$PeerDescriptor = @(),
    [string]$Python = "python",
    [ValidateRange(60, 86400)][int]$DescriptorLifetime = 86400,
    [ValidateRange(2, 512)][int]$MaxConnections = 128,
    [ValidateRange(1, 1024)][int]$MaxCircuits = 64,
    [string]$ReadyFile = "",
    [string]$CaptureFile = "",
    [string]$DiagnosticsFile = "",
    [switch]$InitOnly
)

$ErrorActionPreference = "Stop"
$networkRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "../.."))
$state = [IO.Path]::GetFullPath($StateDir)
$oldPythonPath = $env:PYTHONPATH
try {
    $env:PYTHONPATH = Join-Path $networkRoot "src"
    if (-not (Test-Path -LiteralPath (Join-Path $state "node-descriptor.json"))) {
        $arguments = @("-m", "granger_network.node", "init", "--state-dir", $state,
            "--listen-host", $ListenHost, "--listen-port", $ListenPort,
            "--descriptor-lifetime", $DescriptorLifetime,
            "--max-connections", $MaxConnections, "--max-circuits", $MaxCircuits)
        foreach ($role in $Capability) { $arguments += @("--capability", $role) }
        & $Python @arguments
        if ($LASTEXITCODE -ne 0) { throw "Relay initialization failed." }
    }
    Write-Host "Descriptor: $(Join-Path $state 'node-descriptor.json')"
    if ($InitOnly) { return }
    $arguments = @("-m", "granger_network.node", "run", "--state-dir", $state)
    foreach ($path in $PeerDescriptor) {
        $arguments += @("--peer-descriptor", [IO.Path]::GetFullPath($path))
    }
    if ($ReadyFile) { $arguments += @("--ready-file", [IO.Path]::GetFullPath($ReadyFile)) }
    if ($CaptureFile) { $arguments += @("--capture", [IO.Path]::GetFullPath($CaptureFile)) }
    if ($DiagnosticsFile) {
        $arguments += @("--diagnostics", [IO.Path]::GetFullPath($DiagnosticsFile))
    }
    & $Python @arguments
    if ($LASTEXITCODE -ne 0) { throw "Relay stopped with exit code $LASTEXITCODE." }
} finally {
    $env:PYTHONPATH = $oldPythonPath
}
