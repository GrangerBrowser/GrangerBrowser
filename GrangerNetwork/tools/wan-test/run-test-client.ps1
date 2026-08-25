[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$StateDir,
    [Parameter(Mandatory)][string]$Bootstrap,
    [Parameter(Mandatory)][string]$AuthorityPin,
    [string]$Python = "python",
    [string]$Message = "GRANGER_PHYSICAL_WAN_MESSAGE_123",
    [string]$Report = "",
    [ValidateRange(1, 30)][int]$TimeoutSeconds = 8,
    [ValidateRange(1, 8)][int]$RouteAttempts = 8,
    [ValidateRange(2, 8)][int]$ReplicationFactor = 3,
    [ValidateRange(2, 8)][int]$MinimumReplicas = 2
)

$ErrorActionPreference = "Stop"
$networkRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "../.."))
$state = [IO.Path]::GetFullPath($StateDir)
New-Item -ItemType Directory -Path $state -Force | Out-Null
if (-not $Report) { $Report = Join-Path $state "client-report.json" }
$oldPythonPath = $env:PYTHONPATH
try {
    $env:PYTHONPATH = Join-Path $networkRoot "src"
    & $Python -m granger_network.wan_client demo $Name --state-dir $state `
        --bootstrap ([IO.Path]::GetFullPath($Bootstrap)) `
        --authority-pin ([IO.Path]::GetFullPath($AuthorityPin)) `
        --message $Message --report ([IO.Path]::GetFullPath($Report)) `
        --timeout $TimeoutSeconds --route-attempts $RouteAttempts `
        --replication-factor $ReplicationFactor --minimum-replicas $MinimumReplicas
    if ($LASTEXITCODE -ne 0) { throw "WAN test client failed closed with exit code $LASTEXITCODE." }
    Get-Content -LiteralPath ([IO.Path]::GetFullPath($Report)) -Raw
} finally {
    $env:PYTHONPATH = $oldPythonPath
}
