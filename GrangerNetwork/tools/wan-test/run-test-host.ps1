[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$StateDir,
    [Parameter(Mandatory)][string]$Bootstrap,
    [Parameter(Mandatory)][string]$AuthorityPin,
    [string]$Python = "python",
    [string]$Title = "Granger physical WAN test",
    [string]$ReadyFile = "",
    [ValidateRange(1, 30)][int]$TimeoutSeconds = 8,
    [ValidateRange(2, 8)][int]$ReplicationFactor = 3,
    [ValidateRange(2, 8)][int]$MinimumReplicas = 2
)

$ErrorActionPreference = "Stop"
$networkRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "../.."))
$state = [IO.Path]::GetFullPath($StateDir)
New-Item -ItemType Directory -Path $state -Force | Out-Null
if (-not $ReadyFile) { $ReadyFile = Join-Path $state "host-ready.json" }
$fixtureReady = Join-Path $state "forum-ready.json"
$fixtureScript = Join-Path $networkRoot "tools/wan_forum_fixture.py"
$oldPythonPath = $env:PYTHONPATH
$fixture = $null
try {
    $env:PYTHONPATH = Join-Path $networkRoot "src"
    if (-not (Test-Path -LiteralPath (Join-Path $state "service-identity.json"))) {
        & $Python -m granger_network.wan_host init --state-dir $state --title $Title
        if ($LASTEXITCODE -ne 0) { throw "Test service identity initialization failed." }
    }
    $fixtureArguments = '"' + $fixtureScript + '" --ready-file "' + $fixtureReady + '"'
    $fixture = Start-Process -FilePath $Python -ArgumentList $fixtureArguments `
        -PassThru -WindowStyle Hidden
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    while (-not (Test-Path -LiteralPath $fixtureReady)) {
        if ($fixture.HasExited) { throw "Loopback forum fixture exited before readiness." }
        if ([DateTime]::UtcNow -ge $deadline) { throw "Loopback forum fixture timed out." }
        Start-Sleep -Milliseconds 100
    }
    $fixtureDocument = Get-Content -LiteralPath $fixtureReady -Raw | ConvertFrom-Json
    $upstream = "127.0.0.1:$([int]$fixtureDocument.port)"
    & $Python -m granger_network.wan_host serve --state-dir $state `
        --bootstrap ([IO.Path]::GetFullPath($Bootstrap)) `
        --authority-pin ([IO.Path]::GetFullPath($AuthorityPin)) `
        --upstream $upstream --ready-file ([IO.Path]::GetFullPath($ReadyFile)) `
        --timeout $TimeoutSeconds --introduction-points 2 `
        --minimum-introduction-points 2 --replication-factor $ReplicationFactor `
        --minimum-replicas $MinimumReplicas --startup-attempts 8
    if ($LASTEXITCODE -ne 0) { throw "WAN test host stopped with exit code $LASTEXITCODE." }
} finally {
    if ($fixture -and -not $fixture.HasExited) {
        Stop-Process -Id $fixture.Id -Force -ErrorAction SilentlyContinue
        $fixture.WaitForExit(5000) | Out-Null
    }
    $env:PYTHONPATH = $oldPythonPath
}
