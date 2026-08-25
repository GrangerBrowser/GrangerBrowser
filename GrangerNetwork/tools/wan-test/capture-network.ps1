[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OutputBase,
    [ValidateRange(5, 3600)][int]$DurationSeconds = 180
)

$ErrorActionPreference = "Stop"
$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "PktMon capture requires an elevated PowerShell session."
}
$base = [IO.Path]::GetFullPath($OutputBase)
$parent = Split-Path -Parent $base
New-Item -ItemType Directory -Path $parent -Force | Out-Null
$etl = "$base.etl"
$pcap = "$base.pcapng"
$pktmon = Join-Path $env:SystemRoot "System32/PktMon.exe"
$started = $false
try {
    & $pktmon start --capture --comp nics --pkt-size 0 --file-name $etl `
        --file-size 1024 --log-mode circular
    if ($LASTEXITCODE -ne 0) { throw "PktMon failed to start; another capture may be active." }
    $started = $true
    Write-Host "Capturing all interfaces for $DurationSeconds seconds..."
    Start-Sleep -Seconds $DurationSeconds
} finally {
    if ($started) { & $pktmon stop | Out-Null }
}
& $pktmon etl2pcap $etl --out $pcap
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $pcap)) {
    throw "PktMon capture conversion failed."
}
$hash = Get-FileHash -LiteralPath $pcap -Algorithm SHA256
[pscustomobject]@{
    Capture = $pcap
    Sha256 = $hash.Hash
    Size = (Get-Item -LiteralPath $pcap).Length
} | Format-List
