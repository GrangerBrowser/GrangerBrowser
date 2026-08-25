[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$AuthorityState,
    [Parameter(Mandatory)][string[]]$Descriptor,
    [Parameter(Mandatory)][string]$Bundle,
    [Parameter(Mandatory)][string]$AuthorityPin,
    [ValidateRange(60, 86400)][int]$Lifetime = 21600,
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
$arguments = @((Join-Path $PSScriptRoot "provision_bootstrap.py"),
    "--authority-state", [IO.Path]::GetFullPath($AuthorityState),
    "--bundle", [IO.Path]::GetFullPath($Bundle),
    "--authority-pin", [IO.Path]::GetFullPath($AuthorityPin),
    "--lifetime", $Lifetime)
foreach ($path in $Descriptor) {
    $arguments += @("--descriptor", [IO.Path]::GetFullPath($path))
}
& $Python @arguments
if ($LASTEXITCODE -ne 0) { throw "Bootstrap provisioning failed." }
