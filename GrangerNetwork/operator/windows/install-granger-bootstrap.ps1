[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$BrowserExe,
    [Parameter(Mandatory)][string]$PublicBundle,
    [Parameter(Mandatory)][string]$ExpectedConfigAuthorityPin,
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA "GrangerBrowser\granger-network\wan-operator"),
    [string]$RollbackState = (Join-Path $env:LOCALAPPDATA "GrangerBrowser\granger-network\wan-operator-rollback.json")
)

$ErrorActionPreference = "Stop"
$browser = [IO.Path]::GetFullPath($BrowserExe)
$bundleRoot = [IO.Path]::GetFullPath($PublicBundle)
$config = Join-Path $bundleRoot "browser-wan.json"
$trust = Join-Path $bundleRoot "config-authority.pin"
foreach ($path in @($browser, $config, $trust,
        (Join-Path $bundleRoot "bootstrap-set.json"),
        (Join-Path $bundleRoot "bootstrap-authority.pin"))) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required signed Granger WAN file is missing: $path"
    }
}
$actualPin = (Get-Content -LiteralPath $trust -Raw).Trim()
if ($actualPin -cne $ExpectedConfigAuthorityPin.Trim()) {
    throw "Config authority pin does not match the out-of-band expected value."
}
$arguments = @(
    "--granger-network-wan-bundle=$config",
    "--granger-network-wan-trust-anchor=$trust",
    "--granger-network-wan-install-root=$([IO.Path]::GetFullPath($InstallRoot))",
    "--granger-network-wan-rollback-state=$([IO.Path]::GetFullPath($RollbackState))"
)
Start-Process -FilePath $browser -ArgumentList $arguments
