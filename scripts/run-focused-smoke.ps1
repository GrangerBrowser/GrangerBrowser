[CmdletBinding()]
param(
    [string]$PackageDirectory = "release/Granger Browser",
    [Parameter(Mandatory)]
    [string[]]$SmokeArguments,
    [string]$RunDirectory = "output/focused-smoke",
    [int]$TimeoutSeconds = 240
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$packageRoot = [IO.Path]::GetFullPath((Join-Path $projectRoot $PackageDirectory))
$runRoot = [IO.Path]::GetFullPath((Join-Path $projectRoot $RunDirectory))
$workspaceRoot = [IO.Path]::GetFullPath($projectRoot).TrimEnd('\')
if (-not $runRoot.StartsWith($workspaceRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw "RunDirectory must remain inside the project workspace."
}

$executable = Join-Path $packageRoot "GrangerBrowser.exe"
if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
    throw "Packaged executable was not found: $executable"
}

$dataRoot = Join-Path $runRoot "data"
$settingsRoot = Join-Path $runRoot "settings"
$downloadsRoot = Join-Path $runRoot "downloads"
$workingRoot = Join-Path $runRoot "working"
New-Item -ItemType Directory -Path $dataRoot,$settingsRoot,$downloadsRoot,$workingRoot -Force |
    Out-Null

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $executable
$psi.WorkingDirectory = $workingRoot
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true
$psi.EnvironmentVariables["GRANGER_DATA_ROOT"] = $dataRoot
$psi.EnvironmentVariables["GRANGER_SETTINGS_ROOT"] = $settingsRoot
$psi.EnvironmentVariables["GRANGER_DOWNLOAD_ROOT"] = $downloadsRoot
$psi.EnvironmentVariables["PATH"] = "$(Join-Path $env:SystemRoot 'System32');$env:SystemRoot"
$quoted = foreach ($argument in $SmokeArguments) {
    '"' + $argument.Replace('"', '\"') + '"'
}
$psi.Arguments = $quoted -join ' '

$process = [Diagnostics.Process]::Start($psi)
if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
    & taskkill.exe /PID $process.Id /T /F | Out-Null
    throw "Granger Browser focused smoke timed out after $TimeoutSeconds seconds."
}
if ($process.ExitCode -ne 0) {
    throw "Granger Browser focused smoke failed with exit code $($process.ExitCode)."
}

[pscustomobject]@{
    OK = $true
    Executable = $executable
    ExitCode = $process.ExitCode
    DataRoot = $dataRoot
    SettingsRoot = $settingsRoot
    Arguments = $SmokeArguments
}
