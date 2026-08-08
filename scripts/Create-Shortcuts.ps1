[CmdletBinding()]
param([switch]$StartMenu)

$ErrorActionPreference = "Stop"
$applicationRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $applicationRoot "GrangerBrowser.exe"
if (-not (Test-Path -LiteralPath $target)) { throw "GrangerBrowser.exe was not found beside this script." }
$shell = New-Object -ComObject WScript.Shell
$desktop = [Environment]::GetFolderPath("Desktop")
$shortcut = $shell.CreateShortcut((Join-Path $desktop "Granger Browser.lnk"))
$shortcut.TargetPath = $target
$shortcut.WorkingDirectory = $applicationRoot
$shortcut.IconLocation = "$target,0"
$shortcut.Save()
if ($StartMenu) {
    $programs = [Environment]::GetFolderPath("Programs")
    $menuShortcut = $shell.CreateShortcut((Join-Path $programs "Granger Browser.lnk"))
    $menuShortcut.TargetPath = $target
    $menuShortcut.WorkingDirectory = $applicationRoot
    $menuShortcut.IconLocation = "$target,0"
    $menuShortcut.Save()
}
