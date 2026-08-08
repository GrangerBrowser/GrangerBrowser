[CmdletBinding()]
param(
    [string]$QtRoot = $env:QTDIR,
    [string]$BuildDirectory = "build/desktop",
    [string]$Generator = "Visual Studio 17 2022",
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot

if ([string]::IsNullOrWhiteSpace($QtRoot)) { $QtRoot = $env:CMAKE_PREFIX_PATH }
if ([string]::IsNullOrWhiteSpace($QtRoot) -or -not (Test-Path -LiteralPath $QtRoot)) {
    throw "QtRoot was not found. Pass -QtRoot or set QTDIR/CMAKE_PREFIX_PATH."
}

$cmake = (Get-Command cmake.exe -ErrorAction SilentlyContinue).Source
if ([string]::IsNullOrWhiteSpace($cmake)) {
    $bundledCMake = "C:/Program Files/Microsoft Visual Studio/2022/Community/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe"
    if (Test-Path -LiteralPath $bundledCMake) { $cmake = $bundledCMake }
    else { throw "cmake.exe was not found." }
}

$resolvedProject = [IO.Path]::GetFullPath($projectRoot).TrimEnd('\')
$buildPath = [IO.Path]::GetFullPath((Join-Path $projectRoot $BuildDirectory))
if (-not $buildPath.StartsWith($resolvedProject + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw "BuildDirectory must remain inside the project workspace."
}
if ($Clean -and (Test-Path -LiteralPath $buildPath)) {
    Remove-Item -LiteralPath $buildPath -Recurse -Force
}

& $cmake -S $projectRoot -B $buildPath -G $Generator -A x64 "-DCMAKE_PREFIX_PATH=$QtRoot"
if ($LASTEXITCODE -ne 0) { throw "CMake configure failed." }
& $cmake --build $buildPath --config Release --parallel
if ($LASTEXITCODE -ne 0) { throw "Release build failed." }

$executable = Join-Path $buildPath "Release/GrangerBrowser.exe"
if (-not (Test-Path -LiteralPath $executable)) {
    throw "Release executable was not produced: $executable"
}
Write-Host "Built $executable"
