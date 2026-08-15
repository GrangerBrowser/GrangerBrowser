[CmdletBinding()]
param(
    [string]$GifPath = "Banner_Installer/Emma.gif",
    [string]$PackageArchive,
    [string]$BuildDirectory = "build/installer",
    [string]$OutputDirectory = "output/distribution",
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$workspaceRoot = [IO.Path]::GetFullPath($projectRoot).TrimEnd('\')
$gif = [IO.Path]::GetFullPath((Join-Path $projectRoot $GifPath))
$buildRoot = [IO.Path]::GetFullPath((Join-Path $projectRoot $BuildDirectory))
$outputRoot = [IO.Path]::GetFullPath((Join-Path $projectRoot $OutputDirectory))
foreach ($path in @($gif, $buildRoot, $outputRoot)) {
    if (-not $path.StartsWith($workspaceRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Installer build paths must remain inside the project workspace: $path"
    }
}
if (-not (Test-Path -LiteralPath $gif -PathType Leaf)) { throw "Installer GIF not found: $gif" }
$gifBytes = [IO.File]::ReadAllBytes($gif)
if ($gifBytes.Length -lt 6 -or [Text.Encoding]::ASCII.GetString($gifBytes, 0, 6) -notin @('GIF87a', 'GIF89a')) {
    throw "Installer branding asset is not a valid GIF."
}

if ([string]::IsNullOrWhiteSpace($PackageArchive)) {
    $candidate = Get-ChildItem -LiteralPath (Join-Path $projectRoot 'output/distribution') `
        -Filter 'Granger-Browser-v*-windows-x64.zip' -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $candidate) { throw "Pass -PackageArchive for the canonical portable ZIP." }
    $PackageArchive = $candidate.FullName
}
$manifest = & (Join-Path $PSScriptRoot 'New-InstallerManifest.ps1') `
    -PackageArchive $PackageArchive -OutputDirectory $OutputDirectory
if (-not $manifest.OK) { throw "Installer manifest generation failed." }

$cmake = (Get-Command cmake.exe -ErrorAction SilentlyContinue).Source
if ([string]::IsNullOrWhiteSpace($cmake)) {
    $cmake = 'C:/Program Files/Microsoft Visual Studio/2022/Community/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe'
}
if (-not (Test-Path -LiteralPath $cmake -PathType Leaf)) { throw "cmake.exe was not found." }
if ($Clean -and (Test-Path -LiteralPath $buildRoot)) {
    Remove-Item -LiteralPath $buildRoot -Recurse -Force
}

& $cmake -S (Join-Path $projectRoot 'installer') -B $buildRoot `
    -G 'Visual Studio 17 2022' -A x64 `
    "-DEMMA_GIF_PATH=$($gif.Replace('\', '/'))" `
    "-DGRANGER_INSTALLER_VERSION=$($manifest.Version)"
if ($LASTEXITCODE -ne 0) { throw "Installer CMake configure failed." }
& $cmake --build $buildRoot --config Release --parallel
if ($LASTEXITCODE -ne 0) { throw "Installer build failed." }

$builtSetup = Join-Path $buildRoot 'Release/GrangerSetup.exe'
if (-not (Test-Path -LiteralPath $builtSetup -PathType Leaf)) {
    throw "Installer executable was not produced."
}
New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null
$setup = Join-Path $outputRoot 'GrangerSetup.exe'
Copy-Item -LiteralPath $builtSetup -Destination $setup -Force

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
$visualStudio = & $vswhere -latest -products * `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
$dumpbin = Get-ChildItem -LiteralPath (Join-Path $visualStudio 'VC/Tools/MSVC') -Filter dumpbin.exe -Recurse |
    Where-Object FullName -like '*\Hostx64\x64\dumpbin.exe' |
    Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
if ([string]::IsNullOrWhiteSpace($dumpbin)) { throw "dumpbin.exe was not found." }
$headers = & $dumpbin /headers $setup | Out-String
$dependencies = & $dumpbin /dependents $setup | Out-String
if ($headers -notmatch '8664 machine \(x64\)' -or $headers -notmatch 'Windows GUI') {
    throw "GrangerSetup.exe is not a Windows x64 GUI executable."
}
if ($dependencies -match '(?im)^\s+(Qt6|MSVCP|VCRUNTIME|CONCRT|VCCORLIB).*\.dll\s*$') {
    throw "GrangerSetup.exe has a non-system runtime dependency."
}

$standaloneRoot = Join-Path $projectRoot 'output/installer-standalone-check'
if (Test-Path -LiteralPath $standaloneRoot) { Remove-Item -LiteralPath $standaloneRoot -Recurse -Force }
New-Item -ItemType Directory -Path $standaloneRoot -Force | Out-Null
$standaloneSetup = Join-Path $standaloneRoot 'GrangerSetup.exe'
Copy-Item -LiteralPath $setup -Destination $standaloneSetup
$selfTest = Join-Path $standaloneRoot 'self-test.json'
$selfTestProcess = Start-Process -FilePath $standaloneSetup `
    -ArgumentList @('--test-mode', "--self-test=$selfTest") -Wait -PassThru
if ($selfTestProcess.ExitCode -ne 0) { throw "Standalone installer self-test failed." }
$selfTestResult = Get-Content -LiteralPath $selfTest -Raw | ConvertFrom-Json
if (-not $selfTestResult.ok -or -not $selfTestResult.gifEmbedded -or $selfTestResult.externalGifRequired) {
    throw "Embedded installer branding self-test failed."
}

$checksums = Join-Path $outputRoot 'SHA256SUMS.txt'
$checksumFiles = @(
    $setup,
    $manifest.Package,
    $manifest.Manifest
)
$checksumLines = foreach ($file in $checksumFiles) {
    "{0}  {1}" -f (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash, [IO.Path]::GetFileName($file)
}
$checksumLines | Set-Content -LiteralPath $checksums -Encoding ASCII

[pscustomobject]@{
    OK = $true
    Version = $manifest.Version
    Setup = $setup
    SetupSize = (Get-Item -LiteralPath $setup).Length
    SetupSHA256 = (Get-FileHash -LiteralPath $setup -Algorithm SHA256).Hash
    Portable = $manifest.Package
    PortableSize = $manifest.PackageSize
    PortableSHA256 = $manifest.PackageSHA256
    Manifest = $manifest.Manifest
    Checksums = $checksums
    GifSHA256 = (Get-FileHash -LiteralPath $gif -Algorithm SHA256).Hash
    GifFrames = [int]$selfTestResult.gifFrames
    Standalone = $true
    Architecture = 'x64'
    RuntimeLinkage = 'MSVC /MT'
}
