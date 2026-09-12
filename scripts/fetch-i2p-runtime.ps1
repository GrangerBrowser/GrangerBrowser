[CmdletBinding()]
param(
    [string]$SourceArchivePath = "build/dependency-cache/i2pd-download/i2pd-2.61.0-source.zip",
    [string]$Destination = "build/dependency-cache/i2p-runtime",
    [string]$VcpkgRoot = "build/dependency-cache/vcpkg-2026.07.29"
)

$ErrorActionPreference = "Stop"
$projectRoot = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot)).TrimEnd('\')
$cacheRoot = [IO.Path]::GetFullPath((Join-Path $projectRoot "build/dependency-cache")).TrimEnd('\')
$version = "2.61.0"
$sourceTag = "2.61.0"
$sourceCommit = "635b013a612ff47278ef02acf8580a28e10e26c5"
$sourceUrl = "https://github.com/PurpleI2P/i2pd/archive/refs/tags/2.61.0.zip"
$expectedSourceSha256 = "AFEA2C34A8FDBE36DF5AFAAACE79CEB0B45898B9EF9011946E3A692F8F318099"
$expectedSourceTreeSha256 = "6D9DC6E53E98F7548B07A82F5607D02988A82FA8885F04607B5F646328B406A4"
$expectedExecutableSha256 = "96C6DF64F8003384EB5ABC2F7210BF04E5D75F91A3D822F2E7A62D41D8AE2591"
$vcpkgUrl = "https://github.com/microsoft/vcpkg.git"
$vcpkgTag = "2026.07.29"
$vcpkgCommit = "9e593bb18ea69cc5095e012465dcd675a822ed0d"
$triplet = "granger-x64-windows-static"
$compilerVersion = "19.44.35228.0"
$toolsetVersion = "14.44.35207"
$boostVersion = "1.91.0"
$opensslVersion = "3.6.3"
$zlibVersion = "1.3.2#1"

function Resolve-CachePath {
    param([Parameter(Mandatory)][string]$Path)
    $resolved = if ([IO.Path]::IsPathRooted($Path)) {
        [IO.Path]::GetFullPath($Path)
    } else {
        [IO.Path]::GetFullPath((Join-Path $projectRoot $Path))
    }
    if (-not $resolved.StartsWith($cacheRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "I2P build inputs and outputs must remain under build/dependency-cache: $resolved"
    }
    return $resolved
}

function Invoke-NativeCommand {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$Description
    )
    & $FilePath @Arguments 2>&1 | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE."
    }
}

function Get-CMakeExecutable {
    $command = Get-Command cmake.exe -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }

    $visualStudioCMake = Get-ChildItem -Path (Join-Path $env:ProgramFiles "Microsoft Visual Studio/2022") `
        -Filter cmake.exe -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match '\\CommonExtensions\\Microsoft\\CMake\\CMake\\bin\\cmake\.exe$' } |
        Select-Object -First 1
    if ($visualStudioCMake) { return $visualStudioCMake.FullName }
    throw "CMake from Visual Studio 2022 was not found."
}

function Get-SourceTreeSha256 {
    param([Parameter(Mandatory)][string]$Root)
    $records = [Collections.Generic.List[string]]::new()
    foreach ($file in Get-ChildItem -LiteralPath $Root -Recurse -File) {
        $relative = $file.FullName.Substring($Root.Length + 1).Replace('\', '/')
        $records.Add(('{0} {1} {2}' -f $relative, $file.Length,
            (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash))
    }
    $ordered = $records.ToArray()
    [Array]::Sort($ordered, [StringComparer]::Ordinal)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash(
            [Text.Encoding]::UTF8.GetBytes(($ordered -join "`n") + "`n")))).Replace('-', '')
    } finally {
        $sha.Dispose()
    }
}

function Assert-BinaryDoesNotContainLocalPath {
    param([Parameter(Mandatory)][string]$Path)

    $bytes = [IO.File]::ReadAllBytes($Path)
    $singleByteText = [Text.Encoding]::GetEncoding(28591).GetString($bytes)
    $utf16Text = [Text.Encoding]::Unicode.GetString($bytes)
    foreach ($candidate in @($projectRoot, $projectRoot.Replace('\', '/'))) {
        if ($singleByteText.Contains($candidate, [StringComparison]::OrdinalIgnoreCase) -or
            $utf16Text.Contains($candidate, [StringComparison]::OrdinalIgnoreCase)) {
            throw "The i2pd binary contains a local build path."
        }
    }
}

$archive = Resolve-CachePath $SourceArchivePath
$runtimeRoot = Resolve-CachePath $Destination
$resolvedVcpkgRoot = Resolve-CachePath $VcpkgRoot
$sourceRoot = Resolve-CachePath "build/dependency-cache/i2pd-source-2.61.0"
$buildRoot = Resolve-CachePath "build/dependency-cache/i2pd-msvc-brepro-pathmap-2.61.0"
$installRoot = Resolve-CachePath "build/dependency-cache/i2pd-msvc-brepro-pathmap-install-2.61.0"
$binaryCache = Resolve-CachePath "build/dependency-cache/vcpkg-binary-cache"
$downloadCache = Resolve-CachePath "build/dependency-cache/vcpkg-downloads"
$overlayTriplets = Resolve-CachePath "build/dependency-cache/granger-vcpkg-triplets"
$overlayTriplet = Join-Path $overlayTriplets "$triplet.cmake"

New-Item -ItemType Directory -Path (Split-Path -Parent $archive) -Force | Out-Null
if (-not (Test-Path -LiteralPath $archive -PathType Leaf)) {
    $partial = "$archive.part"
    if (Test-Path -LiteralPath $partial) { Remove-Item -LiteralPath $partial -Force }
    Invoke-WebRequest -Uri $sourceUrl -OutFile $partial -UseBasicParsing
    Move-Item -LiteralPath $partial -Destination $archive
}
$actualSourceSha256 = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
if (-not $actualSourceSha256.Equals($expectedSourceSha256, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Pinned i2pd source archive hash mismatch. Expected $expectedSourceSha256, got $actualSourceSha256"
}

if (Test-Path -LiteralPath (Join-Path $sourceRoot ".git") -PathType Container) {
    $actualSourceCommit = (& git -C $sourceRoot rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $actualSourceCommit -ne $sourceCommit) {
        throw "Cached i2pd source checkout is not the pinned commit $sourceCommit."
    }
    if (-not [string]::IsNullOrWhiteSpace((& git -C $sourceRoot status --porcelain | Out-String))) {
        throw "Cached i2pd source checkout contains local changes."
    }
} elseif (-not (Test-Path -LiteralPath (Join-Path $sourceRoot "build/CMakeLists.txt") -PathType Leaf)) {
    $extractRoot = Resolve-CachePath "build/dependency-cache/i2pd-source-extract-2.61.0"
    if (Test-Path -LiteralPath $extractRoot) { Remove-Item -LiteralPath $extractRoot -Recurse -Force }
    New-Item -ItemType Directory -Path $extractRoot -Force | Out-Null
    Expand-Archive -LiteralPath $archive -DestinationPath $extractRoot -Force
    $extractedSource = Join-Path $extractRoot "i2pd-2.61.0"
    if (-not (Test-Path -LiteralPath (Join-Path $extractedSource "build/CMakeLists.txt") -PathType Leaf)) {
        throw "Pinned i2pd source archive has an unexpected layout."
    }
    Move-Item -LiteralPath $extractedSource -Destination $sourceRoot
    Remove-Item -LiteralPath $extractRoot -Recurse -Force
}
if (-not (Test-Path -LiteralPath (Join-Path $sourceRoot ".git") -PathType Container)) {
    $actualSourceTreeSha256 = Get-SourceTreeSha256 -Root $sourceRoot
    if (-not $actualSourceTreeSha256.Equals(
        $expectedSourceTreeSha256, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Cached i2pd source tree does not match the pinned archive."
    }
}

$sourceBuildFile = Join-Path $sourceRoot "build/CMakeLists.txt"
$sourceLicense = Join-Path $sourceRoot "LICENSE"
$sourceCertificates = Join-Path $sourceRoot "contrib/certificates"
if (-not (Test-Path -LiteralPath $sourceBuildFile -PathType Leaf) -or
    -not (Test-Path -LiteralPath $sourceLicense -PathType Leaf) -or
    -not (Test-Path -LiteralPath (Join-Path $sourceCertificates "reseed") -PathType Container)) {
    throw "Pinned i2pd source tree is incomplete."
}

if (-not (Test-Path -LiteralPath (Join-Path $resolvedVcpkgRoot ".git") -PathType Container)) {
    if (Test-Path -LiteralPath $resolvedVcpkgRoot) {
        throw "The pinned vcpkg cache path exists but is not a Git checkout."
    }
    Invoke-NativeCommand -FilePath (Get-Command git.exe -ErrorAction Stop).Source `
        -Arguments @("clone", "--branch", $vcpkgTag, "--depth", "1", $vcpkgUrl, $resolvedVcpkgRoot) `
        -Description "Pinned vcpkg checkout"
}
$actualVcpkgCommit = (& git -C $resolvedVcpkgRoot rev-parse HEAD).Trim()
$actualVcpkgOrigin = (& git -C $resolvedVcpkgRoot remote get-url origin).Trim()
if ($LASTEXITCODE -ne 0 -or $actualVcpkgCommit -ne $vcpkgCommit -or $actualVcpkgOrigin -ne $vcpkgUrl) {
    throw "Cached vcpkg checkout does not match the pinned official revision."
}
if (-not [string]::IsNullOrWhiteSpace((& git -C $resolvedVcpkgRoot status --porcelain | Out-String))) {
    throw "Cached vcpkg checkout contains local changes."
}

New-Item -ItemType Directory -Path $overlayTriplets -Force | Out-Null
$escapedProjectRoot = $projectRoot.Replace('\', '\\')
$tripletContents = @"
set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE static)
set(VCPKG_LIBRARY_LINKAGE static)
set(VCPKG_BUILD_TYPE release)
set(VCPKG_C_FLAGS "/experimental:deterministic /Brepro /pathmap:${escapedProjectRoot}=Z:\\granger-src")
set(VCPKG_CXX_FLAGS "/experimental:deterministic /Brepro /pathmap:${escapedProjectRoot}=Z:\\granger-src")
set(VCPKG_LINKER_FLAGS "/Brepro")
"@
[IO.File]::WriteAllText($overlayTriplet, $tripletContents.Replace("`r`n", "`n"),
    [Text.UTF8Encoding]::new($false))

$vcpkg = Join-Path $resolvedVcpkgRoot "vcpkg.exe"
if (-not (Test-Path -LiteralPath $vcpkg -PathType Leaf)) {
    Invoke-NativeCommand -FilePath (Join-Path $resolvedVcpkgRoot "bootstrap-vcpkg.bat") `
        -Arguments @("-disableMetrics") -Description "vcpkg bootstrap"
}

New-Item -ItemType Directory -Path $binaryCache -Force | Out-Null
New-Item -ItemType Directory -Path $downloadCache -Force | Out-Null
$previousDisableMetrics = $env:VCPKG_DISABLE_METRICS
$previousBinarySources = $env:VCPKG_BINARY_SOURCES
$previousDownloads = $env:VCPKG_DOWNLOADS
try {
    $env:VCPKG_DISABLE_METRICS = "1"
    $env:VCPKG_BINARY_SOURCES = "clear;files,$binaryCache,readwrite"
    $env:VCPKG_DOWNLOADS = $downloadCache
    $ports = @(
        "boost-filesystem",
        "boost-program-options",
        "boost-atomic",
        "boost-asio",
        "boost-algorithm",
        "boost-property-tree",
        "boost-dynamic-bitset",
        "openssl",
        "zlib"
    )
    Invoke-NativeCommand -FilePath $vcpkg -Arguments (@("install") + $ports + @(
        "--triplet=$triplet", "--overlay-triplets=$overlayTriplets")) `
        -Description "Pinned i2pd dependency installation"
} finally {
    $env:VCPKG_DISABLE_METRICS = $previousDisableMetrics
    $env:VCPKG_BINARY_SOURCES = $previousBinarySources
    $env:VCPKG_DOWNLOADS = $previousDownloads
}

$installedPackages = (& $vcpkg list --triplet=$triplet 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0) { throw "Could not inspect the pinned vcpkg dependency set." }
$requiredPackageVersions = [ordered]@{
    "boost-filesystem" = $boostVersion
    "boost-program-options" = $boostVersion
    "boost-atomic" = $boostVersion
    "boost-asio" = $boostVersion
    "boost-algorithm" = $boostVersion
    "boost-property-tree" = $boostVersion
    "boost-dynamic-bitset" = $boostVersion
    "openssl" = $opensslVersion
    "zlib" = "1.3.2"
}
foreach ($entry in $requiredPackageVersions.GetEnumerator()) {
    $pattern = "(?m)^$([regex]::Escape($entry.Key)):$([regex]::Escape($triplet))\s+$([regex]::Escape($entry.Value))(?:#\d+)?(?:\s|$)"
    if ($installedPackages -notmatch $pattern) {
        throw "Pinned vcpkg dependency is missing or has the wrong version: $($entry.Key) $($entry.Value)"
    }
}

$builtExecutable = Join-Path $installRoot "bin/i2pd.exe"
$buildRequired = -not (Test-Path -LiteralPath $builtExecutable -PathType Leaf)
if (-not $buildRequired) {
    $cachedHash = (Get-FileHash -LiteralPath $builtExecutable -Algorithm SHA256).Hash
    $buildRequired = -not $cachedHash.Equals($expectedExecutableSha256, [StringComparison]::OrdinalIgnoreCase)
}
if ($buildRequired) {
    $cmake = Get-CMakeExecutable
    $toolchain = Join-Path $resolvedVcpkgRoot "scripts/buildsystems/vcpkg.cmake"
    Invoke-NativeCommand -FilePath $cmake -Arguments @(
        "-S", (Join-Path $sourceRoot "build"),
        "-B", $buildRoot,
        "-G", "Visual Studio 17 2022",
        "-A", "x64",
        "-DCMAKE_TOOLCHAIN_FILE=$toolchain",
        "-DVCPKG_TARGET_TRIPLET=$triplet",
        "-DVCPKG_OVERLAY_TRIPLETS=$overlayTriplets",
        "-DWITH_STATIC=ON",
        "-DWITH_UPNP=OFF",
        "-DWITH_GIT_VERSION=OFF",
        "-DBUILD_TESTING=OFF",
        "-DCMAKE_INSTALL_PREFIX=$installRoot",
        "-DCMAKE_C_FLAGS=/DWIN32 /D_WINDOWS /experimental:deterministic /Brepro /pathmap:$projectRoot=Z:\granger-src",
        "-DCMAKE_CXX_FLAGS=/DWIN32 /D_WINDOWS /EHsc /experimental:deterministic /Brepro /pathmap:$projectRoot=Z:\granger-src",
        "-DCMAKE_EXE_LINKER_FLAGS=/machine:x64 /Brepro",
        "-DCMAKE_STATIC_LINKER_FLAGS=/machine:x64 /Brepro"
    ) -Description "i2pd CMake configuration"

    $compilerConfig = Get-ChildItem -LiteralPath (Join-Path $buildRoot "CMakeFiles") `
        -Recurse -File -Filter "CMakeCXXCompiler.cmake" | Select-Object -First 1
    $compilerText = if ($compilerConfig) { Get-Content -LiteralPath $compilerConfig.FullName -Raw } else { "" }
    if ($compilerText -notmatch "CMAKE_CXX_COMPILER_VERSION `"$([regex]::Escape($compilerVersion))`"" -or
        $compilerText -notmatch "MSVC/$([regex]::Escape($toolsetVersion))/bin/Hostx64/x64/cl\.exe") {
        throw "The installed MSVC compiler does not match the pinned i2pd release toolchain."
    }

    Invoke-NativeCommand -FilePath $cmake `
        -Arguments @("--build", $buildRoot, "--config", "Release", "--target", "install", "--parallel", "6") `
        -Description "i2pd Release build"
}

if (-not (Test-Path -LiteralPath $builtExecutable -PathType Leaf)) {
    throw "The i2pd source build did not produce i2pd.exe."
}
$executableSha256 = (Get-FileHash -LiteralPath $builtExecutable -Algorithm SHA256).Hash
Assert-BinaryDoesNotContainLocalPath -Path $builtExecutable
if (-not $executableSha256.Equals($expectedExecutableSha256, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Reproducible i2pd executable hash mismatch. Expected $expectedExecutableSha256, got $executableSha256"
}

$savedPath = $env:PATH
try {
    $env:PATH = "$env:SystemRoot\System32;$env:SystemRoot;$env:SystemRoot\System32\Wbem"
    $versionOutput = (& $builtExecutable --version 2>&1 | Out-String).Trim()
} finally {
    $env:PATH = $savedPath
}
if ($LASTEXITCODE -ne 0 -or $versionOutput -notmatch '(?m)^i2pd version 2\.61\.0') {
    throw "Unexpected app-local i2pd runtime version: $versionOutput"
}

if (Test-Path -LiteralPath $runtimeRoot) { Remove-Item -LiteralPath $runtimeRoot -Recurse -Force }
New-Item -ItemType Directory -Path $runtimeRoot -Force | Out-Null
Copy-Item -LiteralPath $builtExecutable -Destination (Join-Path $runtimeRoot "i2pd.exe")
Copy-Item -LiteralPath $sourceCertificates -Destination (Join-Path $runtimeRoot "certificates") -Recurse
Copy-Item -LiteralPath $sourceLicense -Destination (Join-Path $runtimeRoot "LICENSE.txt")
Copy-Item -LiteralPath (Join-Path $sourceRoot "README.md") -Destination (Join-Path $runtimeRoot "README.txt")

$certificateCount = @(Get-ChildItem -LiteralPath (Join-Path $runtimeRoot "certificates") -Recurse -File).Count
if ($certificateCount -ne 22) { throw "The staged i2pd certificate bundle is incomplete." }

[pscustomobject]@{
    OK = $true
    Version = $version
    Source = $sourceUrl
    SourceTag = $sourceTag
    SourceCommit = $sourceCommit
    SourceArchive = $archive
    SourceArchiveSHA256 = $actualSourceSha256
    SourceTreeSHA256 = $expectedSourceTreeSha256
    RuntimeRoot = $runtimeRoot
    Executable = Join-Path $runtimeRoot "i2pd.exe"
    ExecutableSHA256 = $executableSha256
    ReproducibleBuild = $true
    BuildPathMapped = $true
    BuildToolchain = "MSVC $compilerVersion (VS 2022 toolset $toolsetVersion)"
    BuildFlags = "/experimental:deterministic; /Brepro; /pathmap; static CRT/dependencies; UPnP off; Git version off"
    VcpkgTag = $vcpkgTag
    VcpkgCommit = $vcpkgCommit
    VcpkgTriplet = $triplet
    BoostVersion = $boostVersion
    OpenSslVersion = $opensslVersion
    ZlibVersion = $zlibVersion
    CertificateCount = $certificateCount
    License = "BSD-3-Clause"
}
