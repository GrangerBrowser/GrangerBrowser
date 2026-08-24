[CmdletBinding()]
param(
    [string]$PackageDirectory = "release/Granger Browser"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$workspaceRoot = [IO.Path]::GetFullPath($projectRoot).TrimEnd('\')
$packageRoot = [IO.Path]::GetFullPath((Join-Path $projectRoot $PackageDirectory)).TrimEnd('\')
if (-not $packageRoot.StartsWith($workspaceRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw "PackageDirectory must remain inside the project workspace."
}
if (-not (Test-Path -LiteralPath $packageRoot -PathType Container)) {
    throw "Package directory not found: $packageRoot"
}

function Read-AsciiString {
    param(
        [Parameter(Mandatory)][IO.BinaryReader]$Reader,
        [Parameter(Mandatory)][long]$Offset,
        [int]$MaximumLength = 512
    )

    $Reader.BaseStream.Position = $Offset
    $bytes = New-Object Collections.Generic.List[byte]
    while ($bytes.Count -lt $MaximumLength -and $Reader.BaseStream.Position -lt $Reader.BaseStream.Length) {
        $value = $Reader.ReadByte()
        if ($value -eq 0) { break }
        $bytes.Add($value) | Out-Null
    }
    return [Text.Encoding]::ASCII.GetString($bytes.ToArray())
}

function Convert-RvaToFileOffset {
    param(
        [Parameter(Mandatory)][uint32]$Rva,
        [Parameter(Mandatory)][object[]]$Sections
    )

    foreach ($section in $Sections) {
        $span = [Math]::Max([uint64]$section.VirtualSize, [uint64]$section.RawSize)
        if ([uint64]$Rva -ge [uint64]$section.VirtualAddress -and
            [uint64]$Rva -lt ([uint64]$section.VirtualAddress + $span)) {
            return [long]([uint64]$section.RawPointer + ([uint64]$Rva - [uint64]$section.VirtualAddress))
        }
    }
    return -1
}

function Get-PeInfo {
    param([Parameter(Mandatory)][string]$Path)

    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
        $reader = New-Object IO.BinaryReader($stream)
        if ($reader.ReadUInt16() -ne 0x5A4D) { throw "Missing MZ header: $Path" }

        $stream.Position = 0x3c
        $peOffset = $reader.ReadUInt32()
        if ($peOffset -gt ($stream.Length - 24)) { throw "Invalid PE offset: $Path" }
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) { throw "Missing PE signature: $Path" }

        $machine = $reader.ReadUInt16()
        $sectionCount = $reader.ReadUInt16()
        $timestamp = $reader.ReadUInt32()
        $reader.ReadUInt32() | Out-Null
        $reader.ReadUInt32() | Out-Null
        $optionalHeaderSize = $reader.ReadUInt16()
        $characteristics = $reader.ReadUInt16()
        $optionalHeaderOffset = $peOffset + 24

        $stream.Position = $optionalHeaderOffset
        $optionalMagic = $reader.ReadUInt16()
        $majorLinker = $reader.ReadByte()
        $minorLinker = $reader.ReadByte()
        if ($optionalMagic -notin @(0x10b, 0x20b)) { throw "Unsupported optional header: $Path" }

        $stream.Position = $optionalHeaderOffset + 40
        $majorOs = $reader.ReadUInt16()
        $minorOs = $reader.ReadUInt16()
        $reader.ReadUInt16() | Out-Null
        $reader.ReadUInt16() | Out-Null
        $majorSubsystem = $reader.ReadUInt16()
        $minorSubsystem = $reader.ReadUInt16()
        $stream.Position = $optionalHeaderOffset + 68
        $subsystem = $reader.ReadUInt16()
        $dllCharacteristics = $reader.ReadUInt16()

        $sectionHeadersOffset = $optionalHeaderOffset + $optionalHeaderSize
        $sections = @()
        for ($index = 0; $index -lt $sectionCount; ++$index) {
            $stream.Position = $sectionHeadersOffset + (40 * $index)
            $nameBytes = $reader.ReadBytes(8)
            $name = [Text.Encoding]::ASCII.GetString($nameBytes).Trim([char]0)
            $virtualSize = $reader.ReadUInt32()
            $virtualAddress = $reader.ReadUInt32()
            $rawSize = $reader.ReadUInt32()
            $rawPointer = $reader.ReadUInt32()
            $sections += [pscustomobject]@{
                Name = $name
                VirtualSize = $virtualSize
                VirtualAddress = $virtualAddress
                RawSize = $rawSize
                RawPointer = $rawPointer
            }
        }

        $dataDirectoryOffset = if ($optionalMagic -eq 0x20b) {
            $optionalHeaderOffset + 112
        } else {
            $optionalHeaderOffset + 96
        }
        $numberOfDirectoriesOffset = if ($optionalMagic -eq 0x20b) {
            $optionalHeaderOffset + 108
        } else {
            $optionalHeaderOffset + 92
        }
        $stream.Position = $numberOfDirectoriesOffset
        $directoryCount = $reader.ReadUInt32()
        $imports = New-Object Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)

        if ($directoryCount -gt 1) {
            $stream.Position = $dataDirectoryOffset + 8
            $importRva = $reader.ReadUInt32()
            $importSize = $reader.ReadUInt32()
            if ($importRva -ne 0 -and $importSize -ne 0) {
                $descriptorOffset = Convert-RvaToFileOffset -Rva $importRva -Sections $sections
                if ($descriptorOffset -lt 0) { throw "Invalid import directory RVA: $Path" }
                for ($index = 0; $index -lt 4096; ++$index) {
                    $stream.Position = $descriptorOffset + (20 * $index)
                    $originalThunk = $reader.ReadUInt32()
                    $timeDateStamp = $reader.ReadUInt32()
                    $forwarderChain = $reader.ReadUInt32()
                    $nameRva = $reader.ReadUInt32()
                    $firstThunk = $reader.ReadUInt32()
                    if (($originalThunk -bor $timeDateStamp -bor $forwarderChain -bor $nameRva -bor $firstThunk) -eq 0) { break }
                    $nameOffset = Convert-RvaToFileOffset -Rva $nameRva -Sections $sections
                    if ($nameOffset -lt 0) { throw "Invalid import name RVA: $Path" }
                    $dependency = Read-AsciiString -Reader $reader -Offset $nameOffset
                    if (-not [string]::IsNullOrWhiteSpace($dependency)) { $imports.Add($dependency) | Out-Null }
                }
            }
        }

        if ($directoryCount -gt 13) {
            $stream.Position = $dataDirectoryOffset + (13 * 8)
            $delayImportRva = $reader.ReadUInt32()
            $delayImportSize = $reader.ReadUInt32()
            if ($delayImportRva -ne 0 -and $delayImportSize -ne 0) {
                $descriptorOffset = Convert-RvaToFileOffset -Rva $delayImportRva -Sections $sections
                if ($descriptorOffset -lt 0) { throw "Invalid delay-import directory RVA: $Path" }
                for ($index = 0; $index -lt 4096; ++$index) {
                    $stream.Position = $descriptorOffset + (32 * $index)
                    $attributes = $reader.ReadUInt32()
                    $nameRva = $reader.ReadUInt32()
                    $moduleHandle = $reader.ReadUInt32()
                    $iat = $reader.ReadUInt32()
                    $int = $reader.ReadUInt32()
                    $boundIat = $reader.ReadUInt32()
                    $unloadIat = $reader.ReadUInt32()
                    $timeDateStamp = $reader.ReadUInt32()
                    if (($attributes -bor $nameRva -bor $moduleHandle -bor $iat -bor $int -bor $boundIat -bor $unloadIat -bor $timeDateStamp) -eq 0) { break }
                    $nameOffset = Convert-RvaToFileOffset -Rva $nameRva -Sections $sections
                    if ($nameOffset -lt 0) { throw "Invalid delay-import name RVA: $Path" }
                    $dependency = Read-AsciiString -Reader $reader -Offset $nameOffset
                    if (-not [string]::IsNullOrWhiteSpace($dependency)) { $imports.Add($dependency) | Out-Null }
                }
            }
        }

        return [pscustomobject]@{
            Path = $Path
            Machine = $machine
            Format = $optionalMagic
            Subsystem = $subsystem
            OperatingSystemVersion = "$majorOs.$minorOs"
            SubsystemVersion = "$majorSubsystem.$minorSubsystem"
            LinkerVersion = "$majorLinker.$minorLinker"
            Timestamp = [DateTimeOffset]::FromUnixTimeSeconds($timestamp).UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
            Characteristics = $characteristics
            DllCharacteristics = $dllCharacteristics
            Imports = @($imports | Sort-Object)
        }
    } finally {
        $stream.Dispose()
    }
}

function Test-LfsPointer {
    param([Parameter(Mandatory)][string]$Path)

    $stream = [IO.File]::OpenRead($Path)
    try {
        $buffer = New-Object byte[] 200
        $count = $stream.Read($buffer, 0, $buffer.Length)
        if ($count -eq 0) { return $false }
        $prefix = [Text.Encoding]::ASCII.GetString($buffer, 0, $count)
        return $prefix.StartsWith("version https://git-lfs.github.com/spec/v1", [StringComparison]::Ordinal)
    } finally {
        $stream.Dispose()
    }
}

function Read-QtPathConfiguration {
    param([Parameter(Mandatory)][string]$Path)

    $section = ""
    $paths = @{}
    foreach ($rawLine in Get-Content -LiteralPath $Path -Encoding ASCII) {
        $line = $rawLine.Trim()
        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith(';') -or $line.StartsWith('#')) {
            continue
        }
        if ($line.StartsWith('[') -and $line.EndsWith(']')) {
            $section = $line.Substring(1, $line.Length - 2).Trim()
            continue
        }
        if (-not $section.Equals('Paths', [StringComparison]::OrdinalIgnoreCase)) { continue }
        $separator = $line.IndexOf('=')
        if ($separator -le 0) { throw "Invalid qt.conf path entry: $rawLine" }
        $key = $line.Substring(0, $separator).Trim()
        $value = $line.Substring($separator + 1).Trim()
        if ([string]::IsNullOrWhiteSpace($key) -or [string]::IsNullOrWhiteSpace($value)) {
            throw "Empty qt.conf path entry: $rawLine"
        }
        $paths[$key] = $value
    }
    return $paths
}

if (-not ('GrangerPortableNativeLoader' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class GrangerPortableNativeLoader
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr LoadLibraryEx(string fileName, IntPtr file, uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool FreeLibrary(IntPtr module);
}
'@
}

$requiredFiles = @(
    "GrangerBrowser.exe",
    "QtWebEngineProcess.exe",
    "Qt6Core.dll",
    "Qt6Gui.dll",
    "Qt6Network.dll",
    "Qt6Widgets.dll",
    "Qt6WebEngineCore.dll",
    "Qt6WebEngineWidgets.dll",
    "qt.conf",
    "deployment-metadata.json",
    "d3dcompiler_47.dll",
    "icu.dll",
    "icuuc.dll",
    "dxcompiler.dll",
    "dxil.dll",
    "platforms/qwindows.dll",
    "resources/icudtl.dat",
    "resources/qtwebengine_resources.pak",
    "resources/v8_context_snapshot.bin",
    "translations/qtwebengine_locales/en-US.pak",
    "MSVCP140.dll",
    "MSVCP140_ATOMIC_WAIT.dll",
    "VCRUNTIME140.dll",
    "VCRUNTIME140_1.dll",
    "runtime/tor/tor.exe",
    "runtime/tor/data/geoip",
    "runtime/tor/data/geoip6",
    "runtime/tor/pluggable_transports/lyrebird.exe",
    "runtime/tor/pluggable_transports/conjure-client.exe",
    "runtime/tor/pluggable_transports/pt_config.json",
    "licenses/tor.txt",
    "licenses/lyrebird.txt",
    "licenses/conjure.txt",
    "runtime/i2p/i2pd.exe",
    "runtime/i2p/LICENSE.txt",
    "licenses/i2pd-LICENSE.txt",
    "licenses/i2pd-SOURCE.md",
    "release-manifest.json"
)
foreach ($relativePath in $requiredFiles) {
    if (-not (Test-Path -LiteralPath (Join-Path $packageRoot $relativePath) -PathType Leaf)) {
        throw "Portable package is missing $relativePath"
    }
}

$qtPaths = Read-QtPathConfiguration -Path (Join-Path $packageRoot "qt.conf")
$requiredQtPaths = @("Prefix", "Binaries", "Libraries", "LibraryExecutables", "Plugins", "Data", "Translations")
foreach ($key in $requiredQtPaths) {
    if (-not $qtPaths.ContainsKey($key)) { throw "qt.conf does not define $key" }
}
foreach ($key in $qtPaths.Keys) {
    $value = [string]$qtPaths[$key]
    $normalized = $value.Replace('/', '\')
    if ([IO.Path]::IsPathRooted($normalized) -or
        @($normalized.Split('\') | Where-Object { $_ -eq '..' }).Count -ne 0) {
        throw "qt.conf contains a non-portable path for ${key}: $value"
    }
}
if (-not ([string]$qtPaths.LibraryExecutables).Equals('.', [StringComparison]::Ordinal) -or
    -not ([string]$qtPaths.Translations).Equals('translations', [StringComparison]::OrdinalIgnoreCase)) {
    throw "qt.conf does not pin WebEngine executables and locales to the package."
}

$deploymentMetadataPath = Join-Path $packageRoot "deployment-metadata.json"
$deploymentMetadata = Get-Content -LiteralPath $deploymentMetadataPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ([int]$deploymentMetadata.SchemaVersion -ne 2 -or
    [string]$deploymentMetadata.Architecture -ne "x64" -or
    [string]$deploymentMetadata.QtVersion -notmatch '^6\.11\.2(?:\.0)?$' -or
    [string]$deploymentMetadata.WinDeployQtVersion -notmatch '^6\.11\.2(?:\.0)?$' -or
    [string]$deploymentMetadata.TorBundleVersion -ne "15.0.20" -or
    [string]$deploymentMetadata.TorVersion -ne "0.4.9.11" -or
    [string]$deploymentMetadata.TorArchiveSHA256 -ne "D59BFF934E3AD876E1623E24AE60C19AEEA56F50178093B9F86FBA230639F949" -or
    [string]$deploymentMetadata.TorSigningKeyFingerprint -ne "EF6E286DDA85EA2A4BA7DE684E2C6E8793298290" -or
    -not [bool]$deploymentMetadata.TorSignatureVerified -or
    [string]$deploymentMetadata.TorLicense -ne "GPL-3.0-or-later" -or
    [string]$deploymentMetadata.LyrebirdVersion -ne "0.8.1" -or
    [string]$deploymentMetadata.LyrebirdLicense -ne "BSD-3-Clause" -or
    [string]$deploymentMetadata.ConjureVersion -ne "devel" -or
    [string]$deploymentMetadata.GeoIpBundleVersion -ne "15.0.20" -or
    [string]$deploymentMetadata.I2pVersion -ne "2.61.0" -or
    [string]$deploymentMetadata.I2pArchiveSHA256 -ne "A0A8FB199A6BC5B487DF71567791DE6997050B921D65622EF9E936FFA88BC83F" -or
    [string]$deploymentMetadata.I2pLicense -ne "BSD-3-Clause" -or
    [int]$deploymentMetadata.I2pCertificateCount -lt 1) {
    throw "Deployment metadata does not describe the supported Qt 6.11.2 x64 runtime."
}
$pinnedPrivateNetworkFiles = [ordered]@{
    "runtime/tor/tor.exe" = "EA61BA0ED5B89D0622D2894B2A86F5FF34CE9B48E6E40D64341E7C0C7EE03E08"
    "runtime/tor/pluggable_transports/lyrebird.exe" = "83D4D39D438A36066AF5161806A448B5D099033DDA901ECD0B2663EC58A5790F"
    "runtime/tor/pluggable_transports/conjure-client.exe" = "6FB2DCE9803157A6B871D6B5CD644B4D216350D81623E5548B887040DA1BA5CB"
    "runtime/tor/pluggable_transports/pt_config.json" = "3F11D303C30191B3B1D382B9BADD882D87FD87550D061F7D25A1B31226FC9B75"
    "runtime/tor/data/geoip" = "AF9CCD060A712D090EE07D5678B5D45B0038EC1573116FAE724A6695A8485703"
    "runtime/tor/data/geoip6" = "2393124667BA2CCB4C806F226A33B2EF7A8188D1BA55831C1A5D3DCA2B062514"
    "runtime/i2p/i2pd.exe" = "3BFAC576443EA76586C2AB3D688CBA98EDAAACAAAABD72308C058249F10C493E"
}
foreach ($entry in $pinnedPrivateNetworkFiles.GetEnumerator()) {
    $actual = (Get-FileHash -LiteralPath (Join-Path $packageRoot $entry.Key) -Algorithm SHA256).Hash
    if (-not $actual.Equals($entry.Value, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Pinned private-network runtime hash mismatch: $($entry.Key)"
    }
}
$i2pCertificates = @(
    Get-ChildItem -LiteralPath (Join-Path $packageRoot "runtime/i2p/certificates") -Recurse -File -ErrorAction Stop
)
if ($i2pCertificates.Count -ne [int]$deploymentMetadata.I2pCertificateCount) {
    throw "Packaged i2pd certificate count does not match deployment metadata."
}
$metadataPaths = New-Object Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
foreach ($entry in $deploymentMetadata.RuntimeFiles) {
    $relativePath = ([string]$entry.Path).Replace('/', '\')
    if ([IO.Path]::IsPathRooted($relativePath) -or
        @($relativePath.Split('\') | Where-Object { $_ -eq '..' }).Count -ne 0) {
        throw "Deployment metadata escaped the package: $relativePath"
    }
    if (-not $metadataPaths.Add($relativePath)) { throw "Duplicate deployment metadata entry: $relativePath" }
    $candidate = Join-Path $packageRoot $relativePath
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw "Deployment metadata file is missing: $relativePath"
    }
    $item = Get-Item -LiteralPath $candidate
    if ($item.Length -ne [long]$entry.Size -or
        [string]$item.VersionInfo.FileVersion -ne [string]$entry.Version -or
        -not (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash.Equals(
            [string]$entry.SHA256, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Deployment metadata mismatch: $relativePath"
    }
}
foreach ($relativePath in @("Qt6Core.dll", "Qt6WebEngineCore.dll", "QtWebEngineProcess.exe",
                             "d3dcompiler_47.dll", "icu.dll", "icuuc.dll", "dxcompiler.dll", "dxil.dll",
                             "MSVCP140.dll", "VCRUNTIME140.dll", "VCRUNTIME140_1.dll",
                             "runtime\tor\tor.exe", "runtime\tor\pluggable_transports\lyrebird.exe",
                             "runtime\tor\pluggable_transports\conjure-client.exe",
                             "runtime\tor\pluggable_transports\pt_config.json",
                             "runtime\tor\data\geoip", "runtime\tor\data\geoip6",
                             "runtime\i2p\i2pd.exe")) {
    if (-not $metadataPaths.Contains($relativePath)) {
        throw "Deployment metadata does not cover $relativePath"
    }
}

$localRuntimeMetadataPath = Join-Path $packageRoot "local-runtime-metadata.json"
$localRuntimeMetadata = $null
if (Test-Path -LiteralPath $localRuntimeMetadataPath -PathType Leaf) {
    $localRuntimeMetadata = Get-Content -LiteralPath $localRuntimeMetadataPath -Raw -Encoding UTF8 |
        ConvertFrom-Json
    if ([int]$localRuntimeMetadata.SchemaVersion -ne 1 -or
        [string]$localRuntimeMetadata.SourceHead -notmatch '^[0-9a-f]{40}$' -or
        [string]$localRuntimeMetadata.PythonArchitecture -ne "x64" -or
        [version]$localRuntimeMetadata.PythonVersion -lt [version]"3.11" -or
        [version]$localRuntimeMetadata.CryptographyVersion -lt [version]"44.0" -or
        [version]$localRuntimeMetadata.CffiVersion -lt [version]"1.0" -or
        [version]$localRuntimeMetadata.PycparserVersion -lt [version]"2.0" -or
        [string]$localRuntimeMetadata.GrangerNetworkVersion -ne "0.2.0" -or
        -not [bool]$localRuntimeMetadata.IsolatedRuntime) {
        throw "Local Granger Network runtime metadata is invalid."
    }
    $browserHash = (Get-FileHash -LiteralPath (Join-Path $packageRoot "GrangerBrowser.exe") `
        -Algorithm SHA256).Hash
    if (-not $browserHash.Equals(
            [string]$localRuntimeMetadata.BrowserExecutableSHA256,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "Local runtime metadata does not match GrangerBrowser.exe."
    }
    foreach ($entry in $localRuntimeMetadata.RuntimeFiles) {
        $relativePath = ([string]$entry.Path).Replace('/', '\')
        if (-not $relativePath.StartsWith("runtime\python\", [StringComparison]::OrdinalIgnoreCase) -or
            [IO.Path]::IsPathRooted($relativePath) -or
            @($relativePath.Split('\') | Where-Object { $_ -eq '..' }).Count -ne 0) {
            throw "Local runtime metadata escaped runtime/python: $relativePath"
        }
        $candidate = Join-Path $packageRoot $relativePath
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            throw "Local runtime metadata file is missing: $relativePath"
        }
        $item = Get-Item -LiteralPath $candidate
        if ($item.Length -ne [long]$entry.Size -or
            -not (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash.Equals(
                [string]$entry.SHA256, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Local runtime metadata mismatch: $relativePath"
        }
    }
    $pythonExecutable = Join-Path $packageRoot "runtime/python/python.exe"
    $pythonDlls = @(Get-ChildItem -LiteralPath (Join-Path $packageRoot "runtime/python") `
        -File -Filter "python*.dll")
    $pythonPathFiles = @(Get-ChildItem -LiteralPath (Join-Path $packageRoot "runtime/python") `
        -File -Filter "python*._pth")
    if (-not (Test-Path -LiteralPath $pythonExecutable -PathType Leaf) -or
        $pythonDlls.Count -lt 2 -or $pythonPathFiles.Count -ne 1) {
        throw "App-local Python runtime layout is incomplete."
    }
    foreach ($signedFile in @($pythonExecutable) + $pythonDlls.FullName) {
        $signature = Get-AuthenticodeSignature -LiteralPath $signedFile
        if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
            -not $signature.SignerCertificate -or
            $signature.SignerCertificate.Subject -notmatch "Python Software Foundation") {
            throw "App-local Python signature validation failed: $signedFile"
        }
    }
}

$signedRuntimeFiles = @(
    @{ Path = "Qt6Core.dll"; Publisher = "The Qt Company" },
    @{ Path = "Qt6WebEngineCore.dll"; Publisher = "The Qt Company" },
    @{ Path = "QtWebEngineProcess.exe"; Publisher = "The Qt Company" },
    @{ Path = "d3dcompiler_47.dll"; Publisher = "Microsoft" },
    @{ Path = "icu.dll"; Publisher = "Microsoft Windows" },
    @{ Path = "icuuc.dll"; Publisher = "Microsoft Windows" },
    @{ Path = "dxcompiler.dll"; Publisher = "Microsoft" },
    @{ Path = "dxil.dll"; Publisher = "Microsoft" },
    @{ Path = "MSVCP140.dll"; Publisher = "Microsoft" },
    @{ Path = "VCRUNTIME140.dll"; Publisher = "Microsoft" },
    @{ Path = "VCRUNTIME140_1.dll"; Publisher = "Microsoft" }
)
foreach ($record in $signedRuntimeFiles) {
    $candidate = Join-Path $packageRoot $record.Path
    $signature = Get-AuthenticodeSignature -LiteralPath $candidate
    if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
        -not $signature.SignerCertificate -or
        $signature.SignerCertificate.Subject -notmatch [regex]::Escape([string]$record.Publisher)) {
        throw "Runtime signature validation failed for $($record.Path): $($signature.Status)"
    }
}

$allFiles = @(Get-ChildItem -LiteralPath $packageRoot -Recurse -File)
$lfsPointers = @($allFiles | Where-Object { Test-LfsPointer -Path $_.FullName })
if ($lfsPointers.Count -ne 0) {
    throw "Portable package contains Git LFS pointer files: $($lfsPointers.FullName -join ', ')"
}

$qmlDebugFiles = @(Get-ChildItem -LiteralPath $packageRoot -Recurse -File -Filter "qmldbg_*.dll")
$qmlDebugDirectories = @(Get-ChildItem -LiteralPath $packageRoot -Recurse -Directory | Where-Object {
    $_.Name.Equals("qmltooling", [StringComparison]::OrdinalIgnoreCase)
})

$manifestPath = Join-Path $packageRoot "release-manifest.json"
$manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
$manifestPaths = New-Object Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
foreach ($entry in $manifest) {
    $relativePath = ([string]$entry.Path).Replace('/', '\')
    if ([IO.Path]::IsPathRooted($relativePath) -or
        @($relativePath.Split('\') | Where-Object { $_ -eq '..' }).Count -ne 0) {
        throw "Manifest path escaped the package: $relativePath"
    }
    $candidate = Join-Path $packageRoot $relativePath
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { throw "Manifest file is missing: $relativePath" }
    $file = Get-Item -LiteralPath $candidate
    if ($file.Length -ne [long]$entry.Size) { throw "Manifest size mismatch: $relativePath" }
    $hash = (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash
    if (-not $hash.Equals([string]$entry.SHA256, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Manifest hash mismatch: $relativePath"
    }
    $manifestPaths.Add($relativePath) | Out-Null
}
$unlistedFiles = @($allFiles | Where-Object {
    $relativePath = $_.FullName.Substring($packageRoot.Length + 1)
    -not $relativePath.Equals("release-manifest.json", [StringComparison]::OrdinalIgnoreCase) -and
    -not $manifestPaths.Contains($relativePath)
})
if ($unlistedFiles.Count -ne 0) {
    throw "Package files are missing from release-manifest.json: $($unlistedFiles.FullName -join ', ')"
}

$textExtensions = @('.json', '.md', '.ps1', '.txt')
$machinePathMatches = @()
foreach ($file in @($allFiles | Where-Object { $_.Extension.ToLowerInvariant() -in $textExtensions })) {
    $content = [IO.File]::ReadAllText($file.FullName)
    if ($content.IndexOf('C:\Users\', [StringComparison]::OrdinalIgnoreCase) -ge 0 -or
        $content.IndexOf('C:/Users/', [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        $machinePathMatches += $file.FullName
    }
}
if ($machinePathMatches.Count -ne 0) {
    throw "Package text contains machine-specific user paths: $($machinePathMatches -join ', ')"
}

$peFiles = @($allFiles | Where-Object { $_.Extension.ToLowerInvariant() -in @('.exe', '.dll') })
$peResults = @($peFiles | ForEach-Object { Get-PeInfo -Path $_.FullName })
$wrongArchitecture = @($peResults | Where-Object { $_.Machine -ne 0x8664 -or $_.Format -ne 0x20b })
if ($wrongArchitecture.Count -ne 0) {
    throw "Portable package contains non-x64 PE files: $($wrongArchitecture.Path -join ', ')"
}

$criticalSubsystems = @{
    "GrangerBrowser.exe" = 2
    "QtWebEngineProcess.exe" = 2
    "runtime\tor\tor.exe" = 3
    "runtime\tor\pluggable_transports\lyrebird.exe" = 3
    "runtime\tor\pluggable_transports\conjure-client.exe" = 3
    "runtime\i2p\i2pd.exe" = 2
}
foreach ($relativePath in $criticalSubsystems.Keys) {
    $fullPath = Join-Path $packageRoot $relativePath
    $pe = $peResults | Where-Object { $_.Path.Equals($fullPath, [StringComparison]::OrdinalIgnoreCase) } | Select-Object -First 1
    if (-not $pe -or $pe.Subsystem -ne $criticalSubsystems[$relativePath]) {
        throw "Unexpected PE subsystem for $relativePath"
    }
    $minimumMajor = [int]($pe.SubsystemVersion.Split('.')[0])
    if ($minimumMajor -gt 10) { throw "Unsupported Windows subsystem version for ${relativePath}: $($pe.SubsystemVersion)" }
}

$dependencyRows = @()
$unresolvedDependencies = @()
foreach ($pe in $peResults) {
    foreach ($dependency in $pe.Imports) {
        $sameDirectory = Join-Path (Split-Path -Parent $pe.Path) $dependency
        $packageDirectory = Join-Path $packageRoot $dependency
        $pythonRuntimeDirectory = Join-Path $packageRoot "runtime\python"
        $pythonRuntimeDependency = Join-Path $pythonRuntimeDirectory $dependency
        $isPythonRuntimeFile = $pe.Path.StartsWith(
            $pythonRuntimeDirectory.TrimEnd('\') + '\',
            [StringComparison]::OrdinalIgnoreCase)
        $systemDirectory = Join-Path $env:SystemRoot "System32\$dependency"
        $resolution = if (Test-Path -LiteralPath $sameDirectory -PathType Leaf) {
            "same-directory"
        } elseif (Test-Path -LiteralPath $packageDirectory -PathType Leaf) {
            "package-root"
        } elseif ($isPythonRuntimeFile -and
                  (Test-Path -LiteralPath $pythonRuntimeDependency -PathType Leaf)) {
            "python-runtime-root"
        } elseif ($dependency.StartsWith("api-ms-win-", [StringComparison]::OrdinalIgnoreCase) -or
                  $dependency.StartsWith("ext-ms-", [StringComparison]::OrdinalIgnoreCase)) {
            "Windows API set"
        } elseif (Test-Path -LiteralPath $systemDirectory -PathType Leaf) {
            "System32"
        } else {
            "unresolved"
        }
        $row = [pscustomobject]@{
            File = $pe.Path.Substring($packageRoot.Length + 1)
            Dependency = $dependency
            Resolution = $resolution
        }
        $dependencyRows += $row
        if ($resolution -eq "unresolved") { $unresolvedDependencies += $row }
    }
}
if ($unresolvedDependencies.Count -ne 0) {
    $details = $unresolvedDependencies | ForEach-Object { "$($_.File) -> $($_.Dependency)" }
    throw "Unresolved PE imports: $($details -join ', ')"
}
if ($qmlDebugFiles.Count -ne 0 -or $qmlDebugDirectories.Count -ne 0) {
    throw "Production package contains QML debugger tooling."
}

$loadLibraryFlags = 0x00000100 -bor 0x00001000
$loadLibraryResults = @()
foreach ($relativePath in @("Qt6Core.dll", "Qt6Gui.dll", "Qt6Network.dll", "Qt6Widgets.dll",
                             "Qt6WebEngineCore.dll", "Qt6WebEngineWidgets.dll")) {
    $candidate = Join-Path $packageRoot $relativePath
    $handle = [GrangerPortableNativeLoader]::LoadLibraryEx($candidate, [IntPtr]::Zero, $loadLibraryFlags)
    if ($handle -eq [IntPtr]::Zero) {
        $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        $message = (New-Object ComponentModel.Win32Exception($errorCode)).Message
        throw "Windows Loader rejected $relativePath (error $errorCode): $message"
    }
    try {
        $loadLibraryResults += $relativePath
    } finally {
        if (-not [GrangerPortableNativeLoader]::FreeLibrary($handle)) {
            throw "Windows Loader could not release $relativePath"
        }
    }
}

$mainExecutable = Join-Path $packageRoot "GrangerBrowser.exe"
$mainPe = $peResults | Where-Object { $_.Path.Equals($mainExecutable, [StringComparison]::OrdinalIgnoreCase) } | Select-Object -First 1
if (-not ([string]$deploymentMetadata.ProductVersion).Equals(
        [string](Get-Item -LiteralPath $mainExecutable).VersionInfo.ProductVersion,
        [StringComparison]::OrdinalIgnoreCase)) {
    throw "Deployment metadata product version does not match GrangerBrowser.exe."
}
[pscustomobject]@{
    OK = $true
    Package = $packageRoot
    PackageFiles = $allFiles.Count
    PeFiles = $peResults.Count
    Machine = "x64 (0x8664)"
    MainSubsystem = "Windows GUI"
    MainSubsystemVersion = $mainPe.SubsystemVersion
    MainLinkerVersion = $mainPe.LinkerVersion
    MainTimestamp = $mainPe.Timestamp
    ImportedLibraries = @($dependencyRows | Select-Object -ExpandProperty Dependency -Unique).Count
    UnresolvedImports = $unresolvedDependencies.Count
    LfsPointers = $lfsPointers.Count
    QmlDebugFiles = $qmlDebugFiles.Count
    QtConfPaths = $qtPaths
    DeploymentMetadata = $deploymentMetadataPath
    LocalRuntimeMetadata = if ($localRuntimeMetadata) { $localRuntimeMetadataPath } else { "" }
    SignedRuntimeFiles = $signedRuntimeFiles.Count
    LoadLibraryChecks = $loadLibraryResults
    ManifestEntries = $manifest.Count
    ExecutableSize = (Get-Item -LiteralPath $mainExecutable).Length
    ExecutableSHA256 = (Get-FileHash -LiteralPath $mainExecutable -Algorithm SHA256).Hash
}
