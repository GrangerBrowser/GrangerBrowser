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

$requiredFiles = @(
    "GrangerBrowser.exe",
    "QtWebEngineProcess.exe",
    "Qt6Core.dll",
    "Qt6Gui.dll",
    "Qt6Network.dll",
    "Qt6Widgets.dll",
    "Qt6WebEngineCore.dll",
    "Qt6WebEngineWidgets.dll",
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
    "release-manifest.json"
)
foreach ($relativePath in $requiredFiles) {
    if (-not (Test-Path -LiteralPath (Join-Path $packageRoot $relativePath) -PathType Leaf)) {
        throw "Portable package is missing $relativePath"
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
        $systemDirectory = Join-Path $env:SystemRoot "System32\$dependency"
        $resolution = if (Test-Path -LiteralPath $sameDirectory -PathType Leaf) {
            "same-directory"
        } elseif (Test-Path -LiteralPath $packageDirectory -PathType Leaf) {
            "package-root"
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

$mainExecutable = Join-Path $packageRoot "GrangerBrowser.exe"
$mainPe = $peResults | Where-Object { $_.Path.Equals($mainExecutable, [StringComparison]::OrdinalIgnoreCase) } | Select-Object -First 1
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
    ManifestEntries = $manifest.Count
    ExecutableSize = (Get-Item -LiteralPath $mainExecutable).Length
    ExecutableSHA256 = (Get-FileHash -LiteralPath $mainExecutable -Algorithm SHA256).Hash
}
