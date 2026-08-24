[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$SourceDirectory
)

$ErrorActionPreference = "Stop"
$sourceRoot = [IO.Path]::GetFullPath($SourceDirectory).TrimEnd('\')
if (-not (Test-Path -LiteralPath $sourceRoot -PathType Container)) {
    throw "Granger Network source directory was not found: $sourceRoot"
}

$versionPath = Join-Path $sourceRoot "__init__.py"
if (-not (Test-Path -LiteralPath $versionPath -PathType Leaf)) {
    throw "Granger Network version source is missing: $versionPath"
}
$versionContent = Get-Content -LiteralPath $versionPath -Raw -Encoding UTF8
$versionMatches = [regex]::Matches(
    $versionContent,
    '(?m)^__version__\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"\s*$'
)
if ($versionMatches.Count -ne 1) {
    throw "Granger Network must declare exactly one semantic __version__."
}
$version = $versionMatches[0].Groups[1].Value

$files = @(Get-ChildItem -LiteralPath $sourceRoot -Recurse -File | Where-Object {
    $_.Extension.Equals(".py", [StringComparison]::OrdinalIgnoreCase) -and
    $_.FullName.StartsWith($sourceRoot + '\', [StringComparison]::OrdinalIgnoreCase)
} | ForEach-Object {
    $relativePath = $_.FullName.Substring($sourceRoot.Length).TrimStart('\').Replace('\', '/')
    [pscustomobject]@{
        Path = $relativePath
        FullName = $_.FullName
        Size = $_.Length
    }
} | Sort-Object Path)
if ($files.Count -eq 0) {
    throw "Granger Network source directory contains no Python modules."
}

$canonical = New-Object Text.StringBuilder
$records = foreach ($file in $files) {
    $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToUpperInvariant()
    [void]$canonical.Append($file.Path)
    [void]$canonical.Append([char]0)
    [void]$canonical.Append($hash)
    [void]$canonical.Append("`n")
    [ordered]@{
        Path = $file.Path
        Size = [long]$file.Size
        SHA256 = $hash
    }
}
$algorithm = [Security.Cryptography.SHA256]::Create()
try {
    $digest = $algorithm.ComputeHash([Text.Encoding]::UTF8.GetBytes($canonical.ToString()))
} finally {
    $algorithm.Dispose()
}
$identityHash = [BitConverter]::ToString($digest).Replace("-", "")

[pscustomobject]@{
    Version = $version
    SHA256 = $identityHash
    FileCount = $records.Count
    Files = @($records)
}
