function Resolve-PackageCandidate {
    param(
        [Parameter(Mandatory)][string]$ProjectRoot,
        [Parameter(Mandatory)][string]$Path
    )

    $root = [IO.Path]::GetFullPath((Join-Path $ProjectRoot 'build/package-work')).TrimEnd('\')
    $candidateInput = if ([IO.Path]::IsPathRooted($Path)) { $Path } else { Join-Path $ProjectRoot $Path }
    $candidate = [IO.Path]::GetFullPath($candidateInput).TrimEnd('\')
    if (-not $candidate.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($candidate) -ne 'candidate' -or
        [IO.Path]::GetDirectoryName([IO.Path]::GetDirectoryName($candidate)) -ne $root) {
        throw 'Package destination must be build/package-work/<run>/candidate, outside release.'
    }
    # Lexical containment alone does not protect recursive operations from junctions.
    $parent = $candidate
    $project = [IO.Path]::GetFullPath($ProjectRoot).TrimEnd('\')
    while ($parent -and $parent.Length -ge $project.Length) {
        if ((Test-Path -LiteralPath $parent) -and
            ((Get-Item -LiteralPath $parent -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Package workspace must not contain a reparse point.'
        }
        $parent = [IO.Path]::GetDirectoryName($parent)
    }
    return $candidate
}

function Get-PackageSourceFingerprint {
    param([Parameter(Mandatory)][string]$ProjectRoot)

    $paths = @(& git -C $ProjectRoot -c core.quotepath=false ls-files --cached --others --exclude-standard)
    if ($LASTEXITCODE -ne 0) { throw 'Unable to enumerate the source snapshot.' }
    $records = foreach ($relative in ($paths | Sort-Object -Unique)) {
        $path = Join-Path $ProjectRoot $relative
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            '{0} {1} {2}' -f $relative, (Get-Item -LiteralPath $path).Length,
                (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
        } else {
            "$relative DELETED"
        }
    }
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash(
            [Text.Encoding]::UTF8.GetBytes(($records -join "`n") + "`n")))).Replace('-', '')
    } finally { $sha.Dispose() }
}
