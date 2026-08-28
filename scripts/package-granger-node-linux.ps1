[CmdletBinding()]
param(
    [string]$OutputDirectory = "output/granger-node-linux",
    [string]$WheelCache = "output/granger-node-wheel-cache",
    [string]$Python = ""
)

$ErrorActionPreference = "Stop"
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$outputRoot = [IO.Path]::GetFullPath((Join-Path $projectRoot "output"))
$destination = [IO.Path]::GetFullPath((Join-Path $projectRoot $OutputDirectory))
$cache = [IO.Path]::GetFullPath((Join-Path $projectRoot $WheelCache))
foreach ($path in @($destination, $cache)) {
    if (-not $path.StartsWith($outputRoot + [IO.Path]::DirectorySeparatorChar,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "Granger node package path escaped output: $path"
    }
}
if ([string]::IsNullOrWhiteSpace($Python)) {
    $pythonCommand = Get-Command python.exe -CommandType Application -ErrorAction Stop |
        Select-Object -First 1
    $Python = $pythonCommand.Source
}
if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
    throw "Packaging Python is unavailable: $Python"
}

$wheelSpecs = @(
    [pscustomobject]@{Name="cryptography-49.0.0-cp311-abi3-manylinux_2_28_x86_64.whl"; Hash="2AFE9051DA7AE7BD5905DA5A949280C7D2BB75682E188F650A9D0F2756B834C6"; Package="cryptography==49.0.0"; Platform="manylinux_2_28_x86_64"; Version="311"; Abi="abi3"},
    [pscustomobject]@{Name="cffi-2.0.0-cp311-cp311-manylinux2014_x86_64.manylinux_2_17_x86_64.whl"; Hash="8941AAADAF67246224CEE8C3803777EED332A19D909B47E29C9842EF1E79AC26"; Package="cffi==2.0.0"; Platform="manylinux2014_x86_64"; Version="311"; Abi="cp311"},
    [pscustomobject]@{Name="cffi-2.0.0-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.whl"; Hash="3E17ED538242334BF70832644A32A7AAE3D83B57567F9FD60A26257E992B79BA"; Package="cffi==2.0.0"; Platform="manylinux2014_x86_64"; Version="312"; Abi="cp312"},
    [pscustomobject]@{Name="cffi-2.0.0-cp313-cp313-manylinux2014_x86_64.manylinux_2_17_x86_64.whl"; Hash="C8D3B5532FC71B7A77C09192B4A5A200EA992702734A2E9279A37F2478236F26"; Package="cffi==2.0.0"; Platform="manylinux2014_x86_64"; Version="313"; Abi="cp313"},
    [pscustomobject]@{Name="cffi-2.0.0-cp314-cp314-manylinux2014_x86_64.manylinux_2_17_x86_64.whl"; Hash="AFB8DB5439B81CF9C9D0C80404B60C3CC9C3ADD93E114DCAE767F1477CB53775"; Package="cffi==2.0.0"; Platform="manylinux2014_x86_64"; Version="314"; Abi="cp314"},
    [pscustomobject]@{Name="pycparser-2.23-py3-none-any.whl"; Hash="E5C6E8D3FBAD53479CAB09AC03729E0A9FAF2BEE3DB8208A550DAF5AF81A5934"; Package="pycparser==2.23"; Platform="any"; Version="311"; Abi="none"}
)
New-Item -ItemType Directory -Path $cache -Force | Out-Null
foreach ($spec in $wheelSpecs) {
    $wheel = Join-Path $cache $spec.Name
    $valid = (Test-Path -LiteralPath $wheel -PathType Leaf) -and
        ((Get-FileHash -LiteralPath $wheel -Algorithm SHA256).Hash -eq $spec.Hash)
    if (-not $valid) {
        if (Test-Path -LiteralPath $wheel) { Remove-Item -LiteralPath $wheel -Force }
        $arguments = @("-m", "pip", "download", "--disable-pip-version-check", "--no-deps",
            "--dest", $cache, "--only-binary=:all:")
        if ($spec.Platform -ne "any") {
            $arguments += @("--platform", $spec.Platform, "--implementation", "cp",
                "--python-version", $spec.Version, "--abi", $spec.Abi)
        }
        $arguments += $spec.Package
        & $Python @arguments
        if ($LASTEXITCODE -ne 0) { throw "Unable to acquire pinned wheel: $($spec.Name)" }
    }
    if (-not (Test-Path -LiteralPath $wheel -PathType Leaf) -or
        (Get-FileHash -LiteralPath $wheel -Algorithm SHA256).Hash -ne $spec.Hash) {
        throw "Pinned wheel hash mismatch: $($spec.Name)"
    }
}

$staging = Join-Path $outputRoot (".granger-node-linux-staging-" + $PID)
foreach ($target in @($staging, $destination)) {
    $full = [IO.Path]::GetFullPath($target)
    if (-not $full.StartsWith($outputRoot + [IO.Path]::DirectorySeparatorChar,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "Unsafe package target: $full"
    }
    if ([IO.Directory]::Exists($full)) { [IO.Directory]::Delete($full, $true) }
}
New-Item -ItemType Directory -Path $staging -Force | Out-Null
$template = Join-Path $projectRoot "GrangerNetwork/operator/linux"
Copy-Item -Path (Join-Path $template "*") -Destination $staging -Recurse -Force
New-Item -ItemType Directory -Path (Join-Path $staging "runtime/src") -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $projectRoot "GrangerNetwork/src/granger_network") `
    -Destination (Join-Path $staging "runtime/src/granger_network") -Recurse -Force
New-Item -ItemType Directory -Path (Join-Path $staging "runtime/wheels") -Force | Out-Null
foreach ($spec in $wheelSpecs) {
    Copy-Item -LiteralPath (Join-Path $cache $spec.Name) `
        -Destination (Join-Path $staging "runtime/wheels/$($spec.Name)")
}
New-Item -ItemType Directory -Path (Join-Path $staging "tools") -Force | Out-Null
foreach ($tool in @("operator_bundle.py", "reseed_tool.py", "wan_config_tool.py")) {
    Copy-Item -LiteralPath (Join-Path $projectRoot "GrangerNetwork/tools/$tool") `
        -Destination (Join-Path $staging "tools/$tool")
}
New-Item -ItemType Directory -Path (Join-Path $staging "windows") -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $projectRoot "GrangerNetwork/operator/windows/install-granger-bootstrap.ps1") `
    -Destination (Join-Path $staging "windows/install-granger-bootstrap.ps1")
Copy-Item -LiteralPath (Join-Path $projectRoot "NOTICE.txt") -Destination (Join-Path $staging "NOTICE.txt")
foreach ($directory in @("state", "private", "public", "run", "logs")) {
    New-Item -ItemType Directory -Path (Join-Path $staging $directory) -Force | Out-Null
}
Get-ChildItem -LiteralPath $staging -Recurse -Directory -Filter "__pycache__" | ForEach-Object {
    [IO.Directory]::Delete($_.FullName, $true)
}
Get-ChildItem -LiteralPath $staging -Recurse -File -Include "*.pyc" | Remove-Item -Force
foreach ($script in @(
        Get-ChildItem -LiteralPath $staging -File -Filter "*.sh"
        Get-Item -LiteralPath (Join-Path $staging "granger-node")
    )) {
    $content = [IO.File]::ReadAllText($script.FullName).Replace("`r`n", "`n")
    [IO.File]::WriteAllText($script.FullName, $content, [Text.UTF8Encoding]::new($false))
}

$head = (& git -C $projectRoot rev-parse HEAD).Trim()
$manifest = [ordered]@{
    architecture = "x86_64"
    bundledPythonDependencies = [ordered]@{
        cffi = "2.0.0"
        cryptography = "49.0.0"
        pycparser = "2.23"
    }
    grangerNodePort = 62441
    networkId = "granger-network-v0.4"
    deploymentModes = @("distributed-public-router", "single-physical-host-test-topology")
    logicalRouterCount = 4
    physicalLinuxStart = "UNVERIFIED"
    protocolVersion = 3
    publicWan = "UNVERIFIED"
    sourceHead = $head
    version = 1
}
$manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $staging "package-manifest.json") -Encoding utf8NoBOM

$forbidden = Get-ChildItem -LiteralPath $staging -Recurse -File | Where-Object {
    $_.FullName -match '[\\/](state|private)[\\/].+' -or
    $_.Name -in @("node-identity.json", "bootstrap-authority.json", "config-authority.json")
}
if ($forbidden) { throw "Private operator state entered the public package." }
$checksumPath = Join-Path $staging "SHA256SUMS.txt"
$checksums = Get-ChildItem -LiteralPath $staging -Recurse -File | Where-Object {
    $_.FullName -ne $checksumPath
} | ForEach-Object {
    $relative = [IO.Path]::GetRelativePath($staging, $_.FullName).Replace('\', '/')
    "{0}  {1}" -f (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), $relative
} | Sort-Object
[IO.File]::WriteAllText($checksumPath, (($checksums -join "`n") + "`n"), [Text.UTF8Encoding]::new($false))
Move-Item -LiteralPath $staging -Destination $destination
$measure = Get-ChildItem -LiteralPath $destination -Recurse -File | Measure-Object -Property Length -Sum
[pscustomobject]@{
    Files = $measure.Count
    Output = $destination
    SizeBytes = $measure.Sum
    SourceHead = $head
    PhysicalLinuxStart = "UNVERIFIED"
    PublicWan = "UNVERIFIED"
} | ConvertTo-Json
