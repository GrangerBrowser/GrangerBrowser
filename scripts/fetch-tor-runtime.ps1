[CmdletBinding()]
param(
    [string]$ArchivePath = "output/third-party/tor-download/tor-expert-bundle-windows-x86_64-15.0.20.tar.gz",
    [string]$Destination = "output/tor-runtime"
)

$ErrorActionPreference = "Stop"
$projectRoot = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot)).TrimEnd('\')
$bundleVersion = "15.0.20"
$torVersion = "0.4.9.11"
$lyrebirdVersion = "0.8.1"
$assetName = "tor-expert-bundle-windows-x86_64-$bundleVersion.tar.gz"
$assetBaseUrl = "https://archive.torproject.org/tor-package-archive/torbrowser/$bundleVersion"
$assetUrl = "$assetBaseUrl/$assetName"
$signatureUrl = "$assetUrl.asc"
$signingKeyUrl = "https://openpgpkey.torproject.org/.well-known/openpgpkey/torproject.org/hu/kounek7zrdx745qydx6p59t9mqjpuhdf"
$expectedArchiveSha256 = "D59BFF934E3AD876E1623E24AE60C19AEEA56F50178093B9F86FBA230639F949"
$expectedSignatureSha256 = "84DD299F9ECEF112891C71DAED709DBE8F2E226FD88B868DB43898DBE3A83F0D"
$expectedSigningKeySha256 = "C2ED2CB463BF384630F2C746448399AB944C3AEADE4619F940F07372A57780D7"
$signingKeyFingerprint = "EF6E286DDA85EA2A4BA7DE684E2C6E8793298290"
$expectedFiles = [ordered]@{
    "tor/tor.exe" = "EA61BA0ED5B89D0622D2894B2A86F5FF34CE9B48E6E40D64341E7C0C7EE03E08"
    "tor/pluggable_transports/lyrebird.exe" = "83D4D39D438A36066AF5161806A448B5D099033DDA901ECD0B2663EC58A5790F"
    "tor/pluggable_transports/conjure-client.exe" = "6FB2DCE9803157A6B871D6B5CD644B4D216350D81623E5548B887040DA1BA5CB"
    "tor/pluggable_transports/pt_config.json" = "3F11D303C30191B3B1D382B9BADD882D87FD87550D061F7D25A1B31226FC9B75"
    "data/geoip" = "AF9CCD060A712D090EE07D5678B5D45B0038EC1573116FAE724A6695A8485703"
    "data/geoip6" = "2393124667BA2CCB4C806F226A33B2EF7A8188D1BA55831C1A5D3DCA2B062514"
}

function Resolve-WorkspaceOutputPath {
    param([Parameter(Mandatory)][string]$Path)
    $resolved = if ([IO.Path]::IsPathRooted($Path)) {
        [IO.Path]::GetFullPath($Path)
    } else {
        [IO.Path]::GetFullPath((Join-Path $projectRoot $Path))
    }
    $outputRoot = [IO.Path]::GetFullPath((Join-Path $projectRoot "output")).TrimEnd('\')
    if (-not $resolved.StartsWith($outputRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Tor build inputs must remain under the ignored output directory: $resolved"
    }
    return $resolved
}

function Receive-PinnedFile {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$ExpectedSha256
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        $partial = "$Path.part"
        if (Test-Path -LiteralPath $partial) { Remove-Item -LiteralPath $partial -Force }
        Invoke-WebRequest -Uri $Uri -OutFile $partial -UseBasicParsing
        Move-Item -LiteralPath $partial -Destination $Path
    }
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    if (-not $actual.Equals($ExpectedSha256, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Pinned Tor download hash mismatch for $(Split-Path -Leaf $Path). Expected $ExpectedSha256, got $actual"
    }
    return $actual
}

function Find-Gpg {
    $command = Get-Command gpg.exe -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    $candidates = @(
        (Join-Path $env:ProgramFiles "Git/usr/bin/gpg.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "GnuPG/bin/gpg.exe"),
        (Join-Path $env:ProgramFiles "GnuPG/bin/gpg.exe")
    )
    return $candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
}

$archive = Resolve-WorkspaceOutputPath $ArchivePath
$downloadRoot = Split-Path -Parent $archive
$runtimeRoot = Resolve-WorkspaceOutputPath $Destination
$signature = Join-Path $downloadRoot "$assetName.asc"
$signingKey = Join-Path $downloadRoot "tor-browser-developers-key.gpg"
New-Item -ItemType Directory -Path $downloadRoot -Force | Out-Null

$archiveSha256 = Receive-PinnedFile -Uri $assetUrl -Path $archive -ExpectedSha256 $expectedArchiveSha256
$signatureSha256 = Receive-PinnedFile -Uri $signatureUrl -Path $signature -ExpectedSha256 $expectedSignatureSha256
$signingKeySha256 = Receive-PinnedFile -Uri $signingKeyUrl -Path $signingKey -ExpectedSha256 $expectedSigningKeySha256

$gpg = Find-Gpg
if ([string]::IsNullOrWhiteSpace($gpg)) {
    throw "GnuPG is required to validate the Tor Browser Developers signature."
}
$gpgHomeName = ".gnupg-tor-$bundleVersion"
$gpgHome = Join-Path $downloadRoot $gpgHomeName
if (Test-Path -LiteralPath $gpgHome) { Remove-Item -LiteralPath $gpgHome -Recurse -Force }
New-Item -ItemType Directory -Path $gpgHome | Out-Null
Push-Location $downloadRoot
try {
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        # GnuPG writes normal status messages to stderr. Capture them and rely on
        # its exit code and machine-readable status records for validation.
        $ErrorActionPreference = "Continue"
        $importOutput = (& $gpg --batch --no-autostart --homedir "./$gpgHomeName" `
            --import "./$(Split-Path -Leaf $signingKey)" 2>&1 | Out-String)
        $fingerprints = (& $gpg --batch --no-autostart --homedir "./$gpgHomeName" `
            --with-colons --fingerprint 2>&1 | Out-String)
        if ($LASTEXITCODE -ne 0 -or $fingerprints -notmatch "fpr:::::::::${signingKeyFingerprint}:") {
            throw "The imported Tor signing key fingerprint did not match $signingKeyFingerprint. Import output: $importOutput"
        }
        $verifyOutput = (& $gpg --batch --no-autostart --homedir "./$gpgHomeName" --status-fd 1 --verify `
            "./$(Split-Path -Leaf $signature)" "./$(Split-Path -Leaf $archive)" 2>&1 | Out-String)
        if ($LASTEXITCODE -ne 0 -or $verifyOutput -notmatch '\[GNUPG:\] VALIDSIG ' -or
            $verifyOutput -notmatch $signingKeyFingerprint) {
            throw "Tor archive signature validation failed: $verifyOutput"
        }
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
} finally {
    Pop-Location
    if (Test-Path -LiteralPath $gpgHome) { Remove-Item -LiteralPath $gpgHome -Recurse -Force }
}

$entries = @(& tar.exe -tf $archive)
if ($LASTEXITCODE -ne 0 -or $entries.Count -lt $expectedFiles.Count) {
    throw "Unable to enumerate the signed Tor archive."
}
foreach ($entry in $entries) {
    $normalized = ([string]$entry).Replace('\', '/')
    if ($normalized.StartsWith('/') -or $normalized -match '(^|/)\.\.(/|$)') {
        throw "The signed Tor archive contains an unsafe path: $entry"
    }
}

$extractRoot = Resolve-WorkspaceOutputPath "output/third-party/tor-extract-$bundleVersion"
if (Test-Path -LiteralPath $extractRoot) { Remove-Item -LiteralPath $extractRoot -Recurse -Force }
New-Item -ItemType Directory -Path $extractRoot | Out-Null
& tar.exe -xf $archive -C $extractRoot
if ($LASTEXITCODE -ne 0) { throw "Unable to extract the signed Tor archive." }

foreach ($entry in $expectedFiles.GetEnumerator()) {
    $path = Join-Path $extractRoot $entry.Key
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "The signed Tor archive does not contain $($entry.Key)."
    }
    $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    if (-not $actual.Equals($entry.Value, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Unexpected hash for $($entry.Key). Expected $($entry.Value), got $actual"
    }
}

$torOutput = (& (Join-Path $extractRoot "tor/tor.exe") --version 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $torOutput -notmatch "(?m)^Tor version $([regex]::Escape($torVersion))\b") {
    throw "Unexpected Tor runtime version: $torOutput"
}
$lyrebirdOutput = (& (Join-Path $extractRoot "tor/pluggable_transports/lyrebird.exe") --version 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $lyrebirdOutput -notmatch "(?m)^lyrebird $([regex]::Escape($lyrebirdVersion))\b") {
    throw "Unexpected lyrebird runtime version: $lyrebirdOutput"
}
$conjureBytes = [IO.File]::ReadAllBytes((Join-Path $extractRoot "tor/pluggable_transports/conjure-client.exe"))
$conjureText = [Text.Encoding]::ASCII.GetString($conjureBytes)
$conjureGoVersion = [regex]::Match($conjureText, 'go1\.[0-9.]+').Value
if ($conjureText -notmatch 'mod\tgitlab\.torproject\.org/tpo/anti-censorship/pluggable-transports/conjure\t\(devel\)' -or
    [string]::IsNullOrWhiteSpace($conjureGoVersion)) {
    throw "Unable to validate the bundled Conjure client build metadata."
}

if (Test-Path -LiteralPath $runtimeRoot) { Remove-Item -LiteralPath $runtimeRoot -Recurse -Force }
New-Item -ItemType Directory -Path $runtimeRoot | Out-Null
foreach ($directory in @("data", "docs", "tor")) {
    Copy-Item -LiteralPath (Join-Path $extractRoot $directory) -Destination $runtimeRoot -Recurse
}
Remove-Item -LiteralPath $extractRoot -Recurse -Force

[pscustomobject]@{
    OK = $true
    BundleVersion = $bundleVersion
    TorVersion = $torVersion
    LyrebirdVersion = $lyrebirdVersion
    ConjureVersion = "devel"
    ConjureGoVersion = $conjureGoVersion
    Source = $assetUrl
    SignatureSource = $signatureUrl
    SigningKeySource = $signingKeyUrl
    SigningKeyFingerprint = $signingKeyFingerprint
    SignatureVerified = $true
    Archive = $archive
    ArchiveSHA256 = $archiveSha256
    SignatureSHA256 = $signatureSha256
    SigningKeySHA256 = $signingKeySha256
    RuntimeRoot = $runtimeRoot
    TorSHA256 = $expectedFiles["tor/tor.exe"]
    LyrebirdSHA256 = $expectedFiles["tor/pluggable_transports/lyrebird.exe"]
    ConjureSHA256 = $expectedFiles["tor/pluggable_transports/conjure-client.exe"]
    GeoIpSHA256 = $expectedFiles["data/geoip"]
    GeoIp6SHA256 = $expectedFiles["data/geoip6"]
    TorLicense = "GPL-3.0-or-later"
    LyrebirdLicense = "BSD-3-Clause"
}
