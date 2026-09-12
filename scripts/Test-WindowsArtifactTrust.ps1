[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string[]]$Path,
    [string]$ExpectedCertificateThumbprint = '',
    [switch]$RequireTrustedSignature
)

$ErrorActionPreference = 'Stop'
if ($ExpectedCertificateThumbprint -and $ExpectedCertificateThumbprint -notmatch '^[A-Fa-f0-9]{40}$') {
    throw 'ExpectedCertificateThumbprint must be the public certificate SHA-1 identifier.'
}
$failed = $false
foreach ($item in $Path) {
    $file = Get-Item -LiteralPath $item
    if ($file.PSIsContainer) { throw 'An artifact must be a file.' }
    $signature = Get-AuthenticodeSignature -LiteralPath $file.FullName
    $publisherMatches = -not $ExpectedCertificateThumbprint -or (
        $null -ne $signature.SignerCertificate -and
        $signature.SignerCertificate.Thumbprint -eq $ExpectedCertificateThumbprint
    )
    $trusted = $signature.Status -eq 'Valid' -and $publisherMatches
    $timestampPresent = $null -ne $signature.TimeStamperCertificate
    [pscustomobject]@{
        Path = $file.FullName
        Size = $file.Length
        SHA256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
        Signature = [string]$signature.Status
        Publisher = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { '' }
        CertificateThumbprint = if ($signature.SignerCertificate) { $signature.SignerCertificate.Thumbprint } else { '' }
        ExpectedPublisherMatches = $publisherMatches
        TimestampPresent = $timestampPresent
        WindowsTrustValid = $trusted
        SmartScreenReputation = 'UNVERIFIED'
    }
    if (-not $trusted -or -not $timestampPresent) { $failed = $true }
}
if ($RequireTrustedSignature -and $failed) {
    throw 'Artifact trust gate failed: a valid expected publisher and timestamp are required.'
}
