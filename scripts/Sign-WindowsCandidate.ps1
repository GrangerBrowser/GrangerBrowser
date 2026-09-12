[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$CertificateThumbprint,
    [Parameter(Mandatory)][uri]$TimestampUrl,
    [Parameter(Mandatory)][string]$SignToolPath
)

$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..')).TrimEnd('\')
$file = Get-Item -LiteralPath $Path
$allowed = @('build\', 'release\.local-staging\', 'output\signing-candidate\')
if ($file.PSIsContainer -or $file.Name -notin @('GrangerBrowser.exe', 'GrangerSetup.exe') -or
    -not ($allowed | Where-Object { $file.FullName.StartsWith((Join-Path $root $_), [StringComparison]::OrdinalIgnoreCase) })) {
    throw 'Only project-owned executables inside isolated build/candidate directories may be signed.'
}
if ($TimestampUrl.Scheme -ne 'https' -or $TimestampUrl.UserInfo -or $TimestampUrl.Fragment) {
    throw 'Pass the owner-approved HTTPS RFC 3161 timestamp endpoint without credentials.'
}
$tool = Get-Item -LiteralPath $SignToolPath
$toolSignature = Get-AuthenticodeSignature -LiteralPath $tool.FullName
if ($toolSignature.Status -ne 'Valid' -or $toolSignature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
    throw 'The signing tool must be an official trusted Microsoft SignTool.'
}
$certificate = Get-Item -LiteralPath "Cert:\CurrentUser\My\$CertificateThumbprint" -ErrorAction SilentlyContinue
if (-not $certificate -or -not $certificate.HasPrivateKey -or
    $certificate.NotBefore -gt (Get-Date) -or $certificate.NotAfter -le (Get-Date) -or
    -not ($certificate.EnhancedKeyUsageList | Where-Object { $_.ObjectId -eq '1.3.6.1.5.5.7.3.3' })) {
    throw 'A valid owner-provisioned code-signing certificate/provider is required. No certificate will be generated.'
}
if ($PSCmdlet.ShouldProcess($file.FullName, 'Sign and timestamp with the explicit certificate-store identity')) {
    & $tool.FullName sign /sha1 $CertificateThumbprint /s My /fd SHA256 /tr $TimestampUrl.AbsoluteUri /td SHA256 $file.FullName
    if ($LASTEXITCODE -ne 0) { throw 'SignTool signing failed; do not package or promote this candidate.' }
    & $tool.FullName verify /pa /all /tw $file.FullName
    if ($LASTEXITCODE -ne 0) { throw 'SignTool verification failed; do not package or promote this candidate.' }
    & (Join-Path $PSScriptRoot 'Test-WindowsArtifactTrust.ps1') -Path $file.FullName `
        -ExpectedCertificateThumbprint $CertificateThumbprint -RequireTrustedSignature
}
