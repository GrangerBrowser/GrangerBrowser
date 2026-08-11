param(
    [Parameter(Mandatory = $true)]
    [string[]]$ReportPath,
    [string]$OutputPath = ""
)

$ErrorActionPreference = "Stop"

function Get-Sha256([string]$Value) {
    $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($algorithm.ComputeHash($bytes))).Replace("-", "").ToLowerInvariant()
    } finally {
        $algorithm.Dispose()
    }
}

function Get-Stage($Report, [string]$Id) {
    return @($Report.stages | Where-Object { $_.id -eq $Id }) | Select-Object -First 1
}

function Get-ComparableSurface($Report) {
    $javascript = Get-Stage $Report "javascript"
    $fonts = Get-Stage $Report "fonts"
    $probe = $javascript.probe
    [ordered]@{
        strictEvidence = $Report.strictEvidence
        userAgent = $probe.userAgent
        appVersion = $probe.appVersion
        platform = $probe.platform
        language = $probe.language
        languages = @($probe.languages)
        intlLocale = $probe.intlLocale
        timezone = $probe.timezone
        timezoneOffset = $probe.timezoneOffset
        hardwareConcurrency = $probe.hardwareConcurrency
        deviceMemoryType = $probe.deviceMemoryType
        screen = $probe.screen
        viewport = $probe.viewport
        userAgentData = $probe.userAgentData
        pluginsLength = $probe.pluginsLength
        mimeTypesLength = $probe.mimeTypesLength
        canvasReadback = $probe.canvasReadback
        webgl = $probe.webgl
        webgl2 = $probe.webgl2
        webRtcType = $probe.webRtcType
        workerType = $probe.workerType
        sharedWorkerType = $probe.sharedWorkerType
        serviceWorkerType = $probe.serviceWorkerType
        audioContextType = $probe.audioContextType
        offlineAudioContextType = $probe.offlineAudioContextType
        batteryType = $probe.batteryType
        bluetoothType = $probe.bluetoothType
        gpuType = $probe.gpuType
        localFontsType = $probe.localFontsType
        networkInformationType = $probe.networkInformationType
        fontMetricsHash = $fonts.probe.browserLeaks.fontMetricsHash
        fontGlyphsHash = $fonts.probe.browserLeaks.fontGlyphsHash
        fontMetricsReport = $fonts.probe.browserLeaks.fontMetricsReport
        tlsJa3Normalized = $Report.tls.ja3n_hash
        tlsJa4 = $Report.tls.ja4
        http2AkamaiHash = $Report.tls.akamai_hash
    }
}

$items = @()
foreach ($path in $ReportPath) {
    $resolved = (Resolve-Path -LiteralPath $path).Path
    $report = Get-Content -Raw -LiteralPath $resolved | ConvertFrom-Json
    $surface = Get-ComparableSurface $report
    $canonical = $surface | ConvertTo-Json -Depth 20 -Compress
    $valid = [bool]$report.ok -and [bool]$report.routeVerified -and [bool]$report.torConfirmed `
        -and [bool]$report.corePolicyConfirmed -and -not [bool]$report.productionPolicyModifiedForAudit
    $items += [ordered]@{
        path = $resolved
        valid = $valid
        routeVerified = [bool]$report.routeVerified
        torConfirmed = [bool]$report.torConfirmed
        signature = Get-Sha256 $canonical
        surface = $surface
    }
}

$signatures = @($items | ForEach-Object { $_.signature } | Sort-Object -Unique)
$allValid = @($items | Where-Object { -not $_.valid }).Count -eq 0
$uniform = $signatures.Count -eq 1
$crossDeviceValidated = $items.Count -ge 2 -and $allValid -and $uniform
$result = [ordered]@{
    schema = "granger-cross-device-privacy-comparison-v1"
    generatedAtUtc = [DateTime]::UtcNow.ToString("o")
    reportCount = $items.Count
    allReportsValid = $allValid
    comparableSurfaceUniform = $uniform
    crossDeviceValidated = $crossDeviceValidated
    status = if ($items.Count -lt 2) { "pending-second-device" }
             elseif ($crossDeviceValidated) { "matched" }
             else { "different-or-invalid" }
    reports = $items
    excludedRouteSpecificFields = @("exitIp", "Tor circuit", "DNS resolver rows")
    limitations = @(
        "Reports must be captured on physically distinct Windows computers with the same Granger build and audit window size.",
        "A matching surface reduces observed variance; it does not prove anonymity or eliminate network-layer fingerprinting.",
        "TLS comparison uses normalized JA3 plus JA4 and HTTP/2 hashes because extension order may vary per connection."
    )
}

$json = $result | ConvertTo-Json -Depth 30
if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    $fullOutput = [IO.Path]::GetFullPath($OutputPath)
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($fullOutput)) | Out-Null
    [IO.File]::WriteAllText($fullOutput, $json, [Text.UTF8Encoding]::new($false))
}
$json

if (-not $allValid -or ($items.Count -ge 2 -and -not $uniform)) { exit 1 }
