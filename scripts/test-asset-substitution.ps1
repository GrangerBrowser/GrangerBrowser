[CmdletBinding()]
param(
    [string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$PackageDirectory = "release/Granger Browser"
)

$ErrorActionPreference = "Stop"

$resolvedProject = [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $ProjectRoot).Path).TrimEnd('\')
$packageRoot = [IO.Path]::GetFullPath((Join-Path $resolvedProject $PackageDirectory)).TrimEnd('\')
if (-not $packageRoot.StartsWith($resolvedProject + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw "Package directory escaped the project workspace."
}

$executable = Join-Path $packageRoot "GrangerBrowser.exe"
if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
    throw "Packaged executable was not found: $executable"
}

$fakeSupport = Join-Path $packageRoot "Support-block"
$fakeChat = Join-Path $packageRoot "Chat-bot"
if ((Test-Path -LiteralPath $fakeSupport) -or (Test-Path -LiteralPath $fakeChat)) {
    throw "Refusing to replace pre-existing asset directories next to the executable."
}

$testRoot = Join-Path $resolvedProject "output/fake-asset-substitution"
$resultPath = Join-Path $testRoot "ui-focus.json"
$capturePath = Join-Path $testRoot "captures"
$dataRoot = Join-Path $testRoot "data"
$settingsRoot = Join-Path $testRoot "settings"
$downloadRoot = Join-Path $testRoot "downloads"
$unrelatedCwd = Join-Path $testRoot "unrelated-cwd"
if (Test-Path -LiteralPath $testRoot) {
    Remove-Item -LiteralPath $testRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $fakeSupport,$fakeChat,$dataRoot,$settingsRoot,$downloadRoot,$unrelatedCwd -Force | Out-Null

$fakePayload = [Text.Encoding]::UTF8.GetBytes("FAKE EXTERNAL ASSET - MUST NEVER BE LOADED")
foreach ($name in @(
    "bitcoin.png", "CryptoBot_QR.jpg", "EmmaWatson.gif", "Ethereum Eth-1.png",
    "Gram.png", "Solana Sol.png", "trc20.png"
)) {
    [IO.File]::WriteAllBytes((Join-Path $fakeSupport $name), $fakePayload)
}
[IO.File]::WriteAllBytes((Join-Path $fakeChat "icons8-chatbot-64.png"), $fakePayload)

$oldEnvironment = @{
    PATH = $env:PATH
    GRANGER_DATA_ROOT = $env:GRANGER_DATA_ROOT
    GRANGER_SETTINGS_ROOT = $env:GRANGER_SETTINGS_ROOT
    GRANGER_DOWNLOAD_ROOT = $env:GRANGER_DOWNLOAD_ROOT
}

try {
    $env:PATH = "$(Join-Path $env:SystemRoot 'System32');$env:SystemRoot"
    $env:GRANGER_DATA_ROOT = $dataRoot
    $env:GRANGER_SETTINGS_ROOT = $settingsRoot
    $env:GRANGER_DOWNLOAD_ROOT = $downloadRoot

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $executable
    $startInfo.WorkingDirectory = $unrelatedCwd
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $arguments = @(
        "--smoke-ui-focus",
        "--smoke-output=$resultPath",
        "--smoke-capture-dir=$capturePath"
    )
    $startInfo.Arguments = ($arguments | ForEach-Object { '"' + $_.Replace('"', '\"') + '"' }) -join ' '

    $process = [Diagnostics.Process]::Start($startInfo)
    if (-not $process.WaitForExit(600000)) {
        $process.Kill()
        throw "Fake-asset substitution smoke timed out."
    }
    if ($process.ExitCode -ne 0) {
        throw "Fake-asset substitution smoke failed with exit code $($process.ExitCode)."
    }
    if (-not (Test-Path -LiteralPath $resultPath -PathType Leaf)) {
        throw "Fake-asset substitution smoke did not produce a result."
    }

    $result = Get-Content -Raw -Encoding UTF8 -LiteralPath $resultPath | ConvertFrom-Json
    if (-not $result.ok) {
        $failed = @($result.cases | Where-Object { -not $_.passed } | ForEach-Object { $_.name })
        throw "Fake-asset substitution smoke reported failures: $($failed -join ', ')"
    }

    $requiredCases = @(
        "AI Chat icon is the integrity-checked supplied 64x64 asset",
        "all five project-support icons are exact compiled RGBA resources",
        "project-support banner preserves the supplied 37-frame GIF",
        "start page uses compiled wallpaper, provider icon, and AI icon only",
        "project-support Settings page is local, aligned, accessible, and responsive",
        "all five support actions copy the exact native-owned addresses"
    )
    foreach ($name in $requiredCases) {
        $case = @($result.cases | Where-Object { $_.name -eq $name })
        if ($case.Count -ne 1 -or -not $case[0].passed) {
            throw "Required embedded-asset case did not pass: $name"
        }
    }

    $aiCase = @($result.cases | Where-Object {
        $_.name -eq "AI Chat icon is the integrity-checked supplied 64x64 asset"
    })[0]
    if ($aiCase.actual -ne "8D8EC69A2CAC4ECE41F937BB838270B1016D0212FFBFEA0BA5E61F88E327A1F7") {
        throw "AI Chat rendered an unexpected asset hash."
    }
} finally {
    $env:PATH = $oldEnvironment.PATH
    $env:GRANGER_DATA_ROOT = $oldEnvironment.GRANGER_DATA_ROOT
    $env:GRANGER_SETTINGS_ROOT = $oldEnvironment.GRANGER_SETTINGS_ROOT
    $env:GRANGER_DOWNLOAD_ROOT = $oldEnvironment.GRANGER_DOWNLOAD_ROOT
    if (Test-Path -LiteralPath $fakeSupport) {
        Remove-Item -LiteralPath $fakeSupport -Recurse -Force
    }
    if (Test-Path -LiteralPath $fakeChat) {
        Remove-Item -LiteralPath $fakeChat -Recurse -Force
    }
}

if ((Test-Path -LiteralPath $fakeSupport) -or (Test-Path -LiteralPath $fakeChat)) {
    throw "Fake asset directories were not removed after acceptance."
}

[pscustomobject]@{
    Package = $packageRoot
    Result = $resultPath
    EmbeddedCasesPassed = $requiredCases.Count
    FakeSupportRemoved = $true
    FakeChatRemoved = $true
}
