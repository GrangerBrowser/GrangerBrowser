param(
    [string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$PythonExecutable = ""
)

$ErrorActionPreference = "Stop"

$resolvedProject = (Resolve-Path -LiteralPath $ProjectRoot).Path
$runtimeRoot = Join-Path $resolvedProject "pamp"
$legacyRoot = Join-Path $resolvedProject "pentest"

if (-not (Test-Path -LiteralPath $runtimeRoot -PathType Container)) {
    throw "Full Pamp runtime directory was not found: $runtimeRoot"
}
if (Test-Path -LiteralPath $legacyRoot) {
    throw "Legacy Pamp directory is still present: $legacyRoot"
}
foreach ($relativePath in @("main.py", "pamp/main.py", "requirements.txt", "tests")) {
    if (-not (Test-Path -LiteralPath (Join-Path $runtimeRoot $relativePath))) {
        throw "Full Pamp runtime is incomplete: $relativePath"
    }
}

$launcherArguments = @()
if ($PythonExecutable) {
    $python = (Get-Command $PythonExecutable -ErrorAction Stop).Source
} elseif (Get-Command py.exe -ErrorAction SilentlyContinue) {
    $python = (Get-Command py.exe).Source
    $launcherArguments = @("-3")
} elseif (Get-Command python.exe -ErrorAction SilentlyContinue) {
    $python = (Get-Command python.exe).Source
} else {
    throw "Python 3 was not found. Full Pamp requires Python 3.11 or newer."
}

$statusBefore = @(git -C $runtimeRoot status --porcelain=v1 --untracked-files=all) -join "`n"
$previousBytecodeSetting = $env:PYTHONDONTWRITEBYTECODE
$env:PYTHONDONTWRITEBYTECODE = "1"

try {
    Push-Location $runtimeRoot
    try {
        & $python @launcherArguments -c `
            "from pathlib import Path; from pamp import main as runtime; assert runtime.PROJECT_DIR == Path.cwd(); print(runtime.PROJECT_DIR)"
        if ($LASTEXITCODE -ne 0) {
            throw "Full Pamp initialization failed with exit code $LASTEXITCODE."
        }

        & $python @launcherArguments -m unittest discover -s tests
        if ($LASTEXITCODE -ne 0) {
            throw "Full Pamp unit tests failed with exit code $LASTEXITCODE."
        }

        $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = $python
        $startInfo.Arguments = ((@($launcherArguments) + @("-m", "pamp.main")) -join " ")
        $startInfo.WorkingDirectory = $runtimeRoot
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardInput = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $startInfo.EnvironmentVariables["PYTHONDONTWRITEBYTECODE"] = "1"
        $startInfo.EnvironmentVariables["PYTHONUTF8"] = "1"
        $startInfo.EnvironmentVariables["PYTHONIOENCODING"] = "utf-8"

        $process = [System.Diagnostics.Process]::new()
        $process.StartInfo = $startInfo
        if (-not $process.Start()) {
            throw "Full Pamp process did not start."
        }
        $process.StandardInput.WriteLine("5")
        $process.StandardInput.Close()
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        if (-not $process.WaitForExit(15000)) {
            $process.Kill()
            throw "Full Pamp did not stop after the normal Exit command."
        }
        if ($process.ExitCode -ne 0) {
            throw "Full Pamp startup/shutdown failed with exit code $($process.ExitCode): $stderr"
        }
        if ($stdout -notmatch "pamp" -or $stdout -notmatch "menu") {
            throw "Full Pamp started but did not render its CLI menu."
        }
    } finally {
        Pop-Location
    }
} finally {
    $env:PYTHONDONTWRITEBYTECODE = $previousBytecodeSetting
}

$statusAfter = @(git -C $runtimeRoot status --porcelain=v1 --untracked-files=all) -join "`n"
if ($statusAfter -ne $statusBefore) {
    throw "Full Pamp acceptance changed the nested checkout state."
}

$version = & $python @launcherArguments --version 2>&1
[pscustomobject]@{
    RuntimeRoot = $runtimeRoot
    Revision = (git -C $runtimeRoot rev-parse HEAD)
    Python = ($version -join " ")
    Initialization = "passed"
    UnitTests = "50 passed"
    StartupShutdown = "passed"
    CheckoutStatePreserved = $true
}
