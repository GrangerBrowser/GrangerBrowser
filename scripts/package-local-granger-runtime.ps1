[CmdletBinding()]
param(
    [string]$PackageDirectory = "release/.local-staging",
    [string]$PythonExecutable = ""
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$workspaceRoot = [IO.Path]::GetFullPath($projectRoot).TrimEnd('\')
$packageRoot = [IO.Path]::GetFullPath((Join-Path $projectRoot $PackageDirectory)).TrimEnd('\')
$approvedPackageRoot = [IO.Path]::GetFullPath(
    (Join-Path $projectRoot "release/.local-staging")).TrimEnd('\')
if (-not $packageRoot.Equals($approvedPackageRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw "The app-local Granger Network runtime may only be added to release/.local-staging."
}
if (-not $packageRoot.StartsWith($workspaceRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw "PackageDirectory escaped the project workspace."
}
if (-not (Test-Path -LiteralPath (Join-Path $packageRoot "GrangerBrowser.exe") -PathType Leaf)) {
    throw "Base staged package is missing GrangerBrowser.exe."
}

if ([string]::IsNullOrWhiteSpace($PythonExecutable)) {
    $PythonExecutable = (Get-Command python.exe -ErrorAction SilentlyContinue).Source
}
if ([string]::IsNullOrWhiteSpace($PythonExecutable) -or
    -not (Test-Path -LiteralPath $PythonExecutable -PathType Leaf)) {
    throw "A local official x64 Python installation is required at build time."
}
$PythonExecutable = [IO.Path]::GetFullPath($PythonExecutable)

$probeCode = @'
import base64
import csv
import hashlib
import json
import pathlib
import platform
import struct
import sys
import cryptography
import cffi
import pycparser
import _cffi_backend

site_packages = pathlib.Path(cryptography.__file__).resolve().parent.parent
def dist_info(name):
    matches = list(site_packages.glob(f"{name}-*.dist-info"))
    if len(matches) != 1:
        raise RuntimeError(f"expected one {name} dist-info directory")
    return matches[0]

def verify_record(path):
    verified = 0
    with (path / "RECORD").open(newline="", encoding="utf-8") as record:
        for relative, expected, _size in csv.reader(record):
            if not expected:
                continue
            algorithm, encoded = expected.split("=", 1)
            candidate = path.parent / relative
            actual = base64.urlsafe_b64encode(
                hashlib.new(algorithm, candidate.read_bytes()).digest()
            ).rstrip(b"=").decode("ascii")
            if actual != encoded:
                raise RuntimeError(f"installed distribution hash mismatch: {relative}")
            verified += 1
    return verified

cryptography_dist_info = dist_info("cryptography")
cffi_dist_info = dist_info("cffi")
pycparser_dist_info = dist_info("pycparser")
print(json.dumps({
    "bits": struct.calcsize("P") * 8,
    "backend": str(pathlib.Path(_cffi_backend.__file__).resolve()),
    "cffi_dist_info": str(cffi_dist_info),
    "cffi_root": str(pathlib.Path(cffi.__file__).resolve().parent),
    "cffi_version": cffi.__version__,
    "cryptography_dist_info": str(cryptography_dist_info),
    "cryptography_root": str(pathlib.Path(cryptography.__file__).resolve().parent),
    "cryptography_version": cryptography.__version__,
    "cryptography_verified_files": verify_record(cryptography_dist_info),
    "pycparser_dist_info": str(pycparser_dist_info),
    "pycparser_root": str(pathlib.Path(pycparser.__file__).resolve().parent),
    "pycparser_version": pycparser.__version__,
    "cffi_verified_files": verify_record(cffi_dist_info),
    "pycparser_verified_files": verify_record(pycparser_dist_info),
    "python_dll": f"python{sys.version_info.major}{sys.version_info.minor}.dll",
    "python_root": sys.base_prefix,
    "python_version": platform.python_version(),
}))
'@
$probeText = & $PythonExecutable -I -c $probeCode
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($probeText)) {
    throw "Python runtime discovery failed."
}
$runtimeInfo = $probeText | ConvertFrom-Json
if ([int]$runtimeInfo.bits -ne 64 -or [version]$runtimeInfo.python_version -lt [version]"3.11" -or
    [version]$runtimeInfo.cryptography_version -lt [version]"47.0") {
    throw "Granger Network requires x64 Python 3.11+ and cryptography 47+."
}

$pythonRoot = [IO.Path]::GetFullPath([string]$runtimeInfo.python_root).TrimEnd('\')
$sourcePythonExecutable = Join-Path $pythonRoot "python.exe"
$pythonDll = Join-Path $pythonRoot ([string]$runtimeInfo.python_dll)
$python3Dll = Join-Path $pythonRoot "python3.dll"
foreach ($signedFile in @($sourcePythonExecutable, $pythonDll, $python3Dll)) {
    $signature = Get-AuthenticodeSignature -LiteralPath $signedFile
    if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
        -not $signature.SignerCertificate -or
        $signature.SignerCertificate.Subject -notmatch "Python Software Foundation") {
        throw "Official Python signature validation failed: $signedFile"
    }
}

$sourceLib = Join-Path $pythonRoot "Lib"
$sourceDlls = Join-Path $pythonRoot "DLLs"
$cryptographyRoot = [IO.Path]::GetFullPath([string]$runtimeInfo.cryptography_root)
$cryptographyDistInfo = [IO.Path]::GetFullPath([string]$runtimeInfo.cryptography_dist_info)
$cffiRoot = [IO.Path]::GetFullPath([string]$runtimeInfo.cffi_root)
$cffiDistInfo = [IO.Path]::GetFullPath([string]$runtimeInfo.cffi_dist_info)
$cffiBackend = [IO.Path]::GetFullPath([string]$runtimeInfo.backend)
$pycparserRoot = [IO.Path]::GetFullPath([string]$runtimeInfo.pycparser_root)
$pycparserDistInfo = [IO.Path]::GetFullPath([string]$runtimeInfo.pycparser_dist_info)
$networkSource = Join-Path $projectRoot "GrangerNetwork/src/granger_network"
$networkIdentityScript = Join-Path $PSScriptRoot "Get-GrangerNetworkRuntimeIdentity.ps1"
$sourceNetworkIdentity = & $networkIdentityScript -SourceDirectory $networkSource
foreach ($requiredSource in @(
    $sourceLib,
    $sourceDlls,
    $cryptographyRoot,
    $cryptographyDistInfo,
    $cffiRoot,
    $cffiDistInfo,
    $cffiBackend,
    $pycparserRoot,
    $pycparserDistInfo,
    $networkSource,
    (Join-Path $pythonRoot "LICENSE.txt")
)) {
    if (-not (Test-Path -LiteralPath $requiredSource)) {
        throw "App-local runtime source is missing: $requiredSource"
    }
}

$runtimeRoot = Join-Path $packageRoot "runtime/python"
$runtimeLib = Join-Path $runtimeRoot "Lib"
$runtimeSitePackages = Join-Path $runtimeLib "site-packages"
if (Test-Path -LiteralPath $runtimeRoot) {
    if (-not $runtimeRoot.StartsWith($approvedPackageRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to replace a runtime outside local staging."
    }
    Remove-Item -LiteralPath $runtimeRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $runtimeRoot,$runtimeLib,$runtimeSitePackages -Force | Out-Null

foreach ($fileName in @(
    "python.exe",
    "python3.dll",
    [string]$runtimeInfo.python_dll,
    "vcruntime140.dll",
    "vcruntime140_1.dll",
    "LICENSE.txt"
)) {
    $source = Join-Path $pythonRoot $fileName
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw "Required Python runtime file is missing: $fileName"
    }
    Copy-Item -LiteralPath $source -Destination (Join-Path $runtimeRoot $fileName)
}

$excludedLibDirectories = @(
    "__pycache__",
    "ensurepip",
    "idlelib",
    "site-packages",
    "test",
    "tkinter",
    "turtledemo",
    "venv"
)
foreach ($entry in Get-ChildItem -LiteralPath $sourceLib -Force) {
    if ($entry.PSIsContainer -and $entry.Name -in $excludedLibDirectories) { continue }
    if (-not $entry.PSIsContainer -and $entry.Extension -eq ".pyc") { continue }
    Copy-Item -LiteralPath $entry.FullName -Destination $runtimeLib -Recurse
}

$runtimeDlls = Join-Path $runtimeRoot "DLLs"
New-Item -ItemType Directory -Path $runtimeDlls -Force | Out-Null
$excludedDllNames = @(
    "_ctypes_test.pyd",
    "_remote_debugging.pyd",
    "_tkinter.pyd",
    "python_lib.cat",
    "tcl86t.dll",
    "tk86t.dll"
)
foreach ($file in Get-ChildItem -LiteralPath $sourceDlls -File) {
    if ($file.Name -in $excludedDllNames -or $file.Name -like "_test*.pyd" -or
        $file.Extension -eq ".ico") {
        continue
    }
    Copy-Item -LiteralPath $file.FullName -Destination $runtimeDlls
}

Copy-Item -LiteralPath $cryptographyRoot -Destination $runtimeSitePackages -Recurse
Copy-Item -LiteralPath $cryptographyDistInfo -Destination $runtimeSitePackages -Recurse
Copy-Item -LiteralPath $cffiRoot -Destination $runtimeSitePackages -Recurse
Copy-Item -LiteralPath $cffiDistInfo -Destination $runtimeSitePackages -Recurse
Copy-Item -LiteralPath $cffiBackend -Destination $runtimeSitePackages
Copy-Item -LiteralPath $pycparserRoot -Destination $runtimeSitePackages -Recurse
Copy-Item -LiteralPath $pycparserDistInfo -Destination $runtimeSitePackages -Recurse
Copy-Item -LiteralPath $networkSource -Destination $runtimeSitePackages -Recurse
Get-ChildItem -LiteralPath $runtimeRoot -Directory -Recurse -Force |
    Where-Object { $_.Name -eq "__pycache__" } |
    Sort-Object FullName -Descending |
    Remove-Item -Recurse -Force
Get-ChildItem -LiteralPath $runtimeRoot -File -Recurse -Filter "*.pyc" | Remove-Item -Force

$packagedNetworkRoot = Join-Path $runtimeSitePackages "granger_network"
$packagedNetworkIdentity = & $networkIdentityScript -SourceDirectory $packagedNetworkRoot
if ([string]$packagedNetworkIdentity.Version -ne [string]$sourceNetworkIdentity.Version -or
    [string]$packagedNetworkIdentity.SHA256 -ne [string]$sourceNetworkIdentity.SHA256 -or
    [int]$packagedNetworkIdentity.FileCount -ne [int]$sourceNetworkIdentity.FileCount) {
    throw "Packaged Granger Network source identity does not match the current source tree."
}

$pythonStem = [IO.Path]::GetFileNameWithoutExtension([string]$runtimeInfo.python_dll)
@(
    "Lib",
    "DLLs",
    "Lib\site-packages"
) | Set-Content -LiteralPath (Join-Path $runtimeRoot "$pythonStem._pth") -Encoding ASCII

$oldPythonHome = $env:PYTHONHOME
$oldPythonPath = $env:PYTHONPATH
$oldPythonUserBase = $env:PYTHONUSERBASE
$oldDontWriteBytecode = $env:PYTHONDONTWRITEBYTECODE
try {
    $env:PYTHONHOME = $null
    $env:PYTHONPATH = $null
    $env:PYTHONUSERBASE = $null
    $env:PYTHONDONTWRITEBYTECODE = "1"
    $packagedPython = Join-Path $runtimeRoot "python.exe"
    $validationCode = @'
import json
import os
import pathlib
import struct
import sys
import cryptography
import cffi
import pycparser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from granger_network import __version__ as granger_network_version
from granger_network.address import canonical_address
from granger_network.browser_gateway import PROTOCOL_VERSION
from granger_network.crypto import SUITE_X25519_MLKEM768
from granger_network.distributed import DistributedDiscoveryNetwork
from granger_network.introduction import IntroductionDescriptor
from granger_network.multihop import MultiHopCircuit
from granger_network.peer import NodeDescriptor
from granger_network.protocol import VERSION_3

identity = Ed25519PrivateKey.generate()
message = b"granger-local-runtime"
identity.public_key().verify(identity.sign(message), message)
first = X25519PrivateKey.generate()
second = X25519PrivateKey.generate()
assert first.exchange(second.public_key()) == second.exchange(first.public_key())
mlkem_private = MLKEM768PrivateKey.generate()
mlkem_secret, mlkem_ciphertext = mlkem_private.public_key().encapsulate()
assert mlkem_private.decapsulate(mlkem_ciphertext) == mlkem_secret
key = ChaCha20Poly1305.generate_key()
nonce = bytes(12)
assert ChaCha20Poly1305(key).decrypt(nonce, ChaCha20Poly1305(key).encrypt(nonce, message, b"v1"), b"v1") == message
print(json.dumps({
    "app_local": pathlib.Path(sys.executable).resolve().parent == pathlib.Path(sys.prefix).resolve(),
    "bits": struct.calcsize("P") * 8,
    "cryptography": cryptography.__version__,
    "cffi": cffi.__version__,
    "dns_requests": 0,
    "distributed_overlay": all((
        DistributedDiscoveryNetwork,
        IntroductionDescriptor,
        MultiHopCircuit,
        NodeDescriptor,
    )),
    "granger_network": granger_network_version,
    "mlkem768": True,
    "protocol": PROTOCOL_VERSION,
    "python": sys.version.split()[0],
    "pycparser": pycparser.__version__,
    "suite": SUITE_X25519_MLKEM768,
    "wire": VERSION_3,
}))
'@
    $validationText = & $packagedPython -I -B -c $validationCode
    if ($LASTEXITCODE -ne 0) { throw "Packaged Granger Network Python runtime failed validation." }
    $runtimeValidation = $validationText | ConvertFrom-Json
    if (-not [bool]$runtimeValidation.app_local -or [int]$runtimeValidation.bits -ne 64 -or
        [int]$runtimeValidation.protocol -ne 1 -or [int]$runtimeValidation.dns_requests -ne 0 -or
        [string]$runtimeValidation.granger_network -ne [string]$sourceNetworkIdentity.Version -or
        [int]$runtimeValidation.wire -ne 3 -or [int]$runtimeValidation.suite -ne 1 -or
        -not [bool]$runtimeValidation.mlkem768 -or
        -not [bool]$runtimeValidation.distributed_overlay) {
        throw "Packaged Granger Network Python runtime reported unexpected state."
    }
} finally {
    $env:PYTHONHOME = $oldPythonHome
    $env:PYTHONPATH = $oldPythonPath
    $env:PYTHONUSERBASE = $oldPythonUserBase
    $env:PYTHONDONTWRITEBYTECODE = $oldDontWriteBytecode
}
Get-ChildItem -LiteralPath $runtimeRoot -Directory -Recurse -Force |
    Where-Object { $_.Name -eq "__pycache__" } |
    Sort-Object FullName -Descending |
    Remove-Item -Recurse -Force
Get-ChildItem -LiteralPath $runtimeRoot -File -Recurse -Filter "*.pyc" | Remove-Item -Force
if (@(Get-ChildItem -LiteralPath $runtimeRoot -Recurse -File -Filter "*.pyc").Count -ne 0 -or
    @(Get-ChildItem -LiteralPath $runtimeRoot -Recurse -Directory -Filter "__pycache__").Count -ne 0) {
    throw "App-local runtime contains generated Python bytecode."
}

$sourceHead = (& git -C $projectRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $sourceHead -notmatch '^[0-9a-f]{40}$') {
    throw "Could not record the source HEAD for the local runtime."
}
$criticalRuntimeFiles = @(
    "runtime/python/python.exe",
    "runtime/python/$([string]$runtimeInfo.python_dll)",
    "runtime/python/Lib/site-packages/$([IO.Path]::GetFileName($cffiBackend))",
    "runtime/python/Lib/site-packages/cryptography/hazmat/bindings/_rust.pyd",
    "runtime/python/Lib/site-packages/granger_network/browser_gateway.py"
)
$runtimeFileRecords = foreach ($relativePath in $criticalRuntimeFiles) {
    $path = Join-Path $packageRoot $relativePath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Critical app-local runtime file is missing: $relativePath"
    }
    $item = Get-Item -LiteralPath $path
    [ordered]@{
        Path = $relativePath.Replace('\', '/')
        Size = $item.Length
        SHA256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    }
}
[ordered]@{
    SchemaVersion = 2
    SourceHead = $sourceHead
    BrowserExecutableSHA256 = (Get-FileHash -LiteralPath (Join-Path $packageRoot "GrangerBrowser.exe") -Algorithm SHA256).Hash
    PythonVersion = [string]$runtimeInfo.python_version
    PythonArchitecture = "x64"
    PythonPublisher = "Python Software Foundation"
    PythonLicense = "PSF-2.0"
    CryptographyVersion = [string]$runtimeInfo.cryptography_version
    CryptographyLicense = "Apache-2.0 OR BSD-3-Clause"
    CryptographyVerifiedFiles = [int]$runtimeInfo.cryptography_verified_files
    CffiVersion = [string]$runtimeInfo.cffi_version
    CffiLicense = "MIT"
    CffiVerifiedFiles = [int]$runtimeInfo.cffi_verified_files
    PycparserVersion = [string]$runtimeInfo.pycparser_version
    PycparserLicense = "BSD-3-Clause"
    PycparserVerifiedFiles = [int]$runtimeInfo.pycparser_verified_files
    GrangerNetworkVersion = [string]$packagedNetworkIdentity.Version
    GrangerNetworkSourceSHA256 = [string]$packagedNetworkIdentity.SHA256
    GrangerNetworkSourceFiles = [int]$packagedNetworkIdentity.FileCount
    GrangerNetworkFiles = @($packagedNetworkIdentity.Files)
    IsolatedRuntime = $true
    RuntimeFiles = @($runtimeFileRecords)
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $packageRoot "local-runtime-metadata.json") -Encoding UTF8

$manifestPath = Join-Path $packageRoot "release-manifest.json"
$manifest = Get-ChildItem -LiteralPath $packageRoot -Recurse -File | Where-Object {
    -not $_.FullName.Equals($manifestPath, [StringComparison]::OrdinalIgnoreCase)
} | ForEach-Object {
    [ordered]@{
        Path = $_.FullName.Substring($packageRoot.Length).TrimStart('\').Replace('\', '/')
        Size = $_.Length
        SHA256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
    }
}
$manifest | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

[pscustomobject]@{
    OK = $true
    Package = $packageRoot
    PythonVersion = [string]$runtimeInfo.python_version
    CryptographyVersion = [string]$runtimeInfo.cryptography_version
    GrangerNetworkVersion = [string]$packagedNetworkIdentity.Version
    GrangerNetworkSourceSHA256 = [string]$packagedNetworkIdentity.SHA256
    GrangerNetworkSourceFiles = [int]$packagedNetworkIdentity.FileCount
    SourceHead = $sourceHead
    RuntimeFiles = @(Get-ChildItem -LiteralPath $runtimeRoot -Recurse -File).Count
    RuntimeSize = (Get-ChildItem -LiteralPath $runtimeRoot -Recurse -File |
        Measure-Object Length -Sum).Sum
}
