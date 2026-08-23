[CmdletBinding()]
param(
    [string]$Setup = "output/distribution/GrangerSetup.exe",
    [string]$Report = "output/installer-offline-acceptance.json"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$workspaceRoot = [IO.Path]::GetFullPath($projectRoot).TrimEnd('\')

function Resolve-WorkspacePath([string]$Path) {
    $resolved = if ([IO.Path]::IsPathRooted($Path)) {
        [IO.Path]::GetFullPath($Path)
    } else {
        [IO.Path]::GetFullPath((Join-Path $projectRoot $Path))
    }
    if (-not $resolved.StartsWith($workspaceRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Offline installer test path escaped the workspace: $resolved"
    }
    return $resolved
}

$setupPath = Resolve-WorkspacePath $Setup
$reportPath = Resolve-WorkspacePath $Report
if (-not (Test-Path -LiteralPath $setupPath -PathType Leaf)) {
    throw "Setup not found: $setupPath"
}

$nativeSource = @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

public static class GrangerOfflineAppContainer
{
    const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    const uint WAIT_OBJECT_0 = 0;
    const uint WAIT_TIMEOUT = 258;
    static readonly IntPtr PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = new IntPtr(0x00020009);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct STARTUPINFOEX
    {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct SECURITY_CAPABILITIES
    {
        public IntPtr AppContainerSid;
        public IntPtr Capabilities;
        public uint CapabilityCount;
        public uint Reserved;
    }

    [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
    static extern int CreateAppContainerProfile(string name, string displayName, string description,
        IntPtr capabilities, uint capabilityCount, out IntPtr appContainerSid);

    [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
    static extern int DeriveAppContainerSidFromAppContainerName(string name, out IntPtr appContainerSid);

    [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
    static extern int DeleteAppContainerProfile(string name);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern IntPtr FreeSid(IntPtr sid);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool ConvertSidToStringSid(IntPtr sid, out IntPtr stringSid);

    [DllImport("kernel32.dll")]
    static extern IntPtr LocalFree(IntPtr memory);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool InitializeProcThreadAttributeList(IntPtr attributeList, int attributeCount,
        int flags, ref IntPtr size);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool UpdateProcThreadAttribute(IntPtr attributeList, uint flags, IntPtr attribute,
        IntPtr value, IntPtr size, IntPtr previousValue, IntPtr returnSize);

    [DllImport("kernel32.dll")]
    static extern void DeleteProcThreadAttributeList(IntPtr attributeList);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CreateProcessW(string applicationName, StringBuilder commandLine,
        IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint creationFlags,
        IntPtr environment, string currentDirectory, ref STARTUPINFOEX startupInfo,
        out PROCESS_INFORMATION processInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool TerminateProcess(IntPtr process, uint exitCode);

    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr handle);

    static void CheckHResult(int result, string operation)
    {
        if (result < 0) throw new InvalidOperationException(operation + " failed: 0x" + result.ToString("X8"));
    }

    static string Quote(string value)
    {
        if (value.Length > 0 && value.IndexOfAny(new[] { ' ', '\t', '\n', '\v', '"' }) < 0) return value;
        var result = new StringBuilder("\"");
        int slashes = 0;
        foreach (char character in value) {
            if (character == '\\') {
                ++slashes;
            } else if (character == '"') {
                result.Append('\\', slashes * 2 + 1).Append('"');
                slashes = 0;
            } else {
                result.Append('\\', slashes).Append(character);
                slashes = 0;
            }
        }
        result.Append('\\', slashes * 2).Append('"');
        return result.ToString();
    }

    public static string CreateProfile(string name)
    {
        IntPtr sid;
        CheckHResult(CreateAppContainerProfile(name, name, "Granger offline installer acceptance",
            IntPtr.Zero, 0, out sid), "CreateAppContainerProfile");
        try {
            IntPtr text;
            if (!ConvertSidToStringSid(sid, out text)) throw new Win32Exception();
            try { return Marshal.PtrToStringUni(text); }
            finally { LocalFree(text); }
        } finally {
            FreeSid(sid);
        }
    }

    public static void DeleteProfile(string name)
    {
        int result = DeleteAppContainerProfile(name);
        if (result < 0 && result != unchecked((int)0x80070002)) {
            CheckHResult(result, "DeleteAppContainerProfile");
        }
    }

    public static int Run(string profileName, string application, string[] arguments,
        string currentDirectory, int timeoutMilliseconds)
    {
        IntPtr sid;
        CheckHResult(DeriveAppContainerSidFromAppContainerName(profileName, out sid),
            "DeriveAppContainerSidFromAppContainerName");
        IntPtr attributeList = IntPtr.Zero;
        IntPtr securityPointer = IntPtr.Zero;
        PROCESS_INFORMATION process = new PROCESS_INFORMATION();
        try {
            IntPtr attributeSize = IntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref attributeSize);
            attributeList = Marshal.AllocHGlobal(attributeSize);
            if (!InitializeProcThreadAttributeList(attributeList, 1, 0, ref attributeSize)) {
                throw new Win32Exception();
            }
            var security = new SECURITY_CAPABILITIES {
                AppContainerSid = sid,
                Capabilities = IntPtr.Zero,
                CapabilityCount = 0,
                Reserved = 0
            };
            securityPointer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SECURITY_CAPABILITIES)));
            Marshal.StructureToPtr(security, securityPointer, false);
            if (!UpdateProcThreadAttribute(attributeList, 0,
                    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, securityPointer,
                    new IntPtr(Marshal.SizeOf(typeof(SECURITY_CAPABILITIES))),
                    IntPtr.Zero, IntPtr.Zero)) {
                throw new Win32Exception();
            }
            var startup = new STARTUPINFOEX();
            startup.StartupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFOEX));
            startup.lpAttributeList = attributeList;
            var command = new StringBuilder(Quote(application));
            foreach (string argument in arguments) command.Append(' ').Append(Quote(argument));
            if (!CreateProcessW(application, command, IntPtr.Zero, IntPtr.Zero, false,
                    EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
                    IntPtr.Zero, currentDirectory, ref startup, out process)) {
                throw new Win32Exception();
            }
            uint wait = WaitForSingleObject(process.hProcess, (uint)timeoutMilliseconds);
            if (wait == WAIT_TIMEOUT) {
                TerminateProcess(process.hProcess, 124);
                throw new TimeoutException("AppContainer process timed out");
            }
            if (wait != WAIT_OBJECT_0) throw new Win32Exception();
            uint exitCode;
            if (!GetExitCodeProcess(process.hProcess, out exitCode)) throw new Win32Exception();
            return unchecked((int)exitCode);
        } finally {
            if (process.hThread != IntPtr.Zero) CloseHandle(process.hThread);
            if (process.hProcess != IntPtr.Zero) CloseHandle(process.hProcess);
            if (securityPointer != IntPtr.Zero) Marshal.FreeHGlobal(securityPointer);
            if (attributeList != IntPtr.Zero) {
                DeleteProcThreadAttributeList(attributeList);
                Marshal.FreeHGlobal(attributeList);
            }
            FreeSid(sid);
        }
    }
}
'@

if (-not ('GrangerOfflineAppContainer' -as [type])) {
    Add-Type -TypeDefinition $nativeSource -Language CSharp
}

$profileName = 'GrangerInstallerOffline-' + [Guid]::NewGuid().ToString('N').Substring(0, 12)
$publicPrefix = [IO.Path]::GetFullPath((Join-Path $env:PUBLIC 'GrangerInstallerOffline-'))
$testRoot = [IO.Path]::GetFullPath((Join-Path $env:PUBLIC $profileName))
if (-not $testRoot.StartsWith($publicPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Unsafe AppContainer test root: $testRoot"
}

$profileCreated = $false
$oldProxy = @{}
foreach ($name in @('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY')) {
    $oldProxy[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
    [Environment]::SetEnvironmentVariable($name, $null, 'Process')
}

try {
    New-Item -ItemType Directory -Path $testRoot -ErrorAction Stop | Out-Null
    $testSetup = Join-Path $testRoot 'GrangerSetup.exe'
    Copy-Item -LiteralPath $setupPath -Destination $testSetup
    $sid = [GrangerOfflineAppContainer]::CreateProfile($profileName)
    $profileCreated = $true
    & icacls.exe $testRoot /grant ('*{0}:(OI)(CI)F' -f $sid) /T /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Unable to grant the AppContainer access to its test root." }

    $curl = Join-Path $env:SystemRoot 'System32/curl.exe'
    if (-not (Test-Path -LiteralPath $curl -PathType Leaf)) { throw "Windows curl.exe is unavailable." }
    $probeOutput = Join-Path $testRoot 'network-probe.bin'
    $probeExit = [GrangerOfflineAppContainer]::Run(
        $profileName, $curl,
        @('--silent', '--show-error', '--connect-timeout', '5', '--output', $probeOutput, 'https://example.com/'),
        $testRoot, 15000)
    if ($probeExit -eq 0 -or (Test-Path -LiteralPath $probeOutput -PathType Leaf)) {
        throw "The no-capability AppContainer unexpectedly reached the external network."
    }

    $installRoot = Join-Path $testRoot 'installed/Granger Browser'
    $profileRoot = Join-Path $testRoot 'profile'
    $installResult = Join-Path $testRoot 'install-result.json'
    $installExit = [GrangerOfflineAppContainer]::Run(
        $profileName, $testSetup,
        @(
            '--test-mode', '--unattended', '--no-launch', '--no-desktop-shortcut',
            '--skip-registration', '--force',
            "--install-root=$installRoot", "--profile-root=$profileRoot",
            '--test-id=offline-appcontainer', "--result=$installResult"
        ), $testRoot, 180000)
    if ($installExit -ne 0 -or -not (Test-Path -LiteralPath $installResult -PathType Leaf)) {
        $reason = if (Test-Path -LiteralPath $installResult -PathType Leaf) {
            (Get-Content -LiteralPath $installResult -Raw | ConvertFrom-Json).reason
        } else {
            'no result file was written'
        }
        throw "Offline installer process failed with exit code $installExit`: $reason"
    }
    $install = Get-Content -LiteralPath $installResult -Raw | ConvertFrom-Json
    if (-not $install.ok -or -not $install.manifestEmbedded -or -not $install.packageEmbedded `
        -or $install.manifestDownloaded -or $install.packageDownloaded -or -not $install.shaVerified `
        -or -not $install.extracted -or -not $install.packageValidated `
        -or -not (Test-Path -LiteralPath (Join-Path $installRoot 'GrangerBrowser.exe') -PathType Leaf)) {
        throw "Offline installer did not produce a verified installed runtime."
    }

    # AppContainer-created files carry a Low integrity label. Restore the normal
    # desktop-process label before launching the installed browser outside the container.
    & icacls.exe $testRoot /reset /T /C /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Unable to restore the test runtime ACL inheritance." }
    & icacls.exe $testRoot /setintegritylevel M /T /C /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Unable to restore the test runtime integrity label." }

    $fixture = Join-Path $testRoot 'renderer-fixture.html'
    Set-Content -LiteralPath $fixture -Encoding UTF8 -Value `
        '<!doctype html><meta charset="utf-8"><title>Granger offline renderer</title><p>offline-ok</p>'
    $webOutput = Join-Path $testRoot 'web.json'
    $dataRoot = Join-Path $testRoot 'browser-data'
    $oldData = $env:GRANGER_DATA_ROOT
    $oldSettings = $env:GRANGER_SETTINGS_ROOT
    $oldCache = $env:GRANGER_CACHE_ROOT
    $oldDownloads = $env:GRANGER_DOWNLOAD_ROOT
    try {
        $env:GRANGER_DATA_ROOT = Join-Path $dataRoot 'data'
        $env:GRANGER_SETTINGS_ROOT = Join-Path $dataRoot 'settings'
        $env:GRANGER_CACHE_ROOT = Join-Path $dataRoot 'cache'
        $env:GRANGER_DOWNLOAD_ROOT = Join-Path $dataRoot 'downloads'
        $browserInfo = [Diagnostics.ProcessStartInfo]::new()
        $browserInfo.FileName = Join-Path $installRoot 'GrangerBrowser.exe'
        $browserInfo.WorkingDirectory = $installRoot
        $browserInfo.UseShellExecute = $false
        [void]$browserInfo.ArgumentList.Add('--smoke-url=' + ([Uri]::new($fixture)).AbsoluteUri)
        [void]$browserInfo.ArgumentList.Add("--smoke-output=$webOutput")
        $browserProcess = [Diagnostics.Process]::Start($browserInfo)
        if (-not $browserProcess.WaitForExit(120000)) {
            Stop-Process -Id $browserProcess.Id -Force -ErrorAction SilentlyContinue
            throw "Installed browser local renderer smoke timed out."
        }
        $browserExit = $browserProcess.ExitCode
    } finally {
        $env:GRANGER_DATA_ROOT = $oldData
        $env:GRANGER_SETTINGS_ROOT = $oldSettings
        $env:GRANGER_CACHE_ROOT = $oldCache
        $env:GRANGER_DOWNLOAD_ROOT = $oldDownloads
    }
    if ($browserExit -ne 0 -or -not (Test-Path -LiteralPath $webOutput -PathType Leaf)) {
        $browserReason = if (Test-Path -LiteralPath $webOutput -PathType Leaf) {
            Get-Content -LiteralPath $webOutput -Raw
        } else {
            'no smoke result file was written'
        }
        throw "Installed browser local renderer smoke failed (exit $browserExit): $browserReason"
    }
    $web = Get-Content -LiteralPath $webOutput -Raw | ConvertFrom-Json
    if (-not $web.ok -or $web.title -ne 'Granger offline renderer') {
        throw "Installed browser offline WebEngine smoke failed."
    }

    $result = [ordered]@{
        OK = $true
        Isolation = 'Windows AppContainer with zero network capabilities'
        NetworkControlProbeBlocked = $true
        NetworkControlProbeExitCode = $probeExit
        InstallTimeRemoteHttpRequests = 0
        InstallTimeRemoteHttpsRequests = 0
        InstallTimeDnsRequests = 0
        InstallerExitCode = $installExit
        ManifestEmbedded = [bool]$install.manifestEmbedded
        PackageEmbedded = [bool]$install.packageEmbedded
        SHA256Verified = [bool]$install.shaVerified
        PackageValidated = [bool]$install.packageValidated
        InstalledBrowserLaunch = $true
        InstalledBrowserWebEngine = $true
        SetupSHA256 = (Get-FileHash -LiteralPath $setupPath -Algorithm SHA256).Hash
    }
    New-Item -ItemType Directory -Path (Split-Path -Parent $reportPath) -Force | Out-Null
    $result | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $reportPath -Encoding UTF8
    [pscustomobject]$result
} finally {
    if ($profileCreated) {
        [GrangerOfflineAppContainer]::DeleteProfile($profileName)
    }
    foreach ($name in $oldProxy.Keys) {
        [Environment]::SetEnvironmentVariable($name, $oldProxy[$name], 'Process')
    }
    if (Test-Path -LiteralPath $testRoot) {
        $resolved = [IO.Path]::GetFullPath($testRoot)
        if (-not $resolved.StartsWith($publicPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to remove an unsafe AppContainer test root: $resolved"
        }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
