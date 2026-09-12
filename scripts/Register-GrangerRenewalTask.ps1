[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$ConfigPath,
    [Parameter(Mandatory)][string]$PythonExecutable
)

$ErrorActionPreference = 'Stop'
$config = (Resolve-Path -LiteralPath $ConfigPath).Path
$python = (Resolve-Path -LiteralPath $PythonExecutable).Path
$tool = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '../GrangerNetwork/tools/operator_renewal.py')).Path
foreach ($path in @($config, $python, $tool)) {
    $item = Get-Item -LiteralPath $path
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $path.Contains('"')) {
        throw 'Renewal paths must be regular local files without quote characters.'
    }
}
$document = Get-Content -LiteralPath $config -Raw | ConvertFrom-Json
$root = (Resolve-Path -LiteralPath $document.operatorRoot).Path
$account = [Security.Principal.WindowsIdentity]::GetCurrent()
$sid = $account.User.Value
$allowedSids = @($sid, 'S-1-5-18', 'S-1-5-32-544')
foreach ($path in @($root, $config)) {
    if ((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'Operator control paths must not be reparse points.'
    }
    $acl = Get-Acl -LiteralPath $path
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid) {
        throw 'The current operator must own the configuration and authority root.'
    }
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin $allowedSids) {
            throw 'Operator control paths grant access outside the operator, SYSTEM and Administrators.'
        }
    }
}
$prefix = $root.TrimEnd('\') + '\'
if (-not $config.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Renewal configuration must be inside the protected operator root.'
}

$name = 'Granger Network Renewal'
$description = 'Renew existing Granger signed configuration from the trusted operator workstation.'
$arguments = '-I -B "{0}" --config "{1}"' -f $tool, $config
$existing = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
if ($existing -and ($existing.Description -ne $description -or $existing.Principal.UserId -notin @($sid, $account.Name))) {
    throw 'An unrelated scheduled task already uses the renewal task name.'
}
$action = New-ScheduledTaskAction -Execute $python -Argument $arguments -WorkingDirectory (Split-Path $tool)
$triggers = @(
    (New-ScheduledTaskTrigger -AtLogOn -User $sid),
    (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5))
)
$principal = New-ScheduledTaskPrincipal -UserId $sid -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 10) `
    -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
if ($PSCmdlet.ShouldProcess($name, 'Register passwordless operator-side renewal')) {
    Register-ScheduledTask -TaskName $name -Description $description -Action $action -Trigger $triggers `
        -Principal $principal -Settings $settings -Force | Select-Object TaskName, State
}
