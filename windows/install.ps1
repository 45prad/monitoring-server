# Windows Monitoring Agent Installer
param(
    [int]$Port = 9323
)

$ErrorActionPreference = 'SilentlyContinue'

$InstallDir = "C:\MonitoringAgent"
if (!(Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

$CurrentDir = if ($MyInvocation.MyCommand.Definition) { Split-Path -Parent $MyInvocation.MyCommand.Definition } else { "" }
if ($CurrentDir -and (Test-Path "$CurrentDir\server.ps1")) {
    Copy-Item -Path "$CurrentDir\server.ps1" -Destination "$InstallDir\server.ps1" -Force
} else {
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/45prad/monitoring-server/main/windows/server.ps1" -OutFile "$InstallDir\server.ps1" -UseBasicParsing -ErrorAction SilentlyContinue
}

# 1. Allow URL ACL
netsh http add urlacl url="http://+:$Port/" sddl="D:(A;;GX;;;WD)" 2>$null

# 2. Add Firewall Rule
Remove-NetFirewallRule -DisplayName "MonitoringAgent" -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "MonitoringAgent" -Direction Inbound -LocalPort $Port -Protocol TCP -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null

# 3. Create Scheduled Task to run as SYSTEM at startup
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File `"$InstallDir\server.ps1`" -Port $Port"
$TriggerStartup = New-ScheduledTaskTrigger -AtStartup
$TriggerRepeat = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 3650)
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan) -MultipleInstances IgnoreNew -RestartCount 10 -RestartInterval (New-TimeSpan -Minutes 1)

Unregister-ScheduledTask -TaskName "MonitoringAgent" -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName "MonitoringAgent" -Action $Action -Trigger @($TriggerStartup, $TriggerRepeat) -Principal $Principal -Settings $Settings -Force | Out-Null

# 4. Start Task immediately
Start-ScheduledTask -TaskName "MonitoringAgent" -ErrorAction SilentlyContinue

Write-Host "[+] Windows Monitoring Agent installed and running on port $Port"
