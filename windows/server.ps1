<#
.SYNOPSIS
    Monitoring Agent API Server - Windows PowerShell
    Listens on port 9323 (default) and executes the exact monitoring commands.

.DESCRIPTION
    Endpoints:
      /health               -> JSON health check
      /failed-login-events  -> Windows Security Event 4625 logs
      /network              -> Get-NetFirewallRule & netstat -ano
      /system-resources     -> CPU, Memory, Disk, OS metrics
      /services             -> Services status and System event logs
      /traffic-analytics    -> Bandwidth and suspicious ports
#>

param(
    [int]$Port = 9323,
    [string]$ApiKey = "",
    [string]$SecretKey = ""
)

$ErrorActionPreference = 'SilentlyContinue'

# ---------------------------------------------------------------------------
# Cryptographic helpers (HMAC-SHA256 CTR stream cipher with rotating key)
# ---------------------------------------------------------------------------

function Derive-MonitoringKey([string]$masterSecret, [string]$nonce) {
    $hm = [System.Security.Cryptography.HMACSHA256]::new([System.Text.Encoding]::UTF8.GetBytes($masterSecret))
    return $hm.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($nonce))
}

function Encrypt-MonitoringResponse([string]$text, [string]$masterSecret, [string]$nonce) {
    $key = Derive-MonitoringKey $masterSecret $nonce
    $iv = New-Object byte[] 16
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($iv)

    $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($text)
    $cipherBytes = New-Object byte[] $plainBytes.Length
    $hm = [System.Security.Cryptography.HMACSHA256]::new($key)

    for ($offset = 0; $offset -lt $plainBytes.Length; $offset += 32) {
        $blockIndex = [int][Math]::Floor($offset / 32)
        $counterBytes = [System.BitConverter]::GetBytes($blockIndex)
        if ([System.BitConverter]::IsLittleEndian) {
            [System.Array]::Reverse($counterBytes)
        }
        $combined = New-Object byte[] ($iv.Length + $counterBytes.Length)
        [System.Buffer]::BlockCopy($iv, 0, $combined, 0, $iv.Length)
        [System.Buffer]::BlockCopy($counterBytes, 0, $combined, $iv.Length, $counterBytes.Length)
        $keystream = $hm.ComputeHash($combined)

        $chunkLen = [Math]::Min(32, $plainBytes.Length - $offset)
        for ($j = 0; $j -lt $chunkLen; $j++) {
            $cipherBytes[$offset + $j] = $plainBytes[$offset + $j] -bxor $keystream[$j]
        }
    }

    $tagInput = New-Object byte[] ($iv.Length + $cipherBytes.Length)
    [System.Buffer]::BlockCopy($iv, 0, $tagInput, 0, $iv.Length)
    [System.Buffer]::BlockCopy($cipherBytes, 0, $tagInput, $iv.Length, $cipherBytes.Length)
    $tagBytes = $hm.ComputeHash($tagInput)
    $tag = [System.BitConverter]::ToString($tagBytes).Replace("-", "").ToLower()

    $ivHex = [System.BitConverter]::ToString($iv).Replace("-", "").ToLower()
    $b64Data = [System.Convert]::ToBase64String($cipherBytes)

    $payload = [PSCustomObject]@{
        encrypted = $true
        iv = $ivHex
        data = $b64Data
        tag = $tag
        nonce = $nonce
    }
    return ($payload | ConvertTo-Json -Compress)
}

function Get-FailedLoginEvents {
    try {
        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.AppendLine("__FAILED_LOGIN_EVENTS__")
        $h = $env:COMPUTERNAME
        $events = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=(Get-Date).AddDays(-30)} -MaxEvents 50 -ErrorAction SilentlyContinue
        if (!$events) {
            [void]$sb.AppendLine("NO_FAILED_LOGIN_EVENTS_FOUND")
        } else {
            foreach ($evt in $events) {
                try {
                    $x = [xml]$evt.ToXml()
                    $d = @{}
                    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.InnerText }
                    $ip = $d["IpAddress"]
                    if (!$ip -or $ip -eq "-") { $ip = $d["WorkstationName"] }
                    $line = "{0} | {1} | Failed Login | {2} | Windows failed logon. Account={3}; Domain={4}; LogonType={5}; Status={6}; SubStatus={7}" -f $evt.TimeCreated.ToString("yyyy-MM-dd HH:mm"), $h, $ip, $d["TargetUserName"], $d["TargetDomainName"], $d["LogonType"], $d["Status"], $d["SubStatus"]
                    [void]$sb.AppendLine($line)
                } catch {}
            }
        }
        return $sb.ToString()
    } catch {
        return "__FAILED_LOGIN_EVENTS__`r`nCOMMAND_ERROR: $($_.Exception.Message)"
    }
}

function Get-NetworkData {
    try {
        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.AppendLine("================ FIREWALL RULES ================")

        # Fast query for enabled firewall rules (limit to 50 for rapid response)
        $rules = Get-NetFirewallRule -Enabled True -ErrorAction SilentlyContinue | Select-Object -First 50
        $i = 1
        foreach ($r in $rules) {
            [void]$sb.AppendLine("--------------------------------------------------")
            [void]$sb.AppendLine("RULE ID     : FW-$i")
            [void]$sb.AppendLine("INTERFACE   : ANY")
            [void]$sb.AppendLine("SOURCE      : ANY")
            [void]$sb.AppendLine("DESTINATION : ANY")
            [void]$sb.AppendLine("PROTOCOL    : ANY")
            [void]$sb.AppendLine("PORT        : ANY")
            [void]$sb.AppendLine("ACTION      : $($r.Action)")
            [void]$sb.AppendLine("")
            $i++
        }

        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("================ ACTIVE CONNECTIONS ================")

        # Fast connection list via TCP connection table
        $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object -First 50
        foreach ($c in $connections) {
            [void]$sb.AppendLine("--------------------------------------------------")
            [void]$sb.AppendLine("PROTOCOL       : TCP")
            [void]$sb.AppendLine("LOCAL ADDRESS  : $($c.LocalAddress)")
            [void]$sb.AppendLine("LOCAL PORT     : $($c.LocalPort)")
            [void]$sb.AppendLine("REMOTE ADDRESS : $($c.RemoteAddress)")
            [void]$sb.AppendLine("REMOTE PORT    : $($c.RemotePort)")
            [void]$sb.AppendLine("STATE          : $($c.State)")
            [void]$sb.AppendLine("")
        }

        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("================ BLOCKED IPS ================")
        # Any blocked firewall rules
        $blocked = $rules | Where-Object { $_.Action -eq "Block" } | Select-Object -First 20
        $now = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        foreach ($b in $blocked) {
            [void]$sb.AppendLine("--------------------------------------------------")
            [void]$sb.AppendLine("TIME        : $now")
            [void]$sb.AppendLine("BLOCKED IP  : $($b.DisplayName)")
            [void]$sb.AppendLine("INTERFACE   : ANY")
            [void]$sb.AppendLine("PROTOCOL    : ANY")
            [void]$sb.AppendLine("PORT        : ANY")
            [void]$sb.AppendLine("")
        }

        # Include netstat output for UI raw feed
        $outNetstat = netstat -ano | Out-String
        [void]$sb.AppendLine($outNetstat)

        return $sb.ToString()
    } catch {
        return "COMMAND_ERROR: $($_.Exception.Message)"
    }
}

function Get-SystemResources {
    try {
        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.AppendLine("__TIMESTAMP__")
        [void]$sb.AppendLine(((Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")))
        [void]$sb.AppendLine("__HOSTNAME__")
        [void]$sb.AppendLine($env:COMPUTERNAME)
        [void]$sb.AppendLine("__OS__")
        $os = Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture,LastBootUpTime | Out-String
        [void]$sb.Append($os)
        [void]$sb.AppendLine("__CPU__")
        $cpu = Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed | Out-String
        [void]$sb.Append($cpu)
        [void]$sb.AppendLine("__CPU_USAGE__")
        $cpuUsage = Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 1 -MaxSamples 2 -ErrorAction SilentlyContinue | Out-String
        [void]$sb.Append($cpuUsage)
        [void]$sb.AppendLine("__MEMORY__")
        $mem = Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize,FreePhysicalMemory,TotalVirtualMemorySize,FreeVirtualMemory | Out-String
        [void]$sb.Append($mem)
        [void]$sb.AppendLine("__DISK__")
        $disk = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | Select-Object DeviceID,FileSystem,Size,FreeSpace | Out-String
        [void]$sb.Append($disk)
        [void]$sb.AppendLine("__PROCESSES__")
        $proc = Get-Process | Measure-Object | Out-String
        [void]$sb.Append($proc)
        return $sb.ToString()
    } catch {
        return "COMMAND_ERROR: $($_.Exception.Message)"
    }
}

function Get-ServicesData {
    try {
        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.AppendLine("==================== SERVICE STATUS ====================")
        [void]$sb.AppendLine("")

        # Bulk fetch all service startup modes in a single CIM call (~0.2s)
        $startModes = @{}
        Get-CimInstance Win32_Service -Property Name,StartMode -ErrorAction SilentlyContinue | ForEach-Object {
            $startModes[$_.Name] = $_.StartMode
        }

        $services = Get-Service -ErrorAction SilentlyContinue | Select-Object -First 100
        foreach ($service in $services) {
            [void]$sb.AppendLine("--------------------------------------------------------")
            [void]$sb.AppendLine("SERVICE : $($service.Name)")
            [void]$sb.AppendLine("STATUS  : $($service.Status)")
            $startup = if ($startModes.ContainsKey($service.Name)) { $startModes[$service.Name] } else { "Unknown" }
            [void]$sb.AppendLine("ENABLED : $startup")
            [void]$sb.AppendLine("")
        }

        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("==================== RECENT LOGS =======================")
        [void]$sb.AppendLine("")

        # Single fast query for recent System service logs instead of querying per service
        $recentLogs = Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2,3,4} -MaxEvents 30 -ErrorAction SilentlyContinue
        if ($recentLogs) {
            foreach ($evt in $recentLogs) {
                [void]$sb.AppendLine("========================================================")
                [void]$sb.AppendLine("LOGS : $($evt.ProviderName)")
                [void]$sb.AppendLine("========================================================")
                $line = "{0} | ID:{1} | {2} | {3}" -f $evt.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss"), $evt.Id, $evt.LevelDisplayName, $evt.Message.Replace("`r`n", " ")
                [void]$sb.AppendLine($line)
                [void]$sb.AppendLine("")
            }
        }
        return $sb.ToString()
    } catch {
        return "COMMAND_ERROR: $($_.Exception.Message)"
    }
}

function Get-TrafficAnalytics {
    try {
        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.AppendLine("__TRAFFIC_ANALYTICS__")
        $h = $env:COMPUTERNAME
        $a = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
        if (!$a) {
            [void]$sb.AppendLine("NO_ACTIVE_ADAPTER_FOUND")
        } else {
            $s1 = Get-NetAdapterStatistics -Name $a.Name -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 1
            $s2 = Get-NetAdapterStatistics -Name $a.Name -ErrorAction SilentlyContinue
            $bytes = ($s2.ReceivedBytes + $s2.SentBytes) - ($s1.ReceivedBytes + $s1.SentBytes)
            $mbps = [math]::Round(($bytes * 8) / 1000000, 2)
            $badPorts = @(23, 445, 3389, 4444, 31337)
            $susp = (Get-NetTCPConnection -ErrorAction SilentlyContinue |
                Where-Object { $_.State -in @("SynSent", "SynReceived") -or $badPorts -contains $_.RemotePort -or $badPorts -contains $_.LocalPort } |
                Measure-Object).Count
            $line = "{0} | {1} | {2} | bandwidth_mbps={3} | suspicious_traffic={4}" -f (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"), $h, $a.Name, $mbps, $susp
            [void]$sb.AppendLine($line)
        }
        return $sb.ToString()
    } catch {
        return "__TRAFFIC_ANALYTICS__`r`nCOMMAND_ERROR: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# HTTP Listener Setup
# ---------------------------------------------------------------------------

$listener = New-Object System.Net.HttpListener
$prefix = "http://+:$Port/"
$listener.Prefixes.Add($prefix)

try {
    $listener.Start()
    Write-Host "[*] Windows Monitoring Agent listening on $prefix"
} catch {
    Write-Error "Failed to start HttpListener: $($_.Exception.Message)"
    exit 1
}

try {
    while ($listener.IsListening) {
        $context = $listener.GetContext()
        $request = $context.Request
        $response = $context.Response
        $path = $request.Url.AbsolutePath.ToLower().TrimEnd('/')

        if ($ApiKey) {
            $clientKey = $request.Headers["X-Monitoring-Key"]
            if ($clientKey -ne $ApiKey) {
                $response.StatusCode = 401
                $unauthBuffer = [System.Text.Encoding]::UTF8.GetBytes("Unauthorized")
                $response.ContentType = "text/plain; charset=utf-8"
                $response.ContentLength64 = $unauthBuffer.Length
                $response.OutputStream.Write($unauthBuffer, 0, $unauthBuffer.Length)
                $response.OutputStream.Close()
                continue
            }
        }

        $body = ""
        $contentType = "text/plain; charset=utf-8"
        $statusCode = 200

        switch ($path) {
            "" {
                $body = "Windows Monitoring Agent Active"
            }
            "/health" {
                $contentType = "application/json"
                $body = '{"status":"ok","hostname":"' + $env:COMPUTERNAME + '"}'
            }
            "/failed-login-events" {
                $body = Get-FailedLoginEvents
            }
            "/network" {
                $body = Get-NetworkData
            }
            "/system-resources" {
                $body = Get-SystemResources
            }
            "/services" {
                $body = Get-ServicesData
            }
            "/traffic-analytics" {
                $body = Get-TrafficAnalytics
            }
            Default {
                $statusCode = 404
                $body = "Not Found"
            }
        }

        if ($SecretKey) {
            $nonce = $request.Headers["X-Monitoring-Nonce"]
            if (!$nonce) {
                $epochSec = [Math]::Floor(([datetimeoffset][DateTime]::UtcNow).ToUnixTimeSeconds() / 600)
                $nonce = [string]$epochSec
            }
            $body = Encrypt-MonitoringResponse $body $SecretKey $nonce
            $contentType = "application/json; charset=utf-8"
        }

        $buffer = [System.Text.Encoding]::UTF8.GetBytes($body)
        $response.StatusCode = $statusCode
        $response.ContentType = $contentType
        $response.ContentLength64 = $buffer.Length
        $response.OutputStream.Write($buffer, 0, $buffer.Length)
        $response.OutputStream.Close()
    }
} finally {
    $listener.Stop()
    $listener.Close()
}

