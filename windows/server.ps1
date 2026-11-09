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
        $outRules = Get-NetFirewallRule | Out-String
        $outNetstat = netstat -ano | Out-String
        return "$outRules`r`n$outNetstat"
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
        $services = Get-Service -ErrorAction SilentlyContinue
        foreach ($service in $services) {
            [void]$sb.AppendLine("--------------------------------------------------------")
            [void]$sb.AppendLine("SERVICE : $($service.Name)")
            [void]$sb.AppendLine("STATUS  : $($service.Status)")
            $startup = (Get-CimInstance Win32_Service -Filter "Name='$($service.Name)'" -ErrorAction SilentlyContinue).StartMode
            [void]$sb.AppendLine("ENABLED : $startup")
            [void]$sb.AppendLine("")
        }
        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("==================== RECENT LOGS =======================")
        [void]$sb.AppendLine("")
        foreach ($service in $services) {
            [void]$sb.AppendLine("========================================================")
            [void]$sb.AppendLine("LOGS : $($service.Name)")
            [void]$sb.AppendLine("========================================================")
            $logs = Get-WinEvent -LogName System -MaxEvents 20 -ErrorAction SilentlyContinue |
                Where-Object { $_.Message -like "*$($service.Name)*" } |
                Select-Object TimeCreated, Id, LevelDisplayName, Message |
                Format-List | Out-String
            if ($logs) {
                [void]$sb.Append($logs)
            }
            [void]$sb.AppendLine("")
            [void]$sb.AppendLine("")
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

