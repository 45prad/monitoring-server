# VM Monitoring Agent

Standalone lightweight API agent running on target VMs (Linux and Windows) to collect system monitoring telemetry and logs without requiring Caldera.

## Architecture

The agent exposes an HTTP server on port `9323` (configurable via `MONITORING_PORT`) with 5 data endpoints:
- `GET /health` - Health and hostname check
- `GET /failed-login-events` - Collect Failed Login Events (T1087)
- `GET /network` - Firewall rules, active connections, and blocked IPs
- `GET /system-resources` - CPU, RAM, Disk utilization snapshots (T1082)
- `GET /services` - System service states and recent logs (T1087)
- `GET /traffic-analytics` - Network bandwidth Mbps and suspicious connection counts (T1049)

Output formats exactly match the output signatures parsed by the platform's monitoring module.

## Linux Setup
- Path: `linux/`
- Requires: Python 3 (standard library only, no external pip packages needed)
- Run installer:
  ```bash
  sudo bash install.sh
  ```
  This installs `server.py` to `/opt/monitoring-agent/` and registers/starts the `monitoring-agent.service` systemd unit.

## Windows Setup
- Path: `windows/`
- Requires: PowerShell 5.1+ (built into Windows, no extra dependencies)
- Run installer as Administrator / SYSTEM:
  ```powershell
  powershell -ExecutionPolicy Bypass -File .\install.ps1
  ```
  This creates `C:\MonitoringAgent`, opens port 9323 on Windows Firewall, registers a startup Scheduled Task running as SYSTEM, and starts the service.

