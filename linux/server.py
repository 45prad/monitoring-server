#!/usr/bin/env python3
"""
Monitoring Agent API Server - Linux
Runs on each target VM and exposes 5 endpoints that replicate exactly
what the Caldera APT "Monitoring..." used to collect.

Endpoints (all GET):
  /health                  -> liveness check
  /failed-login-events     -> Collect Failed Login Events
  /network                 -> Collect Firewall and IPTable Logs
  /system-resources        -> Collect Raw System Resource Data
  /services                -> Collect Service Logs
  /traffic-analytics       -> Collect Traffic Analytics Numbers

Default port: 9323 (configurable via MONITORING_PORT env var)
"""

import os
import subprocess
import time
import json
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

PORT = int(os.environ.get("MONITORING_PORT", 9323))
API_KEY = os.environ.get("MONITORING_API_KEY", "")


# ---------------------------------------------------------------------------
# Shell helpers
# ---------------------------------------------------------------------------

def run_shell(cmd, timeout=60):
    """Run a shell command and return stdout as a string."""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            executable="/bin/bash",
        )
        return result.stdout.decode("utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        return "COMMAND_TIMEOUT"
    except Exception as e:
        return f"COMMAND_ERROR: {e}"


# ---------------------------------------------------------------------------
# Data collectors  — each function returns a plain-text string identical to
# what the corresponding Caldera executor used to produce.
# ---------------------------------------------------------------------------

def collect_failed_login_events():
    cmd = r"""
printf "__FAILED_LOGIN_EVENTS__\n"
H=$(hostname)
if command -v journalctl >/dev/null 2>&1; then
    journalctl -u ssh -u sshd --since "30 days ago" --no-pager -o short-iso 2>/dev/null
else
    cat /var/log/auth.log /var/log/secure 2>/dev/null
fi | grep -Ei "failed password|invalid user|authentication failure|failed publickey" \
   | awk -v h="$H" 'BEGIN{OFS=" | "} {
       ip=""
       if(match($0,/from ([0-9]{1,3}\.){3}[0-9]{1,3}/)) ip=substr($0,RSTART+5,RLENGTH-5)
       else if(match($0,/rhost=([^ ]+)/)) ip=substr($0,RSTART+6,RLENGTH-6)
       print $1,h,"Failed Login",ip,$0
     }'
"""
    return run_shell(cmd)


def collect_network():
    cmd = r"""
echo "================ FIREWALL RULES ================"
sudo iptables -L INPUT -n --line-numbers 2>/dev/null | tail -n +3 | while read num target prot opt source destination extra; do
    port=$(echo "$extra" | grep -o 'dpt:[0-9]*' | cut -d: -f2)
    echo "--------------------------------------------------"
    echo "RULE ID     : FW-$num"
    echo "INTERFACE   : ANY"
    echo "SOURCE      : $source"
    echo "DESTINATION : $destination"
    echo "PROTOCOL    : $prot"
    echo "PORT        : ${port:-ANY}"
    echo "ACTION      : $target"
    echo
done

echo
echo "================ ACTIVE CONNECTIONS ================"
ss -tunapH 2>/dev/null | while read proto state recvq sendq local peer process; do
    local_addr=$(echo "$local" | rev | cut -d: -f2- | rev)
    local_port=$(echo "$local" | rev | cut -d: -f1 | rev)
    remote_addr=$(echo "$peer" | rev | cut -d: -f2- | rev)
    remote_port=$(echo "$peer" | rev | cut -d: -f1 | rev)
    echo "--------------------------------------------------"
    echo "PROTOCOL       : $proto"
    echo "LOCAL ADDRESS  : $local_addr"
    echo "LOCAL PORT     : $local_port"
    echo "REMOTE ADDRESS : $remote_addr"
    echo "REMOTE PORT    : $remote_port"
    echo "STATE          : $state"
    echo
done

echo
echo "================ BLOCKED IPS ================"
sudo iptables -L INPUT -n --line-numbers 2>/dev/null | grep DROP | while read num target prot opt source destination extra; do
    port=$(echo "$extra" | grep -o 'dpt:[0-9]*' | cut -d: -f2)
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "--------------------------------------------------"
    echo "TIME        : $timestamp"
    echo "BLOCKED IP  : $source"
    echo "INTERFACE   : ANY"
    echo "PROTOCOL    : $prot"
    echo "PORT        : ${port:-ANY}"
    echo
done
"""
    return run_shell(cmd)


def collect_system_resources():
    cmd = r"""
printf "__TIMESTAMP__\n"; date -u +"%Y-%m-%dT%H:%M:%SZ"
printf "__HOSTNAME__\n";  hostname
printf "__UNAME__\n";     uname -a
printf "__LOADAVG__\n";   cat /proc/loadavg
printf "__CPU_STAT_1__\n"; head -n 1 /proc/stat
sleep 1
printf "__CPU_STAT_2__\n"; head -n 1 /proc/stat
printf "__MEMINFO__\n";   grep -E "MemTotal|MemFree|MemAvailable|Buffers|Cached|SwapTotal|SwapFree" /proc/meminfo
printf "__DF__\n";        df -P /
"""
    return run_shell(cmd, timeout=65)


def collect_services():
    cmd = r"""
echo "==================== SERVICE STATUS ===================="
echo

services=$(systemctl list-units --type=service --all --no-legend 2>/dev/null | awk '{print $1}' | grep '\.service$')

for service in $services; do
    echo "--------------------------------------------------------"
    echo "SERVICE : $service"
    echo "STATUS  : $(systemctl is-active "$service" 2>/dev/null)"
    echo "ENABLED : $(systemctl is-enabled "$service" 2>/dev/null)"
    echo
done

echo
echo "==================== RECENT LOGS ======================="
echo

for service in $services; do
    echo "========================================================"
    echo "LOGS : $service"
    echo "========================================================"
    journalctl -u "$service" -n 20 --no-pager 2>/dev/null
    echo
    echo
done
"""
    return run_shell(cmd, timeout=60)


def collect_traffic_analytics():
    cmd = r"""
printf "__TRAFFIC_ANALYTICS__\n"
H=$(hostname)
IF=$(ip route 2>/dev/null | awk '/default/ {print $5; exit}')
[ -z "$IF" ] && IF=$(awk -F: 'NR>2 && $1 !~ /lo/ {gsub(/ /,"",$1); print $1; exit}' /proc/net/dev)
B1=$(awk -v i="$IF:" '$1==i {print $2+$10}' /proc/net/dev)
sleep 1
B2=$(awk -v i="$IF:" '$1==i {print $2+$10}' /proc/net/dev)
MBPS=$(awk -v a="$B1" -v b="$B2" 'BEGIN{printf "%.2f", ((b-a)*8)/1000000}')
SUSP=$(ss -Htun 2>/dev/null | awk 'BEGIN{c=0} $0 ~ /(SYN-SENT|SYN-RECV|:23 |:23$|:445 |:445$|:3389 |:3389$|:4444 |:4444$|:31337 |:31337$)/ {c++} END{print c+0}')
printf "%s | %s | %s | bandwidth_mbps=%s | suspicious_traffic=%s\n" \
    "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "$H" "$IF" "$MBPS" "$SUSP"
"""
    return run_shell(cmd, timeout=65)


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

ROUTES = {
    "/health":               lambda: json.dumps({"status": "ok", "hostname": socket.gethostname()}),
    "/failed-login-events":  collect_failed_login_events,
    "/network":              collect_network,
    "/system-resources":     collect_system_resources,
    "/services":             collect_services,
    "/traffic-analytics":    collect_traffic_analytics,
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Suppress default access log to stdout noise; real errors still print.
        pass

    def _send(self, code, body, content_type="text/plain; charset=utf-8"):
        encoded = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        path = urlparse(self.path).path

        # Optional API key auth
        if API_KEY:
            token = self.headers.get("X-Monitoring-Key", "")
            if token != API_KEY:
                self._send(401, "Unauthorized")
                return

        handler_fn = ROUTES.get(path)
        if handler_fn is None:
            self._send(404, "Not Found")
            return

        try:
            result = handler_fn()
            if path == "/health":
                self._send(200, result, "application/json")
            else:
                self._send(200, result)
        except Exception as e:
            self._send(500, f"Internal Error: {e}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"[monitoring-agent] Listening on 0.0.0.0:{PORT}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass

