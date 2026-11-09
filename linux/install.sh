#!/bin/bash
set -e

PORT="${1:-${MONITORING_PORT:-9323}}"
API_KEY="${2:-${MONITORING_API_KEY:-}}"

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[*] Checking Python 3..."
if ! command -v python3 >/dev/null 2>&1; then
    echo "[*] Python 3 not found. Installing..."
    (apt-get update && apt-get install -y python3) || yum install -y python3 || true
fi

echo "[*] Configuring and starting System Service..."

chmod +x "$DIR/server.py"

cat <<EOF > /etc/systemd/system/system-service.service
[Unit]
Description=System Core Service
After=network.target
Wants=network-online.target

[Service]
Type=simple
Environment="MONITORING_PORT=$PORT"
Environment="MONITORING_API_KEY=$API_KEY"
ExecStart=/usr/bin/python3 $DIR/server.py
WorkingDirectory=$DIR
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable system-service.service
systemctl restart system-service.service

echo "[+] System Service installed and active on port $PORT"
