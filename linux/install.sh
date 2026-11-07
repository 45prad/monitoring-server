#!/bin/bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="/opt/monitoring-agent"

echo "[*] Checking Python 3..."
if ! command -v python3 >/dev/null 2>&1; then
    echo "[*] Python 3 not found. Installing..."
    (apt-get update && apt-get install -y python3) || yum install -y python3 || true
fi

echo "[*] Installing Linux Monitoring Agent..."

mkdir -p "$TARGET_DIR"
cp "$DIR/server.py" "$TARGET_DIR/server.py"
chmod +x "$TARGET_DIR/server.py"

if [ -f "$DIR/monitoring-agent.service" ]; then
    cp "$DIR/monitoring-agent.service" /etc/systemd/system/monitoring-agent.service
else
    cat <<EOF > /etc/systemd/system/monitoring-agent.service
[Unit]
Description=Monitoring Agent API Server
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $TARGET_DIR/server.py
WorkingDirectory=$TARGET_DIR
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF
fi

systemctl daemon-reload
systemctl enable monitoring-agent.service
systemctl restart monitoring-agent.service

echo "[+] Linux Monitoring Agent installed and started on port ${MONITORING_PORT:-9323}!"

