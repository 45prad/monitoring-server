#!/bin/bash
set -e

TARGET_DIR="/opt/monitoring-agent"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || echo "")"
REPO_RAW_URL="https://raw.githubusercontent.com/45prad/monitoring-server/main/linux"

echo "[*] Installing Linux Monitoring Agent..."

mkdir -p "$TARGET_DIR"

# 1. Copy server.py from local directory or download from GitHub if piped via curl
if [ -n "$DIR" ] && [ -f "$DIR/server.py" ]; then
    cp "$DIR/server.py" "$TARGET_DIR/server.py"
else
    echo "[*] Fetching server.py from GitHub..."
    curl -sL "$REPO_RAW_URL/server.py" -o "$TARGET_DIR/server.py"
fi
chmod +x "$TARGET_DIR/server.py"

# 2. Determine python3 binary
PYTHON_BIN="$(command -v python3 || echo "/usr/bin/python3")"

# 3. Create systemd service unit
cat <<EOF > /etc/systemd/system/monitoring-agent.service
[Unit]
Description=Monitoring Agent API Server
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$PYTHON_BIN $TARGET_DIR/server.py
WorkingDirectory=$TARGET_DIR
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

# 4. Enable and start service
systemctl daemon-reload
systemctl enable monitoring-agent.service
systemctl restart monitoring-agent.service

echo "[+] Linux Monitoring Agent installed and running on port ${MONITORING_PORT:-9323}!"
