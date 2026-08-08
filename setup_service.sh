#!/usr/bin/env bash
# Setup script for the telegram-bot systemd service.
#
# Installs telegram-bot.service into /etc/systemd/system, reloads systemd,
# enables the service to start on boot and starts it immediately.
#
# Run as a user with sudo privileges:
#   ./setup_service.sh
#
# Expected layout (adjust SCRIPT_DIR if the repo is not in /home/ubuntu/telegram-bot):
#   /home/ubuntu/telegram-bot/
#       bot.py
#       .venv/bin/python
#       .env          (must exist; BOT_TOKEN + OWNER_ID required)

set -euo pipefail

SERVICE_NAME="telegram-bot"
SERVICE_FILE="telegram-bot.service"
SYSTEMD_DIR="/etc/systemd/system"
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -f "$INSTALL_DIR/.env" ]]; then
    echo "ERROR: $INSTALL_DIR/.env not found."
    echo "Copy .env.example to .env and fill in BOT_TOKEN / OWNER_ID first."
    exit 1
fi

if [[ ! -x "$INSTALL_DIR/.venv/bin/python" ]]; then
    echo "ERROR: virtualenv not found at $INSTALL_DIR/.venv"
    echo "Run: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"
    exit 1
fi

echo "[1/4] Installing $SERVICE_FILE into $SYSTEMD_DIR ..."
sudo install -o root -g root -m 644 "$INSTALL_DIR/$SERVICE_FILE" "$SYSTEMD_DIR/$SERVICE_FILE"

echo "[2/4] Reloading systemd daemon ..."
sudo systemctl daemon-reload

echo "[3/4] Enabling $SERVICE_NAME (start on boot) ..."
sudo systemctl enable "$SERVICE_NAME.service"

echo "[4/4] Starting $SERVICE_NAME ..."
sudo systemctl restart "$SERVICE_NAME.service"

echo
echo "Done. Useful commands:"
echo "  systemctl status $SERVICE_NAME        # service status"
echo "  journalctl -u $SERVICE_NAME -f        # live logs"
echo "  curl http://127.0.0.1:8080/api/healthz  # health check"
