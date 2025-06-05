#!/bin/bash
set -e

AGENT_DIR="/opt/platform_agent"
SERVICE_NAME="platform-agent"
PYTHON_BIN="$(which python3)"

# Create agent directory
sudo mkdir -p $AGENT_DIR
sudo cp $(dirname "$0")/client.py $AGENT_DIR/
sudo cp $(dirname "$0")/client_config.json $AGENT_DIR/

# Create systemd service file
SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME.service"

sudo bash -c "cat > $SERVICE_FILE" <<EOL
[Unit]
Description=Platform Agent Service
After=network.target

[Service]
Type=simple
ExecStart=$PYTHON_BIN $AGENT_DIR/client.py
Restart=always
User=root
WorkingDirectory=$AGENT_DIR

[Install]
WantedBy=multi-user.target
EOL

# Reload systemd, enable and start service
sudo systemctl daemon-reload
sudo systemctl enable $SERVICE_NAME
sudo systemctl restart $SERVICE_NAME

echo "Agent installed and running as service: $SERVICE_NAME" 