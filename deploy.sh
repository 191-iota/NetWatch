#!/bin/bash
set -e
source .env
cross build --release --target aarch64-unknown-linux-gnu
ssh ${PI_USER}@${PI_HOST} "sudo pkill netwatch || true"
scp target/aarch64-unknown-linux-gnu/release/netwatch ${PI_USER}@${PI_HOST}:${PI_PATH}/
ssh ${PI_USER}@${PI_HOST} "sudo setcap cap_net_raw=eip ${PI_PATH}/netwatch"
ssh $PI_USER@$PI_HOST "cat > /tmp/netwatch.service << 'EOF'
[Unit]
Description=NetWatch Network Monitor
After=network.target

[Service]
ExecStart=/home/algo/netwatch
WorkingDirectory=/home/algo
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF
sudo mv /tmp/netwatch.service /etc/systemd/system/ && sudo systemctl daemon-reload"
ssh $PI_USER@$PI_HOST "sudo systemctl restart netwatch"
echo "deployed and running"
