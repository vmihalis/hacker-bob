#!/usr/bin/env bash
set -euo pipefail

install -d -m 0755 /opt/kyberfork
test -x "$(command -v anvil)"
test -s /opt/kyberfork/kyberswap-fork.json

cat >/etc/systemd/system/kyberfork-anvil.service <<'UNIT'
[Unit]
Description=KyberFork anvil deterministic JSON-RPC node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/kyberfork
ExecStart=/usr/bin/env anvil --load-state kyberswap-fork.json --host 0.0.0.0 --port 8545 --no-request-size-limit
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now kyberfork-anvil.service
