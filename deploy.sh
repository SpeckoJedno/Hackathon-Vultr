#!/usr/bin/env bash
# One-command deploy on the Vultr VM (Ubuntu 24.04 with Docker), run from the repo root:
#   ./deploy.sh
set -euo pipefail
cd "$(dirname "$0")"

PUBLIC_HOST="${PUBLIC_HOST:-$(curl -fsS -m 5 http://169.254.169.254/v1/interfaces/0/ipv4/address 2>/dev/null || hostname -I | awk '{print $1}')}"
echo "==> Public host: $PUBLIC_HOST"

if [ ! -f .env ]; then
  cp .env.example .env
  echo "!!  Created .env from .env.example. Put your VULTR_INFERENCE_KEY in .env and run ./deploy.sh again."
  exit 1
fi
chmod 600 .env
grep -q '^PUBLIC_HOST=' .env || echo "PUBLIC_HOST=$PUBLIC_HOST" >> .env
export PUBLIC_HOST

echo "==> Demo files"
[ -f demo/attachment.eml ] || python3 demo/make_attachment_eml.py

echo "==> Building sandbox image (Playwright + Chromium)"
docker compose --profile build-only build sandbox

echo "==> Starting backend + demo web server"
docker compose up -d --build backend demo-web

echo "==> Installing sandbox firewall"
install -m 755 deploy/netguard.sh /opt/mailguard-netguard.sh
echo "PUBLIC_IP=$PUBLIC_HOST" > /etc/mailguard-netguard.env
install -m 644 deploy/netguard.service /etc/systemd/system/mailguard-netguard.service
systemctl daemon-reload
systemctl enable mailguard-netguard.service >/dev/null
systemctl restart mailguard-netguard.service
iptables -S MAILGUARD-SBX | head -4

if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
  ufw allow 80/tcp >/dev/null && echo "==> ufw: allowed port 80"
fi

echo "==> Health"
for i in $(seq 1 20); do
  if curl -fsS http://127.0.0.1/api/health; then echo; break; fi; sleep 2
done
echo "==> MailGuard is up at http://$PUBLIC_HOST"
