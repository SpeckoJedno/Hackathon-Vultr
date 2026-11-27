#!/usr/bin/env bash
# One-shot setup on a fresh Ubuntu 22.04/24.04 Vultr VM. Run as root:
#   bash setup_vm.sh <git-repo-url>
set -euo pipefail
REPO="${1:?usage: setup_vm.sh <git-repo-url>}"
apt-get update
apt-get install -y docker.io git python3-venv
systemctl enable --now docker
git clone "$REPO" /opt/mailguard
cd /opt/mailguard
python3 -m venv .venv
.venv/bin/pip install -r mailguard/requirements.txt
docker pull python:3.12-alpine
(cd mailguard && ../.venv/bin/python make_samples.py)
if [ ! -f /etc/mailguard.env ]; then
  printf 'VULTR_INFERENCE_API_KEY=\nMODEL=\n' > /etc/mailguard.env
  chmod 600 /etc/mailguard.env
fi
cp mailguard/deploy/mailguard.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now mailguard
echo "Done. Put your key in /etc/mailguard.env, then: systemctl restart mailguard"
