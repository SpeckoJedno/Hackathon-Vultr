#!/bin/sh
# MailGuard sandbox firewall. Runs on the VM host (installed as a systemd unit by deploy.sh).
#
# Sandbox containers sit on their own Docker bridge "mg-sandbox" (172.30.99.0/24).
# Policy for traffic coming FROM that bridge:
#   - allowed: the public internet, and the demo web server (172.30.99.10:80)
#   - rejected: the VM itself (incl. its public IP and the MailGuard backend),
#               cloud metadata 169.254.169.254, Docker networks, private/VPC ranges.
# REJECT (not DROP) so hostile pages fail fast instead of hanging until the timeout.
# Idempotent: safe to run again at any time.
set -eu

IF="${SANDBOX_IF:-mg-sandbox}"
DEMO_IP="${DEMO_IP:-172.30.99.10}"
CHAIN=MAILGUARD-SBX

# Make same-bridge traffic (sandbox -> sandbox) go through iptables too.
modprobe br_netfilter 2>/dev/null || true
sysctl -qw net.bridge.bridge-nf-call-iptables=1 2>/dev/null || true

iptables -N "$CHAIN" 2>/dev/null || iptables -F "$CHAIN"
iptables -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
iptables -A "$CHAIN" -d "$DEMO_IP" -p tcp --dport 80 -j RETURN
for net in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 \
           192.168.0.0/16 198.18.0.0/15 224.0.0.0/4 240.0.0.0/4 ${PUBLIC_IP:+$PUBLIC_IP/32}; do
  iptables -A "$CHAIN" -d "$net" -p tcp -j REJECT --reject-with tcp-reset
  iptables -A "$CHAIN" -d "$net" -j REJECT --reject-with icmp-port-unreachable
done
iptables -A "$CHAIN" -j RETURN   # everything else (the internet): normal Docker NAT

# Forwarded traffic (to other containers, the metadata service, the internet).
# DOCKER-USER is evaluated before Docker's own rules and is never flushed by Docker.
iptables -N DOCKER-USER 2>/dev/null || true
iptables -C DOCKER-USER -i "$IF" -j "$CHAIN" 2>/dev/null || iptables -I DOCKER-USER 1 -i "$IF" -j "$CHAIN"

# Traffic addressed to the VM itself (any of its IPs): never allowed from the sandbox.
iptables -C INPUT -i "$IF" -p tcp -j REJECT --reject-with tcp-reset 2>/dev/null \
  || iptables -I INPUT 1 -i "$IF" -p tcp -j REJECT --reject-with tcp-reset
iptables -C INPUT -i "$IF" -j REJECT 2>/dev/null || iptables -I INPUT 2 -i "$IF" -j REJECT

echo "netguard: sandbox bridge $IF -> internet only (demo server $DEMO_IP allowed)"
