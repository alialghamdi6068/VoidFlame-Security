#!/usr/bin/env bash
set -euo pipefail

if [[ "$EUID" -ne 0 ]]; then
  echo "Run as root."
  exit 1
fi

apt-get update
apt-get install -y haproxy fail2ban nftables

install -d /etc/haproxy /etc/fail2ban/filter.d /etc/fail2ban/jail.d
install network/haproxy.cfg /etc/haproxy/haproxy.cfg
install network/fail2ban/filter.d/voidflame-minecraft.conf /etc/fail2ban/filter.d/voidflame-minecraft.conf
install network/fail2ban/jail.d/voidflame-minecraft.local /etc/fail2ban/jail.d/voidflame-minecraft.local

haproxy -c -f /etc/haproxy/haproxy.cfg
fail2ban-client -t
systemctl enable --now nftables
systemctl enable --now fail2ban
systemctl restart haproxy

echo "VoidFlame network protection installed."
echo "Review /etc/haproxy/haproxy.cfg and replace BACKEND_IP before exposing the service."
