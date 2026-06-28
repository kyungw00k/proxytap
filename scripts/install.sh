#!/usr/bin/env bash
set -euo pipefail

OS="${1:-$(uname -s | tr A-Z a-z)}"
ARCH="${2:-$(uname -m)}"
case "$ARCH" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
esac

VERSION=$(curl -fsSL https://api.github.com/repos/kyungw00k/proxytap/releases/latest | grep -oP '"tag_name":\s*"\K[^"]+')
if [ -z "$VERSION" ]; then
  echo "could not determine latest version" >&2
  exit 1
fi

URL="https://github.com/kyungw00k/proxytap/releases/download/${VERSION}/proxytapd-${OS}-${ARCH}"
DST="${3:-/usr/local/bin/proxytapd}"
echo "Downloading $URL → $DST"
sudo install -m 0755 /dev/stdin "$DST" < <(curl -fsSL "$URL")

if [ "$OS" = "linux" ] && command -v systemctl >/dev/null; then
  sudo useradd --system --shell /usr/sbin/nologin --home /var/lib/proxytap proxytap 2>/dev/null || true
  sudo mkdir -p /var/lib/proxytap/cache
  sudo chown -R proxytap:proxytap /var/lib/proxytap
  sudo install -m 0644 scripts/proxytap.service /etc/systemd/system/proxytap.service 2>/dev/null || \
    sudo install -m 0644 /dev/stdin /etc/systemd/system/proxytap.service < \
    <(curl -fsSL https://raw.githubusercontent.com/kyungw00k/proxytap/master/scripts/proxytap.service)
  sudo systemctl daemon-reload
  sudo systemctl enable --now proxytap
  echo
  echo "Installed and started. Dashboard: http://127.0.0.1:9099/"
  echo "Use as HTTP proxy: http://127.0.0.1:8888"
fi
