#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="kudex-vpn-manager"
INSTALL_DIR="/opt/kudex-vpn-manager"
BIN_PATH="/usr/local/sbin/kudex"

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
info() { printf '[Kudex] %s\n' "$*"; }

[[ "${EUID}" -eq 0 ]] || die "Run with sudo: sudo bash install.sh"
command -v apt-get >/dev/null 2>&1 || die "This installer currently supports apt-based Ubuntu/Debian only."
[[ -r /etc/os-release ]] || die "Cannot identify operating system."
. /etc/os-release

case "${ID:-}" in
  ubuntu)
    case "${VERSION_ID:-}" in 22.04|24.04) ;; *) die "Unsupported Ubuntu version: ${VERSION_ID:-unknown}. Supported: 22.04 and 24.04." ;; esac
    ;;
  debian)
    case "${VERSION_ID:-}" in 12) ;; *) die "Unsupported Debian version: ${VERSION_ID:-unknown}. Supported: Debian 12." ;; esac
    ;;
  *) die "Unsupported OS: ${ID:-unknown}. Use Ubuntu 22.04/24.04 or Debian 12." ;;
esac

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
[[ -f "$SCRIPT_DIR/bin/kudex" && -f "$SCRIPT_DIR/lib/common.sh" ]] || die "Run this installer from the repository root."

info "Installing baseline dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends bash coreutils curl ca-certificates openssl python3 nginx openssh-server

info "Installing Kudex files..."
install -d -m 0755 "$INSTALL_DIR/bin" "$INSTALL_DIR/lib" /var/lib/kudex /var/log/kudex
install -m 0755 "$SCRIPT_DIR/bin/kudex" "$INSTALL_DIR/bin/kudex"
install -m 0644 "$SCRIPT_DIR/lib/common.sh" "$INSTALL_DIR/lib/common.sh"
ln -sfn "$INSTALL_DIR/bin/kudex" "$BIN_PATH"

if systemctl list-unit-files ssh.service >/dev/null 2>&1; then
  systemctl enable ssh.service
  systemctl start ssh.service
elif systemctl list-unit-files sshd.service >/dev/null 2>&1; then
  systemctl enable sshd.service
  systemctl start sshd.service
fi

info "Baseline installation complete."
info "No firewall rules or existing SSH settings were modified."
info "Launch with: sudo kudex"
