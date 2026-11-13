#!/usr/bin/env bash
set -Eeuo pipefail
INSTALL_DIR="/opt/kudex-vpn-manager"
BIN_PATH="/usr/local/sbin/kudex"
info() { printf '[Kudex] %s\n' "$*"; }
die() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }
[[ "$EUID" -eq 0 ]] || die "Run with sudo: sudo bash install.sh"
command -v apt-get >/dev/null 2>&1 || die "Only apt-based Ubuntu/Debian systems are supported."
[[ -r /etc/os-release ]] || die "Cannot identify operating system."
. /etc/os-release
case "$ID" in
 ubuntu) [[ "$VERSION_ID" == "22.04" || "$VERSION_ID" == "24.04" ]] || die "Supported Ubuntu versions: 22.04 and 24.04." ;;
 debian) [[ "$VERSION_ID" == "12" ]] || die "Supported Debian version: 12." ;;
 *) die "Supported operating systems: Ubuntu 22.04/24.04 and Debian 12." ;;
esac
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
[[ -f "$SCRIPT_DIR/lib/kudex.py" && -f "$SCRIPT_DIR/bin/kudex" ]] || die "Run from repository root."
export DEBIAN_FRONTEND=noninteractive
info "Installing dependencies..."
apt-get update
apt-get install -y --no-install-recommends bash coreutils curl ca-certificates openssl python3 nginx openssh-server dropbear certbot
info "Configuring Dropbear on TCP/2222; OpenSSH remains on TCP/22."
if [[ -f /etc/default/dropbear ]]; then cp -a /etc/default/dropbear "/etc/default/dropbear.kudex-backup.$(date +%s)"; fi
cat > /etc/default/dropbear <<'DROPBEAR'
# Managed by Kudex VPN Manager. OpenSSH remains on TCP/22.
NO_START=0
DROPBEAR_PORT=2222
DROPBEAR_EXTRA_ARGS="-w"
DROPBEAR
chmod 0644 /etc/default/dropbear
info "Installing Kudex application..."
install -d -m 0755 "$INSTALL_DIR/bin" "$INSTALL_DIR/lib" /var/www/kudex-acme
install -d -m 0700 /etc/kudex /var/lib/kudex /var/log/kudex /var/backups/kudex
install -m 0755 "$SCRIPT_DIR/bin/kudex" "$INSTALL_DIR/bin/kudex"
install -m 0644 "$SCRIPT_DIR/lib/kudex.py" "$INSTALL_DIR/lib/kudex.py"
install -m 0644 "$SCRIPT_DIR/lib/common.sh" "$INSTALL_DIR/lib/common.sh"
install -m 0755 "$SCRIPT_DIR/install.sh" "$INSTALL_DIR/install.sh"
ln -sfn "$INSTALL_DIR/bin/kudex" "$BIN_PATH"
if [[ ! -e /etc/kudex/state.json ]]; then
 cat > /etc/kudex/state.json <<'STATE'
{
 "domain": "",
 "email": "",
 "tls": false,
 "protocols": {"vmess": true, "vless": true, "trojan": true, "sshws": true}
}
STATE
 chmod 0600 /etc/kudex/state.json
fi
if [[ ! -e /etc/kudex/clients.json ]]; then printf '[]\n' > /etc/kudex/clients.json; chmod 0600 /etc/kudex/clients.json; fi
systemctl enable --now nginx.service
if systemctl list-unit-files ssh.service --no-legend 2>/dev/null | grep -q .; then
 systemctl enable --now ssh.service
elif systemctl list-unit-files sshd.service --no-legend 2>/dev/null | grep -q .; then
 systemctl enable --now sshd.service
fi
if systemctl list-unit-files dropbear.service --no-legend 2>/dev/null | grep -q .; then
 systemctl enable --now dropbear.service || info "Dropbear did not start; inspect systemctl status dropbear."
fi
if [[ -t 0 ]]; then
 read -r -p "Install official Xray-core now? [Y/n]: " answer
 if [[ -z "$answer" || "$answer" =~ ^[Yy]$ ]]; then
  python3 "$INSTALL_DIR/lib/kudex.py" --install-xray --yes
  python3 "$INSTALL_DIR/lib/kudex.py" --apply-config
 fi
fi
info "Installation complete. Open provider firewall TCP/2222 if Dropbear is required."
info "Keep your current SSH session open. Launch: sudo kudex"
info "Then choose [10] Install/Update Xray, [07] DOMAIN & SSL, and [11] APPLY CONFIG."
