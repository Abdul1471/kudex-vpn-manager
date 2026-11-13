#!/usr/bin/env bash
set -Eeuo pipefail
INSTALL_DIR="/opt/kudex-vpn-manager"
BIN_PATH="/usr/local/sbin/kudex"
LICENSE_API="https://kudex-license-api.yabdulqudus1471.workers.dev"
info() { printf '[Kudex] %s\n' "$*"; }
die() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }
valid_dns_name() {
 local value="${1%.}"
 [[ ${#value} -le 253 ]] || return 1
 [[ "$value" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$ ]]
}
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

# Bootstrap only the HTTPS client needed to contact the licensing service.
export DEBIAN_FRONTEND=noninteractive
info "Preparing secure connection to KudexTech licensing..."
apt-get update
apt-get install -y --no-install-recommends curl ca-certificates

AUTH_RESPONSE="$(mktemp)"
trap 'rm -f "$AUTH_RESPONSE"' EXIT
if ! curl --silent --show-error --fail --max-time 20 \
  --request POST "$LICENSE_API/api/authenticate" \
  --header "Accept: application/json" \
  --output "$AUTH_RESPONSE"; then
  die "Could not reach KudexTech License API. Installation stopped before domain setup."
fi
if ! grep -Eq '"authenticated"[[:space:]]*:[[:space:]]*true' "$AUTH_RESPONSE"; then
  printf '\n'
  info "This VPS IP is not currently licensed."
  info "For a free 24-hour trial, run this on the VPS: curl -X POST $LICENSE_API/trialip"
  info "Alternatively, ask the administrator to assign a 30-day or Lifetime license to this VPS IP."
  info "License API response:"
  cat "$AUTH_RESPONSE"
  die "VPS authentication failed. No VPN services have been installed or configured."
fi
rm -f "$AUTH_RESPONSE"
trap - EXIT
info "VPS IP authenticated successfully."

POINTED_DOMAIN=""
NAMESERVER=""
if [[ -t 0 ]]; then
  while true; do
    read -r -p "Enter Pointed Domain (e.g. vpn.example.com): " POINTED_DOMAIN
    POINTED_DOMAIN="${POINTED_DOMAIN,,}"
    POINTED_DOMAIN="${POINTED_DOMAIN%.}"
    valid_dns_name "$POINTED_DOMAIN" && break
    info "Invalid hostname. Enter a full domain such as vpn.example.com."
  done
  while true; do
    read -r -p "Enter NameServer (e.g. ns.vpn.example.com): " NAMESERVER
    NAMESERVER="${NAMESERVER,,}"
    NAMESERVER="${NAMESERVER%.}"
    valid_dns_name "$NAMESERVER" && break
    info "Invalid nameserver hostname. Enter a full hostname such as ns.vpn.example.com."
  done
fi

info "Installing Kudex VPN Manager dependencies..."
apt-get install -y --no-install-recommends bash coreutils openssl python3 nginx openssh-server dropbear certbot
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
 if ! python3 "$INSTALL_DIR/lib/kudex.py" --configure-pointed-domain "$POINTED_DOMAIN" "$NAMESERVER"; then
  info "Domain setup did not finish. You can retry later from sudo kudex → [07] DOMAIN & SSL."
 fi
else
 info "Non-interactive install: domain and nameserver prompts were skipped."
fi
info "Installation complete. Open provider firewall TCP/2222 if Dropbear is required."
info "Keep your current SSH session open. Launch: sudo kudex"
info "Then choose [10] Install/Update Xray, [07] DOMAIN & SSL, and [11] APPLY CONFIG."
