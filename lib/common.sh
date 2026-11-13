#!/usr/bin/env bash
# Shared helpers for Kudex VPN Manager.
set -o pipefail

KUDEx_STATE_DIR="/var/lib/kudex"
KUDEx_LOG_DIR="/var/log/kudex"

kudex_info() { printf '[Kudex] %s\n' "$*"; }
kudex_warn() { printf '[WARNING] %s\n' "$*" >&2; }
kudex_error() { printf '[ERROR] %s\n' "$*" >&2; }

kudex_require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    kudex_error "This operation requires root. Run: sudo kudex"
    return 1
  fi
}

kudex_service_state() {
  local unit="$1"
  if ! command -v systemctl >/dev/null 2>&1; then
    printf 'unknown'
  elif ! systemctl list-unit-files "$unit" --no-legend 2>/dev/null | grep -q .; then
    printf 'not installed'
  elif systemctl is-active --quiet "$unit"; then
    printf 'ON'
  else
    printf 'OFF'
  fi
}

kudex_service_menu() {
  local label="$1" unit="$2" choice
  printf '\n%s service (%s)\n' "$label" "$(kudex_service_state "$unit")"
  printf '[1] Start  [2] Stop  [3] Restart  [4] Enable at boot  [5] Disable at boot  [0] Back\n'
  read -r -p 'Select: ' choice
  case "$choice" in
    1) systemctl start "$unit" ;;
    2) systemctl stop "$unit" ;;
    3) systemctl restart "$unit" ;;
    4) systemctl enable "$unit" ;;
    5) systemctl disable "$unit" ;;
    0) return 0 ;;
    *) kudex_warn "Invalid selection." ;;
  esac
}
