# Kudex VPN Manager

A terminal-first VPN and tunnel administration toolkit for Ubuntu and Debian.

> **Status: Foundation release (v0.1.0).** The installer, interactive CLI, service controls, diagnostics, and SSH account workflows are being established first. Xray protocol provisioning (VMess, VLESS, Trojan), WebSocket routing, and automated certificate management are planned modules; do not treat them as production-ready until their implementation and tests land.

## Supported systems

- Ubuntu 22.04 / 24.04 LTS
- Debian 12 (Bookworm)

Other releases are not yet tested and are intentionally rejected by the installer.

## Included service targets

| Component | Purpose |
|---|---|
| OpenSSH | SSH accounts and remote access |
| Dropbear | Lightweight SSH daemon (optional package) |
| Nginx | Reverse proxy and future WebSocket front end |
| Xray | VMess, VLESS and Trojan core (protocol module planned) |
| SSH-WS | SSH over WebSocket (routing module planned) |

The menu shows service state; it does not imply that an unimplemented protocol is already provisioned.

## Install

Clone the repository and run:

```bash
git clone https://github.com/Abdul1471/kudex-vpn-manager.git
cd kudex-vpn-manager
sudo bash install.sh
```

Then launch:

```bash
sudo kudex
```

## Safety notes

- Run only on a server you own or are authorized to administer.
- Keep an existing SSH session open while changing SSH settings.
- The installer does not replace your SSH configuration or change firewall rules.
- No default public passwords, hidden accounts, or stealth mechanisms are created.
- Review any proposed firewall, TLS, or listener changes before applying them.
- Back up `/etc/ssh`, `/etc/nginx`, and `/usr/local/etc/xray` before manual changes.

## Menu

```text
SSH       : service state
NGINX     : service state
XRAY      : service state
DROPBEAR  : service state
SSH-WS    : planned module

[01] SSH       [Menu]
[02] VMESS     [Menu]  (planned)
[03] VLESS     [Menu]  (planned)
[04] TROJAN    [Menu]  (planned)
[06] BACKUP
[07] DOMAIN & SSL (planned)
[08] CHECK RUNNING
[00] EXIT SYSTEM
```

## Project layout

```text
bin/kudex             Terminal menu
lib/common.sh         Shared validation and service helpers
install.sh            Dependency and launcher installer
```

## Uninstall

No automatic destructive uninstaller is provided in this foundation release. Remove the launcher and project files manually after reviewing what was installed.

## License

MIT. See [LICENSE](LICENSE).
