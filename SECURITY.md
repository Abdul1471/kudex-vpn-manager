# Security Policy

## Supported versions

Security fixes target the current default branch.

## Reporting a vulnerability

Do not open a public issue containing credentials, private keys, VPN client URIs, or exploit details. Use GitHub's private vulnerability reporting for this repository where available, or contact the repository maintainer privately.

## Operational guidance

- Install only on servers you own or are authorized to administer.
- Protect /etc/kudex and /var/backups/kudex; both may contain authentication secrets.
- Keep OpenSSH on a known reachable port and retain an active recovery session.
- Review provider firewall rules before exposing ports.
- Never share VMess, VLESS, or Trojan URIs publicly.
- Keep Xray, Nginx, OpenSSH, Dropbear, and the operating system updated.
