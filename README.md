# Kudex VPN Manager

Kudex VPN Manager is a terminal-only administration tool for SSH accounts and Xray-based VMess, VLESS, Trojan, and SSH-over-WebSocket services.

> Current implementation: v0.2.0. Protocol provisioning, client CRUD, Xray config validation, Nginx WebSocket reverse proxy, Let's Encrypt webroot issuance, service controls, diagnostics, and configuration backups are implemented. Test on a fresh VPS before production use.

## Supported systems
- Ubuntu 22.04 / 24.04 LTS
- Debian 12 (Bookworm)
- amd64, arm64 and armv7 architectures supported by the pinned official Xray release

## Components

| Component | Purpose | Default |
|---|---|---|
| OpenSSH | SSH accounts, TCP/22 | enabled |
| Dropbear | Secondary SSH daemon, TCP/2222 | enabled |
| Nginx | HTTPS termination and WebSocket reverse proxy | enabled |
| Xray | VMess, VLESS, Trojan and SSH-WS inbounds | install from menu |
| SSH-WS | WebSocket bridge to OpenSSH TCP/22 | enabled in app config |

Dropbear uses TCP/2222 to avoid conflict with OpenSSH. Provider firewalls/security groups must allow TCP/80, 443, 22, and optionally 2222. Installer does not alter UFW/nftables or cloud firewall rules.

## Install

Clone this repository, enter its directory, and run:

    git clone https://github.com/Abdul1471/kudex-vpn-manager.git
    cd kudex-vpn-manager
    sudo bash install.sh
    sudo kudex

### Update later — no clone or reinstall required

Once Kudex is installed, use these commands directly on Ubuntu/Debian:

    sudo kudex update

This downloads the latest application files from the repository's main branch, validates the Python source, saves a pre-update backup, and replaces the installed Kudex program. Your VPN users, client credentials, domain, certificates, and server configuration remain in place. It does not reinstall packages or restart VPN services.

To update Ubuntu/Debian system packages as well:

    sudo kudex upgrade

This runs apt-get update followed by apt-get upgrade and asks for confirmation first. It upgrades operating-system packages, not the Kudex application.

To do both:

    sudo kudex update
    sudo kudex upgrade

You can also choose [13] UPDATE KUDEX APPLICATION or [14] UPGRADE UBUNTU/DEBIAN PACKAGES from the terminal menu. Keep your current SSH session open during system upgrades.

Installer installs dependencies and enables Nginx, OpenSSH and Dropbear. It does not change OpenSSH port or rewrite sshd_config. Existing Dropbear defaults are backed up before setting port 2222 and disabling Dropbear root login.

## First-time setup

1. Keep your existing SSH session open.
2. Allow provider firewall TCP ports 80 and 443; allow 2222 only if Dropbear is needed.
3. Choose [10] Install/Update Xray. The app downloads pinned official Xray-core v26.10.31 and verifies the archive against its accompanying SHA-256 digest.
4. Choose [07] DOMAIN & SSL. Use the manager to add/change a DNS name pointing to this server, issue a certificate, force-renew the current certificate, or inspect Certbot certificate details. Enter a valid email when configuring the domain. Certbot uses HTTP-01; public TCP/80 must be reachable.
5. Choose [11] APPLY CONFIG to validate and start Xray. Nginx config is tested before reload.
6. Add VMess, VLESS or Trojan accounts using menus [02], [03], [04]. Share URIs are shown only after TLS is ready.
7. For SSH over WebSocket, create a normal SSH account in menu [01], then enable SSH-WS in menu [05]. WebSocket path /ssh forwards to OpenSSH; SSH authentication remains enabled.

## Menu

    [01] SSH [Menu]
    [02] VMESS [Menu]
    [03] VLESS [Menu]
    [04] TROJAN [Menu]
    [05] SSH-WEBSOCKET [Menu]
    [06] BACKUP MANAGER
    [07] DOMAIN & SSL MANAGER
    [08] CHECK RUNNING
    [09] SERVICE CONTROL
    [10] INSTALL/UPDATE XRAY
    [11] APPLY CONFIG
    [12] RESTORE BACKUP
    [13] UPDATE KUDEX APPLICATION
    [14] UPGRADE UBUNTU/DEBIAN PACKAGES
    [15] BANDWIDTH MONITOR (live; daily/monthly via optional vnStat)
    [16] RESTART MANAGED SERVICES (SSH deliberately excluded)
    [17] PORTS & SERVER INFO
    [18] STUNNEL4 & OPENVPN\n    [19] SSH SECURITY MANAGER
    [00] EXIT SYSTEM

## Terminal dashboard and monitoring

The main screen shows live hostname, detected server interface IP, domain/TLS configuration, OS, local time, uptime, CPU and RAM readings, enabled VPN client counts, and actual systemd service states. Live traffic is read from `/proc/net/dev`. Historical daily/monthly totals are shown when optional `vnstat` is installed; Kudex does not invent historical totals when it is absent. Service states distinguish running, stopped, not installed, and waiting for TLS. The restart-all action intentionally excludes OpenSSH to reduce the risk of disconnecting a remote administrator.

## Trial, timed accounts and expiry

SSH, VMess, VLESS and Trojan account creation now asks for a validity period in days. Enter **1** for a one-day trial, a number from 1 to 36500 for a timed account, or **0** for an account without an expiry date. Xray clients carry an ISO-8601 expiry timestamp in the protected Kudex client database; expired clients are disabled and removed from the generated active Xray configuration when expiry enforcement runs. Kudex checks expiry while the dashboard and account menus are open. SSH accounts receive a Linux account-expiry date with `chage`; Kudex-managed SSH accounts are also tracked in `/etc/kudex/ssh-accounts.json`.

Use each protocol menu's **Renew account** option or SSH menu's **Renew account** option to extend validity and re-enable an account. An expired account cannot be manually unlocked without renewal. Existing accounts created before this feature have no recorded expiry and remain unchanged. Expiry is enforced while Kudex menus are open. For unattended enforcement of Xray client expiry, open **Backup Manager → Enable automatic account expiry checks**; this installs and enables a systemd timer that checks every five minutes. SSH account expiry is also enforced directly by the operating system through `chage`.

## Backup scheduling

The Backup Manager supports manual backups and automatic systemd-timer schedules every 12 or 24 hours. Backups include the protected `/etc/kudex` data, Xray configuration and Kudex Nginx site when present. Automatic jobs run as root and store archives under `/var/backups/kudex`. Choose **Disable automatic backups** to stop the timer. The Backup Manager also offers an optional systemd expiry timer that checks timed Xray accounts every five minutes. The current local backup scheduler does not upload archives to Telegram or Google Drive; remote backup integrations are a separate future feature. Treat every archive as sensitive because it contains account credentials.

The Domain & SSL menu supports certificate renewal on demand with Certbot's `--force-renewal` option. Use this only when needed; repeated forced renewals can consume Let's Encrypt rate limits. Normal automatic renewal remains managed by Certbot's system timer.

## Stunnel4 TLS and OpenVPN service controls

Menu **[18] Stunnel4 & OpenVPN** can install Stunnel4 from Ubuntu/Debian repositories after confirmation, then use the configured Let's Encrypt certificate to provide a separate TLS-wrapped SSH listener on TCP/444 forwarding to OpenSSH on loopback TCP/22. This avoids a port conflict with Nginx, which owns HTTPS TCP/443. Kudex stores the combined certificate/key file with root-only permissions and refreshes it from the Certbot deploy hook after certificate renewal. Open TCP/444 in the provider firewall only if you intend to use Stunnel4. The OpenVPN controls only manage an already-installed recognized systemd service; they do not create or replace OpenVPN server/client configuration.

## Network layout

Xray listens on loopback only:
- VMess WS: 127.0.0.1:10001, path /vmess
- VLESS WS: 127.0.0.1:10002, path /vless
- Trojan WS: 127.0.0.1:10003, path /trojan
- SSH-WS: 127.0.0.1:10004, path /ssh, forwards to 127.0.0.1:22

Nginx terminates TLS on TCP/443 and proxies WebSocket paths to Xray. Xray inbounds are not exposed directly on the public interface.

## Security notes

- Use only on infrastructure you own or are authorized to administer.
- No hidden accounts, default VPN passwords, interception, or stealth features are created.
- Account secrets and state are stored under /etc/kudex with root-only permissions.
- Xray config is tested before activation; Nginx config is tested before reload.
- OpenSSH configuration is not modified. Keep an existing SSH session open during remote-access changes.
- SSH-WS is only a transport bridge; it does not bypass SSH authentication.
- Dropbear root login is disabled. Confirm TCP/2222 is allowed by your provider firewall before relying on it.
- Certbot renewal is managed by the system package timer; verify with certbot renew --dry-run.
- Backups contain credentials and must be protected. Never publish client URIs; they contain secrets.

## Troubleshooting

    sudo systemctl status xray nginx ssh dropbear
    sudo journalctl -u xray -n 100 --no-pager
    sudo journalctl -u nginx -n 100 --no-pager
    sudo nginx -t
    sudo /usr/local/bin/xray run -test -config /usr/local/etc/xray/config.json
    sudo certbot renew --dry-run

## License
MIT. See LICENSE.

## SSH concurrent-login security

Menu **[19] SSH Security Manager** sets a per-user hard `maxlogins` limit using `/etc/security/limits.d/99-kudex-vpn.conf`. Choose a limit from 1 to 100, list configured rules, or remove a rule. The SSH account submenu also links to this manager. Kudex checks whether `pam_limits.so` appears in the common SSH PAM session files and warns if it cannot detect it. It does not rewrite PAM or OpenSSH configuration automatically; actual enforcement depends on the server's PAM session configuration. Keep an existing administrator session open while testing any access-control change. Root is protected from per-user changes.


## SlowDNS / DNSTT manager

Menu [20] SLOWDNS / DNSTT builds the upstream dnstt-server from its Go source, generates a persistent server keypair, displays the public key, and can create a systemd service listening on UDP/53 and forwarding tunnel streams to a chosen local TCP service (default 127.0.0.1:22). The service runs as a dedicated unprivileged dnstt account with only CAP_NET_BIND_SERVICE; the private key is readable only by that account and root.

A working DNS tunnel also requires a delegated DNS zone: create an A/AAAA record for the authoritative nameserver host pointing to this VPS, then delegate the tunnel subdomain with an NS record to that host. Allow inbound UDP/53 in provider and host firewalls. Kudex does not modify DNS records, firewall rules, or NAT. It refuses to start if UDP/53 is already occupied. Rotating the keypair invalidates the previous client public key; redistribute the new public key to authorized clients. Never share server.key.


## SSH banner editor and scheduled reboot

Menu [21] edits the SSH pre-login banner in /etc/issue.net and manages a dedicated sshd_config.d drop-in. Kudex validates the SSH daemon configuration with sshd -t before reloading the service. Disabling the feature removes only Kudex's drop-in and preserves the banner file.

Menu [22] can schedule or disable a daily VPS reboot using a systemd timer. Reboot scheduling is off by default and requires explicit confirmation. Reboots interrupt SSH, VPN tunnels, and all hosted workloads; choose a maintenance window in the server's local timezone.

Service Control [09] now discovers installed OpenSSH, Nginx, Xray, Dropbear, Stunnel4, DNSTT, OpenVPN, Cron, Squid, and Apache services. SSH stop/restart actions retain a separate confirmation warning.

## Telegram backup integration

Open **Backup Manager → Telegram backup integration** to configure a Telegram bot token and destination chat ID, test delivery, upload the latest local archive, or remove the saved credentials. Bot tokens are entered with hidden terminal input and stored in `/etc/kudex/telegram.json` with mode `0600`; the containing `/etc/kudex` directory is root-only. Create a bot with Telegram's `@BotFather`, start a private chat with it (or add it to a channel where it can post), and supply the destination chat ID or channel username. The connection test sends a visible test message.

When Telegram is configured, scheduled automatic backups also attempt to upload each new archive. A Telegram delivery failure does not delete or invalidate the local backup; the failure is written to the systemd service log. Manual backups remain local until you choose **Upload latest local backup**. Telegram credentials are deliberately excluded from Kudex backup archives and are not restored from them. Treat bot tokens as passwords; if a token was ever shared publicly or pasted into an untrusted template, revoke it with `@BotFather` and configure a fresh token.

Telegram upload availability and maximum document size depend on Telegram's current Bot API limits. Kudex reports Telegram's rejection without removing the local archive. This integration uploads backups to Telegram; downloading/restoring archives from Telegram is not currently included. Existing local restore remains available from the main menu.

Telegram restore is available from **Backup Manager → Telegram backup integration → Restore a backup sent to this bot**. Configure a numeric private-chat ID, then send the backup document from that same private chat to the bot. Kudex lists matching incoming documents, downloads the selected archive into /var/backups/kudex, and then opens the existing local restore confirmation flow. The normal restore routine still limits restored files to recognized Kudex configuration paths and validates Xray/Nginx configuration before applying changes. A Telegram webhook or another active getUpdates consumer can prevent polling; in that case, disable the webhook/other poller before using this restore option. Only send backups from a trusted private chat. Existing local backup files are never overwritten by a Telegram download.

Backup Manager also includes **Verify a backup archive**. It checks that the archive can be read, rejects links and special filesystem entries, validates recognized JSON configuration files, and confirms that recognized Kudex restore files are present. Verification does not modify the server or restore the archive.

## Server speed test and smart backup retention

Menu **[23] Server Speed Test** runs the installed Speedtest CLI after an explicit confirmation because the test transfers data and consumes bandwidth. If no CLI is installed, Kudex offers to install the Ubuntu/Debian `speedtest-cli` package. The test uses external test servers; results depend on the selected server and network conditions.

Backup Manager → **[10] Smart backup retention** can keep the latest 5–100 local Kudex archives. Automatic rotation is disabled until an administrator enables a retention policy. Once enabled, new scheduled or manual backups trigger rotation after the new archive is safely written. The administrator must confirm before an immediate cleanup; disabling retention preserves existing archives. Only matching regular Kudex backup archives in `/var/backups/kudex` are eligible, and Telegram copies are never deleted.

The dashboard now displays the latest local backup filename and the backup/reboot timer states, alongside the existing VPS, resource, client, and service information.

Backup Manager → **[11] Smart backup sync** can mirror each new local Kudex archive to an already-mounted external disk or network share. Configure the mount point once; Kudex writes copies into its `KudexBackups` subdirectory and creates a SHA-256 checksum sidecar. The mount must already be active when a backup runs. If it is disconnected or the copy fails, the local backup is retained and Kudex reports a sync warning. Manual sync of the latest archive is also available. Disabling sync does not delete existing copies on the mounted destination. This is mounted-storage mirroring, not a built-in Google Drive client.

## Account expiry cleanup

SSH Account Manager → **[8] Clean expired** lists only Kudex-managed SSH users whose recorded expiry has passed, then asks for confirmation before deleting their Linux accounts and home directories. It also removes their Kudex concurrency-limit entries. Existing SSH sessions can remain active until they disconnect. VMess, VLESS, and Trojan account menus include **[6] Clean expired**, which removes expired client records and reapplies the validated Xray configuration; if applying the new configuration fails, Kudex restores the previous client database.
