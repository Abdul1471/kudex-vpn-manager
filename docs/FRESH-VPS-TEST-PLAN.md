# Kudex fresh VPS acceptance test plan

Use this checklist on a disposable VPS before relying on Kudex for customers. Prefer Ubuntu 24.04 LTS x86_64 for the first pass. Keep the cloud-provider console open and keep the original SSH connection alive throughout the test.

## 0. Before installation

- [ ] Create a VPS snapshot or rebuildable instance.
- [ ] Record the public IPv4/IPv6 address, OS release, CPU architecture, RAM, disk size, and provider firewall rules.
- [ ] Confirm TCP/22 SSH access works in a second terminal.
- [ ] Point a test domain's A/AAAA records to the VPS; wait for DNS propagation.
- [ ] Do not expose optional proxy or UDPGW ports yet.

Baseline commands:

```bash
cat /etc/os-release
uname -m
free -h
df -h /
sudo ss -lntup
sudo systemctl --failed
```

## 1. Install

```bash
sudo apt-get update
sudo apt-get install -y git
git clone https://github.com/Abdul1471/kudex-vpn-manager.git
cd kudex-vpn-manager
sudo bash install.sh
```

- [ ] Installer completes without errors.
- [ ] Existing OpenSSH remains reachable on its original port.
- [ ] If Dropbear is enabled, verify it listens on TCP/2222 and test a second login before closing the original SSH session.
- [ ] Launch `sudo kudex`; dashboard loads and no traceback appears.

Capture:

```bash
sudo systemctl --failed
sudo systemctl status ssh nginx dropbear --no-pager
sudo ss -lntup
```

## 2. Core server setup

- [ ] Run Kudex diagnostics and record warnings.
- [ ] Configure the test domain.
- [ ] Verify DNS resolves to this VPS from an external network.
- [ ] Request Let's Encrypt certificate; confirm Nginx config test passes and HTTPS opens.
- [ ] Install Xray; check the reported version and service status.
- [ ] Apply configuration; confirm Kudex validates Xray config before reload/restart.
- [ ] Reboot only if you deliberately choose to; confirm services return.

Useful checks:

```bash
sudo nginx -t
sudo systemctl status nginx xray --no-pager
sudo journalctl -u nginx -u xray -n 100 --no-pager
sudo ss -lntup
```

## 3. Account and client tests

Create one disposable account per protocol you intend to use.

- [ ] SSH: create, list, connect, renew, lock, unlock, delete.
- [ ] VMess WebSocket: create, copy link, import into a compatible client, connect, disable, re-enable, delete.
- [ ] VLESS WebSocket: repeat.
- [ ] Trojan WebSocket: repeat.
- [ ] SSH over WebSocket: verify the bridge and client connection.
- [ ] Reality and HTTPUpgrade: configure only after the base TLS/domain path works; test using a compatible client and confirm the actual negotiated transport.
- [ ] Confirm account names reject invalid characters and duplicate names.
- [ ] Confirm expired/disabled users cannot authenticate; check both SSH and Xray behavior.

Do not use real customer credentials for this test.

## 4. Optional services — one at a time

Enable only the service being tested. Check its configuration, service state, bound address, and port before moving to the next item.

- [ ] Stunnel4: confirm TLS listener and local SSH target.
- [ ] OpenVPN: provision a test client profile; import and connect from a separate device. Confirm no default-route/NAT/firewall changes were made unexpectedly.
- [ ] DNSTT/SlowDNS: verify generated keys, server unit, DNS delegation, and a real compatible client.
- [ ] Squid HTTP proxy: create a password, test authenticated access, then verify unauthenticated access is rejected. Remember Basic authentication is not encrypted without a protected tunnel.
- [ ] Dante SOCKS5: create a test user, test authentication, lock/unlock it, and confirm anonymous access fails. Protect the credential with a tunnel or trusted network.
- [ ] BadVPN UDPGW: leave bound to loopback unless you have a separate authenticated/protected access path; it has no client authentication.
- [ ] Google Drive: configure an rclone Drive remote on the VPS, create a backup, verify it appears in the expected remote folder, and test restore to a disposable location.
- [ ] Fail2ban: verify the Kudex SSH jail and test only with a controlled test account/IP; confirm the administrator IP is allowlisted.
- [ ] Connection guard: configure a correct administrator allowlist first. Test its nftables table and timer; do not simulate high connection counts against a production service.
- [ ] Session manager: list sessions and verify the current/root sessions are protected. Test termination only against a disposable secondary login.

## 5. Backup, restore, update and recovery

- [ ] Create a local backup.
- [ ] Inspect backup file permissions; it contains sensitive server configuration and may contain keys.
- [ ] Restore only on a disposable VPS or to a test environment first.
- [ ] Run `sudo kudex update`; verify a pre-update app backup is created and service state/data remain intact.
- [ ] Run OS package upgrade only after taking a VPS snapshot.
- [ ] Confirm the provider console can recover the VPS if networking or firewall configuration goes wrong.

## 6. Final evidence to collect

For every failed check, record the exact menu number, command, error text, expected behavior, and actual behavior. Do not paste private keys, passwords, bot tokens, client URIs, or backup archives into public issues.

```bash
cat /etc/os-release
uname -a
sudo systemctl --failed
sudo ss -lntup
sudo journalctl -p warning -n 150 --no-pager
sudo ls -lah /var/backups/kudex
```

## Release decision

A feature is considered **verified** only after its unit/static checks and the relevant fresh-VPS integration test pass. A menu item existing or a service unit being generated is not proof that the VPN client can connect. Record unsupported features as unavailable rather than treating them as completed.
