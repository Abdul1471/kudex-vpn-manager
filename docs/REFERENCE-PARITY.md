# Kudex VPN Manager — Reference Feature Parity

This document tracks the requested feature parity with the user-provided
"TheTechSavage Premium VPS Manager (Final Edition)" reference. Kudex retains
its own name, code, and branding; this is a functional compatibility target,
not a copy of another project's identity or proprietary implementation.

## Current baseline

Already present in Kudex:
- SSH account creation, renewal, locking, expiry tracking, and manual expired-account cleanup
- VMess, VLESS, and Trojan WebSocket client management and share links
- Xray configuration validation before activation
- Nginx TLS termination and WebSocket reverse proxy
- SSH over WebSocket, Dropbear, and Stunnel4
- OpenVPN service controls (not full OpenVPN provisioning)
- DNSTT/SlowDNS server/key management
- SSH concurrency limits, banner editor, daily reboot scheduler
- Backups, scheduled backups, Telegram upload/restore, retention, mounted-storage sync
- Service controls, diagnostics, bandwidth monitoring, speed test, OTA update, OS upgrade

## Reference parity backlog

| Reference capability | Kudex status | Required work |
|---|---|---|
| VMess / VLESS / Trojan WebSocket | Implemented | Keep compatibility tests and client URI tests |
| VLESS Reality / XTLS-style Reality transport | Implemented (opt-in, VLESS + Vision) | Separate TCP/8443 listener; generated X25519 keys; configured target/serverName/short ID; share URI and config unit tests. Still requires live-core/VPS verification |
| HTTPUpgrade transport | Implemented (opt-in for VMess/VLESS/Trojan) | Loopback listeners TCP/10005–10007, Nginx TLS routes, client links and unit tests. Still requires live-core/VPS verification |
| SSH, Dropbear, Stunnel4 | Partial | Align configurable listener ports while detecting conflicts and preserving existing SSH access |
| SSH-WS on TCP/80 | Not implemented as a dedicated listener | Add an explicit listener option with conflict checks; do not silently take Nginx port 80 |
| HTTPS VPN listener on TCP/443 | Partial | Existing Nginx terminates TLS; add supported transport routing without breaking ACME |
| HTTP proxy on TCP/8880 | Not implemented | Add authenticated proxy provisioning, service lifecycle, firewall guidance, and tests |
| OpenVPN TCP/UDP provisioning | Not implemented | Add server/client configuration lifecycle; current menu only controls existing services |
| OHP custom-header transport | Not implemented | Add supported OHP service and client configuration only after compatibility tests |
| SlowDNS / DNSTT | Partial | Add multiple named profiles/custom keypairs and safe rotation/rollback |
| Dante SOCKS5 on TCP/1080 | Not implemented | Add authenticated SOCKS5 service, account lifecycle integration, port checks, and tests |
| BadVPN UDPGW | Not implemented | Add UDP gateway service lifecycle and port-range validation |
| Premium cloud license | Not implemented | Requires a real licensing API, issuer, terms, and secure server-side validation; no fake/offline success mode |
| Telegram cloud backup/restore | Partial | Current implementation uploads and restores documents sent to the configured bot chat; arbitrary share-link restore is not supported |
| Google Drive backup/restore | Not implemented | Requires OAuth/client configuration and secure token storage |
| OTA application update | Implemented | Preserve pre-update backup and validate release contents |
| Automatic expiry | Partial | Existing expiry checks run every five minutes; add configurable expiry policy and optional session termination after safe identity checks |
| Anti-multilogin / live session termination | Partial | Existing PAM maxlogins limit; implement reliable session tracking, protected-admin exclusions, and explicit termination confirmation |
| Three-strike account lock | Not implemented | Requires reliable authentication-failure event collection, threshold/window policy, and recovery flow |
| DDoS-Deflate / connection protection | Not implemented | Add conservative rate detection, temporary bans, allowlists, expiry, and firewall rollback safeguards |
| RAM maintenance | Not implemented | Provide diagnostics and safe maintenance; do not market cache dropping as a performance fix |
| Scheduled reboot | Implemented | Keep disabled by default and require explicit confirmation |
| Diagnostics and speed test | Implemented | Extend reporting as new services are added |
| Reference dashboard and numbered menus | Partial | Reorganize the existing dashboard/menu after corresponding features are real and testable |
| Reference port map | Not aligned | Make ports configurable; detect collisions and never silently replace existing listeners |
| Ubuntu 20.04/22.04/24.04 and Debian 10/11/12 | Partial | Current documented support is Ubuntu 22.04/24.04 and Debian 12; do not add end-of-life OS releases without a security decision |

## Implementation rules

1. Every advertised feature must have a real implementation, service check, and
   documentation. No placeholder menu items or simulated status.
2. Validate generated Xray configuration before activation and roll back on
   failure.
3. Never overwrite OpenSSH configuration, terminate the current administrator
   session, or change firewall rules without explicit confirmation.
4. Never install unauthenticated public HTTP/SOCKS proxies.
5. Keep secrets out of the repository, logs, backup archives where practical,
   and command-line arguments.
6. Do not claim cloud licensing, DNS-provider integration, or cloud-drive
   backup until a real provider integration is configured and tested.
7. Run unit tests and static checks for each feature; separately label VPS
   integration tests that have not been performed.

## Delivery sequence

1. Protocol engine: Reality and HTTPUpgrade implemented in the application; finish live-core compatibility and VPS integration tests.
2. Proxy services: authenticated HTTP proxy, Dante SOCKS5, OHP, BadVPN UDPGW.
3. Access controls: expiry policy, reliable session tracking, three-strike lock.
4. Host protection: conservative connection-rate protection and diagnostics.
5. Cloud integrations: licensing provider and Google Drive; improve Telegram
   restore workflow where supported.
6. Dashboard, port configuration, installer, supported-platform documentation,
   and end-to-end verification.
