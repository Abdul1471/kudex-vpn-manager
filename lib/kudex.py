#!/usr/bin/env python3
"""Kudex VPN Manager: terminal-first SSH and Xray administration."""
from __future__ import annotations
import base64, datetime, getpass, ipaddress, json, os, pathlib, platform, re, secrets, shutil, socket, string, subprocess, sys, tarfile, tempfile, urllib.parse, urllib.request, hashlib, time, grp

ETC = pathlib.Path("/etc/kudex")
STATE = ETC / "state.json"
CLIENTS = ETC / "clients.json"
XRAY_DIR = pathlib.Path("/usr/local/etc/xray")
XRAY_CONFIG = XRAY_DIR / "config.json"
NGINX_SITE = pathlib.Path("/etc/nginx/sites-available/kudex.conf")
NGINX_LINK = pathlib.Path("/etc/nginx/sites-enabled/kudex.conf")
WEBROOT = pathlib.Path("/var/www/kudex-acme")
BACKUPS = pathlib.Path("/var/backups/kudex")
XRAY_UNIT = pathlib.Path("/etc/systemd/system/xray.service")
XRAY_VERSION = "26.10.31"
PORTS = {"vmess": 10001, "vless": 10002, "trojan": 10003, "sshws": 10004}
HTTPUPGRADE_PORTS = {"vmess": 10005, "vless": 10006, "trojan": 10007}
HTTPUPGRADE_PATHS = {"vmess": "/vmess-hu", "vless": "/vless-hu", "trojan": "/trojan-hu"}
REALITY_PORT = 8443
REALITY_CONFIG = ETC / "reality.json"
PATHS = {"vmess": "/vmess", "vless": "/vless", "trojan": "/trojan", "sshws": "/ssh"}
PROTO_NAMES = {"vmess": "VMess", "vless": "VLESS", "trojan": "Trojan", "sshws": "SSH over WebSocket"}

def run(args, check=True, capture=False, input_text=None):
    try:
        return subprocess.run(args, check=check, text=True, input=input_text,
                              stdout=subprocess.PIPE if capture else None,
                              stderr=subprocess.PIPE if capture else None)
    except FileNotFoundError:
        raise RuntimeError(f"Required command not found: {args[0]}")
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "").strip()
        raise RuntimeError(detail or f"Command failed: {' '.join(args)}")

def require_root():
    if os.geteuid() != 0:
        raise RuntimeError("Run with sudo: sudo kudex")

def ensure_dirs():
    ETC.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(ETC, 0o700)
    XRAY_DIR.mkdir(mode=0o750, parents=True, exist_ok=True)
    BACKUPS.mkdir(mode=0o700, parents=True, exist_ok=True)
    WEBROOT.mkdir(mode=0o755, parents=True, exist_ok=True)

def read_json(path, default):
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return default
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{path} is invalid JSON: {exc}")

def atomic_json(path, data, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".kudex-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w") as handle:
            json.dump(data, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

def state():
    return read_json(STATE, {"domain": "", "email": "", "tls": False, "protocols": {"vmess": True, "vless": True, "trojan": True, "sshws": True}})

def clients():
    return read_json(CLIENTS, [])

def service_state(unit):
    p = subprocess.run(["systemctl", "is-active", unit], text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    return p.stdout.strip() if p.returncode in (0, 3, 4) else "unknown"

def ask(prompt, default=""):
    suffix = f" [{default}]" if default else ""
    value = input(prompt + suffix + ": ").strip()
    return value or default

def confirm(prompt):
    return input(prompt + " [y/N]: ").strip().lower() == "y"

def valid_name(name):
    return bool(re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{2,31}", name))

def valid_domain(domain):
    if len(domain) > 253 or "." not in domain or domain.endswith("."):
        return False
    return all(re.fullmatch(r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)", part) for part in domain.rstrip(".").split("."))

def uuid4():
    import uuid
    return str(uuid.uuid4())

def random_secret(length=28):
    alphabet = string.ascii_letters + string.digits + "-_"
    return "".join(secrets.choice(alphabet) for _ in range(length))

def xray_binary():
    return shutil.which("xray") or ("/usr/local/bin/xray" if pathlib.Path("/usr/local/bin/xray").exists() else None)

def install_xray(force=False):
    require_root()
    machine = platform.machine().lower()
    asset = {"x86_64": "Xray-linux-64.zip", "amd64": "Xray-linux-64.zip",
             "aarch64": "Xray-linux-arm64-v8a.zip", "arm64": "Xray-linux-arm64-v8a.zip",
             "armv7l": "Xray-linux-arm32-v7a.zip"}.get(machine)
    if not asset:
        raise RuntimeError(f"Unsupported CPU architecture: {machine}")
    if not force and not confirm(f"Download official Xray-core v{XRAY_VERSION} for {machine} from XTLS/Xray-core?"):
        return
    import zipfile
    base = f"https://github.com/XTLS/Xray-core/releases/download/v{XRAY_VERSION}/"
    with tempfile.TemporaryDirectory(prefix="kudex-xray-") as td:
        archive = pathlib.Path(td) / asset
        digest = pathlib.Path(td) / (asset + ".dgst")
        for url, dest in ((base + asset, archive), (base + asset + ".dgst", digest)):
            req = urllib.request.Request(url, headers={"User-Agent": "KudexVPNManager"})
            with urllib.request.urlopen(req, timeout=60) as response, open(dest, "wb") as out:
                shutil.copyfileobj(response, out)
        expected = re.search(r"\b([a-fA-F0-9]{64})\b", digest.read_text(errors="ignore"))
        if not expected:
            raise RuntimeError("Could not read the official SHA-256 digest.")
        actual = hashlib.sha256(archive.read_bytes()).hexdigest()
        if actual.lower() != expected.group(1).lower():
            raise RuntimeError("Xray archive SHA-256 verification failed; refusing installation.")
        with zipfile.ZipFile(archive) as zf:
            member = next((n for n in zf.namelist() if n == "xray" or n.endswith("/xray")), None)
            if not member:
                raise RuntimeError("The official archive did not contain the xray executable.")
            extracted = pathlib.Path(td) / "xray"
            extracted.write_bytes(zf.read(member))
            os.chmod(extracted, 0o755)
            pathlib.Path("/usr/local/bin/xray").parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(extracted, "/usr/local/bin/xray")
    XRAY_UNIT.write_text("""[Unit]
Description=Xray Service
After=network-online.target
Wants=network-online.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
""")
    run(["systemctl", "daemon-reload"])
    run(["systemctl", "enable", "xray.service"])
    print("Official Xray binary installed and systemd unit created.")

def reality_profile():
    profile = read_json(REALITY_CONFIG, {})
    if not isinstance(profile, dict):
        raise RuntimeError("Kudex REALITY settings must be a JSON object.")
    if profile.get("enabled"):
        required = ("target", "server_name", "private_key", "public_key", "short_id")
        if any(not isinstance(profile.get(key), str) or not profile.get(key) for key in required):
            raise RuntimeError("Kudex REALITY settings are incomplete. Reconfigure VLESS REALITY.")
        target = re.fullmatch(r"([A-Za-z0-9.-]+):([0-9]{1,5})", profile["target"])
        if (not target or not valid_domain(target.group(1)) or
                not 1 <= int(target.group(2)) <= 65535 or
                not valid_domain(profile["server_name"]) or
                not re.fullmatch(r"[0-9a-fA-F]{2,16}", profile["short_id"]) or
                len(profile["short_id"]) % 2):
            raise RuntimeError("Kudex REALITY settings are invalid. Reconfigure VLESS REALITY.")
    return profile

def protocol_clients(protocol, entries, reality=False):
    if protocol == "vmess":
        return [{"id": c["secret"], "alterId": 0, "email": c["name"], "security": "auto"} for c in entries]
    if protocol == "vless":
        return [{"id": c["secret"], "email": c["name"], **({"flow": "xtls-rprx-vision"} if reality else {})} for c in entries]
    if protocol == "trojan":
        return [{"password": c["secret"], "email": c["name"]} for c in entries]
    return []

def inbound(protocol, entries, transport="websocket"):
    if protocol == "sshws":
        port, path = PORTS[protocol], PATHS[protocol]
        settings = {"address": "127.0.0.1", "port": 22, "network": "tcp"}
        proto_name = "dokodemo-door"
    else:
        port = PORTS[protocol] if transport == "websocket" else HTTPUPGRADE_PORTS[protocol]
        path = PATHS[protocol] if transport == "websocket" else HTTPUPGRADE_PATHS[protocol]
        settings = {"clients": protocol_clients(protocol, entries)}
        if protocol == "vless":
            settings["decryption"] = "none"
        if protocol == "vmess":
            settings["disableInsecureEncryption"] = False
        proto_name = protocol
    if transport == "httpupgrade":
        stream = {"network": "httpupgrade", "security": "none",
                  "httpupgradeSettings": {"path": path, "host": state().get("domain", "")}}
    else:
        stream = {"network": "ws", "security": "none",
                  "wsSettings": {"path": path, "headers": {"Host": state().get("domain", "")}}}
    return {"tag": protocol + ("-httpupgrade" if transport == "httpupgrade" else ""),
            "listen": "127.0.0.1", "port": port, "protocol": proto_name,
            "settings": settings, "streamSettings": stream}

def reality_inbound(entries, profile):
    users = [{"id": c["secret"], "email": c["name"], "flow": "xtls-rprx-vision"}
             for c in entries if c.get("enabled", True)]
    return {"tag": "vless-reality", "listen": "0.0.0.0", "port": REALITY_PORT,
            "protocol": "vless", "settings": {"clients": users, "decryption": "none"},
            "streamSettings": {"network": "tcp", "security": "reality",
                "realitySettings": {"show": False, "target": profile["target"],
                    "serverNames": [profile["server_name"]], "privateKey": profile["private_key"],
                    "shortIds": [profile["short_id"]]}}}

def build_xray_config():
    st = state()
    all_clients = clients()
    ins = []
    for proto in ("vmess", "vless", "trojan"):
        if st.get("protocols", {}).get(proto, True):
            selected = [c for c in all_clients if c["protocol"] == proto and c.get("enabled", True)]
            ins.append(inbound(proto, selected))
            if st.get("transports", {}).get(proto, {}).get("httpupgrade", False):
                ins.append(inbound(proto, selected, "httpupgrade"))
    if st.get("protocols", {}).get("sshws", True):
        ins.append(inbound("sshws", []))
    profile = reality_profile()
    if profile.get("enabled") and st.get("protocols", {}).get("vless", True):
        ins.append(reality_inbound([c for c in all_clients if c.get("protocol") == "vless"], profile))
    return {"log": {"loglevel": "warning"}, "inbounds": ins,
            "outbounds": [{"protocol": "freedom", "tag": "direct"}]}

def apply_xray():
    require_root()
    binary = xray_binary()
    if not binary:
        raise RuntimeError("Xray is not installed. Choose 'Install/Update Xray' first.")
    ensure_dirs()
    config = build_xray_config()
    fd, temp = tempfile.mkstemp(prefix="xray-test-", suffix=".json", dir=str(XRAY_DIR))
    os.close(fd)
    try:
        pathlib.Path(temp).write_text(json.dumps(config, indent=2))
        test = subprocess.run([binary, "run", "-test", "-config", temp], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if test.returncode:
            raise RuntimeError("Xray rejected the generated configuration:\n" + test.stdout[-3000:])
        previous = None
        if XRAY_CONFIG.exists():
            previous = XRAY_CONFIG.read_bytes()
            backup = XRAY_CONFIG.with_suffix(".json.kudex-backup")
            shutil.copy2(XRAY_CONFIG, backup)
        os.replace(temp, XRAY_CONFIG)
        os.chmod(XRAY_CONFIG, 0o600)
        try:
            run(["systemctl", "restart", "xray.service"])
        except Exception:
            if previous is not None:
                XRAY_CONFIG.write_bytes(previous)
                os.chmod(XRAY_CONFIG, 0o600)
                subprocess.run(["systemctl", "restart", "xray.service"], check=False)
            else:
                XRAY_CONFIG.unlink(missing_ok=True)
            raise
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
    print("Xray configuration validated and service restarted.")

def nginx_config(st):
    domain = st["domain"]
    ssl = st.get("tls") and pathlib.Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem").exists()
    lines = ["map $http_upgrade $connection_upgrade { default upgrade; '' close; }",
             "server {", "    listen 80;", "    listen [::]:80;", f"    server_name {domain};",
             "    location /.well-known/acme-challenge/ { root /var/www/kudex-acme; }"]
    if ssl:
        lines += ["    location / { return 301 https://$host$request_uri; }", "}", "",
                  "server {", "    listen 443 ssl http2;", "    listen [::]:443 ssl http2;", f"    server_name {domain};",
                  f"    ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem;",
                  f"    ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;",
                  "    ssl_protocols TLSv1.2 TLSv1.3;",
                  "    ssl_session_cache shared:KudexTLS:10m;",
                  "    client_max_body_size 1m;"]
    else:
        lines += ["    location / { return 200 'Kudex VPN Manager endpoint'; add_header Content-Type text/plain; }", "}"]
    if ssl:
        for proto, port in PORTS.items():
            if proto == "sshws" and not st.get("protocols", {}).get("sshws", True):
                continue
            path = PATHS[proto]
            lines += [f"    location = {path} {{", "        proxy_redirect off;",
                      f"        proxy_pass http://127.0.0.1:{port};",
                      "        proxy_http_version 1.1;", "        proxy_set_header Upgrade $http_upgrade;",
                      "        proxy_set_header Connection $connection_upgrade;",
                      "        proxy_set_header Host $host;", "        proxy_set_header X-Real-IP $remote_addr;",
                      "        proxy_read_timeout 3600s;", "    }"]
        for proto, port in HTTPUPGRADE_PORTS.items():
            if not st.get("transports", {}).get(proto, {}).get("httpupgrade", False):
                continue
            path = HTTPUPGRADE_PATHS[proto]
            lines += [f"    location = {path} {{", "        proxy_redirect off;",
                      f"        proxy_pass http://127.0.0.1:{port};",
                      "        proxy_http_version 1.1;", "        proxy_set_header Upgrade $http_upgrade;",
                      "        proxy_set_header Connection $connection_upgrade;",
                      "        proxy_set_header Host $host;", "        proxy_set_header X-Real-IP $remote_addr;",
                      "        proxy_read_timeout 3600s;", "    }"]
        lines += ["}"]
    return "\n".join(lines) + "\n"

def apply_nginx():
    require_root()
    st = state()
    domain = st.get("domain", "")
    if not valid_domain(domain):
        raise RuntimeError("Set a valid domain first in DOMAIN & SSL.")
    if not shutil.which("nginx"):
        raise RuntimeError("Nginx is not installed.")
    NGINX_SITE.parent.mkdir(parents=True, exist_ok=True)
    NGINX_SITE.write_text(nginx_config(st))
    os.chmod(NGINX_SITE, 0o644)
    NGINX_LINK.parent.mkdir(parents=True, exist_ok=True)
    if not NGINX_LINK.exists():
        NGINX_LINK.symlink_to(NGINX_SITE)
    test = subprocess.run(["nginx", "-t"], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if test.returncode:
        raise RuntimeError("Nginx config test failed; configuration was not reloaded:\n" + test.stdout)
    run(["systemctl", "reload", "nginx"])
    print("Nginx configuration validated and reloaded.")

def domain_ssl_menu():
    while True:
        st = state()
        domain = st.get("domain") or "NOT CONFIGURED"
        print("\n--- DOMAIN & SSL MANAGER ---")
        print(f"Current domain: {domain}")
        print(f"TLS status: {'ENABLED' if st.get('tls') else 'NOT CONFIGURED'}")
        print("[1] Add/change domain and SSL")
        print("[2] Force-renew current Let's Encrypt certificate")
        print("[3] Show certificate details")
        print("[0] Back")
        choice = input("Select: ").strip()
        if choice == "0":
            return
        if choice == "1":
            configure_domain()
        elif choice == "2":
            domain = state().get("domain", "")
            if not valid_domain(domain) or not state().get("tls"):
                print("Configure a domain and issue its certificate first.")
                continue
            if not shutil.which("certbot"):
                print("Certbot is not installed.")
                continue
            if confirm(f"Force-renew the Let's Encrypt certificate for {domain}?"):
                run(["certbot", "renew", "--cert-name", domain, "--force-renewal"])
                if pathlib.Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem").exists():
                    apply_nginx()
                    if service_state("stunnel4.service") == "active":
                        run(["systemctl", "restart", "stunnel4.service"])
                    print("Certificate renewal command completed.")
        elif choice == "3":
            domain = state().get("domain", "")
            if not valid_domain(domain):
                print("No valid domain is configured.")
                continue
            run(["certbot", "certificates"], check=False)
        else:
            print("Invalid selection.")

def configure_domain():
    require_root()
    st = state()
    domain = ask("Domain name (A/AAAA record must point to this server)", st.get("domain", ""))
    if not valid_domain(domain):
        raise RuntimeError("Invalid domain name.")
    domain = domain.lower()
    email = ask("Email address for Let's Encrypt notices", st.get("email", ""))
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise RuntimeError("A valid email address is required.")
    st.update({"domain": domain, "email": email, "tls": False})
    atomic_json(STATE, st)
    apply_nginx()
    if xray_binary():
        apply_xray()
    if not shutil.which("certbot"):
        print("Certbot is not installed. Install it with: apt-get install certbot")
        return
    if not confirm(f"Request a Let's Encrypt certificate for {domain}? Ensure DNS points here and TCP ports 80/443 are reachable."):
        return
    run(["certbot", "certonly", "--webroot", "-w", str(WEBROOT), "-d", domain,
         "--email", email, "--agree-tos", "--non-interactive", "--keep-until-expiring"])
    st["tls"] = True
    atomic_json(STATE, st)
    apply_nginx()
    if xray_binary():
        apply_xray()
    hook = pathlib.Path("/etc/letsencrypt/renewal-hooks/deploy/kudex-nginx-reload")
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text("#!/bin/sh\nset -eu\nsystemctl reload nginx.service\n"
                    "if [ -f /etc/stunnel/kudex.conf ]; then\n"
                    "  cat /etc/letsencrypt/live/" + domain + "/fullchain.pem "
                    "/etc/letsencrypt/live/" + domain + "/privkey.pem > /etc/stunnel/kudex.pem\n"
                    "  chmod 600 /etc/stunnel/kudex.pem\n"
                    "  systemctl restart stunnel4.service || true\n"
                    "fi\n")
    os.chmod(hook, 0o755)
    print("TLS certificate issued. Certbot renewal timer will reload Nginx after renewal.")


SSH_ACCOUNTS = ETC / "ssh-accounts.json"

def expiry_from_days(days):
    if days <= 0:
        return None
    return (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days)).isoformat()

def expiry_status(value):
    if not value:
        return "NO EXPIRY"
    try:
        expiry = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=datetime.timezone.utc)
        remaining = (expiry - datetime.datetime.now(datetime.timezone.utc)).total_seconds()
        if remaining <= 0:
            return "EXPIRED"
        return f"{max(1, int((remaining + 86399) // 86400))} day(s) left"
    except (ValueError, TypeError):
        return "INVALID EXPIRY"

def expire_due_accounts():
    """Disable expired Xray clients and lock Kudex-managed SSH users."""
    changed = False
    data = clients()
    for item in data:
        if item.get("enabled", True) and item.get("expires_at") and expiry_status(item["expires_at"]) == "EXPIRED":
            item["enabled"] = False
            item["expired_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            changed = True
    if changed:
        previous = clients()
        atomic_json(CLIENTS, data)
        try:
            if xray_binary():
                apply_xray()
        except Exception:
            atomic_json(CLIENTS, previous)
            raise
        print("Expired VPN accounts were disabled automatically.")
    ssh_data = read_json(SSH_ACCOUNTS, {})
    ssh_changed = False
    for username, details in ssh_data.items():
        if details.get("expires_at") and expiry_status(details["expires_at"]) == "EXPIRED" and not details.get("locked"):
            if subprocess.run(["id", username], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                subprocess.run(["usermod", "--lock", username], check=False)
            details["locked"] = True
            details["expired_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            ssh_changed = True
    if ssh_changed:
        atomic_json(SSH_ACCOUNTS, ssh_data)

def ask_duration():
    while True:
        raw = ask("Validity in days (1 = trial, 0 = unlimited)", "30")
        if raw.isdigit() and int(raw) <= 36500:
            return int(raw)
        print("Enter 0 for unlimited or a number from 1 to 36500.")

def renew_client(proto):
    name = ask("Account label to renew")
    data = clients()
    item = next((c for c in data if c.get("protocol") == proto and c.get("name") == name), None)
    if not item:
        print("Account not found.")
        return
    previous = json.loads(json.dumps(data))
    days = ask_duration()
    item["expires_at"] = expiry_from_days(days)
    item["enabled"] = True
    item.pop("expired_at", None)
    atomic_json(CLIENTS, data)
    try:
        apply_xray()
    except Exception:
        atomic_json(CLIENTS, previous)
        raise
    print(f"{name} renewed: {'unlimited' if days == 0 else str(days) + ' day(s)'}.")

def cleanup_expired_protocol_accounts(proto):
    require_root()
    data = clients()
    expired = [item for item in data if item.get("protocol") == proto
               and item.get("expires_at") and expiry_status(item.get("expires_at")) == "EXPIRED"]
    if not expired:
        print("No expired " + PROTO_NAMES[proto] + " accounts to clean.")
        return 0
    print("Expired accounts:")
    for item in expired:
        print(" - " + item.get("name", "(unnamed)"))
    if not confirm("Permanently remove these " + str(len(expired)) + " expired " + PROTO_NAMES[proto] + " account(s)?"):
        return 0
    expired_ids = {(item.get("protocol"), item.get("name"), item.get("secret")) for item in expired}
    remaining = [item for item in data
                 if (item.get("protocol"), item.get("name"), item.get("secret")) not in expired_ids]
    atomic_json(CLIENTS, remaining)
    try:
        apply_xray()
    except Exception:
        atomic_json(CLIENTS, data)
        raise
    print("Removed " + str(len(expired)) + " expired account(s).")
    return len(expired)

def configure_reality():
    require_root()
    binary = xray_binary()
    if not binary:
        raise RuntimeError("Install Xray before configuring VLESS REALITY.")
    server_domain = state().get("domain", "")
    if not valid_domain(server_domain):
        raise RuntimeError("Configure a valid server domain before setting up VLESS REALITY.")
    target = ask("REALITY target host:port (use a stable HTTPS origin, not a CDN proxy)").strip()
    match = re.fullmatch(r"([A-Za-z0-9.-]+):([0-9]{1,5})", target)
    if not match or not valid_domain(match.group(1)) or not 1 <= int(match.group(2)) <= 65535:
        raise RuntimeError("Enter a valid target such as www.example.com:443.")
    server_name = ask("Allowed REALITY serverName", match.group(1)).strip().lower()
    if not valid_domain(server_name):
        raise RuntimeError("Enter a valid DNS serverName.")
    if not confirm("REALITY forwards unauthenticated handshakes to the configured target. Confirm you are authorized to configure this endpoint and understand the fallback behavior?"):
        return
    result = subprocess.run([binary, "x25519"], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if result.returncode:
        raise RuntimeError("Xray could not generate REALITY keys: " + result.stdout[-1000:])
    private_match = re.search(r"(?im)^\s*(?:PrivateKey|Private key)\s*:\s*([A-Za-z0-9_-]+)\s*$", result.stdout)
    public_match = re.search(r"(?im)^\s*(?:Password|PublicKey|Public key)\s*:\s*([A-Za-z0-9_-]+)\s*$", result.stdout)
    if not private_match or not public_match:
        raise RuntimeError("Unrecognized Xray x25519 output; no REALITY settings were changed.")
    previous = reality_profile()
    profile = {"enabled": True, "target": target, "server_name": server_name,
               "private_key": private_match.group(1), "public_key": public_match.group(1),
               "short_id": secrets.token_hex(8)}
    atomic_json(REALITY_CONFIG, profile, 0o600)
    try:
        apply_xray()
    except Exception:
        if previous:
            atomic_json(REALITY_CONFIG, previous, 0o600)
        else:
            REALITY_CONFIG.unlink(missing_ok=True)
        raise
    print(f"VLESS REALITY enabled on TCP/{REALITY_PORT}. Allow this port in your provider firewall.")
    print("The private key is stored in the root-only Kudex configuration directory.")

def transport_manager_menu():
    require_root()
    while True:
        st = state()
        profile = reality_profile()
        print("\n--- XRAY TRANSPORT MANAGER ---")
        print("HTTPUpgrade:")
        for proto in ("vmess", "vless", "trojan"):
            enabled = st.get("transports", {}).get(proto, {}).get("httpupgrade", False)
            print(f"  {proto.upper():<8} {'ENABLED' if enabled else 'DISABLED'}")
        print(f"VLESS REALITY: {'ENABLED' if profile.get('enabled') else 'DISABLED'}")
        print(f"REALITY listener: TCP/{REALITY_PORT} (direct Xray listener)")
        print("[1] Enable HTTPUpgrade for a protocol")
        print("[2] Disable HTTPUpgrade for a protocol")
        print("[3] Configure / rotate VLESS REALITY keys")
        print("[4] Disable VLESS REALITY")
        print("[0] Back")
        choice = input("Select: ").strip()
        if choice == "0":
            return
        if choice in ("1", "2"):
            proto = ask("Protocol (vmess, vless, trojan)").lower()
            if proto not in HTTPUPGRADE_PORTS:
                print("Choose vmess, vless, or trojan.")
                continue
            if choice == "1" and (not valid_domain(st.get("domain", "")) or not st.get("tls")):
                print("Configure the server domain and TLS certificate before enabling HTTPUpgrade.")
                continue
            previous = read_json(STATE, {})
            st.setdefault("transports", {}).setdefault(proto, {})["httpupgrade"] = choice == "1"
            atomic_json(STATE, st)
            try:
                apply_xray()
                if st.get("domain") and st.get("tls"):
                    apply_nginx()
            except Exception:
                if previous:
                    atomic_json(STATE, previous)
                    try:
                        apply_xray()
                        if previous.get("domain") and previous.get("tls"):
                            apply_nginx()
                    except Exception:
                        pass
                raise
            print(f"{proto.upper()} HTTPUpgrade {'enabled' if choice == '1' else 'disabled'}.")
            if choice == "1":
                print(f"Public endpoint: {st.get('domain') or 'YOUR_DOMAIN'}:443{HTTPUPGRADE_PATHS[proto]}")
        elif choice == "3":
            configure_reality()
        elif choice == "4":
            if not profile.get("enabled"):
                print("VLESS REALITY is already disabled.")
                continue
            if not confirm("Disable VLESS REALITY and remove its private key from the active configuration?"):
                continue
            previous = profile
            atomic_json(REALITY_CONFIG, {**profile, "enabled": False}, 0o600)
            try:
                apply_xray()
            except Exception:
                atomic_json(REALITY_CONFIG, previous, 0o600)
                raise
            print("VLESS REALITY disabled. Existing client records were preserved.")
        else:
            print("Invalid selection.")

def protocol_menu(proto):
    if proto == "sshws":
        st = state()
        print("\n--- SSH OVER WEBSOCKET ---")
        print("This exposes the existing SSH daemon through Xray WebSocket at path /ssh.")
        print("SSH authentication remains enforced by OpenSSH; create a normal SSH user in menu 01.")
        print(f"Endpoint: {st.get('domain') or 'YOUR_DOMAIN'}:443/ssh (TLS required)")
        if confirm("Enable SSH over WebSocket?"):
            st.setdefault("protocols", {})["sshws"] = True
            atomic_json(STATE, st); apply_xray()
            if st.get("domain") and st.get("tls"): apply_nginx()
        elif confirm("Disable SSH over WebSocket?"):
            st.setdefault("protocols", {})["sshws"] = False
            atomic_json(STATE, st); apply_xray()
            if st.get("domain") and st.get("tls"): apply_nginx()
        return
    while True:
        expire_due_accounts()
        rows = [c for c in clients() if c.get("protocol") == proto]
        print(f"\n--- {PROTO_NAMES[proto]} ---")
        for item in rows:
            status = "enabled" if item.get("enabled", True) else "disabled"
            print(f" {item['name']:<20} {status:<9} {expiry_status(item.get('expires_at'))}")
        print("[1] Create timed/trial account  [2] Delete  [3] Enable/disable")
        print("[4] Show share links  [5] Renew account  [6] Clean expired  [0] Back")
        choice = input("Select: ").strip()
        if choice == "0":
            return
        if choice == "1":
            name = ask("Account label")
            if not valid_name(name):
                print("Use 3-32 letters/numbers/._-; begin with a letter.")
                continue
            if any(c.get("name") == name and c.get("protocol") == proto for c in clients()):
                print("That label already exists for this protocol.")
                continue
            days = ask_duration()
            secret = uuid4() if proto in ("vmess", "vless") else random_secret(36)
            data = clients()
            item = {"name": name, "protocol": proto, "secret": secret, "enabled": True,
                    "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "expires_at": expiry_from_days(days)}
            data.append(item)
            atomic_json(CLIENTS, data)
            try:
                apply_xray()
            except Exception:
                atomic_json(CLIENTS, [c for c in data if not (c["name"] == name and c["protocol"] == proto)])
                raise
            print(f"Account created ({'unlimited' if days == 0 else str(days) + ' day(s)'}). Connection links:")
            for label, link in share_links(item):
                print(f"\n{label}:\n{link}")
        elif choice == "2":
            name = ask("Account label to delete")
            data = clients()
            new = [c for c in data if not (c.get("protocol") == proto and c.get("name") == name)]
            if len(new) == len(data):
                print("Account not found.")
                continue
            if not confirm(f"Delete {name} permanently?"):
                continue
            atomic_json(CLIENTS, new)
            apply_xray()
            print("Account deleted.")
        elif choice == "3":
            name = ask("Account label")
            data = clients()
            found = next((c for c in data if c.get("protocol") == proto and c.get("name") == name), None)
            if not found:
                print("Account not found.")
                continue
            if found.get("expires_at") and expiry_status(found["expires_at"]) == "EXPIRED":
                print("This account has expired. Use Renew account first.")
                continue
            found["enabled"] = not found.get("enabled", True)
            atomic_json(CLIENTS, data)
            apply_xray()
            print(f"Account {'enabled' if found['enabled'] else 'disabled'}.")
        elif choice == "4":
            for item in rows:
                if item.get("enabled", True):
                    print(f"\n{item['name']} ({expiry_status(item.get('expires_at'))})")
                    for label, link in share_links(item):
                        print(f"{label}:\n{link}")
        elif choice == "5":
            renew_client(proto)
        elif choice == "6":
            cleanup_expired_protocol_accounts(proto)
        else:
            print("Invalid selection.")

def share_link(client, transport="websocket"):
    st = state()
    host = st.get("domain") or "YOUR_DOMAIN"
    proto = client["protocol"]
    if transport == "reality":
        profile = reality_profile()
        if host == "YOUR_DOMAIN" or not valid_domain(host):
            return "Configure a valid server domain before sharing a REALITY URI."
        if proto != "vless" or not profile.get("enabled"):
            return "VLESS REALITY is not configured."
        query = urllib.parse.urlencode({
            "encryption": "none", "flow": "xtls-rprx-vision", "security": "reality",
            "sni": profile["server_name"], "fp": "chrome", "pbk": profile["public_key"],
            "sid": profile["short_id"], "type": "tcp"
        })
        return f"vless://{client['secret']}@{host}:{REALITY_PORT}?{query}#{urllib.parse.quote(client['name'] + ' REALITY')}"
    if not st.get("tls") or host == "YOUR_DOMAIN":
        return "TLS/domain not configured. Configure DOMAIN & SSL before sharing a connection URI."
    if transport == "httpupgrade":
        if not st.get("transports", {}).get(proto, {}).get("httpupgrade", False):
            return "HTTPUpgrade is not enabled for this protocol."
        path, net = HTTPUPGRADE_PATHS[proto], "httpupgrade"
    else:
        path, net = PATHS[proto], "ws"
    name = client["name"]
    secret = client["secret"]
    if proto == "vmess":
        obj = {"v": "2", "ps": name + (" HTTPUpgrade" if transport == "httpupgrade" else ""),
               "add": host, "port": "443", "id": secret, "aid": "0", "scy": "auto",
               "net": net, "type": "none", "host": host, "path": path, "tls": "tls", "sni": host}
        return "vmess://" + base64.b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode().rstrip("=")
    query_values = {"type": net, "security": "tls", "path": path, "host": host, "sni": host}
    if proto == "vless":
        query_values["encryption"] = "none"
    query = urllib.parse.urlencode(query_values)
    scheme = "vless" if proto == "vless" else "trojan"
    suffix = " HTTPUpgrade" if transport == "httpupgrade" else ""
    return f"{scheme}://{secret}@{host}:443?{query}#{urllib.parse.quote(name + suffix)}"

def share_links(client):
    links = [("WebSocket + TLS", share_link(client))]
    proto = client["protocol"]
    if proto == "vless" and reality_profile().get("enabled"):
        links.append(("REALITY + Vision", share_link(client, "reality")))
    if state().get("transports", {}).get(proto, {}).get("httpupgrade", False):
        links.append(("HTTPUpgrade + TLS", share_link(client, "httpupgrade")))
    return links

def cleanup_expired_ssh_accounts():
    require_root()
    managed = read_json(SSH_ACCOUNTS, {})
    expired = [name for name, details in managed.items()
               if valid_name(name) and details.get("expires_at")
               and expiry_status(details.get("expires_at")) == "EXPIRED"]
    if not expired:
        print("No expired Kudex SSH accounts to clean.")
        return 0
    print("Expired Kudex SSH accounts:")
    for name in sorted(expired):
        print(" - " + name)
    print("Existing login sessions may remain active until they disconnect.")
    if not confirm("Delete these expired Linux users and their home directories?"):
        return 0
    limits = ssh_login_limits()
    removed = 0
    for name in expired:
        exists = subprocess.run(["id", name], stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL).returncode == 0
        if exists:
            result = run(["userdel", "--remove", name], check=False)
            if result.returncode != 0:
                print("Could not remove " + name + "; keeping its Kudex record.")
                continue
        managed.pop(name, None)
        limits.pop(name, None)
        removed += 1
    atomic_json(SSH_ACCOUNTS, managed)
    if removed:
        write_ssh_login_limits(limits)
    print("Cleaned " + str(removed) + " expired SSH account(s).")
    return removed

def ssh_menu():
    while True:
        expire_due_accounts()
        print("\n--- SSH ACCOUNTS ---")
        print("[1] Create timed/trial user  [2] List users  [3] Lock user")
        print("[4] Unlock user  [5] Delete user  [6] Renew account  [7] SSH security  [8] Clean expired  [0] Back")
        c = input("Select: ").strip()
        if c == "0":
            return
        if c == "7":
            ssh_security_menu()
            continue
        if c == "8":
            cleanup_expired_ssh_accounts()
            continue
        if c == "1":
            name = ask("Username")
            if not valid_name(name):
                print("Invalid username.")
                continue
            if name in ("root", "daemon", "nobody") or name.isdigit():
                print("Reserved username.")
                continue
            if subprocess.run(["id", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                print("User already exists.")
                continue
            password = getpass.getpass("Temporary password (min 14 chars): ")
            if len(password) < 14:
                print("Password too short.")
                continue
            days = ask_duration()
            run(["useradd", "--create-home", "--shell", "/bin/bash", name])
            try:
                run(["chpasswd"], input_text=f"{name}:{password}\n")
                expiry = expiry_from_days(days)
                if expiry:
                    expiry_date = (datetime.datetime.now().date() + datetime.timedelta(days=days)).isoformat()
                    run(["chage", "-E", expiry_date, name])
                else:
                    run(["chage", "-E", "-1", name])
                data = read_json(SSH_ACCOUNTS, {})
                data[name] = {"created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                              "expires_at": expiry, "locked": False}
                atomic_json(SSH_ACCOUNTS, data)
            except Exception:
                subprocess.run(["userdel", "--remove", name], check=False)
                raise
            print(f"Created {name}; validity: {'unlimited' if days == 0 else str(days) + ' day(s)'}.")
            print("Require the user to change this temporary password.")
        elif c == "2":
            managed = read_json(SSH_ACCOUNTS, {})
            for username, details in sorted(managed.items()):
                print(f"{username:<24} {expiry_status(details.get('expires_at'))} "
                      f"{'LOCKED' if details.get('locked') else 'ACTIVE'}")
            if not managed:
                print("No Kudex-managed SSH accounts recorded yet.")
        elif c in ("3", "4", "5", "6"):
            name = ask("Username")
            if name == "root" or subprocess.run(["id", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
                print("User not found or protected.")
                continue
            managed = read_json(SSH_ACCOUNTS, {})
            if c == "3":
                run(["usermod", "--lock", name])
                if name in managed:
                    managed[name]["locked"] = True
                    atomic_json(SSH_ACCOUNTS, managed)
            elif c == "4":
                details = managed.get(name, {})
                if details.get("expires_at") and expiry_status(details["expires_at"]) == "EXPIRED":
                    print("This account has expired. Renew it first.")
                    continue
                run(["usermod", "--unlock", name])
                if name in managed:
                    managed[name]["locked"] = False
                    atomic_json(SSH_ACCOUNTS, managed)
            elif c == "5":
                if confirm(f"Delete {name} and its home directory?"):
                    run(["userdel", "--remove", name])
                    managed.pop(name, None)
                    atomic_json(SSH_ACCOUNTS, managed)
            elif c == "6":
                days = ask_duration()
                expiry = expiry_from_days(days)
                run(["chage", "-E", (datetime.datetime.now().date() + datetime.timedelta(days=days)).isoformat(), name] if expiry
                    else ["chage", "-E", "-1", name])
                details = managed.setdefault(name, {})
                details.update({"expires_at": expiry, "locked": False})
                atomic_json(SSH_ACCOUNTS, managed)
                run(["usermod", "--unlock", name])
                print(f"{name} renewed: {'unlimited' if days == 0 else str(days) + ' day(s)'}.")
        else:
            print("Invalid selection.")



SSH_LIMITS = pathlib.Path("/etc/security/limits.d/99-kudex-vpn.conf")

def pam_limits_enabled():
    """Return whether an SSH PAM session appears to load pam_limits."""
    candidates = (pathlib.Path("/etc/pam.d/sshd"),
                  pathlib.Path("/etc/pam.d/common-session"),
                  pathlib.Path("/etc/pam.d/common-session-noninteractive"))
    for path in candidates:
        try:
            for line in path.read_text().splitlines():
                stripped = line.strip()
                if stripped and not stripped.startswith("#") and "pam_limits.so" in stripped:
                    return True
        except OSError:
            continue
    return False

def ssh_login_limits():
    """Read Kudex-owned maxlogins entries, ignoring unrelated limits."""
    result = {}
    try:
        lines = SSH_LIMITS.read_text().splitlines()
    except FileNotFoundError:
        return result
    for line in lines:
        parts = line.split()
        if len(parts) == 4 and parts[1:3] == ["hard", "maxlogins"] and valid_name(parts[0]) and parts[0] != "root" and parts[3].isdigit():
            result[parts[0]] = int(parts[3])
    return result

def write_ssh_login_limits(entries):
    """Atomically write only Kudex-managed per-user maxlogins rules."""
    require_root()
    SSH_LIMITS.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".kudex-limits-", dir=str(SSH_LIMITS.parent))
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write("# Managed by Kudex VPN Manager. Do not edit managed lines manually.\n")
            for username, maximum in sorted(entries.items()):
                handle.write(f"{username} hard maxlogins {maximum}\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, SSH_LIMITS)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

def set_ssh_login_limit(username, maximum):
    require_root()
    if not valid_name(username) or username == "root":
        raise RuntimeError("Invalid or protected username.")
    if not isinstance(maximum, int) or not 1 <= maximum <= 100:
        raise RuntimeError("Maximum concurrent logins must be between 1 and 100.")
    if subprocess.run(["id", username], stdout=subprocess.DEVNULL,
                      stderr=subprocess.DEVNULL).returncode != 0:
        raise RuntimeError("That Linux user does not exist.")
    entries = ssh_login_limits()
    entries[username] = maximum
    write_ssh_login_limits(entries)

def remove_ssh_login_limit(username):
    require_root()
    entries = ssh_login_limits()
    if username not in entries:
        return False
    entries.pop(username)
    write_ssh_login_limits(entries)
    return True

def ssh_security_menu():
    while True:
        print("\n--- SSH SECURITY MANAGER ---")
        print("[1] Set/update a user's concurrent-login limit")
        print("[2] List Kudex login limits")
        print("[3] Remove a user's login limit")
        print("[4] Check PAM limit enforcement")
        print("[0] Back")
        choice = input("Select: ").strip()
        if choice == "0":
            return
        if choice == "1":
            username = ask("Existing SSH username")
            raw = ask("Maximum simultaneous logins (1-100)", "1")
            if not raw.isdigit():
                print("Enter a whole number from 1 to 100.")
                continue
            set_ssh_login_limit(username, int(raw))
            print(f"Limit saved: {username} may have up to {int(raw)} concurrent login(s).")
            if not pam_limits_enabled():
                print("WARNING: pam_limits.so was not detected in the common SSH PAM session files.")
                print("The rule is saved, but enforcement may require PAM configuration. Kudex did not alter PAM.")
        elif choice == "2":
            entries = ssh_login_limits()
            if not entries:
                print("No per-user concurrent-login limits are configured.")
            else:
                for username, maximum in sorted(entries.items()):
                    print(f"{username:<24} maximum concurrent logins: {maximum}")
            print(f"PAM limits module detected: {'YES' if pam_limits_enabled() else 'NO'}")
        elif choice == "3":
            username = ask("Username whose limit should be removed")
            if remove_ssh_login_limit(username):
                print(f"Removed Kudex login limit for {username}.")
            else:
                print("No Kudex login limit exists for that user.")
        elif choice == "4":
            if pam_limits_enabled():
                print("pam_limits.so detected in an SSH/common PAM session file.")
            else:
                print("pam_limits.so was not detected. Kudex will not edit PAM files automatically.")
        else:
            print("Invalid selection.")



DNSTT_DIR = ETC / "dnstt"
DNSTT_PRIVATE_KEY = DNSTT_DIR / "server.key"
DNSTT_PUBLIC_KEY = DNSTT_DIR / "server.pub"
DNSTT_STATE = DNSTT_DIR / "server.json"
DNSTT_UNIT = pathlib.Path("/etc/systemd/system/kudex-dnstt.service")
DNSTT_BINARY = pathlib.Path("/usr/local/bin/dnstt-server")

def dnstt_server_installed():
    return shutil.which("dnstt-server") or (str(DNSTT_BINARY) if DNSTT_BINARY.exists() else None)

def install_dnstt_server():
    require_root()
    go = shutil.which("go")
    if not go:
        if not confirm("Go is required. Install golang-go using apt?"):
            return False
        run(["apt-get", "update"])
        run(["apt-get", "install", "-y", "golang-go"])
        go = shutil.which("go")
    if not go:
        raise RuntimeError("Go compiler was not found.")
    env = os.environ.copy()
    env["GOBIN"] = "/usr/local/bin"
    p = subprocess.run([go, "install", "www.bamsoftware.com/git/dnstt.git/dnstt-server@latest"],
                       text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
    if p.returncode:
        raise RuntimeError("DNSTT build failed:\n" + p.stdout[-3000:])
    if not DNSTT_BINARY.exists():
        raise RuntimeError("DNSTT executable was not created in /usr/local/bin.")
    os.chmod(DNSTT_BINARY, 0o755)
    print("Upstream DNSTT server built and installed.")
    return True

def generate_dnstt_keys():
    require_root()
    binary = dnstt_server_installed()
    if not binary:
        raise RuntimeError("Install the DNSTT server binary first.")
    if DNSTT_PRIVATE_KEY.exists() and not confirm("A keypair exists. Rotate it? Existing clients will need the new public key."):
        return False
    DNSTT_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    if DNSTT_PRIVATE_KEY.exists():
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        backup_dir = BACKUPS / ("dnstt-key-" + stamp)
        backup_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copy2(DNSTT_PRIVATE_KEY, backup_dir / "server.key")
        if DNSTT_PUBLIC_KEY.exists():
            shutil.copy2(DNSTT_PUBLIC_KEY, backup_dir / "server.pub")
        os.chmod(backup_dir / "server.key", 0o600)
    p = subprocess.run([binary, "-gen-key", "-privkey-file", str(DNSTT_PRIVATE_KEY),
                        "-pubkey-file", str(DNSTT_PUBLIC_KEY)],
                       text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if p.returncode:
        raise RuntimeError("DNSTT key generation failed:\n" + p.stdout[-2000:])
    os.chmod(DNSTT_PRIVATE_KEY, 0o600)
    os.chmod(DNSTT_PUBLIC_KEY, 0o644)
    try:
        import pwd
        account = pwd.getpwnam("dnstt")
        os.chown(DNSTT_DIR, account.pw_uid, account.pw_gid)
        os.chown(DNSTT_PRIVATE_KEY, account.pw_uid, account.pw_gid)
        os.chmod(DNSTT_DIR, 0o750)
    except KeyError:
        os.chmod(DNSTT_DIR, 0o700)
    print("DNSTT keypair generated. Keep server.key private; share only server.pub.")
    if service_state("kudex-dnstt.service") == "active":
        run(["systemctl", "restart", "kudex-dnstt.service"])
        print("DNSTT service restarted to load the rotated keypair.")
    return True

def dnstt_key_status():
    print("\n--- SLOWDNS / DNSTT KEY STATUS ---")
    print(f"Server binary : {'INSTALLED' if dnstt_server_installed() else 'NOT INSTALLED'}")
    print(f"Private key   : {'PRESENT' if DNSTT_PRIVATE_KEY.exists() else 'MISSING'}")
    print(f"Public key    : {'PRESENT' if DNSTT_PUBLIC_KEY.exists() else 'MISSING'}")
    if DNSTT_PUBLIC_KEY.exists():
        print("Public key (share with authorized clients):")
        print(DNSTT_PUBLIC_KEY.read_text().strip())

def configure_dnstt_server():
    require_root()
    if not dnstt_server_installed():
        raise RuntimeError("Install the DNSTT server binary first.")
    if not DNSTT_PRIVATE_KEY.exists():
        raise RuntimeError("Generate a DNSTT keypair first.")
    zone = ask("Delegated tunnel DNS zone (for example t.example.com)")
    if not valid_domain(zone):
        raise RuntimeError("Enter a valid tunnel zone such as t.example.com.")
    upstream = ask("Local TCP service to forward to", "127.0.0.1:22")
    match = re.fullmatch(r"([A-Za-z0-9.-]+):(\d{1,5})", upstream)
    if not match or not 1 <= int(match.group(2)) <= 65535 or match.group(1).startswith("-"):
        raise RuntimeError("Invalid upstream. Use host:port, for example 127.0.0.1:22.")
    if shutil.which("ss"):
        check = subprocess.run(["ss", "-H", "-lun", "sport", "=", ":53"],
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        if check.stdout.strip():
            raise RuntimeError("UDP/53 is already in use. Resolve the conflict before enabling DNSTT.")
    print("\nDNS prerequisites:")
    print("  A/AAAA record for your authoritative nameserver host must point to this VPS.")
    print(f"  Delegate NS for {zone} to that nameserver host at your registrar.")
    print("  Allow inbound UDP/53 in provider and host firewalls.")
    print("  Kudex does not edit DNS records, firewall rules, or NAT.")
    if not confirm(f"Create and start DNSTT on UDP/53 for {zone}, forwarding streams to {upstream}?"):
        return
    try:
        import pwd
        try:
            account = pwd.getpwnam("dnstt")
        except KeyError:
            run(["useradd", "--system", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", "dnstt"])
            account = pwd.getpwnam("dnstt")
        os.chown(DNSTT_DIR, account.pw_uid, account.pw_gid)
        os.chown(DNSTT_PRIVATE_KEY, account.pw_uid, account.pw_gid)
        os.chmod(DNSTT_DIR, 0o750)
        os.chmod(DNSTT_PRIVATE_KEY, 0o600)
    except (ImportError, KeyError, OSError) as exc:
        raise RuntimeError(f"Could not prepare restricted DNSTT account: {exc}")
    atomic_json(DNSTT_STATE, {"zone": zone.lower(), "upstream": upstream}, 0o600)
    unit = f"""[Unit]
Description=Kudex DNSTT DNS tunnel server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=dnstt
Group=dnstt
ExecStart={DNSTT_BINARY} -udp :53 -privkey-file {DNSTT_PRIVATE_KEY} {zone.lower()} {upstream}
Restart=on-failure
RestartSec=5
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
ReadOnlyPaths={DNSTT_PRIVATE_KEY} {DNSTT_PUBLIC_KEY}

[Install]
WantedBy=multi-user.target
"""
    DNSTT_UNIT.write_text(unit)
    os.chmod(DNSTT_UNIT, 0o644)
    run(["systemctl", "daemon-reload"])
    run(["systemctl", "enable", "--now", "kudex-dnstt.service"])
    if service_state("kudex-dnstt.service") != "active":
        raise RuntimeError("DNSTT unit is not active. Inspect journalctl -u kudex-dnstt.")
    print("DNSTT is active on UDP/53. Verify DNS delegation before sharing client settings.")

def dnstt_menu():
    while True:
        st = read_json(DNSTT_STATE, {})
        print("\n--- SLOWDNS / DNSTT MANAGER ---")
        print(f"Server: {'INSTALLED' if dnstt_server_installed() else 'NOT INSTALLED'} | Service: {service_state('kudex-dnstt.service')}")
        print(f"Zone: {st.get('zone', 'NOT CONFIGURED')} | Upstream: {st.get('upstream', 'NOT CONFIGURED')}")
        print("[1] Install/build upstream DNSTT server")
        print("[2] Generate/rotate server keypair")
        print("[3] Show key status and public key")
        print("[4] Configure/start DNSTT server")
        print("[5] Restart DNSTT server")
        print("[6] Stop/disable DNSTT server")
        print("[0] Back")
        choice = input("Select: ").strip()
        if choice == "0":
            return
        if choice == "1":
            install_dnstt_server()
        elif choice == "2":
            generate_dnstt_keys()
        elif choice == "3":
            dnstt_key_status()
        elif choice == "4":
            configure_dnstt_server()
        elif choice == "5":
            if service_state("kudex-dnstt.service") == "active":
                run(["systemctl", "restart", "kudex-dnstt.service"])
            else:
                print("DNSTT service is not active; configure it first.")
        elif choice == "6":
            if service_state("kudex-dnstt.service") != "unknown" and confirm("Stop and disable DNSTT service?"):
                run(["systemctl", "disable", "--now", "kudex-dnstt.service"])
        else:
            print("Invalid selection.")

def stunnel_config_text(pem_path):
    return f"""foreground = no
pid = /run/stunnel4-kudex.pid
output = /var/log/stunnel4-kudex.log
debug = 4

[ssh]
accept = 0.0.0.0:444
connect = 127.0.0.1:22
cert = {pem_path}
TIMEOUTclose = 0
"""

def configure_stunnel():
    require_root()
    st = state()
    domain = st.get("domain", "")
    if not st.get("tls") or not valid_domain(domain):
        raise RuntimeError("Configure DOMAIN & SSL and issue a valid certificate before enabling Stunnel.")
    cert_dir = pathlib.Path("/etc/letsencrypt/live") / domain
    fullchain = cert_dir / "fullchain.pem"
    private_key = cert_dir / "privkey.pem"
    if not fullchain.exists() or not private_key.exists():
        raise RuntimeError("Let's Encrypt certificate files are missing.")
    if not shutil.which("stunnel4"):
        if not confirm("Install Stunnel4 from Ubuntu/Debian repositories?"):
            return
        run(["apt-get", "update"])
        run(["apt-get", "install", "-y", "stunnel4"])
    config_dir = pathlib.Path("/etc/stunnel")
    config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    pathlib.Path("/var/log/stunnel4").mkdir(mode=0o750, parents=True, exist_ok=True)
    pem = config_dir / "kudex.pem"
    pem.write_bytes(fullchain.read_bytes() + b"\n" + private_key.read_bytes())
    os.chmod(pem, 0o600)
    config = config_dir / "kudex.conf"
    config.write_text(stunnel_config_text(str(pem)))
    os.chmod(config, 0o600)
    defaults = pathlib.Path("/etc/default/stunnel4")
    current = defaults.read_text() if defaults.exists() else ""
    def set_default(text, key, value):
        pattern = rf"(?m)^\s*{re.escape(key)}=.*$"
        line = f'{key}="{value}"'
        return re.sub(pattern, line, text) if re.search(pattern, text) else text.rstrip() + "\n" + line + "\n"
    current = set_default(current, "ENABLED", "1")
    current = set_default(current, "FILES", "/etc/stunnel/kudex.conf")
    defaults.write_text(current)
    os.chmod(defaults, 0o644)
    run(["systemctl", "daemon-reload"])
    run(["systemctl", "enable", "--now", "stunnel4.service"])
    if service_state("stunnel4.service") != "active":
        raise RuntimeError("Stunnel configuration was written but the service is not active. Check journalctl -u stunnel4.")
    print("Stunnel4 is active on TCP/444 and forwards TLS traffic to OpenSSH on 127.0.0.1:22.")
    print("Allow TCP/444 in your cloud firewall/security group if you intend to use this listener.")

def openvpn_units():
    p = subprocess.run(["systemctl", "list-unit-files", "--type=service", "--no-legend"],
                       text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    available = []
    for line in p.stdout.splitlines():
        unit = line.split()[0] if line.split() else ""
        if unit in ("openvpn.service", "openvpn@server.service", "openvpn-server@server.service"):
            available.append(unit)
    return available

SQUID_CONFIG = pathlib.Path("/etc/squid/squid.conf")
SQUID_PASSWORDS = pathlib.Path("/etc/squid/passwd")
SQUID_PORT = 8880

def squid_proxy_config():
    return """# Managed by Kudex VPN Manager. Local changes are backed up before replacement.
http_port 0.0.0.0:8880
auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/passwd
auth_param basic realm Kudex Authenticated Proxy
auth_param basic credentialsttl 2 hours
acl kudex_authenticated proxy_auth REQUIRED
http_access allow localhost
http_access allow kudex_authenticated
http_access deny all
cache deny all
via off
forwarded_for delete
"""

def squid_proxy_installed():
    return bool(shutil.which("squid") and shutil.which("htpasswd") and
                pathlib.Path("/usr/lib/squid/basic_ncsa_auth").exists())

def squid_proxy_configure():
    require_root()
    if not confirm("Install Squid and Apache htpasswd tools for an authenticated HTTP proxy on TCP/8880?"):
        return
    run(["apt-get", "update"])
    run(["apt-get", "install", "-y", "--no-install-recommends", "squid", "apache2-utils"])
    if not squid_proxy_installed():
        raise RuntimeError("Squid or its basic_ncsa_auth helper is missing after installation.")
    if service_state("squid.service") != "active":
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            try:
                probe.bind(("0.0.0.0", SQUID_PORT))
            except OSError as exc:
                raise RuntimeError(f"TCP/{SQUID_PORT} is already in use; free the port before configuring Squid.") from exc
    SQUID_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    backup_path = None
    if SQUID_CONFIG.exists():
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        backup_path = SQUID_CONFIG.with_name(f"squid.conf.kudex-backup-{stamp}")
        shutil.copy2(SQUID_CONFIG, backup_path)
    SQUID_PASSWORDS.touch(mode=0o640, exist_ok=True)
    os.chown(SQUID_PASSWORDS, 0, grp.getgrnam("proxy").gr_gid)
    os.chmod(SQUID_PASSWORDS, 0o640)
    SQUID_CONFIG.write_text(squid_proxy_config())
    os.chmod(SQUID_CONFIG, 0o640)
    test = subprocess.run(["squid", "-k", "parse"], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if test.returncode:
        if backup_path and backup_path.exists():
            shutil.copy2(backup_path, SQUID_CONFIG)
        else:
            SQUID_CONFIG.unlink(missing_ok=True)
        raise RuntimeError("Squid rejected the generated configuration:\\n" + test.stdout[-2500:])
    run(["systemctl", "enable", "--now", "squid.service"])
    run(["systemctl", "restart", "squid.service"])
    print("Authenticated Squid proxy configured on TCP/8880. Add a proxy user before connecting.")

def squid_proxy_add_user():
    require_root()
    if not squid_proxy_installed() or not SQUID_CONFIG.exists():
        print("Configure/install the Squid proxy first.")
        return
    username = ask("Proxy username")
    if not valid_name(username):
        raise RuntimeError("Username must be 3–32 characters and start with a letter.")
    password = getpass.getpass("Proxy password (minimum 12 characters): ")
    if len(password) < 12 or "\n" in password or "\r" in password:
        raise RuntimeError("Use a password of at least 12 characters without line breaks.")
    helper = shutil.which("htpasswd")
    cmd = [helper, "-B", "-i"]
    if not SQUID_PASSWORDS.exists() or SQUID_PASSWORDS.stat().st_size == 0:
        cmd.append("-c")
    cmd += [str(SQUID_PASSWORDS), username]
    proc = subprocess.run(cmd, input=password + "\n", text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if proc.returncode:
        raise RuntimeError("Could not create the proxy account: " + proc.stdout[-1500:])
    os.chmod(SQUID_PASSWORDS, 0o640)
    run(["systemctl", "reload", "squid.service"])
    print(f"Authenticated proxy account '{username}' added.")

def squid_proxy_list_users():
    if not SQUID_PASSWORDS.exists():
        print("No proxy users configured.")
        return
    users = [line.split(":", 1)[0] for line in SQUID_PASSWORDS.read_text().splitlines() if ":" in line]
    print("\nProxy users:")
    for username in users:
        print(" - " + username)
    if not users:
        print("No proxy users configured.")

def squid_proxy_menu():
    while True:
        print("\n--- AUTHENTICATED HTTP PROXY ---")
        print(f"Squid service: {service_state('squid.service')} | Port: TCP/{SQUID_PORT}")
        print("[1] Install/configure authenticated proxy")
        print("[2] Add or reset proxy user")
        print("[3] List proxy usernames")
        print("[4] Restart Squid")
        print("[5] Stop Squid")
        print("[0] Back")
        choice = input("Select: ").strip()
        if choice == "0":
            return
        if choice == "1":
            squid_proxy_configure()
        elif choice == "2":
            squid_proxy_add_user()
        elif choice == "3":
            squid_proxy_list_users()
        elif choice == "4":
            if confirm("Restart Squid and disconnect active proxy sessions?"):
                run(["systemctl", "restart", "squid.service"])
        elif choice == "5":
            if confirm("Stop the authenticated HTTP proxy?"):
                run(["systemctl", "stop", "squid.service"])
        else:
            print("Invalid selection.")

DANTE_CONFIG = pathlib.Path("/etc/danted.conf")
DANTE_PAM = pathlib.Path("/etc/pam.d/sockd")
DANTE_GROUP = "kudex-socks"
DANTE_PORT = 1080

def dante_config(interface):
    return f"""# Managed by Kudex VPN Manager
logoutput: syslog
internal: 0.0.0.0 port = {DANTE_PORT}
external: {interface}
user.privileged: root
user.notprivileged: nobody
socksmethod: pam.username
client pass {{
    from: 0/0 to: 0/0
}}
socks pass {{
    from: 0/0 to: 0/0
    pam.servicename: sockd
}}
"""

def dante_pam_config():
    return """# Managed by Kudex VPN Manager: only dedicated Kudex SOCKS users may authenticate.
auth required pam_succeed_if.so user ingroup kudex-socks
@include common-auth
account required pam_succeed_if.so user ingroup kudex-socks
@include common-account
@include common-session
"""

def dante_external_interface():
    ip = shutil.which("ip")
    if not ip:
        raise RuntimeError("The iproute2 'ip' command is required to detect the outbound interface.")
    result = subprocess.run([ip, "route", "get", "1.1.1.1"], text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    match = re.search(r"\bdev\s+([A-Za-z0-9_.:-]+)", result.stdout)
    if result.returncode or not match:
        raise RuntimeError("Could not determine the default outbound network interface.")
    return match.group(1)

def dante_installed():
    return bool(shutil.which("sockd") and shutil.which("useradd") and shutil.which("chpasswd"))

def dante_pam_supported():
    binary = shutil.which("sockd")
    if not binary:
        return False
    result = subprocess.run([binary, "-vv"], text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT)
    output = result.stdout.lower()
    return "pam:" in output and "enabled" in output

def dante_configure():
    require_root()
    if not confirm("Install Dante SOCKS5 on TCP/1080 with PAM-authenticated dedicated users? SOCKS username/password authentication is not encrypted; use a trusted tunnel or TLS-protected network."):
        return
    run(["apt-get", "update"])
    run(["apt-get", "install", "-y", "--no-install-recommends", "dante-server", "libpam-modules"])
    if not dante_installed() or not dante_pam_supported():
        raise RuntimeError("Installed Dante binary does not report PAM support; refusing to expose an unauthenticated SOCKS service.")
    interface = dante_external_interface()
    if service_state("danted.service") != "active":
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            try:
                probe.bind(("0.0.0.0", DANTE_PORT))
            except OSError as exc:
                raise RuntimeError(f"TCP/{DANTE_PORT} is already in use; resolve the port conflict before enabling Dante.") from exc
    group = subprocess.run(["getent", "group", DANTE_GROUP], text=True,
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    if group.returncode:
        run(["groupadd", "--system", DANTE_GROUP])
    ETC.mkdir(parents=True, exist_ok=True)
    backups = []
    for path in (DANTE_CONFIG, DANTE_PAM):
        if path.exists():
            stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
            backup = path.with_name(path.name + ".kudex-backup-" + stamp)
            shutil.copy2(path, backup)
            backups.append((path, backup))
    DANTE_CONFIG.write_text(dante_config(interface))
    os.chmod(DANTE_CONFIG, 0o640)
    DANTE_PAM.write_text(dante_pam_config())
    os.chmod(DANTE_PAM, 0o644)
    try:
        run(["systemctl", "enable", "--now", "danted.service"])
        run(["systemctl", "restart", "danted.service"])
        if service_state("danted.service") != "active":
            raise RuntimeError("Dante did not become active after configuration.")
    except Exception:
        for path in (DANTE_CONFIG, DANTE_PAM):
            backup = next((b for pth, b in backups if pth == path), None)
            if backup:
                shutil.copy2(backup, path)
            else:
                path.unlink(missing_ok=True)
        run(["systemctl", "restart", "danted.service"], check=False)
        raise
    print(f"Authenticated Dante SOCKS5 is active on TCP/{DANTE_PORT} via {interface}. Create a Kudex SOCKS user before connecting.")

def dante_add_user():
    require_root()
    if service_state("danted.service") != "active" or not DANTE_CONFIG.exists():
        print("Configure Dante first.")
        return
    username = ask("SOCKS username (must start with kpx_)")
    if not re.fullmatch(r"kpx_[A-Za-z0-9_.-]{3,24}", username):
        raise RuntimeError("Use a dedicated username beginning kpx_ followed by 3–24 letters, digits, dots, underscores or hyphens.")
    password = getpass.getpass("SOCKS password (minimum 16 characters): ")
    if len(password) < 16 or "\n" in password or "\r" in password or ":" in password:
        raise RuntimeError("Use at least 16 characters without line breaks or colons.")
    entry = subprocess.run(["getent", "passwd", username], text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    if entry.returncode:
        run(["useradd", "--no-create-home", "--shell", "/usr/sbin/nologin",
             "--gid", DANTE_GROUP, username])
    else:
        groups = subprocess.run(["id", "-nG", username], text=True, stdout=subprocess.PIPE, check=True)
        if DANTE_GROUP not in groups.stdout.split():
            raise RuntimeError("That Linux username already exists and is not a Kudex SOCKS account; choose another username.")
    run(["chpasswd"], input_text=f"{username}:{password}")
    print(f"SOCKS account '{username}' is ready. SOCKS5 username/password is not encrypted in transit; use a protected tunnel.")

def dante_list_users():
    entries = subprocess.run(["getent", "passwd"], text=True, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL)
    if entries.returncode:
        print("Could not read system account database.")
        return
    members = []
    for line in entries.stdout.splitlines():
        username = line.split(":", 1)[0]
        if not username.startswith("kpx_"):
            continue
        groups = subprocess.run(["id", "-nG", username], text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        if groups.returncode == 0 and DANTE_GROUP in groups.stdout.split():
            members.append(username)
    print("\nKudex SOCKS users:")
    for username in sorted(members):
        print(" - " + username)
    if not members:
        print("No Kudex SOCKS users configured.")

def dante_lock_user(lock=True):
    require_root()
    username = ask("SOCKS username to " + ("lock" if lock else "unlock"))
    if not re.fullmatch(r"kpx_[A-Za-z0-9_.-]{3,24}", username):
        raise RuntimeError("Invalid Kudex SOCKS username.")
    groups = subprocess.run(["id", "-nG", username], text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    if groups.returncode or DANTE_GROUP not in groups.stdout.split():
        raise RuntimeError("That is not a Kudex SOCKS account.")
    run(["usermod", "-L" if lock else "-U", username])
    print(f"SOCKS account '{username}' {'locked' if lock else 'unlocked'}.")

def dante_socks_menu():
    while True:
        print("\n--- DANTE SOCKS5 MANAGER ---")
        print(f"Dante service: {service_state('danted.service')} | TCP/{DANTE_PORT}")
        print("[1] Install/configure authenticated SOCKS5")
        print("[2] Add/reset SOCKS username and password")
        print("[3] List Kudex SOCKS users")
        print("[4] Lock SOCKS user")
        print("[5] Unlock SOCKS user")
        print("[6] Restart Dante")
        print("[7] Stop Dante")
        print("[0] Back")
        choice = input("Select: ").strip()
        if choice == "0":
            return
        if choice == "1":
            dante_configure()
        elif choice == "2":
            dante_add_user()
        elif choice == "3":
            dante_list_users()
        elif choice == "4":
            dante_lock_user(True)
        elif choice == "5":
            dante_lock_user(False)
        elif choice == "6":
            if confirm("Restart Dante and disconnect active SOCKS sessions?"):
                run(["systemctl", "restart", "danted.service"])
        elif choice == "7":
            if confirm("Stop the SOCKS5 proxy?"):
                run(["systemctl", "stop", "danted.service"])
        else:
            print("Invalid selection.")

def optional_services_menu():
    while True:
        print("\n--- STUNNEL4 & OPENVPN ---")
        print(f"[1] Configure/enable Stunnel4 TLS on TCP/444 ({service_state('stunnel4.service')})")
        print(f"[2] Restart Stunnel4 ({service_state('stunnel4.service')})")
        print("[3] OpenVPN service controls")
        print("[0] Back")
        choice = input("Select: ").strip()
        if choice == "0":
            return
        if choice == "1":
            configure_stunnel()
        elif choice == "2":
            if service_state("stunnel4.service") == "active":
                run(["systemctl", "restart", "stunnel4.service"])
            else:
                print("Stunnel4 is not active; configure it first.")
        elif choice == "3":
            units = openvpn_units()
            if not units:
                print("No OpenVPN systemd service is installed. Kudex will not create or overwrite an OpenVPN server configuration.")
                continue
            for index, unit in enumerate(units, 1):
                print(f"[{index}] {unit}: {service_state(unit)}")
            selected = ask("Select service number")
            if not selected.isdigit() or not (1 <= int(selected) <= len(units)):
                print("Invalid selection.")
                continue
            unit = units[int(selected) - 1]
            print(f"{unit}: {service_state(unit)}")
            print("[1] Start [2] Stop [3] Restart [4] Enable at boot [5] Disable at boot [0] Back")
            action = input("Select: ").strip()
            actions = {"1": "start", "2": "stop", "3": "restart", "4": "enable", "5": "disable"}
            if action in actions:
                if action in ("2", "3") and not confirm(f"{action} may disconnect OpenVPN clients. Continue?"):
                    continue
                run(["systemctl", actions[action], unit])
        else:
            print("Invalid selection.")

def service_menu(label, unit):
    while True:
        print(f"\n{label}: {service_state(unit)}")
        print("[1] Start [2] Stop [3] Restart [4] Enable at boot [5] Disable at boot [0] Back")
        c = input("Select: ").strip()
        actions = {"1": "start", "2": "stop", "3": "restart", "4": "enable", "5": "disable"}
        if c == "0": return
        if c in actions:
            if c in ("2", "3") and unit in ("ssh.service", "sshd.service") and not confirm("Stopping/restarting SSH can disconnect remote access. Continue?"):
                continue
            run(["systemctl", actions[c], unit])
        else: print("Invalid selection.")


TELEGRAM_CONFIG = ETC / "telegram.json"

def telegram_settings():
    data = read_json(TELEGRAM_CONFIG, {})
    token = data.get("bot_token", "")
    chat_id = str(data.get("chat_id", ""))
    return {"bot_token": token, "chat_id": chat_id} if token and chat_id else None

def telegram_api(method, token, payload=None):
    url = "https://api.telegram.org/bot" + token + "/" + method
    body = urllib.parse.urlencode(payload).encode() if payload is not None else None
    request = urllib.request.Request(url, data=body, headers={"User-Agent": "KudexVPNManager"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            result = json.loads(response.read().decode("utf-8"))
    except Exception:
        raise RuntimeError("Telegram request failed. Check internet access and bot configuration.")
    if not result.get("ok"):
        raise RuntimeError("Telegram API error: " + str(result.get("description", "request rejected"))[:300])
    return result.get("result")

def configure_telegram():
    require_root()
    print("Create a bot with @BotFather and obtain a fresh token.")
    token = getpass.getpass("Telegram bot token (input hidden): ").strip()
    if not re.fullmatch(r"[0-9]{5,15}:[A-Za-z0-9_-]{20,}", token):
        raise RuntimeError("The bot token format does not look valid.")
    chat_id = ask("Telegram chat ID (numeric ID or @channel username)")
    if not re.fullmatch(r"-?[0-9]{1,20}|@[A-Za-z0-9_]{5,}", chat_id):
        raise RuntimeError("Enter a numeric chat ID or a channel username beginning with @.")
    telegram_api("getMe", token)
    atomic_json(TELEGRAM_CONFIG, {"bot_token": token, "chat_id": chat_id}, 0o600)
    os.chmod(TELEGRAM_CONFIG, 0o600)
    print("Telegram bot configuration saved securely. Token hidden.")

def test_telegram_connection():
    settings = telegram_settings()
    if not settings:
        raise RuntimeError("Telegram is not configured. Choose Configure Telegram first.")
    bot = telegram_api("getMe", settings["bot_token"])
    telegram_api("sendMessage", settings["bot_token"], {
        "chat_id": settings["chat_id"],
        "text": "Kudex VPN Manager: Telegram backup connection test successful."
    })
    print("Telegram connection successful. Bot: @" + str(bot.get("username", "configured")) + ". Test message sent.")

def upload_telegram_backup(archive):
    settings = telegram_settings()
    if not settings:
        raise RuntimeError("Telegram backup is not configured.")
    path = pathlib.Path(archive)
    if path.parent.resolve() != BACKUPS.resolve() or not re.fullmatch(r"kudex-[0-9]{8}-[0-9]{6}\.tar\.gz", path.name):
        raise RuntimeError("Refusing to upload a file outside the Kudex backup directory.")
    if not path.is_file():
        raise RuntimeError("The selected backup file does not exist.")
    boundary = "----Kudex" + secrets.token_hex(16)
    chunks = []
    fields = [("chat_id", settings["chat_id"]), ("caption", "Kudex server backup: " + path.name)]
    for name, value in fields:
        chunks.extend(["--" + boundary + "\r\n",
                       'Content-Disposition: form-data; name="' + name + '"\r\n\r\n',
                       value, "\r\n"])
    chunks.extend(["--" + boundary + "\r\n",
                   'Content-Disposition: form-data; name="document"; filename="' + path.name + '"\r\n',
                   "Content-Type: application/gzip\r\n\r\n"])
    body = "".join(chunks).encode() + path.read_bytes() + ("\r\n--" + boundary + "--\r\n").encode()
    url = "https://api.telegram.org/bot" + settings["bot_token"] + "/sendDocument"
    request = urllib.request.Request(url, data=body, headers={
        "Content-Type": "multipart/form-data; boundary=" + boundary,
        "User-Agent": "KudexVPNManager"
    })
    try:
        with urllib.request.urlopen(request, timeout=180) as response:
            result = json.loads(response.read().decode("utf-8"))
    except Exception:
        raise RuntimeError("Telegram backup upload failed. The local backup remains safe; check network access and Telegram file-size limits.")
    if not result.get("ok"):
        raise RuntimeError("Telegram upload failed: " + str(result.get("description", "request rejected"))[:300])
    print("Backup uploaded to Telegram: " + path.name)

def telegram_incoming_backups():
    settings = telegram_settings()
    if not settings:
        raise RuntimeError("Telegram is not configured.")
    if not re.fullmatch(r"-?[0-9]{1,20}", settings["chat_id"]):
        raise RuntimeError("Use a numeric private-chat ID for Telegram restore.")
    updates = telegram_api("getUpdates", settings["bot_token"], {"limit": "100", "timeout": "0"})
    found = []
    for update in updates or []:
        message = update.get("message", {})
        document = message.get("document", {})
        if str(message.get("chat", {}).get("id", "")) != settings["chat_id"]:
            continue
        name = str(document.get("file_name", ""))
        if document and re.fullmatch(r"kudex-[0-9]{8}-[0-9]{6}\.tar\.gz", name):
            found.append({"file_id": document["file_id"], "name": name,
                          "date": int(message.get("date", 0)), "size": int(document.get("file_size", 0))})
    return sorted(found, key=lambda item: item["date"], reverse=True)

def download_telegram_backup(file_id, filename):
    settings = telegram_settings()
    if not settings or not re.fullmatch(r"kudex-[0-9]{8}-[0-9]{6}\.tar\.gz", filename):
        raise RuntimeError("Telegram backup configuration or filename is invalid.")
    info = telegram_api("getFile", settings["bot_token"], {"file_id": file_id})
    remote_path = info.get("file_path", "")
    if not remote_path or ".." in pathlib.PurePosixPath(remote_path).parts or remote_path.startswith("/"):
        raise RuntimeError("Telegram returned an invalid file path.")
    url = "https://api.telegram.org/file/bot" + settings["bot_token"] + "/" + remote_path
    fd, temporary = tempfile.mkstemp(prefix=".telegram-restore-", dir=str(BACKUPS))
    total = 0
    try:
        with os.fdopen(fd, "wb") as output, urllib.request.urlopen(url, timeout=120) as response:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > 1073741824:
                    raise RuntimeError("Telegram backup exceeds the 1 GiB safety limit.")
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        if total < 1 or not tarfile.is_tarfile(temporary):
            raise RuntimeError("Downloaded Telegram document is not a valid tar archive.")
        os.chmod(temporary, 0o600)
        target = BACKUPS / filename
        if target.exists():
            raise RuntimeError("A local backup with this filename already exists; move it aside before downloading again.")
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    print("Telegram backup downloaded: " + target.name)
    return target

def restore_from_telegram():
    require_root()
    ensure_dirs()
    print("Send a Kudex backup document to your configured bot in a private chat first.")
    incoming = telegram_incoming_backups()
    if not incoming:
        print("No matching incoming backups found. Send a backup to the bot and try again.")
        return
    for index, item in enumerate(incoming, 1):
        stamp = datetime.datetime.fromtimestamp(item["date"]).strftime("%Y-%m-%d %H:%M:%S")
        print("[" + str(index) + "] " + item["name"] + " | " + human_bytes(item["size"]) + " | " + stamp)
    raw = ask("Telegram backup number")
    if not raw.isdigit() or not 1 <= int(raw) <= len(incoming):
        print("Invalid selection.")
        return
    selected = incoming[int(raw) - 1]
    if not confirm("Download " + selected["name"] + " and open the normal Kudex restore workflow?"):
        return
    download_telegram_backup(selected["file_id"], selected["name"])
    restore_backup()

def telegram_backup_menu():
    while True:
        print("\n--- TELEGRAM BACKUP ---")
        print("Configuration: " + ("READY" if telegram_settings() else "NOT CONFIGURED"))
        print("[1] Configure / replace bot credentials")
        print("[2] Test connection (sends a test message)")
        print("[3] Upload latest local backup")
        print("[4] Remove Telegram configuration")
        print("[5] Restore a backup sent to this bot")
        print("[0] Back")
        choice = input("Select: ").strip()
        if choice == "0":
            return
        if choice == "1":
            configure_telegram()
        elif choice == "2":
            test_telegram_connection()
        elif choice == "3":
            archives = sorted(BACKUPS.glob("kudex-*.tar.gz"), reverse=True)
            if not archives:
                print("No local Kudex backups found. Create a backup first.")
            else:
                upload_telegram_backup(archives[0])
        elif choice == "4":
            if TELEGRAM_CONFIG.exists() and confirm("Remove the saved Telegram bot token and chat ID?"):
                TELEGRAM_CONFIG.unlink()
                print("Telegram configuration removed.")
        elif choice == "5":
            restore_from_telegram()
        else:
            print("Invalid selection.")


BACKUP_POLICY = ETC / "backup-policy.json"

def backup_retention_count():
    policy = read_json(BACKUP_POLICY, {})
    count = policy.get("keep_last", 0)
    return count if isinstance(count, int) and not isinstance(count, bool) and 5 <= count <= 100 else 0

def prune_old_backups(keep_last=None, silent=False):
    require_root()
    keep = backup_retention_count() if keep_last is None else keep_last
    if not isinstance(keep, int) or not 5 <= keep <= 100:
        raise RuntimeError("Backup retention must be between 5 and 100 archives.")
    archives = sorted(
        (p for p in BACKUPS.glob("kudex-*.tar.gz")
         if p.is_file() and not p.is_symlink()
         and re.fullmatch(r"kudex-[0-9]{8}-[0-9]{6}\.tar\.gz", p.name)),
        key=lambda p: p.name, reverse=True
    )
    removed = 0
    for old in archives[keep:]:
        old.unlink()
        removed += 1
    if not silent:
        print(f"Smart backup cleanup complete: kept {min(len(archives), keep)}, removed {removed} older local archive(s).")
        print("Telegram copies are not affected.")
    return removed

def backup_retention_menu():
    require_root()
    current = backup_retention_count()
    print("\n--- SMART BACKUP RETENTION ---")
    print("Current policy: " + (f"keep latest {current} local archives" if current else "disabled"))
    print("Only local Kudex archives are rotated; Telegram copies are not deleted.")
    print("[1] Enable / change retention")
    print("[2] Disable automatic retention")
    print("[3] Run cleanup now")
    print("[0] Back")
    choice = input("Select: ").strip()
    if choice == "1":
        raw = ask("Number of recent backups to keep (5-100)", str(current or 30))
        if not raw.isdigit() or not 5 <= int(raw) <= 100:
            print("Enter a number from 5 to 100.")
            return
        atomic_json(BACKUP_POLICY, {"keep_last": int(raw)})
        print(f"Smart retention enabled: keep the latest {raw} local backups.")
        if confirm("Run cleanup now and permanently remove older local archives beyond this limit?"):
            prune_old_backups(int(raw), silent=False)
    elif choice == "2":
        if BACKUP_POLICY.exists() and confirm("Disable automatic local backup rotation?"):
            BACKUP_POLICY.unlink()
            print("Automatic backup rotation disabled. Existing archives were preserved.")
    elif choice == "3":
        raw = ask("Keep how many recent archives (5-100)", str(current or 30))
        if not raw.isdigit() or not 5 <= int(raw) <= 100:
            print("Enter a number from 5 to 100.")
            return
        if confirm("Permanently remove local archives older than the selected retention limit?"):
            prune_old_backups(int(raw))
    elif choice != "0":
        print("Invalid selection.")

def speed_test_menu():
    require_root()
    print("\n--- SERVER INTERNET SPEED TEST ---")
    print("Uses Speedtest CLI infrastructure. The test transfers data and may consume bandwidth.")
    tool = shutil.which("speedtest") or shutil.which("speedtest-cli")
    if not tool:
        if not confirm("Speedtest CLI is not installed. Install the Ubuntu/Debian speedtest-cli package?"):
            return
        if not pathlib.Path("/usr/bin/apt-get").exists():
            raise RuntimeError("Automatic installation is available only on Ubuntu/Debian.")
        run(["apt-get", "update"])
        run(["apt-get", "install", "-y", "speedtest-cli"])
        tool = shutil.which("speedtest-cli") or shutil.which("speedtest")
    if not tool:
        raise RuntimeError("Speedtest CLI installation completed but no executable was found.")
    if not confirm("Run a speed test now? This uses external test servers and transfers data."):
        return
    if pathlib.Path(tool).name == "speedtest":
        run([tool, "--accept-license", "--accept-gdpr"])
    else:
        run([tool, "--secure"])


BACKUP_SYNC_CONFIG = ETC / "backup-sync.json"

def configured_backup_mount():
    config = read_json(BACKUP_SYNC_CONFIG, {})
    raw = config.get("mount_path", "")
    if not isinstance(raw, str) or not raw:
        return None
    mount = pathlib.Path(raw)
    if not mount.is_absolute() or mount.resolve() == pathlib.Path("/"):
        return None
    if not mount.is_dir() or not os.path.ismount(str(mount)):
        return None
    return mount.resolve()

def sync_backup_to_mount(archive):
    require_root()
    source = pathlib.Path(archive)
    if source.parent.resolve() != BACKUPS.resolve() or not source.is_file() or source.is_symlink():
        raise RuntimeError("Only a regular Kudex archive inside the local backup directory can be synced.")
    if not re.fullmatch(r"kudex-[0-9]{8}-[0-9]{6}\.tar\.gz", source.name):
        raise RuntimeError("Unrecognized Kudex backup filename.")
    mount = configured_backup_mount()
    if not mount:
        raise RuntimeError("Configured backup mount is not currently mounted. Local backup remains safe.")
    destination_dir = mount / "KudexBackups"
    destination_dir.mkdir(mode=0o700, exist_ok=True)
    if destination_dir.is_symlink() or destination_dir.resolve().parent != mount:
        raise RuntimeError("Backup sync destination is not a safe directory on the configured mount.")
    destination = destination_dir / source.name
    fd, temporary = tempfile.mkstemp(prefix=".kudex-sync-", dir=str(destination_dir))
    digest = hashlib.sha256()
    try:
        with os.fdopen(fd, "wb") as output, source.open("rb") as incoming:
            while True:
                chunk = incoming.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    checksum = destination.with_name(destination.name + ".sha256")
    checksum.write_text(digest.hexdigest() + "  " + destination.name + "\n")
    os.chmod(checksum, 0o600)
    print("Backup synced to mounted storage: " + str(destination))
    return destination

def backup_sync_menu():
    require_root()
    while True:
        mount = configured_backup_mount()
        print("\n--- SMART BACKUP SYNC ---")
        print("Configured mount: " + (str(mount) if mount else "NOT CONFIGURED / NOT MOUNTED"))
        print("Destination folder: KudexBackups")
        print("[1] Configure mounted backup destination")
        print("[2] Sync latest local backup now")
        print("[3] Disable mounted backup sync")
        print("[0] Back")
        choice = input("Select: ").strip()
        if choice == "0":
            return
        if choice == "1":
            raw = ask("Absolute path of an already-mounted backup disk or network share")
            candidate = pathlib.Path(raw).expanduser()
            if not candidate.is_absolute() or not candidate.is_dir() or not os.path.ismount(str(candidate)):
                print("That path is not an active mount point. Mount the external disk/network share first.")
                continue
            candidate = candidate.resolve()
            if candidate == pathlib.Path("/"):
                print("The filesystem root cannot be used as a backup destination.")
                continue
            if confirm("Save this mounted destination for automatic backup copies: " + str(candidate) + "?"):
                atomic_json(BACKUP_SYNC_CONFIG, {"mount_path": str(candidate)})
                print("Mounted backup sync configured.")
        elif choice == "2":
            archives = sorted(BACKUPS.glob("kudex-*.tar.gz"), reverse=True)
            if not archives:
                print("No local Kudex backup exists yet.")
            else:
                sync_backup_to_mount(archives[0])
        elif choice == "3":
            if BACKUP_SYNC_CONFIG.exists() and confirm("Disable mounted backup sync? Existing copies on the mounted storage will be preserved."):
                BACKUP_SYNC_CONFIG.unlink()
                print("Mounted backup sync disabled.")
        else:
            print("Invalid selection.")

def backup(auto_upload=False):
    ensure_dirs()
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    target = BACKUPS / f"kudex-{stamp}.tar.gz"
    items = [p for p in (ETC, XRAY_CONFIG, NGINX_SITE, OPENVPN_SERVER_DIR / "kudex", OPENVPN_SERVER_DIR / "kudex.conf") if p.exists()]
    with tarfile.open(target, "w:gz") as tf:
        for p in items:
            def exclude_telegram_secret(member):
                return None if member.name.rstrip("/") == "etc/kudex/telegram.json" else member
            tf.add(p, arcname=str(p).lstrip("/"), filter=exclude_telegram_secret)
    os.chmod(target, 0o600)
    print(f"Backup created: {target}")
    if backup_retention_count():
        prune_old_backups(silent=True)
    if BACKUP_SYNC_CONFIG.exists():
        try:
            sync_backup_to_mount(target)
        except (RuntimeError, OSError) as exc:
            print(f"[BACKUP SYNC WARNING] {exc}")
    if google_drive_settings():
        try: google_drive_sync(target)
        except (RuntimeError, OSError) as exc: print(f"[GOOGLE DRIVE WARNING] {exc}")
    if auto_upload and telegram_settings():
        try:
            upload_telegram_backup(target)
        except RuntimeError as exc:
            print(f"[TELEGRAM WARNING] {exc}")
    return target


def install_backup_schedule(hours):
    require_root()
    if hours not in (12, 24):
        raise RuntimeError("Backup interval must be 12 or 24 hours.")
    service = pathlib.Path("/etc/systemd/system/kudex-backup.service")
    timer = pathlib.Path("/etc/systemd/system/kudex-backup.timer")
    app = pathlib.Path("/opt/kudex-vpn-manager/lib/kudex.py")
    if not app.exists():
        raise RuntimeError("Kudex is not installed in /opt/kudex-vpn-manager.")
    service.write_text(f"""[Unit]
Description=Kudex protected configuration backup

[Service]
Type=oneshot
User=root
ExecStart=/usr/bin/python3 {app} --backup-auto
""")
    schedule = "*-*-* 00,12:00:00" if hours == 12 else "*-*-* 02:00:00"
    timer.write_text(f"""[Unit]
Description=Run Kudex backups every {hours} hours

[Timer]
OnCalendar={schedule}
Persistent=true
Unit=kudex-backup.service

[Install]
WantedBy=timers.target
""")
    os.chmod(service, 0o644)
    os.chmod(timer, 0o644)
    run(["systemctl", "daemon-reload"])
    run(["systemctl", "enable", "--now", "kudex-backup.timer"])
    print(f"Automatic Kudex backups enabled every {hours} hours.")

def install_expiry_schedule():
    require_root()
    app = pathlib.Path("/opt/kudex-vpn-manager/lib/kudex.py")
    if not app.exists():
        raise RuntimeError("Kudex is not installed in /opt/kudex-vpn-manager.")
    service = pathlib.Path("/etc/systemd/system/kudex-expiry.service")
    timer = pathlib.Path("/etc/systemd/system/kudex-expiry.timer")
    service.write_text(f"""[Unit]
Description=Enforce expired Kudex VPN accounts

[Service]
Type=oneshot
User=root
ExecStart=/usr/bin/python3 {app} --expire
""")
    timer.write_text("""[Unit]
Description=Check Kudex account expiry every five minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
Persistent=true
Unit=kudex-expiry.service

[Install]
WantedBy=timers.target
""")
    os.chmod(service, 0o644)
    os.chmod(timer, 0o644)
    run(["systemctl", "daemon-reload"])
    run(["systemctl", "enable", "--now", "kudex-expiry.timer"])
    print("Automatic account expiry enforcement enabled (checks every five minutes).")

def verify_kudex_backup(path):
    path = pathlib.Path(path)
    if path.parent.resolve() != BACKUPS.resolve() or not path.is_file():
        raise RuntimeError("Select a backup stored inside the Kudex backup directory.")
    allowed = {"etc/kudex/state.json", "etc/kudex/clients.json",
               "etc/kudex/reality.json", "usr/local/etc/xray/config.json", "etc/nginx/sites-available/kudex.conf",
               "etc/openvpn/server/kudex.conf", "etc/openvpn/server/kudex/ca.crt",
               "etc/openvpn/server/kudex/server.crt", "etc/openvpn/server/kudex/server.key",
               "etc/openvpn/server/kudex/tls-crypt.key"}
    checked = []
    try:
        with tarfile.open(path, "r:gz") as archive:
            for member in archive.getmembers():
                name = member.name.lstrip("./")
                if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                    raise RuntimeError("Backup contains an unsafe filesystem entry.")
                if name in allowed and member.isfile():
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise RuntimeError("Could not read backup member: " + name)
                    content = stream.read()
                    if name.endswith(".json"):
                        json.loads(content.decode("utf-8"))
                    checked.append(name)
    except (tarfile.TarError, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Backup verification failed: " + str(exc))
    if not checked:
        raise RuntimeError("Archive contains no recognized Kudex configuration files.")
    print("Backup verification passed. Recognized files:")
    for name in sorted(set(checked)):
        print(" - " + name)
    return True

def verify_backups_menu():
    archives = sorted(BACKUPS.glob("kudex-*.tar.gz"), reverse=True)
    if not archives:
        print("No Kudex backups found.")
        return
    for index, item in enumerate(archives, 1):
        print("[" + str(index) + "] " + item.name + " (" + human_bytes(item.stat().st_size) + ")")
    raw = ask("Backup number to verify")
    if not raw.isdigit() or not 1 <= int(raw) <= len(archives):
        print("Invalid selection.")
        return
    verify_kudex_backup(archives[int(raw) - 1])

def backup_menu():
    while True:
        timer_state = service_state("kudex-backup.timer")
        print("\n--- BACKUP MANAGER ---")
        print("[1] Create manual backup")
        print("[2] Automatic backup every 12 hours")
        print("[3] Automatic backup every 24 hours")
        print("[4] Disable automatic backups")
        expiry_timer_state = service_state("kudex-expiry.timer")
        print("[5] List available backups")
        print("[6] Enable automatic account expiry checks")
        print("[7] Disable automatic account expiry checks")
        print("[8] Telegram backup integration")
        print("[9] Verify a backup archive")
        print("[10] Smart backup retention")
        print("[11] Smart backup sync (mounted storage)")
        print(f"Backup schedule: {timer_state} | Expiry checks: {expiry_timer_state}")
        print("[0] Back")
        choice = input("Select: ").strip()
        if choice == "0":
            return
        if choice == "1":
            backup()
        elif choice == "2":
            install_backup_schedule(12)
        elif choice == "3":
            install_backup_schedule(24)
        elif choice == "4":
            if confirm("Disable automatic Kudex backups?"):
                subprocess.run(["systemctl", "disable", "--now", "kudex-backup.timer"], check=False)
                print("Automatic backups disabled.")
        elif choice == "5":
            archives = sorted(BACKUPS.glob("kudex-*.tar.gz"), reverse=True)
            if not archives:
                print("No backups found.")
            for item in archives:
                print(f"{item.name} ({human_bytes(item.stat().st_size)})")
        elif choice == "6":
            install_expiry_schedule()
        elif choice == "7":
            if confirm("Disable automatic account expiry checks?"):
                subprocess.run(["systemctl", "disable", "--now", "kudex-expiry.timer"], check=False)
                print("Automatic account expiry checks disabled.")
        elif choice == "8":
            telegram_backup_menu()
        elif choice == "9":
            verify_backups_menu()
        elif choice == "10":
            backup_retention_menu()
        elif choice == "11":
            backup_sync_menu()
        else:
            print("Invalid selection.")

def restore_backup():
    ensure_dirs()
    archives = sorted(BACKUPS.glob("kudex-*.tar.gz"), reverse=True)
    if not archives:
        print("No Kudex backups found."); return
    for i, item in enumerate(archives, 1): print(f"[{i}] {item.name}")
    raw = ask("Backup number")
    if not raw.isdigit() or not (1 <= int(raw) <= len(archives)):
        print("Invalid selection."); return
    chosen = archives[int(raw)-1]
    if not confirm(f"Restore protected configuration from {chosen.name}?"):
        return
    allowed = {"etc/kudex/state.json", "etc/kudex/clients.json",
               "etc/kudex/reality.json", "usr/local/etc/xray/config.json", "etc/nginx/sites-available/kudex.conf",
               "etc/openvpn/server/kudex.conf", "etc/openvpn/server/kudex/ca.crt",
               "etc/openvpn/server/kudex/server.crt", "etc/openvpn/server/kudex/server.key",
               "etc/openvpn/server/kudex/tls-crypt.key"}
    staged = {}
    with tarfile.open(chosen, "r:gz") as tf:
        for member in tf.getmembers():
            name = member.name.lstrip("./")
            if name in allowed and member.isfile():
                stream = tf.extractfile(member)
                if stream: staged[name] = stream.read()
    if not staged:
        raise RuntimeError("Backup contained no recognized Kudex configuration files.")
    targets = {
        "etc/kudex/state.json": STATE, "etc/kudex/clients.json": CLIENTS,
        "etc/kudex/reality.json": REALITY_CONFIG,
        "usr/local/etc/xray/config.json": XRAY_CONFIG, "etc/nginx/sites-available/kudex.conf": NGINX_SITE,
        "etc/openvpn/server/kudex.conf": OPENVPN_SERVER_DIR / "kudex.conf",
        "etc/openvpn/server/kudex/ca.crt": OPENVPN_SERVER_DIR / "kudex/ca.crt",
        "etc/openvpn/server/kudex/server.crt": OPENVPN_SERVER_DIR / "kudex/server.crt",
        "etc/openvpn/server/kudex/server.key": OPENVPN_SERVER_DIR / "kudex/server.key",
        "etc/openvpn/server/kudex/tls-crypt.key": OPENVPN_SERVER_DIR / "kudex/tls-crypt.key"
    }
    previous = {name: (path.read_bytes() if path.exists() else None) for name, path in targets.items() if name in staged}
    try:
        for name, content in staged.items():
            path = targets[name]; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content); os.chmod(path, 0o600 if name.startswith(("etc/kudex", "usr/local/etc/xray", "etc/openvpn/server")) else 0o644)
        if any(name.startswith("etc/openvpn/server/kudex/") for name in staged):
            (OPENVPN_SERVER_DIR / "kudex").mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(OPENVPN_SERVER_DIR / "kudex", 0o700)
        if "usr/local/etc/xray/config.json" in staged and xray_binary():
            test = subprocess.run([xray_binary(), "run", "-test", "-config", str(XRAY_CONFIG)], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            if test.returncode: raise RuntimeError("Restored Xray config failed validation: " + test.stdout[-2000:])
        if "etc/nginx/sites-available/kudex.conf" in staged:
            test = subprocess.run(["nginx", "-t"], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            if test.returncode: raise RuntimeError("Restored Nginx config failed validation: " + test.stdout[-2000:])
        if "usr/local/etc/xray/config.json" in staged and xray_binary(): run(["systemctl", "restart", "xray.service"])
        if "etc/nginx/sites-available/kudex.conf" in staged: run(["systemctl", "reload", "nginx.service"])
    except Exception:
        for name, old in previous.items():
            path = targets[name]
            if old is None: path.unlink(missing_ok=True)
            else: path.write_bytes(old)
        raise
    print(f"Restored {len(staged)} configuration files from {chosen.name}.")

def diagnostics():
    print("\n--- SERVICE STATUS ---")
    for label, unit in (("SSH", "ssh.service"), ("NGINX", "nginx.service"), ("XRAY", "xray.service"), ("DROPBEAR", "dropbear.service")):
        print(f"{label:<12}: {service_state(unit)}")
    print(f"{'SSH-WS':<12}: {service_state('xray.service')} (Xray inbound)")
    print("\n--- SYSTEM ---")
    run(["df", "-h", "/"])
    run(["free", "-h"])
    print("\n--- PORT LISTENERS ---")
    if shutil.which("ss"): run(["ss", "-lntp"], check=False)

def update_app():
    """Safely update installed Kudex application files from the public main branch."""
    require_root()
    ensure_dirs()
    import io
    repo_url = "https://codeload.github.com/Abdul1471/kudex-vpn-manager/tar.gz/refs/heads/main"
    request = urllib.request.Request(repo_url, headers={"User-Agent": "KudexVPNManager-Updater"})
    with urllib.request.urlopen(request, timeout=90) as response:
        archive_data = response.read()
    wanted = {"lib/kudex.py", "lib/common.sh", "bin/kudex"}
    staged = {}
    with tarfile.open(fileobj=io.BytesIO(archive_data), mode="r:gz") as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            parts = pathlib.PurePosixPath(member.name).parts
            if len(parts) >= 2:
                relative = "/".join(parts[1:])
                if relative in wanted:
                    stream = archive.extractfile(member)
                    if stream:
                        staged[relative] = stream.read()
    missing = wanted - staged.keys()
    if missing:
        raise RuntimeError("Update archive is incomplete: " + ", ".join(sorted(missing)))
    try:
        compile(staged["lib/kudex.py"].decode("utf-8"), "kudex.py", "exec")
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise RuntimeError(f"Downloaded Kudex update failed Python validation: {exc}")
    install_root = pathlib.Path("/opt/kudex-vpn-manager")
    targets = {
        "lib/kudex.py": install_root / "lib/kudex.py",
        "lib/common.sh": install_root / "lib/common.sh",
        "bin/kudex": install_root / "bin/kudex",
    }
    for target in targets.values():
        if not target.exists():
            raise RuntimeError(f"Installed file missing: {target}. Run the installer once to repair the installation.")
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_path = BACKUPS / f"kudex-app-before-update-{stamp}.tar.gz"
    with tarfile.open(backup_path, "w:gz") as archive:
        for relative, target in targets.items():
            archive.add(target, arcname=relative)
    os.chmod(backup_path, 0o600)
    replaced = []
    try:
        for relative, target in targets.items():
            target.parent.mkdir(parents=True, exist_ok=True)
            fd, temporary = tempfile.mkstemp(prefix=".kudex-update-", dir=str(target.parent))
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(staged[relative])
                    handle.flush()
                    os.fsync(handle.fileno())
                os.chmod(temporary, 0o755 if relative == "bin/kudex" else 0o644)
                os.replace(temporary, target)
                replaced.append(relative)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
    except Exception:
        with tarfile.open(backup_path, "r:gz") as archive:
            for relative in replaced:
                member = archive.getmember(relative)
                stream = archive.extractfile(member)
                if stream:
                    targets[relative].write_bytes(stream.read())
        raise
    print("Kudex application updated successfully.")
    print(f"Pre-update application backup: {backup_path}")
    print("Your VPN clients, domain, TLS certificates and server configuration were preserved.")
    print("No VPN services were restarted. Run 'sudo kudex apply' if the release notes require reapplying configuration.")

def upgrade_system():
    """Upgrade installed Ubuntu/Debian packages without changing Kudex data."""
    require_root()
    if not pathlib.Path("/usr/bin/apt-get").exists():
        raise RuntimeError("System package upgrade is available only on apt-based Ubuntu/Debian systems.")
    if not confirm("Run apt-get update and apt-get upgrade on this server?"):
        print("System upgrade cancelled.")
        return
    os.environ["DEBIAN_FRONTEND"] = "noninteractive"
    run(["apt-get", "update"])
    run(["apt-get", "upgrade", "-y"])
    print("System package upgrade completed. Review any service restart notices above.")

def human_bytes(value):
    amount = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if amount < 1024 or unit == "TiB": return f"{amount:.1f} {unit}"
        amount /= 1024

def system_memory():
    try:
        data = {}
        for line in pathlib.Path("/proc/meminfo").read_text().splitlines():
            key, value = line.split(":", 1)
            data[key] = int(value.strip().split()[0]) * 1024
        total = data.get("MemTotal", 0)
        free = data.get("MemAvailable", data.get("MemFree", 0))
        return total, max(0, total-free), free
    except (OSError, ValueError): return 0, 0, 0

def system_cpu_percent():
    def sample():
        n = [int(x) for x in pathlib.Path("/proc/stat").read_text().splitlines()[0].split()[1:]]
        return sum(n), n[3] + (n[4] if len(n) > 4 else 0)
    try:
        a = sample(); time.sleep(0.12); b = sample()
        total, idle = b[0]-a[0], b[1]-a[1]
        return max(0.0, min(100.0, (1-idle/total)*100)) if total else None
    except (OSError, ValueError, IndexError): return None

def system_uptime():
    try:
        sec = int(float(pathlib.Path("/proc/uptime").read_text().split()[0]))
        d, sec = divmod(sec, 86400); h, sec = divmod(sec, 3600); m = sec//60
        return (f"{d}d " if d else "") + (f"{h}h " if h or d else "") + f"{m}m"
    except (OSError, ValueError, IndexError): return "unknown"

def server_ip():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("1.1.1.1", 80)); ip = sock.getsockname()[0]; sock.close()
        return ip
    except OSError: return "unavailable"

def service_summary():
    checks = (("SSH", ("ssh.service", "sshd.service")), ("NGINX", ("nginx.service",)),
              ("XRAY", ("xray.service",)), ("DROPBEAR", ("dropbear.service",)),
              ("STUNNEL4", ("stunnel4.service",)), ("SLOWDNS", ("kudex-dnstt.service",)), ("SOCKS5", ("danted.service",)), ("BADVPN", ("kudex-badvpn.service",)), ("FAIL2BAN", ("fail2ban.service",)))
    result = {}
    for label, units in checks:
        states = [service_state(u) for u in units]
        result[label] = "RUNNING" if "active" in states else ("NOT INSTALLED" if all(x == "unknown" for x in states) else "STOPPED")
    st = state()
    openvpn = openvpn_units() if "openvpn_units" in globals() else []
    result["OPENVPN"] = "RUNNING" if any(service_state(u) == "active" for u in openvpn) else ("STOPPED" if openvpn else "NOT INSTALLED")
    result["SSH-WS"] = "DISABLED" if not st.get("protocols", {}).get("sshws", True) else (
        "RUNNING" if result["XRAY"] == "RUNNING" and st.get("tls") else "WAITING FOR TLS")
    return result

def dashboard():
    if sys.stdout.isatty(): os.system("clear")
    st = state(); total, used, free = system_memory(); cpu = system_cpu_percent()
    now = datetime.datetime.now().astimezone()
    counts = {p: sum(1 for c in clients() if c.get("protocol") == p and c.get("enabled", True))
              for p in ("vmess", "vless", "trojan")}
    try:
        p = subprocess.run(["bash", "-lc", "getent passwd | awk -F: '$7 ~ /(bash|sh|zsh)$/ {n++} END {print n+0}'"],
                           text=True, capture_output=True, check=False)
        ssh_count = int(p.stdout.strip() or "0")
    except (OSError, ValueError): ssh_count = 0
    cyan = "\033[96m" if sys.stdout.isatty() else ""; gold = "\033[93m" if sys.stdout.isatty() else ""
    reset = "\033[0m" if sys.stdout.isatty() else ""
    print(cyan+"╔══════════════════════════════════════════════════════════════╗")
    print("║                       KUDEX VPN MANAGER                      ║")
    print("╚══════════════════════════════════════════════════════════════╝"+reset)
    print(gold+" VPS INFORMATION"+reset)
    print(f" Hostname       : {socket.gethostname()}")
    print(f" Server IP      : {server_ip()}")
    print(f" Domain         : {st.get('domain') or 'NOT CONFIGURED'}")
    print(f" Operating System: {platform.platform()}")
    print(f" Current Time   : {now.strftime('%d-%m-%Y %H:%M:%S %Z')}")
    print(f" Uptime         : {system_uptime()}")
    print(f" CPU Usage      : {cpu:.1f}%" if cpu is not None else " CPU Usage      : unavailable")
    print(f" RAM            : {human_bytes(used)} used / {human_bytes(total)} total / {human_bytes(free)} free")
    print(f" TLS            : {'ENABLED' if st.get('tls') else 'NOT CONFIGURED'}")
    backups = sorted(BACKUPS.glob("kudex-*.tar.gz"), reverse=True) if BACKUPS.exists() else []
    latest_backup = backups[0].name if backups else "NONE"
    print(f" Latest Backup  : {latest_backup}")
    print(f" Backup Timer   : {service_state('kudex-backup.timer')}")
    print(f" Reboot Timer   : {service_state('kudex-auto-reboot.timer')}")
    print(f" Backup Sync    : {'MOUNTED' if configured_backup_mount() else 'NOT READY'}")
    retention = backup_retention_count()
    print(f" Retention      : {str(retention) + ' archives' if retention else 'DISABLED'}")
    print(gold+"\n CLIENT STATISTICS"+reset)
    print(f" SSH users: {ssh_count} | VMess: {counts['vmess']} | VLESS: {counts['vless']} | Trojan: {counts['trojan']}")
    print(gold+"\n SERVICE STATUS"+reset)
    for label, status in service_summary().items(): print(f" {label:<12}: {status}")
    print(gold+"\n MAIN MENU"+reset)
    print(" [01] SSH Accounts       [02] VMess Accounts")
    print(" [03] VLESS Accounts     [04] Trojan Accounts")
    print(" [05] SSH over WebSocket [06] Backup Manager")
    print(" [07] Domain & SSL       [08] Server Health")
    print(" [09] Service Control    [10] Install/Update Xray")
    print(" [11] Apply Configuration[12] Restore Backup")
    print(" [13] Update Kudex       [14] Upgrade OS Packages")
    print(" [15] Bandwidth Monitor  [16] Restart Services")
    print(" [17] Ports & Server Info  [18] Stunnel4 & OpenVPN")
    print(" [19] SSH Security Manager [20] SlowDNS / DNSTT")
    print(" [21] SSH Banner Editor    [22] Auto-Reboot Scheduler")
    print(" [23] Server Speed Test      [24] Xray Transport Manager")
    print(" [25] Authenticated HTTP Proxy")
    print(" [26] Dante SOCKS5 Proxy")
    print(" [27] BadVPN UDP Gateway   [28] OpenVPN Provisioning")
    print(" [29] Google Drive Backup  [30] SSH / Host Protection")
    print(" [31] Active Session Manager")
    print(" [00] Exit")
    print(cyan+"─"*64+reset)

def network_counters():
    result = {}
    try:
        for line in pathlib.Path("/proc/net/dev").read_text().splitlines()[2:]:
            if ":" not in line: continue
            iface, raw = line.split(":", 1); f = raw.split()
            if len(f) >= 9 and iface.strip() != "lo": result[iface.strip()] = (int(f[0]), int(f[8]))
    except (OSError, ValueError): pass
    return result

def bandwidth_menu():
    while True:
        print("\n--- BANDWIDTH MONITOR ---\n[1] Live Traffic\n[2] Daily Usage (vnStat)\n[3] Monthly Usage (vnStat)\n[0] Back")
        choice = input("Select: ").strip()
        if choice == "0": return
        if choice == "1":
            print("Monitoring interfaces. Press CTRL-C to stop.")
            try:
                old = network_counters()
                while True:
                    time.sleep(1); new = network_counters()
                    for iface, (rx, tx) in new.items():
                        pr, pt = old.get(iface, (rx, tx))
                        print(f"{iface}: RX {human_bytes(max(0,rx-pr))}/s | TX {human_bytes(max(0,tx-pt))}/s")
                    old = new
            except KeyboardInterrupt: print("\nLive monitor stopped.")
        elif choice in ("2", "3"):
            if not shutil.which("vnstat"):
                print("vnStat is not installed; historical usage is unavailable.")
            else: run(["vnstat", "-d" if choice == "2" else "-m"], check=False)
        else: print("Invalid selection.")

def ports_info():
    print("\n--- KUDEX SERVICE PORTS ---")
    print("OpenSSH       : TCP/22 (existing SSH configuration)")
    print("Dropbear      : TCP/2222 (when installed)")
    print("Nginx HTTP    : TCP/80")
    print("Nginx HTTPS   : TCP/443 (when TLS configured)")
    if reality_profile().get("enabled"):
        print(f"VLESS REALITY : TCP/{REALITY_PORT} (direct listener)")
    for proto, port in HTTPUPGRADE_PORTS.items():
        if state().get("transports", {}).get(proto, {}).get("httpupgrade", False):
            print(f"{proto.upper()} HTTPUpgrade: 127.0.0.1:{port} {HTTPUPGRADE_PATHS[proto]} via Nginx/443")
    for proto in ("vmess", "vless", "trojan", "sshws"):
        print(f"{PROTO_NAMES[proto]:<14}: 127.0.0.1:{PORTS[proto]} {PATHS[proto]}")
    print(f"Authenticated HTTP proxy: TCP/{SQUID_PORT} (when Squid is configured)")
    badvpn = read_json(BADVPN_CONFIG, {})
    if badvpn: print(f"BadVPN UDPGW: TCP/{badvpn.get('bind', '127.0.0.1')}:{badvpn.get('port', 7300)}")
    if service_state(OPENVPN_UNIT) != "unknown": print("OpenVPN server: UDP/2200")
    print("\n--- LISTENING SOCKETS ---")
    if shutil.which("ss"): run(["ss", "-lntup"], check=False)

def restart_services():
    units = (("nginx.service", "Nginx"), ("xray.service", "Xray"), ("dropbear.service", "Dropbear"))
    available = [(unit, label) for unit, label in units if service_state(unit) != "unknown"]
    print("OpenSSH is deliberately excluded to protect your remote session.")
    if not available: print("No managed services detected."); return
    if not confirm("Restart "+", ".join(label for _,label in available)+"?"): return
    for unit, label in available:
        try: run(["systemctl", "restart", unit]); print(f"{label}: restarted")
        except RuntimeError as exc: print(f"{label}: FAILED - {exc}")


SSH_BANNER_FILE = pathlib.Path("/etc/issue.net")
SSH_BANNER_DROPIN = pathlib.Path("/etc/ssh/sshd_config.d/99-kudex-banner.conf")
REBOOT_SERVICE = pathlib.Path("/etc/systemd/system/kudex-auto-reboot.service")
REBOOT_TIMER = pathlib.Path("/etc/systemd/system/kudex-auto-reboot.timer")

def banner_menu():
    require_root()
    while True:
        print("\n--- SSH BANNER EDITOR ---")
        try:
            current = SSH_BANNER_FILE.read_text()
        except OSError:
            current = ""
        print("Current banner:")
        print(current.rstrip() if current.strip() else "(empty)")
        print("\n[1] Replace banner text")
        print("[2] Disable Kudex SSH banner")
        print("[0] Back")
        choice = input("Select: ").strip()
        if choice == "0":
            return
        if choice == "1":
            print("Enter banner text. Finish with a line containing only .")
            lines = []
            while True:
                line = input()
                if line == ".":
                    break
                if len(line) > 300:
                    print("Line too long (maximum 300 characters).")
                    continue
                lines.append(line)
                if len(lines) > 30:
                    print("Maximum 30 lines reached.")
                    break
            content = "\n".join(lines).strip() + "\n"
            if not content.strip():
                print("Empty banner rejected.")
                continue
            if not confirm("Save this text to /etc/issue.net and enable it for SSH logins?"):
                continue
            SSH_BANNER_FILE.write_text(content)
            os.chmod(SSH_BANNER_FILE, 0o644)
            SSH_BANNER_DROPIN.parent.mkdir(parents=True, exist_ok=True)
            SSH_BANNER_DROPIN.write_text("Banner /etc/issue.net\n")
            os.chmod(SSH_BANNER_DROPIN, 0o644)
            try:
                run(["sshd", "-t"])
            except RuntimeError:
                SSH_BANNER_DROPIN.unlink(missing_ok=True)
                raise RuntimeError("sshd configuration validation failed; Kudex removed its banner drop-in. Review existing SSH configuration.")
            run(["systemctl", "reload", "ssh.service"], check=False)
            if service_state("ssh.service") == "unknown":
                run(["systemctl", "reload", "sshd.service"], check=False)
            print("SSH login banner saved and SSH configuration validated.")
        elif choice == "2":
            if not SSH_BANNER_DROPIN.exists():
                print("No Kudex-managed SSH banner is enabled.")
                continue
            if confirm("Disable only the Kudex-managed SSH banner?"):
                SSH_BANNER_DROPIN.unlink()
                run(["sshd", "-t"])
                run(["systemctl", "reload", "ssh.service"], check=False)
                if service_state("ssh.service") == "unknown":
                    run(["systemctl", "reload", "sshd.service"], check=False)
                print("Kudex SSH banner disabled. /etc/issue.net was preserved.")
        else:
            print("Invalid selection.")

def install_auto_reboot(hour, minute):
    require_root()
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        raise RuntimeError("Enter a valid 24-hour time.")
    if not confirm(f"Schedule this VPS to reboot every day at {hour:02d}:{minute:02d} server local time? This interrupts all users and tunnels."):
        return False
    REBOOT_SERVICE.write_text("""[Unit]
Description=Kudex scheduled VPS reboot

[Service]
Type=oneshot
ExecStart=/usr/bin/systemctl reboot
""")
    REBOOT_TIMER.write_text(f"""[Unit]
Description=Kudex daily automatic reboot schedule

[Timer]
OnCalendar=*-*-* {hour:02d}:{minute:02d}:00
Persistent=false
Unit=kudex-auto-reboot.service

[Install]
WantedBy=timers.target
""")
    os.chmod(REBOOT_SERVICE, 0o644)
    os.chmod(REBOOT_TIMER, 0o644)
    run(["systemctl", "daemon-reload"])
    run(["systemctl", "enable", "--now", "kudex-auto-reboot.timer"])
    print(f"Daily reboot scheduled for {hour:02d}:{minute:02d} server local time.")
    return True

def auto_reboot_menu():
    require_root()
    while True:
        status = service_state("kudex-auto-reboot.timer")
        print(f"\n--- AUTO-REBOOT SCHEDULER ---\nTimer: {status}")
        if shutil.which("systemctl"):
            run(["systemctl", "list-timers", "kudex-auto-reboot.timer", "--no-pager"], check=False)
        print("[1] Set/replace daily reboot time")
        print("[2] Disable scheduled reboot")
        print("[0] Back")
        choice = input("Select: ").strip()
        if choice == "0":
            return
        if choice == "1":
            raw = ask("Daily time in 24-hour HH:MM format (server local time)", "04:00")
            match = re.fullmatch(r"([01]\d|2[0-3]):([0-5]\d)", raw)
            if not match:
                print("Invalid time. Example: 04:30")
                continue
            install_auto_reboot(int(match.group(1)), int(match.group(2)))
        elif choice == "2":
            if status != "unknown" and confirm("Disable the daily automatic reboot schedule?"):
                run(["systemctl", "disable", "--now", "kudex-auto-reboot.timer"])
                print("Automatic reboot schedule disabled.")
        else:
            print("Invalid selection.")

def managed_service_units():
    candidates = (
        ("OpenSSH", "ssh.service"), ("Nginx", "nginx.service"),
        ("Xray core", "xray.service"), ("Dropbear", "dropbear.service"),
        ("Stunnel4 TLS", "stunnel4.service"), ("SlowDNS / DNSTT", "kudex-dnstt.service"),
        ("OpenVPN", "openvpn.service"), ("OpenVPN server", "openvpn-server@server.service"),
        ("OpenVPN instance", "openvpn@server.service"), ("Kudex OpenVPN", "openvpn-server@kudex.service"), ("Cron", "cron.service"),
        ("HTTP proxy (Squid)", "squid.service"), ("Apache web server", "apache2.service"),
    )
    return [(label, unit) for label, unit in candidates if service_state(unit) != "unknown"]

def expanded_service_menu():
    while True:
        units = managed_service_units()
        print("\n--- SERVICE CONTROL ---")
        for i, (label, unit) in enumerate(units, 1):
            print(f"[{i:02d}] {label:<22} {service_state(unit)} ({unit})")
        print("[0] Back")
        choice = input("Select service: ").strip()
        if choice == "0":
            return
        if not choice.isdigit() or not 1 <= int(choice) <= len(units):
            print("Invalid selection.")
            continue
        label, unit = units[int(choice)-1]
        service_menu(label, unit)


# --- Additional services and cloud backup integrations ---------------------
BADVPN_CONFIG = ETC / "badvpn.json"
BADVPN_UNIT = pathlib.Path("/etc/systemd/system/kudex-badvpn.service")

def badvpn_service_text(binary, bind, port):
    return f"""[Unit]
Description=Kudex BadVPN UDP Gateway
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart={binary} --listen-addr {bind}:{port} --max-clients 256 --max-connections-for-client 10
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
CapabilityBoundingSet=
[Install]
WantedBy=multi-user.target
"""

def badvpn_configure():
    require_root()
    binary = shutil.which("badvpn-udpgw")
    if not binary:
        if not confirm("Install BadVPN from Ubuntu/Debian repositories?"): return
        run(["apt-get", "update"])
        run(["apt-get", "install", "-y", "--no-install-recommends", "badvpn"])
        binary = shutil.which("badvpn-udpgw")
    if not binary: raise RuntimeError("badvpn-udpgw was not provided by the installed package.")
    old = read_json(BADVPN_CONFIG, {"bind": "127.0.0.1", "port": 7300})
    raw = ask("Gateway TCP port (7100-7300)", str(old.get("port", 7300)))
    if not raw.isdigit() or not 7100 <= int(raw) <= 7300: raise RuntimeError("Choose a TCP port from 7100 to 7300.")
    bind = ask("Listen address (127.0.0.1 safest; 0.0.0.0 exposes publicly)", old.get("bind", "127.0.0.1"))
    if bind not in ("127.0.0.1", "0.0.0.0"): raise RuntimeError("Only 127.0.0.1 or 0.0.0.0 is supported.")
    port = int(raw)
    if bind == "0.0.0.0" and not confirm("BadVPN UDPGW has no client authentication. Public exposure can be abused. Continue?"): return
    if service_state("kudex-badvpn.service") != "active":
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            try: probe.bind((bind, port))
            except OSError as exc: raise RuntimeError(f"TCP/{port} is already occupied.") from exc
    atomic_json(BADVPN_CONFIG, {"bind": bind, "port": port})
    BADVPN_UNIT.write_text(badvpn_service_text(binary, bind, port)); os.chmod(BADVPN_UNIT, 0o644)
    run(["systemctl", "daemon-reload"]); run(["systemctl", "enable", "--now", "kudex-badvpn.service"])
    if service_state("kudex-badvpn.service") != "active": raise RuntimeError("BadVPN did not start; inspect journalctl -u kudex-badvpn.")
    print(f"BadVPN UDPGW active on {bind}:TCP/{port}. Provider firewall changes are manual.")

def badvpn_menu():
    while True:
        c = read_json(BADVPN_CONFIG, {})
        print(f"\\n--- BADVPN UDP GATEWAY ---\\nService: {service_state('kudex-badvpn.service')} | {c.get('bind','not configured')}:{c.get('port','—')}")
        print("[1] Install/configure [2] Restart [3] Stop [4] Disable at boot [0] Back")
        x = input("Select: ").strip()
        if x == "0": return
        if x == "1": badvpn_configure()
        elif x == "2":
            if service_state("kudex-badvpn.service") == "unknown": print("Configure BadVPN first.")
            else: run(["systemctl", "restart", "kudex-badvpn.service"])
        elif x == "3":
            if confirm("Stop BadVPN and disconnect clients?"): run(["systemctl", "stop", "kudex-badvpn.service"])
        elif x == "4":
            if confirm("Disable BadVPN at boot?"): run(["systemctl", "disable", "--now", "kudex-badvpn.service"])
        else: print("Invalid selection.")

OPENVPN_EASYRSA = pathlib.Path("/etc/kudex/openvpn-easy-rsa")
OPENVPN_SERVER_DIR = pathlib.Path("/etc/openvpn/server")
OPENVPN_CLIENT_DIR = pathlib.Path("/etc/kudex/openvpn-clients")
OPENVPN_UNIT = "openvpn-server@kudex.service"

def openvpn_easyrsa(*args):
    executable = OPENVPN_EASYRSA / "easyrsa"
    env = os.environ.copy(); env["EASYRSA_BATCH"] = "1"; env["EASYRSA_PKI"] = str(OPENVPN_EASYRSA / "pki")
    proc = subprocess.run([str(executable), *args], cwd=str(OPENVPN_EASYRSA), env=env, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if proc.returncode: raise RuntimeError("Easy-RSA failed: " + proc.stdout[-2500:])
    return proc.stdout

def openvpn_provision():
    require_root()
    if (OPENVPN_SERVER_DIR / "kudex.conf").exists(): raise RuntimeError("Kudex OpenVPN is already provisioned; refusing to overwrite it.")
    if OPENVPN_EASYRSA.exists() and any(OPENVPN_EASYRSA.iterdir()): raise RuntimeError("Existing Easy-RSA data found; refusing to overwrite a CA.")
    if not confirm("Install OpenVPN/Easy-RSA and create a UDP/2200 certificate-authenticated server? No NAT or firewall rules will be changed."): return
    run(["apt-get", "update"]); run(["apt-get", "install", "-y", "--no-install-recommends", "openvpn", "easy-rsa"])
    easyrsa = shutil.which("easyrsa") or "/usr/share/easy-rsa/easyrsa"
    if not pathlib.Path(easyrsa).exists(): raise RuntimeError("Easy-RSA executable not found.")
    OPENVPN_EASYRSA.mkdir(mode=0o700, parents=True, exist_ok=True); shutil.copy2(easyrsa, OPENVPN_EASYRSA / "easyrsa")
    (OPENVPN_EASYRSA / "vars").write_text("set_var EASYRSA_ALGO ec\\nset_var EASYRSA_CURVE prime256v1\\nset_var EASYRSA_DIGEST sha256\\n")
    os.chmod(OPENVPN_EASYRSA / "vars", 0o600)
    openvpn_easyrsa("init-pki"); openvpn_easyrsa("build-ca", "nopass"); openvpn_easyrsa("build-server-full", "server", "nopass")
    pki = OPENVPN_EASYRSA / "pki"
    OPENVPN_SERVER_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    server_dir = OPENVPN_SERVER_DIR / "kudex"; server_dir.mkdir(mode=0o700, exist_ok=True)
    for source, target in ((pki/"ca.crt",server_dir/"ca.crt"),(pki/"issued/server.crt",server_dir/"server.crt"),(pki/"private/server.key",server_dir/"server.key")):
        shutil.copy2(source,target); os.chmod(target,0o600)
    tls = server_dir / "tls-crypt.key"; run(["openvpn","--genkey","secret",str(tls)]); os.chmod(tls,0o600)
    conf = """# Kudex-managed; routed VPN subnet only, no default-route push or NAT.
port 2200
proto udp4
dev tun
topology subnet
server 10.8.0.0 255.255.255.0
ca /etc/openvpn/server/kudex/ca.crt
cert /etc/openvpn/server/kudex/server.crt
key /etc/openvpn/server/kudex/server.key
dh none
ecdh-curve prime256v1
tls-crypt /etc/openvpn/server/kudex/tls-crypt.key
tls-version-min 1.2
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
auth SHA256
keepalive 10 60
persist-key
persist-tun
user nobody
group nogroup
verb 3
"""
    target = OPENVPN_SERVER_DIR / "kudex.conf"; target.write_text(conf); os.chmod(target,0o600)
    run(["systemctl","enable","--now",OPENVPN_UNIT])
    if service_state(OPENVPN_UNIT) != "active": raise RuntimeError("OpenVPN failed to start; inspect journalctl -u openvpn-server@kudex.")
    print("OpenVPN is active on UDP/2200. NAT, forwarding and firewall were intentionally left unchanged.")

def openvpn_create_client():
    require_root()
    if not (OPENVPN_SERVER_DIR/"kudex.conf").exists(): print("Provision OpenVPN first."); return
    name = ask("Client name")
    if not re.fullmatch(r"[A-Za-z0-9_-]{3,32}",name): raise RuntimeError("Use 3-32 letters, digits, '_' or '-'.")
    remote = ask("Public server hostname or IP",state().get("domain") or server_ip())
    try: ipaddress.ip_address(remote); valid = True
    except ValueError: valid = valid_domain(remote)
    if not valid: raise RuntimeError("Enter a valid IP address or hostname.")
    pki=OPENVPN_EASYRSA/"pki"; cert=pki/"issued"/(name+".crt"); key=pki/"private"/(name+".key")
    if cert.exists() or key.exists(): raise RuntimeError("That client already exists.")
    openvpn_easyrsa("build-client-full",name,"nopass")
    profile=f"""client
dev tun
proto udp
remote {remote} 2200
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verify-x509-name server name
auth SHA256
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
verb 3
<ca>
{(pki/'ca.crt').read_text()}</ca>
<cert>
{cert.read_text()}</cert>
<key>
{key.read_text()}</key>
<tls-crypt>
{(OPENVPN_SERVER_DIR/'kudex/tls-crypt.key').read_text()}</tls-crypt>
"""
    OPENVPN_CLIENT_DIR.mkdir(mode=0o700,parents=True,exist_ok=True)
    out=OPENVPN_CLIENT_DIR/(name+".ovpn"); out.write_text(profile); os.chmod(out,0o600)
    print("Client profile created: "+str(out)+". It contains a private key; transfer it securely.")

def openvpn_menu():
    while True:
        print(f"\\n--- OPENVPN PROVISIONING ---\\nServer: {service_state(OPENVPN_UNIT)} | UDP/2200")
        print("[1] Provision server [2] Create client profile [3] List client profiles [4] Restart [5] Stop [0] Back")
        x=input("Select: ").strip()
        if x=="0": return
        if x=="1": openvpn_provision()
        elif x=="2": openvpn_create_client()
        elif x=="3":
            for p in sorted(OPENVPN_CLIENT_DIR.glob("*.ovpn")) if OPENVPN_CLIENT_DIR.exists() else []: print(" - "+p.name)
        elif x=="4":
            if confirm("Restart OpenVPN and disconnect clients?"): run(["systemctl","restart",OPENVPN_UNIT])
        elif x=="5":
            if confirm("Stop OpenVPN?"): run(["systemctl","stop",OPENVPN_UNIT])
        else: print("Invalid selection.")

GOOGLE_DRIVE_CONFIG = ETC / "google-drive.json"

def google_drive_settings():
    data=read_json(GOOGLE_DRIVE_CONFIG,{})
    remote=data.get("remote",""); folder=data.get("folder","KudexBackups")
    if not isinstance(remote,str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}",remote): return None
    if not isinstance(folder,str) or not folder or folder.startswith("/") or ".." in pathlib.PurePosixPath(folder).parts: return None
    return {"remote":remote,"folder":folder}

def google_drive_sync(archive):
    require_root(); source=pathlib.Path(archive)
    if source.parent.resolve()!=BACKUPS.resolve() or not source.is_file() or source.is_symlink(): raise RuntimeError("Only a local regular Kudex archive can be uploaded.")
    if not re.fullmatch(r"kudex-[0-9]{8}-[0-9]{6}\\.tar\\.gz",source.name): raise RuntimeError("Unrecognized backup filename.")
    cfg=google_drive_settings()
    if not cfg: raise RuntimeError("Google Drive is not configured.")
    binary=shutil.which("rclone")
    if not binary: raise RuntimeError("rclone is not installed.")
    target=f"{cfg['remote']}:{cfg['folder'].strip('/')}/{source.name}"
    run([binary,"copyto","--immutable",str(source),target])
    print("Google Drive backup uploaded: "+target)
    return target

def google_drive_menu():
    require_root()
    while True:
        cfg=google_drive_settings()
        print("\\n--- GOOGLE DRIVE BACKUP ---")
        print("Configuration: "+(f"{cfg['remote']}:{cfg['folder']}" if cfg else "NOT CONFIGURED"))
        print("[1] Install rclone / open secure remote setup")
        print("[2] Select existing remote and folder")
        print("[3] Upload latest backup")
        print("[4] Test remote")
        print("[5] Disable automatic copies")
        print("[0] Back")
        x=input("Select: ").strip()
        if x=="0": return
        if x=="1":
            if not shutil.which("rclone"):
                if not confirm("Install rclone from Ubuntu/Debian repositories?"): continue
                run(["apt-get","update"]); run(["apt-get","install","-y","--no-install-recommends","rclone"])
            os.umask(0o077); run(["rclone","config"])
        elif x=="2":
            if not shutil.which("rclone"): print("Install rclone first."); continue
            result=subprocess.run(["rclone","listremotes"],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
            if result.returncode: raise RuntimeError("rclone listremotes failed: "+result.stdout[-1000:])
            remotes=[v.strip().rstrip(":") for v in result.stdout.splitlines() if v.strip()]
            if not remotes: print("No remotes configured. Use option 1."); continue
            print("Available: "+", ".join(remotes)); remote=ask("Remote name",remotes[0])
            if remote not in remotes: print("Choose a listed remote."); continue
            remote_config=subprocess.run(["rclone","config","show",remote],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
            if remote_config.returncode or not re.search(r"(?m)^\s*type\s*=\s*drive\s*$",remote_config.stdout):
                print("That rclone remote is not configured as Google Drive."); continue
            folder=ask("Remote folder path","KudexBackups")
            if not folder or folder.startswith("/") or ".." in pathlib.PurePosixPath(folder).parts: print("Use a relative path without '..'."); continue
            atomic_json(GOOGLE_DRIVE_CONFIG,{"remote":remote,"folder":folder})
        elif x=="3":
            archives=sorted(BACKUPS.glob("kudex-*.tar.gz"),reverse=True)
            if not archives: print("Create a local backup first.")
            else: google_drive_sync(archives[0])
        elif x=="4":
            if not cfg or not shutil.which("rclone"): print("Configure Drive first.")
            else: run(["rclone","lsd",f"{cfg['remote']}:{cfg['folder']}"])
        elif x=="5":
            if GOOGLE_DRIVE_CONFIG.exists() and confirm("Disable automatic Drive copies? Existing cloud backups are preserved."): GOOGLE_DRIVE_CONFIG.unlink()
        else: print("Invalid selection.")

def install_fail2ban_protection():
    require_root()
    if not confirm("Enable Fail2ban SSH protection: ban source IP after 3 failures in 10 minutes for 1 hour? This is not per-account locking."): return
    run(["apt-get","update"]); run(["apt-get","install","-y","--no-install-recommends","fail2ban"])
    ignore=["127.0.0.1/8","::1"]
    peer=os.environ.get("SSH_CONNECTION","").split()
    if peer:
        try: ignore.append(str(ipaddress.ip_address(peer[0])))
        except ValueError: pass
    path=pathlib.Path("/etc/fail2ban/jail.d/kudex-sshd.local"); path.parent.mkdir(parents=True,exist_ok=True)
    if path.exists():
        stamp=datetime.datetime.now().strftime("%Y%m%d-%H%M%S"); shutil.copy2(path,path.with_name(path.name+".backup-"+stamp))
    path.write_text("[sshd]\\nenabled = true\\nbackend = systemd\\nport = ssh\\nmaxretry = 3\\nfindtime = 10m\\nbantime = 1h\\nignoreip = "+" ".join(ignore)+"\\n")
    os.chmod(path,0o644); run(["systemctl","enable","--now","fail2ban.service"]); run(["fail2ban-client","reload"])
    print("Fail2ban SSH jail active: 3 failures / 10 minutes / 1-hour source-IP ban.")
    print("This is brute-force protection, not general DDoS mitigation or account-based three-strike locking.")

def host_protection_menu():
    while True:
        print(f"\\n--- SSH / HOST PROTECTION ---\\nFail2ban: {service_state('fail2ban.service')}")
        print("[1] Enable SSH protection [2] Show SSH jail [3] Remove Kudex jail [0] Back")
        x=input("Select: ").strip()
        if x=="0": return
        if x=="1": install_fail2ban_protection()
        elif x=="2":
            if shutil.which("fail2ban-client"): run(["fail2ban-client","status","sshd"],check=False)
            else: print("Fail2ban is not installed.")
        elif x=="3":
            p=pathlib.Path("/etc/fail2ban/jail.d/kudex-sshd.local")
            if p.exists() and confirm("Remove only Kudex's Fail2ban jail?"): p.unlink(); run(["fail2ban-client","reload"],check=False)
        else: print("Invalid selection.")



def current_login_identity():
    """Return the current loginctl session ID and terminal, when detectable."""
    session_id = os.environ.get("XDG_SESSION_ID", "").strip()
    tty = os.environ.get("SSH_TTY", "").strip()
    if not tty:
        try:
            if sys.stdin.isatty():
                tty = os.ttyname(sys.stdin.fileno())
        except (OSError, ValueError):
            tty = ""
    return session_id, pathlib.Path(tty).name if tty else ""


def loginctl_session(session_id):
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", str(session_id)):
        return None
    proc = subprocess.run(
        ["loginctl", "show-session", str(session_id), "--no-pager"],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False
    )
    if proc.returncode:
        return None
    values = {}
    for line in proc.stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return {
        "id": str(session_id), "uid": values.get("User", ""),
        "user": values.get("Name", ""),
        "tty": pathlib.Path(values.get("TTY", "")).name if values.get("TTY") else "",
        "remote": values.get("Remote", "no").lower() == "yes",
        "remote_host": values.get("RemoteHost", ""), "state": values.get("State", "unknown"),
    }


def list_login_sessions():
    """Return loginctl sessions with identity and remote-session metadata."""
    proc = subprocess.run(
        ["loginctl", "list-sessions", "--no-legend", "--no-pager"],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False
    )
    if proc.returncode:
        raise RuntimeError("systemd-logind session listing is unavailable on this server.")
    rows = []
    for line in proc.stdout.splitlines():
        fields = line.split()
        if fields:
            row = loginctl_session(fields[0])
            if row:
                rows.append(row)
    return rows


def session_termination_allowed(row, current_session_id, current_tty):
    """Never allow terminating root, the current session, or an unverified target."""
    if not current_session_id and not current_tty:
        return False
    if not row or not row.get("id") or row.get("user") in ("", "root"):
        return False
    if row["id"] == current_session_id:
        return False
    if current_tty and row.get("tty") == current_tty:
        return False
    return bool(row.get("remote") or row.get("tty", "").startswith("pts/"))


def terminate_login_session(session_id):
    require_root()
    current_id, current_tty = current_login_identity()
    row = loginctl_session(session_id)
    if not session_termination_allowed(row, current_id, current_tty):
        raise RuntimeError("Session is protected, is not a verified remote login, or the current session could not be identified.")
    run(["loginctl", "terminate-session", str(session_id)])
    print("Session " + str(session_id) + " terminated.")


def session_manager_menu():
    require_root()
    while True:
        current_id, current_tty = current_login_identity()
        try:
            rows = list_login_sessions()
        except RuntimeError as exc:
            print(str(exc))
            return
        print("\\n--- ACTIVE LOGIN SESSIONS ---")
        if not rows:
            print("No login sessions were reported by systemd-logind.")
        for row in rows:
            protected = (row.get("user") == "root" or row.get("id") == current_id
                         or (current_tty and row.get("tty") == current_tty))
            kind = "REMOTE" if row.get("remote") or row.get("tty", "").startswith("pts/") else "LOCAL"
            status = "PROTECTED" if protected else ("TERMINABLE" if session_termination_allowed(row, current_id, current_tty) else "NOT SAFE TO TERMINATE")
            print(f" [{row['id']}] {row.get('user') or 'unknown':<16} {kind:<6} {row.get('remote_host') or row.get('tty') or '—':<24} {status}")
        print("[1] Terminate a remote session [0] Back")
        choice = input("Select: ").strip()
        if choice == "0":
            return
        if choice == "1":
            if not current_id and not current_tty:
                print("Kudex cannot identify this terminal session. Termination is disabled to prevent administrator lockout.")
                continue
            session_id = ask("Session ID")
            row = loginctl_session(session_id)
            if not session_termination_allowed(row, current_id, current_tty):
                print("That session is protected or cannot be safely verified.")
                continue
            if confirm(f"Terminate {row['user']}'s session {session_id} from {row.get('remote_host') or row.get('tty')}?"):
                terminate_login_session(session_id)

def main():
    require_root(); ensure_dirs()
    if len(sys.argv) > 1:
        if sys.argv[1] == "--install-xray": install_xray(force="--yes" in sys.argv); return
        if sys.argv[1] in ("--apply-config", "apply"):
            apply_xray()
            if state().get("domain"): apply_nginx()
            return
        if sys.argv[1] == "update": update_app(); return
        if sys.argv[1] == "upgrade": upgrade_system(); return
        if sys.argv[1] == "--backup-auto": backup(auto_upload=True); return
        if sys.argv[1] == "--expire": expire_due_accounts(); return
    expire_due_accounts()
    while True:
        expire_due_accounts()
        dashboard()
        choice = input("\nSelect menu: ").strip()
        try:
            if choice in ("1","01"): ssh_menu()
            elif choice in ("2","02"): protocol_menu("vmess")
            elif choice in ("3","03"): protocol_menu("vless")
            elif choice in ("4","04"): protocol_menu("trojan")
            elif choice in ("5","05"): protocol_menu("sshws")
            elif choice in ("6","06"): backup_menu()
            elif choice in ("7","07"): domain_ssl_menu()
            elif choice in ("8","08"): diagnostics()
            elif choice in ("9","09"): expanded_service_menu()
            elif choice == "10": install_xray()
            elif choice == "11":
                apply_xray()
                if state().get("domain"): apply_nginx()
            elif choice == "12": restore_backup()
            elif choice == "13": update_app()
            elif choice == "14": upgrade_system()
            elif choice == "15": bandwidth_menu()
            elif choice == "16": restart_services()
            elif choice == "17": ports_info()
            elif choice == "18": optional_services_menu()
            elif choice == "19": ssh_security_menu()
            elif choice == "20": dnstt_menu()
            elif choice == "21": banner_menu()
            elif choice == "22": auto_reboot_menu()
            elif choice == "23": speed_test_menu()
            elif choice == "24": transport_manager_menu()
            elif choice == "25": squid_proxy_menu()
            elif choice == "26": dante_socks_menu()
            elif choice == "27": badvpn_menu()
            elif choice == "28": openvpn_menu()
            elif choice == "29": google_drive_menu()
            elif choice == "30": host_protection_menu()
            elif choice == "31": session_manager_menu()
            elif choice in ("0","00"): print("Kudex session closed."); return
            else: print("Invalid option.")
        except (RuntimeError, OSError, ValueError) as exc: print(f"\n[ERROR] {exc}")
        input("\nPress Enter to return to the main menu...")

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: print("\nCancelled."); sys.exit(130)
