#!/usr/bin/env python3
"""Kudex VPN Manager: terminal-first SSH and Xray administration."""
from __future__ import annotations
import base64, datetime, getpass, ipaddress, json, os, pathlib, platform, re, secrets, shutil, socket, string, subprocess, sys, tarfile, tempfile, urllib.parse, urllib.request, hashlib, time

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

def inbound(protocol, entries):
    port = PORTS[protocol]
    path = PATHS[protocol]
    clients_cfg = []
    if protocol == "vmess":
        clients_cfg = [{"id": c["secret"], "alterId": 0, "email": c["name"], "security": "auto"} for c in entries]
        settings = {"clients": clients_cfg, "disableInsecureEncryption": False}
    elif protocol == "vless":
        clients_cfg = [{"id": c["secret"], "email": c["name"]} for c in entries]
        settings = {"clients": clients_cfg, "decryption": "none"}
    elif protocol == "trojan":
        clients_cfg = [{"password": c["secret"], "email": c["name"]} for c in entries]
        settings = {"clients": clients_cfg}
    else:
        settings = {"address": "127.0.0.1", "port": 22, "network": "tcp"}
    return {"tag": protocol, "listen": "127.0.0.1", "port": port,
            "protocol": "dokodemo-door" if protocol == "sshws" else protocol,
            "settings": settings,
            "streamSettings": {"network": "ws", "security": "none",
                               "wsSettings": {"path": path, "headers": {"Host": state().get("domain", "")}}}}

def build_xray_config():
    st = state()
    all_clients = clients()
    ins = []
    for proto in ("vmess", "vless", "trojan"):
        if st.get("protocols", {}).get(proto, True):
            ins.append(inbound(proto, [c for c in all_clients if c["protocol"] == proto and c.get("enabled", True)]))
    if st.get("protocols", {}).get("sshws", True):
        ins.append(inbound("sshws", []))
    return {"log": {"loglevel": "warning"},
            "inbounds": ins,
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
    hook.write_text("#!/bin/sh\nsystemctl reload nginx.service\n")
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
        atomic_json(CLIENTS, data)
        if xray_binary():
            apply_xray()
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
        print("[4] Show share links  [5] Renew account  [0] Back")
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
            print(f"Account created ({'unlimited' if days == 0 else str(days) + ' day(s)'}). Share link:")
            print(share_link(item))
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
                    print(f"\n{item['name']} ({expiry_status(item.get('expires_at'))})\n{share_link(item)}")
        elif choice == "5":
            renew_client(proto)
        else:
            print("Invalid selection.")

def share_link(client):
    st = state(); host = st.get("domain") or "YOUR_DOMAIN"
    if not st.get("tls") or host == "YOUR_DOMAIN":
        return "TLS/domain not configured. Configure DOMAIN & SSL before sharing a connection URI."
    name = client["name"]; secret = client["secret"]; path = PATHS[client["protocol"]]
    if client["protocol"] == "vmess":
        obj = {"v": "2", "ps": name, "add": host, "port": "443", "id": secret,
               "aid": "0", "scy": "auto", "net": "ws", "type": "none",
               "host": host, "path": path, "tls": "tls", "sni": host}
        return "vmess://" + base64.b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode().rstrip("=")
    query_values = {"type": "ws", "security": "tls", "path": path, "host": host, "sni": host}
    if client["protocol"] == "vless": query_values["encryption"] = "none"
    query = urllib.parse.urlencode(query_values)
    if client["protocol"] == "vless":
        return f"vless://{secret}@{host}:443?{query}#{urllib.parse.quote(name)}"
    return f"trojan://{secret}@{host}:443?{query}#{urllib.parse.quote(name)}"

def ssh_menu():
    while True:
        expire_due_accounts()
        print("\n--- SSH ACCOUNTS ---")
        print("[1] Create timed/trial user  [2] List users  [3] Lock user")
        print("[4] Unlock user  [5] Delete user  [6] Renew account  [0] Back")
        c = input("Select: ").strip()
        if c == "0":
            return
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
                    expiry_date = datetime.datetime.fromisoformat(expiry).date().isoformat()
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
                run(["chage", "-E", datetime.datetime.fromisoformat(expiry).date().isoformat(), name] if expiry
                    else ["chage", "-E", "-1", name])
                details = managed.setdefault(name, {})
                details.update({"expires_at": expiry, "locked": False})
                atomic_json(SSH_ACCOUNTS, managed)
                run(["usermod", "--unlock", name])
                print(f"{name} renewed: {'unlimited' if days == 0 else str(days) + ' day(s)'}.")
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

def backup():
    ensure_dirs()
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    target = BACKUPS / f"kudex-{stamp}.tar.gz"
    items = [p for p in (ETC, XRAY_CONFIG, NGINX_SITE) if p.exists()]
    with tarfile.open(target, "w:gz") as tf:
        for p in items: tf.add(p, arcname=str(p).lstrip("/"))
    os.chmod(target, 0o600)
    print(f"Backup created: {target}")

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
               "usr/local/etc/xray/config.json", "etc/nginx/sites-available/kudex.conf"}
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
        "usr/local/etc/xray/config.json": XRAY_CONFIG, "etc/nginx/sites-available/kudex.conf": NGINX_SITE
    }
    previous = {name: (path.read_bytes() if path.exists() else None) for name, path in targets.items() if name in staged}
    try:
        for name, content in staged.items():
            path = targets[name]; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content); os.chmod(path, 0o600 if name.startswith(("etc/kudex", "usr/local/etc/xray")) else 0o644)
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
              ("XRAY", ("xray.service",)), ("DROPBEAR", ("dropbear.service",)))
    result = {}
    for label, units in checks:
        states = [service_state(u) for u in units]
        result[label] = "RUNNING" if "active" in states else ("NOT INSTALLED" if all(x == "unknown" for x in states) else "STOPPED")
    st = state()
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
    print(" [17] Ports & Server Info")
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
    for proto in ("vmess", "vless", "trojan", "sshws"):
        print(f"{PROTO_NAMES[proto]:<14}: 127.0.0.1:{PORTS[proto]} {PATHS[proto]}")
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
            elif choice in ("6","06"): backup()
            elif choice in ("7","07"): configure_domain()
            elif choice in ("8","08"): diagnostics()
            elif choice in ("9","09"):
                units = (("SSH","ssh.service"),("NGINX","nginx.service"),("XRAY","xray.service"),("DROPBEAR","dropbear.service"))
                for label, unit in units: print(f"[{label}] {service_state(unit)}")
                unit = ask("Service unit (ssh.service/nginx.service/xray.service/dropbear.service)")
                if unit in {u for _,u in units}: service_menu(unit, unit)
                else: print("Unsupported service.")
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
            elif choice in ("0","00"): print("Kudex session closed."); return
            else: print("Invalid option.")
        except (RuntimeError, OSError, ValueError) as exc: print(f"\n[ERROR] {exc}")
        input("\nPress Enter to return to the main menu...")

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: print("\nCancelled."); sys.exit(130)
