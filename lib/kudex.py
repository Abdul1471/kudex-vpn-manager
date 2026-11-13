#!/usr/bin/env python3
"""Kudex VPN Manager: terminal-first SSH and Xray administration."""
from __future__ import annotations
import base64, datetime, getpass, ipaddress, json, os, pathlib, platform, re, secrets, shutil, socket, string, subprocess, sys, tarfile, tempfile, urllib.parse, urllib.request, hashlib

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
    if len(domain) > 253 or "." not in domain:
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

def install_xray():
    require_root()
    machine = platform.machine().lower()
    asset = {"x86_64": "Xray-linux-64.zip", "amd64": "Xray-linux-64.zip",
             "aarch64": "Xray-linux-arm64-v8a.zip", "arm64": "Xray-linux-arm64-v8a.zip",
             "armv7l": "Xray-linux-arm32-v7a.zip"}.get(machine)
    if not asset:
        raise RuntimeError(f"Unsupported CPU architecture: {machine}")
    if not confirm(f"Download official Xray-core v{XRAY_VERSION} for {machine} from XTLS/Xray-core?"):
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
            "outbounds": [{"protocol": "freedom", "tag": "direct"},
                          {"protocol": "blackhole", "tag": "blocked"}],
            "routing": {"rules": [{"type": "field", "ip": ["geoip:private"], "outboundTag": "blocked"}]}}

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
        if XRAY_CONFIG.exists():
            backup = XRAY_CONFIG.with_suffix(".json.kudex-backup")
            shutil.copy2(XRAY_CONFIG, backup)
        os.replace(temp, XRAY_CONFIG)
        os.chmod(XRAY_CONFIG, 0o600)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
    run(["systemctl", "restart", "xray.service"])
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
    email = ask("Email address for Let's Encrypt notices", st.get("email", ""))
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise RuntimeError("A valid email address is required.")
    st.update({"domain": domain, "email": email, "tls": False})
    atomic_json(STATE, st)
    apply_nginx()
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
    print("TLS certificate issued. Certbot renewal timer should manage renewals.")

def protocol_menu(proto):
    while True:
        print(f"\n--- {PROTO_NAMES[proto]} ---")
        rows = [c for c in clients() if c["protocol"] == proto]
        for c in rows:
            print(f" {c['name']:<20} {'enabled' if c.get('enabled', True) else 'disabled'}")
        print("[1] Create account  [2] Delete account  [3] Enable/disable account  [4] Show share links  [0] Back")
        choice = input("Select: ").strip()
        if choice == "0": return
        if choice == "1":
            name = ask("Account label")
            if not valid_name(name):
                print("Use 3-32 letters/numbers/._-; begin with a letter."); continue
            if any(c["name"] == name and c["protocol"] == proto for c in clients()):
                print("That label already exists for this protocol."); continue
            secret = uuid4() if proto in ("vmess", "vless") else random_secret(36)
            data = clients()
            data.append({"name": name, "protocol": proto, "secret": secret, "enabled": True,
                         "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat()})
            atomic_json(CLIENTS, data)
            try:
                apply_xray()
            except Exception:
                atomic_json(CLIENTS, [c for c in data if not (c["name"] == name and c["protocol"] == proto)])
                raise
            print("Account created. Share link:")
            print(share_link(data[-1]))
        elif choice == "2":
            name = ask("Account label to delete")
            data = clients()
            new = [c for c in data if not (c["protocol"] == proto and c["name"] == name)]
            if len(new) == len(data): print("Account not found."); continue
            if not confirm(f"Delete {name} permanently?"): continue
            atomic_json(CLIENTS, new); apply_xray(); print("Account deleted.")
        elif choice == "3":
            name = ask("Account label")
            data = clients(); found = next((c for c in data if c["protocol"] == proto and c["name"] == name), None)
            if not found: print("Account not found."); continue
            found["enabled"] = not found.get("enabled", True)
            atomic_json(CLIENTS, data); apply_xray()
            print(f"Account {'enabled' if found['enabled'] else 'disabled'}.")
        elif choice == "4":
            for c in rows: print(f"\n{c['name']}\n{share_link(c)}")
        else: print("Invalid selection.")

def share_link(client):
    st = state(); host = st.get("domain") or "YOUR_DOMAIN"
    if not st.get("tls") or host == "YOUR_DOMAIN":
        return "TLS/domain not configured. Configure DOMAIN & SSL before sharing a connection URI."
    name = client["name"]; secret = client["secret"]; path = PATHS[client["protocol"]]
    if client["protocol"] == "vmess":
        obj = {"v": "2", "ps": name, "add": host, "port": "443", "id": secret,
               "aid": "0", "scy": "auto", "net": "ws", "type": "none",
               "host": host, "path": path, "tls": "tls", "sni": host}
        return "vmess://" + base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode().rstrip("=")
    query = urllib.parse.urlencode({"type": "ws", "security": "tls", "path": path, "host": host, "sni": host})
    if client["protocol"] == "vless":
        return f"vless://{secret}@{host}:443?{query}#{urllib.parse.quote(name)}"
    return f"trojan://{secret}@{host}:443?{query}#{urllib.parse.quote(name)}"

def ssh_menu():
    while True:
        print("\n--- SSH ACCOUNTS ---\n[1] Create user  [2] List users  [3] Lock user  [4] Unlock user  [5] Delete user  [0] Back")
        c = input("Select: ").strip()
        if c == "0": return
        if c == "1":
            name = ask("Username")
            if not valid_name(name): print("Invalid username."); continue
            if name in ("root", "daemon", "nobody") or name.isdigit(): print("Reserved username."); continue
            if subprocess.run(["id", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                print("User already exists."); continue
            password = getpass.getpass("Temporary password (min 14 chars): ")
            if len(password) < 14: print("Password too short."); continue
            run(["useradd", "--create-home", "--shell", "/bin/bash", name])
            run(["chpasswd"], input_text=f"{name}:{password}\n")
            print(f"Created {name}; require the user to change this temporary password.")
        elif c == "2":
            run(["bash", "-lc", "getent passwd | awk -F: '$7 ~ /(bash|sh|zsh)$/ {printf \"%-24s %s\\n\",$1,$6}'"])
        elif c in ("3", "4", "5"):
            name = ask("Username")
            if name == "root" or subprocess.run(["id", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
                print("User not found or protected."); continue
            if c == "3": run(["passwd", "-l", name])
            elif c == "4": run(["passwd", "-u", name])
            elif confirm(f"Delete {name} and its home directory?"):
                run(["userdel", "--remove", name])
        else: print("Invalid selection.")

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

def main():
    require_root(); ensure_dirs()
    while True:
        st = state()
        print("\n" + "=" * 46 + "\n           KUDEX VPN MANAGER\n" + "=" * 46)
        for label, unit in (("SSH", "ssh.service"), ("NGINX", "nginx.service"), ("XRAY", "xray.service"), ("DROPBEAR", "dropbear.service")):
            print(f"{label:<12}: {service_state(unit).upper()}")
        print(f"{'SSH-WS':<12}: {'READY' if st.get('protocols',{}).get('sshws') and xray_binary() else 'NOT CONFIGURED'}")
        print("\n[01] SSH [Menu]\n[02] VMESS [Menu]\n[03] VLESS [Menu]\n[04] TROJAN [Menu]\n[05] SSH-WEBSOCKET [Menu]")
        print("[06] BACKUP  [07] DOMAIN & SSL  [08] CHECK RUNNING")
        print("[09] SERVICE CONTROL  [10] INSTALL/UPDATE XRAY  [11] APPLY CONFIG")
        print("[00] EXIT SYSTEM")
        choice = input("\nSelect option: ").strip()
        try:
            if choice in ("1", "01"): ssh_menu()
            elif choice in ("2", "02"): protocol_menu("vmess")
            elif choice in ("3", "03"): protocol_menu("vless")
            elif choice in ("4", "04"): protocol_menu("trojan")
            elif choice in ("5", "05"): protocol_menu("sshws")
            elif choice in ("6", "06"): backup()
            elif choice in ("7", "07"): configure_domain()
            elif choice in ("8", "08"): diagnostics()
            elif choice == "9":
                for label, unit in (("SSH", "ssh.service"), ("NGINX", "nginx.service"), ("XRAY", "xray.service"), ("DROPBEAR", "dropbear.service")):
                    print(f"[{label}] {unit}")
                unit = ask("Enter service unit (ssh.service/nginx.service/xray.service/dropbear.service)")
                if unit in ("ssh.service", "nginx.service", "xray.service", "dropbear.service"): service_menu(unit, unit)
                else: print("Unsupported service.")
            elif choice == "10": install_xray()
            elif choice == "11": apply_xray(); apply_nginx() if state().get("domain") else None
            elif choice in ("0", "00"): print("Kudex session closed."); return
            else: print("Invalid option.")
        except (RuntimeError, OSError, ValueError) as exc:
            print(f"\n[ERROR] {exc}")
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: print("\nCancelled."); sys.exit(130)
