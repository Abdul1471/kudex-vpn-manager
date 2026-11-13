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
        return "vmess://" + base64.b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode().rstrip("=")
    query_values = {"type": "ws", "security": "tls", "path": path, "host": host, "sni": host}
    if client["protocol"] == "vless": query_values["encryption"] = "none"
    query = urllib.parse.urlencode(query_values)
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

def main():
    require_root(); ensure_dirs()
    if len(sys.argv) > 1:
        if sys.argv[1] == "--install-xray":
            install_xray(force="--yes" in sys.argv); return
        if sys.argv[1] == "--apply-config" or sys.argv[1] == "apply":
            apply_xray()
            if state().get("domain"): apply_nginx()
            return
        if sys.argv[1] == "update":
            update_app(); return
        if sys.argv[1] == "upgrade":
            upgrade_system(); return
    while True:
        st = state()
        print("\n" + "=" * 46 + "\n           KUDEX VPN MANAGER\n" + "=" * 46)
        for label, unit in (("SSH", "ssh.service"), ("NGINX", "nginx.service"), ("XRAY", "xray.service"), ("DROPBEAR", "dropbear.service")):
            print(f"{label:<12}: {service_state(unit).upper()}")
        ws_enabled = st.get("protocols", {}).get("sshws", True)
        ws_status = "OFF" if not ws_enabled else ("ON" if service_state("xray.service") == "active" and st.get("tls") else "WAITING FOR TLS")
        print(f"{'SSH-WS':<12}: {ws_status}")
        print("\n[01] SSH [Menu]\n[02] VMESS [Menu]\n[03] VLESS [Menu]\n[04] TROJAN [Menu]\n[05] SSH-WEBSOCKET [Menu]")
        print("[06] BACKUP  [07] DOMAIN & SSL  [08] CHECK RUNNING  [12] RESTORE BACKUP")
        print("[09] SERVICE CONTROL  [10] INSTALL/UPDATE XRAY  [11] APPLY CONFIG")
        print("[13] UPDATE KUDEX APPLICATION  [14] UPGRADE UBUNTU/DEBIAN PACKAGES")
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
            elif choice == "12": restore_backup()
            elif choice == "13": update_app()
            elif choice == "14": upgrade_system()
            elif choice in ("0", "00"): print("Kudex session closed."); return
            else: print("Invalid option.")
        except (RuntimeError, OSError, ValueError) as exc:
            print(f"\n[ERROR] {exc}")
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: print("\nCancelled."); sys.exit(130)
