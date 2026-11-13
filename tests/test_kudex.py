import importlib.util
import pathlib
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("kudex", ROOT / "lib" / "kudex.py")
kudex = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(kudex)

class KudexValidationTests(unittest.TestCase):
    def test_fail2ban_jail_config_uses_real_newlines(self):
        config = kudex.fail2ban_jail_config(["127.0.0.1/8", "::1", "203.0.113.7"])
        self.assertIn("[sshd]\nenabled = true\nbackend = systemd\n", config)
        self.assertIn("ignoreip = 127.0.0.1/8 ::1 203.0.113.7\n", config)
        self.assertNotIn("\\n", config)

    def test_openvpn_vars_config_uses_real_newlines(self):
        config = kudex.openvpn_vars_config()
        self.assertEqual(config.splitlines(), [
            "set_var EASYRSA_ALGO ec",
            "set_var EASYRSA_CURVE prime256v1",
            "set_var EASYRSA_DIGEST sha256",
        ])
        self.assertNotIn("\\n", config)

    def test_openvpn_unit_discovery_includes_kudex_instance(self):
        completed = mock.Mock(stdout="openvpn-server@kudex.service enabled\n")
        with mock.patch.object(kudex.subprocess, "run", return_value=completed):
            self.assertEqual(kudex.openvpn_units(), ["openvpn-server@kudex.service"])

    def test_squid_proxy_config_requires_authentication_and_denies_others(self):
        config = kudex.squid_proxy_config()
        self.assertIn("http_port 0.0.0.0:8880", config)
        self.assertIn("acl kudex_authenticated proxy_auth REQUIRED", config)
        self.assertIn("http_access allow kudex_authenticated", config)
        self.assertIn("http_access deny all", config)
        self.assertIn("cache deny all", config)

    def test_dante_config_requires_pam_auth_and_does_not_allow_anonymous(self):
        config = kudex.dante_config("eth0")
        self.assertIn("internal: 0.0.0.0 port = 1080", config)
        self.assertIn("external: eth0", config)
        self.assertIn("socksmethod: pam.username", config)
        self.assertIn("pam.servicename: sockd", config)
        self.assertNotIn("socksmethod: none", config)

    def test_dante_pam_restricts_authentication_to_kudex_group(self):
        policy = kudex.dante_pam_config()
        self.assertIn("user ingroup kudex-socks", policy)
        self.assertIn("@include common-auth", policy)
        self.assertIn("@include common-account", policy)

    def test_valid_user_labels(self):
        self.assertTrue(kudex.valid_name("vpn_user-01"))
        self.assertFalse(kudex.valid_name("ab"))
        self.assertFalse(kudex.valid_name("1badname"))
        self.assertFalse(kudex.valid_name("bad name"))

    def test_expiry_status_handles_expired_and_unlimited_accounts(self):
        self.assertEqual(kudex.expiry_status(None), "NO EXPIRY")
        self.assertEqual(kudex.expiry_status("2000-01-01T00:00:00+00:00"), "EXPIRED")

    def test_expiry_from_days_returns_none_for_unlimited(self):
        self.assertIsNone(kudex.expiry_from_days(0))
        value = kudex.expiry_from_days(1)
        self.assertIsNotNone(value)
        self.assertIn("T", value)

    def test_stunnel_config_uses_separate_tls_port_and_local_ssh(self):
        config = kudex.stunnel_config_text("/etc/stunnel/kudex.pem")
        self.assertIn("accept = 0.0.0.0:444", config)
        self.assertIn("connect = 127.0.0.1:22", config)
        self.assertIn("cert = /etc/stunnel/kudex.pem", config)

    def test_ssh_limit_parser_reads_only_valid_maxlogins_rules(self):
        with mock.patch.object(kudex, "SSH_LIMITS", pathlib.Path("/tmp/kudex-test-limits")):
            path = pathlib.Path("/tmp/kudex-test-limits")
            try:
                path.write_text("# comment\nalice hard maxlogins 2\nbob soft maxlogins 3\nroot hard maxlogins 9\n")
                self.assertEqual(kudex.ssh_login_limits(), {"alice": 2})
            finally:
                path.unlink(missing_ok=True)

    def test_ssh_limit_rejects_root_and_out_of_range_values(self):
        with mock.patch.object(kudex, "require_root"):
            with self.assertRaises(RuntimeError):
                kudex.set_ssh_login_limit("root", 1)
            with self.assertRaises(RuntimeError):
                kudex.set_ssh_login_limit("alice", 0)
            with self.assertRaises(RuntimeError):
                kudex.set_ssh_login_limit("alice", 101)

    def test_dnstt_zone_validation(self):
        self.assertTrue(kudex.valid_domain("t.example.com"))
        self.assertFalse(kudex.valid_domain("bad..example.com"))

    def test_valid_domains(self):
        self.assertTrue(kudex.valid_domain("vpn.example.com"))
        self.assertFalse(kudex.valid_domain("localhost"))
        self.assertFalse(kudex.valid_domain("-bad.example.com"))
        self.assertFalse(kudex.valid_domain("bad..example.com"))

    def test_certbot_domain_setup_does_not_require_email(self):
        args = kudex.certbot_issue_args("vpn.example.com", "/var/www/kudex-acme")
        self.assertIn("--register-unsafely-without-email", args)
        self.assertIn("--agree-tos", args)
        self.assertIn("--non-interactive", args)
        self.assertIn("vpn.example.com", args)
        self.assertNotIn("--email", args)

    @mock.patch.object(kudex, "state", return_value={
        "domain": "vpn.example.com",
        "protocols": {"vmess": True, "vless": True, "trojan": True, "sshws": True}
    })
    @mock.patch.object(kudex, "clients", return_value=[])
    def test_config_contains_loopback_only_inbounds(self, _clients, _state):
        config = kudex.build_xray_config()
        self.assertEqual(len(config["inbounds"]), 4)
        self.assertTrue(all(item["listen"] == "127.0.0.1" for item in config["inbounds"]))
        self.assertEqual([item["port"] for item in config["inbounds"]], [10001, 10002, 10003, 10004])
        self.assertEqual(config["inbounds"][3]["protocol"], "dokodemo-door")
        self.assertEqual(config["inbounds"][3]["settings"]["port"], 22)

    @mock.patch.object(kudex, "state", return_value={
        "domain": "vpn.example.com",
        "protocols": {"vmess": True, "vless": True, "trojan": True, "sshws": True},
        "transports": {"vmess": {"httpupgrade": True}, "vless": {"httpupgrade": False},
                       "trojan": {"httpupgrade": True}}
    })
    @mock.patch.object(kudex, "clients", return_value=[])
    @mock.patch.object(kudex, "reality_profile", return_value={
        "enabled": True, "target": "www.example.com:443", "server_name": "www.example.com",
        "private_key": "private", "public_key": "public", "short_id": "a1b2c3d4"
    })
    def test_build_config_adds_enabled_httpupgrade_and_reality_inbounds(self, _profile, _clients, _state):
        config = kudex.build_xray_config()
        tags = {item["tag"]: item for item in config["inbounds"]}
        self.assertIn("vmess-httpupgrade", tags)
        self.assertNotIn("vless-httpupgrade", tags)
        self.assertIn("trojan-httpupgrade", tags)
        self.assertIn("vless-reality", tags)
        self.assertEqual(tags["vless-reality"]["port"], 8443)

    def test_httpupgrade_inbound_has_separate_loopback_listener(self):
        with mock.patch.object(kudex, "state", return_value={"domain": "vpn.example.com"}):
            inbound = kudex.inbound("vless", [], "httpupgrade")
        self.assertEqual(inbound["port"], 10006)
        self.assertEqual(inbound["listen"], "127.0.0.1")
        self.assertEqual(inbound["streamSettings"]["network"], "httpupgrade")
        self.assertEqual(inbound["streamSettings"]["httpupgradeSettings"]["path"], "/vless-hu")

    def test_reality_inbound_uses_vision_and_server_private_key(self):
        profile = {"enabled": True, "target": "www.example.com:443",
                   "server_name": "www.example.com", "private_key": "private",
                   "public_key": "public", "short_id": "a1b2c3d4"}
        clients = [{"name": "alice", "secret": "00000000-0000-4000-8000-000000000000",
                    "protocol": "vless", "enabled": True}]
        inbound = kudex.reality_inbound(clients, profile)
        self.assertEqual(inbound["port"], kudex.REALITY_PORT)
        self.assertEqual(inbound["listen"], "0.0.0.0")
        self.assertEqual(inbound["streamSettings"]["security"], "reality")
        self.assertEqual(inbound["streamSettings"]["realitySettings"]["privateKey"], "private")
        self.assertEqual(inbound["settings"]["clients"][0]["flow"], "xtls-rprx-vision")

    @mock.patch.object(kudex, "state", return_value={
        "domain": "vpn.example.com", "tls": True,
        "transports": {"vless": {"httpupgrade": True}}
    })
    def test_httpupgrade_vless_share_link_uses_httpupgrade_transport(self, _state):
        client = {"name": "alice", "secret": "00000000-0000-4000-8000-000000000000",
                  "protocol": "vless"}
        link = kudex.share_link(client, "httpupgrade")
        self.assertIn("vless://", link)
        self.assertIn("type=httpupgrade", link)
        self.assertIn("vless-hu", link)

    @mock.patch.object(kudex, "state", return_value={"domain": "vpn.example.com"})
    @mock.patch.object(kudex, "reality_profile", return_value={
        "enabled": True, "server_name": "www.example.com", "public_key": "public-key",
        "short_id": "a1b2c3d4"
    })
    def test_reality_vless_share_link_contains_client_parameters(self, _profile, _state):
        client = {"name": "alice", "secret": "00000000-0000-4000-8000-000000000000",
                  "protocol": "vless"}
        link = kudex.share_link(client, "reality")
        self.assertIn(":8443?", link)
        self.assertIn("security=reality", link)
        self.assertIn("flow=xtls-rprx-vision", link)
        self.assertIn("pbk=public-key", link)
        self.assertIn("sid=a1b2c3d4", link)

    @mock.patch.object(kudex, "read_json", return_value={"keep_last": 12})
    def test_backup_retention_policy_reads_valid_count(self, _read):
        self.assertEqual(kudex.backup_retention_count(), 12)

    @mock.patch.object(kudex, "read_json", return_value={"keep_last": 2})
    def test_backup_retention_policy_rejects_unsafe_count(self, _read):
        self.assertEqual(kudex.backup_retention_count(), 0)

    def test_backup_pruning_keeps_newest_archives_and_ignores_unmanaged_files(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            names = [f"kudex-202611{day:02d}-120000.tar.gz" for day in range(1, 7)]
            for name in names:
                (root / name).write_bytes(b"backup")
            (root / "notes.txt").write_text("keep")
            with mock.patch.object(kudex, "BACKUPS", root), mock.patch.object(kudex, "require_root"):
                removed = kudex.prune_old_backups(5, silent=True)
            self.assertEqual(removed, 1)
            self.assertFalse((root / names[0]).exists())
            self.assertTrue((root / names[-1]).exists())
            self.assertTrue((root / "notes.txt").exists())

    def test_badvpn_unit_is_restricted_and_uses_validated_port(self):
        text = kudex.badvpn_service_text("/usr/bin/badvpn-udpgw", "127.0.0.1", 7300)
        self.assertIn("--listen-addr 127.0.0.1:7300", text)
        self.assertNotIn("--listen-port", text)
        self.assertIn("--max-clients 256", text)
        self.assertIn("NoNewPrivileges=true", text)

    def test_google_drive_settings_reject_path_traversal(self):
        with mock.patch.object(kudex, "read_json", return_value={"remote": "drive", "folder": "../escape"}):
            self.assertIsNone(kudex.google_drive_settings())

    def test_google_drive_settings_accept_relative_folder(self):
        with mock.patch.object(kudex, "read_json", return_value={"remote": "gdrive", "folder": "KudexBackups"}):
            self.assertEqual(kudex.google_drive_settings(), {"remote": "gdrive", "folder": "KudexBackups"})

    def test_openvpn_profile_templates_avoid_default_route_push(self):
        # The generated server template is intentionally a routed subnet only.
        import inspect
        source = inspect.getsource(kudex.openvpn_provision)
        self.assertIn("server 10.8.0.0 255.255.255.0", source)
        self.assertNotIn("push \"redirect-gateway", source)
        self.assertIn("tls-crypt", source)

    def test_google_drive_remote_must_be_drive_type(self):
        import inspect
        # The remote type check is kept in the menu flow; the stored settings
        # remain provider-neutral so the token is never copied into Kudex state.
        self.assertIn('["rclone","config","show",remote]', inspect.getsource(kudex.google_drive_menu))



class KudexPointedDomainTests(unittest.TestCase):
    def test_pointed_domain_and_nameserver_are_normalized(self):
        self.assertEqual(
            kudex.validate_pointed_domain("VPN.Example.COM.", "NS.VPN.Example.COM."),
            ("vpn.example.com", "ns.vpn.example.com")
        )

    def test_invalid_pointed_domain_is_rejected(self):
        with self.assertRaises(RuntimeError):
            kudex.validate_pointed_domain("not-a-domain", "ns.example.com")

    def test_invalid_nameserver_is_rejected(self):
        with self.assertRaises(RuntimeError):
            kudex.validate_pointed_domain("vpn.example.com", "invalid")



class KudexDomainCompositionTests(unittest.TestCase):
    def test_main_domain_without_subdomain_is_preserved(self):
        self.assertEqual(kudex.compose_domain("Example.COM", ""), "example.com")

    def test_subdomain_is_combined_with_main_domain(self):
        self.assertEqual(kudex.compose_domain("example.com", "VPN"), "vpn.example.com")

    def test_nested_subdomain_is_supported(self):
        self.assertEqual(kudex.compose_domain("example.com", "node.eu"), "node.eu.example.com")

    def test_invalid_subdomain_is_rejected(self):
        with self.assertRaises(RuntimeError):
            kudex.compose_domain("example.com", "-vpn")

    def test_invalid_main_domain_is_rejected(self):
        with self.assertRaises(RuntimeError):
            kudex.compose_domain("example", "vpn")


class KudexSessionSafetyTests(unittest.TestCase):
    def test_current_session_is_never_terminable(self):
        row = {"id": "7", "user": "alice", "tty": "pts/2", "remote": True}
        self.assertFalse(kudex.session_termination_allowed(row, "7", "pts/2"))

    def test_root_session_is_never_terminable(self):
        row = {"id": "8", "user": "root", "tty": "pts/3", "remote": True}
        self.assertFalse(kudex.session_termination_allowed(row, "7", "pts/2"))

    def test_uid_zero_is_protected_even_if_name_is_unexpected(self):
        row = {"id": "8", "uid": "0", "user": "admin-root-alias", "tty": "pts/3", "remote": True}
        self.assertFalse(kudex.session_termination_allowed(row, "7", "pts/2"))

    def test_pty_without_remote_flag_is_not_terminable(self):
        row = {"id": "8", "uid": "1001", "user": "alice", "tty": "pts/3", "remote": False}
        self.assertFalse(kudex.session_termination_allowed(row, "7", "pts/2"))

    def test_same_terminal_is_protected_even_with_different_session_id(self):
        row = {"id": "8", "user": "alice", "tty": "pts/2", "remote": True}
        self.assertFalse(kudex.session_termination_allowed(row, "7", "pts/2"))

    def test_unverified_session_is_not_terminable_when_current_terminal_unknown(self):
        row = {"id": "8", "user": "alice", "tty": "pts/3", "remote": True}
        self.assertFalse(kudex.session_termination_allowed(row, "", ""))

    def test_non_remote_ttyless_session_is_not_terminable(self):
        row = {"id": "8", "user": "alice", "tty": "", "remote": False}
        self.assertFalse(kudex.session_termination_allowed(row, "7", "pts/2"))

    def test_other_verified_remote_session_can_be_terminated(self):
        row = {"id": "8", "user": "alice", "tty": "pts/3", "remote": True}
        self.assertTrue(kudex.session_termination_allowed(row, "7", "pts/2"))



class KudexConnectionGuardTests(unittest.TestCase):
    def test_guard_exempts_private_and_loopback_addresses(self):
        self.assertTrue(kudex.guard_ip_exempt("10.1.2.3", []))
        self.assertTrue(kudex.guard_ip_exempt("127.0.0.1", []))
        self.assertTrue(kudex.guard_ip_exempt("::1", []))

    def test_guard_exempts_explicit_admin_network(self):
        self.assertTrue(kudex.guard_ip_exempt("203.0.113.7", ["203.0.113.0/24"]))

    def test_guard_does_not_exempt_unlisted_public_address(self):
        self.assertFalse(kudex.guard_ip_exempt("8.8.8.8", []))

    def test_ss_peer_parser_handles_ipv4_and_ipv6(self):
        self.assertEqual(kudex.parse_ss_peer_address("198.51.100.4:54321"), "198.51.100.4")
        self.assertEqual(kudex.parse_ss_peer_address("[2001:4860:4860::8888]:443"), "2001:4860:4860::8888")
        self.assertIsNone(kudex.parse_ss_peer_address("invalid"))

    def test_guard_settings_validate_threshold_and_allowlist(self):
        with mock.patch.object(kudex, "read_json", return_value={"threshold": 150, "ban_minutes": 10, "allowlist": ["203.0.113.5/32"]}):
            self.assertEqual(kudex.ddos_guard_settings()["threshold"], 150)
        with mock.patch.object(kudex, "read_json", return_value={"threshold": 5, "ban_minutes": 10, "allowlist": []}):
            self.assertIsNone(kudex.ddos_guard_settings())

    def test_guard_settings_reject_invalid_allowlist(self):
        with mock.patch.object(kudex, "read_json", return_value={"threshold": 150, "ban_minutes": 10, "allowlist": ["not-an-ip"]}):
            self.assertIsNone(kudex.ddos_guard_settings())

if __name__ == "__main__":
    unittest.main()
