import importlib.util
import pathlib
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("kudex", ROOT / "lib" / "kudex.py")
kudex = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(kudex)

class KudexValidationTests(unittest.TestCase):
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

if __name__ == "__main__":
    unittest.main()
