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

if __name__ == "__main__":
    unittest.main()
