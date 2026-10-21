import json
import tempfile
import unittest
from pathlib import Path

from defensive_mcp_audit.mcp_config import parse_mcp_configs


class ConfigAuthHintTests(unittest.TestCase):
    def parse_server(self, server, name="server"):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "mcp.json"
            config.write_text(
                json.dumps({"mcpServers": {name: server}}), encoding="utf-8"
            )
            servers, _ = parse_mcp_configs([config])
            return servers[0]

    def test_stdio_does_not_require_http_endpoint_auth_hints(self):
        server = self.parse_server({"command": "local-mcp-server"})

        self.assertEqual(server["transport"], "stdio")
        self.assertFalse(server["has_auth_hints"])
        self.assertEqual(server["risk_notes"], [])

    def test_https_without_static_auth_hint_is_not_assumed_unauthenticated(self):
        server = self.parse_server({"url": "https://mcp.example.test/mcp"})

        self.assertFalse(server["has_auth_hints"])
        self.assertEqual(server["risk_notes"], [])

    def test_non_loopback_http_is_flagged_even_with_an_auth_hint(self):
        server = self.parse_server(
            {
                "url": "http://mcp.example.test/mcp",
                "headers": {"Authorization": "synthetic-secret-value"},
            }
        )

        self.assertTrue(server["has_auth_hints"])
        self.assertEqual(
            server["risk_notes"],
            ["non-loopback HTTP endpoint uses cleartext — review transport protection"],
        )
        self.assertNotIn("synthetic-secret-value", json.dumps(server))

    def test_loopback_http_is_not_mistaken_for_remote_cleartext(self):
        for url in (
            "http://localhost:8080/mcp",
            "http://127.0.0.1:8080/mcp",
            "http://[::1]:8080/mcp",
        ):
            with self.subTest(url=url):
                server = self.parse_server({"url": url})
                self.assertEqual(server["risk_notes"], [])

    def test_empty_authorization_header_is_not_an_auth_hint(self):
        server = self.parse_server(
            {"url": "https://mcp.example.test/mcp", "headers": {"Authorization": "  "}}
        )

        self.assertFalse(server["has_auth_hints"])
        self.assertEqual(server["risk_notes"], [])

    def test_nonempty_env_value_is_only_a_hint_and_does_not_mask_http_risk(self):
        server = self.parse_server(
            {
                "url": "http://mcp.example.test/mcp",
                "env": {"MCP_API_TOKEN": "synthetic-env-secret"},
            }
        )

        self.assertTrue(server["has_auth_hints"])
        self.assertTrue(server["risk_notes"])
        self.assertNotIn("synthetic-env-secret", json.dumps(server))

    def test_malformed_json_and_url_do_not_abort_config_parsing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            malformed_json = root / "malformed.json"
            malformed_json.write_text("{", encoding="utf-8")
            config = root / "servers.json"
            config.write_text(
                json.dumps(
                    {
                        "mcpServers": {
                            "malformed-url": {"url": "http://[invalid"},
                            "stdio": {"command": "local-mcp-server"},
                        }
                    }
                ),
                encoding="utf-8",
            )

            servers, _ = parse_mcp_configs([malformed_json, config])

        self.assertEqual([server["name"] for server in servers], ["malformed-url", "stdio"])
        self.assertEqual(servers[0]["risk_notes"], [])
        self.assertEqual(servers[1]["risk_notes"], [])


if __name__ == "__main__":
    unittest.main()
