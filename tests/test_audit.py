import json
import tempfile
import unittest
from pathlib import Path

from defensive_mcp_audit.audit import audit_mcp_environment
from defensive_mcp_audit.html_report import generate_html_report
from defensive_mcp_audit.sarif import generate_sarif


FIXTURE = Path(__file__).parent / "fixtures" / "ss_sample.txt"


class AuditTests(unittest.TestCase):
    def test_fixture_audit_scores_mcp_not_samba(self):
        report = audit_mcp_environment(
            ss_output=FIXTURE.read_text(encoding="utf-8"),
            enable_plugins=False,
        )
        self.assertLess(report["risk_score"], 80)
        finding_ids = {finding["id"] for finding in report["findings"]}
        self.assertIn("MCP_EXPOSED_NON_LOCALHOST", finding_ids)
        self.assertIn("SYSTEM_EXPOSED_LISTENER", finding_ids)
        self.assertNotEqual(report["risk_level"], "critical")

    def test_sarif_uses_repo_url(self):
        report = audit_mcp_environment(
            ss_output=FIXTURE.read_text(encoding="utf-8"),
            enable_plugins=False,
        )
        sarif = generate_sarif(report)
        uri = sarif["runs"][0]["tool"]["driver"]["informationUri"]
        self.assertEqual(uri, "https://github.com/Stijnman/defensive-mcp-audit")

    def test_html_report_is_self_contained(self):
        report = audit_mcp_environment(
            ss_output=FIXTURE.read_text(encoding="utf-8"),
            enable_plugins=False,
        )
        html = generate_html_report(report)
        self.assertIn("<style>", html)
        self.assertNotIn("cdn.tailwindcss.com", html)

    def test_mcp_config_parsing(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "mcp.json"
            config.write_text(
                json.dumps(
                    {
                        "mcpServers": {
                            "shell-runner": {
                                "command": "npx",
                                "args": ["-y", "shell-mcp"],
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            report = audit_mcp_environment(
                ss_output=FIXTURE.read_text(encoding="utf-8"),
                enable_plugins=False,
            )
            report["mcp_config_paths"] = [str(config)]
            servers, _ = __import__(
                "defensive_mcp_audit.mcp_config", fromlist=["parse_mcp_configs"]
            ).parse_mcp_configs([config])
            self.assertEqual(len(servers), 1)
            self.assertTrue(servers[0]["risk_notes"])


if __name__ == "__main__":
    unittest.main()