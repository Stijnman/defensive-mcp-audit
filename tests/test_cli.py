"""CLI regressions that never inspect the host environment."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from defensive_mcp_audit import cli

REPORT = {
    "timestamp": "2026-01-01T00:00:00Z", "risk_level": "low", "risk_score": 0,
    "findings": [], "recommendations": [], "version": "0.3.2",
}


class CliTests(unittest.TestCase):
    def invoke(self, args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(cli, "audit_mcp_environment", return_value=REPORT) as audit:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                cli.run_cli(args)
        return stdout.getvalue(), stderr.getvalue(), audit

    def test_json_is_emitted_without_verbose(self):
        stdout, stderr, audit = self.invoke(["--format", "json", "--no-plugins"])
        self.assertEqual(json.loads(stdout), REPORT)
        self.assertEqual(stderr, "")
        audit.assert_called_once_with(enable_plugins=False)

    def test_sarif_is_emitted_to_stdout(self):
        stdout, _, _ = self.invoke(["-f", "sarif"])
        self.assertEqual(json.loads(stdout)["version"], "2.1.0")

    def test_html_is_emitted_to_stdout(self):
        stdout, _, _ = self.invoke(["-f", "html"])
        self.assertIn("<html", stdout.lower())

    def test_text_file_is_written_without_printing_report_to_stdout(self):
        with tempfile.TemporaryDirectory(prefix="audit report ") as directory:
            output = Path(directory) / "report.txt"
            stdout, stderr, _ = self.invoke(["-o", str(output)])
            self.assertEqual(stdout, "")
            self.assertIn("Report saved to", stderr)
            self.assertIn("Defensive MCP", output.read_text(encoding="utf-8"))

    def test_suffix_inference_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            stdout, _, _ = self.invoke(["-o", str(output)])
            self.assertEqual(stdout, "")
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), REPORT)

    def test_invalid_format_is_rejected_before_audit(self):
        with patch.object(cli, "audit_mcp_environment") as audit:
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    cli.run_cli(["--format", "typo"])
        self.assertEqual(raised.exception.code, 2)
        audit.assert_not_called()

    def test_unknown_option_is_not_ignored(self):
        with patch.object(cli, "audit_mcp_environment") as audit:
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    cli.run_cli(["--unknown"])
        audit.assert_not_called()

    def test_no_optional_console_dependency_is_required(self):
        with patch.object(cli, "Console", None), patch.object(cli, "RICH_AVAILABLE", False):
            stdout, _, _ = self.invoke(["-f", "json"])
        self.assertEqual(json.loads(stdout), REPORT)

    def test_bad_output_destination_has_clean_error(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(cli, "audit_mcp_environment", return_value=REPORT):
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    with self.assertRaises(SystemExit) as raised:
                        cli.run_cli(["-f", "json", "-o", directory])
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("cannot write report", stderr.getvalue())

    def test_default_does_not_save_implicit_json_side_file(self):
        with patch.object(cli, "Console", None), patch.object(cli, "RICH_AVAILABLE", False):
            with patch.object(Path, "write_text") as write:
                stdout, _, _ = self.invoke([])
        write.assert_not_called()
        self.assertIn("Defensive MCP", stdout)


if __name__ == "__main__":
    unittest.main()
