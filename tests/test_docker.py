import unittest
from unittest.mock import patch

from defensive_mcp_audit.docker_runtime import docker_findings, inspect_docker_publishers


class DockerTests(unittest.TestCase):
    @patch("defensive_mcp_audit.docker_runtime._docker_available", return_value=False)
    def test_no_docker(self, _mock):
        self.assertEqual(inspect_docker_publishers(), [])
        self.assertEqual(docker_findings(), [])

    @patch("defensive_mcp_audit.docker_runtime._docker_available", return_value=True)
    @patch("defensive_mcp_audit.docker_runtime.subprocess.run")
    def test_risky_publish_finding(self, mock_run, _mock):
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = (
            '{"Names":"mcp-server","Image":"local/mcp","Ports":"0.0.0.0:8080->8080/tcp"}\n'
        )
        findings = docker_findings()
        ids = {item["id"] for item in findings}
        self.assertIn("DOCKER_PUBLISHED_PORTS", ids)
        self.assertIn("DOCKER_RISKY_PUBLISH", ids)


if __name__ == "__main__":
    unittest.main()