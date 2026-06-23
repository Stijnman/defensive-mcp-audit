import unittest
from pathlib import Path

from defensive_mcp_audit.network import (
    classify_service,
    discover_listening_services,
    enrich_services,
    is_localhost_binding,
    is_risky_binding,
)


class NetworkTests(unittest.TestCase):
    def test_risky_and_localhost_bindings(self):
        self.assertTrue(is_risky_binding("0.0.0.0"))
        self.assertTrue(is_risky_binding("[::]"))
        self.assertTrue(is_localhost_binding("127.0.0.1"))
        self.assertTrue(is_localhost_binding("127.0.0.53%lo"))

    def test_service_classification(self):
        self.assertEqual(classify_service("uvicorn", 8080), "mcp_related")
        self.assertEqual(classify_service("smbd", 445), "system")
        self.assertEqual(classify_service("", 2222), "unknown")

    def test_parse_fixture_and_weighting(self):
        fixture = Path(__file__).parent / "fixtures" / "ss_sample.txt"
        services = enrich_services(
            discover_listening_services(ss_output=fixture.read_text(encoding="utf-8"))
        )
        by_port = {service["port"]: service for service in services}
        self.assertEqual(by_port[8080]["classification"], "mcp_related")
        self.assertEqual(by_port[8080]["risk_weight"], 40)
        self.assertEqual(by_port[445]["classification"], "system")
        self.assertEqual(by_port[445]["risk_weight"], 2)
        self.assertEqual(by_port[11434]["risk_weight"], 0)


if __name__ == "__main__":
    unittest.main()