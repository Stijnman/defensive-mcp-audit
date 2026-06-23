import unittest

from defensive_mcp_audit.scoring import compute_risk_level, dedupe_recommendations


class ScoringTests(unittest.TestCase):
    def test_risk_levels(self):
        self.assertEqual(compute_risk_level(0), "low")
        self.assertEqual(compute_risk_level(20), "medium")
        self.assertEqual(compute_risk_level(45), "high")
        self.assertEqual(compute_risk_level(90), "critical")

    def test_dedupe_recommendations(self):
        items = ["a", "b", "a", "c"]
        self.assertEqual(dedupe_recommendations(items), ["a", "b", "c"])


if __name__ == "__main__":
    unittest.main()