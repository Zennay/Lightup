"""Validate the offline revocation interleaving acceptance fixture.

This is a specification consistency check, NOT a runtime authorization test.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path


FIXTURE = Path(__file__).parent / "fixtures" / "scope_revocation_linearization_cases_20261008.json"


class RevocationGateFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_no_authority_or_network_effects(self):
        safety = self.data["safety"]
        self.assertEqual(
            safety,
            {
                "network": False,
                "real_targets": False,
                "active_scans": False,
                "production_changes": False,
            },
        )

    def test_case_identity_and_deterministic_steps(self):
        cases = self.data["cases"]
        names = [case["id"] for case in cases]
        self.assertEqual(len(names), len(set(names)))
        self.assertGreaterEqual(len(names), 10)
        for case in cases:
            with self.subTest(case=case["id"]):
                self.assertTrue(case["order"])
                self.assertTrue(all(type(step) is str and step for step in case["order"]))
                self.assertIn(case["expected"], {"deny", "deny_issue", "allow", "ordered_by_linearization_point"})
                self.assertIn(case["expected_handler_calls"], {None, 0, 1})

    def test_revocation_denials_and_positive_control(self):
        by_id = {case["id"]: case for case in self.data["cases"]}
        for name in ("revoke-before-dispatch", "close-before-dispatch", "expiry-between-checks", "durable-scope-narrowing"):
            with self.subTest(case=name):
                self.assertEqual(by_id[name]["expected"], "deny")
                self.assertEqual(by_id[name]["expected_handler_calls"], 0)
        self.assertEqual(by_id["valid-current-grant-control"]["expected_handler_calls"], 1)
        self.assertIsNone(by_id["revocation-race"]["expected_handler_calls"])


if __name__ == "__main__":
    unittest.main()
