"""Offline contract-shape validation; not proof of runtime authorization."""

import json
from pathlib import Path
import unittest


FIXTURE = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "fixtures"
    / "scope-incident-response-exercises.json"
)
EXPECTED = {
    "revoked-before-dispatch": ("deny", "none"),
    "expired-retry": ("deny", "none"),
    "in-flight-revocation": ("deny_next_step", "none"),
    "audit-write-failure": ("deny", "none"),
    "cross-tenant-id-reuse": ("deny_cross_tenant", "none"),
    "broadened-replacement": ("deny", "none"),
    "new-approval": ("new_run_only", "fresh_gate"),
    "analysis-only": ("analysis_only", "no_target_io"),
}


class IncidentFixtureContractTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_closed_schema(self):
        self.assertEqual(set(self.data), {"schema_version", "purpose", "exercises"})
        self.assertIs(type(self.data["schema_version"]), int)
        self.assertEqual(self.data["schema_version"], 1)
        self.assertIs(type(self.data["purpose"]), str)
        self.assertIn("never an authorization grant", self.data["purpose"])

    def test_unique_exact_case_coverage(self):
        cases = self.data["exercises"]
        self.assertIs(type(cases), list)
        self.assertEqual(len(cases), len(EXPECTED))
        self.assertEqual({case["id"] for case in cases}, set(EXPECTED))

    def test_fail_closed_expectations_are_pinned(self):
        for case in self.data["exercises"]:
            with self.subTest(case=case.get("id")):
                self.assertEqual(
                    set(case),
                    {"id", "trigger", "expected_dispatch", "expected_next_action", "tenant_isolation"},
                )
                for field in ("id", "trigger", "expected_dispatch", "expected_next_action"):
                    self.assertIs(type(case[field]), str)
                    self.assertTrue(case[field].strip())
                self.assertIs(case["tenant_isolation"], True)
                self.assertEqual(
                    (case["expected_dispatch"], case["expected_next_action"]),
                    EXPECTED[case["id"]],
                )


if __name__ == "__main__":
    unittest.main()
