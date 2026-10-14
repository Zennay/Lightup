"""Validate the offline authorization review fixture without touching targets."""
import json
import unittest
from pathlib import Path

FIXTURE = Path(__file__).resolve().parents[1] / "docs/fixtures/scope-authorization-offline-review-v1.json"

class OfflineAuthorizationReviewFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_schema_and_safe_defaults(self):
        self.assertEqual(self.data["schema_version"], 1)
        self.assertEqual(self.data["defaults"]["mode"], "ANALYSIS_ONLY")
        for key in ("network_access", "active_execution", "external_targets"):
            self.assertIs(self.data["defaults"][key], False)

    def test_cases_are_unique_and_nonexecuting(self):
        cases = self.data["cases"]
        ids = [case["id"] for case in cases]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertGreaterEqual(len(ids), 10)
        self.assertTrue(all(case["expected"] in {"DENY", "ALLOW_ANALYSIS_ONLY"} for case in cases))

    def test_required_negative_boundaries_present(self):
        by_id = {case["id"]: case for case in self.data["cases"]}
        for name in (
            "absent-grant", "expired-grant", "not-yet-valid", "undeclared-asset",
            "excluded-asset", "revoked-grant", "different-tenant",
            "changed-asset-snapshot", "missing-admin-approval",
        ):
            self.assertEqual(by_id[name]["expected"], "DENY")
        self.assertEqual(by_id["analysis-only"]["expected"], "ALLOW_ANALYSIS_ONLY")

if __name__ == "__main__":
    unittest.main()
