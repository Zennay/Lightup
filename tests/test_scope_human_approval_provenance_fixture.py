"""Offline contract-integrity checks; not a production authorization test."""
import json
import unittest
from pathlib import Path

FIXTURE = Path(__file__).parent / "fixtures" / "scope_human_approval_provenance_cases.json"
REQUIRED = {
    "pending_request", "same_tenant_exact_revision", "changed_request_revision",
    "cross_tenant_approval", "requester_claims_reviewer", "ai_recommends_approval",
    "revoked_approval", "outside_approval_window", "asset_or_capability_expansion",
    "analysis_only_with_approval", "risk_ceiling_expansion", "missing_provenance",
}

class HumanApprovalProvenanceFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_explicitly_offline_fail_closed_metadata(self):
        self.assertEqual(self.data["schema_version"], 1)
        self.assertEqual(self.data["classification"], "offline_contract_only")
        self.assertEqual(self.data["default_active_dispatch"], "deny")

    def test_unique_complete_scenarios(self):
        ids = [row["id"] for row in self.data["cases"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(set(ids), REQUIRED)

    def test_no_unconditional_active_permission(self):
        allowed = {"deny", "conditionally_allow"}
        for row in self.data["cases"]:
            with self.subTest(case=row["id"]):
                self.assertIn(row["expected_active_dispatch"], allowed)
                for key in ("approval_state", "reason"):
                    self.assertIs(type(row[key]), str)
                    self.assertTrue(row[key].strip())

    def test_only_exact_revision_has_conditional_allow(self):
        conditional = [
            row["id"] for row in self.data["cases"]
            if row["expected_active_dispatch"] == "conditionally_allow"
        ]
        self.assertEqual(conditional, ["same_tenant_exact_revision"])

    def test_all_denial_scenarios_stay_denied(self):
        for row in self.data["cases"]:
            if row["id"] != "same_tenant_exact_revision":
                with self.subTest(case=row["id"]):
                    self.assertEqual(row["expected_active_dispatch"], "deny")

if __name__ == "__main__":
    unittest.main()
