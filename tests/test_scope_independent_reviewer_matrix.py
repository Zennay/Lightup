"""Offline schema-only acceptance matrix checks; never dispatch capabilities."""
import json
import unittest
from pathlib import Path

FIXTURE = Path(__file__).parent / "fixtures" / "scope_independent_reviewer_matrix.json"
REQUIRED = {
    "self_approval", "same_human_alias", "missing_principal",
    "approval_before_revision", "revision_changed", "cross_tenant",
    "scope_expanded", "missing_permission", "revoked", "malformed_proof",
    "distinct_verified_exact_revision",
}

class IndependentReviewerMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_no_runtime_authority(self):
        self.assertIs(self.data["execution_allowed"], False)
        self.assertEqual(self.data["classification"], "offline_acceptance_contract_only")
        self.assertEqual(self.data["schema_version"], 1)

    def test_exact_expected_case_set(self):
        ids = [case["id"] for case in self.data["cases"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(set(ids), REQUIRED)

    def test_all_negative_cases_are_denied(self):
        for case in self.data["cases"]:
            with self.subTest(case=case["id"]):
                self.assertEqual(case["expected"],
                    "conditionally_eligible" if case["id"] == "distinct_verified_exact_revision"
                    else "deny")

    def test_no_extra_or_untyped_fields(self):
        for case in self.data["cases"]:
            with self.subTest(case=case.get("id")):
                self.assertEqual(set(case), {"id", "expected"})
                self.assertIs(type(case["id"]), str)
                self.assertIs(type(case["expected"]), str)
