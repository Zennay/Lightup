"""Static, offline integrity checks for the proposed issuer-rotation contract.

These tests validate acceptance-fixture completeness, NOT production enforcement.
"""
import json
import unittest
from pathlib import Path

FIXTURE = Path(__file__).parent / "fixtures" / "scope_issuer_key_rotation_matrix.json"

DENIALS = {
    "unknown_issuer", "missing_kid", "duplicate_kid", "retired_key",
    "rotation_after_queue_admission", "unsigned_algorithm",
    "algorithm_substitution", "cross_tenant_key", "future_key",
    "issued_outside_key_window", "ambiguous_signed_claim",
    "revoked_issuer", "trust_store_unavailable", "rotation_during_retry",
    "audit_persistence_failed",
}


class IssuerKeyRotationMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.matrix = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_schema_is_explicit(self):
        self.assertIs(type(self.matrix["schema_version"]), int)
        self.assertEqual(self.matrix["schema_version"], 1)
        self.assertEqual(self.matrix["contract"], "issuer-key-rotation-fail-closed")

    def test_each_case_is_unique_and_typed(self):
        cases = self.matrix["cases"]
        self.assertEqual(len(cases), len({case["id"] for case in cases}))
        for case in cases:
            self.assertEqual(set(case), {"id", "expected", "requires_live_trust_check"})
            self.assertIs(type(case["id"]), str)
            self.assertTrue(case["id"])
            self.assertIn(case["expected"], {"deny", "conditional"})
            self.assertIs(case["requires_live_trust_check"], True)

    def test_all_required_denials_are_fail_closed(self):
        mapping = {case["id"]: case["expected"] for case in self.matrix["cases"]}
        self.assertEqual(set(mapping), DENIALS | {"current_exact_grant"})
        self.assertTrue(all(mapping[key] == "deny" for key in DENIALS))

    def test_positive_fixture_is_only_conditional(self):
        cases = [c for c in self.matrix["cases"] if c["expected"] != "deny"]
        self.assertEqual([c["id"] for c in cases], ["current_exact_grant"])
        self.assertEqual(cases[0]["expected"], "conditional")


if __name__ == "__main__":
    unittest.main()
