"""Validate static replay acceptance fixtures without issuing an approval or contacting targets."""
import json
import unittest
from pathlib import Path

FIXTURE = Path(__file__).parent / "fixtures" / "scope_approval_replay_matrix.json"
DENIALS = {"deny_replay", "deny_request_mismatch", "deny_tenant_mismatch", "deny_revision_mismatch"}


class ApprovalReplayFixtureContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.matrix = json.loads(FIXTURE.read_text(encoding="utf-8"))
        cls.cases = cls.matrix["cases"]

    def test_version_and_explicit_non_production_purpose(self):
        self.assertEqual(self.matrix["schema_version"], 1)
        self.assertIn("no production runtime claim", self.matrix["purpose"])

    def test_unique_scenario_ids_and_required_fields(self):
        ids = [case["id"] for case in self.cases]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(ids)
        for case in self.cases:
            with self.subTest(case=case["id"]):
                self.assertTrue(all(case.get(k) for k in ("request_id", "approval_id", "tenant", "event", "expect")))
                self.assertIs(type(case["revision"]), int)
                self.assertGreater(case["revision"], 0)

    def test_replay_and_binding_denials_present(self):
        by_id = {case["id"]: case for case in self.cases}
        for name, expected in (
            ("duplicate_same_request", "deny_replay"),
            ("cross_request_reuse", "deny_request_mismatch"),
            ("cross_tenant_reuse", "deny_tenant_mismatch"),
            ("stale_revision", "deny_revision_mismatch"),
        ):
            self.assertEqual(by_id[name]["expect"], expected)
        self.assertTrue(DENIALS.issubset({case["expect"] for case in self.cases}))

    def test_positive_cases_are_conditional_not_authorization(self):
        eligible = [case for case in self.cases if case["expect"] == "conditionally_eligible"]
        self.assertEqual({case["id"] for case in eligible}, {"fresh_approval_once", "unrelated_approval"})
        self.assertFalse(any(case["expect"] == "allow" for case in self.cases))

    def test_replay_changes_no_authority_identity(self):
        first, replay = self.cases[0], self.cases[1]
        for field in ("request_id", "approval_id", "tenant", "revision"):
            self.assertEqual(first[field], replay[field])
        self.assertNotEqual(first["expect"], replay["expect"])


if __name__ == "__main__":
    unittest.main()
