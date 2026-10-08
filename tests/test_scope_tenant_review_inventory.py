"""Offline shape checks for the reviewer-only tenant authorization inventory."""
import json
from pathlib import Path
import unittest

FIXTURE = Path(__file__).parent / "fixtures" / "scope_tenant_review_checklist.json"

class TenantAuthorizationReviewInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.payload = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_version_and_purpose_are_explicit(self):
        self.assertEqual(self.payload["version"], 1)
        self.assertIn("not executable authorization", self.payload["purpose"])

    def test_identifiers_unique_and_exact_strings(self):
        identifiers = [case["id"] for case in self.payload["cases"]]
        self.assertEqual(len(identifiers), len(set(identifiers)))
        self.assertGreaterEqual(len(identifiers), 8)
        self.assertTrue(all(type(name) is str and name and name.strip() == name for name in identifiers))

    def test_all_expectations_are_fail_closed(self):
        allowed = {"deny_before_dispatch", "deny_next_step_and_cancel"}
        for case in self.payload["cases"]:
            with self.subTest(case=case["id"]):
                self.assertEqual(set(case), {"id", "given", "expect"})
                self.assertIs(type(case["given"]), str)
                self.assertTrue(case["given"].strip())
                self.assertIn(case["expect"], allowed)

    def test_review_domains_are_covered(self):
        ids = {case["id"] for case in self.payload["cases"]}
        self.assertTrue({"cross_tenant_grant", "stale_revision", "revoked_multistep", "audit_store_failure", "persisted_tenant_mismatch"} <= ids)

if __name__ == "__main__":
    unittest.main()
