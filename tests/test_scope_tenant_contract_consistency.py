"""Review-only contract consistency tests: no production authorization imports.

These checks do not prove that the real executor denies a request. They ensure the
human-readable reviewer contract and its negative-evidence inventory cannot drift
silently apart while the source owners implement real enforcement separately.
"""
from pathlib import Path
import json
import unittest

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "docs" / "scope-authorization-tenant-boundary-review-checklist.md"
INVENTORY = ROOT / "tests" / "fixtures" / "scope_tenant_review_checklist.json"

class ScopeTenantContractConsistencyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = CONTRACT.read_text(encoding="utf-8")
        cls.inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))

    def test_all_required_negative_cases_are_unique_and_present(self):
        required = {
            "cross_tenant_grant",
            "cross_engagement_approval",
            "stale_revision",
            "narrowed_capability",
            "revoked_multistep",
            "audit_store_failure",
            "passive_mode_confusion",
            "persisted_tenant_mismatch",
        }
        ids = [row["id"] for row in self.inventory["cases"]]
        self.assertEqual(set(ids), required)
        self.assertEqual(len(ids), len(required))

    def test_each_review_dimension_has_a_fail_closed_outcome(self):
        expected = {
            "cross_tenant_grant": "deny_before_dispatch",
            "cross_engagement_approval": "deny_before_dispatch",
            "stale_revision": "deny_before_dispatch",
            "narrowed_capability": "deny_before_dispatch",
            "revoked_multistep": "deny_next_step_and_cancel",
            "audit_store_failure": "deny_before_dispatch",
            "passive_mode_confusion": "deny_before_dispatch",
            "persisted_tenant_mismatch": "deny_before_dispatch",
        }
        self.assertEqual(
            {item["id"]: item["expect"] for item in self.inventory["cases"]},
            expected,
        )

    def test_document_disclaims_enforcement_and_active_permission(self):
        for claim in (
            "not evidence that enforcement exists",
            "does not authorize assessments",
            "no change to production authorization",
            "zero target-capable invocations",
        ):
            with self.subTest(claim=claim):
                self.assertIn(claim, self.contract)

    def test_document_records_source_owner_and_validation_gates(self):
        for marker in ("PR #107", "permanent", "commit SHA", "tenant", "revocation"):
            with self.subTest(marker=marker):
                self.assertIn(marker, self.contract)

if __name__ == "__main__":
    unittest.main()
