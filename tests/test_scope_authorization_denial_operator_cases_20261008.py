"""Offline integrity contract for the denial operator cases; not an executor test."""
import json
import unittest
from pathlib import Path

CASES = Path(__file__).parent / "fixtures" / "scope_authorization_denial_operator_cases_20261008.json"
EXPECTED = {
    "expired_prior_success", "revocation_store_unavailable", "cross_tenant_binding",
    "cross_engagement_binding", "risk_above_grant", "audit_persistence_failed",
    "support_ticket_ack_only", "clock_source_untrusted", "asset_out_of_scope",
    "conflicting_policies", "missing_current_grant",
    "malformed_approval_provenance", "new_grant_during_stopped_request",
}

class DenialOperatorCasesContract(unittest.TestCase):
    def test_fixtures_are_explicitly_non_executable(self):
        source = json.loads(CASES.read_text(encoding="utf-8"))
        self.assertEqual(type(source["schema_version"]), int)
        self.assertEqual(source["schema_version"], 1)
        self.assertEqual(source["mode"], "OFFLINE_REFERENCE_ONLY")
        self.assertIs(source["activation_permitted"], False)
        rows = source["examples"]
        self.assertEqual(type(rows), list)
        self.assertEqual(len(rows), len(EXPECTED))
        self.assertEqual({row["id"] for row in rows}, EXPECTED)
        self.assertEqual(len({row["id"] for row in rows}), len(rows))
        for row in rows:
            with self.subTest(case=row["id"]):
                self.assertEqual(type(row["id"]), str)
                self.assertEqual(type(row["reason"]), str)
                self.assertTrue(row["reason"])
                self.assertIs(row["synthetic"], True)
                self.assertEqual(row["expected"], "DENY")
                self.assertIs(row["target_io"], False)
                self.assertIs(row["capability_dispatch"], False)
                self.assertIs(row["may_reuse_prior_decision"], False)
                self.assertIs(row["requires_fresh_authoritative_evaluation"], True)

if __name__ == "__main__":
    unittest.main()
