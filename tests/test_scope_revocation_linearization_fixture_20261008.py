"""Validate the offline revocation acceptance fixture (not runtime proof)."""
from __future__ import annotations

import json
import unittest
from pathlib import Path

FIXTURE = Path(__file__).parent / "fixtures" / "scope_revocation_linearization_cases_20261008.json"

EXPECTED = {
    "revoke-before-dispatch": (("resolve", "revoke_commit", "dispatch"), "deny", 0),
    "close-before-dispatch": (("resolve", "close_commit", "dispatch"), "deny", 0),
    "close-before-issue": (("close_commit", "issue_grant"), "deny_issue", 0),
    "issue-before-close": (("issue_grant", "close_commit", "dispatch"), "deny", 0),
    "reopen-does-not-revive": (("issue_grant", "close_commit", "reopen", "dispatch_old_grant"), "deny", 0),
    "tenant-substitution": (("resolve_tenant_a", "substitute_tenant_b", "dispatch"), "deny", 0),
    "expiry-between-checks": (("resolve_before_expiry", "advance_clock_after_expiry", "dispatch"), "deny", 0),
    "durable-scope-narrowing": (("resolve_broad_snapshot", "narrow_durable_scope", "dispatch_excluded_asset"), "deny", 0),
    "valid-current-grant-control": (("issue_current_grant", "resolve_live", "dispatch_fake_handler"), "allow", 1),
    "revocation-race": (("concurrent_dispatch_and_revoke", "record_linearization_order"), "ordered_by_linearization_point", None),
}


class RevocationGateFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_fixture_is_offline_only(self):
        self.assertEqual(self.data["schema_version"], 1)
        self.assertEqual(
            self.data["safety"],
            {"network": False, "real_targets": False, "active_scans": False, "production_changes": False},
        )

    def test_complete_exact_interleaving_contract(self):
        cases = self.data["cases"]
        self.assertIs(type(cases), list)
        self.assertEqual(len(cases), len(EXPECTED))
        seen = set()
        for case in cases:
            with self.subTest(case=case.get("id")):
                self.assertIs(type(case), dict)
                self.assertEqual(set(case), {"id", "order", "expected_handler_calls", "expected"})
                name = case["id"]
                self.assertIn(name, EXPECTED)
                self.assertNotIn(name, seen)
                seen.add(name)
                steps, decision, count = EXPECTED[name]
                self.assertIs(type(case["order"]), list)
                self.assertEqual(case["order"], list(steps))
                self.assertEqual(case["expected"], decision)
                self.assertIs(case["expected_handler_calls"], count) if count is None else self.assertEqual(case["expected_handler_calls"], count)
        self.assertEqual(seen, set(EXPECTED))

    def test_no_denial_can_call_handler(self):
        for case in self.data["cases"]:
            with self.subTest(case=case["id"]):
                if case["expected"] in {"deny", "deny_issue"}:
                    self.assertIs(type(case["expected_handler_calls"]), int)
                    self.assertEqual(case["expected_handler_calls"], 0)
                elif case["expected"] == "allow":
                    self.assertEqual(case["expected_handler_calls"], 1)
                else:
                    self.assertIsNone(case["expected_handler_calls"])


if __name__ == "__main__":
    unittest.main()
