"""Offline acceptance-matrix shape checks; not production revocation tests."""

import json
from pathlib import Path
import unittest


MATRIX = Path(__file__).parent / "fixtures" / "scope_revocation_transition_matrix.json"
EXPECTED = {
    "revoked_before_dispatch", "expired_in_queue", "resolver_missing_or_error",
    "asset_narrowed", "capability_or_risk_broadened",
    "validity_window_broadened", "revoked_between_steps",
    "retry_after_revocation", "cross_tenant_isolation",
    "denial_audit_sink_failed", "analysis_only_non_target",
}
DENIAL_CASES = {
    "revoked_before_dispatch", "expired_in_queue", "resolver_missing_or_error",
    "asset_narrowed", "capability_or_risk_broadened",
    "validity_window_broadened", "retry_after_revocation",
    "denial_audit_sink_failed",
}


class RevocationTransitionMatrixTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.matrix = json.loads(MATRIX.read_text(encoding="utf-8"))

    def test_metadata_never_claims_implementation_or_target_permission(self):
        self.assertEqual(self.matrix["schema_version"], 1)
        self.assertEqual(self.matrix["kind"], "offline-revocation-transition-acceptance")
        self.assertIs(self.matrix["implementation_verified"], False)
        self.assertIs(self.matrix["requires_real_target"], False)

    def test_scenarios_are_exact_and_unique(self):
        scenarios = self.matrix["scenarios"]
        self.assertTrue(all(isinstance(s, list) and len(s) == 3 for s in scenarios))
        ids = [s[0] for s in scenarios]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(set(ids), EXPECTED)

    def test_fail_closed_cases_explicitly_deny(self):
        cases = {row[0]: row[1] for row in self.matrix["scenarios"]}
        for scenario in DENIAL_CASES:
            with self.subTest(scenario=scenario):
                self.assertEqual(cases[scenario], "deny")

    def test_inflight_revocation_halts_before_next_step(self):
        cases = {row[0]: row[1:] for row in self.matrix["scenarios"]}
        self.assertEqual(cases["revoked_between_steps"],
                         ["halt_before_next_step", "cancellation_checkpoint"])

    def test_contract_lists_every_machine_scenario(self):
        contract = (Path(__file__).resolve().parents[1] / "docs" /
                    "scope-authorization-revocation-transition-contract.md").read_text(
                        encoding="utf-8"
                    ).lower()
        markers = {
            "revoked_before_dispatch": "revoked before dispatch",
            "expired_in_queue": "expires while job is queued",
            "resolver_missing_or_error": "resolver errors",
            "asset_narrowed": "narrowed to exclude requested asset",
            "capability_or_risk_broadened": "broadened capability or risk",
            "validity_window_broadened": "validity starts earlier or expires later",
            "revoked_between_steps": "revoked during a multi-step run",
            "retry_after_revocation": "retries after revocation",
            "cross_tenant_isolation": "tenant a revoked, tenant b still valid",
            "denial_audit_sink_failed": "denial ledger unavailable",
            "analysis_only_non_target": "analysis-only operation with no target i/o",
        }
        for case, phrase in markers.items():
            with self.subTest(case=case):
                self.assertIn(phrase, contract)

    def test_every_case_has_nonempty_expected_result_and_guard(self):
        for case, result, guard in self.matrix["scenarios"]:
            with self.subTest(case=case):
                self.assertIs(type(case), str)
                self.assertIs(type(result), str)
                self.assertIs(type(guard), str)
                self.assertTrue(case.strip() and result.strip() and guard.strip())


    def test_case_results_and_guards_use_closed_vocabulary(self):
        # Prevent a future fixture edit from silently weakening expected outcomes.
        allowed = {
            "revoked_before_dispatch": ("deny", "zero_handler_calls"),
            "expired_in_queue": ("deny", "zero_handler_calls"),
            "resolver_missing_or_error": ("deny", "zero_handler_calls"),
            "asset_narrowed": ("deny", "zero_handler_calls"),
            "capability_or_risk_broadened": ("deny", "new_run_required"),
            "validity_window_broadened": ("deny", "new_run_required"),
            "revoked_between_steps": ("halt_before_next_step", "cancellation_checkpoint"),
            "retry_after_revocation": ("deny", "fresh_revalidation"),
            "cross_tenant_isolation": ("tenant_specific", "no_cross_tenant_authority"),
            "denial_audit_sink_failed": ("deny", "no_permission_fallback"),
            "analysis_only_non_target": ("analysis_only", "no_target_dispatch"),
        }
        actual = {case: (result, guard) for case, result, guard in self.matrix["scenarios"]}
        self.assertEqual(actual, allowed)

    def test_fixture_does_not_accidentally_authorize_any_target(self):
        for case, result, guard in self.matrix["scenarios"]:
            with self.subTest(case=case):
                self.assertNotIn(result, {"allow", "permit", "execute", "authorized"})
                self.assertNotIn(guard, {"skip_revalidation", "ignore_revocation", "fallback_allow"})


if __name__ == "__main__":
    unittest.main()
