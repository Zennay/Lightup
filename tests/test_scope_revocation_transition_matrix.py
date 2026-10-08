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


if __name__ == "__main__":
    unittest.main()
