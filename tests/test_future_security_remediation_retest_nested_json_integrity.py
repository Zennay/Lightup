from __future__ import annotations

import unittest

import test_future_security_remediation_retest_plan_handoff as handoff_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_security_remediation_retest_plan_handoff import (
    future_security_remediation_retest_plan_from_json,
)


class FutureSecurityRemediationRetestNestedJsonIntegrityTest(unittest.TestCase):
    def setUp(self):
        self.h = handoff_tests.FutureSecurityRemediationRetestPlanHandoffTest(
            "test_round_trip_accepts_exact_builder_output"
        )
        self.h.setUp()
        self.addCleanup(self.h.tearDown)

    def _canonical_raw(self) -> tuple[object, str]:
        plan = self.h._plan(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="nested-json-integrity",
        )
        return plan, plan.to_json()

    def test_canonical_json_still_round_trips(self):
        plan, raw = self._canonical_raw()

        parsed = future_security_remediation_retest_plan_from_json(raw)

        self.assertEqual(parsed, plan)

    def test_duplicate_nested_item_keys_fail_closed_recursively(self):
        _, raw = self._canonical_raw()
        duplicate_cases = {
            "identity": (
                '"change_node_id":',
                '"change_node_id":"shadow-change","change_node_id":',
            ),
            "classification": (
                '"classification":',
                '"classification":"removed","classification":',
            ),
            "requirement": (
                '"remediation_required":',
                '"remediation_required":false,"remediation_required":',
            ),
            "lineage-array": (
                '"capability_ids":',
                '"capability_ids":["shadow-capability"],"capability_ids":',
            ),
        }

        for case, (marker, replacement) in duplicate_cases.items():
            with self.subTest(case=case):
                self.assertIn(marker, raw)
                duplicated = raw.replace(marker, replacement, 1)
                with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                    future_security_remediation_retest_plan_from_json(duplicated)


if __name__ == "__main__":
    unittest.main()
