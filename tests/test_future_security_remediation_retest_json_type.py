from __future__ import annotations

import unittest

import test_future_security_remediation_retest_plan_handoff as handoff_tests
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_security_remediation_retest_plan_handoff import (
    future_security_remediation_retest_plan_from_json,
)


class _StringSubclass(str):
    pass


class FutureSecurityRemediationRetestJsonTypeTest(unittest.TestCase):
    def setUp(self):
        self.h = handoff_tests.FutureSecurityRemediationRetestPlanHandoffTest(
            "test_round_trip_accepts_exact_builder_output"
        )
        self.h.setUp()
        self.addCleanup(self.h.tearDown)
        self.plan = self.h._plan(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="json-type",
        )

    def test_real_producer_json_uses_exact_builtin_string_and_remains_valid(self):
        raw = self.plan.to_json()

        parsed = future_security_remediation_retest_plan_from_json(raw)

        self.assertEqual(parsed, self.plan)
        self.assertIs(type(raw), str)

    def test_json_string_subclass_is_rejected_before_decode(self):
        raw = self.plan.to_json()
        adversarial = _StringSubclass(raw)

        with self.assertRaises(ValueError):
            future_security_remediation_retest_plan_from_json(adversarial)

        self.assertEqual(adversarial, raw)
        self.assertIs(type(adversarial), _StringSubclass)


if __name__ == "__main__":
    unittest.main()
