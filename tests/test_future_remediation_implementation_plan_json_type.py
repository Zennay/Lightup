from __future__ import annotations

import unittest

import test_future_remediation_implementation_plan as plan_tests
from lightup.future_remediation_implementation_plan_handoff import (
    future_remediation_implementation_plan_from_json,
)


class _StringSubclass(str):
    pass


class FutureRemediationImplementationPlanJsonTypeTest(unittest.TestCase):
    def setUp(self):
        self.base = plan_tests.FutureRemediationImplementationPlanTest(
            "test_live_approved_request_generates_non_executable_plan"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        gateway, _ = self.base._gateway()
        self.plan = self.base._generate(gateway)

    def test_exact_builtin_json_remains_valid(self):
        raw = self.plan.to_json()
        parsed = future_remediation_implementation_plan_from_json(raw)
        self.assertEqual(parsed, self.plan)
        self.assertIs(type(raw), str)

    def test_string_subclass_is_rejected_before_decode(self):
        raw = self.plan.to_json()
        adversarial = _StringSubclass(raw)
        with self.assertRaises(ValueError):
            future_remediation_implementation_plan_from_json(adversarial)
        self.assertEqual(adversarial, raw)
        self.assertIs(type(adversarial), _StringSubclass)


if __name__ == "__main__":
    unittest.main()
