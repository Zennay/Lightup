from __future__ import annotations

import unittest

import test_future_remediation_implementation_plan_revision_request_handoff as handoff_tests
from lightup.future_remediation_implementation_plan_revision_request_handoff import (
    future_remediation_implementation_plan_revision_request_from_json,
)


class _StringSubclass(str):
    pass


class FutureRemediationImplementationPlanRevisionRequestJsonTypeTest(
    unittest.TestCase
):
    def setUp(self):
        self.request = handoff_tests._request()

    def test_exact_builtin_json_remains_valid(self):
        raw = self.request.to_json()
        parsed = future_remediation_implementation_plan_revision_request_from_json(raw)
        self.assertEqual(parsed, self.request)
        self.assertIs(type(raw), str)

    def test_string_subclass_is_rejected_before_decode(self):
        raw = self.request.to_json()
        adversarial = _StringSubclass(raw)
        with self.assertRaises(ValueError):
            future_remediation_implementation_plan_revision_request_from_json(adversarial)
        self.assertEqual(adversarial, raw)
        self.assertIs(type(adversarial), _StringSubclass)


if __name__ == "__main__":
    unittest.main()
