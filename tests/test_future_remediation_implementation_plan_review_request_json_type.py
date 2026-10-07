from __future__ import annotations

import unittest

import test_future_remediation_implementation_plan_review_request as request_tests
from lightup.future_remediation_implementation_plan_review_request_handoff import (
    future_remediation_implementation_plan_review_request_from_json,
)


class _StringSubclass(str):
    pass


class FutureRemediationImplementationPlanReviewRequestJsonTypeTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = request_tests.FutureRemediationImplementationPlanReviewRequestTest(
            "test_live_valid_plan_produces_review_only_request"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.request = self.base.request

    def test_exact_builtin_json_remains_valid(self):
        raw = self.request.to_json()
        parsed = future_remediation_implementation_plan_review_request_from_json(raw)
        self.assertEqual(parsed, self.request)
        self.assertIs(type(raw), str)

    def test_string_subclass_is_rejected_before_decode(self):
        raw = self.request.to_json()
        adversarial = _StringSubclass(raw)
        with self.assertRaises(ValueError):
            future_remediation_implementation_plan_review_request_from_json(adversarial)
        self.assertEqual(adversarial, raw)
        self.assertIs(type(adversarial), _StringSubclass)


if __name__ == "__main__":
    unittest.main()
