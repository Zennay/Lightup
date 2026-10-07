from __future__ import annotations

import unittest

import test_future_remediation_implementation_plan_review_request as request_tests
from lightup.future_remediation_implementation_plan_review_request_handoff import (
    future_remediation_implementation_plan_review_request_from_dict,
)


class _ListSubclass(list):
    pass


class FutureRemediationImplementationPlanReviewRequestSequenceTypeTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = request_tests.FutureRemediationImplementationPlanReviewRequestTest(
            "test_live_valid_plan_produces_review_only_request"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.request = self.base.request

    def test_exact_builtin_sequence_remains_valid(self):
        payload = self.request.as_dict()
        payload["required_checks"] = list(payload["required_checks"])
        self.assertIs(type(payload["required_checks"]), list)
        parsed = future_remediation_implementation_plan_review_request_from_dict(
            payload
        )
        self.assertEqual(parsed, self.request)

    def test_sequence_subclass_is_rejected_before_normalization(self):
        payload = self.request.as_dict()
        canonical = list(payload["required_checks"])
        payload["required_checks"] = _ListSubclass(canonical)
        with self.assertRaises(ValueError):
            future_remediation_implementation_plan_review_request_from_dict(payload)
        self.assertEqual(payload["required_checks"], canonical)
        self.assertIs(type(payload["required_checks"]), _ListSubclass)


if __name__ == "__main__":
    unittest.main()
