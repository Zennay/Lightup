from __future__ import annotations

import unittest

import test_future_remediation_implementation_plan_review_request as request_tests
from lightup.future_remediation_implementation_plan_review_request_handoff import (
    future_remediation_implementation_plan_review_request_from_dict,
)


class _DictSubclass(dict):
    pass


class FutureRemediationImplementationPlanReviewRequestMappingTypeTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = request_tests.FutureRemediationImplementationPlanReviewRequestTest(
            "test_live_valid_plan_produces_review_only_request"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.request = self.base.request

    def test_exact_builtin_mapping_remains_valid(self):
        payload = self.request.as_dict()
        self.assertIs(type(payload), dict)
        parsed = future_remediation_implementation_plan_review_request_from_dict(
            payload
        )
        self.assertEqual(parsed, self.request)

    def test_mapping_subclass_is_rejected_before_schema_traversal(self):
        payload = self.request.as_dict()
        adversarial = _DictSubclass(payload)
        with self.assertRaises(ValueError):
            future_remediation_implementation_plan_review_request_from_dict(
                adversarial
            )
        self.assertEqual(adversarial, payload)
        self.assertIs(type(adversarial), _DictSubclass)


if __name__ == "__main__":
    unittest.main()
