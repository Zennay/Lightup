from __future__ import annotations

import unittest

import test_future_remediation_implementation_plan_review_request as request_tests
from lightup.future_remediation_implementation_plan_review_request_handoff import (
    future_remediation_implementation_plan_review_request_from_dict,
)


class _StringSubclass(str):
    pass


class _IntSubclass(int):
    pass


class FutureRemediationImplementationPlanReviewRequestScalarTypeTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = request_tests.FutureRemediationImplementationPlanReviewRequestTest(
            "test_live_valid_plan_produces_review_only_request"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.request = self.base.request

    def test_exact_builtin_scalars_remain_valid(self):
        payload = self.request.as_dict()
        parsed = future_remediation_implementation_plan_review_request_from_dict(
            payload
        )
        self.assertEqual(parsed, self.request)
        self.assertIs(type(payload["plan_sha256"]), str)
        self.assertIs(type(payload["planner_model_id"]), str)
        self.assertIs(type(payload["plan_item_count"]), int)

    def test_digest_string_subclass_is_rejected(self):
        payload = self.request.as_dict()
        payload["plan_sha256"] = _StringSubclass(payload["plan_sha256"])
        with self.assertRaises(ValueError):
            future_remediation_implementation_plan_review_request_from_dict(payload)

    def test_provenance_string_subclass_is_rejected(self):
        payload = self.request.as_dict()
        payload["planner_model_id"] = _StringSubclass(payload["planner_model_id"])
        with self.assertRaises(ValueError):
            future_remediation_implementation_plan_review_request_from_dict(payload)

    def test_item_count_int_subclass_is_rejected(self):
        payload = self.request.as_dict()
        payload["plan_item_count"] = _IntSubclass(payload["plan_item_count"])
        with self.assertRaises(ValueError):
            future_remediation_implementation_plan_review_request_from_dict(payload)


if __name__ == "__main__":
    unittest.main()
