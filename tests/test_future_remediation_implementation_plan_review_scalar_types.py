from __future__ import annotations

import unittest

import test_future_remediation_implementation_plan_review as review_tests
from lightup.future_remediation_implementation_plan_review_handoff import (
    future_remediation_implementation_plan_review_from_dict,
)


class _StringSubclass(str):
    pass


class FutureRemediationImplementationPlanReviewScalarTypeTest(unittest.TestCase):
    def setUp(self):
        self.base = review_tests.FutureRemediationImplementationPlanReviewTest(
            "test_all_pass_review_accepts_plan_without_action_authority"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        gateway, _ = self.base._review_gateway(review_tests._review_json())
        self.review = self.base._review(gateway)

    def test_exact_builtin_strings_remain_valid(self):
        payload = self.review.as_dict()
        parsed = future_remediation_implementation_plan_review_from_dict(payload)
        self.assertEqual(parsed, self.review)
        self.assertIs(type(payload["review_sha256"]), str)
        self.assertIs(type(payload["reviewer_model_id"]), str)
        self.assertIs(type(payload["summary"]), str)

    def test_digest_string_subclass_is_rejected(self):
        payload = self.review.as_dict()
        payload["review_sha256"] = _StringSubclass(payload["review_sha256"])
        with self.assertRaises(ValueError):
            future_remediation_implementation_plan_review_from_dict(payload)

    def test_provenance_string_subclass_is_rejected(self):
        payload = self.review.as_dict()
        payload["reviewer_model_id"] = _StringSubclass(payload["reviewer_model_id"])
        with self.assertRaises(ValueError):
            future_remediation_implementation_plan_review_from_dict(payload)

    def test_summary_string_subclass_is_rejected(self):
        payload = self.review.as_dict()
        payload["summary"] = _StringSubclass(payload["summary"])
        with self.assertRaises(ValueError):
            future_remediation_implementation_plan_review_from_dict(payload)


if __name__ == "__main__":
    unittest.main()
