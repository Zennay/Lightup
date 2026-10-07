from __future__ import annotations

import unittest

import test_future_remediation_implementation_plan_review as review_tests
from lightup.future_remediation_implementation_plan_review_handoff import (
    future_remediation_implementation_plan_review_from_dict,
)


class _DictSubclass(dict):
    pass


class FutureRemediationImplementationPlanReviewMappingTypeTest(unittest.TestCase):
    def setUp(self):
        self.base = review_tests.FutureRemediationImplementationPlanReviewTest(
            "test_all_pass_review_accepts_plan_without_action_authority"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        gateway, _ = self.base._review_gateway(review_tests._review_json())
        self.review = self.base._review(gateway)

    def test_exact_builtin_mapping_remains_valid(self):
        payload = self.review.as_dict()
        self.assertIs(type(payload), dict)
        parsed = future_remediation_implementation_plan_review_from_dict(payload)
        self.assertEqual(parsed, self.review)

    def test_mapping_subclass_is_rejected_before_schema_traversal(self):
        payload = self.review.as_dict()
        adversarial = _DictSubclass(payload)
        with self.assertRaises(ValueError):
            future_remediation_implementation_plan_review_from_dict(adversarial)
        self.assertEqual(adversarial, payload)
        self.assertIs(type(adversarial), _DictSubclass)


if __name__ == "__main__":
    unittest.main()
