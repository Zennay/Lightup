from __future__ import annotations

from dataclasses import replace
import unittest

import test_future_remediation_implementation_plan_revision_review_request as request_tests


class _StringSubclass(str):
    pass


class FutureRemediationImplementationPlanRevisionReviewRequestCheckStringTypesTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = (
            request_tests.FutureRemediationImplementationPlanRevisionReviewRequestTest(
                "test_live_valid_revised_plan_produces_review_only_request"
            )
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.request = self.base.request

    def test_canonical_required_check_items_are_exact_strings(self):
        self.assertTrue(
            all(type(item) is str for item in self.request.required_checks)
        )

    def test_required_check_string_subclass_fails_closed(self):
        subclassed = tuple(_StringSubclass(item) for item in self.request.required_checks)

        with self.assertRaises(ValueError):
            replace(self.request, required_checks=subclassed)


if __name__ == "__main__":
    unittest.main()
