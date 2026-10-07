from __future__ import annotations

import unittest
from unittest import mock

import test_future_remediation_text_revision_review as revision_review_tests
import test_future_remediation_text_review as review_tests


_MAX_RAW_REVIEW_CHARS = 32_768


class FutureRemediationTextRevisionReviewRawResponseBoundTest(unittest.TestCase):
    def setUp(self):
        self.base = revision_review_tests.FutureRemediationTextRevisionReviewTest(
            "test_all_pass_review_accepts_revised_text_without_action_authority"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def _padded_canonical_review(self, size: int) -> str:
        canonical = review_tests._review_json()
        self.assertLessEqual(len(canonical), size)
        return canonical + (" " * (size - len(canonical)))

    def test_exact_raw_revised_review_boundary_is_accepted(self):
        raw = self._padded_canonical_review(_MAX_RAW_REVIEW_CHARS)
        gateway, provider = self.base._gateway(raw)

        review = self.base._review(gateway)

        self.assertEqual(len(raw), _MAX_RAW_REVIEW_CHARS)
        self.assertEqual(len(provider.requests), 1)
        self.assertTrue(review.review_completed)
        self.assertFalse(review.execution_allowed)
        self.assertFalse(review.target_interaction_allowed)
        self.assertFalse(review.future_state_retest_allowed)
        self.assertFalse(review.deployment_authorized)
        self.assertFalse(review.attack_path_mutation_allowed)

    def test_oversized_raw_revised_review_is_rejected_before_json_parsing(self):
        raw = self._padded_canonical_review(_MAX_RAW_REVIEW_CHARS + 1)
        gateway, provider = self.base._gateway(raw)

        with mock.patch(
            "lightup.future_remediation_text_revision_review.json.loads",
            side_effect=AssertionError(
                "json.loads must not run for oversized revised-review output"
            ),
        ) as json_loads:
            with self.assertRaisesRegex(ValueError, "bounded response size"):
                self.base._review(gateway)

        json_loads.assert_not_called()
        self.assertEqual(len(provider.requests), 1)

    def test_normal_canonical_revised_review_remains_accepted(self):
        gateway, provider = self.base._gateway(review_tests._review_json())

        review = self.base._review(gateway)

        self.assertEqual(len(provider.requests), 1)
        self.assertTrue(review.review_completed)
        self.assertFalse(review.code_change_authorized)
        self.assertFalse(review.tool_call_created)
        self.assertFalse(review.execution_allowed)
        self.assertFalse(review.target_interaction_allowed)
        self.assertFalse(review.future_state_retest_allowed)
        self.assertFalse(review.deployment_authorized)
        self.assertFalse(review.attack_path_mutation_allowed)


if __name__ == "__main__":
    unittest.main()
