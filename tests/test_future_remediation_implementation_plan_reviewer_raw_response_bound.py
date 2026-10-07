from __future__ import annotations

import unittest
from unittest.mock import patch

import test_future_remediation_implementation_plan_review as review_tests
import lightup.future_remediation_implementation_plan_review as review_module


_RAW_RESPONSE_LIMIT = 32_768


class FutureRemediationImplementationPlanReviewerRawResponseBoundTest(unittest.TestCase):
    def test_exact_raw_response_bound_remains_parseable(self):
        canonical = review_tests._review_json(summary="bounded")
        self.assertLess(len(canonical), _RAW_RESPONSE_LIMIT)
        raw = (" " * (_RAW_RESPONSE_LIMIT - len(canonical))) + canonical
        self.assertEqual(len(raw), _RAW_RESPONSE_LIMIT)

        decision, checks, summary = review_module._parse_reviewer_content(raw)

        self.assertEqual(decision.value, "approved")
        self.assertEqual(len(checks), 5)
        self.assertEqual(summary, "bounded")

    def test_oversized_raw_response_fails_before_json_parser(self):
        canonical = review_tests._review_json(summary="bounded")
        raw = (" " * (_RAW_RESPONSE_LIMIT + 1 - len(canonical))) + canonical
        self.assertEqual(len(raw), _RAW_RESPONSE_LIMIT + 1)

        with patch.object(
            review_module.json,
            "loads",
            side_effect=AssertionError("JSON parser must not receive oversized response"),
        ):
            with self.assertRaisesRegex(ValueError, "bounded"):
                review_module._parse_reviewer_content(raw)


if __name__ == "__main__":
    unittest.main()
