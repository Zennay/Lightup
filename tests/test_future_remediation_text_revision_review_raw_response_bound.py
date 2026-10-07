from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from lightup.future_remediation_text_revision_review import _parse_reviewer_content
from lightup.future_remediation_text_review import RemediationTextReviewDecision
from lightup.future_remediation_text_review_request import REQUIRED_REVIEW_CHECKS


RAW_REVISION_REVIEW_RESPONSE_CHAR_LIMIT = 32_768


class RevisedRemediationReviewRawResponseBoundAcceptanceTest(unittest.TestCase):
    def _canonical_raw(
        self,
        *,
        summary: str = "The revised proposal addresses the required review checks.",
    ) -> str:
        return json.dumps(
            {
                "decision": "approved",
                "check_results": {
                    check: "pass" for check in REQUIRED_REVIEW_CHECKS
                },
                "summary": summary,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    def test_canonical_revised_reviewer_response_remains_green(self) -> None:
        raw = self._canonical_raw()

        decision, checks, summary = _parse_reviewer_content(raw)

        self.assertIs(decision, RemediationTextReviewDecision.APPROVED)
        self.assertEqual(
            tuple(check.check for check in checks),
            tuple(REQUIRED_REVIEW_CHECKS),
        )
        self.assertEqual(
            summary,
            "The revised proposal addresses the required review checks.",
        )
        self.assertLessEqual(
            len(raw),
            RAW_REVISION_REVIEW_RESPONSE_CHAR_LIMIT,
        )

    def test_oversized_raw_response_fails_before_json_parser(self) -> None:
        raw = self._canonical_raw(
            summary="x" * RAW_REVISION_REVIEW_RESPONSE_CHAR_LIMIT,
        )
        self.assertGreater(
            len(raw),
            RAW_REVISION_REVIEW_RESPONSE_CHAR_LIMIT,
        )

        with patch(
            "lightup.future_remediation_text_revision_review.json.loads",
            side_effect=AssertionError("oversized response reached json.loads"),
        ) as loads:
            with self.assertRaisesRegex(
                ValueError,
                "reviewer response|raw response|bounded size|response size",
            ):
                _parse_reviewer_content(raw)

        loads.assert_not_called()


if __name__ == "__main__":
    unittest.main()
