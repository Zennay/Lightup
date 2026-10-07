from __future__ import annotations

import json
import unittest

import test_future_remediation_text_review_handoff as handoff_tests
from lightup.future_remediation_text_review_handoff import (
    future_remediation_text_review_from_dict,
)


class FutureRemediationTextReviewSummaryCanonicalityAcceptanceTest(unittest.TestCase):
    def setUp(self):
        self.h = handoff_tests.FutureRemediationTextReviewHandoffTest(
            "test_approved_review_round_trips_without_action_authority"
        )
        self.h.setUp()
        self.addCleanup(self.h.tearDown)

    def test_canonical_producer_review_round_trips(self):
        payload = json.loads(self.h.review.to_json())
        self.assertEqual(
            future_remediation_text_review_from_dict(payload),
            self.h.review,
        )

    def test_summary_rejects_producer_impossible_outer_whitespace(self):
        original = self.h.review.summary
        for label, bad_value in (
            ("leading-space", f" {original}"),
            ("trailing-space", f"{original} "),
            ("outer-tab", f"\t{original}\t"),
        ):
            with self.subTest(shape=label):
                payload = json.loads(self.h.review.to_json())
                payload["summary"] = bad_value

                # Keep the original producer digest. The producer hashes the
                # already-stripped summary, while the current handoff strips
                # persisted input before digest verification. A strict persisted
                # boundary must reject these noncanonical bytes instead of
                # normalizing them back under the canonical digest.
                with self.assertRaisesRegex(
                    ValueError,
                    "summary|canonical|normalized|whitespace",
                ):
                    future_remediation_text_review_from_dict(payload)


if __name__ == "__main__":
    unittest.main()
