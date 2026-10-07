from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
import unittest

import test_future_remediation_text_review_handoff as handoff_tests
from lightup.future_remediation_text_review_handoff import (
    future_remediation_text_review_from_dict,
)


def _rehash_review(payload: dict) -> None:
    digest_payload = deepcopy(payload)
    digest_payload.pop("review_sha256")
    payload["review_sha256"] = sha256(
        json.dumps(
            digest_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


class FutureRemediationTextReviewModelIdentityAcceptanceTest(unittest.TestCase):
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

    def test_reviewer_model_id_rejects_producer_impossible_outer_whitespace(self):
        original = self.h.review.reviewer_model_id
        for label, bad_value in (
            ("leading-space", f" {original}"),
            ("trailing-space", f"{original} "),
            ("outer-tab", f"\t{original}\t"),
        ):
            with self.subTest(shape=label):
                payload = json.loads(self.h.review.to_json())
                payload["reviewer_model_id"] = bad_value
                _rehash_review(payload)

                with self.assertRaisesRegex(
                    ValueError,
                    "reviewer_model_id|model|canonical|normalized|whitespace",
                ):
                    future_remediation_text_review_from_dict(payload)


if __name__ == "__main__":
    unittest.main()
