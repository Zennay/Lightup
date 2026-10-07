from __future__ import annotations

import copy
import json
import unittest

import test_future_remediation_text_review_handoff as handoff_tests
from lightup.future_remediation_text_review_handoff import (
    future_remediation_text_review_from_dict,
)


class FutureRemediationTextReviewParserPurityTest(unittest.TestCase):
    def setUp(self):
        self.base = handoff_tests.FutureRemediationTextReviewHandoffTest(
            "test_approved_review_round_trips_without_action_authority"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.review = self.base.review

    @staticmethod
    def _shape(payload: dict) -> tuple:
        return (
            id(payload),
            id(payload["checks"]),
            tuple(id(check) for check in payload["checks"]),
            tuple(payload.keys()),
            tuple(tuple(check.keys()) for check in payload["checks"]),
        )

    def _assert_success_is_pure(self, payload: dict):
        before = copy.deepcopy(payload)
        shape = self._shape(payload)

        parsed = future_remediation_text_review_from_dict(payload)

        self.assertEqual(parsed, self.review)
        self.assertEqual(payload, before)
        self.assertEqual(self._shape(payload), shape)
        return parsed

    def test_json_list_and_programmatic_tuple_success_are_pure(self):
        payloads = (
            json.loads(self.review.to_json()),
            self.review.as_dict(),
        )

        for payload in payloads:
            with self.subTest(container=type(payload["checks"]).__name__):
                first = self._assert_success_is_pure(payload)
                second = self._assert_success_is_pure(payload)
                self.assertEqual(first, second)

    def test_late_digest_rejection_is_repeatably_pure(self):
        payload = self.review.as_dict()
        payload["review_sha256"] = "0" * 64
        before = copy.deepcopy(payload)
        shape = self._shape(payload)

        errors = []
        for _ in range(2):
            with self.assertRaisesRegex(ValueError, "digest mismatch") as caught:
                future_remediation_text_review_from_dict(payload)
            errors.append(str(caught.exception))
            self.assertEqual(payload, before)
            self.assertEqual(self._shape(payload), shape)

        self.assertEqual(errors[0], errors[1])

    def test_nested_check_coherence_rejection_is_repeatably_pure(self):
        payload = self.review.as_dict()
        payload["checks"][0]["result"] = "fail"
        before = copy.deepcopy(payload)
        shape = self._shape(payload)

        errors = []
        for _ in range(2):
            with self.assertRaisesRegex(ValueError, "every check to pass") as caught:
                future_remediation_text_review_from_dict(payload)
            errors.append(str(caught.exception))
            self.assertEqual(payload, before)
            self.assertEqual(self._shape(payload), shape)

        self.assertEqual(errors[0], errors[1])

    def test_authority_rejection_is_repeatably_pure(self):
        payload = json.loads(self.review.to_json())
        payload["execution_allowed"] = True
        before = copy.deepcopy(payload)
        shape = self._shape(payload)

        errors = []
        for _ in range(2):
            with self.assertRaisesRegex(ValueError, "authority flag") as caught:
                future_remediation_text_review_from_dict(payload)
            errors.append(str(caught.exception))
            self.assertEqual(payload, before)
            self.assertEqual(self._shape(payload), shape)

        self.assertEqual(errors[0], errors[1])


if __name__ == "__main__":
    unittest.main()
