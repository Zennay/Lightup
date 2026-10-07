from __future__ import annotations

import copy
import json
import unittest

import test_future_remediation_text_review_request_handoff as handoff_tests
from lightup.future_remediation_text_review_request_handoff import (
    future_remediation_text_review_request_from_dict,
)


class FutureRemediationTextReviewRequestParserPurityTest(unittest.TestCase):
    def setUp(self):
        self.base = handoff_tests.FutureRemediationTextReviewRequestHandoffTest(
            "test_round_trip_rebuilds_exact_live_review_request"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.request = self.base.review_request

    @staticmethod
    def _shape(payload: dict) -> tuple:
        return (
            id(payload),
            id(payload["required_checks"]),
            tuple(payload.keys()),
        )

    def _assert_success_is_pure(self, payload: dict):
        before = copy.deepcopy(payload)
        shape = self._shape(payload)

        parsed = future_remediation_text_review_request_from_dict(payload)

        self.assertEqual(parsed, self.request)
        self.assertEqual(payload, before)
        self.assertEqual(self._shape(payload), shape)
        return parsed

    def test_json_list_and_programmatic_tuple_success_are_pure(self):
        payloads = (
            json.loads(self.request.to_json()),
            self.request.as_dict(),
        )

        for payload in payloads:
            with self.subTest(container=type(payload["required_checks"]).__name__):
                first = self._assert_success_is_pure(payload)
                second = self._assert_success_is_pure(payload)
                self.assertEqual(first, second)

    def test_late_digest_rejection_is_repeatably_pure(self):
        payload = self.request.as_dict()
        payload["review_request_sha256"] = "0" * 64
        before = copy.deepcopy(payload)
        shape = self._shape(payload)

        errors = []
        for _ in range(2):
            with self.assertRaisesRegex(ValueError, "digest mismatch") as caught:
                future_remediation_text_review_request_from_dict(payload)
            errors.append(str(caught.exception))
            self.assertEqual(payload, before)
            self.assertEqual(self._shape(payload), shape)

        self.assertEqual(errors[0], errors[1])

    def test_rubric_rejection_is_repeatably_pure(self):
        payload = self.request.as_dict()
        payload["required_checks"] = tuple(reversed(payload["required_checks"]))
        before = copy.deepcopy(payload)
        shape = self._shape(payload)

        errors = []
        for _ in range(2):
            with self.assertRaisesRegex(ValueError, "required_checks mismatch") as caught:
                future_remediation_text_review_request_from_dict(payload)
            errors.append(str(caught.exception))
            self.assertEqual(payload, before)
            self.assertEqual(self._shape(payload), shape)

        self.assertEqual(errors[0], errors[1])

    def test_authority_rejection_is_repeatably_pure(self):
        payload = json.loads(self.request.to_json())
        payload["execution_allowed"] = True
        before = copy.deepcopy(payload)
        shape = self._shape(payload)

        errors = []
        for _ in range(2):
            with self.assertRaisesRegex(ValueError, "authority flag") as caught:
                future_remediation_text_review_request_from_dict(payload)
            errors.append(str(caught.exception))
            self.assertEqual(payload, before)
            self.assertEqual(self._shape(payload), shape)

        self.assertEqual(errors[0], errors[1])


if __name__ == "__main__":
    unittest.main()
