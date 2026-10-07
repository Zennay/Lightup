from __future__ import annotations

import copy
import json
import unittest

import test_future_remediation_text_revision_review_request_handoff as handoff_tests
from lightup.future_remediation_text_revision_review_request_handoff import (
    future_remediation_text_revision_review_request_from_dict,
)


class FutureRemediationTextRevisionReviewRequestParserPurityTest(unittest.TestCase):
    def setUp(self):
        self.base = handoff_tests.FutureRemediationTextRevisionReviewRequestHandoffTest(
            "test_round_trip_rebuilds_exact_live_review_request"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.request = self.base.request
        self.json_payload = json.loads(self.request.to_json())
        self.programmatic_payload = self.request.as_dict()

    @staticmethod
    def _fingerprint(payload):
        checks = payload["required_checks"]
        return {
            "value": copy.deepcopy(payload),
            "root_id": id(payload),
            "checks_id": id(checks),
            "root_key_order": tuple(payload.keys()),
            "checks_value": tuple(checks),
        }

    def _assert_fingerprint_unchanged(self, payload, before):
        after = self._fingerprint(payload)
        self.assertEqual(after["value"], before["value"])
        self.assertEqual(after["root_id"], before["root_id"])
        self.assertEqual(after["checks_id"], before["checks_id"])
        self.assertEqual(after["root_key_order"], before["root_key_order"])
        self.assertEqual(after["checks_value"], before["checks_value"])

    def test_successful_json_and_programmatic_parsing_preserve_caller_objects(self):
        cases = (
            ("json", self.json_payload, list),
            ("programmatic", self.programmatic_payload, tuple),
        )
        for name, payload, expected_checks_type in cases:
            with self.subTest(name=name):
                before = self._fingerprint(payload)
                parsed = (
                    future_remediation_text_revision_review_request_from_dict(payload)
                )

                self.assertEqual(parsed, self.request)
                self.assertIs(type(payload["required_checks"]), expected_checks_type)
                self._assert_fingerprint_unchanged(payload, before)

    def test_repeated_success_on_same_object_is_deterministic_and_pure(self):
        payload = self.json_payload
        before = self._fingerprint(payload)

        first = future_remediation_text_revision_review_request_from_dict(payload)
        second = future_remediation_text_revision_review_request_from_dict(payload)

        self.assertEqual(first, self.request)
        self.assertEqual(second, self.request)
        self.assertEqual(first, second)
        self._assert_fingerprint_unchanged(payload, before)

    def test_late_digest_mismatch_rejection_preserves_caller_objects(self):
        payload = copy.deepcopy(self.json_payload)
        payload["review_request_sha256"] = "0" * 64
        before = self._fingerprint(payload)

        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            future_remediation_text_revision_review_request_from_dict(payload)

        self._assert_fingerprint_unchanged(payload, before)

    def test_rubric_rejection_preserves_caller_objects(self):
        payload = copy.deepcopy(self.json_payload)
        payload["required_checks"][0] = "different_check"
        before = self._fingerprint(payload)

        with self.assertRaisesRegex(ValueError, "required_checks mismatch"):
            future_remediation_text_revision_review_request_from_dict(payload)

        self._assert_fingerprint_unchanged(payload, before)

    def test_authority_rejection_preserves_caller_objects(self):
        payload = copy.deepcopy(self.json_payload)
        payload["execution_allowed"] = True
        before = self._fingerprint(payload)

        with self.assertRaisesRegex(ValueError, "authority flag"):
            future_remediation_text_revision_review_request_from_dict(payload)

        self._assert_fingerprint_unchanged(payload, before)

    def test_repeated_rejection_is_deterministic_and_pure(self):
        payload = copy.deepcopy(self.json_payload)
        payload["review_request_sha256"] = "0" * 64
        before = self._fingerprint(payload)

        messages = []
        for _ in range(2):
            with self.assertRaises(ValueError) as raised:
                future_remediation_text_revision_review_request_from_dict(payload)
            messages.append(str(raised.exception))
            self._assert_fingerprint_unchanged(payload, before)

        self.assertEqual(messages[0], messages[1])
        self.assertIn("digest mismatch", messages[0])


if __name__ == "__main__":
    unittest.main()
