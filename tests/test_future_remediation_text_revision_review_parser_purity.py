from __future__ import annotations

import copy
import json
import unittest

import test_future_remediation_text_revision_review_handoff as handoff_tests
from lightup.future_remediation_text_revision_review_handoff import (
    future_remediation_text_revision_review_from_dict,
)


class FutureRemediationTextRevisionReviewParserPurityTest(unittest.TestCase):
    def setUp(self):
        self.base = handoff_tests.FutureRemediationTextRevisionReviewHandoffTest(
            "test_approved_review_round_trips_without_action_authority"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.review = self.base.review
        self.json_payload = json.loads(self.review.to_json())
        self.programmatic_payload = self.review.as_dict()

    @staticmethod
    def _fingerprint(payload):
        checks = payload["checks"]
        return {
            "value": copy.deepcopy(payload),
            "root_id": id(payload),
            "checks_id": id(checks),
            "check_ids": tuple(id(check) for check in checks),
            "root_key_order": tuple(payload.keys()),
            "check_key_orders": tuple(tuple(check.keys()) for check in checks),
        }

    def _assert_fingerprint_unchanged(self, payload, before):
        after = self._fingerprint(payload)
        self.assertEqual(after["value"], before["value"])
        self.assertEqual(after["root_id"], before["root_id"])
        self.assertEqual(after["checks_id"], before["checks_id"])
        self.assertEqual(after["check_ids"], before["check_ids"])
        self.assertEqual(after["root_key_order"], before["root_key_order"])
        self.assertEqual(after["check_key_orders"], before["check_key_orders"])

    def test_successful_json_and_programmatic_parsing_preserve_caller_objects(self):
        cases = (
            ("json", self.json_payload, list),
            ("programmatic", self.programmatic_payload, tuple),
        )
        for name, payload, expected_checks_type in cases:
            with self.subTest(name=name):
                before = self._fingerprint(payload)
                parsed = future_remediation_text_revision_review_from_dict(payload)

                self.assertEqual(parsed, self.review)
                self.assertIs(type(payload["checks"]), expected_checks_type)
                self._assert_fingerprint_unchanged(payload, before)

    def test_repeated_success_on_same_object_is_deterministic_and_pure(self):
        payload = self.json_payload
        before = self._fingerprint(payload)

        first = future_remediation_text_revision_review_from_dict(payload)
        middle = self._fingerprint(payload)
        second = future_remediation_text_revision_review_from_dict(payload)

        self.assertEqual(first, self.review)
        self.assertEqual(second, self.review)
        self.assertEqual(first, second)
        self.assertEqual(middle, before)
        self._assert_fingerprint_unchanged(payload, before)

    def test_late_digest_mismatch_rejection_preserves_caller_objects(self):
        payload = copy.deepcopy(self.json_payload)
        payload["review_sha256"] = "0" * 64
        before = self._fingerprint(payload)

        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            future_remediation_text_revision_review_from_dict(payload)

        self._assert_fingerprint_unchanged(payload, before)

    def test_nested_coherence_rejection_preserves_caller_objects(self):
        payload = copy.deepcopy(self.json_payload)
        payload["checks"][0]["result"] = "fail"
        before = self._fingerprint(payload)

        with self.assertRaisesRegex(ValueError, "every check to pass"):
            future_remediation_text_revision_review_from_dict(payload)

        self._assert_fingerprint_unchanged(payload, before)

    def test_authority_rejection_preserves_caller_objects(self):
        payload = copy.deepcopy(self.json_payload)
        payload["execution_allowed"] = True
        before = self._fingerprint(payload)

        with self.assertRaisesRegex(ValueError, "authority flag"):
            future_remediation_text_revision_review_from_dict(payload)

        self._assert_fingerprint_unchanged(payload, before)

    def test_repeated_rejection_is_deterministic_and_pure(self):
        payload = copy.deepcopy(self.json_payload)
        payload["review_sha256"] = "0" * 64
        before = self._fingerprint(payload)

        messages = []
        for _ in range(2):
            with self.assertRaises(ValueError) as raised:
                future_remediation_text_revision_review_from_dict(payload)
            messages.append(str(raised.exception))
            self._assert_fingerprint_unchanged(payload, before)

        self.assertEqual(messages[0], messages[1])
        self.assertIn("digest mismatch", messages[0])


if __name__ == "__main__":
    unittest.main()
