from __future__ import annotations

import unittest

import test_future_remediation_text_review as review_tests
import test_future_remediation_text_revision_review as revision_review_tests
from lightup.future_remediation_text_revision_review_handoff import (
    future_remediation_text_revision_review_from_json,
)


class _StringSubclass(str):
    pass


class FutureRemediationTextRevisionReviewJsonTypeTest(unittest.TestCase):
    def setUp(self):
        self.base = revision_review_tests.FutureRemediationTextRevisionReviewTest(
            "test_all_pass_review_accepts_revised_text_without_action_authority"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        gateway, _ = self.base._gateway(review_tests._review_json())
        self.review = self.base._review(gateway)

    def test_exact_builtin_json_remains_valid(self):
        raw = self.review.to_json()
        parsed = future_remediation_text_revision_review_from_json(raw)
        self.assertEqual(parsed, self.review)
        self.assertIs(type(raw), str)

    def test_string_subclass_is_rejected_before_decode(self):
        raw = self.review.to_json()
        adversarial = _StringSubclass(raw)
        with self.assertRaises(ValueError):
            future_remediation_text_revision_review_from_json(adversarial)
        self.assertEqual(adversarial, raw)
        self.assertIs(type(adversarial), _StringSubclass)


if __name__ == "__main__":
    unittest.main()
