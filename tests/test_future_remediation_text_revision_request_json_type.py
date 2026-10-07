from __future__ import annotations

import unittest

import test_future_remediation_text_revision_request as revision_tests
import test_future_remediation_text_review as review_tests
from lightup.future_remediation_text_revision_request_handoff import (
    future_remediation_text_revision_request_from_json,
)


class _StringSubclass(str):
    pass


class FutureRemediationTextRevisionRequestJsonTypeTest(unittest.TestCase):
    def setUp(self):
        self.base = revision_tests.FutureRemediationTextRevisionRequestTest(
            "test_revision_required_creates_bounded_non_executable_request"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        review = self.base._review(
            review_tests._review_json(
                decision="revision_required",
                unsupported_claims="fail",
            )
        )
        self.request = self.base._build(review)

    def test_exact_builtin_json_remains_valid(self):
        raw = self.request.to_json()
        parsed = future_remediation_text_revision_request_from_json(raw)
        self.assertEqual(parsed, self.request)
        self.assertIs(type(raw), str)

    def test_string_subclass_is_rejected_before_decode(self):
        raw = self.request.to_json()
        adversarial = _StringSubclass(raw)
        with self.assertRaises(ValueError):
            future_remediation_text_revision_request_from_json(adversarial)
        self.assertEqual(adversarial, raw)
        self.assertIs(type(adversarial), _StringSubclass)


if __name__ == "__main__":
    unittest.main()
