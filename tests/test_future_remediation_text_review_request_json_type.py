from __future__ import annotations

import unittest

import test_future_remediation_text_proposal as proposal_tests
from lightup.future_remediation_text_review_request import (
    build_future_remediation_text_review_request,
)
from lightup.future_remediation_text_review_request_handoff import (
    future_remediation_text_review_request_from_json,
)


class _StringSubclass(str):
    pass


class FutureRemediationTextReviewRequestJsonTypeTest(unittest.TestCase):
    def setUp(self):
        self.base = proposal_tests.FutureRemediationTextProposalTest(
            "test_live_valid_request_generates_bounded_non_executable_proposal"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        gateway, _ = self.base._gateway()
        proposal = self.base._generate(gateway)
        self.review_request = build_future_remediation_text_review_request(
            proposal.to_json(),
            self.base.request,
            self.base.bundle,
            self.base.plan,
            self.base.report,
            self.base.preview,
            self.base.transition_proposal,
            (self.base.resolution,),
            (self.base.context,),
            self.base.state,
        )

    def test_exact_builtin_json_remains_valid(self):
        raw = self.review_request.to_json()
        parsed = future_remediation_text_review_request_from_json(raw)
        self.assertEqual(parsed, self.review_request)
        self.assertIs(type(raw), str)

    def test_string_subclass_is_rejected_before_decode(self):
        raw = self.review_request.to_json()
        adversarial = _StringSubclass(raw)
        with self.assertRaises(ValueError):
            future_remediation_text_review_request_from_json(adversarial)
        self.assertEqual(adversarial, raw)
        self.assertIs(type(adversarial), _StringSubclass)


if __name__ == "__main__":
    unittest.main()
