from __future__ import annotations

import unittest
from unittest import mock

import test_future_remediation_text_review as review_tests
import lightup.future_remediation_text_review_handoff as handoff


class _PersistedText(str):
    pass


class _PersistedMapping(dict):
    pass


class RemediationReviewPersistedConsumerRuntimeTypeTest(unittest.TestCase):
    def setUp(self):
        self.base = review_tests.FutureRemediationTextReviewTest(
            "test_all_pass_review_accepts_text_without_action_authority"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        gateway, _ = self.base._review_gateway(review_tests._review_json())
        self.review = self.base._review(gateway)

    def _load(self, persisted_review: object):
        return handoff.load_and_validate_future_remediation_text_review(
            persisted_review,
            self.base.review_request.to_json(),
            self.base.proposal.to_json(),
            self.base.base.request,
            self.base.base.bundle,
            self.base.base.plan,
            self.base.base.report,
            self.base.base.preview,
            self.base.base.transition_proposal,
            (self.base.base.resolution,),
            (self.base.base.context,),
            self.base.base.state,
        )

    def test_exact_builtin_persisted_forms_remain_green(self):
        self.assertEqual(self._load(self.review.to_json()), self.review)
        self.assertEqual(self._load(self.review.as_dict()), self.review)

    def test_string_subclass_fails_before_json_parser_dispatch(self):
        canonical = self.review.to_json()
        persisted = _PersistedText(canonical)

        with mock.patch.object(
            handoff,
            "future_remediation_text_review_from_json",
            side_effect=AssertionError("JSON parser must not receive a str subclass"),
        ):
            with self.assertRaises(ValueError):
                self._load(persisted)

        self.assertEqual(str(persisted), canonical)
        self.assertFalse(self.review.execution_allowed)
        self.assertFalse(self.review.target_interaction_allowed)

    def test_mapping_subclass_fails_before_direct_parser_dispatch(self):
        canonical = self.review.as_dict()
        persisted = _PersistedMapping(canonical)
        before = dict(persisted)

        with mock.patch.object(
            handoff,
            "future_remediation_text_review_from_dict",
            side_effect=AssertionError("direct parser must not receive a dict subclass"),
        ):
            with self.assertRaises(ValueError):
                self._load(persisted)

        self.assertEqual(persisted, before)
        self.assertFalse(self.review.execution_allowed)
        self.assertFalse(self.review.target_interaction_allowed)


if __name__ == "__main__":
    unittest.main()
