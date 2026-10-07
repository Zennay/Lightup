from __future__ import annotations

import unittest
from unittest import mock

import test_future_remediation_text_proposal as proposal_tests
import lightup.future_remediation_text_review_request_handoff as handoff
from lightup.future_remediation_text_review_request import (
    build_future_remediation_text_review_request,
)


class _PersistedText(str):
    pass


class _PersistedMapping(dict):
    pass


class RemediationReviewRequestPersistedConsumerRuntimeTypeTest(unittest.TestCase):
    def setUp(self):
        self.base = proposal_tests.FutureRemediationTextProposalTest(
            "test_live_valid_request_generates_bounded_non_executable_proposal"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        gateway, _ = self.base._gateway()
        self.proposal = self.base._generate(gateway)
        self.review_request = build_future_remediation_text_review_request(
            self.proposal.to_json(),
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

    def _load(self, persisted_review_request: object):
        return handoff.load_and_validate_future_remediation_text_review_request(
            persisted_review_request,
            self.proposal.to_json(),
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

    def test_exact_builtin_persisted_forms_remain_green(self):
        self.assertEqual(self._load(self.review_request.to_json()), self.review_request)
        self.assertEqual(self._load(self.review_request.as_dict()), self.review_request)

    def test_string_subclass_fails_before_json_parser_dispatch(self):
        canonical = self.review_request.to_json()
        persisted = _PersistedText(canonical)

        with mock.patch.object(
            handoff,
            "future_remediation_text_review_request_from_json",
            side_effect=AssertionError(
                "JSON parser must not receive a str subclass"
            ),
        ):
            with self.assertRaises(ValueError):
                self._load(persisted)

        self.assertEqual(str(persisted), canonical)
        self.assertFalse(self.review_request.execution_allowed)
        self.assertFalse(self.review_request.target_interaction_allowed)

    def test_mapping_subclass_fails_before_direct_parser_dispatch(self):
        canonical = self.review_request.as_dict()
        persisted = _PersistedMapping(canonical)
        before = dict(persisted)

        with mock.patch.object(
            handoff,
            "future_remediation_text_review_request_from_dict",
            side_effect=AssertionError(
                "direct parser must not receive a dict subclass"
            ),
        ):
            with self.assertRaises(ValueError):
                self._load(persisted)

        self.assertEqual(persisted, before)
        self.assertFalse(self.review_request.execution_allowed)
        self.assertFalse(self.review_request.target_interaction_allowed)


if __name__ == "__main__":
    unittest.main()
