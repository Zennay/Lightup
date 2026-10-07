from __future__ import annotations

import unittest
from unittest import mock

import test_future_remediation_text_revision_request as revision_tests
import test_future_remediation_text_review as review_tests
import lightup.future_remediation_text_revision_request_handoff as handoff


class _PersistedText(str):
    pass


class _PersistedMapping(dict):
    pass


class RemediationRevisionRequestPersistedConsumerRuntimeTypeTest(unittest.TestCase):
    def setUp(self):
        self.base = revision_tests.FutureRemediationTextRevisionRequestTest(
            "test_revision_required_creates_bounded_non_executable_request"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.review = self.base._review(
            review_tests._review_json(
                decision="revision_required",
                unsupported_claims="fail",
            )
        )
        self.request = self.base._build(self.review)

    def _load(self, persisted_revision_request: object):
        return handoff.load_and_validate_future_remediation_text_revision_request(
            persisted_revision_request,
            self.review.to_json(),
            self.base.base.review_request.to_json(),
            self.base.base.proposal.to_json(),
            self.base.base.base.request,
            self.base.base.base.bundle,
            self.base.base.base.plan,
            self.base.base.base.report,
            self.base.base.base.preview,
            self.base.base.base.transition_proposal,
            (self.base.base.base.resolution,),
            (self.base.base.base.context,),
            self.base.base.base.state,
        )

    def test_exact_builtin_persisted_forms_remain_green(self):
        self.assertEqual(self._load(self.request.to_json()), self.request)
        self.assertEqual(self._load(self.request.as_dict()), self.request)

    def test_string_subclass_fails_before_json_parser_dispatch(self):
        canonical = self.request.to_json()
        persisted = _PersistedText(canonical)

        with mock.patch.object(
            handoff,
            "future_remediation_text_revision_request_from_json",
            side_effect=AssertionError(
                "JSON parser must not receive a str subclass"
            ),
        ):
            with self.assertRaises(ValueError):
                self._load(persisted)

        self.assertEqual(str(persisted), canonical)
        self.assertFalse(self.request.execution_allowed)
        self.assertFalse(self.request.target_interaction_allowed)

    def test_mapping_subclass_fails_before_direct_parser_dispatch(self):
        canonical = self.request.as_dict()
        persisted = _PersistedMapping(canonical)
        before = dict(persisted)

        with mock.patch.object(
            handoff,
            "future_remediation_text_revision_request_from_dict",
            side_effect=AssertionError(
                "direct parser must not receive a dict subclass"
            ),
        ):
            with self.assertRaises(ValueError):
                self._load(persisted)

        self.assertEqual(persisted, before)
        self.assertFalse(self.request.execution_allowed)
        self.assertFalse(self.request.target_interaction_allowed)


if __name__ == "__main__":
    unittest.main()
