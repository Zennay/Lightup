from __future__ import annotations

import unittest

import test_future_remediation_text_proposal as proposal_tests
from lightup.future_remediation_text_review_request import (
    REMEDIATION_TEXT_REVIEW_REQUEST_SCHEMA_VERSION,
    REQUIRED_REVIEW_CHECKS,
    build_future_remediation_text_review_request,
)


class FutureRemediationTextReviewRequestTest(unittest.TestCase):
    def setUp(self):
        self.base = proposal_tests.FutureRemediationTextProposalTest(
            "test_live_valid_request_generates_bounded_non_executable_proposal"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        gateway, _ = self.base._gateway()
        self.proposal = self.base._generate(gateway)

    def _build(self, persisted=None):
        return build_future_remediation_text_review_request(
            self.proposal.to_json() if persisted is None else persisted,
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

    def test_live_valid_proposal_produces_review_only_request(self):
        review = self._build()

        self.assertEqual(
            review.schema_version,
            REMEDIATION_TEXT_REVIEW_REQUEST_SCHEMA_VERSION,
        )
        self.assertEqual(review.request_sha256, self.proposal.request_sha256)
        self.assertEqual(review.bundle_sha256, self.proposal.bundle_sha256)
        self.assertEqual(review.proposal_sha256, self.proposal.proposal_sha256)
        self.assertEqual(review.content_sha256, self.proposal.content_sha256)
        self.assertEqual(review.provider_id, self.proposal.provider_id)
        self.assertEqual(review.model_id, self.proposal.model_id)
        self.assertEqual(review.item_count, self.proposal.item_count)
        self.assertEqual(review.required_checks, REQUIRED_REVIEW_CHECKS)
        self.assertEqual(len(review.review_request_sha256), 64)

        self.assertTrue(review.review_requested)
        self.assertFalse(review.remediation_accepted)
        self.assertFalse(review.code_change_authorized)
        self.assertFalse(review.tool_call_created)
        self.assertFalse(review.execution_allowed)
        self.assertFalse(review.target_interaction_allowed)
        self.assertFalse(review.future_state_retest_allowed)
        self.assertFalse(review.deployment_authorized)
        self.assertFalse(review.attack_path_mutation_allowed)
        self.assertEqual(review.future_semantics, "unresolved")
        self.assertEqual(review.security_verdict, "not_evaluated")

    def test_review_request_is_deterministic_for_same_live_proposal(self):
        first = self._build()
        second = self._build()

        self.assertEqual(first, second)
        self.assertEqual(first.to_json(), second.to_json())

    def test_tampered_persisted_proposal_is_rejected_before_review_request(self):
        payload = self.proposal.as_dict()
        payload["content"] += " tampered"

        with self.assertRaisesRegex(ValueError, "content digest mismatch"):
            self._build(payload)

    def test_live_evidence_drift_is_rejected_before_review_request(self):
        evidence_id = self.base.bundle.items[0].evidence[0].evidence_id
        current_sha = self.base.bundle.items[0].evidence[0].sha256
        replacement = "f" * 64 if current_sha != "f" * 64 else "e" * 64
        with self.base.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                (replacement, evidence_id),
            )

        with self.assertRaises(ValueError):
            self._build()

    def test_review_request_contains_no_remediation_body_or_action_payload(self):
        review = self._build()
        serialized = review.to_json().lower()

        self.assertNotIn(self.proposal.content.lower(), serialized)
        for forbidden in (
            '"patch"',
            '"command"',
            '"tool_arguments"',
            '"target_arguments"',
            '"credentials"',
            '"source"',
            '"metadata"',
        ):
            self.assertNotIn(forbidden, serialized)


if __name__ == "__main__":
    unittest.main()
