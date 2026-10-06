from __future__ import annotations

import unittest

import test_future_remediation_text_review as review_tests
from lightup.future_remediation_text_review_handoff import (
    load_and_validate_future_remediation_text_review,
)


class FutureRemediationReviewChainInvariantTest(unittest.TestCase):
    def setUp(self):
        self.base = review_tests.FutureRemediationTextReviewTest(
            "test_all_pass_review_accepts_text_without_action_authority"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def _strict_review(self, reviewer_content: str):
        gateway, _ = self.base._review_gateway(reviewer_content)
        review = self.base._review(gateway)
        strict = load_and_validate_future_remediation_text_review(
            review.to_json(),
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
        return review, strict

    def test_approved_text_never_becomes_action_authority(self):
        review, strict = self._strict_review(review_tests._review_json())

        self.assertEqual(strict, review)
        self.assertTrue(strict.review_completed)
        self.assertTrue(strict.remediation_accepted)
        self.assertFalse(strict.code_change_authorized)
        self.assertFalse(strict.tool_call_created)
        self.assertFalse(strict.execution_allowed)
        self.assertFalse(strict.target_interaction_allowed)
        self.assertFalse(strict.future_state_retest_allowed)
        self.assertFalse(strict.deployment_authorized)
        self.assertFalse(strict.attack_path_mutation_allowed)
        self.assertEqual(strict.future_semantics, "unresolved")
        self.assertEqual(strict.security_verdict, "not_evaluated")

    def test_nonapproved_review_results_remain_unaccepted_and_non_executable(self):
        cases = (
            review_tests._review_json(
                decision="revision_required",
                least_privilege="fail",
            ),
            review_tests._review_json(
                decision="insufficient_evidence",
                evidence_alignment="unclear",
            ),
        )
        for content in cases:
            with self.subTest(content=content):
                _, strict = self._strict_review(content)
                self.assertFalse(strict.remediation_accepted)
                self.assertFalse(strict.execution_allowed)
                self.assertFalse(strict.target_interaction_allowed)
                self.assertFalse(strict.future_state_retest_allowed)
                self.assertFalse(strict.deployment_authorized)
                self.assertEqual(strict.security_verdict, "not_evaluated")

    def test_live_evidence_drift_breaks_review_chain_before_reuse(self):
        review, strict = self._strict_review(review_tests._review_json())
        self.assertTrue(strict.remediation_accepted)

        evidence_id = self.base.base.bundle.items[0].evidence[0].evidence_id
        current_sha = self.base.base.bundle.items[0].evidence[0].sha256
        replacement = "f" * 64 if current_sha != "f" * 64 else "e" * 64
        with self.base.base.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                (replacement, evidence_id),
            )

        with self.assertRaises(ValueError):
            load_and_validate_future_remediation_text_review(
                review.to_json(),
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

    def test_persisted_review_contains_no_execution_or_target_payload(self):
        _, strict = self._strict_review(review_tests._review_json())
        serialized = strict.to_json().lower()

        for forbidden in (
            '"patch"',
            '"command"',
            '"tool_arguments"',
            '"target_arguments"',
            '"credentials"',
            '"authorization_ref"',
        ):
            self.assertNotIn(forbidden, serialized)


if __name__ == "__main__":
    unittest.main()
