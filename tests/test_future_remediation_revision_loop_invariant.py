from __future__ import annotations

import unittest

import test_future_remediation_text_revision_review_handoff as handoff_tests
from lightup.future_remediation_text_revision_review_handoff import (
    future_remediation_text_revision_review_from_dict,
)


_AUTHORITY_FLAGS = (
    "code_change_authorized",
    "tool_call_created",
    "execution_allowed",
    "target_interaction_allowed",
    "future_state_retest_allowed",
    "deployment_authorized",
    "attack_path_mutation_allowed",
)


class FutureRemediationRevisionLoopInvariantTest(unittest.TestCase):
    def setUp(self):
        self.base = handoff_tests.FutureRemediationTextRevisionReviewHandoffTest(
            "test_approved_review_round_trips_without_action_authority"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def _artifacts(self):
        final_review = self.base.review
        revised_review_request = self.base.base.base.request
        revised_proposal = self.base.base.base.base.base.proposal
        revision_request = (
            self.base.base.base.base.base.base.revision_request
        )
        return (
            revision_request,
            revised_proposal,
            revised_review_request,
            final_review,
        )

    def test_complete_revision_loop_never_grants_action_authority(self):
        (
            revision_request,
            revised_proposal,
            revised_review_request,
            final_review,
        ) = self._artifacts()

        self.assertTrue(revision_request.revision_requested)
        self.assertTrue(revised_proposal.remediation_revision_proposal_created)
        self.assertTrue(revised_review_request.review_requested)
        self.assertTrue(final_review.review_completed)
        self.assertTrue(final_review.remediation_accepted)

        for artifact in (
            revision_request,
            revised_proposal,
            revised_review_request,
            final_review,
        ):
            with self.subTest(artifact=type(artifact).__name__):
                for flag in _AUTHORITY_FLAGS:
                    self.assertFalse(getattr(artifact, flag), flag)
                self.assertEqual(artifact.future_semantics, "unresolved")
                self.assertEqual(artifact.security_verdict, "not_evaluated")

        self.assertFalse(revision_request.remediation_accepted)
        self.assertFalse(revised_proposal.remediation_accepted)
        self.assertFalse(revised_review_request.remediation_accepted)

    def test_approved_revised_prose_cannot_be_reinterpreted_as_execution(self):
        payload = self.base.review.as_dict()

        for field in _AUTHORITY_FLAGS:
            with self.subTest(field=field):
                widened = dict(payload)
                widened[field] = True
                with self.assertRaisesRegex(ValueError, "authority flag"):
                    future_remediation_text_revision_review_from_dict(widened)

    def test_live_evidence_drift_invalidates_final_persisted_review(self):
        evidence_id = (
            self.base.base.base.base.base.base.base.base.base.bundle.items[0]
            .evidence[0]
            .evidence_id
        )
        current_sha = (
            self.base.base.base.base.base.base.base.base.base.bundle.items[0]
            .evidence[0]
            .sha256
        )
        replacement = "f" * 64 if current_sha != "f" * 64 else "e" * 64
        with self.base.base.base.base.base.base.base.base.base.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                (replacement, evidence_id),
            )

        with self.assertRaises(ValueError):
            self.base._load()

    def test_revision_loop_keeps_review_acceptance_separate_from_verdict(self):
        final_review = self.base.review

        self.assertTrue(final_review.remediation_accepted)
        self.assertEqual(final_review.future_semantics, "unresolved")
        self.assertEqual(final_review.security_verdict, "not_evaluated")
        self.assertFalse(final_review.future_state_retest_allowed)
        self.assertFalse(final_review.deployment_authorized)
        self.assertFalse(final_review.attack_path_mutation_allowed)


if __name__ == "__main__":
    unittest.main()
