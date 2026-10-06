from __future__ import annotations

from dataclasses import replace
import unittest

import test_future_remediation_text_revision_review_handoff as handoff_tests
from lightup.future_remediation_text_review import RemediationTextReviewDecision


_AUTHORITY_FLAGS = (
    "code_change_authorized",
    "tool_call_created",
    "execution_allowed",
    "target_interaction_allowed",
    "future_state_retest_allowed",
    "deployment_authorized",
    "attack_path_mutation_allowed",
)


class FutureRemediationRevisionDirectConstructionTest(unittest.TestCase):
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
        revision_request = self.base.base.base.base.base.base.revision_request
        return (
            revision_request,
            revised_proposal,
            revised_review_request,
            final_review,
        )

    def test_direct_construction_rejects_authority_widening(self):
        for artifact in self._artifacts():
            for field in _AUTHORITY_FLAGS:
                with self.subTest(artifact=type(artifact).__name__, field=field):
                    with self.assertRaisesRegex(ValueError, "authority flag"):
                        replace(artifact, **{field: True})

    def test_direct_construction_rejects_bool_int_authority_confusion(self):
        for artifact in self._artifacts():
            with self.subTest(artifact=type(artifact).__name__):
                with self.assertRaisesRegex(ValueError, "authority flag"):
                    replace(artifact, execution_allowed=0)

    def test_direct_construction_rejects_lifecycle_forgery(self):
        revision_request, revised_proposal, revised_review_request, final_review = (
            self._artifacts()
        )

        cases = (
            (revision_request, {"revision_requested": False}),
            (revision_request, {"remediation_accepted": True}),
            (revision_request, {"review_decision": "approved"}),
            (
                revised_proposal,
                {"remediation_revision_proposal_created": False},
            ),
            (revised_proposal, {"remediation_accepted": True}),
            (revised_review_request, {"review_requested": False}),
            (revised_review_request, {"remediation_accepted": True}),
            (final_review, {"review_completed": False}),
            (final_review, {"remediation_accepted": False}),
        )
        for artifact, changes in cases:
            with self.subTest(artifact=type(artifact).__name__, changes=changes):
                with self.assertRaises(ValueError):
                    replace(artifact, **changes)

    def test_direct_review_requires_enum_decision_and_acceptance_coherence(self):
        final_review = self._artifacts()[-1]

        with self.assertRaisesRegex(ValueError, "RemediationTextReviewDecision"):
            replace(final_review, decision="approved")

        with self.assertRaisesRegex(ValueError, "remediation_accepted mismatch"):
            replace(
                final_review,
                decision=RemediationTextReviewDecision.REVISION_REQUIRED,
            )

    def test_direct_construction_rejects_resolved_or_verdict_claims(self):
        for artifact in self._artifacts():
            with self.subTest(artifact=type(artifact).__name__, field="future_semantics"):
                with self.assertRaisesRegex(ValueError, "future_semantics"):
                    replace(artifact, future_semantics="resolved")
            with self.subTest(artifact=type(artifact).__name__, field="security_verdict"):
                with self.assertRaisesRegex(ValueError, "security_verdict"):
                    replace(artifact, security_verdict="pass")


if __name__ == "__main__":
    unittest.main()
