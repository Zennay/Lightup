from __future__ import annotations

from dataclasses import replace
import unittest

import test_future_remediation_text_review_handoff as handoff_tests
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


class FutureRemediationDirectConstructionTest(unittest.TestCase):
    def setUp(self):
        self.base = handoff_tests.FutureRemediationTextReviewHandoffTest(
            "test_approved_review_round_trips_without_action_authority"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def _artifacts(self):
        return (
            self.base.base.base.request,
            self.base.base.proposal,
            self.base.base.review_request,
            self.base.review,
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
        authoring_request, proposal, review_request, review = self._artifacts()

        cases = (
            (authoring_request, {"authoring_requested": False}),
            (authoring_request, {"remediation_proposal_created": True}),
            (proposal, {"remediation_proposal_created": False}),
            (review_request, {"review_requested": False}),
            (review_request, {"remediation_accepted": True}),
            (review, {"review_completed": False}),
            (review, {"remediation_accepted": False}),
        )
        for artifact, changes in cases:
            with self.subTest(artifact=type(artifact).__name__, changes=changes):
                with self.assertRaises(ValueError):
                    replace(artifact, **changes)

    def test_direct_review_requires_enum_decision_and_acceptance_coherence(self):
        review = self._artifacts()[-1]

        with self.assertRaisesRegex(ValueError, "RemediationTextReviewDecision"):
            replace(review, decision="approved")

        with self.assertRaisesRegex(ValueError, "remediation_accepted mismatch"):
            replace(review, decision=RemediationTextReviewDecision.REVISION_REQUIRED)

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
