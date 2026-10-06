from __future__ import annotations

import unittest

import test_future_remediation_text_review as review_tests
from lightup.future_remediation_implementation_plan_request import (
    REMEDIATION_IMPLEMENTATION_PLAN_REQUEST_SCHEMA_VERSION,
    build_future_remediation_implementation_plan_request,
)


class FutureRemediationImplementationPlanRequestTest(unittest.TestCase):
    def setUp(self):
        self.base = review_tests.FutureRemediationTextReviewTest(
            "test_all_pass_review_accepts_text_without_action_authority"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        gateway, _ = self.base._review_gateway(review_tests._review_json())
        self.review = self.base._review(gateway)

    def _build(self, *, review=None):
        return build_future_remediation_implementation_plan_request(
            (self.review if review is None else review).to_json(),
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

    def test_approved_review_requests_planning_without_action_authority(self):
        request = self._build()

        self.assertEqual(
            request.schema_version,
            REMEDIATION_IMPLEMENTATION_PLAN_REQUEST_SCHEMA_VERSION,
        )
        self.assertEqual(request.review_sha256, self.review.review_sha256)
        self.assertEqual(
            request.review_request_sha256,
            self.review.review_request_sha256,
        )
        self.assertEqual(request.proposal_sha256, self.review.proposal_sha256)
        self.assertEqual(request.content_sha256, self.review.content_sha256)
        self.assertEqual(request.item_count, self.base.proposal.item_count)
        self.assertEqual(len(request.implementation_request_sha256), 64)

        self.assertTrue(request.implementation_planning_requested)
        self.assertFalse(request.implementation_plan_created)
        self.assertFalse(request.code_change_authorized)
        self.assertFalse(request.tool_call_created)
        self.assertFalse(request.execution_allowed)
        self.assertFalse(request.target_interaction_allowed)
        self.assertFalse(request.future_state_retest_allowed)
        self.assertFalse(request.deployment_authorized)
        self.assertFalse(request.attack_path_mutation_allowed)
        self.assertEqual(request.future_semantics, "unresolved")
        self.assertEqual(request.security_verdict, "not_evaluated")

    def test_request_is_deterministic_for_same_approved_live_review(self):
        first = self._build()
        second = self._build()

        self.assertEqual(first, second)
        self.assertEqual(first.to_json(), second.to_json())

    def test_revision_and_insufficient_evidence_reviews_cannot_request_planning(self):
        cases = (
            review_tests._review_json(
                decision="revision_required",
                unsupported_claims="fail",
            ),
            review_tests._review_json(
                decision="insufficient_evidence",
                evidence_alignment="unclear",
            ),
        )
        for reviewer_content in cases:
            with self.subTest(reviewer_content=reviewer_content):
                gateway, _ = self.base._review_gateway(reviewer_content)
                review = self.base._review(gateway)
                with self.assertRaisesRegex(PermissionError, "requires approved text"):
                    self._build(review=review)

    def test_live_evidence_drift_blocks_planning_request(self):
        evidence_id = self.base.base.bundle.items[0].evidence[0].evidence_id
        current_sha = self.base.base.bundle.items[0].evidence[0].sha256
        replacement = "f" * 64 if current_sha != "f" * 64 else "e" * 64
        with self.base.base.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                (replacement, evidence_id),
            )

        with self.assertRaises(ValueError):
            self._build()

    def test_request_contains_no_patch_command_target_or_remediation_body(self):
        request = self._build()
        serialized = request.to_json().lower()

        self.assertNotIn(self.base.proposal.content.lower(), serialized)
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
