from __future__ import annotations

import unittest

import test_future_remediation_text_proposal as proposal_tests
import test_future_remediation_text_review as review_tests
import test_future_remediation_text_revision_review_request_handoff as handoff_tests
from lightup.ai.gateway import ModelGateway, ModelRole
from lightup.future_remediation_text_revision_review import (
    REMEDIATION_TEXT_REVISION_REVIEW_SCHEMA_VERSION,
    review_future_remediation_text_revision,
)
from lightup.future_remediation_text_review import RemediationTextReviewDecision


class FutureRemediationTextRevisionReviewTest(unittest.TestCase):
    def setUp(self):
        self.base = handoff_tests.FutureRemediationTextRevisionReviewRequestHandoffTest(
            "test_round_trip_rebuilds_exact_live_review_request"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def _gateway(self, content: str, **provider_kwargs):
        provider = proposal_tests.RecordingProvider(
            content,
            provider_id="revision-reviewer",
            **provider_kwargs,
        )
        gateway = ModelGateway()
        gateway.register_provider(provider)
        gateway.bind_role(
            ModelRole.VERIFIER,
            provider.provider_id,
            "revision-verifier-model-v1",
        )
        return gateway, provider

    def _review(self, gateway: ModelGateway):
        return review_future_remediation_text_revision(
            self.base.request.to_json(),
            self.base.base.base.proposal.to_json(),
            self.base.base.base.base.revision_request.to_json(),
            self.base.base.base.base.review.to_json(),
            self.base.base.base.base.base.base.review_request.to_json(),
            self.base.base.base.base.base.base.proposal.to_json(),
            self.base.base.base.base.base.base.base.request,
            self.base.base.base.base.base.base.base.bundle,
            self.base.base.base.base.base.base.base.plan,
            self.base.base.base.base.base.base.base.report,
            self.base.base.base.base.base.base.base.preview,
            self.base.base.base.base.base.base.base.transition_proposal,
            (self.base.base.base.base.base.base.base.resolution,),
            (self.base.base.base.base.base.base.base.context,),
            self.base.base.base.base.base.base.base.state,
            gateway,
        )

    def test_all_pass_review_accepts_revised_text_without_action_authority(self):
        gateway, provider = self._gateway(review_tests._review_json())

        review = self._review(gateway)

        self.assertEqual(review.decision, RemediationTextReviewDecision.APPROVED)
        self.assertTrue(review.review_completed)
        self.assertTrue(review.remediation_accepted)
        self.assertFalse(review.code_change_authorized)
        self.assertFalse(review.tool_call_created)
        self.assertFalse(review.execution_allowed)
        self.assertFalse(review.target_interaction_allowed)
        self.assertFalse(review.future_state_retest_allowed)
        self.assertFalse(review.deployment_authorized)
        self.assertFalse(review.attack_path_mutation_allowed)
        self.assertEqual(review.future_semantics, "unresolved")
        self.assertEqual(review.security_verdict, "not_evaluated")
        self.assertEqual(
            review.schema_version,
            REMEDIATION_TEXT_REVISION_REVIEW_SCHEMA_VERSION,
        )
        self.assertEqual(len(review.review_sha256), 64)

        self.assertEqual(len(provider.requests), 1)
        request = provider.requests[0]
        self.assertEqual(request.role, ModelRole.VERIFIER)
        self.assertEqual(request.max_output_tokens, 800)
        self.assertIn(self.base.base.base.proposal.content, request.messages[1].content)

    def test_decision_must_be_coherent_with_check_results(self):
        cases = (
            (
                review_tests._review_json(
                    decision="approved",
                    evidence_alignment="fail",
                ),
                "every check to pass",
            ),
            (
                review_tests._review_json(decision="revision_required"),
                "requires a non-pass check",
            ),
            (
                review_tests._review_json(
                    decision="insufficient_evidence",
                    evidence_alignment="fail",
                ),
                "requires an unclear check",
            ),
        )
        for content, message in cases:
            with self.subTest(message=message):
                gateway, _ = self._gateway(content)
                with self.assertRaisesRegex(ValueError, message):
                    self._review(gateway)

    def test_non_approved_reviews_never_accept_revised_text(self):
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
        for content in cases:
            with self.subTest(content=content):
                gateway, _ = self._gateway(content)
                review = self._review(gateway)
                self.assertFalse(review.remediation_accepted)
                self.assertFalse(review.execution_allowed)
                self.assertEqual(review.security_verdict, "not_evaluated")

    def test_live_evidence_drift_fails_before_reviewer_invocation(self):
        gateway, provider = self._gateway(review_tests._review_json())
        evidence_id = (
            self.base.base.base.base.base.base.base.bundle.items[0]
            .evidence[0]
            .evidence_id
        )
        current_sha = (
            self.base.base.base.base.base.base.base.bundle.items[0].evidence[0].sha256
        )
        replacement = "f" * 64 if current_sha != "f" * 64 else "e" * 64
        with self.base.base.base.base.base.base.base.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                (replacement, evidence_id),
            )

        with self.assertRaises(ValueError):
            self._review(gateway)

        self.assertEqual(provider.requests, [])

    def test_reviewer_model_identity_substitution_is_rejected(self):
        gateway, provider = self._gateway(
            review_tests._review_json(),
            response_model_id="unexpected-revision-verifier",
        )

        with self.assertRaisesRegex(ValueError, "wrong model identity"):
            self._review(gateway)

        self.assertEqual(len(provider.requests), 1)

    def test_same_review_response_and_lineage_have_same_digest(self):
        content = review_tests._review_json()
        first_gateway, _ = self._gateway(content)
        second_gateway, _ = self._gateway(content)

        first = self._review(first_gateway)
        second = self._review(second_gateway)

        self.assertEqual(first.review_sha256, second.review_sha256)
        self.assertEqual(first.to_json(), second.to_json())


if __name__ == "__main__":
    unittest.main()
