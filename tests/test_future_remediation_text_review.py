from __future__ import annotations

import json
import unittest

import test_future_remediation_text_proposal as proposal_tests
from lightup.ai.gateway import ModelGateway, ModelRole
from lightup.future_remediation_text_review import (
    RemediationTextReviewDecision,
    review_future_remediation_text,
)
from lightup.future_remediation_text_review_request import (
    build_future_remediation_text_review_request,
)


def _review_json(
    decision: str = "approved",
    *,
    evidence_alignment: str = "pass",
    unsupported_claims: str = "pass",
    least_privilege: str = "pass",
    future_retest_separation: str = "pass",
    summary: str = "The proposal is bounded, evidence-aligned, and keeps retest separate.",
) -> str:
    return json.dumps(
        {
            "decision": decision,
            "check_results": {
                "evidence_alignment": evidence_alignment,
                "unsupported_claims": unsupported_claims,
                "least_privilege": least_privilege,
                "future_retest_separation": future_retest_separation,
            },
            "summary": summary,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


class FutureRemediationTextReviewTest(unittest.TestCase):
    def setUp(self):
        self.base = proposal_tests.FutureRemediationTextProposalTest(
            "test_live_valid_request_generates_bounded_non_executable_proposal"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        author_gateway, _ = self.base._gateway()
        self.proposal = self.base._generate(author_gateway)
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

    def _review_gateway(self, content: str, **provider_kwargs):
        provider = proposal_tests.RecordingProvider(
            content,
            provider_id="reviewer",
            **provider_kwargs,
        )
        gateway = ModelGateway()
        gateway.register_provider(provider)
        gateway.bind_role(ModelRole.VERIFIER, provider.provider_id, "verifier-model-v1")
        return gateway, provider

    def _review(self, gateway: ModelGateway):
        return review_future_remediation_text(
            self.review_request.to_json(),
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
            gateway,
        )

    def test_all_pass_review_accepts_text_without_action_authority(self):
        gateway, provider = self._review_gateway(_review_json())

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
        self.assertEqual(len(review.review_sha256), 64)

        self.assertEqual(len(provider.requests), 1)
        request = provider.requests[0]
        self.assertEqual(request.role, ModelRole.VERIFIER)
        self.assertEqual(request.max_output_tokens, 800)
        self.assertIn(self.proposal.content, request.messages[1].content)

    def test_decision_must_be_coherent_with_check_results(self):
        cases = (
            (
                _review_json(decision="approved", evidence_alignment="fail"),
                "every check to pass",
            ),
            (
                _review_json(decision="revision_required"),
                "requires a non-pass check",
            ),
            (
                _review_json(
                    decision="insufficient_evidence",
                    evidence_alignment="fail",
                ),
                "requires an unclear check",
            ),
        )
        for content, message in cases:
            with self.subTest(message=message):
                gateway, _ = self._review_gateway(content)
                with self.assertRaisesRegex(ValueError, message):
                    self._review(gateway)

    def test_revision_and_insufficient_evidence_never_accept_text(self):
        cases = (
            _review_json(
                decision="revision_required",
                unsupported_claims="fail",
            ),
            _review_json(
                decision="insufficient_evidence",
                evidence_alignment="unclear",
            ),
        )
        for content in cases:
            with self.subTest(content=content):
                gateway, _ = self._review_gateway(content)
                review = self._review(gateway)
                self.assertFalse(review.remediation_accepted)
                self.assertFalse(review.execution_allowed)
                self.assertEqual(review.security_verdict, "not_evaluated")

    def test_live_evidence_drift_fails_before_reviewer_invocation(self):
        gateway, provider = self._review_gateway(_review_json())
        evidence_id = self.base.bundle.items[0].evidence[0].evidence_id
        current_sha = self.base.bundle.items[0].evidence[0].sha256
        replacement = "f" * 64 if current_sha != "f" * 64 else "e" * 64
        with self.base.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                (replacement, evidence_id),
            )

        with self.assertRaises(ValueError):
            self._review(gateway)

        self.assertEqual(provider.requests, [])

    def test_reviewer_model_identity_substitution_is_rejected(self):
        gateway, provider = self._review_gateway(
            _review_json(),
            response_model_id="unexpected-verifier",
        )

        with self.assertRaisesRegex(ValueError, "wrong model identity"):
            self._review(gateway)

        self.assertEqual(len(provider.requests), 1)

    def test_same_review_response_and_lineage_have_same_digest(self):
        first_gateway, _ = self._review_gateway(_review_json())
        second_gateway, _ = self._review_gateway(_review_json())

        first = self._review(first_gateway)
        second = self._review(second_gateway)

        self.assertEqual(first.review_sha256, second.review_sha256)
        self.assertEqual(first.to_json(), second.to_json())


if __name__ == "__main__":
    unittest.main()
