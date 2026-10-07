from __future__ import annotations

import unittest

import test_future_remediation_text_proposal as proposal_tests
import test_future_remediation_text_revision_request as revision_tests
import test_future_remediation_text_review as review_tests
from lightup.ai.gateway import ModelGateway, ModelRole
from lightup.future_remediation_text_revision_proposal import (
    REMEDIATION_TEXT_REVISION_PROPOSAL_SCHEMA_VERSION,
    generate_future_remediation_text_revision_proposal,
)


class FutureRemediationTextRevisionProposalTest(unittest.TestCase):
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
        self.revision_request = self.base._build(self.review)

    def _gateway(
        self,
        content: str = (
            "Tighten the defensive control wording to stay within the cited evidence "
            "and leave verification to a separately authorized future retest."
        ),
        **provider_kwargs,
    ):
        provider = proposal_tests.RecordingProvider(
            content,
            provider_id="revision-advisor",
            **provider_kwargs,
        )
        gateway = ModelGateway()
        gateway.register_provider(provider)
        gateway.bind_role(
            ModelRole.REMEDIATION_ADVISOR,
            provider.provider_id,
            "remediation-revision-model-v1",
        )
        return gateway, provider

    def _generate(self, gateway: ModelGateway):
        return generate_future_remediation_text_revision_proposal(
            self.revision_request.to_json(),
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
            gateway,
        )

    def test_live_revision_request_generates_unaccepted_non_executable_proposal(self):
        gateway, provider = self._gateway()

        result = self._generate(gateway)

        self.assertEqual(
            result.schema_version,
            REMEDIATION_TEXT_REVISION_PROPOSAL_SCHEMA_VERSION,
        )
        self.assertEqual(
            result.revision_request_sha256,
            self.revision_request.revision_request_sha256,
        )
        self.assertEqual(result.prior_review_sha256, self.review.review_sha256)
        self.assertEqual(
            result.prior_proposal_sha256,
            self.base.base.proposal.proposal_sha256,
        )
        self.assertEqual(
            result.prior_content_sha256,
            self.base.base.proposal.content_sha256,
        )
        self.assertTrue(result.remediation_revision_proposal_created)
        self.assertFalse(result.remediation_accepted)
        self.assertFalse(result.code_change_authorized)
        self.assertFalse(result.tool_call_created)
        self.assertFalse(result.execution_allowed)
        self.assertFalse(result.target_interaction_allowed)
        self.assertFalse(result.future_state_retest_allowed)
        self.assertFalse(result.deployment_authorized)
        self.assertFalse(result.attack_path_mutation_allowed)
        self.assertEqual(result.future_semantics, "unresolved")
        self.assertEqual(result.security_verdict, "not_evaluated")
        self.assertEqual(len(result.content_sha256), 64)
        self.assertEqual(len(result.revision_proposal_sha256), 64)

        self.assertEqual(len(provider.requests), 1)
        request = provider.requests[0]
        self.assertEqual(request.role, ModelRole.REMEDIATION_ADVISOR)
        self.assertEqual(request.max_output_tokens, 1200)
        self.assertEqual(
            dict(request.metadata)["revision_request_sha256"],
            self.revision_request.revision_request_sha256,
        )

    def test_model_receives_prior_prose_and_bounded_review_feedback_only(self):
        gateway, provider = self._gateway()

        self._generate(gateway)

        user_content = provider.requests[0].messages[1].content
        lowered = user_content.lower()
        self.assertIn(self.base.base.proposal.content, user_content)
        self.assertIn(self.review.summary, user_content)
        self.assertIn("unsupported_claims", user_content)
        for forbidden in (
            '"source"',
            '"metadata"',
            '"credentials"',
            '"target"',
            '"authorization_ref"',
        ):
            self.assertNotIn(forbidden, lowered)

    def test_live_evidence_drift_fails_before_model_invocation(self):
        gateway, provider = self._gateway()
        evidence_id = self.base.base.base.bundle.items[0].evidence[0].evidence_id
        current_sha = self.base.base.base.bundle.items[0].evidence[0].sha256
        replacement = "f" * 64 if current_sha != "f" * 64 else "e" * 64
        with self.base.base.base.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                (replacement, evidence_id),
            )

        with self.assertRaises(ValueError):
            self._generate(gateway)

        self.assertEqual(provider.requests, [])

    def test_provider_cannot_substitute_model_identity(self):
        gateway, provider = self._gateway(
            response_model_id="unexpected-revision-model",
        )

        with self.assertRaisesRegex(ValueError, "wrong model identity"):
            self._generate(gateway)

        self.assertEqual(len(provider.requests), 1)

    def test_empty_or_oversized_model_output_is_rejected(self):
        for content, message in (
            ("   ", "empty content"),
            ("x" * 16001, "bounded output size"),
        ):
            with self.subTest(message=message):
                gateway, _ = self._gateway(content)
                with self.assertRaisesRegex(ValueError, message):
                    self._generate(gateway)

    def test_same_response_and_lineage_produce_same_digest(self):
        content = "Revise only the unsupported claim and preserve future retest separation."
        first_gateway, _ = self._gateway(content)
        second_gateway, _ = self._gateway(content)

        first = self._generate(first_gateway)
        second = self._generate(second_gateway)

        self.assertEqual(first.content_sha256, second.content_sha256)
        self.assertEqual(
            first.revision_proposal_sha256,
            second.revision_proposal_sha256,
        )
        self.assertEqual(first.to_json(), second.to_json())


if __name__ == "__main__":
    unittest.main()
