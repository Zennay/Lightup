from __future__ import annotations

import unittest

import test_future_remediation_text_proposal as proposal_tests
import test_future_remediation_text_review as review_tests
import test_future_remediation_text_revision_review as revision_review_tests
from lightup.ai.gateway import ModelGateway, ModelRole


class FutureRevisedRemediationReviewerIndependenceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.base = revision_review_tests.FutureRemediationTextRevisionReviewTest(
            "test_all_pass_review_accepts_revised_text_without_action_authority"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.revised_proposal = self.base.base.base.proposal

    def test_distinct_revision_reviewer_binding_remains_accepted(self) -> None:
        gateway, provider = self.base._gateway(review_tests._review_json())

        review = self.base._review(gateway)

        self.assertEqual(review.reviewer_provider_id, provider.provider_id)
        self.assertEqual(review.reviewer_model_id, "revision-verifier-model-v1")
        self.assertNotEqual(
            (review.reviewer_provider_id, review.reviewer_model_id),
            (self.revised_proposal.provider_id, self.revised_proposal.model_id),
        )

    def test_exact_revision_author_binding_cannot_review_its_own_text(self) -> None:
        provider = proposal_tests.RecordingProvider(
            review_tests._review_json(),
            provider_id=self.revised_proposal.provider_id,
        )
        gateway = ModelGateway()
        gateway.register_provider(provider)
        gateway.bind_role(
            ModelRole.VERIFIER,
            provider.provider_id,
            self.revised_proposal.model_id,
        )

        with self.assertRaisesRegex(ValueError, "independent|reviewer|author"):
            self.base._review(gateway)

        self.assertEqual(
            provider.requests,
            [],
            "revised self-review must fail before verifier invocation",
        )


if __name__ == "__main__":
    unittest.main()
