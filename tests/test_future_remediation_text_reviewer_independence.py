from __future__ import annotations

import unittest

import test_future_remediation_text_proposal as proposal_tests
import test_future_remediation_text_review as review_tests
from lightup.ai.gateway import ModelGateway, ModelRole


class FutureRemediationTextReviewerIndependenceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.base = review_tests.FutureRemediationTextReviewTest(
            "test_all_pass_review_accepts_text_without_action_authority"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def test_distinct_reviewer_binding_remains_accepted(self) -> None:
        gateway, provider = self.base._review_gateway(review_tests._review_json())

        review = self.base._review(gateway)

        self.assertEqual(review.reviewer_provider_id, provider.provider_id)
        self.assertEqual(review.reviewer_model_id, "verifier-model-v1")
        self.assertNotEqual(
            (review.reviewer_provider_id, review.reviewer_model_id),
            (self.base.proposal.provider_id, self.base.proposal.model_id),
        )

    def test_exact_proposal_author_binding_cannot_review_its_own_text(self) -> None:
        provider = proposal_tests.RecordingProvider(
            review_tests._review_json(),
            provider_id=self.base.proposal.provider_id,
        )
        gateway = ModelGateway()
        gateway.register_provider(provider)
        gateway.bind_role(
            ModelRole.VERIFIER,
            provider.provider_id,
            self.base.proposal.model_id,
        )

        with self.assertRaisesRegex(ValueError, "independent|reviewer|author"):
            self.base._review(gateway)

        self.assertEqual(
            provider.requests,
            [],
            "self-review must fail before the verifier provider is invoked",
        )


if __name__ == "__main__":
    unittest.main()
