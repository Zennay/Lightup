from __future__ import annotations

import unittest

import test_future_remediation_text_proposal as proposal_tests
import test_future_remediation_text_revision_review as revision_review_tests
import test_future_remediation_text_review as review_tests
from lightup.ai.gateway import ModelGateway, ModelRole


class FutureRemediationTextRevisionReviewerIndependenceTest(unittest.TestCase):
    def setUp(self):
        self.base = revision_review_tests.FutureRemediationTextRevisionReviewTest(
            "test_all_pass_review_accepts_revised_text_without_action_authority"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.revision_proposal = self.base.base.base.proposal

    def test_distinct_revision_reviewer_binding_remains_accepted(self):
        gateway, provider = self.base._gateway(review_tests._review_json())

        review = self.base._review(gateway)

        self.assertEqual(len(provider.requests), 1)
        self.assertTrue(review.review_completed)
        self.assertTrue(review.remediation_accepted)
        self.assertNotEqual(
            (review.reviewer_provider_id, review.reviewer_model_id),
            (self.revision_proposal.provider_id, self.revision_proposal.model_id),
        )
        self.assertFalse(review.execution_allowed)
        self.assertFalse(review.target_interaction_allowed)
        self.assertFalse(review.future_state_retest_allowed)
        self.assertFalse(review.deployment_authorized)
        self.assertFalse(review.attack_path_mutation_allowed)

    def test_exact_revision_author_model_cannot_review_its_own_text(self):
        provider = proposal_tests.RecordingProvider(
            review_tests._review_json(),
            provider_id=self.revision_proposal.provider_id,
            response_model_id=self.revision_proposal.model_id,
        )
        gateway = ModelGateway()
        gateway.register_provider(provider)
        gateway.bind_role(
            ModelRole.VERIFIER,
            provider.provider_id,
            self.revision_proposal.model_id,
        )

        with self.assertRaisesRegex(ValueError, "independent|reviewer|author"):
            self.base._review(gateway)

        self.assertEqual(
            provider.requests,
            [],
            "self-review must fail before invoking the revised-text reviewer provider",
        )


if __name__ == "__main__":
    unittest.main()
