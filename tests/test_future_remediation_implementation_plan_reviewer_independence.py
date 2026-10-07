from __future__ import annotations

import unittest

import test_future_remediation_implementation_plan_review as review_tests
import test_future_remediation_text_proposal as proposal_tests
from lightup.ai.gateway import ModelGateway, ModelRole


class FutureRemediationImplementationPlanReviewerIndependenceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.base = review_tests.FutureRemediationImplementationPlanReviewTest(
            "test_all_pass_review_accepts_plan_without_action_authority"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def test_distinct_plan_reviewer_binding_remains_accepted(self) -> None:
        gateway, provider = self.base._review_gateway(review_tests._review_json())

        review = self.base._review(gateway)

        self.assertEqual(review.reviewer_provider_id, provider.provider_id)
        self.assertEqual(
            review.reviewer_model_id,
            "implementation-plan-verifier-v1",
        )
        self.assertNotEqual(
            (review.reviewer_provider_id, review.reviewer_model_id),
            (
                self.base.implementation_plan.provider_id,
                self.base.implementation_plan.model_id,
            ),
        )

    def test_exact_plan_author_binding_cannot_review_its_own_plan(self) -> None:
        provider = proposal_tests.RecordingProvider(
            review_tests._review_json(),
            provider_id=self.base.implementation_plan.provider_id,
        )
        gateway = ModelGateway()
        gateway.register_provider(provider)
        gateway.bind_role(
            ModelRole.VERIFIER,
            provider.provider_id,
            self.base.implementation_plan.model_id,
        )

        with self.assertRaisesRegex(ValueError, "independent|reviewer|author"):
            self.base._review(gateway)

        self.assertEqual(
            provider.requests,
            [],
            "plan self-review must fail before verifier invocation",
        )


if __name__ == "__main__":
    unittest.main()
