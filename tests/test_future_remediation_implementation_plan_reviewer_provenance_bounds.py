from __future__ import annotations

from dataclasses import replace
import unittest

import test_future_remediation_implementation_plan_review as review_tests
import test_future_remediation_implementation_plan_review_handoff as handoff_tests
import test_future_remediation_text_proposal as proposal_tests
from lightup.ai.gateway import ModelGateway, ModelRole
from lightup.future_remediation_implementation_plan_review_handoff import (
    future_remediation_implementation_plan_review_from_json,
)


class FutureRemediationImplementationPlanReviewerProvenanceBoundsTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = (
            handoff_tests.FutureRemediationImplementationPlanReviewHandoffTest(
                "test_approved_review_round_trips_without_action_authority"
            )
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.review_fixture = self.base.base

    def _gateway(self, *, provider_id: str, model_id: str):
        provider = proposal_tests.RecordingProvider(
            review_tests._review_json(),
            provider_id=provider_id,
        )
        gateway = ModelGateway()
        gateway.register_provider(provider)
        gateway.bind_role(
            ModelRole.VERIFIER,
            provider.provider_id,
            model_id,
        )
        return gateway, provider

    def test_exact_256_character_provenance_survives_strict_reload(self):
        provider_id = "p" * 256
        model_id = "m" * 256
        gateway, _ = self._gateway(
            provider_id=provider_id,
            model_id=model_id,
        )

        review = self.review_fixture._review(gateway)

        self.assertEqual(review.reviewer_provider_id, provider_id)
        self.assertEqual(review.reviewer_model_id, model_id)
        self.assertEqual(
            future_remediation_implementation_plan_review_from_json(
                review.to_json()
            ),
            review,
        )
        self.assertEqual(
            self.base._load(persisted=review.to_json()),
            review,
        )

    def test_oversized_provider_id_fails_before_review_artifact_exists(self):
        gateway, provider = self._gateway(
            provider_id="p" * 257,
            model_id="bounded-model",
        )

        with self.assertRaisesRegex(
            ValueError,
            "reviewer_provider_id exceeds bounded size",
        ):
            self.review_fixture._review(gateway)

        self.assertEqual(len(provider.requests), 1)

    def test_oversized_model_id_fails_before_review_artifact_exists(self):
        gateway, provider = self._gateway(
            provider_id="bounded-provider",
            model_id="m" * 257,
        )

        with self.assertRaisesRegex(
            ValueError,
            "reviewer_model_id exceeds bounded size",
        ):
            self.review_fixture._review(gateway)

        self.assertEqual(len(provider.requests), 1)

    def test_nul_provenance_fails_closed_without_truncation(self):
        cases = (
            ("provider\x00id", "bounded-model", "reviewer_provider_id contains NUL"),
            ("bounded-provider", "model\x00id", "reviewer_model_id contains NUL"),
        )
        for provider_id, model_id, message in cases:
            with self.subTest(message=message):
                gateway, _ = self._gateway(
                    provider_id=provider_id,
                    model_id=model_id,
                )
                with self.assertRaisesRegex(ValueError, message):
                    self.review_fixture._review(gateway)

    def test_direct_construction_keeps_same_provenance_boundary(self):
        review = self.base.review

        for field, value, message in (
            (
                "reviewer_provider_id",
                "p" * 257,
                "reviewer_provider_id exceeds bounded size",
            ),
            (
                "reviewer_model_id",
                "m" * 257,
                "reviewer_model_id exceeds bounded size",
            ),
            (
                "reviewer_provider_id",
                "provider\x00id",
                "reviewer_provider_id contains NUL",
            ),
            (
                "reviewer_model_id",
                "model\x00id",
                "reviewer_model_id contains NUL",
            ),
        ):
            with self.subTest(field=field, message=message):
                with self.assertRaisesRegex(ValueError, message):
                    replace(review, **{field: value})


if __name__ == "__main__":
    unittest.main()
