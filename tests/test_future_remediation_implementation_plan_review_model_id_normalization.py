from __future__ import annotations

import unittest

import test_future_remediation_implementation_plan_review as review_tests
from lightup.ai.gateway import ModelRole
from lightup.future_remediation_implementation_plan_review import (
    RemediationImplementationPlanReviewCheck,
    RemediationImplementationPlanReviewDecision,
    _review_digest,
)
from lightup.future_remediation_implementation_plan_review_handoff import (
    future_remediation_implementation_plan_review_from_dict,
)


class FutureRemediationImplementationPlanReviewModelIdNormalizationTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = review_tests.FutureRemediationImplementationPlanReviewTest(
            "test_all_pass_review_accepts_plan_without_action_authority"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.gateway, _ = self.base._review_gateway(review_tests._review_json())
        self.review = self.base._review(self.gateway)

    @staticmethod
    def _recompute_review_sha256(payload: dict) -> str:
        return _review_digest(
            review_request_sha256=payload["review_request_sha256"],
            plan_sha256=payload["plan_sha256"],
            implementation_request_sha256=payload[
                "implementation_request_sha256"
            ],
            reviewer_provider_id=payload["reviewer_provider_id"],
            reviewer_model_id=payload["reviewer_model_id"],
            decision=RemediationImplementationPlanReviewDecision(
                payload["decision"]
            ),
            checks=tuple(
                RemediationImplementationPlanReviewCheck(
                    check=item["check"],
                    result=item["result"],
                )
                for item in payload["checks"]
            ),
            summary=payload["summary"],
        )

    def test_real_producer_review_uses_exact_bound_model_identity(self):
        binding = self.gateway.binding_for(ModelRole.VERIFIER)

        self.assertEqual(self.review.reviewer_model_id, binding.model_id)
        self.assertEqual(
            self.review.reviewer_model_id,
            self.review.reviewer_model_id.strip(),
        )
        self.assertEqual(
            future_remediation_implementation_plan_review_from_dict(
                self.review.as_dict()
            ),
            self.review,
        )

    def test_persisted_reviewer_model_whitespace_rejects_with_matching_digest(self):
        for boundary in (" ", "\t", "\n"):
            with self.subTest(boundary=repr(boundary)):
                payload = self.review.as_dict()
                canonical = payload["reviewer_model_id"]
                payload["reviewer_model_id"] = (
                    f"{boundary}{canonical}{boundary}"
                )
                payload["review_sha256"] = self._recompute_review_sha256(payload)
                before = dict(payload)

                self.assertNotEqual(
                    payload["review_sha256"],
                    self.review.review_sha256,
                    "test must carry a digest matching the forged provenance",
                )

                with self.assertRaises(ValueError):
                    future_remediation_implementation_plan_review_from_dict(payload)

                self.assertEqual(payload, before)
                self.assertEqual(
                    payload["reviewer_model_id"],
                    f"{boundary}{canonical}{boundary}",
                )


if __name__ == "__main__":
    unittest.main()
