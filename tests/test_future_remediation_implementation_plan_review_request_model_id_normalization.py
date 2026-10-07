from __future__ import annotations

import unittest

import test_future_remediation_implementation_plan_review_request as request_tests
from lightup.future_remediation_implementation_plan_review_request import (
    _review_request_digest,
)
from lightup.future_remediation_implementation_plan_review_request_handoff import (
    future_remediation_implementation_plan_review_request_from_dict,
    load_and_validate_future_remediation_implementation_plan_review_request,
)


class FutureRemediationImplementationPlanReviewRequestModelIdNormalizationTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = request_tests.FutureRemediationImplementationPlanReviewRequestTest(
            "test_live_valid_plan_produces_review_only_request"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.request = self.base.request

    @staticmethod
    def _recompute_request_sha256(payload: dict) -> str:
        return _review_request_digest(
            implementation_request_sha256=payload[
                "implementation_request_sha256"
            ],
            remediation_review_sha256=payload["remediation_review_sha256"],
            proposal_sha256=payload["proposal_sha256"],
            content_sha256=payload["content_sha256"],
            plan_sha256=payload["plan_sha256"],
            planner_provider_id=payload["planner_provider_id"],
            planner_model_id=payload["planner_model_id"],
            plan_item_count=payload["plan_item_count"],
        )

    def _forged_payload(self, boundary: str) -> dict:
        payload = self.request.as_dict()
        canonical = payload["planner_model_id"]
        payload["planner_model_id"] = f"{boundary}{canonical}{boundary}"
        payload["review_request_sha256"] = self._recompute_request_sha256(payload)
        return payload

    def _load(self, persisted):
        return load_and_validate_future_remediation_implementation_plan_review_request(
            persisted,
            self.base.base.plan.to_json(),
            self.base.base.base.planning_request.to_json(),
            self.base.base.base.base.review.to_json(),
            self.base.base.base.base.base.review_request.to_json(),
            self.base.base.base.base.base.proposal.to_json(),
            self.base.base.base.base.base.base.request,
            self.base.base.base.base.base.base.bundle,
            self.base.base.base.base.base.base.plan,
            self.base.base.base.base.base.base.report,
            self.base.base.base.base.base.base.preview,
            self.base.base.base.base.base.base.transition_proposal,
            (self.base.base.base.base.base.base.resolution,),
            (self.base.base.base.base.base.context,),
            self.base.base.base.base.base.base.state,
        )

    def test_canonical_request_inherits_exact_live_plan_model_identity(self):
        self.assertEqual(
            self.request.planner_model_id,
            self.base.base.plan.model_id,
        )
        self.assertEqual(
            self.request.planner_model_id,
            self.request.planner_model_id.strip(),
        )
        self.assertEqual(
            future_remediation_implementation_plan_review_request_from_dict(
                self.request.as_dict()
            ),
            self.request,
        )

    def test_live_rebuild_already_rejects_forged_model_identity(self):
        payload = self._forged_payload(" ")

        with self.assertRaises(ValueError):
            self._load(payload)

    def test_strict_parser_rejects_producer_impossible_model_identity(self):
        for boundary in (" ", "\t", "\n"):
            with self.subTest(boundary=repr(boundary)):
                payload = self._forged_payload(boundary)
                before = dict(payload)

                self.assertNotEqual(
                    payload["review_request_sha256"],
                    self.request.review_request_sha256,
                    "test must carry a digest matching the forged model identity",
                )

                with self.assertRaises(ValueError):
                    future_remediation_implementation_plan_review_request_from_dict(
                        payload
                    )

                self.assertEqual(payload, before)


if __name__ == "__main__":
    unittest.main()
