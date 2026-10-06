from __future__ import annotations

from dataclasses import replace
import unittest

import test_future_remediation_implementation_plan_handoff as handoff_tests
from lightup.future_remediation_implementation_plan_review_request import (
    REMEDIATION_IMPLEMENTATION_PLAN_REVIEW_REQUEST_SCHEMA_VERSION,
    REQUIRED_IMPLEMENTATION_PLAN_REVIEW_CHECKS,
    FutureRemediationImplementationPlanReviewRequest,
    build_future_remediation_implementation_plan_review_request,
)


_AUTHORITY_FLAGS = (
    "code_change_authorized",
    "tool_call_created",
    "execution_allowed",
    "target_interaction_allowed",
    "future_state_retest_allowed",
    "deployment_authorized",
    "attack_path_mutation_allowed",
)


class FutureRemediationImplementationPlanReviewRequestTest(unittest.TestCase):
    def setUp(self):
        self.base = handoff_tests.FutureRemediationImplementationPlanHandoffTest(
            "test_round_trip_requires_exact_live_planning_lineage"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.request = self._build()

    def _build(self, persisted_plan=None):
        return build_future_remediation_implementation_plan_review_request(
            self.base.plan.to_json() if persisted_plan is None else persisted_plan,
            self.base.base.planning_request.to_json(),
            self.base.base.base.review.to_json(),
            self.base.base.base.base.review_request.to_json(),
            self.base.base.base.base.proposal.to_json(),
            self.base.base.base.base.base.request,
            self.base.base.base.base.base.bundle,
            self.base.base.base.base.base.plan,
            self.base.base.base.base.base.report,
            self.base.base.base.base.base.preview,
            self.base.base.base.base.base.transition_proposal,
            (self.base.base.base.base.base.resolution,),
            (self.base.base.base.base.base.context,),
            self.base.base.base.base.base.state,
        )

    def test_live_valid_plan_produces_review_only_request(self):
        request = self.request
        plan = self.base.plan

        self.assertEqual(
            request.schema_version,
            REMEDIATION_IMPLEMENTATION_PLAN_REVIEW_REQUEST_SCHEMA_VERSION,
        )
        self.assertEqual(
            request.implementation_request_sha256,
            plan.implementation_request_sha256,
        )
        self.assertEqual(request.remediation_review_sha256, plan.review_sha256)
        self.assertEqual(request.proposal_sha256, plan.proposal_sha256)
        self.assertEqual(request.content_sha256, plan.content_sha256)
        self.assertEqual(request.plan_sha256, plan.plan_sha256)
        self.assertEqual(request.planner_provider_id, plan.provider_id)
        self.assertEqual(request.planner_model_id, plan.model_id)
        self.assertEqual(request.plan_item_count, len(plan.plan_items))
        self.assertEqual(
            request.required_checks,
            REQUIRED_IMPLEMENTATION_PLAN_REVIEW_CHECKS,
        )
        self.assertEqual(len(request.review_request_sha256), 64)

        self.assertTrue(request.implementation_plan_review_requested)
        self.assertFalse(request.implementation_plan_accepted)
        for field in _AUTHORITY_FLAGS:
            self.assertFalse(getattr(request, field))
        self.assertEqual(request.future_semantics, "unresolved")
        self.assertEqual(request.security_verdict, "not_evaluated")

    def test_review_request_is_deterministic_for_same_live_plan(self):
        first = self._build()
        second = self._build()

        self.assertEqual(first, second)
        self.assertEqual(first.to_json(), second.to_json())

    def test_tampered_persisted_plan_is_rejected_before_review_request(self):
        payload = self.base.plan.as_dict()
        payload["summary"] += " tampered"

        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            self._build(payload)

    def test_live_evidence_drift_is_rejected_before_review_request(self):
        evidence = self.base.base.base.base.base.bundle.items[0].evidence[0]
        replacement = "f" * 64 if evidence.sha256 != "f" * 64 else "e" * 64
        with self.base.base.base.base.base.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                (replacement, evidence.evidence_id),
            )

        with self.assertRaises(ValueError):
            self._build()

    def test_review_request_contains_no_plan_body_or_action_payload(self):
        serialized = self.request.to_json().lower()
        plan = self.base.plan

        self.assertNotIn(plan.summary.lower(), serialized)
        self.assertNotIn(plan.plan_items[0].intent.lower(), serialized)
        for forbidden in (
            '"patch"',
            '"command"',
            '"tool_arguments"',
            '"target_arguments"',
            '"credentials"',
            '"source"',
            '"metadata"',
            '"authorization_ref"',
        ):
            self.assertNotIn(forbidden, serialized)

    def test_direct_construction_rejects_lifecycle_and_authority_widening(self):
        with self.assertRaisesRegex(ValueError, "accepted"):
            replace(self.request, implementation_plan_accepted=True)
        with self.assertRaisesRegex(ValueError, "review_requested"):
            replace(self.request, implementation_plan_review_requested=False)
        with self.assertRaisesRegex(ValueError, "required checks"):
            replace(
                self.request,
                required_checks=tuple(reversed(self.request.required_checks)),
            )
        with self.assertRaisesRegex(ValueError, "future_semantics"):
            replace(self.request, future_semantics="resolved")
        with self.assertRaisesRegex(ValueError, "security_verdict"):
            replace(self.request, security_verdict="pass")

        for field in _AUTHORITY_FLAGS:
            for value in (True, 0):
                with self.subTest(field=field, value=value):
                    with self.assertRaisesRegex(ValueError, "authority flag"):
                        replace(self.request, **{field: value})

    def test_direct_construction_rejects_lineage_and_digest_drift(self):
        alternate = (
            "0" * 64
            if self.request.plan_sha256 != "0" * 64
            else "f" * 64
        )
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            replace(self.request, plan_sha256=alternate)

        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            replace(self.request, planner_model_id="forged-model")

        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            replace(self.request, plan_item_count=self.request.plan_item_count + 1)

        with self.assertRaisesRegex(ValueError, "canonical lowercase"):
            replace(self.request, review_request_sha256="A" * 64)

    def test_canonical_dict_reconstructs_exact_request(self):
        reconstructed = FutureRemediationImplementationPlanReviewRequest(
            **self.request.as_dict()
        )

        self.assertEqual(reconstructed, self.request)


if __name__ == "__main__":
    unittest.main()
