from __future__ import annotations

from dataclasses import replace
import unittest

import test_future_remediation_implementation_plan_revision_proposal_handoff as handoff_tests
from lightup.future_remediation_implementation_plan_review_request import (
    REQUIRED_IMPLEMENTATION_PLAN_REVIEW_CHECKS,
)
from lightup.future_remediation_implementation_plan_revision_review_request import (
    REMEDIATION_IMPLEMENTATION_PLAN_REVISION_REVIEW_REQUEST_SCHEMA_VERSION,
    FutureRemediationImplementationPlanRevisionReviewRequest,
    build_future_remediation_implementation_plan_revision_review_request,
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


class FutureRemediationImplementationPlanRevisionReviewRequestTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = (
            handoff_tests.FutureRemediationImplementationPlanRevisionProposalHandoffTest(
                "test_json_and_dict_round_trip_require_live_revision_lineage"
            )
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.request = self._build()

    def _build(self, persisted_revised_plan=None):
        producer = self.base.base
        return build_future_remediation_implementation_plan_revision_review_request(
            self.base.revised_plan.to_json()
            if persisted_revised_plan is None
            else persisted_revised_plan,
            producer.revision_request.to_json(),
            producer.review.to_json(),
            producer.plan_review_request.to_json(),
            producer.prior_plan.to_json(),
            producer.planning_request.to_json(),
            producer.remediation_review.to_json(),
            producer.remediation_review_request.to_json(),
            producer.proposal.to_json(),
            producer.root.request,
            producer.root.bundle,
            producer.root.plan,
            producer.root.report,
            producer.root.preview,
            producer.root.transition_proposal,
            (producer.root.resolution,),
            (producer.root.context,),
            producer.root.state,
        )

    def test_live_valid_revised_plan_produces_review_only_request(self):
        request = self.request
        revised_plan = self.base.revised_plan

        self.assertEqual(
            request.schema_version,
            REMEDIATION_IMPLEMENTATION_PLAN_REVISION_REVIEW_REQUEST_SCHEMA_VERSION,
        )
        self.assertEqual(
            request.revision_request_sha256,
            revised_plan.revision_request_sha256,
        )
        self.assertEqual(
            request.prior_review_sha256,
            revised_plan.prior_review_sha256,
        )
        self.assertEqual(request.prior_plan_sha256, revised_plan.prior_plan_sha256)
        self.assertEqual(
            request.implementation_request_sha256,
            revised_plan.implementation_request_sha256,
        )
        self.assertEqual(
            request.revised_plan_sha256,
            revised_plan.revised_plan_sha256,
        )
        self.assertEqual(request.planner_provider_id, revised_plan.provider_id)
        self.assertEqual(request.planner_model_id, revised_plan.model_id)
        self.assertEqual(request.plan_item_count, len(revised_plan.plan_items))
        self.assertEqual(
            request.required_checks,
            REQUIRED_IMPLEMENTATION_PLAN_REVIEW_CHECKS,
        )
        self.assertEqual(len(request.review_request_sha256), 64)

        self.assertTrue(request.implementation_plan_revision_review_requested)
        self.assertFalse(request.revised_implementation_plan_accepted)
        for field in _AUTHORITY_FLAGS:
            self.assertFalse(getattr(request, field))
        self.assertEqual(request.future_semantics, "unresolved")
        self.assertEqual(request.security_verdict, "not_evaluated")

    def test_review_request_is_deterministic_for_same_live_revised_plan(self):
        first = self._build()
        second = self._build()

        self.assertEqual(first, second)
        self.assertEqual(first.to_json(), second.to_json())

    def test_tampered_persisted_revised_plan_is_rejected_before_review_request(self):
        payload = self.base.revised_plan.as_dict()
        payload["summary"] += " tampered"

        with self.assertRaises(ValueError):
            self._build(payload)

    def test_live_evidence_drift_is_rejected_before_review_request(self):
        producer = self.base.base
        evidence = producer.root.bundle.items[0].evidence[0]
        replacement = "f" * 64 if evidence.sha256 != "f" * 64 else "e" * 64
        with producer.root.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                (replacement, evidence.evidence_id),
            )

        with self.assertRaises(ValueError):
            self._build()

    def test_review_request_contains_no_revised_plan_body_or_action_payload(self):
        serialized = self.request.to_json().lower()
        revised_plan = self.base.revised_plan

        self.assertNotIn(revised_plan.summary.lower(), serialized)
        self.assertNotIn(revised_plan.plan_items[0].intent.lower(), serialized)
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

    def test_direct_construction_rejects_lifecycle_authority_and_identity_drift(self):
        with self.assertRaisesRegex(ValueError, "accepted"):
            replace(self.request, revised_implementation_plan_accepted=True)
        with self.assertRaisesRegex(ValueError, "review_requested"):
            replace(
                self.request,
                implementation_plan_revision_review_requested=False,
            )
        with self.assertRaisesRegex(ValueError, "required checks"):
            replace(
                self.request,
                required_checks=tuple(reversed(self.request.required_checks)),
            )
        with self.assertRaisesRegex(ValueError, "canonical trimmed"):
            replace(
                self.request,
                planner_model_id=f" {self.request.planner_model_id}",
            )
        with self.assertRaisesRegex(ValueError, "positive exact integer"):
            replace(self.request, plan_item_count=True)
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
            if self.request.revised_plan_sha256 != "0" * 64
            else "f" * 64
        )
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            replace(self.request, revised_plan_sha256=alternate)

        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            replace(
                self.request,
                planner_provider_id="different-provider",
            )

        with self.assertRaisesRegex(ValueError, "canonical lowercase"):
            replace(self.request, review_request_sha256="A" * 64)

    def test_canonical_dict_reconstructs_exact_request(self):
        reconstructed = FutureRemediationImplementationPlanRevisionReviewRequest(
            **self.request.as_dict()
        )
        self.assertEqual(reconstructed, self.request)


if __name__ == "__main__":
    unittest.main()
