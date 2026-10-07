from __future__ import annotations

import json
import unittest

import test_future_remediation_implementation_plan_review as review_tests
import test_future_remediation_text_proposal as proposal_tests
from lightup.ai.gateway import ModelGateway, ModelRole
from lightup.future_remediation_implementation_plan_revision_proposal import (
    REMEDIATION_IMPLEMENTATION_PLAN_REVISION_PROPOSAL_SCHEMA_VERSION,
    generate_future_remediation_implementation_plan_revision_proposal,
)
from lightup.future_remediation_implementation_plan_revision_request import (
    build_future_remediation_implementation_plan_revision_request,
)


def _revision_plan_json() -> str:
    return json.dumps(
        {
            "summary": (
                "Revise the bounded defensive implementation plan to address the "
                "independent review while keeping verification separate."
            ),
            "plan_items": [
                {
                    "plan_item_id": "plan-1-revised",
                    "change_area": "configuration",
                    "intent": (
                        "Narrow the planned defensive configuration change to the "
                        "least-privilege behavior requested by review."
                    ),
                    "verification_intent": (
                        "Validate the intended behavior only in separately authorized "
                        "future-state verification."
                    ),
                    "rollback_intent": (
                        "Restore the prior reviewed configuration if the eventual "
                        "authorized change introduces a regression."
                    ),
                }
            ],
            "assumptions": [
                "The strict review lineage and evidence remain current."
            ],
            "unresolved_questions": [],
        },
        sort_keys=True,
        separators=(",", ":"),
    )


class FutureRemediationImplementationPlanRevisionProposalTest(unittest.TestCase):
    def setUp(self):
        self.base = review_tests.FutureRemediationImplementationPlanReviewTest(
            "test_revision_and_insufficient_evidence_never_accept_plan"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

        review_gateway, _ = self.base._review_gateway(
            review_tests._review_json(
                decision="revision_required",
                rollback_sufficiency="fail",
                summary=(
                    "Rollback sufficiency needs revision before the plan can be "
                    "accepted."
                ),
            )
        )
        self.review = self.base._review(review_gateway)
        self.prior_plan = self.base.implementation_plan
        self.plan_review_request = self.base.review_request
        self.planning_request = self.base.base.base.base.planning_request
        self.remediation_review = self.base.base.base.base.base.review
        self.remediation_review_request = (
            self.base.base.base.base.base.base.review_request
        )
        self.proposal = self.base.base.base.base.base.base.proposal
        self.root = self.base.base.base.base.base.base.base

        self.revision_request = (
            build_future_remediation_implementation_plan_revision_request(
                self.review.to_json(),
                self.plan_review_request.to_json(),
                self.prior_plan.to_json(),
                self.planning_request.to_json(),
                self.remediation_review.to_json(),
                self.remediation_review_request.to_json(),
                self.proposal.to_json(),
                self.root.request,
                self.root.bundle,
                self.root.plan,
                self.root.report,
                self.root.preview,
                self.root.transition_proposal,
                (self.root.resolution,),
                (self.root.context,),
                self.root.state,
            )
        )

    def _gateway(self, content: str = _revision_plan_json(), **provider_kwargs):
        provider = proposal_tests.RecordingProvider(
            content,
            provider_id="implementation-plan-revision-advisor",
            **provider_kwargs,
        )
        gateway = ModelGateway()
        gateway.register_provider(provider)
        gateway.bind_role(
            ModelRole.REMEDIATION_ADVISOR,
            provider.provider_id,
            "implementation-plan-revision-v1",
        )
        return gateway, provider

    def _generate(self, gateway: ModelGateway):
        return generate_future_remediation_implementation_plan_revision_proposal(
            self.revision_request.to_json(),
            self.review.to_json(),
            self.plan_review_request.to_json(),
            self.prior_plan.to_json(),
            self.planning_request.to_json(),
            self.remediation_review.to_json(),
            self.remediation_review_request.to_json(),
            self.proposal.to_json(),
            self.root.request,
            self.root.bundle,
            self.root.plan,
            self.root.report,
            self.root.preview,
            self.root.transition_proposal,
            (self.root.resolution,),
            (self.root.context,),
            self.root.state,
            gateway,
        )

    def test_live_revision_request_generates_unaccepted_non_executable_revised_plan(self):
        gateway, provider = self._gateway()

        result = self._generate(gateway)

        self.assertEqual(
            result.schema_version,
            REMEDIATION_IMPLEMENTATION_PLAN_REVISION_PROPOSAL_SCHEMA_VERSION,
        )
        self.assertEqual(
            result.revision_request_sha256,
            self.revision_request.revision_request_sha256,
        )
        self.assertEqual(result.prior_review_sha256, self.review.review_sha256)
        self.assertEqual(result.prior_plan_sha256, self.prior_plan.plan_sha256)
        self.assertEqual(
            result.implementation_request_sha256,
            self.prior_plan.implementation_request_sha256,
        )
        self.assertTrue(result.revised_implementation_plan_created)
        self.assertFalse(result.implementation_plan_accepted)
        self.assertFalse(result.code_change_authorized)
        self.assertFalse(result.tool_call_created)
        self.assertFalse(result.execution_allowed)
        self.assertFalse(result.target_interaction_allowed)
        self.assertFalse(result.future_state_retest_allowed)
        self.assertFalse(result.deployment_authorized)
        self.assertFalse(result.attack_path_mutation_allowed)
        self.assertEqual(result.future_semantics, "unresolved")
        self.assertEqual(result.security_verdict, "not_evaluated")
        self.assertEqual(len(result.revised_plan_sha256), 64)

        self.assertEqual(len(provider.requests), 1)
        request = provider.requests[0]
        self.assertEqual(request.role, ModelRole.REMEDIATION_ADVISOR)
        self.assertEqual(request.max_output_tokens, 2000)
        self.assertEqual(
            dict(request.metadata)["revision_request_sha256"],
            self.revision_request.revision_request_sha256,
        )

    def test_model_receives_prior_plan_and_bounded_review_feedback_only(self):
        gateway, provider = self._gateway()

        self._generate(gateway)

        user_content = provider.requests[0].messages[1].content
        lowered = user_content.lower()
        self.assertIn(self.prior_plan.summary, user_content)
        self.assertIn(self.review.summary, user_content)
        self.assertIn("rollback_sufficiency", user_content)
        for forbidden in (
            '"source"',
            '"metadata"',
            '"credentials"',
            '"target"',
            '"authorization_ref"',
        ):
            self.assertNotIn(forbidden, lowered)

    def test_live_evidence_drift_fails_before_revision_model_invocation(self):
        gateway, provider = self._gateway()
        evidence = self.root.bundle.items[0].evidence[0]
        replacement = "f" * 64 if evidence.sha256 != "f" * 64 else "e" * 64
        with self.root.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                (replacement, evidence.evidence_id),
            )

        with self.assertRaises(ValueError):
            self._generate(gateway)

        self.assertEqual(provider.requests, [])

    def test_response_schema_rejects_executable_payload_keys(self):
        payload = json.loads(_revision_plan_json())
        payload["commands"] = ["apply-change"]
        gateway, _ = self._gateway(
            json.dumps(payload, sort_keys=True, separators=(",", ":"))
        )

        with self.assertRaisesRegex(ValueError, "response schema mismatch"):
            self._generate(gateway)

    def test_duplicate_plan_item_ids_and_invalid_change_area_are_rejected(self):
        payload = json.loads(_revision_plan_json())
        payload["plan_items"].append(dict(payload["plan_items"][0]))
        gateway, _ = self._gateway(
            json.dumps(payload, sort_keys=True, separators=(",", ":"))
        )
        with self.assertRaisesRegex(ValueError, "must be unique"):
            self._generate(gateway)

        payload = json.loads(_revision_plan_json())
        payload["plan_items"][0]["change_area"] = "target_exploitation"
        gateway, _ = self._gateway(
            json.dumps(payload, sort_keys=True, separators=(",", ":"))
        )
        with self.assertRaisesRegex(ValueError, "change_area is invalid"):
            self._generate(gateway)

    def test_provider_cannot_substitute_model_identity(self):
        gateway, provider = self._gateway(
            response_model_id="unexpected-revision-model",
        )

        with self.assertRaisesRegex(ValueError, "wrong model identity"):
            self._generate(gateway)

        self.assertEqual(len(provider.requests), 1)

    def test_same_response_and_lineage_produce_same_revised_plan_digest(self):
        first_gateway, _ = self._gateway()
        second_gateway, _ = self._gateway()

        first = self._generate(first_gateway)
        second = self._generate(second_gateway)

        self.assertEqual(first.revised_plan_sha256, second.revised_plan_sha256)
        self.assertEqual(first.to_json(), second.to_json())


if __name__ == "__main__":
    unittest.main()
