from __future__ import annotations

import json
import unittest

import test_future_remediation_implementation_plan_request as request_tests
import test_future_remediation_text_proposal as proposal_tests
from lightup.ai.gateway import ModelGateway, ModelRole
from lightup.future_remediation_implementation_plan import (
    REMEDIATION_IMPLEMENTATION_PLAN_SCHEMA_VERSION,
    generate_future_remediation_implementation_plan,
)


def _plan_json() -> str:
    return json.dumps(
        {
            "summary": (
                "Apply the reviewed defensive control as a bounded change and keep "
                "future-state verification separate from implementation."
            ),
            "plan_items": [
                {
                    "plan_item_id": "plan-1",
                    "change_area": "configuration",
                    "intent": "Tighten the affected defensive control.",
                    "verification_intent": (
                        "Confirm the intended control behavior in separately "
                        "authorized future-state validation."
                    ),
                    "rollback_intent": (
                        "Restore the prior reviewed configuration if the planned "
                        "change causes a regression."
                    ),
                }
            ],
            "assumptions": [
                "The accepted remediation proposal remains evidence-aligned."
            ],
            "unresolved_questions": [],
        },
        sort_keys=True,
        separators=(",", ":"),
    )


class FutureRemediationImplementationPlanTest(unittest.TestCase):
    def setUp(self):
        self.base = request_tests.FutureRemediationImplementationPlanRequestTest(
            "test_approved_review_requests_planning_without_action_authority"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.planning_request = self.base._build()

    def _gateway(self, content: str = _plan_json(), **provider_kwargs):
        provider = proposal_tests.RecordingProvider(
            content,
            provider_id="implementation-planner",
            **provider_kwargs,
        )
        gateway = ModelGateway()
        gateway.register_provider(provider)
        gateway.bind_role(
            ModelRole.REMEDIATION_ADVISOR,
            provider.provider_id,
            "implementation-planner-v1",
        )
        return gateway, provider

    def _generate(self, gateway: ModelGateway):
        return generate_future_remediation_implementation_plan(
            self.planning_request.to_json(),
            self.base.review.to_json(),
            self.base.base.review_request.to_json(),
            self.base.base.proposal.to_json(),
            self.base.base.base.request,
            self.base.base.base.bundle,
            self.base.base.base.plan,
            self.base.base.base.report,
            self.base.base.base.preview,
            self.base.base.base.transition_proposal,
            (self.base.base.base.resolution,),
            (self.base.base.base.context,),
            self.base.base.base.state,
            gateway,
        )

    def test_live_approved_request_generates_non_executable_plan(self):
        gateway, provider = self._gateway()

        plan = self._generate(gateway)

        self.assertEqual(
            plan.schema_version,
            REMEDIATION_IMPLEMENTATION_PLAN_SCHEMA_VERSION,
        )
        self.assertEqual(
            plan.implementation_request_sha256,
            self.planning_request.implementation_request_sha256,
        )
        self.assertEqual(plan.review_sha256, self.base.review.review_sha256)
        self.assertEqual(
            plan.proposal_sha256,
            self.base.base.proposal.proposal_sha256,
        )
        self.assertEqual(plan.content_sha256, self.base.base.proposal.content_sha256)
        self.assertEqual(len(plan.plan_items), 1)
        self.assertEqual(plan.plan_items[0].change_area, "configuration")
        self.assertEqual(len(plan.plan_sha256), 64)

        self.assertTrue(plan.implementation_plan_created)
        self.assertFalse(plan.code_change_authorized)
        self.assertFalse(plan.tool_call_created)
        self.assertFalse(plan.execution_allowed)
        self.assertFalse(plan.target_interaction_allowed)
        self.assertFalse(plan.future_state_retest_allowed)
        self.assertFalse(plan.deployment_authorized)
        self.assertFalse(plan.attack_path_mutation_allowed)
        self.assertEqual(plan.future_semantics, "unresolved")
        self.assertEqual(plan.security_verdict, "not_evaluated")

        self.assertEqual(len(provider.requests), 1)
        model_request = provider.requests[0]
        self.assertEqual(model_request.role, ModelRole.REMEDIATION_ADVISOR)
        self.assertEqual(model_request.max_output_tokens, 2000)
        self.assertEqual(
            dict(model_request.metadata)["implementation_request_sha256"],
            self.planning_request.implementation_request_sha256,
        )

    def test_model_context_is_evidence_bounded_and_omits_state_payloads(self):
        gateway, provider = self._gateway()

        self._generate(gateway)

        user_content = provider.requests[0].messages[1].content.lower()
        self.assertIn(self.base.base.proposal.proposal_sha256, user_content)
        self.assertIn(
            self.base.base.base.request.items[0].evidence[0].sha256,
            user_content,
        )
        for forbidden in (
            '"source"',
            '"metadata"',
            '"credentials"',
            '"authorization_ref"',
            '"target_arguments"',
        ):
            self.assertNotIn(forbidden, user_content)

    def test_live_evidence_drift_fails_before_model_invocation(self):
        gateway, provider = self._gateway()
        evidence_id = self.base.base.base.bundle.items[0].evidence[0].evidence_id
        current_sha = self.base.base.base.bundle.items[0].evidence[0].sha256
        replacement = "f" * 64 if current_sha != "f" * 64 else "e" * 64
        with self.base.base.base.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                (replacement, evidence_id),
            )

        with self.assertRaises(ValueError):
            self._generate(gateway)

        self.assertEqual(provider.requests, [])

    def test_response_schema_rejects_executable_payload_keys(self):
        payload = json.loads(_plan_json())
        payload["commands"] = ["apply-change"]
        gateway, _ = self._gateway(
            json.dumps(payload, sort_keys=True, separators=(",", ":"))
        )

        with self.assertRaisesRegex(ValueError, "response schema mismatch"):
            self._generate(gateway)

    def test_duplicate_plan_item_ids_and_invalid_change_area_are_rejected(self):
        payload = json.loads(_plan_json())
        payload["plan_items"].append(dict(payload["plan_items"][0]))
        gateway, _ = self._gateway(
            json.dumps(payload, sort_keys=True, separators=(",", ":"))
        )
        with self.assertRaisesRegex(ValueError, "must be unique"):
            self._generate(gateway)

        payload = json.loads(_plan_json())
        payload["plan_items"][0]["change_area"] = "target_exploitation"
        gateway, _ = self._gateway(
            json.dumps(payload, sort_keys=True, separators=(",", ":"))
        )
        with self.assertRaisesRegex(ValueError, "change_area is invalid"):
            self._generate(gateway)

    def test_provider_cannot_substitute_model_identity(self):
        gateway, provider = self._gateway(
            response_model_id="unexpected-model",
        )

        with self.assertRaisesRegex(ValueError, "wrong model identity"):
            self._generate(gateway)

        self.assertEqual(len(provider.requests), 1)

    def test_same_response_and_lineage_produce_same_plan_digest(self):
        first_gateway, _ = self._gateway()
        second_gateway, _ = self._gateway()

        first = self._generate(first_gateway)
        second = self._generate(second_gateway)

        self.assertEqual(first.plan_sha256, second.plan_sha256)
        self.assertEqual(first.to_json(), second.to_json())


if __name__ == "__main__":
    unittest.main()
