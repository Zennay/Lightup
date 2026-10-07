from __future__ import annotations

import unittest

import test_future_remediation_evidence_bundle as bundle_tests
from lightup.ai.gateway import (
    ModelGateway,
    ModelProvider,
    ModelRequest,
    ModelResponse,
    ModelRole,
)
from lightup.future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from lightup.future_remediation_authoring_request import (
    build_future_remediation_authoring_request,
)
from lightup.future_remediation_evidence_bundle_handoff import (
    load_and_validate_future_remediation_evidence_bundle,
)
from lightup.future_remediation_text_proposal import (
    REMEDIATION_TEXT_PROPOSAL_SCHEMA_VERSION,
    generate_future_remediation_text_proposal,
)


class RecordingProvider(ModelProvider):
    def __init__(
        self,
        content: str,
        *,
        provider_id: str = "recording",
        response_model_id: str | None = None,
        response_role: ModelRole | None = None,
    ):
        self._provider_id = provider_id
        self.content = content
        self.response_model_id = response_model_id
        self.response_role = response_role
        self.requests: list[ModelRequest] = []

    @property
    def provider_id(self) -> str:
        return self._provider_id

    def complete(self, request: ModelRequest) -> ModelResponse:
        self.requests.append(request)
        return ModelResponse(
            provider_id=self._provider_id,
            model_id=self.response_model_id or request.model_id,
            role=self.response_role or request.role,
            content=self.content,
        )


class FutureRemediationTextProposalTest(unittest.TestCase):
    def setUp(self):
        self.base = bundle_tests.FutureRemediationEvidenceBundleTest(
            "test_bundle_is_deterministic_and_json_serializable"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        self.state = self.base.state
        self.produced = self.base._bundle(
            AttackPathTransitionClassification.INTRODUCED,
            suffix="remediation-text-proposal",
        )
        (
            _,
            self.transition_proposal,
            self.context,
            self.resolution,
            self.preview,
            self.report,
            self.plan,
            raw_bundle,
        ) = self.produced
        self.bundle = load_and_validate_future_remediation_evidence_bundle(
            raw_bundle.to_json(),
            self.plan,
            self.report,
            self.preview,
            self.transition_proposal,
            (self.resolution,),
            (self.context,),
            self.state,
        )
        self.request = build_future_remediation_authoring_request(
            self.bundle,
            self.plan,
            self.report,
            self.preview,
            self.transition_proposal,
            (self.resolution,),
            (self.context,),
            self.state,
        )

    def _gateway(
        self,
        content: str = (
            "Reduce the introduced exposure by tightening the affected control, "
            "then perform the separately authorized future-state retest before "
            "treating the finding as resolved."
        ),
        **provider_kwargs,
    ):
        provider = RecordingProvider(content, **provider_kwargs)
        gateway = ModelGateway()
        gateway.register_provider(provider)
        gateway.bind_role(
            ModelRole.REMEDIATION_ADVISOR,
            provider.provider_id,
            "remediation-model-v1",
        )
        return gateway, provider

    def _generate(self, gateway: ModelGateway):
        return generate_future_remediation_text_proposal(
            self.request,
            self.bundle,
            self.plan,
            self.report,
            self.preview,
            self.transition_proposal,
            (self.resolution,),
            (self.context,),
            self.state,
            gateway,
        )

    def test_live_valid_request_generates_bounded_non_executable_proposal(self):
        gateway, provider = self._gateway()

        result = self._generate(gateway)

        self.assertEqual(
            result.schema_version,
            REMEDIATION_TEXT_PROPOSAL_SCHEMA_VERSION,
        )
        self.assertEqual(result.request_sha256, self.request.request_sha256)
        self.assertEqual(result.bundle_sha256, self.bundle.bundle_sha256)
        self.assertEqual(result.item_count, self.request.item_count)
        self.assertTrue(result.remediation_proposal_created)
        self.assertFalse(result.code_change_authorized)
        self.assertFalse(result.tool_call_created)
        self.assertFalse(result.execution_allowed)
        self.assertFalse(result.target_interaction_allowed)
        self.assertFalse(result.future_state_retest_allowed)
        self.assertFalse(result.deployment_authorized)
        self.assertFalse(result.attack_path_mutation_allowed)
        self.assertEqual(result.future_semantics, "unresolved")
        self.assertEqual(result.security_verdict, "not_evaluated")
        self.assertEqual(len(result.content_sha256), 64)
        self.assertEqual(len(result.proposal_sha256), 64)

        self.assertEqual(len(provider.requests), 1)
        model_request = provider.requests[0]
        self.assertEqual(model_request.role, ModelRole.REMEDIATION_ADVISOR)
        self.assertEqual(model_request.max_output_tokens, 1200)
        self.assertEqual(
            dict(model_request.metadata)["request_sha256"],
            self.request.request_sha256,
        )

    def test_model_receives_bounded_evidence_refs_not_state_source_or_metadata(self):
        gateway, provider = self._gateway()

        self._generate(gateway)

        user_content = provider.requests[0].messages[1].content.lower()
        self.assertIn(self.request.request_sha256, user_content)
        self.assertIn(self.bundle.items[0].evidence[0].sha256, user_content)
        for forbidden in (
            '"source"',
            '"metadata"',
            '"credentials"',
            '"target"',
            '"authorization_ref"',
        ):
            self.assertNotIn(forbidden, user_content)

    def test_live_evidence_drift_fails_before_model_invocation(self):
        gateway, provider = self._gateway()
        evidence_id = self.bundle.items[0].evidence[0].evidence_id
        current_sha = self.bundle.items[0].evidence[0].sha256
        replacement = "f" * 64 if current_sha != "f" * 64 else "e" * 64
        with self.state.connect() as con:
            con.execute(
                "UPDATE evidence SET sha256=? WHERE evidence_id=?",
                (replacement, evidence_id),
            )

        with self.assertRaises(ValueError):
            self._generate(gateway)

        self.assertEqual(provider.requests, [])

    def test_provider_cannot_substitute_model_identity(self):
        gateway, provider = self._gateway(
            response_model_id="unexpected-model",
        )

        with self.assertRaisesRegex(ValueError, "wrong model identity"):
            self._generate(gateway)

        self.assertEqual(len(provider.requests), 1)

    def test_empty_or_oversized_model_output_is_rejected(self):
        for content, message in (
            ("   ", "empty content"),
            ("x" * 16001, "bounded output size"),
        ):
            with self.subTest(message=message):
                gateway, _ = self._gateway(content)
                with self.assertRaisesRegex(ValueError, message):
                    self._generate(gateway)

    def test_same_response_and_lineage_produce_same_canonical_digest(self):
        first_gateway, _ = self._gateway("Apply the defensive control and retest later.")
        second_gateway, _ = self._gateway("Apply the defensive control and retest later.")

        first = self._generate(first_gateway)
        second = self._generate(second_gateway)

        self.assertEqual(first.content_sha256, second.content_sha256)
        self.assertEqual(first.proposal_sha256, second.proposal_sha256)
        self.assertEqual(first.to_json(), second.to_json())


if __name__ == "__main__":
    unittest.main()
