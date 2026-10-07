from __future__ import annotations

import unittest

import test_future_remediation_implementation_plan_revision_proposal as revision_tests
from lightup.ai.gateway import (
    GatewayConfigurationError,
    ModelGateway,
    ModelProvider,
    ModelRequest,
    ModelResponse,
    ModelRole,
)


class EqualitySpoofProviderId(str):
    def __new__(cls):
        return super().__new__(cls, "forged-revision-provider")

    def __eq__(self, other):
        return other == "implementation-plan-revision-advisor"

    def __ne__(self, other):
        return False


class ProviderIdentitySpoofProvider(ModelProvider):
    def __init__(self, content: str, *, polymorphic: bool = False):
        self.content = content
        self.polymorphic = polymorphic
        self.requests: list[ModelRequest] = []

    @property
    def provider_id(self) -> str:
        return "implementation-plan-revision-advisor"

    def complete(self, request: ModelRequest) -> ModelResponse:
        self.requests.append(request)
        response_provider_id = (
            EqualitySpoofProviderId()
            if self.polymorphic
            else "forged-revision-provider"
        )
        return ModelResponse(
            provider_id=response_provider_id,
            model_id=request.model_id,
            role=request.role,
            content=self.content,
        )


class FutureRemediationImplementationPlanRevisionProviderIdentityTest(
    unittest.TestCase
):
    def setUp(self):
        self.base = revision_tests.FutureRemediationImplementationPlanRevisionProposalTest(
            "test_live_revision_request_generates_unaccepted_non_executable_revised_plan"
        )
        self.base.setUp()
        self.addCleanup(self.base.tearDown)

    def _gateway(self, *, polymorphic: bool = False):
        provider = ProviderIdentitySpoofProvider(
            revision_tests._revision_plan_json(),
            polymorphic=polymorphic,
        )
        gateway = ModelGateway()
        gateway.register_provider(provider)
        gateway.bind_role(
            ModelRole.REMEDIATION_ADVISOR,
            provider.provider_id,
            "implementation-plan-revision-v1",
        )
        return gateway, provider

    def test_canonical_bound_provider_identity_remains_accepted(self):
        gateway, provider = self.base._gateway()

        result = self.base._generate(gateway)

        self.assertIs(type(result.provider_id), str)
        self.assertEqual(result.provider_id, provider.provider_id)
        self.assertEqual(len(provider.requests), 1)
        self.assertFalse(result.implementation_plan_accepted)
        self.assertFalse(result.execution_allowed)
        self.assertFalse(result.target_interaction_allowed)
        self.assertFalse(result.deployment_authorized)

    def test_gateway_rejects_plain_response_provider_identity_substitution(self):
        gateway, provider = self._gateway()

        with self.assertRaisesRegex(
            GatewayConfigurationError,
            "provider returned a response under a different provider_id",
        ):
            self.base._generate(gateway)

        self.assertEqual(len(provider.requests), 1)

    def test_gateway_rejects_polymorphic_provider_identity_substitution(self):
        gateway, provider = self._gateway(polymorphic=True)

        with self.assertRaisesRegex(
            GatewayConfigurationError,
            "provider returned a response under a different provider_id",
        ):
            self.base._generate(gateway)

        self.assertEqual(len(provider.requests), 1)


if __name__ == "__main__":
    unittest.main()
