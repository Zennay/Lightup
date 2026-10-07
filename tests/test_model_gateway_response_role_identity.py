from __future__ import annotations

import unittest

from lightup.ai.gateway import (
    GatewayConfigurationError,
    ModelGateway,
    ModelMessage,
    ModelProvider,
    ModelRequest,
    ModelResponse,
    ModelRole,
)


class ResponseRoleProvider(ModelProvider):
    def __init__(self, response_role: object):
        self._response_role = response_role

    @property
    def provider_id(self) -> str:
        return "role-provider"

    def complete(self, request: ModelRequest) -> ModelResponse:
        return ModelResponse(
            provider_id=self.provider_id,
            model_id=request.model_id,
            role=self._response_role,  # type: ignore[arg-type]
            content="bounded defensive guidance",
        )


class ModelGatewayResponseRoleIdentityTest(unittest.TestCase):
    @staticmethod
    def _gateway(response_role: object) -> ModelGateway:
        gateway = ModelGateway()
        provider = ResponseRoleProvider(response_role)
        gateway.register_provider(provider)
        gateway.bind_role(
            ModelRole.REMEDIATION_ADVISOR,
            provider.provider_id,
            "remediation-model-v1",
        )
        return gateway

    @staticmethod
    def _complete(gateway: ModelGateway) -> ModelResponse:
        return gateway.complete(
            ModelRole.REMEDIATION_ADVISOR,
            (ModelMessage("user", "return bounded defensive guidance"),),
        )

    def test_exact_requested_response_role_remains_green(self):
        response = self._complete(
            self._gateway(ModelRole.REMEDIATION_ADVISOR)
        )

        self.assertIs(response.role, ModelRole.REMEDIATION_ADVISOR)
        self.assertEqual(response.provider_id, "role-provider")
        self.assertEqual(response.model_id, "remediation-model-v1")
        self.assertEqual(response.content, "bounded defensive guidance")

    def test_different_model_role_fails_closed_in_gateway(self):
        with self.assertRaises(GatewayConfigurationError):
            self._complete(self._gateway(ModelRole.VERIFIER))

    def test_plain_string_role_with_same_value_fails_closed_in_gateway(self):
        plain_role = "".join(["remediation", "_advisor"])
        self.assertIs(type(plain_role), str)
        self.assertEqual(plain_role, ModelRole.REMEDIATION_ADVISOR.value)

        with self.assertRaises(GatewayConfigurationError):
            self._complete(self._gateway(plain_role))


if __name__ == "__main__":
    unittest.main()
