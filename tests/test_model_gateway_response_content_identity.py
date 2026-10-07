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


class PolymorphicResponseContent(str):
    def __new__(cls, value: str = "bounded defensive guidance"):
        return super().__new__(cls, value)

    def strip(self, chars=None):
        raise AssertionError(
            "provider-controlled string methods must not reach remediation consumers"
        )


class ContentProvider(ModelProvider):
    def __init__(self, content: str):
        self._content = content

    @property
    def provider_id(self) -> str:
        return "content-provider"

    def complete(self, request: ModelRequest) -> ModelResponse:
        return ModelResponse(
            provider_id=self.provider_id,
            model_id=request.model_id,
            role=request.role,
            content=self._content,
        )


class ModelGatewayResponseContentIdentityTest(unittest.TestCase):
    @staticmethod
    def _gateway(content: str) -> ModelGateway:
        gateway = ModelGateway()
        provider = ContentProvider(content)
        gateway.register_provider(provider)
        gateway.bind_role(
            ModelRole.REMEDIATION_ADVISOR,
            provider.provider_id,
            "remediation-model-v1",
        )
        return gateway

    @staticmethod
    def _messages() -> tuple[ModelMessage, ...]:
        return (ModelMessage("user", "return bounded defensive guidance"),)

    def test_exact_builtin_response_content_remains_green(self):
        gateway = self._gateway("bounded defensive guidance")

        response = gateway.complete(
            ModelRole.REMEDIATION_ADVISOR,
            self._messages(),
        )

        self.assertIs(type(response.content), str)
        self.assertEqual(response.content, "bounded defensive guidance")
        self.assertEqual(response.provider_id, "content-provider")
        self.assertEqual(response.model_id, "remediation-model-v1")
        self.assertIs(response.role, ModelRole.REMEDIATION_ADVISOR)

    def test_string_subclass_response_content_fails_closed_in_gateway(self):
        gateway = self._gateway(PolymorphicResponseContent())

        with self.assertRaises(GatewayConfigurationError):
            gateway.complete(
                ModelRole.REMEDIATION_ADVISOR,
                self._messages(),
            )


if __name__ == "__main__":
    unittest.main()
