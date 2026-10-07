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


class PolymorphicContent(str):
    def strip(self, *args, **kwargs):  # pragma: no cover - must never be trusted
        raise AssertionError("provider-controlled string behavior must not cross gateway")


class FixedProvider(ModelProvider):
    def __init__(self, content: str) -> None:
        self._content = content

    @property
    def provider_id(self) -> str:
        return "fixed-provider"

    def complete(self, request: ModelRequest) -> ModelResponse:
        return ModelResponse(
            provider_id=self.provider_id,
            model_id=request.model_id,
            role=request.role,
            content=self._content,
        )


def _gateway(content: str) -> ModelGateway:
    gateway = ModelGateway()
    gateway.register_provider(FixedProvider(content))
    gateway.bind_role(ModelRole.REMEDIATION_ADVISOR, "fixed-provider", "fixed-model")
    return gateway


class GatewayResponseContentExactTypeAcceptanceTest(unittest.TestCase):
    def test_exact_builtin_response_content_remains_accepted(self) -> None:
        response = _gateway("canonical remediation prose").complete(
            ModelRole.REMEDIATION_ADVISOR,
            (ModelMessage("user", "evidence-bound request"),),
        )

        self.assertIs(type(response.content), str)
        self.assertEqual(response.content, "canonical remediation prose")

    def test_polymorphic_response_content_fails_closed_at_gateway(self) -> None:
        content = PolymorphicContent("canonical-looking remediation prose")

        with self.assertRaisesRegex(
            GatewayConfigurationError,
            "content",
        ):
            _gateway(content).complete(
                ModelRole.REMEDIATION_ADVISOR,
                (ModelMessage("user", "evidence-bound request"),),
            )

        self.assertIs(type(content), PolymorphicContent)
        self.assertEqual(str(content), "canonical-looking remediation prose")


if __name__ == "__main__":
    unittest.main()
