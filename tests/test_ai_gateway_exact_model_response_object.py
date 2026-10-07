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


class DuckResponse:
    provider_id = "fixed-provider"
    model_id = "fixed-model"
    role = ModelRole.REMEDIATION_ADVISOR
    content = "canonical-looking remediation prose"


class ResponseSubclass(ModelResponse):
    pass


class FixedProvider(ModelProvider):
    def __init__(self, response: object) -> None:
        self._response = response

    @property
    def provider_id(self) -> str:
        return "fixed-provider"

    def complete(self, request: ModelRequest) -> ModelResponse:
        return self._response  # type: ignore[return-value]


def _complete(response: object):
    gateway = ModelGateway()
    gateway.register_provider(FixedProvider(response))
    gateway.bind_role(ModelRole.REMEDIATION_ADVISOR, "fixed-provider", "fixed-model")
    return gateway.complete(
        ModelRole.REMEDIATION_ADVISOR,
        (ModelMessage("user", "evidence-bound request"),),
    )


class GatewayExactModelResponseObjectAcceptanceTest(unittest.TestCase):
    def test_exact_model_response_remains_accepted(self) -> None:
        response = ModelResponse(
            provider_id="fixed-provider",
            model_id="fixed-model",
            role=ModelRole.REMEDIATION_ADVISOR,
            content="canonical remediation prose",
        )

        returned = _complete(response)

        self.assertIs(returned, response)
        self.assertIs(type(returned), ModelResponse)

    def test_duck_typed_response_fails_closed(self) -> None:
        with self.assertRaisesRegex(GatewayConfigurationError, "response"):
            _complete(DuckResponse())

    def test_model_response_subclass_fails_closed(self) -> None:
        response = ResponseSubclass(
            provider_id="fixed-provider",
            model_id="fixed-model",
            role=ModelRole.REMEDIATION_ADVISOR,
            content="canonical remediation prose",
        )

        with self.assertRaisesRegex(GatewayConfigurationError, "response"):
            _complete(response)


if __name__ == "__main__":
    unittest.main()
