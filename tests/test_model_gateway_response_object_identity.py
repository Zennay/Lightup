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
    def __init__(self, request: ModelRequest):
        self.provider_id = "response-provider"
        self.model_id = request.model_id
        self.role = request.role
        self.content = "bounded defensive guidance"


class ExplosiveDuckResponse:
    @property
    def provider_id(self):
        raise AssertionError(
            "gateway must reject a non-ModelResponse before reading provider attributes"
        )


class SubclassedModelResponse(ModelResponse):
    pass


class ResponseShapeProvider(ModelProvider):
    def __init__(self, mode: str):
        self.mode = mode

    @property
    def provider_id(self) -> str:
        return "response-provider"

    def complete(self, request: ModelRequest) -> ModelResponse:
        if self.mode == "duck":
            return DuckResponse(request)  # type: ignore[return-value]
        if self.mode == "explosive-duck":
            return ExplosiveDuckResponse()  # type: ignore[return-value]
        if self.mode == "subclass":
            return SubclassedModelResponse(
                provider_id=self.provider_id,
                model_id=request.model_id,
                role=request.role,
                content="bounded defensive guidance",
            )
        return ModelResponse(
            provider_id=self.provider_id,
            model_id=request.model_id,
            role=request.role,
            content="bounded defensive guidance",
        )


class ModelGatewayResponseObjectIdentityTest(unittest.TestCase):
    @staticmethod
    def _gateway(mode: str) -> ModelGateway:
        gateway = ModelGateway()
        provider = ResponseShapeProvider(mode)
        gateway.register_provider(provider)
        gateway.bind_role(
            ModelRole.REMEDIATION_ADVISOR,
            provider.provider_id,
            "remediation-model-v1",
        )
        return gateway

    @staticmethod
    def _complete(gateway: ModelGateway):
        return gateway.complete(
            ModelRole.REMEDIATION_ADVISOR,
            (ModelMessage("user", "return bounded defensive guidance"),),
        )

    def test_exact_model_response_remains_green(self):
        response = self._complete(self._gateway("exact"))

        self.assertIs(type(response), ModelResponse)
        self.assertEqual(response.provider_id, "response-provider")
        self.assertEqual(response.model_id, "remediation-model-v1")
        self.assertIs(response.role, ModelRole.REMEDIATION_ADVISOR)
        self.assertEqual(response.content, "bounded defensive guidance")

    def test_duck_typed_provider_response_fails_closed(self):
        with self.assertRaises(GatewayConfigurationError):
            self._complete(self._gateway("duck"))

    def test_non_response_fails_before_provider_attribute_access(self):
        with self.assertRaises(GatewayConfigurationError):
            self._complete(self._gateway("explosive-duck"))

    def test_model_response_subclass_fails_closed(self):
        with self.assertRaises(GatewayConfigurationError):
            self._complete(self._gateway("subclass"))


if __name__ == "__main__":
    unittest.main()
