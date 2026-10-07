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
    ScriptedProvider,
)


class EqualitySpoofProviderId(str):
    def __new__(cls):
        return super().__new__(cls, "forged-provider")

    def __eq__(self, other):
        return other == "spoof-provider"

    def __ne__(self, other):
        return False


class EqualitySpoofModelId(str):
    def __new__(cls):
        return super().__new__(cls, "forged-model")

    def __eq__(self, other):
        return other == "lab-model"

    def __ne__(self, other):
        return False


class ResponseProviderSpoof(ModelProvider):
    @property
    def provider_id(self) -> str:
        return "spoof-provider"

    def complete(self, request: ModelRequest) -> ModelResponse:
        return ModelResponse(
            provider_id=EqualitySpoofProviderId(),
            model_id=request.model_id,
            role=request.role,
            content="ok",
        )


class ResponseModelSpoof(ModelProvider):
    @property
    def provider_id(self) -> str:
        return "model-spoof-provider"

    def complete(self, request: ModelRequest) -> ModelResponse:
        return ModelResponse(
            provider_id=self.provider_id,
            model_id=EqualitySpoofModelId(),
            role=request.role,
            content="ok",
        )


class ModelGatewayTest(unittest.TestCase):
    def setUp(self):
        self.gateway = ModelGateway()
        self.provider = ScriptedProvider(
            "scripted", {ModelRole.PLANNER: ["plan: enumerate surface"]}
        )
        self.gateway.register_provider(self.provider)

    def test_unbound_role_fails_closed(self):
        with self.assertRaises(GatewayConfigurationError):
            self.gateway.complete(
                ModelRole.PLANNER,
                (ModelMessage("user", "make a plan"),),
            )

    def test_role_routing_is_configuration(self):
        self.gateway.bind_role(ModelRole.PLANNER, "scripted", "lab-model-1")
        self.gateway.bind_role(ModelRole.VERIFIER, "scripted", "lab-model-2")
        planned = self.gateway.complete(
            ModelRole.PLANNER,
            (ModelMessage("user", "make a plan"),),
        )
        self.assertEqual(planned.content, "plan: enumerate surface")
        self.assertEqual(planned.model_id, "lab-model-1")
        verified = self.gateway.complete(
            ModelRole.VERIFIER,
            (ModelMessage("user", "check finding"),),
        )
        self.assertEqual(verified.model_id, "lab-model-2")
        self.assertEqual(verified.content, "[verifier] check finding")
        self.assertEqual(len(self.gateway.bindings()), 2)

    def test_unknown_provider_rejected(self):
        with self.assertRaises(GatewayConfigurationError):
            self.gateway.bind_role(ModelRole.PLANNER, "nonexistent", "m")

    def test_duplicate_provider_rejected(self):
        with self.assertRaises(GatewayConfigurationError):
            self.gateway.register_provider(ScriptedProvider("scripted"))

    def test_request_validation(self):
        with self.assertRaises(ValueError):
            ModelMessage("tool", "x")
        self.gateway.bind_role(ModelRole.PLANNER, "scripted", "m")
        with self.assertRaises(ValueError):
            self.gateway.complete(ModelRole.PLANNER, ())

    def test_response_provider_identity_requires_exact_string(self):
        provider = ResponseProviderSpoof()
        gateway = ModelGateway()
        gateway.register_provider(provider)
        gateway.bind_role(ModelRole.PLANNER, provider.provider_id, "lab-model")

        with self.assertRaisesRegex(
            GatewayConfigurationError,
            "provider returned a response under a different provider_id",
        ):
            gateway.complete(
                ModelRole.PLANNER,
                (ModelMessage("user", "make a plan"),),
            )

    def test_response_model_identity_requires_exact_string(self):
        provider = ResponseModelSpoof()
        gateway = ModelGateway()
        gateway.register_provider(provider)
        gateway.bind_role(ModelRole.PLANNER, provider.provider_id, "lab-model")

        with self.assertRaisesRegex(
            GatewayConfigurationError,
            "provider returned a response under a different model_id",
        ):
            gateway.complete(
                ModelRole.PLANNER,
                (ModelMessage("user", "make a plan"),),
            )


if __name__ == "__main__":
    unittest.main()
