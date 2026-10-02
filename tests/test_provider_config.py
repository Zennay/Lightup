from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from lightup.ai.config import gateway_from_dict, load_gateway
from lightup.ai.gateway import GatewayConfigurationError, ModelMessage, ModelRequest, ModelRole
from lightup.ai.providers.anthropic_provider import (
    DEFAULT_MODEL,
    ModelProviderError,
    build_request_kwargs,
)


def _request(messages, model=DEFAULT_MODEL, max_tokens=512):
    return ModelRequest(role=ModelRole.VERIFIER, messages=tuple(messages),
                        model_id=model, max_output_tokens=max_tokens)


class RequestShapingTest(unittest.TestCase):
    """The Anthropic request mapping is pure and testable offline."""

    def test_system_messages_become_system_param(self):
        kwargs = build_request_kwargs(_request([
            ModelMessage("system", "You are the verifier."),
            ModelMessage("system", "Be strict."),
            ModelMessage("user", "Check this finding."),
        ]))
        self.assertEqual(kwargs["system"], "You are the verifier.\n\nBe strict.")
        self.assertEqual(kwargs["messages"],
                         [{"role": "user", "content": "Check this finding."}])
        self.assertEqual(kwargs["model"], DEFAULT_MODEL)
        self.assertEqual(kwargs["max_tokens"], 512)

    def test_no_system_messages(self):
        kwargs = build_request_kwargs(_request([ModelMessage("user", "hi")]))
        self.assertNotIn("system", kwargs)

    def test_requires_a_non_system_message(self):
        with self.assertRaises(ModelProviderError):
            build_request_kwargs(_request([ModelMessage("system", "only system")]))

    def test_conversation_order_preserved(self):
        kwargs = build_request_kwargs(_request([
            ModelMessage("user", "a"),
            ModelMessage("assistant", "b"),
            ModelMessage("user", "c"),
        ]))
        self.assertEqual([m["role"] for m in kwargs["messages"]],
                         ["user", "assistant", "user"])


class GatewayConfigTest(unittest.TestCase):
    def test_scripted_config_roundtrip(self):
        gateway = gateway_from_dict({
            "providers": {"scripted": {"type": "scripted"}},
            "roles": {"planner": {"provider": "scripted", "model": "lab-model"}},
        })
        response = gateway.complete(ModelRole.PLANNER,
                                    (ModelMessage("user", "plan it"),))
        self.assertEqual(response.model_id, "lab-model")

    def test_invalid_configs_fail_loudly(self):
        bad_configs = [
            {},
            {"providers": {}, "roles": {}},
            {"providers": {"x": {"type": "mystery"}}, "roles": {"planner": {}}},
            {"providers": {"scripted": {"type": "scripted"}},
             "roles": {"not-a-role": {"provider": "scripted", "model": "m"}}},
            {"providers": {"scripted": {"type": "scripted"}},
             "roles": {"planner": {"provider": "missing", "model": "m"}}},
            {"providers": {"scripted": {"type": "scripted"}},
             "roles": {"planner": {"provider": "scripted", "model": ""}}},
        ]
        for config in bad_configs:
            with self.assertRaises(GatewayConfigurationError, msg=config):
                gateway_from_dict(config)

    def test_load_gateway_from_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "gateway.json"
            path.write_text(json.dumps({
                "providers": {"scripted": {"type": "scripted"}},
                "roles": {"verifier": {"provider": "scripted", "model": "m"}},
            }))
            gateway = load_gateway(path)
            self.assertEqual(gateway.binding_for(ModelRole.VERIFIER).model_id, "m")
        with self.assertRaises(GatewayConfigurationError):
            load_gateway(Path(tmp) / "missing.json")

    def test_anthropic_provider_without_sdk_fails_cleanly(self):
        try:
            import anthropic  # noqa: F401
            self.skipTest("anthropic SDK installed; the no-SDK path is not testable here")
        except ImportError:
            pass
        with self.assertRaises(GatewayConfigurationError) as caught:
            gateway_from_dict({
                "providers": {"anthropic": {"type": "anthropic"}},
                "roles": {"planner": {"provider": "anthropic", "model": DEFAULT_MODEL}},
            })
        self.assertIn("lightup[anthropic]", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
