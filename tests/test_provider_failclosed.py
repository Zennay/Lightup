"""Offline adapter tests: no credentials or model requests leave the process."""
import contextlib
import io
import json
import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from lightup.ai.config import gateway_from_dict
from lightup.ai.gateway import GatewayConfigurationError, ModelMessage, ModelRequest, ModelRole
from lightup.ai.providers.anthropic_provider import AnthropicProvider, ModelProviderError
from lightup.labrun import main_assess


class ApiError(Exception):
    status_code = 503


class RateError(ApiError):
    pass


class ConnectionError(ApiError):
    pass


class ProviderFailClosedTest(unittest.TestCase):
    def setUp(self):
        self.client = Mock()
        self.sdk = SimpleNamespace(Anthropic=Mock(return_value=self.client),
                                   APIStatusError=ApiError, RateLimitError=RateError,
                                   APIConnectionError=ConnectionError)
        self.module_patch = patch.dict(sys.modules, {"anthropic": self.sdk})
        self.module_patch.start()
        self.addCleanup(self.module_patch.stop)
        self.env_patch = patch.dict(os.environ, {"TEST_MODEL_KEY": "offline-test-key"}, clear=True)
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)
        self.request = ModelRequest(ModelRole.VERIFIER, (ModelMessage("user", "test"),),
                                    "configured-model")
        self.client.messages.create.return_value = SimpleNamespace(
            stop_reason="end_turn", content=[SimpleNamespace(type="text", text="verified")],
            usage=SimpleNamespace(input_tokens=10, output_tokens=3))

    def provider(self):
        return AnthropicProvider(api_key_env="TEST_MODEL_KEY", provider_id="review-model")

    def test_configured_alias_routes_request_and_response(self):
        gateway = gateway_from_dict({
            "providers": {"review-model": {"type": "anthropic", "api_key_env": "TEST_MODEL_KEY"}},
            "roles": {"verifier": {"provider": "review-model", "model": "configured-model"}}})
        response = gateway.complete(ModelRole.VERIFIER, (ModelMessage("user", "test"),))
        self.assertEqual(response.provider_id, "review-model")
        self.assertEqual(response.content, "verified")
        self.sdk.Anthropic.assert_called_once_with(
            api_key="offline-test-key", timeout=60.0, max_retries=0)

    def test_missing_custom_key_never_falls_back_to_default_credentials(self):
        os.environ["ANTHROPIC_API_KEY"] = "unrelated-key"
        with self.assertRaises(ModelProviderError):
            AnthropicProvider(api_key_env="MISSING_CUSTOM_KEY")
        self.sdk.Anthropic.assert_not_called()

    def test_empty_explicit_key_does_not_fall_back(self):
        with self.assertRaises(ModelProviderError):
            AnthropicProvider(api_key_env="TEST_MODEL_KEY", api_key="")
        self.sdk.Anthropic.assert_not_called()

    def test_initialization_errors_are_sanitized(self):
        self.sdk.Anthropic.side_effect = ValueError("private-key-and-payload")
        with self.assertRaises(ModelProviderError) as raised:
            self.provider()
        self.assertNotIn("private-key-and-payload", str(raised.exception))
        self.assertTrue(raised.exception.__suppress_context__)

    def test_api_errors_are_sanitized(self):
        provider = self.provider()
        for error in (RateError, ApiError, ConnectionError):
            with self.subTest(error=error), self.assertRaises(ModelProviderError) as raised:
                self.client.messages.create.side_effect = error("private-payload")
                provider.complete(self.request)
            self.assertNotIn("private-payload", str(raised.exception))
            self.assertTrue(raised.exception.__suppress_context__)

    def test_refused_truncated_and_nonfinal_output_is_rejected(self):
        provider = self.provider()
        for reason in ("refusal", "max_tokens", "tool_use", "pause_turn", None):
            with self.subTest(reason=reason), self.assertRaises(ModelProviderError):
                self.client.messages.create.return_value.stop_reason = reason
                provider.complete(self.request)

    def test_empty_or_malformed_text_is_rejected(self):
        provider = self.provider()
        for blocks in ([], [SimpleNamespace(type="text", text="  ")],
                       [SimpleNamespace(type="text", text=None)]):
            with self.subTest(blocks=blocks), self.assertRaises(ModelProviderError):
                self.client.messages.create.return_value.content = blocks
                provider.complete(self.request)

    def test_invalid_config_shapes_raise_configuration_error(self):
        configs = [None, [], "config", 5,
                   {"providers": {"a": {"type": "scripted", "api_key": "secret"}},
                    "roles": {"planner": {"provider": "a", "model": "m"}}},
                   {"providers": {"a": {"type": "anthropic", "api_key_env": None}},
                    "roles": {"planner": {"provider": "a", "model": "m"}}}]
        for model in (None, 3, [], {}):
            configs.append({"providers": {"s": {"type": "scripted"}},
                            "roles": {"planner": {"provider": "s", "model": model}}})
        for config in configs:
            with self.subTest(config=config), self.assertRaises(GatewayConfigurationError):
                gateway_from_dict(config)
        self.sdk.Anthropic.assert_not_called()

    def test_planner_provider_failure_returns_json_without_execution(self):
        stdout = io.StringIO()
        with patch("lightup.ai.config.load_gateway", return_value=Mock()), \
             patch("lightup.labrun.run_planned_assessment",
                   side_effect=ModelProviderError("provider unavailable")), \
             contextlib.redirect_stdout(stdout):
            code = main_assess(["http://127.0.0.1:18081/", "--gateway-config", "unused"])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(stdout.getvalue()), {"error": "provider unavailable"})

    def test_failed_requested_review_preserves_result_and_fails_cli(self):
        stdout = io.StringIO()
        with patch("lightup.labrun.run_planned_assessment", return_value={"findings": []}), \
             patch("lightup.ai.pipeline.AssessmentReviewPipeline.review",
                   side_effect=ModelProviderError("review unavailable")), \
             contextlib.redirect_stdout(stdout):
            code = main_assess(["http://127.0.0.1:18081/"])
        result = json.loads(stdout.getvalue())
        self.assertEqual(code, 2)
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["review_skipped"], "review unavailable")


if __name__ == "__main__":
    unittest.main()
