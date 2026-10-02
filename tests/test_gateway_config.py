from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from lightup.ai.config import (
    MODEL_CONFIG_ENV,
    build_gateway,
    build_gateway_from_config,
    default_scripted_config,
    load_config_from_env,
)
from lightup.ai.gateway import GatewayConfigurationError, ModelMessage, ModelRole
from lightup.ai.pipeline import AssessmentReviewPipeline
from lightup.ai.providers import ProviderCredentialError


class RecordingTransport:
    def __init__(self, payload):
        self.payload = payload
        self.calls = []

    def post_json(self, url, headers, body, timeout):
        self.calls.append({"url": url, "headers": headers, "body": body})
        return 200, self.payload


class DefaultConfigTest(unittest.TestCase):
    def test_default_binds_every_role_offline(self):
        gateway = build_gateway_from_config(default_scripted_config())
        self.assertEqual(len(gateway.bindings()), len(list(ModelRole)))
        resp = gateway.complete(ModelRole.PLANNER, (ModelMessage("user", "go"),))
        self.assertEqual(resp.provider_id, "scripted")

    def test_default_gateway_drives_pipeline_without_credentials(self):
        # The whole review pipeline must run offline on the default config.
        gateway = build_gateway_from_config(default_scripted_config())
        pipeline = AssessmentReviewPipeline(gateway)
        result = pipeline.review({
            "target": "http://127.0.0.1:18080/",
            "evidence_id": "ev-1",
            "findings": [{"finding": "missing CSP", "severity": "medium",
                          "impact": "clickjacking", "fix": "add CSP"}],
            "coverage": {"counts": {"assessed": 1}},
        })
        self.assertEqual(len(result.findings), 1)
        self.assertTrue(result.report)


class EnvConfigTest(unittest.TestCase):
    def test_unset_env_yields_default_scripted(self):
        self.assertEqual(load_config_from_env({}), default_scripted_config())

    def test_build_gateway_offline_by_default(self):
        gateway = build_gateway(env={})
        self.assertEqual(len(gateway.bindings()), len(list(ModelRole)))

    def test_missing_config_file_fails_closed(self):
        with self.assertRaises(GatewayConfigurationError):
            load_config_from_env({MODEL_CONFIG_ENV: "/nonexistent/lightup-model.json"})

    def test_invalid_json_fails_closed(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            path.write_text("{not json", encoding="utf-8")
            with self.assertRaises(GatewayConfigurationError):
                load_config_from_env({MODEL_CONFIG_ENV: str(path)})

    def test_valid_config_file_loaded(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "models.json"
            path.write_text(json.dumps(default_scripted_config()), encoding="utf-8")
            loaded = load_config_from_env({MODEL_CONFIG_ENV: str(path)})
            self.assertEqual(loaded, default_scripted_config())


class RealProviderConfigTest(unittest.TestCase):
    def _real_config(self):
        return {
            "providers": [
                {"id": "anthropic-main", "kind": "anthropic",
                 "api_key_env": "LIGHTUP_ANTHROPIC_API_KEY"},
            ],
            "roles": {
                role.value: {"provider": "anthropic-main", "model": "claude-model-x"}
                for role in ModelRole
            },
        }

    def test_missing_credential_fails_closed(self):
        with self.assertRaises(ProviderCredentialError):
            build_gateway_from_config(self._real_config(), env={})

    def test_credential_present_builds_real_provider_without_network(self):
        transport = RecordingTransport(
            {"content": [{"type": "text", "text": "verdict: confirmed"}]})
        gateway = build_gateway_from_config(
            self._real_config(),
            env={"LIGHTUP_ANTHROPIC_API_KEY": "sk-live"},
            transport_factory=lambda: transport,
        )
        resp = gateway.complete(ModelRole.VERIFIER, (ModelMessage("user", "check"),))
        self.assertEqual(resp.content, "verdict: confirmed")
        self.assertEqual(resp.provider_id, "anthropic-main")
        self.assertEqual(transport.calls[0]["headers"]["x-api-key"], "sk-live")

    def test_unknown_provider_kind_rejected(self):
        config = {
            "providers": [{"id": "x", "kind": "does-not-exist",
                           "api_key_env": "X"}],
            "roles": {"planner": {"provider": "x", "model": "m"}},
        }
        with self.assertRaises(GatewayConfigurationError):
            build_gateway_from_config(config, env={"X": "k"})

    def test_partial_config_rejected_when_roles_required(self):
        config = {
            "providers": [{"id": "scripted", "kind": "scripted"}],
            "roles": {"planner": {"provider": "scripted", "model": "m"}},
        }
        with self.assertRaises(GatewayConfigurationError):
            build_gateway_from_config(config)  # default require_roles = all six

    def test_partial_config_allowed_when_only_that_role_required(self):
        config = {
            "providers": [{"id": "scripted", "kind": "scripted"}],
            "roles": {"planner": {"provider": "scripted", "model": "m"}},
        }
        gateway = build_gateway_from_config(
            config, require_roles=(ModelRole.PLANNER,))
        self.assertEqual(len(gateway.bindings()), 1)

    def test_role_binding_needs_provider_and_model(self):
        config = {
            "providers": [{"id": "scripted", "kind": "scripted"}],
            "roles": {"planner": {"provider": "scripted"}},
        }
        with self.assertRaises(GatewayConfigurationError):
            build_gateway_from_config(config, require_roles=(ModelRole.PLANNER,))


if __name__ == "__main__":
    unittest.main()
