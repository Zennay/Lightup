"""Gateway configuration loader: model choice is configuration, never code.

A gateway config is a JSON document::

    {
      "providers": {
        "scripted": {"type": "scripted"},
        "anthropic": {"type": "anthropic", "api_key_env": "ANTHROPIC_API_KEY"}
      },
      "roles": {
        "planner":             {"provider": "anthropic", "model": "claude-opus-5-5"},
        "verifier":            {"provider": "anthropic", "model": "claude-opus-5-5"},
        "remediation_advisor": {"provider": "anthropic", "model": "claude-opus-5-5"},
        "report_synthesizer":  {"provider": "anthropic", "model": "claude-opus-5-5"}
      }
    }

Unknown provider types, unknown roles and unbound references fail loudly at
load time, before any assessment runs. API keys are referenced by environment
variable name — never stored in the config file itself.
"""

from __future__ import annotations

import json
from pathlib import Path

from .gateway import (
    GatewayConfigurationError,
    ModelGateway,
    ModelProvider,
    ModelRole,
    ScriptedProvider,
)


def _build_provider(name: str, spec: dict) -> ModelProvider:
    provider_type = spec.get("type", name)
    if provider_type == "scripted":
        return ScriptedProvider(provider_id=name)
    if provider_type == "anthropic":
        from .providers.anthropic_provider import AnthropicProvider, ModelProviderError

        try:
            return AnthropicProvider(api_key_env=spec.get("api_key_env", "ANTHROPIC_API_KEY"),
                                     provider_id=name)
        except ModelProviderError as exc:
            raise GatewayConfigurationError(str(exc)) from exc
    raise GatewayConfigurationError(f"unknown provider type {provider_type!r}")


def gateway_from_dict(config: dict) -> ModelGateway:
    if not isinstance(config, dict):
        raise GatewayConfigurationError("gateway config must be an object")
    gateway = ModelGateway()
    providers = config.get("providers")
    roles = config.get("roles")
    if not isinstance(providers, dict) or not providers:
        raise GatewayConfigurationError("config requires a non-empty 'providers' object")
    if not isinstance(roles, dict) or not roles:
        raise GatewayConfigurationError("config requires a non-empty 'roles' object")

    for name, spec in providers.items():
        if not isinstance(name, str) or not name.strip():
            raise GatewayConfigurationError("provider name must be a non-empty string")
        if not isinstance(spec, dict):
            raise GatewayConfigurationError(f"provider {name!r} spec must be an object")
        if "api_key" in spec:
            raise GatewayConfigurationError("inline credentials are not allowed; use api_key_env")
        key_env = spec.get("api_key_env", "ANTHROPIC_API_KEY")
        if not isinstance(key_env, str) or not key_env.strip():
            raise GatewayConfigurationError("api_key_env must be a non-empty string")
        gateway.register_provider(_build_provider(name, spec))

    for role_name, binding in roles.items():
        try:
            role = ModelRole(role_name)
        except ValueError:
            raise GatewayConfigurationError(f"unknown role {role_name!r}") from None
        if not isinstance(binding, dict):
            raise GatewayConfigurationError(f"role {role_name!r} binding must be an object")
        provider_id, model_id = binding.get("provider"), binding.get("model")
        if not isinstance(provider_id, str) or not isinstance(model_id, str):
            raise GatewayConfigurationError("role provider and model must be strings")
        gateway.bind_role(role, provider_id, model_id)

    return gateway


def load_gateway(path: str | Path) -> ModelGateway:
    try:
        config = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GatewayConfigurationError(f"cannot load gateway config {path}: {exc}") from exc
    return gateway_from_dict(config)
