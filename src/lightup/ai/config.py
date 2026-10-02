"""Configuration-driven assembly of a :class:`~lightup.ai.gateway.ModelGateway`.

Which model serves which role is *configuration*, never code. This module turns
a declarative, JSON-serializable config into a wired gateway:

- the default config binds every role to a deterministic
  :class:`~lightup.ai.gateway.ScriptedProvider`, so CI and lab evaluation run
  offline and reproducibly with no credentials;
- a real deployment points ``LIGHTUP_MODEL_CONFIG`` at a JSON file that binds
  roles to real HTTP providers; credentials are resolved from the environment
  at build time and the gateway **fails closed** if a configured credential is
  missing — it never silently falls back to a stub.

Config schema::

    {
      "providers": [
        {"id": "scripted", "kind": "scripted"},
        {"id": "anthropic-main", "kind": "anthropic",
         "api_key_env": "LIGHTUP_ANTHROPIC_API_KEY",
         "endpoint": "https://api.anthropic.com/v1/messages",   # optional
         "timeout": 60.0}                                        # optional
      ],
      "roles": {
        "planner":            {"provider": "anthropic-main", "model": "claude-..."},
        "surface_analyst":    {"provider": "anthropic-main", "model": "claude-..."},
        "security_analyst":   {"provider": "anthropic-main", "model": "claude-..."},
        "verifier":           {"provider": "anthropic-main", "model": "claude-..."},
        "remediation_advisor":{"provider": "anthropic-main", "model": "claude-..."},
        "report_synthesizer": {"provider": "anthropic-main", "model": "claude-..."}
      }
    }
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Callable, Mapping

from .gateway import (
    GatewayConfigurationError,
    ModelGateway,
    ModelProvider,
    ModelRole,
    ScriptedProvider,
)
from .providers import PROFILE_BUILDERS, HttpModelProvider, ProviderCredentialError

__all__ = [
    "MODEL_CONFIG_ENV",
    "default_scripted_config",
    "build_gateway_from_config",
    "load_config_from_env",
    "build_gateway",
]

MODEL_CONFIG_ENV = "LIGHTUP_MODEL_CONFIG"

# Placeholder model ids for the default scripted gateway. They never reach a
# network; they only document the binding shape.
_SCRIPTED_MODEL = "scripted-deterministic"


def default_scripted_config() -> dict:
    """Offline, credential-free config binding all roles to a scripted provider."""
    return {
        "providers": [{"id": "scripted", "kind": "scripted"}],
        "roles": {
            role.value: {"provider": "scripted", "model": _SCRIPTED_MODEL}
            for role in ModelRole
        },
    }


def _build_provider(
    spec: Mapping[str, object],
    env: Mapping[str, str],
    transport_factory: Callable[[], object] | None,
) -> ModelProvider:
    provider_id = str(spec.get("id", "")).strip()
    if not provider_id:
        raise GatewayConfigurationError("each provider needs a non-empty 'id'")
    kind = str(spec.get("kind", "")).strip()

    if kind == "scripted":
        script = spec.get("script")
        if script is not None:
            script = {
                ModelRole(role): list(items) for role, items in dict(script).items()
            }
        return ScriptedProvider(provider_id=provider_id, script=script)

    builder = PROFILE_BUILDERS.get(kind)
    if builder is None:
        raise GatewayConfigurationError(
            f"unknown provider kind {kind!r} for provider {provider_id!r}; "
            f"known kinds: scripted, {', '.join(sorted(PROFILE_BUILDERS))}"
        )

    api_key_env = str(spec.get("api_key_env", "")).strip()
    if not api_key_env:
        raise GatewayConfigurationError(
            f"provider {provider_id!r} of kind {kind!r} needs 'api_key_env'"
        )
    api_key = env.get(api_key_env, "")
    if not api_key:
        # Fail closed: a real provider is configured but its credential is
        # absent from the environment. Do not silently degrade to a stub.
        raise ProviderCredentialError(
            f"provider {provider_id!r} requires environment variable "
            f"{api_key_env!r}, which is unset or empty"
        )

    kwargs: dict = {}
    if spec.get("endpoint"):
        kwargs["endpoint"] = str(spec["endpoint"])
    if spec.get("timeout") is not None:
        kwargs["timeout"] = float(spec["timeout"])  # type: ignore[arg-type]
    if transport_factory is not None:
        kwargs["transport"] = transport_factory()  # type: ignore[assignment]
    return HttpModelProvider(provider_id, api_key, builder(), **kwargs)


def build_gateway_from_config(
    config: Mapping[str, object],
    *,
    env: Mapping[str, str] | None = None,
    require_roles: tuple[ModelRole, ...] = tuple(ModelRole),
    transport_factory: Callable[[], object] | None = None,
) -> ModelGateway:
    """Assemble a :class:`ModelGateway` from a declarative config.

    ``env`` defaults to ``os.environ``. ``require_roles`` are the roles that
    must be bound for the config to be accepted (all six by default), so a
    partial config is rejected at build time rather than failing mid-run.
    ``transport_factory`` lets tests inject a fake transport into every HTTP
    provider without any network access.
    """
    env = os.environ if env is None else env
    providers = config.get("providers")
    roles = config.get("roles")
    if not isinstance(providers, list) or not providers:
        raise GatewayConfigurationError("config needs a non-empty 'providers' list")
    if not isinstance(roles, Mapping) or not roles:
        raise GatewayConfigurationError("config needs a non-empty 'roles' mapping")

    gateway = ModelGateway()
    for spec in providers:
        if not isinstance(spec, Mapping):
            raise GatewayConfigurationError("each provider entry must be an object")
        gateway.register_provider(_build_provider(spec, env, transport_factory))

    for role_name, binding in roles.items():
        try:
            role = ModelRole(role_name)
        except ValueError as exc:
            raise GatewayConfigurationError(f"unknown role {role_name!r}") from exc
        if not isinstance(binding, Mapping):
            raise GatewayConfigurationError(f"role {role_name!r} needs an object value")
        provider_id = str(binding.get("provider", "")).strip()
        model_id = str(binding.get("model", "")).strip()
        if not provider_id or not model_id:
            raise GatewayConfigurationError(
                f"role {role_name!r} needs both 'provider' and 'model'"
            )
        gateway.bind_role(role, provider_id, model_id)

    missing = [r.value for r in require_roles if r not in {b.role for b in gateway.bindings()}]
    if missing:
        raise GatewayConfigurationError(
            f"config leaves required roles unbound: {', '.join(missing)}"
        )
    return gateway


def load_config_from_env(env: Mapping[str, str] | None = None) -> dict:
    """Load the model config named by ``LIGHTUP_MODEL_CONFIG``, else the default.

    When the variable is unset the offline scripted config is returned, so the
    platform always has a working, credential-free gateway for lab and CI.
    """
    env = os.environ if env is None else env
    path = env.get(MODEL_CONFIG_ENV, "").strip()
    if not path:
        return default_scripted_config()
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise GatewayConfigurationError(
            f"{MODEL_CONFIG_ENV} points at {path!r} which cannot be read: {exc}"
        ) from exc
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise GatewayConfigurationError(
            f"{MODEL_CONFIG_ENV} file {path!r} is not valid JSON: {exc}"
        ) from exc
    if not isinstance(parsed, dict):
        raise GatewayConfigurationError(f"{MODEL_CONFIG_ENV} file must be a JSON object")
    return parsed


def build_gateway(
    *,
    env: Mapping[str, str] | None = None,
    require_roles: tuple[ModelRole, ...] = tuple(ModelRole),
) -> ModelGateway:
    """Convenience: load config from the environment and build the gateway."""
    return build_gateway_from_config(
        load_config_from_env(env), env=env, require_roles=require_roles
    )
