"""Anthropic provider adapter for the LightUp model gateway.

Uses the official ``anthropic`` SDK, installed as an optional extra::

    pip install lightup[anthropic]

The SDK is imported lazily so LightUp's core (and CI) stays dependency-free;
constructing this provider without the SDK installed raises a clear error.
Which roles route here, and with which model, is gateway configuration
(see :mod:`lightup.ai.config`) — never business logic.

The provider is not a security boundary: whatever a model returns, tool
execution still passes the orchestration policy gate.
"""

from __future__ import annotations

import os
from typing import Any

from ..gateway import ModelProvider, ModelRequest, ModelResponse

# Default per Anthropic's current guidance; override via configuration.
DEFAULT_MODEL = "claude-opus-5-5"


class ModelProviderError(RuntimeError):
    """A provider could not complete a request (configuration or API error)."""


def build_request_kwargs(request: ModelRequest) -> dict[str, Any]:
    """Map a gateway request onto Anthropic Messages API kwargs.

    Pure function so request shaping is testable without the SDK or network.
    System-role messages become the ``system`` parameter; the rest pass
    through in order. Thinking is left at the model's default (adaptive on
    current models).
    """
    system_parts = [m.content for m in request.messages if m.role == "system"]
    messages = [
        {"role": m.role, "content": m.content}
        for m in request.messages
        if m.role != "system"
    ]
    if not messages:
        raise ModelProviderError("a request needs at least one non-system message")
    kwargs: dict[str, Any] = {
        "model": request.model_id,
        "max_tokens": request.max_output_tokens,
        "messages": messages,
    }
    if system_parts:
        kwargs["system"] = "\n\n".join(system_parts)
    return kwargs


class AnthropicProvider(ModelProvider):
    """Routes gateway completions to the Anthropic Messages API."""

    def __init__(self, api_key_env: str = "ANTHROPIC_API_KEY",
                 api_key: str | None = None, provider_id: str = "anthropic"):
        try:
            import anthropic
        except ImportError as exc:
            raise ModelProviderError(
                "the 'anthropic' SDK is not installed; "
                "install LightUp with the optional extra: pip install lightup[anthropic]"
            ) from exc
        self._anthropic = anthropic
        key = api_key if api_key is not None else os.environ.get(api_key_env)
        if not isinstance(key, str) or not key.strip():
            raise ModelProviderError("configured provider credential is missing")
        self._provider_id = provider_id
        try:
            self._client = anthropic.Anthropic(api_key=key, timeout=60.0, max_retries=0)
        except Exception:
            # SDK diagnostics can contain credentials or request contents.
            raise ModelProviderError("provider client initialization failed") from None

    @property
    def provider_id(self) -> str:
        return self._provider_id

    def complete(self, request: ModelRequest) -> ModelResponse:
        anthropic = self._anthropic
        try:
            response = self._client.messages.create(**build_request_kwargs(request))
        except anthropic.RateLimitError:
            raise ModelProviderError("anthropic rate limit") from None
        except anthropic.APIStatusError as exc:
            raise ModelProviderError(f"anthropic API error (status {exc.status_code})") from None
        except anthropic.APIConnectionError:
            raise ModelProviderError("anthropic connection error") from None

        # A refusal, tool request or truncated response is not completed analysis.
        if getattr(response, "stop_reason", None) != "end_turn":
            raise ModelProviderError("model did not return a completed text response")
        try:
            text = "".join(block.text for block in response.content if block.type == "text")
        except (AttributeError, TypeError):
            raise ModelProviderError("model returned invalid text content") from None
        if not text.strip():
            raise ModelProviderError("model returned empty text content")
        usage = response.usage
        return ModelResponse(
            provider_id=self.provider_id,
            model_id=request.model_id,
            role=request.role,
            content=text,
            input_tokens=getattr(usage, "input_tokens", 0) or 0,
            output_tokens=getattr(usage, "output_tokens", 0) or 0,
        )
