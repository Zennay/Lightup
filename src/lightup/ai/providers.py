"""Real, provider-neutral model backends for the :mod:`lightup.ai.gateway`.

The gateway speaks in *roles* and knows nothing about any vendor. This module
is the only place where vendor-specific request/response shapes live, and it
expresses them as data (:class:`ProviderProfile`) rather than as branches in
business logic. Adding a new API vendor is a new profile, not a new code path
anywhere else in LightUp.

Design rules, in order of importance:

1. **Fail closed.** A provider that has no usable credential cannot be
   constructed. A non-success HTTP status, or a response we cannot parse into
   text, raises — we never fabricate model output or silently return empty
   text to the pipeline/planner.
2. **No network in tests.** All I/O goes through an injectable
   :class:`Transport`. Unit tests inject a fake; the default transport is the
   only thing that touches the network, and only when a real provider is both
   configured and actually invoked.
3. **Dependency-free.** The default transport uses the standard library only
   (``urllib``), consistent with the rest of the platform.

This module performs no scope, authorization or risk decisions. Those remain
with the execution policy and orchestration layer regardless of which model
produced a plan or a verdict.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Protocol

from .gateway import (
    GatewayConfigurationError,
    ModelProvider,
    ModelRequest,
    ModelResponse,
)

__all__ = [
    "ProviderCredentialError",
    "ProviderRequestError",
    "ProviderResponseError",
    "Transport",
    "UrllibTransport",
    "ProviderProfile",
    "HttpModelProvider",
    "anthropic_profile",
    "openai_profile",
    "PROFILE_BUILDERS",
]


class ProviderCredentialError(GatewayConfigurationError):
    """A real provider was asked for but has no usable credential."""


class ProviderRequestError(RuntimeError):
    """The provider endpoint returned a non-success status or was unreachable."""


class ProviderResponseError(RuntimeError):
    """The provider replied, but no usable text could be parsed from it."""


class Transport(Protocol):
    """Minimal HTTP seam so tests never touch the network."""

    def post_json(
        self, url: str, headers: dict[str, str], body: dict, timeout: float
    ) -> tuple[int, dict]:
        """POST ``body`` as JSON and return ``(status_code, parsed_json)``."""
        ...


class UrllibTransport:
    """Default transport: standard-library ``urllib``, no third-party deps.

    Any transport-level failure (DNS, TLS, connection reset, timeout) is
    surfaced as :class:`ProviderRequestError` so callers fail closed instead of
    hanging or swallowing the error.
    """

    def post_json(
        self, url: str, headers: dict[str, str], body: dict, timeout: float
    ) -> tuple[int, dict]:
        data = json.dumps(body).encode("utf-8")
        request = urllib.request.Request(url, data=data, method="POST")
        request.add_header("content-type", "application/json")
        for name, value in headers.items():
            request.add_header(name, value)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                status = response.getcode()
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:  # non-2xx with a body
            try:
                detail = exc.read().decode("utf-8", "replace")
            except Exception:  # pragma: no cover - defensive
                detail = ""
            raise ProviderRequestError(
                f"provider returned HTTP {exc.code}: {detail[:500]}"
            ) from exc
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            raise ProviderRequestError(f"provider request failed: {exc}") from exc
        if not isinstance(payload, dict):
            raise ProviderResponseError("provider response was not a JSON object")
        return status, payload


@dataclass(frozen=True)
class ProviderProfile:
    """Vendor-specific request/response shape, expressed as data.

    ``build_body`` turns a role-neutral :class:`ModelRequest` into the vendor's
    JSON body; ``extract_content`` pulls the assistant text out of the parsed
    JSON response; ``extract_usage`` returns ``(input_tokens, output_tokens)``.
    Keeping these as callables means no vendor ``if`` branch exists anywhere
    outside this module.
    """

    kind: str
    default_endpoint: str
    auth_header: str
    auth_template: str  # e.g. "{key}" or "Bearer {key}"
    build_body: Callable[[ModelRequest], dict]
    extract_content: Callable[[dict], str]
    extract_usage: Callable[[dict], tuple[int, int]] = lambda _payload: (0, 0)
    static_headers: dict[str, str] = field(default_factory=dict)


class HttpModelProvider(ModelProvider):
    """A real HTTP-backed provider, driven entirely by a :class:`ProviderProfile`."""

    def __init__(
        self,
        provider_id: str,
        api_key: str,
        profile: ProviderProfile,
        *,
        endpoint: str | None = None,
        transport: Transport | None = None,
        timeout: float = 60.0,
    ):
        if not provider_id.strip():
            raise GatewayConfigurationError("provider_id is required")
        if not api_key or not api_key.strip():
            # Fail closed: a real provider with no credential must not exist.
            raise ProviderCredentialError(
                f"provider {provider_id!r} has no API key configured"
            )
        if timeout <= 0:
            raise GatewayConfigurationError("timeout must be positive")
        self._provider_id = provider_id
        self._api_key = api_key.strip()
        self._profile = profile
        self._endpoint = (endpoint or profile.default_endpoint).strip()
        if not self._endpoint:
            raise GatewayConfigurationError("endpoint is required")
        self._transport = transport or UrllibTransport()
        self._timeout = timeout

    @property
    def provider_id(self) -> str:
        return self._provider_id

    @property
    def endpoint(self) -> str:
        return self._endpoint

    def _headers(self) -> dict[str, str]:
        headers = dict(self._profile.static_headers)
        headers[self._profile.auth_header] = self._profile.auth_template.format(
            key=self._api_key
        )
        return headers

    def complete(self, request: ModelRequest) -> ModelResponse:
        body = self._profile.build_body(request)
        status, payload = self._transport.post_json(
            self._endpoint, self._headers(), body, self._timeout
        )
        if not (200 <= status < 300):
            raise ProviderRequestError(f"provider returned HTTP {status}")
        try:
            content = self._profile.extract_content(payload)
        except (KeyError, IndexError, TypeError) as exc:
            raise ProviderResponseError(
                f"could not extract content from {self._provider_id!r} response"
            ) from exc
        if not isinstance(content, str) or not content.strip():
            raise ProviderResponseError(
                f"provider {self._provider_id!r} returned empty content"
            )
        try:
            input_tokens, output_tokens = self._profile.extract_usage(payload)
        except Exception:  # usage is best-effort, never fatal
            input_tokens, output_tokens = 0, 0
        return ModelResponse(
            provider_id=self._provider_id,
            model_id=request.model_id,
            role=request.role,
            content=content,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        )


# --- Built-in vendor profiles -------------------------------------------------
#
# These encode only the request/response *shape* of each vendor. Model ids,
# endpoints and credentials remain configuration.


def _split_system(request: ModelRequest) -> tuple[str, list[dict]]:
    """Return (system_text, non_system_messages) for vendors that separate them."""
    system_parts = [m.content for m in request.messages if m.role == "system"]
    turns = [
        {"role": m.role, "content": m.content}
        for m in request.messages
        if m.role != "system"
    ]
    return "\n\n".join(system_parts), turns


def anthropic_profile() -> ProviderProfile:
    """Anthropic Messages API shape (system is a top-level field)."""

    def build_body(request: ModelRequest) -> dict:
        system, turns = _split_system(request)
        body: dict = {
            "model": request.model_id,
            "max_tokens": request.max_output_tokens,
            "messages": turns or [{"role": "user", "content": ""}],
        }
        if system:
            body["system"] = system
        return body

    def extract_content(payload: dict) -> str:
        blocks = payload["content"]
        return "".join(
            block.get("text", "")
            for block in blocks
            if isinstance(block, dict) and block.get("type", "text") == "text"
        )

    def extract_usage(payload: dict) -> tuple[int, int]:
        usage = payload.get("usage", {})
        return int(usage.get("input_tokens", 0)), int(usage.get("output_tokens", 0))

    return ProviderProfile(
        kind="anthropic",
        default_endpoint="https://api.anthropic.com/v1/messages",
        auth_header="x-api-key",
        auth_template="{key}",
        build_body=build_body,
        extract_content=extract_content,
        extract_usage=extract_usage,
        static_headers={"anthropic-version": "2023-06-01"},
    )


def openai_profile() -> ProviderProfile:
    """OpenAI-compatible chat-completions shape (also fits many local runtimes)."""

    def build_body(request: ModelRequest) -> dict:
        return {
            "model": request.model_id,
            "max_tokens": request.max_output_tokens,
            "messages": [
                {"role": m.role, "content": m.content} for m in request.messages
            ],
        }

    def extract_content(payload: dict) -> str:
        return payload["choices"][0]["message"]["content"]

    def extract_usage(payload: dict) -> tuple[int, int]:
        usage = payload.get("usage", {})
        return int(usage.get("prompt_tokens", 0)), int(usage.get("completion_tokens", 0))

    return ProviderProfile(
        kind="openai",
        default_endpoint="https://api.openai.com/v1/chat/completions",
        auth_header="Authorization",
        auth_template="Bearer {key}",
        build_body=build_body,
        extract_content=extract_content,
        extract_usage=extract_usage,
    )


# Registry of known profile builders, keyed by the ``kind`` used in config.
PROFILE_BUILDERS: dict[str, Callable[[], ProviderProfile]] = {
    "anthropic": anthropic_profile,
    "openai": openai_profile,
}
