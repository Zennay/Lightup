"""Provider-neutral model gateway.

The gateway routes *roles* (planner, analyst, verifier, ...) to configured
providers. Model choice is configuration, never business logic:

- the rest of LightUp talks to :class:`ModelGateway` in terms of roles;
- providers implement one small interface (:class:`ModelProvider`);
- no provider-specific behavior may leak outside this module's implementations.

The gateway is not a security boundary. Scope, authorization and risk are
enforced by the execution policy and orchestration layer regardless of which
model produced a plan.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum


class ModelRole(str, Enum):
    PLANNER = "planner"
    SURFACE_ANALYST = "surface_analyst"
    SECURITY_ANALYST = "security_analyst"
    VERIFIER = "verifier"
    REMEDIATION_ADVISOR = "remediation_advisor"
    REPORT_SYNTHESIZER = "report_synthesizer"


@dataclass(frozen=True)
class ModelMessage:
    role: str  # "system" | "user" | "assistant"
    content: str

    def __post_init__(self) -> None:
        if self.role not in {"system", "user", "assistant"}:
            raise ValueError(f"unsupported message role {self.role!r}")


@dataclass(frozen=True)
class ModelRequest:
    role: ModelRole
    messages: tuple[ModelMessage, ...]
    model_id: str
    max_output_tokens: int = 2048
    metadata: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not self.messages:
            raise ValueError("a model request requires at least one message")
        if self.max_output_tokens <= 0:
            raise ValueError("max_output_tokens must be positive")


@dataclass(frozen=True)
class ModelResponse:
    provider_id: str
    model_id: str
    role: ModelRole
    content: str
    input_tokens: int = 0
    output_tokens: int = 0


class ModelProvider(ABC):
    """One AI backend (API vendor, local runtime, scripted stub)."""

    @property
    @abstractmethod
    def provider_id(self) -> str: ...

    @abstractmethod
    def complete(self, request: ModelRequest) -> ModelResponse: ...


@dataclass(frozen=True)
class RoleBinding:
    role: ModelRole
    provider_id: str
    model_id: str


class GatewayConfigurationError(RuntimeError):
    pass


class ScriptedProvider(ModelProvider):
    """Deterministic provider for tests and lab evaluation.

    Responses are either a fixed script (FIFO per role) or an echo of the last
    user message. No network, no external dependency.
    """

    def __init__(self, provider_id: str = "scripted", script: dict[ModelRole, list[str]] | None = None):
        self._provider_id = provider_id
        self._script = {role: list(items) for role, items in (script or {}).items()}

    @property
    def provider_id(self) -> str:
        return self._provider_id

    def complete(self, request: ModelRequest) -> ModelResponse:
        queued = self._script.get(request.role)
        if queued:
            content = queued.pop(0)
        else:
            last_user = next(
                (m.content for m in reversed(request.messages) if m.role == "user"), ""
            )
            content = f"[{request.role.value}] {last_user}"
        return ModelResponse(
            provider_id=self._provider_id,
            model_id=request.model_id,
            role=request.role,
            content=content,
        )


@dataclass
class ModelGateway:
    """Routes role-based completion requests to registered providers."""

    _providers: dict[str, ModelProvider] = field(default_factory=dict)
    _bindings: dict[ModelRole, RoleBinding] = field(default_factory=dict)

    def register_provider(self, provider: ModelProvider) -> None:
        if provider.provider_id in self._providers:
            raise GatewayConfigurationError(
                f"provider {provider.provider_id!r} is already registered"
            )
        self._providers[provider.provider_id] = provider

    def bind_role(self, role: ModelRole, provider_id: str, model_id: str) -> None:
        if provider_id not in self._providers:
            raise GatewayConfigurationError(f"unknown provider {provider_id!r}")
        if not model_id.strip():
            raise GatewayConfigurationError("model_id is required")
        self._bindings[role] = RoleBinding(role, provider_id, model_id.strip())

    def binding_for(self, role: ModelRole) -> RoleBinding:
        binding = self._bindings.get(role)
        if binding is None:
            raise GatewayConfigurationError(f"no provider bound for role {role.value!r}")
        return binding

    def bindings(self) -> tuple[RoleBinding, ...]:
        return tuple(self._bindings[role] for role in ModelRole if role in self._bindings)

    def complete(
        self,
        role: ModelRole,
        messages: tuple[ModelMessage, ...],
        max_output_tokens: int = 2048,
        metadata: tuple[tuple[str, str], ...] = (),
    ) -> ModelResponse:
        binding = self.binding_for(role)
        provider = self._providers[binding.provider_id]
        request = ModelRequest(
            role=role,
            messages=messages,
            model_id=binding.model_id,
            max_output_tokens=max_output_tokens,
            metadata=metadata,
        )
        response = provider.complete(request)
        if response.provider_id != binding.provider_id:
            raise GatewayConfigurationError(
                "provider returned a response under a different provider_id"
            )
        return response
