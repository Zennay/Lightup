"""AI orchestration contracts: typed tools, immutable run context, policy gate.

Design rules:

- the model never gets a shell; it can only request **typed tool calls**;
- every call carries an **immutable** :class:`RunContext`;
- the :class:`ToolExecutor` checks the product :class:`ExecutionPolicy` and the
  run's risk ceiling **before** any handler runs — a prompt is never the
  security boundary;
- a call above the run's approved risk raises :class:`RiskElevationRequired`
  without executing; a new explicit approval must create a new run context;
- every successful call returns evidence through the evidence ledger, so
  findings stay traceable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from math import isfinite
from typing import Any, Callable

from ..capabilities import get_capabilities
from ..engagements import AssessmentMode, AuthorizationGrant, RiskLevel
from ..execution_policy import ExecutionPolicy, ExecutionRequest, InteractionKind
from ..state import StateStore


class OrchestrationError(RuntimeError):
    pass


class ToolDenied(PermissionError):
    """The policy gate refused the call before execution."""


class RiskElevationRequired(PermissionError):
    """The call needs a risk level above the run's approved ceiling."""

    def __init__(self, tool_id: str, required: RiskLevel, approved: RiskLevel):
        super().__init__(
            f"tool {tool_id!r} requires risk {int(required)} but the run is "
            f"approved up to {int(approved)}; file a risk elevation request"
        )
        self.tool_id = tool_id
        self.required = required
        self.approved = approved


class ParamKind(str, Enum):
    STRING = "string"
    INTEGER = "integer"
    NUMBER = "number"
    BOOLEAN = "boolean"

    def accepts(self, value: Any) -> bool:
        if self is ParamKind.STRING:
            return type(value) is str
        if self is ParamKind.INTEGER:
            return type(value) is int
        if self is ParamKind.NUMBER:
            # NaN/Infinity can evade range comparisons and cannot be safely
            # serialized as ordinary JSON numbers; no handler may receive them.
            return type(value) is int or (type(value) is float and isfinite(value))
        return type(value) is bool


@dataclass(frozen=True)
class ToolParameter:
    name: str
    kind: ParamKind
    required: bool = True
    description: str = ""


@dataclass(frozen=True)
class ToolDefinition:
    tool_id: str
    capability_id: str
    interaction: InteractionKind
    min_risk: RiskLevel
    description: str
    parameters: tuple[ToolParameter, ...] = ()

    def validate_schema(self) -> None:
        # Reject ambiguous tool declarations before any handler can be stored.
        # A dict built from duplicate names would silently shadow a constraint.
        if (
            type(self.tool_id) is not str
            or not self.tool_id.strip()
            or self.tool_id != self.tool_id.strip()
            or type(self.capability_id) is not str
            or not self.capability_id.strip()
            or self.capability_id != self.capability_id.strip()
            or type(self.interaction) is not InteractionKind
            or type(self.min_risk) is not RiskLevel
            or type(self.description) is not str
        ):
            raise OrchestrationError("tool definition authority fields are not canonical")
        if type(self.parameters) is not tuple:
            raise OrchestrationError("tool parameters must be a canonical tuple")
        names: set[str] = set()
        for parameter in self.parameters:
            if (
                type(parameter) is not ToolParameter
                or type(parameter.name) is not str
                or not parameter.name.strip()
                or parameter.name != parameter.name.strip()
                or any(ord(char) < 33 or ord(char) == 127 for char in parameter.name)
                or type(parameter.kind) is not ParamKind
                or type(parameter.required) is not bool
                or type(parameter.description) is not str
            ):
                raise OrchestrationError("tool parameter declaration is not canonical")
            if parameter.name in names:
                raise OrchestrationError(
                    f"tool {self.tool_id!r}: duplicate parameter name {parameter.name!r}"
                )
            names.add(parameter.name)

    def validate_arguments(self, arguments: dict[str, Any]) -> None:
        self.validate_schema()
        known = {p.name: p for p in self.parameters}
        for name in arguments:
            if name not in known:
                raise OrchestrationError(f"tool {self.tool_id!r}: unknown argument {name!r}")
        for parameter in self.parameters:
            if parameter.name not in arguments:
                if parameter.required:
                    raise OrchestrationError(
                        f"tool {self.tool_id!r}: missing required argument {parameter.name!r}"
                    )
                continue
            value = arguments[parameter.name]
            if not parameter.kind.accepts(value):
                raise OrchestrationError(
                    f"tool {self.tool_id!r}: argument {parameter.name!r} "
                    f"must be a {parameter.kind.value}"
                )


@dataclass(frozen=True)
class RunContext:
    """Immutable context attached to every tool call in a run.

    ``approved_risk`` is the ceiling granted by operator approval; raising it
    requires a *new* context created after a new explicit approval.
    """

    run_id: str
    client_id: str
    engagement_id: str
    mode: AssessmentMode
    approved_risk: RiskLevel
    authorization: AuthorizationGrant | None
    is_lab: bool
    created_at: datetime

    @staticmethod
    def for_lab(run_id: str, engagement_id: str = "lab", client_id: str = "lab") -> "RunContext":
        return RunContext(
            run_id=run_id,
            client_id=client_id,
            engagement_id=engagement_id,
            mode=AssessmentMode.LAB_AUTONOMOUS,
            approved_risk=RiskLevel.DESTRUCTIVE_LAB_ONLY,
            authorization=None,
            is_lab=True,
            created_at=datetime.now(timezone.utc),
        )


@dataclass(frozen=True)
class ToolCall:
    tool_id: str
    asset: str
    arguments: tuple[tuple[str, Any], ...] = ()

    def arguments_dict(self) -> dict[str, Any]:
        # Conversion to dict must never quietly discard a duplicate or invoke
        # foreign comparison/hash hooks on a polymorphic argument key.
        if type(self.arguments) is not tuple:
            raise OrchestrationError("tool arguments must be an immutable tuple")
        result: dict[str, Any] = {}
        for pair in self.arguments:
            if type(pair) is not tuple or len(pair) != 2:
                raise OrchestrationError("tool argument entry must be a pair")
            name, value = pair
            if (
                type(name) is not str or not name.strip()
                or name != name.strip()
                or any(ord(char) < 33 or ord(char) == 127 for char in name)
            ):
                raise OrchestrationError("tool argument name is not canonical")
            if name in result:
                raise OrchestrationError(f"duplicate tool argument {name!r}")
            result[name] = value
        return result


_RESERVED_EVIDENCE_METADATA_KEYS = frozenset(
    {"asset", "client_id", "engagement_id", "mode", "is_lab"}
)


@dataclass(frozen=True)
class ToolOutput:
    """What a capability worker must hand back: a summary plus raw evidence."""

    summary: str
    evidence_kind: str
    evidence_payload: bytes
    metadata: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        self.validate_contract()

    def validate_contract(self) -> None:
        # Validate at construction AND immediately before the evidence handoff.
        # Do not coerce mutable or foreign objects into audit evidence.
        if type(self.summary) is not str or not self.summary.strip():
            raise OrchestrationError("tool output summary must be nonempty plain text")
        if (
            type(self.evidence_kind) is not str
            or not self.evidence_kind.strip()
            or any(ord(char) < 33 or ord(char) == 127 for char in self.evidence_kind)
        ):
            raise OrchestrationError("tool output evidence kind is not canonical")
        if type(self.evidence_payload) is not bytes:
            raise OrchestrationError("tool output evidence payload must be immutable bytes")
        if type(self.metadata) is not tuple:
            raise OrchestrationError("tool output metadata must be a canonical tuple")
        seen: set[str] = set()
        for pair in self.metadata:
            if (
                type(pair) is not tuple or len(pair) != 2
                or type(pair[0]) is not str or type(pair[1]) is not str
            ):
                raise OrchestrationError("tool output metadata pair is not canonical")
            key = pair[0]
            if (
                not key.strip() or key != key.strip()
                or any(ord(char) < 33 or ord(char) == 127 for char in key)
                or key in seen or key in _RESERVED_EVIDENCE_METADATA_KEYS
            ):
                raise OrchestrationError("duplicate or reserved evidence metadata key")
            seen.add(key)


@dataclass(frozen=True)
class ToolResult:
    tool_id: str
    run_id: str
    capability_id: str
    summary: str
    evidence_id: str
    policy_reason: str
    metadata: tuple[tuple[str, str], ...] = ()


ToolHandler = Callable[[RunContext, dict[str, Any]], ToolOutput]


@dataclass
class ToolRegistry:
    _tools: dict[str, tuple[ToolDefinition, ToolHandler]] = field(default_factory=dict)

    def register(self, definition: ToolDefinition, handler: ToolHandler) -> None:
        if type(definition) is not ToolDefinition:
            raise OrchestrationError("tool definition must be canonical")
        definition.validate_schema()
        if not callable(handler):
            raise OrchestrationError(
                f"tool {definition.tool_id!r}: handler must be callable"
            )
        if definition.tool_id in self._tools:
            raise OrchestrationError(f"tool {definition.tool_id!r} is already registered")
        if definition.capability_id not in {c.capability_id for c in get_capabilities()}:
            raise OrchestrationError(
                f"tool {definition.tool_id!r} references unknown capability "
                f"{definition.capability_id!r}"
            )
        self._tools[definition.tool_id] = (definition, handler)

    def get(self, tool_id: str) -> tuple[ToolDefinition, ToolHandler]:
        if type(tool_id) is not str or not tool_id.strip():
            raise OrchestrationError("lookup tool identity is not canonical")
        try:
            return self._tools[tool_id]
        except KeyError:
            raise OrchestrationError(f"unknown tool {tool_id!r}") from None

    def definitions(self) -> tuple[ToolDefinition, ...]:
        return tuple(definition for definition, _ in self._tools.values())


# Interactions a passive-discovery or analysis-only run may ever use.
_NON_ACTIVE_INTERACTIONS = {InteractionKind.ANALYSIS, InteractionKind.PASSIVE_PUBLIC}


class ToolExecutor:
    """Executes typed tool calls behind the product policy gate."""

    def __init__(
        self,
        registry: ToolRegistry,
        state: StateStore,
        policy: ExecutionPolicy | None = None,
    ):
        if state is None:
            raise OrchestrationError("the evidence ledger (StateStore) is mandatory")
        self.registry = registry
        self.policy = policy or ExecutionPolicy()
        self.state = state

    def execute(self, context: RunContext, call: ToolCall) -> ToolResult:
        # Inspect exact immutable call identity BEFORE any registry, policy,
        # handler or evidence interaction. Do not invoke str-subclass hooks.
        if (
            type(call) is not ToolCall
            or type(call.tool_id) is not str
            or not call.tool_id.strip()
            or call.tool_id != call.tool_id.strip()
            or type(call.asset) is not str
            or not call.asset.strip()
        ):
            raise OrchestrationError("tool call identity is not canonical")
        definition, handler = self.registry.get(call.tool_id)
        arguments = call.arguments_dict()
        definition.validate_arguments(arguments)

        # Mode boundary: passive/analysis runs can never reach active tools,
        # regardless of any authorization attached to the run.
        if (
            context.mode in {AssessmentMode.PASSIVE_DISCOVERY, AssessmentMode.ANALYSIS_ONLY}
            and definition.interaction not in _NON_ACTIVE_INTERACTIONS
        ):
            raise ToolDenied(
                f"mode {context.mode.value!r} cannot invoke active tool {call.tool_id!r}"
            )

        # Lab tools never run outside a lab context; real-target tools never
        # run inside one (lab results must not masquerade as target evidence).
        if definition.interaction is InteractionKind.LAB_ACTIVE and not context.is_lab:
            raise ToolDenied(f"tool {call.tool_id!r} is lab-only")
        if definition.interaction is InteractionKind.TARGET_ACTIVE and context.is_lab:
            raise ToolDenied(f"lab runs cannot invoke real-target tool {call.tool_id!r}")

        # Risk ceiling: elevation is a human decision, never an AI one.
        if definition.min_risk > context.approved_risk:
            raise RiskElevationRequired(call.tool_id, definition.min_risk, context.approved_risk)

        request = ExecutionRequest(
            interaction=definition.interaction,
            asset=call.asset,
            capability_id=definition.capability_id,
            requested_risk=definition.min_risk,
            authorization=context.authorization,
            is_lab=context.is_lab,
        )
        decision = self.policy.decide(request)
        if not decision.allowed:
            raise ToolDenied(f"policy denied tool {call.tool_id!r}: {decision.reason}")

        output = handler(context, arguments)
        if type(output) is not ToolOutput:
            raise OrchestrationError(
                f"tool {call.tool_id!r} violated the evidence contract: "
                "handlers must return a canonical ToolOutput"
            )
        output.validate_contract()

        evidence_id = self.state.add_evidence(
            run_id=context.run_id,
            capability_id=definition.capability_id,
            kind=output.evidence_kind,
            source=call.tool_id,
            payload=output.evidence_payload,
            metadata={
                **dict(output.metadata),
                "asset": call.asset,
                "client_id": context.client_id,
                "engagement_id": context.engagement_id,
                "mode": context.mode.value,
                "is_lab": "true" if context.is_lab else "false",
            },
        )

        return ToolResult(
            tool_id=call.tool_id,
            run_id=context.run_id,
            capability_id=definition.capability_id,
            summary=output.summary,
            evidence_id=evidence_id,
            policy_reason=decision.reason,
            metadata=output.metadata,
        )
