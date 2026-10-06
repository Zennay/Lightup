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

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
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
            return isinstance(value, str)
        if self is ParamKind.INTEGER:
            return isinstance(value, int) and not isinstance(value, bool)
        if self is ParamKind.NUMBER:
            return isinstance(value, (int, float)) and not isinstance(value, bool)
        return isinstance(value, bool)


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

    def validate_arguments(self, arguments: dict[str, Any]) -> None:
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
        return dict(self.arguments)


@dataclass(frozen=True)
class ToolOutput:
    """What a capability worker must hand back: a summary plus raw evidence."""

    summary: str
    evidence_kind: str
    evidence_payload: bytes
    metadata: tuple[tuple[str, str], ...] = ()


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
AuthorizationResolver = Callable[[AuthorizationGrant], AuthorizationGrant | None]


@dataclass
class ToolRegistry:
    _tools: dict[str, tuple[ToolDefinition, ToolHandler]] = field(default_factory=dict)

    def register(self, definition: ToolDefinition, handler: ToolHandler) -> None:
        if definition.tool_id in self._tools:
            raise OrchestrationError(f"tool {definition.tool_id!r} is already registered")
        if definition.capability_id not in {c.capability_id for c in get_capabilities()}:
            raise OrchestrationError(
                f"tool {definition.tool_id!r} references unknown capability "
                f"{definition.capability_id!r}"
            )
        self._tools[definition.tool_id] = (definition, handler)

    def get(self, tool_id: str) -> tuple[ToolDefinition, ToolHandler]:
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
        authorization_resolver: AuthorizationResolver | None = None,
    ):
        if state is None:
            raise OrchestrationError("the evidence ledger (StateStore) is mandatory")
        self.registry = registry
        self.policy = policy or ExecutionPolicy()
        self.state = state
        self.authorization_resolver = authorization_resolver

    def execute(self, context: RunContext, call: ToolCall) -> ToolResult:
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

        authorization = context.authorization
        handler_context = context
        if definition.interaction is InteractionKind.TARGET_ACTIVE:
            if authorization is None:
                raise ToolDenied("target-active execution requires authorization")
            if self.authorization_resolver is None:
                raise ToolDenied(
                    "target-active execution requires live authorization revalidation"
                )
            snapshot_grant_id = authorization.grant_id
            authorization = self.authorization_resolver(authorization)
            if authorization is None:
                raise ToolDenied(
                    "authorization grant is not live in authoritative state"
                )
            if authorization.grant_id != snapshot_grant_id:
                raise ToolDenied(
                    "live authorization resolver returned a different grant"
                )
            # The policy and the handler must see the same authoritative grant.
            # Keep the caller's immutable snapshot unchanged, but never expose
            # stale broader authorization metadata to a target-active handler.
            handler_context = replace(context, authorization=authorization)

        request = ExecutionRequest(
            interaction=definition.interaction,
            asset=call.asset,
            capability_id=definition.capability_id,
            requested_risk=definition.min_risk,
            client_id=context.client_id,
            engagement_id=context.engagement_id,
            authorization=authorization,
            is_lab=context.is_lab,
        )
        decision = self.policy.decide(request)
        if not decision.allowed:
            raise ToolDenied(f"policy denied tool {call.tool_id!r}: {decision.reason}")

        output = handler(handler_context, arguments)
        if not isinstance(output, ToolOutput):
            raise OrchestrationError(
                f"tool {call.tool_id!r} violated the evidence contract: "
                "handlers must return a ToolOutput"
            )

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
