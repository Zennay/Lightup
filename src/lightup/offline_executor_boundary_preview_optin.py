"""Offline-only synthetic ToolExecutor trust-boundary preview (#1307).

Explicitly non-authorizing: never calls an executor, handler, policy decision,
resolver, database, scanner, adapter, network or model. Not used by production.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from math import isfinite
import re

from .ai.orchestration import (
    ParamKind, RunContext, ToolCall, ToolDefinition, ToolExecutor,
    ToolParameter, ToolRegistry,
)
from .engagements import AssessmentMode, RiskLevel
from .execution_policy import ExecutionPolicy, InteractionKind
from .state import StateStore


_IDENT = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}\Z")


class OfflineAdmissionDenied(PermissionError):
    """Opaque failure: untrusted fields are never reflected to callers."""


@dataclass(frozen=True, slots=True)
class OfflineBoundaryReceipt:
    registered_analysis_tools: int
    contracts_checked: int = 7
    permit_issued: bool = False
    execution_enabled: bool = False
    authorization_verified: bool = False


def _deny() -> None:
    raise OfflineAdmissionDenied("offline boundary preview refused")


def _identifier(value: object) -> bool:
    return type(value) is str and _IDENT.fullmatch(value) is not None


def _parameter_fingerprint(parameter: object) -> tuple:
    if type(parameter) is not ToolParameter:
        _deny()
    if not _identifier(parameter.name):
        _deny()
    if type(parameter.kind) is not ParamKind:
        _deny()
    if type(parameter.required) is not bool:
        _deny()
    if type(parameter.description) is not str or len(parameter.description) > 2048:
        _deny()
    return parameter.name, parameter.kind, parameter.required, parameter.description


def _registry_fingerprint(registry: ToolRegistry) -> tuple:
    # Use only raw built-in data in known, exact canonical container objects.
    table = vars(registry).get("_tools")
    if type(table) is not dict or len(table) > 64:
        _deny()
    fingerprint = []
    for key, entry in table.items():
        if not _identifier(key) or type(entry) is not tuple or len(entry) != 2:
            _deny()
        definition, handler = entry
        if type(definition) is not ToolDefinition or not callable(handler):
            _deny()
        if type(definition.tool_id) is not str or definition.tool_id != key:
            _deny()
        if not _identifier(definition.capability_id):
            _deny()
        if type(definition.interaction) is not InteractionKind:
            _deny()
        if type(definition.min_risk) is not RiskLevel:
            _deny()
        if type(definition.description) is not str or len(definition.description) > 2048:
            _deny()
        parameters = definition.parameters
        if type(parameters) is not tuple or len(parameters) > 16:
            _deny()
        params = tuple(_parameter_fingerprint(p) for p in parameters)
        if len({p[0] for p in params}) != len(params):
            _deny()
        fingerprint.append((
            key, id(definition), id(handler), definition.capability_id,
            definition.interaction, definition.min_risk, definition.description,
            params,
        ))
    return tuple(sorted(fingerprint, key=lambda entry: entry[0]))


def _arguments_are_valid(parameters: tuple, arguments: tuple) -> bool:
    if type(arguments) is not tuple or len(arguments) > 16:
        return False
    parsed = {}
    for item in arguments:
        if type(item) is not tuple or len(item) != 2:
            return False
        name, value = item
        if not _identifier(name) or name in parsed:
            return False
        parsed[name] = value
    allowed = {param[0]: param for param in parameters}
    if set(parsed) - set(allowed):
        return False
    for name, kind, required, _description in parameters:
        if name not in parsed:
            if required:
                return False
            continue
        value = parsed[name]
        if kind is ParamKind.STRING:
            if type(value) is not str or len(value) > 4096:
                return False
        elif kind is ParamKind.INTEGER:
            if type(value) is not int or not -(2**63) <= value <= 2**63 - 1:
                return False
        elif kind is ParamKind.NUMBER:
            if (type(value) not in (int, float)\n                or (type(value) is int and value.bit_length() > 63)\n                or not isfinite(value)):
                return False
        elif kind is ParamKind.BOOLEAN:
            if type(value) is not bool:
                return False
        else:
            return False
    return True


@dataclass(frozen=True, slots=True)
class OfflineExecutorBoundaryPreview:
    """Captures and checks offline constructor bindings, without executing.

    Snapshot starts when constructed. Cannot prove that an executor wasn't
    compromised *before* snapshot, resist arbitrary Python reflection, or
    provide atomicity with concurrent mutations. Never use as active gate.
    """

    _executor: ToolExecutor
    _registry: ToolRegistry
    _state: StateStore
    _policy: ExecutionPolicy
    _registry_at_creation: tuple

    @classmethod
    def capture(cls, executor: ToolExecutor) -> "OfflineExecutorBoundaryPreview":
        # Check the outer object before reading a single user-owned attribute.
        if type(executor) is not ToolExecutor:
            _deny()
        bindings = vars(executor)
        registry, state, policy = (
            bindings.get("registry"), bindings.get("state"), bindings.get("policy")
        )
        if (
            type(registry) is not ToolRegistry
            or type(state) is not StateStore
            or type(policy) is not ExecutionPolicy
            or bindings.get("authorization_resolver") is not None
            or "execute" in bindings
            or "get" in vars(registry)
            or "decide" in vars(policy)
            or "add_evidence" in vars(state)
        ):
            _deny()
        return cls(executor, registry, state, policy, _registry_fingerprint(registry))

    def preview(self, context: RunContext, call: ToolCall) -> OfflineBoundaryReceipt:
        # Require exact outer classes before ANY caller-controlled getter.
        if type(context) is not RunContext or type(call) is not ToolCall:
            _deny()
        if (
            type(self._executor) is not ToolExecutor
            or type(self._registry) is not ToolRegistry
            or type(self._state) is not StateStore
            or type(self._policy) is not ExecutionPolicy
        ):
            _deny()
        bindings = vars(self._executor)
        if (
            bindings.get("registry") is not self._registry
            or bindings.get("state") is not self._state
            or bindings.get("policy") is not self._policy
            or bindings.get("authorization_resolver") is not None
            or "execute" in bindings
            or "get" in vars(self._registry)
            or "decide" in vars(self._policy)
            or "add_evidence" in vars(self._state)
        ):
            _deny()
        fingerprint = _registry_fingerprint(self._registry)
        if fingerprint != self._registry_at_creation:
            _deny()
        # The reserved asset is only a label. No DNS, URL or handler use.
        if (
            type(context.mode) is not AssessmentMode
            or context.mode is not AssessmentMode.ANALYSIS_ONLY
            or type(context.approved_risk) is not RiskLevel
            or context.approved_risk is not RiskLevel.ANALYSIS_ONLY
            or context.authorization is not None
            or context.is_lab is not False
            or type(context.created_at) is not datetime
            or context.created_at.tzinfo is None
            or context.created_at.utcoffset() is None
            or not all(_identifier(x) for x in (
                context.run_id, context.client_id, context.engagement_id,
            ))
            or not _identifier(call.tool_id)
            or type(call.asset) is not str
            or call.asset != "synthetic.invalid"
        ):
            _deny()
        entry = next((x for x in fingerprint if x[0] == call.tool_id), None)
        if (
            entry is None
            or entry[4] is not InteractionKind.ANALYSIS
            or entry[5] is not RiskLevel.ANALYSIS_ONLY
            or not _arguments_are_valid(entry[7], call.arguments)
        ):
            _deny()
        # No permit, no evaluator; success is metadata shape only.
        return OfflineBoundaryReceipt(registered_analysis_tools=len(fingerprint))
