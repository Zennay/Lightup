"""Offline-only exact primitive value snapshots for scope issue #1095.

Opt-in reference ONLY. The installed ToolExecutor and ToolDefinition are never
patched or wrapped by this module. Success is not customer consent, permission,
risk approval or evidence of safe execution. No handler, state, DNS or network IO.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .ai.orchestration import OrchestrationError, ParamKind, ToolDefinition, ToolParameter
from .engagements import RiskLevel
from .execution_policy import InteractionKind

MAX_SYNTHETIC_BATCH_ITEMS = 32
MAX_SYNTHETIC_PARAMETERS = 32


@dataclass(frozen=True, slots=True)
class PrimitiveValueSnapshot:
    """Immutable copies of canonical builtin values, NOT an execution token."""

    items: tuple[tuple[str, object], ...]
    @property
    def authorization_verified(self) -> bool:
        return False

    @property
    def permit_issued(self) -> bool:
        return False

    @property
    def execution_enabled(self) -> bool:
        return False

    def as_arguments(self) -> dict[str, object]:
        """Make a fresh ordinary dict. Caller must still enforce all real gates."""
        return dict(self.items)


@dataclass(frozen=True, slots=True)
class PrimitiveBatchSnapshot:
    entries: tuple[PrimitiveValueSnapshot, ...]
    @property
    def authorization_verified(self) -> bool:
        return False

    @property
    def permit_issued(self) -> bool:
        return False

    @property
    def execution_enabled(self) -> bool:
        return False

    @property
    def count(self) -> int:
        return len(self.entries)


def _exact_builtin_value(kind: ParamKind, value: Any) -> bool:
    """No isinstance, coercion, custom __eq__, or polymorphic numeric values."""
    if kind is ParamKind.STRING:
        return type(value) is str
    if kind is ParamKind.INTEGER:
        return type(value) is int
    if kind is ParamKind.NUMBER:
        return type(value) in (int, float)
    if kind is ParamKind.BOOLEAN:
        return type(value) is bool
    return False


def snapshot_exact_primitive_values(
    definition: ToolDefinition, arguments: dict[str, object]
) -> PrimitiveValueSnapshot:
    """Fail closed on mismatched runtime values before constructing a tool call.

    Definitions are trusted source-owner registry metadata; this helper does
    not attest their origin, policy, capability, grant or current authorization.
    """
    if type(definition) is not ToolDefinition:
        raise OrchestrationError("untrusted synthetic tool definition")
    # An optional shape diagnostic MUST NOT be used as an input gate for
    # real, passive, lab-active or target-active tools. This check supplies
    # no authorization, even for these synthetic ANALYSIS_ONLY definitions.
    if (
        type(definition.tool_id) is not str
        or not definition.tool_id.startswith("synthetic-")
        or len(definition.tool_id) <= len("synthetic-")
        or definition.interaction is not InteractionKind.ANALYSIS
        or definition.min_risk is not RiskLevel.ANALYSIS_ONLY
    ):
        raise OrchestrationError("primitive preflight supports synthetic ANALYSIS_ONLY tools only")
    if type(definition.parameters) is not tuple or len(definition.parameters) > MAX_SYNTHETIC_PARAMETERS:
        raise OrchestrationError("synthetic parameter metadata must be a bounded builtin tuple")
    if type(arguments) is not dict:
        raise OrchestrationError("synthetic arguments must be an ordinary dict")
    if len(arguments) > MAX_SYNTHETIC_PARAMETERS:
        raise OrchestrationError("too many synthetic arguments")
    if any(type(key) is not str for key in arguments):
        raise OrchestrationError("synthetic argument keys must be builtin strings")

    ordered: list[tuple[str, object]] = []
    seen: set[str] = set()
    for parameter in definition.parameters:
        # The original registry owner owns metadata validation. This is a
        # narrow protective check, not an independent definition attestation.
        if (
            type(parameter) is not ToolParameter
            or type(parameter.name) is not str
            or type(parameter.kind) is not ParamKind
            or type(parameter.required) is not bool
        ):
            raise OrchestrationError("invalid synthetic parameter metadata")
        if parameter.name in seen:
            raise OrchestrationError("duplicate synthetic parameter metadata")
        seen.add(parameter.name)
        if parameter.name not in arguments:
            if parameter.required:
                raise OrchestrationError("missing required synthetic argument")
            continue
        value = arguments[parameter.name]
        if not _exact_builtin_value(parameter.kind, value):
            raise OrchestrationError("synthetic primitive value has noncanonical type")
        ordered.append((parameter.name, value))

    if set(arguments) != seen.intersection(arguments):
        raise OrchestrationError("unexpected synthetic argument")
    return PrimitiveValueSnapshot(tuple(ordered))


def snapshot_exact_primitive_batch(
    requests: tuple[tuple[ToolDefinition, dict[str, object]], ...],
) -> PrimitiveBatchSnapshot:
    """All-or-nothing synthetic preflight: return nothing on a late invalid row.

    No execution or state mutation is performed, even after a valid row.
    """
    if type(requests) is not tuple or not 1 <= len(requests) <= MAX_SYNTHETIC_BATCH_ITEMS:
        raise OrchestrationError("synthetic batch size must be 1..32")
    snapshots: list[PrimitiveValueSnapshot] = []
    for request in requests:
        if type(request) is not tuple or len(request) != 2:
            raise OrchestrationError("invalid synthetic batch entry")
        definition, arguments = request
        snapshots.append(snapshot_exact_primitive_values(definition, arguments))
    return PrimitiveBatchSnapshot(tuple(snapshots))
