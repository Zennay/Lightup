"""Offline argument-integrity helper for future source-owner integration.

This module does not authorize targets and is not wired into ToolExecutor.
It preserves the current ToolDefinition schema contract while rejecting
ambiguous duplicate keys and non-finite numeric inputs before dispatch.
"""
from __future__ import annotations

import math
from typing import Any, Iterable

from .orchestration import OrchestrationError, ParamKind, ToolDefinition


def validate_unambiguous_arguments(
    definition: ToolDefinition,
    pairs: Iterable[tuple[str, Any]],
) -> dict[str, Any]:
    """Return validated arguments or fail closed without side effects.

    The caller must still enforce durable consent, destination authorization,
    revocation, run mode, and risk policy. This is only input integrity.
    """
    if not isinstance(pairs, (tuple, list)):
        raise OrchestrationError("tool arguments must be ordered pairs")
    result: dict[str, Any] = {}
    for pair in pairs:
        if not isinstance(pair, (tuple, list)) or len(pair) != 2:
            raise OrchestrationError("tool argument entry must contain exactly two items")
        name, value = pair
        if type(name) is not str:
            raise OrchestrationError("tool argument names must be strings")
        if name in result:
            raise OrchestrationError(f"duplicate tool argument name {name!r}")
        result[name] = value

    definition.validate_arguments(result)
    parameter_by_name = {p.name: p for p in definition.parameters}
    for name, value in result.items():
        if parameter_by_name[name].kind is ParamKind.NUMBER:
            if not math.isfinite(value):
                raise OrchestrationError(f"tool argument {name!r} must be finite")
    return result
