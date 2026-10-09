"""Offline argument-integrity helper for future source-owner integration.

This module does not authorize targets and is not wired into ToolExecutor.
It preserves the current ToolDefinition schema contract while rejecting
ambiguous duplicate keys and non-finite numeric inputs before dispatch.
"""
from __future__ import annotations

import math
from typing import Any, Iterable

from .orchestration import OrchestrationError, ParamKind, ToolDefinition, ToolParameter


def validate_unambiguous_arguments(
    definition: ToolDefinition,
    pairs: Iterable[tuple[str, Any]],
) -> dict[str, Any]:
    """Return validated arguments or fail closed without side effects.

    The caller must still enforce durable consent, destination authorization,
    revocation, run mode, and risk policy. This is only input integrity.
    """
    if type(definition) is not ToolDefinition:
        raise OrchestrationError("tool definition must be a registered ToolDefinition")
    if type(definition.parameters) is not tuple:
        raise OrchestrationError("tool parameter registry must be a tuple")
    if any(type(parameter) is not ToolParameter for parameter in definition.parameters):
        raise OrchestrationError("tool parameter registry contains invalid definition")
    if any(type(p.kind) is not ParamKind or type(p.required) is not bool\n           for p in definition.parameters):\n        raise OrchestrationError("tool parameter registry has invalid kind or required flag")\n    parameter_names = [p.name for p in definition.parameters]
    if any(type(name) is not str for name in parameter_names):
        raise OrchestrationError("tool parameter names must be strings")
    if len(parameter_names) != len(set(parameter_names)):
        raise OrchestrationError("duplicate tool parameter names in registry definition")
    if type(pairs) not in (tuple, list):
        raise OrchestrationError("tool arguments must be ordered pairs")
    result: dict[str, Any] = {}
    for pair in pairs:
        if type(pair) not in (tuple, list) or len(pair) != 2:
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
            if isinstance(value, float) and not math.isfinite(value):
                raise OrchestrationError(f"tool argument {name!r} must be finite")
    return result
