"""Offline-only ToolDefinition parameter schema integrity review (#1520).

This module is intentionally NOT registered with ToolRegistry or ToolExecutor.
REVIEW_ONLY never means consent, authorization, dispatch, or release.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

from .ai.orchestration import ParamKind, ToolDefinition, ToolParameter


_NAME: Final = re.compile(r"[a-z][a-z0-9_]*\Z", re.ASCII)
_MAX_PARAMETERS: Final = 32
_MAX_NAME: Final = 64


@dataclass(frozen=True)
class ParameterSchemaReview:
    status: str
    authorized: bool = False
    consent_verified: bool = False
    dispatch_allowed: bool = False
    release_allowed: bool = False


_HOLD = ParameterSchemaReview(status="HOLD")
_REVIEW = ParameterSchemaReview(status="REVIEW_ONLY")


def review_parameter_schema(definition: object) -> ParameterSchemaReview:
    """Inspect one in-memory definition without invoking registry or a handler.

    The parameter names must be exact, unique, canonical ASCII identifiers.
    Review success remains non-authorizing and is NOT a source-side fix.
    """
    if type(definition) is not ToolDefinition:
        return _HOLD
    parameters = definition.parameters
    if type(parameters) is not tuple or len(parameters) > _MAX_PARAMETERS:
        return _HOLD

    names: set[str] = set()
    for parameter in parameters:
        if type(parameter) is not ToolParameter:
            return _HOLD
        name = parameter.name
        if (
            type(name) is not str
            or not (1 <= len(name) <= _MAX_NAME)
            or _NAME.fullmatch(name) is None
            or name in names
        ):
            return _HOLD
        if (
            type(parameter.kind) is not ParamKind
            or type(parameter.required) is not bool
            or type(parameter.description) is not str
        ):
            return _HOLD
        names.add(name)
    return _REVIEW
