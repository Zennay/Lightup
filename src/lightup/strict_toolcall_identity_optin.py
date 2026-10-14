"""Optional pre-dispatch ToolCall field-identity admission (#1094).

This module is deliberately NOT installed in the default ToolExecutor. It can
only narrow caller-supplied tool-call shapes before the existing policy gate;
it cannot create grants, skip the existing executor, or approve a target.
"""

from __future__ import annotations

from dataclasses import dataclass
from string import ascii_letters, digits

from .ai.orchestration import RunContext, ToolCall, ToolDenied, ToolExecutor, ToolResult


_ALLOWED_INITIAL = frozenset(ascii_letters + "_")
_ALLOWED_REMAINDER = frozenset(ascii_letters + digits + "_.:-")
_MAX_IDENTIFIER = 128
_REFUSAL = "noncanonical tool-call identity"


def _canonical_identifier(value: object) -> bool:
    """Reject coercion, subclass methods, parser ambiguity and oversized IDs."""
    return (
        type(value) is str
        and 1 <= len(value) <= _MAX_IDENTIFIER
        and value[0] in _ALLOWED_INITIAL
        and all(ch in _ALLOWED_REMAINDER for ch in value[1:])
    )


def require_canonical_toolcall(call: object) -> ToolCall:
    """Validate *before* registry lookup or lossy ``dict(arguments)`` projection.

    Exact built-in identity, tuple shape and duplicate-name checks are
    intentionally conservative. Rejections contain no untrusted input.
    The returned immutable tuple snapshot is safe from structural mutation.
    Argument value types and target/grant authority remain the existing
    ToolDefinition, ExecutionPolicy and future installed authorization owner's
    responsibility.
    """
    if type(call) is not ToolCall:
        raise ToolDenied(_REFUSAL)
    if not _canonical_identifier(call.tool_id):
        raise ToolDenied(_REFUSAL)
    if type(call.arguments) is not tuple:
        raise ToolDenied(_REFUSAL)

    seen: set[str] = set()
    pairs: list[tuple[str, object]] = []
    for entry in call.arguments:
        if type(entry) is not tuple or len(entry) != 2:
            raise ToolDenied(_REFUSAL)
        key, value = entry
        if not _canonical_identifier(key) or key in seen:
            raise ToolDenied(_REFUSAL)
        seen.add(key)
        pairs.append((key, value))

    return ToolCall(tool_id=call.tool_id, asset=call.asset, arguments=tuple(pairs))


@dataclass(frozen=True)
class StrictFieldIdentityExecutor:
    """Explicit opt-in adapter, never an alternate authorization authority."""

    delegate: ToolExecutor

    def execute(self, context: RunContext, call: ToolCall) -> ToolResult:
        return self.delegate.execute(context, require_canonical_toolcall(call))
