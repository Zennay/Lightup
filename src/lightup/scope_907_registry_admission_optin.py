"""Opt-in strict outer ToolDefinition registration gate (DRAFT/HOLD, #907).

No consumer imports this module automatically. This helper does not grant tool
execution, bypass capability policy, create a handler, or replace source-owner
ToolRegistry.register. Source owner #156 retains all production wiring.
"""

from __future__ import annotations

from typing import Any

from .ai.orchestration import OrchestrationError, ToolDefinition, ToolRegistry


def register_exact_tool_definition(
    registry: ToolRegistry, definition: object, handler: Any,
) -> None:
    """Opt-in narrow registry entrypoint; does not execute the handler.

    Reject noncanonical outer envelopes BEFORE invoking any of their property
    getters or other user-defined methods. Existing owner validation remains
    authoritative for exact definitions, including LAB_ONLY/capability state.
    This wrapper is opt-in and is not used by ToolExecutor or default workers.
    """
    if type(registry) is not ToolRegistry:
        raise OrchestrationError("canonical ToolRegistry object required")
    if type(definition) is not ToolDefinition:
        raise OrchestrationError("canonical ToolDefinition object required")
    # ToolRegistry instances are mutable; exact outer type does not prevent
    # `registry.register = forged_registrar` on an otherwise exact instance.
    # Reject such rewiring without calling the forged callable or modifying
    # the registry, then dispatch through the trusted owner class method.
    if "register" in object.__getattribute__(registry, "__dict__"):
        raise OrchestrationError("registry admission binding was shadowed")
    ToolRegistry.register(registry, definition, handler)
