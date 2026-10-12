"""Optional emergency STOP pre-dispatch gate for offline scope-authorization review.

This helper is deliberately NOT installed in default LightUp routes, workers,
queues, CLI or ToolExecutor. It cannot confer consent or grant authority.
It is not a durable/atomic emergency-stop or post-dispatch cancellation system.
"""

from __future__ import annotations

from .ai.orchestration import RunContext, ToolCall, ToolDenied, ToolExecutor, ToolResult


def execute_with_emergency_gate(
    executor: ToolExecutor,
    context: RunContext,
    call: ToolCall,
    *,
    stop_active: bool,
    override_requested: bool,
) -> ToolResult:
    """Deny malformed signals and STOP before delegating to the *normal* gate.

    The override signal is observational only: it never alters RunContext,
    ToolCall, requested risk, trusted policy, authorization or permissions.
    Even override=True must pass the existing ToolExecutor/ExecutionPolicy.
    Use only in a controlled synthetic lab until a source owner integrates a
    trusted persisted STOP with pre-I/O revalidation and dispatch fencing.
    """
    if type(stop_active) is not bool or type(override_requested) is not bool:
        raise ToolDenied("invalid emergency control signal")
    if stop_active:
        raise ToolDenied("emergency STOP: dispatch refused")
    return executor.execute(context, call)
