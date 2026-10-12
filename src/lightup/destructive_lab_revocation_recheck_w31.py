"""Deny-only post-isolation approval recheck for offline risk-5 review (#1173).

This is an optional, uninstalled defense-in-depth helper. Passing it is NEVER
authorization to dispatch: a durable transactional approval/dispatch fence,
operator issuance, and real lab egress isolation are still required.
"""
from __future__ import annotations

from datetime import datetime, timezone

from .ai.orchestration import RunContext, ToolCall, ToolDefinition, ToolDenied
from .destructive_lab_step_up import (
    ApprovalResolver,
    DestructiveLabApproval,
    destructive_lab_approval_matches,
)


def require_unchanged_live_lab_approval(
    original: object,
    resolver: ApprovalResolver | None,
    context: RunContext,
    call: ToolCall,
    definition: ToolDefinition,
) -> None:
    """Deny if the live trusted approval changed after an isolation callback.

    Return None, not a grant or permission token. This second read narrows one
    synchronous revocation window; it does NOT close the TOCTOU window between
    this read and a real handler. A durable versioned lock/fence is mandatory.
    """
    if (
        type(context) is not RunContext
        or type(call) is not ToolCall
        or type(definition) is not ToolDefinition
        or type(original) is not DestructiveLabApproval
        or resolver is None
        or not callable(resolver)
    ):
        raise ToolDenied("destructive-lab approval recheck unavailable")
    if not destructive_lab_approval_matches(
        original, context, call, definition, now=datetime.now(timezone.utc)
    ):
        raise ToolDenied("destructive-lab approval no longer current")
    try:
        fresh = resolver(context.run_id)
    except Exception:
        # Do not leak approval-store errors or their private details.
        raise ToolDenied("destructive-lab approval recheck unavailable") from None
    # Equality covers the exact operator record ID, all scope dimensions,
    # provenance, times and revocation state. This is NOT a durable revision.
    if type(fresh) is not DestructiveLabApproval or fresh != original:
        raise ToolDenied("destructive-lab approval changed during isolation")
    if not destructive_lab_approval_matches(
        fresh, context, call, definition, now=datetime.now(timezone.utc)
    ):
        raise ToolDenied("destructive-lab approval no longer current")
