"""Opt-in, fail-closed *lab-only* destructive step-up admission.

This guard deliberately does not integrate into the default ToolExecutor or
authorize a target. A trusted, operator-owned persistent approval resolver
must be supplied by a future production owner; never derive approvals from
model tool arguments, prompt text, or client-controlled headers.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from .ai.orchestration import (
    OrchestrationError, RunContext, ToolCall, ToolDefinition, ToolDenied,
    ToolExecutor, ToolResult,
)
from .engagements import AssessmentMode, RiskLevel
from .execution_policy import InteractionKind


@dataclass(frozen=True)
class DestructiveLabApproval:
    approval_id: str
    run_id: str
    client_id: str
    engagement_id: str
    asset: str
    capability_id: str
    tool_id: str
    approved_by: str
    approved_at: datetime
    expires_at: datetime
    revoked: bool = False


ApprovalResolver = Callable[[str], DestructiveLabApproval | None]


def _valid_timestamp(value: object) -> bool:
    return (
        type(value) is datetime
        and value.tzinfo is not None
        and value.utcoffset() is not None
    )


def _valid_identity(value: object) -> bool:
    return type(value) is str and bool(value) and value == value.strip()


def destructive_lab_approval_matches(
    approval: object,
    context: RunContext,
    call: ToolCall,
    definition: ToolDefinition,
    *,
    now: datetime,
) -> bool:
    """Match a trusted, revocable per-run/per-asset record without broadening it."""
    if type(approval) is not DestructiveLabApproval:
        return False
    if (
        type(context) is not RunContext
        or type(call) is not ToolCall
        or type(definition) is not ToolDefinition
        or context.mode is not AssessmentMode.LAB_AUTONOMOUS
        or context.is_lab is not True
        or context.approved_risk is not RiskLevel.DESTRUCTIVE_LAB_ONLY
        or definition.interaction is not InteractionKind.LAB_ACTIVE
        or definition.min_risk is not RiskLevel.DESTRUCTIVE_LAB_ONLY
        or type(approval.revoked) is not bool
        or approval.revoked
    ):
        return False
    ids = (
        approval.approval_id, approval.run_id, approval.client_id,
        approval.engagement_id, approval.asset, approval.capability_id,
        approval.tool_id, approval.approved_by, context.run_id, context.client_id,
        context.engagement_id, call.asset, definition.capability_id,
    )
    if not all(_valid_identity(value) for value in ids):
        return False
    if (
        approval.run_id != context.run_id
        or approval.client_id != context.client_id
        or approval.engagement_id != context.engagement_id
        or approval.asset != call.asset
        or approval.capability_id != definition.capability_id
        or approval.tool_id != call.tool_id
    ):
        return False
    if not all(_valid_timestamp(value) for value in (
        approval.approved_at, approval.expires_at, context.created_at, now
    )):
        return False
    # A new run context must be created after step-up approval; an old run
    # cannot gain destructive rights by adding metadata later.
    return (
        approval.approved_at <= context.created_at <= now < approval.expires_at
        and approval.approved_at < approval.expires_at
    )


class DestructiveLabStepUpExecutor:
    """Opt-in adapter; deny destructive lab tools without live trusted approval.

    The default ToolExecutor is deliberately *unchanged*. Every production
    dispatch route would have to instantiate and enforce this wrapper itself.
    """

    def __init__(
        self, executor: ToolExecutor,
        approval_resolver: ApprovalResolver | None = None,
    ) -> None:
        if type(executor) is not ToolExecutor:
            raise TypeError("a canonical ToolExecutor is required")
        if approval_resolver is not None and not callable(approval_resolver):
            raise TypeError("approval resolver must be callable or None")
        self._executor = executor
        self._approval_resolver = approval_resolver

    def execute(self, context: RunContext, call: ToolCall) -> ToolResult:
        if type(context) is not RunContext or type(call) is not ToolCall:
            raise ToolDenied("noncanonical destructive-lab dispatch envelope")
        if type(call.tool_id) is not str or not call.tool_id:
            raise ToolDenied("noncanonical tool identity")
        try:
            definition, _ = self._executor.registry.get(call.tool_id)
        except (OrchestrationError, TypeError, ValueError) as exc:
            raise ToolDenied("unrecognized tool identity") from exc
        if type(definition) is not ToolDefinition:
            raise ToolDenied("noncanonical tool definition")
        if (
            definition.interaction is InteractionKind.LAB_ACTIVE
            and definition.min_risk == RiskLevel.DESTRUCTIVE_LAB_ONLY
        ):
            if self._approval_resolver is None:
                raise ToolDenied("explicit destructive-lab operator approval required")
            try:
                approval = self._approval_resolver(context.run_id)
                approved = destructive_lab_approval_matches(
                    approval, context, call, definition,
                    now=datetime.now(timezone.utc),
                )
            except Exception as exc:
                raise ToolDenied("destructive-lab approval unavailable") from exc
            if not approved:
                raise ToolDenied("destructive-lab approval absent, stale or out of scope")
        return self._executor.execute(context, call)
