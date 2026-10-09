"""Opt-in, fail-closed *lab-only* destructive step-up admission.

This guard deliberately does not integrate into the default ToolExecutor or
authorize a target. A trusted, operator-owned persistent approval resolver
must be supplied by a future production owner; never derive approvals from
model tool arguments, prompt text, or client-controlled headers.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
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
LabIsolationVerifier = Callable[[RunContext, ToolCall], bool]

# A single operator approval must never authorize unbounded future work.
# Proof of who issued it still belongs to a trusted persistent approval store.
MAX_DESTRUCTIVE_APPROVAL_WINDOW = timedelta(hours=24)


def _valid_timestamp(value: object) -> bool:
    return (
        type(value) is datetime
        and value.tzinfo is not None
        and value.utcoffset() is not None
    )


def _valid_identity(value: object) -> bool:
    return (
        type(value) is str
        and 0 < len(value) <= 256
        and value == value.strip()
        and all(0x20 <= ord(char) < 0x7F for char in value)
    )


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
        or context.authorization is not None
        or definition.interaction is not InteractionKind.LAB_ACTIVE
        or definition.min_risk is not RiskLevel.DESTRUCTIVE_LAB_ONLY
        or type(approval.revoked) is not bool
        or approval.revoked
        or type(definition.tool_id) is not str
        or type(definition.capability_id) is not str
        or not _valid_identity(call.tool_id)
        or definition.tool_id != call.tool_id
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
        and approval.expires_at - approval.approved_at <= MAX_DESTRUCTIVE_APPROVAL_WINDOW
    )


class DestructiveLabStepUpExecutor:
    """Opt-in adapter; deny destructive lab tools without live trusted approval.

    The default ToolExecutor is deliberately *unchanged*. Every production
    dispatch route would have to instantiate and enforce this wrapper itself.
    """

    def __init__(
        self, executor: ToolExecutor,
        approval_resolver: ApprovalResolver | None = None,
        isolation_verifier: LabIsolationVerifier | None = None,
    ) -> None:
        if type(executor) is not ToolExecutor:
            raise TypeError("a canonical ToolExecutor is required")
        if approval_resolver is not None and not callable(approval_resolver):
            raise TypeError("approval resolver must be callable or None")
        if isolation_verifier is not None and not callable(isolation_verifier):
            raise TypeError("lab isolation verifier must be callable or None")
        self._executor = executor
        # A registry reference swapped after construction cannot inherit
        # existing approvals. The source owner must still freeze registration
        # and prevent concurrent mutations at the real entrypoint.
        self._registry = executor.registry
        self._approval_resolver = approval_resolver
        self._isolation_verifier = isolation_verifier

    def execute(self, context: RunContext, call: ToolCall) -> ToolResult:
        if type(context) is not RunContext or type(call) is not ToolCall:
            raise ToolDenied("noncanonical destructive-lab dispatch envelope")
        if type(call.tool_id) is not str or not call.tool_id:
            raise ToolDenied("noncanonical tool identity")
        if self._executor.registry is not self._registry:
            raise ToolDenied("lab tool registry identity changed")
        try:
            definition, handler = self._registry.get(call.tool_id)
        except (OrchestrationError, TypeError, ValueError):
            raise ToolDenied("unrecognized tool identity") from None
        # Do not let raw 5, bool, foreign enums, or duck definitions skip the
        # step-up branch and fall through to a permissive downstream policy.
        if (
            type(definition) is not ToolDefinition
            or type(definition.tool_id) is not str
            or definition.tool_id != call.tool_id
            or not _valid_identity(definition.capability_id)
            or type(definition.interaction) is not InteractionKind
            or type(definition.min_risk) is not RiskLevel
        ):
            raise ToolDenied("noncanonical lab tool definition")
        if (
            definition.interaction is InteractionKind.LAB_ACTIVE
            and definition.min_risk is RiskLevel.DESTRUCTIVE_LAB_ONLY
        ):
            # Parameter schemas do not yet describe destination authority.
            # Until a trusted lab-only argument binder is integrated, even
            # optional/default parameters must not choose a second asset.
            if type(definition.parameters) is not tuple or definition.parameters:
                raise ToolDenied("destructive lab tool arguments lack a reviewed scope binding")
            if type(call.arguments) is not tuple or call.arguments:
                raise ToolDenied("destructive lab tool arguments are not authorized")
            if self._approval_resolver is None:
                raise ToolDenied("explicit destructive-lab operator approval required")
            try:
                approval = self._approval_resolver(context.run_id)
                approved = destructive_lab_approval_matches(
                    approval, context, call, definition,
                    now=datetime.now(timezone.utc),
                )
            except Exception:
                # A resolver may expose private approval or DB details in its
                # exception text. Never chain that exception into an audit log.
                raise ToolDenied("destructive-lab approval unavailable") from None
            if not approved:
                raise ToolDenied("destructive-lab approval absent, stale or out of scope")
            # Operator consent and actual lab confinement are independent.
            # Never infer isolation from is_lab=True or the asset label.
            if self._isolation_verifier is None:
                raise ToolDenied("verified lab isolation is required")
            try:
                isolated = self._isolation_verifier(context, call)
            except Exception:
                raise ToolDenied("lab isolation verification unavailable") from None
            if isolated is not True:
                raise ToolDenied("lab isolation is not verified")
        # Check again after any resolver callbacks: synchronous changes to
        # registered handler/tool metadata must not switch what was approved.
        # This is not a substitute for owner-controlled immutable registries.
        if self._executor.registry is not self._registry:
            raise ToolDenied("lab tool registry identity changed")
        try:
            current_definition, current_handler = self._registry.get(call.tool_id)
        except (OrchestrationError, TypeError, ValueError):
            raise ToolDenied("lab tool identity changed during admission") from None
        if current_definition is not definition or current_handler is not handler:
            raise ToolDenied("lab tool definition changed during admission")
        return self._executor.execute(context, call)
