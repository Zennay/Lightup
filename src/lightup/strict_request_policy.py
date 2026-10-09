"""Opt-in strict admission for ExecutionRequest's *runtime* authority types.

This is a conservative defense-in-depth wrapper around ExecutionPolicy. It
never grants authority on its own and is intentionally not installed into the
shared production executor while the executor/source owner is active.

It only checks the request envelope before delegating to the existing product
policy. Actual authorization requires the current trusted grant resolver,
operator approval, confinement and dispatch-time revocation enforcement.
"""
from __future__ import annotations

from datetime import datetime

from .engagements import AuthorizationGrant, RiskLevel, ScopeDefinition
from .execution_policy import (
    ExecutionPolicy,
    ExecutionRequest,
    InteractionKind,
    PolicyDecision,
)


def _canonical_text(value: object) -> bool:
    """Reject polymorphic, empty and control-bearing authority identifiers."""
    return (
        type(value) is str
        and bool(value)
        and value == value.strip()
        and not any(ord(char) < 32 or ord(char) == 127 for char in value)
    )


def _grant_shape_is_canonical(grant: AuthorizationGrant) -> bool:
    """Check data shape, not signature/trust, before delegating to policy.

    Frozen dataclasses do not enforce annotation types at construction time.
    In particular a non-ScopeDefinition object can supply permissive
    `allows_asset` / `allows_capability` methods to the ordinary policy.
    """
    try:
        scope = grant.scope
        if type(scope) is not ScopeDefinition or type(scope.max_risk) is not RiskLevel:
            return False
        for value in (
            grant.grant_id, grant.client_id, grant.engagement_id,
            grant.approved_by, grant.reference,
        ):
            if not _canonical_text(value):
                return False
        for values in (scope.assets, scope.allowed_capabilities, scope.excluded_assets):
            if type(values) is not tuple or not all(_canonical_text(item) for item in values):
                return False
        if type(grant.recurring_retest_allowed) is not bool:
            return False
        start, end = grant.valid_from, grant.valid_until
        if type(start) is not datetime or type(end) is not datetime:
            return False
        if start.utcoffset() is None or end.utcoffset() is None:
            return False
        if start > end:
            return False
        return True
    except (AttributeError, TypeError, ValueError, OverflowError):
        return False


class StrictExecutionRequestPolicy(ExecutionPolicy):
    """Reject ambiguous types before the ordinary scope/risk gate runs.

    Callers may opt in using ToolExecutor(registry, state, policy=...).
    Default application wiring is unchanged; opting in is not equivalent to
    authorization to run against a real target.
    """

    def decide(self, request: ExecutionRequest) -> PolicyDecision:
        if type(request) is not ExecutionRequest:
            return PolicyDecision(False, "invalid execution request type")
        if type(request.interaction) is not InteractionKind:
            return PolicyDecision(False, "invalid interaction kind type")
        if type(request.requested_risk) is not RiskLevel:
            return PolicyDecision(False, "invalid requested risk type")
        if type(request.is_lab) is not bool:
            return PolicyDecision(False, "invalid lab marker type")
        if not _canonical_text(request.asset):
            return PolicyDecision(False, "invalid asset identity")
        if not _canonical_text(request.capability_id):
            return PolicyDecision(False, "invalid capability identity")
        if request.authorization is not None:
            if type(request.authorization) is not AuthorizationGrant:
                return PolicyDecision(False, "invalid authorization grant type")
            if not _grant_shape_is_canonical(request.authorization):
                return PolicyDecision(False, "invalid authorization grant envelope")

        # The base policy relies on the caller (ToolExecutor) to separate
        # target-active and lab contexts. This opt-in admission additionally
        # enforces the invariant for standalone policy consumers.
        if request.interaction is InteractionKind.TARGET_ACTIVE and request.is_lab:
            return PolicyDecision(False, "lab marker cannot authorize real-target execution")

        return super().decide(request)
