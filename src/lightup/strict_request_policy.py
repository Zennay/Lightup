"""Opt-in strict admission for ExecutionRequest's *runtime* authority types.

This is a conservative defense-in-depth wrapper around ExecutionPolicy. It
never grants authority on its own and is intentionally not installed into the
shared production executor while the executor/source owner is active.

It only checks the request envelope before delegating to the existing product
policy. Actual authorization requires the current trusted grant resolver,
operator approval, confinement and dispatch-time revocation enforcement.
"""
from __future__ import annotations

from .engagements import AuthorizationGrant, RiskLevel
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
        if request.authorization is not None and type(request.authorization) is not AuthorizationGrant:
            return PolicyDecision(False, "invalid authorization grant type")

        # The base policy relies on the caller (ToolExecutor) to separate
        # target-active and lab contexts. This opt-in admission additionally
        # enforces the invariant for standalone policy consumers.
        if request.interaction is InteractionKind.TARGET_ACTIVE and request.is_lab:
            return PolicyDecision(False, "lab marker cannot authorize real-target execution")

        return super().decide(request)
