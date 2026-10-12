"""Opt-in, non-authorizing exact-enum policy identity gate.

Standalone reference for #986 / #987. This class is NOT wired into the
default ToolExecutor or production factory. The real grant/tenant/asset/
capability/revocation checks must remain mandatory at execution time.
"""
from __future__ import annotations

from .engagements import RiskLevel
from .execution_policy import (
    ExecutionPolicy,
    ExecutionRequest,
    InteractionKind,
    PolicyDecision,
)


class StrictIdentityExecutionPolicy(ExecutionPolicy):
    """Narrow refusal-only wrapper around the existing product policy.

    Invalid enum identities are refused BEFORE the inherited policy's
    TARGET_ACTIVE fallthrough or PASSIVE_PUBLIC numeric comparisons.
    No input coercion, grant creation, state change or network activity.
    """

    def decide(self, request: ExecutionRequest) -> PolicyDecision:
        if type(request.interaction) is not InteractionKind:
            return PolicyDecision(False, "noncanonical interaction kind")
        if type(request.requested_risk) is not RiskLevel:
            return PolicyDecision(False, "noncanonical requested risk")
        return super().decide(request)
