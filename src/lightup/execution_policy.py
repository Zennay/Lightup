from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .engagements import AuthorizationGrant, RiskLevel


class InteractionKind(str, Enum):
    ANALYSIS = "analysis"
    PASSIVE_PUBLIC = "passive_public"
    LAB_ACTIVE = "lab_active"
    TARGET_ACTIVE = "target_active"


@dataclass(frozen=True)
class ExecutionRequest:
    interaction: InteractionKind
    asset: str
    capability_id: str
    requested_risk: RiskLevel
    authorization: AuthorizationGrant | None = None
    is_lab: bool = False
    client_id: str | None = None
    engagement_id: str | None = None


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str


class ExecutionPolicy:
    """Product-level invariant gate.

    This policy is deliberately independent from the network adapter layer.
    Future adapters must pass both this policy and the existing ActivationGate.
    """

    def decide(self, request: ExecutionRequest) -> PolicyDecision:
        if not isinstance(request.interaction, InteractionKind):
            return PolicyDecision(False, "interaction must be an InteractionKind")
        if not isinstance(request.requested_risk, RiskLevel):
            return PolicyDecision(False, "requested risk must be a RiskLevel")

        if request.interaction is InteractionKind.ANALYSIS:
            if request.requested_risk is not RiskLevel.ANALYSIS_ONLY:
                return PolicyDecision(False, "analysis mode cannot request active risk")
            return PolicyDecision(True, "analysis-only")

        if request.interaction is InteractionKind.PASSIVE_PUBLIC:
            if request.requested_risk > RiskLevel.PASSIVE:
                return PolicyDecision(False, "passive discovery cannot request active risk")
            return PolicyDecision(True, "public passive discovery")

        if request.interaction is InteractionKind.LAB_ACTIVE:
            if not request.is_lab:
                return PolicyDecision(False, "lab execution requires a lab target")
            return PolicyDecision(True, "isolated lab execution")

        if request.interaction is not InteractionKind.TARGET_ACTIVE:
            return PolicyDecision(False, "unsupported interaction kind")

        if request.requested_risk == RiskLevel.DESTRUCTIVE_LAB_ONLY:
            return PolicyDecision(False, "destructive risk is restricted to isolated labs")

        grant = request.authorization
        if grant is None:
            return PolicyDecision(False, "active target interaction requires authorization")
        if not request.client_id or not request.engagement_id:
            return PolicyDecision(
                False, "active target interaction requires client and engagement binding"
            )
        if grant.client_id != request.client_id:
            return PolicyDecision(False, "authorization client does not match execution client")
        if grant.engagement_id != request.engagement_id:
            return PolicyDecision(
                False, "authorization engagement does not match execution engagement"
            )
        if not grant.is_current():
            return PolicyDecision(False, "authorization is not currently valid")
        if request.requested_risk > grant.scope.max_risk:
            return PolicyDecision(False, "requested risk exceeds authorized maximum")
        if not grant.scope.allows_asset(request.asset):
            return PolicyDecision(False, "asset is outside the authorized scope")
        if not grant.scope.allows_capability(request.capability_id):
            return PolicyDecision(False, "capability is outside the authorized scope")

        return PolicyDecision(True, "authorized active assessment")
