from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum

from .engagements import AuthorizationGrant, RiskLevel, ScopeDefinition


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


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str


def _plain_identity(value: object) -> bool:
    return type(value) is str and bool(value.strip())


def _canonical_request(request: object) -> bool:
    """Reject duck-typed requests and ambiguous enum/bool/string fields."""
    return (
        type(request) is ExecutionRequest
        and type(request.interaction) is InteractionKind
        and type(request.requested_risk) is RiskLevel
        and type(request.is_lab) is bool
        and _plain_identity(request.asset)
        and _plain_identity(request.capability_id)
        and (
            request.authorization is None
            or type(request.authorization) is AuthorizationGrant
        )
    )


class ExecutionPolicy:
    """Product-level invariant gate; no direct network or handler access.

    This does not replace the separate application-side approval, durable-grant
    read, consent/revocation-at-use or future active adapter gates.
    """

    def decide(self, request: ExecutionRequest) -> PolicyDecision:
        # Fail closed before reading values that could otherwise be supplied by
        # a polymorphic request or an arbitrary enum-like object. In particular
        # an unknown interaction may never fall through as TARGET_ACTIVE.
        if not _canonical_request(request):
            return PolicyDecision(False, "noncanonical execution request")

        if request.interaction is InteractionKind.ANALYSIS:
            if request.requested_risk is not RiskLevel.ANALYSIS_ONLY:
                return PolicyDecision(False, "analysis mode cannot request active risk")
            return PolicyDecision(True, "analysis-only")

        if request.interaction is InteractionKind.PASSIVE_PUBLIC:
            if request.requested_risk > RiskLevel.PASSIVE:
                return PolicyDecision(False, "passive discovery cannot request active risk")
            return PolicyDecision(True, "public passive discovery")

        if request.interaction is InteractionKind.LAB_ACTIVE:
            if request.is_lab is not True:
                return PolicyDecision(False, "lab execution requires a lab target")
            return PolicyDecision(True, "isolated lab execution")

        # Only an exact TARGET_ACTIVE enum reaches the real-target boundary.
        if request.interaction is not InteractionKind.TARGET_ACTIVE:
            return PolicyDecision(False, "unknown interaction is not authorized")
        if request.is_lab is True:
            return PolicyDecision(False, "lab runs cannot authorize real-target interaction")
        if request.requested_risk is RiskLevel.DESTRUCTIVE_LAB_ONLY:
            return PolicyDecision(False, "destructive risk is restricted to isolated labs")

        grant = request.authorization
        if grant is None:
            return PolicyDecision(False, "active target interaction requires authorization")
        if not _canonical_grant(grant):
            return PolicyDecision(False, "noncanonical authorization grant")
        scope = grant.scope
        if not _canonical_scope(scope):
            return PolicyDecision(False, "noncanonical authorization scope")

        # Use a detached canonical source value rather than polymorphic
        # grant/scope methods. Check the same UTC instant used for both bounds.
        now = datetime.now(timezone.utc)
        if not (grant.valid_from <= now <= grant.valid_until):
            return PolicyDecision(False, "authorization is not currently valid")
        if request.requested_risk > scope.max_risk:
            return PolicyDecision(False, "requested risk exceeds authorized maximum")
        if not scope.allows_asset(request.asset):
            return PolicyDecision(False, "asset is outside the authorized scope")
        if not scope.allows_capability(request.capability_id):
            return PolicyDecision(False, "capability is outside the authorized scope")

        return PolicyDecision(True, "authorized active assessment")


def _canonical_scope(scope: object) -> bool:
    if type(scope) is not ScopeDefinition or type(scope.max_risk) is not RiskLevel:
        return False
    for entries in (scope.assets, scope.allowed_capabilities, scope.excluded_assets):
        if type(entries) is not tuple or not all(_plain_identity(item) for item in entries):
            return False
    return bool(scope.assets)


def _canonical_grant(grant: object) -> bool:
    if type(grant) is not AuthorizationGrant:
        return False
    for value in (
        grant.grant_id, grant.client_id, grant.engagement_id,
        grant.approved_by, grant.reference,
    ):
        if not _plain_identity(value):
            return False
    if type(grant.recurring_retest_allowed) is not bool:
        return False
    for bound in (grant.valid_from, grant.valid_until):
        if (
            type(bound) is not datetime
            or bound.tzinfo is None
            or bound.utcoffset() is None
        ):
            return False
    return grant.valid_from <= grant.valid_until
