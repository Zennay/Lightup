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
        original_request = request
        request = ExecutionRequest(
            interaction=request.interaction,
            asset=request.asset,
            capability_id=request.capability_id,
            requested_risk=request.requested_risk,
            authorization=request.authorization,
            is_lab=request.is_lab,
        )
        if not _canonical_request(request):
            return PolicyDecision(False, "execution request changed while reading")

        if request.interaction is InteractionKind.ANALYSIS:
            if request.requested_risk is not RiskLevel.ANALYSIS_ONLY:
                return PolicyDecision(False, "analysis mode cannot request active risk")
            return _positive_if_request_unchanged(original_request, request, "analysis-only")

        if request.interaction is InteractionKind.PASSIVE_PUBLIC:
            if request.requested_risk > RiskLevel.PASSIVE:
                return PolicyDecision(False, "passive discovery cannot request active risk")
            return _positive_if_request_unchanged(original_request, request, "public passive discovery")

        if request.interaction is InteractionKind.LAB_ACTIVE:
            if request.is_lab is not True:
                return PolicyDecision(False, "lab execution requires a lab target")
            return _positive_if_request_unchanged(original_request, request, "isolated lab execution")

        # Only an exact TARGET_ACTIVE enum reaches the real-target boundary.
        if request.interaction is not InteractionKind.TARGET_ACTIVE:
            return PolicyDecision(False, "unknown interaction is not authorized")
        if request.is_lab is True:
            return PolicyDecision(False, "lab runs cannot authorize real-target interaction")
        if request.requested_risk is RiskLevel.DESTRUCTIVE_LAB_ONLY:
            return PolicyDecision(False, "destructive risk is restricted to isolated labs")

        original_grant = request.authorization
        if original_grant is None:
            return PolicyDecision(False, "active target interaction requires authorization")
        if not _canonical_grant(original_grant):
            return PolicyDecision(False, "noncanonical authorization grant")
        original_scope = original_grant.scope
        if not _canonical_scope(original_scope):
            return PolicyDecision(False, "noncanonical authorization scope")
        grant = _grant_snapshot(original_grant)
        if not _canonical_grant(grant) or not _canonical_scope(grant.scope):
            return PolicyDecision(False, "authorization snapshot changed while reading")
        scope = grant.scope
        now = datetime.now(timezone.utc)
        if not (grant.valid_from <= now <= grant.valid_until):
            return PolicyDecision(False, "authorization is not currently valid")
        if request.requested_risk > scope.max_risk:
            return PolicyDecision(False, "requested risk exceeds authorized maximum")
        if not scope.allows_asset(request.asset):
            return PolicyDecision(False, "asset is outside the authorized scope")
        if not scope.allows_capability(request.capability_id):
            return PolicyDecision(False, "capability is outside the authorized scope")
        if (
            request.authorization is not original_grant
            or original_grant.scope is not original_scope
            or not _canonical_grant(original_grant)
            or not _canonical_scope(original_scope)
        ):
            return PolicyDecision(False, "authorization identity changed during decision")
        if _grant_snapshot(original_grant) != grant:
            return PolicyDecision(False, "authorization fields changed during decision")
        # An authorization valid at the first check may have expired while
        # scope membership was being evaluated. The latest check is still
        # not a substitute for revocation-at-use in the future adapter.
        final_instant = datetime.now(timezone.utc)
        if not (grant.valid_from <= final_instant <= grant.valid_until):
            return PolicyDecision(False, "authorization expired during decision")

        return _positive_if_request_unchanged(original_request, request, "authorized active assessment")


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
            or type(bound.tzinfo) is not timezone
            or bound.utcoffset() is None
        ):
            return False
    return grant.valid_from <= grant.valid_until


def _grant_snapshot(grant: AuthorizationGrant) -> AuthorizationGrant:
    scope = grant.scope
    return AuthorizationGrant(
        grant_id=grant.grant_id,
        client_id=grant.client_id,
        engagement_id=grant.engagement_id,
        approved_by=grant.approved_by,
        reference=grant.reference,
        scope=ScopeDefinition(
            assets=scope.assets,
            max_risk=scope.max_risk,
            allowed_capabilities=scope.allowed_capabilities,
            excluded_assets=scope.excluded_assets,
        ),
        valid_from=grant.valid_from,
        valid_until=grant.valid_until,
        recurring_retest_allowed=grant.recurring_retest_allowed,
    )


def _positive_if_request_unchanged(
    original: ExecutionRequest, snapshot: ExecutionRequest, reason: str
) -> PolicyDecision:
    if not _canonical_request(original):
        return PolicyDecision(False, "execution request changed during decision")
    if not (
        original.interaction is snapshot.interaction
        and original.asset == snapshot.asset
        and original.capability_id == snapshot.capability_id
        and original.requested_risk is snapshot.requested_risk
        and original.authorization is snapshot.authorization
        and original.is_lab is snapshot.is_lab
    ):
        return PolicyDecision(False, "execution request changed during decision")
    return PolicyDecision(True, reason)
