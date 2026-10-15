"""Opt-in, OFFLINE request/grant coherence review for issue #177.

This module deliberately cannot issue permission. Both arguments are untrusted
snapshots, not persisted provenance. Callers MUST NOT use REVIEW_ONLY to
authorize traffic, a permit, grant persistence, or a release.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum

from .capabilities import CapabilityState, get_capabilities
from .domain import AssessmentRequestRecord, EngagementRecord, RequestStatus
from .engagements import AssessmentMode, AuthorizationGrant, EngagementStatus, RiskLevel, ScopeDefinition


class ReviewStatus(str, Enum):
    HOLD = "HOLD"
    REVIEW_ONLY = "REVIEW_ONLY"


@dataclass(frozen=True, slots=True)
class RequestGrantReview:
    status: ReviewStatus
    reason: str
    authorized: bool = False
    grant_allowed: bool = False
    dispatch_allowed: bool = False
    scan_allowed: bool = False
    merge_allowed: bool = False
    deploy_allowed: bool = False

    def __post_init__(self) -> None:
        # A plain caller cannot manufacture an apparently approved review
        # receipt through this constructor. This is NOT a security boundary
        # against in-process hostile Python/reflection or a signed authority.
        if type(self.status) is not ReviewStatus or type(self.reason) is not str:
            raise ValueError("invalid non-authorizing review receipt")
        expected_reason = (
            "invalid_or_unverified_input" if self.status is ReviewStatus.HOLD
            else "structurally_coherent_untrusted_snapshot"
        )
        if self.reason != expected_reason or any(
            value is not False
            for value in (
                self.authorized,
                self.grant_allowed,
                self.dispatch_allowed,
                self.scan_allowed,
                self.merge_allowed,
                self.deploy_allowed,
            )
        ):
            raise ValueError("invalid non-authorizing review receipt")


_HOLD = RequestGrantReview(ReviewStatus.HOLD, "invalid_or_unverified_input")
_REVIEW = RequestGrantReview(ReviewStatus.REVIEW_ONLY, "structurally_coherent_untrusted_snapshot")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z", re.ASCII)
# Static high-level planning capability catalog; review metadata, never grant rights.
_PLANNING_CAPS = frozenset(
    capability.capability_id
    for capability in get_capabilities()
    if capability.state is CapabilityState.PLANNING
)
_DECISION_INSTANT = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]"
    r"(?:\.[0-9]{1,6})?\+00:00\Z", re.ASCII
)


def _identifier(value: object) -> bool:
    return type(value) is str and bool(_IDENTIFIER.fullmatch(value))


def _asset(value: object) -> bool:
    """Accept exact ASCII host/IP spelling, never resolve or normalize claims."""
    if not _identifier(value) or len(value) > 253 or value != value.lower():
        return False
    if ":" in value or value[0].isdigit():
        try:
            parsed = ipaddress.ip_address(value)
            return parsed.compressed == value and not getattr(parsed, "ipv4_mapped", None)
        except ValueError:
            # Decimal-leading DNS labels are allowed; dotted invalid IP literals
            # intentionally do not get reinterpreted as hostnames.
            if ":" in value or all(p.isdigit() for p in value.split(".")):
                return False
    if value.endswith(".") or ".." in value:
        return False
    return all(_DNS_LABEL.fullmatch(label) for label in value.split("."))


def _assets(values: object) -> bool:
    return (
        type(values) is tuple
        and 0 < len(values) <= 64
        and all(_asset(v) for v in values)
        and len(set(values)) == len(values)
    )


def _utc_instant(value: object) -> bool:
    # Compare identity before invoking any untrusted tzinfo callback or arithmetic.
    # A builtin fixed offset such as +01:00 is aware but NOT the required UTC.
    return type(value) is datetime and value.tzinfo is timezone.utc


def _decision_time(value: object) -> datetime | None:
    if type(value) is not str or not _DECISION_INSTANT.fullmatch(value):
        return None
    try:
        instant = datetime.fromisoformat(value)
    except ValueError:
        return None
    return instant if _utc_instant(instant) else None


def _capabilities(values: object) -> bool:
    return (
        type(values) is tuple
        and 0 < len(values) <= len(_PLANNING_CAPS)
        and all(type(item) is str and item in _PLANNING_CAPS for item in values)
        and len(set(values)) == len(values)
    )


def review_request_grant(
    request: object, grant: object, *, reviewed_at: object
) -> RequestGrantReview:
    """Conservative structural review only. Every outcome is NON-authorizing.

    No I/O, DNS, grant issuance, scanning, clock access, or persistence.
    Values are exact native types: bool/int/str subclasses do not coerce.
    The product currently has no durable approved-request ID on a grant;
    even an exact synthetic match is REVIEW_ONLY, never permission.
    """
    if type(request) is not AssessmentRequestRecord or type(grant) is not AuthorizationGrant:
        return _HOLD
    if not _utc_instant(reviewed_at):
        return _HOLD

    if (
        not _identifier(request.request_id)
        or not _identifier(request.client_id)
        or not _identifier(request.requested_by)
        or not _identifier(request.decided_by)
        or request.status is not RequestStatus.APPROVED
        or request.requested_mode is not AssessmentMode.AUTHORIZED_ASSESSMENT
        or type(request.requested_risk) is not RiskLevel
        or request.requested_risk is RiskLevel.DESTRUCTIVE_LAB_ONLY
        or not _assets(request.requested_assets)
    ):
        return _HOLD

    created_at = _decision_time(request.created_at)
    decided_at = _decision_time(request.decided_at)
    if created_at is None or decided_at is None or not (created_at <= decided_at <= reviewed_at):
        return _HOLD

    if (
        not _identifier(grant.grant_id)
        or not _identifier(grant.client_id)
        or not _identifier(grant.engagement_id)
        or not _identifier(grant.reference)
        or not _identifier(grant.approved_by)
        or grant.client_id != request.client_id
        or grant.approved_by != request.decided_by
        or type(grant.scope) is not ScopeDefinition
        or type(grant.scope.max_risk) is not RiskLevel
        or grant.scope.max_risk > request.requested_risk
        or grant.scope.max_risk is RiskLevel.DESTRUCTIVE_LAB_ONLY
        or not _assets(grant.scope.assets)
        or not set(grant.scope.assets).issubset(request.requested_assets)
        or type(grant.scope.excluded_assets) is not tuple
        or not all(_asset(v) for v in grant.scope.excluded_assets)
        or len(set(grant.scope.excluded_assets)) != len(grant.scope.excluded_assets)
        or not set(grant.scope.excluded_assets).issubset(grant.scope.assets)
        or not _capabilities(grant.scope.allowed_capabilities)
        or type(grant.recurring_retest_allowed) is not bool
        or not _utc_instant(grant.valid_from)
        or not _utc_instant(grant.valid_until)
    ):
        return _HOLD

    if not (decided_at <= grant.valid_from <= reviewed_at <= grant.valid_until):
        return _HOLD
    return _REVIEW


def review_request_grant_batch(
    pairs: object, *, reviewed_at: object
) -> RequestGrantReview:
    """Atomic, bounded, non-authorizing review of one tenant's fake proposals.

    A valid batch is REVIEW_ONLY, not a persisted consent record. Duplicate
    requests, duplicated grant identities, multi-tenant packets and repeated
    granted assets produce one generic HOLD for the *entire* batch. No partial
    approvals, per-record receipt, I/O, current clock lookup or active tools.
    """
    if type(pairs) is not tuple or not (1 <= len(pairs) <= 32):
        return _HOLD
    if not _utc_instant(reviewed_at):
        return _HOLD
    request_ids: set[str] = set()
    grant_ids: set[str] = set()
    seen_assets: set[str] = set()
    tenant: str | None = None
    for pair in pairs:
        if type(pair) is not tuple or len(pair) != 2:
            return _HOLD
        request, grant = pair
        if review_request_grant(request, grant, reviewed_at=reviewed_at) is not _REVIEW:
            return _HOLD
        if (
            request.request_id in request_ids
            or grant.grant_id in grant_ids
            or (tenant is not None and request.client_id != tenant)
        ):
            return _HOLD
        effective = set(grant.scope.assets) - set(grant.scope.excluded_assets)
        if seen_assets.intersection(effective):
            return _HOLD
        request_ids.add(request.request_id)
        grant_ids.add(grant.grant_id)
        seen_assets.update(effective)
        tenant = request.client_id
    return _REVIEW


def review_request_grant_engagement(
    request: object,
    grant: object,
    engagement: object,
    *,
    reviewed_at: object,
) -> RequestGrantReview:
    """Non-authorizing cross-check of a *claimed* engagement snapshot.

    REVIEW_ONLY must never imply an authenticated request→engagement link:
    that foreign key does not exist in current production persistence.
    """
    if type(engagement) is not EngagementRecord or not _utc_instant(reviewed_at):
        return _HOLD
    if (
        not _identifier(engagement.engagement_id)
        or not _identifier(engagement.client_id)
        or engagement.status is not EngagementStatus.AUTHORIZED
        or type(grant) is not AuthorizationGrant
        or type(request) is not AssessmentRequestRecord
        or engagement.engagement_id != grant.engagement_id
        or engagement.client_id != grant.client_id
        or engagement.client_id != request.client_id
    ):
        return _HOLD
    created_at = _decision_time(engagement.created_at)
    if created_at is None or not _utc_instant(grant.valid_from):
        return _HOLD
    if not (created_at <= grant.valid_from <= reviewed_at):
        return _HOLD
    return review_request_grant(request, grant, reviewed_at=reviewed_at)


def review_request_grant_engagement_batch(
    entries: object, *, reviewed_at: object
) -> RequestGrantReview:
    """Atomic same-tenant review of 1..32 untrusted request/grant/engagements.

    Each row first has to satisfy the independent three-way relationship
    review; then the exact same request/grant pairs must satisfy the existing
    atomic duplicate-ID, tenant, risk, and effective-asset overlap gate.
    Neither step authenticates stored provenance or permits an action.
    """
    if type(entries) is not tuple or not (1 <= len(entries) <= 32):
        return _HOLD
    if not _utc_instant(reviewed_at):
        return _HOLD
    pairs = []
    for entry in entries:
        if type(entry) is not tuple or len(entry) != 3:
            return _HOLD
        request, grant, engagement = entry
        if review_request_grant_engagement(
            request, grant, engagement, reviewed_at=reviewed_at
        ) is not _REVIEW:
            return _HOLD
        pairs.append((request, grant))
    return review_request_grant_batch(tuple(pairs), reviewed_at=reviewed_at)
