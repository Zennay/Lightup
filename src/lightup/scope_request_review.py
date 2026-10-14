"""Offline-only human review preview for a requested active assessment.

This is a *non-authorizing* diagnostic over self-declared in-memory models.
It is not wired into dispatch, HTTP handlers, policy, or grant issuance.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
import re

from .engagements import (
    AssessmentMode,
    AssessmentRequest,
    AuthorizationGrant,
    RiskLevel,
    ScopeDefinition,
)

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z", re.ASCII)
_CAP = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z", re.ASCII)


@dataclass(frozen=True)
class ActiveRequestReview:
    status: str
    reason: str
    requested_asset_count: int
    authorization_verified: bool = False
    permit_issued: bool = False
    execution_enabled: bool = False
    merge_approved: bool = False
    release_approved: bool = False


def _hold(reason: str) -> ActiveRequestReview:
    return ActiveRequestReview("HOLD", reason, 0)


def _id(value: object) -> bool:
    return type(value) is str and _ID.fullmatch(value) is not None


def _asset(value: object) -> bool:
    if type(value) is not str or not value or len(value) > 253:
        return False
    if value != value.lower() or value != value.strip() or "*" in value:
        return False
    try:
        return str(ip_address(value)) == value
    except ValueError:
        labels = value.split(".")
        return len(labels) >= 2 and all(_LABEL.fullmatch(label) for label in labels)


def _assets(values: object, *, limit: int) -> bool:
    return (
        type(values) is tuple
        and 0 < len(values) <= limit
        and all(_asset(value) for value in values)
        and len(set(values)) == len(values)
    )


def _capabilities(values: object) -> bool:
    return (
        type(values) is tuple
        and 0 < len(values) <= 64
        and all(type(value) is str and _CAP.fullmatch(value) for value in values)
        and len(set(values)) == len(values)
    )


def _utc(value: object) -> bool:
    if type(value) is not datetime or value.tzinfo is None:
        return False
    try:
        return value.utcoffset() == timedelta(0)
    except (TypeError, ValueError, OverflowError):
        return False


def preview_active_request(
    request: AssessmentRequest,
    grant: AuthorizationGrant | None,
    *,
    now: datetime | None = None,
) -> ActiveRequestReview:
    """Review syntax and consistency; NEVER validate real consent or issue a permit.

    `REVIEW_ONLY` is only a prompt for independent operator verification.
    All authority/release fields remain false, including for REVIEW_ONLY.
    Identifiers and exception messages never appear in the returned receipt.
    """
    if type(request) is not AssessmentRequest:
        return _hold("INVALID_REQUEST")
    if request.requested_mode is not AssessmentMode.AUTHORIZED_ASSESSMENT:
        return _hold("INVALID_MODE")
    if type(request.requested_risk) is not RiskLevel:
        return _hold("INVALID_RISK")
    if not (RiskLevel.LOW_IMPACT <= request.requested_risk <= RiskLevel.ELEVATED):
        return _hold("RISK_NOT_ELIGIBLE")
    if not all(_id(value) for value in (
        request.request_id, request.client_id, request.requested_by
    )):
        return _hold("INVALID_REQUEST_IDENTITY")
    if not _assets(request.requested_assets, limit=32):
        return _hold("INVALID_REQUEST_ASSETS")
    if type(grant) is not AuthorizationGrant:
        return _hold("NO_CANONICAL_GRANT")
    if not all(_id(value) for value in (
        grant.grant_id, grant.client_id, grant.engagement_id,
        grant.approved_by, grant.reference
    )):
        return _hold("INVALID_GRANT_IDENTITY")
    if grant.client_id != request.client_id:
        return _hold("TENANT_MISMATCH")
    if grant.approved_by == request.requested_by:
        return _hold("SELF_APPROVAL")
    if type(grant.recurring_retest_allowed) is not bool:
        return _hold("INVALID_RETEST_MARKER")
    if type(grant.scope) is not ScopeDefinition:
        return _hold("INVALID_SCOPE")
    scope = grant.scope
    if type(scope.max_risk) is not RiskLevel:
        return _hold("INVALID_GRANT_RISK")
    if not (RiskLevel.LOW_IMPACT <= scope.max_risk <= RiskLevel.ELEVATED):
        return _hold("GRANT_RISK_NOT_ELIGIBLE")
    if request.requested_risk > scope.max_risk:
        return _hold("RISK_EXCEEDS_GRANT")
    if not _assets(scope.assets, limit=128):
        return _hold("INVALID_GRANT_ASSETS")
    if (
        type(scope.excluded_assets) is not tuple
        or len(scope.excluded_assets) > 128
        or not all(_asset(value) for value in scope.excluded_assets)
        or len(set(scope.excluded_assets)) != len(scope.excluded_assets)
    ):
        return _hold("INVALID_EXCLUSIONS")
    if not _capabilities(scope.allowed_capabilities):
        # The legacy empty tuple means ALL capabilities: never infer that
        # wildcard is sufficient for an active-review preview.
        return _hold("CAPABILITY_WILDCARD_OR_INVALID")
    covered = set(scope.assets) - set(scope.excluded_assets)
    if not set(request.requested_assets).issubset(covered):
        return _hold("ASSETS_OUTSIDE_GRANT")
    observed = datetime.now(timezone.utc) if now is None else now
    if not all(_utc(value) for value in (
        grant.valid_from, grant.valid_until, observed
    )):
        return _hold("INVALID_TIME")
    if not grant.valid_from < grant.valid_until:
        return _hold("INVALID_WINDOW")
    # Strict half-open interval: an exact end instant is not sufficient.
    if not grant.valid_from <= observed < grant.valid_until:
        return _hold("GRANT_NOT_CURRENT")
    return ActiveRequestReview(
        status="REVIEW_ONLY",
        reason="INDEPENDENT_HUMAN_AUTHORIZATION_REQUIRED",
        requested_asset_count=len(request.requested_assets),
    )
