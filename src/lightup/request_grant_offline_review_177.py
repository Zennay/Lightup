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

from .domain import AssessmentRequestRecord, RequestStatus
from .engagements import AssessmentMode, AuthorizationGrant, RiskLevel, ScopeDefinition


class ReviewStatus(str, Enum):
    HOLD = "HOLD"
    REVIEW_ONLY = "REVIEW_ONLY"


@dataclass(frozen=True)
class RequestGrantReview:
    status: ReviewStatus
    reason: str
    authorized: bool = False
    grant_allowed: bool = False
    dispatch_allowed: bool = False
    scan_allowed: bool = False
    merge_allowed: bool = False
    deploy_allowed: bool = False


_HOLD = RequestGrantReview(ReviewStatus.HOLD, "invalid_or_unverified_input")
_REVIEW = RequestGrantReview(ReviewStatus.REVIEW_ONLY, "structurally_coherent_untrusted_snapshot")
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z", re.ASCII)
_DECISION_INSTANT = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]"
    r"(?:\.[0-9]{1,6})?\+00:00\Z", re.ASCII
)


def _identifier(value: object) -> bool:
    return type(value) is str and bool(value) and value == value.strip() and value.isascii()


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
    if type(value) is not datetime:
        return False
    try:
        return value.utcoffset() is not None and value.astimezone(timezone.utc).tzinfo is timezone.utc
    except (TypeError, ValueError, OverflowError):
        return False


def _decision_time(value: object) -> datetime | None:
    if type(value) is not str or not _DECISION_INSTANT.fullmatch(value):
        return None
    try:
        instant = datetime.fromisoformat(value)
    except ValueError:
        return None
    return instant if _utc_instant(instant) else None


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

    decided_at = _decision_time(request.decided_at)
    if decided_at is None or decided_at > reviewed_at:
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
        or type(grant.scope.allowed_capabilities) is not tuple
        or not all(_identifier(v) for v in grant.scope.allowed_capabilities)
        or len(set(grant.scope.allowed_capabilities)) != len(grant.scope.allowed_capabilities)
        or type(grant.recurring_retest_allowed) is not bool
        or not _utc_instant(grant.valid_from)
        or not _utc_instant(grant.valid_until)
    ):
        return _HOLD

    if not (decided_at <= grant.valid_from <= reviewed_at <= grant.valid_until):
        return _HOLD
    return _REVIEW
