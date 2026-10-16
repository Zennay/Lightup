"""Unwired, non-authorizing cross-grant lineage *review* for issue #1493.

Both inputs are caller-supplied assertions. REVIEW_ONLY is not authentication,
consent, an execution permit, a revocation check, or a release decision.
This module deliberately imports no adapters, stores, clients, or handlers.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal

from .engagements import AuthorizationGrant, RiskLevel, ScopeDefinition
from .models import Authorization

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9@._:/-]{0,127}\Z", re.ASCII)
_ASSET = re.compile(r"[a-z0-9][a-z0-9.-]{0,252}\Z", re.ASCII)


@dataclass(frozen=True)
class CrossGrantLineageReview:
    status: Literal["HOLD", "REVIEW_ONLY"]
    reason: str
    authorized: bool = False
    consent_verified: bool = False
    dispatch_allowed: bool = False
    release_allowed: bool = False


def _hold(reason: str) -> CrossGrantLineageReview:
    return CrossGrantLineageReview("HOLD", reason)


def _identifier(value: object) -> bool:
    return type(value) is str and _ID.fullmatch(value) is not None


def _asset(value: object) -> bool:
    return type(value) is str and _ASSET.fullmatch(value) is not None and ".." not in value and not value.endswith(".")


def _utc(value: object) -> bool:
    return type(value) is datetime and value.tzinfo is timezone.utc and value.fold == 0


def _exact_set(value: object, *, assets: bool = False, required: bool = True) -> bool:
    if type(value) is not tuple or len(value) > 256 or (required and not value):
        return False
    checker = _asset if assets else _identifier
    return all(checker(item) for item in value) and len(set(value)) == len(value)


def review_cross_grant_lineage(
    legacy: Authorization,
    durable: AuthorizationGrant,
    *,
    asset: str,
    capability_id: str,
    client_id: str,
    engagement_id: str,
    requested_risk: RiskLevel,
    evaluated_at: datetime,
) -> CrossGrantLineageReview:
    """Review shape/coherence only; never derive trusted authority.

    Unlike either product gate, requires an explicitly bounded legacy window
    within the durable window and an explicitly listed exact capability.
    Every failure is atomic HOLD, including exceptional/corrupt field shapes.
    """
    if type(legacy) is not Authorization or type(durable) is not AuthorizationGrant:
        return _hold("grant object identity")
    if not all(_identifier(item) for item in (
        legacy.owner, legacy.reference, durable.grant_id, durable.client_id,
        durable.engagement_id, durable.approved_by, durable.reference,
        client_id, engagement_id, capability_id,
    )):
        return _hold("noncanonical identity")
    if not _asset(asset):
        return _hold("noncanonical asset")
    if type(durable.recurring_retest_allowed) is not bool:
        return _hold("noncanonical retest flag")
    if type(requested_risk) is not RiskLevel:
        return _hold("noncanonical requested risk")
    if not all(_utc(value) for value in (
        legacy.valid_from, legacy.valid_until, durable.valid_from,
        durable.valid_until, evaluated_at,
    )):
        return _hold("missing or noncanonical UTC instant")
    if not (
        durable.valid_from <= legacy.valid_from <= evaluated_at
        <= legacy.valid_until <= durable.valid_until
    ):
        return _hold("authorization window mismatch")
    if legacy.reference != durable.reference or legacy.owner != durable.approved_by:
        return _hold("source reference or actor mismatch")
    if client_id != durable.client_id or engagement_id != durable.engagement_id:
        return _hold("client or engagement mismatch")
    scope = durable.scope
    if type(scope) is not ScopeDefinition or type(scope.max_risk) is not RiskLevel:
        return _hold("noncanonical scope")
    if not (
        _exact_set(scope.assets, assets=True)
        and _exact_set(scope.excluded_assets, assets=True, required=False)
        and _exact_set(scope.allowed_capabilities)
    ):
        return _hold("ambiguous scope entries")
    if asset not in scope.assets or asset in scope.excluded_assets:
        return _hold("asset not explicitly permitted")
    if capability_id not in scope.allowed_capabilities:
        return _hold("capability not explicitly permitted")
    if requested_risk > scope.max_risk or requested_risk is RiskLevel.DESTRUCTIVE_LAB_ONLY:
        return _hold("risk not explicitly permitted")
    # Even agreement can be forged with two perfectly coherent caller-owned
    # objects. An independent authenticated source/consent/revocation check
    # remains mandatory outside this preview; no dispatch result exists.
    return CrossGrantLineageReview("REVIEW_ONLY", "synthetic records are internally coherent")
