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


@dataclass(frozen=True)
class CrossGrantCandidate:
    """Caller-supplied fictional assertions; never an execution instruction."""
    legacy: Authorization
    durable: AuthorizationGrant
    asset: str
    capability_id: str
    client_id: str
    engagement_id: str
    requested_risk: RiskLevel


@dataclass(frozen=True)
class CrossGrantBatchReview:
    status: Literal["HOLD", "REVIEW_ONLY"]
    reason: str
    reviewed: int = 0
    authorized: bool = False
    consent_verified: bool = False
    dispatch_allowed: bool = False
    release_allowed: bool = False


def review_cross_grant_batch(
    candidates: tuple[CrossGrantCandidate, ...],
    *,
    evaluated_at: datetime,
) -> CrossGrantBatchReview:
    """Atomic, bounded HOLD-only gate on a supplied fictional cohort.

    No partial results are published; a single malformed/replayed/mixed-tenant
    claim invalidates the entire review. Both HOLD and REVIEW_ONLY are
    categorically non-authorizing.
    """
    if type(candidates) is not tuple or not (1 <= len(candidates) <= 32):
        return CrossGrantBatchReview("HOLD", "noncanonical batch length")
    if not _utc(evaluated_at):
        return CrossGrantBatchReview("HOLD", "noncanonical batch instant")
    if not all(type(candidate) is CrossGrantCandidate for candidate in candidates):
        return CrossGrantBatchReview("HOLD", "noncanonical batch claim")
    first = candidates[0]
    # Dataclass field annotations do not validate runtime identity. Check
    # exact built-in strings BEFORE any == / !=, so attacker-supplied objects
    # cannot run their custom equality code in a purported pure review.
    if not _identifier(first.client_id) or not _identifier(first.engagement_id):
        return CrossGrantBatchReview("HOLD", "noncanonical tenant cohort")
    seen: set[tuple[str, str, str]] = set()
    grant_snapshots: dict[str, tuple[object, ...]] = {}
    legacy_snapshots: dict[str, tuple[object, ...]] = {}
    for item in candidates:
        if not _identifier(item.client_id) or not _identifier(item.engagement_id):
            return CrossGrantBatchReview("HOLD", "noncanonical tenant cohort")
        if item.client_id != first.client_id or item.engagement_id != first.engagement_id:
            return CrossGrantBatchReview("HOLD", "mixed tenant or engagement")
        if type(item.durable) is not AuthorizationGrant or not _identifier(item.durable.grant_id):
            return CrossGrantBatchReview("HOLD", "invalid durable grant identity")
        if not _asset(item.asset) or not _identifier(item.capability_id):
            return CrossGrantBatchReview("HOLD", "noncanonical claim identity")
        key = (item.durable.grant_id, item.asset, item.capability_id)
        # Keep the same exact identity on every replay; do not allow duplicates
        # to inflate a report's apparent proof count.
        if key in seen:
            return CrossGrantBatchReview("HOLD", "duplicate grant-asset-capability claim")
        seen.add(key)
        result = review_cross_grant_lineage(
            item.legacy, item.durable, asset=item.asset,
            capability_id=item.capability_id,
            client_id=item.client_id,
            engagement_id=item.engagement_id,
            requested_risk=item.requested_risk,
            evaluated_at=evaluated_at,
        )
        if result.status != "REVIEW_ONLY":
            return CrossGrantBatchReview("HOLD", "at least one claim failed review")
        # A durable grant ID must denote one exact, immutable grant snapshot
        # throughout the batch. Multiple distinct assets under the *same*
        # explicit grant are fine; changing its scope, time, approval or risk
        # mid-batch is NOT lineage proof. Only compare validated primitives,
        # never arbitrary objects with attacker-supplied equality methods.
        grant = item.durable
        scope = grant.scope
        snapshot = (
            grant.client_id, grant.engagement_id, grant.approved_by,
            grant.reference, grant.valid_from, grant.valid_until,
            grant.recurring_retest_allowed, scope.assets,
            scope.excluded_assets, scope.allowed_capabilities, scope.max_risk,
        )
        previous = grant_snapshots.setdefault(grant.grant_id, snapshot)
        if previous != snapshot:
            return CrossGrantBatchReview("HOLD", "conflicting durable grant snapshot")
        # The legacy side must also remain stable for the same claimed grant.
        # Otherwise two individually coherent records can silently switch
        # which Authorization timestamp interval backs the shared grant ID.
        # This is only synthetic shape consistency, never trusted provenance.
        legacy_snapshot = (
            item.legacy.owner, item.legacy.reference,
            item.legacy.valid_from, item.legacy.valid_until,
        )
        prior_legacy = legacy_snapshots.setdefault(grant.grant_id, legacy_snapshot)
        if prior_legacy != legacy_snapshot:
            return CrossGrantBatchReview("HOLD", "conflicting legacy authorization snapshot")
    return CrossGrantBatchReview(
        "REVIEW_ONLY", "coherent synthetic batch without trusted authority", len(candidates)
    )
