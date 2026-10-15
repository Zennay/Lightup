"""Uninstalled, in-memory risk-shape review for untrusted synthetic scope claims.

A REVIEW_ONLY receipt is never consent, a grant, an execution permit or
evidence that a target is in scope. No persistence, networking or dispatch.
Issue #773: direct ScopeDefinition.max_risk must have canonical enum identity.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from lightup.engagements import RiskLevel, ScopeDefinition


class ReviewStatus(str, Enum):
    HOLD = "HOLD"
    REVIEW_ONLY = "REVIEW_ONLY"


@dataclass(frozen=True)
class RiskReviewReceipt:
    status: ReviewStatus
    reason_code: str
    authorized: bool = False
    may_scan: bool = False
    may_dispatch: bool = False
    may_issue_grant: bool = False
    release_ready: bool = False
    may_deploy: bool = False


def inspect_direct_scope_risk(
    scope: object, requested_risk: object
) -> RiskReviewReceipt:
    """Classify *only* the exact type and ceiling of a synthetic risk claim.

    This has deliberately no access to grant provenance, tenant, consent, assets,
    destinations, timestamps, revocation or executors. Even a structurally valid
    claim can only be REVIEW_ONLY. Any invalid claim is HOLD. The caller must
    never use this result as an authorization decision.
    """
    if type(scope) is not ScopeDefinition:
        return RiskReviewReceipt(ReviewStatus.HOLD, "noncanonical_scope")

    max_risk = scope.max_risk
    if type(max_risk) is not RiskLevel or type(requested_risk) is not RiskLevel:
        return RiskReviewReceipt(ReviewStatus.HOLD, "noncanonical_risk")

    # The destructive tier is laboratory-only and is not a direct-target permit.
    if (
        max_risk is RiskLevel.DESTRUCTIVE_LAB_ONLY
        or requested_risk is RiskLevel.DESTRUCTIVE_LAB_ONLY
    ):
        return RiskReviewReceipt(ReviewStatus.HOLD, "lab_only_risk")

    if requested_risk.value > max_risk.value:
        return RiskReviewReceipt(ReviewStatus.HOLD, "above_ceiling")

    return RiskReviewReceipt(ReviewStatus.REVIEW_ONLY, "risk_shape_only")
