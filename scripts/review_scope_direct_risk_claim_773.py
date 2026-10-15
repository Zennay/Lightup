"""Uninstalled, in-memory risk-shape review for untrusted synthetic scope claims.

A REVIEW_ONLY receipt is never consent, a grant, an execution permit or
evidence that a target is in scope. No persistence, networking or dispatch.
Issue #773: direct ScopeDefinition.max_risk must have canonical enum identity.
"""
from __future__ import annotations

from enum import Enum
from typing import NamedTuple

from lightup.engagements import RiskLevel, ScopeDefinition


class ReviewStatus(str, Enum):
    HOLD = "HOLD"
    REVIEW_ONLY = "REVIEW_ONLY"


class RiskReviewReceipt(NamedTuple):
    """Immutable risk-only classification with non-overridable false flags.

    No constructor accepts an authorization or release flag. Consumers must not
    treat a serialized or manually constructed receipt as a source of authority.
    """

    status: ReviewStatus
    reason_code: str

    @property
    def authorized(self) -> bool:
        return False

    @property
    def may_scan(self) -> bool:
        return False

    @property
    def may_dispatch(self) -> bool:
        return False

    @property
    def may_issue_grant(self) -> bool:
        return False

    @property
    def release_ready(self) -> bool:
        return False

    @property
    def may_deploy(self) -> bool:
        return False

    def to_dict(self) -> dict[str, str | bool]:
        """Serialize only canonical, bounded reviewer-owned receipts.

        NamedTuple constructors are public: callers can fabricate arbitrary
        status/reason payloads. Such untrusted objects must never be reflected
        or serialized as APPROVED/REVIEW_ONLY with a forged reason. Unknown,
        polymorphic and inconsistent shapes collapse to a generic HOLD.
        """
        status = "HOLD"
        reason_code = "invalid_receipt"
        if type(self) is RiskReviewReceipt:
            raw_status, raw_reason = self
            valid_hold = (
                "noncanonical_scope", "noncanonical_risk",
                "lab_only_risk", "above_ceiling", "batch_hold",
            )
            valid_review = ("risk_shape_only", "batch_risk_shape_only")
            if type(raw_status) is ReviewStatus and type(raw_reason) is str:
                if raw_status is ReviewStatus.HOLD and raw_reason in valid_hold:
                    status, reason_code = raw_status.value, raw_reason
                elif raw_status is ReviewStatus.REVIEW_ONLY and raw_reason in valid_review:
                    status, reason_code = raw_status.value, raw_reason
        return {
            "status": status,
            "reason_code": reason_code,
            "authorized": False,
            "may_scan": False,
            "may_dispatch": False,
            "may_issue_grant": False,
            "release_ready": False,
            "may_deploy": False,
        }

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


MAX_SYNTHETIC_REVIEW_ITEMS = 32


def inspect_direct_scope_risk_batch(claims: object) -> RiskReviewReceipt:
    """All-or-nothing, bounded synthetic-only risk-shape inspection.

    Claims must be an *exact* tuple of 1..32 exact 2-tuples
    (ScopeDefinition, RiskLevel). A single malformed, over-ceiling or
    lab-only claim makes the entire review HOLD; nothing is disclosed about
    which entry failed. The result never permits execution.
    """
    if type(claims) is not tuple:
        return RiskReviewReceipt(ReviewStatus.HOLD, "batch_hold")
    if not 1 <= len(claims) <= MAX_SYNTHETIC_REVIEW_ITEMS:
        return RiskReviewReceipt(ReviewStatus.HOLD, "batch_hold")
    # A frozen dataclass can still be changed through object.__setattr__
    # or its instance __dict__. Retain exact enum identities before visiting
    # subsequent entries, then re-check every observed ceiling. This rejects
    # in-call drift in earlier entries, without claiming an atomic lock or
    # authorization over caller-owned objects after the review returns.
    snapshots = []
    for claim in claims:
        if type(claim) is not tuple or len(claim) != 2:
            return RiskReviewReceipt(ReviewStatus.HOLD, "batch_hold")
        scope, requested_risk = claim
        if type(scope) is not ScopeDefinition or type(requested_risk) is not RiskLevel:
            return RiskReviewReceipt(ReviewStatus.HOLD, "batch_hold")
        try:
            ceiling = scope.max_risk
        except (AttributeError, TypeError):
            return RiskReviewReceipt(ReviewStatus.HOLD, "batch_hold")
        if type(ceiling) is not RiskLevel:
            return RiskReviewReceipt(ReviewStatus.HOLD, "batch_hold")
        if inspect_direct_scope_risk(scope, requested_risk).status is not ReviewStatus.REVIEW_ONLY:
            return RiskReviewReceipt(ReviewStatus.HOLD, "batch_hold")
        snapshots.append((scope, ceiling))
    for scope, ceiling in snapshots:
        try:
            current_ceiling = scope.max_risk
        except (AttributeError, TypeError):
            return RiskReviewReceipt(ReviewStatus.HOLD, "batch_hold")
        if current_ceiling is not ceiling:
            return RiskReviewReceipt(ReviewStatus.HOLD, "batch_hold")
    return RiskReviewReceipt(ReviewStatus.REVIEW_ONLY, "batch_risk_shape_only")
