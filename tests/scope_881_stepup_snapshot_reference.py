"""NON-AUTHORIZING, TEST-ONLY review predicate for grant step-up issue #881.

Never import this from production. A check outside the grant INSERT transaction
is vulnerable to approval changes and must never be mistaken for permission.
This predicate demonstrates strict typed, tenant+engagement bound review input.
"""
from __future__ import annotations

from lightup.domain import ApprovalStatus, RiskApprovalRecord
from lightup.engagements import RiskLevel


def check_synthetic_stepup_snapshot(
    *,
    client_id: str,
    engagement_id: str,
    requested_risk: RiskLevel,
    approvals: tuple[RiskApprovalRecord, ...],
) -> None:
    """Return None on a candidate *review* pass, never an authorization token.

    A future source owner MUST bind the true persisted state and INSERT in the
    same transaction and separately enforce assessment provenance, issuer,
    trusted operator identity, revocation, target, capability and risk-5.
    """
    if (
        type(client_id) is not str
        or not client_id
        or client_id != client_id.strip()
        or type(engagement_id) is not str
        or not engagement_id
        or engagement_id != engagement_id.strip()
    ):
        raise ValueError("noncanonical review context")
    if type(requested_risk) is not RiskLevel:
        raise PermissionError("noncanonical requested risk")
    if type(approvals) is not tuple:
        raise PermissionError("review evidence must be immutable tuple")

    for approval in approvals:
        if type(approval) is not RiskApprovalRecord:
            raise PermissionError("noncanonical persisted review record")
        if (
            type(approval.client_id) is not str
            or type(approval.engagement_id) is not str
            or type(approval.requested_risk) is not RiskLevel
            or type(approval.status) is not ApprovalStatus
        ):
            raise PermissionError("corrupt review record")

    if requested_risk > RiskLevel.ELEVATED:
        # Risk-5 requires separate LAB-only durable decision (#1173); this
        # narrow snapshot reviewer has zero authority over that domain.
        raise PermissionError("risk-5 out of reference scope")
    if requested_risk < RiskLevel.ELEVATED:
        return None

    for approval in approvals:
        if (
            approval.client_id == client_id
            and approval.engagement_id == engagement_id
            and approval.status is ApprovalStatus.APPROVED
            and approval.requested_risk >= requested_risk
        ):
            return None
    raise PermissionError("no matching approved risk elevation")
