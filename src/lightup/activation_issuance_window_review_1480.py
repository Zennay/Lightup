"""Offline issuance-window *review*, NOT a live permit or grant authority.

Owner-isolated #1480 reusable narrow reference. Deliberately unwired from
ActivationGate/ToolExecutor and incapable of issuing an ExecutionPermit.
A REVIEW_ONLY verdict means only canonical finite UTC instants were coherent.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from .models import Authorization


@dataclass(frozen=True)
class IssuanceWindowReview:
    status: str
    reason: str
    may_issue_permits: bool = False
    may_dispatch_tools: bool = False
    release_authorized: bool = False


def review_issuance_window(
    *, authorization: Authorization, issued_at: datetime
) -> IssuanceWindowReview:
    """Check one immutable *provided* issuance instant against finite UTC bounds.

    This cannot authenticate owner, consent, revocation or external scope. It
    neither samples wall time nor calls any execution/persistence primitives.
    A separate source owner must integrate a real current-time admission
    boundary before any permit can be safely returned.
    """
    hold = lambda reason: IssuanceWindowReview("HOLD", reason)

    if type(authorization) is not Authorization:
        return hold("noncanonical_authorization")
    if type(issued_at) is not datetime or issued_at.tzinfo is not timezone.utc:
        return hold("noncanonical_issuance_instant")
    first = authorization.valid_from
    last = authorization.valid_until
    if (
        type(first) is not datetime
        or type(last) is not datetime
        or first.tzinfo is not timezone.utc
        or last.tzinfo is not timezone.utc
    ):
        return hold("noncanonical_finite_utc_window")
    if first > last:
        return hold("inverted_window")
    if issued_at < first:
        return hold("before_approved_window")
    if issued_at > last:
        return hold("after_approved_window")
    return IssuanceWindowReview("REVIEW_ONLY", "structural_window_coherent")
