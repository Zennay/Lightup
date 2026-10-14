"""Opt-in, non-authorizing shape review for direct grant validity windows (#738).

This deliberately does not participate in ToolExecutor, registry, web, active
dispatch, persistence, real client consent or authorization.  REVIEW_ONLY means
a caller-supplied window has canonical datetime shape *only*.  Never treat the
receipt as a permit, trusted time attestation or proof that a grant is genuine.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import NamedTuple

from .engagements import AuthorizationGrant


class WindowShapeReview(NamedTuple):
    decision: str
    reason: str
    authorization_verified: bool = False
    permit_issued: bool = False
    execution_enabled: bool = False
    merge_approved: bool = False
    release_approved: bool = False

    def as_receipt(self) -> dict[str, str | bool]:
        # Explicitly construct and pin every authority-bearing flag false.
        return {
            "decision": self.decision,
            "reason": self.reason,
            "authorization_verified": False,
            "permit_issued": False,
            "execution_enabled": False,
            "merge_approved": False,
            "release_approved": False,
        }


def _hold(reason: str) -> WindowShapeReview:
    return WindowShapeReview("HOLD", reason)


def _canonical_aware(value: object) -> bool:
    # Reject datetime subclasses, spoofed comparators and custom tzinfo code.
    # Builtin fixed-offset timezone objects are well-defined and deterministic.
    return (
        type(value) is datetime
        and type(value.tzinfo) is timezone
        and value.utcoffset() is not None
    )


def review_direct_grant_window_shape(
    grant: object,
    *,
    observed_at: object,
) -> WindowShapeReview:
    """Return only HOLD / REVIEW_ONLY (never active authorization).

    This diagnostic checks the *caller-supplied* programmatic temporal shape;
    it has NO trusted grant ledger, tenant proof, signatures, revocation
    check, asset or capability policy, clock attestation, or target I/O.

    The caller must always supply an explicit evaluation time.  No implicit
    current clock is ever read.  Source-owner repair of AuthorizationGrant
    remains mandatory independently of this opt-in check.
    """
    if type(grant) is not AuthorizationGrant:
        return _hold("grant_type")
    if not _canonical_aware(observed_at):
        return _hold("evaluation_time")
    if not _canonical_aware(grant.valid_from):
        return _hold("valid_from")
    if not _canonical_aware(grant.valid_until):
        return _hold("valid_until")
    # These are now all exact builtin datetimes and exact builtin timezones.
    # Comparisons cannot invoke subclass overrides.
    if grant.valid_until <= grant.valid_from:
        return _hold("invalid_window")
    if not grant.valid_from <= observed_at <= grant.valid_until:
        return _hold("outside_window")
    return WindowShapeReview("REVIEW_ONLY", "temporal_shape_only")
