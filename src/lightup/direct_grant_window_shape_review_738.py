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

    # These are computed constant properties, NOT caller-selectable fields.
    @property
    def authorization_verified(self) -> bool:
        return False

    @property
    def permit_issued(self) -> bool:
        return False

    @property
    def execution_enabled(self) -> bool:
        return False

    @property
    def merge_approved(self) -> bool:
        return False

    @property
    def release_approved(self) -> bool:
        return False

    def as_receipt(self) -> dict[str, str | bool]:
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
    # Builtin fixed-offset timezone objects are deterministic and nonvirtual.
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

    This checks the *caller-supplied* programmatic temporal shape only.
    No trusted ledger, tenant proof, signatures, revocation, asset or
    capability policy, time attestation, or target I/O exists here.

    The caller must supply an explicit evaluation time. No wall clock is read.
    Source-owner repair of AuthorizationGrant remains mandatory independently.
    """
    if type(grant) is not AuthorizationGrant:
        return _hold("grant_type")
    if not _canonical_aware(observed_at):
        return _hold("evaluation_time")
    if not _canonical_aware(grant.valid_from):
        return _hold("valid_from")
    if not _canonical_aware(grant.valid_until):
        return _hold("valid_until")
    if grant.valid_until <= grant.valid_from:
        return _hold("invalid_window")
    if not grant.valid_from <= observed_at <= grant.valid_until:
        return _hold("outside_window")
    return WindowShapeReview("REVIEW_ONLY", "temporal_shape_only")
