"""Opt-in read-only comparison of stored UTC window against an original snapshot.

This is a purely syntactic, non-authorizing audit for issue #647. The trusted
approval source is deliberately NOT implemented here. A match is not customer
consent, an issuance permit, or evidence of real-world ownership.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import NamedTuple

from .grant_issuance_window_snapshot_647 import CanonicalIssueWindow


class WindowStorageConsistencyReview(NamedTuple):
    decision: str
    reason: str

    @property
    def authorization_verified(self) -> bool:
        return False

    @property
    def grant_issued(self) -> bool:
        return False

    @property
    def execution_enabled(self) -> bool:
        return False

    @property
    def release_approved(self) -> bool:
        return False

    def as_receipt(self) -> dict[str, str | bool]:
        return {
            "decision": self.decision,
            "reason": self.reason,
            "authorization_verified": False,
            "grant_issued": False,
            "execution_enabled": False,
            "release_approved": False,
        }


def _hold(reason: str) -> WindowStorageConsistencyReview:
    return WindowStorageConsistencyReview("HOLD", reason)


def _exact_utc(value: object) -> bool:
    return (
        type(value) is datetime
        and value.tzinfo is timezone.utc
    )


def _canonical_utc_storage(value: object) -> datetime | None:
    """Parse only exact built-in UTC isoformat, without lenient coercion."""
    if type(value) is not str or len(value) < 25 or len(value) > 32:
        return None
    if not value.isascii() or not value.endswith("+00:00"):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    if not _exact_utc(parsed):
        return None
    # Reject ISO parsing leniency, alternate separators/offsets, fractions
    # with unusual padding, and noncanonical rendering.
    if parsed.isoformat() != value:
        return None
    return parsed


def review_grant_window_storage_consistency(
    approved_window: object,
    *,
    stored_valid_from: object,
    stored_valid_until: object,
) -> WindowStorageConsistencyReview:
    """Read-only temporal equality review, never an authorization decision.

    The caller must supply a trusted, immutable reference window from outside
    this helper. This function CANNOT establish that the caller's reference
    was actually approved by a real customer or bound to an engagement.
    """
    if type(approved_window) is not CanonicalIssueWindow:
        return _hold("reference_type")
    begin = approved_window.starts_at_utc
    end = approved_window.expires_at_utc
    if not _exact_utc(begin) or not _exact_utc(end):
        return _hold("reference_time")
    if end <= begin:
        return _hold("reference_window")
    stored_begin = _canonical_utc_storage(stored_valid_from)
    if stored_begin is None:
        return _hold("stored_start")
    stored_end = _canonical_utc_storage(stored_valid_until)
    if stored_end is None:
        return _hold("stored_expiry")
    if stored_begin != begin:
        return _hold("start_mismatch")
    if stored_end != end:
        return _hold("expiry_mismatch")
    # We do NOT return an execution permit, grant validity, or trust verdict.
    return WindowStorageConsistencyReview("REVIEW_ONLY", "shape_and_values_match")
