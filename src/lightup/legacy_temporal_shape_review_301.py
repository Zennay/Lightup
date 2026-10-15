"""Strict offline shape review for *legacy* Authorization timestamps (#301).

This is an opt-in diagnostic, not installed in ActivationGate, ScopePolicy, or
any execution path. REVIEW_ONLY never means authorized or allowed to scan.
No network, filesystem, storage, clock lookup, or customer interaction occurs.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import NamedTuple

from lightup.models import Authorization


class LegacyTemporalReview(NamedTuple):
    status: str
    reason: str

    def as_receipt(self) -> dict[str, str | bool]:
        """Only static classifications; never disclose claims or give authority."""
        allowed = (
            ("HOLD", "invalid_shape"),
            ("HOLD", "unbounded_window"),
            ("HOLD", "inverted_window"),
            ("HOLD", "outside_window"),
            ("REVIEW_ONLY", "temporal_shape_only"),
        )
        if type(self) is not LegacyTemporalReview or (
            type(self.status) is not str or type(self.reason) is not str
        ) or (self.status, self.reason) not in allowed:
            status, reason = "HOLD", "invalid_shape"
        else:
            status, reason = self.status, self.reason
        return {
            "status": status,
            "reason": reason,
            "authorization_verified": False,
            "permit_issued": False,
            "execution_enabled": False,
            "target_dispatch_allowed": False,
            "merge_approved": False,
            "release_approved": False,
        }


def _canonical_datetime(value: object) -> bool:
    # Reject subclasses and untrusted tzinfo BEFORE calling an overloaded
    # comparison, utcoffset(), astimezone(), or any custom method.
    return type(value) is datetime and type(value.tzinfo) is timezone


def review_legacy_authorization_window(
    authorization: Authorization,
    *,
    observed_at: datetime,
) -> LegacyTemporalReview:
    """Review an in-memory fictional legacy window; never decide authorization.

    Exact builtin datetime/timezone only. The stricter fixed-offset subset
    intentionally HOLDS other timezone implementations for human review.
    Neither a canonical REVIEW_ONLY nor a HOLD is an execution grant.
    """
    hold = LegacyTemporalReview("HOLD", "invalid_shape")
    if type(authorization) is not Authorization or not _canonical_datetime(observed_at):
        return hold

    try:
        start = authorization.valid_from
        end = authorization.valid_until
    except AttributeError:
        return hold
    if (start is not None and not _canonical_datetime(start)) or (
        end is not None and not _canonical_datetime(end)
    ):
        return hold
    if start is None and end is None:
        return LegacyTemporalReview("HOLD", "unbounded_window")

    # Exact built-in datetime and timezone implementations only. No comparison
    # hooks, network resolution, or current-time lookup on untrusted objects.
    observed_utc = observed_at.astimezone(timezone.utc)
    start_utc = start.astimezone(timezone.utc) if start is not None else None
    end_utc = end.astimezone(timezone.utc) if end is not None else None

    if start_utc is not None and end_utc is not None and start_utc > end_utc:
        return LegacyTemporalReview("HOLD", "inverted_window")
    if (start_utc is not None and observed_utc < start_utc) or (
        end_utc is not None and observed_utc > end_utc
    ):
        return LegacyTemporalReview("HOLD", "outside_window")
    # A supposedly frozen dataclass can still be mutated with object.__setattr__.
    # Refuse obvious in-call field drift; this is not a cross-thread lock.
    try:
        if authorization.valid_from is not start or authorization.valid_until is not end:
            return hold
    except AttributeError:
        return hold
    return LegacyTemporalReview("REVIEW_ONLY", "temporal_shape_only")
