"""Strict offline shape review for *legacy* Authorization timestamps (#301).

This is an opt-in diagnostic, not installed in ActivationGate, ScopePolicy, or
any execution path. REVIEW_ONLY never means authorized or allowed to scan.
No network, filesystem I/O, persistent storage, clock lookup, or customer interaction occurs.
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
            ("HOLD", "invalid_batch"),
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



def _stored_fields(authorization: Authorization) -> dict | None:
    """Read actual instance storage, bypassing a patched __getattribute__.

    Never treat a synthetic subclass, intercepted __dict__ getter, or a
    non-builtin mapping as trustworthy stored validity metadata.
    """
    try:
        fields = object.__getattribute__(authorization, "__dict__")
    except (AttributeError, TypeError):
        return None
    return fields if type(fields) is dict else None


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

    # Dataclass fields with class-level None defaults may appear present on
    # object.__new__ instances even when the instance never set those fields.
    # Require explicitly materialized validity fields, not inherited defaults.
    fields = _stored_fields(authorization)
    if fields is None or (
        "valid_from" not in fields or "valid_until" not in fields
    ):
        return hold
    # Read only materialized storage. Even exact Authorization instances can
    # have __getattribute__ replaced at class level with a malicious callback;
    # invoking auth.valid_from would permit arbitrary target or filesystem I/O.
    try:
        start = fields["valid_from"]
        end = fields["valid_until"]
    except KeyError:
        return hold
    if (start is not None and not _canonical_datetime(start)) or (
        end is not None and not _canonical_datetime(end)
    ):
        return hold
    if start is None and end is None:
        return LegacyTemporalReview("HOLD", "unbounded_window")

    # Exact built-in datetime and timezone implementations only. No comparison
    # hooks, network resolution, or current-time lookup on untrusted objects.
    try:
        observed_utc = observed_at.astimezone(timezone.utc)
        start_utc = start.astimezone(timezone.utc) if start is not None else None
        end_utc = end.astimezone(timezone.utc) if end is not None else None
    except (OverflowError, ValueError):
        # Even exact built-in aware datetimes can overflow the representable
        # year range when normalized from an extreme fixed offset.
        return hold

    if start_utc is not None and end_utc is not None and start_utc > end_utc:
        return LegacyTemporalReview("HOLD", "inverted_window")
    if (start_utc is not None and observed_utc < start_utc) or (
        end_utc is not None and observed_utc > end_utc
    ):
        return LegacyTemporalReview("HOLD", "outside_window")
    # A nominally frozen dataclass remains mutable through object.__setattr__.
    # Re-read actual storage without invoking class getter hooks. This detects
    # observable in-call drift but is NOT a thread-safe transactional snapshot.
    final_fields = _stored_fields(authorization)
    if (
        final_fields is None
        or "valid_from" not in final_fields
        or "valid_until" not in final_fields
        or final_fields["valid_from"] is not start
        or final_fields["valid_until"] is not end
    ):
        return hold
    return LegacyTemporalReview("REVIEW_ONLY", "temporal_shape_only")



def review_legacy_authorization_batch(
    authorizations: tuple[Authorization, ...],
    *,
    observed_at: datetime,
) -> LegacyTemporalReview:
    """Atomically summarize 1–32 fictional legacy windows without authorizing.

    No partial result or per-claim explanation leaves this function. A shape,
    window, or detectable in-call consistency problem in *any* member forces
    one generic HOLD; REVIEW_ONLY means all shapes survived this offline
    inspection, never that any member has an active client grant.

    This is best-effort single-thread consistency, not a transactional snapshot
    or protection from concurrent mutations after return.
    """
    hold = LegacyTemporalReview("HOLD", "invalid_batch")
    if (
        type(authorizations) is not tuple
        or not 1 <= len(authorizations) <= 32
        or not _canonical_datetime(observed_at)
    ):
        return hold

    snapshots: list[tuple[Authorization, object, object]] = []
    for authorization in authorizations:
        if type(authorization) is not Authorization:
            return hold
        try:
            fields = _stored_fields(authorization)
            if fields is None or (
                "valid_from" not in fields or "valid_until" not in fields
            ):
                return hold
            start = fields["valid_from"]
            end = fields["valid_until"]
        except (TypeError, KeyError):
            return hold
        verdict = review_legacy_authorization_window(
            authorization, observed_at=observed_at
        )
        if (
            type(verdict) is not LegacyTemporalReview
            or type(verdict.status) is not str
            or type(verdict.reason) is not str
            or (verdict.status, verdict.reason)
            != ("REVIEW_ONLY", "temporal_shape_only")
        ):
            return hold
        snapshots.append((authorization, start, end))

    # Reject earlier claims silently mutated while later claims were reviewed.
    # Never reveal which member failed, the number of successful claims, or IDs.
    for authorization, start, end in snapshots:
        try:
            fields = _stored_fields(authorization)
            if (
                fields is None
                or "valid_from" not in fields
                or "valid_until" not in fields
                or fields["valid_from"] is not start
                or fields["valid_until"] is not end
            ):
                return hold
        except (TypeError, AttributeError, KeyError):
            return hold
    return LegacyTemporalReview("REVIEW_ONLY", "temporal_shape_only")
