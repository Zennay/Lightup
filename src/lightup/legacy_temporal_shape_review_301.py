"""Strict offline shape review for *legacy* Authorization timestamps (#301).

This is an opt-in diagnostic, not installed in ActivationGate, ScopePolicy, or
any execution path. REVIEW_ONLY never means authorized or allowed to scan.
No network, filesystem I/O, persistent storage, clock lookup, or customer interaction occurs.
"""
from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from typing import NamedTuple

from lightup.models import Authorization



_RECEIPT_KEYS = (
    "status", "reason",
    "authorization_verified", "permit_issued", "execution_enabled",
    "target_dispatch_allowed", "merge_approved", "release_approved",
)

_RECEIPT_PAIRS = (
    ("HOLD", "invalid_shape"),
    ("HOLD", "invalid_batch"),
    ("HOLD", "unbounded_window"),
    ("HOLD", "inverted_window"),
    ("HOLD", "outside_window"),
    ("REVIEW_ONLY", "temporal_shape_only"),
)


def _canonical_receipt_pair(receipt: LegacyTemporalReceipt) -> tuple[str, str]:
    """A bypassed tuple.__new__ cannot smuggle noncanonical result labels."""
    try:
        status = tuple.__getitem__(receipt, 0)
        reason = tuple.__getitem__(receipt, 1)
    except (IndexError, TypeError):
        return "HOLD", "invalid_shape"
    if (
        type(status) is not str or type(reason) is not str
        or (status, reason) not in _RECEIPT_PAIRS
    ):
        return "HOLD", "invalid_shape"
    return status, reason


class LegacyTemporalReceipt(tuple, Mapping[str, str | bool]):
    """Immutable, falsy, permission-free synthetic review receipt.

    Underlying built-in tuple storage cannot be changed with setitem,
    attribute assignment or object.__setattr__. Mapping keys are only
    static labels; all six authority/release fields always return False.
    """

    __slots__ = ()

    def __new__(cls, status: object, reason: object) -> LegacyTemporalReceipt:
        if (
            type(status) is not str or type(reason) is not str
            or (status, reason) not in _RECEIPT_PAIRS
        ):
            status, reason = "HOLD", "invalid_shape"
        return tuple.__new__(cls, (status, reason))

    def __getitem__(self, key: object) -> str | bool:
        if type(key) is not str:
            raise KeyError("noncanonical receipt key")
        if key in _RECEIPT_KEYS[2:]:
            return False
        if key == "status":
            return _canonical_receipt_pair(self)[0]
        if key == "reason":
            return _canonical_receipt_pair(self)[1]
        raise KeyError("unknown receipt key")

    def __iter__(self):
        return iter(_RECEIPT_KEYS)

    def __len__(self) -> int:
        return 8

    def __contains__(self, key: object) -> bool:
        return type(key) is str and key in _RECEIPT_KEYS

    def __bool__(self) -> bool:
        return False

    def __eq__(self, other: object) -> bool:
        # Built-in tuple comparison would evaluate arbitrary equality hooks
        # on a raw forged tuple payload; compare only canonical safe strings.
        return (
            type(other) is LegacyTemporalReceipt
            and _canonical_receipt_pair(self) == _canonical_receipt_pair(other)
        )

    def __ne__(self, other: object) -> bool:
        return not (
            type(other) is LegacyTemporalReceipt
            and _canonical_receipt_pair(self) == _canonical_receipt_pair(other)
        )

    # A raw forged tuple might contain an object with a hostile __hash__.
    # Receipts are mapping views, not set keys, so forbid hashing outright.
    __hash__ = None

    def __repr__(self) -> str:
        status, reason = _canonical_receipt_pair(self)
        return "LegacyTemporalReceipt(" + status + ", " + reason + "; no_authority)"

    def to_json(self) -> str:
        """Serialize all eight fields, never tuple-as-array or inferred grants.

        Only canonical fixed status/reason words are interpolated. No JSON
        parser, serializer callbacks, system clock, network or file I/O.
        """
        status, reason = _canonical_receipt_pair(self)
        return (
            '{"status":"' + status + '","reason":"' + reason + '",'
            '"authorization_verified":false,"permit_issued":false,'
            '"execution_enabled":false,"target_dispatch_allowed":false,'
            '"merge_approved":false,"release_approved":false}'
        )


class LegacyTemporalReview(NamedTuple):
    status: str
    reason: str

    def __bool__(self) -> bool:
        """A review verdict is NEVER a truthy grant, even REVIEW_ONLY.

        An ordinary two-slot NamedTuple is truthy by default, which could be
        mistakenly treated by a caller as authorization when checking only
        'if review(...)'. Keep every result explicitly false in that context.
        """
        return False

    def as_receipt(self) -> LegacyTemporalReceipt:
        """Return immutable, always-falsy status with six denied authority flags."""
        if type(self) is not LegacyTemporalReview:
            return LegacyTemporalReceipt("HOLD", "invalid_shape")
        return LegacyTemporalReceipt(
            tuple.__getitem__(self, 0), tuple.__getitem__(self, 1)
        )


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

    The entire bounded tuple is examined; no partial result or per-claim explanation leaves this function. A shape,
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

    # For a canonical bounded tuple, evaluate every member before deciding.
    # This avoids exposing *which position* first failed through a premature
    # return. It does not make Python execution constant-time.
    bad_member = False
    snapshots: list[tuple[Authorization, object, object]] = []
    for authorization in authorizations:
        if type(authorization) is not Authorization:
            bad_member = True
            continue
        fields = _stored_fields(authorization)
        if fields is None or (
            "valid_from" not in fields or "valid_until" not in fields
        ):
            bad_member = True
            continue
        try:
            start = fields["valid_from"]
            end = fields["valid_until"]
        except KeyError:
            # A concurrent rebind can invalidate a dictionary between checks.
            bad_member = True
            continue
        verdict = review_legacy_authorization_window(
            authorization, observed_at=observed_at
        )
        if type(verdict) is not LegacyTemporalReview:
            bad_member = True
        else:
            verdict_status = tuple.__getitem__(verdict, 0)
            verdict_reason = tuple.__getitem__(verdict, 1)
            if (
                type(verdict_status) is not str
                or type(verdict_reason) is not str
                or (verdict_status, verdict_reason)
                != ("REVIEW_ONLY", "temporal_shape_only")
            ):
                bad_member = True
        snapshots.append((authorization, start, end))

    # Always recheck every previously materialized member, even after an
    # unrelated HOLD. Never emit a count, position, identifier or partial pass.
    for authorization, start, end in snapshots:
        fields = _stored_fields(authorization)
        if (
            fields is None
            or "valid_from" not in fields
            or "valid_until" not in fields
        ):
            bad_member = True
            continue
        try:
            if fields["valid_from"] is not start or fields["valid_until"] is not end:
                bad_member = True
        except KeyError:
            bad_member = True
    if bad_member:
        return hold
    return LegacyTemporalReview("REVIEW_ONLY", "temporal_shape_only")
