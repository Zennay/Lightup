"""Opt-in, non-authorizing integrity review for legacy Authorization time windows.

This module deliberately does NOT issue consent, allow a target, dispatch a tool,
or replace the persisted issuer/grant and revocation checks. It only refuses
ambiguous legacy timestamps before owners consider runtime integration.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Final
from unicodedata import category, normalize

from .models import Authorization

_MAX_PROVENANCE_CHARS: Final[int] = 256


@dataclass(frozen=True, slots=True)
class LegacyWindowReview:
    integrity_ok: bool
    reason: str

    def __bool__(self) -> bool:
        # Review artifacts must never become an implicit permission bit.
        raise TypeError("legacy window review is not an authorization decision")


def _identity_valid(value: object) -> bool:
    return (
        type(value) is str
        and 0 < len(value) <= _MAX_PROVENANCE_CHARS
        and value == value.strip()
        and normalize("NFKC", value) == value
        and not any(
            category(c).startswith("C")
            or (category(c).startswith("Z") and c != " ")
            for c in value
        )
    )


def _canonical_time(value: object) -> datetime | None:
    """Conservatively admit built-in fixed-offset aware datetimes only.

    A noncanonical or custom tzinfo is inconclusive; a source owner can later
    explicitly define and test a broader admitted timestamp contract.
    """
    if type(value) is not datetime or type(value.tzinfo) is not timezone:
        return None
    try:
        return value.astimezone(timezone.utc)
    except (ValueError, OverflowError, TypeError):
        return None


def review_legacy_window(
    auth: object, *, now: datetime | None = None
) -> LegacyWindowReview:
    """Inspect temporal integrity, NOT proof of ownership or live authority.

    Start is inclusive; expiry is exclusive, a deliberate narrowing of legacy
    `Authorization.is_current`'s inclusive expiry semantics. A bounded expiry
    is mandatory for this stricter, opt-in review. No network or persistence.
    """
    if type(auth) is not Authorization:
        return LegacyWindowReview(False, "noncanonical_authorization")
    if not _identity_valid(auth.owner) or not _identity_valid(auth.reference):
        return LegacyWindowReview(False, "invalid_provenance_shape")

    if auth.valid_until is None:
        return LegacyWindowReview(False, "missing_expiry")
    end = _canonical_time(auth.valid_until)
    if end is None:
        return LegacyWindowReview(False, "invalid_expiry")
    if auth.valid_from is not None:
        start = _canonical_time(auth.valid_from)
        if start is None:
            return LegacyWindowReview(False, "invalid_start")
        if start >= end:
            return LegacyWindowReview(False, "inverted_or_empty_window")
    else:
        start = None

    # No hidden wall-clock fallback. A caller must explicitly sample the clock
    # for every review; the sample is diagnostic, NOT trusted dispatch time.
    if now is None:
        return LegacyWindowReview(False, "missing_explicit_clock")
    clock = _canonical_time(now)
    if clock is None:
        return LegacyWindowReview(False, "invalid_clock")
    if start is not None and clock < start:
        return LegacyWindowReview(False, "not_yet_valid")
    if clock >= end:
        return LegacyWindowReview(False, "expired")
    return LegacyWindowReview(True, "window_integrity_ok_not_authorized")
