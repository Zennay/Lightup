"""Offline, non-authorizing review of durable-grant revocation provenance.

#737 / LightUp INCUBATE M3/M7. This module is intentionally NOT imported by
installed scope/dispatch/WSGI/worker code. It must never issue a permit, call a
handler, mutate a grant, fetch a target, or decide a real authorization.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class RevocationReview:
    """Privacy-minimal, always non-authorizing result for human reviewers."""

    decision: str
    classification: str
    reason_codes: tuple[str, ...]
    can_authorize: bool = False
    can_dispatch: bool = False
    can_release: bool = False


def _canonical_text(value: object) -> bool:
    return type(value) is str and bool(value) and value == value.strip() and len(value) <= 256


def review_revocation_metadata(
    *, revoked_at: object = None, revoked_by: object = None,
    revocation_reason: object = None,
) -> RevocationReview:
    """Fail-closed structural review of the *revocation fields only*.

    A seemingly consistent row still returns HOLD: validity, engagement,
    consent, signed scope, current source-of-truth revocation and execution
    approval are independent checks performed by their OWN source owners.

    Never stringifies/unpacks unknown input objects, calls their truthiness or
    custom comparison, or returns personal provenance values.
    """
    codes: list[str] = []

    at_present = revoked_at is not None
    actor_present = revoked_by is not None
    reason_present = revocation_reason is not None

    if at_present:
        if type(revoked_at) is not datetime:
            codes.append("noncanonical_revoked_at")
        elif revoked_at.tzinfo is None:
            codes.append("naive_revoked_at")
        elif type(revoked_at.tzinfo) is not timezone:
            # Never call polymorphic tzinfo.utcoffset()/dst() in this
            # non-authorizing review; foreign zones require owner validation.
            codes.append("noncanonical_revocation_timezone")

    if actor_present and not _canonical_text(revoked_by):
        codes.append("noncanonical_revoked_by")
    if reason_present and not _canonical_text(revocation_reason):
        codes.append("noncanonical_revocation_reason")

    if not at_present and (actor_present or reason_present):
        codes.append("stale_revocation_provenance")
    elif at_present and (not actor_present or not reason_present):
        codes.append("incomplete_revocation_event")

    if codes:
        classification = "inconsistent"
    elif at_present:
        classification = "revocation_recorded"
        codes.append("independent_revocation_verification_required")
    else:
        classification = "no_revocation_claim"
        codes.append("independent_authorization_verification_required")

    return RevocationReview(
        decision="HOLD",
        classification=classification,
        reason_codes=tuple(codes),
    )
