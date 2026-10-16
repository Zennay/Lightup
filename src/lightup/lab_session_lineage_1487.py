"""Opt-in, non-authorizing shape review of fictional LAB session lineage (#1487).

This module NEVER authenticates an actor, verifies consent, reads a durable
ledger, fetches scope, grants a permit, or dispatches tools. All claims and
the evaluation instant are caller-supplied, so REVIEW_ONLY is NOT permission.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import re

from .lab_reference_review_1487 import (
    LabReferenceReview,
    review_lab_reference_batch,
)

_MAX_CLAIMS = 64
_MAX_SESSION = timedelta(hours=8)
_IDENTIFIER = re.compile(r"(?:ACTOR|SESSION|ENG|ASSET|CAP)-[A-Z0-9]+(?:-[A-Z0-9]+)*", re.ASCII)
_HOLD = LabReferenceReview("HOLD")
_REVIEW = LabReferenceReview("REVIEW_ONLY")


@dataclass(frozen=True, slots=True)
class FictionalLabLineageClaim:
    lab_reference: str
    operator_id: str
    session_id: str
    engagement_id: str
    asset_id: str
    capability_id: str
    starts_at: datetime
    expires_at: datetime
    revoked: bool


def _identity(value: object, kind: str) -> bool:
    # These synthetic identifiers are NOT the project's production ID format.
    # Type admission must precede any possible polymorphic string operations.
    return (
        type(value) is str
        and 8 <= len(value) <= 80
        and value.startswith(kind + "-")
        and _IDENTIFIER.fullmatch(value) is not None
    )


def _utc_instant(value: object) -> bool:
    # No subclass, local wall time, fold ambiguity or timezone coercion.
    return (
        type(value) is datetime
        and value.tzinfo is timezone.utc
        and value.fold == 0
    )


def review_fictional_lab_lineage(
    claims: object, assessment_time: object
) -> LabReferenceReview:
    """Atomically review exact, bounded caller-provided synthetic lineage.

    A positive receipt confirms only that the caller's *own* presented
    shape and temporal relationships are internally consistent. The caller
    also provides assessment_time, and can omit/rewrite any claim; no live
    authority, revocation guarantee, full history or proof of consent exists.
    """
    if type(claims) is not tuple or not (1 <= len(claims) <= _MAX_CLAIMS):
        return _HOLD
    if not _utc_instant(assessment_time):
        return _HOLD

    seen_refs: set[str] = set()
    seen_sessions: set[str] = set()
    cohort: tuple[str, str] | None = None
    for claim in claims:
        if type(claim) is not FictionalLabLineageClaim:
            return _HOLD
        try:
            ref = claim.lab_reference
            actor = claim.operator_id
            session = claim.session_id
            engagement = claim.engagement_id
            asset = claim.asset_id
            capability = claim.capability_id
            start = claim.starts_at
            end = claim.expires_at
            revoked = claim.revoked
        except AttributeError:
            return _HOLD

        if review_lab_reference_batch((ref,)).status != "REVIEW_ONLY":
            return _HOLD
        if not all((
            _identity(actor, "ACTOR"),
            _identity(session, "SESSION"),
            _identity(engagement, "ENG"),
            _identity(asset, "ASSET"),
            _identity(capability, "CAP"),
        )):
            return _HOLD
        # This standalone fictional review accepts only one claimed operator
        # and engagement per batch. Mixed actor/engagement claims are held
        # atomically rather than implicitly combining distinct authorities.
        # The caller may still fabricate the entire cohort: NOT consent.
        if cohort is None:
            cohort = (actor, engagement)
        elif cohort != (actor, engagement):
            return _HOLD
        if type(revoked) is not bool or revoked:
            return _HOLD
        if not (_utc_instant(start) and _utc_instant(end)):
            return _HOLD
        if not (start <= assessment_time <= end):
            return _HOLD
        if not (timedelta(0) < end - start <= _MAX_SESSION):
            return _HOLD
        if ref in seen_refs or session in seen_sessions:
            return _HOLD
        seen_refs.add(ref)
        seen_sessions.add(session)
    return _REVIEW
