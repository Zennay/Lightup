"""Offline fictional dual-party acknowledgement consistency check.

INCUBATE / PLAN-LAB ONLY. Caller supplied claims are NEVER authenticated
consent, evidence of human identity, authorization, or dispatch approval.
No I/O, storage, network, handlers, grants or runtime integration.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import re


_CASE = re.compile(r"case-[a-z0-9]{1,16}\\Z")
_ACTOR = re.compile(r"fictional-(client|operator)-[a-z0-9]{1,16}\\Z")
_ASSET = re.compile(r"[a-z][a-z0-9-]{0,25}\\.example\\.test\\Z")
_CAPABILITIES = frozenset(("inventory", "observe", "report"))
_MAX_WINDOW = timedelta(hours=24)


@dataclass(frozen=True, slots=True)
class FictionalAcknowledgement:
    case_id: str
    role: str
    actor_id: str
    asset: str
    capabilities: tuple[str, ...]
    risk: int
    issued_at: datetime
    expires_at: datetime
    decision: str
    revoked: bool


@dataclass(frozen=True, slots=True)
class ReviewResult:
    status: str
    authorized: bool = False
    consent_verified: bool = False
    dispatch_allowed: bool = False
    release_allowed: bool = False


_HOLD = ReviewResult("HOLD")
_REVIEW = ReviewResult("REVIEW_ONLY")


def _canonical_instant(value: object) -> bool:
    return (
        type(value) is datetime
        and value.tzinfo is timezone.utc
        and value.microsecond == 0
        and value.fold == 0
    )


def _valid(item: object, now: datetime) -> bool:
    if type(item) is not FictionalAcknowledgement:
        return False
    if type(item.role) is not str or item.role not in ("client", "operator"):
        return False
    if type(item.case_id) is not str or _CASE.fullmatch(item.case_id) is None:
        return False
    if type(item.actor_id) is not str:
        return False
    match = _ACTOR.fullmatch(item.actor_id)
    if match is None or match.group(1) != item.role:
        return False
    if type(item.asset) is not str or _ASSET.fullmatch(item.asset) is None:
        return False
    if "xn--" in item.asset or "--" in item.asset:
        return False
    if type(item.capabilities) is not tuple:
        return False
    if not 1 <= len(item.capabilities) <= 3:
        return False
    if any(type(c) is not str or c not in _CAPABILITIES for c in item.capabilities):
        return False
    if tuple(sorted(set(item.capabilities))) != item.capabilities:
        return False
    if type(item.risk) is not int or not 1 <= item.risk <= 5:
        return False
    if not _canonical_instant(item.issued_at) or not _canonical_instant(item.expires_at):
        return False
    if not item.issued_at < item.expires_at or item.expires_at - item.issued_at > _MAX_WINDOW:
        return False
    if not item.issued_at <= now < item.expires_at:
        return False
    if type(item.decision) is not str or item.decision != "acknowledge":
        return False
    if type(item.revoked) is not bool or item.revoked is not False:
        return False
    return True


def review_fictional_acknowledgements(
    claims: object, review_at: object
) -> ReviewResult:
    """Compare EXACT TWO synthetic statements; never return permission.

    All records and the clock are user-provided, so REVIEW_ONLY only indicates
    internal consistency, NOT authenticity, revocation-at-use or consent.
    """
    if not _canonical_instant(review_at):
        return _HOLD
    if type(claims) is not tuple or len(claims) != 2:
        return _HOLD
    if not all(_valid(item, review_at) for item in claims):
        return _HOLD
    left, right = claims
    if left.role == right.role or left.actor_id == right.actor_id:
        return _HOLD
    for field in ("case_id", "asset", "capabilities", "risk", "issued_at", "expires_at"):
        if getattr(left, field) != getattr(right, field):
            return _HOLD
    return _REVIEW
