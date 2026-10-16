"""Isolated #1517 fictional identity-drift diagnostic. NEVER an authorization gate.

No production component imports this module. Caller-provided labels are not
authenticated evidence. REVIEW_ONLY means solely in-memory consistency.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

_ASSET = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.example\.test", re.ASCII)
_OWNER = re.compile(r"owner-[a-z0-9]{1,20}", re.ASCII)
_GRANT = re.compile(r"grant-[a-z0-9]{1,24}", re.ASCII)
_MAX_REVISION = 2**31 - 1


@dataclass(frozen=True, slots=True, init=False)
class BindingReview1517:
    status: str
    authorized: bool = False
    consent_verified: bool = False
    dispatch_allowed: bool = False
    release_allowed: bool = False

    def __init__(self, status: str):
        if type(status) is not str or status not in ("HOLD", "REVIEW_ONLY"):
            raise ValueError("invalid review status")
        object.__setattr__(self, "status", status)
        for key in ("authorized", "consent_verified", "dispatch_allowed", "release_allowed"):
            object.__setattr__(self, key, False)


def _canonical(record: object) -> bool:
    """Accept ONLY (fictional_asset, owner, grant_reference, revision)."""
    if type(record) is not tuple or len(record) != 4:
        return False
    asset, owner, grant, revision = record
    return (
        type(asset) is str and _ASSET.fullmatch(asset) is not None
        and type(owner) is str and _OWNER.fullmatch(owner) is not None
        and type(grant) is str and _GRANT.fullmatch(grant) is not None
        and type(revision) is int and 1 <= revision <= _MAX_REVISION
    )


def review_target_binding_1517(before: object, after: object) -> BindingReview1517:
    """Non-authorizing fictional snapshot drift check: HOLD on ANY ambiguity.

    Exact built-in tuple/string/integer input only: no normalization, object
    hooks, equality from user-defined types, I/O, source owner imports or echo.
    The source owner must separately bind live scope, issuer and at-use grant.
    """
    if not _canonical(before) or not _canonical(after):
        return BindingReview1517("HOLD")
    if before != after:
        return BindingReview1517("HOLD")
    return BindingReview1517("REVIEW_ONLY")
