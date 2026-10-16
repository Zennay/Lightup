"""Offline, NON-AUTHORIZING comparison of reserved fictional scope proposals.

Not wired into ScopePolicy, ActivationGate, ExecutionPolicy or any adapter.
An identical/narrower proposal produces REVIEW_ONLY, NEVER permission.
Caller-supplied data is not authenticated consent or trusted provenance.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import re

_CAPABILITIES = frozenset({"headers_view", "metadata_view", "robots_view", "tls_summary"})
_ASSET = re.compile(r"(?:[a-z]|[a-z][a-z0-9-]{0,30}[a-z0-9])\.example\.test\Z", re.ASCII)
_DIMENSIONS = ("assets", "capabilities", "exclusions", "risk", "valid_from", "valid_until")


@dataclass(frozen=True, slots=True)
class FictionalScopeProposal:
    """Untrusted review-only values; NOT an authorization/grant record."""

    assets: tuple[str, ...]
    capabilities: tuple[str, ...]
    exclusions: tuple[str, ...]
    risk: int
    valid_from: datetime
    valid_until: datetime


@dataclass(frozen=True, slots=True)
class ScopeDeltaReview:
    """Immutable outcome; never grants rights even on REVIEW_ONLY."""

    status: str
    expanded_dimensions: tuple[str, ...]
    narrowed_dimensions: tuple[str, ...]
    authorized: bool = field(default=False, init=False)
    consent_verified: bool = field(default=False, init=False)
    dispatch_allowed: bool = field(default=False, init=False)
    release_allowed: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        if type(self.status) is not str or self.status not in ("HOLD", "REVIEW_ONLY"):
            raise ValueError("invalid review status")
        for group in (self.expanded_dimensions, self.narrowed_dimensions):
            if type(group) is not tuple or any(type(x) is not str for x in group):
                raise ValueError("invalid review dimensions")
            if len(group) > len(_DIMENSIONS) or len(set(group)) != len(group):
                raise ValueError("invalid review dimensions")
            if any(x not in _DIMENSIONS for x in group) or group != tuple(
                name for name in _DIMENSIONS if name in group
            ):
                raise ValueError("invalid review dimensions")
        if self.status == "REVIEW_ONLY" and self.expanded_dimensions:
            raise ValueError("an expansion cannot be review-only")
        if self.status == "HOLD" and self.narrowed_dimensions:
            raise ValueError("HOLD must not imply an accepted narrowed scope")


_HOLD = ScopeDeltaReview("HOLD", (), ())


def _items(value: object, *, assets: bool, max_count: int, nonempty: bool) -> bool:
    if type(value) is not tuple or len(value) > max_count or (nonempty and not value):
        return False
    if any(type(item) is not str for item in value):
        return False
    if value != tuple(sorted(set(value))):
        return False
    if assets:
        return all(len(item) <= 48 and _ASSET.fullmatch(item) is not None for item in value)
    return all(item in _CAPABILITIES for item in value)


def _instant(value: object) -> bool:
    return (
        type(value) is datetime
        and value.tzinfo is timezone.utc
        and value.microsecond == 0
        and 2020 <= value.year <= 2100
        and value.fold == 0
    )


def _valid(proposal: object) -> bool:
    if type(proposal) is not FictionalScopeProposal:
        return False
    if not _items(proposal.assets, assets=True, max_count=16, nonempty=True):
        return False
    if not _items(proposal.capabilities, assets=False, max_count=4, nonempty=True):
        return False
    if not _items(proposal.exclusions, assets=True, max_count=16, nonempty=False):
        return False
    if not set(proposal.exclusions).issubset(proposal.assets):
        return False
    if type(proposal.risk) is not int or not 1 <= proposal.risk <= 5:
        return False
    if not _instant(proposal.valid_from) or not _instant(proposal.valid_until):
        return False
    return (
        proposal.valid_from < proposal.valid_until
        and proposal.valid_until - proposal.valid_from <= timedelta(days=31)
    )


def review_fictional_scope_delta(
    previous: object, proposed: object
) -> ScopeDeltaReview:
    """Flag any scope widening atomically; no sources, IO, or live authority.

    Old exclusions removed are widening; new exclusions are narrowing.
    Earlier starts or later ends are widening, even for valid UTC windows.
    Completely invalid proposals return a generic, zero-echo HOLD.
    """
    if not _valid(previous) or not _valid(proposed):
        return _HOLD
    old, new = previous, proposed
    widened = {
        "assets": not set(new.assets).issubset(old.assets),
        "capabilities": not set(new.capabilities).issubset(old.capabilities),
        "exclusions": not set(old.exclusions).issubset(new.exclusions),
        "risk": new.risk > old.risk,
        "valid_from": new.valid_from < old.valid_from,
        "valid_until": new.valid_until > old.valid_until,
    }
    if any(widened.values()):
        return ScopeDeltaReview(
            "HOLD", tuple(name for name in _DIMENSIONS if widened[name]), ()
        )
    narrowed = {
        "assets": new.assets != old.assets,
        "capabilities": new.capabilities != old.capabilities,
        "exclusions": new.exclusions != old.exclusions,
        "risk": new.risk < old.risk,
        "valid_from": new.valid_from > old.valid_from,
        "valid_until": new.valid_until < old.valid_until,
    }
    return ScopeDeltaReview(
        "REVIEW_ONLY", (), tuple(name for name in _DIMENSIONS if narrowed[name])
    )
