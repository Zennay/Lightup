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


def _hold() -> ScopeDeltaReview:
    # Fresh record: no shared object can be poisoned by a caller using
    # object.__setattr__ to bypass the frozen dataclass guard.
    return ScopeDeltaReview("HOLD", (), ())


def _items(value: object, *, assets: bool, max_count: int, nonempty: bool) -> bool:
    if type(value) is not tuple or len(value) > max_count or (nonempty and not value):
        return False
    # Reject oversized/invalid elements BEFORE hashing or sorting any caller
    # supplied string. Otherwise a very long value can make canonicality
    # checking expensive even though the bounded reviewer should HOLD.
    if assets:
        if any(type(item) is not str or len(item) > 48 or _ASSET.fullmatch(item) is None
               for item in value):
            return False
    elif any(type(item) is not str or len(item) > 16 or item not in _CAPABILITIES
             for item in value):
        return False
    return value == tuple(sorted(set(value)))


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



def _snapshot(proposal: object) -> FictionalScopeProposal | None:
    """Double-capture untrusted fields; reject visible in-flight mutation.

    A frozen dataclass can still be mutated by hostile in-process code using
    object.__setattr__. Compare two separately captured exact built-in records,
    validate BOTH, and use only our first private copy for the decision.
    This detects observable mixed reads, not an atomic cross-thread snapshot:
    a coordinated A->B->A mutation can still evade the consistency check.
    """
    if type(proposal) is not FictionalScopeProposal:
        return None
    try:
        first = FictionalScopeProposal(
            assets=proposal.assets,
            capabilities=proposal.capabilities,
            exclusions=proposal.exclusions,
            risk=proposal.risk,
            valid_from=proposal.valid_from,
            valid_until=proposal.valid_until,
        )
        second = FictionalScopeProposal(
            assets=proposal.assets,
            capabilities=proposal.capabilities,
            exclusions=proposal.exclusions,
            risk=proposal.risk,
            valid_from=proposal.valid_from,
            valid_until=proposal.valid_until,
        )
        # Reject invalid/alien fields BEFORE equality can invoke user code.
        if not _valid(first) or not _valid(second):
            return None
        return first if first == second else None
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None


def review_fictional_scope_delta(
    previous: object, proposed: object
) -> ScopeDeltaReview:
    """Flag any scope widening atomically; no sources, IO, or live authority.

    Old exclusions removed are widening; new exclusions are narrowing.
    Earlier starts or later ends are widening, even for valid UTC windows.
    Completely invalid proposals return a generic, zero-echo HOLD.
    """
    old = _snapshot(previous)
    new = _snapshot(proposed)
    if old is None or new is None:
        return _hold()
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


@dataclass(frozen=True, slots=True)
class ScopeHistoryReview:
    """Inert entire-chain review; caller-owned snapshot history is not trusted."""

    status: str
    transition_count: int
    first_held_step: int | None
    expanded_dimensions: tuple[str, ...]
    narrowed_dimensions: tuple[str, ...]
    held_steps: tuple[int, ...] = ()
    held_step_dimensions: tuple[tuple[str, ...], ...] = ()
    authorized: bool = field(default=False, init=False)
    consent_verified: bool = field(default=False, init=False)
    dispatch_allowed: bool = field(default=False, init=False)
    release_allowed: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        if type(self.status) is not str or self.status not in ("HOLD", "REVIEW_ONLY"):
            raise ValueError("invalid history review status")
        if type(self.transition_count) is not int or not 0 <= self.transition_count <= 15:
            raise ValueError("invalid history length")
        if type(self.held_steps) is not tuple or len(self.held_steps) > 15:
            raise ValueError("invalid held transition indices")
        if (
            any(type(step) is not int or not 1 <= step <= self.transition_count
                for step in self.held_steps)
            or self.held_steps != tuple(sorted(set(self.held_steps)))
        ):
            raise ValueError("held transitions must be unique sorted bounded indices")
        # Reject untrusted object types before comparing/iterating dimensions.
        # An alien __eq__/__bool__ must never participate in constructor checks.
        if type(self.expanded_dimensions) is not tuple or type(self.narrowed_dimensions) is not tuple:
            raise ValueError("invalid dimension type")
        if (
            type(self.held_step_dimensions) is not tuple
            or len(self.held_step_dimensions) != len(self.held_steps)
        ):
            raise ValueError("held step categories must match step indices")
        for categories in self.held_step_dimensions:
            if (
                type(categories) is not tuple or not categories
                or any(type(item) is not str for item in categories)
                or categories != tuple(name for name in _DIMENSIONS if name in categories)
            ):
                raise ValueError("held categories must be nonempty canonical dimensions")
        if self.held_step_dimensions:
            union = set(item for group in self.held_step_dimensions for item in group)
            if self.expanded_dimensions != tuple(name for name in _DIMENSIONS if name in union):
                raise ValueError("hold dimension summary must equal per-step union")
        for group in (self.expanded_dimensions, self.narrowed_dimensions):
            if any(type(x) is not str for x in group):
                raise ValueError("invalid dimension type")
            if group != tuple(name for name in _DIMENSIONS if name in group):
                raise ValueError("invalid history dimensions")
        if self.status == "HOLD":
            if self.narrowed_dimensions:
                raise ValueError("HOLD cannot certify narrowing")
            if self.first_held_step is None:
                if self.transition_count != 0 or self.expanded_dimensions or self.held_steps:
                    raise ValueError("invalid generic HOLD")
            elif (
                type(self.first_held_step) is not int
                or not 1 <= self.first_held_step <= self.transition_count
                or not self.expanded_dimensions
                or not self.held_steps
                or self.held_steps[0] != self.first_held_step
            ):
                raise ValueError("invalid hold witness")
        elif (
            not 1 <= self.transition_count <= 15
            or self.first_held_step is not None
            or self.expanded_dimensions
            or self.held_steps
        ):
            raise ValueError("history cannot approve an expansion")


def review_fictional_scope_history(history: object) -> ScopeHistoryReview:
    """Atomic offline review of every adjacent fictional proposal transition.

    Never compare only endpoints: A->B->A can hide an intermediate expansion.
    2..16 exact tuple snapshots, all checked before any result; invalid input
    returns generic zero-echo HOLD. Valid expanding history reports only fixed
    per-step fixed dimension names and ALL widened transition indices, never asset names or grants.
    """
    def generic_hold() -> ScopeHistoryReview:
        return ScopeHistoryReview("HOLD", 0, None, (), ())

    if type(history) is not tuple or not 2 <= len(history) <= 16:
        return generic_hold()
    try:
        # Atomic validation: even if an early step widens, a malformed later
        # snapshot takes precedence and suppresses all partial review details.
        # Capture each record only once; all later comparisons use solely
        # reviewer-owned snapshots, never caller-mutable original instances.
        snapshots = tuple(_snapshot(record) for record in history)
        if any(record is None for record in snapshots):
            return generic_hold()
        expanded = set()
        narrowed = set()
        first_held = None
        held_steps = []
        held_step_dimensions = []
        for step in range(1, len(snapshots)):
            result = review_fictional_scope_delta(snapshots[step - 1], snapshots[step])
            if result.status == "HOLD":
                if first_held is None:
                    first_held = step
                held_steps.append(step)
                held_step_dimensions.append(result.expanded_dimensions)
                expanded.update(result.expanded_dimensions)
            else:
                narrowed.update(result.narrowed_dimensions)
    except (AttributeError, TypeError, ValueError, OverflowError):
        return generic_hold()
    count = len(history) - 1
    if first_held is not None:
        return ScopeHistoryReview(
            "HOLD", count, first_held,
            tuple(name for name in _DIMENSIONS if name in expanded), (),
            tuple(held_steps), tuple(held_step_dimensions),
        )
    return ScopeHistoryReview(
        "REVIEW_ONLY", count, None, (),
        tuple(name for name in _DIMENSIONS if name in narrowed),
    )
