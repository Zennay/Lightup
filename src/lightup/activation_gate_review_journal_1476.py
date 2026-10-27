"""Pure, non-authorizing monotonic observation journal for LightUp #1476.

This is a voluntary OFFLINE review protocol. The caller MUST retain the
returned next journal; an old/fabricated journal is not a secure authority
record. Only original source owners can integrate durable run/revoke gates.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from .activation_gate_cohort_review_1476 import (
    PinnedGateCohort,
    pin_gate_cohort_for_offline_review,
    review_gate_cohort_offline,
)
from .activation_gate_lifetime_review_1476 import LifetimeReceipt, LifetimeStatus


_MAX_OBSERVATIONS = 1024


@dataclass(frozen=True, slots=True, repr=False)
class OfflineCohortJournal:
    """Immutable-in-normal-code review history, never a grant or dispatch lock."""

    cohort: PinnedGateCohort = field(repr=False)
    held: bool = False
    observation_count: int = 0


@dataclass(frozen=True, slots=True, repr=False)
class OfflineCohortStep:
    """Next non-authorizing journal + privacy-minimal deny-only receipt."""

    next_journal: OfflineCohortJournal | None = field(repr=False)
    receipt: LifetimeReceipt = field(repr=False)


def _hold(reason: Literal["invalid_input", "changed"] = "invalid_input") -> LifetimeReceipt:
    return LifetimeReceipt(status=LifetimeStatus.HOLD, reason=reason)


def begin_offline_cohort_journal(gates: object) -> OfflineCohortJournal | None:
    """Start only with a complete, valid bounded cohort snapshot."""
    cohort = pin_gate_cohort_for_offline_review(gates)
    if cohort is None:
        return None
    return OfflineCohortJournal(cohort=cohort)


def advance_offline_cohort_journal(
    gates: object,
    journal: object,
) -> OfflineCohortStep:
    """Monotone HOLD across *observed* rounds; never authorize anything.

    No guarantee about unobserved mutation, swapped-and-restored objects,
    stale callers that reuse earlier journal values, or Python-level forgery.
    """
    if type(journal) is not OfflineCohortJournal:
        return OfflineCohortStep(None, _hold())
    try:
        cohort = object.__getattribute__(journal, "cohort")
        held = object.__getattribute__(journal, "held")
        count = object.__getattribute__(journal, "observation_count")
    except (AttributeError, TypeError, ValueError):
        return OfflineCohortStep(None, _hold())
    if (
        type(cohort) is not PinnedGateCohort
        or type(held) is not bool
        or type(count) is not int
        or not 0 <= count <= _MAX_OBSERVATIONS
    ):
        return OfflineCohortStep(None, _hold())

    # Terminal HOLD cannot revert within this returned journal chain even
    # if the original objects are restored after a detected bad observation.
    if held:
        return OfflineCohortStep(journal, _hold("changed"))

    if count >= _MAX_OBSERVATIONS:
        next_journal = OfflineCohortJournal(cohort, held=True, observation_count=count)
        return OfflineCohortStep(next_journal, _hold("changed"))

    receipt = review_gate_cohort_offline(gates, cohort)
    if receipt.status is not LifetimeStatus.REVIEW_ONLY:
        next_journal = OfflineCohortJournal(cohort, held=True, observation_count=count + 1)
        return OfflineCohortStep(next_journal, _hold("changed"))

    next_journal = OfflineCohortJournal(cohort, held=False, observation_count=count + 1)
    return OfflineCohortStep(next_journal, LifetimeReceipt(
        status=LifetimeStatus.REVIEW_ONLY, reason="unchanged"
    ))



@dataclass(slots=True, repr=False, eq=False)
class OfflineReviewSession:
    """Voluntary in-memory cursor. Never a trusted revocation authority.

    This prevents *accidental* replay of stale journal versions by a caller
    which retains the same session object. Starting or forging a new session,
    mutating Python memory, crashing/restarting, or replaying outside this
    object are explicitly outside this offline helper's guarantees.
    """

    _current: OfflineCohortJournal = field(repr=False)
    _terminal: bool = False

    @property
    def current(self) -> OfflineCohortJournal:
        """Return the identity that must be submitted on the next step."""
        return self._current


def open_offline_review_session(gates: object) -> OfflineReviewSession | None:
    """Start a bounded cohort *review*, not an authorization session."""
    journal = begin_offline_cohort_journal(gates)
    if journal is None:
        return None
    return OfflineReviewSession(journal)


def advance_offline_review_session(
    gates: object,
    session: object,
    presented_journal: object,
) -> OfflineCohortStep:
    """Reject stale cursors and terminal holds in one session object's life.

    Passing the *same object* returned by previous step is required. This
    guards benign replay bugs only, NOT attackers controlling Python memory.
    """
    if type(session) is not OfflineReviewSession:
        return OfflineCohortStep(None, _hold())
    try:
        current = object.__getattribute__(session, "_current")
        terminal = object.__getattribute__(session, "_terminal")
    except (AttributeError, TypeError, ValueError):
        return OfflineCohortStep(None, _hold())
    if type(current) is not OfflineCohortJournal or type(terminal) is not bool:
        return OfflineCohortStep(None, _hold())
    if terminal:
        return OfflineCohortStep(current, _hold("changed"))
    if presented_journal is not current:
        session._terminal = True
        return OfflineCohortStep(current, _hold("changed"))

    step = advance_offline_cohort_journal(gates, current)
    new_journal = step.next_journal
    if type(new_journal) is not OfflineCohortJournal:
        session._terminal = True
        return OfflineCohortStep(current, _hold("changed"))
    session._current = new_journal
    if step.receipt.status is not LifetimeStatus.REVIEW_ONLY:
        session._terminal = True
        return OfflineCohortStep(new_journal, _hold("changed"))
    return step
