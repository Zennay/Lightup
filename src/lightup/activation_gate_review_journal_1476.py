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
