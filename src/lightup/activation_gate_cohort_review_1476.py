"""Atomic, offline, non-authorizing cohort review for #1476.

Cohort results are *observations* of a collection of real installed
ActivationGate objects. They never authorize a target, grant, dispatch,
scan, release or deployment. No use at actual execution time is wired.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .activation import ActivationGate
from .activation_gate_lifetime_review_1476 import (
    LifetimeReceipt,
    LifetimeStatus,
    PinnedGateReview,
    pin_gate_for_offline_review,
    review_gate_lifetime,
)

_MAX_COHORT = 64


@dataclass(frozen=True, slots=True, repr=False)
class PinnedGateCohort:
    """Offline collection of immutable observations, NOT a live gate lock.

    A Python object can be forged or modified by other in-process code.
    This is intentionally not a trust token or check-before-dispatch API.
    """
    pins: tuple[PinnedGateReview, ...] = field(repr=False)


def _hold(reason: str = "invalid_input") -> LifetimeReceipt:
    # No policy texts, grant references or gate names ever enter the receipt.
    return LifetimeReceipt(status=LifetimeStatus.HOLD, reason=reason)


def pin_gate_cohort_for_offline_review(gates: object) -> PinnedGateCohort | None:
    """All-or-nothing bounded pinning, with strict tuple and gate identities.

    Reject duplicate gate identities, partial invalid snapshots, subclasses,
    oversized cohorts and even empty cohorts. This does not call issue().
    """
    if type(gates) is not tuple or not 1 <= len(gates) <= _MAX_COHORT:
        return None
    seen: set[int] = set()
    pins: list[PinnedGateReview] = []
    for gate in gates:
        if type(gate) is not ActivationGate or id(gate) in seen:
            return None
        seen.add(id(gate))
        pinned = pin_gate_for_offline_review(gate)
        if pinned is None:
            return None
        pins.append(pinned)
    # A later gate may have changed an earlier one while we were pinning.
    # Second bounded pass refuses such mid-pinning drift. This is still
    # observational, not an atomic inter-thread lock or authorization.
    for gate, pinned in zip(gates, pins):
        if review_gate_lifetime(gate, pinned).status is not LifetimeStatus.REVIEW_ONLY:
            return None
    return PinnedGateCohort(pins=tuple(pins))


def review_gate_cohort_offline(
    gates: object, cohort: object,
) -> LifetimeReceipt:
    """Fail atomically on any changed/invalid gate, never give authority.

    This does not validate consent or a grant, and cannot prevent policy
    rebinding after the review. REVIEW_ONLY is not permission of any kind.
    """
    if type(cohort) is not PinnedGateCohort:
        return _hold()
    if type(gates) is not tuple or not 1 <= len(gates) <= _MAX_COHORT:
        return _hold()
    try:
        pins = object.__getattribute__(cohort, "pins")
        if type(pins) is not tuple or len(pins) != len(gates):
            return _hold()
        seen: set[int] = set()
        for gate, pin in zip(gates, pins):
            if type(gate) is not ActivationGate or type(pin) is not PinnedGateReview:
                return _hold()
            if id(gate) in seen:
                return _hold("changed")
            seen.add(id(gate))
            if review_gate_lifetime(gate, pin).status is not LifetimeStatus.REVIEW_ONLY:
                return _hold("changed")
        # A second complete pass catches earlier objects altered while the
        # later objects were inspected. This is NOT a transaction; any
        # change after this observation remains outside our authority.
        for gate, pin in zip(gates, pins):
            if review_gate_lifetime(gate, pin).status is not LifetimeStatus.REVIEW_ONLY:
                return _hold("changed")
    except (AttributeError, TypeError, ValueError):
        return _hold()
    return LifetimeReceipt(status=LifetimeStatus.REVIEW_ONLY, reason="unchanged")
