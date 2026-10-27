"""Offline reconciliation of TWO fictional review-handoff capture histories.

Separately owned scope review #1505. Both inputs can be fabricated together;
matching histories are NOT authentic provenance, client/operator permission,
consent, approval or safe scope execution. Never wired into runtime.
"""
from __future__ import annotations

from lightup.fictional_review_sequence_1505 import (
    FictionalHandoff, ReviewOutcome, _copy, review_fictional_handoff_sequence,
)


def review_matching_fictional_captures(
    capture_a: tuple[FictionalHandoff, ...],
    capture_b: tuple[FictionalHandoff, ...],
) -> ReviewOutcome:
    """Generic no-echo HOLD on any contradictory, invalid or observed-changing copy.

    This is a bounded consistency hint across two caller-supplied independent
    fictional copies. It cannot detect omitted matching events or coordinated
    tampering, and does not establish a trusted snapshot or external authority.
    """
    hold = ReviewOutcome("HOLD")
    if (type(capture_a) is not tuple or type(capture_b) is not tuple
            or not 2 <= len(capture_a) <= 16
            or len(capture_a) != len(capture_b)):
        return hold
    a_first = _copy(capture_a)
    b_first = _copy(capture_b)
    if a_first is None or b_first is None or a_first != b_first:
        return hold
    # Only exact built-in scalar copies reach this point. Reconstruct ordinary
    # immutable records before invoking the proven strict single-capture checks.
    canonical_copy = tuple(FictionalHandoff(*row) for row in a_first)
    if review_fictional_handoff_sequence(canonical_copy).status != "REVIEW_ONLY":
        return hold

    a_after = _copy(capture_a)
    b_after = _copy(capture_b)
    if a_after is None or b_after is None or a_after != a_first or b_after != b_first:
        return hold
    return ReviewOutcome("REVIEW_ONLY", len(a_first))
