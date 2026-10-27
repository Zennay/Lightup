"""Offline reconciliation of 2..4 *fictional* handoff segments (#1505).

This is a bounded, disconnected review-only helper.  Source records can be
fabricated.  A contiguous reconstruction NEVER proves authentic provenance,
completeness of actual history, consent, approval or release authority.
"""
from __future__ import annotations

from lightup.fictional_review_sequence_1505 import (
    FictionalHandoff, ReviewOutcome, _copy, review_fictional_handoff_sequence,
)


def _capture_segments(
    segments: tuple[tuple[FictionalHandoff, ...], ...],
) -> tuple[tuple[tuple[object, ...], ...], ...] | None:
    """Freeze only canonical builtins without foreign comparison or sorting."""
    copies: list[tuple[tuple[object, ...], ...]] = []
    count = 0
    for segment in segments:
        if type(segment) is not tuple or not 1 <= len(segment) <= 16:
            return None
        count += len(segment)
        if count > 16:
            return None
        copied = _copy(segment)
        if copied is None:
            return None
        copies.append(copied)
    return tuple(copies)


def review_fictional_segment_join(
    segments: tuple[tuple[FictionalHandoff, ...], ...],
    expected_records: int,
) -> ReviewOutcome:
    """Reconcile caller-declared 1..N sequence over out-of-order segments.

    Two to four segment tuples with at least one entry each are accepted;
    each segment must internally be ordered and uninterrupted. Out-of-order
    segment delivery is permitted, but duplicate steps, a missing step, a
    digest replay, mixed fictional cases, invalid dates and all type aliases
    fail closed. The caller-provided expected count is NOT an authority claim.
    """
    hold = ReviewOutcome("HOLD")
    if (type(segments) is not tuple or not 2 <= len(segments) <= 4
            or type(expected_records) is not int
            or not 2 <= expected_records <= 16):
        return hold
    first = _capture_segments(segments)
    second = _capture_segments(segments)
    if first is None or second is None or first != second:
        return hold
    if sum(map(len, first)) != expected_records:
        return hold

    # _copy already asserted every row is an exact four-tuple of builtin
    # strings and integers. These primitive operations cannot call alien
    # user-defined comparators and no source values are emitted.
    rows = []
    for segment in first:
        for previous, current in zip(segment, segment[1:]):
            if current[1] != previous[1] + 1:
                return hold
        rows.extend(segment)
    rows.sort(key=lambda record: record[1])
    ordered = tuple(FictionalHandoff(*row) for row in rows)
    result = review_fictional_handoff_sequence(ordered)
    if result.status != "REVIEW_ONLY":
        return hold
    third = _capture_segments(segments)
    if third is None or third != first:
        return hold
    return result
