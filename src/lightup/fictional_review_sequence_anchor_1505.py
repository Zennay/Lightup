"""Compare synthetic segmented review with a separately supplied full capture.

#1505-only local consistency check. Both sides remain fully user-controlled;
matching values are NEVER provenance, permission, consent or release evidence.
"""
from __future__ import annotations

from lightup.fictional_review_sequence_1505 import (
    FictionalHandoff, ReviewOutcome, _copy, review_fictional_handoff_sequence,
)
from lightup.fictional_review_sequence_segments_1505 import (
    _capture_segments, review_fictional_segment_join,
)


def review_fictional_segments_against_capture(
    segments: tuple[tuple[FictionalHandoff, ...], ...],
    expected_records: int,
    capture: tuple[FictionalHandoff, ...],
) -> ReviewOutcome:
    """Require exact equality of a fragmented and independently copied history.

    The two representations must not reference the *same Python records*.
    This reduces trivial accidental alias comparisons but absolutely does not
    attest to separate origin: both sides may be deliberately jointly forged.
    """
    hold = ReviewOutcome("HOLD")
    if (type(segments) is not tuple or not 2 <= len(segments) <= 4
            or type(expected_records) is not int
            or not 2 <= expected_records <= 16
            or type(capture) is not tuple or len(capture) != expected_records):
        return hold
    segmented_before = _capture_segments(segments)
    complete_before = _copy(capture)
    if segmented_before is None or complete_before is None:
        return hold
    if sum(map(len, segmented_before)) != expected_records:
        return hold

    # Reject even a directly aliased Python record view advertised as an
    # independent witness. This is a weak separation hint, not provenance.
    original_record_ids = {id(record) for record in capture}
    for segment in segments:
        if any(id(record) in original_record_ids for record in segment):
            return hold

    if review_fictional_segment_join(segments, expected_records).status != "REVIEW_ONLY":
        return hold
    if review_fictional_handoff_sequence(capture).status != "REVIEW_ONLY":
        return hold

    flat = [row for fragment in segmented_before for row in fragment]
    flat.sort(key=lambda fields: fields[1])
    if tuple(flat) != complete_before:
        return hold
    segmented_after = _capture_segments(segments)
    complete_after = _copy(capture)
    if (segmented_after is None or complete_after is None
            or segmented_after != segmented_before or complete_after != complete_before):
        return hold
    return ReviewOutcome("REVIEW_ONLY", expected_records)
