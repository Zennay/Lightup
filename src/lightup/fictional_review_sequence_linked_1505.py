"""Pure fictional predecessor-pointer chronology hints; never authorization.

#1505's independent and intentionally unwired extension.  Every digest,
parent pointer and genesis marker is caller-controlled and does NOT prove
cryptographic linkage, authentic provenance, consent, scope or execution.
"""
from __future__ import annotations

from dataclasses import dataclass

from lightup.fictional_review_sequence_1505 import (
    FictionalHandoff, ReviewOutcome, review_fictional_handoff_sequence,
)

_GENESIS = "0" * 64
_HEX = frozenset("0123456789abcdef")


@dataclass(frozen=True, slots=True)
class FictionalLinkedHandoff:
    case_id: str
    sequence: int
    packet_sha256: str
    observed_at: str
    previous_packet_sha256: str


def _safe_snapshot(
    records: tuple[FictionalLinkedHandoff, ...],
) -> tuple[tuple[str, int, str, str, str], ...] | None:
    """Copy literal builtin scalar fields only, before comparing anything."""
    rows = []
    for item in records:
        if type(item) is not FictionalLinkedHandoff:
            return None
        fields = (item.case_id, item.sequence, item.packet_sha256,
                  item.observed_at, item.previous_packet_sha256)
        if (type(fields[0]) is not str or type(fields[1]) is not int or
                type(fields[2]) is not str or type(fields[3]) is not str or
                type(fields[4]) is not str):
            return None
        rows.append(fields)
    return tuple(rows)


def review_fictional_parent_links(
    records: tuple[FictionalLinkedHandoff, ...],
) -> ReviewOutcome:
    """Check locally coherent predecessor copy *hints*, never permissions.

    REVIEW_ONLY never implies authentic hash-chaining: no packet body, real
    digest, signature, operator or client is inspected or trusted.
    """
    hold = ReviewOutcome("HOLD")
    if type(records) is not tuple or not 2 <= len(records) <= 16:
        return hold
    before = _safe_snapshot(records)
    twice = _safe_snapshot(records)
    if before is None or twice is None or before != twice:
        return hold
    previous = _GENESIS
    raw = []
    for case_id, sequence, digest, instant, linked_from in before:
        if (len(linked_from) != 64 or any(c not in _HEX for c in linked_from)
                or linked_from != previous):
            return hold
        raw.append(FictionalHandoff(case_id, sequence, digest, instant))
        previous = digest
    result = review_fictional_handoff_sequence(tuple(raw))
    if result.status != "REVIEW_ONLY":
        return hold
    after = _safe_snapshot(records)
    if after is None or before != after:
        return hold
    return ReviewOutcome("REVIEW_ONLY", len(before))
