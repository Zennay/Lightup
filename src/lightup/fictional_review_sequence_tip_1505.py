"""Separate caller-supplied fictional chain-tip consistency hint (#1505).

Neither linked digest hints nor the supplied expected tip are authenticated.
This pure code is NEVER a grant/consent/dispatch/release authorization path.
"""
from __future__ import annotations

from lightup.fictional_review_sequence_1505 import ReviewOutcome
from lightup.fictional_review_sequence_linked_1505 import (
    FictionalLinkedHandoff, _safe_snapshot, review_fictional_parent_links,
    _HEX,
)


def review_fictional_tip_pin(
    records: tuple[FictionalLinkedHandoff, ...],
    expected_tip_sha256: str,
) -> ReviewOutcome:
    """Pin the final untrusted copy-hint against a separate untrusted string.

    This catches accidental local tail drift if the caller independently kept
    a copy of the original last digest. A malicious caller may change BOTH
    tip and records; REVIEW_ONLY is NEVER authenticated provenance/consent.
    """
    hold = ReviewOutcome("HOLD")
    if (type(expected_tip_sha256) is not str
            or len(expected_tip_sha256) != 64
            or any(ch not in _HEX for ch in expected_tip_sha256)
            or type(records) is not tuple or not 2 <= len(records) <= 16):
        return hold
    before = _safe_snapshot(records)
    if before is None or before[-1][2] != expected_tip_sha256:
        return hold
    if review_fictional_parent_links(records).status != "REVIEW_ONLY":
        return hold
    after = _safe_snapshot(records)
    if after is None or after != before:
        return hold
    return ReviewOutcome("REVIEW_ONLY", len(before))
