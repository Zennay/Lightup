"""Standalone offline fictional review-handoff chronology, never an authority gate.

#1505 owns this NEW module. Production scope/activation/grant/execution code must not
import or call it. Packet digests are untrusted hints, NOT authenticated provenance.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
import re

_CASE = re.compile(r"review-[a-z][a-z0-9]{0,31}\.example\.test\Z", re.ASCII)
_SHA = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_UTC = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z", re.ASCII)
_MAX_RECORDS = 16


@dataclass(frozen=True, slots=True)
class FictionalHandoff:
    case_id: str
    sequence: int
    packet_sha256: str
    observed_at: str


@dataclass(frozen=True, slots=True)
class ReviewOutcome:
    status: str
    checked_records: int = 0
    authorized: bool = field(default=False, init=False)
    consent_verified: bool = field(default=False, init=False)
    dispatch_allowed: bool = field(default=False, init=False)
    release_allowed: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        if type(self.status) is not str or type(self.checked_records) is not int:
            raise ValueError("noncanonical review outcome")
        if (self.status == "HOLD" and self.checked_records == 0):
            return
        if self.status == "REVIEW_ONLY" and 2 <= self.checked_records <= _MAX_RECORDS:
            return
        raise ValueError("noncanonical review outcome")


def _copy(records: tuple[FictionalHandoff, ...]) -> tuple[tuple[object, ...], ...] | None:
    """Exact builtin records only; copy every field without invoking user comparisons."""
    rows = []
    for record in records:
        if type(record) is not FictionalHandoff:
            return None
        rows.append((record.case_id, record.sequence, record.packet_sha256, record.observed_at))
    return tuple(rows)


def _parse_utc(value: str) -> datetime | None:
    if type(value) is not str or len(value) != 20 or _UTC.fullmatch(value) is None:
        return None
    try:
        return datetime(
            int(value[0:4]), int(value[5:7]), int(value[8:10]),
            int(value[11:13]), int(value[14:16]), int(value[17:19])
        )
    except ValueError:
        return None


def review_fictional_handoff_sequence(
    records: tuple[FictionalHandoff, ...],
) -> ReviewOutcome:
    """Reject obvious local continuity defects. Never establishes complete provenance.

    No I/O, imports of production authorization, source-value echo, or dispatch.
    Even REVIEW_ONLY means human review without any permission whatsoever.
    """
    hold = ReviewOutcome("HOLD")
    if type(records) is not tuple or not 2 <= len(records) <= _MAX_RECORDS:
        return hold
    first = _copy(records)
    second = _copy(records)
    if first is None or second is None or first != second:
        return hold

    case_id = None
    first_time = None
    last_time = None
    seen: set[str] = set()
    for expected, row in enumerate(first, 1):
        candidate, sequence, digest, instant = row
        if (type(candidate) is not str or not 1 <= len(candidate) <= 52
                or _CASE.fullmatch(candidate) is None
                or type(sequence) is not int or sequence != expected
                or type(digest) is not str or _SHA.fullmatch(digest) is None
                or digest in seen):
            return hold
        at = _parse_utc(instant)
        if at is None:
            return hold
        if case_id is None:
            case_id, first_time = candidate, at
        if candidate != case_id or (last_time is not None and at <= last_time):
            return hold
        if at - first_time > timedelta(hours=24):
            return hold
        seen.add(digest)
        last_time = at
    return ReviewOutcome("REVIEW_ONLY", len(first))
