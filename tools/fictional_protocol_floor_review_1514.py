"""Offline fictional review-protocol downgrade diagnostic (#1514).

UNWIRED, NOT A PERMIT, never real client/operator consent. No I/O.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re

_CASE = re.compile(r"case-[a-z0-9]{1,24}\.example\.test", re.ASCII)
MAX_FRAMES = 32
MAX_VERSION = 16


@dataclass(frozen=True, slots=True)
class FictionalFrame:
    version: int
    case_id: str
    sequence: int


@dataclass(frozen=True, slots=True)
class ReviewReceipt:
    status: str
    authorized: bool = field(default=False, init=False)
    consent_verified: bool = field(default=False, init=False)
    dispatch_allowed: bool = field(default=False, init=False)
    release_allowed: bool = field(default=False, init=False)


def review_protocol_floor(
    frames: tuple[FictionalFrame, ...],
    expected_version: int,
    minimum_version: int,
) -> ReviewReceipt:
    """Conservative format-only review: REVIEW_ONLY is NEVER permission.

    All inputs are caller-controlled and cannot establish authenticity.
    In particular there is no fallback to a legacy schema, and a later
    version is not silently reinterpreted as an older version.
    """
    def hold() -> ReviewReceipt:
        return ReviewReceipt("HOLD")

    if type(frames) is not tuple or not (1 <= len(frames) <= MAX_FRAMES):
        return hold()
    if type(expected_version) is not int or type(minimum_version) is not int:
        return hold()
    if not (1 <= minimum_version <= expected_version <= MAX_VERSION):
        return hold()

    first_case = None
    for position, frame in enumerate(frames, start=1):
        if type(frame) is not FictionalFrame:
            return hold()
        if type(frame.version) is not int or frame.version != expected_version:
            return hold()
        if type(frame.case_id) is not str or not _CASE.fullmatch(frame.case_id):
            return hold()
        if type(frame.sequence) is not int or frame.sequence != position:
            return hold()
        if first_case is None:
            first_case = frame.case_id
        elif frame.case_id != first_case:
            return hold()
    return ReviewReceipt("REVIEW_ONLY")
