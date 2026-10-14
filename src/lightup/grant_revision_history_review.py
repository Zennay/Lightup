"""Atomic offline review of a self-declared multi-version authorization grant history.

No state persistence, target I/O, execution or grant issuance occurs here.
A syntactically clean self-reported history is not a trusted history.
"""
from __future__ import annotations

from dataclasses import dataclass

from .engagements import AuthorizationGrant
from .grant_revision_review import review_grant_revision


@dataclass(frozen=True)
class GrantHistoryReview:
    verdict: str
    reason_code: str
    version_count: int = 0
    reviewed_transitions: int = 0
    narrowed_fields: tuple[str, ...] = ()
    authorization_verified: bool = False
    permit_issued: bool = False
    execution_enabled: bool = False
    merge_approved: bool = False
    release_approved: bool = False


def _hold(reason: str) -> GrantHistoryReview:
    # Never report a successful prefix when a later version is unsafe.
    return GrantHistoryReview("HOLD", reason)


def review_grant_history(snapshots: object) -> GrantHistoryReview:
    """Check a complete declared 2..8-version chain for monotonic narrowing.

    Every *adjacent* transition must be individually canonical and narrowing.
    A late return to a narrower grant cannot erase an intermediate expansion.
    Duplicate no-op versions are denied as ambiguous version progression.

    This only reviews user-provided in-memory snapshots. It cannot establish
    the existence, completeness, authenticity or order of historical versions.
    """
    if type(snapshots) is not tuple or not 2 <= len(snapshots) <= 8:
        return _hold("invalid_history_shape")
    if any(type(item) is not AuthorizationGrant for item in snapshots):
        return _hold("invalid_grant_type")

    changed: set[str] = set()
    for previous, current in zip(snapshots, snapshots[1:]):
        result = review_grant_revision(previous, current)
        if result.verdict != "REVIEW_ONLY":
            return _hold("transition_held")
        if not result.narrowed_fields:
            return _hold("duplicate_or_noop_version")
        changed.update(result.narrowed_fields)

    # Defense in depth: although pairwise narrowing should imply this,
    # the complete start/end snapshots must independently be nonwidening.
    endpoint = review_grant_revision(snapshots[0], snapshots[-1])
    if endpoint.verdict != "REVIEW_ONLY":
        return _hold("end_to_end_held")

    return GrantHistoryReview(
        verdict="REVIEW_ONLY",
        reason_code="declared_history_syntactically_nonwidening",
        version_count=len(snapshots),
        reviewed_transitions=len(snapshots) - 1,
        narrowed_fields=tuple(sorted(changed)),
    )
