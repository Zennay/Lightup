"""Offline historical capability drift reviewer: never authorizes any operation.

Comparing only first and last snapshots hides intermediate changes that are
subsequently reverted. Review every adjacent snapshot, not just endpoints.
This is a bounded developer metadata audit, not proof of provenance/consent.
"""
from __future__ import annotations

from dataclasses import dataclass

from .capability_registry_drift_review import review_capability_registry_drift

_MIN_SNAPSHOTS = 2
_MAX_SNAPSHOTS = 16


@dataclass(frozen=True)
class HistoricalTransition:
    from_index: int
    to_index: int
    changed_fields: tuple[tuple[str, tuple[str, ...]], ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "from_index": self.from_index,
            "to_index": self.to_index,
            "changed_fields": {name: list(fields) for name, fields in self.changed_fields},
        }


@dataclass(frozen=True)
class HistoricalReview:
    status: str
    reason: str
    snapshot_count: int
    fingerprint_history: tuple[str, ...]
    transitions: tuple[HistoricalTransition, ...]
    authorization_verified: bool = False
    permit_issued: bool = False
    execution_enabled: bool = False
    merge_approved: bool = False
    release_approved: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "reason": self.reason,
            "snapshot_count": self.snapshot_count,
            "fingerprint_history": list(self.fingerprint_history),
            "transitions": [transition.as_dict() for transition in self.transitions],
            "authorization_verified": False,
            "permit_issued": False,
            "execution_enabled": False,
            "merge_approved": False,
            "release_approved": False,
        }


def _hold(reason: str) -> HistoricalReview:
    return HistoricalReview("HOLD", reason, 0, (), ())


def review_capability_registry_history(snapshots: tuple[bytes, ...]) -> HistoricalReview:
    """Every valid transition must match or the entire history is HOLD.

    The order is caller-declared (not independently verified chronology).
    No network, disk, Git or privileged runtime is accessed here.
    """
    if type(snapshots) is not tuple or not _MIN_SNAPSHOTS <= len(snapshots) <= _MAX_SNAPSHOTS:
        return _hold("invalid_snapshot_count")
    fingerprints: list[str] = []
    for raw in snapshots:
        if type(raw) is not bytes:
            return _hold("invalid_snapshot")
        self_review = review_capability_registry_drift(raw, raw)
        if self_review.status != "REVIEW_ONLY" or type(self_review.baseline_fingerprint) is not str:
            return _hold("invalid_snapshot")
        fingerprints.append(self_review.baseline_fingerprint)

    transitions: list[HistoricalTransition] = []
    for index in range(len(snapshots) - 1):
        pair_review = review_capability_registry_drift(snapshots[index], snapshots[index + 1])
        if pair_review.status not in ("HOLD", "REVIEW_ONLY") or pair_review.baseline_fingerprint is None:
            return _hold("invalid_transition")
        if pair_review.baseline_fingerprint != fingerprints[index] or pair_review.candidate_fingerprint != fingerprints[index + 1]:
            return _hold("incoherent_transition")
        if pair_review.changed_fields:
            transitions.append(HistoricalTransition(index, index + 1, pair_review.changed_fields))

    return HistoricalReview(
        "HOLD" if transitions else "REVIEW_ONLY",
        "historical_drift_requires_independent_review" if transitions else "unchanged_declared_history_only",
        len(snapshots),
        tuple(fingerprints),
        tuple(transitions),
    )
