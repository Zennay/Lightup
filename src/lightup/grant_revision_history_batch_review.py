"""Atomic local review of several self-declared grant-revision histories.

Only synthetic review logic; never a trusted approval or live executor gate.
"""
from __future__ import annotations

from dataclasses import dataclass

from .grant_revision_batch_review import review_grant_revision_batch
from .grant_revision_history_review import review_grant_history


@dataclass(frozen=True)
class GrantHistoryBatchReview:
    verdict: str
    reason_code: str
    reviewed_histories: int = 0
    reviewed_transitions: int = 0
    narrowed_dimensions: int = 0
    authorization_verified: bool = False
    permit_issued: bool = False
    execution_enabled: bool = False
    merge_approved: bool = False
    release_approved: bool = False


def _hold(reason: str) -> GrantHistoryBatchReview:
    return GrantHistoryBatchReview("HOLD", reason)


def review_grant_history_batch(histories: object) -> GrantHistoryBatchReview:
    """Validate 1..16 full 2..8-version histories as an atomic operator packet.

    First validates *every version transition* across every submitted history,
    then composes start/end snapshots through the existing multi-tenant batch
    reviewer to detect duplicate IDs and self-declared tenant/asset collision.
    Any failure returns HOLD without reporting partial accepted counts.

    Inputs are untrusted: omitted versions or forged original snapshots cannot
    be detected. Even a clean result never grants access, deployment or a scan.
    """
    if type(histories) is not tuple or not 1 <= len(histories) <= 16:
        return _hold("invalid_histories_shape")

    endpoint_pairs = []
    changes = 0
    transitions = 0
    for history in histories:
        result = review_grant_history(history)
        if result.verdict != "REVIEW_ONLY":
            return _hold("history_held")
        endpoint_pairs.append((history[0], history[-1]))
        transitions += result.reviewed_transitions
        changes += len(result.narrowed_fields)

    composed = review_grant_revision_batch(tuple(endpoint_pairs))
    if composed.verdict != "REVIEW_ONLY":
        return _hold("cross_history_coherence_held")

    return GrantHistoryBatchReview(
        "REVIEW_ONLY", "declared_history_batch_syntactically_nonwidening",
        reviewed_histories=len(histories),
        reviewed_transitions=transitions,
        narrowed_dimensions=changes,
    )
