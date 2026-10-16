"""Non-authorizing, atomic offline cohort inspection for issue #1482.

This is an uninstalled review aid, NOT a scan, grant, permit or release check.
The input must already be an exact finite tuple of exact built-in tuples;
no callbacks, generators, iterators, resolvers, policy.decide or I/O.
"""
from __future__ import annotations

from typing import NamedTuple

from .activation_decision_shape_review_1482 import review_decision_shape
from .models import Target
from .scope import ScopeDecision, ScopePolicy


class CohortReview(NamedTuple):
    status: str
    reason: str
    inspected: int
    authorizes_execution: bool = False
    authorizes_release: bool = False


def _hold(reason: str) -> CohortReview:
    return CohortReview("HOLD", reason, 0)


def review_decision_cohort(rows: object) -> CohortReview:
    """Check *shape coherence only*. Even REVIEW_ONLY always denies authority.

    Processing is atomic: malformed or conflicting rows return no partial
    verdicts or hostnames. The integer count is informational, not evidence
    that any scope policy was faithfully evaluated.
    """
    if type(rows) is not tuple or not 1 <= len(rows) <= 64:
        return _hold("invalid_batch")
    hosts: set[str] = set()
    for row in rows:
        if type(row) is not tuple or len(row) != 3:
            return _hold("invalid_row")
        policy, target, decision = row
        if (
            type(policy) is not ScopePolicy
            or type(target) is not Target
            or type(decision) is not ScopeDecision
        ):
            return _hold("noncanonical_row")
        try:
            verdict = review_decision_shape(policy, target, decision)
            if verdict.status != "REVIEW_ONLY":
                return _hold("row_on_hold")
            # Only strings accepted by review_decision_shape reach here.
            host = decision.normalized_host
            if host in hosts:
                return _hold("duplicate_host")
            hosts.add(host)
        except Exception:
            return _hold("row_review_error")
    # This does not assert trust in policy origin, permissions or output.
    return CohortReview("REVIEW_ONLY", "coherent_shape_only", len(rows))
