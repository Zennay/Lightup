"""Non-authorizing, atomic offline cohort inspection for issue #1482.

This is an uninstalled review aid, NOT a scan, grant, permit or release check.
The input must already be an exact finite tuple of exact built-in tuples;
no callbacks, generators, iterators, resolvers, policy.decide or I/O.
"""
from __future__ import annotations

from typing import NamedTuple
from ipaddress import ip_address

from .activation_decision_shape_review_1482 import review_decision_shape
from .models import Target
from .scope import ScopeDecision, ScopePolicy, ScopeReason


class CohortReview(NamedTuple):
    status: str
    reason: str
    inspected: int
    authorizes_execution: bool = False
    authorizes_release: bool = False


def _hold(reason: str) -> CohortReview:
    return CohortReview("HOLD", reason, 0)



def _exact_policy_configuration(policy: ScopePolicy) -> bool:
    """Read exact original dataclass field keys ONCE; never authorize grants."""
    try:
        snapshot = vars(policy).copy()
        if type(snapshot) is not dict or set(snapshot) != {
            "allow_private_lab", "require_authorization_for_public",
            "explicit_hosts", "explicit_networks",
        }:
            return False
        hosts = snapshot["explicit_hosts"]
        networks = snapshot["explicit_networks"]
        if (
            type(snapshot["allow_private_lab"]) is not bool
            or type(snapshot["require_authorization_for_public"]) is not bool
            or type(hosts) is not frozenset
            or type(networks) is not tuple
            or len(hosts) > 64
            or len(networks) > 64
        ):
            return False
        return all(
            type(host) is str and 0 < len(host) <= 512 for host in hosts
        ) and all(
            type(network) is str and 0 < len(network) <= 128
            for network in networks
        )
    except (AttributeError, TypeError, ValueError, KeyError):
        return False


def _reason_matches_host_kind(reason: ScopeReason, host: str) -> bool:
    """Lexical contradiction check only: not private-lab authorization."""
    try:
        addr = ip_address(host)
    except ValueError:
        addr = None
    if reason in {ScopeReason.PRIVATE_LAB, ScopeReason.EXPLICIT_NETWORK}:
        if addr is None:
            return False
        if reason is ScopeReason.PRIVATE_LAB and addr.is_global:
            return False
    if reason is ScopeReason.EXPLICIT_HOST and addr is not None:
        return False
    return True

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
        if not _exact_policy_configuration(policy):
            return _hold("invalid_policy_configuration")
        try:
            verdict = review_decision_shape(policy, target, decision)
            if verdict.status != "REVIEW_ONLY":
                return _hold("row_on_hold")
            # Only strings accepted by review_decision_shape reach here.
            host = decision.normalized_host
            if not _reason_matches_host_kind(decision.reason, host):
                return _hold("reason_host_kind_mismatch")
            if host in hosts:
                return _hold("duplicate_host")
            hosts.add(host)
        except Exception:
            return _hold("row_review_error")
    # This does not assert trust in policy origin, permissions or output.
    return CohortReview("REVIEW_ONLY", "coherent_shape_only", len(rows))
