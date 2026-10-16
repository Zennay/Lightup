"""Offline scope-decision *shape* review; NEVER a grant or execution gate.

Issue #1482. Not wired to ActivationGate, ScopePolicy or ToolExecutor.
A REVIEW_ONLY result is not proof that a policy/decision/target is trusted.
"""
from __future__ import annotations

from ipaddress import ip_address
from typing import NamedTuple

from .models import Target
from .scope import ScopeDecision, ScopePolicy, ScopeReason


class DecisionShapeReview(NamedTuple):
    status: str
    reason: str
    authorizes_execution: bool = False
    authorizes_release: bool = False


def _hold(reason: str) -> DecisionShapeReview:
    return DecisionShapeReview("HOLD", reason)


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ip_address(host).is_loopback
    except ValueError:
        return False


def review_decision_shape(
    policy: object, target: object, decision: object
) -> DecisionShapeReview:
    """Review exact primitive/enum shape without re-running a policy.

    There is intentionally NO permit/consent/tenant/grant/revocation decision
    here. Avoid calling user-provided policy methods, DNS, sockets, or I/O.
    The result MUST NOT be consumed as an allow bit.
    """
    if type(policy) is not ScopePolicy:
        return _hold("noncanonical_policy")
    if type(target) is not Target or type(decision) is not ScopeDecision:
        return _hold("noncanonical_envelope")
    try:
        value = target.value
        if type(value) is not str or not value or len(value) > 512:
            return _hold("invalid_target_value")
        allowed = decision.allowed
        reason = decision.reason
        normalized = decision.normalized_host
        if type(allowed) is not bool or type(reason) is not ScopeReason:
            return _hold("noncanonical_decision_fields")
        if normalized is not None and (
            type(normalized) is not str or not normalized or len(normalized) > 512
        ):
            return _hold("noncanonical_host")
        # This is a lexical sanity check, not trustworthy proof of scope.
        expected = ScopePolicy.normalize_host(value)
    except (AttributeError, TypeError, ValueError, UnicodeError):
        return _hold("incomplete_or_malformed_envelope")

    if expected is None or normalized != expected:
        return _hold("host_mismatch")

    allow_reasons = {
        ScopeReason.LOOPBACK,
        ScopeReason.PRIVATE_LAB,
        ScopeReason.EXPLICIT_HOST,
        ScopeReason.EXPLICIT_NETWORK,
    }
    if allowed != (reason in allow_reasons):
        return _hold("inconsistent_decision")
    if reason is ScopeReason.LOOPBACK and not _is_loopback(expected):
        return _hold("invalid_loopback_claim")
    if reason is ScopeReason.PRIVATE_LAB and _is_loopback(expected):
        return _hold("invalid_private_lab_claim")

    # Deliberately NEVER an authorization outcome, even for plausible inputs.
    return DecisionShapeReview("REVIEW_ONLY", "shape_well_formed")
