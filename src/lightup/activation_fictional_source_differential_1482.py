"""Synthetic-only, opt-in installed-source differential for issue #1482.

Separate from shape/batch review. Unlike those no-callback helpers, THIS
function deliberately calls the current in-process ScopePolicy.decide ONCE,
but only after rejecting anything beyond localhost/loopback and invented
*.example.test targets with no authorization or private/network admission.
It never issues a permit, grant, scan, dispatch or release authority.
"""
from __future__ import annotations

from typing import NamedTuple

from .activation_decision_cohort_review_1482 import _exact_policy_configuration
from .models import Target
from .scope import ScopeDecision, ScopePolicy


class SourceDifferentialReview(NamedTuple):
    status: str
    reason: str
    authorizes_execution: bool = False
    authorizes_release: bool = False


def _hold(reason: str) -> SourceDifferentialReview:
    return SourceDifferentialReview("HOLD", reason)


def _fictional_host(value: str) -> bool:
    if value in {"localhost", "127.0.0.1"}:
        return True
    if not value.endswith(".example.test"):
        return False
    if len(value) > 256 or value != value.lower():
        return False
    if any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-." for c in value):
        return False
    parts = value.split(".")
    return (
        len(parts) >= 3 and parts[-2:] == ["example", "test"]
        and all(p and len(p) <= 63 and p[0] != "-" and p[-1] != "-" for p in parts)
    )


def review_fictional_installed_scope_decision(
    policy: object, target: object, claimed: object
) -> SourceDifferentialReview:
    """Only check an exact synthetic original-source decision against a claim.

    Output is NEVER a trustworthy authorization, even when REVIEW_ONLY.
    Original source integrity, trusted scope, operator/tenant/asset consent,
    revocation and target execution MUST be reviewed separately.
    """
    if type(policy) is not ScopePolicy or not _exact_policy_configuration(policy):
        return _hold("invalid_policy")
    if type(target) is not Target or type(claimed) is not ScopeDecision:
        return _hold("invalid_envelope")
    try:
        host = target.value
        if type(host) is not str or not _fictional_host(host):
            return _hold("nonfictional_target")
        if target.authorization is not None or target.labels != ():
            return _hold("untrusted_target_metadata")
        if (
            policy.allow_private_lab is not False
            or policy.require_authorization_for_public is not True
            or policy.explicit_networks != ()
            or not all(_fictional_host(h) and h.endswith(".example.test")
                       for h in policy.explicit_hosts)
        ):
            return _hold("policy_outside_synthetic_lab")
        # Exact original method, only on restricted in-memory invented data.
        actual = policy.decide(target)
        if type(actual) is not ScopeDecision:
            return _hold("noncanonical_source_decision")
        if (
            type(actual.allowed) is not bool
            or type(claimed.allowed) is not bool
            or type(actual.reason) is not type(claimed.reason)
            or type(actual.normalized_host) is not str
            or type(claimed.normalized_host) is not str
            or actual.allowed is not claimed.allowed
            or actual.reason is not claimed.reason
            or actual.normalized_host != claimed.normalized_host
        ):
            return _hold("source_claim_mismatch")
    except Exception:
        return _hold("source_review_error")
    return SourceDifferentialReview("REVIEW_ONLY", "fictional_source_matches_claim")
