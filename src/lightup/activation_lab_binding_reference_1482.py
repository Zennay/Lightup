"""Synthetic-only LAB_ONLY decision binding reference for #1482.

UNWIRED: no ExecutionPermit, tokens, grants, active handlers, external targets,
customer identity, DNS, network or database. REVIEW_ONLY never authorizes use.
This independent lexical reference does not prove the installed source is trusted.
"""
from __future__ import annotations

from typing import NamedTuple

from .activation_decision_cohort_review_1482 import _exact_policy_configuration
from .activation import ActivationMode, ActivationPolicy
from .models import Target
from .scope import ScopeDecision, ScopePolicy, ScopeReason


class LabBindingReview(NamedTuple):
    status: str
    reason: str
    authorizes_execution: bool = False
    authorizes_release: bool = False


def _hold(reason: str) -> LabBindingReview:
    return LabBindingReview("HOLD", reason)


def _fictional_name(host: str) -> bool:
    if not host.endswith(".example.test") or len(host) > 253:
        return False
    labels = host.split(".")
    return (
        len(labels) >= 3
        and labels[-2:] == ["example", "test"]
        and all(
            label and len(label) <= 63
            and label[0] != "-" and label[-1] != "-"
            and all(ch in "abcdefghijklmnopqrstuvwxyz0123456789-" for ch in label)
            for label in labels
        )
    )


def review_lab_binding(
    scope_policy: object,
    activation_policy: object,
    target: object,
    claimed_decision: object,
) -> LabBindingReview:
    """Compare a caller claim against a deliberately tiny lexical lab model.

    Only exact localhost / 127.0.0.1 and .example.test, no authorization,
    labels, private-lab networks or real target interaction. Never call
    policy.decide; this models expected shape independently of the runtime.
    """
    if type(scope_policy) is not ScopePolicy or not _exact_policy_configuration(scope_policy):
        return _hold("invalid_scope_policy")
    if type(activation_policy) is not ActivationPolicy:
        return _hold("invalid_activation_policy")
    try:
        fields = vars(activation_policy).copy()
        if set(fields) != {"mode", "activation_reference"}:
            return _hold("activation_field_integrity")
        ref = fields["activation_reference"]
        if (
            fields["mode"] is not ActivationMode.LAB_ONLY
            or type(ref) is not str
            or not 1 <= len(ref) <= 64
            or any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for ch in ref)
        ):
            return _hold("invalid_lab_activation")
    except (AttributeError, TypeError, ValueError):
        return _hold("activation_field_integrity")

    if type(target) is not Target or type(claimed_decision) is not ScopeDecision:
        return _hold("invalid_envelope")
    try:
        fields = vars(target).copy()
        if set(fields) != {"value", "authorization", "labels"}:
            return _hold("target_field_integrity")
        value = fields["value"]
        if type(value) is not str or not (
            value in ("localhost", "127.0.0.1") or _fictional_name(value)
        ):
            return _hold("nonfictional_target")
        if fields["authorization"] is not None or type(fields["labels"]) is not tuple or fields["labels"]:
            return _hold("target_authority_not_allowed")
        conf = vars(scope_policy).copy()
        if (
            conf["allow_private_lab"] is not False
            or conf["require_authorization_for_public"] is not True
            or conf["explicit_networks"] != ()
            or not all(_fictional_name(host) for host in conf["explicit_hosts"])
        ):
            return _hold("non_synthetic_lab_policy")
        result = vars(claimed_decision).copy()
        if set(result) != {"allowed", "normalized_host", "reason"}:
            return _hold("decision_field_integrity")
        if type(result["allowed"]) is not bool or type(result["reason"]) is not ScopeReason:
            return _hold("decision_type_confusion")
        if type(result["normalized_host"]) is not str or result["normalized_host"] != value:
            return _hold("decision_target_mismatch")
        is_loopback = value in ("localhost", "127.0.0.1")
        expected_allowed = is_loopback
        expected_reason = (
            ScopeReason.LOOPBACK if is_loopback else
            ScopeReason.AUTHORIZATION_MISSING if value in conf["explicit_hosts"] else
            ScopeReason.OUT_OF_SCOPE
        )
        if result["allowed"] is not expected_allowed or result["reason"] is not expected_reason:
            return _hold("decision_policy_mismatch")
    except (AttributeError, KeyError, TypeError, ValueError):
        return _hold("malformed_synthetic_envelope")

    # This is a shape comparison, NOT an authorization or validated consent.
    return LabBindingReview("REVIEW_ONLY", "synthetic_decision_matches")
