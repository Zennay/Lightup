"""Opt-in, non-authorizing ActivationGate lifetime review for #1476.

The *real* ActivationGate is owned elsewhere. This module never constructs
or invokes a permit, authorization grant, tool, network adapter, or handler.
It only detects in-process policy rebinding/drift between two observations.
A REVIEW_ONLY receipt is NOT an execution or release permission.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Literal

from .activation import ActivationGate, ActivationMode, ActivationPolicy
from .scope import ScopePolicy


_MAX_COLLECTION_ITEMS = 256
_MAX_TEXT_LENGTH = 2048


class LifetimeStatus(str, Enum):
    HOLD = "HOLD"
    REVIEW_ONLY = "REVIEW_ONLY"


@dataclass(frozen=True, slots=True)
class LifetimeReceipt:
    status: LifetimeStatus
    reason: Literal["invalid_input", "changed", "unchanged"]
    may_issue_permit: bool = False
    may_issue_grant: bool = False
    may_dispatch: bool = False
    may_scan: bool = False
    may_deploy: bool = False
    may_release: bool = False


@dataclass(frozen=True, slots=True, repr=False)
class PinnedGateReview:
    """Strong references, not a token, authorization or unforgeable lock.

    These are deliberately held inside the process only. Neither exporting
    them nor a standalone review result permits a target interaction.
    """

    gate: ActivationGate = field(repr=False)
    scope: ScopePolicy = field(repr=False)
    activation: ActivationPolicy = field(repr=False)
    scope_fields: tuple[object, ...] = field(repr=False)
    activation_fields: tuple[object, ...] = field(repr=False)


def _bounded_text(value: object) -> bool:
    return type(value) is str and 0 < len(value) <= _MAX_TEXT_LENGTH


def _scope_fields(scope: object) -> tuple[object, ...] | None:
    if type(scope) is not ScopePolicy:
        return None
    # Frozen dataclasses expose class defaults after an instance attribute
    # is deleted. Reject missing (or injected) instance fields explicitly
    # before reading their values; getattr alone would silently mask drift.
    if set(vars(scope)) != {
        "allow_private_lab", "explicit_hosts", "explicit_networks",
        "require_authorization_for_public",
    }:
        return None
    if type(scope.allow_private_lab) is not bool:
        return None
    if type(scope.require_authorization_for_public) is not bool:
        return None
    hosts = scope.explicit_hosts
    nets = scope.explicit_networks
    if type(hosts) is not frozenset or type(nets) is not tuple:
        return None
    if len(hosts) > _MAX_COLLECTION_ITEMS or len(nets) > _MAX_COLLECTION_ITEMS:
        return None
    if not all(_bounded_text(v) for v in hosts):
        return None
    if not all(_bounded_text(v) for v in nets):
        return None
    # Sorting is solely to compare unchanged immutable metadata. It is
    # intentionally NOT a normalization, DNS check or scope decision.
    return (
        scope.allow_private_lab,
        tuple(sorted(hosts)),
        nets,
        scope.require_authorization_for_public,
    )


def _activation_fields(policy: object) -> tuple[object, ...] | None:
    if type(policy) is not ActivationPolicy:
        return None
    if set(vars(policy)) != {"mode", "activation_reference"}:
        return None
    if type(policy.mode) is not ActivationMode:
        return None
    ref = policy.activation_reference
    if ref is not None and not _bounded_text(ref):
        return None
    if policy.mode is ActivationMode.AUTHORIZED and ref is None:
        return None
    return (policy.mode, ref)


def _hold(reason: Literal["invalid_input", "changed"]) -> LifetimeReceipt:
    return LifetimeReceipt(status=LifetimeStatus.HOLD, reason=reason)


def pin_gate_for_offline_review(gate: object) -> PinnedGateReview | None:
    """Snapshot only exact, bounded, structurally coherent source instances.

    Not a policy authorization decision and never a reference to a live
    grant. Mutable/swappable configuration is not repaired by this helper.
    """
    if type(gate) is not ActivationGate:
        return None
    if set(vars(gate)) != {"scope_policy", "activation_policy"}:
        return None
    try:
        scope = object.__getattribute__(gate, "scope_policy")
        activation = object.__getattribute__(gate, "activation_policy")
        scope_fields = _scope_fields(scope)
        activation_fields = _activation_fields(activation)
    except (AttributeError, TypeError, ValueError):
        # Incomplete/externally corrupted gate objects cannot produce a pin.
        return None
    if scope_fields is None or activation_fields is None:
        return None
    return PinnedGateReview(
        gate=gate,
        scope=scope,
        activation=activation,
        scope_fields=scope_fields,
        activation_fields=activation_fields,
    )


def review_gate_lifetime(
    gate: object, pin: object,
) -> LifetimeReceipt:
    """Review unchanged lifetime at this instant; always deny authority.

    A result is observational only and may become stale immediately. It
    must never be used as a check-then-execute bypass for the real gates.
    """
    if type(gate) is not ActivationGate or type(pin) is not PinnedGateReview:
        return _hold("invalid_input")
    if set(vars(gate)) != {"scope_policy", "activation_policy"}:
        return _hold("changed")
    if gate is not pin.gate:
        return _hold("changed")
    try:
        scope = object.__getattribute__(gate, "scope_policy")
        activation = object.__getattribute__(gate, "activation_policy")
        if scope is not pin.scope or activation is not pin.activation:
            return _hold("changed")
        if (_scope_fields(scope) != pin.scope_fields or
                _activation_fields(activation) != pin.activation_fields):
            return _hold("changed")
    except (AttributeError, TypeError, ValueError):
        # A removed source field is a generic HOLD, never an exception leak.
        return _hold("changed")
    return LifetimeReceipt(status=LifetimeStatus.REVIEW_ONLY, reason="unchanged")
