from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from secrets import token_urlsafe
from re import fullmatch

from .capabilities import get_capabilities
from .models import Authorization, Target
from .scope import ScopeDecision, ScopePolicy, ScopeReason


class ActivationMode(str, Enum):
    PLAN_ONLY = "plan_only"
    LAB_ONLY = "lab_only"
    AUTHORIZED = "authorized"


@dataclass(frozen=True)
class ActivationPolicy:
    mode: ActivationMode = ActivationMode.PLAN_ONLY
    activation_reference: str | None = None

    def validate(self) -> None:
        if type(self.mode) is not ActivationMode:
            raise ValueError("activation mode must be a canonical ActivationMode")
        if self.mode in (ActivationMode.AUTHORIZED, ActivationMode.LAB_ONLY):
            reference = self.activation_reference
            if (
                type(reference) is not str or not reference.strip()
                or reference != reference.strip()
                or len(reference) > 256
                or any(ord(char) < 33 or ord(char) == 127 for char in reference)
            ):
                raise ValueError(
                    "active modes require an explicit canonical activation_reference"
                )


@dataclass(frozen=True)
class ExecutionPermit:
    permit_id: str
    target: str
    capability_id: str
    mode: ActivationMode
    activation_reference: str
    issued_at: datetime


def _target_authority_snapshot(target: Target) -> Target:
    """Capture only canonical builtin identity fields, not caller-controlled methods.

    Both passes are deliberately independent of Authorization subclasses,
    polymorphic equality hooks and arbitrary Target attribute implementations.
    This is an issuance-time identity check, NOT an execution-time authorization.
    """
    if type(target) is not Target or type(target.value) is not str:
        raise PermissionError("target identity is not canonical")

    authorization = target.authorization
    if authorization is None:
        return Target(value=target.value)
    if type(authorization) is not Authorization:
        raise PermissionError("authorization identity is not canonical")

    owner, reference = authorization.owner, authorization.reference
    valid_from, valid_until = authorization.valid_from, authorization.valid_until
    if type(owner) is not str or type(reference) is not str:
        raise PermissionError("authorization provenance is not canonical")
    for bound in (valid_from, valid_until):
        if bound is not None and (
            type(bound) is not datetime or bound.tzinfo is None
            or bound.utcoffset() is None
        ):
            raise PermissionError("authorization window is not a canonical aware datetime")

    return Target(
        value=target.value,
        authorization=Authorization(
            owner=owner,
            reference=reference,
            valid_from=valid_from,
            valid_until=valid_until,
        ),
    )


def _scope_policy_snapshot(policy: ScopePolicy) -> ScopePolicy:
    """Read a strictly canonical immutable scope policy before making a decision."""
    if (
        type(policy) is not ScopePolicy
        or type(policy.allow_private_lab) is not bool
        or type(policy.require_authorization_for_public) is not bool
        or type(policy.explicit_hosts) is not frozenset
        or type(policy.explicit_networks) is not tuple
        or any(type(host) is not str for host in policy.explicit_hosts)
        or any(type(network) is not str for network in policy.explicit_networks)
    ):
        raise PermissionError("scope policy is not canonical")
    return ScopePolicy(
        allow_private_lab=policy.allow_private_lab,
        explicit_hosts=frozenset(policy.explicit_hosts),
        explicit_networks=tuple(policy.explicit_networks),
        require_authorization_for_public=policy.require_authorization_for_public,
    )


def _activation_policy_snapshot(policy: ActivationPolicy) -> ActivationPolicy:
    # A frozen dataclass may still be changed through object.__setattr__.
    if type(policy) is not ActivationPolicy or type(policy.mode) is not ActivationMode:
        raise PermissionError("activation policy mode is not canonical")
    reference = policy.activation_reference
    if reference is not None and (
        type(reference) is not str or not reference.strip()
    ):
        raise PermissionError("activation policy reference is not canonical")
    return ActivationPolicy(mode=policy.mode, activation_reference=reference)


class ActivationGate:
    """
    Policy gate for future active adapters.

    M0 ships no active adapters. Permits cannot substitute for source-record
    approval, authenticated consent, revocation-at-use, or a future adapter gate.
    """

    __slots__ = (
        "scope_policy", "activation_policy", "_bound_scope_policy",
        "_bound_activation_policy", "_bound_scope_values",
        "_bound_activation_values", "_sealed",
    )

    def __setattr__(self, name: str, value: object) -> None:
        # Read-only once fully constructed: ordinary Python attribute assignment
        # must not widen an already approved/created activation gate.
        if getattr(self, "_sealed", False):
            raise AttributeError("activation gate policies are immutable after construction")
        object.__setattr__(self, name, value)

    def __init__(self, scope_policy: ScopePolicy, activation_policy: ActivationPolicy):
        # Validate exact source types BEFORE calling caller-controlled methods.
        bound_scope = _scope_policy_snapshot(scope_policy)
        bound_activation = _activation_policy_snapshot(activation_policy)
        bound_activation.validate()
        self.scope_policy = scope_policy
        self.activation_policy = activation_policy
        # Retain original object identity and immutable contents.
        self._bound_scope_policy = scope_policy
        self._bound_activation_policy = activation_policy
        self._bound_scope_values = bound_scope
        self._bound_activation_values = bound_activation
        self._sealed = True

    def issue(self, target: Target, capability_id: str) -> ExecutionPermit:
        # Evaluate an independent canonical snapshot so a ScopePolicy callback
        # cannot change the original target/authorization during its own decision.
        if (
            type(capability_id) is not str
            or not 1 <= len(capability_id) <= 128
            or fullmatch(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*", capability_id) is None
        ):
            raise PermissionError("capability identity is not canonical")
        # A syntactically valid invented ID is not automatically an installed
        # capability: the registry is an identity inventory, not permission.
        if capability_id not in {
            item.capability_id for item in get_capabilities()
            if type(item.capability_id) is str
        }:
            raise PermissionError("capability is not registered")
        if (
            self.scope_policy is not self._bound_scope_policy
            or self.activation_policy is not self._bound_activation_policy
        ):
            raise PermissionError("activation gate policy binding changed")
        activation = _activation_policy_snapshot(self.activation_policy)
        scope = _scope_policy_snapshot(self.scope_policy)
        if (
            activation != self._bound_activation_values
            or scope != self._bound_scope_values
        ):
            raise PermissionError("activation gate policy contents changed")
        # Preserve object provenance as well as field values: swapping an
        # otherwise identical Authorization instance is still identity drift.
        caller_authorization = target.authorization
        snapshot = _target_authority_snapshot(target)
        if target.authorization is not caller_authorization:
            raise PermissionError("target authorization identity changed before scope decision")
        snapshot_authorization = snapshot.authorization
        decision = scope.decide(snapshot)
        # A policy response is an input to permit issuance, not authority by
        # annotation alone. Reject forged/noncanonical results before reading it.
        expected_host = ScopePolicy.normalize_host(snapshot.value)
        if (
            type(decision) is not ScopeDecision
            or type(decision.allowed) is not bool
            or type(decision.reason) is not ScopeReason
            or type(decision.normalized_host) is not str
            or expected_host is None
            or decision.normalized_host != expected_host
        ):
            raise PermissionError("scope policy returned a noncanonical decision")
        if not decision.allowed:
            raise PermissionError(f"target denied by scope gate: {decision.reason.value}")

        if activation.mode is ActivationMode.PLAN_ONLY:
            raise PermissionError("active execution is disabled: project is plan-only")

        issued_at = datetime.now(timezone.utc)
        if activation.mode is ActivationMode.LAB_ONLY:
            if decision.reason.value not in {"loopback", "private_lab"}:
                raise PermissionError("lab-only mode cannot issue permits for public targets")
            # Never synthesize a generic, untraceable LAB provenance.
            reference = activation.activation_reference
            if reference is None:
                raise PermissionError("lab execution needs explicit provenance")
        else:
            authorization = snapshot.authorization
            if (
                authorization is None
                or not authorization.owner.strip()
                or not authorization.reference.strip()
                or not authorization.is_current(issued_at)
            ):
                raise PermissionError("authorized execution requires current target authorization")
            reference = activation.activation_reference or authorization.reference

        # Explicitly reject in-process mutation of the original fields while
        # the scope decision or permit construction was being prepared.
        if (
            snapshot.authorization is not snapshot_authorization
            or _target_authority_snapshot(snapshot) != snapshot
        ):
            raise PermissionError("scope decision mutated the authority snapshot")
        if (
            target.authorization is not caller_authorization
            or _target_authority_snapshot(target) != snapshot
        ):
            raise PermissionError("target authorization changed during permit issuance")

        if (
            self.scope_policy is not self._bound_scope_policy
            or self.activation_policy is not self._bound_activation_policy
            or _scope_policy_snapshot(self.scope_policy) != scope
            or _activation_policy_snapshot(self.activation_policy) != activation
        ):
            raise PermissionError("gate policy changed during permit issuance")

        return ExecutionPermit(
            permit_id=token_urlsafe(24),
            target=decision.normalized_host or snapshot.value,
            capability_id=capability_id,
            mode=activation.mode,
            activation_reference=reference,
            issued_at=issued_at,
        )
