from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from secrets import token_urlsafe

from .models import Authorization, Target
from .scope import ScopePolicy


class ActivationMode(str, Enum):
    PLAN_ONLY = "plan_only"
    LAB_ONLY = "lab_only"
    AUTHORIZED = "authorized"


@dataclass(frozen=True)
class ActivationPolicy:
    mode: ActivationMode = ActivationMode.PLAN_ONLY
    activation_reference: str | None = None

    def validate(self) -> None:
        if self.mode is ActivationMode.AUTHORIZED and not self.activation_reference:
            raise ValueError("authorized mode requires an explicit activation_reference")


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


class ActivationGate:
    """
    Policy gate for future active adapters.

    M0 ships no active adapters. Permits cannot substitute for source-record
    approval, authenticated consent, revocation-at-use, or a future adapter gate.
    """

    def __init__(self, scope_policy: ScopePolicy, activation_policy: ActivationPolicy):
        activation_policy.validate()
        self.scope_policy = scope_policy
        self.activation_policy = activation_policy

    def issue(self, target: Target, capability_id: str) -> ExecutionPermit:
        # Evaluate an independent canonical snapshot so a ScopePolicy callback
        # cannot change the original target/authorization during its own decision.
        snapshot = _target_authority_snapshot(target)
        decision = self.scope_policy.decide(snapshot)
        if not decision.allowed:
            raise PermissionError(f"target denied by scope gate: {decision.reason.value}")

        if self.activation_policy.mode is ActivationMode.PLAN_ONLY:
            raise PermissionError("active execution is disabled: project is plan-only")

        issued_at = datetime.now(timezone.utc)
        if self.activation_policy.mode is ActivationMode.LAB_ONLY:
            if decision.reason.value not in {"loopback", "private_lab"}:
                raise PermissionError("lab-only mode cannot issue permits for public targets")
            reference = self.activation_policy.activation_reference or "LAB"
        else:
            authorization = snapshot.authorization
            if (
                authorization is None
                or not authorization.owner.strip()
                or not authorization.reference.strip()
                or not authorization.is_current(issued_at)
            ):
                raise PermissionError("authorized execution requires current target authorization")
            reference = self.activation_policy.activation_reference or authorization.reference

        # Explicitly reject in-process mutation of the original fields while
        # the scope decision or permit construction was being prepared.
        if _target_authority_snapshot(snapshot) != snapshot:
            raise PermissionError("scope decision mutated the authority snapshot")
        if _target_authority_snapshot(target) != snapshot:
            raise PermissionError("target authorization changed during permit issuance")

        return ExecutionPermit(
            permit_id=token_urlsafe(24),
            target=decision.normalized_host or snapshot.value,
            capability_id=capability_id,
            mode=self.activation_policy.mode,
            activation_reference=reference,
            issued_at=issued_at,
        )
