from __future__ import annotations

from dataclasses import asdict, dataclass

from .capabilities import CapabilityState, get_capabilities
from .models import Target
from .scope import ScopeDecision, ScopePolicy, ScopeReason


class ExecutionDisabled(RuntimeError):
    pass


_ALLOWED_SCOPE_REASONS = frozenset(
    {
        ScopeReason.LOOPBACK,
        ScopeReason.PRIVATE_LAB,
        ScopeReason.EXPLICIT_HOST,
        ScopeReason.EXPLICIT_NETWORK,
    }
)
_LAB_SCOPE_REASONS = frozenset({ScopeReason.LOOPBACK, ScopeReason.PRIVATE_LAB})


@dataclass(frozen=True)
class AssessmentPlan:
    target: str
    scope: ScopeDecision
    capability_ids: tuple[str, ...]
    execution_enabled: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.scope, ScopeDecision):
            raise TypeError("scope must be a ScopeDecision")
        if type(self.scope.allowed) is not bool:
            raise TypeError("scope.allowed must be a boolean")
        if not isinstance(self.scope.reason, ScopeReason):
            raise TypeError("scope.reason must be a ScopeReason")
        if self.execution_enabled is not False:
            raise ValueError("assessment plans are plan-only; execution_enabled must be false")
        if type(self.capability_ids) is not tuple:
            raise TypeError("capability_ids must be a tuple")

        if self.scope.allowed != (self.scope.reason in _ALLOWED_SCOPE_REASONS):
            raise ValueError("scope decision has incoherent allow/reason metadata")
        if not self.scope.allowed:
            if self.capability_ids:
                raise ValueError("denied assessment plans cannot carry capabilities")
            return

        if any(type(capability_id) is not str or not capability_id for capability_id in self.capability_ids):
            raise ValueError("capability_ids must contain non-empty strings")
        if len(set(self.capability_ids)) != len(self.capability_ids):
            raise ValueError("assessment plans cannot contain duplicate capability IDs")

        registry = {}
        for capability in get_capabilities():
            if capability.capability_id in registry:
                raise ValueError("capability registry contains duplicate capability IDs")
            registry[capability.capability_id] = capability

        for capability_id in self.capability_ids:
            capability = registry.get(capability_id)
            if capability is None:
                raise ValueError(f"unknown capability ID: {capability_id}")
            if capability.state is CapabilityState.DISABLED:
                raise ValueError(f"disabled capability cannot be planned: {capability_id}")
            if capability.state is CapabilityState.LAB_ONLY and self.scope.reason not in _LAB_SCOPE_REASONS:
                raise ValueError(
                    f"lab-only capability cannot be used for public scope: {capability_id}"
                )
            if capability.state not in {CapabilityState.PLANNING, CapabilityState.LAB_ONLY}:
                raise ValueError(f"unsupported capability state: {capability_id}")

    def to_dict(self) -> dict:
        data = asdict(self)
        data["scope"]["reason"] = self.scope.reason.value
        return data


class Planner:
    def __init__(self, scope_policy: ScopePolicy):
        self.scope_policy = scope_policy

    def build(self, target: Target) -> AssessmentPlan:
        decision = self.scope_policy.decide(target)
        if decision.allowed != (decision.reason in _ALLOWED_SCOPE_REASONS):
            raise ValueError("scope policy returned an inconsistent allow decision")
        if not decision.allowed:
            return AssessmentPlan(target.value, decision, ())
        allowed_states = {CapabilityState.PLANNING}
        if decision.reason in _LAB_SCOPE_REASONS:
            allowed_states.add(CapabilityState.LAB_ONLY)
        capabilities = tuple(
            item.capability_id
            for item in get_capabilities()
            if item.state in allowed_states
        )
        return AssessmentPlan(target.value, decision, capabilities)


class NetworkExecutor:
    """M0 hard stop: active target interaction does not exist yet."""

    def execute(self, *_args, **_kwargs):
        raise ExecutionDisabled(
            "LightUp M0 is plan-only. Active network execution requires a later explicit activation."
        )
