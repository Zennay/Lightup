"""Offline reference only: emergency signals cannot mint positive authority.

Not wired into LightUp runtime or external targets.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class EmergencyDecision:
    allow_dispatch: bool
    require_normal_gate: bool
    reason: str


def emergency_boundary(*, stop_active: bool, override_requested: bool,
                       normal_gate_allowed: bool) -> EmergencyDecision:
    for value in (stop_active, override_requested, normal_gate_allowed):
        if type(value) is not bool:
            return EmergencyDecision(False, False, "invalid_emergency_input")
    if stop_active:
        return EmergencyDecision(False, False, "emergency_stop")
    if override_requested and not normal_gate_allowed:
        return EmergencyDecision(False, False, "override_not_authority")
    if not normal_gate_allowed:
        return EmergencyDecision(False, False, "normal_gate_denied")
    return EmergencyDecision(True, True, "normal_gate_only")
