"""Offline acceptance: lab-only permission requires a canonical boolean lab flag.

This is a RED contract against implementations that use truthiness for is_lab.
No real target, handler, network operation or filesystem side effect is involved.
"""
import pytest

from lightup.engagements import RiskLevel
from lightup.execution_policy import ExecutionPolicy, ExecutionRequest, InteractionKind


@pytest.mark.parametrize("is_lab", ["true", "false", 1, -1, [], [1], {"lab": True}, object()])
def test_lab_active_never_accepts_non_boolean_lab_context(is_lab):
    decision = ExecutionPolicy().decide(
        ExecutionRequest(
            interaction=InteractionKind.LAB_ACTIVE,
            asset="example.invalid",
            capability_id="offline-noop",
            requested_risk=RiskLevel.PASSIVE,
            is_lab=is_lab,
        )
    )
    assert decision.allowed is False


def test_lab_active_allows_explicit_true_lab_context():
    decision = ExecutionPolicy().decide(
        ExecutionRequest(
            interaction=InteractionKind.LAB_ACTIVE,
            asset="example.invalid",
            capability_id="offline-noop",
            requested_risk=RiskLevel.PASSIVE,
            is_lab=True,
        )
    )
    assert decision.allowed is True


def test_lab_active_rejects_explicit_false_lab_context():
    decision = ExecutionPolicy().decide(
        ExecutionRequest(
            interaction=InteractionKind.LAB_ACTIVE,
            asset="example.invalid",
            capability_id="offline-noop",
            requested_risk=RiskLevel.PASSIVE,
            is_lab=False,
        )
    )
    assert decision.allowed is False
