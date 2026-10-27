"""Offline expected-RED regression: LAB_ACTIVE requires an exact boolean lab attestation.

No network, handler, target, or runtime capability execution is performed.
"""
import pytest

from lightup.engagements import RiskLevel
from lightup.execution_policy import ExecutionPolicy, ExecutionRequest, InteractionKind


@pytest.mark.parametrize("invalid_lab_flag", [1, "yes", [True], {"lab": True}, object()])
def test_lab_active_rejects_noncanonical_truthy_lab_flags(invalid_lab_flag):
    request = ExecutionRequest(
        interaction=InteractionKind.LAB_ACTIVE,
        asset="local-fixture.invalid",
        capability_id="offline-fixture",
        requested_risk=RiskLevel.ANALYSIS_ONLY,
        is_lab=invalid_lab_flag,
    )
    decision = ExecutionPolicy().decide(request)
    assert decision.allowed is False


def test_lab_active_accepts_canonical_true_lab_flag():
    request = ExecutionRequest(
        interaction=InteractionKind.LAB_ACTIVE,
        asset="local-fixture.invalid",
        capability_id="offline-fixture",
        requested_risk=RiskLevel.ANALYSIS_ONLY,
        is_lab=True,
    )
    assert ExecutionPolicy().decide(request).allowed is True


def test_lab_active_rejects_canonical_false_lab_flag():
    request = ExecutionRequest(
        interaction=InteractionKind.LAB_ACTIVE,
        asset="local-fixture.invalid",
        capability_id="offline-fixture",
        requested_risk=RiskLevel.ANALYSIS_ONLY,
        is_lab=False,
    )
    assert ExecutionPolicy().decide(request).allowed is False
