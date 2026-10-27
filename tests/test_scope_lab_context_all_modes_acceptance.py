"""Acceptance contract for canonical lab marker across all interaction modes.

This module is deliberately in-memory and contains no capability handlers.
Existing source owner: PR #163 / issue #162.
"""
import pytest
from lightup.engagements import RiskLevel
from lightup.execution_policy import ExecutionPolicy, ExecutionRequest, InteractionKind


@pytest.mark.parametrize("interaction,risk", [
    (InteractionKind.ANALYSIS, RiskLevel.ANALYSIS_ONLY),
    (InteractionKind.PASSIVE_PUBLIC, RiskLevel.PASSIVE),
    (InteractionKind.LAB_ACTIVE, RiskLevel.PASSIVE),
    (InteractionKind.TARGET_ACTIVE, RiskLevel.PASSIVE),
])
@pytest.mark.parametrize("invalid_lab_marker", [
    "false", "true", 0, 1, None, (), [], {}, object()
])
def test_all_interactions_reject_non_boolean_lab_marker(interaction, risk, invalid_lab_marker):
    request = ExecutionRequest(
        interaction=interaction,
        asset="example.invalid",
        capability_id="offline-noop",
        requested_risk=risk,
        is_lab=invalid_lab_marker,
    )
    result = ExecutionPolicy().decide(request)
    assert result.allowed is False


@pytest.mark.parametrize("interaction,risk,expected", [
    (InteractionKind.ANALYSIS, RiskLevel.ANALYSIS_ONLY, True),
    (InteractionKind.PASSIVE_PUBLIC, RiskLevel.PASSIVE, True),
    (InteractionKind.LAB_ACTIVE, RiskLevel.PASSIVE, False),
    (InteractionKind.TARGET_ACTIVE, RiskLevel.PASSIVE, False),
])
def test_canonical_false_preserves_existing_no_grant_results(interaction, risk, expected):
    result = ExecutionPolicy().decide(ExecutionRequest(
        interaction=interaction, asset="example.invalid",
        capability_id="offline-noop", requested_risk=risk, is_lab=False,
    ))
    assert result.allowed is expected
