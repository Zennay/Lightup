"""Fail-closed consumer for persisted ST5 remediation/retest plans.

Strict serialization parsing is composed with immediate live reconstruction so a
persisted plan cannot be consumed after its ST4 report, resolution, RunContext,
or StateStore lineage has drifted.
"""

from __future__ import annotations

from .ai.orchestration import RunContext
from .future_attack_path_graph_diff_preview import FutureAttackPathGraphDiffPreview
from .future_attack_path_security_delta_report import FutureAttackPathSecurityDeltaReport
from .future_attack_path_transition import FutureAttackPathTransitionProposal
from .future_attack_path_transition_resolution import (
    FutureAttackPathTransitionResolution,
)
from .future_security_remediation_retest_plan import (
    FutureSecurityRemediationRetestPlan,
    build_future_security_remediation_retest_plan,
)
from .future_security_remediation_retest_plan_handoff import (
    future_security_remediation_retest_plan_from_dict,
    future_security_remediation_retest_plan_from_json,
)
from .state import StateStore


def load_and_validate_future_security_remediation_retest_plan(
    persisted: object,
    report: FutureAttackPathSecurityDeltaReport,
    preview: FutureAttackPathGraphDiffPreview,
    proposal: FutureAttackPathTransitionProposal,
    resolutions: tuple[FutureAttackPathTransitionResolution, ...],
    contexts: tuple[RunContext, ...],
    state: StateStore,
) -> FutureSecurityRemediationRetestPlan:
    """Strictly parse one persisted plan and immediately require live validity."""

    if isinstance(persisted, str):
        parsed = future_security_remediation_retest_plan_from_json(persisted)
    elif isinstance(persisted, dict):
        parsed = future_security_remediation_retest_plan_from_dict(persisted)
    else:
        raise ValueError(
            "remediation/retest plan persisted value must be JSON text or object"
        )

    live = build_future_security_remediation_retest_plan(
        report,
        preview,
        proposal,
        resolutions,
        contexts,
        state,
    )
    if parsed != live:
        raise ValueError(
            "persisted remediation/retest plan does not match live lineage rebuild"
        )
    return parsed
