"""Evidence-complete ST6 isolated future-state retest request.

This module turns a live-revalidated ST5 remediation/retest plan into an
immutable *request* for an isolated future-state retest. A request is not an
authorization: it grants no execution, deployment or target access, and it
must still pass its own scope, authorization and tool-policy gates before any
later package may act on it.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json

from .ai.orchestration import RunContext
from .future_attack_path_graph_diff_preview import (
    AttackPathGraphDiffAction,
    FutureAttackPathGraphDiffPreview,
)
from .future_attack_path_security_delta_report import (
    FutureAttackPathSecurityDeltaReport,
)
from .future_attack_path_transition import FutureAttackPathTransitionProposal
from .future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
    FutureAttackPathTransitionResolution,
)
from .future_security_remediation_retest_plan import (
    FutureRemediationNextAction,
    FutureSecurityRemediationRetestPlan,
    build_future_security_remediation_retest_plan,
)
from .state import StateStore


REQUEST_SCHEMA_VERSION = "st6.future_state_retest_request.v1"


@dataclass(frozen=True)
class FutureStateRetestRequestItem:
    change_node_id: str
    subject_node_id: str
    resolution_id: str
    resolution_sha256: str
    classification: AttackPathTransitionClassification
    graph_diff_action: AttackPathGraphDiffAction
    # True when a remediation must land before this retest may be scheduled.
    blocked_on_remediation: bool
    current_attack_path_ids: tuple[str, ...]
    effect_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    capability_ids: tuple[str, ...]

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class FutureStateRetestRequest:
    schema_version: str
    client_id: str
    current_twin_id: str
    current_twin_version: int
    twin_id: str
    twin_version: int
    changeset_id: str
    proposal_sha256: str
    impact_analysis_sha256: str
    preview_sha256: str
    report_sha256: str
    plan_sha256: str
    items: tuple[FutureStateRetestRequestItem, ...]
    retest_item_count: int
    blocked_on_remediation_count: int
    request_sha256: str
    # Isolation is a hard requirement of the request, not a preference.
    isolated_environment_required: bool = True
    scope_gate_required: bool = True
    authorization_gate_required: bool = True
    tool_policy_gate_required: bool = True
    real_target_interaction_allowed: bool = False
    execution_allowed: bool = False
    deployment_authorized: bool = False
    attack_path_mutation_allowed: bool = False
    future_semantics: str = "unresolved"
    security_verdict: str = "not_evaluated"

    def as_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(
            self.as_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )


def _request_digest(
    *,
    plan: FutureSecurityRemediationRetestPlan,
    items: tuple[FutureStateRetestRequestItem, ...],
    blocked_on_remediation_count: int,
) -> str:
    payload = {
        "schema_version": REQUEST_SCHEMA_VERSION,
        "client_id": plan.client_id,
        "current_twin_id": plan.current_twin_id,
        "current_twin_version": plan.current_twin_version,
        "twin_id": plan.twin_id,
        "twin_version": plan.twin_version,
        "changeset_id": plan.changeset_id,
        "proposal_sha256": plan.proposal_sha256,
        "impact_analysis_sha256": plan.impact_analysis_sha256,
        "preview_sha256": plan.preview_sha256,
        "report_sha256": plan.report_sha256,
        "plan_sha256": plan.plan_sha256,
        "items": [
            {
                "change_node_id": item.change_node_id,
                "subject_node_id": item.subject_node_id,
                "resolution_id": item.resolution_id,
                "resolution_sha256": item.resolution_sha256,
                "classification": item.classification.value,
                "graph_diff_action": item.graph_diff_action.value,
                "blocked_on_remediation": item.blocked_on_remediation,
                "current_attack_path_ids": list(item.current_attack_path_ids),
                "effect_ids": list(item.effect_ids),
                "evidence_ids": list(item.evidence_ids),
                "capability_ids": list(item.capability_ids),
            }
            for item in items
        ],
        "retest_item_count": len(items),
        "blocked_on_remediation_count": blocked_on_remediation_count,
        "isolated_environment_required": True,
        "scope_gate_required": True,
        "authorization_gate_required": True,
        "tool_policy_gate_required": True,
        "real_target_interaction_allowed": False,
        "execution_allowed": False,
        "deployment_authorized": False,
        "attack_path_mutation_allowed": False,
        "future_semantics": "unresolved",
        "security_verdict": "not_evaluated",
    }
    return sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def build_future_state_retest_request(
    plan: FutureSecurityRemediationRetestPlan,
    report: FutureAttackPathSecurityDeltaReport,
    preview: FutureAttackPathGraphDiffPreview,
    proposal: FutureAttackPathTransitionProposal,
    resolutions: tuple[FutureAttackPathTransitionResolution, ...],
    contexts: tuple[RunContext, ...],
    state: StateStore,
) -> FutureStateRetestRequest:
    """Build an immutable isolated retest request from a live-validated plan."""

    live_plan = build_future_security_remediation_retest_plan(
        report,
        preview,
        proposal,
        resolutions,
        contexts,
        state,
    )
    if plan != live_plan:
        raise ValueError(
            "remediation/retest plan is stale, tampered, cross-tenant, or lineage-drifted"
        )
    if not plan.plan_complete:
        raise ValueError("retest request requires a complete plan")
    if plan.contains_insufficient_evidence or plan.evidence_gap_count:
        raise ValueError(
            "retest request requires an evidence-complete plan; collect more evidence first"
        )
    if (
        plan.execution_allowed
        or plan.deployment_authorized
        or plan.attack_path_mutation_allowed
    ):
        raise ValueError("plan must not carry execution, deployment or mutation rights")
    if plan.future_semantics != "unresolved":
        raise ValueError("plan future_semantics must remain unresolved")
    if plan.security_verdict != "not_evaluated":
        raise ValueError("plan must not precompute a security verdict")

    request_items: list[FutureStateRetestRequestItem] = []
    for item in plan.items:
        if item.evidence_required or (
            item.next_action is FutureRemediationNextAction.COLLECT_MORE_EVIDENCE
        ):
            raise ValueError("plan item still requires evidence collection")
        if not item.future_state_retest_required:
            raise ValueError("evidence-complete plan item must require a retest")
        request_items.append(
            FutureStateRetestRequestItem(
                change_node_id=item.change_node_id,
                subject_node_id=item.subject_node_id,
                resolution_id=item.resolution_id,
                resolution_sha256=item.resolution_sha256,
                classification=item.classification,
                graph_diff_action=item.graph_diff_action,
                blocked_on_remediation=item.remediation_required,
                current_attack_path_ids=item.current_attack_path_ids,
                effect_ids=item.effect_ids,
                evidence_ids=item.evidence_ids,
                capability_ids=item.capability_ids,
            )
        )
    if not request_items:
        raise ValueError("retest request requires at least one retest item")

    items = tuple(request_items)
    blocked = sum(item.blocked_on_remediation for item in items)
    if len(items) != plan.retest_item_count or blocked != plan.remediation_item_count:
        raise ValueError("retest request counts are inconsistent with the plan")

    return FutureStateRetestRequest(
        schema_version=REQUEST_SCHEMA_VERSION,
        client_id=plan.client_id,
        current_twin_id=plan.current_twin_id,
        current_twin_version=plan.current_twin_version,
        twin_id=plan.twin_id,
        twin_version=plan.twin_version,
        changeset_id=plan.changeset_id,
        proposal_sha256=plan.proposal_sha256,
        impact_analysis_sha256=plan.impact_analysis_sha256,
        preview_sha256=plan.preview_sha256,
        report_sha256=plan.report_sha256,
        plan_sha256=plan.plan_sha256,
        items=items,
        retest_item_count=len(items),
        blocked_on_remediation_count=blocked,
        request_sha256=_request_digest(
            plan=plan,
            items=items,
            blocked_on_remediation_count=blocked,
        ),
    )
