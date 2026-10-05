"""Planning-only ST5 evidence collection request for unresolved security deltas.

This module turns live-revalidated insufficient-evidence remediation-plan items
into immutable metadata saying that fresh evidence is required. It does not
choose a collection capability, create a tool call, interact with a target,
author remediation, schedule a retest, or authorize deployment.
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
from .future_attack_path_security_delta_report import FutureAttackPathSecurityDeltaReport
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


REQUEST_SCHEMA_VERSION = "st5.evidence_collection_request.v1"


@dataclass(frozen=True)
class FutureSecurityEvidenceCollectionItem:
    change_node_id: str
    subject_node_id: str
    resolution_id: str
    resolution_sha256: str
    current_attack_path_ids: tuple[str, ...]
    effect_ids: tuple[str, ...]
    prior_evidence_ids: tuple[str, ...]
    prior_capability_ids: tuple[str, ...]
    classification: AttackPathTransitionClassification
    graph_diff_action: AttackPathGraphDiffAction
    collection_reason: str = "insufficient_evidence"
    fresh_evidence_required: bool = True
    fresh_run_required: bool = True
    remediation_authoring_allowed: bool = False
    future_state_retest_allowed: bool = False

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class FutureSecurityEvidenceCollectionRequest:
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
    items: tuple[FutureSecurityEvidenceCollectionItem, ...]
    evidence_gap_count: int
    request_sha256: str
    collection_authorized: bool = False
    capability_selected: bool = False
    tool_call_created: bool = False
    execution_allowed: bool = False
    target_interaction_allowed: bool = False
    remediation_authoring_allowed: bool = False
    future_state_retest_allowed: bool = False
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
    items: tuple[FutureSecurityEvidenceCollectionItem, ...],
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
                "current_attack_path_ids": list(item.current_attack_path_ids),
                "effect_ids": list(item.effect_ids),
                "prior_evidence_ids": list(item.prior_evidence_ids),
                "prior_capability_ids": list(item.prior_capability_ids),
                "classification": item.classification.value,
                "graph_diff_action": item.graph_diff_action.value,
                "collection_reason": item.collection_reason,
                "fresh_evidence_required": True,
                "fresh_run_required": True,
                "remediation_authoring_allowed": False,
                "future_state_retest_allowed": False,
            }
            for item in items
        ],
        "evidence_gap_count": len(items),
        "collection_authorized": False,
        "capability_selected": False,
        "tool_call_created": False,
        "execution_allowed": False,
        "target_interaction_allowed": False,
        "remediation_authoring_allowed": False,
        "future_state_retest_allowed": False,
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


def build_future_security_evidence_collection_request(
    plan: FutureSecurityRemediationRetestPlan,
    report: FutureAttackPathSecurityDeltaReport,
    preview: FutureAttackPathGraphDiffPreview,
    proposal: FutureAttackPathTransitionProposal,
    resolutions: tuple[FutureAttackPathTransitionResolution, ...],
    contexts: tuple[RunContext, ...],
    state: StateStore,
) -> FutureSecurityEvidenceCollectionRequest:
    """Build immutable follow-up metadata only for unresolved evidence gaps."""

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
            "evidence collection request requires the exact live remediation plan"
        )
    if not plan.contains_insufficient_evidence or plan.evidence_gap_count <= 0:
        raise ValueError("evidence collection request requires an evidence gap")
    if plan.execution_allowed:
        raise ValueError("source remediation plan must not allow execution")
    if plan.deployment_authorized:
        raise ValueError("source remediation plan must not authorize deployment")
    if plan.attack_path_mutation_allowed:
        raise ValueError("source remediation plan must not allow attack-path mutation")
    if plan.future_semantics != "unresolved":
        raise ValueError("source remediation plan future_semantics must remain unresolved")
    if plan.security_verdict != "not_evaluated":
        raise ValueError("source remediation plan must not precompute a security verdict")

    request_items: list[FutureSecurityEvidenceCollectionItem] = []
    for item in plan.items:
        if not item.evidence_required:
            continue
        if item.classification is not AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE:
            raise ValueError("evidence-required plan item must be insufficient_evidence")
        if item.next_action is not FutureRemediationNextAction.COLLECT_MORE_EVIDENCE:
            raise ValueError("evidence gap must retain collect_more_evidence next action")
        if item.graph_diff_action is not AttackPathGraphDiffAction.NO_GRAPH_CHANGE_CLAIM:
            raise ValueError("evidence gap must not carry a graph-change claim")
        if item.remediation_required or item.future_state_retest_required:
            raise ValueError(
                "evidence gap cannot authorize remediation or future-state retest"
            )
        if not item.evidence_ids:
            raise ValueError("evidence gap must preserve prior evidence provenance")
        if not item.capability_ids:
            raise ValueError("evidence gap must preserve prior capability provenance")

        request_items.append(
            FutureSecurityEvidenceCollectionItem(
                change_node_id=item.change_node_id,
                subject_node_id=item.subject_node_id,
                resolution_id=item.resolution_id,
                resolution_sha256=item.resolution_sha256,
                current_attack_path_ids=item.current_attack_path_ids,
                effect_ids=item.effect_ids,
                prior_evidence_ids=item.evidence_ids,
                prior_capability_ids=item.capability_ids,
                classification=item.classification,
                graph_diff_action=item.graph_diff_action,
            )
        )

    items = tuple(
        sorted(
            request_items,
            key=lambda item: (
                item.change_node_id,
                item.subject_node_id,
                item.resolution_id,
            ),
        )
    )
    if not items or len(items) != plan.evidence_gap_count:
        raise ValueError("evidence collection request gap count is inconsistent")

    request_sha256 = _request_digest(plan=plan, items=items)

    return FutureSecurityEvidenceCollectionRequest(
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
        evidence_gap_count=len(items),
        request_sha256=request_sha256,
    )


def validate_future_security_evidence_collection_request(
    request: FutureSecurityEvidenceCollectionRequest,
    plan: FutureSecurityRemediationRetestPlan,
    report: FutureAttackPathSecurityDeltaReport,
    preview: FutureAttackPathGraphDiffPreview,
    proposal: FutureAttackPathTransitionProposal,
    resolutions: tuple[FutureAttackPathTransitionResolution, ...],
    contexts: tuple[RunContext, ...],
    state: StateStore,
) -> FutureSecurityEvidenceCollectionRequest:
    """Rebuild a persisted request from live lineage before follow-up use."""

    if not isinstance(request, FutureSecurityEvidenceCollectionRequest):
        raise ValueError(
            "request must be a FutureSecurityEvidenceCollectionRequest"
        )

    rebuilt = build_future_security_evidence_collection_request(
        plan,
        report,
        preview,
        proposal,
        resolutions,
        contexts,
        state,
    )
    if rebuilt != request:
        raise ValueError(
            "evidence collection request does not match its live validated lineage"
        )
    return rebuilt
