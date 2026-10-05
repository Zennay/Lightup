"""Immutable isolated future-state retest requests for Security Twin ST5.

This module converts a live-revalidated remediation/retest plan into planning
metadata that can later be submitted to the existing authorization, scope, and
tool-policy gates. It does not execute a retest, interact with a target, mutate
attack paths, widen authorization, merge, or deploy.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
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


RETEST_REQUEST_SCHEMA_VERSION = "st5.future_state_retest_request.v1"


class FutureStateRetestPurpose(str, Enum):
    REMEDIATION_VALIDATION = "remediation_validation"
    IMPROVEMENT_VERIFICATION = "improvement_verification"


@dataclass(frozen=True)
class FutureSecurityRetestRequestItem:
    change_node_id: str
    subject_node_id: str
    resolution_id: str
    resolution_sha256: str
    classification: AttackPathTransitionClassification
    graph_diff_action: AttackPathGraphDiffAction
    source_next_action: FutureRemediationNextAction
    purpose: FutureStateRetestPurpose
    remediation_required: bool
    current_attack_path_ids: tuple[str, ...]
    effect_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    capability_ids: tuple[str, ...]

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class FutureSecurityRetestRequest:
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
    remediation_plan_sha256: str
    items: tuple[FutureSecurityRetestRequestItem, ...]
    requested_capability_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    request_sha256: str
    request_complete: bool = True
    isolated_future_state_required: bool = True
    execution_allowed: bool = False
    target_interaction_allowed: bool = False
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


def _request_purpose(
    *,
    classification: AttackPathTransitionClassification,
    next_action: FutureRemediationNextAction,
    remediation_required: bool,
) -> FutureStateRetestPurpose:
    if remediation_required:
        if classification not in {
            AttackPathTransitionClassification.INTRODUCED,
            AttackPathTransitionClassification.WORSENED,
        }:
            raise ValueError("remediation retest item has an incompatible classification")
        if next_action is not FutureRemediationNextAction.AUTHOR_REMEDIATION_THEN_RETEST:
            raise ValueError("remediation retest item has an incompatible next action")
        return FutureStateRetestPurpose.REMEDIATION_VALIDATION

    if classification not in {
        AttackPathTransitionClassification.IMPROVED,
        AttackPathTransitionClassification.REMOVED,
    }:
        raise ValueError("verification retest item has an incompatible classification")
    if next_action is not FutureRemediationNextAction.VERIFY_IMPROVEMENT_WITH_RETEST:
        raise ValueError("verification retest item has an incompatible next action")
    return FutureStateRetestPurpose.IMPROVEMENT_VERIFICATION


def _request_digest(
    *,
    plan: FutureSecurityRemediationRetestPlan,
    items: tuple[FutureSecurityRetestRequestItem, ...],
    requested_capability_ids: tuple[str, ...],
    evidence_ids: tuple[str, ...],
) -> str:
    payload = {
        "schema_version": RETEST_REQUEST_SCHEMA_VERSION,
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
        "remediation_plan_sha256": plan.plan_sha256,
        "items": [
            {
                "change_node_id": item.change_node_id,
                "subject_node_id": item.subject_node_id,
                "resolution_id": item.resolution_id,
                "resolution_sha256": item.resolution_sha256,
                "classification": item.classification.value,
                "graph_diff_action": item.graph_diff_action.value,
                "source_next_action": item.source_next_action.value,
                "purpose": item.purpose.value,
                "remediation_required": item.remediation_required,
                "current_attack_path_ids": list(item.current_attack_path_ids),
                "effect_ids": list(item.effect_ids),
                "evidence_ids": list(item.evidence_ids),
                "capability_ids": list(item.capability_ids),
            }
            for item in items
        ],
        "requested_capability_ids": list(requested_capability_ids),
        "evidence_ids": list(evidence_ids),
        "request_complete": True,
        "isolated_future_state_required": True,
        "execution_allowed": False,
        "target_interaction_allowed": False,
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


def build_future_security_retest_request(
    plan: FutureSecurityRemediationRetestPlan,
    report: FutureAttackPathSecurityDeltaReport,
    preview: FutureAttackPathGraphDiffPreview,
    proposal: FutureAttackPathTransitionProposal,
    resolutions: tuple[FutureAttackPathTransitionResolution, ...],
    contexts: tuple[RunContext, ...],
    state: StateStore,
) -> FutureSecurityRetestRequest:
    """Build a non-executable isolated future-state retest request."""

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
    if not plan.plan_complete or not plan.items:
        raise ValueError("future-state retest request requires a complete non-empty plan")
    if plan.execution_allowed or plan.deployment_authorized or plan.attack_path_mutation_allowed:
        raise ValueError("remediation/retest plan must remain non-executable")
    if plan.future_semantics != "unresolved":
        raise ValueError("remediation/retest plan future_semantics must remain unresolved")
    if plan.security_verdict != "not_evaluated":
        raise ValueError("remediation/retest plan must not precompute a security verdict")
    if plan.contains_insufficient_evidence or plan.evidence_gap_count:
        raise ValueError(
            "future-state retest request requires evidence-complete remediation planning"
        )

    request_items: list[FutureSecurityRetestRequestItem] = []
    for item in plan.items:
        if item.evidence_required:
            raise ValueError("evidence-required plan item cannot become a retest request")
        if not item.future_state_retest_required:
            continue
        purpose = _request_purpose(
            classification=item.classification,
            next_action=item.next_action,
            remediation_required=item.remediation_required,
        )
        request_items.append(
            FutureSecurityRetestRequestItem(
                change_node_id=item.change_node_id,
                subject_node_id=item.subject_node_id,
                resolution_id=item.resolution_id,
                resolution_sha256=item.resolution_sha256,
                classification=item.classification,
                graph_diff_action=item.graph_diff_action,
                source_next_action=item.next_action,
                purpose=purpose,
                remediation_required=item.remediation_required,
                current_attack_path_ids=item.current_attack_path_ids,
                effect_ids=item.effect_ids,
                evidence_ids=item.evidence_ids,
                capability_ids=item.capability_ids,
            )
        )

    items = tuple(request_items)
    if not items:
        raise ValueError("remediation/retest plan contains no future-state retest items")

    requested_capability_ids = tuple(
        sorted(
            {
                capability_id
                for item in items
                for capability_id in item.capability_ids
            }
        )
    )
    evidence_ids = tuple(
        sorted({evidence_id for item in items for evidence_id in item.evidence_ids})
    )
    if not requested_capability_ids:
        raise ValueError("future-state retest request requires bounded capabilities")
    if not evidence_ids:
        raise ValueError("future-state retest request requires evidence lineage")

    request_sha256 = _request_digest(
        plan=plan,
        items=items,
        requested_capability_ids=requested_capability_ids,
        evidence_ids=evidence_ids,
    )

    return FutureSecurityRetestRequest(
        schema_version=RETEST_REQUEST_SCHEMA_VERSION,
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
        remediation_plan_sha256=plan.plan_sha256,
        items=items,
        requested_capability_ids=requested_capability_ids,
        evidence_ids=evidence_ids,
        request_sha256=request_sha256,
    )
