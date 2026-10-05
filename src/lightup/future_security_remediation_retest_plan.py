"""Evidence-linked ST5 remediation and future-state retest planning.

This module turns a live-revalidated ST4 security delta report into immutable
follow-up metadata. It does not execute remediation, retests, target actions,
merge/deploy actions, or attack-path mutations.
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
from .future_attack_path_security_delta_report import (
    FutureAttackPathSecurityDeltaReport,
    build_future_attack_path_security_delta_report,
)
from .future_attack_path_transition import FutureAttackPathTransitionProposal
from .future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
    FutureAttackPathTransitionResolution,
)
from .state import StateStore


PLAN_SCHEMA_VERSION = "st5.remediation_retest_plan.v1"


class FutureRemediationNextAction(str, Enum):
    AUTHOR_REMEDIATION_THEN_RETEST = "author_remediation_then_retest"
    VERIFY_IMPROVEMENT_WITH_RETEST = "verify_improvement_with_retest"
    COLLECT_MORE_EVIDENCE = "collect_more_evidence"


@dataclass(frozen=True)
class FutureSecurityRemediationRetestPlanItem:
    change_node_id: str
    subject_node_id: str
    resolution_id: str
    resolution_sha256: str
    classification: AttackPathTransitionClassification
    graph_diff_action: AttackPathGraphDiffAction
    next_action: FutureRemediationNextAction
    remediation_required: bool
    future_state_retest_required: bool
    evidence_required: bool
    current_attack_path_ids: tuple[str, ...]
    effect_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    capability_ids: tuple[str, ...]

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class FutureSecurityRemediationRetestPlan:
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
    items: tuple[FutureSecurityRemediationRetestPlanItem, ...]
    remediation_item_count: int
    retest_item_count: int
    evidence_gap_count: int
    plan_complete: bool
    contains_insufficient_evidence: bool
    plan_sha256: str
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


def _planning_action(
    classification: AttackPathTransitionClassification,
) -> tuple[FutureRemediationNextAction, bool, bool, bool]:
    if classification in {
        AttackPathTransitionClassification.INTRODUCED,
        AttackPathTransitionClassification.WORSENED,
    }:
        return (
            FutureRemediationNextAction.AUTHOR_REMEDIATION_THEN_RETEST,
            True,
            True,
            False,
        )
    if classification in {
        AttackPathTransitionClassification.IMPROVED,
        AttackPathTransitionClassification.REMOVED,
    }:
        return (
            FutureRemediationNextAction.VERIFY_IMPROVEMENT_WITH_RETEST,
            False,
            True,
            False,
        )
    if classification is AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE:
        return (
            FutureRemediationNextAction.COLLECT_MORE_EVIDENCE,
            False,
            False,
            True,
        )
    raise ValueError("unsupported ST4 attack-path classification")


def _plan_digest(
    *,
    report: FutureAttackPathSecurityDeltaReport,
    items: tuple[FutureSecurityRemediationRetestPlanItem, ...],
    remediation_item_count: int,
    retest_item_count: int,
    evidence_gap_count: int,
) -> str:
    payload = {
        "schema_version": PLAN_SCHEMA_VERSION,
        "client_id": report.client_id,
        "current_twin_id": report.current_twin_id,
        "current_twin_version": report.current_twin_version,
        "twin_id": report.twin_id,
        "twin_version": report.twin_version,
        "changeset_id": report.changeset_id,
        "proposal_sha256": report.proposal_sha256,
        "impact_analysis_sha256": report.impact_analysis_sha256,
        "preview_sha256": report.preview_sha256,
        "report_sha256": report.report_sha256,
        "items": [
            {
                "change_node_id": item.change_node_id,
                "subject_node_id": item.subject_node_id,
                "resolution_id": item.resolution_id,
                "resolution_sha256": item.resolution_sha256,
                "classification": item.classification.value,
                "graph_diff_action": item.graph_diff_action.value,
                "next_action": item.next_action.value,
                "remediation_required": item.remediation_required,
                "future_state_retest_required": item.future_state_retest_required,
                "evidence_required": item.evidence_required,
                "current_attack_path_ids": list(item.current_attack_path_ids),
                "effect_ids": list(item.effect_ids),
                "evidence_ids": list(item.evidence_ids),
                "capability_ids": list(item.capability_ids),
            }
            for item in items
        ],
        "remediation_item_count": remediation_item_count,
        "retest_item_count": retest_item_count,
        "evidence_gap_count": evidence_gap_count,
        "plan_complete": True,
        "contains_insufficient_evidence": report.contains_insufficient_evidence,
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


def build_future_security_remediation_retest_plan(
    report: FutureAttackPathSecurityDeltaReport,
    preview: FutureAttackPathGraphDiffPreview,
    proposal: FutureAttackPathTransitionProposal,
    resolutions: tuple[FutureAttackPathTransitionResolution, ...],
    contexts: tuple[RunContext, ...],
    state: StateStore,
) -> FutureSecurityRemediationRetestPlan:
    """Build immutable follow-up planning metadata from live-validated ST4 output."""

    live_report = build_future_attack_path_security_delta_report(
        preview,
        proposal,
        resolutions,
        contexts,
        state,
    )
    if report != live_report:
        raise ValueError(
            "security delta report is stale, tampered, cross-tenant, or lineage-drifted"
        )
    if not report.report_complete or not report.items:
        raise ValueError("remediation/retest plan requires a complete non-empty report")
    if report.attack_path_mutation_allowed:
        raise ValueError("security delta report must not allow attack-path mutation")
    if report.future_semantics != "unresolved":
        raise ValueError("security delta report future_semantics must remain unresolved")
    if report.security_verdict != "not_evaluated":
        raise ValueError("security delta report must not precompute a security verdict")

    plan_items: list[FutureSecurityRemediationRetestPlanItem] = []
    for item in report.items:
        next_action, remediation_required, retest_required, evidence_required = (
            _planning_action(item.classification)
        )
        plan_items.append(
            FutureSecurityRemediationRetestPlanItem(
                change_node_id=item.change_node_id,
                subject_node_id=item.subject_node_id,
                resolution_id=item.resolution_id,
                resolution_sha256=item.resolution_sha256,
                classification=item.classification,
                graph_diff_action=item.action,
                next_action=next_action,
                remediation_required=remediation_required,
                future_state_retest_required=retest_required,
                evidence_required=evidence_required,
                current_attack_path_ids=item.current_attack_path_ids,
                effect_ids=item.effect_ids,
                evidence_ids=item.evidence_ids,
                capability_ids=item.capability_ids,
            )
        )

    items = tuple(plan_items)
    remediation_item_count = sum(item.remediation_required for item in items)
    retest_item_count = sum(item.future_state_retest_required for item in items)
    evidence_gap_count = sum(item.evidence_required for item in items)
    if bool(evidence_gap_count) != report.contains_insufficient_evidence:
        raise ValueError("remediation/retest evidence-gap state is inconsistent")

    plan_sha256 = _plan_digest(
        report=report,
        items=items,
        remediation_item_count=remediation_item_count,
        retest_item_count=retest_item_count,
        evidence_gap_count=evidence_gap_count,
    )

    return FutureSecurityRemediationRetestPlan(
        schema_version=PLAN_SCHEMA_VERSION,
        client_id=report.client_id,
        current_twin_id=report.current_twin_id,
        current_twin_version=report.current_twin_version,
        twin_id=report.twin_id,
        twin_version=report.twin_version,
        changeset_id=report.changeset_id,
        proposal_sha256=report.proposal_sha256,
        impact_analysis_sha256=report.impact_analysis_sha256,
        preview_sha256=report.preview_sha256,
        report_sha256=report.report_sha256,
        items=items,
        remediation_item_count=remediation_item_count,
        retest_item_count=retest_item_count,
        evidence_gap_count=evidence_gap_count,
        plan_complete=True,
        contains_insufficient_evidence=report.contains_insufficient_evidence,
        plan_sha256=plan_sha256,
    )
