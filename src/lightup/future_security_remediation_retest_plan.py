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


def _is_canonical_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _require_non_empty_string(value: object, *, field: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"remediation/retest plan {field} must be a non-empty string")


def _require_string_tuple(value: object, *, field: str) -> tuple[str, ...]:
    if not isinstance(value, tuple):
        raise ValueError(f"remediation/retest plan item {field} must be a tuple")
    if any(not isinstance(item, str) or not item for item in value):
        raise ValueError(
            f"remediation/retest plan item {field} must contain non-empty strings"
        )
    if len(set(value)) != len(value):
        raise ValueError(
            f"remediation/retest plan item {field} must not contain duplicates"
        )
    return value


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

    def __post_init__(self) -> None:
        for field in ("change_node_id", "subject_node_id", "resolution_id"):
            _require_non_empty_string(getattr(self, field), field=f"item.{field}")
        if not _is_canonical_sha256(self.resolution_sha256):
            raise ValueError(
                "remediation/retest plan item resolution_sha256 must be canonical"
            )
        if not isinstance(self.classification, AttackPathTransitionClassification):
            raise ValueError(
                "remediation/retest plan item classification must be an enum member"
            )
        if not isinstance(self.graph_diff_action, AttackPathGraphDiffAction):
            raise ValueError(
                "remediation/retest plan item graph_diff_action must be an enum member"
            )
        if not isinstance(self.next_action, FutureRemediationNextAction):
            raise ValueError(
                "remediation/retest plan item next_action must be an enum member"
            )
        for field in (
            "remediation_required",
            "future_state_retest_required",
            "evidence_required",
        ):
            if type(getattr(self, field)) is not bool:
                raise ValueError(
                    f"remediation/retest plan item {field} must be boolean"
                )
        expected = _planning_action(self.classification)
        actual = (
            self.next_action,
            self.remediation_required,
            self.future_state_retest_required,
            self.evidence_required,
        )
        if actual != expected:
            raise ValueError(
                "remediation/retest plan item action/requirement semantics mismatch"
            )
        for field in (
            "current_attack_path_ids",
            "effect_ids",
            "evidence_ids",
            "capability_ids",
        ):
            _require_string_tuple(getattr(self, field), field=field)

    def as_dict(self) -> dict:
        return asdict(self)


def _canonical_plan_digest(
    *,
    schema_version: str,
    client_id: str,
    current_twin_id: str,
    current_twin_version: int,
    twin_id: str,
    twin_version: int,
    changeset_id: str,
    proposal_sha256: str,
    impact_analysis_sha256: str,
    preview_sha256: str,
    report_sha256: str,
    items: tuple[FutureSecurityRemediationRetestPlanItem, ...],
    remediation_item_count: int,
    retest_item_count: int,
    evidence_gap_count: int,
    contains_insufficient_evidence: bool,
) -> str:
    payload = {
        "schema_version": schema_version,
        "client_id": client_id,
        "current_twin_id": current_twin_id,
        "current_twin_version": current_twin_version,
        "twin_id": twin_id,
        "twin_version": twin_version,
        "changeset_id": changeset_id,
        "proposal_sha256": proposal_sha256,
        "impact_analysis_sha256": impact_analysis_sha256,
        "preview_sha256": preview_sha256,
        "report_sha256": report_sha256,
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
        "contains_insufficient_evidence": contains_insufficient_evidence,
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

    def __post_init__(self) -> None:
        if self.schema_version != PLAN_SCHEMA_VERSION:
            raise ValueError("remediation/retest plan schema version mismatch")
        for field in (
            "client_id",
            "current_twin_id",
            "twin_id",
            "changeset_id",
        ):
            _require_non_empty_string(getattr(self, field), field=field)
        for field in (
            "proposal_sha256",
            "impact_analysis_sha256",
            "preview_sha256",
            "report_sha256",
            "plan_sha256",
        ):
            if not _is_canonical_sha256(getattr(self, field)):
                raise ValueError(
                    f"remediation/retest plan {field} must be a canonical SHA-256"
                )
        for field in (
            "current_twin_version",
            "twin_version",
            "remediation_item_count",
            "retest_item_count",
            "evidence_gap_count",
        ):
            value = getattr(self, field)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(
                    f"remediation/retest plan {field} must be a non-negative integer"
                )
        if not isinstance(self.items, tuple) or not self.items:
            raise ValueError("remediation/retest plan items must be a non-empty tuple")
        if any(type(item) is not FutureSecurityRemediationRetestPlanItem for item in self.items):
            raise ValueError(
                "remediation/retest plan items must contain exact plan-item values"
            )
        identities = [
            (item.change_node_id, item.subject_node_id, item.resolution_id)
            for item in self.items
        ]
        if len(set(identities)) != len(identities):
            raise ValueError("remediation/retest plan item identity must be unique")

        remediation_count = sum(item.remediation_required for item in self.items)
        retest_count = sum(item.future_state_retest_required for item in self.items)
        gap_count = sum(item.evidence_required for item in self.items)
        if self.remediation_item_count != remediation_count:
            raise ValueError("remediation/retest plan remediation count mismatch")
        if self.retest_item_count != retest_count:
            raise ValueError("remediation/retest plan retest count mismatch")
        if self.evidence_gap_count != gap_count:
            raise ValueError("remediation/retest plan evidence-gap count mismatch")
        if self.plan_complete is not True:
            raise ValueError("remediation/retest plan must remain complete")
        if type(self.contains_insufficient_evidence) is not bool:
            raise ValueError(
                "remediation/retest plan contains_insufficient_evidence must be boolean"
            )
        contains_insufficient = any(
            item.classification
            is AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE
            for item in self.items
        )
        if self.contains_insufficient_evidence != contains_insufficient:
            raise ValueError(
                "remediation/retest plan insufficient-evidence state mismatch"
            )
        if bool(gap_count) != contains_insufficient:
            raise ValueError(
                "remediation/retest plan evidence-gap semantics are inconsistent"
            )
        for field in (
            "execution_allowed",
            "deployment_authorized",
            "attack_path_mutation_allowed",
        ):
            if getattr(self, field) is not False:
                raise ValueError(
                    f"remediation/retest plan safety flag {field} must remain false"
                )
        if self.future_semantics != "unresolved":
            raise ValueError(
                "remediation/retest plan future semantics must remain unresolved"
            )
        if self.security_verdict != "not_evaluated":
            raise ValueError("remediation/retest plan must not claim a security verdict")

    def as_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(
            self.as_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )


def _plan_digest(
    *,
    report: FutureAttackPathSecurityDeltaReport,
    items: tuple[FutureSecurityRemediationRetestPlanItem, ...],
    remediation_item_count: int,
    retest_item_count: int,
    evidence_gap_count: int,
) -> str:
    return _canonical_plan_digest(
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
        contains_insufficient_evidence=report.contains_insufficient_evidence,
    )


def build_future_security_remediation_retest_plan(
    report: FutureAttackPathSecurityDeltaReport,
    preview: FutureAttackPathGraphDiffPreview,
    proposal: FutureAttackPathTransitionProposal,
    resolutions: tuple[FutureAttackPathTransitionResolution, ...],
    contexts: tuple[RunContext, ...],
    state: StateStore,
) -> FutureSecurityRemediationRetestPlan:
    """Build immutable follow-up planning metadata from live-validated ST4 output."""

    if type(report) is not FutureAttackPathSecurityDeltaReport:
        raise ValueError(
            "report must be an exact FutureAttackPathSecurityDeltaReport"
        )

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
