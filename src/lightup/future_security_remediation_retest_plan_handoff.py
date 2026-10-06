"""Strict serialization handoff for the ST5 remediation/retest plan.

Parsing proves only that a persisted/transported plan is structurally exact,
internally coherent, and digest-consistent. It does not grant execution,
remediation, retest, deployment, or attack-path mutation authority. Callers
that use a parsed plan for follow-up work must still rebuild/revalidate it
against the live ST4 lineage and StateStore via
`build_future_security_remediation_retest_plan`.
"""

from __future__ import annotations

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
    PLAN_SCHEMA_VERSION,
    FutureRemediationNextAction,
    FutureSecurityRemediationRetestPlan,
    FutureSecurityRemediationRetestPlanItem,
    build_future_security_remediation_retest_plan,
)
from .state import StateStore


_PLAN_KEYS = {
    "schema_version",
    "client_id",
    "current_twin_id",
    "current_twin_version",
    "twin_id",
    "twin_version",
    "changeset_id",
    "proposal_sha256",
    "impact_analysis_sha256",
    "preview_sha256",
    "report_sha256",
    "items",
    "remediation_item_count",
    "retest_item_count",
    "evidence_gap_count",
    "plan_complete",
    "contains_insufficient_evidence",
    "plan_sha256",
    "execution_allowed",
    "deployment_authorized",
    "attack_path_mutation_allowed",
    "future_semantics",
    "security_verdict",
}

_ITEM_KEYS = {
    "change_node_id",
    "subject_node_id",
    "resolution_id",
    "resolution_sha256",
    "classification",
    "graph_diff_action",
    "next_action",
    "remediation_required",
    "future_state_retest_required",
    "evidence_required",
    "current_attack_path_ids",
    "effect_ids",
    "evidence_ids",
    "capability_ids",
}


def _is_canonical_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _non_empty_string(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"remediation/retest plan {field} must be a non-empty string")
    return value


def _string_tuple(value: object, *, field: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError(f"remediation/retest plan item {field} must be a string list")
    if any(not isinstance(item, str) or not item for item in value):
        raise ValueError(
            f"remediation/retest plan item {field} must contain non-empty strings"
        )
    parsed = tuple(value)
    if len(set(parsed)) != len(parsed):
        raise ValueError(
            f"remediation/retest plan item {field} must not contain duplicates"
        )
    return parsed


def _expected_action(
    classification: AttackPathTransitionClassification,
) -> tuple[AttackPathGraphDiffAction, FutureRemediationNextAction, bool, bool, bool]:
    if classification is AttackPathTransitionClassification.INTRODUCED:
        return (
            AttackPathGraphDiffAction.ADD_PATH_HYPOTHESIS,
            FutureRemediationNextAction.AUTHOR_REMEDIATION_THEN_RETEST,
            True,
            True,
            False,
        )
    if classification is AttackPathTransitionClassification.WORSENED:
        return (
            AttackPathGraphDiffAction.MODIFY_EXISTING_PATH_RISK_UP,
            FutureRemediationNextAction.AUTHOR_REMEDIATION_THEN_RETEST,
            True,
            True,
            False,
        )
    if classification is AttackPathTransitionClassification.IMPROVED:
        return (
            AttackPathGraphDiffAction.MODIFY_EXISTING_PATH_RISK_DOWN,
            FutureRemediationNextAction.VERIFY_IMPROVEMENT_WITH_RETEST,
            False,
            True,
            False,
        )
    if classification is AttackPathTransitionClassification.REMOVED:
        return (
            AttackPathGraphDiffAction.REMOVE_EXISTING_PATH_CANDIDATE,
            FutureRemediationNextAction.VERIFY_IMPROVEMENT_WITH_RETEST,
            False,
            True,
            False,
        )
    if classification is AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE:
        return (
            AttackPathGraphDiffAction.NO_GRAPH_CHANGE_CLAIM,
            FutureRemediationNextAction.COLLECT_MORE_EVIDENCE,
            False,
            False,
            True,
        )
    raise ValueError("unsupported remediation/retest classification")

def _plan_digest_from_plan(plan: FutureSecurityRemediationRetestPlan) -> str:
    payload = {
        "schema_version": PLAN_SCHEMA_VERSION,
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
            for item in plan.items
        ],
        "remediation_item_count": plan.remediation_item_count,
        "retest_item_count": plan.retest_item_count,
        "evidence_gap_count": plan.evidence_gap_count,
        "plan_complete": True,
        "contains_insufficient_evidence": plan.contains_insufficient_evidence,
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


def future_security_remediation_retest_plan_from_dict(
    payload: dict,
) -> FutureSecurityRemediationRetestPlan:
    """Parse one exact serialized plan and verify its semantic digest."""

    if not isinstance(payload, dict):
        raise ValueError("remediation/retest plan payload must be an object")
    if set(payload) != _PLAN_KEYS:
        raise ValueError("remediation/retest plan payload schema mismatch")
    if payload["schema_version"] != PLAN_SCHEMA_VERSION:
        raise ValueError("remediation/retest plan schema version mismatch")

    for field in (
        "client_id",
        "current_twin_id",
        "twin_id",
        "changeset_id",
        "future_semantics",
        "security_verdict",
    ):
        _non_empty_string(payload[field], field=field)

    for field in (
        "proposal_sha256",
        "impact_analysis_sha256",
        "preview_sha256",
        "report_sha256",
        "plan_sha256",
    ):
        if not _is_canonical_sha256(payload[field]):
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
        value = payload[field]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(
                f"remediation/retest plan {field} must be a non-negative integer"
            )

    if payload["plan_complete"] is not True:
        raise ValueError("remediation/retest plan must remain complete")
    if not isinstance(payload["contains_insufficient_evidence"], bool):
        raise ValueError(
            "remediation/retest plan contains_insufficient_evidence must be boolean"
        )
    for field in (
        "execution_allowed",
        "deployment_authorized",
        "attack_path_mutation_allowed",
    ):
        if payload[field] is not False:
            raise ValueError(
                f"remediation/retest plan safety flag {field} must remain false"
            )
    if payload["future_semantics"] != "unresolved":
        raise ValueError("remediation/retest plan future semantics must be unresolved")
    if payload["security_verdict"] != "not_evaluated":
        raise ValueError("remediation/retest plan must not claim a security verdict")

    raw_items = payload["items"]
    if not isinstance(raw_items, list) or not raw_items:
        raise ValueError("remediation/retest plan items must be a non-empty list")

    items: list[FutureSecurityRemediationRetestPlanItem] = []
    identities: set[tuple[str, str, str]] = set()
    for raw_item in raw_items:
        if not isinstance(raw_item, dict) or set(raw_item) != _ITEM_KEYS:
            raise ValueError("remediation/retest plan item schema mismatch")

        change_node_id = _non_empty_string(
            raw_item["change_node_id"], field="item.change_node_id"
        )
        subject_node_id = _non_empty_string(
            raw_item["subject_node_id"], field="item.subject_node_id"
        )
        resolution_id = _non_empty_string(
            raw_item["resolution_id"], field="item.resolution_id"
        )
        if not _is_canonical_sha256(raw_item["resolution_sha256"]):
            raise ValueError(
                "remediation/retest plan item resolution_sha256 must be canonical"
            )

        try:
            classification = AttackPathTransitionClassification(
                raw_item["classification"]
            )
            graph_diff_action = AttackPathGraphDiffAction(
                raw_item["graph_diff_action"]
            )
            next_action = FutureRemediationNextAction(raw_item["next_action"])
        except (TypeError, ValueError) as exc:
            raise ValueError("remediation/retest plan item enum value is invalid") from exc

        for field in (
            "remediation_required",
            "future_state_retest_required",
            "evidence_required",
        ):
            if not isinstance(raw_item[field], bool):
                raise ValueError(
                    f"remediation/retest plan item {field} must be boolean"
                )

        expected = _expected_action(classification)
        actual = (
            graph_diff_action,
            next_action,
            raw_item["remediation_required"],
            raw_item["future_state_retest_required"],
            raw_item["evidence_required"],
        )
        if actual != expected:
            raise ValueError(
                "remediation/retest plan item action/requirement semantics mismatch"
            )

        identity = (change_node_id, subject_node_id, resolution_id)
        if identity in identities:
            raise ValueError("remediation/retest plan item identity must be unique")
        identities.add(identity)

        items.append(
            FutureSecurityRemediationRetestPlanItem(
                change_node_id=change_node_id,
                subject_node_id=subject_node_id,
                resolution_id=resolution_id,
                resolution_sha256=raw_item["resolution_sha256"],
                classification=classification,
                graph_diff_action=graph_diff_action,
                next_action=next_action,
                remediation_required=raw_item["remediation_required"],
                future_state_retest_required=raw_item[
                    "future_state_retest_required"
                ],
                evidence_required=raw_item["evidence_required"],
                current_attack_path_ids=_string_tuple(
                    raw_item["current_attack_path_ids"],
                    field="current_attack_path_ids",
                ),
                effect_ids=_string_tuple(
                    raw_item["effect_ids"],
                    field="effect_ids",
                ),
                evidence_ids=_string_tuple(
                    raw_item["evidence_ids"],
                    field="evidence_ids",
                ),
                capability_ids=_string_tuple(
                    raw_item["capability_ids"],
                    field="capability_ids",
                ),
            )
        )

    parsed_items = tuple(items)
    remediation_count = sum(item.remediation_required for item in parsed_items)
    retest_count = sum(item.future_state_retest_required for item in parsed_items)
    gap_count = sum(item.evidence_required for item in parsed_items)
    if payload["remediation_item_count"] != remediation_count:
        raise ValueError("remediation/retest plan remediation count mismatch")
    if payload["retest_item_count"] != retest_count:
        raise ValueError("remediation/retest plan retest count mismatch")
    if payload["evidence_gap_count"] != gap_count:
        raise ValueError("remediation/retest plan evidence-gap count mismatch")

    contains_insufficient = any(
        item.classification
        is AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE
        for item in parsed_items
    )
    if payload["contains_insufficient_evidence"] != contains_insufficient:
        raise ValueError(
            "remediation/retest plan insufficient-evidence state mismatch"
        )
    if bool(gap_count) != contains_insufficient:
        raise ValueError(
            "remediation/retest plan evidence-gap semantics are inconsistent"
        )

    plan = FutureSecurityRemediationRetestPlan(
        schema_version=payload["schema_version"],
        client_id=payload["client_id"],
        current_twin_id=payload["current_twin_id"],
        current_twin_version=payload["current_twin_version"],
        twin_id=payload["twin_id"],
        twin_version=payload["twin_version"],
        changeset_id=payload["changeset_id"],
        proposal_sha256=payload["proposal_sha256"],
        impact_analysis_sha256=payload["impact_analysis_sha256"],
        preview_sha256=payload["preview_sha256"],
        report_sha256=payload["report_sha256"],
        items=parsed_items,
        remediation_item_count=payload["remediation_item_count"],
        retest_item_count=payload["retest_item_count"],
        evidence_gap_count=payload["evidence_gap_count"],
        plan_complete=True,
        contains_insufficient_evidence=payload["contains_insufficient_evidence"],
        plan_sha256=payload["plan_sha256"],
        execution_allowed=False,
        deployment_authorized=False,
        attack_path_mutation_allowed=False,
        future_semantics=payload["future_semantics"],
        security_verdict=payload["security_verdict"],
    )
    if plan.plan_sha256 != _plan_digest_from_plan(plan):
        raise ValueError("remediation/retest plan digest mismatch")
    return plan


def validate_future_security_remediation_retest_plan_handoff(
    plan: FutureSecurityRemediationRetestPlan,
    report: FutureAttackPathSecurityDeltaReport,
    preview: FutureAttackPathGraphDiffPreview,
    proposal: FutureAttackPathTransitionProposal,
    resolutions: tuple[FutureAttackPathTransitionResolution, ...],
    contexts: tuple[RunContext, ...],
    state: StateStore,
) -> FutureSecurityRemediationRetestPlan:
    """Require exact equality with a plan rebuilt from live ST4 lineage."""

    if not isinstance(plan, FutureSecurityRemediationRetestPlan):
        raise ValueError(
            "plan must be a FutureSecurityRemediationRetestPlan"
        )
    rebuilt = build_future_security_remediation_retest_plan(
        report,
        preview,
        proposal,
        resolutions,
        contexts,
        state,
    )
    if rebuilt != plan:
        raise ValueError(
            "remediation/retest plan does not match its live validated lineage"
        )
    return rebuilt


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key in remediation/retest plan: {key}")
        result[key] = value
    return result


def future_security_remediation_retest_plan_from_json(
    raw: str,
) -> FutureSecurityRemediationRetestPlan:
    """Decode JSON without duplicate-key collapse, then apply the strict parser."""

    if not isinstance(raw, str) or not raw:
        raise ValueError("remediation/retest plan JSON must be a non-empty string")
    try:
        payload = json.loads(raw, object_pairs_hook=_reject_duplicate_json_keys)
    except json.JSONDecodeError as exc:
        raise ValueError("remediation/retest plan JSON is invalid") from exc
    return future_security_remediation_retest_plan_from_dict(payload)
