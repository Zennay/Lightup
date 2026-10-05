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


_REQUEST_KEYS = {
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
    "plan_sha256",
    "items",
    "evidence_gap_count",
    "request_sha256",
    "collection_authorized",
    "capability_selected",
    "tool_call_created",
    "execution_allowed",
    "target_interaction_allowed",
    "remediation_authoring_allowed",
    "future_state_retest_allowed",
    "deployment_authorized",
    "attack_path_mutation_allowed",
    "future_semantics",
    "security_verdict",
}

_REQUEST_ITEM_KEYS = {
    "change_node_id",
    "subject_node_id",
    "resolution_id",
    "resolution_sha256",
    "current_attack_path_ids",
    "effect_ids",
    "prior_evidence_ids",
    "prior_capability_ids",
    "classification",
    "graph_diff_action",
    "collection_reason",
    "fresh_evidence_required",
    "fresh_run_required",
    "remediation_authoring_allowed",
    "future_state_retest_allowed",
}


def _is_canonical_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def _strict_string_tuple(value: object, *, field: str) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item for item in value)
    ):
        raise ValueError(
            f"evidence collection request item {field} must be a non-empty string list"
        )
    parsed = tuple(value)
    if parsed != tuple(sorted(set(parsed))):
        raise ValueError(
            f"evidence collection request item {field} must be sorted and unique"
        )
    return parsed


def _strict_optional_string_tuple(
    value: object,
    *,
    field: str,
) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or any(not isinstance(item, str) or not item for item in value)
    ):
        raise ValueError(
            f"evidence collection request item {field} must be a string list"
        )
    parsed = tuple(value)
    if parsed != tuple(sorted(set(parsed))):
        raise ValueError(
            f"evidence collection request item {field} must be sorted and unique"
        )
    return parsed


def _request_digest_from_request(
    request: FutureSecurityEvidenceCollectionRequest,
) -> str:
    payload = {
        "schema_version": REQUEST_SCHEMA_VERSION,
        "client_id": request.client_id,
        "current_twin_id": request.current_twin_id,
        "current_twin_version": request.current_twin_version,
        "twin_id": request.twin_id,
        "twin_version": request.twin_version,
        "changeset_id": request.changeset_id,
        "proposal_sha256": request.proposal_sha256,
        "impact_analysis_sha256": request.impact_analysis_sha256,
        "preview_sha256": request.preview_sha256,
        "report_sha256": request.report_sha256,
        "plan_sha256": request.plan_sha256,
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
            for item in request.items
        ],
        "evidence_gap_count": len(request.items),
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


def future_security_evidence_collection_request_from_dict(
    payload: dict,
) -> FutureSecurityEvidenceCollectionRequest:
    """Parse an exact serialized request and verify its canonical digest."""

    if not isinstance(payload, dict):
        raise ValueError("evidence collection request payload must be an object")
    if set(payload) != _REQUEST_KEYS:
        raise ValueError("evidence collection request payload schema mismatch")
    if payload["schema_version"] != REQUEST_SCHEMA_VERSION:
        raise ValueError("evidence collection request schema version mismatch")

    string_fields = (
        "client_id",
        "current_twin_id",
        "twin_id",
        "changeset_id",
        "future_semantics",
        "security_verdict",
    )
    if any(
        not isinstance(payload[field], str) or not payload[field]
        for field in string_fields
    ):
        raise ValueError("evidence collection request string field is invalid")

    for field in (
        "proposal_sha256",
        "impact_analysis_sha256",
        "preview_sha256",
        "report_sha256",
        "plan_sha256",
        "request_sha256",
    ):
        if not _is_canonical_sha256(payload[field]):
            raise ValueError(
                f"evidence collection request {field} must be a canonical SHA-256"
            )

    for field in ("current_twin_version", "twin_version", "evidence_gap_count"):
        value = payload[field]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(
                f"evidence collection request {field} must be a non-negative integer"
            )

    for field in (
        "collection_authorized",
        "capability_selected",
        "tool_call_created",
        "execution_allowed",
        "target_interaction_allowed",
        "remediation_authoring_allowed",
        "future_state_retest_allowed",
        "deployment_authorized",
        "attack_path_mutation_allowed",
    ):
        if payload[field] is not False:
            raise ValueError(
                f"evidence collection request safety flag {field} must remain false"
            )
    if payload["future_semantics"] != "unresolved":
        raise ValueError("evidence collection request future semantics must be unresolved")
    if payload["security_verdict"] != "not_evaluated":
        raise ValueError(
            "evidence collection request must not claim a security verdict"
        )

    raw_items = payload["items"]
    if not isinstance(raw_items, list) or not raw_items:
        raise ValueError("evidence collection request items must be a non-empty list")

    items: list[FutureSecurityEvidenceCollectionItem] = []
    for raw_item in raw_items:
        if not isinstance(raw_item, dict) or set(raw_item) != _REQUEST_ITEM_KEYS:
            raise ValueError("evidence collection request item schema mismatch")

        for field in (
            "change_node_id",
            "subject_node_id",
            "resolution_id",
            "collection_reason",
        ):
            if not isinstance(raw_item[field], str) or not raw_item[field]:
                raise ValueError(
                    f"evidence collection request item {field} is invalid"
                )
        if not _is_canonical_sha256(raw_item["resolution_sha256"]):
            raise ValueError(
                "evidence collection request item resolution_sha256 is invalid"
            )

        try:
            classification = AttackPathTransitionClassification(
                raw_item["classification"]
            )
            graph_diff_action = AttackPathGraphDiffAction(
                raw_item["graph_diff_action"]
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "evidence collection request item enum value is invalid"
            ) from exc
        if classification is not AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE:
            raise ValueError(
                "evidence collection request item must remain insufficient_evidence"
            )
        if graph_diff_action is not AttackPathGraphDiffAction.NO_GRAPH_CHANGE_CLAIM:
            raise ValueError(
                "evidence collection request item must retain no_graph_change_claim"
            )
        if raw_item["collection_reason"] != "insufficient_evidence":
            raise ValueError(
                "evidence collection request item collection reason is invalid"
            )
        if raw_item["fresh_evidence_required"] is not True:
            raise ValueError(
                "evidence collection request item must require fresh evidence"
            )
        if raw_item["fresh_run_required"] is not True:
            raise ValueError(
                "evidence collection request item must require a fresh run"
            )
        if raw_item["remediation_authoring_allowed"] is not False:
            raise ValueError(
                "evidence collection request item cannot authorize remediation"
            )
        if raw_item["future_state_retest_allowed"] is not False:
            raise ValueError(
                "evidence collection request item cannot authorize a retest"
            )

        items.append(
            FutureSecurityEvidenceCollectionItem(
                change_node_id=raw_item["change_node_id"],
                subject_node_id=raw_item["subject_node_id"],
                resolution_id=raw_item["resolution_id"],
                resolution_sha256=raw_item["resolution_sha256"],
                current_attack_path_ids=_strict_optional_string_tuple(
                    raw_item["current_attack_path_ids"],
                    field="current_attack_path_ids",
                ),
                effect_ids=_strict_string_tuple(
                    raw_item["effect_ids"],
                    field="effect_ids",
                ),
                prior_evidence_ids=_strict_string_tuple(
                    raw_item["prior_evidence_ids"],
                    field="prior_evidence_ids",
                ),
                prior_capability_ids=_strict_string_tuple(
                    raw_item["prior_capability_ids"],
                    field="prior_capability_ids",
                ),
                classification=classification,
                graph_diff_action=graph_diff_action,
            )
        )

    parsed_items = tuple(items)
    item_keys = tuple(
        (item.change_node_id, item.subject_node_id, item.resolution_id)
        for item in parsed_items
    )
    if len(set(item_keys)) != len(item_keys):
        raise ValueError("evidence collection request items must be unique")
    canonical_items = tuple(
        sorted(
            parsed_items,
            key=lambda item: (
                item.change_node_id,
                item.subject_node_id,
                item.resolution_id,
            ),
        )
    )
    if parsed_items != canonical_items:
        raise ValueError("evidence collection request items must be canonically ordered")
    if payload["evidence_gap_count"] != len(parsed_items):
        raise ValueError("evidence collection request gap count mismatch")

    request = FutureSecurityEvidenceCollectionRequest(
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
        plan_sha256=payload["plan_sha256"],
        items=parsed_items,
        evidence_gap_count=payload["evidence_gap_count"],
        request_sha256=payload["request_sha256"],
        collection_authorized=False,
        capability_selected=False,
        tool_call_created=False,
        execution_allowed=False,
        target_interaction_allowed=False,
        remediation_authoring_allowed=False,
        future_state_retest_allowed=False,
        deployment_authorized=False,
        attack_path_mutation_allowed=False,
        future_semantics=payload["future_semantics"],
        security_verdict=payload["security_verdict"],
    )
    expected = _request_digest_from_request(request)
    if request.request_sha256 != expected:
        raise ValueError("evidence collection request digest mismatch")
    return request
