"""Strict persisted handoff for the ST5 isolated future-state retest request.

Parsing proves only that persisted request metadata is structurally exact,
semantically coherent, and digest-consistent. A parsed request is not execution
or target-interaction authority. Follow-up consumers must still rebuild and
revalidate it against the live remediation/retest plan, ST4 lineage, and
StateStore.
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
    FutureRemediationNextAction,
    FutureSecurityRemediationRetestPlan,
)
from .future_security_retest_request import (
    RETEST_REQUEST_SCHEMA_VERSION,
    FutureSecurityRetestRequest,
    FutureSecurityRetestRequestItem,
    FutureStateRetestPurpose,
    build_future_security_retest_request,
)
from .state import StateStore


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
    "remediation_plan_sha256",
    "items",
    "requested_capability_ids",
    "evidence_ids",
    "request_sha256",
    "request_complete",
    "isolated_future_state_required",
    "execution_allowed",
    "target_interaction_allowed",
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
    "source_next_action",
    "purpose",
    "remediation_required",
    "current_attack_path_ids",
    "effect_ids",
    "evidence_ids",
    "capability_ids",
}


def _is_canonical_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _non_empty_string(value: object, *, field: str) -> str:
    if type(value) is not str or not value:
        raise ValueError(f"future-state retest request {field} must be a non-empty string")
    return value


def _string_tuple(
    value: object,
    *,
    field: str,
    require_non_empty: bool = False,
    require_sorted: bool = False,
) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError(f"future-state retest request {field} must be a string list")
    if any(type(item) is not str or not item for item in value):
        raise ValueError(
            f"future-state retest request {field} must contain non-empty strings"
        )
    parsed = tuple(value)
    if require_non_empty and not parsed:
        raise ValueError(f"future-state retest request {field} must not be empty")
    if len(set(parsed)) != len(parsed):
        raise ValueError(f"future-state retest request {field} must not contain duplicates")
    if require_sorted and tuple(sorted(parsed)) != parsed:
        raise ValueError(
            f"future-state retest request {field} must use canonical sorted order"
        )
    return parsed


def _expected_item_semantics(
    classification: AttackPathTransitionClassification,
) -> tuple[
    AttackPathGraphDiffAction,
    FutureRemediationNextAction,
    FutureStateRetestPurpose,
    bool,
]:
    if classification is AttackPathTransitionClassification.INTRODUCED:
        return (
            AttackPathGraphDiffAction.ADD_PATH_HYPOTHESIS,
            FutureRemediationNextAction.AUTHOR_REMEDIATION_THEN_RETEST,
            FutureStateRetestPurpose.REMEDIATION_VALIDATION,
            True,
        )
    if classification is AttackPathTransitionClassification.WORSENED:
        return (
            AttackPathGraphDiffAction.MODIFY_EXISTING_PATH_RISK_UP,
            FutureRemediationNextAction.AUTHOR_REMEDIATION_THEN_RETEST,
            FutureStateRetestPurpose.REMEDIATION_VALIDATION,
            True,
        )
    if classification is AttackPathTransitionClassification.IMPROVED:
        return (
            AttackPathGraphDiffAction.MODIFY_EXISTING_PATH_RISK_DOWN,
            FutureRemediationNextAction.VERIFY_IMPROVEMENT_WITH_RETEST,
            FutureStateRetestPurpose.IMPROVEMENT_VERIFICATION,
            False,
        )
    if classification is AttackPathTransitionClassification.REMOVED:
        return (
            AttackPathGraphDiffAction.REMOVE_EXISTING_PATH_CANDIDATE,
            FutureRemediationNextAction.VERIFY_IMPROVEMENT_WITH_RETEST,
            FutureStateRetestPurpose.IMPROVEMENT_VERIFICATION,
            False,
        )
    raise ValueError(
        "future-state retest request item classification cannot produce a retest"
    )


def _request_digest_from_request(request: FutureSecurityRetestRequest) -> str:
    payload = {
        "schema_version": RETEST_REQUEST_SCHEMA_VERSION,
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
        "remediation_plan_sha256": request.remediation_plan_sha256,
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
            for item in request.items
        ],
        "requested_capability_ids": list(request.requested_capability_ids),
        "evidence_ids": list(request.evidence_ids),
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


def future_security_retest_request_from_dict(
    payload: dict,
) -> FutureSecurityRetestRequest:
    """Parse one exact serialized retest request and verify its semantic digest."""

    if not isinstance(payload, dict):
        raise ValueError("future-state retest request payload must be an object")
    if set(payload) != _REQUEST_KEYS:
        raise ValueError("future-state retest request payload schema mismatch")
    if payload["schema_version"] != RETEST_REQUEST_SCHEMA_VERSION:
        raise ValueError("future-state retest request schema version mismatch")

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
        "remediation_plan_sha256",
        "request_sha256",
    ):
        if not _is_canonical_sha256(payload[field]):
            raise ValueError(
                f"future-state retest request {field} must be a canonical SHA-256"
            )

    for field in ("current_twin_version", "twin_version"):
        value = payload[field]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(
                f"future-state retest request {field} must be a non-negative integer"
            )

    if payload["request_complete"] is not True:
        raise ValueError("future-state retest request must remain complete")
    if payload["isolated_future_state_required"] is not True:
        raise ValueError(
            "future-state retest request must require isolated future state"
        )
    for field in (
        "execution_allowed",
        "target_interaction_allowed",
        "deployment_authorized",
        "attack_path_mutation_allowed",
    ):
        if payload[field] is not False:
            raise ValueError(
                f"future-state retest request safety flag {field} must remain false"
            )
    if payload["future_semantics"] != "unresolved":
        raise ValueError("future-state retest request future semantics must be unresolved")
    if payload["security_verdict"] != "not_evaluated":
        raise ValueError("future-state retest request must not claim a security verdict")

    raw_items = payload["items"]
    if not isinstance(raw_items, list) or not raw_items:
        raise ValueError("future-state retest request items must be a non-empty list")

    items: list[FutureSecurityRetestRequestItem] = []
    identities: set[tuple[str, str, str]] = set()
    for raw_item in raw_items:
        if not isinstance(raw_item, dict) or set(raw_item) != _ITEM_KEYS:
            raise ValueError("future-state retest request item schema mismatch")

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
                "future-state retest request item resolution_sha256 must be canonical"
            )

        for field in (
            "classification",
            "graph_diff_action",
            "source_next_action",
            "purpose",
        ):
            if type(raw_item[field]) is not str:
                raise ValueError(
                    f"future-state retest request item {field} must be a string"
                )

        try:
            classification = AttackPathTransitionClassification(
                raw_item["classification"]
            )
            graph_diff_action = AttackPathGraphDiffAction(
                raw_item["graph_diff_action"]
            )
            source_next_action = FutureRemediationNextAction(
                raw_item["source_next_action"]
            )
            purpose = FutureStateRetestPurpose(raw_item["purpose"])
        except ValueError as exc:
            raise ValueError("future-state retest request item enum value is invalid") from exc

        if not isinstance(raw_item["remediation_required"], bool):
            raise ValueError(
                "future-state retest request item remediation_required must be boolean"
            )

        expected = _expected_item_semantics(classification)
        actual = (
            graph_diff_action,
            source_next_action,
            purpose,
            raw_item["remediation_required"],
        )
        if actual != expected:
            raise ValueError(
                "future-state retest request item graph/action/purpose semantics mismatch"
            )

        identity = (change_node_id, subject_node_id, resolution_id)
        if identity in identities:
            raise ValueError("future-state retest request item identity must be unique")
        identities.add(identity)

        items.append(
            FutureSecurityRetestRequestItem(
                change_node_id=change_node_id,
                subject_node_id=subject_node_id,
                resolution_id=resolution_id,
                resolution_sha256=raw_item["resolution_sha256"],
                classification=classification,
                graph_diff_action=graph_diff_action,
                source_next_action=source_next_action,
                purpose=purpose,
                remediation_required=raw_item["remediation_required"],
                current_attack_path_ids=_string_tuple(
                    raw_item["current_attack_path_ids"],
                    field="item.current_attack_path_ids",
                ),
                effect_ids=_string_tuple(
                    raw_item["effect_ids"],
                    field="item.effect_ids",
                ),
                evidence_ids=_string_tuple(
                    raw_item["evidence_ids"],
                    field="item.evidence_ids",
                ),
                capability_ids=_string_tuple(
                    raw_item["capability_ids"],
                    field="item.capability_ids",
                ),
            )
        )

    parsed_items = tuple(items)
    requested_capability_ids = _string_tuple(
        payload["requested_capability_ids"],
        field="requested_capability_ids",
        require_non_empty=True,
        require_sorted=True,
    )
    evidence_ids = _string_tuple(
        payload["evidence_ids"],
        field="evidence_ids",
        require_non_empty=True,
        require_sorted=True,
    )

    expected_capabilities = tuple(
        sorted({value for item in parsed_items for value in item.capability_ids})
    )
    expected_evidence = tuple(
        sorted({value for item in parsed_items for value in item.evidence_ids})
    )
    if requested_capability_ids != expected_capabilities:
        raise ValueError(
            "future-state retest request requested capabilities do not match item lineage"
        )
    if evidence_ids != expected_evidence:
        raise ValueError(
            "future-state retest request evidence ids do not match item lineage"
        )

    request = FutureSecurityRetestRequest(
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
        remediation_plan_sha256=payload["remediation_plan_sha256"],
        items=parsed_items,
        requested_capability_ids=requested_capability_ids,
        evidence_ids=evidence_ids,
        request_sha256=payload["request_sha256"],
        request_complete=True,
        isolated_future_state_required=True,
        execution_allowed=False,
        target_interaction_allowed=False,
        deployment_authorized=False,
        attack_path_mutation_allowed=False,
        future_semantics=payload["future_semantics"],
        security_verdict=payload["security_verdict"],
    )
    if request.request_sha256 != _request_digest_from_request(request):
        raise ValueError("future-state retest request digest mismatch")
    return request


def validate_future_security_retest_request_handoff(
    request: FutureSecurityRetestRequest,
    plan: FutureSecurityRemediationRetestPlan,
    report: FutureAttackPathSecurityDeltaReport,
    preview: FutureAttackPathGraphDiffPreview,
    proposal: FutureAttackPathTransitionProposal,
    resolutions: tuple[FutureAttackPathTransitionResolution, ...],
    contexts: tuple[RunContext, ...],
    state: StateStore,
) -> FutureSecurityRetestRequest:
    """Require exact equality with a request rebuilt from live validated lineage."""

    if not isinstance(request, FutureSecurityRetestRequest):
        raise ValueError("request must be a FutureSecurityRetestRequest")
    rebuilt = build_future_security_retest_request(
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
            "future-state retest request does not match its live validated lineage"
        )
    return rebuilt


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key in future-state retest request: {key}")
        result[key] = value
    return result


def future_security_retest_request_from_json(
    raw: str,
) -> FutureSecurityRetestRequest:
    """Decode JSON without duplicate-key collapse, then apply the strict parser."""

    if type(raw) is not str or not raw:
        raise ValueError("future-state retest request JSON must be a non-empty string")
    try:
        payload = json.loads(raw, object_pairs_hook=_reject_duplicate_json_keys)
    except json.JSONDecodeError as exc:
        raise ValueError("future-state retest request JSON is invalid") from exc
    return future_security_retest_request_from_dict(payload)
