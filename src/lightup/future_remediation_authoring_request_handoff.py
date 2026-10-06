"""Strict persisted handoff for ST5 remediation authoring requests.

Structural parsing is not authoring authority. Persisted input must pass this
strict boundary and then be revalidated against the live remediation evidence
bundle and upstream ST4/ST5 lineage before any later remediation-advisor use.
"""

from __future__ import annotations

from hashlib import sha256
import json

from .ai.orchestration import RunContext
from .future_attack_path_graph_diff_preview import FutureAttackPathGraphDiffPreview
from .future_attack_path_security_delta_report import FutureAttackPathSecurityDeltaReport
from .future_attack_path_transition import FutureAttackPathTransitionProposal
from .future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
    FutureAttackPathTransitionResolution,
)
from .future_remediation_authoring_request import (
    AUTHORING_REQUEST_SCHEMA_VERSION,
    FutureRemediationAuthoringRequest,
    FutureRemediationAuthoringRequestItem,
    RemediationAuthoringEvidenceRef,
    validate_future_remediation_authoring_request,
)
from .future_remediation_evidence_bundle import FutureRemediationEvidenceBundle
from .future_security_remediation_retest_plan import (
    FutureSecurityRemediationRetestPlan,
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
    "report_sha256",
    "plan_sha256",
    "bundle_sha256",
    "items",
    "item_count",
    "request_sha256",
    "authoring_requested",
    "remediation_proposal_created",
    "code_change_authorized",
    "tool_call_created",
    "execution_allowed",
    "target_interaction_allowed",
    "future_state_retest_allowed",
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
    "current_attack_path_ids",
    "effect_ids",
    "capability_ids",
    "evidence",
    "evidence_manifest_sha256",
    "requested_output",
    "remediation_required",
    "future_state_retest_required",
}

_EVIDENCE_KEYS = {
    "evidence_id",
    "run_id",
    "capability_id",
    "kind",
    "sha256",
}

_ALLOWED_CLASSIFICATIONS = {
    AttackPathTransitionClassification.INTRODUCED,
    AttackPathTransitionClassification.WORSENED,
}


def _canonical_sha256(value: object, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{field} must be a canonical lowercase SHA-256 digest")
    return value


def _non_empty_string(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _non_negative_int(value: object, *, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{field} must be a non-negative integer")
    return value


def _string_tuple(
    value: object,
    *,
    field: str,
    require_non_empty: bool = False,
) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a string list")
    if require_non_empty and not value:
        raise ValueError(f"{field} must not be empty")
    if any(not isinstance(item, str) or not item for item in value):
        raise ValueError(f"{field} must contain non-empty strings")
    parsed = tuple(value)
    if len(set(parsed)) != len(parsed):
        raise ValueError(f"{field} must not contain duplicates")
    return parsed


def _manifest_digest(
    evidence: tuple[RemediationAuthoringEvidenceRef, ...],
) -> str:
    payload = [
        {
            "evidence_id": record.evidence_id,
            "run_id": record.run_id,
            "capability_id": record.capability_id,
            "kind": record.kind,
            "sha256": record.sha256,
        }
        for record in evidence
    ]
    return sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def _request_digest(request: FutureRemediationAuthoringRequest) -> str:
    payload = {
        "schema_version": AUTHORING_REQUEST_SCHEMA_VERSION,
        "client_id": request.client_id,
        "current_twin_id": request.current_twin_id,
        "current_twin_version": request.current_twin_version,
        "twin_id": request.twin_id,
        "twin_version": request.twin_version,
        "changeset_id": request.changeset_id,
        "report_sha256": request.report_sha256,
        "plan_sha256": request.plan_sha256,
        "bundle_sha256": request.bundle_sha256,
        "items": [
            {
                "change_node_id": item.change_node_id,
                "subject_node_id": item.subject_node_id,
                "resolution_id": item.resolution_id,
                "resolution_sha256": item.resolution_sha256,
                "classification": item.classification.value,
                "current_attack_path_ids": list(item.current_attack_path_ids),
                "effect_ids": list(item.effect_ids),
                "capability_ids": list(item.capability_ids),
                "evidence": [record.as_dict() for record in item.evidence],
                "evidence_manifest_sha256": item.evidence_manifest_sha256,
                "requested_output": "remediation_text_proposal",
                "remediation_required": True,
                "future_state_retest_required": True,
            }
            for item in request.items
        ],
        "item_count": request.item_count,
        "authoring_requested": True,
        "remediation_proposal_created": False,
        "code_change_authorized": False,
        "tool_call_created": False,
        "execution_allowed": False,
        "target_interaction_allowed": False,
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


def future_remediation_authoring_request_from_dict(
    payload: dict,
) -> FutureRemediationAuthoringRequest:
    """Parse one exact persisted authoring request and verify canonical digests."""

    if not isinstance(payload, dict):
        raise ValueError("remediation authoring request payload must be an object")
    if set(payload) != _REQUEST_KEYS:
        raise ValueError("remediation authoring request payload schema mismatch")
    if payload["schema_version"] != AUTHORING_REQUEST_SCHEMA_VERSION:
        raise ValueError("remediation authoring request schema version mismatch")

    for field in (
        "client_id",
        "current_twin_id",
        "twin_id",
        "changeset_id",
    ):
        _non_empty_string(
            payload[field],
            field=f"remediation authoring request {field}",
        )
    for field in (
        "report_sha256",
        "plan_sha256",
        "bundle_sha256",
        "request_sha256",
    ):
        _canonical_sha256(
            payload[field],
            field=f"remediation authoring request {field}",
        )
    for field in ("current_twin_version", "twin_version", "item_count"):
        _non_negative_int(
            payload[field],
            field=f"remediation authoring request {field}",
        )

    if payload["authoring_requested"] is not True:
        raise ValueError(
            "remediation authoring request authoring_requested must remain true"
        )
    for field in (
        "remediation_proposal_created",
        "code_change_authorized",
        "tool_call_created",
        "execution_allowed",
        "target_interaction_allowed",
        "future_state_retest_allowed",
        "deployment_authorized",
        "attack_path_mutation_allowed",
    ):
        if payload[field] is not False:
            raise ValueError(
                f"remediation authoring request authority flag {field} must remain false"
            )
    if payload["future_semantics"] != "unresolved":
        raise ValueError(
            "remediation authoring request future_semantics must remain unresolved"
        )
    if payload["security_verdict"] != "not_evaluated":
        raise ValueError(
            "remediation authoring request security_verdict must remain not_evaluated"
        )

    raw_items = payload["items"]
    if not isinstance(raw_items, list) or not raw_items:
        raise ValueError(
            "remediation authoring request items must be a non-empty list"
        )

    items: list[FutureRemediationAuthoringRequestItem] = []
    item_identities: list[tuple[str, str, str]] = []
    for raw_item in raw_items:
        if not isinstance(raw_item, dict) or set(raw_item) != _ITEM_KEYS:
            raise ValueError("remediation authoring request item schema mismatch")

        change_node_id = _non_empty_string(
            raw_item["change_node_id"],
            field="remediation authoring item change_node_id",
        )
        subject_node_id = _non_empty_string(
            raw_item["subject_node_id"],
            field="remediation authoring item subject_node_id",
        )
        resolution_id = _non_empty_string(
            raw_item["resolution_id"],
            field="remediation authoring item resolution_id",
        )
        resolution_sha256 = _canonical_sha256(
            raw_item["resolution_sha256"],
            field="remediation authoring item resolution_sha256",
        )
        evidence_manifest_sha256 = _canonical_sha256(
            raw_item["evidence_manifest_sha256"],
            field="remediation authoring item evidence_manifest_sha256",
        )

        try:
            classification = AttackPathTransitionClassification(
                raw_item["classification"]
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "remediation authoring item classification is invalid"
            ) from exc
        if classification not in _ALLOWED_CLASSIFICATIONS:
            raise ValueError(
                "remediation authoring item classification is not authoring eligible"
            )

        if raw_item["requested_output"] != "remediation_text_proposal":
            raise ValueError(
                "remediation authoring item requested_output must remain remediation_text_proposal"
            )
        if raw_item["remediation_required"] is not True:
            raise ValueError(
                "remediation authoring item remediation_required must remain true"
            )
        if raw_item["future_state_retest_required"] is not True:
            raise ValueError(
                "remediation authoring item future_state_retest_required must remain true"
            )

        current_attack_path_ids = _string_tuple(
            raw_item["current_attack_path_ids"],
            field="remediation authoring item current_attack_path_ids",
        )
        effect_ids = _string_tuple(
            raw_item["effect_ids"],
            field="remediation authoring item effect_ids",
        )
        capability_ids = _string_tuple(
            raw_item["capability_ids"],
            field="remediation authoring item capability_ids",
            require_non_empty=True,
        )

        raw_evidence = raw_item["evidence"]
        if not isinstance(raw_evidence, list) or not raw_evidence:
            raise ValueError(
                "remediation authoring item evidence must be a non-empty list"
            )
        evidence_records: list[RemediationAuthoringEvidenceRef] = []
        evidence_ids: list[str] = []
        for raw_record in raw_evidence:
            if not isinstance(raw_record, dict) or set(raw_record) != _EVIDENCE_KEYS:
                raise ValueError("remediation authoring evidence schema mismatch")
            evidence_id = _non_empty_string(
                raw_record["evidence_id"],
                field="remediation authoring evidence evidence_id",
            )
            run_id = _non_empty_string(
                raw_record["run_id"],
                field="remediation authoring evidence run_id",
            )
            capability_id = _non_empty_string(
                raw_record["capability_id"],
                field="remediation authoring evidence capability_id",
            )
            kind = _non_empty_string(
                raw_record["kind"],
                field="remediation authoring evidence kind",
            )
            evidence_sha256 = _canonical_sha256(
                raw_record["sha256"],
                field="remediation authoring evidence sha256",
            )
            if capability_id not in capability_ids:
                raise ValueError(
                    "remediation authoring evidence capability is outside item lineage"
                )
            evidence_ids.append(evidence_id)
            evidence_records.append(
                RemediationAuthoringEvidenceRef(
                    evidence_id=evidence_id,
                    run_id=run_id,
                    capability_id=capability_id,
                    kind=kind,
                    sha256=evidence_sha256,
                )
            )

        if len(set(evidence_ids)) != len(evidence_ids):
            raise ValueError(
                "remediation authoring evidence IDs must be unique"
            )
        if evidence_ids != sorted(evidence_ids):
            raise ValueError(
                "remediation authoring evidence must be canonically ordered"
            )

        evidence = tuple(evidence_records)
        if evidence_manifest_sha256 != _manifest_digest(evidence):
            raise ValueError(
                "remediation authoring evidence manifest digest mismatch"
            )

        identity = (change_node_id, subject_node_id, resolution_id)
        if identity in item_identities:
            raise ValueError(
                "remediation authoring request item identity must be unique"
            )
        item_identities.append(identity)

        items.append(
            FutureRemediationAuthoringRequestItem(
                change_node_id=change_node_id,
                subject_node_id=subject_node_id,
                resolution_id=resolution_id,
                resolution_sha256=resolution_sha256,
                classification=classification,
                current_attack_path_ids=current_attack_path_ids,
                effect_ids=effect_ids,
                capability_ids=capability_ids,
                evidence=evidence,
                evidence_manifest_sha256=evidence_manifest_sha256,
                requested_output="remediation_text_proposal",
                remediation_required=True,
                future_state_retest_required=True,
            )
        )

    if item_identities != sorted(item_identities):
        raise ValueError(
            "remediation authoring request items must be canonically ordered"
        )

    parsed_items = tuple(items)
    if payload["item_count"] != len(parsed_items):
        raise ValueError("remediation authoring request item count mismatch")

    request = FutureRemediationAuthoringRequest(
        schema_version=AUTHORING_REQUEST_SCHEMA_VERSION,
        client_id=payload["client_id"],
        current_twin_id=payload["current_twin_id"],
        current_twin_version=payload["current_twin_version"],
        twin_id=payload["twin_id"],
        twin_version=payload["twin_version"],
        changeset_id=payload["changeset_id"],
        report_sha256=payload["report_sha256"],
        plan_sha256=payload["plan_sha256"],
        bundle_sha256=payload["bundle_sha256"],
        items=parsed_items,
        item_count=payload["item_count"],
        request_sha256=payload["request_sha256"],
        authoring_requested=True,
        remediation_proposal_created=False,
        code_change_authorized=False,
        tool_call_created=False,
        execution_allowed=False,
        target_interaction_allowed=False,
        future_state_retest_allowed=False,
        deployment_authorized=False,
        attack_path_mutation_allowed=False,
        future_semantics="unresolved",
        security_verdict="not_evaluated",
    )
    if request.request_sha256 != _request_digest(request):
        raise ValueError("remediation authoring request digest mismatch")
    return request


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict:
    payload: dict = {}
    for key, value in pairs:
        if key in payload:
            raise ValueError(
                f"duplicate JSON key in remediation authoring request: {key}"
            )
        payload[key] = value
    return payload


def future_remediation_authoring_request_from_json(
    raw: str,
) -> FutureRemediationAuthoringRequest:
    """Decode JSON without duplicate-key collapse, then apply the strict parser."""

    if not isinstance(raw, str) or not raw:
        raise ValueError(
            "remediation authoring request JSON must be a non-empty string"
        )
    try:
        payload = json.loads(raw, object_pairs_hook=_reject_duplicate_json_keys)
    except json.JSONDecodeError as exc:
        raise ValueError("remediation authoring request JSON is invalid") from exc
    return future_remediation_authoring_request_from_dict(payload)


def load_and_validate_future_remediation_authoring_request(
    persisted: object,
    bundle: FutureRemediationEvidenceBundle,
    plan: FutureSecurityRemediationRetestPlan,
    report: FutureAttackPathSecurityDeltaReport,
    preview: FutureAttackPathGraphDiffPreview,
    proposal: FutureAttackPathTransitionProposal,
    resolutions: tuple[FutureAttackPathTransitionResolution, ...],
    contexts: tuple[RunContext, ...],
    state: StateStore,
) -> FutureRemediationAuthoringRequest:
    """Strictly parse persisted input and immediately require live validity."""

    if isinstance(persisted, str):
        parsed = future_remediation_authoring_request_from_json(persisted)
    elif isinstance(persisted, dict):
        parsed = future_remediation_authoring_request_from_dict(persisted)
    else:
        raise ValueError(
            "remediation authoring request persisted value must be JSON text or object"
        )

    return validate_future_remediation_authoring_request(
        parsed,
        bundle,
        plan,
        report,
        preview,
        proposal,
        resolutions,
        contexts,
        state,
    )
