"""Strict persisted handoff for ST5 remediation evidence bundles.

Parsing establishes only structural, semantic and digest integrity. A parsed
bundle is not safe for remediation authoring until it is immediately
revalidated against the current remediation plan, ST4 lineage and StateStore
through validate_future_remediation_evidence_bundle.
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
from .future_remediation_evidence_bundle import (
    BUNDLE_SCHEMA_VERSION,
    FutureRemediationEvidenceBundle,
    FutureRemediationEvidenceItem,
    RemediationEvidenceRef,
    validate_future_remediation_evidence_bundle,
)
from .future_security_remediation_retest_plan import (
    FutureSecurityRemediationRetestPlan,
)
from .state import StateStore


_BUNDLE_KEYS = {
    "schema_version",
    "client_id",
    "current_twin_id",
    "current_twin_version",
    "twin_id",
    "twin_version",
    "changeset_id",
    "report_sha256",
    "plan_sha256",
    "items",
    "remediation_item_count",
    "blocking_evidence_gap_count",
    "remediation_authoring_ready",
    "bundle_sha256",
    "execution_allowed",
    "code_change_authorized",
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
    "current_attack_path_ids",
    "effect_ids",
    "capability_ids",
    "evidence",
    "evidence_manifest_sha256",
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

_REMEDIATION_CLASSIFICATIONS = {
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


def _strict_string_tuple(
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


def _manifest_digest(evidence: tuple[RemediationEvidenceRef, ...]) -> str:
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


def _bundle_digest(bundle: FutureRemediationEvidenceBundle) -> str:
    payload = {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "client_id": bundle.client_id,
        "current_twin_id": bundle.current_twin_id,
        "current_twin_version": bundle.current_twin_version,
        "twin_id": bundle.twin_id,
        "twin_version": bundle.twin_version,
        "changeset_id": bundle.changeset_id,
        "report_sha256": bundle.report_sha256,
        "plan_sha256": bundle.plan_sha256,
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
                "remediation_required": True,
                "future_state_retest_required": True,
            }
            for item in bundle.items
        ],
        "remediation_item_count": bundle.remediation_item_count,
        "blocking_evidence_gap_count": bundle.blocking_evidence_gap_count,
        "remediation_authoring_ready": bundle.remediation_authoring_ready,
        "execution_allowed": False,
        "code_change_authorized": False,
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


def future_remediation_evidence_bundle_from_dict(
    payload: dict,
) -> FutureRemediationEvidenceBundle:
    """Parse one exact persisted bundle and verify all canonical digests."""

    if not isinstance(payload, dict):
        raise ValueError("remediation evidence bundle payload must be an object")
    if set(payload) != _BUNDLE_KEYS:
        raise ValueError("remediation evidence bundle payload schema mismatch")
    if payload["schema_version"] != BUNDLE_SCHEMA_VERSION:
        raise ValueError("remediation evidence bundle schema version mismatch")

    for field in (
        "client_id",
        "current_twin_id",
        "twin_id",
        "changeset_id",
    ):
        _non_empty_string(
            payload[field],
            field=f"remediation evidence bundle {field}",
        )
    for field in ("report_sha256", "plan_sha256", "bundle_sha256"):
        _canonical_sha256(
            payload[field],
            field=f"remediation evidence bundle {field}",
        )
    for field in (
        "current_twin_version",
        "twin_version",
        "remediation_item_count",
        "blocking_evidence_gap_count",
    ):
        _non_negative_int(
            payload[field],
            field=f"remediation evidence bundle {field}",
        )

    if not isinstance(payload["remediation_authoring_ready"], bool):
        raise ValueError(
            "remediation evidence bundle remediation_authoring_ready must be boolean"
        )
    for field in (
        "execution_allowed",
        "code_change_authorized",
        "target_interaction_allowed",
        "deployment_authorized",
        "attack_path_mutation_allowed",
    ):
        if payload[field] is not False:
            raise ValueError(
                f"remediation evidence bundle safety flag {field} must remain false"
            )
    if payload["future_semantics"] != "unresolved":
        raise ValueError(
            "remediation evidence bundle future_semantics must remain unresolved"
        )
    if payload["security_verdict"] != "not_evaluated":
        raise ValueError(
            "remediation evidence bundle security_verdict must remain not_evaluated"
        )

    raw_items = payload["items"]
    if not isinstance(raw_items, list):
        raise ValueError("remediation evidence bundle items must be a list")

    items: list[FutureRemediationEvidenceItem] = []
    item_identities: list[tuple[str, str, str]] = []
    for raw_item in raw_items:
        if not isinstance(raw_item, dict) or set(raw_item) != _ITEM_KEYS:
            raise ValueError("remediation evidence bundle item schema mismatch")

        change_node_id = _non_empty_string(
            raw_item["change_node_id"],
            field="remediation evidence item change_node_id",
        )
        subject_node_id = _non_empty_string(
            raw_item["subject_node_id"],
            field="remediation evidence item subject_node_id",
        )
        resolution_id = _non_empty_string(
            raw_item["resolution_id"],
            field="remediation evidence item resolution_id",
        )
        resolution_sha256 = _canonical_sha256(
            raw_item["resolution_sha256"],
            field="remediation evidence item resolution_sha256",
        )
        evidence_manifest_sha256 = _canonical_sha256(
            raw_item["evidence_manifest_sha256"],
            field="remediation evidence item evidence_manifest_sha256",
        )

        try:
            classification = AttackPathTransitionClassification(
                raw_item["classification"]
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "remediation evidence item classification is invalid"
            ) from exc
        if classification not in _REMEDIATION_CLASSIFICATIONS:
            raise ValueError(
                "remediation evidence item classification is not remediation-authoring eligible"
            )

        if raw_item["remediation_required"] is not True:
            raise ValueError(
                "remediation evidence item remediation_required must remain true"
            )
        if raw_item["future_state_retest_required"] is not True:
            raise ValueError(
                "remediation evidence item future_state_retest_required must remain true"
            )

        current_attack_path_ids = _strict_string_tuple(
            raw_item["current_attack_path_ids"],
            field="remediation evidence item current_attack_path_ids",
        )
        effect_ids = _strict_string_tuple(
            raw_item["effect_ids"],
            field="remediation evidence item effect_ids",
        )
        capability_ids = _strict_string_tuple(
            raw_item["capability_ids"],
            field="remediation evidence item capability_ids",
            require_non_empty=True,
        )

        raw_evidence = raw_item["evidence"]
        if not isinstance(raw_evidence, list) or not raw_evidence:
            raise ValueError(
                "remediation evidence item evidence must be a non-empty list"
            )
        evidence_records: list[RemediationEvidenceRef] = []
        evidence_ids: list[str] = []
        for raw_record in raw_evidence:
            if not isinstance(raw_record, dict) or set(raw_record) != _EVIDENCE_KEYS:
                raise ValueError("remediation evidence reference schema mismatch")
            evidence_id = _non_empty_string(
                raw_record["evidence_id"],
                field="remediation evidence reference evidence_id",
            )
            run_id = _non_empty_string(
                raw_record["run_id"],
                field="remediation evidence reference run_id",
            )
            capability_id = _non_empty_string(
                raw_record["capability_id"],
                field="remediation evidence reference capability_id",
            )
            kind = _non_empty_string(
                raw_record["kind"],
                field="remediation evidence reference kind",
            )
            evidence_sha256 = _canonical_sha256(
                raw_record["sha256"],
                field="remediation evidence reference sha256",
            )
            evidence_ids.append(evidence_id)
            evidence_records.append(
                RemediationEvidenceRef(
                    evidence_id=evidence_id,
                    run_id=run_id,
                    capability_id=capability_id,
                    kind=kind,
                    sha256=evidence_sha256,
                )
            )

        if len(set(evidence_ids)) != len(evidence_ids):
            raise ValueError(
                "remediation evidence item evidence IDs must be unique"
            )
        if evidence_ids != sorted(evidence_ids):
            raise ValueError(
                "remediation evidence item evidence must be canonically ordered"
            )

        evidence = tuple(evidence_records)
        if evidence_manifest_sha256 != _manifest_digest(evidence):
            raise ValueError(
                "remediation evidence item evidence manifest digest mismatch"
            )

        identity = (change_node_id, subject_node_id, resolution_id)
        if identity in item_identities:
            raise ValueError(
                "remediation evidence bundle item identity must be unique"
            )
        item_identities.append(identity)

        items.append(
            FutureRemediationEvidenceItem(
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
                remediation_required=True,
                future_state_retest_required=True,
            )
        )

    if item_identities != sorted(item_identities):
        raise ValueError(
            "remediation evidence bundle items must be canonically ordered"
        )

    parsed_items = tuple(items)
    if payload["remediation_item_count"] != len(parsed_items):
        raise ValueError("remediation evidence bundle item count mismatch")

    expected_ready = (
        bool(parsed_items) and payload["blocking_evidence_gap_count"] == 0
    )
    if payload["remediation_authoring_ready"] != expected_ready:
        raise ValueError(
            "remediation evidence bundle authoring readiness is inconsistent"
        )

    bundle = FutureRemediationEvidenceBundle(
        schema_version=BUNDLE_SCHEMA_VERSION,
        client_id=payload["client_id"],
        current_twin_id=payload["current_twin_id"],
        current_twin_version=payload["current_twin_version"],
        twin_id=payload["twin_id"],
        twin_version=payload["twin_version"],
        changeset_id=payload["changeset_id"],
        report_sha256=payload["report_sha256"],
        plan_sha256=payload["plan_sha256"],
        items=parsed_items,
        remediation_item_count=payload["remediation_item_count"],
        blocking_evidence_gap_count=payload["blocking_evidence_gap_count"],
        remediation_authoring_ready=payload["remediation_authoring_ready"],
        bundle_sha256=payload["bundle_sha256"],
        execution_allowed=False,
        code_change_authorized=False,
        target_interaction_allowed=False,
        deployment_authorized=False,
        attack_path_mutation_allowed=False,
        future_semantics="unresolved",
        security_verdict="not_evaluated",
    )
    if bundle.bundle_sha256 != _bundle_digest(bundle):
        raise ValueError("remediation evidence bundle digest mismatch")
    return bundle


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict:
    payload: dict = {}
    for key, value in pairs:
        if key in payload:
            raise ValueError(
                f"duplicate JSON key in remediation evidence bundle: {key}"
            )
        payload[key] = value
    return payload


def future_remediation_evidence_bundle_from_json(
    raw: str,
) -> FutureRemediationEvidenceBundle:
    """Decode raw JSON without duplicate-key collapse, then parse strictly."""

    if not isinstance(raw, str) or not raw:
        raise ValueError(
            "remediation evidence bundle JSON must be a non-empty string"
        )
    try:
        payload = json.loads(raw, object_pairs_hook=_reject_duplicate_json_keys)
    except json.JSONDecodeError as exc:
        raise ValueError("remediation evidence bundle JSON is invalid") from exc
    return future_remediation_evidence_bundle_from_dict(payload)


def load_and_validate_future_remediation_evidence_bundle(
    persisted: object,
    plan: FutureSecurityRemediationRetestPlan,
    report: FutureAttackPathSecurityDeltaReport,
    preview: FutureAttackPathGraphDiffPreview,
    proposal: FutureAttackPathTransitionProposal,
    resolutions: tuple[FutureAttackPathTransitionResolution, ...],
    contexts: tuple[RunContext, ...],
    state: StateStore,
) -> FutureRemediationEvidenceBundle:
    """Strictly parse persisted input and immediately require live validity."""

    if isinstance(persisted, str):
        parsed = future_remediation_evidence_bundle_from_json(persisted)
    elif isinstance(persisted, dict):
        parsed = future_remediation_evidence_bundle_from_dict(persisted)
    else:
        raise ValueError(
            "remediation evidence bundle persisted value must be JSON text or object"
        )

    return validate_future_remediation_evidence_bundle(
        parsed,
        plan,
        report,
        preview,
        proposal,
        resolutions,
        contexts,
        state,
    )
