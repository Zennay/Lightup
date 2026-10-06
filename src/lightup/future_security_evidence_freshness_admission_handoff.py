"""Strict serialized handoff for ST5 evidence freshness admissions.

Parsing a persisted admission proves only serialization integrity. Callers must
still run validate_future_security_evidence_freshness_admission against the
live request, constraints, lineage and StateStore before using the admission.
"""

from __future__ import annotations

from hashlib import sha256
import json

from .future_security_evidence_freshness_admission import (
    ADMISSION_SCHEMA_VERSION,
    CandidateEvidenceFingerprint,
    FutureSecurityEvidenceFreshnessAdmission,
)


_ADMISSION_KEYS = {
    "schema_version",
    "client_id",
    "current_twin_id",
    "current_twin_version",
    "twin_id",
    "twin_version",
    "changeset_id",
    "request_sha256",
    "constraints_sha256",
    "source_resolution_id",
    "change_node_id",
    "subject_node_id",
    "candidate_run_id",
    "candidate_evidence",
    "candidate_evidence_ids",
    "candidate_capability_ids",
    "admission_sha256",
    "freshness_check_passed",
    "evidence_suitability_evaluated",
    "classification_selected",
    "transition_resolution_created",
    "collection_authorized",
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

_CANDIDATE_EVIDENCE_KEYS = {
    "evidence_id",
    "run_id",
    "capability_id",
    "kind",
    "sha256",
}


def _strict_identifier(value: object, *, name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{name} must be a canonical non-empty string")
    if len(value) > 256 or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError(f"{name} is not canonical")
    return value


def _strict_sha256(value: object, *, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise ValueError(f"{name} must be a canonical lowercase SHA-256")
    return value


def _strict_string_list(
    value: object,
    *,
    name: str,
    allow_empty: bool = False,
) -> tuple[str, ...]:
    if not isinstance(value, list) or (not allow_empty and not value):
        qualifier = "" if allow_empty else " non-empty"
        raise ValueError(f"{name} must be a{qualifier} string list")
    parsed = tuple(_strict_identifier(item, name=name) for item in value)
    if parsed != tuple(sorted(set(parsed))):
        raise ValueError(f"{name} must be sorted and unique")
    return parsed


def _digest_from_admission(
    admission: FutureSecurityEvidenceFreshnessAdmission,
) -> str:
    payload = admission.as_dict()
    payload.pop("admission_sha256")
    return sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def future_security_evidence_freshness_admission_from_dict(
    payload: dict,
) -> FutureSecurityEvidenceFreshnessAdmission:
    """Parse an exact persisted freshness admission and verify its digest."""

    if not isinstance(payload, dict):
        raise ValueError("evidence freshness admission payload must be an object")
    if set(payload) != _ADMISSION_KEYS:
        raise ValueError("evidence freshness admission payload schema mismatch")
    if payload["schema_version"] != ADMISSION_SCHEMA_VERSION:
        raise ValueError("evidence freshness admission schema version mismatch")

    for field in (
        "client_id",
        "current_twin_id",
        "twin_id",
        "changeset_id",
        "source_resolution_id",
        "change_node_id",
        "subject_node_id",
        "candidate_run_id",
    ):
        _strict_identifier(
            payload[field],
            name=f"evidence freshness admission {field}",
        )

    for field in ("request_sha256", "constraints_sha256", "admission_sha256"):
        _strict_sha256(payload[field], name=field)

    for field in ("current_twin_version", "twin_version"):
        value = payload[field]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(
                f"evidence freshness admission {field} must be a non-negative integer"
            )

    if payload["freshness_check_passed"] is not True:
        raise ValueError("evidence freshness admission must retain a passed freshness check")

    for field in (
        "evidence_suitability_evaluated",
        "classification_selected",
        "transition_resolution_created",
        "collection_authorized",
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
                f"evidence freshness admission safety flag {field} must remain false"
            )

    if payload["future_semantics"] != "unresolved":
        raise ValueError(
            "evidence freshness admission future semantics must remain unresolved"
        )
    if payload["security_verdict"] != "not_evaluated":
        raise ValueError("evidence freshness admission must not claim a security verdict")

    raw_evidence = payload["candidate_evidence"]
    if not isinstance(raw_evidence, list) or not raw_evidence:
        raise ValueError(
            "evidence freshness admission candidate_evidence must be a non-empty list"
        )

    evidence: list[CandidateEvidenceFingerprint] = []
    for raw in raw_evidence:
        if not isinstance(raw, dict) or set(raw) != _CANDIDATE_EVIDENCE_KEYS:
            raise ValueError(
                "evidence freshness admission candidate evidence schema mismatch"
            )
        evidence_id = _strict_identifier(
            raw["evidence_id"],
            name="evidence freshness admission evidence_id",
        )
        run_id = _strict_identifier(
            raw["run_id"],
            name="evidence freshness admission evidence run_id",
        )
        capability_id = _strict_identifier(
            raw["capability_id"],
            name="evidence freshness admission capability_id",
        )
        kind = _strict_identifier(
            raw["kind"],
            name="evidence freshness admission evidence kind",
        )
        digest = _strict_sha256(
            raw["sha256"],
            name="candidate evidence sha256",
        )
        if run_id != payload["candidate_run_id"]:
            raise ValueError(
                "evidence freshness admission candidate evidence run must match candidate_run_id"
            )
        evidence.append(
            CandidateEvidenceFingerprint(
                evidence_id=evidence_id,
                run_id=run_id,
                capability_id=capability_id,
                kind=kind,
                sha256=digest,
            )
        )

    candidate_evidence = tuple(evidence)
    canonical_evidence = tuple(
        sorted(candidate_evidence, key=lambda item: item.evidence_id)
    )
    if candidate_evidence != canonical_evidence:
        raise ValueError(
            "evidence freshness admission candidate evidence must be canonically ordered"
        )
    evidence_ids = tuple(item.evidence_id for item in candidate_evidence)
    if len(set(evidence_ids)) != len(evidence_ids):
        raise ValueError(
            "evidence freshness admission candidate evidence IDs must be unique"
        )

    candidate_evidence_ids = _strict_string_list(
        payload["candidate_evidence_ids"],
        name="evidence freshness admission candidate_evidence_ids",
    )
    if candidate_evidence_ids != evidence_ids:
        raise ValueError(
            "evidence freshness admission candidate evidence IDs must match fingerprints"
        )

    candidate_capability_ids = _strict_string_list(
        payload["candidate_capability_ids"],
        name="evidence freshness admission candidate_capability_ids",
    )
    live_capabilities = tuple(
        sorted({item.capability_id for item in candidate_evidence})
    )
    if candidate_capability_ids != live_capabilities:
        raise ValueError(
            "evidence freshness admission candidate capabilities must match fingerprints"
        )

    admission = FutureSecurityEvidenceFreshnessAdmission(
        schema_version=payload["schema_version"],
        client_id=payload["client_id"],
        current_twin_id=payload["current_twin_id"],
        current_twin_version=payload["current_twin_version"],
        twin_id=payload["twin_id"],
        twin_version=payload["twin_version"],
        changeset_id=payload["changeset_id"],
        request_sha256=payload["request_sha256"],
        constraints_sha256=payload["constraints_sha256"],
        source_resolution_id=payload["source_resolution_id"],
        change_node_id=payload["change_node_id"],
        subject_node_id=payload["subject_node_id"],
        candidate_run_id=payload["candidate_run_id"],
        candidate_evidence=candidate_evidence,
        candidate_evidence_ids=candidate_evidence_ids,
        candidate_capability_ids=candidate_capability_ids,
        admission_sha256=payload["admission_sha256"],
        freshness_check_passed=True,
        evidence_suitability_evaluated=False,
        classification_selected=False,
        transition_resolution_created=False,
        collection_authorized=False,
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
    expected = _digest_from_admission(admission)
    if admission.admission_sha256 != expected:
        raise ValueError("evidence freshness admission digest mismatch")
    return admission
