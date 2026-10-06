"""Strict serialized handoff for ST5 evidence-sufficiency verifier preflights.

Parsing a persisted preflight proves only serialization integrity. Callers must
still run validate_future_security_evidence_sufficiency_verifier_preflight
against the live sufficiency request, verifier authorization context, upstream
lineage and StateStore before using the preflight.
"""

from __future__ import annotations

from hashlib import sha256
import json

from .future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from .future_security_evidence_sufficiency_verifier_preflight import (
    SUFFICIENCY_VERIFIER_PREFLIGHT_SCHEMA_VERSION,
    FutureSecurityEvidenceSufficiencyVerifierPreflight,
)


_PREFLIGHT_KEYS = {
    "schema_version",
    "client_id",
    "sufficiency_request_sha256",
    "metadata_review_sha256",
    "admission_sha256",
    "source_resolution_id",
    "change_node_id",
    "subject_node_id",
    "candidate_run_id",
    "candidate_evidence_ids",
    "candidate_capability_ids",
    "candidate_classification_claim",
    "verifier_user_id",
    "verifier_role",
    "eligible_for_sufficiency_review",
    "preflight_sha256",
    "sufficiency_decision_created",
    "evidence_sufficiency_evaluated",
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


def _strict_string_list(value: object, *, name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{name} must be a non-empty string list")
    parsed = tuple(_strict_identifier(item, name=name) for item in value)
    if parsed != tuple(sorted(set(parsed))):
        raise ValueError(f"{name} must be sorted and unique")
    return parsed


def _digest_from_preflight(
    preflight: FutureSecurityEvidenceSufficiencyVerifierPreflight,
) -> str:
    payload = preflight.as_dict()
    payload.pop("preflight_sha256")
    return sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def future_security_evidence_sufficiency_verifier_preflight_from_dict(
    payload: dict,
) -> FutureSecurityEvidenceSufficiencyVerifierPreflight:
    """Parse an exact persisted verifier preflight and verify its digest."""

    if not isinstance(payload, dict):
        raise ValueError("evidence sufficiency verifier preflight payload must be an object")
    if set(payload) != _PREFLIGHT_KEYS:
        raise ValueError("evidence sufficiency verifier preflight payload schema mismatch")
    if payload["schema_version"] != SUFFICIENCY_VERIFIER_PREFLIGHT_SCHEMA_VERSION:
        raise ValueError("evidence sufficiency verifier preflight schema version mismatch")

    for field in (
        "client_id",
        "source_resolution_id",
        "change_node_id",
        "subject_node_id",
        "candidate_run_id",
        "verifier_user_id",
    ):
        _strict_identifier(
            payload[field],
            name=f"evidence sufficiency verifier preflight {field}",
        )

    for field in (
        "sufficiency_request_sha256",
        "metadata_review_sha256",
        "admission_sha256",
        "preflight_sha256",
    ):
        _strict_sha256(payload[field], name=field)

    candidate_evidence_ids = _strict_string_list(
        payload["candidate_evidence_ids"],
        name="evidence sufficiency verifier preflight candidate_evidence_ids",
    )
    candidate_capability_ids = _strict_string_list(
        payload["candidate_capability_ids"],
        name="evidence sufficiency verifier preflight candidate_capability_ids",
    )

    raw_claim = payload["candidate_classification_claim"]
    if not isinstance(raw_claim, str):
        raise ValueError(
            "evidence sufficiency verifier preflight classification claim must be a string"
        )
    try:
        classification_claim = AttackPathTransitionClassification(raw_claim)
    except ValueError as exc:
        raise ValueError(
            "evidence sufficiency verifier preflight classification claim is unsupported"
        ) from exc

    if payload["verifier_role"] != "operator":
        raise ValueError(
            "evidence sufficiency verifier preflight verifier role must remain operator"
        )
    if payload["eligible_for_sufficiency_review"] is not True:
        raise ValueError(
            "evidence sufficiency verifier preflight must retain review eligibility"
        )

    for field in (
        "sufficiency_decision_created",
        "evidence_sufficiency_evaluated",
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
                "evidence sufficiency verifier preflight safety flag "
                f"{field} must remain false"
            )

    if payload["future_semantics"] != "unresolved":
        raise ValueError(
            "evidence sufficiency verifier preflight future semantics must remain unresolved"
        )
    if payload["security_verdict"] != "not_evaluated":
        raise ValueError(
            "evidence sufficiency verifier preflight must not claim a security verdict"
        )

    preflight = FutureSecurityEvidenceSufficiencyVerifierPreflight(
        schema_version=payload["schema_version"],
        client_id=payload["client_id"],
        sufficiency_request_sha256=payload["sufficiency_request_sha256"],
        metadata_review_sha256=payload["metadata_review_sha256"],
        admission_sha256=payload["admission_sha256"],
        source_resolution_id=payload["source_resolution_id"],
        change_node_id=payload["change_node_id"],
        subject_node_id=payload["subject_node_id"],
        candidate_run_id=payload["candidate_run_id"],
        candidate_evidence_ids=candidate_evidence_ids,
        candidate_capability_ids=candidate_capability_ids,
        candidate_classification_claim=classification_claim,
        verifier_user_id=payload["verifier_user_id"],
        verifier_role="operator",
        eligible_for_sufficiency_review=True,
        preflight_sha256=payload["preflight_sha256"],
        sufficiency_decision_created=False,
        evidence_sufficiency_evaluated=False,
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
    expected = _digest_from_preflight(preflight)
    if preflight.preflight_sha256 != expected:
        raise ValueError("evidence sufficiency verifier preflight digest mismatch")
    return preflight
