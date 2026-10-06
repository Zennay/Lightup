"""Strict serialized handoff for ST5 evidence-sufficiency attestations.

Parsing a persisted attestation proves only serialization integrity. Callers
must still run validate_future_security_evidence_sufficiency_attestation
against the live verifier, preflight, upstream lineage and StateStore before
using the attestation.
"""

from __future__ import annotations

from hashlib import sha256
import json

from .future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from .future_security_evidence_sufficiency_attestation import (
    SUFFICIENCY_ATTESTATION_SCHEMA_VERSION,
    EvidenceSufficiencyAttestationDisposition,
    FutureSecurityEvidenceSufficiencyAttestation,
    _derived_disposition_flags,
)


_ATTESTATION_KEYS = {
    "schema_version",
    "client_id",
    "sufficiency_request_sha256",
    "verifier_preflight_sha256",
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
    "disposition",
    "evidence_sufficient",
    "classification_claim_justified",
    "needs_more_evidence",
    "eligible_for_classification_review",
    "attestation_sha256",
    "sufficiency_decision_created",
    "evidence_sufficiency_evaluated",
    "classification_justification_evaluated",
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


def _digest_from_attestation(
    attestation: FutureSecurityEvidenceSufficiencyAttestation,
) -> str:
    payload = attestation.as_dict()
    payload.pop("attestation_sha256")
    return sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def future_security_evidence_sufficiency_attestation_from_dict(
    payload: dict,
) -> FutureSecurityEvidenceSufficiencyAttestation:
    """Parse an exact persisted sufficiency attestation and verify its digest."""

    if not isinstance(payload, dict):
        raise ValueError("evidence sufficiency attestation payload must be an object")
    if set(payload) != _ATTESTATION_KEYS:
        raise ValueError("evidence sufficiency attestation payload schema mismatch")
    if payload["schema_version"] != SUFFICIENCY_ATTESTATION_SCHEMA_VERSION:
        raise ValueError("evidence sufficiency attestation schema version mismatch")

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
            name=f"evidence sufficiency attestation {field}",
        )

    for field in (
        "sufficiency_request_sha256",
        "verifier_preflight_sha256",
        "metadata_review_sha256",
        "admission_sha256",
        "attestation_sha256",
    ):
        _strict_sha256(payload[field], name=field)

    candidate_evidence_ids = _strict_string_list(
        payload["candidate_evidence_ids"],
        name="evidence sufficiency attestation candidate_evidence_ids",
    )
    candidate_capability_ids = _strict_string_list(
        payload["candidate_capability_ids"],
        name="evidence sufficiency attestation candidate_capability_ids",
    )

    raw_claim = payload["candidate_classification_claim"]
    if not isinstance(raw_claim, str):
        raise ValueError(
            "evidence sufficiency attestation classification claim must be a string"
        )
    try:
        classification_claim = AttackPathTransitionClassification(raw_claim)
    except ValueError as exc:
        raise ValueError(
            "evidence sufficiency attestation classification claim is unsupported"
        ) from exc

    raw_disposition = payload["disposition"]
    if not isinstance(raw_disposition, str):
        raise ValueError(
            "evidence sufficiency attestation disposition must be a string"
        )
    try:
        disposition = EvidenceSufficiencyAttestationDisposition(raw_disposition)
    except ValueError as exc:
        raise ValueError(
            "evidence sufficiency attestation disposition is unsupported"
        ) from exc

    (
        evidence_sufficient,
        classification_claim_justified,
        needs_more_evidence,
        eligible_for_classification_review,
    ) = _derived_disposition_flags(disposition)

    derived = {
        "evidence_sufficient": evidence_sufficient,
        "classification_claim_justified": classification_claim_justified,
        "needs_more_evidence": needs_more_evidence,
        "eligible_for_classification_review": eligible_for_classification_review,
    }
    for field, expected in derived.items():
        if payload[field] is not expected:
            raise ValueError(
                "evidence sufficiency attestation derived flag "
                f"{field} does not match disposition"
            )

    for field in (
        "sufficiency_decision_created",
        "evidence_sufficiency_evaluated",
        "classification_justification_evaluated",
    ):
        if payload[field] is not True:
            raise ValueError(
                f"evidence sufficiency attestation {field} must remain true"
            )

    for field in (
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
                "evidence sufficiency attestation safety flag "
                f"{field} must remain false"
            )

    if payload["future_semantics"] != "unresolved":
        raise ValueError(
            "evidence sufficiency attestation future semantics must remain unresolved"
        )
    if payload["security_verdict"] != "not_evaluated":
        raise ValueError(
            "evidence sufficiency attestation must not claim a security verdict"
        )

    attestation = FutureSecurityEvidenceSufficiencyAttestation(
        schema_version=payload["schema_version"],
        client_id=payload["client_id"],
        sufficiency_request_sha256=payload["sufficiency_request_sha256"],
        verifier_preflight_sha256=payload["verifier_preflight_sha256"],
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
        disposition=disposition,
        evidence_sufficient=evidence_sufficient,
        classification_claim_justified=classification_claim_justified,
        needs_more_evidence=needs_more_evidence,
        eligible_for_classification_review=eligible_for_classification_review,
        attestation_sha256=payload["attestation_sha256"],
        sufficiency_decision_created=True,
        evidence_sufficiency_evaluated=True,
        classification_justification_evaluated=True,
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
    expected = _digest_from_attestation(attestation)
    if attestation.attestation_sha256 != expected:
        raise ValueError("evidence sufficiency attestation digest mismatch")
    return attestation
