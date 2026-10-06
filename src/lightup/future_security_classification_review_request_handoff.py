"""Strict serialized handoff for ST5 classification-review requests.

Parsing a persisted classification-review request proves only serialization
integrity. Callers must still run
validate_future_security_classification_review_request against the live
attestation and complete upstream evidence-remediation lineage before use.
"""

from __future__ import annotations

from hashlib import sha256
import json

from .future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from .future_security_classification_review_request import (
    CLASSIFICATION_REVIEW_REQUEST_SCHEMA_VERSION,
    FutureSecurityClassificationReviewRequest,
)


_REQUEST_KEYS = {
    "schema_version",
    "client_id",
    "evidence_collection_request_sha256",
    "freshness_constraints_sha256",
    "admission_sha256",
    "metadata_review_sha256",
    "sufficiency_request_sha256",
    "verifier_preflight_sha256",
    "attestation_sha256",
    "source_resolution_id",
    "change_node_id",
    "subject_node_id",
    "candidate_run_id",
    "candidate_evidence_ids",
    "candidate_capability_ids",
    "candidate_classification_claim",
    "verifier_user_id",
    "classification_review_request_sha256",
    "evidence_sufficient",
    "classification_claim_justified",
    "sufficiency_decision_created",
    "evidence_sufficiency_evaluated",
    "classification_justification_evaluated",
    "eligible_for_classification_review",
    "classification_review_required",
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


def _digest_from_request(
    request: FutureSecurityClassificationReviewRequest,
) -> str:
    payload = request.as_dict()
    payload.pop("classification_review_request_sha256")
    return sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def future_security_classification_review_request_from_dict(
    payload: dict,
) -> FutureSecurityClassificationReviewRequest:
    """Parse an exact persisted request and verify its canonical digest."""

    if not isinstance(payload, dict):
        raise ValueError("classification review request payload must be an object")
    if set(payload) != _REQUEST_KEYS:
        raise ValueError("classification review request payload schema mismatch")
    if payload["schema_version"] != CLASSIFICATION_REVIEW_REQUEST_SCHEMA_VERSION:
        raise ValueError("classification review request schema version mismatch")

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
            name=f"classification review request {field}",
        )

    for field in (
        "evidence_collection_request_sha256",
        "freshness_constraints_sha256",
        "admission_sha256",
        "metadata_review_sha256",
        "sufficiency_request_sha256",
        "verifier_preflight_sha256",
        "attestation_sha256",
        "classification_review_request_sha256",
    ):
        _strict_sha256(payload[field], name=field)

    candidate_evidence_ids = _strict_string_list(
        payload["candidate_evidence_ids"],
        name="classification review request candidate_evidence_ids",
    )
    candidate_capability_ids = _strict_string_list(
        payload["candidate_capability_ids"],
        name="classification review request candidate_capability_ids",
    )

    raw_claim = payload["candidate_classification_claim"]
    if not isinstance(raw_claim, str):
        raise ValueError(
            "classification review request classification claim must be a string"
        )
    try:
        classification_claim = AttackPathTransitionClassification(raw_claim)
    except ValueError as exc:
        raise ValueError(
            "classification review request classification claim is unsupported"
        ) from exc

    for field in (
        "evidence_sufficient",
        "classification_claim_justified",
        "sufficiency_decision_created",
        "evidence_sufficiency_evaluated",
        "classification_justification_evaluated",
        "eligible_for_classification_review",
        "classification_review_required",
    ):
        if payload[field] is not True:
            raise ValueError(
                f"classification review request {field} must remain true"
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
                f"classification review request safety flag {field} must remain false"
            )

    if payload["future_semantics"] != "unresolved":
        raise ValueError(
            "classification review request future semantics must remain unresolved"
        )
    if payload["security_verdict"] != "not_evaluated":
        raise ValueError(
            "classification review request must not claim a security verdict"
        )

    request = FutureSecurityClassificationReviewRequest(
        schema_version=payload["schema_version"],
        client_id=payload["client_id"],
        evidence_collection_request_sha256=payload[
            "evidence_collection_request_sha256"
        ],
        freshness_constraints_sha256=payload["freshness_constraints_sha256"],
        admission_sha256=payload["admission_sha256"],
        metadata_review_sha256=payload["metadata_review_sha256"],
        sufficiency_request_sha256=payload["sufficiency_request_sha256"],
        verifier_preflight_sha256=payload["verifier_preflight_sha256"],
        attestation_sha256=payload["attestation_sha256"],
        source_resolution_id=payload["source_resolution_id"],
        change_node_id=payload["change_node_id"],
        subject_node_id=payload["subject_node_id"],
        candidate_run_id=payload["candidate_run_id"],
        candidate_evidence_ids=candidate_evidence_ids,
        candidate_capability_ids=candidate_capability_ids,
        candidate_classification_claim=classification_claim,
        verifier_user_id=payload["verifier_user_id"],
        classification_review_request_sha256=payload[
            "classification_review_request_sha256"
        ],
        evidence_sufficient=True,
        classification_claim_justified=True,
        sufficiency_decision_created=True,
        evidence_sufficiency_evaluated=True,
        classification_justification_evaluated=True,
        eligible_for_classification_review=True,
        classification_review_required=True,
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
    expected = _digest_from_request(request)
    if request.classification_review_request_sha256 != expected:
        raise ValueError("classification review request digest mismatch")
    return request
