"""Strict serialized handoff for ST5 evidence metadata contract reviews.

Parsing a persisted review proves only serialization integrity. Callers must
still run validate_future_security_evidence_metadata_contract_review against
the live admission, request, lineage and StateStore before using the review.
"""

from __future__ import annotations

from hashlib import sha256
import json

from .future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from .future_security_evidence_metadata_contract_review import (
    REVIEW_SCHEMA_VERSION,
    FutureSecurityEvidenceMetadataContractReview,
)


_REVIEW_KEYS = {
    "schema_version",
    "client_id",
    "current_twin_id",
    "current_twin_version",
    "twin_id",
    "twin_version",
    "changeset_id",
    "request_sha256",
    "constraints_sha256",
    "admission_sha256",
    "source_resolution_id",
    "change_node_id",
    "subject_node_id",
    "candidate_run_id",
    "candidate_evidence_ids",
    "candidate_capability_ids",
    "candidate_classification_claim",
    "metadata_contract_verified",
    "review_sha256",
    "freshness_check_passed",
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


def _digest_from_review(review: FutureSecurityEvidenceMetadataContractReview) -> str:
    payload = review.as_dict()
    payload.pop("review_sha256")
    return sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def future_security_evidence_metadata_contract_review_from_dict(
    payload: dict,
) -> FutureSecurityEvidenceMetadataContractReview:
    """Parse an exact persisted metadata-contract review and verify its digest."""

    if not isinstance(payload, dict):
        raise ValueError("evidence metadata contract review payload must be an object")
    if set(payload) != _REVIEW_KEYS:
        raise ValueError("evidence metadata contract review payload schema mismatch")
    if payload["schema_version"] != REVIEW_SCHEMA_VERSION:
        raise ValueError("evidence metadata contract review schema version mismatch")

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
            name=f"evidence metadata contract review {field}",
        )

    for field in (
        "request_sha256",
        "constraints_sha256",
        "admission_sha256",
        "review_sha256",
    ):
        _strict_sha256(payload[field], name=field)

    for field in ("current_twin_version", "twin_version"):
        value = payload[field]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(
                f"evidence metadata contract review {field} must be a non-negative integer"
            )

    candidate_evidence_ids = _strict_string_list(
        payload["candidate_evidence_ids"],
        name="evidence metadata contract review candidate_evidence_ids",
    )
    candidate_capability_ids = _strict_string_list(
        payload["candidate_capability_ids"],
        name="evidence metadata contract review candidate_capability_ids",
    )

    raw_claim = payload["candidate_classification_claim"]
    if not isinstance(raw_claim, str):
        raise ValueError(
            "evidence metadata contract review classification claim must be a string"
        )
    try:
        claim = AttackPathTransitionClassification(raw_claim)
    except ValueError as exc:
        raise ValueError(
            "evidence metadata contract review classification claim is unsupported"
        ) from exc

    if payload["metadata_contract_verified"] is not True:
        raise ValueError(
            "evidence metadata contract review must retain verified metadata contract"
        )
    if payload["freshness_check_passed"] is not True:
        raise ValueError(
            "evidence metadata contract review must retain passed freshness check"
        )

    for field in (
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
                f"evidence metadata contract review safety flag {field} must remain false"
            )

    if payload["future_semantics"] != "unresolved":
        raise ValueError(
            "evidence metadata contract review future semantics must remain unresolved"
        )
    if payload["security_verdict"] != "not_evaluated":
        raise ValueError(
            "evidence metadata contract review must not claim a security verdict"
        )

    review = FutureSecurityEvidenceMetadataContractReview(
        schema_version=payload["schema_version"],
        client_id=payload["client_id"],
        current_twin_id=payload["current_twin_id"],
        current_twin_version=payload["current_twin_version"],
        twin_id=payload["twin_id"],
        twin_version=payload["twin_version"],
        changeset_id=payload["changeset_id"],
        request_sha256=payload["request_sha256"],
        constraints_sha256=payload["constraints_sha256"],
        admission_sha256=payload["admission_sha256"],
        source_resolution_id=payload["source_resolution_id"],
        change_node_id=payload["change_node_id"],
        subject_node_id=payload["subject_node_id"],
        candidate_run_id=payload["candidate_run_id"],
        candidate_evidence_ids=candidate_evidence_ids,
        candidate_capability_ids=candidate_capability_ids,
        candidate_classification_claim=claim,
        metadata_contract_verified=True,
        review_sha256=payload["review_sha256"],
        freshness_check_passed=True,
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
    expected = _digest_from_review(review)
    if review.review_sha256 != expected:
        raise ValueError("evidence metadata contract review digest mismatch")
    return review
