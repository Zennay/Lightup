"""Strict serialized handoff for ST5 evidence sufficiency-review requests.

Parsing a persisted request proves only serialization integrity. Callers must
still run validate_future_security_evidence_sufficiency_review_request against
the live metadata review, admission, lineage and StateStore before use.
"""

from __future__ import annotations

from hashlib import sha256
import json

from .future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
)
from .future_security_evidence_sufficiency_review_request import (
    REQUIRED_SUFFICIENCY_REVIEW_CHECKS,
    SUFFICIENCY_REVIEW_REQUEST_SCHEMA_VERSION,
    FutureSecurityEvidenceSufficiencyReviewRequest,
)


_REQUEST_KEYS = {
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
    "metadata_review_sha256",
    "source_resolution_id",
    "change_node_id",
    "subject_node_id",
    "candidate_run_id",
    "candidate_evidence_ids",
    "candidate_capability_ids",
    "candidate_classification_claim",
    "required_checks",
    "sufficiency_request_sha256",
    "metadata_contract_verified",
    "freshness_check_passed",
    "independent_verifier_required",
    "review_required",
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


def _digest_from_request(
    request: FutureSecurityEvidenceSufficiencyReviewRequest,
) -> str:
    payload = request.as_dict()
    payload.pop("sufficiency_request_sha256")
    return sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def future_security_evidence_sufficiency_review_request_from_dict(
    payload: dict,
) -> FutureSecurityEvidenceSufficiencyReviewRequest:
    """Parse an exact persisted sufficiency-review request and verify its digest."""

    if not isinstance(payload, dict):
        raise ValueError("evidence sufficiency review request payload must be an object")
    if set(payload) != _REQUEST_KEYS:
        raise ValueError("evidence sufficiency review request payload schema mismatch")
    if payload["schema_version"] != SUFFICIENCY_REVIEW_REQUEST_SCHEMA_VERSION:
        raise ValueError("evidence sufficiency review request schema version mismatch")

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
            name=f"evidence sufficiency review request {field}",
        )

    for field in (
        "request_sha256",
        "constraints_sha256",
        "admission_sha256",
        "metadata_review_sha256",
        "sufficiency_request_sha256",
    ):
        _strict_sha256(payload[field], name=field)

    for field in ("current_twin_version", "twin_version"):
        value = payload[field]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(
                f"evidence sufficiency review request {field} "
                "must be a non-negative integer"
            )

    candidate_evidence_ids = _strict_string_list(
        payload["candidate_evidence_ids"],
        name="evidence sufficiency review request candidate_evidence_ids",
    )
    candidate_capability_ids = _strict_string_list(
        payload["candidate_capability_ids"],
        name="evidence sufficiency review request candidate_capability_ids",
    )

    raw_claim = payload["candidate_classification_claim"]
    if not isinstance(raw_claim, str):
        raise ValueError(
            "evidence sufficiency review request classification claim must be a string"
        )
    try:
        claim = AttackPathTransitionClassification(raw_claim)
    except ValueError as exc:
        raise ValueError(
            "evidence sufficiency review request classification claim is unsupported"
        ) from exc

    raw_checks = payload["required_checks"]
    if not isinstance(raw_checks, list):
        raise ValueError(
            "evidence sufficiency review request required_checks must be a list"
        )
    if tuple(raw_checks) != REQUIRED_SUFFICIENCY_REVIEW_CHECKS:
        raise ValueError(
            "evidence sufficiency review request required_checks must match "
            "the canonical independent review checks"
        )

    for field in (
        "metadata_contract_verified",
        "freshness_check_passed",
        "independent_verifier_required",
        "review_required",
    ):
        if payload[field] is not True:
            raise ValueError(
                f"evidence sufficiency review request {field} must remain true"
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
                f"evidence sufficiency review request safety flag {field} "
                "must remain false"
            )

    if payload["future_semantics"] != "unresolved":
        raise ValueError(
            "evidence sufficiency review request future semantics must remain unresolved"
        )
    if payload["security_verdict"] != "not_evaluated":
        raise ValueError(
            "evidence sufficiency review request must not claim a security verdict"
        )

    request = FutureSecurityEvidenceSufficiencyReviewRequest(
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
        metadata_review_sha256=payload["metadata_review_sha256"],
        source_resolution_id=payload["source_resolution_id"],
        change_node_id=payload["change_node_id"],
        subject_node_id=payload["subject_node_id"],
        candidate_run_id=payload["candidate_run_id"],
        candidate_evidence_ids=candidate_evidence_ids,
        candidate_capability_ids=candidate_capability_ids,
        candidate_classification_claim=claim,
        required_checks=REQUIRED_SUFFICIENCY_REVIEW_CHECKS,
        sufficiency_request_sha256=payload["sufficiency_request_sha256"],
        metadata_contract_verified=True,
        freshness_check_passed=True,
        independent_verifier_required=True,
        review_required=True,
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
    expected = _digest_from_request(request)
    if request.sufficiency_request_sha256 != expected:
        raise ValueError("evidence sufficiency review request digest mismatch")
    return request
