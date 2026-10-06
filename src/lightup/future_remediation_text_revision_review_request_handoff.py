"""Strict persisted handoff for revised-remediation review requests.

A persisted request for independent review of revised remediation prose remains
planning-only. This boundary validates exact schema, canonical lineage digests,
model provenance, the fixed review rubric and fail-closed authority flags, then
rebuilds the request from the strict live revised-proposal chain before reuse.
"""

from __future__ import annotations

from hashlib import sha256
import json

from .ai.orchestration import RunContext
from .future_attack_path_graph_diff_preview import FutureAttackPathGraphDiffPreview
from .future_attack_path_security_delta_report import FutureAttackPathSecurityDeltaReport
from .future_attack_path_transition import FutureAttackPathTransitionProposal
from .future_attack_path_transition_resolution import FutureAttackPathTransitionResolution
from .future_remediation_authoring_request import FutureRemediationAuthoringRequest
from .future_remediation_evidence_bundle import FutureRemediationEvidenceBundle
from .future_remediation_text_revision_review_request import (
    REMEDIATION_TEXT_REVISION_REVIEW_REQUEST_SCHEMA_VERSION,
    FutureRemediationTextRevisionReviewRequest,
    build_future_remediation_text_revision_review_request,
)
from .future_remediation_text_review_request import REQUIRED_REVIEW_CHECKS
from .future_security_remediation_retest_plan import FutureSecurityRemediationRetestPlan
from .state import StateStore


_REVIEW_REQUEST_KEYS = {
    "schema_version",
    "revision_proposal_sha256",
    "revision_request_sha256",
    "prior_review_sha256",
    "content_sha256",
    "provider_id",
    "model_id",
    "required_checks",
    "review_request_sha256",
    "review_requested",
    "remediation_accepted",
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


def _canonical_sha256(value: object, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{field} must be a canonical lowercase SHA-256 digest")
    return value


def _non_empty_string(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _review_request_digest(
    request: FutureRemediationTextRevisionReviewRequest,
) -> str:
    payload = {
        "schema_version": REMEDIATION_TEXT_REVISION_REVIEW_REQUEST_SCHEMA_VERSION,
        "revision_proposal_sha256": request.revision_proposal_sha256,
        "revision_request_sha256": request.revision_request_sha256,
        "prior_review_sha256": request.prior_review_sha256,
        "content_sha256": request.content_sha256,
        "provider_id": request.provider_id,
        "model_id": request.model_id,
        "required_checks": list(REQUIRED_REVIEW_CHECKS),
        "review_requested": True,
        "remediation_accepted": False,
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


def future_remediation_text_revision_review_request_from_dict(
    payload: dict,
) -> FutureRemediationTextRevisionReviewRequest:
    """Parse one exact persisted revised-remediation review request."""

    if not isinstance(payload, dict):
        raise ValueError(
            "remediation text revision review request payload must be an object"
        )
    if set(payload) != _REVIEW_REQUEST_KEYS:
        raise ValueError(
            "remediation text revision review request payload schema mismatch"
        )
    if (
        payload["schema_version"]
        != REMEDIATION_TEXT_REVISION_REVIEW_REQUEST_SCHEMA_VERSION
    ):
        raise ValueError(
            "remediation text revision review request schema version mismatch"
        )

    revision_proposal_sha256 = _canonical_sha256(
        payload["revision_proposal_sha256"],
        field="remediation text revision review request revision_proposal_sha256",
    )
    revision_request_sha256 = _canonical_sha256(
        payload["revision_request_sha256"],
        field="remediation text revision review request revision_request_sha256",
    )
    prior_review_sha256 = _canonical_sha256(
        payload["prior_review_sha256"],
        field="remediation text revision review request prior_review_sha256",
    )
    content_sha256 = _canonical_sha256(
        payload["content_sha256"],
        field="remediation text revision review request content_sha256",
    )
    review_request_sha256 = _canonical_sha256(
        payload["review_request_sha256"],
        field="remediation text revision review request review_request_sha256",
    )
    provider_id = _non_empty_string(
        payload["provider_id"],
        field="remediation text revision review request provider_id",
    )
    model_id = _non_empty_string(
        payload["model_id"],
        field="remediation text revision review request model_id",
    )

    raw_checks = payload["required_checks"]
    if not isinstance(raw_checks, (list, tuple)):
        raise ValueError(
            "remediation text revision review request required_checks "
            "must be a list or tuple"
        )
    if tuple(raw_checks) != REQUIRED_REVIEW_CHECKS:
        raise ValueError(
            "remediation text revision review request required_checks mismatch"
        )

    if payload["review_requested"] is not True:
        raise ValueError(
            "remediation text revision review request review_requested must remain true"
        )
    if payload["remediation_accepted"] is not False:
        raise ValueError(
            "remediation text revision review request remediation_accepted "
            "must remain false"
        )
    for field in (
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
                "remediation text revision review request authority flag "
                f"{field} must remain false"
            )
    if payload["future_semantics"] != "unresolved":
        raise ValueError(
            "remediation text revision review request future_semantics "
            "must remain unresolved"
        )
    if payload["security_verdict"] != "not_evaluated":
        raise ValueError(
            "remediation text revision review request security_verdict "
            "must remain not_evaluated"
        )

    parsed = FutureRemediationTextRevisionReviewRequest(
        schema_version=REMEDIATION_TEXT_REVISION_REVIEW_REQUEST_SCHEMA_VERSION,
        revision_proposal_sha256=revision_proposal_sha256,
        revision_request_sha256=revision_request_sha256,
        prior_review_sha256=prior_review_sha256,
        content_sha256=content_sha256,
        provider_id=provider_id,
        model_id=model_id,
        required_checks=REQUIRED_REVIEW_CHECKS,
        review_request_sha256=review_request_sha256,
    )
    if _review_request_digest(parsed) != parsed.review_request_sha256:
        raise ValueError("remediation text revision review request digest mismatch")
    return parsed


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def future_remediation_text_revision_review_request_from_json(
    raw: str,
) -> FutureRemediationTextRevisionReviewRequest:
    """Parse strict JSON without duplicate-key last-value-wins behavior."""

    if not isinstance(raw, str) or not raw.strip():
        raise ValueError(
            "remediation text revision review request JSON must be a non-empty string"
        )
    try:
        payload = json.loads(raw, object_pairs_hook=_reject_duplicate_json_keys)
    except json.JSONDecodeError as exc:
        raise ValueError(
            "remediation text revision review request JSON is invalid"
        ) from exc
    return future_remediation_text_revision_review_request_from_dict(payload)


def load_and_validate_future_remediation_text_revision_review_request(
    persisted_revision_review_request: object,
    persisted_revision_proposal: object,
    persisted_revision_request: object,
    persisted_review: object,
    persisted_review_request: object,
    persisted_proposal: object,
    request: FutureRemediationAuthoringRequest,
    bundle: FutureRemediationEvidenceBundle,
    plan: FutureSecurityRemediationRetestPlan,
    report: FutureAttackPathSecurityDeltaReport,
    preview: FutureAttackPathGraphDiffPreview,
    transition_proposal: FutureAttackPathTransitionProposal,
    resolutions: tuple[FutureAttackPathTransitionResolution, ...],
    contexts: tuple[RunContext, ...],
    state: StateStore,
) -> FutureRemediationTextRevisionReviewRequest:
    """Parse and rebuild from the complete strict live revised-proposal chain."""

    if isinstance(persisted_revision_review_request, str):
        parsed = future_remediation_text_revision_review_request_from_json(
            persisted_revision_review_request
        )
    elif isinstance(persisted_revision_review_request, dict):
        parsed = future_remediation_text_revision_review_request_from_dict(
            persisted_revision_review_request
        )
    else:
        raise ValueError(
            "remediation text revision review request persisted value "
            "must be JSON text or object"
        )

    rebuilt = build_future_remediation_text_revision_review_request(
        persisted_revision_proposal,
        persisted_revision_request,
        persisted_review,
        persisted_review_request,
        persisted_proposal,
        request,
        bundle,
        plan,
        report,
        preview,
        transition_proposal,
        resolutions,
        contexts,
        state,
    )
    if parsed != rebuilt:
        raise ValueError(
            "remediation text revision review request does not match "
            "its live validated revised proposal"
        )
    return rebuilt
