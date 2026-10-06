"""Strict persisted handoff for ST5 implementation-planning requests.

This boundary verifies the exact request schema, canonical digest and
fail-closed authority state, then rebuilds the request from the still-live
accepted remediation-review chain before any later implementation planning.
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
from .future_remediation_implementation_plan_request import (
    REMEDIATION_IMPLEMENTATION_PLAN_REQUEST_SCHEMA_VERSION,
    FutureRemediationImplementationPlanRequest,
    build_future_remediation_implementation_plan_request,
)
from .future_security_remediation_retest_plan import FutureSecurityRemediationRetestPlan
from .state import StateStore


_REQUEST_KEYS = {
    "schema_version",
    "review_sha256",
    "review_request_sha256",
    "proposal_sha256",
    "content_sha256",
    "reviewer_provider_id",
    "reviewer_model_id",
    "item_count",
    "implementation_request_sha256",
    "implementation_planning_requested",
    "implementation_plan_created",
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


def _positive_int(value: object, *, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{field} must be a positive integer")
    return value


def _request_digest(request: FutureRemediationImplementationPlanRequest) -> str:
    payload = {
        "schema_version": REMEDIATION_IMPLEMENTATION_PLAN_REQUEST_SCHEMA_VERSION,
        "review_sha256": request.review_sha256,
        "review_request_sha256": request.review_request_sha256,
        "proposal_sha256": request.proposal_sha256,
        "content_sha256": request.content_sha256,
        "reviewer_provider_id": request.reviewer_provider_id,
        "reviewer_model_id": request.reviewer_model_id,
        "item_count": request.item_count,
        "implementation_planning_requested": True,
        "implementation_plan_created": False,
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


def future_remediation_implementation_plan_request_from_dict(
    payload: dict,
) -> FutureRemediationImplementationPlanRequest:
    """Parse one exact persisted implementation-planning request."""

    if not isinstance(payload, dict):
        raise ValueError("implementation-planning request payload must be an object")
    if set(payload) != _REQUEST_KEYS:
        raise ValueError("implementation-planning request payload schema mismatch")
    if payload["schema_version"] != REMEDIATION_IMPLEMENTATION_PLAN_REQUEST_SCHEMA_VERSION:
        raise ValueError("implementation-planning request schema version mismatch")

    review_sha256 = _canonical_sha256(
        payload["review_sha256"],
        field="implementation-planning request review_sha256",
    )
    review_request_sha256 = _canonical_sha256(
        payload["review_request_sha256"],
        field="implementation-planning request review_request_sha256",
    )
    proposal_sha256 = _canonical_sha256(
        payload["proposal_sha256"],
        field="implementation-planning request proposal_sha256",
    )
    content_sha256 = _canonical_sha256(
        payload["content_sha256"],
        field="implementation-planning request content_sha256",
    )
    implementation_request_sha256 = _canonical_sha256(
        payload["implementation_request_sha256"],
        field="implementation-planning request implementation_request_sha256",
    )
    reviewer_provider_id = _non_empty_string(
        payload["reviewer_provider_id"],
        field="implementation-planning request reviewer_provider_id",
    )
    reviewer_model_id = _non_empty_string(
        payload["reviewer_model_id"],
        field="implementation-planning request reviewer_model_id",
    )
    item_count = _positive_int(
        payload["item_count"],
        field="implementation-planning request item_count",
    )

    if payload["implementation_planning_requested"] is not True:
        raise ValueError(
            "implementation-planning request implementation_planning_requested must remain true"
        )
    if payload["implementation_plan_created"] is not False:
        raise ValueError(
            "implementation-planning request implementation_plan_created must remain false"
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
                f"implementation-planning request authority flag {field} must remain false"
            )
    if payload["future_semantics"] != "unresolved":
        raise ValueError(
            "implementation-planning request future_semantics must remain unresolved"
        )
    if payload["security_verdict"] != "not_evaluated":
        raise ValueError(
            "implementation-planning request security_verdict must remain not_evaluated"
        )

    parsed = FutureRemediationImplementationPlanRequest(
        schema_version=REMEDIATION_IMPLEMENTATION_PLAN_REQUEST_SCHEMA_VERSION,
        review_sha256=review_sha256,
        review_request_sha256=review_request_sha256,
        proposal_sha256=proposal_sha256,
        content_sha256=content_sha256,
        reviewer_provider_id=reviewer_provider_id,
        reviewer_model_id=reviewer_model_id,
        item_count=item_count,
        implementation_request_sha256=implementation_request_sha256,
    )
    if _request_digest(parsed) != parsed.implementation_request_sha256:
        raise ValueError("implementation-planning request digest mismatch")
    return parsed


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def future_remediation_implementation_plan_request_from_json(
    raw: str,
) -> FutureRemediationImplementationPlanRequest:
    """Parse strict JSON without duplicate-key last-value-wins behavior."""

    if not isinstance(raw, str) or not raw.strip():
        raise ValueError("implementation-planning request JSON must be a non-empty string")
    try:
        payload = json.loads(raw, object_pairs_hook=_reject_duplicate_json_keys)
    except json.JSONDecodeError as exc:
        raise ValueError("implementation-planning request JSON is invalid") from exc
    return future_remediation_implementation_plan_request_from_dict(payload)


def load_and_validate_future_remediation_implementation_plan_request(
    persisted_request: object,
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
) -> FutureRemediationImplementationPlanRequest:
    """Strictly parse and rebuild from the accepted live review chain."""

    if isinstance(persisted_request, str):
        parsed = future_remediation_implementation_plan_request_from_json(
            persisted_request
        )
    elif isinstance(persisted_request, dict):
        parsed = future_remediation_implementation_plan_request_from_dict(
            persisted_request
        )
    else:
        raise ValueError(
            "implementation-planning request persisted value must be JSON text or object"
        )

    rebuilt = build_future_remediation_implementation_plan_request(
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
            "implementation-planning request does not match its live accepted review"
        )
    return rebuilt
