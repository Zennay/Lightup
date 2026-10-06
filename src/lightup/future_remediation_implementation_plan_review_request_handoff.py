"""Strict persisted handoff for ST5 implementation-plan review requests.

Persisted review-request metadata remains planning-only. This boundary validates
the exact schema, canonical lineage and action-denying state, then immediately
rebuilds the request from the still-live strict implementation-plan chain before
allowing reuse.
"""

from __future__ import annotations

import json

from .ai.orchestration import RunContext
from .future_attack_path_graph_diff_preview import FutureAttackPathGraphDiffPreview
from .future_attack_path_security_delta_report import FutureAttackPathSecurityDeltaReport
from .future_attack_path_transition import FutureAttackPathTransitionProposal
from .future_attack_path_transition_resolution import FutureAttackPathTransitionResolution
from .future_remediation_authoring_request import FutureRemediationAuthoringRequest
from .future_remediation_evidence_bundle import FutureRemediationEvidenceBundle
from .future_remediation_implementation_plan_review_request import (
    REMEDIATION_IMPLEMENTATION_PLAN_REVIEW_REQUEST_SCHEMA_VERSION,
    REQUIRED_IMPLEMENTATION_PLAN_REVIEW_CHECKS,
    FutureRemediationImplementationPlanReviewRequest,
    build_future_remediation_implementation_plan_review_request,
)
from .future_security_remediation_retest_plan import FutureSecurityRemediationRetestPlan
from .state import StateStore


_REQUEST_KEYS = {
    "schema_version",
    "implementation_request_sha256",
    "remediation_review_sha256",
    "proposal_sha256",
    "content_sha256",
    "plan_sha256",
    "planner_provider_id",
    "planner_model_id",
    "plan_item_count",
    "required_checks",
    "review_request_sha256",
    "implementation_plan_review_requested",
    "implementation_plan_accepted",
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
_MAX_PROVENANCE_CHARS = 256


def _canonical_sha256(value: object, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{field} must be a canonical lowercase SHA-256 digest")
    return value


def _bounded_non_empty_string(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    if "\x00" in value:
        raise ValueError(f"{field} contains NUL")
    if len(value) > _MAX_PROVENANCE_CHARS:
        raise ValueError(f"{field} exceeds bounded size")
    return value


def _positive_int(value: object, *, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{field} must be a positive integer")
    return value


def future_remediation_implementation_plan_review_request_from_dict(
    payload: dict,
) -> FutureRemediationImplementationPlanReviewRequest:
    """Parse one exact persisted implementation-plan review request."""

    if not isinstance(payload, dict):
        raise ValueError("implementation plan review-request payload must be an object")
    if set(payload) != _REQUEST_KEYS:
        raise ValueError("implementation plan review-request payload schema mismatch")
    if (
        payload["schema_version"]
        != REMEDIATION_IMPLEMENTATION_PLAN_REVIEW_REQUEST_SCHEMA_VERSION
    ):
        raise ValueError("implementation plan review-request schema version mismatch")

    for field in (
        "implementation_request_sha256",
        "remediation_review_sha256",
        "proposal_sha256",
        "content_sha256",
        "plan_sha256",
        "review_request_sha256",
    ):
        _canonical_sha256(
            payload[field],
            field=f"implementation plan review-request {field}",
        )
    planner_provider_id = _bounded_non_empty_string(
        payload["planner_provider_id"],
        field="implementation plan review-request planner_provider_id",
    )
    planner_model_id = _bounded_non_empty_string(
        payload["planner_model_id"],
        field="implementation plan review-request planner_model_id",
    )
    plan_item_count = _positive_int(
        payload["plan_item_count"],
        field="implementation plan review-request plan_item_count",
    )

    raw_checks = payload["required_checks"]
    if not isinstance(raw_checks, (list, tuple)):
        raise ValueError(
            "implementation plan review-request required_checks must be a list or tuple"
        )
    required_checks = tuple(raw_checks)
    if required_checks != REQUIRED_IMPLEMENTATION_PLAN_REVIEW_CHECKS:
        raise ValueError("implementation plan review-request required checks mismatch")

    return FutureRemediationImplementationPlanReviewRequest(
        schema_version=payload["schema_version"],
        implementation_request_sha256=payload["implementation_request_sha256"],
        remediation_review_sha256=payload["remediation_review_sha256"],
        proposal_sha256=payload["proposal_sha256"],
        content_sha256=payload["content_sha256"],
        plan_sha256=payload["plan_sha256"],
        planner_provider_id=planner_provider_id,
        planner_model_id=planner_model_id,
        plan_item_count=plan_item_count,
        required_checks=required_checks,
        review_request_sha256=payload["review_request_sha256"],
        implementation_plan_review_requested=payload[
            "implementation_plan_review_requested"
        ],
        implementation_plan_accepted=payload["implementation_plan_accepted"],
        code_change_authorized=payload["code_change_authorized"],
        tool_call_created=payload["tool_call_created"],
        execution_allowed=payload["execution_allowed"],
        target_interaction_allowed=payload["target_interaction_allowed"],
        future_state_retest_allowed=payload["future_state_retest_allowed"],
        deployment_authorized=payload["deployment_authorized"],
        attack_path_mutation_allowed=payload["attack_path_mutation_allowed"],
        future_semantics=payload["future_semantics"],
        security_verdict=payload["security_verdict"],
    )


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def future_remediation_implementation_plan_review_request_from_json(
    raw: str,
) -> FutureRemediationImplementationPlanReviewRequest:
    """Parse strict JSON without duplicate-key last-value-wins behavior."""

    if not isinstance(raw, str) or not raw.strip():
        raise ValueError(
            "implementation plan review-request JSON must be a non-empty string"
        )
    try:
        payload = json.loads(raw, object_pairs_hook=_reject_duplicate_json_keys)
    except json.JSONDecodeError as exc:
        raise ValueError("implementation plan review-request JSON is invalid") from exc
    return future_remediation_implementation_plan_review_request_from_dict(payload)


def load_and_validate_future_remediation_implementation_plan_review_request(
    persisted_plan_review_request: object,
    persisted_plan: object,
    persisted_planning_request: object,
    persisted_review: object,
    persisted_remediation_review_request: object,
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
) -> FutureRemediationImplementationPlanReviewRequest:
    """Strictly parse and rebuild from the live bounded implementation plan."""

    if isinstance(persisted_plan_review_request, str):
        parsed = future_remediation_implementation_plan_review_request_from_json(
            persisted_plan_review_request
        )
    elif isinstance(persisted_plan_review_request, dict):
        parsed = future_remediation_implementation_plan_review_request_from_dict(
            persisted_plan_review_request
        )
    else:
        raise ValueError(
            "implementation plan review-request persisted value "
            "must be JSON text or object"
        )

    rebuilt = build_future_remediation_implementation_plan_review_request(
        persisted_plan,
        persisted_planning_request,
        persisted_review,
        persisted_remediation_review_request,
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
            "implementation plan review-request does not match its live plan lineage"
        )
    return rebuilt
