"""Strict persisted handoff for ST5 implementation-plan revision requests.

A persisted revision request remains planning-only. This boundary validates the
exact schema, canonical lineage/digest values, canonical revision-check order
and fixed fail-closed authority flags, then rebuilds the request from the strict
live implementation-plan review chain before allowing later reuse.
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
    REQUIRED_IMPLEMENTATION_PLAN_REVIEW_CHECKS,
)
from .future_remediation_implementation_plan_revision_request import (
    REMEDIATION_IMPLEMENTATION_PLAN_REVISION_REQUEST_SCHEMA_VERSION,
    FutureRemediationImplementationPlanRevisionRequest,
    build_future_remediation_implementation_plan_revision_request,
)
from .future_security_remediation_retest_plan import FutureSecurityRemediationRetestPlan
from .state import StateStore


_REVISION_REQUEST_KEYS = {
    "schema_version",
    "review_sha256",
    "review_request_sha256",
    "plan_sha256",
    "implementation_request_sha256",
    "reviewer_provider_id",
    "reviewer_model_id",
    "required_revisions",
    "revision_request_sha256",
    "source_review_decision",
    "implementation_plan_revision_requested",
    "revised_implementation_plan_created",
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


def _required_revisions(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise ValueError(
            "implementation plan revision request required_revisions "
            "must be a list or tuple"
        )
    revisions = tuple(value)
    if not revisions:
        raise ValueError(
            "implementation plan revision request required_revisions "
            "must be non-empty"
        )
    if any(type(item) is not str or not item for item in revisions):
        raise ValueError(
            "implementation plan revision request required_revisions "
            "must contain exact non-empty strings"
        )
    if len(set(revisions)) != len(revisions):
        raise ValueError(
            "implementation plan revision request required_revisions "
            "must be unique"
        )
    canonical = tuple(
        check
        for check in REQUIRED_IMPLEMENTATION_PLAN_REVIEW_CHECKS
        if check in set(revisions)
    )
    if canonical != revisions:
        raise ValueError(
            "implementation plan revision request required_revisions "
            "are invalid or out of order"
        )
    return revisions


def future_remediation_implementation_plan_revision_request_from_dict(
    payload: dict,
) -> FutureRemediationImplementationPlanRevisionRequest:
    """Parse one exact persisted implementation-plan revision request."""

    if not isinstance(payload, dict):
        raise ValueError(
            "implementation plan revision request payload must be an object"
        )
    if set(payload) != _REVISION_REQUEST_KEYS:
        raise ValueError(
            "implementation plan revision request payload schema mismatch"
        )
    if (
        payload["schema_version"]
        != REMEDIATION_IMPLEMENTATION_PLAN_REVISION_REQUEST_SCHEMA_VERSION
    ):
        raise ValueError(
            "implementation plan revision request schema version mismatch"
        )

    review_sha256 = _canonical_sha256(
        payload["review_sha256"],
        field="implementation plan revision request review_sha256",
    )
    review_request_sha256 = _canonical_sha256(
        payload["review_request_sha256"],
        field="implementation plan revision request review_request_sha256",
    )
    plan_sha256 = _canonical_sha256(
        payload["plan_sha256"],
        field="implementation plan revision request plan_sha256",
    )
    implementation_request_sha256 = _canonical_sha256(
        payload["implementation_request_sha256"],
        field="implementation plan revision request implementation_request_sha256",
    )
    revision_request_sha256 = _canonical_sha256(
        payload["revision_request_sha256"],
        field="implementation plan revision request revision_request_sha256",
    )
    reviewer_provider_id = _bounded_non_empty_string(
        payload["reviewer_provider_id"],
        field="implementation plan revision request reviewer_provider_id",
    )
    reviewer_model_id = _bounded_non_empty_string(
        payload["reviewer_model_id"],
        field="implementation plan revision request reviewer_model_id",
    )
    required_revisions = _required_revisions(payload["required_revisions"])

    if payload["source_review_decision"] != "revision_required":
        raise ValueError(
            "implementation plan revision request source_review_decision "
            "must remain revision_required"
        )
    if payload["implementation_plan_revision_requested"] is not True:
        raise ValueError(
            "implementation_plan_revision_requested must remain true"
        )
    if payload["revised_implementation_plan_created"] is not False:
        raise ValueError(
            "revised_implementation_plan_created must remain false"
        )
    if payload["implementation_plan_accepted"] is not False:
        raise ValueError("implementation_plan_accepted must remain false")
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
                "implementation plan revision request authority flag "
                f"{field} must remain false"
            )
    if payload["future_semantics"] != "unresolved":
        raise ValueError(
            "implementation plan revision request "
            "future_semantics must remain unresolved"
        )
    if payload["security_verdict"] != "not_evaluated":
        raise ValueError(
            "implementation plan revision request "
            "security_verdict must remain not_evaluated"
        )

    return FutureRemediationImplementationPlanRevisionRequest(
        schema_version=REMEDIATION_IMPLEMENTATION_PLAN_REVISION_REQUEST_SCHEMA_VERSION,
        review_sha256=review_sha256,
        review_request_sha256=review_request_sha256,
        plan_sha256=plan_sha256,
        implementation_request_sha256=implementation_request_sha256,
        reviewer_provider_id=reviewer_provider_id,
        reviewer_model_id=reviewer_model_id,
        required_revisions=required_revisions,
        revision_request_sha256=revision_request_sha256,
    )


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def future_remediation_implementation_plan_revision_request_from_json(
    raw: str,
) -> FutureRemediationImplementationPlanRevisionRequest:
    """Parse strict JSON without duplicate-key last-value-wins behavior."""

    if not isinstance(raw, str) or not raw.strip():
        raise ValueError(
            "implementation plan revision request JSON must be a non-empty string"
        )
    try:
        payload = json.loads(raw, object_pairs_hook=_reject_duplicate_json_keys)
    except json.JSONDecodeError as exc:
        raise ValueError(
            "implementation plan revision request JSON is invalid"
        ) from exc
    return future_remediation_implementation_plan_revision_request_from_dict(
        payload
    )


def load_and_validate_future_remediation_implementation_plan_revision_request(
    persisted_revision_request: object,
    persisted_plan_review: object,
    persisted_plan_review_request: object,
    persisted_plan: object,
    persisted_planning_request: object,
    persisted_remediation_review: object,
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
) -> FutureRemediationImplementationPlanRevisionRequest:
    """Parse and immediately rebuild from the strict live review chain."""

    if isinstance(persisted_revision_request, str):
        parsed = future_remediation_implementation_plan_revision_request_from_json(
            persisted_revision_request
        )
    elif isinstance(persisted_revision_request, dict):
        parsed = future_remediation_implementation_plan_revision_request_from_dict(
            persisted_revision_request
        )
    else:
        raise ValueError(
            "implementation plan revision request persisted value "
            "must be JSON text or object"
        )

    rebuilt = build_future_remediation_implementation_plan_revision_request(
        persisted_plan_review,
        persisted_plan_review_request,
        persisted_plan,
        persisted_planning_request,
        persisted_remediation_review,
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
            "implementation plan revision request does not match "
            "its live validated review"
        )
    return rebuilt
