"""Strict persisted handoff for independent ST5 implementation-plan reviews.

A persisted review may record that bounded implementation-plan text passed
independent review, but it never grants action authority. This boundary
validates the exact review schema, nested checks, decision coherence, canonical
digest and still-live review-request/plan lineage before later reuse. It never
re-invokes the verifier.
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
from .future_remediation_implementation_plan_handoff import (
    load_and_validate_future_remediation_implementation_plan,
)
from .future_remediation_implementation_plan_review import (
    REMEDIATION_IMPLEMENTATION_PLAN_REVIEW_SCHEMA_VERSION,
    FutureRemediationImplementationPlanReview,
    RemediationImplementationPlanReviewCheck,
    RemediationImplementationPlanReviewDecision,
)
from .future_remediation_implementation_plan_review_request import (
    REQUIRED_IMPLEMENTATION_PLAN_REVIEW_CHECKS,
)
from .future_remediation_implementation_plan_review_request_handoff import (
    load_and_validate_future_remediation_implementation_plan_review_request,
)
from .future_security_remediation_retest_plan import FutureSecurityRemediationRetestPlan
from .state import StateStore


_REVIEW_KEYS = {
    "schema_version",
    "review_request_sha256",
    "plan_sha256",
    "implementation_request_sha256",
    "reviewer_provider_id",
    "reviewer_model_id",
    "decision",
    "checks",
    "summary",
    "review_sha256",
    "implementation_plan_review_completed",
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
_CHECK_KEYS = {"check", "result"}
_ALLOWED_CHECK_RESULTS = {"pass", "fail", "unclear"}
_MAX_REVIEW_SUMMARY_CHARS = 4_000
_MAX_PROVENANCE_CHARS = 256


def _canonical_sha256(value: object, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{field} must be a canonical lowercase SHA-256 digest")
    return value


def _bounded_non_empty_string(
    value: object,
    *,
    field: str,
    max_chars: int,
) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    if "\x00" in value:
        raise ValueError(f"{field} contains NUL")
    if len(value) > max_chars:
        raise ValueError(f"{field} exceeds bounded size")
    return value


def _validate_decision_checks(
    decision: RemediationImplementationPlanReviewDecision,
    checks: tuple[RemediationImplementationPlanReviewCheck, ...],
) -> None:
    results = tuple(check.result for check in checks)
    if decision is RemediationImplementationPlanReviewDecision.APPROVED and any(
        result != "pass" for result in results
    ):
        raise ValueError(
            "approved implementation plan review requires every check to pass"
        )
    if (
        decision is RemediationImplementationPlanReviewDecision.REVISION_REQUIRED
        and all(result == "pass" for result in results)
    ):
        raise ValueError(
            "revision_required implementation plan review requires a non-pass check"
        )
    if (
        decision is RemediationImplementationPlanReviewDecision.INSUFFICIENT_EVIDENCE
        and "unclear" not in results
    ):
        raise ValueError(
            "insufficient_evidence implementation plan review "
            "requires an unclear check"
        )


def _review_digest(review: FutureRemediationImplementationPlanReview) -> str:
    payload = {
        "schema_version": REMEDIATION_IMPLEMENTATION_PLAN_REVIEW_SCHEMA_VERSION,
        "review_request_sha256": review.review_request_sha256,
        "plan_sha256": review.plan_sha256,
        "implementation_request_sha256": review.implementation_request_sha256,
        "reviewer_provider_id": review.reviewer_provider_id,
        "reviewer_model_id": review.reviewer_model_id,
        "decision": review.decision.value,
        "checks": [check.as_dict() for check in review.checks],
        "summary": review.summary,
        "implementation_plan_review_completed": True,
        "implementation_plan_accepted": (
            review.decision is RemediationImplementationPlanReviewDecision.APPROVED
        ),
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


def future_remediation_implementation_plan_review_from_dict(
    payload: dict,
) -> FutureRemediationImplementationPlanReview:
    """Parse one exact persisted implementation-plan review."""

    if not isinstance(payload, dict):
        raise ValueError("implementation plan review payload must be an object")
    if set(payload) != _REVIEW_KEYS:
        raise ValueError("implementation plan review payload schema mismatch")
    if payload["schema_version"] != REMEDIATION_IMPLEMENTATION_PLAN_REVIEW_SCHEMA_VERSION:
        raise ValueError("implementation plan review schema version mismatch")

    review_request_sha256 = _canonical_sha256(
        payload["review_request_sha256"],
        field="implementation plan review review_request_sha256",
    )
    plan_sha256 = _canonical_sha256(
        payload["plan_sha256"],
        field="implementation plan review plan_sha256",
    )
    implementation_request_sha256 = _canonical_sha256(
        payload["implementation_request_sha256"],
        field="implementation plan review implementation_request_sha256",
    )
    review_sha256 = _canonical_sha256(
        payload["review_sha256"],
        field="implementation plan review review_sha256",
    )
    reviewer_provider_id = _bounded_non_empty_string(
        payload["reviewer_provider_id"],
        field="implementation plan review reviewer_provider_id",
        max_chars=_MAX_PROVENANCE_CHARS,
    )
    reviewer_model_id = _bounded_non_empty_string(
        payload["reviewer_model_id"],
        field="implementation plan review reviewer_model_id",
        max_chars=_MAX_PROVENANCE_CHARS,
    )

    try:
        decision = RemediationImplementationPlanReviewDecision(payload["decision"])
    except (TypeError, ValueError):
        raise ValueError("implementation plan review decision is invalid") from None

    raw_checks = payload["checks"]
    if not isinstance(raw_checks, (list, tuple)):
        raise ValueError("implementation plan review checks must be a list or tuple")
    if len(raw_checks) != len(REQUIRED_IMPLEMENTATION_PLAN_REVIEW_CHECKS):
        raise ValueError("implementation plan review checks count mismatch")
    checks: list[RemediationImplementationPlanReviewCheck] = []
    for index, raw_check in enumerate(raw_checks):
        if not isinstance(raw_check, dict) or set(raw_check) != _CHECK_KEYS:
            raise ValueError("implementation plan review check schema mismatch")
        expected = REQUIRED_IMPLEMENTATION_PLAN_REVIEW_CHECKS[index]
        if raw_check["check"] != expected:
            raise ValueError(
                "implementation plan review check order or name mismatch"
            )
        result = raw_check["result"]
        if result not in _ALLOWED_CHECK_RESULTS:
            raise ValueError(
                f"implementation plan review result for {expected!r} is invalid"
            )
        checks.append(
            RemediationImplementationPlanReviewCheck(
                check=expected,
                result=result,
            )
        )
    parsed_checks = tuple(checks)
    _validate_decision_checks(decision, parsed_checks)

    summary = _bounded_non_empty_string(
        payload["summary"],
        field="implementation plan review summary",
        max_chars=_MAX_REVIEW_SUMMARY_CHARS,
    )
    if summary != summary.strip():
        raise ValueError(
            "implementation plan review summary must be canonical trimmed text"
        )

    if payload["implementation_plan_review_completed"] is not True:
        raise ValueError(
            "implementation plan review "
            "implementation_plan_review_completed must remain true"
        )
    expected_accepted = (
        decision is RemediationImplementationPlanReviewDecision.APPROVED
    )
    if payload["implementation_plan_accepted"] is not expected_accepted:
        raise ValueError(
            "implementation plan review implementation_plan_accepted mismatch"
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
                f"implementation plan review authority flag {field} must remain false"
            )
    if payload["future_semantics"] != "unresolved":
        raise ValueError(
            "implementation plan review future_semantics must remain unresolved"
        )
    if payload["security_verdict"] != "not_evaluated":
        raise ValueError(
            "implementation plan review security_verdict must remain not_evaluated"
        )

    parsed = FutureRemediationImplementationPlanReview(
        schema_version=REMEDIATION_IMPLEMENTATION_PLAN_REVIEW_SCHEMA_VERSION,
        review_request_sha256=review_request_sha256,
        plan_sha256=plan_sha256,
        implementation_request_sha256=implementation_request_sha256,
        reviewer_provider_id=reviewer_provider_id,
        reviewer_model_id=reviewer_model_id,
        decision=decision,
        checks=parsed_checks,
        summary=summary,
        review_sha256=review_sha256,
        implementation_plan_accepted=expected_accepted,
    )
    if _review_digest(parsed) != parsed.review_sha256:
        raise ValueError("implementation plan review digest mismatch")
    return parsed


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def future_remediation_implementation_plan_review_from_json(
    raw: str,
) -> FutureRemediationImplementationPlanReview:
    """Parse strict review JSON without duplicate-key last-value-wins behavior."""

    if not isinstance(raw, str) or not raw.strip():
        raise ValueError("implementation plan review JSON must be a non-empty string")
    try:
        payload = json.loads(raw, object_pairs_hook=_reject_duplicate_json_keys)
    except json.JSONDecodeError as exc:
        raise ValueError("implementation plan review JSON is invalid") from exc
    return future_remediation_implementation_plan_review_from_dict(payload)


def load_and_validate_future_remediation_implementation_plan_review(
    persisted_review: object,
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
) -> FutureRemediationImplementationPlanReview:
    """Parse a review and require its full referenced lineage to remain live."""

    if isinstance(persisted_review, str):
        parsed = future_remediation_implementation_plan_review_from_json(
            persisted_review
        )
    elif isinstance(persisted_review, dict):
        parsed = future_remediation_implementation_plan_review_from_dict(
            persisted_review
        )
    else:
        raise ValueError(
            "implementation plan review persisted value must be JSON text or object"
        )

    review_request = (
        load_and_validate_future_remediation_implementation_plan_review_request(
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
    )
    implementation_plan = load_and_validate_future_remediation_implementation_plan(
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

    if parsed.review_request_sha256 != review_request.review_request_sha256:
        raise ValueError("implementation plan review request lineage mismatch")
    if parsed.plan_sha256 != implementation_plan.plan_sha256:
        raise ValueError("implementation plan review plan lineage mismatch")
    if (
        parsed.implementation_request_sha256
        != implementation_plan.implementation_request_sha256
    ):
        raise ValueError(
            "implementation plan review implementation-request lineage mismatch"
        )
    return parsed
