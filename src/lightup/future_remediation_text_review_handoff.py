"""Strict persisted handoff for independent ST5 remediation-text reviews.

A persisted review may record that remediation prose passed review, but it
never grants action authority. This boundary validates the exact review schema,
decision/check coherence, canonical digest and still-live upstream proposal and
review-request lineage before any later use.
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
from .future_remediation_text_proposal_handoff import (
    load_and_validate_future_remediation_text_proposal,
)
from .future_remediation_text_review import (
    REMEDIATION_TEXT_REVIEW_SCHEMA_VERSION,
    FutureRemediationTextReview,
    RemediationTextReviewCheck,
    RemediationTextReviewDecision,
)
from .future_remediation_text_review_request import REQUIRED_REVIEW_CHECKS
from .future_remediation_text_review_request_handoff import (
    load_and_validate_future_remediation_text_review_request,
)
from .future_security_remediation_retest_plan import FutureSecurityRemediationRetestPlan
from .state import StateStore


_REVIEW_KEYS = {
    "schema_version",
    "review_request_sha256",
    "proposal_sha256",
    "content_sha256",
    "reviewer_provider_id",
    "reviewer_model_id",
    "decision",
    "checks",
    "summary",
    "review_sha256",
    "review_completed",
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
_CHECK_KEYS = {"check", "result"}
_ALLOWED_CHECK_RESULTS = {"pass", "fail", "unclear"}
_MAX_REVIEW_SUMMARY_CHARS = 4_000


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


def _validate_decision_checks(
    decision: RemediationTextReviewDecision,
    checks: tuple[RemediationTextReviewCheck, ...],
) -> None:
    results = tuple(check.result for check in checks)
    if decision is RemediationTextReviewDecision.APPROVED and any(
        result != "pass" for result in results
    ):
        raise ValueError("approved remediation text review requires every check to pass")
    if decision is RemediationTextReviewDecision.REVISION_REQUIRED and all(
        result == "pass" for result in results
    ):
        raise ValueError("revision_required remediation text review requires a non-pass check")
    if (
        decision is RemediationTextReviewDecision.INSUFFICIENT_EVIDENCE
        and "unclear" not in results
    ):
        raise ValueError(
            "insufficient_evidence remediation text review requires an unclear check"
        )


def _review_digest(review: FutureRemediationTextReview) -> str:
    payload = {
        "schema_version": REMEDIATION_TEXT_REVIEW_SCHEMA_VERSION,
        "review_request_sha256": review.review_request_sha256,
        "proposal_sha256": review.proposal_sha256,
        "content_sha256": review.content_sha256,
        "reviewer_provider_id": review.reviewer_provider_id,
        "reviewer_model_id": review.reviewer_model_id,
        "decision": review.decision.value,
        "checks": [check.as_dict() for check in review.checks],
        "summary": review.summary,
        "review_completed": True,
        "remediation_accepted": (
            review.decision is RemediationTextReviewDecision.APPROVED
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


def future_remediation_text_review_from_dict(payload: dict) -> FutureRemediationTextReview:
    """Parse one exact persisted remediation-text review."""

    if not isinstance(payload, dict):
        raise ValueError("remediation text review payload must be an object")
    if set(payload) != _REVIEW_KEYS:
        raise ValueError("remediation text review payload schema mismatch")
    if payload["schema_version"] != REMEDIATION_TEXT_REVIEW_SCHEMA_VERSION:
        raise ValueError("remediation text review schema version mismatch")

    review_request_sha256 = _canonical_sha256(
        payload["review_request_sha256"],
        field="remediation text review review_request_sha256",
    )
    proposal_sha256 = _canonical_sha256(
        payload["proposal_sha256"],
        field="remediation text review proposal_sha256",
    )
    content_sha256 = _canonical_sha256(
        payload["content_sha256"],
        field="remediation text review content_sha256",
    )
    review_sha256 = _canonical_sha256(
        payload["review_sha256"],
        field="remediation text review review_sha256",
    )
    reviewer_provider_id = _non_empty_string(
        payload["reviewer_provider_id"],
        field="remediation text review reviewer_provider_id",
    )
    reviewer_model_id = _non_empty_string(
        payload["reviewer_model_id"],
        field="remediation text review reviewer_model_id",
    )
    try:
        decision = RemediationTextReviewDecision(payload["decision"])
    except (TypeError, ValueError):
        raise ValueError("remediation text review decision is invalid") from None

    raw_checks = payload["checks"]
    if not isinstance(raw_checks, (list, tuple)):
        raise ValueError("remediation text review checks must be a list or tuple")
    if len(raw_checks) != len(REQUIRED_REVIEW_CHECKS):
        raise ValueError("remediation text review checks count mismatch")
    checks: list[RemediationTextReviewCheck] = []
    for index, raw_check in enumerate(raw_checks):
        if not isinstance(raw_check, dict) or set(raw_check) != _CHECK_KEYS:
            raise ValueError("remediation text review check schema mismatch")
        expected = REQUIRED_REVIEW_CHECKS[index]
        if raw_check["check"] != expected:
            raise ValueError("remediation text review check order or name mismatch")
        result = raw_check["result"]
        if result not in _ALLOWED_CHECK_RESULTS:
            raise ValueError(
                f"remediation text review result for {expected!r} is invalid"
            )
        checks.append(RemediationTextReviewCheck(check=expected, result=result))
    parsed_checks = tuple(checks)
    _validate_decision_checks(decision, parsed_checks)

    summary = _non_empty_string(
        payload["summary"],
        field="remediation text review summary",
    ).strip()
    if "\x00" in summary:
        raise ValueError("remediation text review summary contains NUL")
    if len(summary) > _MAX_REVIEW_SUMMARY_CHARS:
        raise ValueError("remediation text review summary exceeds bounded size")

    if payload["review_completed"] is not True:
        raise ValueError("remediation text review review_completed must remain true")
    expected_accepted = decision is RemediationTextReviewDecision.APPROVED
    if payload["remediation_accepted"] is not expected_accepted:
        raise ValueError("remediation text review remediation_accepted mismatch")
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
                f"remediation text review authority flag {field} must remain false"
            )
    if payload["future_semantics"] != "unresolved":
        raise ValueError("remediation text review future_semantics must remain unresolved")
    if payload["security_verdict"] != "not_evaluated":
        raise ValueError(
            "remediation text review security_verdict must remain not_evaluated"
        )

    parsed = FutureRemediationTextReview(
        schema_version=REMEDIATION_TEXT_REVIEW_SCHEMA_VERSION,
        review_request_sha256=review_request_sha256,
        proposal_sha256=proposal_sha256,
        content_sha256=content_sha256,
        reviewer_provider_id=reviewer_provider_id,
        reviewer_model_id=reviewer_model_id,
        decision=decision,
        checks=parsed_checks,
        summary=summary,
        review_sha256=review_sha256,
        remediation_accepted=expected_accepted,
    )
    if _review_digest(parsed) != parsed.review_sha256:
        raise ValueError("remediation text review digest mismatch")
    return parsed


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def future_remediation_text_review_from_json(raw: str) -> FutureRemediationTextReview:
    """Parse strict review JSON without duplicate-key last-value-wins behavior."""

    if not isinstance(raw, str) or not raw.strip():
        raise ValueError("remediation text review JSON must be a non-empty string")
    try:
        payload = json.loads(raw, object_pairs_hook=_reject_duplicate_json_keys)
    except json.JSONDecodeError as exc:
        raise ValueError("remediation text review JSON is invalid") from exc
    return future_remediation_text_review_from_dict(payload)


def load_and_validate_future_remediation_text_review(
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
) -> FutureRemediationTextReview:
    """Parse a review and require its referenced planning lineage to remain live."""

    if isinstance(persisted_review, str):
        parsed = future_remediation_text_review_from_json(persisted_review)
    elif isinstance(persisted_review, dict):
        parsed = future_remediation_text_review_from_dict(persisted_review)
    else:
        raise ValueError("remediation text review persisted value must be JSON text or object")

    review_request = load_and_validate_future_remediation_text_review_request(
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
    proposal = load_and_validate_future_remediation_text_proposal(
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
        raise ValueError("remediation text review request lineage mismatch")
    if parsed.proposal_sha256 != proposal.proposal_sha256:
        raise ValueError("remediation text review proposal lineage mismatch")
    if parsed.content_sha256 != proposal.content_sha256:
        raise ValueError("remediation text review content lineage mismatch")
    return parsed
