"""Strict persisted handoff for ST5 remediation-text revision requests.

A persisted revision request remains planning-only. This boundary validates the
exact schema, canonical digest, canonical revision-check ordering and fixed
fail-closed authority flags, then rebuilds the request from the strict live
remediation-text review chain before allowing reuse.
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
from .future_remediation_text_revision_request import (
    REMEDIATION_TEXT_REVISION_REQUEST_SCHEMA_VERSION,
    FutureRemediationTextRevisionRequest,
    build_future_remediation_text_revision_request,
)
from .future_remediation_text_review import RemediationTextReviewDecision
from .future_remediation_text_review_request import REQUIRED_REVIEW_CHECKS
from .future_security_remediation_retest_plan import FutureSecurityRemediationRetestPlan
from .state import StateStore


_REVISION_REQUEST_KEYS = {
    "schema_version",
    "review_sha256",
    "review_request_sha256",
    "proposal_sha256",
    "content_sha256",
    "review_decision",
    "revision_checks",
    "revision_request_sha256",
    "revision_requested",
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


def _revision_request_digest(
    request: FutureRemediationTextRevisionRequest,
) -> str:
    payload = {
        "schema_version": REMEDIATION_TEXT_REVISION_REQUEST_SCHEMA_VERSION,
        "review_sha256": request.review_sha256,
        "review_request_sha256": request.review_request_sha256,
        "proposal_sha256": request.proposal_sha256,
        "content_sha256": request.content_sha256,
        "review_decision": RemediationTextReviewDecision.REVISION_REQUIRED.value,
        "revision_checks": list(request.revision_checks),
        "revision_requested": True,
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


def future_remediation_text_revision_request_from_dict(
    payload: dict,
) -> FutureRemediationTextRevisionRequest:
    """Parse one exact persisted remediation-text revision request."""

    if not isinstance(payload, dict):
        raise ValueError("remediation text revision request payload must be an object")
    if set(payload) != _REVISION_REQUEST_KEYS:
        raise ValueError("remediation text revision request payload schema mismatch")
    if payload["schema_version"] != REMEDIATION_TEXT_REVISION_REQUEST_SCHEMA_VERSION:
        raise ValueError("remediation text revision request schema version mismatch")

    review_sha256 = _canonical_sha256(
        payload["review_sha256"],
        field="remediation text revision request review_sha256",
    )
    review_request_sha256 = _canonical_sha256(
        payload["review_request_sha256"],
        field="remediation text revision request review_request_sha256",
    )
    proposal_sha256 = _canonical_sha256(
        payload["proposal_sha256"],
        field="remediation text revision request proposal_sha256",
    )
    content_sha256 = _canonical_sha256(
        payload["content_sha256"],
        field="remediation text revision request content_sha256",
    )
    revision_request_sha256 = _canonical_sha256(
        payload["revision_request_sha256"],
        field="remediation text revision request revision_request_sha256",
    )

    if (
        payload["review_decision"]
        != RemediationTextReviewDecision.REVISION_REQUIRED.value
    ):
        raise ValueError(
            "remediation text revision request review_decision must remain "
            "revision_required"
        )

    raw_checks = payload["revision_checks"]
    if not isinstance(raw_checks, (list, tuple)):
        raise ValueError(
            "remediation text revision request revision_checks must be a list or tuple"
        )
    revision_checks = tuple(raw_checks)
    if not revision_checks:
        raise ValueError(
            "remediation text revision request revision_checks must be non-empty"
        )
    if any(not isinstance(check, str) for check in revision_checks):
        raise ValueError(
            "remediation text revision request revision_checks must contain strings"
        )
    if len(set(revision_checks)) != len(revision_checks):
        raise ValueError(
            "remediation text revision request revision_checks must be unique"
        )
    canonical_checks = tuple(
        check for check in REQUIRED_REVIEW_CHECKS if check in set(revision_checks)
    )
    if canonical_checks != revision_checks:
        raise ValueError(
            "remediation text revision request revision_checks are invalid or out of order"
        )

    if payload["revision_requested"] is not True:
        raise ValueError(
            "remediation text revision request revision_requested must remain true"
        )
    if payload["remediation_accepted"] is not False:
        raise ValueError(
            "remediation text revision request remediation_accepted must remain false"
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
                f"remediation text revision request authority flag {field} must remain false"
            )
    if payload["future_semantics"] != "unresolved":
        raise ValueError(
            "remediation text revision request future_semantics must remain unresolved"
        )
    if payload["security_verdict"] != "not_evaluated":
        raise ValueError(
            "remediation text revision request security_verdict must remain not_evaluated"
        )

    parsed = FutureRemediationTextRevisionRequest(
        schema_version=REMEDIATION_TEXT_REVISION_REQUEST_SCHEMA_VERSION,
        review_sha256=review_sha256,
        review_request_sha256=review_request_sha256,
        proposal_sha256=proposal_sha256,
        content_sha256=content_sha256,
        review_decision=RemediationTextReviewDecision.REVISION_REQUIRED.value,
        revision_checks=revision_checks,
        revision_request_sha256=revision_request_sha256,
    )
    if _revision_request_digest(parsed) != parsed.revision_request_sha256:
        raise ValueError("remediation text revision request digest mismatch")
    return parsed


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def future_remediation_text_revision_request_from_json(
    raw: str,
) -> FutureRemediationTextRevisionRequest:
    """Parse strict JSON without duplicate-key last-value-wins behavior."""

    if not isinstance(raw, str) or not raw.strip():
        raise ValueError(
            "remediation text revision request JSON must be a non-empty string"
        )
    try:
        payload = json.loads(raw, object_pairs_hook=_reject_duplicate_json_keys)
    except json.JSONDecodeError as exc:
        raise ValueError("remediation text revision request JSON is invalid") from exc
    return future_remediation_text_revision_request_from_dict(payload)


def load_and_validate_future_remediation_text_revision_request(
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
) -> FutureRemediationTextRevisionRequest:
    """Parse and immediately rebuild from the strict live review chain."""

    if isinstance(persisted_revision_request, str):
        parsed = future_remediation_text_revision_request_from_json(
            persisted_revision_request
        )
    elif isinstance(persisted_revision_request, dict):
        parsed = future_remediation_text_revision_request_from_dict(
            persisted_revision_request
        )
    else:
        raise ValueError(
            "remediation text revision request persisted value must be JSON text or object"
        )

    rebuilt = build_future_remediation_text_revision_request(
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
            "remediation text revision request does not match its live validated review"
        )
    return rebuilt
