"""Bounded ST5 request for revising independently reviewed remediation text.

This planning-only boundary consumes the strict persisted remediation-text
review handoff. Only an explicit revision_required review may create a
revision request. Approved text must not be rewritten through this path, while
insufficient_evidence must return to evidence collection instead of laundering
an evidence gap into a prose edit.

The request grants no code, tool, target, execution, retest, deployment,
security-verdict, future-state or attack-path authority.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json

from .ai.orchestration import RunContext
from .future_attack_path_graph_diff_preview import FutureAttackPathGraphDiffPreview
from .future_attack_path_security_delta_report import FutureAttackPathSecurityDeltaReport
from .future_attack_path_transition import FutureAttackPathTransitionProposal
from .future_attack_path_transition_resolution import FutureAttackPathTransitionResolution
from .future_remediation_authoring_request import FutureRemediationAuthoringRequest
from .future_remediation_evidence_bundle import FutureRemediationEvidenceBundle
from .future_remediation_text_review import RemediationTextReviewDecision
from .future_remediation_text_review_handoff import (
    load_and_validate_future_remediation_text_review,
)
from .future_security_remediation_retest_plan import FutureSecurityRemediationRetestPlan
from .state import StateStore


REMEDIATION_TEXT_REVISION_REQUEST_SCHEMA_VERSION = (
    "st5.remediation_text_revision_request.v1"
)


@dataclass(frozen=True)
class FutureRemediationTextRevisionRequest:
    schema_version: str
    review_sha256: str
    review_request_sha256: str
    proposal_sha256: str
    content_sha256: str
    review_decision: str
    revision_checks: tuple[str, ...]
    revision_request_sha256: str
    revision_requested: bool = True
    remediation_accepted: bool = False
    code_change_authorized: bool = False
    tool_call_created: bool = False
    execution_allowed: bool = False
    target_interaction_allowed: bool = False
    future_state_retest_allowed: bool = False
    deployment_authorized: bool = False
    attack_path_mutation_allowed: bool = False
    future_semantics: str = "unresolved"
    security_verdict: str = "not_evaluated"

    def __post_init__(self) -> None:
        if self.review_decision != RemediationTextReviewDecision.REVISION_REQUIRED.value:
            raise ValueError("remediation revision request review_decision must remain revision_required")
        if self.revision_requested is not True:
            raise ValueError("revision_requested must remain true")
        if self.remediation_accepted is not False:
            raise ValueError("remediation_accepted must remain false")
        for field in (
            "code_change_authorized",
            "tool_call_created",
            "execution_allowed",
            "target_interaction_allowed",
            "future_state_retest_allowed",
            "deployment_authorized",
            "attack_path_mutation_allowed",
        ):
            if getattr(self, field) is not False:
                raise ValueError(f"authority flag {field} must remain false")
        if self.future_semantics != "unresolved":
            raise ValueError("future_semantics must remain unresolved")
        if self.security_verdict != "not_evaluated":
            raise ValueError("security_verdict must remain not_evaluated")

    def as_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(
            self.as_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )


def _revision_request_digest(
    *,
    review_sha256: str,
    review_request_sha256: str,
    proposal_sha256: str,
    content_sha256: str,
    revision_checks: tuple[str, ...],
) -> str:
    payload = {
        "schema_version": REMEDIATION_TEXT_REVISION_REQUEST_SCHEMA_VERSION,
        "review_sha256": review_sha256,
        "review_request_sha256": review_request_sha256,
        "proposal_sha256": proposal_sha256,
        "content_sha256": content_sha256,
        "review_decision": RemediationTextReviewDecision.REVISION_REQUIRED.value,
        "revision_checks": list(revision_checks),
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


def build_future_remediation_text_revision_request(
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
    """Create a bounded revision request from one strict live review.

    The function intentionally has no model gateway or execution dependency.
    """

    review = load_and_validate_future_remediation_text_review(
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

    if review.decision is RemediationTextReviewDecision.APPROVED:
        raise ValueError(
            "approved remediation text must not enter the revision-request path"
        )
    if review.decision is RemediationTextReviewDecision.INSUFFICIENT_EVIDENCE:
        raise ValueError(
            "insufficient-evidence remediation review requires fresh evidence, "
            "not text revision"
        )
    if review.decision is not RemediationTextReviewDecision.REVISION_REQUIRED:
        raise ValueError("remediation text review decision cannot request revision")

    revision_checks = tuple(
        check.check for check in review.checks if check.result != "pass"
    )
    if not revision_checks:
        raise ValueError(
            "revision_required remediation review must identify a non-pass check"
        )

    revision_request_sha256 = _revision_request_digest(
        review_sha256=review.review_sha256,
        review_request_sha256=review.review_request_sha256,
        proposal_sha256=review.proposal_sha256,
        content_sha256=review.content_sha256,
        revision_checks=revision_checks,
    )
    return FutureRemediationTextRevisionRequest(
        schema_version=REMEDIATION_TEXT_REVISION_REQUEST_SCHEMA_VERSION,
        review_sha256=review.review_sha256,
        review_request_sha256=review.review_request_sha256,
        proposal_sha256=review.proposal_sha256,
        content_sha256=review.content_sha256,
        review_decision=RemediationTextReviewDecision.REVISION_REQUIRED.value,
        revision_checks=revision_checks,
        revision_request_sha256=revision_request_sha256,
    )
