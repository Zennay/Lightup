"""Bounded ST5 request for remediation implementation planning.

This contract advances only reviewed remediation prose into a request for a
later, non-executable implementation plan. It does not generate code/config,
patches, commands, tool calls, target interactions, remediation/retest actions,
deployment authority, or a security verdict.
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
from .future_remediation_text_proposal_handoff import (
    load_and_validate_future_remediation_text_proposal,
)
from .future_remediation_text_review import RemediationTextReviewDecision
from .future_remediation_text_review_handoff import (
    load_and_validate_future_remediation_text_review,
)
from .future_security_remediation_retest_plan import FutureSecurityRemediationRetestPlan
from .state import StateStore


REMEDIATION_IMPLEMENTATION_PLAN_REQUEST_SCHEMA_VERSION = (
    "st5.remediation_implementation_plan_request.v1"
)


def _require_canonical_sha256(value: object, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{field} must be a canonical lowercase SHA-256 digest")
    return value


def _require_non_empty_string(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _require_positive_int(value: object, *, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{field} must be a positive integer")
    return value


@dataclass(frozen=True)
class FutureRemediationImplementationPlanRequest:
    schema_version: str
    review_sha256: str
    review_request_sha256: str
    proposal_sha256: str
    content_sha256: str
    reviewer_provider_id: str
    reviewer_model_id: str
    item_count: int
    implementation_request_sha256: str
    implementation_planning_requested: bool = True
    implementation_plan_created: bool = False
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
        if self.schema_version != REMEDIATION_IMPLEMENTATION_PLAN_REQUEST_SCHEMA_VERSION:
            raise ValueError("implementation-planning request schema version mismatch")
        for field in (
            "review_sha256",
            "review_request_sha256",
            "proposal_sha256",
            "content_sha256",
            "implementation_request_sha256",
        ):
            _require_canonical_sha256(
                getattr(self, field),
                field=f"implementation-planning request {field}",
            )
        _require_non_empty_string(
            self.reviewer_provider_id,
            field="implementation-planning request reviewer_provider_id",
        )
        _require_non_empty_string(
            self.reviewer_model_id,
            field="implementation-planning request reviewer_model_id",
        )
        _require_positive_int(
            self.item_count,
            field="implementation-planning request item_count",
        )
        if self.implementation_planning_requested is not True:
            raise ValueError(
                "implementation-planning request "
                "implementation_planning_requested must remain true"
            )
        if self.implementation_plan_created is not False:
            raise ValueError(
                "implementation-planning request "
                "implementation_plan_created must remain false"
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
            if getattr(self, field) is not False:
                raise ValueError(
                    f"implementation-planning request authority flag "
                    f"{field} must remain false"
                )
        if self.future_semantics != "unresolved":
            raise ValueError(
                "implementation-planning request future_semantics must remain unresolved"
            )
        if self.security_verdict != "not_evaluated":
            raise ValueError(
                "implementation-planning request "
                "security_verdict must remain not_evaluated"
            )
        expected_digest = _request_digest(
            review_sha256=self.review_sha256,
            review_request_sha256=self.review_request_sha256,
            proposal_sha256=self.proposal_sha256,
            content_sha256=self.content_sha256,
            reviewer_provider_id=self.reviewer_provider_id,
            reviewer_model_id=self.reviewer_model_id,
            item_count=self.item_count,
        )
        if self.implementation_request_sha256 != expected_digest:
            raise ValueError("implementation-planning request digest mismatch")

    def as_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(
            self.as_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )


def _request_digest(
    *,
    review_sha256: str,
    review_request_sha256: str,
    proposal_sha256: str,
    content_sha256: str,
    reviewer_provider_id: str,
    reviewer_model_id: str,
    item_count: int,
) -> str:
    payload = {
        "schema_version": REMEDIATION_IMPLEMENTATION_PLAN_REQUEST_SCHEMA_VERSION,
        "review_sha256": review_sha256,
        "review_request_sha256": review_request_sha256,
        "proposal_sha256": proposal_sha256,
        "content_sha256": content_sha256,
        "reviewer_provider_id": reviewer_provider_id,
        "reviewer_model_id": reviewer_model_id,
        "item_count": item_count,
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


def build_future_remediation_implementation_plan_request(
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
    """Request implementation planning only for an approved live review."""

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

    if not review.review_completed:
        raise PermissionError("remediation implementation planning requires completed review")
    if review.decision is not RemediationTextReviewDecision.APPROVED:
        raise PermissionError("remediation implementation planning requires approved text")
    if not review.remediation_accepted:
        raise PermissionError("remediation implementation planning requires accepted text")
    if review.execution_allowed or review.target_interaction_allowed:
        raise ValueError("accepted remediation text review must remain non-executable")
    if review.future_semantics != "unresolved":
        raise ValueError("accepted remediation text review must remain unresolved")
    if review.security_verdict != "not_evaluated":
        raise ValueError("accepted remediation text review must not precompute a verdict")

    implementation_request_sha256 = _request_digest(
        review_sha256=review.review_sha256,
        review_request_sha256=review.review_request_sha256,
        proposal_sha256=review.proposal_sha256,
        content_sha256=review.content_sha256,
        reviewer_provider_id=review.reviewer_provider_id,
        reviewer_model_id=review.reviewer_model_id,
        item_count=proposal.item_count,
    )
    return FutureRemediationImplementationPlanRequest(
        schema_version=REMEDIATION_IMPLEMENTATION_PLAN_REQUEST_SCHEMA_VERSION,
        review_sha256=review.review_sha256,
        review_request_sha256=review.review_request_sha256,
        proposal_sha256=review.proposal_sha256,
        content_sha256=review.content_sha256,
        reviewer_provider_id=review.reviewer_provider_id,
        reviewer_model_id=review.reviewer_model_id,
        item_count=proposal.item_count,
        implementation_request_sha256=implementation_request_sha256,
    )
