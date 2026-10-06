"""Bounded ST5 revision request for remediation implementation plans.

This module converts only a strict live persisted implementation-plan review
with decision revision_required into immutable metadata requesting a later
bounded plan revision. It does not invoke a model, create a revised plan,
generate code/config, call tools, interact with targets, execute remediation or
retests, authorize deployment, resolve future state, create a security verdict,
or mutate attack paths.
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
from .future_remediation_implementation_plan_review import (
    RemediationImplementationPlanReviewDecision,
)
from .future_remediation_implementation_plan_review_handoff import (
    load_and_validate_future_remediation_implementation_plan_review,
)
from .future_remediation_implementation_plan_review_request import (
    REQUIRED_IMPLEMENTATION_PLAN_REVIEW_CHECKS,
)
from .future_security_remediation_retest_plan import FutureSecurityRemediationRetestPlan
from .state import StateStore


REMEDIATION_IMPLEMENTATION_PLAN_REVISION_REQUEST_SCHEMA_VERSION = (
    "st5.remediation_implementation_plan_revision_request.v1"
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
    if "\x00" in value:
        raise ValueError(f"{field} contains NUL")
    return value


def _require_revision_checks(value: object) -> tuple[str, ...]:
    if not isinstance(value, tuple) or not value:
        raise ValueError(
            "implementation plan revision request required_revisions "
            "must be a non-empty tuple"
        )
    if any(not isinstance(item, str) or not item for item in value):
        raise ValueError(
            "implementation plan revision request required_revisions "
            "must contain non-empty strings"
        )
    if len(set(value)) != len(value):
        raise ValueError(
            "implementation plan revision request required_revisions "
            "must not contain duplicates"
        )
    allowed = REQUIRED_IMPLEMENTATION_PLAN_REVIEW_CHECKS
    if any(item not in allowed for item in value):
        raise ValueError(
            "implementation plan revision request required_revisions "
            "contains an unknown review check"
        )
    expected_order = tuple(check for check in allowed if check in value)
    if value != expected_order:
        raise ValueError(
            "implementation plan revision request required_revisions "
            "must preserve rubric order"
        )
    return value


@dataclass(frozen=True)
class FutureRemediationImplementationPlanRevisionRequest:
    schema_version: str
    review_sha256: str
    review_request_sha256: str
    plan_sha256: str
    implementation_request_sha256: str
    reviewer_provider_id: str
    reviewer_model_id: str
    required_revisions: tuple[str, ...]
    revision_request_sha256: str
    source_review_decision: str = "revision_required"
    implementation_plan_revision_requested: bool = True
    revised_implementation_plan_created: bool = False
    implementation_plan_accepted: bool = False
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
        if (
            self.schema_version
            != REMEDIATION_IMPLEMENTATION_PLAN_REVISION_REQUEST_SCHEMA_VERSION
        ):
            raise ValueError("implementation plan revision-request schema mismatch")
        for field in (
            "review_sha256",
            "review_request_sha256",
            "plan_sha256",
            "implementation_request_sha256",
            "revision_request_sha256",
        ):
            _require_canonical_sha256(
                getattr(self, field),
                field=f"implementation plan revision request {field}",
            )
        _require_non_empty_string(
            self.reviewer_provider_id,
            field="implementation plan revision request reviewer_provider_id",
        )
        _require_non_empty_string(
            self.reviewer_model_id,
            field="implementation plan revision request reviewer_model_id",
        )
        _require_revision_checks(self.required_revisions)
        if self.source_review_decision != "revision_required":
            raise ValueError(
                "implementation plan revision request source_review_decision "
                "must remain revision_required"
            )
        if self.implementation_plan_revision_requested is not True:
            raise ValueError(
                "implementation_plan_revision_requested must remain true"
            )
        if self.revised_implementation_plan_created is not False:
            raise ValueError(
                "revised_implementation_plan_created must remain false"
            )
        if self.implementation_plan_accepted is not False:
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
            if getattr(self, field) is not False:
                raise ValueError(
                    f"implementation plan revision request authority flag "
                    f"{field} must remain false"
                )
        if self.future_semantics != "unresolved":
            raise ValueError(
                "implementation plan revision request "
                "future_semantics must remain unresolved"
            )
        if self.security_verdict != "not_evaluated":
            raise ValueError(
                "implementation plan revision request "
                "security_verdict must remain not_evaluated"
            )
        expected_digest = _revision_request_digest(
            review_sha256=self.review_sha256,
            review_request_sha256=self.review_request_sha256,
            plan_sha256=self.plan_sha256,
            implementation_request_sha256=self.implementation_request_sha256,
            reviewer_provider_id=self.reviewer_provider_id,
            reviewer_model_id=self.reviewer_model_id,
            required_revisions=self.required_revisions,
        )
        if self.revision_request_sha256 != expected_digest:
            raise ValueError("implementation plan revision-request digest mismatch")

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
    plan_sha256: str,
    implementation_request_sha256: str,
    reviewer_provider_id: str,
    reviewer_model_id: str,
    required_revisions: tuple[str, ...],
) -> str:
    payload = {
        "schema_version": REMEDIATION_IMPLEMENTATION_PLAN_REVISION_REQUEST_SCHEMA_VERSION,
        "review_sha256": review_sha256,
        "review_request_sha256": review_request_sha256,
        "plan_sha256": plan_sha256,
        "implementation_request_sha256": implementation_request_sha256,
        "reviewer_provider_id": reviewer_provider_id,
        "reviewer_model_id": reviewer_model_id,
        "required_revisions": list(required_revisions),
        "source_review_decision": "revision_required",
        "implementation_plan_revision_requested": True,
        "revised_implementation_plan_created": False,
        "implementation_plan_accepted": False,
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


def build_future_remediation_implementation_plan_revision_request(
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
    """Request a later plan revision only after a strict revision-required review."""

    review = load_and_validate_future_remediation_implementation_plan_review(
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
    if not review.implementation_plan_review_completed:
        raise PermissionError(
            "implementation plan revision requires completed independent review"
        )
    if (
        review.decision
        is not RemediationImplementationPlanReviewDecision.REVISION_REQUIRED
    ):
        raise PermissionError(
            "implementation plan revision requires revision_required review"
        )
    if review.implementation_plan_accepted:
        raise ValueError(
            "implementation plan revision cannot start from an accepted plan"
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
        if getattr(review, field):
            raise ValueError(
                f"implementation plan revision source authority flag {field} "
                "must remain false"
            )
    if review.future_semantics != "unresolved":
        raise ValueError("implementation plan revision source must remain unresolved")
    if review.security_verdict != "not_evaluated":
        raise ValueError(
            "implementation plan revision source must not precompute a verdict"
        )

    required_revisions = tuple(
        check.check for check in review.checks if check.result != "pass"
    )
    if not required_revisions:
        raise ValueError(
            "revision_required implementation plan review has no revision checks"
        )
    revision_request_sha256 = _revision_request_digest(
        review_sha256=review.review_sha256,
        review_request_sha256=review.review_request_sha256,
        plan_sha256=review.plan_sha256,
        implementation_request_sha256=review.implementation_request_sha256,
        reviewer_provider_id=review.reviewer_provider_id,
        reviewer_model_id=review.reviewer_model_id,
        required_revisions=required_revisions,
    )
    return FutureRemediationImplementationPlanRevisionRequest(
        schema_version=REMEDIATION_IMPLEMENTATION_PLAN_REVISION_REQUEST_SCHEMA_VERSION,
        review_sha256=review.review_sha256,
        review_request_sha256=review.review_request_sha256,
        plan_sha256=review.plan_sha256,
        implementation_request_sha256=review.implementation_request_sha256,
        reviewer_provider_id=review.reviewer_provider_id,
        reviewer_model_id=review.reviewer_model_id,
        required_revisions=required_revisions,
        revision_request_sha256=revision_request_sha256,
    )
