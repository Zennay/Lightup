"""Bounded ST5 review request for remediation implementation plans.

This module consumes only a strict, live-valid persisted implementation plan
and emits immutable metadata requesting independent review. It does not invoke
a verifier, accept the plan, generate code/config, call tools, interact with
targets, execute remediation or retests, authorize deployment, resolve future
state, create a security verdict, or mutate attack paths.
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
from .future_remediation_implementation_plan_handoff import (
    load_and_validate_future_remediation_implementation_plan,
)
from .future_security_remediation_retest_plan import FutureSecurityRemediationRetestPlan
from .state import StateStore


REMEDIATION_IMPLEMENTATION_PLAN_REVIEW_REQUEST_SCHEMA_VERSION = (
    "st5.remediation_implementation_plan_review_request.v1"
)
REQUIRED_IMPLEMENTATION_PLAN_REVIEW_CHECKS = (
    "evidence_alignment",
    "least_privilege",
    "verification_separation",
    "rollback_sufficiency",
    "non_executable_scope",
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
class FutureRemediationImplementationPlanReviewRequest:
    schema_version: str
    implementation_request_sha256: str
    remediation_review_sha256: str
    proposal_sha256: str
    content_sha256: str
    plan_sha256: str
    planner_provider_id: str
    planner_model_id: str
    plan_item_count: int
    required_checks: tuple[str, ...]
    review_request_sha256: str
    implementation_plan_review_requested: bool = True
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
            _require_canonical_sha256(
                getattr(self, field),
                field=f"implementation plan review-request {field}",
            )
        _require_non_empty_string(
            self.planner_provider_id,
            field="implementation plan review-request planner_provider_id",
        )
        _require_non_empty_string(
            self.planner_model_id,
            field="implementation plan review-request planner_model_id",
        )
        _require_positive_int(
            self.plan_item_count,
            field="implementation plan review-request plan_item_count",
        )
        if self.required_checks != REQUIRED_IMPLEMENTATION_PLAN_REVIEW_CHECKS:
            raise ValueError("implementation plan review-request required checks mismatch")
        if self.implementation_plan_review_requested is not True:
            raise ValueError(
                "implementation plan review-request "
                "implementation_plan_review_requested must remain true"
            )
        if self.implementation_plan_accepted is not False:
            raise ValueError(
                "implementation plan review-request "
                "implementation_plan_accepted must remain false"
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
                    f"implementation plan review-request authority flag "
                    f"{field} must remain false"
                )
        if self.future_semantics != "unresolved":
            raise ValueError(
                "implementation plan review-request future_semantics must remain unresolved"
            )
        if self.security_verdict != "not_evaluated":
            raise ValueError(
                "implementation plan review-request "
                "security_verdict must remain not_evaluated"
            )

        expected_digest = _review_request_digest(
            implementation_request_sha256=self.implementation_request_sha256,
            remediation_review_sha256=self.remediation_review_sha256,
            proposal_sha256=self.proposal_sha256,
            content_sha256=self.content_sha256,
            plan_sha256=self.plan_sha256,
            planner_provider_id=self.planner_provider_id,
            planner_model_id=self.planner_model_id,
            plan_item_count=self.plan_item_count,
        )
        if self.review_request_sha256 != expected_digest:
            raise ValueError("implementation plan review-request digest mismatch")

    def as_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(
            self.as_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )


def _review_request_digest(
    *,
    implementation_request_sha256: str,
    remediation_review_sha256: str,
    proposal_sha256: str,
    content_sha256: str,
    plan_sha256: str,
    planner_provider_id: str,
    planner_model_id: str,
    plan_item_count: int,
) -> str:
    payload = {
        "schema_version": REMEDIATION_IMPLEMENTATION_PLAN_REVIEW_REQUEST_SCHEMA_VERSION,
        "implementation_request_sha256": implementation_request_sha256,
        "remediation_review_sha256": remediation_review_sha256,
        "proposal_sha256": proposal_sha256,
        "content_sha256": content_sha256,
        "plan_sha256": plan_sha256,
        "planner_provider_id": planner_provider_id,
        "planner_model_id": planner_model_id,
        "plan_item_count": plan_item_count,
        "required_checks": list(REQUIRED_IMPLEMENTATION_PLAN_REVIEW_CHECKS),
        "implementation_plan_review_requested": True,
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


def build_future_remediation_implementation_plan_review_request(
    persisted_plan: object,
    persisted_planning_request: object,
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
) -> FutureRemediationImplementationPlanReviewRequest:
    """Request independent review only after strict live plan validation."""

    implementation_plan = load_and_validate_future_remediation_implementation_plan(
        persisted_plan,
        persisted_planning_request,
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
    if not implementation_plan.implementation_plan_created:
        raise PermissionError(
            "implementation plan review requires an existing implementation plan"
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
        if getattr(implementation_plan, field):
            raise ValueError(
                f"implementation plan review source authority flag {field} "
                "must remain false"
            )
    if implementation_plan.future_semantics != "unresolved":
        raise ValueError("implementation plan review source must remain unresolved")
    if implementation_plan.security_verdict != "not_evaluated":
        raise ValueError(
            "implementation plan review source must not precompute a verdict"
        )

    review_request_sha256 = _review_request_digest(
        implementation_request_sha256=implementation_plan.implementation_request_sha256,
        remediation_review_sha256=implementation_plan.review_sha256,
        proposal_sha256=implementation_plan.proposal_sha256,
        content_sha256=implementation_plan.content_sha256,
        plan_sha256=implementation_plan.plan_sha256,
        planner_provider_id=implementation_plan.provider_id,
        planner_model_id=implementation_plan.model_id,
        plan_item_count=len(implementation_plan.plan_items),
    )
    return FutureRemediationImplementationPlanReviewRequest(
        schema_version=REMEDIATION_IMPLEMENTATION_PLAN_REVIEW_REQUEST_SCHEMA_VERSION,
        implementation_request_sha256=(
            implementation_plan.implementation_request_sha256
        ),
        remediation_review_sha256=implementation_plan.review_sha256,
        proposal_sha256=implementation_plan.proposal_sha256,
        content_sha256=implementation_plan.content_sha256,
        plan_sha256=implementation_plan.plan_sha256,
        planner_provider_id=implementation_plan.provider_id,
        planner_model_id=implementation_plan.model_id,
        plan_item_count=len(implementation_plan.plan_items),
        required_checks=REQUIRED_IMPLEMENTATION_PLAN_REVIEW_CHECKS,
        review_request_sha256=review_request_sha256,
    )
