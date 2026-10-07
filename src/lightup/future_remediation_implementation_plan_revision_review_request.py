"""Bounded independent-review request for revised ST5 implementation plans.

This stage consumes only a strict live-valid persisted revised implementation
plan and emits immutable metadata requesting another independent review. It does
not invoke a verifier, accept the plan, generate code/config, call tools,
interact with targets, execute remediation or retests, authorize deployment,
resolve future state, create a security verdict, or mutate attack paths.
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
from .future_remediation_implementation_plan_review_request import (
    REQUIRED_IMPLEMENTATION_PLAN_REVIEW_CHECKS,
)
from .future_remediation_implementation_plan_revision_proposal_handoff import (
    load_and_validate_future_remediation_implementation_plan_revision_proposal,
)
from .future_security_remediation_retest_plan import FutureSecurityRemediationRetestPlan
from .state import StateStore


REMEDIATION_IMPLEMENTATION_PLAN_REVISION_REVIEW_REQUEST_SCHEMA_VERSION = (
    "st5.remediation_implementation_plan_revision_review_request.v1"
)


def _require_canonical_sha256(value: object, *, field: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{field} must be a canonical lowercase SHA-256 digest")
    return value


def _require_canonical_string(value: object, *, field: str) -> str:
    if type(value) is not str or not value:
        raise ValueError(f"{field} must be an exact non-empty string")
    if value != value.strip():
        raise ValueError(f"{field} must be canonical trimmed text")
    if "\x00" in value:
        raise ValueError(f"{field} contains NUL")
    if len(value) > 256:
        raise ValueError(f"{field} exceeds bounded size")
    return value


def _require_positive_int(value: object, *, field: str) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{field} must be a positive exact integer")
    return value


@dataclass(frozen=True)
class FutureRemediationImplementationPlanRevisionReviewRequest:
    schema_version: str
    revision_request_sha256: str
    prior_review_sha256: str
    prior_plan_sha256: str
    implementation_request_sha256: str
    revised_plan_sha256: str
    planner_provider_id: str
    planner_model_id: str
    plan_item_count: int
    required_checks: tuple[str, ...]
    review_request_sha256: str
    implementation_plan_revision_review_requested: bool = True
    revised_implementation_plan_accepted: bool = False
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
            != REMEDIATION_IMPLEMENTATION_PLAN_REVISION_REVIEW_REQUEST_SCHEMA_VERSION
        ):
            raise ValueError(
                "revised implementation plan review-request schema version mismatch"
            )
        for field in (
            "revision_request_sha256",
            "prior_review_sha256",
            "prior_plan_sha256",
            "implementation_request_sha256",
            "revised_plan_sha256",
            "review_request_sha256",
        ):
            _require_canonical_sha256(
                getattr(self, field),
                field=f"revised implementation plan review-request {field}",
            )
        _require_canonical_string(
            self.planner_provider_id,
            field="revised implementation plan review-request planner_provider_id",
        )
        _require_canonical_string(
            self.planner_model_id,
            field="revised implementation plan review-request planner_model_id",
        )
        _require_positive_int(
            self.plan_item_count,
            field="revised implementation plan review-request plan_item_count",
        )
        if self.required_checks != REQUIRED_IMPLEMENTATION_PLAN_REVIEW_CHECKS:
            raise ValueError(
                "revised implementation plan review-request required checks mismatch"
            )
        if self.implementation_plan_revision_review_requested is not True:
            raise ValueError(
                "revised implementation plan review-request "
                "implementation_plan_revision_review_requested must remain true"
            )
        if self.revised_implementation_plan_accepted is not False:
            raise ValueError(
                "revised implementation plan review-request "
                "revised_implementation_plan_accepted must remain false"
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
                    "revised implementation plan review-request authority flag "
                    f"{field} must remain false"
                )
        if self.future_semantics != "unresolved":
            raise ValueError(
                "revised implementation plan review-request "
                "future_semantics must remain unresolved"
            )
        if self.security_verdict != "not_evaluated":
            raise ValueError(
                "revised implementation plan review-request "
                "security_verdict must remain not_evaluated"
            )

        expected_digest = _review_request_digest(
            revision_request_sha256=self.revision_request_sha256,
            prior_review_sha256=self.prior_review_sha256,
            prior_plan_sha256=self.prior_plan_sha256,
            implementation_request_sha256=self.implementation_request_sha256,
            revised_plan_sha256=self.revised_plan_sha256,
            planner_provider_id=self.planner_provider_id,
            planner_model_id=self.planner_model_id,
            plan_item_count=self.plan_item_count,
        )
        if self.review_request_sha256 != expected_digest:
            raise ValueError(
                "revised implementation plan review-request digest mismatch"
            )

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
    revision_request_sha256: str,
    prior_review_sha256: str,
    prior_plan_sha256: str,
    implementation_request_sha256: str,
    revised_plan_sha256: str,
    planner_provider_id: str,
    planner_model_id: str,
    plan_item_count: int,
) -> str:
    payload = {
        "schema_version": (
            REMEDIATION_IMPLEMENTATION_PLAN_REVISION_REVIEW_REQUEST_SCHEMA_VERSION
        ),
        "revision_request_sha256": revision_request_sha256,
        "prior_review_sha256": prior_review_sha256,
        "prior_plan_sha256": prior_plan_sha256,
        "implementation_request_sha256": implementation_request_sha256,
        "revised_plan_sha256": revised_plan_sha256,
        "planner_provider_id": planner_provider_id,
        "planner_model_id": planner_model_id,
        "plan_item_count": plan_item_count,
        "required_checks": list(REQUIRED_IMPLEMENTATION_PLAN_REVIEW_CHECKS),
        "implementation_plan_revision_review_requested": True,
        "revised_implementation_plan_accepted": False,
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


def build_future_remediation_implementation_plan_revision_review_request(
    persisted_revised_plan: object,
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
) -> FutureRemediationImplementationPlanRevisionReviewRequest:
    """Request independent review only after strict revised-plan validation."""

    revised_plan = (
        load_and_validate_future_remediation_implementation_plan_revision_proposal(
            persisted_revised_plan,
            persisted_revision_request,
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
    )
    if not revised_plan.revised_implementation_plan_created:
        raise PermissionError(
            "revised implementation plan review requires an existing revised plan"
        )
    if revised_plan.implementation_plan_accepted:
        raise ValueError(
            "revised implementation plan review source cannot already be accepted"
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
        if getattr(revised_plan, field):
            raise ValueError(
                "revised implementation plan review source authority flag "
                f"{field} must remain false"
            )
    if revised_plan.future_semantics != "unresolved":
        raise ValueError(
            "revised implementation plan review source must remain unresolved"
        )
    if revised_plan.security_verdict != "not_evaluated":
        raise ValueError(
            "revised implementation plan review source must not precompute a verdict"
        )

    review_request_sha256 = _review_request_digest(
        revision_request_sha256=revised_plan.revision_request_sha256,
        prior_review_sha256=revised_plan.prior_review_sha256,
        prior_plan_sha256=revised_plan.prior_plan_sha256,
        implementation_request_sha256=revised_plan.implementation_request_sha256,
        revised_plan_sha256=revised_plan.revised_plan_sha256,
        planner_provider_id=revised_plan.provider_id,
        planner_model_id=revised_plan.model_id,
        plan_item_count=len(revised_plan.plan_items),
    )
    return FutureRemediationImplementationPlanRevisionReviewRequest(
        schema_version=(
            REMEDIATION_IMPLEMENTATION_PLAN_REVISION_REVIEW_REQUEST_SCHEMA_VERSION
        ),
        revision_request_sha256=revised_plan.revision_request_sha256,
        prior_review_sha256=revised_plan.prior_review_sha256,
        prior_plan_sha256=revised_plan.prior_plan_sha256,
        implementation_request_sha256=revised_plan.implementation_request_sha256,
        revised_plan_sha256=revised_plan.revised_plan_sha256,
        planner_provider_id=revised_plan.provider_id,
        planner_model_id=revised_plan.model_id,
        plan_item_count=len(revised_plan.plan_items),
        required_checks=REQUIRED_IMPLEMENTATION_PLAN_REVIEW_CHECKS,
        review_request_sha256=review_request_sha256,
    )
