"""Planning-only tool-policy catalog review for Security Twin ST5 retests.

This module inspects immutable typed-tool metadata only. It never constructs a
ToolCall, resolves arguments, invokes a handler, issues an activation permit, or
authorizes execution.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from hashlib import sha256
import json

from .ai.orchestration import RunContext, ToolDefinition
from .capabilities import CapabilityState, get_capabilities
from .engagements import AuthorizationGrant, RiskLevel
from .execution_policy import InteractionKind
from .future_attack_path_graph_diff_preview import FutureAttackPathGraphDiffPreview
from .future_attack_path_security_delta_report import FutureAttackPathSecurityDeltaReport
from .future_attack_path_transition import FutureAttackPathTransitionProposal
from .future_attack_path_transition_resolution import FutureAttackPathTransitionResolution
from .future_security_remediation_retest_plan import FutureSecurityRemediationRetestPlan
from .future_security_retest_authorization_preflight import (
    FutureRetestAuthorizationStatus,
    FutureSecurityRetestAssetBinding,
    FutureSecurityRetestAuthorizationPreflight,
    build_future_security_retest_authorization_preflight,
)
from .future_security_retest_request import FutureSecurityRetestRequest
from .state import StateStore


RETEST_TOOL_POLICY_CATALOG_REVIEW_SCHEMA_VERSION = (
    "st5.future_state_retest_tool_policy_catalog_review.v1"
)


class FutureRetestToolPolicyCatalogStatus(str, Enum):
    CANDIDATE_METADATA_AVAILABLE = "candidate_metadata_available"
    CATALOG_GAP_REQUIRES_REVIEW = "catalog_gap_requires_review"


@dataclass(frozen=True)
class FutureSecurityRetestToolPolicyRejection:
    tool_id: str
    reason: str

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class FutureSecurityRetestToolPolicyCapabilityReview:
    capability_id: str
    candidate_tool_ids: tuple[str, ...]
    rejections: tuple[FutureSecurityRetestToolPolicyRejection, ...]
    gap_reason: str | None

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class FutureSecurityRetestToolPolicyCatalogReview:
    schema_version: str
    client_id: str
    engagement_id: str
    request_sha256: str
    preflight_sha256: str
    authorization_grant_sha256: str
    authorization_max_risk: int
    tool_catalog_sha256: str
    capability_reviews: tuple[FutureSecurityRetestToolPolicyCapabilityReview, ...]
    status: FutureRetestToolPolicyCatalogStatus
    review_sha256: str
    tool_policy_review_complete: bool = True
    tool_selection_allowed: bool = False
    tool_call_created: bool = False
    execution_allowed: bool = False
    target_interaction_allowed: bool = False
    deployment_authorized: bool = False
    attack_path_mutation_allowed: bool = False
    future_semantics: str = "unresolved"
    security_verdict: str = "not_evaluated"

    def as_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(
            self.as_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )


def _validate_tool_definition(
    definition: ToolDefinition,
    known_capabilities: dict[str, CapabilityState],
) -> None:
    if not definition.tool_id or definition.tool_id != definition.tool_id.strip():
        raise ValueError("tool definition requires a normalized non-empty tool_id")
    if (
        not definition.capability_id
        or definition.capability_id != definition.capability_id.strip()
    ):
        raise ValueError(
            f"tool {definition.tool_id!r} requires a normalized non-empty capability_id"
        )
    if definition.capability_id not in known_capabilities:
        raise ValueError(
            f"tool {definition.tool_id!r} references unknown capability "
            f"{definition.capability_id!r}"
        )
    if not isinstance(definition.interaction, InteractionKind):
        raise ValueError(f"tool {definition.tool_id!r} has invalid interaction metadata")
    if not isinstance(definition.min_risk, RiskLevel):
        raise ValueError(f"tool {definition.tool_id!r} has invalid risk metadata")

    parameter_names = [parameter.name for parameter in definition.parameters]
    if any(not name or name != name.strip() for name in parameter_names):
        raise ValueError(
            f"tool {definition.tool_id!r} has an invalid parameter name"
        )
    if len(parameter_names) != len(set(parameter_names)):
        raise ValueError(
            f"tool {definition.tool_id!r} has duplicate parameter names"
        )


def _tool_definition_payload(definition: ToolDefinition) -> dict:
    return {
        "tool_id": definition.tool_id,
        "capability_id": definition.capability_id,
        "interaction": definition.interaction.value,
        "min_risk": int(definition.min_risk),
        "description": definition.description,
        "parameters": [
            {
                "name": parameter.name,
                "kind": parameter.kind.value,
                "required": parameter.required,
                "description": parameter.description,
            }
            for parameter in definition.parameters
        ],
    }


def _tool_catalog_digest(definitions: tuple[ToolDefinition, ...]) -> str:
    payload = [_tool_definition_payload(definition) for definition in definitions]
    return sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def _review_digest(
    *,
    preflight: FutureSecurityRetestAuthorizationPreflight,
    authorization: AuthorizationGrant,
    tool_catalog_sha256: str,
    capability_reviews: tuple[FutureSecurityRetestToolPolicyCapabilityReview, ...],
    status: FutureRetestToolPolicyCatalogStatus,
) -> str:
    payload = {
        "schema_version": RETEST_TOOL_POLICY_CATALOG_REVIEW_SCHEMA_VERSION,
        "client_id": preflight.client_id,
        "engagement_id": preflight.engagement_id,
        "request_sha256": preflight.request_sha256,
        "preflight_sha256": preflight.preflight_sha256,
        "authorization_grant_sha256": preflight.authorization_grant_sha256,
        "authorization_max_risk": int(authorization.scope.max_risk),
        "tool_catalog_sha256": tool_catalog_sha256,
        "capability_reviews": [review.as_dict() for review in capability_reviews],
        "status": status.value,
        "tool_policy_review_complete": True,
        "tool_selection_allowed": False,
        "tool_call_created": False,
        "execution_allowed": False,
        "target_interaction_allowed": False,
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


def build_future_security_retest_tool_policy_catalog_review(
    preflight: FutureSecurityRetestAuthorizationPreflight,
    request: FutureSecurityRetestRequest,
    plan: FutureSecurityRemediationRetestPlan,
    report: FutureAttackPathSecurityDeltaReport,
    preview: FutureAttackPathGraphDiffPreview,
    proposal: FutureAttackPathTransitionProposal,
    resolutions: tuple[FutureAttackPathTransitionResolution, ...],
    contexts: tuple[RunContext, ...],
    state: StateStore,
    authorization: AuthorizationGrant,
    asset_bindings: tuple[FutureSecurityRetestAssetBinding, ...],
    checked_at,
    tool_definitions: tuple[ToolDefinition, ...],
) -> FutureSecurityRetestToolPolicyCatalogReview:
    """Review typed-tool catalog metadata without creating any executable call."""

    live_preflight = build_future_security_retest_authorization_preflight(
        request,
        plan,
        report,
        preview,
        proposal,
        resolutions,
        contexts,
        state,
        authorization,
        asset_bindings,
        checked_at,
    )
    if preflight != live_preflight:
        raise ValueError(
            "retest authorization preflight is stale, tampered, or lineage-drifted"
        )
    if (
        preflight.status
        is not FutureRetestAuthorizationStatus.ELIGIBLE_FOR_TOOL_POLICY_REVIEW
        or not preflight.eligible_for_tool_policy_review
    ):
        raise ValueError(
            "tool-policy catalog review requires an eligible authorization preflight"
        )
    if (
        preflight.execution_allowed
        or preflight.target_interaction_allowed
        or preflight.deployment_authorized
        or preflight.attack_path_mutation_allowed
    ):
        raise ValueError("authorization preflight must remain non-executable")

    requested_capability_ids = tuple(request.requested_capability_ids)
    if not requested_capability_ids:
        raise ValueError("retest request must contain at least one requested capability")
    if len(requested_capability_ids) != len(set(requested_capability_ids)):
        raise ValueError("retest request contains duplicate requested capabilities")

    known_capabilities = {
        capability.capability_id: capability.state
        for capability in get_capabilities()
    }
    unknown_requested = sorted(
        set(requested_capability_ids) - set(known_capabilities)
    )
    if unknown_requested:
        raise ValueError(
            "retest request references unknown capabilities: "
            + ", ".join(unknown_requested)
        )

    definitions = tuple(sorted(tool_definitions, key=lambda item: item.tool_id))
    seen_tool_ids: set[str] = set()
    for definition in definitions:
        _validate_tool_definition(definition, known_capabilities)
        if definition.tool_id in seen_tool_ids:
            raise ValueError(f"duplicate tool definition {definition.tool_id!r}")
        seen_tool_ids.add(definition.tool_id)

    reviews: list[FutureSecurityRetestToolPolicyCapabilityReview] = []
    has_gap = False

    for capability_id in requested_capability_ids:
        candidates: list[str] = []
        rejections: list[FutureSecurityRetestToolPolicyRejection] = []

        for definition in definitions:
            if definition.capability_id != capability_id:
                continue

            reasons: list[str] = []
            if known_capabilities[capability_id] is CapabilityState.DISABLED:
                reasons.append("capability_disabled")
            if definition.interaction is not InteractionKind.LAB_ACTIVE:
                reasons.append(
                    f"interaction_not_lab_active:{definition.interaction.value}"
                )
            if definition.min_risk < RiskLevel.LOW_IMPACT:
                reasons.append("active_tool_risk_below_low_impact")
            if definition.min_risk is RiskLevel.DESTRUCTIVE_LAB_ONLY:
                reasons.append("destructive_lab_only_not_candidate")
            if definition.min_risk > authorization.scope.max_risk:
                reasons.append("risk_above_authorized_max")

            if reasons:
                rejections.extend(
                    FutureSecurityRetestToolPolicyRejection(
                        tool_id=definition.tool_id,
                        reason=reason,
                    )
                    for reason in sorted(set(reasons))
                )
            else:
                candidates.append(definition.tool_id)

        candidate_tool_ids = tuple(sorted(candidates))
        rejection_tuple = tuple(
            sorted(rejections, key=lambda item: (item.tool_id, item.reason))
        )
        gap_reason = None
        if not candidate_tool_ids:
            gap_reason = "no_eligible_lab_tool_metadata"
            has_gap = True

        reviews.append(
            FutureSecurityRetestToolPolicyCapabilityReview(
                capability_id=capability_id,
                candidate_tool_ids=candidate_tool_ids,
                rejections=rejection_tuple,
                gap_reason=gap_reason,
            )
        )

    capability_reviews = tuple(reviews)
    status = (
        FutureRetestToolPolicyCatalogStatus.CATALOG_GAP_REQUIRES_REVIEW
        if has_gap
        else FutureRetestToolPolicyCatalogStatus.CANDIDATE_METADATA_AVAILABLE
    )
    tool_catalog_sha256 = _tool_catalog_digest(definitions)
    review_sha256 = _review_digest(
        preflight=preflight,
        authorization=authorization,
        tool_catalog_sha256=tool_catalog_sha256,
        capability_reviews=capability_reviews,
        status=status,
    )

    return FutureSecurityRetestToolPolicyCatalogReview(
        schema_version=RETEST_TOOL_POLICY_CATALOG_REVIEW_SCHEMA_VERSION,
        client_id=preflight.client_id,
        engagement_id=preflight.engagement_id,
        request_sha256=preflight.request_sha256,
        preflight_sha256=preflight.preflight_sha256,
        authorization_grant_sha256=preflight.authorization_grant_sha256,
        authorization_max_risk=int(authorization.scope.max_risk),
        tool_catalog_sha256=tool_catalog_sha256,
        capability_reviews=capability_reviews,
        status=status,
        review_sha256=review_sha256,
    )
