"""Non-executable explicit tool-selection proposals for Security Twin ST5 retests.

This module records one explicitly proposed lab tool ID per requested capability
after a fully eligible tool-policy catalog review. It never constructs a
ToolCall, resolves arguments or target assets, invokes handlers, issues an
activation permit, or authorizes execution.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json

from .ai.orchestration import RunContext, ToolDefinition
from .engagements import AuthorizationGrant
from .future_attack_path_graph_diff_preview import FutureAttackPathGraphDiffPreview
from .future_attack_path_security_delta_report import FutureAttackPathSecurityDeltaReport
from .future_attack_path_transition import FutureAttackPathTransitionProposal
from .future_attack_path_transition_resolution import FutureAttackPathTransitionResolution
from .future_security_remediation_retest_plan import FutureSecurityRemediationRetestPlan
from .future_security_retest_authorization_preflight import (
    FutureSecurityRetestAssetBinding,
    FutureSecurityRetestAuthorizationPreflight,
)
from .future_security_retest_request import FutureSecurityRetestRequest
from .future_security_retest_tool_policy_review import (
    FutureRetestToolPolicyCatalogStatus,
    FutureSecurityRetestToolPolicyCatalogReview,
    build_future_security_retest_tool_policy_catalog_review,
)
from .state import StateStore


RETEST_TOOL_SELECTION_PROPOSAL_SCHEMA_VERSION = (
    "st5.future_state_retest_tool_selection_proposal.v1"
)


@dataclass(frozen=True)
class FutureSecurityRetestToolSelectionProposalItem:
    capability_id: str
    proposed_tool_id: str

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class FutureSecurityRetestToolSelectionProposal:
    schema_version: str
    client_id: str
    engagement_id: str
    request_sha256: str
    preflight_sha256: str
    review_sha256: str
    tool_catalog_sha256: str
    selections: tuple[FutureSecurityRetestToolSelectionProposalItem, ...]
    proposal_sha256: str
    proposal_complete: bool = True
    selection_authorized: bool = False
    tool_call_created: bool = False
    arguments_resolved: bool = False
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


def _proposal_digest(
    *,
    review: FutureSecurityRetestToolPolicyCatalogReview,
    selections: tuple[FutureSecurityRetestToolSelectionProposalItem, ...],
) -> str:
    payload = {
        "schema_version": RETEST_TOOL_SELECTION_PROPOSAL_SCHEMA_VERSION,
        "client_id": review.client_id,
        "engagement_id": review.engagement_id,
        "request_sha256": review.request_sha256,
        "preflight_sha256": review.preflight_sha256,
        "review_sha256": review.review_sha256,
        "tool_catalog_sha256": review.tool_catalog_sha256,
        "selections": [selection.as_dict() for selection in selections],
        "proposal_complete": True,
        "selection_authorized": False,
        "tool_call_created": False,
        "arguments_resolved": False,
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


def build_future_security_retest_tool_selection_proposal(
    review: FutureSecurityRetestToolPolicyCatalogReview,
    preflight: FutureSecurityRetestAuthorizationPreflight,
    request: FutureSecurityRetestRequest,
    plan: FutureSecurityRemediationRetestPlan,
    report: FutureAttackPathSecurityDeltaReport,
    preview: FutureAttackPathGraphDiffPreview,
    transition: FutureAttackPathTransitionProposal,
    resolutions: tuple[FutureAttackPathTransitionResolution, ...],
    contexts: tuple[RunContext, ...],
    state: StateStore,
    authorization: AuthorizationGrant,
    asset_bindings: tuple[FutureSecurityRetestAssetBinding, ...],
    checked_at,
    tool_definitions: tuple[ToolDefinition, ...],
    selections: tuple[FutureSecurityRetestToolSelectionProposalItem, ...],
) -> FutureSecurityRetestToolSelectionProposal:
    """Bind explicit candidate IDs into immutable proposal metadata only."""

    live_review = build_future_security_retest_tool_policy_catalog_review(
        preflight,
        request,
        plan,
        report,
        preview,
        transition,
        resolutions,
        contexts,
        state,
        authorization,
        asset_bindings,
        checked_at,
        tool_definitions,
    )
    if review != live_review:
        raise ValueError(
            "retest tool-policy catalog review is stale, tampered, or lineage-drifted"
        )

    if (
        review.status
        is not FutureRetestToolPolicyCatalogStatus.CANDIDATE_METADATA_AVAILABLE
    ):
        raise ValueError(
            "tool-selection proposal requires gap-free candidate metadata"
        )
    if (
        review.tool_selection_allowed
        or review.tool_call_created
        or review.execution_allowed
        or review.target_interaction_allowed
        or review.deployment_authorized
        or review.attack_path_mutation_allowed
    ):
        raise ValueError("catalog review must remain non-executable")

    capability_reviews = {
        item.capability_id: item for item in review.capability_reviews
    }
    requested_capabilities = tuple(request.requested_capability_ids)
    if set(capability_reviews) != set(requested_capabilities):
        raise ValueError("catalog review capability coverage does not match request")

    for capability_id in requested_capabilities:
        capability_review = capability_reviews[capability_id]
        if capability_review.gap_reason is not None:
            raise ValueError(
                f"capability {capability_id!r} has an unresolved catalog gap"
            )
        if not capability_review.candidate_tool_ids:
            raise ValueError(
                f"capability {capability_id!r} has no admitted candidate metadata"
            )

    normalized: list[FutureSecurityRetestToolSelectionProposalItem] = []
    seen_capabilities: set[str] = set()
    for selection in selections:
        capability_id = selection.capability_id.strip()
        proposed_tool_id = selection.proposed_tool_id.strip()
        if (
            not capability_id
            or capability_id != selection.capability_id
            or not proposed_tool_id
            or proposed_tool_id != selection.proposed_tool_id
        ):
            raise ValueError(
                "tool-selection proposal requires normalized non-empty identifiers"
            )
        if capability_id in seen_capabilities:
            raise ValueError(
                f"duplicate tool-selection proposal for capability {capability_id!r}"
            )
        seen_capabilities.add(capability_id)

        capability_review = capability_reviews.get(capability_id)
        if capability_review is None:
            raise ValueError(
                f"tool-selection proposal references unrequested capability {capability_id!r}"
            )
        if proposed_tool_id not in capability_review.candidate_tool_ids:
            raise ValueError(
                f"tool {proposed_tool_id!r} is not an admitted candidate for "
                f"capability {capability_id!r}"
            )
        normalized.append(
            FutureSecurityRetestToolSelectionProposalItem(
                capability_id=capability_id,
                proposed_tool_id=proposed_tool_id,
            )
        )

    if seen_capabilities != set(requested_capabilities):
        raise ValueError(
            "tool-selection proposal requires exactly one explicit proposal "
            "per requested capability"
        )

    ordered = tuple(
        sorted(normalized, key=lambda item: (item.capability_id, item.proposed_tool_id))
    )
    proposal_sha256 = _proposal_digest(review=review, selections=ordered)

    return FutureSecurityRetestToolSelectionProposal(
        schema_version=RETEST_TOOL_SELECTION_PROPOSAL_SCHEMA_VERSION,
        client_id=review.client_id,
        engagement_id=review.engagement_id,
        request_sha256=review.request_sha256,
        preflight_sha256=review.preflight_sha256,
        review_sha256=review.review_sha256,
        tool_catalog_sha256=review.tool_catalog_sha256,
        selections=ordered,
        proposal_sha256=proposal_sha256,
    )
