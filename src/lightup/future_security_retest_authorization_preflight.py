"""Fail-closed authorization preflight for Security Twin ST5 retest requests.

This package binds every isolated future-state retest item to one explicit asset
and checks the existing authorization grant before any tool/risk selection can
occur. It produces planning metadata only and cannot execute target actions.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum
from hashlib import sha256
import json

from .ai.orchestration import RunContext
from .engagements import AuthorizationGrant
from .future_attack_path_graph_diff_preview import FutureAttackPathGraphDiffPreview
from .future_attack_path_security_delta_report import FutureAttackPathSecurityDeltaReport
from .future_attack_path_transition import FutureAttackPathTransitionProposal
from .future_attack_path_transition_resolution import FutureAttackPathTransitionResolution
from .future_security_remediation_retest_plan import FutureSecurityRemediationRetestPlan
from .future_security_retest_request import (
    FutureSecurityRetestRequest,
    build_future_security_retest_request,
)
from .state import StateStore


RETEST_AUTHORIZATION_PREFLIGHT_SCHEMA_VERSION = (
    "st5.future_state_retest_authorization_preflight.v1"
)


class FutureRetestAuthorizationStatus(str, Enum):
    ELIGIBLE_FOR_TOOL_POLICY_REVIEW = "eligible_for_tool_policy_review"
    REAUTHORIZATION_REQUIRED = "reauthorization_required"


@dataclass(frozen=True)
class FutureSecurityRetestAssetBinding:
    resolution_id: str
    asset: str

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class FutureSecurityRetestAuthorizationPreflight:
    schema_version: str
    client_id: str
    engagement_id: str
    request_sha256: str
    authorization_grant_id: str
    authorization_reference_sha256: str
    checked_at: str
    bindings: tuple[FutureSecurityRetestAssetBinding, ...]
    requested_capability_ids: tuple[str, ...]
    status: FutureRetestAuthorizationStatus
    reasons: tuple[str, ...]
    preflight_sha256: str
    eligible_for_tool_policy_review: bool
    tool_policy_review_required: bool = True
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


def _reference_digest(reference: str) -> str:
    return sha256(reference.encode("utf-8")).hexdigest()


def _preflight_digest(
    *,
    request: FutureSecurityRetestRequest,
    engagement_id: str,
    authorization: AuthorizationGrant,
    checked_at: datetime,
    bindings: tuple[FutureSecurityRetestAssetBinding, ...],
    status: FutureRetestAuthorizationStatus,
    reasons: tuple[str, ...],
) -> str:
    payload = {
        "schema_version": RETEST_AUTHORIZATION_PREFLIGHT_SCHEMA_VERSION,
        "client_id": request.client_id,
        "engagement_id": engagement_id,
        "request_sha256": request.request_sha256,
        "authorization_grant_id": authorization.grant_id,
        "authorization_reference_sha256": _reference_digest(authorization.reference),
        "checked_at": checked_at.isoformat(),
        "bindings": [
            {"resolution_id": binding.resolution_id, "asset": binding.asset}
            for binding in bindings
        ],
        "requested_capability_ids": list(request.requested_capability_ids),
        "status": status.value,
        "reasons": list(reasons),
        "eligible_for_tool_policy_review": (
            status is FutureRetestAuthorizationStatus.ELIGIBLE_FOR_TOOL_POLICY_REVIEW
        ),
        "tool_policy_review_required": True,
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


def build_future_security_retest_authorization_preflight(
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
    checked_at: datetime,
) -> FutureSecurityRetestAuthorizationPreflight:
    """Build non-executable authorization preflight metadata.

    Success only means that the immutable retest request is eligible for a
    later tool/risk policy review. No tool, adapter, risk level, or network
    action is selected or executed here.
    """

    if checked_at.tzinfo is None:
        raise ValueError("authorization preflight time must be timezone-aware")

    live_request = build_future_security_retest_request(
        plan,
        report,
        preview,
        proposal,
        resolutions,
        contexts,
        state,
    )
    if request != live_request:
        raise ValueError(
            "future-state retest request is stale, tampered, cross-tenant, "
            "or lineage-drifted"
        )
    if (
        request.execution_allowed
        or request.target_interaction_allowed
        or request.deployment_authorized
        or request.attack_path_mutation_allowed
    ):
        raise ValueError("future-state retest request must remain non-executable")
    if request.future_semantics != "unresolved":
        raise ValueError("future-state retest request semantics must remain unresolved")
    if request.security_verdict != "not_evaluated":
        raise ValueError("future-state retest request must not precompute a verdict")

    if not contexts:
        raise ValueError("authorization preflight requires source run contexts")
    context_clients = {context.client_id for context in contexts}
    context_engagements = {context.engagement_id for context in contexts}
    if context_clients != {request.client_id}:
        raise ValueError("source run contexts do not match the retest-request client")
    if len(context_engagements) != 1:
        raise ValueError("source run contexts must bind exactly one engagement")
    engagement_id = next(iter(context_engagements))

    if authorization.client_id != request.client_id:
        raise ValueError("authorization grant client does not match retest request")
    if authorization.engagement_id != engagement_id:
        raise ValueError("authorization grant engagement does not match source lineage")

    # A retest preflight must be auditable back to a concrete authorization
    # record. Do not emit a policy-review-eligible artifact from an anonymous,
    # unreferenced, or temporally malformed grant.
    for field_name, value in (
        ("grant_id", authorization.grant_id),
        ("approved_by", authorization.approved_by),
        ("reference", authorization.reference),
    ):
        if not value.strip():
            raise ValueError(f"authorization grant requires non-empty {field_name}")
    for field_name, value in (
        ("valid_from", authorization.valid_from),
        ("valid_until", authorization.valid_until),
    ):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError(
                f"authorization grant {field_name} must be timezone-aware"
            )
    if authorization.valid_until < authorization.valid_from:
        raise ValueError("authorization grant validity window is inverted")

    item_ids = tuple(item.resolution_id for item in request.items)
    expected_ids = set(item_ids)
    if len(expected_ids) != len(item_ids):
        raise ValueError("retest request contains duplicate resolution identities")

    normalized: list[FutureSecurityRetestAssetBinding] = []
    seen: set[str] = set()
    for binding in asset_bindings:
        resolution_id = binding.resolution_id.strip()
        asset = binding.asset.strip().lower()
        if not resolution_id or not asset:
            raise ValueError("asset bindings require non-empty resolution and asset")
        if any(token in asset for token in ("*", "?", "[", "]")):
            raise ValueError("asset binding must name one explicit asset without wildcards")
        if resolution_id in seen:
            raise ValueError("duplicate asset binding for retest item")
        seen.add(resolution_id)
        normalized.append(FutureSecurityRetestAssetBinding(resolution_id, asset))

    if seen != expected_ids:
        raise ValueError("asset bindings must cover every retest item exactly once")

    binding_by_id = {binding.resolution_id: binding for binding in normalized}
    bindings = tuple(binding_by_id[item_id] for item_id in item_ids)

    reasons: list[str] = []
    if not authorization.is_current(checked_at):
        reasons.append("authorization_not_current")
    if not authorization.recurring_retest_allowed:
        reasons.append("recurring_retest_not_authorized")

    for binding in bindings:
        if not authorization.scope.allows_asset(binding.asset):
            reasons.append(f"asset_out_of_scope:{binding.resolution_id}")

    # Retest authorization is intentionally stricter than the generic scope
    # helper: issue #53 requires every requested capability to be explicitly
    # present in the recurring-retest grant. An empty allowlist must therefore
    # fail closed here rather than inheriting ScopeDefinition's generic
    # "unspecified means unrestricted" behavior.
    authorized_capabilities = {
        capability_id.strip()
        for capability_id in authorization.scope.allowed_capabilities
        if capability_id.strip()
    }
    for capability_id in request.requested_capability_ids:
        if capability_id not in authorized_capabilities:
            reasons.append(f"capability_out_of_scope:{capability_id}")

    reason_tuple = tuple(sorted(set(reasons)))
    status = (
        FutureRetestAuthorizationStatus.REAUTHORIZATION_REQUIRED
        if reason_tuple
        else FutureRetestAuthorizationStatus.ELIGIBLE_FOR_TOOL_POLICY_REVIEW
    )
    eligible = (
        status is FutureRetestAuthorizationStatus.ELIGIBLE_FOR_TOOL_POLICY_REVIEW
    )
    preflight_sha256 = _preflight_digest(
        request=request,
        engagement_id=engagement_id,
        authorization=authorization,
        checked_at=checked_at,
        bindings=bindings,
        status=status,
        reasons=reason_tuple,
    )

    return FutureSecurityRetestAuthorizationPreflight(
        schema_version=RETEST_AUTHORIZATION_PREFLIGHT_SCHEMA_VERSION,
        client_id=request.client_id,
        engagement_id=engagement_id,
        request_sha256=request.request_sha256,
        authorization_grant_id=authorization.grant_id,
        authorization_reference_sha256=_reference_digest(authorization.reference),
        checked_at=checked_at.isoformat(),
        bindings=bindings,
        requested_capability_ids=request.requested_capability_ids,
        status=status,
        reasons=reason_tuple,
        preflight_sha256=preflight_sha256,
        eligible_for_tool_policy_review=eligible,
    )
