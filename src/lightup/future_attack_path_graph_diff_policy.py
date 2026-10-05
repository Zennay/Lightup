"""Fail-closed ST4 policy decision over attack-path graph-diff previews.

This stage is decision metadata only. It revalidates a graph-diff preview against
its live proposal/resolution/evidence lineage before producing an immutable
operator-review eligibility decision. It never mutates SecurityTwin.attack_paths
and never emits a deployment or security verdict.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from hashlib import sha256
import json

from .ai.orchestration import RunContext
from .future_attack_path_graph_diff_preview import (
    AttackPathGraphDiffAction,
    FutureAttackPathGraphDiffPreview,
    FutureAttackPathGraphDiffPreviewItem,
    build_future_attack_path_graph_diff_preview,
)
from .future_attack_path_transition import FutureAttackPathTransitionProposal
from .future_attack_path_transition_resolution import (
    FutureAttackPathTransitionResolution,
)
from .state import StateStore


class GraphDiffPolicyDisposition(str, Enum):
    ELIGIBLE_FOR_OPERATOR_REVIEW = "eligible_for_operator_review"
    REQUIRES_MORE_EVIDENCE = "requires_more_evidence"
    REJECTED = "rejected"


@dataclass(frozen=True)
class FutureAttackPathGraphDiffPolicyDecision:
    client_id: str
    current_twin_id: str
    current_twin_version: int
    twin_id: str
    twin_version: int
    changeset_id: str
    proposal_sha256: str
    impact_analysis_sha256: str
    preview_sha256: str
    disposition: GraphDiffPolicyDisposition
    reason_codes: tuple[str, ...]
    change_node_ids: tuple[str, ...]
    resolution_ids: tuple[str, ...]
    resolution_sha256s: tuple[str, ...]
    current_attack_path_ids: tuple[str, ...]
    effect_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    capability_ids: tuple[str, ...]
    decision_sha256: str
    attack_path_mutation_allowed: bool = False
    future_semantics: str = "unresolved"
    security_verdict: str = "not_evaluated"

    def as_dict(self) -> dict:
        return asdict(self)


def _require_nonempty_text(name: str, value: object) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be non-empty text")
    return value


def _require_unique_tuple(
    name: str,
    value: object,
    *,
    required: bool = False,
) -> tuple[str, ...]:
    if not isinstance(value, tuple):
        raise ValueError(f"{name} must be an immutable tuple")
    if required and not value:
        raise ValueError(f"{name} must not be empty")
    for item in value:
        _require_nonempty_text(f"{name} item", item)
    if len(set(value)) != len(value):
        raise ValueError(f"{name} must not contain duplicates")
    return value


def _validate_preview_shape(preview: FutureAttackPathGraphDiffPreview) -> None:
    if not isinstance(preview, FutureAttackPathGraphDiffPreview):
        raise ValueError("preview must be a FutureAttackPathGraphDiffPreview")
    if not preview.preview_complete:
        raise ValueError("graph diff preview is incomplete")
    if preview.attack_path_mutation_allowed:
        raise ValueError("graph diff preview must not allow attack-path mutation")
    if preview.future_semantics != "unresolved":
        raise ValueError("graph diff preview future_semantics must remain unresolved")
    if preview.security_verdict != "not_evaluated":
        raise ValueError("graph diff preview security_verdict must remain not_evaluated")

    _require_nonempty_text("client_id", preview.client_id)
    _require_nonempty_text("current_twin_id", preview.current_twin_id)
    _require_nonempty_text("twin_id", preview.twin_id)
    _require_nonempty_text("changeset_id", preview.changeset_id)
    _require_nonempty_text("proposal_sha256", preview.proposal_sha256)
    _require_nonempty_text("impact_analysis_sha256", preview.impact_analysis_sha256)
    _require_nonempty_text("preview_sha256", preview.preview_sha256)

    if not isinstance(preview.items, tuple) or not preview.items:
        raise ValueError("graph diff preview must contain immutable decision items")

    seen_changes: set[str] = set()
    seen_resolutions: set[str] = set()
    seen_paths: set[str] = set()

    for item in preview.items:
        if not isinstance(item, FutureAttackPathGraphDiffPreviewItem):
            raise ValueError("graph diff preview contains an invalid item")
        _require_nonempty_text("change_node_id", item.change_node_id)
        _require_nonempty_text("subject_node_id", item.subject_node_id)
        _require_nonempty_text("resolution_id", item.resolution_id)
        _require_nonempty_text("resolution_sha256", item.resolution_sha256)
        if not isinstance(item.action, AttackPathGraphDiffAction):
            raise ValueError("graph diff preview contains an unsupported action")

        if item.change_node_id in seen_changes:
            raise ValueError("graph diff preview contains duplicate change lineage")
        if item.resolution_id in seen_resolutions:
            raise ValueError("graph diff preview contains duplicate resolution lineage")
        seen_changes.add(item.change_node_id)
        seen_resolutions.add(item.resolution_id)

        _require_unique_tuple("effect_ids", item.effect_ids, required=True)
        paths = _require_unique_tuple(
            "current_attack_path_ids", item.current_attack_path_ids
        )
        _require_unique_tuple("evidence_ids", item.evidence_ids, required=True)
        _require_unique_tuple("capability_ids", item.capability_ids, required=True)

        for path_id in paths:
            if path_id in seen_paths:
                raise ValueError(
                    "graph diff preview contains duplicate current-path lineage"
                )
            seen_paths.add(path_id)

        if item.action is AttackPathGraphDiffAction.ADD_PATH_HYPOTHESIS and paths:
            raise ValueError(
                "add_path_hypothesis must not reference an existing attack path"
            )
        if item.action in {
            AttackPathGraphDiffAction.REMOVE_EXISTING_PATH_CANDIDATE,
            AttackPathGraphDiffAction.MODIFY_EXISTING_PATH_RISK_UP,
            AttackPathGraphDiffAction.MODIFY_EXISTING_PATH_RISK_DOWN,
        } and not paths:
            raise ValueError(
                "existing-path graph diff action requires current-path lineage"
            )


def _decision_digest(
    *,
    preview: FutureAttackPathGraphDiffPreview,
    disposition: GraphDiffPolicyDisposition,
    reason_codes: tuple[str, ...],
) -> str:
    payload = {
        "client_id": preview.client_id,
        "current_twin_id": preview.current_twin_id,
        "current_twin_version": preview.current_twin_version,
        "twin_id": preview.twin_id,
        "twin_version": preview.twin_version,
        "changeset_id": preview.changeset_id,
        "proposal_sha256": preview.proposal_sha256,
        "impact_analysis_sha256": preview.impact_analysis_sha256,
        "preview_sha256": preview.preview_sha256,
        "disposition": disposition.value,
        "reason_codes": list(reason_codes),
        "change_node_ids": [item.change_node_id for item in preview.items],
        "resolution_ids": [item.resolution_id for item in preview.items],
        "resolution_sha256s": [
            item.resolution_sha256 for item in preview.items
        ],
        "current_attack_path_ids": [
            path_id
            for item in preview.items
            for path_id in item.current_attack_path_ids
        ],
        "effect_ids": [
            effect_id for item in preview.items for effect_id in item.effect_ids
        ],
        "evidence_ids": [
            evidence_id
            for item in preview.items
            for evidence_id in item.evidence_ids
        ],
        "capability_ids": sorted(
            {
                capability_id
                for item in preview.items
                for capability_id in item.capability_ids
            }
        ),
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


def decide_future_attack_path_graph_diff_policy(
    preview: FutureAttackPathGraphDiffPreview,
    proposal: FutureAttackPathTransitionProposal,
    resolutions: tuple[FutureAttackPathTransitionResolution, ...],
    contexts: tuple[RunContext, ...],
    state: StateStore,
) -> FutureAttackPathGraphDiffPolicyDecision:
    """Return immutable operator-review eligibility after live preview revalidation."""

    _validate_preview_shape(preview)

    rebuilt = build_future_attack_path_graph_diff_preview(
        proposal,
        resolutions,
        contexts,
        state,
    )
    if rebuilt != preview:
        raise ValueError(
            "graph diff preview is stale, tampered, cross-tenant, or lineage-drifted"
        )

    if preview.contains_insufficient_evidence:
        disposition = GraphDiffPolicyDisposition.REQUIRES_MORE_EVIDENCE
        reason_codes = ("insufficient_evidence",)
    else:
        disposition = GraphDiffPolicyDisposition.ELIGIBLE_FOR_OPERATOR_REVIEW
        reason_codes = ("validated_preview",)

    change_node_ids = tuple(item.change_node_id for item in preview.items)
    resolution_ids = tuple(item.resolution_id for item in preview.items)
    resolution_sha256s = tuple(item.resolution_sha256 for item in preview.items)
    current_attack_path_ids = tuple(
        path_id for item in preview.items for path_id in item.current_attack_path_ids
    )
    effect_ids = tuple(
        effect_id for item in preview.items for effect_id in item.effect_ids
    )
    evidence_ids = tuple(
        evidence_id for item in preview.items for evidence_id in item.evidence_ids
    )
    capability_ids = tuple(
        sorted(
            {
                capability_id
                for item in preview.items
                for capability_id in item.capability_ids
            }
        )
    )
    decision_sha256 = _decision_digest(
        preview=preview,
        disposition=disposition,
        reason_codes=reason_codes,
    )

    return FutureAttackPathGraphDiffPolicyDecision(
        client_id=preview.client_id,
        current_twin_id=preview.current_twin_id,
        current_twin_version=preview.current_twin_version,
        twin_id=preview.twin_id,
        twin_version=preview.twin_version,
        changeset_id=preview.changeset_id,
        proposal_sha256=preview.proposal_sha256,
        impact_analysis_sha256=preview.impact_analysis_sha256,
        preview_sha256=preview.preview_sha256,
        disposition=disposition,
        reason_codes=reason_codes,
        change_node_ids=change_node_ids,
        resolution_ids=resolution_ids,
        resolution_sha256s=resolution_sha256s,
        current_attack_path_ids=current_attack_path_ids,
        effect_ids=effect_ids,
        evidence_ids=evidence_ids,
        capability_ids=capability_ids,
        decision_sha256=decision_sha256,
    )
