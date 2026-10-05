"""Read-only ST4 preview of attack-path graph changes.

This stage consumes only independently verified transition resolutions. It
describes a deterministic graph-diff preview, but it never mutates a
SecurityTwin or AttackPath and never emits a deployment/security verdict.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from hashlib import sha256
import json

from .ai.orchestration import RunContext
from .future_attack_path_transition import (
    FutureAttackPathTransitionProposal,
    validate_future_attack_path_transition_proposal,
)
from .future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
    FutureAttackPathTransitionResolution,
    validate_future_attack_path_transition_resolution,
)
from .state import StateStore


class AttackPathGraphDiffAction(str, Enum):
    ADD_PATH_HYPOTHESIS = "add_path_hypothesis"
    REMOVE_EXISTING_PATH_CANDIDATE = "remove_existing_path_candidate"
    MODIFY_EXISTING_PATH_RISK_UP = "modify_existing_path_risk_up"
    MODIFY_EXISTING_PATH_RISK_DOWN = "modify_existing_path_risk_down"
    NO_GRAPH_CHANGE_CLAIM = "no_graph_change_claim"


_ACTION_BY_CLASSIFICATION = {
    AttackPathTransitionClassification.INTRODUCED: (
        AttackPathGraphDiffAction.ADD_PATH_HYPOTHESIS
    ),
    AttackPathTransitionClassification.REMOVED: (
        AttackPathGraphDiffAction.REMOVE_EXISTING_PATH_CANDIDATE
    ),
    AttackPathTransitionClassification.WORSENED: (
        AttackPathGraphDiffAction.MODIFY_EXISTING_PATH_RISK_UP
    ),
    AttackPathTransitionClassification.IMPROVED: (
        AttackPathGraphDiffAction.MODIFY_EXISTING_PATH_RISK_DOWN
    ),
    AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE: (
        AttackPathGraphDiffAction.NO_GRAPH_CHANGE_CLAIM
    ),
}


@dataclass(frozen=True)
class FutureAttackPathGraphDiffPreviewItem:
    change_node_id: str
    subject_node_id: str
    resolution_id: str
    resolution_sha256: str
    classification: AttackPathTransitionClassification
    action: AttackPathGraphDiffAction
    effect_ids: tuple[str, ...]
    current_attack_path_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    capability_ids: tuple[str, ...]

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class FutureAttackPathGraphDiffPreview:
    client_id: str
    current_twin_id: str
    current_twin_version: int
    twin_id: str
    twin_version: int
    changeset_id: str
    proposal_sha256: str
    impact_analysis_sha256: str
    items: tuple[FutureAttackPathGraphDiffPreviewItem, ...]
    preview_complete: bool
    contains_insufficient_evidence: bool
    preview_sha256: str
    attack_path_mutation_allowed: bool = False
    future_semantics: str = "unresolved"
    security_verdict: str = "not_evaluated"

    def as_dict(self) -> dict:
        return asdict(self)


def _require_tuple(name: str, value: object) -> tuple:
    if not isinstance(value, tuple):
        raise ValueError(f"{name} must be an immutable tuple")
    return value


def _preview_digest(
    *,
    proposal: FutureAttackPathTransitionProposal,
    items: tuple[FutureAttackPathGraphDiffPreviewItem, ...],
    contains_insufficient_evidence: bool,
) -> str:
    payload = {
        "client_id": proposal.client_id,
        "current_twin_id": proposal.current_twin_id,
        "current_twin_version": proposal.current_twin_version,
        "twin_id": proposal.twin_id,
        "twin_version": proposal.twin_version,
        "changeset_id": proposal.changeset_id,
        "proposal_sha256": proposal.proposal_sha256,
        "impact_analysis_sha256": proposal.impact_analysis_sha256,
        "items": [
            {
                "change_node_id": item.change_node_id,
                "subject_node_id": item.subject_node_id,
                "resolution_id": item.resolution_id,
                "resolution_sha256": item.resolution_sha256,
                "classification": item.classification.value,
                "action": item.action.value,
                "effect_ids": list(item.effect_ids),
                "current_attack_path_ids": list(item.current_attack_path_ids),
                "evidence_ids": list(item.evidence_ids),
                "capability_ids": list(item.capability_ids),
            }
            for item in items
        ],
        "preview_complete": True,
        "contains_insufficient_evidence": contains_insufficient_evidence,
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


def _contexts_by_run(
    contexts: tuple[RunContext, ...],
) -> dict[str, RunContext]:
    _require_tuple("contexts", contexts)
    by_run: dict[str, RunContext] = {}
    for context in contexts:
        if not isinstance(context, RunContext):
            raise ValueError("contexts must contain RunContext values")
        if context.run_id in by_run:
            raise ValueError("contexts contain duplicate run_id values")
        by_run[context.run_id] = context
    return by_run


def build_future_attack_path_graph_diff_preview(
    proposal: FutureAttackPathTransitionProposal,
    resolutions: tuple[FutureAttackPathTransitionResolution, ...],
    contexts: tuple[RunContext, ...],
    state: StateStore,
) -> FutureAttackPathGraphDiffPreview:
    """Build a deterministic read-only preview from verified ST4 resolutions."""
    validate_future_attack_path_transition_proposal(proposal)
    _require_tuple("resolutions", resolutions)

    if len(resolutions) != len(proposal.items):
        raise ValueError(
            "graph diff preview requires exactly one resolution per proposal item"
        )

    resolution_by_change: dict[str, FutureAttackPathTransitionResolution] = {}
    resolution_ids: set[str] = set()
    for resolution in resolutions:
        if not isinstance(resolution, FutureAttackPathTransitionResolution):
            raise ValueError(
                "resolutions must contain FutureAttackPathTransitionResolution values"
            )
        if resolution.change_node_id in resolution_by_change:
            raise ValueError("graph diff preview contains duplicate change resolutions")
        if resolution.resolution_id in resolution_ids:
            raise ValueError("graph diff preview contains duplicate resolution identities")
        resolution_by_change[resolution.change_node_id] = resolution
        resolution_ids.add(resolution.resolution_id)

    proposal_change_ids = tuple(item.change_node_id for item in proposal.items)
    if set(resolution_by_change) != set(proposal_change_ids):
        raise ValueError(
            "graph diff preview resolutions do not exactly cover proposal changes"
        )

    context_by_run = _contexts_by_run(contexts)
    resolution_run_ids = {resolution.run_id for resolution in resolutions}
    if set(context_by_run) != resolution_run_ids:
        raise ValueError(
            "graph diff preview contexts must exactly cover resolution runs"
        )

    preview_items: list[FutureAttackPathGraphDiffPreviewItem] = []
    claimed_current_paths: dict[str, str] = {}

    for proposal_item in proposal.items:
        resolution = resolution_by_change[proposal_item.change_node_id]
        context = context_by_run[resolution.run_id]
        validate_future_attack_path_transition_resolution(
            proposal,
            resolution,
            context,
            state,
        )

        for path_id in resolution.current_attack_path_ids:
            prior_change = claimed_current_paths.get(path_id)
            if prior_change is not None and prior_change != resolution.change_node_id:
                raise ValueError(
                    "graph diff preview has colliding claims on a current attack path"
                )
            claimed_current_paths[path_id] = resolution.change_node_id

        action = _ACTION_BY_CLASSIFICATION.get(resolution.classification)
        if action is None:
            raise ValueError("graph diff preview classification is unsupported")

        preview_items.append(
            FutureAttackPathGraphDiffPreviewItem(
                change_node_id=resolution.change_node_id,
                subject_node_id=resolution.subject_node_id,
                resolution_id=resolution.resolution_id,
                resolution_sha256=resolution.resolution_sha256,
                classification=resolution.classification,
                action=action,
                effect_ids=resolution.effect_ids,
                current_attack_path_ids=resolution.current_attack_path_ids,
                evidence_ids=resolution.evidence_ids,
                capability_ids=resolution.capability_ids,
            )
        )

    items = tuple(preview_items)
    if tuple(item.change_node_id for item in items) != proposal_change_ids:
        raise ValueError("graph diff preview items are not canonically ordered")

    contains_insufficient = any(
        item.classification
        is AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE
        for item in items
    )
    digest = _preview_digest(
        proposal=proposal,
        items=items,
        contains_insufficient_evidence=contains_insufficient,
    )

    return FutureAttackPathGraphDiffPreview(
        client_id=proposal.client_id,
        current_twin_id=proposal.current_twin_id,
        current_twin_version=proposal.current_twin_version,
        twin_id=proposal.twin_id,
        twin_version=proposal.twin_version,
        changeset_id=proposal.changeset_id,
        proposal_sha256=proposal.proposal_sha256,
        impact_analysis_sha256=proposal.impact_analysis_sha256,
        items=items,
        preview_complete=True,
        contains_insufficient_evidence=contains_insufficient,
        preview_sha256=digest,
    )


def validate_future_attack_path_graph_diff_preview(
    preview: FutureAttackPathGraphDiffPreview,
    proposal: FutureAttackPathTransitionProposal,
    resolutions: tuple[FutureAttackPathTransitionResolution, ...],
    contexts: tuple[RunContext, ...],
    state: StateStore,
) -> FutureAttackPathGraphDiffPreview:
    """Rebuild and compare a preview against its live verified lineage.

    Reporting and later policy stages must never trust a previously serialized
    preview on its own. Rebuilding forces proposal, resolution, RunContext and
    evidence validation to run again against current StateStore contents.
    """
    if not isinstance(preview, FutureAttackPathGraphDiffPreview):
        raise ValueError("preview must be a FutureAttackPathGraphDiffPreview")

    rebuilt = build_future_attack_path_graph_diff_preview(
        proposal,
        resolutions,
        contexts,
        state,
    )
    if rebuilt != preview:
        raise ValueError(
            "graph diff preview does not match its live validated lineage"
        )
    return rebuilt
