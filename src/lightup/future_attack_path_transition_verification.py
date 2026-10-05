"""ST4 verification of future attack-path transition proposals.

This module validates one exact read-only ST3 transition proposal item against
fresh isolated-lab evidence. It returns immutable verification state only. It
never mutates a Security Twin or AttackPath and never produces a deployment
security verdict.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import hashlib
import json

from .ai.orchestration import RunContext
from .engagements import AssessmentMode
from .future_attack_path_transition import (
    FutureAttackPathTransitionProposal,
    FutureAttackPathTransitionProposalItem,
    validate_future_attack_path_transition_proposal,
)
from .state import StateStore


class AttackPathTransitionClassification(str, Enum):
    INTRODUCED = "introduced"
    REMOVED = "removed"
    WORSENED = "worsened"
    IMPROVED = "improved"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


@dataclass(frozen=True)
class FutureAttackPathTransitionResolution:
    resolution_id: str
    client_id: str
    proposal_sha256: str
    impact_analysis_sha256: str
    change_node_id: str
    subject_node_id: str
    review_action: str
    effect_ids: tuple[str, ...]
    current_attack_path_ids: tuple[str, ...]
    classification: str
    run_id: str
    engagement_id: str
    evidence_ids: tuple[str, ...]
    capability_ids: tuple[str, ...]
    resolution_sha256: str
    future_semantics: str = "unresolved"
    security_verdict: str = "not_evaluated"
    attack_path_mutation_allowed: bool = False

    def as_dict(self) -> dict:
        """Return a detached JSON-serializable representation."""
        return asdict(self)


_ALLOWED_CLASSIFICATIONS = {
    "review_new_path_hypothesis": {
        AttackPathTransitionClassification.INTRODUCED.value,
        AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE.value,
    },
    "review_existing_paths_for_regression": {
        AttackPathTransitionClassification.WORSENED.value,
        AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE.value,
    },
    "review_existing_paths_for_improvement": {
        AttackPathTransitionClassification.IMPROVED.value,
        AttackPathTransitionClassification.REMOVED.value,
        AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE.value,
    },
    "review_improvement_without_path_claim": {
        AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE.value,
    },
    "no_transition_claim": {
        AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE.value,
    },
    "manual_transition_review": {
        item.value for item in AttackPathTransitionClassification
    },
}


def _canonical_tuple(
    values: tuple[str, ...],
    field: str,
    *,
    allow_empty: bool = False,
) -> tuple[str, ...]:
    if not isinstance(values, tuple):
        raise ValueError(f"transition resolution {field} must be a tuple")
    if not values and not allow_empty:
        raise ValueError(f"transition resolution {field} is required")
    if any(not isinstance(value, str) or not value.strip() for value in values):
        raise ValueError(f"transition resolution {field} contains an invalid identifier")
    canonical = tuple(sorted(values))
    if len(set(canonical)) != len(canonical):
        raise ValueError(f"transition resolution {field} contains duplicates")
    if values != canonical:
        raise ValueError(f"transition resolution {field} is not canonically ordered")
    return canonical


def _lineage_digest(values: tuple[str, ...]) -> str:
    return hashlib.sha256("\x1f".join(values).encode("utf-8")).hexdigest()


def _resolution_digest(
    *,
    resolution_id: str,
    client_id: str,
    proposal_sha256: str,
    impact_analysis_sha256: str,
    change_node_id: str,
    subject_node_id: str,
    review_action: str,
    effect_ids: tuple[str, ...],
    current_attack_path_ids: tuple[str, ...],
    classification: str,
    run_id: str,
    engagement_id: str,
    evidence_ids: tuple[str, ...],
    capability_ids: tuple[str, ...],
) -> str:
    payload = {
        "resolution_id": resolution_id,
        "client_id": client_id,
        "proposal_sha256": proposal_sha256,
        "impact_analysis_sha256": impact_analysis_sha256,
        "change_node_id": change_node_id,
        "subject_node_id": subject_node_id,
        "review_action": review_action,
        "effect_ids": effect_ids,
        "current_attack_path_ids": current_attack_path_ids,
        "classification": classification,
        "run_id": run_id,
        "engagement_id": engagement_id,
        "evidence_ids": evidence_ids,
        "capability_ids": capability_ids,
        "future_semantics": "unresolved",
        "security_verdict": "not_evaluated",
        "attack_path_mutation_allowed": False,
    }
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _proposal_item(
    proposal: FutureAttackPathTransitionProposal,
    change_node_id: str,
) -> FutureAttackPathTransitionProposalItem:
    matches = tuple(
        item for item in proposal.items if item.change_node_id == change_node_id
    )
    if len(matches) != 1:
        raise ValueError(
            "transition resolution must name exactly one proposal change item"
        )
    return matches[0]


def _validate_action_classification(review_action: str, classification: str) -> None:
    allowed = _ALLOWED_CLASSIFICATIONS.get(review_action)
    if allowed is None:
        raise ValueError(
            f"unsupported transition proposal review action {review_action!r}"
        )
    if classification not in allowed:
        raise ValueError(
            f"classification {classification!r} is incompatible with "
            f"proposal action {review_action!r}"
        )


def _proposal_evidence_ids(
    item: FutureAttackPathTransitionProposalItem,
) -> set[str]:
    ids: set[str] = set()
    for ref in item.evidence_refs:
        if ref.startswith("evidence:"):
            ids.add(ref[len("evidence:"):])
        else:
            ids.add(ref)
    return ids


def _validate_resolution(
    resolution: FutureAttackPathTransitionResolution,
    proposal: FutureAttackPathTransitionProposal,
    context: RunContext,
    state: StateStore,
    *,
    require_recorded: bool,
) -> None:
    validate_future_attack_path_transition_proposal(proposal)

    if not isinstance(resolution, FutureAttackPathTransitionResolution):
        raise ValueError("transition resolution type is invalid")
    if not context.is_lab or context.mode is not AssessmentMode.LAB_AUTONOMOUS:
        raise PermissionError(
            "attack-path transition verification requires a LAB_AUTONOMOUS run"
        )

    for field, value in (
        ("resolution_id", resolution.resolution_id),
        ("client_id", resolution.client_id),
        ("proposal_sha256", resolution.proposal_sha256),
        ("impact_analysis_sha256", resolution.impact_analysis_sha256),
        ("change_node_id", resolution.change_node_id),
        ("subject_node_id", resolution.subject_node_id),
        ("review_action", resolution.review_action),
        ("classification", resolution.classification),
        ("run_id", resolution.run_id),
        ("engagement_id", resolution.engagement_id),
        ("resolution_sha256", resolution.resolution_sha256),
    ):
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"transition resolution {field} is invalid")

    if resolution.client_id != proposal.client_id:
        raise ValueError("transition resolution cannot cross proposal tenants")
    if context.client_id != proposal.client_id:
        raise ValueError("RunContext client does not match proposal tenant")
    if resolution.run_id != context.run_id:
        raise ValueError("transition resolution run_id does not match RunContext")
    if resolution.engagement_id != context.engagement_id:
        raise ValueError(
            "transition resolution engagement_id does not match RunContext"
        )
    if resolution.proposal_sha256 != proposal.proposal_sha256:
        raise ValueError("transition resolution proposal SHA-256 mismatch")
    if resolution.impact_analysis_sha256 != proposal.impact_analysis_sha256:
        raise ValueError("transition resolution impact-analysis SHA-256 mismatch")

    item = _proposal_item(proposal, resolution.change_node_id)
    if resolution.subject_node_id != item.subject_node_id:
        raise ValueError("transition resolution subject does not match proposal item")
    if resolution.review_action != item.review_action:
        raise ValueError("transition resolution review action does not match proposal")
    if resolution.effect_ids != item.effect_ids:
        raise ValueError("transition resolution effect lineage does not match proposal")
    if resolution.current_attack_path_ids != item.current_attack_path_ids:
        raise ValueError(
            "transition resolution current path lineage does not match proposal"
        )

    _canonical_tuple(resolution.effect_ids, "effect_ids")
    _canonical_tuple(
        resolution.current_attack_path_ids,
        "current_attack_path_ids",
        allow_empty=True,
    )
    _canonical_tuple(resolution.evidence_ids, "evidence_ids")
    _canonical_tuple(resolution.capability_ids, "capability_ids")
    _validate_action_classification(
        resolution.review_action,
        resolution.classification,
    )

    if resolution.future_semantics != "unresolved":
        raise ValueError(
            "transition resolution must preserve unresolved future semantics"
        )
    if resolution.security_verdict != "not_evaluated":
        raise ValueError("transition resolution cannot claim a security verdict")
    if resolution.attack_path_mutation_allowed:
        raise ValueError("transition resolution cannot allow attack-path mutation")

    prior_evidence = _proposal_evidence_ids(item)
    reused = prior_evidence.intersection(resolution.evidence_ids)
    if reused:
        raise ValueError(
            "transition resolution evidence must be fresh and not reused "
            f"from the proposal: {sorted(reused)!r}"
        )

    expected_effect_digest = _lineage_digest(item.effect_ids)
    expected_path_digest = _lineage_digest(item.current_attack_path_ids)
    evidence = tuple(state.get_evidence(item) for item in resolution.evidence_ids)

    for record in evidence:
        if record.run_id != resolution.run_id:
            raise ValueError("transition verification evidence belongs to another run")
        metadata = dict(record.metadata)
        expected_metadata = {
            "purpose": "future_attack_path_transition_verification",
            "resolution_id": resolution.resolution_id,
            "proposal_sha256": proposal.proposal_sha256,
            "impact_analysis_sha256": proposal.impact_analysis_sha256,
            "client_id": proposal.client_id,
            "engagement_id": context.engagement_id,
            "mode": context.mode.value,
            "is_lab": "true",
            "change_node_id": item.change_node_id,
            "subject_node_id": item.subject_node_id,
            "classification": resolution.classification,
            "effect_ids_sha256": expected_effect_digest,
            "current_attack_path_ids_sha256": expected_path_digest,
        }
        for key, expected in expected_metadata.items():
            if metadata.get(key) != expected:
                raise ValueError(
                    f"transition verification evidence metadata mismatch for {key}"
                )

    evidence_capabilities = {record.capability_id for record in evidence}
    if evidence_capabilities != set(resolution.capability_ids):
        raise ValueError(
            "transition resolution capability_ids must exactly match fresh evidence"
        )

    expected_resolution_digest = _resolution_digest(
        resolution_id=resolution.resolution_id,
        client_id=resolution.client_id,
        proposal_sha256=resolution.proposal_sha256,
        impact_analysis_sha256=resolution.impact_analysis_sha256,
        change_node_id=resolution.change_node_id,
        subject_node_id=resolution.subject_node_id,
        review_action=resolution.review_action,
        effect_ids=resolution.effect_ids,
        current_attack_path_ids=resolution.current_attack_path_ids,
        classification=resolution.classification,
        run_id=resolution.run_id,
        engagement_id=resolution.engagement_id,
        evidence_ids=resolution.evidence_ids,
        capability_ids=resolution.capability_ids,
    )
    if resolution.resolution_sha256 != expected_resolution_digest:
        raise ValueError("transition resolution digest mismatch")

    if require_recorded:
        recorded = state.get_future_attack_path_transition_resolution(
            resolution.resolution_id
        )
        if recorded is None:
            raise ValueError("transition resolution is not recorded")
        if recorded != (
            resolution.resolution_sha256,
            resolution.client_id,
            resolution.run_id,
        ):
            raise ValueError("recorded transition resolution identity mismatch")


def verify_future_attack_path_transition(
    proposal: FutureAttackPathTransitionProposal,
    *,
    change_node_id: str,
    classification: AttackPathTransitionClassification,
    resolution_id: str,
    evidence_ids: tuple[str, ...],
    capability_ids: tuple[str, ...],
    context: RunContext,
    state: StateStore,
) -> FutureAttackPathTransitionResolution:
    """Verify one proposal item with fresh evidence from one exact lab run."""
    validate_future_attack_path_transition_proposal(proposal)
    if not isinstance(classification, AttackPathTransitionClassification):
        raise ValueError("transition classification type is invalid")
    if not isinstance(change_node_id, str) or not change_node_id.strip():
        raise ValueError("change_node_id is required")
    if not isinstance(resolution_id, str) or not resolution_id.strip():
        raise ValueError("resolution_id is required")

    item = _proposal_item(proposal, change_node_id)
    evidence_ids = _canonical_tuple(evidence_ids, "evidence_ids")
    capability_ids = _canonical_tuple(capability_ids, "capability_ids")
    _validate_action_classification(item.review_action, classification.value)

    digest = _resolution_digest(
        resolution_id=resolution_id,
        client_id=proposal.client_id,
        proposal_sha256=proposal.proposal_sha256,
        impact_analysis_sha256=proposal.impact_analysis_sha256,
        change_node_id=item.change_node_id,
        subject_node_id=item.subject_node_id,
        review_action=item.review_action,
        effect_ids=item.effect_ids,
        current_attack_path_ids=item.current_attack_path_ids,
        classification=classification.value,
        run_id=context.run_id,
        engagement_id=context.engagement_id,
        evidence_ids=evidence_ids,
        capability_ids=capability_ids,
    )
    resolution = FutureAttackPathTransitionResolution(
        resolution_id=resolution_id,
        client_id=proposal.client_id,
        proposal_sha256=proposal.proposal_sha256,
        impact_analysis_sha256=proposal.impact_analysis_sha256,
        change_node_id=item.change_node_id,
        subject_node_id=item.subject_node_id,
        review_action=item.review_action,
        effect_ids=item.effect_ids,
        current_attack_path_ids=item.current_attack_path_ids,
        classification=classification.value,
        run_id=context.run_id,
        engagement_id=context.engagement_id,
        evidence_ids=evidence_ids,
        capability_ids=capability_ids,
        resolution_sha256=digest,
    )
    _validate_resolution(
        resolution,
        proposal,
        context,
        state,
        require_recorded=False,
    )
    state.record_future_attack_path_transition_resolution(
        resolution.resolution_id,
        resolution.resolution_sha256,
        resolution.client_id,
        resolution.run_id,
    )
    _validate_resolution(
        resolution,
        proposal,
        context,
        state,
        require_recorded=True,
    )
    return resolution


def validate_future_attack_path_transition_resolution(
    resolution: FutureAttackPathTransitionResolution,
    proposal: FutureAttackPathTransitionProposal,
    context: RunContext,
    state: StateStore,
) -> None:
    """Revalidate a recorded resolution and all live evidence dependencies."""
    _validate_resolution(
        resolution,
        proposal,
        context,
        state,
        require_recorded=True,
    )
