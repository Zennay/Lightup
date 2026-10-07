"""Evidence-gated verification of future attack-path transition proposals.

ST4 verification only. This module consumes an immutable, validated transition
proposal and fresh isolated-lab evidence. It records a classification result but
never mutates a SecurityTwin or AttackPath and never emits a deployment verdict.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from hashlib import sha256
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


_ALLOWED_BY_ACTION = {
    "review_new_path_hypothesis": {
        AttackPathTransitionClassification.INTRODUCED,
        AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
    },
    "review_existing_paths_for_regression": {
        AttackPathTransitionClassification.WORSENED,
        AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
    },
    "review_existing_paths_for_improvement": {
        AttackPathTransitionClassification.IMPROVED,
        AttackPathTransitionClassification.REMOVED,
        AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
    },
    "review_improvement_without_path_claim": {
        AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
    },
    "manual_transition_review": set(AttackPathTransitionClassification),
    "no_transition_claim": {
        AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE,
    },
}

_EVIDENCE_KIND = "future-transition-verification"


@dataclass(frozen=True)
class FutureAttackPathTransitionResolution:
    resolution_id: str
    client_id: str
    proposal_sha256: str
    impact_analysis_sha256: str
    change_node_id: str
    subject_node_id: str
    classification: AttackPathTransitionClassification
    run_id: str
    evidence_ids: tuple[str, ...]
    capability_ids: tuple[str, ...]
    effect_ids: tuple[str, ...]
    current_attack_path_ids: tuple[str, ...]
    resolution_sha256: str
    attack_path_mutation_allowed: bool = False
    security_verdict: str = "not_evaluated"

    def as_dict(self) -> dict:
        return asdict(self)


def _require_identifier(name: str, value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{name} must be a canonical non-empty string")
    if len(value) > 256:
        raise ValueError(f"{name} exceeds 256 characters")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError(f"{name} contains control characters")
    return value


def _require_sha256(name: str, value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise ValueError(f"{name} must be canonical lowercase SHA-256")
    return value


def _require_exact_evidence_ids(values: object) -> tuple[str, ...]:
    if type(values) is not tuple:
        raise ValueError("evidence_ids must be an exact tuple")
    for value in values:
        if type(value) is not str:
            raise ValueError("evidence_ids must contain exact strings")
    return values


def _canonical_tuple(name: str, values: tuple[str, ...], *, allow_empty: bool) -> tuple[str, ...]:
    if not isinstance(values, tuple):
        raise ValueError(f"{name} must be an immutable tuple")
    if not values and not allow_empty:
        raise ValueError(f"{name} is required")
    for value in values:
        _require_identifier(name, value)
    canonical = tuple(sorted(values))
    if values != canonical:
        raise ValueError(f"{name} must be canonically sorted")
    if len(set(values)) != len(values):
        raise ValueError(f"{name} must be unique")
    return values


def _tuple_digest(values: tuple[str, ...]) -> str:
    encoded = json.dumps(
        list(values),
        sort_keys=False,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


def _resolution_identity(
    *,
    proposal_sha256: str,
    impact_analysis_sha256: str,
    item: FutureAttackPathTransitionProposalItem,
    classification: AttackPathTransitionClassification,
    run_id: str,
) -> str:
    payload = {
        "proposal_sha256": proposal_sha256,
        "impact_analysis_sha256": impact_analysis_sha256,
        "change_node_id": item.change_node_id,
        "subject_node_id": item.subject_node_id,
        "classification": classification.value,
        "run_id": run_id,
        "effect_ids": list(item.effect_ids),
        "current_attack_path_ids": list(item.current_attack_path_ids),
    }
    digest = sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()
    return f"transition-resolution:{digest[:24]}"


def _resolution_digest(
    *,
    resolution_id: str,
    client_id: str,
    proposal_sha256: str,
    impact_analysis_sha256: str,
    change_node_id: str,
    subject_node_id: str,
    classification: AttackPathTransitionClassification,
    run_id: str,
    evidence_ids: tuple[str, ...],
    capability_ids: tuple[str, ...],
    effect_ids: tuple[str, ...],
    current_attack_path_ids: tuple[str, ...],
) -> str:
    payload = {
        "resolution_id": resolution_id,
        "client_id": client_id,
        "proposal_sha256": proposal_sha256,
        "impact_analysis_sha256": impact_analysis_sha256,
        "change_node_id": change_node_id,
        "subject_node_id": subject_node_id,
        "classification": classification.value,
        "run_id": run_id,
        "evidence_ids": list(evidence_ids),
        "capability_ids": list(capability_ids),
        "effect_ids": list(effect_ids),
        "current_attack_path_ids": list(current_attack_path_ids),
        "attack_path_mutation_allowed": False,
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


def _proposal_item(
    proposal: FutureAttackPathTransitionProposal,
    change_node_id: str,
) -> FutureAttackPathTransitionProposalItem:
    matches = tuple(
        item for item in proposal.items if item.change_node_id == change_node_id
    )
    if len(matches) != 1:
        raise ValueError(
            "transition verification requires exactly one proposal item for the change"
        )
    return matches[0]


def _validate_action_classification(
    item: FutureAttackPathTransitionProposalItem,
    classification: AttackPathTransitionClassification,
) -> None:
    allowed = _ALLOWED_BY_ACTION.get(item.review_action)
    if allowed is None or classification not in allowed:
        raise ValueError(
            "transition classification is incompatible with proposal review action"
        )
    if (
        classification
        in {
            AttackPathTransitionClassification.REMOVED,
            AttackPathTransitionClassification.WORSENED,
            AttackPathTransitionClassification.IMPROVED,
        }
        and not item.current_attack_path_ids
    ):
        raise ValueError(
            "transition classification requires referenced current attack paths"
        )
    if (
        classification is AttackPathTransitionClassification.INTRODUCED
        and item.current_attack_path_ids
    ):
        raise ValueError(
            "introduced transition cannot reference an existing attack path"
        )


def future_attack_path_transition_evidence_contract(
    proposal: FutureAttackPathTransitionProposal,
    *,
    change_node_id: str,
    classification: AttackPathTransitionClassification,
    context: RunContext,
) -> dict[str, str]:
    """Return the exact metadata contract fresh lab evidence must carry."""
    validate_future_attack_path_transition_proposal(proposal)
    _require_identifier("change_node_id", change_node_id)
    if not isinstance(classification, AttackPathTransitionClassification):
        raise ValueError("transition classification is invalid")
    if not context.is_lab or context.mode is not AssessmentMode.LAB_AUTONOMOUS:
        raise PermissionError("transition verification evidence must come from a lab run")
    if context.client_id != proposal.client_id:
        raise ValueError("transition verification RunContext belongs to another client")

    item = _proposal_item(proposal, change_node_id)
    _validate_action_classification(item, classification)
    resolution_id = _resolution_identity(
        proposal_sha256=proposal.proposal_sha256,
        impact_analysis_sha256=proposal.impact_analysis_sha256,
        item=item,
        classification=classification,
        run_id=context.run_id,
    )
    return {
        "purpose": "future_attack_path_transition_verification",
        "resolution_id": resolution_id,
        "proposal_sha256": proposal.proposal_sha256,
        "impact_analysis_sha256": proposal.impact_analysis_sha256,
        "client_id": proposal.client_id,
        "engagement_id": context.engagement_id,
        "mode": context.mode.value,
        "is_lab": "true",
        "change_node_id": item.change_node_id,
        "subject_node_id": item.subject_node_id,
        "classification": classification.value,
        "effect_ids_sha256": _tuple_digest(item.effect_ids),
        "current_attack_path_ids_sha256": _tuple_digest(
            item.current_attack_path_ids
        ),
    }


def _validate_resolution_shape(
    proposal: FutureAttackPathTransitionProposal,
    item: FutureAttackPathTransitionProposalItem,
    resolution: FutureAttackPathTransitionResolution,
) -> None:
    for name, value in (
        ("resolution_id", resolution.resolution_id),
        ("client_id", resolution.client_id),
        ("change_node_id", resolution.change_node_id),
        ("subject_node_id", resolution.subject_node_id),
        ("run_id", resolution.run_id),
    ):
        _require_identifier(name, value)
    _require_sha256("proposal_sha256", resolution.proposal_sha256)
    _require_sha256("impact_analysis_sha256", resolution.impact_analysis_sha256)
    _require_sha256("resolution_sha256", resolution.resolution_sha256)

    if not isinstance(resolution.classification, AttackPathTransitionClassification):
        raise ValueError("transition classification is invalid")
    if resolution.attack_path_mutation_allowed:
        raise ValueError("transition resolution cannot allow attack-path mutation")
    if resolution.security_verdict != "not_evaluated":
        raise ValueError("transition resolution cannot claim a security verdict")

    _require_exact_evidence_ids(resolution.evidence_ids)
    _canonical_tuple("evidence_ids", resolution.evidence_ids, allow_empty=False)
    _canonical_tuple("capability_ids", resolution.capability_ids, allow_empty=False)
    _canonical_tuple("effect_ids", resolution.effect_ids, allow_empty=False)
    _canonical_tuple(
        "current_attack_path_ids",
        resolution.current_attack_path_ids,
        allow_empty=True,
    )

    if resolution.client_id != proposal.client_id:
        raise ValueError("transition resolution cannot cross tenants")
    if resolution.proposal_sha256 != proposal.proposal_sha256:
        raise ValueError("transition resolution proposal digest mismatch")
    if resolution.impact_analysis_sha256 != proposal.impact_analysis_sha256:
        raise ValueError("transition resolution analysis digest mismatch")
    if resolution.change_node_id != item.change_node_id:
        raise ValueError("transition resolution change identity mismatch")
    if resolution.subject_node_id != item.subject_node_id:
        raise ValueError("transition resolution subject identity mismatch")
    if resolution.effect_ids != item.effect_ids:
        raise ValueError("transition resolution effect lineage mismatch")
    if resolution.current_attack_path_ids != item.current_attack_path_ids:
        raise ValueError("transition resolution path lineage mismatch")

    _validate_action_classification(item, resolution.classification)

    expected_id = _resolution_identity(
        proposal_sha256=proposal.proposal_sha256,
        impact_analysis_sha256=proposal.impact_analysis_sha256,
        item=item,
        classification=resolution.classification,
        run_id=resolution.run_id,
    )
    if resolution.resolution_id != expected_id:
        raise ValueError("transition resolution uses a non-canonical stable id")

    expected_digest = _resolution_digest(
        resolution_id=resolution.resolution_id,
        client_id=resolution.client_id,
        proposal_sha256=resolution.proposal_sha256,
        impact_analysis_sha256=resolution.impact_analysis_sha256,
        change_node_id=resolution.change_node_id,
        subject_node_id=resolution.subject_node_id,
        classification=resolution.classification,
        run_id=resolution.run_id,
        evidence_ids=resolution.evidence_ids,
        capability_ids=resolution.capability_ids,
        effect_ids=resolution.effect_ids,
        current_attack_path_ids=resolution.current_attack_path_ids,
    )
    if resolution.resolution_sha256 != expected_digest:
        raise ValueError("transition resolution digest mismatch")


def validate_future_attack_path_transition_resolution(
    proposal: FutureAttackPathTransitionProposal,
    resolution: FutureAttackPathTransitionResolution,
    context: RunContext,
    state: StateStore,
) -> None:
    """Revalidate one resolution against live fresh lab evidence."""
    validate_future_attack_path_transition_proposal(proposal)
    item = _proposal_item(proposal, resolution.change_node_id)
    _validate_resolution_shape(proposal, item, resolution)

    if not context.is_lab or context.mode is not AssessmentMode.LAB_AUTONOMOUS:
        raise PermissionError("transition verification evidence must come from a lab run")
    if context.run_id != resolution.run_id:
        raise ValueError("transition resolution run_id does not match RunContext")
    if context.client_id != resolution.client_id:
        raise ValueError("transition resolution RunContext belongs to another client")

    prior_evidence_ids = {
        ref[len("evidence:") :]
        for ref in item.evidence_refs
        if ref.startswith("evidence:")
    }
    if prior_evidence_ids.intersection(resolution.evidence_ids):
        raise ValueError("transition resolution must use fresh evidence")

    expected_metadata = future_attack_path_transition_evidence_contract(
        proposal,
        change_node_id=item.change_node_id,
        classification=resolution.classification,
        context=context,
    )

    evidence = tuple(state.get_evidence(evidence_id) for evidence_id in resolution.evidence_ids)
    for record in evidence:
        if record.run_id != resolution.run_id:
            raise ValueError("transition verification evidence belongs to another run")
        if record.kind != _EVIDENCE_KIND:
            raise ValueError("transition verification evidence kind is non-canonical")
        metadata = dict(record.metadata)
        for key, value in expected_metadata.items():
            if metadata.get(key) != value:
                raise ValueError(
                    f"transition verification evidence metadata mismatch for {key}"
                )

    evidence_capabilities = {record.capability_id for record in evidence}
    if evidence_capabilities != set(resolution.capability_ids):
        raise ValueError(
            "transition resolution capability_ids must exactly match fresh evidence"
        )


def verify_future_attack_path_transition(
    proposal: FutureAttackPathTransitionProposal,
    *,
    change_node_id: str,
    classification: AttackPathTransitionClassification,
    run_id: str,
    evidence_ids: tuple[str, ...],
    capability_ids: tuple[str, ...],
    context: RunContext,
    state: StateStore,
) -> FutureAttackPathTransitionResolution:
    """Build and validate one immutable ST4 transition resolution."""
    validate_future_attack_path_transition_proposal(proposal)
    _require_identifier("change_node_id", change_node_id)
    _require_identifier("run_id", run_id)
    if not isinstance(classification, AttackPathTransitionClassification):
        raise ValueError("transition classification is invalid")

    item = _proposal_item(proposal, change_node_id)
    _validate_action_classification(item, classification)
    _require_exact_evidence_ids(evidence_ids)
    evidence_ids = tuple(sorted(evidence_ids))
    capability_ids = tuple(sorted(capability_ids))

    resolution_id = _resolution_identity(
        proposal_sha256=proposal.proposal_sha256,
        impact_analysis_sha256=proposal.impact_analysis_sha256,
        item=item,
        classification=classification,
        run_id=run_id,
    )
    digest = _resolution_digest(
        resolution_id=resolution_id,
        client_id=proposal.client_id,
        proposal_sha256=proposal.proposal_sha256,
        impact_analysis_sha256=proposal.impact_analysis_sha256,
        change_node_id=item.change_node_id,
        subject_node_id=item.subject_node_id,
        classification=classification,
        run_id=run_id,
        evidence_ids=evidence_ids,
        capability_ids=capability_ids,
        effect_ids=item.effect_ids,
        current_attack_path_ids=item.current_attack_path_ids,
    )
    resolution = FutureAttackPathTransitionResolution(
        resolution_id=resolution_id,
        client_id=proposal.client_id,
        proposal_sha256=proposal.proposal_sha256,
        impact_analysis_sha256=proposal.impact_analysis_sha256,
        change_node_id=item.change_node_id,
        subject_node_id=item.subject_node_id,
        classification=classification,
        run_id=run_id,
        evidence_ids=evidence_ids,
        capability_ids=capability_ids,
        effect_ids=item.effect_ids,
        current_attack_path_ids=item.current_attack_path_ids,
        resolution_sha256=digest,
    )
    validate_future_attack_path_transition_resolution(
        proposal,
        resolution,
        context,
        state,
    )
    return resolution
