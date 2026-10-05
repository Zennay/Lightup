"""Read-only attack-path transition proposals for Future Security.

This ST3 layer consumes a validated FutureAttackPathImpactReport and produces
only conservative review proposals. It never creates, deletes, rewrites, or
approves attack paths.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json

from .future_attack_path_analysis import (
    FutureAttackPathImpactItem,
    FutureAttackPathImpactReport,
    validate_future_attack_path_impact_report,
)


_ALLOWED_IMPACTS = {
    "potential_regression",
    "potential_improvement",
    "mixed",
    "unchanged",
}


@dataclass(frozen=True)
class FutureAttackPathTransitionProposalItem:
    change_node_id: str
    subject_node_id: str
    graph_resolution_id: str
    subject_decision_id: str
    materialization_resolution_id: str
    effect_ids: tuple[str, ...]
    current_attack_path_ids: tuple[str, ...]
    impact: str
    review_action: str
    evidence_refs: tuple[str, ...]


@dataclass(frozen=True)
class FutureAttackPathTransitionProposal:
    client_id: str
    current_twin_id: str
    current_twin_version: int
    twin_id: str
    twin_version: int
    changeset_id: str
    impact_analysis_sha256: str
    items: tuple[FutureAttackPathTransitionProposalItem, ...]
    proposal_complete: bool
    proposal_sha256: str
    attack_path_mutation_allowed: bool = False
    future_semantics: str = "unresolved"
    security_verdict: str = "not_evaluated"

    def as_dict(self) -> dict:
        """Return a detached JSON-serializable representation."""
        return asdict(self)


_PROPOSAL_KEYS = {
    "client_id",
    "current_twin_id",
    "current_twin_version",
    "twin_id",
    "twin_version",
    "changeset_id",
    "impact_analysis_sha256",
    "items",
    "proposal_complete",
    "proposal_sha256",
    "attack_path_mutation_allowed",
    "future_semantics",
    "security_verdict",
}

_PROPOSAL_ITEM_KEYS = {
    "change_node_id",
    "subject_node_id",
    "graph_resolution_id",
    "subject_decision_id",
    "materialization_resolution_id",
    "effect_ids",
    "current_attack_path_ids",
    "impact",
    "review_action",
    "evidence_refs",
}


def future_attack_path_transition_proposal_from_dict(
    payload: dict,
) -> FutureAttackPathTransitionProposal:
    """Parse an exact serialized proposal and rerun all fail-closed validation."""
    if not isinstance(payload, dict):
        raise ValueError("future attack-path transition proposal payload must be an object")
    if set(payload) != _PROPOSAL_KEYS:
        raise ValueError("future attack-path transition proposal payload schema mismatch")
    if not isinstance(payload["items"], list):
        raise ValueError("future attack-path transition proposal items must be a list")

    tuple_fields = {
        "effect_ids",
        "current_attack_path_ids",
        "evidence_refs",
    }
    scalar_fields = _PROPOSAL_ITEM_KEYS - tuple_fields
    items = []
    for raw_item in payload["items"]:
        if not isinstance(raw_item, dict) or set(raw_item) != _PROPOSAL_ITEM_KEYS:
            raise ValueError("future attack-path transition proposal item schema mismatch")
        if any(
            not isinstance(raw_item[field], str) or not raw_item[field]
            for field in scalar_fields
        ):
            raise ValueError(
                "future attack-path transition proposal item string field is invalid"
            )
        parsed = {}
        for field in tuple_fields:
            value = raw_item[field]
            if (
                not isinstance(value, list)
                or any(not isinstance(item, str) or not item for item in value)
            ):
                raise ValueError(
                    f"future attack-path transition proposal item {field} "
                    "must be a string list"
                )
            parsed[field] = tuple(value)
        items.append(
            FutureAttackPathTransitionProposalItem(
                change_node_id=raw_item["change_node_id"],
                subject_node_id=raw_item["subject_node_id"],
                graph_resolution_id=raw_item["graph_resolution_id"],
                subject_decision_id=raw_item["subject_decision_id"],
                materialization_resolution_id=raw_item[
                    "materialization_resolution_id"
                ],
                effect_ids=parsed["effect_ids"],
                current_attack_path_ids=parsed["current_attack_path_ids"],
                impact=raw_item["impact"],
                review_action=raw_item["review_action"],
                evidence_refs=parsed["evidence_refs"],
            )
        )

    string_fields = (
        "client_id",
        "current_twin_id",
        "twin_id",
        "changeset_id",
        "impact_analysis_sha256",
        "proposal_sha256",
        "future_semantics",
        "security_verdict",
    )
    if any(
        not isinstance(payload[field], str) or not payload[field]
        for field in string_fields
    ):
        raise ValueError(
            "future attack-path transition proposal string field is invalid"
        )
    for field in ("current_twin_version", "twin_version"):
        value = payload[field]
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ValueError(
                "future attack-path transition proposal version is invalid"
            )
    for field in ("proposal_complete", "attack_path_mutation_allowed"):
        if not isinstance(payload[field], bool):
            raise ValueError(
                f"future attack-path transition proposal {field} flag is invalid"
            )

    proposal = FutureAttackPathTransitionProposal(
        client_id=payload["client_id"],
        current_twin_id=payload["current_twin_id"],
        current_twin_version=payload["current_twin_version"],
        twin_id=payload["twin_id"],
        twin_version=payload["twin_version"],
        changeset_id=payload["changeset_id"],
        impact_analysis_sha256=payload["impact_analysis_sha256"],
        items=tuple(items),
        proposal_complete=payload["proposal_complete"],
        proposal_sha256=payload["proposal_sha256"],
        attack_path_mutation_allowed=payload["attack_path_mutation_allowed"],
        future_semantics=payload["future_semantics"],
        security_verdict=payload["security_verdict"],
    )
    validate_future_attack_path_transition_proposal(proposal)
    return proposal


def _canonical_tuple(values: tuple[str, ...], field: str) -> tuple[str, ...]:
    if not values:
        return ()
    if any(not isinstance(value, str) or not value.strip() for value in values):
        raise ValueError(f"transition proposal {field} contains an invalid identifier")
    canonical = tuple(sorted(values))
    if len(set(canonical)) != len(canonical):
        raise ValueError(f"transition proposal {field} contains duplicates")
    if canonical != values:
        raise ValueError(f"transition proposal {field} is not canonically ordered")
    return canonical


def _require_nonempty_string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"transition proposal {field} is invalid")
    return value


def _require_sha256(value: object, field: str) -> str:
    value = _require_nonempty_string(value, field)
    if len(value) != 64:
        raise ValueError(f"transition proposal {field} is not a SHA-256 digest")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ValueError(
            f"transition proposal {field} is not a SHA-256 digest"
        ) from exc
    return value


def _review_action(item: FutureAttackPathImpactItem) -> str:
    if item.impact == "potential_regression":
        if item.current_attack_path_ids:
            return "review_existing_paths_for_regression"
        return "review_new_path_hypothesis"
    if item.impact == "potential_improvement":
        if item.current_attack_path_ids:
            return "review_existing_paths_for_improvement"
        return "review_improvement_without_path_claim"
    if item.impact == "mixed":
        return "manual_transition_review"
    if item.impact == "unchanged":
        return "no_transition_claim"
    raise ValueError(f"unsupported future attack-path impact {item.impact!r}")


def _proposal_digest(
    *,
    client_id: str,
    current_twin_id: str,
    current_twin_version: int,
    twin_id: str,
    twin_version: int,
    changeset_id: str,
    impact_analysis_sha256: str,
    items: tuple[FutureAttackPathTransitionProposalItem, ...],
) -> str:
    payload = {
        "client_id": client_id,
        "current_twin_id": current_twin_id,
        "current_twin_version": current_twin_version,
        "twin_id": twin_id,
        "twin_version": twin_version,
        "changeset_id": changeset_id,
        "impact_analysis_sha256": impact_analysis_sha256,
        "items": [asdict(item) for item in items],
        "proposal_complete": True,
        "attack_path_mutation_allowed": False,
        "future_semantics": "unresolved",
        "security_verdict": "not_evaluated",
    }
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _validate_sha256(value: str, field: str) -> None:
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError(f"future attack-path transition proposal {field} is invalid")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ValueError(
            f"future attack-path transition proposal {field} is invalid"
        ) from exc


def validate_future_attack_path_transition_proposal(
    proposal: FutureAttackPathTransitionProposal,
) -> None:
    """Fail closed unless a proposal preserves the read-only ST3 boundary."""
    if not isinstance(proposal, FutureAttackPathTransitionProposal):
        raise ValueError("future attack-path transition proposal type is invalid")

    for field, value in (
        ("client_id", proposal.client_id),
        ("current_twin_id", proposal.current_twin_id),
        ("twin_id", proposal.twin_id),
        ("changeset_id", proposal.changeset_id),
    ):
        _require_nonempty_string(value, field)

    for field, value in (
        ("current_twin_version", proposal.current_twin_version),
        ("twin_version", proposal.twin_version),
    ):
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ValueError(f"transition proposal {field} is invalid")

    _require_sha256(proposal.impact_analysis_sha256, "impact_analysis_sha256")
    _require_sha256(proposal.proposal_sha256, "proposal_sha256")

    if not isinstance(proposal.proposal_complete, bool) or not proposal.proposal_complete:
        raise ValueError("future attack-path transition proposal is incomplete")
    if not isinstance(proposal.attack_path_mutation_allowed, bool):
        raise ValueError(
            "future attack-path transition proposal mutation flag is invalid"
        )
    if proposal.attack_path_mutation_allowed:
        raise ValueError("future attack-path transition proposal cannot allow mutation")
    if proposal.future_semantics != "unresolved":
        raise ValueError(
            "future attack-path transition proposal must preserve unresolved semantics"
        )
    if proposal.security_verdict != "not_evaluated":
        raise ValueError(
            "future attack-path transition proposal must not claim a security verdict"
        )
    if not isinstance(proposal.items, tuple) or not proposal.items:
        raise ValueError("future attack-path transition proposal requires items")

    canonical_items = tuple(
        sorted(
            proposal.items,
            key=lambda item: (item.change_node_id, item.subject_node_id),
        )
    )
    if canonical_items != proposal.items:
        raise ValueError(
            "future attack-path transition proposal items are not canonically ordered"
        )

    change_ids: set[str] = set()
    for item in proposal.items:
        if not isinstance(item, FutureAttackPathTransitionProposalItem):
            raise ValueError("future attack-path transition proposal item type is invalid")
        scalar_ids = (
            item.change_node_id,
            item.subject_node_id,
            item.graph_resolution_id,
            item.subject_decision_id,
            item.materialization_resolution_id,
        )
        if any(
            not isinstance(value, str) or not value.strip()
            for value in scalar_ids
        ):
            raise ValueError("future attack-path transition proposal identity is invalid")
        if item.change_node_id in change_ids:
            raise ValueError("future attack-path transition proposal duplicates a change")
        change_ids.add(item.change_node_id)
        if item.impact not in _ALLOWED_IMPACTS:
            raise ValueError("future attack-path transition proposal has invalid impact")
        if item.review_action != _review_action(
            FutureAttackPathImpactItem(
                change_node_id=item.change_node_id,
                subject_node_id=item.subject_node_id,
                graph_resolution_id=item.graph_resolution_id,
                subject_decision_id=item.subject_decision_id,
                materialization_resolution_id=item.materialization_resolution_id,
                effect_ids=item.effect_ids,
                effect_kinds=(),
                risk_directions=(),
                capability_ids=(),
                current_attack_path_ids=item.current_attack_path_ids,
                impact=item.impact,
                evidence_refs=item.evidence_refs,
            )
        ):
            raise ValueError(
                "future attack-path transition proposal review action is not canonical"
            )
        if not item.effect_ids:
            raise ValueError(
                "future attack-path transition proposal requires effect lineage"
            )
        if not item.evidence_refs:
            raise ValueError(
                "future attack-path transition proposal requires evidence lineage"
            )
        _canonical_tuple(item.effect_ids, "effect_ids")
        _canonical_tuple(item.current_attack_path_ids, "current_attack_path_ids")
        _canonical_tuple(item.evidence_refs, "evidence_refs")

    expected = _proposal_digest(
        client_id=proposal.client_id,
        current_twin_id=proposal.current_twin_id,
        current_twin_version=proposal.current_twin_version,
        twin_id=proposal.twin_id,
        twin_version=proposal.twin_version,
        changeset_id=proposal.changeset_id,
        impact_analysis_sha256=proposal.impact_analysis_sha256,
        items=proposal.items,
    )
    if proposal.proposal_sha256 != expected:
        raise ValueError("future attack-path transition proposal digest mismatch")


def propose_future_attack_path_transitions(
    report: FutureAttackPathImpactReport,
) -> FutureAttackPathTransitionProposal:
    """Create a read-only transition review proposal from verified impact state."""
    validate_future_attack_path_impact_report(report)

    items: list[FutureAttackPathTransitionProposalItem] = []
    seen_change_ids: set[str] = set()
    for impact in report.items:
        if impact.change_node_id in seen_change_ids:
            raise ValueError("future attack-path impact report duplicates a change")
        seen_change_ids.add(impact.change_node_id)
        if impact.impact not in _ALLOWED_IMPACTS:
            raise ValueError(f"unsupported future attack-path impact {impact.impact!r}")
        if not impact.effect_ids:
            raise ValueError("future attack-path impact item requires effect lineage")
        if not impact.evidence_refs:
            raise ValueError("future attack-path impact item requires evidence lineage")

        effect_ids = _canonical_tuple(impact.effect_ids, "effect_ids")
        path_ids = _canonical_tuple(
            impact.current_attack_path_ids,
            "current_attack_path_ids",
        )
        evidence_refs = _canonical_tuple(impact.evidence_refs, "evidence_refs")

        items.append(
            FutureAttackPathTransitionProposalItem(
                change_node_id=impact.change_node_id,
                subject_node_id=impact.subject_node_id,
                graph_resolution_id=impact.graph_resolution_id,
                subject_decision_id=impact.subject_decision_id,
                materialization_resolution_id=impact.materialization_resolution_id,
                effect_ids=effect_ids,
                current_attack_path_ids=path_ids,
                impact=impact.impact,
                review_action=_review_action(impact),
                evidence_refs=evidence_refs,
            )
        )

    proposal_items = tuple(
        sorted(items, key=lambda item: (item.change_node_id, item.subject_node_id))
    )
    proposal_sha256 = _proposal_digest(
        client_id=report.client_id,
        current_twin_id=report.current_twin_id,
        current_twin_version=report.current_twin_version,
        twin_id=report.twin_id,
        twin_version=report.twin_version,
        changeset_id=report.changeset_id,
        impact_analysis_sha256=report.analysis_sha256,
        items=proposal_items,
    )
    proposal = FutureAttackPathTransitionProposal(
        client_id=report.client_id,
        current_twin_id=report.current_twin_id,
        current_twin_version=report.current_twin_version,
        twin_id=report.twin_id,
        twin_version=report.twin_version,
        changeset_id=report.changeset_id,
        impact_analysis_sha256=report.analysis_sha256,
        items=proposal_items,
        proposal_complete=True,
        proposal_sha256=proposal_sha256,
    )
    validate_future_attack_path_transition_proposal(proposal)
    return proposal
