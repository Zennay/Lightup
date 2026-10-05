"""Read-only impact analysis over verified Future Security graph state.

This layer consumes only canonical, evidence-backed subject/effect graph
resolution. It does not execute capabilities, infer exploitability, authorize
deployment, or mutate attack paths.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json

from .domain import AccessContext, TenantIsolationError
from .future_effects import RiskDirection, SecurityEffectKind, _fact_id as _effect_fact_id
from .future_subject_review import review_future_subjects
from .state import StateStore
from .twin import FactProvenance, SecurityTwin, TwinSnapshotKind


_EFFECT_PREDICATES = (
    "future_effect.kind",
    "future_effect.risk_direction",
    "future_effect.capability",
    "future_effect.resolution_id",
)


@dataclass(frozen=True)
class FutureAttackPathImpactItem:
    change_node_id: str
    subject_node_id: str
    graph_resolution_id: str
    subject_decision_id: str
    materialization_resolution_id: str
    effect_ids: tuple[str, ...]
    effect_kinds: tuple[str, ...]
    risk_directions: tuple[str, ...]
    capability_ids: tuple[str, ...]
    current_attack_path_ids: tuple[str, ...]
    impact: str
    evidence_refs: tuple[str, ...]


@dataclass(frozen=True)
class FutureAttackPathImpactReport:
    client_id: str
    current_twin_id: str
    current_twin_version: int
    twin_id: str
    twin_version: int
    changeset_id: str
    items: tuple[FutureAttackPathImpactItem, ...]
    analysis_complete: bool
    analysis_sha256: str
    future_semantics: str = "unresolved"
    security_verdict: str = "not_evaluated"

    def as_dict(self) -> dict:
        """Return a detached JSON-serializable representation."""
        return asdict(self)



def _analysis_digest(
    *,
    client_id: str,
    current_twin_id: str,
    current_twin_version: int,
    twin_id: str,
    twin_version: int,
    changeset_id: str,
    items: tuple[FutureAttackPathImpactItem, ...],
) -> str:
    """Bind the handoff report to its exact verified inputs and semantics."""
    payload = {
        "client_id": client_id,
        "current_twin_id": current_twin_id,
        "current_twin_version": current_twin_version,
        "twin_id": twin_id,
        "twin_version": twin_version,
        "changeset_id": changeset_id,
        "items": [asdict(item) for item in items],
        "analysis_complete": True,
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


def _classify_risk(directions: set[RiskDirection]) -> str:
    if RiskDirection.INCREASED in directions and RiskDirection.DECREASED in directions:
        return "mixed"
    if RiskDirection.INCREASED in directions:
        return "potential_regression"
    if RiskDirection.DECREASED in directions:
        return "potential_improvement"
    return "unchanged"


def _attack_paths_touching_subject(
    current: SecurityTwin,
    subject_node_id: str,
) -> tuple[str, ...]:
    path_ids = {
        path.path_id
        for path in current.attack_paths
        if any(
            step.source_id == subject_node_id or step.target_id == subject_node_id
            for step in path.steps
        )
    }
    return tuple(sorted(path_ids))


def analyze_future_attack_path_impact(
    future: SecurityTwin,
    state: StateStore,
    context: AccessContext,
    *,
    current: SecurityTwin,
    client_id: str | None = None,
) -> FutureAttackPathImpactReport:
    """Classify verified future effects against existing attack-path membership.

    This is deliberately conservative: normalized future effects can indicate a
    potential regression or improvement, but they do not prove a new exploit
    path, removal of an old one, or production safety.
    """

    selected_client = context.resolve_client(
        client_id, "analyze future attack-path impact"
    )
    if (
        current.client_id != selected_client
        or future.client_id != selected_client
    ):
        raise TenantIsolationError(
            "future attack-path impact current/future baselines cannot cross tenants"
        )

    current.validate()
    if current.kind is not TwinSnapshotKind.CURRENT:
        raise ValueError(
            "future attack-path impact analysis requires a current Security Twin baseline"
        )

    future_metadata = dict(future.metadata)
    if (
        future_metadata.get("future_base_twin_id") != current.twin_id
        or future_metadata.get("future_base_twin_version") != str(current.version)
        or future_metadata.get("future_base_twin_sha256") != current.stable_digest()
    ):
        raise ValueError(
            "future attack-path impact current baseline identity does not match future lineage"
        )

    if future.attack_paths != current.attack_paths:
        raise ValueError(
            "future attack-path impact requires attack paths unchanged from current baseline"
        )

    review = review_future_subjects(
        future,
        state,
        context,
        client_id=selected_client,
    )
    if not review.graph_resolution_complete:
        raise ValueError(
            "future attack-path impact analysis requires complete verified graph resolution"
        )
    if review.future_semantics != "unresolved":
        raise ValueError(
            "future attack-path impact analysis requires unresolved future semantics"
        )

    facts_by_id = {fact.fact_id: fact for fact in future.facts}
    current_nodes = {node.node_id: node for node in current.nodes}
    future_nodes = {node.node_id: node for node in future.nodes}
    items: list[FutureAttackPathImpactItem] = []

    for reviewed in review.items:
        if (
            reviewed.graph_resolution_status != "verified"
            or reviewed.graph_resolution_id is None
            or reviewed.verified_subject_id is None
            or not reviewed.resolved_effect_ids
        ):
            raise ValueError(
                "future attack-path impact analysis found incomplete verified graph state"
            )

        current_subject = current_nodes.get(reviewed.verified_subject_id)
        future_subject = future_nodes.get(reviewed.verified_subject_id)
        if current_subject is None:
            raise ValueError(
                "future attack-path impact verified subject is absent from current baseline"
            )
        if future_subject != current_subject:
            raise ValueError(
                "future attack-path impact verified subject drifted from current baseline"
            )

        graph_values = {
            fact.predicate: fact.value
            for fact in future.facts
            if fact.subject_id == reviewed.change_node_id
            and fact.predicate in {
                "future_graph.resolution_id",
                "future_graph.subject_decision_id",
                "future_graph.materialization_resolution_id",
            }
        }
        if graph_values.get("future_graph.resolution_id") != reviewed.graph_resolution_id:
            raise ValueError("future attack-path impact graph identity mismatch")
        if (
            reviewed.decision_id is None
            or graph_values.get("future_graph.subject_decision_id")
            != reviewed.decision_id
        ):
            raise ValueError("future attack-path impact subject decision mismatch")
        materialization_resolution_id = graph_values.get(
            "future_graph.materialization_resolution_id"
        )
        if not materialization_resolution_id:
            raise ValueError(
                "future attack-path impact is missing materialization identity"
            )

        effect_kinds: set[SecurityEffectKind] = set()
        directions: set[RiskDirection] = set()
        capabilities: set[str] = set()
        evidence_refs: set[str] = set(reviewed.evidence_refs)

        for effect_id in reviewed.resolved_effect_ids:
            effect_facts = {}
            for predicate in _EFFECT_PREDICATES:
                fact = facts_by_id.get(_effect_fact_id(effect_id, predicate))
                if fact is None:
                    raise ValueError(
                        f"future attack-path impact is missing effect {effect_id!r}"
                    )
                if (
                    fact.subject_id != reviewed.change_node_id
                    or fact.predicate != predicate
                    or fact.provenance is not FactProvenance.VERIFIED
                    or fact.confidence != 1.0
                ):
                    raise ValueError(
                        f"future attack-path impact effect {effect_id!r} is not canonical"
                    )
                effect_facts[predicate] = fact
                evidence_refs.update(fact.evidence_refs)

            try:
                effect_kinds.add(
                    SecurityEffectKind(effect_facts["future_effect.kind"].value)
                )
                directions.add(
                    RiskDirection(effect_facts["future_effect.risk_direction"].value)
                )
            except ValueError as exc:
                raise ValueError(
                    f"future attack-path impact effect {effect_id!r} has invalid semantics"
                ) from exc
            if (
                effect_facts["future_effect.resolution_id"].value
                != materialization_resolution_id
            ):
                raise ValueError(
                    f"future attack-path impact effect {effect_id!r} belongs "
                    "to another materialization"
                )
            capability = effect_facts["future_effect.capability"].value
            if not capability.strip():
                raise ValueError(
                    f"future attack-path impact effect {effect_id!r} has empty capability"
                )
            capabilities.add(capability)

        items.append(
            FutureAttackPathImpactItem(
                change_node_id=reviewed.change_node_id,
                subject_node_id=reviewed.verified_subject_id,
                graph_resolution_id=reviewed.graph_resolution_id,
                subject_decision_id=reviewed.decision_id,
                materialization_resolution_id=materialization_resolution_id,
                effect_ids=tuple(sorted(reviewed.resolved_effect_ids)),
                effect_kinds=tuple(sorted(item.value for item in effect_kinds)),
                risk_directions=tuple(sorted(item.value for item in directions)),
                capability_ids=tuple(sorted(capabilities)),
                current_attack_path_ids=_attack_paths_touching_subject(
                    current, reviewed.verified_subject_id
                ),
                impact=_classify_risk(directions),
                evidence_refs=tuple(sorted(evidence_refs)),
            )
        )

    if not items:
        raise ValueError(
            "future attack-path impact analysis requires at least one resolved change"
        )

    report_items = tuple(items)
    analysis_sha256 = _analysis_digest(
        client_id=review.client_id,
        current_twin_id=current.twin_id,
        current_twin_version=current.version,
        twin_id=review.twin_id,
        twin_version=review.twin_version,
        changeset_id=review.changeset_id,
        items=report_items,
    )
    return FutureAttackPathImpactReport(
        client_id=review.client_id,
        current_twin_id=current.twin_id,
        current_twin_version=current.version,
        twin_id=review.twin_id,
        twin_version=review.twin_version,
        changeset_id=review.changeset_id,
        items=report_items,
        analysis_complete=True,
        analysis_sha256=analysis_sha256,
    )
