"""Verified subject/effect graph resolution for Future Security Twins.

This ST3 layer composes an already verified subject decision with already
verified future security effects from one confirmed isolated materialization.
It records graph-resolution state only. It never executes capabilities, widens
authorization, or mutates attack paths.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from hashlib import sha256

from .future_effects import (
    RiskDirection,
    SecurityEffectKind,
    _fact_id as _effect_fact_id,
)
from .future_materialization import (
    FutureMaterializationResolution,
    MaterializationOutcome,
    _resolution_facts as _materialization_facts,
)
from .future_subject_resolution import validate_future_subject_snapshot
from .state import StateStore
from .twin import (
    FactProvenance,
    SecurityTwin,
    TwinFact,
    TwinNodeKind,
    TwinRelationship,
    TwinSnapshotKind,
)


_MAX_IDENTIFIER_LENGTH = 256
_MAX_EFFECT_IDS = 32
_FIXED_GRAPH_PREDICATES = (
    "future_graph.resolution_id",
    "future_graph.subject_decision_id",
    "future_graph.subject_node_id",
    "future_graph.materialization_resolution_id",
    "future_graph.effect_count",
)
_EFFECT_PREDICATES = (
    "future_effect.kind",
    "future_effect.risk_direction",
    "future_effect.capability",
    "future_effect.resolution_id",
)


def _bounded(name: str, value: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} is required")
    if value != value.strip():
        raise ValueError(f"{name} must not contain surrounding whitespace")
    if len(value) > _MAX_IDENTIFIER_LENGTH:
        raise ValueError(f"{name} exceeds {_MAX_IDENTIFIER_LENGTH} characters")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError(f"{name} contains control characters")


def _stable_id(prefix: str, *parts: str) -> str:
    payload = "\x1f".join(parts).encode("utf-8")
    return f"{prefix}:{sha256(payload).hexdigest()[:24]}"


def _canonical_count(name: str, value: str) -> int:
    if not isinstance(value, str) or not value or not value.isascii() or not value.isdigit():
        raise ValueError(f"{name} must be a canonical non-negative decimal")
    if len(value) > 1 and value.startswith("0"):
        raise ValueError(f"{name} must not contain leading zeroes")
    return int(value)


def _validate_evidence_refs(name: str, refs: tuple[str, ...]) -> None:
    if not refs or len(set(refs)) != len(refs):
        raise ValueError(f"{name} requires unique evidence refs")
    for ref in refs:
        if not ref.startswith("evidence:"):
            raise ValueError(f"{name} contains a non-canonical evidence ref")
        _bounded(f"{name} evidence ref", ref)


@dataclass(frozen=True)
class FutureGraphResolution:
    graph_resolution_id: str
    client_id: str
    changeset_id: str
    change_node_id: str
    subject_node_id: str
    subject_decision_id: str
    materialization_resolution_id: str
    effect_ids: tuple[str, ...]

    def validate(self) -> None:
        for name, value in (
            ("graph_resolution_id", self.graph_resolution_id),
            ("client_id", self.client_id),
            ("changeset_id", self.changeset_id),
            ("change_node_id", self.change_node_id),
            ("subject_node_id", self.subject_node_id),
            ("subject_decision_id", self.subject_decision_id),
            ("materialization_resolution_id", self.materialization_resolution_id),
        ):
            _bounded(name, value)
        if not self.change_node_id.startswith("change:"):
            raise ValueError("graph resolution must target a future change node")
        if not self.effect_ids:
            raise ValueError("graph resolution requires at least one future effect")
        if len(self.effect_ids) > _MAX_EFFECT_IDS:
            raise ValueError(
                f"graph resolution accepts at most {_MAX_EFFECT_IDS} effect ids"
            )
        if len(set(self.effect_ids)) != len(self.effect_ids):
            raise ValueError("graph resolution effect_ids must be unique")
        for effect_id in self.effect_ids:
            _bounded("graph resolution effect_id", effect_id)


def _graph_facts(
    resolution: FutureGraphResolution,
    evidence_refs: tuple[str, ...],
) -> tuple[TwinFact, ...]:
    values = (
        ("future_graph.resolution_id", resolution.graph_resolution_id),
        ("future_graph.subject_decision_id", resolution.subject_decision_id),
        ("future_graph.subject_node_id", resolution.subject_node_id),
        (
            "future_graph.materialization_resolution_id",
            resolution.materialization_resolution_id,
        ),
        ("future_graph.effect_count", str(len(resolution.effect_ids))),
    ) + tuple(
        ("future_graph.effect_id", effect_id)
        for effect_id in sorted(resolution.effect_ids)
    )
    return tuple(
        TwinFact(
            fact_id=_stable_id(
                "future-graph", resolution.graph_resolution_id, predicate, value
            ),
            subject_id=resolution.change_node_id,
            predicate=predicate,
            value=value,
            provenance=FactProvenance.VERIFIED,
            confidence=1.0,
            evidence_refs=evidence_refs,
        )
        for predicate, value in values
    )


def _graph_relationship(
    resolution: FutureGraphResolution,
    evidence_refs: tuple[str, ...],
) -> TwinRelationship:
    return TwinRelationship(
        relationship_id=_stable_id(
            "future-graph-rel",
            resolution.graph_resolution_id,
            resolution.change_node_id,
            resolution.subject_node_id,
        ),
        source_id=resolution.change_node_id,
        target_id=resolution.subject_node_id,
        relation="verified_effects_on_subject",
        provenance=FactProvenance.VERIFIED,
        confidence=1.0,
        evidence_refs=evidence_refs,
    )


def validate_future_graph_snapshot(future: SecurityTwin) -> None:
    """Reject partial or forged persisted graph-resolution state."""

    metadata = dict(future.metadata)
    if len(metadata) != len(future.metadata):
        raise ValueError("future graph resolution requires canonical metadata keys")
    graph_facts = tuple(
        fact for fact in future.facts if fact.predicate.startswith("future_graph.")
    )
    graph_relationships = tuple(
        relationship
        for relationship in future.relationships
        if relationship.relation == "verified_effects_on_subject"
    )
    recorded_count = _canonical_count(
        "future graph resolution metadata count",
        metadata.get("future_graph_resolution_count", "0"),
    )
    if recorded_count != len(graph_relationships):
        raise ValueError(
            "future graph resolution metadata count does not match verified graph state"
        )
    marker = metadata.get("future_graph_resolution")
    if recorded_count == 0:
        if marker is not None or graph_facts:
            raise ValueError("unresolved graph state cannot claim resolution data")
        return
    if marker != "evidence_recorded":
        raise ValueError("verified graph state requires canonical resolution metadata")

    facts_by_change: dict[str, list[TwinFact]] = {}
    relationships_by_change: dict[str, list[TwinRelationship]] = {}
    for fact in graph_facts:
        if fact.provenance is not FactProvenance.VERIFIED or fact.confidence != 1.0:
            raise ValueError("future graph facts must remain verified at confidence 1")
        _validate_evidence_refs("future graph fact", fact.evidence_refs)
        facts_by_change.setdefault(fact.subject_id, []).append(fact)
    for relationship in graph_relationships:
        if (
            relationship.provenance is not FactProvenance.VERIFIED
            or relationship.confidence != 1.0
        ):
            raise ValueError(
                "future graph relationships must remain verified at confidence 1"
            )
        _validate_evidence_refs(
            "future graph relationship", relationship.evidence_refs
        )
        relationships_by_change.setdefault(
            relationship.source_id, []
        ).append(relationship)

    if set(facts_by_change) != set(relationships_by_change):
        raise ValueError("future graph resolution found partial verified graph state")

    for change_id, facts in facts_by_change.items():
        relationships = relationships_by_change[change_id]
        if len(relationships) != 1:
            raise ValueError(
                "future graph resolution requires exactly one graph relationship "
                "per resolved change"
            )
        fixed: dict[str, TwinFact] = {}
        effect_facts: list[TwinFact] = []
        for fact in facts:
            if fact.predicate == "future_graph.effect_id":
                effect_facts.append(fact)
            elif fact.predicate in _FIXED_GRAPH_PREDICATES:
                if fact.predicate in fixed:
                    raise ValueError("future graph resolution has duplicate fixed facts")
                fixed[fact.predicate] = fact
            else:
                raise ValueError("future graph resolution found an unknown predicate")
        if set(fixed) != set(_FIXED_GRAPH_PREDICATES) or not effect_facts:
            raise ValueError("future graph resolution requires one canonical fact set")

        relationship = relationships[0]
        graph_id = fixed["future_graph.resolution_id"].value
        _bounded("verified graph resolution_id", graph_id)
        if relationship.target_id != fixed["future_graph.subject_node_id"].value:
            raise ValueError("future graph fact/relationship targets disagree")
        if any(fact.evidence_refs != relationship.evidence_refs for fact in facts):
            raise ValueError("future graph evidence lineage is inconsistent")

        effect_ids = tuple(fact.value for fact in effect_facts)
        if len(set(effect_ids)) != len(effect_ids):
            raise ValueError("future graph resolution contains duplicate effect ids")
        effect_count = _canonical_count(
            "future graph effect count",
            fixed["future_graph.effect_count"].value,
        )
        if effect_count != len(effect_ids):
            raise ValueError("future graph effect count does not match graph facts")

        for fact in facts:
            if fact.fact_id != _stable_id(
                "future-graph", graph_id, fact.predicate, fact.value
            ):
                raise ValueError("future graph fact uses a non-canonical stable id")
        if relationship.relationship_id != _stable_id(
            "future-graph-rel",
            graph_id,
            change_id,
            relationship.target_id,
        ):
            raise ValueError(
                "future graph relationship uses a non-canonical stable id"
            )


def _validate_materialization(
    future: SecurityTwin,
    resolution: FutureGraphResolution,
    materialization: FutureMaterializationResolution,
    state: StateStore,
) -> None:
    materialization.validate()
    if materialization.resolution_id != resolution.materialization_resolution_id:
        raise ValueError("graph resolution materialization_resolution_id mismatch")
    if materialization.client_id != resolution.client_id:
        raise ValueError("graph resolution materialization cannot cross tenants")
    if materialization.changeset_id != resolution.changeset_id:
        raise ValueError("graph resolution materialization changeset mismatch")
    if materialization.change_node_id != resolution.change_node_id:
        raise ValueError("graph resolution materialization change mismatch")
    if materialization.outcome is not MaterializationOutcome.CONFIRMED:
        raise ValueError("graph resolution requires confirmed materialization")

    existing_by_id = {fact.fact_id: fact for fact in future.facts}
    if any(
        existing_by_id.get(fact.fact_id) != fact
        for fact in _materialization_facts(materialization)
    ):
        raise ValueError(
            "graph resolution requires the exact applied materialization resolution"
        )
    evidence = tuple(
        state.get_evidence(evidence_id)
        for evidence_id in materialization.evidence_ids
    )
    if any(item.run_id != materialization.run_id for item in evidence):
        raise ValueError("graph resolution materialization evidence is stale")
    for item in evidence:
        evidence_context = dict(item.metadata)
        if evidence_context.get("client_id") != resolution.client_id:
            raise ValueError(
                "graph resolution materialization evidence belongs to another client"
            )
        if evidence_context.get("mode") != "lab_autonomous":
            raise ValueError(
                "graph resolution materialization evidence is not lab-autonomous"
            )
        if evidence_context.get("is_lab") != "true":
            raise PermissionError(
                "graph resolution materialization evidence is not lab-bound"
            )
    if {item.capability_id for item in evidence} != set(
        materialization.capability_ids
    ):
        raise ValueError(
            "graph resolution materialization capabilities no longer match evidence"
        )


def _effect_evidence_refs(
    future: SecurityTwin,
    resolution: FutureGraphResolution,
    materialization: FutureMaterializationResolution,
    state: StateStore,
) -> tuple[str, ...]:
    facts_by_id = {fact.fact_id: fact for fact in future.facts}
    allowed_refs = {
        f"evidence:{evidence_id}" for evidence_id in materialization.evidence_ids
    }
    allowed_capabilities = set(materialization.capability_ids)
    consumed_refs: set[str] = set()

    for effect_id in resolution.effect_ids:
        effect_facts: dict[str, TwinFact] = {}
        for predicate in _EFFECT_PREDICATES:
            fact_id = _effect_fact_id(effect_id, predicate)
            fact = facts_by_id.get(fact_id)
            if fact is None:
                raise ValueError(
                    f"graph resolution references missing future effect {effect_id!r}"
                )
            if (
                fact.subject_id != resolution.change_node_id
                or fact.predicate != predicate
                or fact.provenance is not FactProvenance.VERIFIED
                or fact.confidence != 1.0
            ):
                raise ValueError(
                    f"future effect {effect_id!r} is not canonical verified state"
                )
            effect_facts[predicate] = fact

        refs = effect_facts["future_effect.kind"].evidence_refs
        if any(fact.evidence_refs != refs for fact in effect_facts.values()):
            raise ValueError(
                f"future effect {effect_id!r} has inconsistent evidence lineage"
            )
        _validate_evidence_refs(f"future effect {effect_id}", refs)
        if not set(refs).issubset(allowed_refs):
            raise ValueError(
                f"future effect {effect_id!r} evidence is outside materialization"
            )
        if (
            effect_facts["future_effect.resolution_id"].value
            != materialization.resolution_id
        ):
            raise ValueError(
                f"future effect {effect_id!r} belongs to another materialization"
            )
        if effect_facts["future_effect.capability"].value not in allowed_capabilities:
            raise ValueError(
                f"future effect {effect_id!r} capability was not materialized"
            )
        try:
            SecurityEffectKind(effect_facts["future_effect.kind"].value)
            RiskDirection(effect_facts["future_effect.risk_direction"].value)
        except ValueError as exc:
            raise ValueError(
                f"future effect {effect_id!r} contains non-canonical semantics"
            ) from exc

        for ref in refs:
            evidence_id = ref[len("evidence:"):]
            item = state.get_evidence(evidence_id)
            if item.run_id != materialization.run_id:
                raise ValueError(
                    f"future effect {effect_id!r} evidence belongs to another run"
                )
            evidence_context = dict(item.metadata)
            if evidence_context.get("client_id") != resolution.client_id:
                raise ValueError(
                    f"future effect {effect_id!r} evidence belongs to another client"
                )
            if evidence_context.get("mode") != "lab_autonomous":
                raise ValueError(
                    f"future effect {effect_id!r} evidence is not lab-autonomous"
                )
            if evidence_context.get("is_lab") != "true":
                raise PermissionError(
                    f"future effect {effect_id!r} evidence is not lab-bound"
                )
        consumed_refs.update(refs)
    return tuple(sorted(consumed_refs))


def apply_future_graph_resolution(
    future: SecurityTwin,
    resolution: FutureGraphResolution,
    materialization: FutureMaterializationResolution,
    state: StateStore,
) -> SecurityTwin:
    """Bind verified future effects to one explicitly verified subject."""

    resolution.validate()
    future.validate()
    if future.kind is not TwinSnapshotKind.FUTURE:
        raise ValueError("graph resolution requires a future Security Twin")
    if future.client_id != resolution.client_id:
        raise ValueError("graph resolution cannot cross tenants")

    metadata = dict(future.metadata)
    if len(metadata) != len(future.metadata):
        raise ValueError("graph resolution requires canonical future metadata keys")
    if metadata.get("changeset_id") != resolution.changeset_id:
        raise ValueError("graph resolution changeset_id mismatch")
    if metadata.get("future_semantics") != "unresolved":
        raise ValueError("graph resolution requires explicit unresolved future semantics")

    validate_future_subject_snapshot(
        future,
        state,
        client_id=resolution.client_id,
        changeset_id=resolution.changeset_id,
    )
    validate_future_graph_snapshot(future)

    nodes = {node.node_id: node for node in future.nodes}
    change = nodes.get(resolution.change_node_id)
    if change is None or change.kind is not TwinNodeKind.CHANGE:
        raise KeyError(f"unknown future change node {resolution.change_node_id!r}")
    if resolution.subject_node_id not in nodes:
        raise KeyError(f"unknown graph subject node {resolution.subject_node_id!r}")

    subject_links = tuple(
        relationship
        for relationship in future.relationships
        if relationship.source_id == resolution.change_node_id
        and relationship.relation == "verified_affects_subject"
        and relationship.provenance is FactProvenance.VERIFIED
    )
    if len(subject_links) != 1:
        raise ValueError(
            "graph resolution requires exactly one explicit verified subject decision"
        )
    subject_link = subject_links[0]
    if subject_link.target_id != resolution.subject_node_id:
        raise ValueError("graph resolution subject does not match verified subject")

    subject_facts = {
        fact.predicate: fact
        for fact in future.facts
        if fact.subject_id == resolution.change_node_id
        and fact.predicate.startswith("future_subject.")
    }
    if (
        subject_facts.get("future_subject.decision_id") is None
        or subject_facts["future_subject.decision_id"].value
        != resolution.subject_decision_id
    ):
        raise ValueError("graph resolution subject_decision_id mismatch")
    if (
        subject_facts.get("future_subject.node_id") is None
        or subject_facts["future_subject.node_id"].value
        != resolution.subject_node_id
    ):
        raise ValueError("graph resolution subject identity mismatch")

    _validate_materialization(future, resolution, materialization, state)
    effect_refs = _effect_evidence_refs(
        future, resolution, materialization, state
    )
    evidence_refs = tuple(sorted(set(subject_link.evidence_refs) | set(effect_refs)))
    _validate_evidence_refs("future graph resolution", evidence_refs)

    facts = _graph_facts(resolution, evidence_refs)
    relationship = _graph_relationship(resolution, evidence_refs)
    existing_facts = {fact.fact_id: fact for fact in future.facts}
    existing_relationships = {
        item.relationship_id: item for item in future.relationships
    }
    triple_collision = next(
        (
            item
            for item in future.relationships
            if item.source_id == relationship.source_id
            and item.target_id == relationship.target_id
            and item.relation == relationship.relation
        ),
        None,
    )
    fact_collisions = [fact for fact in facts if fact.fact_id in existing_facts]
    relationship_collision = existing_relationships.get(
        relationship.relationship_id
    )

    if fact_collisions or relationship_collision is not None or triple_collision is not None:
        facts_match = (
            len(fact_collisions) == len(facts)
            and all(existing_facts[fact.fact_id] == fact for fact in facts)
        )
        relationship_matches = (
            relationship_collision == relationship
            and triple_collision == relationship
        )
        if facts_match and relationship_matches:
            if metadata.get("future_graph_resolution") != "evidence_recorded":
                raise ValueError(
                    "idempotent graph-resolution replay requires canonical metadata"
                )
            count = _canonical_count(
                "idempotent graph-resolution replay count",
                metadata.get("future_graph_resolution_count", ""),
            )
            graph_relationship_count = sum(
                1
                for item in future.relationships
                if item.relation == "verified_effects_on_subject"
                and item.provenance is FactProvenance.VERIFIED
            )
            if count != graph_relationship_count:
                raise ValueError(
                    "idempotent graph-resolution replay count is inconsistent"
                )
            if metadata.get("future_semantics") != "unresolved":
                raise ValueError(
                    "idempotent graph-resolution replay requires unresolved semantics"
                )
            return future
        raise ValueError("graph resolution collides with existing twin data")

    prior_count = _canonical_count(
        "future graph resolution prior count",
        metadata.get("future_graph_resolution_count", "0"),
    )
    metadata.update(
        {
            "future_graph_resolution": "evidence_recorded",
            "future_graph_resolution_count": str(prior_count + 1),
            "future_semantics": "unresolved",
        }
    )
    snapshot = replace(
        future,
        version=future.version + 1,
        parent_twin_id=future.twin_id,
        parent_version=future.version,
        facts=future.facts + facts,
        relationships=future.relationships + (relationship,),
        metadata=tuple(sorted(metadata.items())),
    )
    snapshot.validate()
    validate_future_graph_snapshot(snapshot)
    if snapshot.attack_paths != future.attack_paths:
        raise AssertionError("future graph resolution must not mutate attack paths")
    return snapshot
