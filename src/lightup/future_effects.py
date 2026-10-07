"""Evidence-backed future security effect observations.

This ST3 layer records bounded, verified security effects on an existing future
CHANGE node after isolated materialization has already been confirmed. It never
creates subject bindings, relationships, attack-path steps, authorization, or
target interaction.

An effect proves only that the cited lab evidence supports the normalized effect
for the future change. Graph semantics remain unresolved until a later stage
explicitly binds verified effects to verified subjects.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from hashlib import sha256

from .future_materialization import (
    FutureMaterializationResolution,
    MaterializationOutcome,
    _resolution_facts,
)
from .twin import (
    FactProvenance,
    SecurityTwin,
    TwinFact,
    TwinNodeKind,
    TwinSnapshotKind,
)


class SecurityEffectKind(str, Enum):
    ATTACK_SURFACE_ADDED = "attack_surface_added"
    ATTACK_SURFACE_REMOVED = "attack_surface_removed"
    CONTROL_WEAKENED = "control_weakened"
    CONTROL_STRENGTHENED = "control_strengthened"
    ACCESS_EXPANDED = "access_expanded"
    ACCESS_RESTRICTED = "access_restricted"


class RiskDirection(str, Enum):
    INCREASED = "increased"
    DECREASED = "decreased"
    UNCHANGED = "unchanged"


@dataclass(frozen=True)
class FutureSecurityEffect:
    effect_id: str
    resolution_id: str
    client_id: str
    changeset_id: str
    change_node_id: str
    capability_id: str
    kind: SecurityEffectKind
    risk_direction: RiskDirection
    evidence_ids: tuple[str, ...]

    def validate(self) -> None:
        for name, value in (
            ("effect_id", self.effect_id),
            ("resolution_id", self.resolution_id),
            ("client_id", self.client_id),
            ("changeset_id", self.changeset_id),
            ("change_node_id", self.change_node_id),
            ("capability_id", self.capability_id),
        ):
            if not value.strip():
                raise ValueError(f"{name} is required")
        if not self.change_node_id.startswith("change:"):
            raise ValueError("future security effect must target a change node")
        if type(self.evidence_ids) is not tuple:
            raise ValueError("future security effect evidence_ids must be an exact tuple")
        if not self.evidence_ids:
            raise ValueError("future security effect requires evidence")
        seen_evidence_ids: set[str] = set()
        for evidence_id in self.evidence_ids:
            if type(evidence_id) is not str or not evidence_id.strip():
                raise ValueError(
                    "future security effect evidence_ids must contain exact non-blank strings"
                )
            if evidence_id in seen_evidence_ids:
                raise ValueError("future security effect evidence_ids must be unique")
            seen_evidence_ids.add(evidence_id)


def _fact_id(effect_id: str, predicate: str) -> str:
    payload = f"{effect_id}\x1f{predicate}".encode("utf-8")
    return f"future-effect:{sha256(payload).hexdigest()[:24]}"


def _effect_facts(effect: FutureSecurityEffect) -> tuple[TwinFact, ...]:
    evidence_refs = tuple(f"evidence:{item}" for item in effect.evidence_ids)
    values = (
        ("future_effect.kind", effect.kind.value),
        ("future_effect.risk_direction", effect.risk_direction.value),
        ("future_effect.capability", effect.capability_id),
        ("future_effect.resolution_id", effect.resolution_id),
    )
    return tuple(
        TwinFact(
            fact_id=_fact_id(effect.effect_id, predicate),
            subject_id=effect.change_node_id,
            predicate=predicate,
            value=value,
            provenance=FactProvenance.VERIFIED,
            confidence=1.0,
            evidence_refs=evidence_refs,
        )
        for predicate, value in values
    )


def _assert_confirmed_materialization(
    future: SecurityTwin,
    resolution: FutureMaterializationResolution,
) -> None:
    if resolution.outcome is not MaterializationOutcome.CONFIRMED:
        raise ValueError("future security effects require confirmed materialization")

    expected_facts = _resolution_facts(resolution)
    existing_by_id = {fact.fact_id: fact for fact in future.facts}
    if any(existing_by_id.get(fact.fact_id) != fact for fact in expected_facts):
        raise ValueError(
            "the exact confirmed materialization resolution must be applied to "
            "the future twin before security effects can be recorded"
        )


def apply_future_security_effects(
    future: SecurityTwin,
    resolution: FutureMaterializationResolution,
    effects: tuple[FutureSecurityEffect, ...],
) -> SecurityTwin:
    """Record verified normalized effects without resolving graph semantics."""

    future.validate()
    resolution.validate()

    if future.kind is not TwinSnapshotKind.FUTURE:
        raise ValueError("future security effects require a future Security Twin")
    if not effects:
        raise ValueError("at least one future security effect is required")
    if len({effect.effect_id for effect in effects}) != len(effects):
        raise ValueError("future security effect IDs must be unique")

    if future.client_id != resolution.client_id:
        raise ValueError("future security effect resolution cannot cross tenants")

    change_node = next(
        (node for node in future.nodes if node.node_id == resolution.change_node_id),
        None,
    )
    if change_node is None or change_node.kind is not TwinNodeKind.CHANGE:
        raise KeyError(f"unknown future change node {resolution.change_node_id!r}")
    if dict(change_node.attributes).get("changeset_id") != resolution.changeset_id:
        raise ValueError("resolution changeset_id does not match the change node")

    _assert_confirmed_materialization(future, resolution)

    allowed_evidence = set(resolution.evidence_ids)
    allowed_capabilities = set(resolution.capability_ids)

    for effect in effects:
        effect.validate()
        if effect.resolution_id != resolution.resolution_id:
            raise ValueError("future security effect resolution_id mismatch")
        if effect.client_id != resolution.client_id:
            raise ValueError("future security effect cannot cross tenants")
        if effect.changeset_id != resolution.changeset_id:
            raise ValueError("future security effect changeset_id mismatch")
        if effect.change_node_id != resolution.change_node_id:
            raise ValueError("future security effect change_node_id mismatch")
        if effect.capability_id not in allowed_capabilities:
            raise ValueError(
                "future security effect capability was not covered by materialization"
            )
        if not set(effect.evidence_ids).issubset(allowed_evidence):
            raise ValueError(
                "future security effect evidence must come from materialization evidence"
            )
    existing_by_id = {fact.fact_id: fact for fact in future.facts}
    new_facts: list[TwinFact] = []
    seen_effect_ids: set[str] = set()

    for effect in effects:
        facts = _effect_facts(effect)
        collisions = [fact for fact in facts if fact.fact_id in existing_by_id]
        if collisions:
            if len(collisions) != len(facts) or any(
                existing_by_id[fact.fact_id] != fact for fact in facts
            ):
                raise ValueError(
                    f"future security effect {effect.effect_id!r} collides with "
                    "existing twin facts"
                )
            seen_effect_ids.add(effect.effect_id)
            continue
        new_facts.extend(facts)

    if not new_facts:
        return future

    metadata = dict(future.metadata)
    prior_count = int(metadata.get("future_security_effect_count", "0"))
    new_effect_count = len(effects) - len(seen_effect_ids)
    metadata.update(
        {
            "future_security_effects": "evidence_recorded",
            "future_security_effect_count": str(prior_count + new_effect_count),
            "future_semantics": "unresolved",
        }
    )

    snapshot = replace(
        future,
        version=future.version + 1,
        parent_twin_id=future.twin_id,
        parent_version=future.version,
        facts=future.facts + tuple(new_facts),
        metadata=tuple(sorted(metadata.items())),
    )
    snapshot.validate()

    if snapshot.relationships != future.relationships:
        raise AssertionError("future security effects must not mutate relationships")
    if snapshot.attack_paths != future.attack_paths:
        raise AssertionError("future security effects must not mutate attack paths")
    return snapshot
