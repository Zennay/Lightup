"""Evidence-gated future-state materialization records.

ST3 foundation only. This module does not execute capabilities or create attack
paths. It can attach an isolated-lab materialization outcome to an existing
future-state CHANGE node only when every referenced evidence record belongs to
the same immutable lab RunContext.

The original change signal remains inferred. A verified materialization outcome
means only that the isolated run produced that outcome; it does not by itself
prove production reachability, authorization, or a future attack path.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from hashlib import sha256

from .ai.orchestration import RunContext
from .engagements import AssessmentMode
from .state import StateStore
from .twin import (
    FactProvenance,
    SecurityTwin,
    TwinFact,
    TwinNodeKind,
    TwinSnapshotKind,
)


class MaterializationOutcome(str, Enum):
    CONFIRMED = "confirmed"
    NOT_OBSERVED = "not_observed"
    INCONCLUSIVE = "inconclusive"


class EnvironmentEquivalence(str, Enum):
    REPRESENTATIVE = "representative"
    PARTIAL = "partial"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class FutureMaterializationResolution:
    resolution_id: str
    client_id: str
    changeset_id: str
    change_node_id: str
    run_id: str
    outcome: MaterializationOutcome
    equivalence: EnvironmentEquivalence
    evidence_ids: tuple[str, ...]
    capability_ids: tuple[str, ...]
    limitations: tuple[str, ...] = ()

    def validate(self) -> None:
        for name, value in (
            ("resolution_id", self.resolution_id),
            ("client_id", self.client_id),
            ("changeset_id", self.changeset_id),
            ("change_node_id", self.change_node_id),
            ("run_id", self.run_id),
        ):
            if not value.strip():
                raise ValueError(f"{name} is required")

        if not self.change_node_id.startswith("change:"):
            raise ValueError("materialization resolution must target a change node")
        if not self.evidence_ids:
            raise ValueError("materialization resolution requires evidence")
        if len(set(self.evidence_ids)) != len(self.evidence_ids):
            raise ValueError("materialization evidence_ids must be unique")
        if not self.capability_ids or any(not item.strip() for item in self.capability_ids):
            raise ValueError("materialization resolution requires capability_ids")
        if len(set(self.capability_ids)) != len(self.capability_ids):
            raise ValueError("materialization capability_ids must be unique")
        if len(set(self.limitations)) != len(self.limitations):
            raise ValueError("materialization limitations must be unique")
        if self.outcome is MaterializationOutcome.CONFIRMED and (
            self.equivalence is EnvironmentEquivalence.UNKNOWN
        ):
            raise ValueError(
                "confirmed materialization requires partial or representative equivalence"
            )


def _fact_id(resolution_id: str, predicate: str, value: str) -> str:
    payload = f"{resolution_id}\x1f{predicate}\x1f{value}".encode("utf-8")
    return f"materialization:{sha256(payload).hexdigest()[:24]}"


def _resolution_facts(
    resolution: FutureMaterializationResolution,
) -> tuple[TwinFact, ...]:
    evidence_refs = tuple(f"evidence:{item}" for item in resolution.evidence_ids)
    facts: list[TwinFact] = [
        TwinFact(
            _fact_id(
                resolution.resolution_id,
                "materialization.outcome",
                resolution.outcome.value,
            ),
            resolution.change_node_id,
            "materialization.outcome",
            resolution.outcome.value,
            FactProvenance.VERIFIED,
            1.0,
            evidence_refs,
        ),
        TwinFact(
            _fact_id(
                resolution.resolution_id,
                "materialization.equivalence",
                resolution.equivalence.value,
            ),
            resolution.change_node_id,
            "materialization.equivalence",
            resolution.equivalence.value,
            FactProvenance.DECLARED,
            1.0,
        ),
    ]

    for capability_id in sorted(resolution.capability_ids):
        facts.append(
            TwinFact(
                _fact_id(
                    resolution.resolution_id,
                    "materialization.capability",
                    capability_id,
                ),
                resolution.change_node_id,
                "materialization.capability",
                capability_id,
                FactProvenance.OBSERVED,
                1.0,
                evidence_refs,
            )
        )

    for limitation in sorted(resolution.limitations):
        facts.append(
            TwinFact(
                _fact_id(
                    resolution.resolution_id,
                    "materialization.limitation",
                    limitation,
                ),
                resolution.change_node_id,
                "materialization.limitation",
                limitation,
                FactProvenance.DECLARED,
                1.0,
            )
        )
    return tuple(facts)


def apply_future_materialization_resolution(
    future: SecurityTwin,
    resolution: FutureMaterializationResolution,
    context: RunContext,
    state: StateStore,
) -> SecurityTwin:
    """Attach one isolated materialization result to a future CHANGE node.

    This is a projection/evidence operation only. It never executes a tool,
    mutates the current twin, changes relationships or attack paths, or upgrades
    the original inferred change facts.
    """

    future.validate()
    resolution.validate()

    if future.kind is not TwinSnapshotKind.FUTURE:
        raise ValueError("materialization resolutions require a future Security Twin")
    if not context.is_lab or context.mode is not AssessmentMode.LAB_AUTONOMOUS:
        raise PermissionError("future materialization evidence must come from a lab run")
    if context.run_id != resolution.run_id:
        raise ValueError("resolution run_id does not match the immutable RunContext")
    if context.client_id != future.client_id or resolution.client_id != future.client_id:
        raise ValueError("future materialization cannot cross tenants")

    change_node = next(
        (node for node in future.nodes if node.node_id == resolution.change_node_id),
        None,
    )
    if change_node is None or change_node.kind is not TwinNodeKind.CHANGE:
        raise KeyError(f"unknown future change node {resolution.change_node_id!r}")

    attributes = dict(change_node.attributes)
    if attributes.get("changeset_id") != resolution.changeset_id:
        raise ValueError("resolution changeset_id does not match the change node")

    evidence = tuple(state.get_evidence(item) for item in resolution.evidence_ids)
    if any(item.run_id != resolution.run_id for item in evidence):
        raise ValueError("materialization evidence belongs to a different run")
    evidence_capabilities = {item.capability_id for item in evidence}
    if evidence_capabilities != set(resolution.capability_ids):
        raise ValueError(
            "resolution capability_ids must exactly match referenced evidence"
        )

    facts = _resolution_facts(resolution)
    existing_by_id = {fact.fact_id: fact for fact in future.facts}
    collisions = [fact for fact in facts if fact.fact_id in existing_by_id]
    if collisions:
        if all(
            fact.fact_id in existing_by_id and existing_by_id[fact.fact_id] == fact
            for fact in facts
        ):
            return future
        raise ValueError("materialization resolution collides with existing twin facts")

    # Guard the central ST2/ST3 invariant explicitly: existing change facts remain
    # inferred. Resolution facts describe the isolated run; they do not rewrite
    # what was inferred from source/config declarations.
    existing_change_facts = tuple(
        fact for fact in future.facts if fact.subject_id == resolution.change_node_id
    )
    for fact in existing_change_facts:
        if fact.predicate.startswith("change.") and fact.provenance is not FactProvenance.INFERRED:
            raise ValueError("future change signal provenance was unexpectedly promoted")

    metadata = dict(future.metadata)
    resolution_count = int(metadata.get("future_materialization_resolution_count", "0")) + 1
    confirmed_count = int(metadata.get("future_materialization_confirmed_count", "0"))
    if resolution.outcome is MaterializationOutcome.CONFIRMED:
        confirmed_count += 1
    metadata.update(
        {
            "future_materialization": "evidence_recorded",
            "future_materialization_resolution_count": str(resolution_count),
            "future_materialization_confirmed_count": str(confirmed_count),
            # Attack-graph semantics stay unresolved until the later graph-diff
            # stage consumes verified security effects, not merely lab outcomes.
            "future_semantics": "unresolved",
        }
    )

    snapshot = replace(
        future,
        version=future.version + 1,
        parent_twin_id=future.twin_id,
        parent_version=future.version,
        facts=future.facts + facts,
        metadata=tuple(sorted(metadata.items())),
    )
    snapshot.validate()

    if snapshot.relationships != future.relationships:
        raise AssertionError("materialization resolution must not mutate relationships")
    if snapshot.attack_paths != future.attack_paths:
        raise AssertionError("materialization resolution must not mutate attack paths")
    return snapshot
